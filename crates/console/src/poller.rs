//! The thread that talks to the daemon, so the frame loop never blocks.
//!
//! Drawing and networking are separated because a request over a tunnelled
//! connection can take a second, and an interface that stops repainting while it
//! waits is one that appears to have crashed at exactly the moment the operator
//! most wants to know what is happening.
//!
//! The two communicate only through [`Snapshot`]: the interface leaves commands
//! in it, this thread carries them out and writes back what the daemon said.
//! Neither calls the other.
//!
//! # Why a poll and not a subscription
//!
//! The interesting changes here are ones nobody asked for — a service crashed, a
//! restart backed off, a log grew. A poll every half second reports those with
//! no protocol beyond the one the API already has, and it re-establishes itself
//! after a disconnection without any reconnect logic: the next poll either works
//! or does not.

use crate::client::{Client, ClientError};
use crate::state::{Command, Link, LogLine, Snapshot};
use selfhost_firewall::FirewallState;
use selfhost_json::Json;
use selfhost_supervisor::state::{ServiceStatus, spec_from_json, spec_to_json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often the thread wakes to look for commands.
///
/// Short, because this is the delay between pressing a button and the request
/// leaving. It costs nothing: a wake with no work is a lock and a comparison.
const TICK: Duration = Duration::from_millis(60);

/// How often the daemon is asked for the state of things.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How many log lines to fetch at once.
///
/// The API caps this itself; asking for a bounded number keeps a service that
/// produced a hundred thousand lines while the console was closed from arriving
/// as one enormous reply.
const LOG_BATCH: usize = 500;

/// Starts the thread and answers a handle to it.
///
/// The thread stops when `running` is cleared, which the console does when its
/// window closes — so a command already in flight finishes rather than being
/// cut off half-written.
pub fn spawn(
    connect: impl Connect,
    shared: Arc<Mutex<Snapshot>>,
    running: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("selfhost-console-poller".into())
        .spawn(move || run(connect, shared, running))
        .expect("the operating system refused to start a thread")
}

/// Builds a client, or says why it cannot yet.
///
/// A function and not a finished [`Client`] because the thing it needs — the
/// token the daemon wrote — may not exist when the console opens. A console
/// launched from the Dock before its daemon has been started is the ordinary
/// case of that, and it must show a window saying so rather than never opening
/// one. Asked again on every poll, so starting the daemon afterwards connects
/// the console that is already on screen.
pub trait Connect: Fn() -> Result<Client, String> + Send + 'static {}

impl<F: Fn() -> Result<Client, String> + Send + 'static> Connect for F {}

/// The loop itself.
fn run(connect: impl Connect, shared: Arc<Mutex<Snapshot>>, running: Arc<AtomicBool>) {
    let mut last_poll: Option<Instant> = None;
    let mut client: Option<Client> = None;

    while running.load(Ordering::Relaxed) {
        let commands: Vec<Command> = {
            let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
            snapshot.commands.drain(..).collect()
        };

        // A command changes what the daemon will report, so its result is
        // fetched immediately rather than up to half a second later. Without
        // this, pressing Start leaves the row saying "Stopped" for long enough
        // to look like the button did nothing.
        let acted = !commands.is_empty();
        let due = last_poll.is_none_or(|at| at.elapsed() >= POLL_INTERVAL);

        if (acted || due) && client.is_none() {
            match connect() {
                Ok(built) => client = Some(built),
                Err(reason) => {
                    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
                    snapshot.link = Link::Lost(reason);
                    // The commands are dropped rather than queued: they were
                    // aimed at a daemon this console has never reached, and
                    // running them later would carry them out against whatever
                    // daemon happened to start next.
                    snapshot.commands.clear();
                }
            }
        }

        let Some(ready) = &client else {
            std::thread::sleep(TICK);
            continue;
        };

        for command in commands {
            carry_out(ready, &shared, command);
        }

        if acted || due {
            last_poll = Some(Instant::now());
            if refresh_services(ready, &shared) {
                refresh_definition(ready, &shared);
                refresh_logs(ready, &shared);
                refresh_firewall(ready, &shared);
            }
        }

        std::thread::sleep(TICK);
    }
}

/// Runs one command and reports what the daemon said about it.
fn carry_out(client: &Client, shared: &Arc<Mutex<Snapshot>>, command: Command) {
    let name = command.service().to_owned();
    let Some(path) = service_path(&name) else {
        let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
        snapshot.report_problem(format!("{name:?} is not a usable service name"));
        return;
    };

    let outcome = match &command {
        Command::Start(_) => client.post(&format!("{path}/start")),
        Command::Stop(_) => client.post(&format!("{path}/stop")),
        Command::Restart(_) => client.post(&format!("{path}/restart")),
        Command::Uninstall(_) => client.delete(&path),
        Command::Install(spec) => client.put(&path, &spec_to_json(spec)),
    };

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    match outcome {
        Ok(_) => {
            snapshot.report_done(command.done_message());
            // The detail pane cannot show something that is no longer installed.
            if matches!(command, Command::Uninstall(_)) && snapshot.selected.as_deref() == Some(&name)
            {
                snapshot.selected = None;
            }
            if matches!(command, Command::Install(_)) {
                snapshot.selected = Some(name);
            }
        }
        Err(error) => {
            snapshot.report_problem(describe(&error));
            if error.is_disconnection() {
                snapshot.link = Link::Lost(error.to_string());
            }
        }
    }
}

/// Fetches every service's state; answers whether the daemon replied.
fn refresh_services(client: &Client, shared: &Arc<Mutex<Snapshot>>) -> bool {
    match client.get("/api/services") {
        Ok(value) => {
            let services: Vec<ServiceStatus> = value
                .get("services")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(ServiceStatus::from_json)
                .collect();

            let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
            snapshot.link = Link::Connected;
            // Choosing the first service saves the operator a click on the
            // common case of watching one thing, and only ever happens when
            // nothing is chosen — it never overrides a selection.
            if snapshot.selected.is_none() {
                snapshot.selected = services.first().map(|service| service.name.clone());
                snapshot.spec = None;
            }
            snapshot.services = services;
            true
        }
        Err(error) => {
            let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
            if error.is_disconnection() {
                snapshot.link = Link::Lost(error.to_string());
            } else {
                snapshot.link = Link::Connected;
                snapshot.report_problem(describe(&error));
            }
            false
        }
    }
}

/// Fetches the selected service's full definition.
///
/// A separate request from the list because the list carries live state only —
/// the thing that changes every half second — and a definition changes when
/// somebody edits it, which is almost never. Sending the whole catalogue's
/// definitions on every poll to keep one pane filled would be the wrong trade.
fn refresh_definition(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let name = {
        let snapshot = shared.lock().expect("the snapshot lock was poisoned");
        let Some(name) = snapshot.selected.clone() else {
            return;
        };
        name
    };

    let Some(path) = service_path(&name) else {
        return;
    };
    let Ok(value) = client.get(&path) else {
        return;
    };
    let Some(spec) = value.get("spec").and_then(spec_from_json) else {
        return;
    };

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // The selection may have moved on while this was in flight; showing one
    // service's program path under another's name would be a lie.
    if snapshot.selected.as_deref() == Some(name.as_str()) {
        snapshot.spec = Some(Box::new(spec));
    }
}

/// Fetches the host firewall's exposure into the snapshot.
///
/// A separate request from the service list, and cheap: the firewall changes
/// only when the operator edits config and the daemon reconciles, which is almost
/// never — the same reasoning [`refresh_definition`] rests on. A failure is
/// silent, not a notice: `GET /api/firewall` on a daemon built before the
/// firewall existed simply 404s, and a message per poll for a missing optional
/// feature would bury the ones that matter. The last good exposure is left in
/// place until a fetch succeeds.
fn refresh_firewall(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    if let Ok(value) = client.get("/api/firewall") {
        if let Some(state) = FirewallState::from_json(&value) {
            shared.lock().expect("the snapshot lock was poisoned").firewall = Some(state);
        }
    }
}

/// Fetches whatever the selected service has printed since last time.
fn refresh_logs(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let (name, from) = {
        let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
        let Some(name) = snapshot.selected.clone() else {
            return;
        };
        if snapshot.logs.service != name {
            snapshot.logs.follow(&name);
        }
        (name, snapshot.logs.next_seq)
    };

    let Some(path) = service_path(&name) else {
        return;
    };
    let Ok(value) = client.get(&format!("{path}/logs?from={from}&limit={LOG_BATCH}")) else {
        // A failed log fetch is not worth a notice: the next poll retries in
        // half a second, and a message per failure would bury everything else.
        return;
    };

    let lines: Vec<LogLine> = value
        .get("lines")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(read_line)
        .collect();
    let next_seq = value.get("nextSeq").and_then(Json::as_u64).unwrap_or(from);
    let missed = value.get("missed").and_then(Json::as_u64).unwrap_or(0);

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // The selection may have changed while this request was in flight. Showing
    // one service's output under another's name is worse than showing none.
    if snapshot.logs.service != name {
        return;
    }
    snapshot.logs.append(lines, next_seq, missed);
}

/// Reads one log line from the wire.
fn read_line(value: &Json) -> Option<LogLine> {
    Some(LogLine {
        seq: value.get("seq").and_then(Json::as_u64).unwrap_or(0),
        is_error: value.get("stream").and_then(Json::as_str) == Some("stderr"),
        text: value.get("text")?.as_str()?.to_owned(),
    })
}

/// The API path for a service, or `None` when the name cannot appear in one.
///
/// Names are checked rather than escaped. The daemon restricts them to these
/// characters already, so anything else did not come from a service the daemon
/// installed — and a name carrying `../` or a query string would otherwise build
/// a request for a different endpoint entirely.
fn service_path(name: &str) -> Option<String> {
    let usable = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && name != "."
        && name != "..";
    usable.then(|| format!("/api/services/{name}"))
}

/// Turns a client error into something worth putting in front of a person.
///
/// A refusal carries the daemon's own explanation, which is more specific than
/// anything this end could say; a disconnection does not, so it says what it
/// tried to reach.
fn describe(error: &ClientError) -> String {
    match error {
        ClientError::Refused { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_service_names_become_paths() {
        assert_eq!(service_path("mongod").as_deref(), Some("/api/services/mongod"));
        assert_eq!(service_path("levelup-api.v2_1").as_deref(), Some("/api/services/levelup-api.v2_1"));
    }

    #[test]
    fn a_name_that_could_reach_a_different_endpoint_is_refused() {
        for name in ["../health", "a/b", "a?from=0", "a b", "a#b", "", ".", "..", "a%2fb"] {
            assert!(service_path(name).is_none(), "accepted the name {name:?}");
        }
    }

    #[test]
    fn an_absurdly_long_name_is_refused() {
        assert!(service_path(&"a".repeat(129)).is_none());
        assert!(service_path(&"a".repeat(128)).is_some());
    }

    #[test]
    fn a_log_line_is_read_from_the_wire() {
        let value = Json::object([
            ("seq", Json::Number(7.0)),
            ("stream", Json::string("stderr")),
            ("text", Json::string("could not bind")),
        ]);
        let line = read_line(&value).expect("a line");
        assert_eq!(line.seq, 7);
        assert!(line.is_error);
        assert_eq!(line.text, "could not bind");
    }

    #[test]
    fn a_line_without_text_is_dropped_rather_than_shown_blank() {
        let value = Json::object([("seq", Json::Number(1.0))]);
        assert!(read_line(&value).is_none());
    }

    #[test]
    fn standard_output_is_not_marked_as_an_error() {
        let value = Json::object([
            ("stream", Json::string("stdout")),
            ("text", Json::string("listening")),
        ]);
        assert!(!read_line(&value).expect("a line").is_error);
    }

    #[test]
    fn a_refusal_is_described_in_the_daemons_own_words() {
        let refused = ClientError::Refused {
            status: selfhost_http::Status(404),
            message: "no such service".into(),
        };
        assert_eq!(describe(&refused), "no such service");
    }

    #[test]
    fn a_disconnection_says_what_it_could_not_reach() {
        let error = ClientError::Unreachable(std::io::Error::other("connection refused"));
        assert!(describe(&error).contains("cannot reach the daemon"));
    }
}
