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
use crate::nas::{self, Listing, Share};
use crate::registry::{Person, Trail};
use crate::remote::{Agent, Node, Settings};
use crate::state::{Command, FileAction, Link, LogLine, Screen, Snapshot, Viewer};
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

        let mut answered = Answered::No;
        if acted || due {
            last_poll = Some(Instant::now());
            answered = refresh_services(ready, &shared);
            if answered == Answered::Yes {
                refresh_viewer(ready, &shared);
                // The service list is fetched whatever is on screen: the
                // masthead's own condition is read off it, and every screen
                // carries the masthead. Everything below is per-screen — see
                // [`Screen`] for why a plate nobody has open costs nothing.
                match screen(&shared) {
                    Screen::Services => {
                        refresh_definition(ready, &shared);
                        refresh_logs(ready, &shared);
                        refresh_firewall(ready, &shared);
                    }
                    Screen::Files => {
                        refresh_shares(ready, &shared);
                        refresh_listing(ready, &shared);
                    }
                    Screen::Desktop => refresh_desktop(ready, &shared),
                    Screen::People => refresh_people(ready, &shared),
                }
            }
        }

        // A refused credential is thrown away rather than retried for ever. The
        // daemon writes a new token every time it starts — which on the
        // production box is every push — so the next poll builds a client from
        // a freshly read one and the console reconnects itself instead of
        // having to be quit and started again.
        if answered == Answered::StaleCredential {
            client = None;
        }

        std::thread::sleep(TICK);
    }
}

/// Asks the daemon who this console's credential is, once.
///
/// Fetched exactly once per connection rather than every poll: a session's
/// identity does not change under it, and a grant that does takes effect on the
/// next connection — which the poller makes by itself whenever the daemon
/// restarts or the credential goes stale. Costing every poll a request to learn
/// an answer that is the same every time is the thing [`Screen`] exists to
/// avoid.
///
/// A daemon built before this route existed answers `404`, and the console then
/// keeps `None` — which draws every screen, exactly as it did before. An older
/// daemon must not look like a person who holds nothing.
fn refresh_viewer(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    if shared.lock().expect("the snapshot lock was poisoned").viewer.is_some() {
        return;
    }
    let Ok(value) = client.get("/api/whoami") else {
        return;
    };
    let Some(viewer) = Viewer::from_json(&value) else {
        return;
    };
    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // A screen this credential may not open must not stay open because it
    // happened to be the one showing when the answer arrived.
    if !Screen::for_viewer(Some(&viewer)).contains(&snapshot.screen) {
        snapshot.screen = Screen::for_viewer(Some(&viewer)).first().copied().unwrap_or_default();
    }
    snapshot.viewer = Some(viewer);
}

/// Which screen the interface has open.
fn screen(shared: &Arc<Mutex<Snapshot>>) -> Screen {
    shared.lock().expect("the snapshot lock was poisoned").screen
}

/// Runs one command and reports what the daemon said about it.
fn carry_out(client: &Client, shared: &Arc<Mutex<Snapshot>>, command: Command) {
    // The two commands that are about no service take their own path: their
    // targets are checked against their own grammars, and building a service
    // path for them would be a path nobody asked for.
    let outcome = match &command {
        Command::Files { share, action } => carry_out_file(client, share, action),
        Command::RevokePasskey { id, .. } => revoke(client, id),
        _ => {
            let name = command.service().to_owned();
            let Some(path) = service_path(&name) else {
                let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
                snapshot.report_problem(format!("{name:?} is not a usable service name"));
                return;
            };
            match &command {
                Command::Start(_) => client.post(&format!("{path}/start")),
                Command::Stop(_) => client.post(&format!("{path}/stop")),
                Command::Restart(_) => client.post(&format!("{path}/restart")),
                Command::Uninstall(_) => client.delete(&path),
                Command::Install(spec) => client.put(&path, &spec_to_json(spec)),
                // Answered above; stated so the match is closed rather than
                // defaulted, which is what makes a variant added later a build
                // error instead of a command that silently does nothing.
                Command::Files { .. } | Command::RevokePasskey { .. } => return,
            }
        }
    };

    let name = command.service().to_owned();
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
            // A directory that has just been written to is stale, and the next
            // ordinary poll is up to half a second away. Clearing the listing
            // is what makes the row appear — or disappear — as the press
            // finishes rather than a beat later.
            if matches!(command, Command::Files { .. }) {
                snapshot.files.listing = None;
                snapshot.files.trouble = None;
            }
            if matches!(command, Command::RevokePasskey { .. }) {
                snapshot.people.holders = None;
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
fn refresh_services(client: &Client, shared: &Arc<Mutex<Snapshot>>) -> Answered {
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
            Answered::Yes
        }
        Err(error) => {
            let stale = error.is_stale_credential();
            let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
            if error.is_disconnection() {
                snapshot.link = Link::Lost(error.to_string());
            } else if stale {
                // Not reported as a problem: the console is about to fix it by
                // itself, and a notice saying the daemon refused it would be a
                // bar to dismiss for something nobody has to do anything about.
                snapshot.link = Link::Connecting;
            } else {
                snapshot.link = Link::Connected;
                snapshot.report_problem(describe(&error));
            }
            if stale { Answered::StaleCredential } else { Answered::No }
        }
    }
}

/// What one fetch of the service list came to.
///
/// Three answers and not a boolean, because the third one is an instruction: a
/// daemon that refused the credential wants a *new client*, and a poller told
/// only "that did not work" would ask the same refused token again every half
/// second for as long as the window stayed open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answered {
    /// The daemon replied, and the snapshot now holds what it said.
    Yes,
    /// It did not, and nothing more is to be done this tick.
    No,
    /// It refused the token in hand, which a freshly read one may fix.
    StaleCredential,
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

/// Carries out one file action against one share.
///
/// # Every path is encoded exactly once, here
///
/// The console keeps plain paths and this is the only place one becomes part of
/// a request, through [`nas::url_path`]. That is what makes a file called
/// `a&b=c` a file rather than a second query parameter, and a directory called
/// `100%` a directory rather than a malformed escape. The share id is *checked*
/// rather than encoded, for the reason [`service_path`] checks a service name.
fn carry_out_file(
    client: &Client,
    share: &str,
    action: &FileAction,
) -> Result<Json, ClientError> {
    let Some(base) = share_path(share) else {
        return Err(refused(400, format!("{share:?} is not a usable share id")));
    };
    match action {
        FileAction::Mkdir { path } => {
            client.request(
                crate::client::Method::Post,
                &format!("{base}/mkdir"),
                Some(&Json::object([("path", Json::string(path.as_str()))])),
            )
        }
        FileAction::Rename { from, to } => client.request(
            crate::client::Method::Post,
            &format!("{base}/rename"),
            Some(&Json::object([
                ("from", Json::string(from.as_str())),
                ("to", Json::string(to.as_str())),
                // Never `true`. A rename that silently replaced an existing
                // name would destroy a file the operator did not name, and the
                // daemon's own refusal is the thing that stops it.
                ("replace", Json::Bool(false)),
            ])),
        ),
        FileAction::Delete { path } => {
            client.delete(&format!("{base}/entry?path={}", nas::url_path(path)))
        }
        FileAction::Download { path, to } => {
            let bytes = client.fetch(&blob_path(share, path))?;
            std::fs::write(to, &bytes)
                .map(|()| Json::Null)
                .map_err(|error| refused(500, format!("could not write the file: {error}")))
        }
        FileAction::Upload { from, path } => {
            let bytes = std::fs::read(from)
                .map_err(|error| refused(400, format!("could not read the file: {error}")))?;
            if bytes.len() as u64 > nas::MAX_TRANSFER {
                return Err(refused(
                    413,
                    format!(
                        "this console uploads files up to {} at a time",
                        nas::size_text(nas::MAX_TRANSFER)
                    ),
                ));
            }
            // The bulk plane takes the bytes as they are; the type is stated as
            // the one that claims nothing, because guessing a type from a
            // suffix is how a file comes back later as something it is not.
            client.send(&blob_path(share, path), "application/octet-stream", &bytes)
        }
    }
}

/// Takes one credential out of the registry.
fn revoke(client: &Client, id: &str) -> Result<Json, ClientError> {
    if !crate::registry::usable_credential_id(id) {
        return Err(refused(400, "that is not a credential this daemon issued".to_owned()));
    }
    client.delete(&format!("/api/webauthn/credentials/{id}"))
}

/// A refusal this console made on its own, in the shape the daemon's would take.
///
/// So that a local objection — an unusable share id, a file that would not open
/// — reaches the notice bar through the same path a remote one does, rather than
/// through a second reporting mechanism that would eventually say it differently.
fn refused(status: u16, message: String) -> ClientError {
    ClientError::Refused { status: selfhost_http::Status(status), message }
}

/// The control-plane path for one share, or `None` for an unusable id.
fn share_path(share: &str) -> Option<String> {
    nas::usable_share_id(share).then(|| format!("/api/storage/shares/{share}"))
}

/// The bulk-plane path for one file inside one share.
///
/// The share id is already checked by the caller and the remainder is
/// percent-encoded here — the same split the daemon makes in
/// `storage_api::split_blob`, from the other side.
fn blob_path(share: &str, path: &str) -> String {
    format!("/api/storage/blob/{share}/{}", nas::url_path(path))
}

/// Fetches every share this caller may open.
///
/// A `404` is not a failure and does not become a notice: a daemon built before
/// the storage subsystem existed, or one with no `[[shares]]`, simply does not
/// serve this route, and a message per poll for a missing optional feature would
/// bury the ones that matter. The plate draws the absence as a sentence.
fn refresh_shares(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let Ok(value) = client.get("/api/storage/shares") else {
        return;
    };
    let shares: Vec<Share> = value
        .get("shares")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(Share::from_json)
        .collect();

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // Choosing the first share saves the operator a press on the common case of
    // one share, and only ever happens when nothing is chosen.
    if snapshot.files.share.is_none() {
        if let Some(first) = shares.first() {
            snapshot.files.open(&first.id);
        }
    }
    snapshot.files.shares = Some(shares);
}

/// Fetches the directory the plate is looking at.
///
/// A refusal is kept beside the listing rather than replacing it: the last good
/// directory stays on screen with the reason above it, which is more use to a
/// person than a blank pane — and the reason is the daemon's own sentence, which
/// on a quota or a permission carries a number this end does not have.
fn refresh_listing(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let (share, path, column, ascending) = {
        let snapshot = shared.lock().expect("the snapshot lock was poisoned");
        let Some(share) = snapshot.files.share.clone() else {
            return;
        };
        (share, snapshot.files.path.clone(), snapshot.files.column, snapshot.files.ascending)
    };
    let Some(base) = share_path(&share) else {
        return;
    };

    let asked = format!("{base}/list?path={}", nas::url_path(&path));
    let (listing, trouble) = match client.get(&asked) {
        Ok(value) => (Listing::from_json(&share, &value), None),
        Err(ClientError::Refused { status, message }) => {
            (None, Some(nas::refusal_text(status.code(), Some(&Json::string(message)))))
        }
        // A disconnection is already stated by the masthead; saying it again
        // over the listing would be the same fact twice.
        Err(_) => return,
    };

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // The operator may have walked on while this was in flight. Drawing one
    // directory's names under another's breadcrumb is worse than drawing none.
    if snapshot.files.share.as_deref() != Some(share.as_str()) || snapshot.files.path != path {
        return;
    }
    if let Some(mut listing) = listing {
        nas::sort_entries(&mut listing.entries, column, ascending);
        snapshot.files.listing = Some(listing);
    }
    snapshot.files.trouble = trouble;
}

/// Fetches the desktop switches, the fleet, and the chosen machine's agent.
///
/// Three requests rather than one, because they are three different lifetimes: a
/// switch changes when somebody edits a file on the box, the fleet changes when
/// a laptop wakes up, and the agent report changes every time it respawns. A
/// `404` on the first means this deployment serves no desktop, which is the
/// ordinary case and is left as `None` for the plate to state.
fn refresh_desktop(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let settings = client.get("/api/desktop").ok().as_ref().and_then(Settings::from_json);
    let nodes: Option<Vec<Node>> = client.get("/api/desktop/nodes").ok().map(|value| {
        value
            .get("nodes")
            .and_then(Json::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(Node::from_json)
            .collect()
    });

    let peer = {
        let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
        snapshot.desk.settings = settings;
        if let Some(nodes) = &nodes {
            // The machine the daemon itself runs on is the one every deployment
            // has, so it is what the picker opens on when nothing is chosen.
            if snapshot.desk.peer.is_none() {
                snapshot.desk.peer = nodes
                    .iter()
                    .find(|node| node.node == crate::remote::LOCAL_NODE)
                    .or_else(|| nodes.first())
                    .map(|node| node.node.clone());
            }
        }
        snapshot.desk.nodes = nodes;
        snapshot.desk.peer.clone()
    };

    let Some(peer) = peer.filter(|peer| crate::remote::usable_node_name(peer)) else {
        return;
    };
    let agent = client
        .get(&format!("/api/desktop/agent?peer={peer}"))
        .ok()
        .as_ref()
        .and_then(Agent::from_json);

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    // The picker may have moved on while this was in flight; an agent report
    // drawn under another machine's name is a lie about which box is up.
    if snapshot.desk.peer.as_deref() == Some(peer.as_str()) {
        snapshot.desk.agent = agent;
    }
}

/// Fetches the identity registry and the audit tail.
///
/// Both are owner-only at the daemon, so both answer `401` on a deployment where
/// this console's credential is not the owner. That is kept as a sentence rather
/// than drawn as an empty list: an empty registry and a refused one are
/// different facts, and only one of them is reassuring.
fn refresh_people(client: &Client, shared: &Arc<Mutex<Snapshot>>) {
    let (holders, trouble) = match client.get("/api/webauthn/credentials") {
        Ok(value) => {
            let holders = value
                .get("passkeys")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Person::from_json)
                .collect();
            (Some(holders), None)
        }
        Err(ClientError::Refused { status, message }) => {
            (None, Some(nas::refusal_text(status.code(), Some(&Json::string(message)))))
        }
        Err(_) => return,
    };
    let trail = client.get("/api/audit").ok().as_ref().and_then(Trail::from_json);

    let mut snapshot = shared.lock().expect("the snapshot lock was poisoned");
    snapshot.people.holders = holders;
    snapshot.people.trouble = trouble;
    if trail.is_some() {
        snapshot.people.trail = trail;
    }
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
