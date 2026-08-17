//! The SSH tunnel to a remote daemon, managed as a child process.
//!
//! The control API binds loopback and refuses anything else, so reaching a daemon
//! on another machine means forwarding its port. This module runs `ssh` to do it,
//! watches the process, and brings it back when it dies.
//!
//! # Why the system `ssh` and not a protocol of our own
//!
//! Everything this project puts on a wire it writes itself, because a lenient
//! parser is a security bug. SSH is the exception for the same reason `rustls` is:
//! the authentication and the transport encryption of the channel that controls
//! every service on the machine are not a place to debut new cryptography.
//! OpenSSH is already installed, already audited, and already holds the operator's
//! keys and known hosts.
//!
//! # Why the console manages it rather than assuming one
//!
//! A tunnel the operator brings up by hand is a second thing to remember, in a
//! second window, that dies silently. Running it as a child means the console can
//! say *tunnel down: permission denied* instead of *no daemon*, which are the same
//! symptom with completely different fixes.
//!
//! # The prompt problem, and how it is avoided rather than handled
//!
//! `ssh` asks questions: to confirm an unknown host key, and for a key passphrase.
//! A graphical program has no terminal to answer them on, so a prompt would hang
//! the tunnel forever with no visible cause. Every invocation therefore passes
//! `-o BatchMode=yes`, which turns each of those prompts into an immediate failure
//! with a message — and [`advice_for`] turns that message into the one-line
//! instruction that fixes it. The console never tries to answer a prompt itself:
//! accepting a host key on the operator's behalf is exactly the check that makes
//! the tunnel worth anything.

use crate::state::{Snapshot, Tunnel};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long to wait for the forwarded port to start accepting connections.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest wait between attempts to bring the tunnel back.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// How long `ssh host cat …` is given to hand back the token.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(20);

/// How much of `ssh`'s complaining is kept, in lines.
const KEPT_LINES: usize = 20;

/// Where the daemon writes its token on the server, relative to the login
/// directory.
///
/// A default rather than a discovery: the daemon's project directory is not
/// something the console can ask about before it can talk to the daemon, which is
/// the very thing the token is needed for.
pub const DEFAULT_REMOTE_TOKEN: &str = "data/admin.token";

/// A tunnel the console should keep open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
    /// The server, as `ssh` takes it: `host` or `user@host`.
    pub destination: String,
    /// The port `sshd` listens on, when it is not 22.
    pub ssh_port: Option<u16>,
    /// A private key to use, when the agent's default is not the right one.
    pub identity: Option<PathBuf>,
    /// The port on this machine the daemon appears at.
    pub local_port: u16,
    /// The port the daemon's control API listens on over there.
    pub remote_port: u16,
}

impl TunnelSpec {
    /// A tunnel forwarding `port` from `destination` to the same port here.
    pub fn new(destination: impl Into<String>, port: u16) -> Self {
        Self {
            destination: destination.into(),
            ssh_port: None,
            identity: None,
            local_port: port,
            remote_port: port,
        }
    }

    /// Where the console talks to reach the forwarded daemon.
    pub fn local_address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.local_port))
    }

    /// The arguments for the forwarding process itself.
    pub fn forward_args(&self) -> Vec<String> {
        let mut args = self.common_args();
        // No command, no terminal: this process exists only to forward a port.
        args.push("-N".into());
        args.push("-T".into());
        // Without this, ssh connects happily when the local port is already taken
        // and the console then talks to whatever else is listening on it.
        args.push("-o".into());
        args.push("ExitOnForwardFailure=yes".into());
        // A tunnel through a home connection outlives the connection itself
        // otherwise: the socket stays open against a server that is long gone, and
        // every request waits for a TCP timeout rather than failing.
        args.push("-o".into());
        args.push("ServerAliveInterval=15".into());
        args.push("-o".into());
        args.push("ServerAliveCountMax=3".into());
        // Bound to loopback explicitly. A bare `-L 9191:…` follows GatewayPorts,
        // which on a machine configured for it would put the control port of a
        // remote server on this machine's network.
        args.push("-L".into());
        args.push(format!("127.0.0.1:{}:127.0.0.1:{}", self.local_port, self.remote_port));
        args.push(self.destination.clone());
        args
    }

    /// The arguments for reading the daemon's token over the same connection.
    ///
    /// `cat` over SSH rather than a new secret to distribute: whoever can open
    /// this tunnel can already control every service on that machine, so a token
    /// they may not read would protect nothing and be one more thing to rotate.
    pub fn token_args(&self, remote_path: &str) -> Vec<String> {
        let mut args = self.common_args();
        args.push(self.destination.clone());
        args.push("--".into());
        args.push("cat".into());
        args.push(remote_path.to_owned());
        args
    }

    /// The options every invocation shares.
    fn common_args(&self) -> Vec<String> {
        let mut args = vec![
            // The reason a prompt can never hang the window.
            "-o".into(),
            "BatchMode=yes".into(),
        ];
        if let Some(port) = self.ssh_port {
            args.push("-p".into());
            args.push(port.to_string());
        }
        if let Some(identity) = &self.identity {
            args.push("-i".into());
            args.push(identity.display().to_string());
            // With a key named explicitly, the agent's other keys are noise: a
            // server that refuses five of them before the right one can hit
            // MaxAuthTries and fail for the wrong reason.
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
        }
        args
    }
}

/// Turns `ssh`'s own complaint into the instruction that fixes it.
///
/// `BatchMode` converts the questions `ssh` would have asked into failures, and
/// each of those failures has exactly one fix that a person has to carry out in a
/// terminal. Saying which is the difference between a console that reports a
/// problem and one that resolves it.
pub fn advice_for(complaint: &str) -> Option<String> {
    let text = complaint.to_ascii_lowercase();

    if text.contains("host key verification failed") || text.contains("no matching host key") {
        return Some(
            "the host key is not known here. Run `ssh <server>` once in a terminal, check the \
             fingerprint, and accept it — the console will not accept it for you"
                .into(),
        );
    }
    if text.contains("remote host identification has changed") {
        return Some(
            "the server is presenting a different host key than the one recorded. Either it was \
             rebuilt or this is not the same machine; resolve it in a terminal before reconnecting"
                .into(),
        );
    }
    if text.contains("permission denied") || text.contains("too many authentication failures") {
        return Some(
            "the server refused the key. Load it with `ssh-add`, name it with --identity, or \
             install it there with `ssh-copy-id`"
                .into(),
        );
    }
    if text.contains("could not resolve hostname") {
        return Some("the server's name does not resolve from here. Check it, or use its address".into());
    }
    if text.contains("connection refused") {
        return Some(
            "nothing accepted the SSH connection. Check that sshd is running, and --ssh-port if \
             it does not listen on 22"
                .into(),
        );
    }
    if text.contains("connection timed out") || text.contains("operation timed out") {
        return Some("the server did not answer. Check that it is up and reachable from here".into());
    }
    if text.contains("cannot listen to port") || text.contains("address already in use") {
        return Some(
            "the local port is already taken — a daemon of your own, or another tunnel. Pass \
             --local-port to use a different one"
                .into(),
        );
    }
    if text.contains("permission denied (publickey)") {
        return Some("the server accepted no key this client offered".into());
    }
    None
}

/// How long to wait before the next attempt, after `failures` in a row.
///
/// Doubles, and stops doubling at [`MAX_RETRY`]. A tunnel that fails because a
/// laptop lid closed should come back quickly; one failing because the key is
/// wrong should not spend a machine's evening asking again.
pub fn retry_delay(failures: u32) -> Duration {
    let seconds = 1u64 << failures.min(6);
    Duration::from_secs(seconds).min(MAX_RETRY)
}

/// Reads the daemon's bearer token from the server, over SSH.
///
/// Blocking, and called before the window opens: a console that cannot
/// authenticate has nothing to draw, and the failure belongs on the terminal the
/// operator started it from, where it can be read and acted on.
pub fn fetch_token(spec: &TunnelSpec, remote_path: &str) -> Result<String, String> {
    let mut child = Command::new(SSH)
        .args(spec.token_args(remote_path))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run ssh: {error}"))?;

    let deadline = Instant::now() + TOKEN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                return Err(format!(
                    "ssh {} did not answer within {}s",
                    spec.destination,
                    TOKEN_TIMEOUT.as_secs()
                ));
            }
            Err(error) => return Err(format!("cannot wait for ssh: {error}")),
        }
    }

    let output = child.wait_with_output().map_err(|error| format!("cannot read ssh: {error}"))?;
    if output.status.success() {
        let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        return if token.is_empty() {
            Err(format!("{remote_path} on {} is empty", spec.destination))
        } else {
            Ok(token)
        };
    }

    let complaint = String::from_utf8_lossy(&output.stderr);
    let first = complaint.lines().find(|line| !line.trim().is_empty()).unwrap_or("ssh failed");
    Err(match advice_for(&complaint) {
        Some(advice) => format!("{first}\n{advice}"),
        None => format!(
            "{first}\nIf the daemon's project directory is not the login directory, pass \
             --remote-token with the path to its {DEFAULT_REMOTE_TOKEN}"
        ),
    })
}

/// Starts the thread that keeps the tunnel open, and answers a handle to it.
///
/// The thread stops when `running` is cleared — which the console does when its
/// window closes — and kills `ssh` on the way out, so closing the window does not
/// leave a forwarded port behind.
pub fn spawn(
    spec: TunnelSpec,
    shared: Arc<Mutex<Snapshot>>,
    running: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("selfhost-console-tunnel".into())
        .spawn(move || keep_open(SSH, spec, shared, running))
        .expect("the operating system refused to start a thread")
}

/// The program that does the forwarding.
///
/// Named, rather than written into the one call, so a test can drive the whole
/// loop — including the part that has to kill the child when the window closes —
/// against a stub instead of a real server.
const SSH: &str = "ssh";

/// Brings the tunnel up, and brings it back whenever it goes down.
fn keep_open(
    program: &str,
    spec: TunnelSpec,
    shared: Arc<Mutex<Snapshot>>,
    running: Arc<AtomicBool>,
) {
    let mut failures = 0u32;

    while running.load(Ordering::Relaxed) {
        report(&shared, Tunnel::Opening);

        let mut child = match Command::new(program)
            .args(spec.forward_args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                report(
                    &shared,
                    Tunnel::Broken {
                        reason: format!("cannot run ssh: {error}"),
                        advice: Some("install OpenSSH, or put ssh on this machine's PATH".into()),
                    },
                );
                return;
            }
        };

        let complaints = drain_stderr(&mut child);
        let opened = wait_for_port(&spec, &mut child, &running);
        if opened {
            failures = 0;
            report(&shared, Tunnel::Open);
        }

        // Either it is up and this waits for it to die, or it never came up and
        // this returns at once with the reason in `complaints`.
        wait_for_exit(&mut child, &running);
        if !running.load(Ordering::Relaxed) {
            let _ = child.kill();
            // Waited for, not only signalled: a killed child that is never reaped
            // stays in the process table as a zombie for as long as the console
            // lives, and reads to anything looking — `ps`, another console — as a
            // tunnel that is still there.
            let _ = child.wait();
            return;
        }

        let complaint = first_complaint(&complaints);
        failures = failures.saturating_add(1);
        let delay = retry_delay(failures);
        report(
            &shared,
            Tunnel::Broken {
                reason: format!("{complaint} — retrying in {}s", delay.as_secs()),
                advice: advice_for(&complaint),
            },
        );
        sleep_while_running(delay, &running);
    }
}

/// Publishes the tunnel's state where the interface can draw it.
fn report(shared: &Arc<Mutex<Snapshot>>, state: Tunnel) {
    let mut snapshot = match shared.lock() {
        Ok(snapshot) => snapshot,
        Err(poisoned) => poisoned.into_inner(),
    };
    snapshot.tunnel = Some(state);
}

/// Collects what `ssh` writes to standard error, keeping the last few lines.
///
/// On its own thread because the pipe has to be drained: an `ssh` that fills it
/// blocks, and a blocked `ssh` never exits, so the console would wait forever for
/// a process that has already decided to fail.
fn drain_stderr(child: &mut Child) -> Arc<Mutex<Vec<String>>> {
    let kept = Arc::new(Mutex::new(Vec::new()));
    let Some(stderr) = child.stderr.take() else {
        return kept;
    };

    let sink = Arc::clone(&kept);
    let _ = std::thread::Builder::new()
        .name("selfhost-console-tunnel-log".into())
        .spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut lines = match sink.lock() {
                    Ok(lines) => lines,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lines.push(line);
                if lines.len() > KEPT_LINES {
                    lines.remove(0);
                }
            }
        });
    kept
}

/// Waits until the forwarded port accepts a connection, or `ssh` gives up.
///
/// Connecting is the only honest signal that the forward is live: `ssh -N` prints
/// nothing on success, so treating "it has not failed yet" as "it is up" would
/// report a working tunnel during the seconds before it fails.
///
/// It cannot tell *our* forward from something else already holding that port,
/// and does not try to. `ExitOnForwardFailure` makes `ssh` exit when it cannot
/// bind, so the mislabel lasts only until that exit is noticed — and the fix for
/// an occupied port is `--local-port`, which the advice already says.
fn wait_for_port(spec: &TunnelSpec, child: &mut Child, running: &Arc<AtomicBool>) -> bool {
    let address = spec.local_address();
    let deadline = Instant::now() + OPEN_TIMEOUT;

    while Instant::now() < deadline && running.load(Ordering::Relaxed) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return false;
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Waits for `ssh` to exit, giving up as soon as the console is closing.
fn wait_for_exit(child: &mut Child, running: &Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Sleeps, waking early if the console is closing.
fn sleep_while_running(delay: Duration, running: &Arc<AtomicBool>) {
    let until = Instant::now() + delay;
    while Instant::now() < until && running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The line worth showing out of everything `ssh` said.
fn first_complaint(kept: &Arc<Mutex<Vec<String>>>) -> String {
    let lines = match kept.lock() {
        Ok(lines) => lines,
        Err(poisoned) => poisoned.into_inner(),
    };
    lines
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .unwrap_or("the tunnel closed")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> TunnelSpec {
        TunnelSpec::new("rocky@server.example", 9191)
    }

    /// Whether `args` contains `flag` immediately followed by `value`.
    fn has_option(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|pair| pair[0] == flag && pair[1] == value)
    }

    #[test]
    fn nothing_this_runs_can_stop_and_ask_a_question() {
        // A prompt with no terminal to answer it on hangs the tunnel with no
        // visible cause, which is the failure this whole module is shaped around.
        assert!(has_option(&spec().forward_args(), "-o", "BatchMode=yes"));
        assert!(has_option(&spec().token_args("data/admin.token"), "-o", "BatchMode=yes"));
    }

    #[test]
    fn the_forward_is_bound_to_loopback_at_both_ends() {
        // A bare `-L 9191:…` follows GatewayPorts, which would publish a remote
        // machine's control port on this machine's network.
        let args = spec().forward_args();
        assert!(
            has_option(&args, "-L", "127.0.0.1:9191:127.0.0.1:9191"),
            "{args:?}"
        );
    }

    #[test]
    fn a_forward_that_cannot_be_established_takes_ssh_down_with_it() {
        // Otherwise ssh connects, the forward silently fails, and the console
        // talks to whatever else happens to hold the local port.
        assert!(has_option(&spec().forward_args(), "-o", "ExitOnForwardFailure=yes"));
    }

    #[test]
    fn a_dead_connection_is_noticed_rather_than_waited_on() {
        let args = spec().forward_args();
        assert!(has_option(&args, "-o", "ServerAliveInterval=15"));
        assert!(has_option(&args, "-o", "ServerAliveCountMax=3"));
    }

    #[test]
    fn the_ports_at_each_end_can_differ() {
        let mut spec = spec();
        spec.local_port = 9292;
        assert!(has_option(&spec.forward_args(), "-L", "127.0.0.1:9292:127.0.0.1:9191"));
        assert_eq!(spec.local_address().to_string(), "127.0.0.1:9292");
    }

    #[test]
    fn a_named_identity_is_used_on_its_own() {
        let mut spec = spec();
        spec.identity = Some(PathBuf::from("/home/rocky/.ssh/selfhost"));
        spec.ssh_port = Some(2222);
        let args = spec.forward_args();
        assert!(has_option(&args, "-i", "/home/rocky/.ssh/selfhost"));
        assert!(has_option(&args, "-o", "IdentitiesOnly=yes"), "{args:?}");
        assert!(has_option(&args, "-p", "2222"));
    }

    #[test]
    fn the_destination_comes_last_so_it_cannot_be_read_as_an_option() {
        assert_eq!(spec().forward_args().last().map(String::as_str), Some("rocky@server.example"));
    }

    #[test]
    fn the_token_is_read_over_the_same_connection_and_the_path_cannot_become_an_option() {
        let args = spec().token_args("data/admin.token");
        let separator = args.iter().position(|a| a == "--").expect("a separator");
        assert_eq!(args[separator + 1], "cat");
        assert_eq!(args[separator + 2], "data/admin.token");
        assert!(args.contains(&"rocky@server.example".to_owned()));
    }

    #[test]
    fn every_question_ssh_would_have_asked_becomes_an_instruction() {
        let cases = [
            ("Host key verification failed.", "ssh <server>"),
            ("rocky@server: Permission denied (publickey).", "ssh-add"),
            ("ssh: Could not resolve hostname serber: nodename nor servname provided", "resolve"),
            ("ssh: connect to host server port 22: Connection refused", "sshd"),
            ("bind [127.0.0.1]:9191: Address already in use", "--local-port"),
            ("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "host key"),
        ];
        for (complaint, expected) in cases {
            let advice = advice_for(complaint)
                .unwrap_or_else(|| panic!("no advice for {complaint:?}"));
            assert!(
                advice.to_ascii_lowercase().contains(&expected.to_ascii_lowercase()),
                "advice for {complaint:?} was {advice:?}"
            );
        }
    }

    #[test]
    fn an_unfamiliar_complaint_gets_no_invented_advice() {
        // A confident wrong instruction costs more than none: it sends somebody
        // to change a setting that was not the problem.
        assert!(advice_for("ssh: something nobody has seen before").is_none());
    }

    #[test]
    fn retries_back_off_and_then_stop_growing() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(9), MAX_RETRY, "a wrong key must not be retried forever faster");
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY, "and the shift must not overflow");
    }

    #[test]
    fn the_reported_complaint_is_the_first_thing_ssh_actually_said() {
        let kept = Arc::new(Mutex::new(vec![
            String::new(),
            "  Permission denied (publickey).".into(),
            "later noise".into(),
        ]));
        assert_eq!(first_complaint(&kept), "Permission denied (publickey).");
    }

    #[test]
    fn a_tunnel_that_said_nothing_still_reports_something() {
        assert_eq!(first_complaint(&Arc::new(Mutex::new(Vec::new()))), "the tunnel closed");
    }

    /// A stand-in for `ssh` that stays running until it is killed, and records
    /// its process id so a test can ask whether it is still alive.
    #[cfg(unix)]
    fn stub_ssh(name: &str) -> (PathBuf, PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("selfhost-tunnel-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let pid_file = dir.join("pid");
        let script = dir.join("stub-ssh");
        let mut file = std::fs::File::create(&script).expect("the stub");
        write!(file, "#!/bin/sh\necho $$ > {}\nexec sleep 60\n", pid_file.display())
            .expect("writing the stub");
        drop(file);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("making the stub executable");

        (script, pid_file)
    }

    /// Whether a process is still alive.
    #[cfg(unix)]
    fn alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .status()
            .expect("kill is available")
            .success()
    }

    #[cfg(unix)]
    #[test]
    fn closing_the_console_takes_the_tunnel_with_it() {
        // Otherwise the window closes and a forwarded port to somebody's server
        // is left open on this machine, with nothing on screen to say so.
        let (script, pid_file) = stub_ssh("cleanup");
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let running = Arc::new(AtomicBool::new(true));

        // A port nothing else on the machine is expected to hold: the stub does
        // not forward, so a port that happened to be busy would read as a tunnel
        // that came up.
        let mut spec = spec();
        spec.local_port = 9391;

        let thread = {
            let (shared, running) = (Arc::clone(&shared), Arc::clone(&running));
            std::thread::spawn(move || keep_open(&script.display().to_string(), spec, shared, running))
        };

        // Wait for the stub to have started and said which process it is.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = std::fs::read_to_string(&pid_file).expect("the stub wrote its pid");
        let pid = pid.trim().to_owned();
        assert!(alive(&pid), "the stub should be running");
        assert_eq!(
            shared.lock().expect("the snapshot lock").tunnel,
            Some(Tunnel::Opening),
            "the interface should say the tunnel is being opened"
        );

        running.store(false, Ordering::Relaxed);
        thread.join().expect("the tunnel thread should stop");

        // The kill is asynchronous at the operating system's end.
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(&pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(&pid), "the forwarding process outlived the console");

        let _ = std::fs::remove_dir_all(pid_file.parent().expect("the scratch directory"));
    }
}
