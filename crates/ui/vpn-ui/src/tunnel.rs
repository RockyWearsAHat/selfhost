//! Bringing the Secure-VPN tunnel up and down, and reporting what it is doing.
//!
//! The tunnel itself is the project's Python client (`~/.securevpn/app/client.py`)
//! — this module owns its lifecycle, not its cryptography. [`Tunnel::connect`]
//! spawns it, a reader thread turns its output into a [`Link`] the window draws
//! from, and [`Tunnel::disconnect`] stops it. Nothing here blocks the window:
//! the child's output is read on its own thread and left in a mutex the view
//! reads once per frame, exactly as the console reads its poller.
//!
//! # Staying connected once the user has asked to be
//!
//! This is a connectable/disconnectable client, like an ordinary VPN toggle —
//! not an always-on background daemon — but between those two presses it must
//! not need a human to notice a drop and click Connect again. `wanted` records
//! which state the user last asked for; `connect()` sets it and spawns the
//! client once, and a supervising thread (mirroring
//! [`crate::tunnel`]'s counterpart in `crates/ui/console`, `keep_open`) watches
//! for the child exiting on its own and respawns it with the same
//! [exponential backoff](retry_delay) the console tunnel already uses, for as
//! long as `wanted` stays true. `disconnect()` clears `wanted` first, which is
//! exactly what tells that thread an exit is intentional rather than a drop to
//! recover from.

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The longest wait between attempts to bring a dropped tunnel back.
///
/// Same ceiling as the console's own tunnel (`crates/ui/console/src/tunnel.rs`)
/// — a dropped connection should feel like a blip, not a thing the user has to
/// notice and fix by hand, but a wrong key or an unreachable server should not
/// spend a machine's evening asking every second either.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// How long to wait before the next attempt, after `failures` in a row.
///
/// Doubles, and stops doubling at [`MAX_RETRY`].
fn retry_delay(failures: u32) -> Duration {
    let seconds = 1u64 << failures.min(6);
    Duration::from_secs(seconds).min(MAX_RETRY)
}

/// Where the client, its interpreter, and its keys live, and what it connects to.
///
/// One place so a move (a different endpoint, a relocated install) is one edit.
#[derive(Clone)]
pub struct Endpoint {
    /// The VPN server hostname the client dials (resolves to the box).
    pub server_host: String,
    /// The VPN server port.
    pub server_port: u16,
    /// The local port the client listens on for the browser.
    pub local_port: u16,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self { server_host: "rockywearsahat.com".into(), server_port: 8443, local_port: 8443 }
    }
}

/// Where the tunnel is in its life, as the window needs to say it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No tunnel: the client is not running.
    Off,
    /// The client has been launched and is dialling the server.
    Dialling,
    /// The mutual handshake succeeded; the server is proven authentic.
    Authenticated,
    /// The local listener is up — the console is reachable through the tunnel.
    Up,
    /// The client stopped or refused; the string is the reason to show.
    Failed(String),
}

impl Phase {
    /// Whether a tunnel is established well enough to carry the console.
    pub fn is_up(&self) -> bool {
        matches!(self, Phase::Up)
    }

    /// Whether the client is running but not yet carrying traffic.
    pub fn is_reaching(&self) -> bool {
        matches!(self, Phase::Dialling | Phase::Authenticated)
    }
}

/// What the tunnel last reported — the whole of what the window draws.
#[derive(Clone, Debug)]
pub struct Link {
    /// Where the tunnel is in its life.
    pub phase: Phase,
    /// When the link came up, for the connected-duration reading.
    pub since: Option<Instant>,
    /// Bytes sent through the tunnel, accumulated across its connections.
    pub tx: u64,
    /// Bytes received through the tunnel.
    pub rx: u64,
    /// The most recent line the client printed, for a diagnostic footer.
    pub last: String,
}

impl Default for Link {
    fn default() -> Self {
        Self { phase: Phase::Off, since: None, tx: 0, rx: 0, last: String::new() }
    }
}

/// The running (or not) tunnel: whether the user wants it up, and the
/// supervising thread that keeps it that way while they do.
pub struct Tunnel {
    endpoint: Endpoint,
    shared: Arc<Mutex<Link>>,
    /// What the user last asked for. `connect()` sets this before spawning the
    /// supervisor; `disconnect()` clears it first — that ordering is what lets
    /// the supervisor tell an intentional stop from a drop to recover from.
    wanted: Arc<AtomicBool>,
    supervisor: Option<JoinHandle<()>>,
    /// True if this instance spawned and supervises the tunnel.
    /// False if this instance adopted a pre-existing tunnel.
    managed: bool,
}

impl Tunnel {
    /// A tunnel that is not yet running, dialling `endpoint` when connected.
    ///
    /// Detects if a tunnel is already running; if so, creates an unmanaged tunnel
    /// that will not kill the process on Drop.
    pub fn new(endpoint: Endpoint) -> Self {
        let managed = !detect_existing_tunnel(&endpoint);
        Self {
            endpoint,
            shared: Arc::new(Mutex::new(Link::default())),
            wanted: Arc::new(AtomicBool::new(false)),
            supervisor: None,
            managed,
        }
    }

    /// A tunnel with no client but a preset report, for drawing the window's
    /// looks headless (see the `--render` mode).
    pub fn demo(endpoint: Endpoint, link: Link) -> Self {
        Self {
            endpoint,
            shared: Arc::new(Mutex::new(link)),
            wanted: Arc::new(AtomicBool::new(false)),
            supervisor: None,
            managed: true,
        }
    }

    /// A handle to the reported state, for the view to read each frame.
    pub fn link(&self) -> Link {
        match self.shared.lock() {
            Ok(link) => link.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Whether this instance is managing the tunnel (spawned it) or adopted a pre-existing one.
    pub fn is_managed(&self) -> bool {
        self.managed
    }

    /// Marks the tunnel wanted and starts the thread that keeps it up.
    ///
    /// Idempotent from the window's side: calling it while already running (or
    /// already trying to recover from a drop) does nothing, so a double-press
    /// cannot spawn a second client. Unlike the one-shot spawn this replaces,
    /// the tunnel does not simply report `Failed` and stop the moment the
    /// client exits on its own — the supervisor thread notices, waits out a
    /// backoff, and tries again for as long as `disconnect()` has not been
    /// called, exactly as an ordinary VPN client would.
    ///
    /// An *adopted* tunnel (`!self.managed`, [`Tunnel::new`] found the local
    /// port already answering) is the one exception: something else is
    /// already listening there, so spawning here would only ever collide with
    /// it — `EADDRINUSE`, immediately, on every retry, forever. There is
    /// nothing to supervise in that case; the port already answering is
    /// itself the evidence the tunnel is up.
    pub fn connect(&mut self) {
        if self.wanted.swap(true, Ordering::SeqCst) {
            return;
        }
        if !self.managed {
            set(&self.shared, |link| {
                *link = Link { phase: Phase::Up, since: Some(Instant::now()), ..Link::default() };
            });
            return;
        }
        set(&self.shared, |link| {
            *link = Link { phase: Phase::Dialling, ..Link::default() };
        });
        let endpoint = self.endpoint.clone();
        let shared = Arc::clone(&self.shared);
        let wanted = Arc::clone(&self.wanted);
        let managed = self.managed;
        self.supervisor = Some(
            std::thread::Builder::new()
                .name("selfhost-vpn-tunnel".into())
                .spawn(move || keep_open(&real_python(), &endpoint, &shared, &wanted, managed))
                .expect("the operating system refused to start a thread"),
        );
    }

    /// Stops the client and returns the tunnel to [`Phase::Off`].
    ///
    /// Clearing `wanted` first is what tells the supervisor thread this exit
    /// is intentional rather than a drop it should recover from.
    pub fn disconnect(&mut self) {
        self.wanted.store(false, Ordering::SeqCst);
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.join();
        }
        set(&self.shared, |link| {
            *link = Link::default();
        });
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Only kill the tunnel if we're the one managing it.
        // If we adopted a pre-existing tunnel, let it run.
        if self.managed {
            self.disconnect();
        } else {
            // For adopted tunnels, just clear the supervisor handle
            // without killing the process.
            self.wanted.store(false, Ordering::SeqCst);
            if let Some(supervisor) = self.supervisor.take() {
                let _ = supervisor.join();
            }
        }
    }
}

/// Brings the tunnel up, and brings it back whenever it drops on its own.
///
/// Mirrors `crates/ui/console/src/tunnel.rs`'s `keep_open`: loop while
/// `wanted` stays true, spawn the client, wait for it to either exit or for
/// `wanted` to go false, and on an unwanted exit back off before retrying.
/// A connection that made it to [`Phase::Up`] before dropping resets the
/// failure count — a laptop waking from sleep should retry quickly, not
/// inherit a long backoff from whatever came before it woke.
///
/// If `detach` is true, spawns the client in a new process session so it
/// survives this *process* dying unexpectedly (a crash, a force-quit) — not
/// so it survives an intentional `disconnect()`/Quit from within the app,
/// which always kills it regardless of `detach` (see the `!wanted` branch
/// below).
fn keep_open(python: &str, endpoint: &Endpoint, shared: &Arc<Mutex<Link>>, wanted: &Arc<AtomicBool>, detach: bool) {
    let mut failures = 0u32;

    while wanted.load(Ordering::SeqCst) {
        set(shared, |link| {
            *link = Link { phase: Phase::Dialling, ..Link::default() };
        });

        let mut child = match if detach {
            spawn_client_detached(python, endpoint)
        } else {
            spawn_client(python, endpoint)
        } {
            Ok(child) => child,
            Err(error) => {
                set(shared, |link| {
                    link.phase = Phase::Failed(format!("could not start the client: {error}"));
                });
                failures = failures.saturating_add(1);
                sleep_while_wanted(retry_delay(failures), wanted);
                continue;
            }
        };

        let alive = Arc::new(AtomicBool::new(true));
        let mut handles = Vec::new();
        for stream in [child.stdout.take().map(Reader::Out), child.stderr.take().map(Reader::Err)] {
            let Some(reader) = stream else { continue };
            let reader_shared = Arc::clone(shared);
            let reader_alive = Arc::clone(&alive);
            handles.push(std::thread::spawn(move || read_output(reader, reader_shared, reader_alive)));
        }

        // Wait for the child to exit on its own, or for the user to disconnect.
        loop {
            if !wanted.load(Ordering::SeqCst) {
                alive.store(false, Ordering::SeqCst);
                // Always kill on an intentional disconnect, detached or not.
                //
                // `detach` (a new process session via `setsid`) exists so the
                // client survives this *process* dying unexpectedly — a crash,
                // a force-quit from Activity Monitor — not so it survives a
                // graceful disconnect the app asked for on purpose. Those are
                // different questions, and conflating them here was a real,
                // severe bug: for a detached (managed) tunnel, this used to
                // `drop(child)` — abandoning the handle without killing the
                // process — and then fall through to `handle.join()` on the
                // stdout/stderr reader threads below, which block on their
                // next `read()` until the pipe's write end closes. That write
                // end is held by the client process, which this had just
                // decided *not* to kill — so those reads had nothing to wake
                // them until the still-running client happened to print
                // another line on its own, which could be seconds or minutes
                // away. That is the actual mechanism behind "Disconnect is
                // laggy" and "Quit is laggy": both call this same path, and
                // both were blocking the calling thread on a join that had no
                // deterministic end. Killing the child first, unconditionally,
                // is what makes the reader threads see EOF right away.
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            match child.try_wait() {
                Ok(Some(_status)) => {
                    alive.store(false, Ordering::SeqCst);
                    break;
                }
                // 20ms, not 200ms: this is also the poll granularity for
                // noticing `disconnect()` was called (the `!wanted` check
                // above runs at the top of every one of these iterations),
                // and `Tunnel::disconnect()` blocks its caller — the UI
                // thread — on this same loop's supervisor thread exiting.
                // 200ms of that was a real, felt part of "Disconnect is
                // laggy"; a cheap `try_wait()` syscall 50 times a second
                // while a client is actively running costs nothing worth
                // trading for a fifth of a second of a frozen button.
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    alive.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
        for handle in handles {
            let _ = handle.join();
        }

        if !wanted.load(Ordering::SeqCst) {
            return;
        }

        // The client exited without being asked to. Reset the backoff if it
        // had gotten as far as carrying traffic — that was a real connection
        // that dropped, not a persistent reason to fail — otherwise count it
        // as another failure in a row.
        let reached_up = matches!(
            shared.lock().map(|link| link.phase.clone()).unwrap_or(Phase::Off),
            Phase::Up
        );
        failures = if reached_up { 0 } else { failures.saturating_add(1) };
        set(shared, |link| {
            if !matches!(link.phase, Phase::Failed(_)) {
                link.phase = Phase::Failed("the tunnel dropped".into());
            }
            link.since = None;
        });
        sleep_while_wanted(retry_delay(failures), wanted);
    }
}

/// Sleeps for `duration`, waking early if the user disconnects.
///
/// Coarse polling rather than a condvar: this only ever waits a handful of
/// seconds, and the tunnel's other threads are already built the same way.
/// 20ms rather than 200ms for the same reason as the other poll in this
/// file: `Tunnel::disconnect()`/`Cancel` blocks its caller (the UI thread) on
/// this loop noticing `wanted` went false, so the poll granularity here is
/// directly how laggy that button feels.
fn sleep_while_wanted(duration: Duration, wanted: &Arc<AtomicBool>) {
    let deadline = Instant::now() + duration;
    while wanted.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20).min(deadline - Instant::now()));
    }
}

/// Where the real client, its interpreter, and its keys live.
///
/// Named apart from [`spawn_client`] so a test can substitute a stub in
/// `python`'s place without touching `HOME` or any real Secure-VPN install.
fn real_python() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.securevpn/venv/bin/python")
}

/// Detects whether a tunnel is already running by checking if the local port is listening.
///
/// Returns `true` if a connection to `127.0.0.1:{endpoint.local_port}` succeeds,
/// indicating a tunnel is already active. This avoids spawning a second client that
/// would fail with EADDRINUSE.
fn detect_existing_tunnel(endpoint: &Endpoint) -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    match TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", endpoint.local_port).parse().unwrap(),
        Duration::from_millis(100),
    ) {
        Ok(stream) => {
            let _ = stream;
            true
        }
        Err(_) => false,
    }
}

/// Launches the Secure-VPN client for `endpoint` via `python`, wired for
/// [`read_output`].
fn spawn_client(python: &str, endpoint: &Endpoint) -> std::io::Result<Child> {
    let home = std::env::var("HOME").unwrap_or_default();
    let client = format!("{home}/.securevpn/app/client.py");
    let keydir = format!("{home}/.securevpn/keys");

    Command::new(python)
        .arg("-u")
        .arg(client)
        .arg(&endpoint.server_host)
        .arg("--port")
        .arg(endpoint.server_port.to_string())
        .arg("--local-host")
        .arg("127.0.0.1")
        .arg("--local-port")
        .arg(endpoint.local_port.to_string())
        .arg("--identity")
        .arg("client")
        .arg("--peer")
        .arg("server")
        .env("SECUREVPN_KEY_DIR", keydir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Spawns the Secure-VPN client in a new process session so it survives the parent's exit.
///
/// On Unix/macOS, this calls `setsid()` in a `pre_exec()` closure to make the child
/// the leader of its own process group. This detaches it from the parent's session,
/// ensuring the child survives when the parent exits.
#[allow(unsafe_code)]
fn spawn_client_detached(python: &str, endpoint: &Endpoint) -> std::io::Result<Child> {
    use nix::unistd::setsid;
    use std::io;

    let home = std::env::var("HOME").unwrap_or_default();
    let client = format!("{home}/.securevpn/app/client.py");
    let keydir = format!("{home}/.securevpn/keys");

    // SAFETY: pre_exec is safe to call here; the closure only executes in the
    // child process after fork() but before exec(), so no other threads interfere.
    unsafe {
        Ok(Command::new(python)
            .arg("-u")
            .arg(client)
            .arg(&endpoint.server_host)
            .arg("--port")
            .arg(endpoint.server_port.to_string())
            .arg("--local-host")
            .arg("127.0.0.1")
            .arg("--local-port")
            .arg(endpoint.local_port.to_string())
            .arg("--identity")
            .arg("client")
            .arg("--peer")
            .arg("server")
            .env("SECUREVPN_KEY_DIR", keydir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Detach from parent's process group
            .pre_exec(|| setsid().map(|_| ()).map_err(|e| io::Error::from_raw_os_error(e as i32)))
            .spawn()?)
    }
}

/// Which of the child's streams a line came from.
enum Reader {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

/// Reads one stream to end, folding each line into the shared [`Link`].
fn read_output(reader: Reader, shared: Arc<Mutex<Link>>, alive: Arc<AtomicBool>) {
    let lines: Box<dyn BufRead> = match reader {
        Reader::Out(out) => Box::new(BufReader::new(out)),
        Reader::Err(err) => Box::new(BufReader::new(err)),
    };
    for line in lines.lines() {
        if !alive.load(Ordering::Relaxed) {
            return;
        }
        let Ok(line) = line else { break };
        set(&shared, |link| interpret(&line, link));
    }
    // The stream closed. If we did not ask for that (a deliberate disconnect
    // clears `alive` first), the client exited on its own — a dropped server or
    // a crash — and the window must stop claiming a tunnel that is gone. A
    // specific failure already recorded from a handshake line is left in place.
    if alive.load(Ordering::Relaxed) {
        set(&shared, |link| {
            if link.phase.is_up() || link.phase.is_reaching() {
                link.phase = Phase::Failed("the tunnel dropped".into());
                link.since = None;
            }
        });
    }
}

/// Turns one line of client output into a change to the link.
///
/// Pure so the marker table is asserted without spawning anything.
pub(crate) fn interpret(line: &str, link: &mut Link) {
    link.last = line.trim().to_string();
    if line.contains("server authenticated") {
        link.phase = Phase::Authenticated;
    } else if line.contains("Local SSH proxy listening") || line.contains("tunnel active") {
        if !link.phase.is_up() {
            link.phase = Phase::Up;
            link.since = Some(Instant::now());
        }
    } else if line.contains("Connecting to VPN server") {
        if !link.phase.is_up() {
            link.phase = Phase::Dialling;
        }
    } else if line.contains("Handshake error")
        || line.contains("Handshake failed")
        || line.contains("Connection failed")
        || line.contains("Connection refused")
    {
        link.phase = Phase::Failed(link.last.clone());
        link.since = None;
    } else if let Some((tx, rx)) = parse_closed(line) {
        link.tx += tx;
        link.rx += rx;
    }
}

/// Pulls the byte counts out of a "Connection closed (TX: n bytes, RX: n bytes)".
///
/// Returns `None` for any other line, so a normal log line adds nothing.
pub(crate) fn parse_closed(line: &str) -> Option<(u64, u64)> {
    let tx = after(line, "TX: ")?;
    let rx = after(line, "RX: ")?;
    Some((tx, rx))
}

/// The integer immediately after `marker`, if the line has one there.
fn after(line: &str, marker: &str) -> Option<u64> {
    let rest = line.split_once(marker)?.1;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Reads-through a poisoned lock: a stale reading beats a blank window.
fn set(shared: &Arc<Mutex<Link>>, change: impl FnOnce(&mut Link)) {
    match shared.lock() {
        Ok(mut link) => change(&mut link),
        Err(poisoned) => change(&mut poisoned.into_inner()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_markers_drive_the_phase() {
        let mut link = Link::default();
        interpret("Connecting to VPN server at 192.168.1.8:8443...", &mut link);
        assert_eq!(link.phase, Phase::Dialling);
        interpret("✓ Handshake complete, server authenticated, secure tunnel ready", &mut link);
        assert_eq!(link.phase, Phase::Authenticated);
        interpret("✓ Local SSH proxy listening on 127.0.0.1:8443", &mut link);
        assert_eq!(link.phase, Phase::Up);
        assert!(link.since.is_some());
    }

    #[test]
    fn a_failure_line_becomes_a_failed_phase_with_its_reason() {
        let mut link = Link::default();
        interpret("Handshake error: Connection closed during handshake", &mut link);
        assert!(matches!(link.phase, Phase::Failed(_)));
        assert!(link.since.is_none());
    }

    #[test]
    fn throughput_accumulates_from_closed_connections() {
        let mut link = Link::default();
        interpret("[127.0.0.1:5000] Connection closed (TX: 50134 bytes, RX: 78 bytes)", &mut link);
        interpret("[127.0.0.1:5001] Connection closed (TX: 12000 bytes, RX: 22 bytes)", &mut link);
        assert_eq!(link.tx, 62134);
        assert_eq!(link.rx, 100);
    }

    #[test]
    fn an_ordinary_line_is_not_a_closed_connection() {
        assert_eq!(parse_closed("✓ Server identity loaded"), None);
    }

    #[test]
    fn coming_up_does_not_get_downgraded_by_a_later_dialling_line() {
        let mut link = Link::default();
        interpret("✓ Local SSH proxy listening on 127.0.0.1:8443", &mut link);
        let when = link.since;
        interpret("Connecting to VPN server at ...", &mut link);
        assert_eq!(link.phase, Phase::Up);
        assert_eq!(link.since, when, "the up-time must not reset");
    }

    #[test]
    fn retries_back_off_and_then_stop_growing() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(9), MAX_RETRY, "a wrong key must not be retried forever faster");
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY, "and the shift must not overflow");
    }

    /// A stand-in for the Python client that counts how many times it was
    /// started (one line per launch in `runs`), prints the marker line
    /// [`interpret`] treats as "up", then exits immediately — a stand-in for a
    /// tunnel that connects and then drops on its own.
    #[cfg(unix)]
    fn stub_client_that_drops(name: &str) -> (String, std::path::PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("selfhost-vpn-tunnel-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let runs = dir.join("runs");
        std::fs::write(&runs, "").expect("seed the run count");
        let script = dir.join("stub-python");
        let mut file = std::fs::File::create(&script).expect("the stub");
        write!(
            file,
            "#!/bin/sh\necho x >> {}\necho '\\xe2\\x9c\\x93 Local SSH proxy listening on 127.0.0.1:1'\nexit 0\n",
            runs.display()
        )
        .expect("writing the stub");
        drop(file);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("making the stub executable");

        (script.display().to_string(), runs)
    }

    /// A stand-in for the Python client that stays running until killed, so a
    /// test can assert `disconnect()` actually stops it rather than leaving a
    /// process (and a forwarded port) behind.
    #[cfg(unix)]
    fn stub_client_that_stays(name: &str) -> (String, std::path::PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("selfhost-vpn-tunnel-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let pid_file = dir.join("pid");
        let script = dir.join("stub-python");
        let mut file = std::fs::File::create(&script).expect("the stub");
        write!(
            file,
            "#!/bin/sh\necho $$ > {}\necho '\\xe2\\x9c\\x93 Local SSH proxy listening on 127.0.0.1:1'\nexec sleep 60\n",
            pid_file.display()
        )
        .expect("writing the stub");
        drop(file);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("making the stub executable");

        (script.display().to_string(), pid_file)
    }

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
    fn a_client_that_drops_on_its_own_is_relaunched_without_being_asked() {
        // This is the whole point of the supervisor: the old one-shot
        // Tunnel::connect() would report Failed once and stop. A tunnel that
        // behaves like an actual VPN must not need a human to notice and press
        // Connect again for an ordinary drop.
        let (python, runs) = stub_client_that_drops("relaunch");
        let shared = Arc::new(Mutex::new(Link::default()));
        let wanted = Arc::new(AtomicBool::new(true));
        let endpoint = Endpoint::default();

        let thread = {
            let (shared, wanted) = (Arc::clone(&shared), Arc::clone(&wanted));
            std::thread::spawn(move || keep_open(&python, &endpoint, &shared, &wanted, false))
        };

        // Each run is near-instant (backoff after the first failure would be at
        // least a second), so a couple of real seconds is enough to see several.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut runs_seen = 0usize;
        while Instant::now() < deadline {
            runs_seen = std::fs::read_to_string(&runs).map(|s| s.lines().count()).unwrap_or(0);
            if runs_seen >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(runs_seen >= 2, "the client should have been relaunched at least once, saw {runs_seen}");

        wanted.store(false, Ordering::SeqCst);
        thread.join().expect("the supervisor thread should stop");
        let _ = std::fs::remove_dir_all(runs.parent().expect("the scratch directory"));
    }

    #[cfg(unix)]
    #[test]
    fn disconnecting_stops_the_client_instead_of_relaunching_it() {
        let (python, pid_file) = stub_client_that_stays("disconnect");
        let shared = Arc::new(Mutex::new(Link::default()));
        let wanted = Arc::new(AtomicBool::new(true));
        let endpoint = Endpoint::default();

        let thread = {
            let (shared, wanted) = (Arc::clone(&shared), Arc::clone(&wanted));
            std::thread::spawn(move || keep_open(&python, &endpoint, &shared, &wanted, false))
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = std::fs::read_to_string(&pid_file).expect("the stub wrote its pid");
        let pid = pid.trim().to_owned();
        assert!(alive(&pid), "the stub should be running");

        wanted.store(false, Ordering::SeqCst);
        thread.join().expect("the supervisor thread should stop");

        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(&pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(&pid), "disconnect must not leave the client running");

        let _ = std::fs::remove_dir_all(pid_file.parent().expect("the scratch directory"));
    }

    /// The regression this session's actual bug was: a *detached* (managed)
    /// client used to be left running on disconnect (`drop(child)` instead of
    /// killing it), which then made the reader-thread `join()`s below block
    /// on a pipe that would never see EOF — the real mechanism behind
    /// "Disconnect is laggy" and "Quit is laggy", both of which call this
    /// same path. Runs the whole disconnect on a timeout: without the fix,
    /// this test does not merely assert a wrong answer, it hangs.
    #[cfg(unix)]
    #[test]
    fn disconnecting_a_detached_client_still_kills_it_promptly() {
        let (python, pid_file) = stub_client_that_stays("disconnect-detached");
        let shared = Arc::new(Mutex::new(Link::default()));
        let wanted = Arc::new(AtomicBool::new(true));
        let endpoint = Endpoint::default();

        let thread = {
            let (shared, wanted) = (Arc::clone(&shared), Arc::clone(&wanted));
            // `detach: true` — the managed/production path, not the `false`
            // every other test in this file uses.
            std::thread::spawn(move || keep_open(&python, &endpoint, &shared, &wanted, true))
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = std::fs::read_to_string(&pid_file).expect("the stub wrote its pid");
        let pid = pid.trim().to_owned();
        assert!(alive(&pid), "the stub should be running");

        let disconnect_started = Instant::now();
        wanted.store(false, Ordering::SeqCst);
        thread.join().expect("the supervisor thread should stop");
        assert!(
            disconnect_started.elapsed() < Duration::from_secs(2),
            "disconnecting a detached client took {:?} — it should be near-instant, \
             not bounded only by the client happening to print another line",
            disconnect_started.elapsed()
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(&pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(&pid), "disconnecting a detached client must still kill it");

        let _ = std::fs::remove_dir_all(pid_file.parent().expect("the scratch directory"));
    }
}
