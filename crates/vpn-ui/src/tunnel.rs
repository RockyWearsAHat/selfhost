//! Bringing the Secure-VPN tunnel up and down, and reporting what it is doing.
//!
//! The tunnel itself is the project's Python client (`~/.securevpn/app/client.py`)
//! — this module owns its lifecycle, not its cryptography. [`Tunnel::connect`]
//! spawns it, a reader thread turns its output into a [`Link`] the window draws
//! from, and [`Tunnel::disconnect`] stops it. Nothing here blocks the window:
//! the child's output is read on its own thread and left in a mutex the view
//! reads once per frame, exactly as the console reads its poller.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// Where the client, its interpreter, and its keys live, and what it connects to.
///
/// One place so a move (a different endpoint, a relocated install) is one edit.
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

/// The running (or not) tunnel: the child process and the state it reports.
pub struct Tunnel {
    endpoint: Endpoint,
    shared: Arc<Mutex<Link>>,
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
    alive: Arc<AtomicBool>,
}

impl Tunnel {
    /// A tunnel that is not yet running, dialling `endpoint` when connected.
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            shared: Arc::new(Mutex::new(Link::default())),
            child: None,
            reader: None,
            alive: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A tunnel with no client but a preset report, for drawing the window's
    /// looks headless (see the `--render` mode).
    pub fn demo(endpoint: Endpoint, link: Link) -> Self {
        Self {
            endpoint,
            shared: Arc::new(Mutex::new(link)),
            child: None,
            reader: None,
            alive: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle to the reported state, for the view to read each frame.
    pub fn link(&self) -> Link {
        match self.shared.lock() {
            Ok(link) => link.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Launches the client and starts reading what it says.
    ///
    /// Idempotent from the window's side: calling it while already running does
    /// nothing, so a double-press cannot spawn a second client.
    pub fn connect(&mut self) {
        if self.child.is_some() {
            return;
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let python = format!("{home}/.securevpn/venv/bin/python");
        let client = format!("{home}/.securevpn/app/client.py");
        let keydir = format!("{home}/.securevpn/keys");

        let mut command = Command::new(python);
        command
            .arg("-u")
            .arg(client)
            .arg(&self.endpoint.server_host)
            .arg("--port")
            .arg(self.endpoint.server_port.to_string())
            .arg("--local-host")
            .arg("127.0.0.1")
            .arg("--local-port")
            .arg(self.endpoint.local_port.to_string())
            .arg("--identity")
            .arg("client")
            .arg("--peer")
            .arg("server")
            .env("SECUREVPN_KEY_DIR", keydir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        set(&self.shared, |link| {
            *link = Link { phase: Phase::Dialling, ..Link::default() };
        });

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                set(&self.shared, |link| {
                    link.phase = Phase::Failed(format!("could not start the client: {error}"));
                });
                return;
            }
        };

        // Read stdout and stderr on one thread each, merged into the same Link.
        self.alive.store(true, Ordering::Relaxed);
        let mut handles = Vec::new();
        for stream in [child.stdout.take().map(Reader::Out), child.stderr.take().map(Reader::Err)] {
            let Some(reader) = stream else { continue };
            let shared = Arc::clone(&self.shared);
            let alive = Arc::clone(&self.alive);
            handles.push(std::thread::spawn(move || read_output(reader, shared, alive)));
        }
        // One join handle is enough to wait on; keep the first, detach the rest.
        self.reader = handles.into_iter().next();
        self.child = Some(child);
    }

    /// Stops the client and returns the tunnel to [`Phase::Off`].
    pub fn disconnect(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        set(&self.shared, |link| {
            *link = Link::default();
        });
    }

}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.disconnect();
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
}
