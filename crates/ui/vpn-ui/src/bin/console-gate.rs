//! The console gate: the loopback bridge that gives the admin console its
//! portless URL.
//!
//! It listens on `127.0.0.1:443` — the *specific* loopback address, beside any
//! wildcard `*:443` the reverse proxy holds (BSD delivers a loopback connect to
//! the most specific bound socket) — and splices each connection, byte for
//! byte, to the Secure-VPN tunnel's local end at `127.0.0.1:8443`. TLS passes
//! through untouched, so the certificate the browser verifies is the far end's
//! real one. With the scoped resolver mapping `admin.rockywearsahat.com` to
//! loopback, `https://admin.rockywearsahat.com/` lands here and comes out of
//! the tunnel.
//!
//! Security posture (docs/SECURITY.md, VPN-04): loopback-only by construction —
//! the bind address is the loopback literal and every accepted peer is checked
//! again before a byte moves. No configuration, no state, no secrets, no
//! environment. It runs as the `com.selfhost.console-gate` LaunchDaemon,
//! installed once by the SelfHost VPN app (`crates/vpn-ui/src/actions.rs`).
//! While the tunnel is down its local end refuses, and the gate drops the
//! client at once — nothing is served from this process itself.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::time::Duration;

/// Where the gate listens: the console host's loopback address, HTTPS port.
const GATE: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443));

/// The Secure-VPN client's local end, the far side of every splice.
const TUNNEL: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443));

/// How long a connect to the tunnel may take before the client is dropped.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    // std's TcpListener sets SO_REUSEADDR on Unix, so the specific loopback
    // bind coexists with the proxy's wildcard *:443. If this exact bind is
    // refused anyway, say so once and exit non-zero: launchd logs the line
    // (StandardErrorPath) and the installer's verify step reports it — the
    // gate must never fall back to a different address.
    let listener = match TcpListener::bind(GATE) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("console-gate: cannot bind {GATE}: {error}");
            std::process::exit(1);
        }
    };
    // A failed accept means the peer vanished between SYN and accept;
    // there is nothing to serve and nothing useful to log per-connection.
    for client in listener.incoming().flatten() {
        std::thread::spawn(move || splice(client));
    }
}

/// Splices one accepted connection to the tunnel, both directions, until EOF.
///
/// Non-loopback peers are dropped unanswered — the bind alone makes them
/// impossible, this is defence in depth. A tunnel that does not answer (the
/// VPN is down) drops the client immediately, which the browser shows as a
/// refused connection rather than a hang.
fn splice(client: TcpStream) {
    if !client.peer_addr().map(|peer| peer.ip().is_loopback()).unwrap_or(false) {
        return;
    }
    let Ok(tunnel) = TcpStream::connect_timeout(&TUNNEL, CONNECT_TIMEOUT) else {
        return;
    };
    let (Ok(client_read), Ok(tunnel_read)) = (client.try_clone(), tunnel.try_clone()) else {
        // Cloning a live socket only fails when the process is out of
        // descriptors; dropping both ends is the whole recovery.
        return;
    };
    std::thread::spawn(move || pump(client_read, tunnel));
    pump(tunnel_read, client);
}

/// Copies `from` into `to` until EOF or error, then half-closes `to`.
///
/// The half-close lets the opposite direction drain before the sockets drop,
/// so each side ends its stream exactly as it would over a direct connection.
/// A copy error is a torn connection — both directions end, nothing to report.
fn pump(mut from: TcpStream, mut to: TcpStream) {
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}
