//! Whether a relay answers the first step of its handshake — not merely
//! whether something holds its port.
//!
//! An open port proves only that the kernel accepted a connection. A tunnel
//! whose event loop is wedged still accepts (the backlog does that for it), and
//! so does any other program that happens to hold the port: a stray copy of the
//! relay started by an old scheduled task, or sshd itself. Each of those looks
//! "up" to a connect and drops every real session right after connect.
//!
//! So the probe speaks the relay's protocol: one length-framed `CLIENT_HELLO`
//! header (type `0x01`, version `0x02`) carrying no keys. The vetted server reads
//! the frame, judges it, refuses it (it names no enrolled device) and closes the
//! connection without sending a byte. That refusal is the answer: it proves the
//! process accepted, read a frame and ran its handshake code within the deadline.
//! A silent socket, a refused connect, or a peer that *speaks first* (sshd sends
//! its banner, an HTTP server its status line) is not the relay.
//!
//! What it does not prove, said plainly: that an enrolled device would be
//! admitted. That needs a device key in the roster and an answer from the
//! account check, which is identity, not liveness, and is not restarted away.
//! No cryptography is done here; the frame is the protocol's public header.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long the relay has to answer, connect included.
///
/// Generous on purpose: on a loaded box the console relay has been measured
/// taking 3.7 s to refuse a hello, and a probe that restarts a slow-but-working
/// relay cuts every live session for nothing.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The probe's one frame: a little-endian length of 2, then `CLIENT_HELLO`
/// (`0x01`) at protocol version `0x02` — Secure-VPN's `frame_packet` around the
/// first two bytes every hello starts with.
pub const HELLO_FRAME: [u8; 6] = [2, 0, 0, 0, 0x01, 0x02];

/// Why a relay did not answer like a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFailure {
    /// Nothing accepted the connection: the port is closed or unreachable.
    Unreachable(String),
    /// Something accepted and then said nothing within [`PROBE_TIMEOUT`]: a
    /// wedged relay, or a program that waits for a protocol it never gets.
    Silent,
    /// Something answered with bytes before any handshake: not the relay.
    NotTheRelay {
        /// The first bytes it sent, as text where printable, for the log.
        said: String,
    },
}

impl fmt::Display for ProbeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(error) => write!(formatter, "nothing accepts on the port ({error})"),
            Self::Silent => write!(
                formatter,
                "the port accepts but never answers a hello within {}s",
                PROBE_TIMEOUT.as_secs()
            ),
            Self::NotTheRelay { said } => write!(
                formatter,
                "the port is held by something that is not the relay; it said \"{said}\""
            ),
        }
    }
}

/// Sends the hello frame to a relay's own port over loopback and judges the
/// answer within `timeout`.
///
/// `listen` is the relay's configured socket. A wildcard host is probed on the
/// loopback address of the same family, so the probe never leaves the machine.
pub async fn hello(listen: SocketAddr, timeout: Duration) -> Result<(), ProbeFailure> {
    match tokio::time::timeout(timeout, exchange(loopback(listen))).await {
        Ok(outcome) => outcome,
        Err(_) => Err(ProbeFailure::Silent),
    }
}

/// Connect, send the frame, and read until the relay's verdict.
async fn exchange(target: SocketAddr) -> Result<(), ProbeFailure> {
    let mut stream = TcpStream::connect(target)
        .await
        .map_err(|error| ProbeFailure::Unreachable(error.to_string()))?;
    // A peer that closed before the frame landed has refused it just the same;
    // only the read below decides.
    let _ = stream.write_all(&HELLO_FRAME).await;
    let mut first = [0u8; 64];
    match stream.read(&mut first).await {
        Ok(0) => Ok(()),
        Ok(read) => Err(ProbeFailure::NotTheRelay { said: printable(&first[..read]) }),
        // A reset is the relay closing on a refused hello with bytes in flight.
        Err(_) => Ok(()),
    }
}

/// The address a probe dials for a configured listening socket.
fn loopback(listen: SocketAddr) -> SocketAddr {
    let host = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(host, listen.port())
}

/// Bytes as log text: printable ASCII kept, the rest as `.`.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' })
        .collect::<String>()
        .trim_end_matches('.')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const QUICK: Duration = Duration::from_millis(500);

    async fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        (listener, address)
    }

    #[tokio::test]
    async fn a_relay_that_reads_the_hello_and_refuses_it_is_answering() {
        let (listener, address) = listener().await;
        let relay = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut frame = [0u8; 6];
            socket.read_exact(&mut frame).await.expect("the hello frame");
            frame
        });
        assert_eq!(hello(address, QUICK).await, Ok(()));
        assert_eq!(relay.await.expect("relay"), HELLO_FRAME, "the probe sends the hello header");
    }

    #[tokio::test]
    async fn a_port_that_is_open_but_never_answers_fails_the_check() {
        let (listener, address) = listener().await;
        let wedged = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        });
        assert_eq!(hello(address, QUICK).await, Err(ProbeFailure::Silent));
        wedged.abort();
    }

    #[tokio::test]
    async fn a_port_held_by_something_that_speaks_first_is_not_the_relay() {
        let (listener, address) = listener().await;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            socket.write_all(b"SSH-2.0-OpenSSH_for_Windows_10.0\r\n").await.expect("banner");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            hello(address, QUICK).await,
            Err(ProbeFailure::NotTheRelay { said: "SSH-2.0-OpenSSH_for_Windows_10.0".into() })
        );
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let (listener, address) = listener().await;
        drop(listener);
        // Windows retries a refused connect for about a second before it says
        // so, longer than QUICK; the probe's own deadline covers that.
        assert!(matches!(hello(address, PROBE_TIMEOUT).await, Err(ProbeFailure::Unreachable(_))));
    }

    #[test]
    fn a_wildcard_listen_is_probed_on_loopback_of_its_own_family() {
        assert_eq!(loopback("0.0.0.0:8444".parse().unwrap()), "127.0.0.1:8444".parse().unwrap());
        assert_eq!(loopback("[::]:8444".parse().unwrap()), "[::1]:8444".parse().unwrap());
        assert_eq!(loopback("127.0.0.1:8443".parse().unwrap()), "127.0.0.1:8443".parse().unwrap());
    }
}
