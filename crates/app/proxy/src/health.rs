//! The active health prober.
//!
//! One task per site, probing every instance on the configured interval. This is
//! what makes the word "balanced" mean something: without it the pool's health
//! flags never change and every instance looks alive forever, including the ones
//! that are not.
//!
//! A probe is a real HTTP request to the configured path, not a TCP connect. An
//! application that has accepted the socket but is deadlocked, out of database
//! connections, or still starting will complete a TCP handshake perfectly well
//! while being unable to serve anybody.

use crate::upstream::Pool;
use selfhost_config::Health;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

/// Outcome of a single probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// The instance answered with an acceptable status.
    Healthy,
    /// The instance answered, but not acceptably.
    BadStatus(u16),
    /// The instance could not be reached, or did not answer in time.
    Unreachable,
}

/// Sends one health probe and classifies the result.
///
/// `Connection: close` is sent because a probe should not occupy a keep-alive
/// slot on an instance that may already be under load.
pub async fn probe_once(address: &str, path: &str, timeout: Duration) -> Probe {
    let attempt = time::timeout(timeout, async {
        let mut stream = TcpStream::connect(address).await.ok()?;

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nUser-Agent: selfhost-health/1\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.ok()?;

        // The status line is all that is needed, so reading stops well before
        // the body. A large body from a misbehaving instance cannot stall this.
        let mut buffer = [0_u8; 256];
        let read = stream.read(&mut buffer).await.ok()?;
        Some(parse_status(&buffer[..read]))
    })
    .await;

    match attempt {
        Ok(Some(Some(status))) => {
            if (200..400).contains(&status) { Probe::Healthy } else { Probe::BadStatus(status) }
        }
        // Answered with something unparseable, or the connection closed early.
        Ok(Some(None)) => Probe::Unreachable,
        Ok(None) => Probe::Unreachable,
        Err(_) => Probe::Unreachable,
    }
}

/// Extracts the status code from the start of an HTTP response.
fn parse_status(bytes: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(bytes.get(..bytes.len().min(64))?).ok()?;
    let mut parts = text.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Runs the probe loop for one site until the process ends.
///
/// Instances are probed concurrently so that one unreachable instance, sitting
/// out its full timeout, does not delay the checks for its healthy siblings.
pub async fn run(site_name: String, pool: Arc<Pool>, health: Health) {
    if pool.is_empty() {
        return;
    }

    let interval = Duration::from_secs(health.interval_secs.max(1));
    let timeout = Duration::from_secs(health.timeout_secs.max(1));
    let mut ticker = time::interval(interval);
    // A missed tick must not cause a burst of catch-up probes.
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        let mut checks = tokio::task::JoinSet::new();
        for upstream in pool.upstreams() {
            let upstream = Arc::clone(upstream);
            let path = health.path.clone();
            let site = site_name.clone();
            let healthy_after = health.healthy_after;
            let unhealthy_after = health.unhealthy_after;

            checks.spawn(async move {
                match probe_once(upstream.address(), &path, timeout).await {
                    Probe::Healthy => {
                        if upstream.record_success(healthy_after) {
                            eprintln!("[health] {site}: {} recovered, back in rotation", upstream.address());
                        }
                    }
                    Probe::BadStatus(code) => {
                        if upstream.record_failure(unhealthy_after) {
                            eprintln!(
                                "[health] {site}: {} answered {code}, removed from rotation",
                                upstream.address()
                            );
                        }
                    }
                    Probe::Unreachable => {
                        if upstream.record_failure(unhealthy_after) {
                            eprintln!(
                                "[health] {site}: {} unreachable, removed from rotation",
                                upstream.address()
                            );
                        }
                    }
                }
            });
        }

        // Drain the round before the next tick. A probe that panics must not
        // abort the loop and leave every instance frozen at its last state.
        while let Some(result) = checks.join_next().await {
            if let Err(error) = result {
                eprintln!("[health] {site_name}: probe task failed: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn reads_the_status_code() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(parse_status(b"HTTP/1.1 404 Not Found\r\n"), Some(404));
    }

    #[test]
    fn refuses_to_read_a_status_from_non_http() {
        // An instance answering with something that is not HTTP is not healthy,
        // however willing it was to accept the socket.
        assert_eq!(parse_status(b"SSH-2.0-OpenSSH_9.0\r\n"), None);
        assert_eq!(parse_status(b""), None);
        assert_eq!(parse_status(b"garbage"), None);
    }

    #[tokio::test]
    async fn an_unreachable_instance_is_unreachable() {
        // Port 1 on loopback: nothing listens, and the connection is refused
        // immediately rather than timing out.
        let result = probe_once("127.0.0.1:1", "/", Duration::from_millis(500)).await;
        assert_eq!(result, Probe::Unreachable);
    }

    #[tokio::test]
    async fn a_healthy_instance_answers_2xx() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut scratch = [0_u8; 512];
            let _ = stream.read(&mut scratch).await;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        });

        assert_eq!(probe_once(&address, "/health", Duration::from_secs(2)).await, Probe::Healthy);
    }

    #[tokio::test]
    async fn an_error_status_is_not_healthy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut scratch = [0_u8; 512];
            let _ = stream.read(&mut scratch).await;
            let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        });

        assert_eq!(probe_once(&address, "/health", Duration::from_secs(2)).await, Probe::BadStatus(503));
    }

    #[tokio::test]
    async fn a_socket_that_accepts_but_never_answers_is_unreachable() {
        // The case a TCP-connect check gets wrong: the process is listening but
        // cannot serve. It must not count as healthy.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let result = probe_once(&address, "/health", Duration::from_millis(300)).await;
        assert_eq!(result, Probe::Unreachable);
    }
}
