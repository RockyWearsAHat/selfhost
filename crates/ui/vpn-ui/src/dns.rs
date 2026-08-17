//! The split-DNS responder behind the console's scoped resolver.
//!
//! macOS is pointed at this responder by `/etc/resolver/admin.rockywearsahat.com`
//! (installed by the console action in [`crate::actions`]): while the app runs,
//! the console host resolves to loopback, so the portless console URL reaches
//! the tunnel's local end instead of the public box. Per `docs/SECURITY.md` the
//! listener is loopback-only — it binds `127.0.0.1`, answers exactly one name,
//! and REFUSES every other question, so it can never serve as an open resolver.

use crate::app::{Activity, CONSOLE_HOST};
use selfhost_dns::wire::{
    self, Query, Record, RecordData, RecordType, ResponseCode, ResponseFlags,
};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The loopback port the scoped resolver file points at.
pub const RESPONDER_PORT: u16 = 53535;

/// How long a receive waits before re-checking the shutdown switch.
const POLL: Duration = Duration::from_millis(500);

/// Seconds a resolver may cache the loopback answer.
const TTL: u32 = 60;

/// Starts the responder on `127.0.0.1:53535` for the app's lifetime.
///
/// It answers until `running` clears; the returned handle joins promptly after
/// that. A failed bind (usually another instance holding the port) is reported
/// through the shared [`Activity`] notice rather than killing the app — the
/// console stays reachable for the session however the name currently resolves.
pub fn spawn(
    running: Arc<AtomicBool>,
    activity: Arc<Mutex<Activity>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let socket = match UdpSocket::bind((Ipv4Addr::LOCALHOST, RESPONDER_PORT)) {
            Ok(socket) => socket,
            Err(error) => {
                notice(&activity, format!("split-DNS responder could not start: {error}"));
                return;
            }
        };
        if let Err(error) = socket.set_read_timeout(Some(POLL)) {
            notice(&activity, format!("split-DNS responder could not start: {error}"));
            return;
        }
        serve(&socket, &running);
    })
}

/// Answers queries on `socket` until `running` clears.
///
/// Expects a read timeout on the socket: each timeout re-checks the switch, so
/// shutdown never waits on a packet. Malformed packets are dropped and per-send
/// errors ignored — UDP owes no delivery, and a scoped stub answers or stays
/// silent.
fn serve(socket: &UdpSocket, running: &AtomicBool) {
    let mut buffer = [0_u8; 512];
    while running.load(Ordering::Relaxed) {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            // Timeout or a transient error: loop around and re-check the switch.
            Err(_) => continue,
        };
        if let Ok(query) = wire::decode_query(&buffer[..length]) {
            let _ = socket.send_to(&reply(&query), peer);
        }
    }
}

/// Builds the one answer this responder gives.
///
/// `A` for the console host is `127.0.0.1`; any other type for that host (AAAA
/// included) is an empty authoritative NOERROR, telling the resolver there is
/// no such record and to fall back to v4; every other name is REFUSED — this is
/// a one-name stub, not a resolver.
fn reply(query: &Query) -> Vec<u8> {
    if !query.name.eq_ignore_ascii_case(CONSOLE_HOST) {
        let flags = ResponseFlags { authoritative: false, truncated: false };
        return wire::encode_response(query, ResponseCode::Refused, flags, &[], &[], &[]);
    }
    let flags = ResponseFlags { authoritative: true, truncated: false };
    let answers = match query.record_type {
        RecordType::A => vec![Record {
            name: query.name.clone(),
            ttl: TTL,
            data: RecordData::A(Ipv4Addr::LOCALHOST),
        }],
        _ => Vec::new(),
    };
    wire::encode_response(query, ResponseCode::NoError, flags, &answers, &[], &[])
}

/// Leaves a failure notice for the footer, reading through a poisoned lock.
fn notice(activity: &Arc<Mutex<Activity>>, message: String) {
    let mut guard = match activity.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.notice = Some((false, message));
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_dns::wire::{decode_response, encode_query};

    /// Encodes a real query, runs it through [`reply`], and returns the bytes.
    fn ask(record_type: RecordType, name: &str) -> Vec<u8> {
        let bytes = encode_query(7, name, record_type).expect("query encodes");
        let query = wire::decode_query(&bytes).expect("query decodes");
        reply(&query)
    }

    #[test]
    fn a_query_answers_loopback() {
        let response = decode_response(&ask(RecordType::A, CONSOLE_HOST)).expect("reply decodes");
        assert!(matches!(response.code, ResponseCode::NoError));
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.first_a(), Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn aaaa_query_answers_empty_noerror() {
        let response =
            decode_response(&ask(RecordType::Aaaa, CONSOLE_HOST)).expect("reply decodes");
        assert!(matches!(response.code, ResponseCode::NoError));
        assert!(response.answers.is_empty());
    }

    #[test]
    fn foreign_name_is_refused() {
        let response = decode_response(&ask(RecordType::A, "example.com")).expect("reply decodes");
        assert!(matches!(response.code, ResponseCode::Refused));
        assert!(response.answers.is_empty());
    }

    #[test]
    fn serves_a_real_query_over_udp() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server binds");
        server.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout sets");
        let address = server.local_addr().expect("server has an address");
        let running = Arc::new(AtomicBool::new(true));
        let worker = {
            let running = Arc::clone(&running);
            std::thread::spawn(move || serve(&server, &running))
        };

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client binds");
        client.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout sets");
        let question = encode_query(99, CONSOLE_HOST, RecordType::A).expect("query encodes");
        client.send_to(&question, address).expect("query sends");

        let mut buffer = [0_u8; 512];
        let (length, _) = client.recv_from(&mut buffer).expect("reply arrives");
        // The reply echoes the query id and carries the loopback answer.
        assert_eq!(buffer[..2], 99_u16.to_be_bytes());
        let response = decode_response(&buffer[..length]).expect("reply decodes");
        assert_eq!(response.first_a(), Some(Ipv4Addr::LOCALHOST));

        running.store(false, Ordering::Relaxed);
        worker.join().expect("responder stops");
    }
}
