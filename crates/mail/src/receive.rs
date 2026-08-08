//! The inbound SMTP receiver — port 25, the mail exchanger.
//!
//! This is the socket-facing half of [`crate::smtp`]. The state machine there
//! decides *what* every command means and, crucially, refuses to relay for
//! strangers; this file only moves bytes: it reads a line, hands it to the
//! session, writes the reply back, and on `DATA` reads the body and stores it.
//! The relay defence is never re-implemented here — it lives once, in the
//! session's `RCPT` check, exactly as the contract demands (seam N-1).
//!
//! What the receiver adds on top of the pure session, because a state machine
//! with no filesystem cannot know it:
//!
//! - **Mailbox existence.** A recipient can be in one of our domains yet name no
//!   real mailbox. Such mail is refused at `RCPT` with `550`, not accepted and
//!   black-holed.
//! - **Message size.** The declared `SIZE` is checked by the session up front;
//!   here the *actual* bytes are counted during `DATA` and an over-limit
//!   message is refused even when it lied about its size.
//! - **STARTTLS.** The plaintext socket is upgraded in place using the same
//!   certificate material the proxy serves.
//! - **Greylisting (optional).** An unknown (ip, sender, recipient) triple is
//!   deferred once with a `4xx`; legitimate senders retry and are then let
//!   through, while much bulk spam never comes back.

use crate::message::Message;
use crate::smtp::{Action, Policy, Reply, Session};
use crate::store::Maildir;
use crate::Path as MailPath;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Everything a receiver connection needs, assembled once by the daemon.
///
/// This is the receiver's projection of the contract's `MailRuntime`: it carries
/// only what inbound delivery uses. The submission and outbound halves add the
/// `Authenticator` and `OutboundQueue` around the same `policy`, `store`, and
/// `tls`.
#[derive(Clone)]
pub struct Receiver {
    /// How the session answers — hostname, local domains, size limit. For the
    /// inbound face `allow_auth_without_tls` is false and no credentials are
    /// accepted; a mail exchanger authenticates nobody.
    pub policy: Policy,
    /// The shared Maildir every accepted message is written to.
    pub store: Maildir,
    /// TLS material for `STARTTLS`, or `None` to run cleartext-only (tests, or a
    /// host with no certificate yet). Must agree with `policy.tls_available`.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Greylist state, or `None` to accept first contact immediately.
    pub greylist: Option<Greylist>,
}

impl Receiver {
    /// A receiver with greylisting off and the given TLS material.
    pub fn new(policy: Policy, store: Maildir, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        Self { policy, store, tls, greylist: None }
    }
}

/// Accepts inbound SMTP connections forever, one task per connection.
///
/// A failed connection is logged-by-return and dropped; it never brings down the
/// listener, because one malformed peer must not stop the mail exchanger.
pub async fn serve_smtp(listener: TcpListener, receiver: Receiver) -> io::Result<()> {
    let receiver = Arc::new(receiver);
    loop {
        let (stream, peer) = listener.accept().await?;
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let _ = handle_connection(stream, receiver, peer.ip()).await;
        });
    }
}

/// Drives one connection: greeting, the plaintext conversation, an optional
/// STARTTLS upgrade, then the encrypted conversation.
async fn handle_connection(stream: TcpStream, receiver: Arc<Receiver>, peer: IpAddr) -> io::Result<()> {
    let mut session = Session::new(receiver.policy.clone());
    let mut stream = stream;
    stream.write_all(session.greeting().to_wire().as_bytes()).await?;

    match converse(&mut stream, &mut session, &receiver, peer).await? {
        Flow::Done => Ok(()),
        Flow::StartTls => {
            let Some(config) = receiver.tls.clone() else {
                // Advertised but unavailable should be impossible; fail safe.
                return Ok(());
            };
            let acceptor = TlsAcceptor::from(config);
            let mut tls = acceptor.accept(stream).await?;
            session.tls_established();
            // A second STARTTLS inside TLS is refused by the session, so this
            // conversation can only end in Done — no unbounded nesting.
            let _ = converse(&mut tls, &mut session, &receiver, peer).await?;
            Ok(())
        }
    }
}

/// How a conversation ended.
enum Flow {
    /// The client quit or the connection closed.
    Done,
    /// The client asked to upgrade to TLS; the caller performs the handshake.
    StartTls,
}

/// Reads commands and writes replies until the session ends or asks for TLS.
///
/// Generic over the transport so the exact same loop runs on a plaintext
/// `TcpStream` and on a `TlsStream`, and so it can be driven by an in-memory
/// duplex in tests with no network at all.
async fn converse<S>(stream: &mut S, session: &mut Session, receiver: &Receiver, peer: IpAddr) -> io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let read = read_command_line(&mut reader, &mut line).await?;
        if read == 0 {
            // The peer hung up.
            return Ok(Flow::Done);
        }

        match session.command(&line) {
            Action::Reply(reply) => {
                let reply = refine_rcpt(&line, reply, session, receiver, peer);
                write_reply(reader.get_mut(), &reply).await?;
            }
            Action::ReadData(reply) => {
                write_reply(reader.get_mut(), &reply).await?;
                let outcome = read_and_store(&mut reader, session, receiver, peer).await?;
                write_reply(reader.get_mut(), &outcome).await?;
            }
            Action::Close(reply) => {
                write_reply(reader.get_mut(), &reply).await?;
                return Ok(Flow::Done);
            }
            Action::StartTls(reply) => {
                if receiver.tls.is_none() {
                    write_reply(reader.get_mut(), &Reply::line(454, "TLS not available")).await?;
                    continue;
                }
                // A command pipelined into the same buffer before the handshake
                // would be plaintext injected under the coming TLS session — the
                // STARTTLS command-injection flaw. Refuse and drop rather than
                // let it through.
                if !reader.buffer().is_empty() {
                    write_reply(reader.get_mut(), &Reply::line(501, "pipelining after STARTTLS is not allowed")).await?;
                    return Ok(Flow::Done);
                }
                write_reply(reader.get_mut(), &reply).await?;
                return Ok(Flow::StartTls);
            }
            // The mail exchanger authenticates no one; AUTH is inbound-only
            // meaningless. Answer plainly rather than pretend to challenge.
            Action::VerifyCredentials { .. } | Action::AwaitCredentials { .. } => {
                write_reply(reader.get_mut(), &Reply::line(538, "this server does not accept authentication on port 25")).await?;
            }
        }
    }
}

/// Adds the two checks the pure session cannot make to a `RCPT` acceptance:
/// the mailbox must actually exist, and greylisting may defer first contact.
///
/// Only a `250` for a `RCPT` line is refined; every other reply — including the
/// session's own `550` relay refusal — passes through untouched, so the relay
/// rule stays in exactly one place.
fn refine_rcpt(line: &str, reply: Reply, session: &Session, receiver: &Receiver, peer: IpAddr) -> Reply {
    if reply.code != 250 || !is_rcpt(line) {
        return reply;
    }
    let Some(address) = rcpt_address(line) else {
        return reply;
    };
    // The session accepted it, so it is either local or authenticated; on :25
    // that means local. A local address with no mailbox is refused here.
    if !receiver.store.exists(&address) {
        return Reply::line(550, "no such mailbox at this domain");
    }
    if let Some(greylist) = &receiver.greylist {
        let sender = session.current_sender().map(|s| s.to_string()).unwrap_or_default();
        if greylist.should_defer(peer, &sender, &address.to_string()) {
            return Reply::line(451, "greylisted: please retry shortly");
        }
    }
    reply
}

/// Reads the message body up to the lone `.` terminator, enforcing the byte
/// limit, then delivers it to every existing local recipient.
///
/// Returns the reply to send after the terminator: `250` on success, `552` if
/// the body overran the limit, `550` if no recipient turned out to be a real
/// mailbox, or `451` if the store could not be written.
async fn read_and_store<S>(reader: &mut BufReader<&mut S>, session: &mut Session, receiver: &Receiver, peer: IpAddr) -> io::Result<Reply>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max = receiver.policy.max_message_bytes;
    // A missing terminator must not let a peer exhaust memory; stop reading well
    // past the accept limit and treat it as an oversize message.
    let hard_ceiling = max.saturating_add(1024 * 1024);

    let mut body: Vec<u8> = Vec::new();
    let mut oversize = false;
    let mut line = Vec::new();

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            // Connection dropped mid-DATA. The message is incomplete; refuse it.
            session.finish_data();
            return Ok(Reply::line(451, "connection closed before end of message"));
        }
        if is_terminator(&line) {
            break;
        }
        let unstuffed = unstuff(&line);
        if (body.len() as u64) + unstuffed.len() as u64 <= max {
            body.extend_from_slice(&unstuffed);
        } else {
            oversize = true;
            // Keep draining until the terminator so the session stays in sync,
            // but stop buffering once we are hopelessly past the limit.
            if body.len() as u64 >= hard_ceiling {
                // Pathological peer: no terminator in sight. Drop the message.
                session.finish_data();
                return Ok(Reply::line(552, "message exceeds the size limit"));
            }
        }
    }

    let Some(envelope) = session.finish_data() else {
        return Ok(Reply::line(451, "no transaction to complete"));
    };
    if oversize {
        return Ok(Reply::line(552, "message exceeds the size limit"));
    }

    let received = received_header(&receiver.policy, &envelope.helo, peer);
    let message = Message::parse(body)
        .map(|m| m.with_prepended_header("Received", &received))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Deliver only to recipients that are real mailboxes here. Unknown ones were
    // already refused at RCPT; filtering again guarantees no black-hole slips
    // through even if a client ignored that refusal.
    let mut delivered = 0u32;
    for recipient in &envelope.recipients {
        if !receiver.store.exists(recipient) {
            continue;
        }
        match receiver.store.deliver(recipient, &message).await {
            Ok(_) => delivered += 1,
            Err(_) => return Ok(Reply::line(451, "temporary failure writing to mailbox")),
        }
    }

    if delivered == 0 {
        Ok(Reply::line(550, "no valid recipients"))
    } else {
        Ok(Reply::line(250, "message accepted for delivery"))
    }
}

/// Reads one command line, capped so an overlong line cannot exhaust memory.
///
/// The session enforces the RFC command-line limit itself and answers `500`, so
/// here we only need to stop reading a runaway line; a truncated line is handed
/// to the session, which rejects it.
async fn read_command_line<S>(reader: &mut BufReader<&mut S>, line: &mut String) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    // Twice the protocol limit is ample headroom; beyond it the peer is abusive.
    let cap = crate::smtp::MAX_COMMAND_LINE * 2;
    loop {
        let mut byte = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(reader, &mut byte).await?;
        if n == 0 {
            break;
        }
        raw.push(byte[0]);
        if byte[0] == b'\n' || raw.len() >= cap {
            break;
        }
    }
    *line = String::from_utf8_lossy(&raw).into_owned();
    Ok(raw.len())
}

/// Writes a reply in wire format.
async fn write_reply<S>(stream: &mut S, reply: &Reply) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(reply.to_wire().as_bytes()).await
}

/// Whether a command line is a `RCPT` command, case-insensitively.
fn is_rcpt(line: &str) -> bool {
    line.trim_start().get(..4).is_some_and(|head| head.eq_ignore_ascii_case("RCPT"))
}

/// Extracts the recipient address from a `RCPT TO:<...>` line, if it parses to a
/// real mailbox address (not the null path).
fn rcpt_address(line: &str) -> Option<crate::Address> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let rest = trimmed.split_once(' ')?.1.trim();
    let after = rest.strip_prefix("TO:").or_else(|| {
        // Case-insensitive "TO:" without allocating for the common exact case.
        rest.get(..3).filter(|h| h.eq_ignore_ascii_case("TO:")).map(|_| &rest[3..])
    })?;
    let path_text = after.split_whitespace().next().unwrap_or("");
    match MailPath::parse(path_text).ok()? {
        MailPath::Mailbox(address) => Some(address),
        MailPath::Null => None,
    }
}

/// Whether a raw DATA line is the lone-dot terminator.
fn is_terminator(line: &[u8]) -> bool {
    matches!(line, b".\r\n" | b".\n" | b".")
}

/// Reverses dot-stuffing on one raw body line at the byte level.
///
/// Byte-level rather than the string helper in [`crate::smtp`] because a message
/// body may not be valid UTF-8 (8BITMIME), and reinterpreting it as text to
/// unstuff would corrupt it. A line beginning `..` loses one dot; every other
/// line is passed through unchanged.
fn unstuff(line: &[u8]) -> Vec<u8> {
    if line.starts_with(b"..") {
        line[1..].to_vec()
    } else {
        line.to_vec()
    }
}

/// Builds the `Received:` trace header stamped on every stored message.
///
/// The trace records who handed us the message and when, so a postmaster reading
/// a delivered message can see the path it took. The timestamp is RFC 5322 date
/// format in UTC.
fn received_header(policy: &Policy, helo: &str, peer: IpAddr) -> String {
    format!(
        "from {helo} ([{peer}]) by {host} with ESMTP; {date}",
        host = policy.hostname,
        date = rfc5322_now(),
    )
}

/// The current time as an RFC 5322 date, e.g. `Thu, 07 Aug 2026 12:00:00 +0000`.
fn rfc5322_now() -> String {
    let secs = crate::time::secs_since_epoch(SystemTime::now());
    let (weekday, year, month, day, hour, minute, second) = crate::time::civil(secs);
    let month_name = crate::time::MONTHS[(month - 1) as usize];
    format!("{weekday}, {day:02} {month_name} {year} {hour:02}:{minute:02}:{second:02} +0000")
}

/// Greylisting state: an (ip, sender, recipient) triple must be seen, deferred,
/// and seen again after a short delay before it is let through.
///
/// The rationale is that most spam engines fire once and never retry a `4xx`,
/// while every conforming mail server does. The tradeoff is a one-time delay on
/// first contact from a new sender, which is why it is optional.
#[derive(Clone)]
pub struct Greylist {
    inner: Arc<Mutex<GreylistState>>,
    delay: Duration,
}

struct GreylistState {
    /// First time a triple was seen; it is accepted once `delay` has elapsed.
    seen: HashMap<(IpAddr, String, String), Instant>,
}

impl Greylist {
    /// A greylist that admits a triple once it retries after `delay`.
    pub fn new(delay: Duration) -> Self {
        Self { inner: Arc::new(Mutex::new(GreylistState { seen: HashMap::new() })), delay }
    }

    /// Whether this delivery attempt should be deferred with a `4xx`.
    ///
    /// The first attempt for a triple is recorded and deferred; a later attempt
    /// after `delay` is admitted. A poisoned lock fails open (admits) rather than
    /// blocking legitimate mail on an internal error.
    pub fn should_defer(&self, ip: IpAddr, sender: &str, recipient: &str) -> bool {
        let key = (ip, sender.to_owned(), recipient.to_owned());
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        match state.seen.get(&key) {
            Some(first) if first.elapsed() >= self.delay => false,
            Some(_) => true,
            None => {
                state.seen.insert(key, Instant::now());
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn temp_root() -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("selfhost-recv-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn policy() -> Policy {
        Policy {
            hostname: "mail.example.com".into(),
            local_domains: vec!["example.com".into()],
            tls_available: false,
            allow_auth_without_tls: false,
            max_message_bytes: 1024 * 1024,
        }
    }

    fn receiver_with(root: &std::path::Path, mailboxes: &[&str]) -> Receiver {
        let addrs: Vec<Address> = mailboxes.iter().map(|m| Address::parse(m).unwrap()).collect();
        let store = Maildir::open(root, &addrs).unwrap();
        Receiver::new(policy(), store, None)
    }

    /// Runs one scripted SMTP conversation against `converse` over an in-memory
    /// duplex and returns everything the server wrote back.
    async fn run_conversation(receiver: &Receiver, script: &str) -> String {
        let (mut client, server) = duplex(64 * 1024);
        let mut server = server;
        let mut session = Session::new(receiver.policy.clone());
        server.write_all(session.greeting().to_wire().as_bytes()).await.unwrap();

        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let recv = receiver.clone();
        let handle = tokio::spawn(async move {
            let _ = converse(&mut server, &mut session, &recv, peer).await;
            // Dropping `server` here closes the duplex so the client read ends.
        });

        client.write_all(script.as_bytes()).await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        handle.await.unwrap();
        out
    }

    #[tokio::test]
    async fn relay_to_a_foreign_domain_is_refused() {
        // The failure the whole receiver exists to prevent: an unauthenticated
        // peer must never get a message relayed to a domain we do not host.
        let root = temp_root();
        let receiver = receiver_with(&root, &["dave@example.com"]);
        let out = run_conversation(
            &receiver,
            "EHLO spammer.test\r\n\
             MAIL FROM:<stranger@elsewhere.com>\r\n\
             RCPT TO:<victim@somewhere-else.com>\r\n\
             QUIT\r\n",
        )
        .await;
        assert!(out.contains("550"), "expected a 550 relay refusal, got:\n{out}");
        assert!(out.to_lowercase().contains("relay"), "the refusal should name relaying:\n{out}");
    }

    #[tokio::test]
    async fn a_local_message_is_written_to_the_maildir() {
        let root = temp_root();
        let receiver = receiver_with(&root, &["dave@example.com"]);
        let out = run_conversation(
            &receiver,
            "EHLO friend.test\r\n\
             MAIL FROM:<sender@elsewhere.com>\r\n\
             RCPT TO:<dave@example.com>\r\n\
             DATA\r\n\
             Subject: hello\r\n\
             \r\n\
             body line\r\n\
             .\r\n\
             QUIT\r\n",
        )
        .await;
        assert!(out.contains("250 message accepted"), "expected acceptance, got:\n{out}");

        // The message is on disk in the recipient's new/, with our Received trace.
        let new_dir = root.join("mail").join("example.com").join("dave").join("new");
        let entries: Vec<_> = std::fs::read_dir(&new_dir).unwrap().filter_map(Result::ok).collect();
        assert_eq!(entries.len(), 1, "exactly one delivered message expected");
        let stored = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(stored.starts_with("Received: from friend.test"), "missing Received trace:\n{stored}");
        assert!(stored.contains("Subject: hello"));
        assert!(stored.contains("body line"));
    }

    #[tokio::test]
    async fn mail_for_an_unknown_local_user_is_refused_not_stored() {
        let root = temp_root();
        let receiver = receiver_with(&root, &["dave@example.com"]);
        let out = run_conversation(
            &receiver,
            "EHLO friend.test\r\n\
             MAIL FROM:<sender@elsewhere.com>\r\n\
             RCPT TO:<ghost@example.com>\r\n\
             QUIT\r\n",
        )
        .await;
        assert!(out.contains("550"), "unknown local mailbox should be refused:\n{out}");
        assert!(out.to_lowercase().contains("no such mailbox"), "{out}");
    }

    #[tokio::test]
    async fn an_oversize_body_is_refused_after_data() {
        let root = temp_root();
        let mut receiver = receiver_with(&root, &["dave@example.com"]);
        receiver.policy.max_message_bytes = 64; // tiny, so a normal body overruns
        let big_line = "x".repeat(500);
        let script = format!(
            "EHLO friend.test\r\n\
             MAIL FROM:<sender@elsewhere.com>\r\n\
             RCPT TO:<dave@example.com>\r\n\
             DATA\r\n{big_line}\r\n.\r\nQUIT\r\n"
        );
        let out = run_conversation(&receiver, &script).await;
        assert!(out.contains("552"), "oversize body should be refused with 552:\n{out}");

        let new_dir = root.join("mail").join("example.com").join("dave").join("new");
        assert_eq!(std::fs::read_dir(&new_dir).unwrap().count(), 0, "nothing should be stored");
    }

    #[tokio::test]
    async fn greylisting_defers_first_contact_then_admits_the_retry() {
        let root = temp_root();
        let mut receiver = receiver_with(&root, &["dave@example.com"]);
        receiver.greylist = Some(Greylist::new(Duration::ZERO)); // admit on immediate retry

        let script = "EHLO friend.test\r\n\
             MAIL FROM:<sender@elsewhere.com>\r\n\
             RCPT TO:<dave@example.com>\r\n\
             QUIT\r\n";
        let first = run_conversation(&receiver, script).await;
        assert!(first.contains("451"), "first contact should be greylisted:\n{first}");

        let second = run_conversation(&receiver, script).await;
        assert!(second.contains("250"), "the retry should be admitted:\n{second}");
    }

    #[test]
    fn rcpt_address_is_extracted_case_insensitively() {
        assert_eq!(rcpt_address("RCPT TO:<dave@example.com>\r\n").unwrap().to_string(), "dave@example.com");
        assert_eq!(rcpt_address("rcpt to:<Dave@Example.com>").unwrap().to_string(), "Dave@example.com");
        assert!(rcpt_address("RCPT TO:<>").is_none(), "the null path is not a mailbox");
    }

    #[test]
    fn dot_unstuffing_is_byte_safe() {
        assert_eq!(unstuff(b"..hidden\r\n"), b".hidden\r\n");
        assert_eq!(unstuff(b"ordinary\r\n"), b"ordinary\r\n");
        // Not valid UTF-8, must still pass through untouched.
        assert_eq!(unstuff(&[0xff, 0xfe, b'\r', b'\n']), vec![0xff, 0xfe, b'\r', b'\n']);
    }

    #[test]
    fn the_rfc5322_date_has_the_expected_shape() {
        // The calendar math itself (civil-from-days, weekday) is covered by
        // `crate::time`'s own tests; this only checks the format this
        // function assembles it into.
        let date = rfc5322_now();
        // "Www, DD Mmm YYYY HH:MM:SS +0000"
        assert!(date.ends_with(" +0000"), "{date}");
        assert_eq!(date.matches(':').count(), 2, "{date}");
    }
}
