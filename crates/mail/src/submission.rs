//! Authenticated submission — port 587, where our own users send mail out.
//!
//! Submission and reception are the *same* SMTP, driven by the *same*
//! [`crate::smtp::Session`]; they differ only in policy and in what happens to an
//! accepted message. The receiver (port 25) stores mail for local mailboxes and
//! authenticates no one; submission requires a logged-in user and hands what they
//! send to the outbound queue. Keeping one session type is the whole defence
//! against divergence: the open-relay rule lives once, in [`crate::smtp`], and
//! both ports inherit it.
//!
//! Two rules make this port safe to expose:
//!
//! - **STARTTLS before AUTH.** `AUTH PLAIN` is base64, not encryption, so
//!   [`crate::smtp::Policy`] with `allow_auth_without_tls = false` makes the
//!   session refuse credentials until the connection is encrypted. This driver
//!   performs that upgrade in place.
//! - **AUTH before MAIL.** Submission is not an inbound mail exchanger: an
//!   unauthenticated `MAIL FROM` is refused outright, so the port cannot be used
//!   to inject mail at all without a login.
//!
//! Credentials are checked by an injected [`Authenticator`], so the byte-moving
//! here stays free of any password logic and the verification can be tested on
//! its own. [`ConfigAuthenticator`] is the production implementation: it verifies
//! PBKDF2-HMAC-SHA256 hashes from the config with `ring`, in constant time, and
//! never stores or compares a plaintext password.

use crate::address::Address;
use crate::client::{b64_encode, OutboundQueue};
use crate::message::Message;
use crate::smtp::{Action, Policy, Reply, Session};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_config::Mailbox;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::{fmt, io};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// The PBKDF2 iteration count for newly hashed passwords.
///
/// High enough to make offline guessing expensive, low enough to verify a login
/// without a perceptible delay. The stored hash records the count it was made
/// with, so this can be raised later without invalidating existing hashes.
const PBKDF2_ITERATIONS: u32 = 200_000;

/// The derived-key length, in bytes (SHA-256 output).
const PBKDF2_KEY_LEN: usize = 32;

/// Verifies a submitted credential, returning the authenticated address.
///
/// Injected into the submission driver so the state machine stays pure and the
/// password logic is tested in isolation. An implementation must be constant-time
/// in its comparison; leaking timing tells an attacker when a username exists.
pub trait Authenticator: Send + Sync {
    /// Whether `username`/`password` identify a real mailbox, and which one.
    fn verify(&self, username: &str, password: &str) -> Option<Address>;
}

/// Verifies credentials against the configured mailboxes' PBKDF2 hashes.
pub struct ConfigAuthenticator {
    entries: Vec<Entry>,
}

/// One mailbox's login: the address it authenticates to, the names it may log in
/// under (full address, bare local part, and any aliases), and its stored hash.
struct Entry {
    address: Address,
    login_names: Vec<String>,
    password_hash: String,
}

impl ConfigAuthenticator {
    /// Builds an authenticator from the configured mailboxes.
    ///
    /// A mailbox whose address does not parse is skipped rather than failing the
    /// whole server; config validation catches those earlier, and refusing every
    /// login because one entry is malformed would be the worse failure.
    pub fn new(mailboxes: &[Mailbox]) -> Self {
        let mut entries = Vec::new();
        for mailbox in mailboxes {
            let Ok(address) = Address::parse(&mailbox.address) else {
                continue;
            };
            let mut login_names = vec![address.to_string().to_ascii_lowercase(), address.local().to_ascii_lowercase()];
            for alias in &mailbox.aliases {
                login_names.push(alias.to_ascii_lowercase());
            }
            entries.push(Entry { address, login_names, password_hash: mailbox.password_hash.clone() });
        }
        Self { entries }
    }
}

impl Authenticator for ConfigAuthenticator {
    fn verify(&self, username: &str, password: &str) -> Option<Address> {
        let key = username.trim().to_ascii_lowercase();
        for entry in &self.entries {
            if entry.login_names.iter().any(|name| name == &key) && verify_pbkdf2(&entry.password_hash, password) {
                return Some(entry.address.clone());
            }
        }
        None
    }
}

/// Hashes a password as `pbkdf2-sha256$<iterations>$<salt>$<derived>` (base64).
///
/// The one place a plaintext password becomes a stored hash: used by mailbox
/// administration to set or reset a password. The salt is random per call, so two
/// mailboxes with the same password store different hashes.
pub fn hash_password(password: &str) -> Result<String, SubmissionError> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| SubmissionError::Rng)?;
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).expect("iteration count is non-zero");

    let mut derived = [0u8; PBKDF2_KEY_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &mut derived);
    Ok(format!("pbkdf2-sha256${PBKDF2_ITERATIONS}${}${}", b64_encode(&salt), b64_encode(&derived)))
}

/// Verifies a password against a stored `pbkdf2-sha256$...` hash, constant-time.
///
/// A hash in any other format returns `false` rather than erroring: an
/// unverifiable stored value must fail closed, never be treated as a match.
fn verify_pbkdf2(stored: &str, password: &str) -> bool {
    let mut parts = stored.split('$');
    if parts.next() != Some("pbkdf2-sha256") {
        return false;
    }
    let (Some(iterations), Some(salt_b64), Some(derived_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(iterations), Ok(salt), Ok(derived)) =
        (iterations.parse::<u32>(), b64_decode(salt_b64), b64_decode(derived_b64))
    else {
        return false;
    };
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    // ring's verify is constant-time in the comparison.
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &derived).is_ok()
}

/// Everything one submission connection needs, assembled once by the daemon.
///
/// The submission projection of the contract's `MailRuntime`: it wraps the same
/// `policy` the receiver uses with the two things submission adds — an
/// [`Authenticator`] and the [`OutboundQueue`] accepted mail is spooled to.
#[derive(Clone)]
pub struct Submission {
    /// The session policy. For submission `tls_available` is true and
    /// `allow_auth_without_tls` is false, so credentials are refused before TLS.
    pub policy: Policy,
    /// TLS material for the mandatory STARTTLS upgrade.
    pub tls: Arc<rustls::ServerConfig>,
    /// Verifies SASL credentials.
    pub auth: Arc<dyn Authenticator>,
    /// Where an accepted message is spooled for the outbound queue runner.
    pub queue: OutboundQueue,
}

impl Submission {
    /// Assembles a submission runtime.
    pub fn new(policy: Policy, tls: Arc<rustls::ServerConfig>, auth: Arc<dyn Authenticator>, queue: OutboundQueue) -> Self {
        Self { policy, tls, auth, queue }
    }
}

/// Why a submission operation could not complete.
#[derive(Debug)]
pub enum SubmissionError {
    /// The system random source failed while hashing a password.
    Rng,
}

impl fmt::Display for SubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => write!(f, "the system random source was unavailable"),
        }
    }
}

impl std::error::Error for SubmissionError {}

/// Accepts submission connections forever, one task per connection.
///
/// A failing connection is dropped, never fatal to the listener — one bad client
/// must not stop everyone else from sending mail.
pub async fn serve_submission(listener: TcpListener, submission: Submission) -> io::Result<()> {
    let submission = Arc::new(submission);
    loop {
        let (stream, peer) = listener.accept().await?;
        let submission = Arc::clone(&submission);
        tokio::spawn(async move {
            let _ = handle_connection(stream, peer, submission).await;
        });
    }
}

/// One `[submission]`-tagged line into the daemon's log stream.
///
/// The same secrecy discipline as the IMAP driver's log: connection events,
/// command verbs, and authentication *verdicts* only. An `AUTH` argument and
/// every credential continuation line are base64-wrapped passwords, so client
/// lines pass through [`verb_summary`] and the SASL reads are never echoed.
fn log_submission(peer: SocketAddr, message: impl AsRef<str>) {
    eprintln!("[submission] {peer} {}", message.as_ref());
}

/// The loggable form of one client line: its uppercased verb — plus, for
/// `AUTH`, the mechanism name, which is public protocol, not credential.
fn verb_summary(line: &str) -> String {
    let mut tokens = line.split_whitespace();
    let verb = tokens.next().unwrap_or("").to_ascii_uppercase();
    match (verb.as_str(), tokens.next()) {
        ("AUTH", Some(mechanism)) => format!("AUTH {}", mechanism.to_ascii_uppercase()),
        _ => verb,
    }
}

/// Drives one connection: greeting, the cleartext phase, the STARTTLS upgrade,
/// then the authenticated phase.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    submission: Arc<Submission>,
) -> io::Result<()> {
    let mut session = Session::new(submission.policy.clone());
    let mut stream = stream;
    log_submission(peer, "connected");
    stream.write_all(session.greeting().to_wire().as_bytes()).await?;

    match converse(&mut stream, peer, &mut session, &submission).await? {
        Flow::Done => {
            log_submission(peer, "closed");
            Ok(())
        }
        Flow::StartTls => {
            let acceptor = TlsAcceptor::from(submission.tls.clone());
            let mut tls = acceptor.accept(stream).await?;
            session.tls_established();
            log_submission(peer, "TLS established via STARTTLS");
            let _ = converse(&mut tls, peer, &mut session, &submission).await?;
            log_submission(peer, "closed");
            Ok(())
        }
    }
}

/// How a conversation ended.
enum Flow {
    /// The client quit or the connection closed.
    Done,
    /// The client asked to upgrade; the caller performs the handshake.
    StartTls,
}

/// Reads commands and writes replies until the session ends or asks for TLS.
///
/// Generic over the transport so the identical loop runs on plaintext and TLS and
/// can be driven by an in-memory duplex in tests.
async fn converse<S>(
    stream: &mut S,
    peer: SocketAddr,
    session: &mut Session,
    submission: &Submission,
) -> io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let read = read_command_line(&mut reader, &mut line).await?;
        if read == 0 {
            return Ok(Flow::Done);
        }

        log_submission(peer, format!(">> {}", verb_summary(&line)));

        // AUTH before MAIL: submission is not an inbound exchanger, so a sender
        // that has not logged in is refused before a transaction can even begin.
        if is_mail(&line) && !session.authenticated() {
            log_submission(peer, "<< 530 authentication required");
            write_reply(reader.get_mut(), &Reply::line(530, "authentication required")).await?;
            continue;
        }

        match session.command(&line) {
            Action::Reply(reply) => write_reply(reader.get_mut(), &reply).await?,
            Action::ReadData(reply) => {
                write_reply(reader.get_mut(), &reply).await?;
                let outcome = read_and_enqueue(&mut reader, session, submission).await?;
                write_reply(reader.get_mut(), &outcome).await?;
            }
            Action::Close(reply) => {
                write_reply(reader.get_mut(), &reply).await?;
                return Ok(Flow::Done);
            }
            Action::StartTls(reply) => {
                // A command pipelined before the handshake would be plaintext
                // smuggled under the coming TLS session — the STARTTLS injection
                // flaw. Refuse and drop.
                if !reader.buffer().is_empty() {
                    write_reply(reader.get_mut(), &Reply::line(501, "pipelining after STARTTLS is not allowed")).await?;
                    return Ok(Flow::Done);
                }
                write_reply(reader.get_mut(), &reply).await?;
                return Ok(Flow::StartTls);
            }
            Action::VerifyCredentials { mechanism, initial_response } => {
                let credential = decode_credential(&mechanism, &initial_response);
                let verdict = credential.and_then(|(user, pass)| submission.auth.verify(&user, &pass));
                log_submission(peer, if verdict.is_some() { "auth ok" } else { "auth FAILED" });
                finish_auth(reader.get_mut(), session, verdict.is_some()).await?;
            }
            Action::AwaitCredentials { mechanism, reply } => {
                write_reply(reader.get_mut(), &reply).await?;
                let credential = read_credentials(&mut reader, &mechanism).await?;
                let verdict = credential.and_then(|(user, pass)| submission.auth.verify(&user, &pass));
                log_submission(peer, if verdict.is_some() { "auth ok" } else { "auth FAILED" });
                finish_auth(reader.get_mut(), session, verdict.is_some()).await?;
            }
        }
    }
}

/// Records the authentication result and answers the client.
async fn finish_auth<S>(stream: &mut S, session: &mut Session, succeeded: bool) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if succeeded {
        session.authentication_succeeded();
        write_reply(stream, &Reply::line(235, "authentication successful")).await
    } else {
        write_reply(stream, &Reply::line(535, "authentication failed")).await
    }
}

/// Reads the challenge-response half of a SASL exchange for `mechanism`.
///
/// `PLAIN` sends one base64 line; `LOGIN` sends the base64 username, then — after
/// a second `334` prompt — the base64 password. Returns `None` when a line is not
/// valid base64 or the payload is malformed, which the caller answers as a
/// failed login.
async fn read_credentials<S>(reader: &mut BufReader<&mut S>, mechanism: &str) -> io::Result<Option<(String, String)>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match mechanism {
        "PLAIN" => {
            let line = read_line_trimmed(reader).await?;
            Ok(decode_plain(&line))
        }
        "LOGIN" => {
            let username = read_line_trimmed(reader).await?;
            let Some(username) = b64_decode(&username).ok().and_then(|b| String::from_utf8(b).ok()) else {
                return Ok(None);
            };
            // Prompt for the password: base64("Password:").
            write_reply(reader.get_mut(), &Reply::line(334, "UGFzc3dvcmQ6")).await?;
            let password = read_line_trimmed(reader).await?;
            let Some(password) = b64_decode(&password).ok().and_then(|b| String::from_utf8(b).ok()) else {
                return Ok(None);
            };
            Ok(Some((username, password)))
        }
        _ => Ok(None),
    }
}

/// Decodes a SASL initial-response for `mechanism` (only `PLAIN` carries one).
fn decode_credential(mechanism: &str, initial_response: &str) -> Option<(String, String)> {
    match mechanism {
        "PLAIN" => decode_plain(initial_response),
        _ => None,
    }
}

/// Decodes a SASL PLAIN token: `authzid \0 authcid \0 password`.
///
/// The authorization identity is ignored; the authentication identity (the
/// username) and the password are what a login needs. Shared with the IMAP
/// session's `AUTHENTICATE PLAIN` — same SASL mechanism, one decoder.
pub(crate) fn decode_plain(token: &str) -> Option<(String, String)> {
    let bytes = b64_decode(token.trim()).ok()?;
    let mut parts = bytes.split(|b| *b == 0);
    let _authzid = parts.next()?;
    let authcid = parts.next()?;
    let password = parts.next()?;
    Some((String::from_utf8(authcid.to_vec()).ok()?, String::from_utf8(password.to_vec()).ok()?))
}

/// Reads the DATA body to the lone-dot terminator and spools it for sending.
///
/// The byte limit is enforced against the actual bytes, not the declared size;
/// dot-stuffing is reversed at the byte level so an 8-bit body is not corrupted.
/// On success the message is written to the outbound queue and `250` returned.
async fn read_and_enqueue<S>(reader: &mut BufReader<&mut S>, session: &mut Session, submission: &Submission) -> io::Result<Reply>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max = submission.policy.max_message_bytes;
    let hard_ceiling = max.saturating_add(1024 * 1024);

    let mut body: Vec<u8> = Vec::new();
    let mut oversize = false;
    let mut raw = Vec::new();

    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw).await?;
        if read == 0 {
            session.finish_data();
            return Ok(Reply::line(451, "connection closed before end of message"));
        }
        if is_terminator(&raw) {
            break;
        }
        let unstuffed = unstuff(&raw);
        if (body.len() as u64) + unstuffed.len() as u64 <= max {
            body.extend_from_slice(&unstuffed);
        } else {
            oversize = true;
            if body.len() as u64 >= hard_ceiling {
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

    let message = match Message::parse(body) {
        Ok(message) => message,
        Err(_) => return Ok(Reply::line(554, "message has no headers")),
    };
    match submission.queue.enqueue(&envelope, &message) {
        Ok(_) => Ok(Reply::line(250, "message accepted for delivery")),
        Err(_) => Ok(Reply::line(451, "could not queue the message; try again")),
    }
}

/// Reads one command line, capped so an overlong line cannot exhaust memory.
async fn read_command_line<S>(reader: &mut BufReader<&mut S>, line: &mut String) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    let cap = crate::smtp::MAX_COMMAND_LINE * 2;
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
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

/// Reads one line and returns it with CR/LF trimmed.
async fn read_line_trimmed<S>(reader: &mut BufReader<&mut S>) -> io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Writes a reply in wire format.
async fn write_reply<S>(stream: &mut S, reply: &Reply) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(reply.to_wire().as_bytes()).await
}

/// Whether a command line is `MAIL`, case-insensitively.
fn is_mail(line: &str) -> bool {
    line.trim_start().get(..4).is_some_and(|head| head.eq_ignore_ascii_case("MAIL"))
}

/// Whether a raw DATA line is the lone-dot terminator.
fn is_terminator(line: &[u8]) -> bool {
    matches!(line, b".\r\n" | b".\n" | b".")
}

/// Reverses dot-stuffing on one raw body line at the byte level.
fn unstuff(line: &[u8]) -> Vec<u8> {
    if line.starts_with(b"..") {
        line[1..].to_vec()
    } else {
        line.to_vec()
    }
}

/// Decodes padded or unpadded standard base64, ignoring embedded whitespace.
///
/// The decode counterpart to [`crate::client::b64_encode`], kept here because SASL
/// is the only consumer of base64 *decoding* in the crate.
fn b64_decode(text: &str) -> Result<Vec<u8>, ()> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut symbols = Vec::new();
    for byte in text.bytes() {
        match byte {
            b'=' | b' ' | b'\t' | b'\r' | b'\n' => {}
            other => symbols.push(value(other).ok_or(())?),
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
        if group.len() == 1 {
            return Err(()); // a lone symbol cannot encode any byte
        }
        let bits = group.iter().enumerate().fold(0u32, |acc, (i, s)| acc | (s << (18 - 6 * i)));
        out.push((bits >> 16) as u8);
        if group.len() > 2 {
            out.push((bits >> 8) as u8);
        }
        if group.len() > 3 {
            out.push(bits as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::OutboundQueue;
    use crate::smtp::Policy;
    use std::sync::Arc;
    use tokio::io::duplex;

    fn mailbox(address: &str, password: &str) -> Mailbox {
        Mailbox { address: address.into(), password_hash: hash_password(password).unwrap(), aliases: Vec::new() }
    }

    // ---- credential verification -------------------------------------------

    #[test]
    fn a_correct_password_authenticates_to_its_address() {
        let auth = ConfigAuthenticator::new(&[mailbox("dave@example.com", "hunter2")]);
        // Login by full address or by bare local part.
        assert_eq!(auth.verify("dave@example.com", "hunter2").unwrap().to_string(), "dave@example.com");
        assert_eq!(auth.verify("dave", "hunter2").unwrap().to_string(), "dave@example.com");
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let auth = ConfigAuthenticator::new(&[mailbox("dave@example.com", "hunter2")]);
        assert!(auth.verify("dave@example.com", "wrong").is_none());
        assert!(auth.verify("nobody@example.com", "hunter2").is_none());
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        // A per-call random salt means identical passwords never share a hash.
        let a = hash_password("secret").unwrap();
        let b = hash_password("secret").unwrap();
        assert_ne!(a, b);
        assert!(verify_pbkdf2(&a, "secret") && verify_pbkdf2(&b, "secret"));
    }

    #[test]
    fn an_unrecognised_hash_format_fails_closed() {
        // A stored value that is not a pbkdf2-sha256 hash must never match.
        assert!(!verify_pbkdf2("plaintextpassword", "plaintextpassword"));
        assert!(!verify_pbkdf2("md5$deadbeef", "anything"));
    }

    #[test]
    fn a_sasl_plain_token_decodes_to_username_and_password() {
        // base64("\0dave\0hunter2")
        assert_eq!(decode_plain("AGRhdmUAaHVudGVyMg=="), Some(("dave".into(), "hunter2".into())));
        assert!(decode_plain("not base64!!").is_none());
    }

    // ---- the submission conversation ---------------------------------------

    fn submission_with(mailboxes: &[Mailbox]) -> (Submission, std::path::PathBuf) {
        let policy = Policy {
            hostname: "mail.example.com".into(),
            local_domains: vec!["example.com".into()],
            tls_available: true,
            allow_auth_without_tls: true, // test over the duplex without real TLS
            max_message_bytes: 1024 * 1024,
        };
        let dir = std::env::temp_dir().join(format!("submit-{}-{}", std::process::id(), fastcount()));
        let queue = OutboundQueue::open(&dir).unwrap();
        let auth: Arc<dyn Authenticator> = Arc::new(ConfigAuthenticator::new(mailboxes));
        // A throwaway ServerConfig; the duplex test never performs a handshake.
        let tls = dummy_server_config();
        (Submission::new(policy, tls, auth, queue), dir)
    }

    fn fastcount() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }

    fn dummy_server_config() -> Arc<rustls::ServerConfig> {
        // Build a minimal config from a throwaway self-signed pair is heavy; the
        // test path never handshakes, so an empty resolver config suffices to
        // satisfy the type. We construct it via a no-client-auth builder with a
        // cert resolver that returns nothing.
        use rustls::server::{ClientHello, ResolvesServerCert};
        use rustls::sign::CertifiedKey;
        #[derive(Debug)]
        struct NoCert;
        impl ResolvesServerCert for NoCert {
            fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                None
            }
        }
        Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(NoCert)))
    }

    /// Runs one scripted submission conversation over an in-memory duplex.
    async fn run(submission: &Submission, script: &str) -> String {
        let (mut client, mut server) = duplex(64 * 1024);
        let mut session = Session::new(submission.policy.clone());
        server.write_all(session.greeting().to_wire().as_bytes()).await.unwrap();

        let sub = submission.clone();
        let peer: SocketAddr = "127.0.0.1:0".parse().expect("a valid dummy peer");
        let handle = tokio::spawn(async move {
            let _ = converse(&mut server, peer, &mut session, &sub).await;
        });
        client.write_all(script.as_bytes()).await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        handle.await.unwrap();
        out
    }

    #[tokio::test]
    async fn unauthenticated_mail_is_refused() {
        let (submission, dir) = submission_with(&[mailbox("dave@example.com", "pw")]);
        let out = run(&submission, "EHLO me\r\nMAIL FROM:<dave@example.com>\r\nQUIT\r\n").await;
        assert!(out.contains("530"), "MAIL before AUTH must be refused:\n{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_authenticated_user_can_submit_and_the_message_is_spooled() {
        let (submission, dir) = submission_with(&[mailbox("dave@example.com", "hunter2")]);
        // base64("\0dave\0hunter2") = AGRhdmUAaHVudGVyMg==
        let out = run(
            &submission,
            "EHLO me\r\n\
             AUTH PLAIN AGRhdmUAaHVudGVyMg==\r\n\
             MAIL FROM:<dave@example.com>\r\n\
             RCPT TO:<friend@far.com>\r\n\
             DATA\r\n\
             Subject: hi\r\n\r\nbody\r\n.\r\n\
             QUIT\r\n",
        )
        .await;
        assert!(out.contains("235"), "auth should succeed:\n{out}");
        assert!(out.contains("250 message accepted"), "submission should be accepted:\n{out}");
        // Authenticated submission may relay to a foreign domain — that is the point.
        assert_eq!(submission.queue.list().unwrap().len(), 1, "one message should be spooled");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_bad_password_is_rejected_and_blocks_submission() {
        let (submission, dir) = submission_with(&[mailbox("dave@example.com", "hunter2")]);
        // base64("\0dave\0wrong") = AGRhdmUAd3Jvbmc=
        let out = run(
            &submission,
            "EHLO me\r\nAUTH PLAIN AGRhdmUAd3Jvbmc=\r\nMAIL FROM:<dave@example.com>\r\nQUIT\r\n",
        )
        .await;
        assert!(out.contains("535"), "a wrong password must be refused:\n{out}");
        assert!(out.contains("530"), "and MAIL must still be blocked:\n{out}");
        assert!(submission.queue.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
