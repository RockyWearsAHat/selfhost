//! The worker side of a link: dialling out, and keeping the link up.
//!
//! # The one decision that shapes all of it
//!
//! **The worker dials the owner. Nothing listens, on either side.**
//!
//! ```text
//! worker daemon ──wss://<owner console host>/api/mesh/link──► owner proxy :443 ──► owner admin
//! ```
//!
//! That direction is not an implementation convenience; it is the security
//! property, and adding a second machine to this mesh is free of perimeter
//! consequences precisely because of it. The worker binds no socket at all —
//! `lsof -nP -iTCP -sTCP:LISTEN` on it shows nothing new, which is a claim the
//! build plan verifies mechanically rather than asserts. The owner binds nothing
//! new either: the dial lands on the console site's existing 443, so it passes
//! the *same* `allowed_cidrs` gate as every other console request, which means
//! the mesh works only over the tunnel and no exemption anywhere is widened. NAT
//! becomes irrelevant, which is what makes a worker behind a domestic router
//! work at all.
//!
//! There is therefore no listener in this module, and there must never be one.
//! If a change appears to need this side to accept a connection, the change has
//! taken a wrong turn: report it rather than opening a port.
//!
//! # The transport is injected, and the handshake is not
//!
//! [`Connector`] supplies a byte stream to a host and port — a TCP connection
//! inside TLS, in production. Everything above that is here: the `GET` that asks
//! for the upgrade, the `Sec-WebSocket-Key` this side generates, the check that
//! the answer is a real `101` with the matching accept value, and the enrolment
//! proof computed over that handshake's own key and accept.
//!
//! The split is drawn there on purpose. The proof's whole value is that it is
//! bound to *this* handshake (see [`crate::enroll`]), so the two values it is
//! bound to must be the ones this code itself produced and read. A connector
//! that handed back a stream *and* a pair of handshake strings would be a
//! connector that could hand back the wrong ones, and the failure would be a
//! credential that binds to nothing while still verifying.
//!
//! A consequence worth stating: the handshake carries **no secret at all**. No
//! bearer token, no ticket, no cookie. The credential is the proof, presented
//! after the upgrade, so nothing in the request head is worth capturing.
//!
//! # Reconnection, and why the reason is recorded
//!
//! [`maintain`] is the supervised loop. A link that drops re-establishes without
//! anybody being asked, with the backoff `crates/console/src/tunnel.rs` already
//! worked out — doubling, capped, and reset only after the link has been healthy
//! for a real stretch — plus jitter, so that a hundred workers that lost the same
//! router do not return in lockstep.
//!
//! Every ending is written into the [`SharedRegistry`], including the ones where
//! nothing was ever established. *"It is not connected"* is a useless thing to
//! read at two in the morning; *"the node's enrolment proof was refused"* is
//! something to act on, and the difference between those two sentences is
//! whether the failure path bothered to record what it knew.
//!
//! Failures are counted **per node**, in [`crate::registry`], and never reach
//! the console's global login gate: a flapping worker must not be able to lock
//! the operator out of their own console.

use crate::channel::{ChannelId, Open, Reject, Role, parse_accept};
use crate::enroll::{Binding, EnrollError, NodeToken};
use crate::link::{Hello, LINK_CONTROL_SERVICE, Link, LinkControl, LinkHandle};
use crate::mux::{self, FrameError, Kind, VERSION};
use crate::registry::{DropReason, NodeName, SharedRegistry};
use selfhost_http::{IncomingResponse, ParseError, Status};
use selfhost_ws::{Duplex, Event, Limits, StreamError};
use std::fmt;
use std::future::Future;
use std::io;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The port a `wss://` URL means when it does not say.
pub const DEFAULT_PORT: u16 = 443;

/// The longest response head this side will read before giving up.
///
/// A `101` is about two hundred bytes. Eight kibibytes is generous for anything
/// an intermediary might add and small enough that a server which answers with
/// an endless stream of header bytes is refused rather than absorbed.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;

/// How long the whole post-connect exchange may take.
///
/// Covers the upgrade request, the response head, the enrolment `OPEN` and the
/// answer to it. A peer that completes a TCP connection and then says nothing
/// must not be able to hold a task open indefinitely — that is a way to consume
/// a worker's tasks without ever proving anything.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// The longest wait between attempts to bring a link back.
///
/// The same ceiling `crates/console/src/tunnel.rs` uses, for the same reason: a
/// link that fails because a laptop lid closed should come back quickly, and one
/// failing because the token is stale should not spend a machine's evening
/// asking again.
pub const MAX_RETRY: Duration = Duration::from_secs(30);

/// How long a link must stay up before it counts as healthy.
///
/// Below this, a link that came up and immediately dropped is treated as another
/// failure rather than as a success — otherwise a peer that accepts a connection
/// and closes it at once resets the backoff on every attempt, and the "backoff"
/// becomes a tight reconnect loop with extra steps.
pub const HEALTHY_AFTER: Duration = Duration::from_secs(60);

/// Where a worker dials, taken apart once so it cannot be re-parsed differently
/// at each use.
///
/// Only `wss://` is representable. Plain `ws://` is refused at the parser rather
/// than warned about: everything this link carries — a screen, the keystrokes
/// going to it, the contents of a share — is exactly what transport security
/// exists for, and an operator who mistypes the scheme should be told at
/// start-up rather than after the first session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: String,
    port: u16,
    path: String,
}

impl Target {
    /// Parses a `wss://host[:port][/path]` URL.
    pub fn parse(url: &str) -> Result<Self, UrlError> {
        let rest = strip_scheme(url)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(UrlError::UserInfo);
        }
        let (host, port) = split_authority(authority)?;
        let path = if tail.is_empty() { "/".to_owned() } else { tail.to_owned() };
        if !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            // A space or a CR here is a request-splitting primitive: the path is
            // written straight into a request line.
            return Err(UrlError::PathNotPrintable);
        }
        Ok(Self { host, port, path })
    }

    /// The host to connect to, without brackets even when it is an IPv6 literal.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port to connect to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The request target — the path and query, as it goes in the request line.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The value of the `Host` field.
    ///
    /// The default port is omitted, and an IPv6 literal is bracketed, which is
    /// what a browser does and therefore what a site's host matching is written
    /// to expect.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == DEFAULT_PORT { host } else { format!("{host}:{}", self.port) }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "wss://{}{}", self.authority(), self.path)
    }
}

/// Removes the scheme, refusing anything but `wss://`.
fn strip_scheme(url: &str) -> Result<&str, UrlError> {
    let (scheme, rest) = url.split_once("://").ok_or(UrlError::NotWss)?;
    if scheme.eq_ignore_ascii_case("ws") {
        return Err(UrlError::Plaintext);
    }
    if !scheme.eq_ignore_ascii_case("wss") {
        return Err(UrlError::NotWss);
    }
    Ok(rest)
}

/// Splits `host[:port]`, bracketed or not.
fn split_authority(authority: &str) -> Result<(String, u16), UrlError> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed.split_once(']').ok_or(UrlError::BadHost)?;
            check_host(host, true)?;
            (host, tail.strip_prefix(':'))
        }
        None => match authority.split_once(':') {
            Some((host, port)) => {
                check_host(host, false)?;
                (host, Some(port))
            }
            None => {
                check_host(authority, false)?;
                (authority, None)
            }
        },
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(text) => match text.parse::<u16>() {
            Ok(0) | Err(_) => return Err(UrlError::BadPort),
            Ok(port) => port,
        },
    };
    Ok((host.to_owned(), port))
}

/// Rejects a host that could not be a host, or that could forge a header line.
fn check_host(host: &str, bracketed: bool) -> Result<(), UrlError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UrlError::BadHost);
    }
    let acceptable = |byte: u8| {
        byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'.'
            || (bracketed && (byte == b':' || byte == b'%'))
    };
    if host.bytes().all(acceptable) { Ok(()) } else { Err(UrlError::BadHost) }
}

/// Why an owner URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// The scheme was not `wss`.
    NotWss,
    /// The scheme was `ws`, which this link does not speak.
    Plaintext,
    /// The URL carried a username or password.
    ///
    /// Refused rather than ignored: a credential in a URL lands in shell
    /// history, in `ps`, and in every log line that prints the target — the same
    /// rule `docs/SECURITY.md` states for an argv password.
    UserInfo,
    /// The host was empty, over-long, or contained something that is not a host.
    BadHost,
    /// The port was absent after a colon, zero, or not a number.
    BadPort,
    /// The path contained a byte outside printable ASCII.
    PathNotPrintable,
}

impl fmt::Display for UrlError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWss => out.write_str("an owner URL is a wss:// URL"),
            Self::Plaintext => out.write_str(
                "ws:// is refused: this link carries a screen, the keystrokes going to it and the \
                 contents of a share, so it runs inside TLS or not at all",
            ),
            Self::UserInfo => {
                out.write_str("an owner URL may not carry a username or password; the node token is the credential")
            }
            Self::BadHost => out.write_str("the URL's host is empty, too long, or not a host"),
            Self::BadPort => out.write_str("the URL's port is not a number between 1 and 65535"),
            Self::PathNotPrintable => {
                out.write_str("the URL's path contains a byte that is not printable ASCII")
            }
        }
    }
}

impl std::error::Error for UrlError {}

/// Everything a worker needs to dial its owner.
#[derive(Debug, Clone)]
pub struct DialConfig {
    /// Where to dial.
    pub target: Target,
    /// This machine's name, as the owner declared it.
    pub node: NodeName,
    /// This machine's enrolment secret. Never printed; see
    /// [`crate::enroll::NodeToken`].
    pub token: NodeToken,
    /// The WebSocket limits the link runs under.
    pub limits: Limits,
}

impl DialConfig {
    /// A configuration with the default WebSocket limits.
    pub fn new(target: Target, node: NodeName, token: NodeToken) -> Self {
        Self { target, node, token, limits: Limits::default() }
    }
}

/// Something that can open a byte stream to a [`Target`].
///
/// In production this is a TCP connection wrapped in TLS. In tests it is one end
/// of an in-memory pipe, which is what lets every rule above the socket — the
/// handshake, the proof, the retry schedule — be asserted without a network, a
/// certificate, or a port.
///
/// It is deliberately *only* a byte stream: see the module documentation for why
/// the handshake is not the connector's business.
pub trait Connector {
    /// The stream this connector produces.
    type Stream: AsyncRead + AsyncWrite + Unpin;

    /// Opens a stream to `target`, or reports why it could not.
    fn connect(&self, target: &Target) -> impl Future<Output = io::Result<Self::Stream>>;
}

/// A link that has been established and whose peer has been proved.
///
/// The three halves arrive together because they are useless apart: run
/// [`Session::link`], write through [`Session::handle`], and read the link's own
/// control traffic from [`Session::control`].
pub struct Session<S> {
    /// The driver. Run it, usually on a task of its own.
    pub link: Link<S>,
    /// The writer and channel-claiming half.
    pub handle: LinkHandle,
    /// Channel 0, and frames for channels nobody holds.
    pub control: LinkControl,
}

impl<S> fmt::Debug for Session<S> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Session").field("role", &self.handle.role()).finish()
    }
}

/// Dials the owner once and proves this node's enrolment.
///
/// The whole establish path, in the order the wire sees it: connect, `GET` with
/// an upgrade, read the `101`, check the accept value, send the enrolment
/// greeting on channel 0, and wait for the owner's answer. Returns a live link,
/// or the reason there is not one.
///
/// The entire post-connect exchange runs under [`HANDSHAKE_TIMEOUT`]. The
/// connector owns its own connect timeout, because how long to wait for a TCP
/// handshake is a property of the transport and not of this protocol.
pub async fn connect<C: Connector>(
    config: &DialConfig,
    connector: &C,
) -> Result<Session<C::Stream>, DialError> {
    let stream = connector.connect(&config.target).await.map_err(DialError::Connect)?;
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, establish(config, stream)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(DialError::Timeout),
    }
}

/// The post-connect half of [`connect`], separated so the timeout wraps exactly
/// it and not the transport's own connect.
async fn establish<S: AsyncRead + AsyncWrite + Unpin>(
    config: &DialConfig,
    mut stream: S,
) -> Result<Session<S>, DialError> {
    let key = client_key()?;
    let request = upgrade_request(&config.target, &key);
    stream.write_all(&request).await.map_err(DialError::Handshake)?;
    stream.flush().await.map_err(DialError::Handshake)?;

    let head = read_head(&mut stream).await?;
    let accept = check_upgrade(&head, &key)?;

    let binding = Binding::new(&key, &accept, config.node.clone()).map_err(DialError::Enroll)?;
    let greeting =
        Hello { node: config.node.clone(), version: VERSION, proof: binding.prove(&config.token) };
    let params = greeting.encode();
    let payload = Open { service: LINK_CONTROL_SERVICE, params: &params }
        .encode()
        .map_err(|_| DialError::Protocol("the enrolment greeting does not fit in an OPEN"))?;

    let mut duplex = Duplex::client(stream, config.limits);
    let frame = mux::encode_frame(Kind::Open, ChannelId::CONTROL, &payload)?;
    duplex.send(&frame).await.map_err(DialError::Stream)?;
    await_admission(&mut duplex).await?;

    let (link, handle, control) = Link::new(duplex, Role::Dialler);
    Ok(Session { link, handle, control })
}

/// Waits for the owner's answer to the enrolment greeting.
///
/// Exactly one mux frame in one WebSocket message: the link-control exchange is
/// the one place where "several frames arrived at once" would mean the peer is
/// talking before it has been admitted, and there is nothing it could usefully
/// say there.
async fn await_admission<S: AsyncRead + AsyncWrite + Unpin>(
    duplex: &mut Duplex<S>,
) -> Result<(), DialError> {
    let message = match duplex.recv().await.map_err(DialError::Stream)? {
        Event::Message(message) => message,
        // A close here is the refusal: the owner answers a node it does not
        // recognise with a bare code and nothing else, deliberately, so there is
        // no prose to read and nothing to distinguish "unenrolled" from "stale
        // token" from the outside.
        Event::Closed(_) => return Err(DialError::Refused),
    };
    let (frame, rest) = mux::parse_frame(&message)?;
    if !rest.is_empty() {
        return Err(DialError::Protocol("the owner packed something behind its answer"));
    }
    if !frame.header.channel.is_control() {
        return Err(DialError::Protocol("the owner answered off the control channel"));
    }
    match frame.header.kind {
        Kind::Accept => {
            parse_accept(frame.payload)
                .map_err(|_| DialError::Protocol("the owner's accept carried a payload"))?;
            Ok(())
        }
        // The code is taken and the prose is not: the plan's refusal rule is a
        // bare code, and a worker that logged the owner's sentence would be
        // logging a string chosen by whatever answered the dial.
        Kind::Reject => {
            let reject = Reject::parse(frame.payload)
                .map_err(|_| DialError::Protocol("the owner's refusal was malformed"))?;
            Err(DialError::Rejected { code: reject.code })
        }
        _ => Err(DialError::Protocol("the owner answered the greeting with neither accept nor reject")),
    }
}

/// The bytes of the upgrade request.
///
/// Pure, so what goes on the wire is asserted directly rather than sniffed out
/// of a socket. Nothing here is a secret: no cookie, no bearer, no ticket. The
/// credential is the proof that follows the upgrade, which is what makes this
/// head safe to relay through a proxy that logs it.
pub fn upgrade_request(target: &Target, key: &str) -> Vec<u8> {
    let mut head = String::with_capacity(200);
    head.push_str("GET ");
    head.push_str(target.path());
    head.push_str(" HTTP/1.1\r\nHost: ");
    head.push_str(&target.authority());
    head.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    head.push_str(key);
    head.push_str("\r\nSec-WebSocket-Version: 13\r\n\r\n");
    head.into_bytes()
}

/// Checks that a response head is the upgrade we asked for, and returns the
/// `Sec-WebSocket-Accept` it carried.
///
/// The accept value is returned rather than merely compared because it is an
/// input to the enrolment proof: binding to the value the *server sent* — after
/// proving it is the value it should have sent — is what makes the proof name
/// this connection and no other.
///
/// Pure. Every refusal is typed, and a non-101 answer carries its status,
/// because a `403` from the console site's source-address gate and a `502` from
/// a proxy with nothing behind it are different problems with the same symptom.
pub fn check_upgrade(head: &[u8], key: &str) -> Result<String, DialError> {
    let parsed = IncomingResponse::parse(head).map_err(DialError::BadResponse)?;
    let response = parsed.response;
    if response.status != Status::SWITCHING_PROTOCOLS {
        return Err(DialError::NotUpgraded { status: response.status.code() });
    }
    if !header_has_token(response.headers.get_str("upgrade"), "websocket") {
        return Err(DialError::Protocol("the 101 did not name the websocket protocol"));
    }
    if !header_has_token(response.headers.get_str("connection"), "upgrade") {
        return Err(DialError::Protocol("the 101 did not ask to upgrade the connection"));
    }
    let offered =
        response.headers.get_str("sec-websocket-accept").ok_or(DialError::MissingAccept)?.trim();
    if offered != selfhost_ws::accept_key(key) {
        return Err(DialError::BadAccept);
    }
    Ok(offered.to_owned())
}

/// Whether a comma-separated header value contains `token`, case-insensitively.
fn header_has_token(value: Option<&str>, token: &str) -> bool {
    value.is_some_and(|value| {
        value.split(',').any(|entry| entry.trim().eq_ignore_ascii_case(token))
    })
}

/// Reads a response head, and not one byte more.
///
/// One byte at a time, which is unusual enough to justify: `selfhost_ws::Duplex`
/// cannot be handed bytes that were already read, so anything this loop takes
/// past the blank line is stranded — the very trap `proxy/server.rs` documents
/// for relayed bodies, and it applies again after an upgrade. A head is a couple
/// of hundred bytes and happens once per link, so the syscalls are not worth an
/// arrangement that could lose a frame.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, DialError> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(DialError::HeadTooLarge);
        }
        match stream.read(&mut byte).await.map_err(DialError::Handshake)? {
            0 => {
                return Err(DialError::Handshake(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the owner closed the connection before answering the upgrade",
                )));
            }
            _ => head.push(byte[0]),
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

/// A fresh `Sec-WebSocket-Key`: sixteen random bytes, padded standard base64.
///
/// RFC 6455 §4.1 fixes both the length and the encoding. The key is not a secret
/// — it is sent in the clear in the request head — but it must be fresh per
/// connection, because it is half of what the enrolment proof is bound to, and a
/// repeated key is a replayable handshake.
pub fn client_key() -> Result<String, DialError> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_| DialError::NoEntropy)?;
    Ok(base64_standard(&bytes))
}

/// The standard base64 alphabet (RFC 4648 §4), which is the one RFC 6455 uses.
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes as padded standard base64.
///
/// Private, and the fifth such encoder in this workspace, which deserves the
/// explanation: `crates/acme` and `crates/admin` both emit the **URL-safe,
/// unpadded** alphabet that JOSE and WebAuthn require, so their output would be
/// rejected by every WebSocket server; `crates/ws` has the right one, but it is
/// private to that crate's accept-key derivation. Exposing it there is the right
/// fix and is recorded as a follow-up; twenty total lines here is the cost of
/// not editing another crate to get them.
fn base64_standard(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        // `get` rather than indexing: the final chunk may be one or two bytes,
        // and a parser that indexes past it is the shape of bug this workspace
        // refuses everywhere.
        let first = u32::from(*chunk.first().unwrap_or(&0));
        let second = u32::from(*chunk.get(1).unwrap_or(&0));
        let third = u32::from(*chunk.get(2).unwrap_or(&0));
        let bits = (first << 16) | (second << 8) | third;
        out.push(char::from(BASE64_ALPHABET[(bits >> 18 & 0x3f) as usize]));
        out.push(char::from(BASE64_ALPHABET[(bits >> 12 & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(BASE64_ALPHABET[(bits >> 6 & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(BASE64_ALPHABET[(bits & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

/// How many times [`maintain`] should try.
///
/// `Forever` is the deployment; `Limited` exists so a test can assert the retry
/// schedule and the recorded reasons without waiting for a loop that by design
/// never ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempts {
    /// Keep dialling for as long as the future is polled.
    Forever,
    /// Stop after this many attempts.
    Limited(u32),
}

impl Attempts {
    /// Whether an attempt numbered `made` is one too many.
    fn reached(self, made: u32) -> bool {
        match self {
            Self::Forever => false,
            Self::Limited(cap) => made >= cap,
        }
    }
}

/// How long to wait before the next attempt, after `failures` in a row.
///
/// Doubles from a second, stops doubling at [`MAX_RETRY`], and spreads the
/// result over the top half of the interval using `jitter`. The jitter is what
/// keeps a fleet that lost the same router from returning in lockstep and
/// turning a recovery into a thundering herd against the owner's console site;
/// the floor at half the interval is what keeps jitter from turning a thirty
/// second backoff into a one second one.
///
/// Pure — `jitter` is supplied — so the schedule is asserted directly and
/// [`random_jitter`] is the only part that needs entropy.
pub fn retry_delay(failures: u32, jitter: u32) -> Duration {
    // `1000 << 6` is 64,000, nowhere near overflowing, and the shift is capped
    // rather than left to wrap.
    let ceiling = u64::try_from(MAX_RETRY.as_millis()).unwrap_or(u64::MAX);
    let base = (1000u64 << failures.min(6)).min(ceiling);
    let floor = base / 2;
    let span = base - floor;
    let extra = if span == 0 { 0 } else { u64::from(jitter) % (span + 1) };
    Duration::from_millis(floor.saturating_add(extra))
}

/// A random jitter value for [`retry_delay`].
///
/// Falls back to zero when the operating system will not provide entropy, which
/// costs the fleet-spreading property and nothing else. Refusing to retry
/// because a random number was unavailable would be a far worse failure than
/// retrying on schedule.
pub fn random_jitter() -> u32 {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 4];
    match ring::rand::SystemRandom::new().fill(&mut bytes) {
        Ok(()) => u32::from_be_bytes(bytes),
        Err(_) => 0,
    }
}

/// The failure count to carry into the next backoff.
///
/// A link that stayed up for [`HEALTHY_AFTER`] resets the count: a machine that
/// has been healthy for a minute and lost its tunnel should come back in a
/// second, not in thirty. A link that came up and dropped immediately does not
/// reset it, because that is a peer that is failing in a way a fast retry cannot
/// fix.
pub fn next_failures(previous: u32, uptime: Duration) -> u32 {
    if uptime >= HEALTHY_AFTER { 0 } else { previous.saturating_add(1) }
}

/// Keeps a link to the owner up, for as long as this future is polled.
///
/// `serve` is handed each established [`Session`] and returns the
/// [`DropReason`] that ended it — it is where the worker's own services live,
/// and this loop deliberately knows nothing about them. Whatever it returns is
/// what the operator reads in the console.
///
/// Returns the number of attempts made, which under [`Attempts::Forever`] means
/// it does not return at all.
///
/// **Cancellation** is the caller's `select!`: dropping this future stops the
/// loop wherever it is, including in the middle of a backoff sleep. There is no
/// separate shutdown channel because there is nothing to unwind — the link's own
/// task ends with the socket, and the registry's last recorded reason is already
/// correct.
pub async fn maintain<C, F, Fut>(
    config: &DialConfig,
    connector: &C,
    registry: &SharedRegistry,
    attempts: Attempts,
    mut serve: F,
) -> u32
where
    C: Connector,
    F: FnMut(Session<C::Stream>) -> Fut,
    Fut: Future<Output = DropReason>,
{
    registry.declare(config.node.clone());
    let mut failures = 0u32;
    let mut made = 0u32;

    loop {
        if attempts.reached(made) {
            return made;
        }
        made = made.saturating_add(1);

        let began = Instant::now();
        match connect(config, connector).await {
            Ok(session) => {
                registry.declare_linked(&config.node, SystemTime::now());
                let reason = serve(session).await;
                registry.declare_dropped(&config.node, SystemTime::now(), reason);
                failures = next_failures(failures, began.elapsed());
            }
            Err(error) => {
                registry.declare_dropped(&config.node, SystemTime::now(), error.drop_reason());
                failures = failures.saturating_add(1);
            }
        }

        if attempts.reached(made) {
            return made;
        }
        tokio::time::sleep(retry_delay(failures, random_jitter())).await;
    }
}

/// Why a dial did not produce a link.
#[derive(Debug)]
pub enum DialError {
    /// The transport would not connect: refused, reset, DNS, TLS.
    Connect(io::Error),
    /// The connection failed while the handshake was in flight.
    Handshake(io::Error),
    /// The response head exceeded [`MAX_HEAD_BYTES`].
    HeadTooLarge,
    /// The response head was not a response.
    BadResponse(ParseError),
    /// The owner answered, but not with a `101`.
    NotUpgraded {
        /// The status it answered with.
        status: u16,
    },
    /// The `101` carried no `Sec-WebSocket-Accept`.
    MissingAccept,
    /// The `Sec-WebSocket-Accept` did not match the key we sent.
    ///
    /// Something between here and the owner answered a handshake it did not
    /// understand — a cache, a captive portal, a proxy replaying a stored `101`.
    BadAccept,
    /// The link's own framing was violated.
    Frame(FrameError),
    /// A handshake field could not be bound to a proof.
    Enroll(EnrollError),
    /// The stream failed while the enrolment greeting was in flight.
    Stream(StreamError),
    /// The owner closed the connection instead of answering the greeting.
    ///
    /// This is what a refusal looks like from the outside, and it is deliberately
    /// indistinguishable from every other refusal: see [`crate::accept`].
    Refused,
    /// The owner refused the greeting with a code.
    Rejected {
        /// The refusal code. The prose the owner sent is deliberately not kept.
        code: u16,
    },
    /// The owner said something this build cannot make sense of.
    Protocol(&'static str),
    /// The whole exchange exceeded [`HANDSHAKE_TIMEOUT`].
    Timeout,
    /// The operating system would not provide entropy for the handshake key.
    NoEntropy,
}

impl DialError {
    /// The reason to record in the registry for this failure.
    ///
    /// The mapping is the whole point of having typed errors here: it is what
    /// turns *"it is not connected"* into a sentence the operator can act on.
    pub fn drop_reason(&self) -> DropReason {
        match self {
            Self::Connect(_)
            | Self::Handshake(_)
            | Self::NotUpgraded { .. }
            | Self::Timeout
            | Self::Stream(_) => DropReason::TransportFailed,
            Self::Refused | Self::Rejected { .. } => DropReason::ProofRefused,
            Self::Frame(FrameError::UnsupportedVersion(offered)) => {
                DropReason::VersionMismatch { offered: *offered }
            }
            Self::HeadTooLarge
            | Self::BadResponse(_)
            | Self::MissingAccept
            | Self::BadAccept
            | Self::Frame(_)
            | Self::Enroll(_)
            | Self::Protocol(_)
            | Self::NoEntropy => DropReason::ProtocolError,
        }
    }
}

impl From<FrameError> for DialError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(out, "the owner could not be reached: {error}"),
            Self::Handshake(error) => write!(out, "the connection failed mid-handshake: {error}"),
            Self::HeadTooLarge => {
                write!(out, "the owner's answer exceeded {MAX_HEAD_BYTES} bytes of head")
            }
            Self::BadResponse(error) => write!(out, "the owner's answer was not a response: {error}"),
            Self::NotUpgraded { status } => {
                write!(out, "the owner answered {status}, not 101; the link route did not upgrade")
            }
            Self::MissingAccept => out.write_str("the owner's 101 carried no sec-websocket-accept"),
            Self::BadAccept => out.write_str(
                "the owner's sec-websocket-accept does not match the key sent; something in \
                 between answered a handshake it did not understand",
            ),
            Self::Frame(error) => write!(out, "{error}"),
            Self::Enroll(error) => write!(out, "{error}"),
            Self::Stream(error) => write!(out, "{error}"),
            Self::Refused => {
                out.write_str("the owner closed the link without admitting this node")
            }
            Self::Rejected { code } => write!(out, "the owner refused this node (code {code})"),
            Self::Protocol(complaint) => out.write_str(complaint),
            Self::Timeout => write!(out, "the owner did not complete the handshake within {HANDSHAKE_TIMEOUT:?}"),
            Self::NoEntropy => out.write_str("the operating system would not provide random bytes"),
        }
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(error) | Self::Handshake(error) => Some(error),
            Self::BadResponse(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Enroll(error) => Some(error),
            Self::Stream(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept::{self, MemoryTokens};
    use crate::enroll::NonceLedger;
    use std::sync::{Arc, Mutex};
    use tokio::io::DuplexStream;

    fn node(text: &str) -> NodeName {
        NodeName::parse(text).expect("valid name")
    }

    fn token() -> NodeToken {
        NodeToken::from_bytes([7u8; 32])
    }

    fn config() -> DialConfig {
        DialConfig::new(
            Target::parse("wss://admin.rockywearsahat.com/api/mesh/link").expect("url"),
            node("alex-desktop"),
            token(),
        )
    }

    #[test]
    fn a_wss_url_is_taken_apart_once() {
        let target = Target::parse("wss://admin.rockywearsahat.com/api/mesh/link").expect("url");
        assert_eq!(target.host(), "admin.rockywearsahat.com");
        assert_eq!(target.port(), 443);
        assert_eq!(target.path(), "/api/mesh/link");
        assert_eq!(target.authority(), "admin.rockywearsahat.com");
        assert_eq!(target.to_string(), "wss://admin.rockywearsahat.com/api/mesh/link");
    }

    #[test]
    fn a_missing_path_becomes_the_root_and_a_port_is_kept() {
        let target = Target::parse("wss://box.example:8443").expect("url");
        assert_eq!(target.path(), "/");
        assert_eq!(target.port(), 8443);
        assert_eq!(target.authority(), "box.example:8443", "a non-default port stays in Host");

        let query = Target::parse("wss://box.example/link?node=a").expect("url");
        assert_eq!(query.path(), "/link?node=a");
    }

    #[test]
    fn an_ipv6_literal_is_bracketed_in_host_and_bare_in_the_connect() {
        let target = Target::parse("wss://[2001:db8::1]:9443/link").expect("url");
        assert_eq!(target.host(), "2001:db8::1", "the connector wants the address, not the brackets");
        assert_eq!(target.authority(), "[2001:db8::1]:9443");
        assert_eq!(Target::parse("wss://[::1]/x").expect("url").authority(), "[::1]");
    }

    #[test]
    fn plaintext_is_refused_with_its_own_message() {
        // The likeliest mistake, and the one worth explaining rather than
        // lumping in with "bad URL".
        assert_eq!(Target::parse("ws://box.example/link").unwrap_err(), UrlError::Plaintext);
        assert!(UrlError::Plaintext.to_string().contains("TLS"));
        assert_eq!(Target::parse("https://box.example/link").unwrap_err(), UrlError::NotWss);
        assert_eq!(Target::parse("box.example/link").unwrap_err(), UrlError::NotWss);
    }

    #[test]
    fn a_credential_in_the_url_is_refused() {
        // docs/SECURITY.md's rule about argv passwords, applied to the one other
        // place a secret ends up in `ps` and in every log line.
        assert_eq!(Target::parse("wss://alex:hunter2@box.example/x").unwrap_err(), UrlError::UserInfo);
    }

    #[test]
    fn a_url_that_could_forge_a_request_line_is_refused() {
        // The path goes straight into the request line; a space or a CR there is
        // a request-splitting primitive.
        for url in [
            "wss://box.example/a b",
            "wss://box.example/a\r\nX-Evil: 1",
            "wss://box.example/a\nb",
        ] {
            assert_eq!(Target::parse(url).unwrap_err(), UrlError::PathNotPrintable, "{url:?}");
        }
        for url in ["wss://box.exa mple/x", "wss:///x", "wss://bo\rx/x"] {
            assert_eq!(Target::parse(url).unwrap_err(), UrlError::BadHost, "{url:?}");
        }
        for url in ["wss://box.example:0/x", "wss://box.example:99999/x", "wss://box.example:/x"] {
            assert_eq!(Target::parse(url).unwrap_err(), UrlError::BadPort, "{url:?}");
        }
    }

    #[test]
    fn url_parsing_never_panics_on_arbitrary_input() {
        let mut state = 0xd1a1_1e40_0000_0001u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 60) as usize;
            let text: String = (0..len).map(|index| char::from((state >> (index % 8 * 8)) as u8)).collect();
            let _ = Target::parse(&text);
            let _ = Target::parse(&format!("wss://{text}"));
        }
    }

    #[test]
    fn the_request_head_is_exactly_what_rfc_6455_asks_for_and_carries_no_secret() {
        let target = Target::parse("wss://admin.example/api/mesh/link").expect("url");
        let head = String::from_utf8(upgrade_request(&target, "dGhlIHNhbXBsZSBub25jZQ==")).expect("ascii");
        assert!(head.starts_with("GET /api/mesh/link HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("\r\nHost: admin.example\r\n"), "{head}");
        assert!(head.contains("\r\nUpgrade: websocket\r\n"), "{head}");
        assert!(head.contains("\r\nConnection: Upgrade\r\n"), "{head}");
        assert!(head.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"), "{head}");
        assert!(head.contains("\r\nSec-WebSocket-Version: 13\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
        let lowered = head.to_ascii_lowercase();
        for forbidden in ["cookie", "authorization", "sec-websocket-protocol", "origin"] {
            assert!(!lowered.contains(forbidden), "the handshake carries no credential: {head}");
        }
    }

    #[test]
    fn a_generated_key_is_sixteen_bytes_of_padded_standard_base64() {
        let key = client_key().expect("entropy");
        assert!(selfhost_ws::accept::client_key_is_well_formed(&key), "{key}");
        assert_ne!(key, client_key().expect("entropy"), "a repeated key is a replayable handshake");
    }

    #[test]
    fn base64_matches_the_known_vectors() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_standard(&[0xff, 0xff, 0xff]), "////");
        assert_eq!(base64_standard(&[0xfb, 0xff, 0xbf]), "+/+/");
    }

    /// A `101` head as the owner's admin API writes it.
    fn switching(key: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            selfhost_ws::accept_key(key)
        )
        .into_bytes()
    }

    #[test]
    fn a_real_101_is_accepted_and_hands_back_the_accept_value() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = check_upgrade(&switching(key), key).expect("a real upgrade");
        assert_eq!(accept, selfhost_ws::accept_key(key));
    }

    #[test]
    fn an_answer_that_is_not_the_upgrade_we_asked_for_is_refused_and_says_which() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let refused = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            check_upgrade(refused, key),
            Err(DialError::NotUpgraded { status: 403 })
        ));

        // A cache or captive portal replaying somebody else's 101.
        let wrong = switching("b3RoZXIgY29ubmVjdGlvbg==");
        assert!(matches!(check_upgrade(&wrong, key), Err(DialError::BadAccept)));

        let no_accept = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(matches!(check_upgrade(no_accept, key), Err(DialError::MissingAccept)));

        let no_upgrade = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            selfhost_ws::accept_key(key)
        );
        assert!(matches!(check_upgrade(no_upgrade.as_bytes(), key), Err(DialError::Protocol(_))));
    }

    #[test]
    fn a_comma_separated_connection_header_still_counts() {
        assert!(header_has_token(Some("keep-alive, Upgrade"), "upgrade"));
        assert!(header_has_token(Some("WebSocket"), "websocket"));
        assert!(!header_has_token(Some("upgraded"), "upgrade"));
        assert!(!header_has_token(None, "upgrade"));
    }

    #[test]
    fn the_retry_schedule_doubles_stops_and_never_collapses_to_zero() {
        // The floor matters as much as the ceiling: jitter that could take the
        // delay to zero would turn a backoff into a tight reconnect loop.
        for jitter in [0u32, 1, 12_345, u32::MAX] {
            assert!(retry_delay(0, jitter) >= Duration::from_millis(500));
            assert!(retry_delay(0, jitter) <= Duration::from_millis(1000));
            assert!(retry_delay(3, jitter) >= Duration::from_millis(4000));
            assert!(retry_delay(3, jitter) <= Duration::from_millis(8000));
            assert!(retry_delay(9, jitter) >= MAX_RETRY / 2);
            assert!(retry_delay(9, jitter) <= MAX_RETRY, "a stale token must not be retried forever faster");
            assert!(retry_delay(u32::MAX, jitter) <= MAX_RETRY, "and the shift must not overflow");
        }
        // Jitter actually spreads: two different values give two different waits.
        assert_ne!(retry_delay(6, 0), retry_delay(6, u32::MAX));
    }

    #[test]
    fn a_link_that_was_healthy_comes_back_quickly_and_a_flapping_one_does_not() {
        assert_eq!(next_failures(9, HEALTHY_AFTER), 0);
        assert_eq!(next_failures(9, HEALTHY_AFTER + Duration::from_secs(1)), 0);
        assert_eq!(next_failures(9, Duration::from_millis(10)), 10);
        assert_eq!(next_failures(u32::MAX, Duration::ZERO), u32::MAX);
    }

    #[test]
    fn every_failure_maps_to_a_reason_the_console_can_render() {
        assert_eq!(
            DialError::Connect(io::Error::other("refused")).drop_reason(),
            DropReason::TransportFailed
        );
        assert_eq!(DialError::NotUpgraded { status: 403 }.drop_reason(), DropReason::TransportFailed);
        assert_eq!(DialError::Timeout.drop_reason(), DropReason::TransportFailed);
        assert_eq!(DialError::Refused.drop_reason(), DropReason::ProofRefused);
        assert_eq!(DialError::Rejected { code: 1 }.drop_reason(), DropReason::ProofRefused);
        assert_eq!(DialError::BadAccept.drop_reason(), DropReason::ProtocolError);
        assert_eq!(
            DialError::Frame(FrameError::UnsupportedVersion(9)).drop_reason(),
            DropReason::VersionMismatch { offered: 9 }
        );
        assert!(DialError::NotUpgraded { status: 502 }.to_string().contains("502"));
    }

    /// A connector that hands out one end of an in-memory pipe and gives the
    /// other end to the test, so a whole dial happens with no socket at all.
    ///
    /// It also counts connections, which is how the retry tests tell a loop that
    /// is retrying from one that is spinning.
    struct PipeConnector {
        owner: Arc<Mutex<Vec<DuplexStream>>>,
        connections: Arc<Mutex<u32>>,
        capacity: usize,
    }

    impl PipeConnector {
        fn new() -> Self {
            Self {
                owner: Arc::new(Mutex::new(Vec::new())),
                connections: Arc::new(Mutex::new(0)),
                capacity: 64 * 1024,
            }
        }

        fn take_owner_end(&self) -> Option<DuplexStream> {
            self.owner.lock().expect("not poisoned").pop()
        }
    }

    impl Connector for PipeConnector {
        type Stream = DuplexStream;

        async fn connect(&self, _target: &Target) -> io::Result<Self::Stream> {
            let (worker, owner) = tokio::io::duplex(self.capacity);
            self.owner.lock().expect("not poisoned").push(owner);
            *self.connections.lock().expect("not poisoned") += 1;
            Ok(worker)
        }
    }

    /// A connector that always fails, for the "the owner is not there" case.
    struct DeadConnector {
        attempts: Arc<Mutex<u32>>,
    }

    impl Connector for DeadConnector {
        type Stream = DuplexStream;

        async fn connect(&self, _target: &Target) -> io::Result<Self::Stream> {
            *self.attempts.lock().expect("not poisoned") += 1;
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "nothing is listening"))
        }
    }

    /// Plays the owner: reads the upgrade request, answers `101`, and admits the
    /// node through the real [`crate::accept`] path.
    async fn play_owner(
        stream: DuplexStream,
        tokens: MemoryTokens,
        registry: SharedRegistry,
        ledger: Arc<Mutex<NonceLedger>>,
    ) -> Result<accept::Admitted<DuplexStream>, accept::Refused> {
        let mut stream = stream;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("the worker sends a head");
            assert_ne!(read, 0, "the worker must send a whole head");
            head.push(byte[0]);
        }
        let request = selfhost_http::Request::parse(&head).expect("a request").request;
        let upgrade = selfhost_ws::handshake::validate(&request).expect("a real handshake");
        let response =
            selfhost_ws::handshake::response_head(&upgrade.accept, None).expect("a response head");
        stream.write_all(&response).await.expect("write");
        stream.flush().await.expect("flush");
        accept::admit(stream, &upgrade.key, &tokens, &ledger, &registry, Limits::default()).await
    }

    #[tokio::test]
    async fn a_worker_dials_proves_itself_and_gets_a_live_link() {
        // The whole establish path, end to end, with no socket: the worker's
        // handshake, the owner's 101, the enrolment proof, and a frame crossing
        // in each direction once the link is up.
        let connector = PipeConnector::new();
        let registry = SharedRegistry::new();
        registry.declare(node("alex-desktop"));
        let tokens = MemoryTokens::from_pairs([(node("alex-desktop"), token())]);
        let ledger = Arc::new(Mutex::new(NonceLedger::new()));

        let config = config();
        let dialling = tokio::spawn({
            let connector = PipeConnector {
                owner: Arc::clone(&connector.owner),
                connections: Arc::clone(&connector.connections),
                capacity: connector.capacity,
            };
            let config = config.clone();
            async move { connect(&config, &connector).await }
        });

        // Wait for the worker's connection to appear, then play the owner.
        let owner_end = loop {
            if let Some(end) = connector.take_owner_end() {
                break end;
            }
            tokio::task::yield_now().await;
        };
        let admitted = play_owner(owner_end, tokens, registry.clone(), ledger)
            .await
            .expect("the node is enrolled");
        assert_eq!(admitted.node, node("alex-desktop"));

        let worker = dialling.await.expect("task").expect("a live link");
        let worker_driver = tokio::spawn(worker.link.run());
        let owner_driver = tokio::spawn(admitted.link.run());

        let mut owner_inbox = admitted.handle.attach(ChannelId::new(1)).expect("attach");
        worker.handle.send_frame(Kind::Data, ChannelId::new(1), b"hello").await.expect("send");
        assert_eq!(owner_inbox.recv().await.expect("frame").payload, b"hello");

        assert!(registry.get(&node("alex-desktop")).expect("record").is_linked());
        worker_driver.abort();
        owner_driver.abort();
    }

    #[tokio::test]
    async fn a_worker_whose_owner_disappears_records_why_and_dials_again() {
        // The "owner disappears" case in both of its forms: the connection is
        // refused outright, and the loop keeps trying with the reason recorded.
        let attempts = Arc::new(Mutex::new(0u32));
        let connector = DeadConnector { attempts: Arc::clone(&attempts) };
        let registry = SharedRegistry::new();
        let config = config();

        tokio::time::pause();
        let made = maintain(&config, &connector, &registry, Attempts::Limited(3), |session| async move {
            drop(session);
            DropReason::LocalShutdown
        })
        .await;

        assert_eq!(made, 3, "a link that will not come up is retried, not given up on");
        assert_eq!(*attempts.lock().expect("not poisoned"), 3);
        let record = registry.get(&node("alex-desktop")).expect("declared even though it never linked");
        assert_eq!(record.consecutive_failures, 3);
        assert_eq!(record.last_seen, None, "a failed attempt is not a sighting");
        assert_eq!(record.describe(), DropReason::TransportFailed.to_string());
    }

    #[tokio::test]
    async fn a_link_that_drops_mid_session_re_establishes_without_being_asked() {
        // The worker's owner vanishes *after* the link is up: the reason is
        // recorded, and the loop dials again on its own.
        let connector = PipeConnector::new();
        let registry = SharedRegistry::new();
        let tokens = MemoryTokens::from_pairs([(node("alex-desktop"), token())]);
        let ledger = Arc::new(Mutex::new(NonceLedger::new()));
        let config = config();

        let owner_slot = Arc::clone(&connector.owner);
        let owner_registry = registry.clone();
        let owner = tokio::spawn(async move {
            let mut admitted = 0u32;
            while admitted < 2 {
                let Some(end) = owner_slot.lock().expect("not poisoned").pop() else {
                    tokio::task::yield_now().await;
                    continue;
                };
                let session =
                    play_owner(end, tokens.clone(), owner_registry.clone(), Arc::clone(&ledger))
                        .await
                        .expect("the node is enrolled");
                admitted += 1;
                // The owner goes away: drop everything, which closes the socket.
                drop(session);
            }
            admitted
        });

        let made = maintain(&config, &connector, &registry, Attempts::Limited(2), |session| async move {
            let Session { link, handle, control } = session;
            drop(handle);
            drop(control);
            link.run().await
        })
        .await;

        assert_eq!(made, 2);
        assert_eq!(owner.await.expect("owner task"), 2, "the worker really did dial twice");
        let record = registry.get(&node("alex-desktop")).expect("record");
        assert!(record.links >= 2, "each dial is a link, and each is counted");
        assert!(record.last_seen.is_some(), "a link that was up is a sighting");
        assert!(!record.is_linked());
    }

    #[tokio::test]
    async fn a_dial_that_is_answered_with_silence_times_out_rather_than_hanging() {
        let connector = PipeConnector::new();
        let config = config();

        tokio::time::pause();
        let dialling = tokio::spawn({
            let connector = PipeConnector {
                owner: Arc::clone(&connector.owner),
                connections: Arc::clone(&connector.connections),
                capacity: connector.capacity,
            };
            let config = config.clone();
            async move { connect(&config, &connector).await }
        });

        // Take the owner's end and hold it without answering, so the connection
        // stays open and nothing arrives.
        let held = loop {
            if let Some(end) = connector.take_owner_end() {
                break end;
            }
            tokio::task::yield_now().await;
        };
        tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
        let outcome = dialling.await.expect("task");
        assert!(matches!(outcome, Err(DialError::Timeout)), "silence must not hold a task open");
        drop(held);
    }
}
