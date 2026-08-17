//! The outbound SMTP client — the sending counterpart to [`crate::smtp`].
//!
//! Where [`crate::smtp::Session`] is the server deciding what an incoming command
//! means, [`SmtpClient`] is the client deciding what to *say* next given the
//! server's last reply. It is the same discipline applied to the other side of
//! the wire: a pure state machine that never touches a socket, so the whole
//! EHLO -> STARTTLS -> AUTH -> MAIL -> RCPT -> DATA sequence can be driven by a
//! scripted server in a test with no network at all. The bytes are moved by
//! [`run_client`] (any transport) and [`deliver_to_host`] (a real TCP connection
//! with an optional opportunistic-TLS upgrade).
//!
//! Routing — which host actually receives a message — is [`mx_delivery_order`]:
//! the recipient domain's MX records, in preference order, with the domain
//! itself as the implicit fallback (RFC 5321 §5.1). That function is pure and
//! testable; the resolver is only asked for the records, never for the decision.
//!
//! Messages accepted for sending are spooled by [`OutboundQueue`] so a send that
//! cannot complete now (the queue runner is offline, the far end is deferring)
//! survives a restart and is retried, rather than being lost the moment it is
//! accepted.

use crate::address::{Address, Path};
use crate::message::Message;
use crate::smtp::{Envelope, Reply};
use std::io;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// What the client must do next, decided from the server's last reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// Write this command line (a trailing CRLF is added by the driver).
    Send(String),
    /// Perform a STARTTLS upgrade, then resume with [`SmtpClient::after_upgrade`].
    StartTls,
    /// Write the (dot-stuffed) message body and the `<CRLF>.<CRLF>` terminator.
    SendBody,
    /// The conversation finished; the message was handed off.
    Finished(Delivery),
    /// The conversation cannot continue — a permanent-looking refusal.
    Failed(String),
}

/// The result of a completed outbound conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Recipients the far server accepted at `RCPT` time.
    pub accepted: Vec<String>,
    /// Recipients the far server rejected, with the reply text it gave.
    pub rejected: Vec<(String, String)>,
    /// The final `DATA` acceptance code (250 on success).
    pub last_code: u16,
}

/// Why an outbound delivery attempt to one host failed.
#[derive(Debug)]
pub enum ClientError {
    /// The socket failed.
    Io(io::Error),
    /// The server refused a step; the reply code and text are kept for the log
    /// and for deciding whether a retry could ever succeed.
    Rejected(u16, String),
    /// The TLS handshake failed after `STARTTLS`.
    Tls(String),
    /// The server spoke something the client could not parse.
    Protocol(String),
    /// No route to the domain — no MX and no address for the fallback host.
    NoRoute(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Rejected(code, text) => write!(f, "server refused: {code} {text}"),
            Self::Tls(m) => write!(f, "TLS handshake failed: {m}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::NoRoute(d) => write!(f, "no route to {d}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// What the client is currently waiting for a reply to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Greeting,
    Ehlo,
    StartTls,
    Auth,
    Mail,
    Rcpt,
    Data,
    Body,
    Quit,
    Done,
}

/// One outbound SMTP conversation, as a pure state machine.
#[derive(Debug, Clone)]
pub struct SmtpClient {
    helo: String,
    mail_from: String,          // the full `MAIL FROM` argument, e.g. `<a@b.com>` or `<>`
    recipients: Vec<String>,    // bare recipient addresses
    auth: Option<(String, String)>,
    want_starttls: bool,
    phase: Phase,
    tls_done: bool,
    auth_done: bool,
    next_rcpt: usize,
    accepted: Vec<String>,
    rejected: Vec<(String, String)>,
    last_code: u16,
}

impl SmtpClient {
    /// A client that will send `mail_from` to `recipients`, greeting as `helo`.
    ///
    /// `mail_from` is the envelope sender in its bracketed path form (`<a@b.com>`,
    /// or `<>` for a bounce); `recipients` are bare addresses. STARTTLS and relay
    /// authentication are off until enabled — direct MX delivery needs neither.
    pub fn new(helo: impl Into<String>, mail_from: impl Into<String>, recipients: Vec<String>) -> Self {
        Self {
            helo: helo.into(),
            mail_from: mail_from.into(),
            recipients,
            auth: None,
            want_starttls: false,
            phase: Phase::Greeting,
            tls_done: false,
            auth_done: false,
            next_rcpt: 0,
            accepted: Vec::new(),
            rejected: Vec::new(),
            last_code: 0,
        }
    }

    /// Builds a client from a completed [`Envelope`], for direct MX delivery.
    ///
    /// Only the `recipients` whose domain matches `domain` are addressed on this
    /// connection — one connection serves one destination domain, so a message to
    /// two domains is delivered by two clients.
    pub fn for_domain(env: &Envelope, domain: &str, helo: impl Into<String>) -> Self {
        let recipients = env
            .recipients
            .iter()
            .filter(|a| a.domain().eq_ignore_ascii_case(domain))
            .map(|a| a.to_string())
            .collect();
        Self::new(helo, env.sender.to_string(), recipients)
    }

    /// Requests opportunistic STARTTLS before the mail transaction.
    pub fn with_starttls(mut self) -> Self {
        self.want_starttls = true;
        self
    }

    /// Supplies relay (smarthost) credentials, sent as SASL PLAIN after TLS.
    pub fn with_relay_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self.want_starttls = true; // credentials never travel in cleartext
        self
    }

    /// The `EHLO` line for this client's HELO name.
    fn ehlo_line(&self) -> String {
        format!("EHLO {}", self.helo)
    }

    /// Resumes the conversation after the driver has completed a TLS handshake.
    ///
    /// TLS discards everything learned in cleartext, so the client re-greets: this
    /// returns the `EHLO` to send and moves back to awaiting its reply.
    pub fn after_upgrade(&mut self) -> String {
        self.tls_done = true;
        self.phase = Phase::Ehlo;
        self.ehlo_line()
    }

    /// Feeds the server's latest reply and returns the next action.
    pub fn step(&mut self, reply: &Reply) -> ClientAction {
        self.last_code = reply.code;
        match self.phase {
            Phase::Greeting => self.expect(reply, 2, Phase::Ehlo, |c| ClientAction::Send(c.ehlo_line())),
            Phase::Ehlo => self.after_ehlo(reply),
            Phase::StartTls => {
                if reply.code / 100 == 2 {
                    ClientAction::StartTls
                } else {
                    // The server offered STARTTLS then refused it; continue in the
                    // clear rather than abandon the message, unless auth is needed.
                    if self.auth.is_some() {
                        self.fail(reply, "server refused STARTTLS but relay auth requires it")
                    } else {
                        self.begin_transaction()
                    }
                }
            }
            Phase::Auth => self.expect(reply, 2, Phase::Mail, |c| {
                c.auth_done = true;
                ClientAction::Send(c.mail_line())
            }),
            Phase::Mail => self.expect(reply, 2, Phase::Rcpt, |c| c.send_first_rcpt()),
            Phase::Rcpt => self.after_rcpt(reply),
            Phase::Data => {
                if reply.code == 354 {
                    self.phase = Phase::Body;
                    ClientAction::SendBody
                } else {
                    self.fail(reply, "server did not accept DATA")
                }
            }
            Phase::Body => self.expect(reply, 2, Phase::Quit, |_| ClientAction::Send("QUIT".into())),
            Phase::Quit => {
                self.phase = Phase::Done;
                ClientAction::Finished(Delivery {
                    accepted: std::mem::take(&mut self.accepted),
                    rejected: std::mem::take(&mut self.rejected),
                    last_code: self.last_code,
                })
            }
            Phase::Done => ClientAction::Failed("conversation already finished".into()),
        }
    }

    /// Decides what follows the `EHLO` reply: STARTTLS, or straight to the mail
    /// transaction.
    fn after_ehlo(&mut self, reply: &Reply) -> ClientAction {
        if reply.code / 100 != 2 {
            return self.fail(reply, "server rejected EHLO");
        }
        let offers_starttls = reply.lines.iter().any(|l| l.trim().eq_ignore_ascii_case("STARTTLS"));
        if self.want_starttls && !self.tls_done && offers_starttls {
            self.phase = Phase::StartTls;
            ClientAction::Send("STARTTLS".into())
        } else if self.auth.is_some() && !self.tls_done {
            // Auth was requested but the server offers no TLS to protect it.
            self.fail(reply, "relay requires authentication but offered no STARTTLS")
        } else {
            self.begin_transaction()
        }
    }

    /// Sends `AUTH` when credentials are configured and not yet presented,
    /// otherwise opens the mail transaction with `MAIL FROM`.
    fn begin_transaction(&mut self) -> ClientAction {
        if let Some((user, pass)) = self.auth.clone() {
            if !self.auth_done {
                self.phase = Phase::Auth;
                let token = b64_encode(format!("\0{user}\0{pass}").as_bytes());
                return ClientAction::Send(format!("AUTH PLAIN {token}"));
            }
        }
        self.phase = Phase::Mail;
        ClientAction::Send(self.mail_line())
    }

    /// The `MAIL FROM` command line.
    fn mail_line(&self) -> String {
        format!("MAIL FROM:{}", self.mail_from)
    }

    /// Sends the first `RCPT`, or fails when there is no recipient for this host.
    fn send_first_rcpt(&mut self) -> ClientAction {
        if self.recipients.is_empty() {
            return ClientAction::Failed("no recipients for this destination".into());
        }
        self.next_rcpt = 1;
        ClientAction::Send(format!("RCPT TO:<{}>", self.recipients[0]))
    }

    /// Records a `RCPT` reply and either sends the next one, moves to `DATA`, or
    /// fails when every recipient was refused.
    fn after_rcpt(&mut self, reply: &Reply) -> ClientAction {
        let index = self.next_rcpt - 1;
        if reply.code / 100 == 2 {
            self.accepted.push(self.recipients[index].clone());
        } else {
            let text = reply.lines.first().cloned().unwrap_or_default();
            self.rejected.push((self.recipients[index].clone(), format!("{} {}", reply.code, text)));
        }

        if self.next_rcpt < self.recipients.len() {
            let next = self.recipients[self.next_rcpt].clone();
            self.next_rcpt += 1;
            return ClientAction::Send(format!("RCPT TO:<{next}>"));
        }

        if self.accepted.is_empty() {
            ClientAction::Failed("every recipient was refused".into())
        } else {
            self.phase = Phase::Data;
            ClientAction::Send("DATA".into())
        }
    }

    /// Advances to `next_phase` and runs `on_success` when the reply is 2xx,
    /// otherwise fails with `context`.
    fn expect(
        &mut self,
        reply: &Reply,
        success_class: u16,
        next_phase: Phase,
        on_success: impl FnOnce(&mut Self) -> ClientAction,
    ) -> ClientAction {
        if reply.code / 100 == success_class {
            self.phase = next_phase;
            on_success(self)
        } else {
            self.fail(reply, "unexpected reply")
        }
    }

    /// Records a failure action from a rejecting reply.
    fn fail(&mut self, reply: &Reply, context: &str) -> ClientAction {
        self.phase = Phase::Done;
        let text = reply.lines.first().cloned().unwrap_or_default();
        ClientAction::Failed(format!("{context}: {} {text}", reply.code))
    }
}

/// The hosts to try for `domain`, in the order to try them (RFC 5321 §5.1).
///
/// MX records are ordered by ascending preference; equal preferences keep their
/// given order. When a domain publishes no MX, the domain itself is the implicit
/// mail exchanger, so it is returned as the sole fallback host. A trailing dot on
/// an MX target is stripped so it can be used directly as a connect host.
pub fn mx_delivery_order(mx: &[(u16, String)], domain: &str) -> Vec<String> {
    if mx.is_empty() {
        return vec![domain.trim_end_matches('.').to_owned()];
    }
    let mut ordered: Vec<&(u16, String)> = mx.iter().collect();
    // Stable sort keeps equal-preference hosts in their published order.
    ordered.sort_by_key(|(preference, _)| *preference);

    let mut hosts = Vec::with_capacity(ordered.len());
    for (_, host) in ordered {
        let host = host.trim_end_matches('.').to_owned();
        if !host.is_empty() && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        hosts.push(domain.trim_end_matches('.').to_owned());
    }
    hosts
}

/// Drives one outbound conversation over an already-connected transport.
///
/// Generic over the stream so it runs identically on plaintext and TLS and can be
/// driven by an in-memory duplex in tests. A [`ClientAction::StartTls`] cannot be
/// honoured here — the concrete stream type is unknown — so a client that reaches
/// it on a generic transport is a programming error; use [`deliver_to_host`] for
/// real STARTTLS. `body` is the exact message bytes; dot-stuffing and the
/// terminator are applied here so callers never hand-roll the on-wire framing.
pub async fn run_client<S>(stream: &mut S, client: &mut SmtpClient, body: &[u8]) -> Result<Delivery, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let greeting = read_reply(&mut reader).await?;
    let mut action = client.step(&greeting);
    loop {
        match action {
            ClientAction::Send(line) => {
                write_line(reader.get_mut(), &line).await?;
                let reply = read_reply(&mut reader).await?;
                action = client.step(&reply);
            }
            ClientAction::SendBody => {
                reader.get_mut().write_all(&frame_body(body)).await?;
                let reply = read_reply(&mut reader).await?;
                action = client.step(&reply);
            }
            ClientAction::StartTls => {
                return Err(ClientError::Protocol(
                    "STARTTLS requested on a transport that cannot upgrade".into(),
                ));
            }
            ClientAction::Finished(delivery) => return Ok(delivery),
            ClientAction::Failed(reason) => {
                return Err(ClientError::Rejected(client.last_code, reason));
            }
        }
    }
}

/// Connects to one host and delivers `body`, upgrading to TLS if offered.
///
/// This is the concrete counterpart to [`run_client`]: it owns a real socket and
/// can therefore honour [`ClientAction::StartTls`], swapping the plaintext stream
/// for a TLS one in place and re-greeting. `tls` is the connector to use for that
/// upgrade; when it is `None`, or the server does not offer STARTTLS, the
/// transaction proceeds in the clear (opportunistic, as internet mail is).
pub async fn deliver_to_host(
    host: &str,
    port: u16,
    client: &mut SmtpClient,
    body: &[u8],
    tls: Option<&TlsConnector>,
) -> Result<Delivery, ClientError> {
    let tcp = TcpStream::connect((host, port)).await?;
    let mut stream = Stream::Plain(tcp);
    let mut reader = BufReader::new(&mut stream);

    let greeting = read_reply(&mut reader).await?;
    let mut action = client.step(&greeting);
    loop {
        match action {
            ClientAction::Send(line) => {
                write_line(reader.get_mut(), &line).await?;
                let reply = read_reply(&mut reader).await?;
                action = client.step(&reply);
            }
            ClientAction::SendBody => {
                reader.get_mut().write_all(&frame_body(body)).await?;
                let reply = read_reply(&mut reader).await?;
                action = client.step(&reply);
            }
            ClientAction::StartTls => {
                // Drop the reader, upgrade the underlying stream, rebuild it.
                drop(reader);
                let Some(connector) = tls else {
                    return Err(ClientError::Tls("no TLS connector configured".into()));
                };
                stream = stream.into_tls(connector, host).await?;
                reader = BufReader::new(&mut stream);
                let ehlo = client.after_upgrade();
                write_line(reader.get_mut(), &ehlo).await?;
                let reply = read_reply(&mut reader).await?;
                action = client.step(&reply);
            }
            ClientAction::Finished(delivery) => return Ok(delivery),
            ClientAction::Failed(reason) => return Err(ClientError::Rejected(client.last_code, reason)),
        }
    }
}

/// A connection that may or may not have been upgraded to TLS.
///
/// STARTTLS replaces the transport mid-conversation, so the driver holds this
/// enum rather than a fixed stream type; both arms delegate the async traits to
/// the concrete stream underneath, with no `unsafe`.
enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Stream {
    /// Performs the STARTTLS handshake, consuming the plaintext stream.
    async fn into_tls(self, connector: &TlsConnector, host: &str) -> Result<Stream, ClientError> {
        let tcp = match self {
            Stream::Plain(tcp) => tcp,
            already => return Ok(already), // already TLS; nothing to do
        };
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| ClientError::Tls(format!("{host} is not a valid TLS server name")))?;
        let tls = connector.connect(server_name, tcp).await.map_err(|e| ClientError::Tls(e.to_string()))?;
        Ok(Stream::Tls(Box::new(tls)))
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Frames a message body for `DATA`: dot-stuffed, CRLF-terminated, then `.<CRLF>`.
fn frame_body(body: &[u8]) -> Vec<u8> {
    let mut out = dot_stuff(body);
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Applies dot-stuffing at the byte level (a body may be 8-bit, not UTF-8).
///
/// Any line beginning with `.` gets a second `.` prepended so its content cannot
/// be read as the end-of-data terminator — the sending-side duty the receiver's
/// unstuffing reverses.
fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    let mut at_line_start = true;
    for &byte in body {
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line_start = byte == b'\n';
    }
    out
}

/// Writes one command line with its CRLF terminator.
async fn write_line<S>(stream: &mut S, line: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\r\n").await
}

/// Reads one (possibly multi-line) SMTP reply.
///
/// A line is `code-text` when more lines follow and `code text` on the last, so
/// this reads until it sees a space after the code. All the text lines are kept;
/// the code is taken from the final line (they are equal by protocol).
async fn read_reply<S>(reader: &mut BufReader<S>) -> Result<Reply, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut lines = Vec::new();
    let mut code;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Err(ClientError::Protocol("connection closed mid-reply".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            return Err(ClientError::Protocol(format!("reply line too short: {trimmed:?}")));
        }
        code = trimmed[..3].parse().map_err(|_| ClientError::Protocol(format!("no status code in {trimmed:?}")))?;
        let continues = trimmed.as_bytes().get(3) == Some(&b'-');
        lines.push(trimmed[3..].trim_start_matches([' ', '-']).to_owned());
        if !continues {
            break;
        }
    }
    Ok(Reply { code, lines })
}

/// Standard padded base64 (RFC 4648 §4) for the SASL PLAIN token.
///
/// The mail crate's DKIM module carries the same alphabet for its own tags; this
/// small copy keeps `client` free of a dependency on that module's internals.
pub(crate) fn b64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(bits >> 6 & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(bits & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// An on-disk spool of messages accepted for outbound sending.
///
/// A message is spooled the instant submission accepts it, before any send is
/// attempted, so nothing is lost if the process restarts or the far end defers.
/// Each message is one file under `<data_dir>/mail/queue`, named by a monotonic
/// id so the queue runner processes them roughly in arrival order.
#[derive(Clone)]
pub struct OutboundQueue {
    dir: PathBuf,
}

/// A message read back off the queue, ready to route and send.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// The spool id, passed to [`OutboundQueue::remove`] once delivered.
    pub id: String,
    /// The envelope sender.
    pub sender: Path,
    /// The envelope recipients.
    pub recipients: Vec<Address>,
    /// The HELO name the submission was made under.
    pub helo: String,
    /// The message itself, exactly as accepted.
    pub message: Message,
}

impl QueuedMessage {
    /// The distinct recipient domains, each served by one outbound connection.
    pub fn domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = Vec::new();
        for recipient in &self.recipients {
            let domain = recipient.domain().to_owned();
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        domains
    }
}

/// A source of monotonic ids, so two enqueues in the same millisecond differ.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl OutboundQueue {
    /// Opens (creating) the spool directory under `data_dir`.
    pub fn open(data_dir: &FsPath) -> io::Result<Self> {
        let dir = data_dir.join("mail").join("queue");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Spools one message, returning its id.
    ///
    /// The file is written under a `.tmp` name and renamed into place, so the
    /// queue runner never reads a half-written message — the same atomic-rename
    /// discipline the Maildir store uses for delivery.
    pub fn enqueue(&self, envelope: &Envelope, message: &Message) -> io::Result<String> {
        let id = next_id();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("FROM {}\n", envelope.sender).as_bytes());
        for recipient in &envelope.recipients {
            bytes.extend_from_slice(format!("RCPT {recipient}\n").as_bytes());
        }
        bytes.extend_from_slice(format!("HELO {}\n", envelope.helo).as_bytes());
        bytes.extend_from_slice(format!("LEN {}\n", message.as_bytes().len()).as_bytes());
        bytes.extend_from_slice(message.as_bytes());

        let temp = self.dir.join(format!("{id}.tmp"));
        let final_path = self.dir.join(format!("{id}.eml"));
        std::fs::write(&temp, &bytes)?;
        std::fs::rename(&temp, &final_path)?;
        Ok(id)
    }

    /// The ids currently spooled, oldest first.
    pub fn list(&self) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".eml") {
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Reads one spooled message by id.
    pub fn load(&self, id: &str) -> io::Result<QueuedMessage> {
        let bytes = std::fs::read(self.dir.join(format!("{id}.eml")))?;
        parse_spool(id, &bytes)
    }

    /// Removes a spooled message once it has been delivered (or is a bounce).
    pub fn remove(&self, id: &str) -> io::Result<()> {
        std::fs::remove_file(self.dir.join(format!("{id}.eml")))
    }
}

/// A monotonic, sortable id: zero-padded millisecond clock plus a sequence.
fn next_id() -> String {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{millis:016}-{seq:08}")
}

/// Parses a spooled message back into its envelope and body.
fn parse_spool(id: &str, bytes: &[u8]) -> io::Result<QueuedMessage> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_owned());

    let mut sender: Option<Path> = None;
    let mut recipients = Vec::new();
    let mut helo = String::new();
    let mut offset = 0;
    loop {
        let newline = bytes[offset..].iter().position(|b| *b == b'\n').ok_or_else(|| bad("spool has no body length"))?;
        let line = std::str::from_utf8(&bytes[offset..offset + newline]).map_err(|_| bad("non-UTF8 spool header"))?;
        offset += newline + 1;

        if let Some(value) = line.strip_prefix("FROM ") {
            sender = Some(Path::parse(value).map_err(|_| bad("bad spool sender"))?);
        } else if let Some(value) = line.strip_prefix("RCPT ") {
            recipients.push(Address::parse(value).map_err(|_| bad("bad spool recipient"))?);
        } else if let Some(value) = line.strip_prefix("HELO ") {
            helo = value.to_owned();
        } else if let Some(value) = line.strip_prefix("LEN ") {
            let len: usize = value.parse().map_err(|_| bad("bad spool length"))?;
            let body = &bytes[offset..];
            if body.len() != len {
                return Err(bad("spool length does not match body"));
            }
            let message = Message::parse(body.to_vec()).map_err(|_| bad("spooled message did not parse"))?;
            let sender = sender.ok_or_else(|| bad("spool has no sender"))?;
            return Ok(QueuedMessage { id: id.to_owned(), sender, recipients, helo, message });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt as _};

    // ---- MX routing ---------------------------------------------------------

    #[test]
    fn mx_records_are_tried_in_preference_order() {
        let mx = vec![(20, "backup.example.com".into()), (10, "primary.example.com".into())];
        assert_eq!(mx_delivery_order(&mx, "example.com"), vec!["primary.example.com", "backup.example.com"]);
    }

    #[test]
    fn a_domain_with_no_mx_falls_back_to_itself() {
        // RFC 5321 §5.1: no MX means the domain is its own mail exchanger.
        assert_eq!(mx_delivery_order(&[], "example.com"), vec!["example.com"]);
    }

    #[test]
    fn trailing_dots_are_stripped_and_duplicates_removed() {
        let mx = vec![(10, "mx.example.com.".into()), (10, "mx.example.com.".into())];
        assert_eq!(mx_delivery_order(&mx, "example.com"), vec!["mx.example.com"]);
    }

    #[test]
    fn equal_preference_hosts_keep_their_order() {
        let mx = vec![(10, "a.example.com".into()), (10, "b.example.com".into())];
        assert_eq!(mx_delivery_order(&mx, "example.com"), vec!["a.example.com", "b.example.com"]);
    }

    // ---- the client state machine, driven by a scripted server --------------

    /// A minimal SMTP server that plays a fixed script, for driving `run_client`.
    async fn scripted_server(mut server: tokio::io::DuplexStream, steps: Vec<(&'static str, &'static str)>) -> String {
        // Greeting first.
        server.write_all(b"220 mx.test ESMTP\r\n").await.unwrap();
        let mut received = String::new();
        let mut buf = [0u8; 4096];
        for (expect_contains, response) in steps {
            // Read one command (or the DATA body, which ends with "\r\n.\r\n").
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    return received;
                }
                received.push_str(&String::from_utf8_lossy(&buf[..n]));
                if expect_contains == "<BODY>" {
                    if received.contains("\r\n.\r\n") {
                        break;
                    }
                } else if received.contains(expect_contains) {
                    break;
                }
            }
            server.write_all(response.as_bytes()).await.unwrap();
        }
        received
    }

    #[tokio::test]
    async fn a_full_direct_delivery_walks_ehlo_to_quit() {
        let (mut client_side, server_side) = duplex(64 * 1024);
        let script = vec![
            ("EHLO", "250-mx.test\r\n250 SIZE 10485760\r\n"),
            ("MAIL FROM:", "250 OK\r\n"),
            ("RCPT TO:", "250 OK\r\n"),
            ("DATA", "354 go ahead\r\n"),
            ("<BODY>", "250 queued as ABC\r\n"),
            ("QUIT", "221 bye\r\n"),
        ];
        let server = tokio::spawn(scripted_server(server_side, script));

        let mut client = SmtpClient::new("mail.example.com", "<dave@example.com>", vec!["friend@other.com".into()]);
        let delivery = run_client(&mut client_side, &mut client, b"Subject: hi\r\n\r\nbody\r\n").await.unwrap();

        assert_eq!(delivery.accepted, vec!["friend@other.com"]);
        assert!(delivery.rejected.is_empty());
        assert_eq!(delivery.last_code, 221);
        let seen = server.await.unwrap();
        assert!(seen.contains("EHLO mail.example.com"));
        assert!(seen.contains("MAIL FROM:<dave@example.com>"));
        assert!(seen.contains("RCPT TO:<friend@other.com>"));
    }

    #[tokio::test]
    async fn a_dot_leading_body_line_is_stuffed_on_the_wire() {
        let (mut client_side, server_side) = duplex(64 * 1024);
        let script = vec![
            ("EHLO", "250 mx.test\r\n"),
            ("MAIL FROM:", "250 OK\r\n"),
            ("RCPT TO:", "250 OK\r\n"),
            ("DATA", "354 go ahead\r\n"),
            ("<BODY>", "250 ok\r\n"),
            ("QUIT", "221 bye\r\n"),
        ];
        let server = tokio::spawn(scripted_server(server_side, script));

        let mut client = SmtpClient::new("h", "<a@b.com>", vec!["c@d.com".into()]);
        // A body line that is a single dot must not terminate the data early.
        run_client(&mut client_side, &mut client, b"before\r\n.\r\nafter\r\n").await.unwrap();
        let seen = server.await.unwrap();
        assert!(seen.contains("before\r\n..\r\nafter"), "single-dot line was not stuffed:\n{seen}");
    }

    #[tokio::test]
    async fn a_rejected_sender_fails_the_delivery() {
        let (mut client_side, server_side) = duplex(64 * 1024);
        let script = vec![("EHLO", "250 mx.test\r\n"), ("MAIL FROM:", "550 not allowed\r\n")];
        let server = tokio::spawn(scripted_server(server_side, script));

        let mut client = SmtpClient::new("h", "<a@b.com>", vec!["c@d.com".into()]);
        let error = run_client(&mut client_side, &mut client, b"x\r\n").await.unwrap_err();
        matches!(error, ClientError::Rejected(_, _)).then_some(()).expect("expected a rejection");
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn one_rejected_recipient_still_delivers_to_the_accepted_one() {
        let (mut client_side, server_side) = duplex(64 * 1024);
        let script = vec![
            ("EHLO", "250 mx.test\r\n"),
            ("MAIL FROM:", "250 OK\r\n"),
            ("RCPT TO:", "550 no such user\r\n"),
            ("RCPT TO:", "250 OK\r\n"),
            ("DATA", "354 go\r\n"),
            ("<BODY>", "250 ok\r\n"),
            ("QUIT", "221 bye\r\n"),
        ];
        let server = tokio::spawn(scripted_server(server_side, script));

        let mut client = SmtpClient::new("h", "<a@b.com>", vec!["ghost@d.com".into(), "real@d.com".into()]);
        let delivery = run_client(&mut client_side, &mut client, b"x\r\n").await.unwrap();
        assert_eq!(delivery.accepted, vec!["real@d.com"]);
        assert_eq!(delivery.rejected.len(), 1);
        let _ = server.await.unwrap();
    }

    // ---- the spool ----------------------------------------------------------

    #[test]
    fn a_spooled_message_round_trips_through_the_queue() {
        let dir = std::env::temp_dir().join(format!("mail-queue-{}", std::process::id()));
        let queue = OutboundQueue::open(&dir).unwrap();

        let envelope = Envelope {
            sender: Path::parse("<dave@example.com>").unwrap(),
            recipients: vec![Address::parse("a@x.com").unwrap(), Address::parse("b@y.com").unwrap()],
            helo: "mail.example.com".into(),
        };
        let message = Message::parse(b"Subject: hi\r\n\r\nbody\r\n.leading\r\n".to_vec()).unwrap();

        let id = queue.enqueue(&envelope, &message).unwrap();
        assert_eq!(queue.list().unwrap(), vec![id.clone()]);

        let loaded = queue.load(&id).unwrap();
        assert_eq!(loaded.sender.to_string(), "<dave@example.com>");
        assert_eq!(loaded.recipients.len(), 2);
        assert_eq!(loaded.helo, "mail.example.com");
        // The body bytes survive verbatim — a DKIM signature over them would hold.
        assert_eq!(loaded.message.as_bytes(), message.as_bytes());
        assert_eq!(loaded.domains(), vec!["x.com", "y.com"]);

        queue.remove(&id).unwrap();
        assert!(queue.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sasl_plain_token_is_the_expected_base64() {
        // base64("\0dave\0secret") — authorize id empty, authcid, password.
        assert_eq!(b64_encode(b"\0dave\0secret"), "AGRhdmUAc2VjcmV0");
    }

    #[test]
    fn a_client_from_an_envelope_addresses_only_the_target_domain() {
        let envelope = Envelope {
            sender: Path::parse("<dave@example.com>").unwrap(),
            recipients: vec![Address::parse("a@x.com").unwrap(), Address::parse("b@y.com").unwrap()],
            helo: "h".into(),
        };
        let client = SmtpClient::for_domain(&envelope, "x.com", "mail.example.com");
        assert_eq!(client.recipients, vec!["a@x.com"]);
    }
}
