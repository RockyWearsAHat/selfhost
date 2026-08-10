//! The IMAP session state machine.
//!
//! Written as a pure state machine — a tagged command in, response lines out,
//! no sockets — for the same reason [`crate::smtp`] is: the parts that decide
//! what a client is allowed to see and how a `FETCH` is rendered are exactly the
//! parts worth testing exhaustively, and a socket in the middle only gets in the
//! way. IMAP is *only how a client reads a mailbox that already arrived* — it
//! never affects deliverability — so the ambition here is deliberately narrow:
//! enough of RFC 3501 for a normal mail client (Apple Mail, Thunderbird) to log
//! in, list folders, open one, and read the messages.
//!
//! # Who does what
//!
//! This file never touches the [`crate::store::Maildir`] and never touches a
//! socket. It parses a command and, for anything that needs stored data, returns
//! an [`IAction`] naming the store work the connection layer (`net.rs`) must do.
//! `net.rs` performs that one read/write against the Maildir and hands the
//! result back through a follow-up method ([`ISession::select_result`],
//! [`ISession::fetch_complete`], …) which turns it into the response lines to
//! write. This is the same "state machine decides, driver does the I/O" split
//! the DATA phase of `smtp.rs` uses, and it is what keeps folder visibility and
//! `FETCH` formatting unit-testable without a filesystem.
//!
//! # What is intentionally left out
//!
//! No `APPEND`, no `IDLE`, no server-side search, and no quota. `EXPUNGE` is
//! accepted but performs no deletion, because the store interface this layer
//! targets exposes no remove. Each such limit is noted where it bites.
//!
//! Command literals (`{n}` synchronising and `{n+}` LITERAL+, RFC 7888) *are*
//! supported: Apple Mail sends `LOGIN` credentials and mailbox names as
//! literals — never quoted strings — so an account cannot even be added
//! without them. Literal contents containing CR/LF are refused (no argument a
//! mail client sends contains a line break); see [`ISession::command`].

use crate::address::Address;
use crate::mime;
use crate::submission::decode_plain;
use std::borrow::Cow;
use std::fmt;

/// Largest command line accepted, in bytes. Generous next to SMTP's 512 because
/// a `FETCH` item list with many header-field names is legitimately long; a line
/// past this is refused rather than buffered without bound.
pub const MAX_COMMAND_LINE: usize = 8192;

/// The status of a status response (`OK`/`NO`/`BAD`) or of an unsolicited one
/// (`BYE`/`PREAUTH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The command succeeded.
    Ok,
    /// The command was understood but refused (e.g. bad credentials).
    No,
    /// The command could not be parsed or was issued in the wrong state.
    Bad,
    /// The server is closing the connection.
    Bye,
    /// The connection is pre-authenticated (unused here, kept for completeness).
    PreAuth,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::Ok => "OK",
            Self::No => "NO",
            Self::Bad => "BAD",
            Self::Bye => "BYE",
            Self::PreAuth => "PREAUTH",
        };
        f.write_str(word)
    }
}

/// One response line, ready for the wire.
///
/// Held as raw bytes rather than a `String` because a `FETCH` body literal
/// carries the message verbatim, and a message need not be valid UTF-8. The
/// bytes always include the trailing `CRLF` (and, for a literal, the interior
/// `CRLF` that follows the `{n}` octet count).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IResponse {
    bytes: Vec<u8>,
}

impl IResponse {
    /// A tagged completion line: `<tag> <status> <text>`.
    pub fn tagged(tag: &str, status: Status, text: impl AsRef<str>) -> Self {
        Self::from_line(format!("{tag} {status} {}", text.as_ref()))
    }

    /// An untagged data or status line: `* <text>`.
    pub fn untagged(text: impl AsRef<str>) -> Self {
        Self::from_line(format!("* {}", text.as_ref()))
    }

    /// A command-continuation line: `+ <text>`.
    pub fn cont(text: impl AsRef<str>) -> Self {
        Self::from_line(format!("+ {}", text.as_ref()))
    }

    /// A response carrying pre-built bytes (used for `FETCH` literals). The
    /// caller supplies everything after `* ` and before the terminating `CRLF`.
    fn untagged_bytes(body: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(body.len() + 4);
        bytes.extend_from_slice(b"* ");
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(b"\r\n");
        Self { bytes }
    }

    fn from_line(mut line: String) -> Self {
        line.push_str("\r\n");
        Self { bytes: line.into_bytes() }
    }

    /// The exact bytes to write, terminating `CRLF` included.
    pub fn to_wire(&self) -> &[u8] {
        &self.bytes
    }

    /// A lossy text view, for logging and tests.
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }
}

/// Where in the protocol a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IState {
    /// No successful `LOGIN` yet. Only the always-available commands and the
    /// authentication ones are accepted.
    NotAuthenticated,
    /// Logged in, but no mailbox open.
    Authenticated,
    /// A mailbox is open for reading (and, unless read-only, flag changes).
    Selected,
    /// `LOGOUT` was received; the connection is being closed.
    Logout,
}

/// What the connection layer must do after feeding one command.
///
/// Most commands answer entirely from session state and produce [`Self::Respond`]
/// (or [`Self::Close`]). The rest name a single store operation the driver
/// performs, then feeds back through the matching `*_result` / `*_complete`
/// method to obtain the response lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IAction {
    /// Write these responses and keep reading commands.
    Respond(Vec<IResponse>),
    /// Write the response, complete the TLS handshake, then call
    /// [`ISession::tls_established`]. Only reachable before authentication.
    StartTls(IResponse),
    /// Verify the credentials against the mailbox table, then call
    /// [`ISession::login_result`] with the authenticated address (or `None`).
    Login {
        /// Command tag to answer.
        tag: String,
        /// The login name as sent (usually the full `local@domain`).
        username: String,
        /// The password as sent.
        password: String,
    },
    /// Enumerate the named mailbox in the store, then call
    /// [`ISession::select_result`].
    Select {
        /// Command tag to answer.
        tag: String,
        /// Canonical mailbox name (`INBOX`, `Sent`, …).
        mailbox: String,
        /// True for `EXAMINE` (open read-only), false for `SELECT`.
        read_only: bool,
    },
    /// Read the mailbox summary for a `STATUS` request, then call
    /// [`ISession::status_result`]. Does not change the selected mailbox.
    Status {
        /// Command tag to answer.
        tag: String,
        /// Mailbox the status was requested for.
        mailbox: String,
        /// Which counters the client asked for.
        items: Vec<StatusItem>,
    },
    /// Load the messages named in the plan, then call
    /// [`ISession::fetch_complete`]. If [`FetchPlan::marks_seen`] is true the
    /// driver must also set `\Seen` on those messages before reading them.
    Fetch(FetchPlan),
    /// Apply the flag change to the named messages, read the resulting flags
    /// back, then call [`ISession::store_complete`].
    Store(StorePlan),
    /// Write these responses, then close the connection.
    Close(Vec<IResponse>),
}

/// The counters `STATUS` can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
    /// `MESSAGES` — total count.
    Messages,
    /// `RECENT` — messages with the `\Recent` flag.
    Recent,
    /// `UIDNEXT` — the UID the next delivered message will get.
    UidNext,
    /// `UIDVALIDITY` — the mailbox's UID-validity token.
    UidValidity,
    /// `UNSEEN` — messages without `\Seen`.
    Unseen,
}

/// A message flag this server understands. Client-defined keywords are dropped
/// silently, because the store has nowhere to keep them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// `\Seen` — has been read.
    Seen,
    /// `\Answered` — has been replied to.
    Answered,
    /// `\Flagged` — marked for attention.
    Flagged,
    /// `\Deleted` — marked for removal.
    Deleted,
    /// `\Draft` — an unfinished message.
    Draft,
}

impl Flag {
    /// The wire spelling, backslash included.
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Seen => "\\Seen",
            Self::Answered => "\\Answered",
            Self::Flagged => "\\Flagged",
            Self::Deleted => "\\Deleted",
            Self::Draft => "\\Draft",
        }
    }

    /// Parses one system-flag keyword, case-insensitively. `None` for unknown
    /// or client-defined keywords.
    fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_uppercase().as_str() {
            "\\SEEN" => Some(Self::Seen),
            "\\ANSWERED" => Some(Self::Answered),
            "\\FLAGGED" => Some(Self::Flagged),
            "\\DELETED" => Some(Self::Deleted),
            "\\DRAFT" => Some(Self::Draft),
            _ => None,
        }
    }

    /// Renders a flag set as `(\Seen \Draft)` in the canonical order.
    fn render_set(flags: &[Flag]) -> String {
        let order = [Self::Seen, Self::Answered, Self::Flagged, Self::Deleted, Self::Draft];
        let present: Vec<&str> =
            order.iter().filter(|f| flags.contains(f)).map(|f| f.keyword()).collect();
        format!("({})", present.join(" "))
    }
}

/// How `STORE` changes a message's flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOp {
    /// `FLAGS` — replace the whole set.
    Replace,
    /// `+FLAGS` — add these.
    Add,
    /// `-FLAGS` — remove these.
    Remove,
}

/// One message a `FETCH`/`STORE` names: its sequence number and its UID. The
/// pair is resolved here, against the selected mailbox's view, so the driver
/// never has to translate between the two numbering schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageRef {
    /// 1-based position in the mailbox.
    pub seq: u32,
    /// Stable unique identifier.
    pub uid: u32,
}

/// A parsed `FETCH`, resolved to concrete messages and ready for the driver to
/// load. Interior order is ascending by sequence number, as clients expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchPlan {
    /// Command tag to answer.
    pub tag: String,
    /// True for `UID FETCH` — responses still carry `UID`, and a `*` in the set
    /// meant the largest UID rather than the largest sequence number.
    pub uid_mode: bool,
    /// The messages to fetch.
    pub messages: Vec<MessageRef>,
    /// What to return for each.
    pub items: Vec<FetchItem>,
}

impl FetchPlan {
    /// Whether serving this fetch implicitly marks the messages `\Seen`. True
    /// when a non-peek body is requested; the driver must set the flag before
    /// reading so the returned `FLAGS` reflect it.
    pub fn marks_seen(&self) -> bool {
        self.items.iter().any(|item| {
            matches!(item, FetchItem::Body { peek: false, .. } | FetchItem::Rfc822 | FetchItem::Rfc822Text)
        })
    }
}

/// A parsed `STORE`, resolved to concrete messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePlan {
    /// Command tag to answer.
    pub tag: String,
    /// True for `UID STORE`.
    pub uid_mode: bool,
    /// The messages to change.
    pub messages: Vec<MessageRef>,
    /// Replace, add, or remove.
    pub op: StoreOp,
    /// The flags to apply.
    pub flags: Vec<Flag>,
    /// `.SILENT` — apply the change but send no `FETCH` echo back.
    pub silent: bool,
}

/// One item of a `FETCH` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    /// `UID`.
    Uid,
    /// `FLAGS`.
    Flags,
    /// `INTERNALDATE`.
    InternalDate,
    /// `RFC822.SIZE`.
    Rfc822Size,
    /// `ENVELOPE` — the parsed header summary.
    Envelope,
    /// `BODY[section]` or `BODY.PEEK[section]`, with an optional partial range.
    Body {
        /// Which part of the message.
        section: Section,
        /// True for `.PEEK` — reading must not set `\Seen`.
        peek: bool,
        /// `<offset.length>` when a substring was requested.
        partial: Option<(u32, Option<u32>)>,
    },
    /// `BODY` / `BODYSTRUCTURE` — the message's parsed MIME structure.
    /// `extended` picks the response key: `BODYSTRUCTURE` when true, `BODY`
    /// when false (both render the same non-extension form).
    BodyStructure {
        /// True for the `BODYSTRUCTURE` spelling of the request.
        extended: bool,
    },
    /// `RFC822` — equivalent to `BODY[]`, but with the `RFC822` response key.
    Rfc822,
    /// `RFC822.HEADER` — equivalent to `BODY.PEEK[HEADER]`.
    Rfc822Header,
    /// `RFC822.TEXT` — equivalent to `BODY[TEXT]`.
    Rfc822Text,
}

/// A body section a `BODY[...]` can name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    /// `[]` — the whole message.
    Full,
    /// `[HEADER]` — all header fields plus the blank separator line.
    Header,
    /// `[TEXT]` — everything after the header block.
    Text,
    /// `[HEADER.FIELDS (...)]` — only the named header fields.
    HeaderFields(Vec<String>),
    /// `[HEADER.FIELDS.NOT (...)]` — every header field except the named ones.
    HeaderFieldsNot(Vec<String>),
    /// `[1.2]`, `[1.MIME]`, … — one MIME part, addressed by its 1-based path,
    /// with an optional sub-target (`MIME`/`HEADER`/`TEXT`) after the numbers.
    Part {
        /// The numeric part path, one index per nesting level.
        path: Vec<u32>,
        /// Which bytes of the addressed part.
        target: mime::Target,
    },
}

impl Section {
    /// The wire spelling inside the brackets.
    fn wire(&self) -> String {
        match self {
            Self::Full => String::new(),
            Self::Header => "HEADER".into(),
            Self::Text => "TEXT".into(),
            Self::HeaderFields(fields) => format!("HEADER.FIELDS ({})", fields.join(" ")),
            Self::HeaderFieldsNot(fields) => format!("HEADER.FIELDS.NOT ({})", fields.join(" ")),
            Self::Part { path, target } => {
                let numbers =
                    path.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
                let suffix = match target {
                    mime::Target::Content => "",
                    mime::Target::Mime => ".MIME",
                    mime::Target::Header => ".HEADER",
                    mime::Target::Text => ".TEXT",
                };
                format!("{numbers}{suffix}")
            }
        }
    }
}

/// Everything the driver learned about a mailbox by enumerating it, handed to
/// [`ISession::select_result`] / [`ISession::status_result`]. Keeping this a
/// plain record here is what lets the state machine depend on no store type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectData {
    /// Every UID in the mailbox, ascending. Position + 1 is the sequence number.
    pub uids: Vec<u32>,
    /// The mailbox's UID-validity token; a change tells the client its cached
    /// UIDs are stale.
    pub uid_validity: u32,
    /// The UID the next delivered message will receive.
    pub uid_next: u32,
    /// How many messages carry `\Recent`.
    pub recent: u32,
    /// Sequence number of the first message without `\Seen`, if any.
    pub first_unseen: Option<u32>,
    /// How many messages lack `\Seen`.
    pub unseen_count: u32,
}

/// One message as the store hands it to a `FETCH`/`STORE` response. The driver
/// builds it from a stored message and its flags; formatting reads only this,
/// never the store, so it stays testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageData {
    /// The message's UID.
    pub uid: u32,
    /// Its current flags.
    pub flags: Vec<Flag>,
    /// `INTERNALDATE` value, already formatted (e.g. `07-Aug-2026 12:00:00 +0000`).
    pub internal_date: String,
    /// The full RFC 5322 bytes (CRLF line endings), as stored.
    pub raw: Vec<u8>,
}

/// How this IMAP server is configured to answer.
#[derive(Debug, Clone)]
pub struct IConfig {
    /// Our own hostname, named in the greeting.
    pub hostname: String,
    /// Whether `STARTTLS` can be offered (a `:993` listener sets this and marks
    /// TLS already active before the greeting).
    pub tls_available: bool,
    /// Refuse `LOGIN` until the connection is encrypted. True in production:
    /// `LOGIN` sends the password in the clear.
    pub require_tls_for_auth: bool,
}

impl Default for IConfig {
    fn default() -> Self {
        Self { hostname: "localhost".into(), tls_available: false, require_tls_for_auth: true }
    }
}

/// The selected mailbox's view: the mapping from sequence number to UID that
/// every `FETCH`/`STORE` in this mailbox is resolved against.
#[derive(Debug, Clone)]
struct Mailbox {
    name: String,
    uids: Vec<u32>,
    read_only: bool,
}

/// One IMAP conversation.
#[derive(Debug)]
pub struct ISession {
    config: IConfig,
    state: IState,
    tls_active: bool,
    user: Option<Address>,
    mailbox: Option<Mailbox>,
    /// The tag of an `AUTHENTICATE PLAIN` awaiting its SASL response: the next
    /// line fed to [`ISession::command`] is that response, not a command.
    pending_auth: Option<String>,
    /// A command paused mid-assembly awaiting literal octets (see
    /// [`ISession::command`]): the text assembled so far, with each completed
    /// literal re-quoted, and the octet count the next line must begin with.
    pending_literal: Option<PendingLiteral>,
}

/// The in-progress state of a command whose next argument arrives as a
/// `{n}`/`{n+}` literal on a following line.
#[derive(Debug)]
struct PendingLiteral {
    /// The command text before the literal marker, completed literals already
    /// folded back in as quoted strings.
    assembled: String,
    /// How many octets the literal announced.
    expected: usize,
}

impl ISession {
    /// Starts a session. The caller sends [`ISession::greeting`] first, then,
    /// on a `:993` implicit-TLS listener, [`ISession::tls_established`] before
    /// the first command.
    pub fn new(config: IConfig) -> Self {
        let tls_active = false;
        Self {
            config,
            state: IState::NotAuthenticated,
            tls_active,
            user: None,
            mailbox: None,
            pending_auth: None,
            pending_literal: None,
        }
    }

    /// The banner sent as soon as the connection opens.
    pub fn greeting(&self) -> IResponse {
        IResponse::untagged(format!(
            "OK [CAPABILITY {}] {} selfhost IMAP ready",
            self.capabilities().join(" "),
            self.config.hostname
        ))
    }

    /// The current protocol state.
    pub fn state(&self) -> IState {
        self.state
    }

    /// Whether the connection is encrypted.
    pub fn tls_active(&self) -> bool {
        self.tls_active
    }

    /// The authenticated mailbox owner, once `LOGIN` has succeeded.
    pub fn user(&self) -> Option<&Address> {
        self.user.as_ref()
    }

    /// The name of the currently selected mailbox, if any. The driver reads it
    /// to route a `FETCH`/`STORE` to the right store folder for the [`user`].
    ///
    /// [`user`]: Self::user
    pub fn selected_mailbox(&self) -> Option<&str> {
        self.mailbox.as_ref().map(|m| m.name.as_str())
    }

    /// Records that TLS is now in effect (after a `STARTTLS` handshake, or
    /// immediately on a `:993` listener).
    pub fn tls_established(&mut self) {
        self.tls_active = true;
    }

    /// Whether the next line fed to [`ISession::command`] is a SASL secret
    /// (the response to a continued `AUTHENTICATE`) rather than a command.
    /// A driver that logs traffic must consult this first: that line is
    /// nothing but base64-wrapped credentials.
    pub fn awaiting_secret(&self) -> bool {
        self.pending_auth.is_some()
    }

    /// Whether the next line fed to [`ISession::command`] begins with literal
    /// octets rather than a fresh command. A driver that logs traffic must
    /// consult this too: a `LOGIN` literal line is the password itself, and an
    /// empty line can be legitimate input (a zero-length literal).
    pub fn awaiting_literal(&self) -> bool {
        self.pending_literal.is_some()
    }

    /// The capabilities advertised in the current state.
    fn capabilities(&self) -> Vec<String> {
        // LITERAL+ (RFC 7888) is advertised unconditionally: literal handling
        // has no protocol state, and clients decide from the greeting whether
        // they may stream `{n+}` literals without waiting for continuations.
        let mut caps = vec!["IMAP4rev1".to_string(), "ID".to_string(), "LITERAL+".to_string()];
        if self.state == IState::NotAuthenticated {
            if self.config.tls_available && !self.tls_active {
                caps.push("STARTTLS".into());
            }
            if self.config.require_tls_for_auth && !self.tls_active {
                // Tells the client not to try LOGIN yet — the password would
                // travel in the clear.
                caps.push("LOGINDISABLED".into());
            } else {
                // Advertised only once credentials may actually be sent. This
                // is what Apple Mail and friends key on: a server offering no
                // AUTH= mechanism reads as "cannot verify", regardless of
                // whether bare LOGIN would have worked.
                caps.push("AUTH=PLAIN".into());
                caps.push("SASL-IR".into());
            }
        }
        caps
    }

    /// Feeds one command line and returns what to do next.
    ///
    /// A line may not be a whole command: an argument sent as a literal
    /// (`{n}`/`{n+}`) splits the command across lines. Assembly happens here —
    /// literal contents are folded back into the command as quoted strings, so
    /// the per-command parsers see one uniform syntax — and a synchronising
    /// literal is answered with the `+` continuation the client is waiting on.
    /// Literal contents containing CR/LF are refused with a `BAD`: octet
    /// counting across the driver's line reads would be required to honour
    /// them, and no argument a mail client sends contains a line break.
    pub fn command(&mut self, line: &str) -> IAction {
        if line.len() > MAX_COMMAND_LINE {
            // No tag is reliably parseable from an over-long line, so this is an
            // untagged protocol error rather than a tagged failure.
            return respond(IResponse::untagged("BAD command line too long"));
        }

        // A pending AUTHENTICATE owns the next line outright: it is the SASL
        // response (or `*` to abort), never a command.
        if let Some(tag) = self.pending_auth.take() {
            return self.authenticate_response(&tag, line);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);

        // A pending literal owns the head of this line: the announced octet
        // count is consumed as the literal's contents and the remainder
        // continues the command.
        let logical = match self.pending_literal.take() {
            Some(pending) => match fold_literal(pending, trimmed) {
                Ok(assembled) => assembled,
                Err(response) => return respond(response),
            },
            None => trimmed.to_owned(),
        };

        match split_trailing_literal(&logical) {
            // The command wants octets that have not arrived yet: hold what is
            // assembled and, for a synchronising literal, invite the rest. A
            // LITERAL+ client has already sent it, so nothing is written.
            Some((prefix, expected, synchronizing)) => {
                if prefix.len() + expected > MAX_COMMAND_LINE {
                    return respond(refuse_literal(&logical));
                }
                self.pending_literal =
                    Some(PendingLiteral { assembled: prefix.to_owned(), expected });
                if synchronizing {
                    respond(IResponse::cont("Ready for literal"))
                } else {
                    IAction::Respond(Vec::new())
                }
            }
            None => self.dispatch(&logical),
        }
    }

    /// Parses and executes one fully-assembled command line.
    fn dispatch(&mut self, trimmed: &str) -> IAction {
        let (tag, remainder) = match trimmed.split_once(' ') {
            Some((tag, rest)) => (tag.trim(), rest.trim_start()),
            None => (trimmed.trim(), ""),
        };
        if tag.is_empty() {
            return respond(IResponse::untagged("BAD empty command"));
        }

        let (verb, args) = match remainder.split_once(' ') {
            Some((verb, rest)) => (verb, rest.trim_start()),
            None => (remainder, ""),
        };

        match verb.to_ascii_uppercase().as_str() {
            "" => respond(IResponse::tagged(tag, Status::Bad, "missing command")),
            "CAPABILITY" => self.capability(tag),
            // RFC 2971: the client introduces itself (Apple Mail always does,
            // first thing). `NIL` declines to identify ourselves back — the
            // point is a polite `OK`, because a `BAD` here reads as a broken
            // server to exactly the clients that send it.
            "ID" => respond_all(vec![
                IResponse::untagged("ID NIL"),
                IResponse::tagged(tag, Status::Ok, "ID completed"),
            ]),
            "NOOP" => respond(IResponse::tagged(tag, Status::Ok, "NOOP completed")),
            "LOGOUT" => self.logout(tag),
            "STARTTLS" => self.starttls(tag),
            "LOGIN" => self.login(tag, args),
            "AUTHENTICATE" => self.authenticate(tag, args),
            "SELECT" => self.select(tag, args, false),
            "EXAMINE" => self.select(tag, args, true),
            "LIST" => self.list(tag, args, false),
            "LSUB" => self.list(tag, args, true),
            "STATUS" => self.status(tag, args),
            "FETCH" => self.fetch(tag, args, false),
            "STORE" => self.store(tag, args, false),
            "CHECK" => self.require_selected(tag).unwrap_or_else(|| {
                respond(IResponse::tagged(tag, Status::Ok, "CHECK completed"))
            }),
            "CLOSE" => self.close_mailbox(tag),
            "EXPUNGE" => self.expunge(tag),
            "UID" => self.uid(tag, args),
            other => respond(IResponse::tagged(
                tag,
                Status::Bad,
                format!("command {other} not implemented"),
            )),
        }
    }

    /// Handles `CAPABILITY`.
    fn capability(&self, tag: &str) -> IAction {
        respond_all(vec![
            IResponse::untagged(format!("CAPABILITY {}", self.capabilities().join(" "))),
            IResponse::tagged(tag, Status::Ok, "CAPABILITY completed"),
        ])
    }

    /// Handles `LOGOUT`.
    fn logout(&mut self, tag: &str) -> IAction {
        self.state = IState::Logout;
        IAction::Close(vec![
            IResponse::untagged("BYE selfhost IMAP signing off"),
            IResponse::tagged(tag, Status::Ok, "LOGOUT completed"),
        ])
    }

    /// Handles `STARTTLS`.
    fn starttls(&mut self, tag: &str) -> IAction {
        if self.state != IState::NotAuthenticated {
            return respond(IResponse::tagged(tag, Status::Bad, "STARTTLS only before login"));
        }
        if !self.config.tls_available {
            return respond(IResponse::tagged(tag, Status::No, "TLS not available"));
        }
        if self.tls_active {
            return respond(IResponse::tagged(tag, Status::No, "TLS already active"));
        }
        IAction::StartTls(IResponse::tagged(tag, Status::Ok, "begin TLS negotiation now"))
    }

    /// Handles `AUTHENTICATE <mechanism> [initial-response]` (RFC 3501 §6.2.2,
    /// initial response per RFC 4959's `SASL-IR`).
    ///
    /// `PLAIN` is the one mechanism served — it is what every mainstream client
    /// sends over TLS, and the TLS gate below is the same one `LOGIN` stands
    /// behind, so the password crosses only an encrypted link. Without the
    /// initial response the client is sent a `+` continuation and the next
    /// line is consumed as the SASL response (see [`ISession::command`]).
    fn authenticate(&mut self, tag: &str, args: &str) -> IAction {
        if self.state != IState::NotAuthenticated {
            return respond(IResponse::tagged(tag, Status::Bad, "already authenticated"));
        }
        if self.config.require_tls_for_auth && !self.tls_active {
            return respond(IResponse::tagged(
                tag,
                Status::No,
                "[PRIVACYREQUIRED] STARTTLS before AUTHENTICATE",
            ));
        }
        let (mechanism, initial) = match args.split_once(' ') {
            Some((mechanism, rest)) => (mechanism, Some(rest.trim())),
            None => (args, None),
        };
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            return respond(IResponse::tagged(
                tag,
                Status::No,
                "unsupported authentication mechanism; use PLAIN",
            ));
        }
        match initial {
            // RFC 4959: a lone `=` is how a zero-length initial response is spelled.
            Some(response) => self.plain_credentials(tag, if response == "=" { "" } else { response }),
            None => {
                self.pending_auth = Some(tag.to_owned());
                respond(IResponse::cont(""))
            }
        }
    }

    /// Consumes the line following a continued `AUTHENTICATE PLAIN`: the SASL
    /// response, or `*`, the client's abort (RFC 3501 §6.2.2).
    fn authenticate_response(&mut self, tag: &str, line: &str) -> IAction {
        let response = line.trim();
        if response == "*" {
            return respond(IResponse::tagged(tag, Status::Bad, "AUTHENTICATE aborted"));
        }
        self.plain_credentials(tag, response)
    }

    /// Turns a SASL PLAIN response into the driver's credential check, sharing
    /// [`IAction::Login`] — and therefore the one verification path — with the
    /// `LOGIN` command.
    fn plain_credentials(&self, tag: &str, response: &str) -> IAction {
        match decode_plain(response) {
            Some((username, password)) => IAction::Login { tag: tag.to_owned(), username, password },
            None => respond(IResponse::tagged(tag, Status::Bad, "invalid SASL PLAIN response")),
        }
    }

    /// Handles `LOGIN <user> <pass>`.
    fn login(&mut self, tag: &str, args: &str) -> IAction {
        if self.state != IState::NotAuthenticated {
            return respond(IResponse::tagged(tag, Status::Bad, "already authenticated"));
        }
        if self.config.require_tls_for_auth && !self.tls_active {
            // Refusing rather than accepting keeps the password off a cleartext
            // link — LOGIN sends it verbatim.
            return respond(IResponse::tagged(
                tag,
                Status::No,
                "[PRIVACYREQUIRED] STARTTLS before LOGIN",
            ));
        }
        let Some((username, rest)) = next_arg(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "LOGIN requires a username"));
        };
        let Some((password, _)) = next_arg(rest) else {
            return respond(IResponse::tagged(tag, Status::Bad, "LOGIN requires a password"));
        };
        IAction::Login { tag: tag.to_owned(), username, password }
    }

    /// Completes a `LOGIN` once the driver has verified the credentials.
    /// `Some(address)` authenticates the session; `None` fails it.
    pub fn login_result(&mut self, tag: &str, authenticated: Option<Address>) -> Vec<IResponse> {
        match authenticated {
            Some(address) => {
                self.user = Some(address);
                self.state = IState::Authenticated;
                vec![IResponse::tagged(
                    tag,
                    Status::Ok,
                    format!("[CAPABILITY {}] LOGIN completed", self.capabilities().join(" ")),
                )]
            }
            None => {
                vec![IResponse::tagged(tag, Status::No, "authentication failed")]
            }
        }
    }

    /// Handles `SELECT`/`EXAMINE <mailbox>`.
    fn select(&mut self, tag: &str, args: &str, read_only: bool) -> IAction {
        if let Some(denied) = self.require_authenticated(tag) {
            return denied;
        }
        let Some((raw_name, _)) = next_arg(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "SELECT requires a mailbox"));
        };
        // A prior selection is dropped the moment a new SELECT is issued, even
        // if the new one turns out not to exist.
        self.mailbox = None;
        self.state = IState::Authenticated;
        IAction::Select { tag: tag.to_owned(), mailbox: canonical_mailbox(&raw_name), read_only }
    }

    /// Completes a `SELECT`/`EXAMINE` once the driver has enumerated the
    /// mailbox, installing the sequence-to-UID view the mailbox's later
    /// `FETCH`/`STORE` commands resolve against.
    pub fn select_result(
        &mut self,
        tag: &str,
        mailbox: &str,
        read_only: bool,
        data: SelectData,
    ) -> Vec<IResponse> {
        let existing = data.uids.len() as u32;
        self.mailbox =
            Some(Mailbox { name: mailbox.to_owned(), uids: data.uids, read_only });
        self.state = IState::Selected;

        let all = "\\Answered \\Flagged \\Deleted \\Seen \\Draft";
        let mut out = vec![
            IResponse::untagged(format!("FLAGS ({all})")),
            IResponse::untagged(format!("{existing} EXISTS")),
            IResponse::untagged(format!("{} RECENT", data.recent)),
            IResponse::untagged(format!("OK [UIDVALIDITY {}] validity", data.uid_validity)),
            IResponse::untagged(format!("OK [UIDNEXT {}] next uid", data.uid_next)),
        ];
        if let Some(seq) = data.first_unseen {
            out.push(IResponse::untagged(format!("OK [UNSEEN {seq}] first unseen")));
        }
        let permanent = if read_only { String::new() } else { all.to_string() };
        out.push(IResponse::untagged(format!("OK [PERMANENTFLAGS ({permanent})] limits")));

        let (code, verb) =
            if read_only { ("READ-ONLY", "EXAMINE") } else { ("READ-WRITE", "SELECT") };
        out.push(IResponse::tagged(tag, Status::Ok, format!("[{code}] {verb} completed")));
        out
    }

    /// Handles `LIST`/`LSUB <reference> <pattern>` from the fixed folder set.
    ///
    /// The folders are the standard Maildir set rather than a live directory
    /// scan: this server stores mail in exactly these, so listing them needs no
    /// store round-trip.
    fn list(&self, tag: &str, args: &str, subscribed: bool) -> IAction {
        if let Some(denied) = self.require_authenticated(tag) {
            return denied;
        }
        let verb = if subscribed { "LSUB" } else { "LIST" };
        let Some((_reference, rest)) = next_arg(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "LIST requires two arguments"));
        };
        let Some((pattern, _)) = next_arg(rest) else {
            return respond(IResponse::tagged(tag, Status::Bad, "LIST requires a pattern"));
        };

        let mut out = Vec::new();
        // The empty pattern is a request for the hierarchy delimiter only.
        if pattern.is_empty() {
            out.push(IResponse::untagged(format!("{verb} (\\Noselect) \"/\" \"\"")));
        } else {
            for (name, attr) in FOLDERS {
                if pattern_matches(&pattern, name) {
                    out.push(IResponse::untagged(format!(
                        "{verb} ({attr}\\HasNoChildren) \"/\" \"{name}\""
                    )));
                }
            }
        }
        out.push(IResponse::tagged(tag, Status::Ok, format!("{verb} completed")));
        respond_all(out)
    }

    /// Handles `STATUS <mailbox> (<items>)`.
    fn status(&self, tag: &str, args: &str) -> IAction {
        if let Some(denied) = self.require_authenticated(tag) {
            return denied;
        }
        let Some((raw_name, rest)) = next_arg(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "STATUS requires a mailbox"));
        };
        let inside = between(rest, '(', ')').unwrap_or(rest.trim());
        let mut items = Vec::new();
        for token in inside.split_whitespace() {
            match token.to_ascii_uppercase().as_str() {
                "MESSAGES" => items.push(StatusItem::Messages),
                "RECENT" => items.push(StatusItem::Recent),
                "UIDNEXT" => items.push(StatusItem::UidNext),
                "UIDVALIDITY" => items.push(StatusItem::UidValidity),
                "UNSEEN" => items.push(StatusItem::Unseen),
                other => {
                    return respond(IResponse::tagged(
                        tag,
                        Status::Bad,
                        format!("unknown STATUS item {other}"),
                    ));
                }
            }
        }
        IAction::Status { tag: tag.to_owned(), mailbox: canonical_mailbox(&raw_name), items }
    }

    /// Completes a `STATUS` once the driver has read the mailbox summary.
    pub fn status_result(
        &self,
        tag: &str,
        mailbox: &str,
        items: &[StatusItem],
        data: &SelectData,
    ) -> Vec<IResponse> {
        let rendered: Vec<String> = items
            .iter()
            .map(|item| match item {
                StatusItem::Messages => format!("MESSAGES {}", data.uids.len()),
                StatusItem::Recent => format!("RECENT {}", data.recent),
                StatusItem::UidNext => format!("UIDNEXT {}", data.uid_next),
                StatusItem::UidValidity => format!("UIDVALIDITY {}", data.uid_validity),
                StatusItem::Unseen => format!("UNSEEN {}", data.unseen_count),
            })
            .collect();
        vec![
            IResponse::untagged(format!("STATUS \"{mailbox}\" ({})", rendered.join(" "))),
            IResponse::tagged(tag, Status::Ok, "STATUS completed"),
        ]
    }

    /// Handles `FETCH <set> <items>` (and, via [`Self::uid`], `UID FETCH`).
    fn fetch(&self, tag: &str, args: &str, uid_mode: bool) -> IAction {
        let Some(mailbox) = self.mailbox.as_ref() else {
            return self
                .require_selected(tag)
                .unwrap_or_else(|| respond(IResponse::tagged(tag, Status::Bad, "no mailbox")));
        };
        let Some((set, rest)) = split_first_token(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "FETCH requires a set and items"));
        };
        let Some(messages) = resolve_set(&set, &mailbox.uids, uid_mode) else {
            return respond(IResponse::tagged(tag, Status::Bad, "malformed sequence set"));
        };
        let mut items = match parse_fetch_items(rest) {
            Some(items) => items,
            None => return respond(IResponse::tagged(tag, Status::Bad, "malformed FETCH items")),
        };
        // A UID FETCH response must always carry the UID, whether or not the
        // client listed it — the client keyed its request on UIDs.
        if uid_mode && !items.contains(&FetchItem::Uid) {
            items.insert(0, FetchItem::Uid);
        }
        IAction::Fetch(FetchPlan { tag: tag.to_owned(), uid_mode, messages, items })
    }

    /// Completes a `FETCH` once the driver has loaded the messages. Pure
    /// formatting: it reads only the supplied data, so a message the driver
    /// could not load is simply skipped rather than aborting the response.
    pub fn fetch_complete(&self, plan: &FetchPlan, loaded: &[MessageData]) -> Vec<IResponse> {
        let mut out = Vec::new();
        for target in &plan.messages {
            let Some(data) = loaded.iter().find(|m| m.uid == target.uid) else {
                continue;
            };
            out.push(render_fetch(target.seq, &plan.items, data));
        }
        out.push(IResponse::tagged(&plan.tag, Status::Ok, "FETCH completed"));
        out
    }

    /// Handles `STORE <set> <op> <flags>` (and, via [`Self::uid`], `UID STORE`).
    fn store(&self, tag: &str, args: &str, uid_mode: bool) -> IAction {
        let Some(mailbox) = self.mailbox.as_ref() else {
            return self
                .require_selected(tag)
                .unwrap_or_else(|| respond(IResponse::tagged(tag, Status::Bad, "no mailbox")));
        };
        if mailbox.read_only {
            return respond(IResponse::tagged(tag, Status::No, "mailbox is read-only"));
        }
        let Some((set, rest)) = split_first_token(args) else {
            return respond(IResponse::tagged(tag, Status::Bad, "STORE requires a set"));
        };
        let Some((op_token, flag_rest)) = split_first_token(rest) else {
            return respond(IResponse::tagged(tag, Status::Bad, "STORE requires an operation"));
        };
        let Some(messages) = resolve_set(&set, &mailbox.uids, uid_mode) else {
            return respond(IResponse::tagged(tag, Status::Bad, "malformed sequence set"));
        };

        let upper = op_token.to_ascii_uppercase();
        let silent = upper.ends_with(".SILENT");
        let (op, keyword) = match upper.trim_end_matches(".SILENT") {
            "FLAGS" => (StoreOp::Replace, "FLAGS"),
            "+FLAGS" => (StoreOp::Add, "+FLAGS"),
            "-FLAGS" => (StoreOp::Remove, "-FLAGS"),
            other => {
                return respond(IResponse::tagged(
                    tag,
                    Status::Bad,
                    format!("unknown STORE operation {other}"),
                ));
            }
        };
        let _ = keyword;
        let inside = between(flag_rest, '(', ')').unwrap_or(flag_rest.trim());
        let flags: Vec<Flag> = inside.split_whitespace().filter_map(Flag::parse).collect();

        IAction::Store(StorePlan {
            tag: tag.to_owned(),
            uid_mode,
            messages,
            op,
            flags,
            silent,
        })
    }

    /// Completes a `STORE` once the driver has applied the change and read the
    /// resulting flags back. Unless `.SILENT` was given, each message's new
    /// flags are echoed as an untagged `FETCH`.
    pub fn store_complete(&self, plan: &StorePlan, updated: &[MessageData]) -> Vec<IResponse> {
        let mut out = Vec::new();
        if !plan.silent {
            for target in &plan.messages {
                let Some(data) = updated.iter().find(|m| m.uid == target.uid) else {
                    continue;
                };
                let items = if plan.uid_mode {
                    vec![FetchItem::Flags, FetchItem::Uid]
                } else {
                    vec![FetchItem::Flags]
                };
                out.push(render_fetch(target.seq, &items, data));
            }
        }
        out.push(IResponse::tagged(&plan.tag, Status::Ok, "STORE completed"));
        out
    }

    /// Handles the `UID` prefix: `UID FETCH` / `UID STORE`.
    fn uid(&self, tag: &str, args: &str) -> IAction {
        if let Some(denied) = self.require_selected(tag) {
            return denied;
        }
        let (sub, rest) = match args.split_once(' ') {
            Some((sub, rest)) => (sub, rest.trim_start()),
            None => (args, ""),
        };
        match sub.to_ascii_uppercase().as_str() {
            "FETCH" => self.fetch(tag, rest, true),
            "STORE" => self.store(tag, rest, true),
            other => respond(IResponse::tagged(
                tag,
                Status::Bad,
                format!("UID {other} not supported"),
            )),
        }
    }

    /// Handles `CLOSE` — leave the mailbox and return to the authenticated
    /// state. No expunge is performed (see the module note on deletion).
    fn close_mailbox(&mut self, tag: &str) -> IAction {
        if let Some(denied) = self.require_selected(tag) {
            return denied;
        }
        self.mailbox = None;
        self.state = IState::Authenticated;
        respond(IResponse::tagged(tag, Status::Ok, "CLOSE completed"))
    }

    /// Handles `EXPUNGE`. Accepted so clients do not error, but this server does
    /// not delete: the store interface it targets exposes no removal, so
    /// `\Deleted` messages remain. Reported honestly as a no-op completion.
    fn expunge(&self, tag: &str) -> IAction {
        if let Some(denied) = self.require_selected(tag) {
            return denied;
        }
        respond(IResponse::tagged(tag, Status::Ok, "EXPUNGE completed (no deletion performed)"))
    }

    /// Refuses a command that needs authentication, returning the refusal when
    /// the session has not logged in.
    fn require_authenticated(&self, tag: &str) -> Option<IAction> {
        match self.state {
            IState::NotAuthenticated => {
                Some(respond(IResponse::tagged(tag, Status::No, "authenticate first")))
            }
            _ => None,
        }
    }

    /// Refuses a command that needs a selected mailbox.
    fn require_selected(&self, tag: &str) -> Option<IAction> {
        match self.state {
            IState::Selected => None,
            IState::NotAuthenticated => {
                Some(respond(IResponse::tagged(tag, Status::No, "authenticate first")))
            }
            _ => Some(respond(IResponse::tagged(tag, Status::Bad, "no mailbox selected"))),
        }
    }
}

/// The mailboxes this server presents, with any RFC 6154 special-use attribute.
const FOLDERS: &[(&str, &str)] = &[
    ("INBOX", ""),
    ("Sent", "\\Sent "),
    ("Drafts", "\\Drafts "),
    ("Trash", "\\Trash "),
    ("Junk", "\\Junk "),
];

/// Wraps a single response as [`IAction::Respond`].
fn respond(response: IResponse) -> IAction {
    IAction::Respond(vec![response])
}

/// Wraps several responses as [`IAction::Respond`].
fn respond_all(responses: Vec<IResponse>) -> IAction {
    IAction::Respond(responses)
}

/// Normalises a mailbox name: `INBOX` is case-insensitive, everything else is
/// taken verbatim (quotes already stripped by [`next_arg`]).
fn canonical_mailbox(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") { "INBOX".to_string() } else { name.to_string() }
}

/// Matches an IMAP `LIST` pattern against a folder name. `*` and `%` both match
/// any run of characters here (this flat hierarchy has no children to
/// distinguish them); an exact pattern matches case-insensitively.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" || pattern == "%" {
        return true;
    }
    pattern.eq_ignore_ascii_case(name)
}

/// Splits a command line ending in a literal marker into the text before the
/// marker, the announced octet count, and whether the literal synchronises
/// (`{n}` — the client waits for `+`) or not (`{n+}`, RFC 7888 LITERAL+).
///
/// The marker must follow a space, as the grammar requires: a `}` inside a
/// quoted string cannot end the line (a quoted argument ends with `"`), so a
/// trailing `sp {digits[+]}` is unambiguously a literal announcement.
fn split_trailing_literal(line: &str) -> Option<(&str, usize, bool)> {
    let body = line.strip_suffix('}')?;
    let open = body.rfind('{')?;
    if open == 0 || !body[..open].ends_with(' ') {
        return None;
    }
    let count = &body[open + 1..];
    let (digits, synchronizing) = match count.strip_suffix('+') {
        Some(digits) => (digits, false),
        None => (count, true),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let expected = digits.parse().ok()?;
    Some((&line[..open], expected, synchronizing))
}

/// Consumes a pending literal's octets from the head of `line`, re-quoting them
/// into the assembled command, and returns the full logical line so far.
///
/// Errs with the `BAD` to send when the line is shorter than the announced
/// count (the literal contains CR/LF, which this server refuses) or the count
/// lands mid-way through a multi-byte character.
fn fold_literal(pending: PendingLiteral, line: &str) -> Result<String, IResponse> {
    if line.len() < pending.expected || !line.is_char_boundary(pending.expected) {
        return Err(IResponse::untagged(
            "BAD literal shorter than announced or split mid-character; \
             literals containing CR/LF are not supported",
        ));
    }
    let (contents, rest) = line.split_at(pending.expected);
    let mut assembled = pending.assembled;
    assembled.push_str(&quote_argument(contents));
    assembled.push_str(rest);
    Ok(assembled)
}

/// Renders an argument as an IMAP quoted string, escaping `\` and `"` so
/// [`next_arg`] reproduces the exact octets a literal carried.
fn quote_argument(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        if ch == '\\' || ch == '"' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

/// The refusal for a literal that would grow the command past
/// [`MAX_COMMAND_LINE`]: tagged when the command's tag is parseable, untagged
/// otherwise, so the client can match the failure to its command.
fn refuse_literal(line: &str) -> IResponse {
    match line.split_whitespace().next() {
        Some(tag) => IResponse::tagged(tag, Status::Bad, "literal too large"),
        None => IResponse::untagged("BAD literal too large"),
    }
}

/// Reads the next `astring` argument: a `"quoted"` string (with `\` escapes) or
/// a bare atom up to the next space. Returns the value and the unconsumed rest.
/// Command literals never reach here: [`ISession::command`] folds them into
/// quoted strings during assembly, so a `{` yields `None` as malformed input.
fn next_arg(input: &str) -> Option<(String, &str)> {
    let text = input.trim_start();
    if text.is_empty() {
        return None;
    }
    if let Some(after_quote) = text.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = after_quote.char_indices();
        while let Some((index, ch)) = chars.next() {
            match ch {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        value.push(escaped);
                    }
                }
                '"' => {
                    let rest = &after_quote[index + 1..];
                    return Some((value, rest.trim_start()));
                }
                _ => value.push(ch),
            }
        }
        // Unterminated quote.
        None
    } else if text.starts_with('{') {
        // A synchronising literal — unsupported.
        None
    } else {
        let end = text.find(' ').unwrap_or(text.len());
        Some((text[..end].to_string(), text[end..].trim_start()))
    }
}

/// Splits off the first whitespace-delimited token, returning it and the rest.
fn split_first_token(input: &str) -> Option<(String, &str)> {
    let text = input.trim_start();
    if text.is_empty() {
        return None;
    }
    let end = text.find(' ').unwrap_or(text.len());
    Some((text[..end].to_string(), text[end..].trim_start()))
}

/// Returns the substring between the first `open` and the last `close`, trimmed.
fn between(input: &str, open: char, close: char) -> Option<&str> {
    let start = input.find(open)?;
    let end = input.rfind(close)?;
    if end <= start {
        return None;
    }
    Some(input[start + 1..end].trim())
}

/// Resolves a sequence-set (or UID-set) string to concrete messages, ascending
/// and de-duplicated. `uids` is the mailbox's ascending UID list. In UID mode
/// the set is read as UIDs and `*` is the largest UID; otherwise it is read as
/// 1-based positions and `*` is the message count. Values outside the mailbox
/// are dropped (a fetch of a nonexistent message is not an error). `None` only
/// on a syntactically malformed set.
fn resolve_set(spec: &str, uids: &[u32], uid_mode: bool) -> Option<Vec<MessageRef>> {
    let count = uids.len() as u32;
    let max = if uid_mode { uids.last().copied().unwrap_or(0) } else { count };

    let mut wanted: Vec<u32> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (lo, hi) = match part.split_once(':') {
            Some((a, b)) => (parse_point(a, max)?, parse_point(b, max)?),
            None => {
                let point = parse_point(part, max)?;
                (point, point)
            }
        };
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        for value in lo..=hi {
            if value != 0 {
                wanted.push(value);
            }
        }
    }

    let mut refs: Vec<MessageRef> = Vec::new();
    for value in wanted {
        let found = if uid_mode {
            uids.iter().position(|u| *u == value).map(|idx| MessageRef {
                seq: idx as u32 + 1,
                uid: value,
            })
        } else if value >= 1 && value <= count {
            Some(MessageRef { seq: value, uid: uids[(value - 1) as usize] })
        } else {
            None
        };
        if let Some(message) = found {
            if !refs.iter().any(|r| r.uid == message.uid) {
                refs.push(message);
            }
        }
    }
    refs.sort_by_key(|r| r.seq);
    Some(refs)
}

/// Parses one endpoint of a set: a positive integer, or `*` for the maximum.
fn parse_point(token: &str, max: u32) -> Option<u32> {
    let token = token.trim();
    if token == "*" {
        return Some(max);
    }
    token.parse::<u32>().ok().filter(|n| *n != 0)
}

/// Parses a `FETCH` item specification: a macro (`ALL`/`FAST`/`FULL`), one item,
/// or a parenthesised list. Returns `None` on a malformed item.
fn parse_fetch_items(spec: &str) -> Option<Vec<FetchItem>> {
    let spec = spec.trim();
    let inner = spec.strip_prefix('(').and_then(|s| s.strip_suffix(')')).unwrap_or(spec).trim();

    // A bare macro is only valid on its own.
    match inner.to_ascii_uppercase().as_str() {
        "ALL" => {
            return Some(vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
            ]);
        }
        "FAST" => {
            return Some(vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Rfc822Size]);
        }
        "FULL" => {
            return Some(vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
                FetchItem::Body { section: Section::Full, peek: false, partial: None },
            ]);
        }
        _ => {}
    }

    let mut items = Vec::new();
    for token in split_top_level(inner) {
        items.push(parse_fetch_item(&token)?);
    }
    if items.is_empty() { None } else { Some(items) }
}

/// Splits a `FETCH` item list on spaces that sit outside any `(...)`/`[...]`,
/// so `BODY.PEEK[HEADER.FIELDS (DATE FROM)]` stays one token.
fn split_top_level(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in input.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ' ' if depth == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parses one `FETCH` item token. `None` on an unrecognised item.
fn parse_fetch_item(token: &str) -> Option<FetchItem> {
    let upper = token.to_ascii_uppercase();
    match upper.as_str() {
        "UID" => return Some(FetchItem::Uid),
        "FLAGS" => return Some(FetchItem::Flags),
        "INTERNALDATE" => return Some(FetchItem::InternalDate),
        "RFC822.SIZE" => return Some(FetchItem::Rfc822Size),
        "ENVELOPE" => return Some(FetchItem::Envelope),
        "RFC822" => {
            return Some(FetchItem::Rfc822);
        }
        "RFC822.HEADER" => return Some(FetchItem::Rfc822Header),
        "RFC822.TEXT" => return Some(FetchItem::Rfc822Text),
        // Bare BODY / BODYSTRUCTURE ask for the parsed MIME structure. Apple
        // Mail sends BODYSTRUCTURE with every body poll, and one unparseable
        // item fails the whole FETCH — so these must parse, not be skipped.
        "BODY" => return Some(FetchItem::BodyStructure { extended: false }),
        "BODYSTRUCTURE" => return Some(FetchItem::BodyStructure { extended: true }),
        _ => {}
    }

    // BODY[...] or BODY.PEEK[...], possibly with a <offset.length> partial.
    let bracket = token.find('[')?;
    let prefix = token[..bracket].to_ascii_uppercase();
    let peek = match prefix.as_str() {
        "BODY" => false,
        "BODY.PEEK" => true,
        _ => return None,
    };
    let close = token.find(']')?;
    let section = parse_section(&token[bracket + 1..close])?;
    let partial = parse_partial(&token[close + 1..]);
    Some(FetchItem::Body { section, peek, partial })
}

/// Parses the text between the brackets of a `BODY[...]`.
fn parse_section(inside: &str) -> Option<Section> {
    let trimmed = inside.trim();
    if trimmed.is_empty() {
        return Some(Section::Full);
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper == "HEADER" {
        return Some(Section::Header);
    }
    if upper == "TEXT" {
        return Some(Section::Text);
    }
    if upper.starts_with("HEADER.FIELDS.NOT") {
        return Some(Section::HeaderFieldsNot(parse_field_list(trimmed)));
    }
    if upper.starts_with("HEADER.FIELDS") {
        return Some(Section::HeaderFields(parse_field_list(trimmed)));
    }
    // Anything unrecognised degrades to the whole message rather than failing
    // the FETCH — a lenient reading keeps exotic clients working.
    Some(parse_part_section(&upper).unwrap_or(Section::Full))
}

/// Parses a numeric part section: a dotted 1-based path (`1.2`) with an
/// optional trailing `MIME`/`HEADER`/`TEXT` sub-target. `None` when the text
/// is not a part section at all.
fn parse_part_section(upper: &str) -> Option<Section> {
    let mut path = Vec::new();
    let mut target = mime::Target::Content;
    let mut segments = upper.split('.').peekable();
    while let Some(segment) = segments.next() {
        if let Ok(number) = segment.parse::<u32>() {
            if number == 0 {
                return None;
            }
            path.push(number);
            continue;
        }
        // The first non-numeric segment must be the final sub-target.
        target = match segment {
            "MIME" => mime::Target::Mime,
            "HEADER" => mime::Target::Header,
            "TEXT" => mime::Target::Text,
            _ => return None,
        };
        if segments.peek().is_some() || path.is_empty() {
            return None;
        }
    }
    if path.is_empty() { None } else { Some(Section::Part { path, target }) }
}

/// Extracts the parenthesised field-name list of a `HEADER.FIELDS` section,
/// upper-cased for case-insensitive matching.
fn parse_field_list(section: &str) -> Vec<String> {
    match between(section, '(', ')') {
        Some(inside) => inside
            .split_whitespace()
            .map(|f| f.trim_matches('"').to_ascii_uppercase())
            .collect(),
        None => Vec::new(),
    }
}

/// Parses a `<offset.length>` or `<offset>` partial suffix, if present.
fn parse_partial(rest: &str) -> Option<(u32, Option<u32>)> {
    let inner = between(rest, '<', '>')?;
    match inner.split_once('.') {
        Some((off, len)) => Some((off.parse().ok()?, Some(len.parse().ok()?))),
        None => Some((inner.parse().ok()?, None)),
    }
}

/// Renders one message's `FETCH` response, `* <seq> FETCH (...)`, appending each
/// item's rendering. Literal bodies are emitted as `{n}\r\n<bytes>` so binary
/// content survives untouched.
fn render_fetch(seq: u32, items: &[FetchItem], data: &MessageData) -> IResponse {
    let mut buf = Vec::new();
    buf.extend_from_slice(format!("{seq} FETCH (").as_bytes());
    let mut first = true;
    for item in items {
        if !first {
            buf.push(b' ');
        }
        first = false;
        render_item(&mut buf, item, data);
    }
    buf.push(b')');
    IResponse::untagged_bytes(buf)
}

/// Appends one item's `key value` rendering to a `FETCH` response buffer.
fn render_item(buf: &mut Vec<u8>, item: &FetchItem, data: &MessageData) {
    match item {
        FetchItem::Uid => buf.extend_from_slice(format!("UID {}", data.uid).as_bytes()),
        FetchItem::Flags => {
            buf.extend_from_slice(format!("FLAGS {}", Flag::render_set(&data.flags)).as_bytes());
        }
        FetchItem::InternalDate => {
            buf.extend_from_slice(format!("INTERNALDATE \"{}\"", data.internal_date).as_bytes());
        }
        FetchItem::Rfc822Size => {
            buf.extend_from_slice(format!("RFC822.SIZE {}", data.raw.len()).as_bytes());
        }
        FetchItem::Envelope => {
            buf.extend_from_slice(b"ENVELOPE ");
            buf.extend_from_slice(envelope(&data.raw).as_bytes());
        }
        FetchItem::BodyStructure { extended } => {
            let key = if *extended { "BODYSTRUCTURE" } else { "BODY" };
            buf.extend_from_slice(key.as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(body_structure(&mime::parse(&data.raw), &data.raw).as_bytes());
        }
        FetchItem::Rfc822 => append_literal(buf, "RFC822", &data.raw),
        FetchItem::Rfc822Header => {
            append_literal(buf, "RFC822.HEADER", header_bytes(&data.raw));
        }
        FetchItem::Rfc822Text => append_literal(buf, "RFC822.TEXT", body_bytes(&data.raw)),
        FetchItem::Body { section, partial, .. } => {
            let full = section_bytes(section, &data.raw);
            let (slice, marker) = apply_partial(&full, *partial);
            let key = format!("BODY[{}]{}", section.wire(), marker);
            append_literal(buf, &key, slice);
        }
    }
}

/// Appends a `KEY {n}\r\n<bytes>` literal to a response buffer.
fn append_literal(buf: &mut Vec<u8>, key: &str, bytes: &[u8]) {
    buf.extend_from_slice(format!("{key} {{{}}}\r\n", bytes.len()).as_bytes());
    buf.extend_from_slice(bytes);
}

/// Applies a `<offset.length>` partial, returning the slice and the `<offset>`
/// marker the response key must carry.
fn apply_partial(bytes: &[u8], partial: Option<(u32, Option<u32>)>) -> (&[u8], String) {
    match partial {
        None => (bytes, String::new()),
        Some((offset, length)) => {
            let start = (offset as usize).min(bytes.len());
            let end = match length {
                Some(len) => (start + len as usize).min(bytes.len()),
                None => bytes.len(),
            };
            (&bytes[start..end], format!("<{offset}>"))
        }
    }
}

/// The byte offset where the body begins — just past the header/body separator,
/// or the end of the message when there is no blank line.
fn body_offset(raw: &[u8]) -> usize {
    if let Some(pos) = find(raw, b"\r\n\r\n") {
        return pos + 4;
    }
    if let Some(pos) = find(raw, b"\n\n") {
        return pos + 2;
    }
    raw.len()
}

/// The header block, including the trailing blank line (what `BODY[HEADER]`
/// returns).
fn header_bytes(raw: &[u8]) -> &[u8] {
    &raw[..body_offset(raw)]
}

/// The message body, everything after the header/body separator.
fn body_bytes(raw: &[u8]) -> &[u8] {
    &raw[body_offset(raw)..]
}

/// The bytes a given section names.
fn section_bytes<'a>(section: &Section, raw: &'a [u8]) -> Cow<'a, [u8]> {
    match section {
        Section::Full => Cow::Borrowed(raw),
        Section::Header => Cow::Borrowed(header_bytes(raw)),
        Section::Text => Cow::Borrowed(body_bytes(raw)),
        Section::HeaderFields(fields) => Cow::Owned(selected_headers(raw, fields, true)),
        Section::HeaderFieldsNot(fields) => Cow::Owned(selected_headers(raw, fields, false)),
        Section::Part { path, target } => {
            let root = mime::parse(raw);
            match mime::section(&root, path, *target) {
                Some(range) => Cow::Borrowed(&raw[range]),
                // A path naming no part yields empty content rather than an
                // error; the client's own structure told it what exists.
                None => Cow::Borrowed(&[][..]),
            }
        }
    }
}

/// Extracts header fields by name. With `keep` true only the named fields are
/// returned; with `keep` false every field except the named ones. The result
/// ends with the blank separator line, as `BODY[HEADER.FIELDS]` requires.
fn selected_headers(raw: &[u8], names: &[String], keep: bool) -> Vec<u8> {
    let header = header_bytes(raw);
    let text = String::from_utf8_lossy(header);
    let mut out = String::new();
    for line in logical_header_lines(&text) {
        let field = line.split(':').next().unwrap_or("").trim().to_ascii_uppercase();
        let named = names.contains(&field);
        if named == keep {
            out.push_str(&line);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Splits a header block into logical (unfolded) header lines, joining
/// continuation lines that begin with whitespace.
fn logical_header_lines(header: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw_line in header.split("\r\n").flat_map(|l| l.split('\n')) {
        if raw_line.is_empty() {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(last) = lines.last_mut() {
                last.push(' ');
                last.push_str(raw_line.trim_start());
                continue;
            }
        }
        lines.push(raw_line.to_string());
    }
    lines
}

/// Reads one header field's unfolded value by name, case-insensitively, first
/// match wins.
fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let header = header_bytes(raw);
    let text = String::from_utf8_lossy(header);
    for line in logical_header_lines(&text) {
        if let Some((field, value)) = line.split_once(':') {
            if field.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Builds the parenthesised `ENVELOPE` structure from the message headers, a
/// best-effort parse sufficient for a client's message-list view. Missing
/// fields render as `NIL`; `sender` and `reply-to` default to `from`, as the
/// specification directs.
fn envelope(raw: &[u8]) -> String {
    let date = nstring(header_value(raw, "Date").as_deref());
    let subject = nstring(header_value(raw, "Subject").as_deref());
    let from = address_list(header_value(raw, "From").as_deref());
    let sender = if header_value(raw, "Sender").is_some() {
        address_list(header_value(raw, "Sender").as_deref())
    } else {
        from.clone()
    };
    let reply_to = if header_value(raw, "Reply-To").is_some() {
        address_list(header_value(raw, "Reply-To").as_deref())
    } else {
        from.clone()
    };
    let to = address_list(header_value(raw, "To").as_deref());
    let cc = address_list(header_value(raw, "Cc").as_deref());
    let bcc = address_list(header_value(raw, "Bcc").as_deref());
    let in_reply_to = nstring(header_value(raw, "In-Reply-To").as_deref());
    let message_id = nstring(header_value(raw, "Message-ID").as_deref());

    format!(
        "({date} {subject} {from} {sender} {reply_to} {to} {cc} {bcc} {in_reply_to} {message_id})"
    )
}

/// Renders a part tree as the parenthesised `BODY`/`BODYSTRUCTURE` structure
/// (RFC 3501's non-extension form, which is all a client needs to locate and
/// decode parts). Multiparts render their children back to back followed by
/// the subtype; `message/rfc822` embeds the inner message's envelope and
/// structure, as the specification requires.
fn body_structure(part: &mime::Part, raw: &[u8]) -> String {
    if part.is_multipart() {
        let children: String = part.children.iter().map(|c| body_structure(c, raw)).collect();
        let children = if children.is_empty() {
            // A boundary that matched nothing still needs one part slot.
            "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0)".into()
        } else {
            children
        };
        return format!("({children} {})", nstring(Some(&part.subtype)));
    }

    let params = if part.params.is_empty() {
        "NIL".into()
    } else {
        let rendered: Vec<String> = part
            .params
            .iter()
            .map(|(attr, val)| format!("{} {}", nstring(Some(attr)), nstring(Some(val))))
            .collect();
        format!("({})", rendered.join(" "))
    };
    let base = format!(
        "{} {} {params} {} {} {} {}",
        nstring(Some(&part.kind)),
        nstring(Some(&part.subtype)),
        nstring(part.content_id.as_deref()),
        nstring(part.description.as_deref()),
        nstring(Some(&part.encoding)),
        part.body.len(),
    );
    if part.is_message() && !part.children.is_empty() {
        let inner_raw = &raw[part.children[0].header.start..part.children[0].body.end];
        let inner = &part.children[0];
        return format!(
            "({base} {} {} {})",
            envelope(inner_raw),
            body_structure(inner, raw),
            part.line_count(raw)
        );
    }
    if part.kind == "text" {
        return format!("({base} {})", part.line_count(raw));
    }
    format!("({base})")
}

/// Renders an address header as an IMAP address list, or `NIL` when absent or
/// empty. Each address becomes `(name NIL mailbox host)`.
fn address_list(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "NIL".into();
    };
    let mut parts = Vec::new();
    for raw in split_addresses(value) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (name, addr) = match (raw.find('<'), raw.find('>')) {
            (Some(open), Some(close)) if close > open => {
                let display = raw[..open].trim().trim_matches('"').trim();
                let display = if display.is_empty() { None } else { Some(display) };
                (display, raw[open + 1..close].trim())
            }
            _ => (None, raw),
        };
        let (mailbox, host) = match addr.rsplit_once('@') {
            Some((mbox, host)) => (Some(mbox), Some(host)),
            None => (Some(addr), None),
        };
        parts.push(format!("({} NIL {} {})", nstring(name), nstring(mailbox), nstring(host)));
    }
    if parts.is_empty() { "NIL".into() } else { format!("({})", parts.join("")) }
}

/// Splits an address header on commas that sit outside `"..."` and `<...>`.
fn split_addresses(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut in_angle = false;
    for ch in value.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                current.push(ch);
            }
            '<' if !in_quote => {
                in_angle = true;
                current.push(ch);
            }
            '>' if !in_quote => {
                in_angle = false;
                current.push(ch);
            }
            ',' if !in_quote && !in_angle => out.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Renders an optional string as an IMAP quoted string, or `NIL` when absent.
/// Interior quotes and backslashes are escaped and folding whitespace collapsed,
/// so the value stays on one line.
fn nstring(value: Option<&str>) -> String {
    match value {
        None => "NIL".into(),
        Some(text) => {
            let mut escaped = String::with_capacity(text.len() + 2);
            escaped.push('"');
            for ch in text.chars() {
                match ch {
                    '"' | '\\' => {
                        escaped.push('\\');
                        escaped.push(ch);
                    }
                    '\r' | '\n' => escaped.push(' '),
                    _ => escaped.push(ch),
                }
            }
            escaped.push('"');
            escaped
        }
    }
}

/// Finds the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> IConfig {
        IConfig {
            hostname: "mail.example.com".into(),
            tls_available: true,
            require_tls_for_auth: true,
        }
    }

    /// A session already logged in and with a mailbox open, so mailbox commands
    /// can be exercised directly. UIDs 5, 6, 9 stand in for a sparse mailbox.
    fn selected_session() -> ISession {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));
        assert_eq!(s.state(), IState::Authenticated);
        s.select_result(
            "a2",
            "INBOX",
            false,
            SelectData {
                uids: vec![5, 6, 9],
                uid_validity: 42,
                uid_next: 10,
                recent: 1,
                first_unseen: Some(2),
                unseen_count: 2,
            },
        );
        assert_eq!(s.state(), IState::Selected);
        s
    }

    fn message(uid: u32, flags: Vec<Flag>) -> MessageData {
        let raw = b"From: Alice <alice@elsewhere.com>\r\n\
                    To: dave@example.com\r\n\
                    Subject: hello there\r\n\
                    Date: Thu, 07 Aug 2026 12:00:00 +0000\r\n\
                    Message-ID: <abc@elsewhere.com>\r\n\
                    \r\n\
                    Body line one\r\nBody line two\r\n"
            .to_vec();
        MessageData { uid, flags, internal_date: "07-Aug-2026 12:00:00 +0000".into(), raw }
    }

    fn tagged_line(responses: &[IResponse], tag: &str) -> String {
        responses
            .iter()
            .map(|r| r.text().into_owned())
            .find(|line| line.starts_with(tag))
            .unwrap_or_default()
    }

    // ---- greeting and capability ------------------------------------------

    #[test]
    fn greeting_advertises_starttls_and_login_disabled_before_tls() {
        let s = ISession::new(config());
        let text = s.greeting().text().into_owned();
        assert!(text.contains("STARTTLS"));
        assert!(text.contains("LOGINDISABLED"));
    }

    #[test]
    fn capability_drops_login_disabled_once_tls_is_active() {
        let mut s = ISession::new(config());
        s.tls_established();
        let action = s.command("a CAPABILITY");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        let caps = responses[0].text().into_owned();
        assert!(caps.contains("IMAP4rev1"));
        assert!(!caps.contains("LOGINDISABLED"));
        assert!(!caps.contains("STARTTLS"));
    }

    // ---- authentication gate ----------------------------------------------

    #[test]
    fn login_is_refused_before_tls() {
        // LOGIN sends the password verbatim; on a cleartext link it must be
        // refused rather than accepted.
        let mut s = ISession::new(config());
        let action = s.command("a LOGIN \"dave@example.com\" \"secret\"");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        let line = responses[0].text().into_owned();
        assert!(line.starts_with("a NO"));
        assert!(line.contains("PRIVACYREQUIRED"));
    }

    #[test]
    fn login_over_tls_asks_the_driver_to_verify_the_credentials() {
        let mut s = ISession::new(config());
        s.tls_established();
        match s.command("a LOGIN \"dave@example.com\" \"secret\"") {
            IAction::Login { tag, username, password } => {
                assert_eq!(tag, "a");
                assert_eq!(username, "dave@example.com");
                assert_eq!(password, "secret");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_login_does_not_authenticate() {
        let mut s = ISession::new(config());
        s.tls_established();
        let responses = s.login_result("a", None);
        assert!(responses[0].text().starts_with("a NO"));
        assert_eq!(s.state(), IState::NotAuthenticated);
    }

    #[test]
    fn id_is_answered_politely_with_nil() {
        // Apple Mail sends ID first thing on every sync connection (RFC 2971);
        // a BAD here reads as a broken server to it.
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("x ID (\"name\" \"Mac OS X Mail\")") else {
            panic!("Respond")
        };
        assert_eq!(responses[0].text(), "* ID NIL\r\n");
        assert!(responses[1].text().starts_with("x OK"), "{}", responses[1].text());
    }

    // ---- AUTHENTICATE PLAIN ------------------------------------------------

    /// `\0dave@example.com\0secret` base64-encoded — the SASL PLAIN response
    /// Apple Mail and friends send.
    const PLAIN_DAVE: &str = "AGRhdmVAZXhhbXBsZS5jb20Ac2VjcmV0";

    #[test]
    fn capability_over_tls_advertises_auth_plain_with_sasl_ir() {
        // This advertisement is what mainstream clients key on: without it
        // they report "unable to verify" instead of falling back to LOGIN.
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("a CAPABILITY") else { panic!("Respond") };
        let caps = responses[0].text().into_owned();
        assert!(caps.contains("AUTH=PLAIN"), "{caps}");
        assert!(caps.contains("SASL-IR"), "{caps}");

        // Before TLS the mechanism must not be offered — LOGINDISABLED rules.
        let greeting = ISession::new(config()).greeting().text().into_owned();
        assert!(!greeting.contains("AUTH=PLAIN"), "{greeting}");
    }

    #[test]
    fn authenticate_plain_with_initial_response_verifies_like_login() {
        let mut s = ISession::new(config());
        s.tls_established();
        match s.command(&format!("a AUTHENTICATE PLAIN {PLAIN_DAVE}")) {
            IAction::Login { tag, username, password } => {
                assert_eq!(tag, "a");
                assert_eq!(username, "dave@example.com");
                assert_eq!(password, "secret");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_plain_without_initial_response_continues_then_verifies() {
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("a AUTHENTICATE PLAIN") else { panic!("Respond") };
        assert!(responses[0].text().starts_with('+'), "{}", responses[0].text());

        // The next line is the SASL response, not a command.
        match s.command(&format!("{PLAIN_DAVE}\r\n")) {
            IAction::Login { tag, username, password } => {
                assert_eq!(tag, "a");
                assert_eq!(username, "dave@example.com");
                assert_eq!(password, "secret");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    // ---- command literals (RFC 3501 {n}, RFC 7888 {n+}) --------------------

    #[test]
    fn login_with_synchronizing_literals_matches_apple_mails_probe() {
        // Apple Mail's account-setup probe sends LOGIN exactly this way —
        // username and password as synchronising literals, never quoted
        // strings — so this conversation is the gate every "Add account"
        // attempt stands behind.
        let mut s = ISession::new(config());
        s.tls_established();

        let IAction::Respond(responses) = s.command("a1 LOGIN {23}\r\n") else {
            panic!("expected continuation")
        };
        assert!(responses[0].text().starts_with("+ "), "{}", responses[0].text());

        let IAction::Respond(responses) = s.command("alex@rockywearsahat.com {9}\r\n") else {
            panic!("expected continuation")
        };
        assert!(responses[0].text().starts_with("+ "), "{}", responses[0].text());

        match s.command("wordpass!\r\n") {
            IAction::Login { tag, username, password } => {
                assert_eq!(tag, "a1");
                assert_eq!(username, "alex@rockywearsahat.com");
                assert_eq!(password, "wordpass!");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn literal_plus_streams_without_continuations() {
        // {n+} (RFC 7888) is sent without waiting; the server must consume the
        // following octets silently rather than answer each marker.
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("a LOGIN {4+}\r\n") else { panic!("Respond") };
        assert!(responses.is_empty(), "nothing to write for LITERAL+");
        let IAction::Respond(responses) = s.command("dave {6+}\r\n") else { panic!("Respond") };
        assert!(responses.is_empty());
        match s.command("secret\r\n") {
            IAction::Login { username, password, .. } => {
                assert_eq!(username, "dave");
                assert_eq!(password, "secret");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn literal_contents_keep_quotes_and_backslashes_verbatim() {
        // The whole point of a literal is octet-exact transport: a password
        // holding the characters that would break a quoted string must survive
        // assembly byte for byte.
        let mut s = ISession::new(config());
        s.tls_established();
        s.command("a LOGIN {4}\r\n");
        s.command("dave {7}\r\n");
        match s.command("pa\"ss\\w\r\n") {
            IAction::Login { password, .. } => assert_eq!(password, "pa\"ss\\w"),
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_literal_is_a_legitimate_argument() {
        // {0} announces zero octets; the following line is empty and must not
        // be dismissed as a blank keep-alive.
        let mut s = ISession::new(config());
        s.tls_established();
        s.command("a LOGIN {4}\r\n");
        s.command("dave {0}\r\n");
        assert!(s.awaiting_literal());
        match s.command("\r\n") {
            IAction::Login { password, .. } => assert_eq!(password, ""),
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_literal_is_refused_with_a_tagged_bad() {
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("a LOGIN {99999}\r\n") else {
            panic!("Respond")
        };
        assert!(responses[0].text().starts_with("a BAD"), "{}", responses[0].text());
        assert!(!s.awaiting_literal(), "a refused literal must not stay pending");
    }

    #[test]
    fn a_literal_line_shorter_than_announced_is_refused_and_recovers() {
        // Fewer octets than announced means the literal spanned a CRLF, which
        // this server refuses; the session must return to reading commands.
        let mut s = ISession::new(config());
        s.tls_established();
        s.command("a LOGIN {10}\r\n");
        let IAction::Respond(responses) = s.command("short\r\n") else { panic!("Respond") };
        assert!(responses[0].text().contains("BAD"), "{}", responses[0].text());
        let IAction::Respond(responses) = s.command("b CAPABILITY\r\n") else { panic!("Respond") };
        assert!(responses.last().unwrap().text().starts_with("b OK"));
    }

    #[test]
    fn capability_advertises_literal_plus_from_the_greeting() {
        // Clients decide from the greeting whether {n+} may be streamed.
        let greeting = ISession::new(config()).greeting().text().into_owned();
        assert!(greeting.contains("LITERAL+"), "{greeting}");
    }

    #[test]
    fn select_accepts_a_literal_mailbox_name() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));
        s.command("a2 SELECT {5}\r\n");
        match s.command("INBOX\r\n") {
            IAction::Select { mailbox, .. } => assert_eq!(mailbox, "INBOX"),
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn a_continued_authenticate_can_be_aborted_with_a_star() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.command("a AUTHENTICATE PLAIN");
        let IAction::Respond(responses) = s.command("*\r\n") else { panic!("Respond") };
        assert!(responses[0].text().starts_with("a BAD"), "{}", responses[0].text());
        assert_eq!(s.state(), IState::NotAuthenticated);

        // The abort consumed the pending state: the next line is a command again.
        let IAction::Respond(responses) = s.command("b NOOP") else { panic!("Respond") };
        assert!(responses[0].text().starts_with("b OK"), "{}", responses[0].text());
    }

    #[test]
    fn authenticate_is_gated_and_particular() {
        // Before TLS: refused for the same reason LOGIN is.
        let mut s = ISession::new(config());
        let IAction::Respond(responses) = s.command(&format!("a AUTHENTICATE PLAIN {PLAIN_DAVE}"))
        else {
            panic!("Respond")
        };
        assert!(responses[0].text().contains("PRIVACYREQUIRED"), "{}", responses[0].text());

        // An unsupported mechanism is named as such.
        let mut s = ISession::new(config());
        s.tls_established();
        let IAction::Respond(responses) = s.command("a AUTHENTICATE CRAM-MD5") else { panic!("Respond") };
        assert!(responses[0].text().starts_with("a NO"), "{}", responses[0].text());

        // A response that is not base64 SASL PLAIN is a protocol error, not a
        // failed login.
        let IAction::Respond(responses) = s.command("b AUTHENTICATE PLAIN not-base64!!") else {
            panic!("Respond")
        };
        assert!(responses[0].text().starts_with("b BAD"), "{}", responses[0].text());
    }

    #[test]
    fn mailbox_commands_are_refused_until_authenticated() {
        let mut s = ISession::new(config());
        s.tls_established();
        let action = s.command("a SELECT INBOX");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        assert!(responses[0].text().starts_with("a NO"));
    }

    // ---- SELECT ------------------------------------------------------------

    #[test]
    fn select_asks_the_driver_to_enumerate_then_reports_the_mailbox() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));

        match s.command("a2 SELECT INBOX") {
            IAction::Select { tag, mailbox, read_only } => {
                assert_eq!(tag, "a2");
                assert_eq!(mailbox, "INBOX");
                assert!(!read_only);
            }
            other => panic!("expected Select, got {other:?}"),
        }

        let responses = s.select_result(
            "a2",
            "INBOX",
            false,
            SelectData {
                uids: vec![5, 6, 9],
                uid_validity: 42,
                uid_next: 10,
                recent: 1,
                first_unseen: Some(2),
                unseen_count: 2,
            },
        );
        let joined: String = responses.iter().map(|r| r.text().into_owned()).collect();
        assert!(joined.contains("3 EXISTS"));
        assert!(joined.contains("[UIDVALIDITY 42]"));
        assert!(joined.contains("[UIDNEXT 10]"));
        assert!(joined.contains("[UNSEEN 2]"));
        assert!(tagged_line(&responses, "a2").contains("[READ-WRITE]"));
        assert_eq!(s.state(), IState::Selected);
    }

    #[test]
    fn inbox_name_is_matched_case_insensitively() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));
        match s.command("a2 SELECT \"inbox\"") {
            IAction::Select { mailbox, .. } => assert_eq!(mailbox, "INBOX"),
            other => panic!("expected Select, got {other:?}"),
        }
    }

    // ---- LIST --------------------------------------------------------------

    #[test]
    fn list_returns_the_standard_folders() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));
        let action = s.command("a2 LIST \"\" \"*\"");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        let joined: String = responses.iter().map(|r| r.text().into_owned()).collect();
        assert!(joined.contains("\"INBOX\""));
        assert!(joined.contains("\"Sent\""));
        assert!(joined.contains("\\Trash"));
        assert!(tagged_line(&responses, "a2").contains("OK"));
    }

    // ---- sequence and UID resolution --------------------------------------

    #[test]
    fn a_star_range_covers_the_whole_mailbox_by_sequence() {
        let uids = vec![5, 6, 9];
        let refs = resolve_set("1:*", &uids, false).unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0], MessageRef { seq: 1, uid: 5 });
        assert_eq!(refs[2], MessageRef { seq: 3, uid: 9 });
    }

    #[test]
    fn uid_mode_reads_the_set_as_uids_not_positions() {
        let uids = vec![5, 6, 9];
        // UID 9 is the third message; a plain sequence 9 would be out of range.
        let refs = resolve_set("9", &uids, true).unwrap();
        assert_eq!(refs, vec![MessageRef { seq: 3, uid: 9 }]);
        // A UID that is not present is dropped, not an error.
        assert!(resolve_set("7", &uids, true).unwrap().is_empty());
    }

    #[test]
    fn a_uid_star_is_the_largest_uid() {
        let uids = vec![5, 6, 9];
        let refs = resolve_set("6:*", &uids, true).unwrap();
        assert_eq!(refs, vec![MessageRef { seq: 2, uid: 6 }, MessageRef { seq: 3, uid: 9 }]);
    }

    #[test]
    fn a_malformed_set_is_rejected() {
        assert!(resolve_set("1:", &[5], false).is_none());
        assert!(resolve_set("", &[5], false).is_none());
        assert!(resolve_set("x", &[5], false).is_none());
    }

    // ---- FETCH item parsing and rendering ---------------------------------

    #[test]
    fn fetch_resolves_the_set_and_items() {
        let mut s = selected_session();
        match s.command("a FETCH 1:2 (FLAGS UID)") {
            IAction::Fetch(plan) => {
                assert_eq!(plan.messages.len(), 2);
                assert_eq!(plan.items, vec![FetchItem::Flags, FetchItem::Uid]);
                assert!(!plan.marks_seen());
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn uid_fetch_always_includes_the_uid_item() {
        let mut s = selected_session();
        match s.command("a UID FETCH 5 (FLAGS)") {
            IAction::Fetch(plan) => {
                assert!(plan.uid_mode);
                assert!(plan.items.contains(&FetchItem::Uid));
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn a_non_peek_body_fetch_marks_the_message_seen() {
        let mut s = selected_session();
        match s.command("a FETCH 1 (BODY[])") {
            IAction::Fetch(plan) => assert!(plan.marks_seen()),
            other => panic!("expected Fetch, got {other:?}"),
        }
        match selected_session().command("b FETCH 1 (BODY.PEEK[])") {
            IAction::Fetch(plan) => assert!(!plan.marks_seen()),
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn fetch_renders_flags_and_a_body_literal() {
        let s = selected_session();
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![
                FetchItem::Flags,
                FetchItem::Body { section: Section::Full, peek: true, partial: None },
            ],
        };
        let responses = s.fetch_complete(&plan, &[message(5, vec![Flag::Seen])]);
        let data = responses[0].text().into_owned();
        assert!(data.starts_with("* 1 FETCH ("));
        assert!(data.contains("FLAGS (\\Seen)"));
        // The body literal announces its exact octet count.
        assert!(data.contains("BODY[] {"));
        assert!(tagged_line(&responses, "a").contains("OK"));
    }

    #[test]
    fn header_fields_fetch_returns_only_the_named_headers() {
        let s = selected_session();
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![FetchItem::Body {
                section: Section::HeaderFields(vec!["SUBJECT".into()]),
                peek: true,
                partial: None,
            }],
        };
        let responses = s.fetch_complete(&plan, &[message(5, vec![])]);
        let data = responses[0].text().into_owned();
        assert!(data.contains("Subject: hello there"));
        assert!(!data.contains("From: Alice"));
    }

    #[test]
    fn fetch_of_a_missing_message_is_skipped_not_fatal() {
        let s = selected_session();
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![FetchItem::Flags],
        };
        // Driver returns nothing for uid 5.
        let responses = s.fetch_complete(&plan, &[]);
        assert_eq!(responses.len(), 1);
        assert!(responses[0].text().starts_with("a OK"));
    }

    #[test]
    fn apple_mail_body_poll_with_bodystructure_parses() {
        // Regression: this exact shape used to answer BAD, which is why Apple
        // Mail rendered every message with an empty body.
        let mut s = selected_session();
        let action = s.command(
            "a3 UID FETCH 5 (INTERNALDATE UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS \
             (date subject from to cc)] BODYSTRUCTURE)",
        );
        match action {
            IAction::Fetch(plan) => {
                assert!(plan.items.contains(&FetchItem::BodyStructure { extended: true }));
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn bodystructure_of_a_plain_message_describes_the_text_part() {
        let s = selected_session();
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![FetchItem::BodyStructure { extended: true }],
        };
        let responses = s.fetch_complete(&plan, &[message(5, vec![])]);
        let data = responses[0].text().into_owned();
        // Body is `Body line one\r\nBody line two\r\n`: 30 octets, 2 lines.
        assert!(data.contains("BODYSTRUCTURE (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 30 2)"), "got: {data}");
    }

    #[test]
    fn numeric_section_fetch_returns_that_part_with_the_matching_key() {
        let s = selected_session();
        let raw = b"From: a@b.c\r\n\
            Content-Type: multipart/alternative; boundary=\"XYZ\"\r\n\
            \r\n\
            --XYZ\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            plain body\r\n\
            --XYZ\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <b>html</b>\r\n\
            --XYZ--\r\n"
            .to_vec();
        let data =
            MessageData { uid: 5, flags: vec![], internal_date: "07-Aug-2026 12:00:00 +0000".into(), raw };
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![FetchItem::Body {
                section: Section::Part { path: vec![2], target: mime::Target::Content },
                peek: true,
                partial: None,
            }],
        };
        let responses = s.fetch_complete(&plan, &[data]);
        let text = responses[0].text().into_owned();
        assert!(text.contains("BODY[2] {11}"), "got: {text}");
        assert!(text.contains("<b>html</b>"), "got: {text}");
    }

    #[test]
    fn part_sections_parse_from_the_wire() {
        assert_eq!(
            parse_fetch_item("BODY.PEEK[1.2]"),
            Some(FetchItem::Body {
                section: Section::Part { path: vec![1, 2], target: mime::Target::Content },
                peek: true,
                partial: None,
            })
        );
        assert_eq!(
            parse_fetch_item("BODY[1.MIME]"),
            Some(FetchItem::Body {
                section: Section::Part { path: vec![1], target: mime::Target::Mime },
                peek: false,
                partial: None,
            })
        );
    }

    #[test]
    fn envelope_is_built_from_the_headers() {
        let env = envelope(&message(5, vec![]).raw);
        assert!(env.contains("\"hello there\""));
        assert!(env.contains("\"alice\" \"elsewhere.com\""));
        assert!(env.contains("<abc@elsewhere.com>"));
    }

    // ---- STORE -------------------------------------------------------------

    #[test]
    fn store_parses_the_operation_and_flags() {
        let mut s = selected_session();
        match s.command("a STORE 1 +FLAGS (\\Seen \\Flagged)") {
            IAction::Store(plan) => {
                assert_eq!(plan.op, StoreOp::Add);
                assert_eq!(plan.flags, vec![Flag::Seen, Flag::Flagged]);
                assert!(!plan.silent);
                assert_eq!(plan.messages, vec![MessageRef { seq: 1, uid: 5 }]);
            }
            other => panic!("expected Store, got {other:?}"),
        }
    }

    #[test]
    fn silent_store_suppresses_the_echo() {
        let s = selected_session();
        let plan = StorePlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            op: StoreOp::Add,
            flags: vec![Flag::Seen],
            silent: true,
        };
        let responses = s.store_complete(&plan, &[message(5, vec![Flag::Seen])]);
        assert_eq!(responses.len(), 1);
        assert!(responses[0].text().starts_with("a OK"));
    }

    #[test]
    fn store_echoes_new_flags_when_not_silent() {
        let s = selected_session();
        let plan = StorePlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            op: StoreOp::Add,
            flags: vec![Flag::Seen],
            silent: false,
        };
        let responses = s.store_complete(&plan, &[message(5, vec![Flag::Seen])]);
        assert!(responses[0].text().contains("FLAGS (\\Seen)"));
    }

    #[test]
    fn store_is_refused_on_a_read_only_mailbox() {
        let mut s = ISession::new(config());
        s.tls_established();
        s.login_result("a1", Some(Address::parse("dave@example.com").unwrap()));
        s.select_result(
            "a2",
            "INBOX",
            true,
            SelectData {
                uids: vec![5],
                uid_validity: 1,
                uid_next: 6,
                recent: 0,
                first_unseen: None,
                unseen_count: 0,
            },
        );
        let action = s.command("a3 STORE 1 +FLAGS (\\Seen)");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        assert!(responses[0].text().starts_with("a3 NO"));
    }

    // ---- STATUS ------------------------------------------------------------

    #[test]
    fn status_reports_the_requested_counters() {
        let s = selected_session();
        let data = SelectData {
            uids: vec![5, 6, 9],
            uid_validity: 42,
            uid_next: 10,
            recent: 1,
            first_unseen: Some(2),
            unseen_count: 2,
        };
        let responses = s.status_result(
            "a",
            "INBOX",
            &[StatusItem::Messages, StatusItem::Unseen, StatusItem::UidNext],
            &data,
        );
        let line = responses[0].text().into_owned();
        assert!(line.contains("MESSAGES 3"));
        assert!(line.contains("UNSEEN 2"));
        assert!(line.contains("UIDNEXT 10"));
    }

    // ---- session lifecycle -------------------------------------------------

    #[test]
    fn logout_closes_with_a_bye() {
        let mut s = selected_session();
        match s.command("z LOGOUT") {
            IAction::Close(responses) => {
                assert!(responses[0].text().contains("BYE"));
                assert!(tagged_line(&responses, "z").contains("OK"));
            }
            other => panic!("expected Close, got {other:?}"),
        }
        assert_eq!(s.state(), IState::Logout);
    }

    #[test]
    fn starttls_upgrades_before_login() {
        let mut s = ISession::new(config());
        match s.command("a STARTTLS") {
            IAction::StartTls(reply) => assert!(reply.text().starts_with("a OK")),
            other => panic!("expected StartTls, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_command_is_declined_but_the_session_survives() {
        let mut s = selected_session();
        let action = s.command("a FROBNICATE now");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        assert!(responses[0].text().starts_with("a BAD"));
        // The next command still works.
        assert!(matches!(s.command("b NOOP"), IAction::Respond(_)));
    }

    #[test]
    fn a_close_leaves_the_selected_state() {
        let mut s = selected_session();
        let action = s.command("a CLOSE");
        let IAction::Respond(responses) = action else { panic!("expected Respond") };
        assert!(responses[0].text().starts_with("a OK"));
        assert_eq!(s.state(), IState::Authenticated);
    }

    // ---- literal safety ----------------------------------------------------

    #[test]
    fn a_body_literal_reports_the_exact_octet_count() {
        // The octet count in the literal header must equal the bytes that
        // follow, or the client and server disagree about where the response
        // ends — a hung session.
        let s = selected_session();
        let msg = message(5, vec![]);
        let plan = FetchPlan {
            tag: "a".into(),
            uid_mode: false,
            messages: vec![MessageRef { seq: 1, uid: 5 }],
            items: vec![FetchItem::Body { section: Section::Full, peek: true, partial: None }],
        };
        let responses = s.fetch_complete(&plan, std::slice::from_ref(&msg));
        let wire = responses[0].to_wire();
        let announced = format!("{{{}}}", msg.raw.len());
        let marker = find(wire, announced.as_bytes()).expect("literal count present");
        // The bytes after `{n}\r\n` must be exactly the message.
        let body_start = marker + announced.len() + 2;
        assert_eq!(&wire[body_start..body_start + msg.raw.len()], &msg.raw[..]);
    }
}
