//! The SMTP session state machine.
//!
//! Written as a pure state machine — commands in, replies out, no sockets — so
//! the relay policy can be tested exhaustively without a network. That matters
//! more here than anywhere else in the project, because the failure mode is not
//! "the site is down", it is **becoming an open relay**: a server that accepts
//! mail for domains it does not own and forwards it on behalf of strangers.
//! Spammers find one within hours, and the address ends up on every blocklist
//! there is.
//!
//! The rule enforced below is the whole defence:
//!
//! > A recipient is accepted only if its domain is one we host, **or** the
//! > session has authenticated. Never otherwise.
//!
//! Note what that means for the second case: authentication is what separates
//! *submission* (our own user sending outward) from *relaying* (a stranger using
//! us as a launchpad). Unauthenticated sessions may only deliver inward.

use crate::address::{Address, Path};
use std::fmt;

/// Maximum bytes accepted in one command line (RFC 5321 §4.5.3.1.4).
pub const MAX_COMMAND_LINE: usize = 512;
/// Maximum recipients accepted for one message.
pub const MAX_RECIPIENTS: usize = 100;

/// A reply sent back to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Three-digit status code. 2xx succeeded, 4xx try again later, 5xx refused.
    pub code: u16,
    /// Human-readable text, one entry per line for multi-line replies.
    pub lines: Vec<String>,
}

impl Reply {
    /// A single-line reply.
    pub fn line(code: u16, text: impl Into<String>) -> Self {
        Self { code, lines: vec![text.into()] }
    }

    /// A multi-line reply, used for the `EHLO` capability list.
    pub fn multi(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// Whether this reply reports success.
    pub fn is_success(&self) -> bool {
        (200..400).contains(&self.code)
    }

    /// Renders the reply in wire format.
    ///
    /// Every line but the last is `code-text`; the last is `code text`. A client
    /// uses that hyphen to know more lines follow, so getting it wrong hangs the
    /// session.
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        let last = self.lines.len().saturating_sub(1);
        for (index, line) in self.lines.iter().enumerate() {
            let separator = if index == last { ' ' } else { '-' };
            out.push_str(&format!("{}{}{}\r\n", self.code, separator, line));
        }
        out
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.lines.join(" / "))
    }
}

/// What the session expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No `HELO`/`EHLO` yet.
    Greeted,
    /// Identified, ready for a new transaction.
    Ready,
    /// A sender is set; recipients may be added.
    HaveSender,
    /// At least one recipient is set.
    HaveRecipients,
    /// Message content is being read.
    ReadingData,
    /// `QUIT` was received.
    Closed,
}

/// What the caller must do after feeding a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send the reply and continue.
    Reply(Reply),
    /// Send the reply, then read message content until a lone `.`.
    ReadData(Reply),
    /// Send the reply, then close the connection.
    Close(Reply),
    /// Send the reply, then upgrade the connection to TLS.
    StartTls(Reply),
}

/// A message accepted for delivery.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The sender, or null for a bounce.
    pub sender: Path,
    /// Everyone the message is for.
    pub recipients: Vec<Address>,
    /// The identity the client claimed in `EHLO`.
    pub helo: String,
}

/// How this server is configured to answer.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Our own hostname, announced in the greeting.
    pub hostname: String,
    /// Domains we accept inbound mail for.
    pub local_domains: Vec<String>,
    /// Whether TLS is available for `STARTTLS`.
    pub tls_available: bool,
    /// Whether authentication may proceed without TLS.
    ///
    /// False in production: `AUTH PLAIN` sends the password in base64, which is
    /// encoding, not encryption. Offering it in cleartext hands credentials to
    /// anyone watching the network.
    pub allow_auth_without_tls: bool,
    /// Largest message accepted, in bytes.
    pub max_message_bytes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            local_domains: Vec::new(),
            tls_available: false,
            allow_auth_without_tls: false,
            max_message_bytes: 25 * 1024 * 1024,
        }
    }
}

/// One SMTP conversation.
#[derive(Debug)]
pub struct Session {
    policy: Policy,
    state: State,
    helo: Option<String>,
    sender: Option<Path>,
    recipients: Vec<Address>,
    tls_active: bool,
    authenticated: bool,
}

impl Session {
    /// Starts a session. The caller sends [`Session::greeting`] first.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            state: State::Greeted,
            helo: None,
            sender: None,
            recipients: Vec::new(),
            tls_active: false,
            authenticated: false,
        }
    }

    /// The banner sent as soon as the connection opens.
    pub fn greeting(&self) -> Reply {
        Reply::line(220, format!("{} selfhost ESMTP ready", self.policy.hostname))
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the connection has been upgraded to TLS.
    pub fn tls_active(&self) -> bool {
        self.tls_active
    }

    /// Whether the session has authenticated.
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Records that TLS is now in effect.
    pub fn tls_established(&mut self) {
        self.tls_active = true;
        // The standard requires forgetting everything learned before the
        // upgrade: anything said in cleartext could have been injected by a
        // man in the middle.
        self.helo = None;
        self.sender = None;
        self.recipients.clear();
        self.state = State::Greeted;
    }

    /// Records a successful authentication.
    pub fn authentication_succeeded(&mut self) {
        self.authenticated = true;
    }

    /// Feeds one command line and returns what to do next.
    pub fn command(&mut self, line: &str) -> Action {
        if line.len() > MAX_COMMAND_LINE {
            return Action::Reply(Reply::line(500, "line too long"));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = match trimmed.split_once(' ') {
            Some((verb, rest)) => (verb, rest.trim()),
            None => (trimmed, ""),
        };

        match verb.to_ascii_uppercase().as_str() {
            "EHLO" => self.ehlo(rest),
            "HELO" => self.helo_command(rest),
            "MAIL" => self.mail(rest),
            "RCPT" => self.rcpt(rest),
            "DATA" => self.data(),
            "RSET" => {
                self.reset_transaction();
                Action::Reply(Reply::line(250, "flushed"))
            }
            "NOOP" => Action::Reply(Reply::line(250, "OK")),
            "VRFY" => {
                // Confirming which addresses exist is a directory service for
                // spammers, so it is declined rather than answered.
                Action::Reply(Reply::line(252, "cannot VRFY, but will accept and attempt delivery"))
            }
            "STARTTLS" => self.starttls(),
            "AUTH" => self.auth(),
            "QUIT" => {
                self.state = State::Closed;
                Action::Close(Reply::line(221, format!("{} closing connection", self.policy.hostname)))
            }
            "" => Action::Reply(Reply::line(500, "empty command")),
            other => Action::Reply(Reply::line(502, format!("command {other} not implemented"))),
        }
    }

    /// Handles `EHLO`, answering with the capability list.
    fn ehlo(&mut self, domain: &str) -> Action {
        if domain.is_empty() {
            return Action::Reply(Reply::line(501, "EHLO requires a domain"));
        }
        self.helo = Some(domain.to_owned());
        self.reset_transaction();
        self.state = State::Ready;

        let mut lines = vec![format!("{} greets {domain}", self.policy.hostname)];
        lines.push(format!("SIZE {}", self.policy.max_message_bytes));
        lines.push("8BITMIME".into());
        lines.push("ENHANCEDSTATUSCODES".into());
        lines.push("PIPELINING".into());
        if self.policy.tls_available && !self.tls_active {
            lines.push("STARTTLS".into());
        }
        // AUTH is advertised only when credentials would be protected. A client
        // that cannot see it will not try to send a password in the clear.
        if self.tls_active || self.policy.allow_auth_without_tls {
            lines.push("AUTH PLAIN LOGIN".into());
        }
        Action::Reply(Reply::multi(250, lines))
    }

    /// Handles the older `HELO`, which has no capability list.
    fn helo_command(&mut self, domain: &str) -> Action {
        if domain.is_empty() {
            return Action::Reply(Reply::line(501, "HELO requires a domain"));
        }
        self.helo = Some(domain.to_owned());
        self.reset_transaction();
        self.state = State::Ready;
        Action::Reply(Reply::line(250, format!("{} greets {domain}", self.policy.hostname)))
    }

    /// Handles `MAIL FROM:<...>`.
    fn mail(&mut self, rest: &str) -> Action {
        if self.helo.is_none() {
            return Action::Reply(Reply::line(503, "send EHLO first"));
        }
        if matches!(self.state, State::HaveSender | State::HaveRecipients) {
            return Action::Reply(Reply::line(503, "sender already given"));
        }

        let Some(argument) = strip_keyword(rest, "FROM:") else {
            return Action::Reply(Reply::line(501, "expected MAIL FROM:<address>"));
        };

        // Trailing ESMTP parameters such as SIZE= are accepted and ignored.
        let path_text = argument.split_whitespace().next().unwrap_or(argument);

        match Path::parse(path_text) {
            Ok(path) => {
                self.sender = Some(path);
                self.recipients.clear();
                self.state = State::HaveSender;
                Action::Reply(Reply::line(250, "sender OK"))
            }
            Err(error) => Action::Reply(Reply::line(553, format!("bad sender: {error}"))),
        }
    }

    /// Handles `RCPT TO:<...>` — where relaying is allowed or refused.
    fn rcpt(&mut self, rest: &str) -> Action {
        if !matches!(self.state, State::HaveSender | State::HaveRecipients) {
            return Action::Reply(Reply::line(503, "send MAIL FROM first"));
        }
        if self.recipients.len() >= MAX_RECIPIENTS {
            return Action::Reply(Reply::line(452, "too many recipients"));
        }

        let Some(argument) = strip_keyword(rest, "TO:") else {
            return Action::Reply(Reply::line(501, "expected RCPT TO:<address>"));
        };
        let path_text = argument.split_whitespace().next().unwrap_or(argument);

        let path = match Path::parse(path_text) {
            Ok(path) => path,
            Err(error) => return Action::Reply(Reply::line(553, format!("bad recipient: {error}"))),
        };

        let Some(address) = path.address() else {
            return Action::Reply(Reply::line(550, "recipient cannot be the null path"));
        };

        // The open-relay check. Everything else in this file is bookkeeping.
        let is_ours = address.is_local_to(&self.policy.local_domains);
        if !is_ours && !self.authenticated {
            return Action::Reply(Reply::line(
                550,
                "relay not permitted: this server accepts mail only for its own domains \
                 unless the session is authenticated",
            ));
        }

        if self.recipients.iter().any(|existing| existing.matches(address)) {
            // A duplicate is accepted but stored once, so the recipient does not
            // receive two copies.
            return Action::Reply(Reply::line(250, "recipient OK"));
        }

        self.recipients.push(address.clone());
        self.state = State::HaveRecipients;
        Action::Reply(Reply::line(250, "recipient OK"))
    }

    /// Handles `DATA`.
    fn data(&mut self) -> Action {
        match self.state {
            State::HaveRecipients => {
                self.state = State::ReadingData;
                Action::ReadData(Reply::line(354, "start mail input; end with <CRLF>.<CRLF>"))
            }
            State::HaveSender => Action::Reply(Reply::line(503, "no recipients given")),
            _ => Action::Reply(Reply::line(503, "send MAIL FROM and RCPT TO first")),
        }
    }

    /// Handles `STARTTLS`.
    fn starttls(&mut self) -> Action {
        if !self.policy.tls_available {
            return Action::Reply(Reply::line(454, "TLS not available"));
        }
        if self.tls_active {
            return Action::Reply(Reply::line(503, "TLS already active"));
        }
        Action::StartTls(Reply::line(220, "ready to start TLS"))
    }

    /// Handles `AUTH`.
    ///
    /// The credential exchange itself is driven by the connection layer; this
    /// only decides whether authentication may be attempted at all.
    fn auth(&mut self) -> Action {
        if self.authenticated {
            return Action::Reply(Reply::line(503, "already authenticated"));
        }
        if !self.tls_active && !self.policy.allow_auth_without_tls {
            // AUTH PLAIN is base64, which is encoding rather than encryption.
            return Action::Reply(Reply::line(538, "encryption required for authentication"));
        }
        Action::Reply(Reply::line(334, ""))
    }

    /// Completes a transaction, returning the envelope to deliver.
    pub fn finish_data(&mut self) -> Option<Envelope> {
        if self.state != State::ReadingData {
            return None;
        }
        let envelope = Envelope {
            sender: self.sender.clone()?,
            recipients: std::mem::take(&mut self.recipients),
            helo: self.helo.clone().unwrap_or_default(),
        };
        self.reset_transaction();
        self.state = State::Ready;
        Some(envelope)
    }

    /// Clears the current transaction without ending the session.
    fn reset_transaction(&mut self) {
        self.sender = None;
        self.recipients.clear();
        if self.helo.is_some() {
            self.state = State::Ready;
        }
    }
}

/// Strips a keyword such as `FROM:` from a command argument, case-insensitively.
fn strip_keyword<'a>(rest: &'a str, keyword: &str) -> Option<&'a str> {
    let trimmed = rest.trim_start();
    if trimmed.len() < keyword.len() {
        return None;
    }
    let (head, tail) = trimmed.split_at(keyword.len());
    head.eq_ignore_ascii_case(keyword).then(|| tail.trim())
}

/// Removes the dot-stuffing applied to message content.
///
/// A line of message text that begins with `.` is sent with an extra `.` so it
/// cannot be mistaken for the terminator. Failing to undo this corrupts any
/// message containing such a line — and failing to *apply* it on the sending
/// side lets content terminate the transfer early, which is a message-injection
/// bug.
pub fn undo_dot_stuffing(body: &str) -> String {
    body.split("\r\n")
        .map(|line| line.strip_prefix("..").map(|rest| format!(".{rest}")).unwrap_or_else(|| line.to_owned()))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Applies dot-stuffing to message content before transmission.
pub fn apply_dot_stuffing(body: &str) -> String {
    body.split("\r\n")
        .map(|line| if let Some(rest) = line.strip_prefix('.') { format!("..{rest}") } else { line.to_owned() })
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            hostname: "mail.example.com".into(),
            local_domains: vec!["example.com".into(), "leveluplongboarding.surf".into()],
            tls_available: true,
            allow_auth_without_tls: false,
            max_message_bytes: 25 * 1024 * 1024,
        }
    }

    fn session() -> Session {
        let mut s = Session::new(policy());
        s.command("EHLO client.test");
        s
    }

    fn reply_of(action: Action) -> Reply {
        match action {
            Action::Reply(r) | Action::ReadData(r) | Action::Close(r) | Action::StartTls(r) => r,
        }
    }

    fn code_of(action: Action) -> u16 {
        reply_of(action).code
    }

    // ---- the open-relay defence -------------------------------------------

    #[test]
    fn accepts_mail_for_our_own_domains() {
        let mut s = session();
        assert_eq!(code_of(s.command("MAIL FROM:<stranger@elsewhere.com>")), 250);
        assert_eq!(code_of(s.command("RCPT TO:<dave@example.com>")), 250);
    }

    #[test]
    fn refuses_to_relay_for_strangers() {
        // The failure this whole module exists to prevent. An unauthenticated
        // session must never be able to send mail to a domain we do not host.
        let mut s = session();
        s.command("MAIL FROM:<stranger@elsewhere.com>");
        let reply = reply_of(s.command("RCPT TO:<victim@somewhere-else.com>"));
        assert_eq!(reply.code, 550);
        assert!(reply.lines[0].contains("relay not permitted"));
    }

    #[test]
    fn authentication_is_what_permits_relaying() {
        let mut s = session();
        s.tls_established();
        s.command("EHLO client.test");
        s.authentication_succeeded();
        s.command("MAIL FROM:<dave@example.com>");
        // Our own user sending outward is submission, not relaying.
        assert_eq!(code_of(s.command("RCPT TO:<friend@somewhere-else.com>")), 250);
    }

    #[test]
    fn relay_check_is_case_insensitive() {
        // Matching raw strings would let EXAMPLE.COM slip past a check written
        // for example.com, or vice versa.
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        assert_eq!(code_of(s.command("RCPT TO:<dave@EXAMPLE.COM>")), 250);
        assert_eq!(code_of(s.command("RCPT TO:<dave@Example.Com>")), 250);
    }

    #[test]
    fn source_routed_relay_attempts_are_judged_on_the_final_mailbox() {
        // Obsolete source routing was a relaying mechanism; the route must not
        // be able to disguise a foreign recipient as a local one.
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        assert_eq!(code_of(s.command("RCPT TO:<@example.com:victim@elsewhere.com>")), 550);
    }

    // ---- credential protection --------------------------------------------

    #[test]
    fn auth_is_refused_before_tls() {
        // AUTH PLAIN is base64, not encryption.
        let mut s = session();
        assert_eq!(code_of(s.command("AUTH PLAIN")), 538);
    }

    #[test]
    fn auth_is_not_advertised_before_tls() {
        let mut s = Session::new(policy());
        let reply = reply_of(s.command("EHLO client.test"));
        assert!(!reply.lines.iter().any(|l| l.starts_with("AUTH")));
        assert!(reply.lines.iter().any(|l| l == "STARTTLS"));
    }

    #[test]
    fn auth_is_advertised_once_tls_is_active() {
        let mut s = Session::new(policy());
        s.tls_established();
        let reply = reply_of(s.command("EHLO client.test"));
        assert!(reply.lines.iter().any(|l| l.starts_with("AUTH")));
        // STARTTLS must not be offered twice.
        assert!(!reply.lines.iter().any(|l| l == "STARTTLS"));
    }

    #[test]
    fn tls_upgrade_discards_everything_learned_in_cleartext() {
        // Anything said before the upgrade could have been injected by a man in
        // the middle, so the standard requires forgetting it.
        let mut s = session();
        s.command("MAIL FROM:<dave@example.com>");
        s.command("RCPT TO:<other@example.com>");
        s.tls_established();

        assert_eq!(s.state(), State::Greeted);
        assert_eq!(code_of(s.command("DATA")), 503);
    }

    // ---- command sequencing ------------------------------------------------

    #[test]
    fn commands_must_arrive_in_order() {
        let mut s = Session::new(policy());
        assert_eq!(code_of(s.command("MAIL FROM:<a@b.com>")), 503);

        s.command("EHLO client.test");
        assert_eq!(code_of(s.command("RCPT TO:<dave@example.com>")), 503);
        assert_eq!(code_of(s.command("DATA")), 503);

        s.command("MAIL FROM:<a@b.com>");
        assert_eq!(code_of(s.command("DATA")), 503, "DATA with no recipients");
    }

    #[test]
    fn a_full_transaction_produces_an_envelope() {
        let mut s = session();
        s.command("MAIL FROM:<sender@elsewhere.com>");
        s.command("RCPT TO:<dave@example.com>");
        s.command("RCPT TO:<crew@leveluplongboarding.surf>");
        assert!(matches!(s.command("DATA"), Action::ReadData(_)));

        let envelope = s.finish_data().unwrap();
        assert_eq!(envelope.recipients.len(), 2);
        assert_eq!(envelope.sender.address().unwrap().to_string(), "sender@elsewhere.com");
        assert_eq!(envelope.helo, "client.test");
        // The session is reusable for another message on the same connection.
        assert_eq!(s.state(), State::Ready);
    }

    #[test]
    fn duplicate_recipients_are_stored_once() {
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        s.command("RCPT TO:<dave@example.com>");
        assert_eq!(code_of(s.command("RCPT TO:<DAVE@example.com>")), 250);
        s.command("DATA");
        assert_eq!(s.finish_data().unwrap().recipients.len(), 1);
    }

    #[test]
    fn rset_clears_the_transaction_but_keeps_the_session() {
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        s.command("RCPT TO:<dave@example.com>");
        assert_eq!(code_of(s.command("RSET")), 250);
        assert_eq!(s.state(), State::Ready);
        assert_eq!(code_of(s.command("DATA")), 503);
    }

    #[test]
    fn the_null_sender_is_accepted_for_bounces() {
        let mut s = session();
        assert_eq!(code_of(s.command("MAIL FROM:<>")), 250);
        assert_eq!(code_of(s.command("RCPT TO:<dave@example.com>")), 250);
    }

    #[test]
    fn the_null_path_is_refused_as_a_recipient() {
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        assert_eq!(code_of(s.command("RCPT TO:<>")), 550);
    }

    #[test]
    fn esmtp_parameters_after_the_address_are_ignored() {
        let mut s = session();
        assert_eq!(code_of(s.command("MAIL FROM:<a@b.com> SIZE=1024 BODY=8BITMIME")), 250);
    }

    #[test]
    fn keywords_are_case_insensitive() {
        let mut s = session();
        assert_eq!(code_of(s.command("mail from:<a@b.com>")), 250);
        assert_eq!(code_of(s.command("rcpt to:<dave@example.com>")), 250);
    }

    #[test]
    fn recipients_are_capped() {
        let mut s = session();
        s.command("MAIL FROM:<a@b.com>");
        for i in 0..MAX_RECIPIENTS {
            assert_eq!(code_of(s.command(&format!("RCPT TO:<user{i}@example.com>"))), 250);
        }
        assert_eq!(code_of(s.command("RCPT TO:<overflow@example.com>")), 452);
    }

    #[test]
    fn overlong_lines_are_refused() {
        let mut s = session();
        assert_eq!(code_of(s.command(&"A".repeat(MAX_COMMAND_LINE + 1))), 500);
    }

    #[test]
    fn vrfy_does_not_confirm_which_addresses_exist() {
        // Answering would be a directory service for spammers.
        let mut s = session();
        assert_eq!(code_of(s.command("VRFY dave@example.com")), 252);
    }

    #[test]
    fn quit_closes_the_connection() {
        let mut s = session();
        assert!(matches!(s.command("QUIT"), Action::Close(_)));
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn unknown_commands_are_declined_not_fatal() {
        let mut s = session();
        assert_eq!(code_of(s.command("FROBNICATE")), 502);
        // The session survives.
        assert_eq!(code_of(s.command("NOOP")), 250);
    }

    // ---- reply formatting ---------------------------------------------------

    #[test]
    fn multi_line_replies_use_the_continuation_hyphen() {
        // A client reads the hyphen to know more lines follow; getting it wrong
        // hangs the session.
        let reply = Reply::multi(250, vec!["first".into(), "second".into(), "last".into()]);
        assert_eq!(reply.to_wire(), "250-first\r\n250-second\r\n250 last\r\n");
    }

    #[test]
    fn single_line_replies_have_no_hyphen() {
        assert_eq!(Reply::line(250, "OK").to_wire(), "250 OK\r\n");
    }

    // ---- dot stuffing -------------------------------------------------------

    #[test]
    fn dot_stuffing_round_trips() {
        let original = "line one\r\n.hidden\r\n..double\r\nlast";
        let stuffed = apply_dot_stuffing(original);
        assert_eq!(stuffed, "line one\r\n..hidden\r\n...double\r\nlast");
        assert_eq!(undo_dot_stuffing(&stuffed), original);
    }

    #[test]
    fn a_line_of_a_single_dot_cannot_terminate_the_message_early() {
        // Without stuffing, this content would end the transfer and the rest
        // would be interpreted as SMTP commands — message injection.
        let body = "before\r\n.\r\nafter";
        let stuffed = apply_dot_stuffing(body);
        assert_eq!(stuffed, "before\r\n..\r\nafter");
        assert_eq!(undo_dot_stuffing(&stuffed), body);
    }
}
