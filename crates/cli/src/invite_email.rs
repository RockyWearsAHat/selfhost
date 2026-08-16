//! Sending an invitation to the person it is for.
//!
//! # Why this exists now, and why it did not before
//!
//! `people-lab.dx` recorded, under what has never executed anywhere: *"An
//! invitation cannot be sent from here … it is deliberately not built, because a
//! credential that travels by itself travels to whatever address was typed, and
//! a typo is then somebody else's account."* That objection is real and this
//! module does not pretend to have dissolved it. What it does is make the
//! failure survivable and visible rather than silent:
//!
//! - The address is echoed back before anything is spooled, next to the name and
//!   the capabilities, so the operator reads the destination as part of reading
//!   the grant.
//! - Where the invitation was sent is recorded beside it, so `people invited`
//!   can answer *where did this go* — the question a typo makes urgent, and the
//!   one a printed code could never answer either.
//! - The invitation is still one-time, still short-lived, and still withdrawable
//!   with `people uninvite`, which is the actual remedy when the address was
//!   wrong. A code that went to a stranger is revoked in one command, and the
//!   stranger holds nothing in the meantime — registering needs the code *and*
//!   an authenticator ceremony, and the name is taken from the invitation, so a
//!   misdelivered code can only ever produce a passkey under the invited name,
//!   which is then visible in the console and revocable there.
//!
//! What it deliberately does not do is hide the sending behind a default:
//! `--email` is typed, every time, and without it the command behaves exactly as
//! it always has.
//!
//! # The message goes through the queue, not down a socket
//!
//! This command spools into `<data_dir>/mail/queue` and returns. It does not
//! open an SMTP connection itself, and that is the whole design: the daemon's
//! queue runner already signs with DKIM at send time, routes over MX, retries a
//! deferral, and speaks STARTTLS. Duplicating any of that here would mean a
//! second, less-tested send path whose failures look different from every other
//! message this deployment sends. The cost is that "sent" means "accepted for
//! delivery" — so the command says exactly that, and says which log to read.

use selfhost_config::Config;
use selfhost_mail::{Address, Envelope, Message, OutboundQueue, Path as MailPath};
use std::path::Path;

/// Why an invitation could not be prepared for sending.
///
/// Each variant is a thing the operator can fix, and the `Display` text says how
/// — these are read at a terminal by somebody mid-task, not caught in code.
#[derive(Debug)]
pub enum SendError {
    /// The deployment declares no `[mail]` section.
    NoMailSubsystem,
    /// `[mail]` exists but declares no mailbox to send from.
    NoMailbox,
    /// The address the operator typed is not a valid address.
    BadAddress {
        /// What they typed.
        typed: String,
        /// Why it did not parse.
        reason: String,
    },
    /// The configured sending mailbox does not parse, which is a config bug.
    BadSender {
        /// The address as configured.
        configured: String,
    },
    /// The spool could not be written.
    Spool(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMailSubsystem => write!(
                f,
                "this deployment has no [mail] section, so it cannot send anything.\n  \
                 Mint the invitation without --email and send the code yourself."
            ),
            Self::NoMailbox => write!(
                f,
                "[mail] declares no mailboxes, so there is no address to send from.\n  \
                 Add a [[mail.mailboxes]] block, or mint the invitation without --email."
            ),
            Self::BadAddress { typed, reason } => write!(
                f,
                "\"{typed}\" is not an email address: {reason}.\n  \
                 Nothing was sent and no invitation was minted."
            ),
            Self::BadSender { configured } => write!(
                f,
                "the configured mailbox \"{configured}\" is not a valid address, so nothing \
                 can be sent from it.\n  Fix the [[mail.mailboxes]] block."
            ),
            Self::Spool(reason) => write!(
                f,
                "the invitation was minted but could not be queued for sending: {reason}.\n  \
                 The code is printed above — send it yourself, or withdraw it with \
                 `selfhost people uninvite`."
            ),
        }
    }
}

impl std::error::Error for SendError {}

/// The address an invitation will be sent from, for a deployment that can send.
///
/// The first declared mailbox, which on every deployment this project has is the
/// owner's own. Chosen rather than invented (`no-reply@`) because a person
/// receiving a credential should be able to reply to the human who sent it and
/// ask whether it is real — an invitation from an address that discards replies
/// trains exactly the habit that makes phishing work.
pub fn sender(config: &Config) -> Result<&str, SendError> {
    let mail = config.mail.as_ref().ok_or(SendError::NoMailSubsystem)?;
    mail.mailboxes
        .first()
        .map(|mailbox| mailbox.address.as_str())
        .ok_or(SendError::NoMailbox)
}

/// Validates the address the operator typed, before anything is minted.
///
/// Separate from [`send`] and called first, so a typo that cannot be an address
/// at all costs nothing: no invitation exists, no previous invitation for that
/// person has been superseded, and there is nothing to withdraw.
pub fn check_address(typed: &str) -> Result<Address, SendError> {
    Address::parse(typed).map_err(|reason| SendError::BadAddress {
        typed: typed.to_owned(),
        reason: reason.to_string(),
    })
}

/// Spools the invitation message, returning the queue id.
///
/// `link` is the whole thing the person needs — either a URL they can open or,
/// on a deployment with no console site, the bare code with a sentence saying so.
pub fn send(
    config: &Config,
    data_dir: &Path,
    name: &str,
    to: &Address,
    body: &str,
) -> Result<String, SendError> {
    let from_text = sender(config)?;
    let from = Address::parse(from_text).map_err(|_| SendError::BadSender {
        configured: from_text.to_owned(),
    })?;
    let helo = config
        .mail
        .as_ref()
        .map(|mail| mail.hostname.clone())
        .unwrap_or_else(|| from.domain().to_owned());

    let message = compose(&from, to, name, body, &helo);
    let envelope = Envelope {
        sender: MailPath::Mailbox(from),
        recipients: vec![to.clone()],
        helo: helo.clone(),
    };

    OutboundQueue::open(data_dir)
        .and_then(|queue| queue.enqueue(&envelope, &message))
        .map_err(|error| SendError::Spool(error.to_string()))
}

/// Builds the RFC 5322 message.
///
/// Plain text only, and no HTML alternative. A message that asks somebody to
/// open a link and prove who they are is the exact shape of a phishing mail, and
/// the honest response to that is to look as little like marketing as possible:
/// no images, no tracking, no styled button hiding its destination. The URL is
/// written out where it can be read before it is clicked.
fn compose(from: &Address, to: &Address, name: &str, body: &str, helo: &str) -> Message {
    let date = rfc5322_date();
    let id = message_id(helo);
    let mut raw = String::new();
    raw.push_str(&format!("Date: {date}\r\n"));
    raw.push_str(&format!("From: {from}\r\n"));
    raw.push_str(&format!("To: {to}\r\n"));
    raw.push_str(&format!("Message-ID: {id}\r\n"));
    raw.push_str(&format!("Subject: You have been given access to {helo}\r\n"));
    raw.push_str("MIME-Version: 1.0\r\n");
    raw.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    raw.push_str("Content-Transfer-Encoding: 8bit\r\n");
    // Nothing here should ever be replied to by an automaton, and no mailing
    // list machinery should touch a credential.
    raw.push_str("Auto-Submitted: auto-generated\r\n");
    raw.push_str("\r\n");

    for line in body.lines() {
        // Dot-stuffing is the SMTP client's job, not the composer's; what
        // matters here is CRLF line endings, which DKIM canonicalisation and
        // every receiving parser assume.
        raw.push_str(line);
        raw.push_str("\r\n");
    }

    raw.push_str("\r\n");
    raw.push_str(&format!(
        "This invitation was created for {name}. If you were not expecting it, ignore \
         this message and tell the person who runs {helo} — the code expires on its own \
         and can be withdrawn at any time.\r\n"
    ));

    Message::parse(raw.into_bytes()).expect("a message this module composed must parse")
}

/// `Date:` in the form RFC 5322 asks for.
///
/// Built from the HTTP date formatter rather than a second implementation of the
/// civil-calendar arithmetic: same instant, same tested conversion, and only the
/// zone spelling differs — HTTP writes the obsolete `GMT`, mail writes `+0000`.
fn rfc5322_date() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0);
    selfhost_http::date::format_unix(now).replace("GMT", "+0000")
}

/// A globally unique `Message-ID`, which a receiver uses to detect duplicates.
///
/// The queue re-attempts every destination on a partial delivery, so the same
/// message can legitimately arrive twice; a stable id is what lets the receiving
/// side collapse them rather than showing the invitation twice.
///
/// The uniqueness comes from the random half, not the clock. A first attempt
/// keyed the whole id on `SystemTime` nanoseconds and collided under test —
/// macOS does not hand out nanosecond-distinct readings for two calls in quick
/// succession, and two invitations minted in the same microsecond would then
/// have shared an id and been collapsed into one by the receiver. The timestamp
/// stays because it makes an id readable in a log; it is not what makes it
/// unique.
fn message_id(helo: &str) -> String {
    use ring::rand::SecureRandom;

    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let mut bytes = [0u8; 12];
    // A failure here would mean the system random source is gone, which is not
    // a condition this deployment can send mail under anyway; fall back to the
    // clock rather than panic in a command that has already minted a code.
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("<invite.{seconds:x}.{suffix}@{helo}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Address {
        Address::parse(text).expect("test address parses")
    }

    #[test]
    fn a_typo_that_is_not_an_address_is_refused_before_anything_is_minted() {
        let refusal = check_address("chriswaldmann.gmail.com").expect_err("no @, not an address");
        assert!(matches!(refusal, SendError::BadAddress { .. }));
        assert!(refusal.to_string().contains("no invitation was minted"));
    }

    #[test]
    fn a_real_address_passes_the_check() {
        assert_eq!(check_address("chriswaldmann@gmail.com").unwrap().to_string(), "chriswaldmann@gmail.com");
    }

    #[test]
    fn the_composed_message_has_the_headers_a_receiver_requires() {
        let message = compose(
            &address("alex@rockywearsahat.com"),
            &address("chriswaldmann@gmail.com"),
            "dad",
            "Open this: https://admin.rockywearsahat.com/#invite=abc",
            "rockywearsahat.com",
        );
        for header in ["Date", "From", "To", "Subject", "Message-ID", "MIME-Version"] {
            assert!(message.header(header).is_some(), "missing {header}");
        }
        assert_eq!(message.header("From").as_deref(), Some("alex@rockywearsahat.com"));
        assert_eq!(message.header("To").as_deref(), Some("chriswaldmann@gmail.com"));
    }

    #[test]
    fn the_body_carries_the_link_verbatim_and_is_not_dressed_up() {
        let link = "https://admin.rockywearsahat.com/#invite=2MoSp51voHUVJkEXtE2jQzhss2dej001";
        let message = compose(
            &address("alex@rockywearsahat.com"),
            &address("chriswaldmann@gmail.com"),
            "dad",
            &format!("Open this: {link}"),
            "rockywearsahat.com",
        );
        let body = String::from_utf8_lossy(message.body()).into_owned();
        assert!(body.contains(link), "the link must survive composition unaltered");
        assert!(!body.contains("<html"), "an invitation is plain text, never markup");
        assert!(
            body.contains("If you were not expecting it"),
            "the recipient is told what to do when the address was wrong"
        );
    }

    #[test]
    fn every_header_line_ends_crlf_so_dkim_canonicalisation_sees_what_it_expects() {
        let message = compose(
            &address("alex@rockywearsahat.com"),
            &address("chriswaldmann@gmail.com"),
            "dad",
            "code: abc",
            "rockywearsahat.com",
        );
        let raw = String::from_utf8_lossy(message.as_bytes()).into_owned();
        let headers = raw.split("\r\n\r\n").next().expect("headers exist");
        assert!(!headers.contains('\n') || headers.contains("\r\n"));
        for line in headers.split("\r\n") {
            assert!(!line.ends_with('\r'), "no bare CR: {line:?}");
        }
    }

    #[test]
    fn the_date_header_uses_the_numeric_zone_mail_expects_not_the_http_spelling() {
        let date = rfc5322_date();
        assert!(date.ends_with("+0000"), "got {date:?}");
        assert!(!date.contains("GMT"));
    }

    #[test]
    fn two_messages_do_not_share_a_message_id() {
        // Many ids, generated as fast as the machine will, because the bug this
        // guards was invisible at two and only appeared under a loaded test run:
        // a clock-keyed id repeats when two calls land inside one clock tick.
        let ids: std::collections::HashSet<String> =
            (0..1_000).map(|_| message_id("example.com")).collect();
        assert_eq!(ids.len(), 1_000, "message ids must not repeat");
    }
}
