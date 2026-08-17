//! Putting a report in the owner's inbox, which is the whole point of the intake.
//!
//! A report that lands in a database nobody opens is a report nobody reads. This box already
//! runs the owner's mail server, so the delivery route that needs nothing on the owner's side
//! — no app, no polling, no dashboard left open — is a message into the mailbox their phone
//! and their laptop are already logged into. An agent files, and the report is *there*.
//!
//! # Local submission, not relaying
//!
//! The message is handed to this machine's own SMTP receiver on loopback, addressed to a
//! mailbox this machine hosts. That is a local delivery — the open-relay rule
//! [`selfhost_mail::smtp`] enforces is not engaged, no credential is needed, and nothing
//! leaves the box. It is also the only sanctioned way in: the receiver is the sole allocator
//! of IMAP UIDs (`selfhost_mail::store`, seam S-1), so a second process writing into the
//! Maildir behind its back would break the mailbox for every client reading it.
//!
//! # The message is built from cleaned fields only
//!
//! Every value written into a header has already been through [`crate::report::one_line`],
//! so it carries no CR, LF or NUL and cannot become a second header. A subject that is not
//! ASCII is encoded as one RFC 2047 word rather than sent raw, because a raw 8-bit subject
//! is what makes a client show mojibake or a filter score the message as spam. The body is
//! `text/plain; charset=utf-8` — never HTML, because rendering a stranger's markup in a mail
//! client is exactly the thing this repository refuses to do anywhere else.
//!
//! # Failure never loses a report
//!
//! Delivery is attempted after the record is stored, never before, and a failure leaves the
//! record marked undelivered for [`crate::service`]'s retry to pick up. The store is the
//! durable thing; the mailbox is the fast thing.

use std::time::{Duration, SystemTime};

use selfhost_mail::{Address, SmtpClient, deliver_to_host};

use crate::clock;
use crate::store::Entry;

/// How long one delivery attempt may take before it is abandoned and retried later.
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);

/// Where notifications come from and go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// The envelope and header sender, e.g. `reports@example.com`.
    pub from: String,
    /// The owner's address — the inbox a report has to reach.
    pub to: String,
    /// The name this box greets its own SMTP server with.
    pub helo: String,
    /// Host of the SMTP server to submit to. Loopback, normally.
    pub host: String,
    /// Port of that server.
    pub port: u16,
}

impl Mailbox {
    /// A mailbox delivering to `to` as `from`, over the SMTP server at `host:port`.
    ///
    /// # Errors
    /// Returns a sentence when either address is not an address. This is checked once, here,
    /// so that nothing downstream has to wonder whether a header value is safe.
    pub fn new(from: &str, to: &str, helo: &str, host: &str, port: u16) -> Result<Self, String> {
        let from = Address::parse(from)
            .map_err(|error| format!("the report sender `{from}` is not an address: {error:?}"))?;
        let to = Address::parse(to)
            .map_err(|error| format!("the report recipient `{to}` is not an address: {error:?}"))?;
        let helo = crate::report::one_line(helo);
        let host = crate::report::one_line(host);
        if helo.is_empty() || host.is_empty() {
            return Err("a mailbox needs a HELO name and an SMTP host".to_string());
        }
        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            helo,
            host,
            port,
        })
    }
}

/// The RFC 5322 message announcing `entry`, as bytes ready for `DATA`.
///
/// `now` stamps the `Date` header and seeds the `Message-ID`, both taken as parameters so the
/// shape of a message is testable without a clock.
#[must_use]
pub fn message(mailbox: &Mailbox, entry: &Entry, now: SystemTime) -> Vec<u8> {
    let subject = subject_for(entry);
    let stamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let domain = mailbox.from.rsplit('@').next().unwrap_or("localhost");

    let mut head = String::new();
    head.push_str(&format!("Date: {}\r\n", clock::rfc5322(now)));
    head.push_str(&format!("From: dx reports <{}>\r\n", mailbox.from));
    head.push_str(&format!("To: <{}>\r\n", mailbox.to));
    head.push_str(&format!("Subject: {subject}\r\n"));
    head.push_str(&format!("Message-ID: <{}.{stamp}@{domain}>\r\n", entry.id));
    head.push_str("MIME-Version: 1.0\r\n");
    head.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    head.push_str("Content-Transfer-Encoding: 8bit\r\n");
    // RFC 3834: this is a machine writing, so nothing should reply to it and no vacation
    // responder should answer it — one loop between two auto-responders is a full mailbox.
    head.push_str("Auto-Submitted: auto-generated\r\n");
    head.push_str(&format!("X-Report-Id: {}\r\n", entry.id));
    head.push_str(&format!("X-Report-Sightings: {}\r\n", entry.sightings));
    head.push_str("\r\n");

    let mut body = String::new();
    body.push_str(&format!(
        "{} · {} — {}\r\n\r\n",
        entry.project,
        entry.kind.as_str(),
        entry.title
    ));
    body.push_str(&wrapped(&entry.detail));
    if !entry.route.is_empty() {
        body.push_str(&format!("\r\n\r\nRoute: {}", entry.route));
    }
    if !entry.repro.is_empty() {
        body.push_str(&format!("\r\n\r\nRepro:\r\n{}", wrapped(&entry.repro)));
    }
    body.push_str("\r\n\r\n--\r\n");
    body.push_str(&format!("{}\r\n", entry.id));
    body.push_str(&format!(
        "reported {} time(s), first {}, last {}\r\n",
        entry.sightings, entry.first_at, entry.last_at
    ));
    for sighting in entry.seen.iter().rev().take(3) {
        body.push_str(&format!(
            "  {} · {} · {} · {} · src {}\r\n",
            sighting.at,
            or_dash(&sighting.tool),
            or_dash(&sighting.platform),
            or_dash(&sighting.workspace),
            or_dash(&sighting.source)
        ));
    }
    body.push_str(&format!(
        "close it with `selfhost reports close {} {}`\r\n",
        entry.project, entry.id
    ));

    let mut out = head.into_bytes();
    out.extend_from_slice(
        body.replace('\n', "\r\n")
            .replace("\r\r\n", "\r\n")
            .as_bytes(),
    );
    out
}

/// Delivers `message` through `mailbox`'s SMTP server.
///
/// # Errors
/// Returns a sentence naming what refused: the socket, the server's reply, or the timeout.
/// Every one of them is a *retry later*, never a lost report — the record is already stored
/// when this is called.
pub async fn send(mailbox: &Mailbox, message: &[u8]) -> Result<(), String> {
    let mut client = SmtpClient::new(
        mailbox.helo.clone(),
        format!("<{}>", mailbox.from),
        vec![mailbox.to.clone()],
    );
    let attempt = deliver_to_host(&mailbox.host, mailbox.port, &mut client, message, None);
    let delivery = tokio::time::timeout(DELIVERY_TIMEOUT, attempt)
        .await
        .map_err(|_| {
            format!(
                "{}:{} did not finish the delivery within {} seconds",
                mailbox.host,
                mailbox.port,
                DELIVERY_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| {
            format!(
                "{}:{} refused the report: {error}",
                mailbox.host, mailbox.port
            )
        })?;

    if delivery.accepted.is_empty() {
        return Err(format!(
            "{}:{} accepted no recipient (last code {})",
            mailbox.host, mailbox.port, delivery.last_code
        ));
    }
    Ok(())
}

/// The `Subject` line for one report, RFC 2047-encoded when it is not ASCII.
fn subject_for(entry: &Entry) -> String {
    let repeat = if entry.sightings > 1 {
        format!(" (seen {} times)", entry.sightings)
    } else {
        String::new()
    };
    let plain = format!(
        "[{} {}] {}{repeat}",
        entry.project,
        entry.kind.as_str(),
        entry.title
    );
    if plain.is_ascii() {
        return plain;
    }
    format!("=?UTF-8?B?{}?=", base64(plain.as_bytes()))
}

/// Standard base64 with padding (RFC 4648 §4), for the one encoded-word above.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let packed = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        let digits = [
            ALPHABET[(packed >> 18) as usize & 63],
            ALPHABET[(packed >> 12) as usize & 63],
            ALPHABET[(packed >> 6) as usize & 63],
            ALPHABET[packed as usize & 63],
        ];
        for (position, digit) in digits.iter().enumerate() {
            if position <= chunk.len() {
                out.push(char::from(*digit));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Hard-wraps prose at 78 columns, leaving existing line breaks alone.
///
/// A mail body with 8,000 characters on one line is legal and unreadable; wrapping is done
/// here rather than left to the client because the client that matters is a phone.
fn wrapped(text: &str) -> String {
    text.lines()
        .map(|line| {
            let mut out = String::new();
            let mut column = 0;
            for word in line.split(' ') {
                let width = word.chars().count();
                if column > 0 && column + 1 + width > 78 {
                    out.push('\n');
                    column = 0;
                } else if column > 0 {
                    out.push(' ');
                    column += 1;
                }
                out.push_str(word);
                column += width;
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The value, or a dash when the reporter did not give one.
fn or_dash(value: &str) -> &str {
    if value.is_empty() { "—" } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Kind;
    use crate::store::Sighting;
    use std::time::UNIX_EPOCH;

    fn mailbox() -> Mailbox {
        Mailbox::new(
            "reports@example.com",
            "owner@example.com",
            "example.com",
            "127.0.0.1",
            25,
        )
        .expect("mailbox")
    }

    fn entry(title: &str) -> Entry {
        Entry {
            project: "dx".to_string(),
            id: "report-1a2b3c4d".to_string(),
            kind: Kind::Bug,
            title: title.to_string(),
            detail: "The search answered with the heading rather than the block.".to_string(),
            route: "dx_search".to_string(),
            repro: "dx search 'gpu'".to_string(),
            first_at: "2026-08-11T00:00:00Z".to_string(),
            last_at: "2026-08-11T00:00:00Z".to_string(),
            sightings: 1,
            seen: vec![Sighting {
                at: "2026-08-11T00:00:00Z".to_string(),
                tool: "dx 0.1.0".to_string(),
                platform: "macos".to_string(),
                workspace: "DOC".to_string(),
                source: "abcd1234".to_string(),
                detail: "…".to_string(),
            }],
            delivered: false,
            account_id: None,
        }
    }

    fn rendered(title: &str) -> String {
        String::from_utf8(message(&mailbox(), &entry(title), UNIX_EPOCH)).expect("utf-8")
    }

    #[test]
    fn the_message_carries_the_headers_a_client_sorts_by() {
        let text = rendered("search answers with the heading");
        assert!(
            text.starts_with("Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"),
            "{text}"
        );
        assert!(text.contains("From: dx reports <reports@example.com>\r\n"));
        assert!(text.contains("To: <owner@example.com>\r\n"));
        assert!(text.contains("Subject: [dx bug] search answers with the heading\r\n"));
        assert!(text.contains("Message-ID: <report-1a2b3c4d.0@example.com>\r\n"));
        assert!(text.contains("Auto-Submitted: auto-generated\r\n"));
        assert!(text.contains("X-Report-Id: report-1a2b3c4d\r\n"));
        assert!(
            text.contains("\r\n\r\n"),
            "the head must end with a blank line"
        );
    }

    #[test]
    fn the_body_says_what_to_do_about_it() {
        let text = rendered("a title");
        assert!(text.contains("dx · bug — a title"));
        assert!(text.contains("Route: dx_search"));
        assert!(text.contains("Repro:"));
        assert!(text.contains("close it with `selfhost reports close dx report-1a2b3c4d`"));
    }

    #[test]
    fn a_repeat_says_so_in_the_subject() {
        let mut repeated = entry("keeps happening");
        repeated.sightings = 7;
        let text = String::from_utf8(message(&mailbox(), &repeated, UNIX_EPOCH)).expect("utf-8");
        assert!(
            text.contains("Subject: [dx bug] keeps happening (seen 7 times)"),
            "{text}"
        );
    }

    /// The property the whole intake depends on: a title cannot open a second header.
    /// [`crate::report`] guarantees it at parse time; this proves the formatter relies on
    /// nothing else.
    #[test]
    fn a_cleaned_title_cannot_split_the_head() {
        let title = crate::report::one_line("boom\r\nBcc: victim@example.com");
        let text = rendered(&title);
        let head = text.split("\r\n\r\n").next().expect("head");
        assert!(!head.to_lowercase().contains("\r\nbcc:"), "{head}");
        assert_eq!(
            head.lines()
                .filter(|line| line.starts_with("Subject:"))
                .count(),
            1
        );
    }

    #[test]
    fn a_subject_that_is_not_ascii_is_encoded_as_one_word() {
        let text = rendered("búsqueda falla — ünicode");
        let subject = text
            .lines()
            .find(|line| line.starts_with("Subject:"))
            .expect("subject");
        assert!(subject.starts_with("Subject: =?UTF-8?B?"), "{subject}");
        assert!(subject.ends_with("?="), "{subject}");
        assert!(subject.is_ascii(), "an encoded word is ASCII by definition");
    }

    #[test]
    fn base64_matches_the_examples_from_the_specification() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn every_body_line_stays_readable_on_a_phone() {
        let mut long = entry("wrapped");
        long.detail = "word ".repeat(120);
        let text = String::from_utf8(message(&mailbox(), &long, UNIX_EPOCH)).expect("utf-8");
        assert!(
            text.lines().all(|line| line.chars().count() <= 80),
            "a line ran long"
        );
    }

    #[test]
    fn an_address_that_is_not_an_address_is_refused_when_the_mailbox_is_built() {
        let error = Mailbox::new("not an address", "owner@example.com", "h", "127.0.0.1", 25)
            .expect_err("refused");
        assert!(error.contains("is not an address"), "{error}");
    }

    #[test]
    fn the_whole_message_ends_with_crlf_line_endings_only() {
        let text = rendered("endings");
        assert!(
            !text.contains("\r\r"),
            "a doubled carriage return would corrupt DATA"
        );
        for line in text.split("\r\n") {
            assert!(!line.contains('\n'), "a bare LF survived: {line:?}");
        }
    }
}
