//! Reading the audit trail back out, so an operator sees it in the console.
//!
//! `selfhost-identity` writes `data/audit.log`: one line per control action,
//! append-only, never rewritten. Writing it is half the job. A record nobody can
//! read is a record nobody checks, and *"grep the box"* is not an answer for the
//! one surface in this repository that can drive the machine — the operator most
//! likely to need the trail is the one who has just noticed their pointer moving
//! on its own, and they are looking at a browser.
//!
//! So this module is the read side: a **pure** parser for the format
//! [`AuditRecord::line`](selfhost_identity::AuditRecord::line) writes, a bounded
//! tail read over the file, and the JSON the console renders.
//!
//! # What a record does and does not say
//!
//! Each line answers four of the five questions an incident asks. *Who* is
//! `identity` and `who` — the owner, or a named person whose passkey signed for
//! them. *When* is `at`, wall-clock seconds since the epoch, because a record
//! outlives the process that wrote it. *What* is `capability` and `target`,
//! from the closed vocabulary the policy decided against, plus a `detail` that
//! names the specific thing without ever quoting it: typed text is recorded as
//! a unit count, never as the characters, so the log of somebody typing a
//! password is not itself a copy of the password. *Whether it was allowed* is
//! `outcome` and `reason`.
//!
//! The fifth question — **from where** — has no field, and its absence is
//! deliberate rather than an omission to be fixed later. Every request that
//! reaches this API arrives from `127.0.0.1`, because the console tunnel exits
//! on loopback and the admin API binds nothing else; a source-address column
//! would print the same four bytes on every line while *reading* as evidence of
//! provenance. What actually distinguishes one caller from another here is the
//! credential — `password`, `passkey`, `bearer`, `session` — and that is
//! recorded. See `docs/SECURITY.md` §3.5.
//!
//! # Bounded on purpose
//!
//! Nothing in this repository rotates the audit log, and one line per input
//! message means a long desktop session writes a lot of them. A reader that
//! loaded the file would be a way for a legitimate caller to make the daemon
//! allocate however large that file has grown, and under `panic = "abort"` a
//! failed allocation is the whole box. So the reader seeks to the end and reads
//! at most [`MAX_TAIL_BYTES`], discarding the first line it lands in the middle
//! of, and the caller may ask for at most [`MAX_LIMIT`] records.

use selfhost_identity::audit::{AUDIT_FORMAT, AuditLog, unescape_field};
use selfhost_json::Json;
use std::io::{Read, Seek, SeekFrom};

/// The most bytes read from the end of the log for one request.
///
/// 256 KiB is several thousand records of the shape this format produces, which
/// is far more than a console tail displays, and it is a ceiling a request
/// cannot raise.
pub const MAX_TAIL_BYTES: u64 = 256 * 1024;

/// The most records returned for one request.
pub const MAX_LIMIT: usize = 500;

/// How many records are returned when the caller does not ask.
pub const DEFAULT_LIMIT: usize = 100;

/// One line of the audit log, parsed.
///
/// Every field is exactly what was written, unescaped. The strings are owned
/// because they came out of a file and the parse is where the borrow ends;
/// there are at most [`MAX_LIMIT`] of these alive at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The record's own identifier, as written.
    pub id: String,
    /// When it happened, in seconds since the Unix epoch.
    pub at_unix: u64,
    /// `owner` or `person` — which kind of identity acted.
    pub identity: String,
    /// The name behind that identity.
    pub who: String,
    /// What was presented: `bearer`, `password`, `passkey` or `session`.
    pub credential: String,
    /// The capability that was decided, by its wire word.
    pub capability: String,
    /// The share or machine it named, empty for the capabilities that name
    /// nothing.
    pub target: String,
    /// `allow` or `refuse`.
    pub outcome: String,
    /// Why it was refused, or `-` for an allowed action.
    pub reason: String,
    /// The specific thing, as the writer described it.
    pub detail: String,
    /// Whether the detail was cut at the writer's length cap.
    ///
    /// Carried rather than folded into the text, so a console can show that
    /// something was elided instead of presenting a truncation as the whole
    /// value.
    pub detail_truncated: bool,
}

impl Entry {
    /// The wire shape the console draws.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("id", Json::string(&self.id)),
            ("at", Json::Number(self.at_unix as f64)),
            ("identity", Json::string(&self.identity)),
            ("who", Json::string(&self.who)),
            ("credential", Json::string(&self.credential)),
            ("capability", Json::string(&self.capability)),
            ("target", Json::string(&self.target)),
            ("outcome", Json::string(&self.outcome)),
            ("reason", Json::string(&self.reason)),
            ("detail", Json::string(&self.detail)),
            ("detailTruncated", Json::Bool(self.detail_truncated)),
        ])
    }
}

/// What one tail read found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tail {
    /// The records, **newest first** — the order a console tail is read in.
    pub entries: Vec<Entry>,
    /// How many lines were looked at.
    pub scanned: usize,
    /// How many of them this parser could not read.
    ///
    /// Reported rather than hidden. A non-zero count means either a line
    /// written by a different version of the format or a file somebody has
    /// edited, and both are things an operator reading an audit trail is
    /// entitled to know before they trust what they are looking at.
    pub unreadable: usize,
}

impl Tail {
    /// The wire shape the console draws.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("records", Json::Array(self.entries.iter().map(Entry::to_json).collect())),
            ("returned", Json::Number(self.entries.len() as f64)),
            ("scanned", Json::Number(self.scanned as f64)),
            ("unreadable", Json::Number(self.unreadable as f64)),
        ])
    }
}

/// Parses one line, or `None` for anything this format did not write.
///
/// Pure and total. The rules are the format's own, read in the strict
/// direction: the line must open with the format marker, every field must be
/// present, and a field whose escaping does not decode makes the whole line
/// unreadable rather than a record with one guessed value in it. A reader that
/// repaired what it could would be a reader whose output is partly evidence and
/// partly invention.
pub fn parse_line(line: &str) -> Option<Entry> {
    let mut tokens = line.split(' ').filter(|token| !token.is_empty());
    if tokens.next()? != AUDIT_FORMAT {
        return None;
    }

    let mut id = None;
    let mut at = None;
    let mut identity = None;
    let mut who = None;
    let mut credential = None;
    let mut capability = None;
    let mut target = None;
    let mut outcome = None;
    let mut reason = None;
    let mut detail = None;

    for token in tokens {
        let (name, value) = token.split_once('=')?;
        match name {
            "id" => id = Some(value.to_owned()),
            "at" => at = Some(value.parse::<u64>().ok()?),
            "identity" => identity = Some(value.to_owned()),
            "who" => who = Some(unescape_field(value)?),
            "credential" => credential = Some(value.to_owned()),
            "capability" => capability = Some(unescape_field(value)?),
            "target" => target = Some(unescape_field(value)?),
            "outcome" => outcome = Some(value.to_owned()),
            "reason" => reason = Some(value.to_owned()),
            "detail" => detail = Some(unescape_field(value)?),
            // A field this build does not know is not a corrupt line: it is a
            // newer writer. The known fields are still exactly what they say.
            _ => {}
        }
    }

    let (detail, detail_truncated) = detail?;
    Some(Entry {
        id: id?,
        at_unix: at?,
        identity: identity?,
        who: who?.0,
        credential: credential?,
        capability: capability?.0,
        target: target?.0,
        outcome: outcome?,
        reason: reason?,
        detail,
        detail_truncated,
    })
}

/// Parses a block of log text, newest first, keeping at most `limit` records.
///
/// Pure, which is what makes the ordering and the truncation rules testable
/// without a file. `text` is expected to be the *tail* of the log with any
/// partial first line already removed — see [`tail`], which is the only thing
/// that knows how to do that safely.
pub fn records(text: &str, limit: usize) -> Tail {
    let mut found = Tail::default();
    for line in text.lines().rev() {
        if line.is_empty() {
            continue;
        }
        found.scanned = found.scanned.saturating_add(1);
        match parse_line(line) {
            Some(entry) => {
                if found.entries.len() < limit {
                    found.entries.push(entry);
                }
            }
            None => found.unreadable = found.unreadable.saturating_add(1),
        }
        // Stop walking once the answer is full and the count of unreadable
        // lines covers everything the answer was drawn from. Scanning the whole
        // 256 KiB to report a number nobody asked for would be work done for the
        // log's benefit rather than the reader's.
        if found.entries.len() >= limit {
            break;
        }
    }
    found
}

/// Reads the end of the log and parses it.
///
/// The only I/O in this module, and the only place the bound on how much of the
/// file may be touched is enforced. A missing log is an empty [`Tail`], not an
/// error: a deployment that has never performed a control action has never
/// written a line, and reporting that as a failure would send an operator
/// looking for a broken subsystem instead of showing them an empty list.
///
/// A partial first line is discarded whenever the read started anywhere but the
/// beginning of the file, because the tail of a 256 KiB window almost never
/// falls on a line boundary and half a record is not a record.
pub fn tail(log: &AuditLog, limit: usize) -> std::io::Result<Tail> {
    let limit = limit.clamp(1, MAX_LIMIT);
    let mut file = match std::fs::File::open(log.path()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Tail::default()),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    let from = length.saturating_sub(MAX_TAIL_BYTES);
    if from > 0 {
        file.seek(SeekFrom::Start(from))?;
    }
    // `take` bounds the read even if the file grew between the metadata call
    // and here, which it can: the daemon appends to this file while it is being
    // read.
    let mut bytes = Vec::new();
    file.take(MAX_TAIL_BYTES).read_to_end(&mut bytes)?;

    // Lossy on purpose. The format escapes every byte outside printable ASCII,
    // so a well-formed line survives this untouched; a line that does not is
    // one `parse_line` refuses anyway, and refusing to show the *rest* of the
    // log because one line has a stray byte in it would be the wrong failure.
    let text = String::from_utf8_lossy(&bytes);
    let complete = if from > 0 {
        match text.find('\n') {
            Some(end) => &text[end + 1..],
            // The whole window is one unterminated line: there is no complete
            // record in it to show.
            None => "",
        }
    } else {
        &text
    };
    Ok(records(complete, limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::audit::{AuditId, AuditRecord};
    use selfhost_identity::{Capability, Credential, Decision, Identity, NodeName, Refusal};

    fn node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a valid node name")
    }

    fn written(detail: &str, decision: Decision) -> String {
        AuditRecord {
            id: AuditId::from_bytes([0x11; 16]),
            at_unix: 1_754_000_000,
            identity: Identity::Owner,
            credential: Credential::Passkey,
            capability: Capability::DesktopControl(node()),
            decision,
            detail: detail.to_owned(),
        }
        .line()
    }

    #[test]
    fn a_line_this_workspace_wrote_reads_back_field_for_field() {
        let entry = parse_line(&written("keydown:0x04", Decision::Allow)).expect("a known format");
        assert_eq!(entry.id, "11111111111111111111111111111111");
        assert_eq!(entry.at_unix, 1_754_000_000);
        assert_eq!(entry.identity, "owner");
        assert_eq!(entry.who, "owner");
        assert_eq!(entry.credential, "passkey");
        assert_eq!(entry.capability, "desktop.control");
        assert_eq!(entry.target, "alex-desktop");
        assert_eq!(entry.outcome, "allow");
        assert_eq!(entry.reason, "-");
        assert_eq!(entry.detail, "keydown:0x04");
        assert!(!entry.detail_truncated);
    }

    #[test]
    fn a_refusal_carries_the_reason_the_policy_gave() {
        let line = written("text:7units", Decision::Refuse(Refusal::CredentialNotArmed));
        let entry = parse_line(&line).expect("a known format");
        assert_eq!(entry.outcome, "refuse");
        assert_eq!(entry.reason, Refusal::CredentialNotArmed.as_str());
    }

    #[test]
    fn a_detail_that_was_cut_says_so_rather_than_presenting_the_stump() {
        let entry = parse_line(&written(&"x".repeat(400), Decision::Allow)).expect("a known format");
        assert!(entry.detail_truncated);
        assert_eq!(entry.detail.len(), 256);
    }

    #[test]
    fn a_detail_that_looks_like_a_log_line_comes_back_as_one_field() {
        // The writer escapes spaces and `=`; the reader must give the text back
        // whole rather than having read a forged record out of the middle of it.
        let forged = "selfhost-audit/1 id=deadbeef outcome=allow";
        let entry = parse_line(&written(forged, Decision::Allow)).expect("a known format");
        assert_eq!(entry.detail, forged);
        assert_eq!(entry.outcome, "allow");
        assert_eq!(entry.id, "11111111111111111111111111111111");
    }

    #[test]
    fn anything_this_format_did_not_write_is_refused_whole() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("selfhost-audit/2 id=a at=1"), None);
        // Every field is required; a line missing one is not a record with a
        // guessed value in it.
        let missing = written("x", Decision::Allow).replace(" outcome=allow", "");
        assert_eq!(parse_line(&missing), None);
        // A malformed escape is a line this crate did not write.
        let broken = written("x", Decision::Allow).replace("detail=x", "detail=%zz");
        assert_eq!(parse_line(&broken), None);
    }

    #[test]
    fn an_unknown_field_from_a_newer_writer_does_not_void_the_line() {
        let extended = format!("{} source=console", written("x", Decision::Allow));
        assert_eq!(parse_line(&extended).map(|entry| entry.detail), Some("x".to_owned()));
    }

    #[test]
    fn the_tail_is_newest_first_and_stops_at_the_limit() {
        let mut log = String::new();
        for index in 0..10u64 {
            let mut record = written("x", Decision::Allow);
            record = record.replace("at=1754000000", &format!("at={}", 1_754_000_000 + index));
            log.push_str(&record);
            log.push('\n');
        }
        let tail = records(&log, 3);
        assert_eq!(tail.entries.len(), 3);
        assert_eq!(tail.entries[0].at_unix, 1_754_000_009);
        assert_eq!(tail.entries[2].at_unix, 1_754_000_007);
        assert_eq!(tail.unreadable, 0);
    }

    #[test]
    fn a_line_that_cannot_be_read_is_counted_and_not_shown() {
        let log = format!("garbage\n{}\n", written("x", Decision::Allow));
        let tail = records(&log, 10);
        assert_eq!(tail.entries.len(), 1);
        assert_eq!(tail.unreadable, 1);
        assert_eq!(tail.scanned, 2);
    }

    #[test]
    fn an_absent_log_is_an_empty_answer_and_never_an_error() {
        let dir = std::env::temp_dir().join(format!("selfhost-audit-{}", std::process::id()));
        let log = AuditLog::in_dir(&dir);
        assert_eq!(tail(&log, 10).expect("a missing file is not a failure"), Tail::default());
    }
}
