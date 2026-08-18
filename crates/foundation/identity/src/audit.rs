//! The record of what was decided, in a form nothing written into it can forge.
//!
//! # What an audit line is for here
//!
//! `docs/SECURITY.md`'s entry for the remote desktop asks for one specific,
//! checkable property: *`grep -c '' data/audit.log` grows by exactly one line
//! per control action*. That sentence is the whole design brief. It means the
//! format must be one record per line, appended, never rewritten — so a
//! verification is a line count and an operator's eye rather than a parser — and
//! it means **no value written into a record may be able to produce a line
//! break**. A capability that can add or remove lines from the log of itself is
//! not an audit trail; it is a place an attacker writes their own history.
//!
//! # Why the escaping is a whitelist and not a blacklist
//!
//! Most of what lands in a record is already incapable of misbehaving:
//! [`Identity`], [`Credential`], [`Capability`] and [`Decision`] all render from
//! closed vocabularies or from newtypes ([`PersonName`](crate::PersonName),
//! [`ShareId`](crate::ShareId), [`NodeName`](crate::NodeName)) whose grammars
//! were chosen partly so that this file would have nothing to defend against.
//! But a record also carries a **detail** — the peer address a session came
//! from, the file a request named, the input a control message asked for — and
//! that string is arbitrary attacker-influenced text.
//!
//! So [`escape_field`] does not hunt for dangerous characters and remove them.
//! It states the small set of characters a field may contain — printable ASCII,
//! minus the five this format gives meaning to — and percent-encodes every
//! single byte outside it, UTF-8 byte by UTF-8 byte. A newline is not "stripped"
//! and a space is not "replaced"; neither can occur, because only listed bytes
//! survive. That is the difference between a rule that is right today and a rule
//! that stays right when somebody adds a field separator in a year.
//!
//! The encoding is reversible, so the console can render the original text after
//! decoding it — and, importantly, decoding is the *reader's* problem. Nothing
//! in this crate ever writes an unescaped byte, so a log-reading tool that
//! forgets to decode shows mangled text rather than being fooled by it.
//!
//! # What this module deliberately does not promise
//!
//! It does not promise tamper-evidence. Anyone who can write the file can
//! rewrite it, and the answer to that is filesystem permissions, not a hash
//! chain this crate would have to key from somewhere. It promises the narrower
//! and more useful thing: that the *subjects* of the log cannot use it to write
//! into their own record, and that one action is one line.

use crate::capability::Capability;
use crate::credential::Credential;
use crate::identity::Identity;
use crate::policy::Decision;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The name of the audit log inside the data directory.
pub const AUDIT_FILENAME: &str = "audit.log";

/// The format marker every line begins with.
///
/// Present so a reader can tell at a glance which format it is looking at, and
/// so the day the fields change there is somewhere to say so rather than a
/// silent reinterpretation of old lines.
pub const AUDIT_FORMAT: &str = "selfhost-audit/2";

/// The marker this format replaced, still accepted by readers.
///
/// Version 1 carried a `capability=` field where version 2 carries `act=`. The
/// rename was not cosmetic: `capability` had become a lie the moment authority
/// acts started being recorded, because those are precisely the things no
/// capability names ([`Authority`]). Nothing else about the line changed, so a
/// reader that handles both is a two-line difference and an existing
/// `data/audit.log` keeps rendering in the console instead of going blank on
/// the day of the upgrade — which is the version bump paying for itself.
pub const AUDIT_FORMAT_V1: &str = "selfhost-audit/1";

/// Bytes of entropy in a record's id: 128 bits, rendered as 32 hex characters.
///
/// Not a secret and not a sequence number. It exists so a console tailing the
/// log can key rows on something stable across re-reads, and so two records
/// that are otherwise identical — the same person exercising the same
/// capability twice in the same second — remain two distinguishable records.
const AUDIT_ID_BYTES: usize = 16;

/// The longest free-text detail a record carries, in characters.
///
/// Counted before escaping, so the bound is on what was meant rather than on
/// what the encoding made of it. A truncated detail is marked, so a reader can
/// tell "this is the whole path" from "this is the start of one".
pub const MAX_DETAIL_CHARS: usize = 256;

/// The marker appended to a detail that was truncated.
///
/// A character that [`escape_field`] never emits on its own, so its presence at
/// the end of a field always means truncation and never means the text ended in
/// a tilde. Public because it is part of the format a reader has to understand,
/// not an implementation detail of the writer.
pub const TRUNCATED: char = '~';

/// A record's identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditId([u8; AUDIT_ID_BYTES]);

impl AuditId {
    /// A fresh id from the operating system's entropy.
    ///
    /// An entropy failure is an error rather than a weaker id: a deployment
    /// whose random source has failed has larger problems than an unlabelled
    /// audit line, and quietly substituting a counter would make the label mean
    /// something different from what it says.
    pub fn random() -> io::Result<Self> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; AUDIT_ID_BYTES];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| io::Error::other("the system random source refused"))?;
        Ok(Self(bytes))
    }

    /// An id from fixed bytes, so a test can assert a whole line.
    pub fn from_bytes(bytes: [u8; AUDIT_ID_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for AuditId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An act that creates, changes or destroys the means to authenticate — the
/// things no [`Capability`] names.
///
/// # Why these are not capabilities, and why they are recorded anyway
///
/// The permission vocabulary has no word for "may grant", deliberately: a grant
/// is a power somebody holds until it is taken away, and no grant should ever
/// confer the ability to mint another. So the routes that write the registry and
/// mint invitations ask for the owner's identity rather than for a capability —
/// and that left them, until 2026-08-18, writing **no audit record at all**,
/// because [`AuditRecord`] was keyed on a `Capability` and there was no honest
/// word to file them under.
///
/// That was the most uncomfortable gap in the trail and the one hardest to
/// argue away: minting a credential for somebody else is precisely the act an
/// audit log exists for. Inventing a `Capability::PeopleAdmin` to hold them
/// would have been the wrong repair — it would put "may grant" into a
/// vocabulary that refuses to contain it, and something would eventually grant
/// it. Widening the *record* instead costs one enum and keeps the permission
/// model exactly as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authority {
    /// Somebody's whole grant set was replaced.
    GrantsChanged,
    /// A person was removed from the registry entirely.
    PersonForgotten,
    /// A one-time invitation code was minted for a name.
    InvitationMinted,
    /// A pending invitation was withdrawn before anybody used it.
    InvitationWithdrawn,
    /// An invitation was redeemed: a passkey now exists under that name.
    ///
    /// The single most consequential line this log carries. Every other entry
    /// here is the owner acting; this one is somebody who was not previously
    /// able to authenticate becoming able to, and it is written by the route
    /// that stands *ahead* of the authorisation wall.
    InvitationRedeemed,
    /// A passkey was enrolled for the owner.
    PasskeyRegistered,
    /// A passkey was removed.
    PasskeyRemoved,
}

impl Authority {
    /// The word this act is written down as.
    ///
    /// Namespaced away from every [`Capability::name`] on purpose: a reader
    /// grepping the log for `capability=` words must never match one of these,
    /// because they are not powers anybody was granted.
    pub fn name(&self) -> &'static str {
        match self {
            Self::GrantsChanged => "authority.grants",
            Self::PersonForgotten => "authority.forget",
            Self::InvitationMinted => "authority.invite",
            Self::InvitationWithdrawn => "authority.uninvite",
            Self::InvitationRedeemed => "authority.redeem",
            Self::PasskeyRegistered => "authority.enrol",
            Self::PasskeyRemoved => "authority.unenrol",
        }
    }
}

/// What a record is about.
///
/// Either a power from the closed vocabulary, exercised or refused — which is
/// every record this log carried before 2026-08-18 — or an [`Authority`] act
/// that has no capability to be filed under. One type so that
/// [`AuditRecord::line`] has one field to render and a reader has one column to
/// read, rather than two record shapes that have to be told apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// A capability was exercised, or asked for and refused.
    Exercised(Capability),
    /// Authority itself was created, changed or destroyed, and whose it was.
    ///
    /// The second field is the subject: the person whose grants changed, the
    /// name an invitation was minted for, the passkey that was removed. It
    /// occupies the same `target=` column a capability's share or node does,
    /// which is what lets one grep answer *everything that has ever concerned
    /// this person* across both kinds of record.
    Authority(Authority, String),
}

impl Act {
    /// The word written into the `act=` field.
    pub fn name(&self) -> &str {
        match self {
            Self::Exercised(capability) => capability.name(),
            Self::Authority(authority, _) => authority.name(),
        }
    }

    /// What the act was about: a capability's target, or the person or
    /// credential an authority act concerns.
    ///
    /// Returns a `&str` the caller must still escape. A [`Capability`]'s target
    /// is a validated token and needs none; an [`Authority`]'s subject is a
    /// [`PersonName`](crate::PersonName) or a passkey id, and the second of
    /// those is a client-supplied string. [`AuditRecord::line`] escapes the
    /// field either way, so this distinction never has to be remembered.
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::Exercised(capability) => capability.target(),
            Self::Authority(_, subject) => Some(subject.as_str()),
        }
    }
}

impl From<Capability> for Act {
    fn from(capability: Capability) -> Self {
        Self::Exercised(capability)
    }
}

impl Authority {
    /// This act, against the person or credential it concerns.
    pub fn against(self, subject: impl Into<String>) -> Act {
        Act::Authority(self, subject.into())
    }
}

/// One decision, as it will be written down.
///
/// A plain record of already-decided facts: it performs no authorisation and
/// consults nothing. Building one from a [`Decision`] the caller has already
/// obtained is what keeps [`crate::Policy::decide`] free of any notion of
/// logging, and what makes it impossible to log an outcome different from the
/// one that was enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// This record's identifier.
    pub id: AuditId,
    /// When it happened, in seconds since the Unix epoch.
    pub at_unix: u64,
    /// Who asked.
    pub identity: Identity,
    /// How they had proved it.
    pub credential: Credential,
    /// What they asked to do: a capability exercised, or an act of authority
    /// that no capability names.
    pub act: Act,
    /// What the policy answered.
    pub decision: Decision,
    /// Free text naming the specific thing: a peer address, a file path, a
    /// service name. Arbitrary, attacker-influenced, and escaped on the way
    /// out — see this module's documentation.
    pub detail: String,
}

impl AuditRecord {
    /// A record of `decision`, with a fresh id and the current wall clock.
    ///
    /// Wall clock rather than a monotonic instant because the record outlives
    /// the process that wrote it, and "17:42 on Tuesday" is what an operator
    /// correlating an incident actually needs.
    pub fn now(
        identity: Identity,
        credential: Credential,
        act: impl Into<Act>,
        decision: Decision,
        detail: impl Into<String>,
    ) -> io::Result<Self> {
        Ok(Self {
            id: AuditId::random()?,
            at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0),
            identity,
            credential,
            act: act.into(),
            decision,
            detail: detail.into(),
        })
    }

    /// The record as exactly one line, without its terminating newline.
    ///
    /// Pure, total, and by construction incapable of containing a line break,
    /// a space inside a value, or an unescaped `=`. The field order is fixed and
    /// the field names are part of the format: a reader splits on spaces, then
    /// on the first `=`, and is done.
    ///
    /// `identity` and `who` are two fields rather than one on purpose. A person
    /// whose name merely *resembles* the owner's in some script — which
    /// [`PersonName`](crate::PersonName) narrows but cannot eliminate across
    /// every writing system — still renders with `identity=person`, so no amount
    /// of clever naming makes a line read as the owner's.
    pub fn line(&self) -> String {
        let mut line = String::with_capacity(160);
        line.push_str(AUDIT_FORMAT);
        line.push_str(" id=");
        line.push_str(&self.id.to_string());
        line.push_str(" at=");
        line.push_str(&self.at_unix.to_string());
        line.push_str(" identity=");
        line.push_str(self.identity.kind());
        line.push_str(" who=");
        line.push_str(&escape_field(self.identity.as_str()));
        line.push_str(" credential=");
        line.push_str(self.credential.as_str());
        line.push_str(" act=");
        line.push_str(&escape_field(self.act.name()));
        line.push_str(" target=");
        line.push_str(&escape_field(self.act.target().unwrap_or("")));
        line.push_str(" outcome=");
        line.push_str(self.decision.as_str());
        line.push_str(" reason=");
        line.push_str(match self.decision.refusal() {
            Some(refusal) => refusal.as_str(),
            None => "-",
        });
        line.push_str(" detail=");
        line.push_str(&escape_field(&self.detail));
        line
    }
}

/// Renders arbitrary text so it cannot escape one field of one line.
///
/// Every byte outside the permitted set becomes `%XX`, uppercase hex, per UTF-8
/// byte. The permitted set is printable ASCII (`0x21..=0x7e`) minus five
/// characters this format reserves:
///
/// - `%`, because it introduces an escape and must mean only that;
/// - `=`, because it separates a field's name from its value;
/// - `"` and `\`, because a reader that hands a field to a JSON or shell
///   context should not have to think about quoting;
/// - `~`, because it marks truncation.
///
/// Space (`0x20`) is outside the range and so is every control byte, which is
/// what makes the two structural guarantees — one record per line, one value per
/// field — properties of the encoding rather than of the caller's care.
///
/// Empty text renders as `-`, so a field is never written as `detail=` followed
/// by nothing, which reads as a truncated line rather than as an absent value.
/// Text longer than [`MAX_DETAIL_CHARS`] characters is cut at a character
/// boundary — never a byte index, which would split a multi-byte character — and
/// marked with a trailing [`TRUNCATED`].
pub fn escape_field(text: &str) -> String {
    let mut kept = String::new();
    let mut truncated = false;
    for (index, character) in text.chars().enumerate() {
        if index == MAX_DETAIL_CHARS {
            truncated = true;
            break;
        }
        kept.push(character);
    }
    if kept.is_empty() {
        return "-".to_owned();
    }

    let mut out = String::with_capacity(kept.len() + 8);
    for byte in kept.bytes() {
        if is_bare(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    if truncated {
        out.push(TRUNCATED);
    }
    out
}

/// Uppercase hex digits, so an escape is visually distinct from the lowercase
/// hex a record id is rendered in.
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Whether a byte may appear in a field as itself.
fn is_bare(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e if !matches!(byte, b'%' | b'=' | b'"' | b'\\' | b'~'))
}

/// Reverses [`escape_field`], for a reader that wants the original text.
///
/// `None` for a malformed escape — a `%` without two hex digits after it, or an
/// escape sequence that reassembles into invalid UTF-8. A reader is entitled to
/// treat that as "this line was not written by this crate", which is more useful
/// than a lossy best effort. The truncation marker, if present, is reported
/// separately rather than being folded into the text.
pub fn unescape_field(field: &str) -> Option<(String, bool)> {
    if field == "-" {
        return Some((String::new(), false));
    }
    let (body, truncated) = match field.strip_suffix(TRUNCATED) {
        Some(body) => (body, true),
        None => (field, false),
    };
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' => {
                let high = *bytes.get(at + 1)?;
                let low = *bytes.get(at + 2)?;
                out.push(from_hex(high)? << 4 | from_hex(low)?);
                at += 3;
            }
            byte if is_bare(byte) => {
                out.push(byte);
                at += 1;
            }
            // A byte the encoder would never have emitted bare.
            _ => return None,
        }
    }
    Some((String::from_utf8(out).ok()?, truncated))
}

/// One hex digit's value, or `None` for anything else.
fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The append-only sink: `<data_dir>/audit.log`.
///
/// A cheap-clone handle over a path and nothing else. There is no open file
/// held and no lock: each append opens the file in append mode, writes the whole
/// line in a single `write_all`, and closes. That is slower than a retained
/// handle and it is the right trade — an `O_APPEND` write of a line this short
/// lands whole even with several writers, no in-process lock can order writes
/// from a second process anyway, and a supervisor that has to hold a file handle
/// open for the life of the daemon is a file handle that outlives a log rotation.
///
/// On unix the file is created `0600`. On other platforms it inherits the data
/// directory's permissions; unlike the people registry this is tolerable rather
/// than refused, because an audit log holds no credential and a deployment that
/// cannot write one at all would lose the record entirely — which is the worse
/// failure. The data directory's own permissions are what make this private, and
/// tightening them is `crates/cli`'s job, recorded as such in `docs/SECURITY.md`.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// The audit log inside a data directory.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { path: data_dir.join(AUDIT_FILENAME) }
    }

    /// Where the log lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record, as exactly one line.
    ///
    /// Never rewrites, never seeks, never truncates. An error is returned rather
    /// than swallowed: a caller that cannot record what it is about to do should
    /// be able to decide not to do it, and for the capabilities that drive a
    /// machine that is exactly the right decision.
    pub fn append(&self, record: &AuditRecord) -> io::Result<()> {
        use std::io::Write;
        let mut line = record.line();
        line.push('\n');
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.path)?.write_all(line.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{NodeName, ShareId};
    use crate::identity::PersonName;
    use crate::policy::Refusal;

    fn node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a valid node name")
    }

    fn record(detail: &str) -> AuditRecord {
        AuditRecord {
            id: AuditId::from_bytes([0xab; AUDIT_ID_BYTES]),
            at_unix: 1_754_000_000,
            identity: Identity::Person(PersonName::parse("Mary-Anne").unwrap()),
            credential: Credential::Passkey,
            act: Act::Exercised(Capability::DesktopControl(node())),
            decision: Decision::Allow,
            detail: detail.to_owned(),
        }
    }

    #[test]
    fn an_act_of_authority_renders_under_a_word_no_capability_can_spell() {
        // The gap this closed: `PUT /api/people/<name>` and the invite routes
        // are owner-only rather than capability-gated, so before `Authority`
        // existed there was no word to file them under and they wrote nothing
        // at all. The property to hold is that the new words cannot be confused
        // with the old ones — a reader grepping for a granted power must never
        // match an act of authority, and the other way round.
        let redeemed = AuditRecord {
            id: AuditId::from_bytes([0x11; AUDIT_ID_BYTES]),
            at_unix: 1_754_000_000,
            identity: Identity::Person(PersonName::parse("guest").unwrap()),
            credential: Credential::Passkey,
            act: Authority::InvitationRedeemed.against("guest"),
            decision: Decision::Allow,
            detail: "label:phone".to_owned(),
        };
        assert_eq!(
            redeemed.line(),
            "selfhost-audit/2 id=11111111111111111111111111111111 at=1754000000 \
             identity=person who=guest credential=passkey act=authority.redeem \
             target=guest outcome=allow reason=- detail=label:phone"
        );

        // No `Authority` word is spellable as a `Capability`, so a grant can
        // never be written that makes a person's row read like an audit act,
        // and no capability word collides with an authority one.
        for authority in [
            Authority::GrantsChanged,
            Authority::PersonForgotten,
            Authority::InvitationMinted,
            Authority::InvitationWithdrawn,
            Authority::InvitationRedeemed,
            Authority::PasskeyRegistered,
            Authority::PasskeyRemoved,
        ] {
            assert!(
                Capability::parse(authority.name()).is_none(),
                "{} parses as a capability, so it could be granted",
                authority.name(),
            );
        }
    }

    #[test]
    fn the_subject_of_an_authority_act_is_escaped_like_any_other_field() {
        // A passkey id is client-supplied, unlike a capability's target, which
        // is always a validated token. It lands in the same `target=` column,
        // so the column's guarantee has to come from the escaping rather than
        // from the grammar of what usually goes there.
        let removed = AuditRecord {
            id: AuditId::from_bytes([0x22; AUDIT_ID_BYTES]),
            at_unix: 1,
            identity: Identity::Owner,
            credential: Credential::Bearer,
            act: Authority::PasskeyRemoved.against("a b\nselfhost-audit/2 id=forged"),
            decision: Decision::Allow,
            detail: "passkey removed".to_owned(),
        };
        let line = removed.line();
        assert_eq!(line.lines().count(), 1, "a subject added a line: {line}");
        assert!(!line.contains("id=forged"), "a subject forged a field: {line}");
    }

    #[test]
    fn a_record_renders_as_one_known_line() {
        let line = record("keydown:0x04").line();
        assert_eq!(
            line,
            "selfhost-audit/2 id=abababababababababababababababab at=1754000000 \
             identity=person who=Mary-Anne credential=passkey act=desktop.control \
             target=alex-desktop outcome=allow reason=- detail=keydown:0x04"
        );
    }

    #[test]
    fn a_refusal_carries_its_reason_and_an_allow_does_not() {
        let mut refused = record("");
        refused.decision = Decision::Refuse(Refusal::CredentialNotArmed);
        assert!(refused.line().contains(" outcome=refuse reason=credential-not-armed "));
        assert!(record("x").line().contains(" outcome=allow reason=- "));
    }

    #[test]
    fn nothing_written_into_a_record_can_forge_a_line_or_a_field() {
        // The property the whole module exists for, asserted over the shapes an
        // attacker would actually try.
        let hostile = [
            "a\nselfhost-audit/1 id=deadbeef outcome=allow", // a whole forged record
            "a\r\nb",
            "a b",
            "outcome=allow",
            "a=b",
            "a\"b\\c",
            "a\0b",
            "a\u{7f}b",
            "a\u{202e}b",
            "100%",
            "~",
        ];
        for detail in hostile {
            let line = record(detail).line();
            assert_eq!(line.lines().count(), 1, "{detail:?} produced more than one line");
            assert!(!line.contains('\n') && !line.contains('\r'), "{detail:?}");
            // Exactly the fields this format defines, and no more: a value that
            // could contain a space or an `=` would show up here as an extra.
            // The format marker plus ten `name=value` fields.
            assert_eq!(
                line.split(' ').count(),
                11,
                "{detail:?} changed the field count of the line"
            );
            assert_eq!(
                line.matches(" outcome=").count(),
                1,
                "{detail:?} introduced a second outcome field"
            );
        }
    }

    #[test]
    fn every_field_round_trips_through_the_decoder() {
        for text in [
            "",
            "-",
            "keydown:0x04",
            "a b",
            "a\nb",
            "a=b",
            "100% \"quoted\" \\ ~",
            "/Users/alex/Documents/tax return.pdf",
            "米",
            "\u{202e}",
            "\u{0}\u{1f}\u{7f}",
        ] {
            let escaped = escape_field(text);
            let (decoded, truncated) = unescape_field(&escaped)
                .unwrap_or_else(|| panic!("{text:?} escaped to {escaped:?} and would not decode"));
            assert!(!truncated, "{text:?} is short enough to survive whole");
            // Empty and "-" are the one deliberate collision: both mean "no
            // value", and no reader needs to tell them apart.
            let expected = if text == "-" { "" } else { text };
            assert_eq!(decoded, expected, "{text:?} did not round-trip");
        }
    }

    #[test]
    fn a_long_detail_is_cut_on_a_character_boundary_and_marked() {
        // Multi-byte characters: cutting on a byte index here would panic under
        // `panic = "abort"`, which is a whole-box outage.
        let long = "米".repeat(MAX_DETAIL_CHARS * 2);
        let escaped = escape_field(&long);
        assert!(escaped.ends_with(TRUNCATED));
        let (decoded, truncated) = unescape_field(&escaped).expect("decodes");
        assert!(truncated);
        assert_eq!(decoded.chars().count(), MAX_DETAIL_CHARS);

        // Exactly at the cap is not truncated.
        let exact = "a".repeat(MAX_DETAIL_CHARS);
        assert_eq!(escape_field(&exact), exact);
        assert!(!escape_field(&exact).ends_with(TRUNCATED));
    }

    #[test]
    fn a_malformed_escape_is_refused_rather_than_guessed() {
        for text in ["%", "%A", "%ZZ", "%4", "a%1", "a b", "a=b", "a\"b"] {
            assert_eq!(unescape_field(text), None, "{text:?} must not decode");
        }
    }

    #[test]
    fn an_id_is_random_and_renders_as_hex() {
        let first = AuditId::random().expect("system entropy");
        let second = AuditId::random().expect("system entropy");
        assert_ne!(first, second, "two ids from the same source differ");
        let text = first.to_string();
        assert_eq!(text.len(), AUDIT_ID_BYTES * 2);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn appending_grows_the_file_by_exactly_one_line_per_record() {
        // The property `docs/SECURITY.md` asks an operator to verify with
        // `grep -c '' data/audit.log`.
        let dir = std::env::temp_dir()
            .join(format!("selfhost-identity-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let log = AuditLog::in_dir(&dir);

        for count in 1..=3 {
            log.append(&record("a\nb c=d")).expect("appends");
            let text = std::fs::read_to_string(log.path()).expect("reads back");
            assert_eq!(text.lines().count(), count, "one line per record");
            assert!(text.ends_with('\n'), "every line is terminated");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_audit_log_is_created_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join(format!("selfhost-identity-audit-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let log = AuditLog::in_dir(&dir);
        log.append(&record("x")).expect("appends");
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_built_now_carries_a_clock_and_a_fresh_id() {
        let first = AuditRecord::now(
            Identity::Owner,
            Credential::Bearer,
            Capability::FilesRead(ShareId::parse("vault").unwrap()),
            Decision::Allow,
            "GET /api/storage/blob/vault/x",
        )
        .expect("system entropy");
        let second = AuditRecord::now(
            Identity::Owner,
            Credential::Bearer,
            Capability::FilesRead(ShareId::parse("vault").unwrap()),
            Decision::Allow,
            "GET /api/storage/blob/vault/x",
        )
        .expect("system entropy");
        assert_ne!(first.id, second.id, "identical actions stay distinguishable records");
        assert!(first.at_unix > 1_700_000_000, "a wall clock, not a monotonic instant");
        assert!(first.line().contains("identity=owner who=owner"));
    }
}
