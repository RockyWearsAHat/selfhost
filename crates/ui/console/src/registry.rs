//! What the PEOPLE plate knows: who holds a credential on this deployment, and
//! what the dangerous capabilities have been used to do.
//!
//! # Why the two halves are one plate
//!
//! A list of people is a list of *authority*, and authority is only meaningful
//! beside the record of what it did. The registry says who may drive this box;
//! the trail says who actually did, and when, and whether the daemon allowed it.
//! Split across two screens, the second is the one nobody opens — which is the
//! failure mode `crates/admin`'s audit route exists to close: "an audit trail an
//! operator cannot read is an audit trail nobody checks."
//!
//! # What this console can and cannot do here
//!
//! **Read.** Registering a passkey is a browser ceremony — it needs a platform
//! authenticator and an origin, and `crates/admin` deliberately allows it only
//! to an already-authenticated caller — so this plate lists holders and does not
//! offer to mint one. Revocation is offered, because removing authority needs no
//! ceremony and an owner who has lost a device needs the fastest path to it.
//!
//! Both halves are owner-only at the daemon, which is why either can come back
//! `401` on a deployment where this console's credential is not the owner. That
//! is drawn as the sentence it is, never as an empty list: an empty registry and
//! a refused one are different facts and only one of them is reassuring.

use selfhost_json::Json;
use rui::Status;

/// One person who holds a credential on this box.
///
/// A passkey is registered under a name, and a verified assertion answers
/// *whose* credential signed it — so this list is the deployment's roster, not a
/// list of devices. Two rows carrying the same `user` are one person with two
/// devices, and the plate groups them under the name for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// The credential's id, which is what a revocation names.
    pub id: String,
    /// The person this credential answers for.
    pub user: String,
    /// What the device called itself when it was registered.
    pub label: String,
    /// When it was registered, in whole Unix seconds.
    pub created_unix: u64,
}

impl Person {
    /// Reads one holder off `GET /api/webauthn/credentials`.
    ///
    /// A credential id that could not appear in a request path is dropped rather
    /// than drawn: the row would offer a REVOKE button that cannot be sent, and
    /// a control that is guaranteed to fail is worse than an absent one.
    pub fn from_json(value: &Json) -> Option<Self> {
        let id = value.get("id")?.as_str()?.to_owned();
        if !usable_credential_id(&id) {
            return None;
        }
        Some(Self {
            user: value.get("user").and_then(Json::as_str).unwrap_or("").to_owned(),
            label: value.get("label").and_then(Json::as_str).unwrap_or("").to_owned(),
            created_unix: value.get("createdUnix").and_then(Json::as_u64).unwrap_or(0),
            id,
        })
    }

    /// The name to draw, which is the person's when there is one.
    ///
    /// A credential registered before passkeys carried a name loads as the
    /// owner's, and the daemon says so by leaving `user` empty. Drawing an empty
    /// cell would make it look like a row that failed to load.
    pub fn display_name(&self) -> &str {
        if self.user.is_empty() { "owner" } else { &self.user }
    }
}

/// Whether a credential id may appear in a request path.
///
/// Mirrors `usableCredentialId`. Credential ids are base64url, which is exactly
/// the alphabet that needs no escaping in a path segment — so this is a check
/// and not an encoder, for the reason every other identifier in this console is
/// checked: an id that is not base64url did not come from the daemon.
pub fn usable_credential_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 512
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// One line of the control-action record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's own id.
    pub id: String,
    /// When it happened, in whole Unix seconds.
    pub at_unix: u64,
    /// The identity the daemon resolved.
    pub identity: String,
    /// The person, when the credential named one.
    pub who: String,
    /// The capability that was exercised.
    pub capability: String,
    /// What it was exercised against.
    pub target: String,
    /// `allow` or `deny`.
    pub outcome: String,
    /// Why, for a refusal.
    pub reason: String,
    /// Whatever else the writer recorded.
    pub detail: String,
}

impl Record {
    /// Reads one record off `GET /api/audit`.
    pub fn from_json(value: &Json) -> Option<Self> {
        let text = |name: &str| {
            value.get(name).and_then(Json::as_str).unwrap_or_default().to_owned()
        };
        Some(Self {
            id: value.get("id")?.as_str()?.to_owned(),
            at_unix: value.get("at").and_then(Json::as_u64).unwrap_or(0),
            identity: text("identity"),
            who: text("who"),
            capability: text("capability"),
            target: text("target"),
            outcome: text("outcome"),
            reason: text("reason"),
            detail: text("detail"),
        })
    }

    /// Whether the daemon allowed it.
    pub fn allowed(&self) -> bool {
        self.outcome == "allow"
    }

    /// The lamp beside the row.
    ///
    /// A refusal is amber and not red. A denied capability is the audit log
    /// working — the wall held — and a trail where every refusal screamed would
    /// be a trail whose red meant "somebody tried something", which is what it
    /// is *for*. Red is kept for a record this console could not read.
    pub fn status(&self) -> Status {
        if self.allowed() { Status::Ok } else { Status::Warn }
    }

    /// Who did it, in one cell.
    pub fn actor(&self) -> String {
        match (self.who.is_empty(), self.identity.is_empty()) {
            (false, _) => self.who.clone(),
            (true, false) => self.identity.clone(),
            (true, true) => "unknown".into(),
        }
    }

    /// What happened, in one cell.
    ///
    /// The capability and its target, and — only for a refusal — the reason.
    /// An allowed action's reason is the empty string in the log format, and
    /// drawing a column that is blank on nearly every row is a column that is
    /// read as broken.
    pub fn action(&self) -> String {
        let mut line = match self.target.is_empty() {
            true => self.capability.clone(),
            false => format!("{} · {}", self.capability, self.target),
        };
        if !self.allowed() && !self.reason.is_empty() {
            line.push_str(&format!(" — {}", self.reason));
        }
        line
    }
}

/// A read of the trail: what came back, and what could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Trail {
    /// The records, newest first, in the order the daemon answered them.
    pub records: Vec<Record>,
    /// How many lines the daemon looked at.
    pub scanned: usize,
    /// How many of them it could not read.
    pub unreadable: usize,
}

impl Trail {
    /// Reads the tail off the wire.
    pub fn from_json(value: &Json) -> Option<Self> {
        let records = value
            .get("records")?
            .as_array()?
            .iter()
            .filter_map(Record::from_json)
            .collect();
        Some(Self {
            records,
            scanned: value.get("scanned").and_then(Json::as_u64).unwrap_or(0) as usize,
            unreadable: value.get("unreadable").and_then(Json::as_u64).unwrap_or(0) as usize,
        })
    }

    /// What to say above the rows, and how loudly.
    ///
    /// Mirrors `trailNote`. The unreadable count is reported rather than hidden,
    /// and it is the one thing on this plate that raises its voice: a non-zero
    /// count means a line written by a different version of the format or a file
    /// somebody has edited, and both are things a person reading an audit trail
    /// is entitled to know *before* they trust what they are looking at.
    pub fn note(&self) -> (Status, String) {
        if self.unreadable > 0 {
            return (
                Status::Bad,
                format!(
                    "{} of the last {} lines could not be read — the file has been edited, or \
                     written by a different version of the format",
                    self.unreadable, self.scanned
                ),
            );
        }
        if self.records.is_empty() {
            return (
                Status::Idle,
                "Nothing has used a recorded capability on this box yet.".into(),
            );
        }
        let refused = self.records.iter().filter(|record| !record.allowed()).count();
        match refused {
            0 => (Status::Ok, format!("{} actions, none refused", self.records.len())),
            1 => (Status::Warn, format!("{} actions · 1 refused", self.records.len())),
            many => (Status::Warn, format!("{} actions · {many} refused", self.records.len())),
        }
    }
}

/// Whether a record is the pointer moving, which floods a trail it should not.
///
/// Mirrors `isPointerNoise`. A desktop session writes one record per authorised
/// action, and a pointer that moved is authorised thousands of times a minute —
/// so the plate offers to hide them, and this is the one place that decides what
/// "them" means. It is deliberately narrow: only the pointer, never a key and
/// never a button, because a keystroke is the thing an audit trail exists to
/// record.
pub fn is_pointer_noise(record: &Record) -> bool {
    record.allowed()
        && record.capability.starts_with("desktop.control")
        && record.detail.starts_with("pointer")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(capability: &str, outcome: &str, detail: &str) -> Record {
        Record {
            id: "r1".into(),
            at_unix: 1_700_000_000,
            identity: "owner".into(),
            who: "alex".into(),
            capability: capability.into(),
            target: "self".into(),
            outcome: outcome.into(),
            reason: String::new(),
            detail: detail.into(),
        }
    }

    #[test]
    fn a_credential_whose_id_could_not_be_revoked_is_not_drawn() {
        for bad in ["", "a/b", "a+b", "a=b"] {
            let value = Json::object([("id", Json::string(bad))]);
            assert!(Person::from_json(&value).is_none(), "accepted the id {bad:?}");
        }
        assert!(usable_credential_id("q0Zm-x_9AA"));
    }

    #[test]
    fn a_passkey_from_before_names_had_meaning_reads_as_the_owners() {
        let value = Json::object([
            ("id", Json::string("abc")),
            ("label", Json::string("MacBook")),
            ("createdUnix", Json::Number(1_700_000_000.0)),
        ]);
        let person = Person::from_json(&value).expect("a holder");
        assert_eq!(person.display_name(), "owner", "an empty cell reads as a failed row");
    }

    #[test]
    fn a_refusal_is_amber_because_a_refusal_is_the_wall_working() {
        assert_eq!(record("files.read", "allow", "").status(), Status::Ok);
        assert_eq!(record("desktop.control", "deny", "").status(), Status::Warn);
    }

    #[test]
    fn a_refused_record_carries_its_reason_and_an_allowed_one_does_not() {
        let mut denied = record("desktop.control", "deny", "");
        denied.reason = "stale-login".into();
        assert!(denied.action().ends_with("— stale-login"));

        let mut allowed = record("desktop.control", "allow", "");
        allowed.reason = "stale-login".into();
        assert!(!allowed.action().contains("stale-login"), "an allowed action has no reason");
    }

    #[test]
    fn the_actor_falls_back_through_the_names_it_has() {
        let mut anonymous = record("files.read", "allow", "");
        assert_eq!(anonymous.actor(), "alex");
        anonymous.who = String::new();
        assert_eq!(anonymous.actor(), "owner");
        anonymous.identity = String::new();
        assert_eq!(anonymous.actor(), "unknown");
    }

    #[test]
    fn an_unreadable_line_is_the_one_thing_the_trail_shouts_about() {
        let trail = Trail { records: vec![record("files.read", "allow", "")], scanned: 10, unreadable: 2 };
        let (status, note) = trail.note();
        assert_eq!(status, Status::Bad);
        assert!(note.contains("could not be read"));
    }

    #[test]
    fn an_empty_trail_is_a_sentence_rather_than_an_alarm() {
        let (status, note) = Trail::default().note();
        assert_eq!(status, Status::Idle);
        assert!(note.contains("Nothing has used"));
    }

    #[test]
    fn a_trail_counts_what_was_refused_without_calling_it_a_failure() {
        let trail = Trail {
            records: vec![
                record("files.read", "allow", ""),
                record("desktop.control", "deny", ""),
            ],
            scanned: 2,
            unreadable: 0,
        };
        let (status, note) = trail.note();
        assert_eq!(status, Status::Warn);
        assert!(note.contains("1 refused"));
    }

    #[test]
    fn only_the_pointer_counts_as_noise() {
        assert!(is_pointer_noise(&record("desktop.control", "allow", "pointer 100,200")));
        assert!(!is_pointer_noise(&record("desktop.control", "allow", "key 0x04 down")));
        assert!(
            !is_pointer_noise(&record("desktop.control", "deny", "pointer 100,200")),
            "a refused pointer move is not noise — it is the wall holding"
        );
        assert!(!is_pointer_noise(&record("files.read", "allow", "pointer")));
    }

    #[test]
    fn a_trail_is_read_newest_first_exactly_as_it_arrived() {
        let value = Json::object([
            (
                "records",
                Json::array([
                    Json::object([("id", Json::string("b")), ("at", Json::Number(2.0))]),
                    Json::object([("id", Json::string("a")), ("at", Json::Number(1.0))]),
                ]),
            ),
            ("scanned", Json::Number(2.0)),
            ("unreadable", Json::Number(0.0)),
        ]);
        let trail = Trail::from_json(&value).expect("a trail");
        assert_eq!(trail.records[0].id, "b", "the order the daemon answered is the order drawn");
    }
}
