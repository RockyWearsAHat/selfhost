//! What this daemon did, written down once per act, in a form the subjects of
//! the log cannot forge.
//!
//! # One line per control action, and what "control action" means here
//!
//! `docs/SECURITY.md` asks for a property that can be checked with `grep -c ''`:
//! the audit log grows by **exactly one line per control action**. This module
//! is what makes that true for `crates/cli`, and it starts by saying precisely
//! which acts are control actions, because a rule that is not enumerated is a
//! rule nobody can verify:
//!
//! 1. **A desktop session is admitted** — one line, written before a single
//!    pixel leaves the machine.
//! 2. **One input message is performed** — one line each. A keystroke, a
//!    pointer move, a button, a wheel notch, a release-all. This is the granular
//!    one and it is deliberate: driving somebody's machine is the only
//!    capability in this repository that is not "serving data", and an audit
//!    trail that recorded only that a session existed would answer none of the
//!    questions an incident asks.
//! 3. **The kill switch is engaged or released** — one line, written by the
//!    daemon that *observes* the change and never by the command that caused
//!    it, so a switch created through a Finder window, an SMB mount or a
//!    recovery shell is recorded exactly like one created by
//!    `selfhost desktop disable`, and neither is recorded twice.
//! 4. **A node is invited, or a node token is stored** — one line.
//!
//! Everything else this daemon does — serving a page, answering DNS, delivering
//! mail — is not a control action and is not written here. A log that grew for
//! ordinary traffic would be a log nobody reads, and the property above would be
//! unverifiable within a week.
//!
//! # Why nothing here can be forged
//!
//! The escaping is [`selfhost_identity::audit`]'s and this module adds none of
//! its own. That crate states the small set of bytes a field may contain and
//! percent-encodes every byte outside it, so a newline cannot occur in a value
//! and one action cannot become two lines — a property of the encoding rather
//! than of this caller's care. What this module has to get right is the other
//! half: **never putting a secret in the detail**. See [`Auditor::performed`]
//! for the one place that matters, where the text a person typed is counted and
//! never quoted.
//!
//! # A failed write is reported, never swallowed
//!
//! [`AuditLog::append`] returns its error and this module prints it on stderr
//! rather than dropping it. It does **not** refuse the action: a box whose data
//! directory has filled up should still let its operator take control of it and
//! fix that, and a remote desktop that stops working because a log file could
//! not be written would be an outage caused by the diagnostics. The complaint on
//! stderr is what stops the loss being silent.

use selfhost_desk::grant::{Capabilities, Redemption};
use selfhost_desk::wire::{Message, Refusal};
use selfhost_identity::audit::{AuditLog, AuditRecord};
use selfhost_identity::{Capability, Credential, Decision, Identity, NodeName, Opening, Session};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

/// The daemon's audit log, ready to be written to from anywhere.
///
/// Cheap to clone — it holds a path, not a file handle. That is
/// [`AuditLog`]'s own decision and it is the right one here too: an `O_APPEND`
/// write of one short line lands whole even with several writers, and a handle
/// held open for the life of the daemon is a handle that outlives a log
/// rotation.
#[derive(Debug, Clone)]
pub struct Auditor {
    log: Arc<AuditLog>,
}

impl Auditor {
    /// The audit log inside a deployment's data directory.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { log: Arc::new(AuditLog::in_dir(data_dir)) }
    }

    /// Where the log is, so an operator can be told rather than made to guess.
    pub fn path(&self) -> &Path {
        self.log.path()
    }

    /// Writes one record, complaining on stderr if it cannot.
    ///
    /// The single funnel every other method here goes through, so there is
    /// exactly one place that decides what happens when the log cannot be
    /// written and exactly one place that could ever write two lines for one
    /// act.
    fn write(&self, record: Result<AuditRecord, std::io::Error>) {
        let record = match record {
            Ok(record) => record,
            // An entropy failure. The action still happens — see the module
            // documentation — but the operator is told the log has a hole in it.
            Err(error) => {
                eprintln!("audit: could not label a record ({error}); this action is unlogged");
                return;
            }
        };
        if let Err(error) = self.log.append(&record) {
            eprintln!(
                "audit: could not write {} ({error}); this action happened and is unlogged",
                self.log.path().display()
            );
        }
    }

    /// A desktop session was admitted.
    ///
    /// The capability recorded is the strongest one the ticket carries, because
    /// that is the one an auditor is looking for: a session that may drive the
    /// machine is a different event from one that may only watch it, and
    /// recording the weaker of the two would hide the stronger.
    pub fn admitted(&self, identity: &Identity, redemption: &Redemption) {
        let capability = if redemption.capabilities.contains(Capabilities::CONTROL) {
            Capability::DesktopControl(node_of(&redemption.peer))
        } else {
            Capability::DesktopView(node_of(&redemption.peer))
        };
        self.write(AuditRecord::now(
            identity.clone(),
            credential_of(identity),
            capability,
            Decision::Allow,
            "session admitted",
        ));
    }

    /// One input message was performed, or the platform refused it.
    ///
    /// # The detail never carries what was typed
    ///
    /// The last thing typed on a machine is routinely a password. So a `Text`
    /// message is recorded as **how many** code units it carried and never as
    /// the units themselves, and a key is recorded by its HID usage — which
    /// names the physical key, not the character the far machine's layout makes
    /// of it. An audit log that quoted its subject's keystrokes would be a
    /// keylogger with a respectable filename, and it would be readable by
    /// anything that can read the data directory.
    ///
    /// # Why a platform refusal is still `outcome=allow`
    ///
    /// The outcome field records what *this daemon decided*, and the daemon
    /// decided to perform it: the session held `CONTROL`, `[desktop].allow_input`
    /// was set, and the message was forwarded to the machine. What happened next
    /// — User Interface Privilege Isolation swallowing it, the secure desktop
    /// refusing it — is the operating system's answer, and it goes in the detail
    /// where it can be read as what it is. Recording it as `refuse` would make
    /// the log say the daemon withheld a capability it had in fact exercised.
    pub fn performed(
        &self,
        identity: &Identity,
        node: &str,
        message: &Message,
        refusal: Option<Refusal>,
    ) {
        let mut detail = describe(message);
        if let Some(refusal) = refusal {
            detail.push_str(" refused:");
            detail.push_str(refusal_word(refusal));
        }
        self.write(AuditRecord::now(
            identity.clone(),
            credential_of(identity),
            Capability::DesktopControl(node_of(node)),
            Decision::Allow,
            detail,
        ));
    }

    /// The kill switch changed state.
    ///
    /// Recorded under [`Capability::DesktopControl`] against this machine
    /// because that is the capability being revoked or restored, and an auditor
    /// searching for every line that concerns driving this box must find this
    /// one among them.
    ///
    /// Called from exactly one place — the daemon's poll — so that one
    /// engagement is one line however the file came to exist. See
    /// [`crate::desk_task::Desk::watch`] for why the observer records and the
    /// command does not.
    pub fn kill_switch(&self, engaged: bool, by: &str) {
        self.write(AuditRecord::now(
            Identity::Owner,
            Credential::Bearer,
            Capability::DesktopControl(node_of(selfhost_admin::desk_api::LOCAL_NODE)),
            Decision::Allow,
            format!("kill-switch:{} by:{by}", if engaged { "engaged" } else { "released" }),
        ));
    }

    /// A node was invited, or a node's token was stored on this machine.
    ///
    /// `what` names which of the two, and `node` the machine it concerns. The
    /// token itself is never written: the log lives beside it in the data
    /// directory and would double the number of places it exists.
    pub fn node_admin(&self, what: &str, node: &str) {
        self.write(AuditRecord::now(
            Identity::Owner,
            Credential::Bearer,
            Capability::NodeAdmin,
            Decision::Allow,
            format!("{what}:{node}"),
        ));
    }
}

/// A node name for the audit record, or a placeholder for one that is not.
///
/// [`NodeName`] has its own grammar and the audit record takes nothing else. A
/// name that fails it cannot have come from a validated config, so it is
/// recorded as `unnamed` rather than dropped: an action against a node this
/// daemon could not name is exactly the line an auditor must still see.
fn node_of(name: &str) -> NodeName {
    NodeName::parse(name).unwrap_or_else(|_| {
        NodeName::parse("unnamed").unwrap_or_else(|_| unreachable!("`unnamed` is a valid node name"))
    })
}

/// The credential the identity proves was presented.
///
/// # This is an inference, and it is the strongest true one available
///
/// A desktop ticket is minted from a console session and redeemed by the route;
/// `Handover` — the daemon's whole view of an admitted session — carries the
/// identity and not the credential, so the exact opening is not knowable here.
/// What *is* knowable is what the identity proves:
///
/// - [`Identity::Person`] can only have been established by a passkey, because
///   a passkey is the only credential in this deployment whose signature names
///   a person. A session carrying a person's name was therefore opened by one.
/// - [`Identity::Machine`] is the bearer token and nothing else, so this row is
///   not an inference at all. It used to be the worst one here: the token
///   resolved to the owner, so an unattended webhook and the operator at a
///   keyboard wrote the same line, and the stronger of the two readings was the
///   one recorded. Giving the token its own identity is what made the record
///   able to tell them apart.
/// - [`Identity::Owner`] is now the console password alone, which is what a
///   console login is.
fn credential_of(identity: &Identity) -> Credential {
    let opening = match identity {
        Identity::Machine => return Credential::Bearer,
        Identity::Person(_) => Opening::Passkey,
        Identity::Owner => Opening::Password,
    };
    Credential::Session(Session::new(opening, Instant::now()))
}

/// One input message as a short, secret-free phrase.
///
/// Pure and total, so what reaches the log is asserted directly in this module's
/// tests rather than sampled from a running session.
fn describe(message: &Message) -> String {
    match message {
        Message::Key { usage, down } => {
            format!("key{}:{:#04x}", if *down { "down" } else { "up" }, usage.hid())
        }
        // The count, never the content. See [`Auditor::performed`].
        Message::Text { text } => format!("text:{}units", text.chars().count()),
        Message::PointerMove { monitor, x, y } => format!("pointer:{monitor}:{x},{y}"),
        Message::Button { button, down } => {
            format!("button:{button:?}:{}", if *down { "down" } else { "up" })
        }
        Message::Scroll { dx, dy } => format!("scroll:{dx},{dy}"),
        Message::ReleaseAll => "release-all".to_owned(),
        // Not input at all — the driver refuses these before they reach a sink,
        // and a line for one would mean the driver had changed underneath us.
        _ => "not-input".to_owned(),
    }
}

/// The word for a platform refusal, from a closed vocabulary.
///
/// Written out rather than derived from `Debug` so that the log's vocabulary is
/// stable across a rename in another crate: an audit format whose words move
/// when somebody tidies an enum is a format nothing can be written to parse.
fn refusal_word(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NotPermitted => "not-permitted",
        Refusal::InputDisabled => "input-disabled",
        Refusal::SecureDesktop => "secure-desktop",
        Refusal::ElevatedWindow => "elevated-window",
        Refusal::NotLive => "not-live",
        Refusal::Unmappable => "unmappable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::audit::AUDIT_FORMAT;
    use selfhost_desk::keys::Usage;
    use selfhost_desk::wire::Button;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-audit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp dir");
        dir
    }

    fn lines(dir: &Path) -> Vec<String> {
        match std::fs::read_to_string(dir.join("audit.log")) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The property `docs/SECURITY.md` asks to be checkable with `grep -c ''`.
    #[test]
    fn one_control_action_is_exactly_one_line() {
        let dir = temp_dir("one-line");
        let auditor = Auditor::in_dir(&dir);

        auditor.performed(
            &Identity::Owner,
            "alex-desktop",
            &Message::Key { usage: Usage::from_hid(0x04).expect("a"), down: true },
            None,
        );
        assert_eq!(lines(&dir).len(), 1);

        auditor.kill_switch(true, "test");
        auditor.node_admin("invite", "alex-desktop");
        assert_eq!(lines(&dir).len(), 3, "three acts, three lines, no more and no fewer");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole point of using `selfhost-identity`'s record: nothing a person
    /// types can add a line to the log of what they typed.
    #[test]
    fn text_that_looks_like_a_log_line_cannot_become_one() {
        let dir = temp_dir("forge");
        let auditor = Auditor::in_dir(&dir);
        auditor.performed(
            &Identity::Owner,
            "alex-desktop",
            &Message::Text {
                text: "x\nselfhost-audit/1 id=0 at=0 identity=owner who=owner".to_owned(),
            },
            None,
        );
        let written = lines(&dir);
        assert_eq!(written.len(), 1, "a newline in the payload must not split the record");
        let line = written.first().expect("one line");
        assert!(
            line.contains("detail=text:"),
            "the detail counts the units rather than quoting them: {line}"
        );
        assert_eq!(
            line.matches(AUDIT_FORMAT).count(),
            1,
            "the payload's own format marker must not appear as a second record: {line}"
        );
        assert!(!line.contains("at=0 "), "the forged timestamp did not survive: {line}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whatever somebody types, the log must never hold it.
    #[test]
    fn what_was_typed_is_counted_and_never_quoted() {
        let described = describe(&Message::Text { text: "hunter2".to_owned() });
        assert_eq!(described, "text:7units");
        assert!(!described.contains("hunter"));
    }

    /// A platform refusal reaches the log as the daemon's decision plus the
    /// machine's answer, and both halves are readable.
    #[test]
    fn a_refused_keystroke_records_the_platform_s_answer() {
        let dir = temp_dir("refused");
        let auditor = Auditor::in_dir(&dir);
        auditor.performed(
            &Identity::Owner,
            "alex-desktop",
            &Message::Button { button: Button::Left, down: true },
            Some(Refusal::ElevatedWindow),
        );
        let line = lines(&dir).first().cloned().expect("one line");
        assert!(line.contains("outcome=allow"), "the daemon did permit it: {line}");
        assert!(line.contains("refused:elevated-window"), "{line}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A person's identity can only have been established by a passkey, and the
    /// log says so.
    #[test]
    fn a_named_person_is_recorded_as_having_used_a_passkey() {
        let person = Identity::parse("Mary-Anne").expect("a valid person name");
        assert_eq!(credential_of(&person).as_str(), "session.passkey");
        assert_eq!(credential_of(&Identity::Owner).as_str(), "session.password");
        // And the line the record could not write before: an unattended token
        // is spelled as the token, not as the operator having logged in.
        assert_eq!(credential_of(&Identity::Machine).as_str(), "bearer");
    }

    /// A node name that is not one must still produce a line.
    #[test]
    fn an_unnameable_node_is_still_audited() {
        assert_eq!(node_of("alex-desktop").as_str(), "alex-desktop");
        assert_eq!(node_of("not a node name at all!").as_str(), "unnamed");
    }
}
