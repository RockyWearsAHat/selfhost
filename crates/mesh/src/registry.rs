//! Who is declared, who is live, and why the last one dropped.
//!
//! The console shows a picker of machines. A picker that lists only the machines
//! that happen to be connected right now is a picker that answers "is
//! ALEX-DESKTOP reachable?" with silence — the entry simply is not there, and the
//! operator cannot tell a machine that is switched off from a machine they never
//! enrolled from a bug in the console. **Absence is never the answer.** Every
//! machine the operator has declared appears, always, with a state and a reason.
//!
//! That is what this module is: the declared set, each peer's liveness, the reason
//! its last link ended, when it was last seen, and a per-node failure count.
//!
//! # Declared, never discovered
//!
//! A peer enters this registry because the operator enrolled it — never because
//! something connected and said it was called that. [`Registry::linked`] on an
//! unknown name is [`RegistryError::Undeclared`], not an insert. An implicit
//! insert would mean anything that reached the owner's console site and completed
//! a link could name itself into the picker; the enrolment proof would still gate
//! whether that link is *trusted*, but the operator's own list of their own
//! machines would be writable from the network, and a list like that stops being
//! evidence of anything.
//!
//! # The failure counter is per node, and it is not the login gate
//!
//! `crates/admin`'s `FailureGate` is deliberately global: five failed console
//! logins in sixty seconds lock the login door, because a password guess is a
//! password guess whoever is making it. A worker whose token is stale, or whose
//! clock is wrong, or which is simply flapping across a bad link, would trip that
//! gate in seconds — and the operator would find themselves locked out of their
//! own console by their own laptop. So peer failures are counted **here**, per
//! node, and this counter must never be wired to the console's login gate.
//!
//! # Time is a parameter
//!
//! Nothing in this module reads a clock. Every state change takes the time as an
//! argument, so "a peer that dropped an hour ago still says why" is a unit test
//! rather than a thing to be observed by waiting an hour. The clock is
//! [`SystemTime`] rather than `Instant` because these timestamps are shown to a
//! person — "last seen 14:02" — and a monotonic instant cannot be rendered.

use std::collections::BTreeMap;
use std::collections::btree_map::Values;
use std::fmt;
use std::time::SystemTime;

/// The longest a node name may be, in bytes.
///
/// Sixty-three is the DNS label limit, and node names are expected to look like
/// hostnames and to end up beside them in the console. Borrowing the limit means
/// a name that works here works there.
pub const MAX_NAME_LEN: usize = 63;

/// The name of one machine in the mesh.
///
/// A validated newtype rather than a `String`, because this name is a key: it
/// selects a peer to drive a desktop on, and it will select a capability grant
/// once per-person permissions arrive. A key that can be any string at all is a
/// key that can be two subtly different strings that a person reads as one.
///
/// The grammar is deliberately narrow — lowercase ASCII letters, digits and
/// hyphens, starting and ending alphanumeric — so that a name is unambiguous in a
/// URL query, in a log line, in a config file and in a file name, without any of
/// them needing an escaping rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    /// Validates and wraps a node name.
    ///
    /// Uppercase is refused with its own error rather than lumped in with "invalid
    /// character", because typing `ALEX-DESKTOP` — the machine's actual Windows
    /// name — is the single most likely mistake, and being told *"node names are
    /// lowercase"* fixes it in one step.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if text.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong { length: text.len() });
        }
        for character in text.chars() {
            if character.is_ascii_uppercase() {
                return Err(NameError::Uppercase);
            }
            if !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-') {
                return Err(NameError::InvalidCharacter { character });
            }
        }
        let first = text.chars().next().unwrap_or('-');
        let last = text.chars().next_back().unwrap_or('-');
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(NameError::HyphenAtEdge);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

/// Why a node name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name was empty.
    Empty,
    /// The name exceeds [`MAX_NAME_LEN`].
    TooLong {
        /// The length offered.
        length: usize,
    },
    /// The name contains an uppercase letter.
    Uppercase,
    /// The name contains a character outside `[a-z0-9-]`.
    InvalidCharacter {
        /// The first offending character.
        character: char,
    },
    /// The name starts or ends with a hyphen.
    HyphenAtEdge,
}

impl fmt::Display for NameError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => out.write_str("a node name cannot be empty"),
            Self::TooLong { length } => {
                write!(out, "a node name is at most {MAX_NAME_LEN} characters, this one is {length}")
            }
            Self::Uppercase => out.write_str("node names are lowercase: write alex-desktop, not ALEX-DESKTOP"),
            Self::InvalidCharacter { character } => {
                write!(out, "a node name may contain only a-z, 0-9 and '-'; found {character:?}")
            }
            Self::HyphenAtEdge => out.write_str("a node name must start and end with a letter or digit"),
        }
    }
}

impl std::error::Error for NameError {}

/// Why a peer's last link ended.
///
/// Named states rather than a string, so the console can render the same reason
/// the same way every time and so a reason cannot carry text a peer chose. Prose
/// for a person comes from [`Display`](fmt::Display), which lives here — one
/// place, shared by both consoles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The peer closed the link cleanly.
    PeerClosed {
        /// The close code it sent.
        code: u16,
    },
    /// We closed it: the operator asked, or this process is shutting down.
    LocalShutdown,
    /// The link went quiet and the liveness probe was not answered.
    Timeout,
    /// The enrolment proof did not verify, or the node presented no proof.
    ProofRefused,
    /// The peer speaks a protocol version this build does not.
    VersionMismatch {
        /// The version the peer offered.
        offered: u8,
    },
    /// The peer sent a frame this build could not make sense of.
    ProtocolError,
    /// The connection failed at the transport: refused, reset, DNS, TLS.
    ///
    /// Deliberately not carrying the underlying message: this value is stored,
    /// rendered and compared, and an `io::Error`'s text varies by platform and by
    /// libc. The detail belongs in the log line written at the moment it happened.
    TransportFailed,
    /// The peer link is configured but has never been established.
    NeverConnected,
}

impl fmt::Display for DropReason {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerClosed { code } => write!(out, "the peer closed the link (code {code})"),
            Self::LocalShutdown => out.write_str("this machine closed the link"),
            Self::Timeout => out.write_str("the link went quiet and the liveness probe was not answered"),
            Self::ProofRefused => out.write_str("the node's enrolment proof was refused"),
            Self::VersionMismatch { offered } => {
                write!(out, "the node speaks mesh protocol version {offered}, which this build does not")
            }
            Self::ProtocolError => out.write_str("the node sent a frame this build could not read"),
            Self::TransportFailed => out.write_str("the connection could not be established"),
            Self::NeverConnected => out.write_str("this node has never connected"),
        }
    }
}

/// Whether a peer is reachable, and since when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Declared, and never linked in this process's lifetime.
    NeverLinked,
    /// A link is up.
    Linked {
        /// When it came up.
        since: SystemTime,
    },
    /// A link was up and is not any more, or an attempt failed.
    Down {
        /// When it went down.
        since: SystemTime,
        /// Why.
        reason: DropReason,
    },
}

impl Liveness {
    /// Whether a link is up right now.
    pub fn is_linked(&self) -> bool {
        matches!(self, Self::Linked { .. })
    }
}

/// Everything the registry knows about one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The peer's name, as declared.
    pub name: NodeName,
    /// Whether it is reachable, and since when.
    pub liveness: Liveness,
    /// When a link to it was last up, if ever.
    ///
    /// Distinct from `liveness`: a peer that is `Down` still has a last-seen time,
    /// and that is exactly what the console needs to grey the entry with *"last
    /// seen 20 minutes ago"* rather than just greying it.
    pub last_seen: Option<SystemTime>,
    /// Failed link attempts since the last success.
    ///
    /// Per node. Never wired to the console's login gate; see the module
    /// documentation.
    pub consecutive_failures: u32,
    /// How many links to this peer have been established in total.
    pub links: u64,
}

impl PeerRecord {
    /// Whether a link to this peer is up.
    pub fn is_linked(&self) -> bool {
        self.liveness.is_linked()
    }

    /// A sentence describing this peer's state, for a console row.
    ///
    /// Written here so both consoles say the same thing: the native one and the
    /// web one share no code, and this is one of the places where a divergence
    /// would be a difference in what the operator is told, not just in how it
    /// looks.
    pub fn describe(&self) -> String {
        match self.liveness {
            Liveness::Linked { .. } => "linked".to_owned(),
            Liveness::NeverLinked => DropReason::NeverConnected.to_string(),
            Liveness::Down { reason, .. } => reason.to_string(),
        }
    }
}

/// The declared peers and their live state.
///
/// Pure and clock-free; see the module documentation. The owner daemon holds one
/// of these, the console reads snapshots of it, and the dialler on a worker holds
/// one with a single entry.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    peers: BTreeMap<String, PeerRecord>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a peer, or leaves an existing declaration untouched.
    ///
    /// Returns whether this call added it. Idempotent because config is reloaded
    /// and re-applied, and a reload must not forget that a peer is currently
    /// linked or why the last one dropped.
    pub fn declare(&mut self, name: NodeName) -> bool {
        if self.peers.contains_key(name.as_str()) {
            return false;
        }
        let record = PeerRecord {
            name: name.clone(),
            liveness: Liveness::NeverLinked,
            last_seen: None,
            consecutive_failures: 0,
            links: 0,
        };
        self.peers.insert(name.0, record);
        true
    }

    /// Declares a peer and marks it linked in one step.
    ///
    /// Exists so that a caller which knows a peer is up *because it is this very
    /// process* — see [`crate::local`] — does not have to handle a
    /// [`RegistryError::Undeclared`] that cannot happen. Splitting it into
    /// `declare` then `linked` would leave such a caller holding a `Result` with
    /// no honest way to treat it, and "no honest way to treat it" is how errors
    /// end up discarded.
    pub fn declare_linked(&mut self, name: NodeName, now: SystemTime) {
        self.declare(name.clone());
        let record = self.peers.get_mut(name.as_str()).expect("just declared");
        record.liveness = Liveness::Linked { since: now };
        record.last_seen = Some(now);
        record.consecutive_failures = 0;
        record.links = record.links.saturating_add(1);
    }

    /// Removes a peer entirely, because the operator withdrew it from config.
    ///
    /// Returns whether it was there. The caller is responsible for closing any
    /// link that was up: this module holds no sockets and cannot.
    pub fn undeclare(&mut self, name: &NodeName) -> bool {
        self.peers.remove(name.as_str()).is_some()
    }

    /// Whether the operator has declared this peer.
    ///
    /// The question the accepter asks before it even looks at an enrolment proof.
    pub fn is_declared(&self, name: &NodeName) -> bool {
        self.peers.contains_key(name.as_str())
    }

    /// Records that a link to `name` is up.
    ///
    /// Clears the failure counter: the peer has just demonstrated it can connect,
    /// and carrying the old count forward would make a machine that has been
    /// healthy for a week back off as if it had just failed.
    pub fn linked(&mut self, name: &NodeName, now: SystemTime) -> Result<(), RegistryError> {
        let record = self.record_mut(name)?;
        record.liveness = Liveness::Linked { since: now };
        record.last_seen = Some(now);
        record.consecutive_failures = 0;
        record.links = record.links.saturating_add(1);
        Ok(())
    }

    /// Records that a link to `name` ended, or that an attempt failed.
    ///
    /// `last_seen` is advanced only if the peer was actually linked: an attempt
    /// that never connected is not a sighting, and reporting it as one would tell
    /// the operator a machine was reachable a moment ago when it has been off all
    /// week.
    pub fn dropped(&mut self, name: &NodeName, now: SystemTime, reason: DropReason) -> Result<(), RegistryError> {
        let record = self.record_mut(name)?;
        if record.liveness.is_linked() {
            record.last_seen = Some(now);
        }
        record.liveness = Liveness::Down { since: now, reason };
        record.consecutive_failures = record.consecutive_failures.saturating_add(1);
        Ok(())
    }

    /// This peer's record, if it is declared.
    pub fn get(&self, name: &NodeName) -> Option<&PeerRecord> {
        self.peers.get(name.as_str())
    }

    /// Every declared peer, in name order.
    ///
    /// Including the ones that are down and the ones that have never connected;
    /// see the module documentation on why absence is never the answer.
    pub fn peers(&self) -> Values<'_, String, PeerRecord> {
        self.peers.values()
    }

    /// How many peers are declared.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether nothing is declared.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// How many peers currently have a link up.
    pub fn linked_count(&self) -> usize {
        self.peers.values().filter(|record| record.is_linked()).count()
    }

    /// Marks every linked peer down, because this process is losing them all at
    /// once — a shutdown, or the link-carrying socket dying.
    ///
    /// Returns the names it changed, so the caller can log or tear down per peer.
    pub fn drop_all(&mut self, now: SystemTime, reason: DropReason) -> Vec<NodeName> {
        let mut changed = Vec::new();
        for record in self.peers.values_mut() {
            if record.liveness.is_linked() {
                record.last_seen = Some(now);
                record.liveness = Liveness::Down { since: now, reason };
                record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                changed.push(record.name.clone());
            }
        }
        changed
    }

    fn record_mut(&mut self, name: &NodeName) -> Result<&mut PeerRecord, RegistryError> {
        self.peers.get_mut(name.as_str()).ok_or_else(|| RegistryError::Undeclared(name.clone()))
    }
}

/// Why a registry operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No such peer has been declared.
    ///
    /// The registry never learns a peer from the wire; see the module
    /// documentation.
    Undeclared(NodeName),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undeclared(name) => write!(out, "node {name} is not declared on this machine"),
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn node(text: &str) -> NodeName {
        NodeName::parse(text).expect("valid name")
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for text in ["a", "alex-desktop", "node1", "0", "mac-mini-2", &"x".repeat(MAX_NAME_LEN)] {
            assert!(NodeName::parse(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn the_uppercase_mistake_gets_its_own_message() {
        // Typing the machine's actual Windows name is the likeliest mistake, and
        // "node names are lowercase" fixes it in one step.
        assert_eq!(NodeName::parse("ALEX-DESKTOP").unwrap_err(), NameError::Uppercase);
        assert!(NameError::Uppercase.to_string().contains("lowercase"));
    }

    #[test]
    fn malformed_names_are_refused_with_a_reason() {
        assert_eq!(NodeName::parse("").unwrap_err(), NameError::Empty);
        assert_eq!(
            NodeName::parse(&"x".repeat(MAX_NAME_LEN + 1)).unwrap_err(),
            NameError::TooLong { length: MAX_NAME_LEN + 1 }
        );
        assert_eq!(NodeName::parse("-lead").unwrap_err(), NameError::HyphenAtEdge);
        assert_eq!(NodeName::parse("trail-").unwrap_err(), NameError::HyphenAtEdge);
        assert_eq!(NodeName::parse("-").unwrap_err(), NameError::HyphenAtEdge);
        for text in ["has space", "dot.ted", "under_score", "slash/es", "colon:s", "emoji🙂"] {
            assert!(
                matches!(NodeName::parse(text), Err(NameError::InvalidCharacter { .. })),
                "{text} should be refused"
            );
        }
    }

    #[test]
    fn a_name_never_panics_on_arbitrary_input() {
        let mut state = 0xfeed_face_dead_beefu64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 70) as usize;
            let text: String = (0..len).map(|index| char::from((state >> (index % 8 * 8)) as u8)).collect();
            if let Ok(name) = NodeName::parse(&text) {
                assert_eq!(name.as_str(), text);
                assert!(name.as_str().len() <= MAX_NAME_LEN);
            }
        }
    }

    #[test]
    fn a_declared_peer_starts_never_linked_and_says_so() {
        let mut registry = Registry::new();
        assert!(registry.declare(node("alex-desktop")));
        assert!(!registry.declare(node("alex-desktop")), "declaring twice is idempotent");
        let record = registry.get(&node("alex-desktop")).expect("declared");
        assert_eq!(record.liveness, Liveness::NeverLinked);
        assert_eq!(record.last_seen, None);
        assert_eq!(record.links, 0);
        assert_eq!(record.describe(), "this node has never connected");
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.linked_count(), 0);
    }

    #[test]
    fn a_peer_is_never_learned_from_the_wire() {
        // The property: nothing that connects can write itself into the operator's
        // list of their own machines.
        let mut registry = Registry::new();
        let stranger = node("not-mine");
        assert_eq!(registry.linked(&stranger, at(1)).unwrap_err(), RegistryError::Undeclared(stranger.clone()));
        assert_eq!(
            registry.dropped(&stranger, at(1), DropReason::Timeout).unwrap_err(),
            RegistryError::Undeclared(stranger)
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn linking_clears_the_failure_counter_and_counts_the_link() {
        let mut registry = Registry::new();
        let name = node("alex-desktop");
        registry.declare(name.clone());
        registry.dropped(&name, at(10), DropReason::TransportFailed).expect("drop");
        registry.dropped(&name, at(20), DropReason::TransportFailed).expect("drop");
        assert_eq!(registry.get(&name).expect("record").consecutive_failures, 2);

        registry.linked(&name, at(30)).expect("link");
        let record = registry.get(&name).expect("record");
        assert_eq!(record.consecutive_failures, 0, "a machine that just connected is not still failing");
        assert_eq!(record.liveness, Liveness::Linked { since: at(30) });
        assert_eq!(record.last_seen, Some(at(30)));
        assert_eq!(record.links, 1);
        assert!(record.is_linked());
        assert_eq!(registry.linked_count(), 1);
    }

    #[test]
    fn a_drop_keeps_the_reason_and_the_last_time_it_was_actually_seen() {
        let mut registry = Registry::new();
        let name = node("alex-desktop");
        registry.declare(name.clone());
        registry.linked(&name, at(100)).expect("link");
        registry.dropped(&name, at(160), DropReason::PeerClosed { code: 1001 }).expect("drop");

        let record = registry.get(&name).expect("record");
        assert_eq!(record.liveness, Liveness::Down { since: at(160), reason: DropReason::PeerClosed { code: 1001 } });
        assert_eq!(record.last_seen, Some(at(160)));
        assert!(record.describe().contains("1001"));
        assert!(!record.is_linked());
    }

    #[test]
    fn a_failed_attempt_is_not_a_sighting() {
        // Reporting a failed dial as a sighting would tell the operator a machine
        // was reachable a moment ago when it has been switched off all week.
        let mut registry = Registry::new();
        let name = node("mac-mini");
        registry.declare(name.clone());
        registry.linked(&name, at(100)).expect("link");
        registry.dropped(&name, at(200), DropReason::Timeout).expect("drop");
        registry.dropped(&name, at(300), DropReason::TransportFailed).expect("retry failed");
        registry.dropped(&name, at(400), DropReason::TransportFailed).expect("retry failed");

        let record = registry.get(&name).expect("record");
        assert_eq!(record.last_seen, Some(at(200)), "the last time it was actually up");
        assert_eq!(record.consecutive_failures, 3);
        assert_eq!(record.liveness, Liveness::Down { since: at(400), reason: DropReason::TransportFailed });
    }

    #[test]
    fn every_declared_peer_is_listed_whatever_its_state() {
        // Absence is never the answer: the picker must show the machine that is
        // switched off, with a reason.
        let mut registry = Registry::new();
        registry.declare(node("alpha"));
        registry.declare(node("bravo"));
        registry.declare(node("charlie"));
        registry.linked(&node("bravo"), at(5)).expect("link");
        registry.dropped(&node("charlie"), at(6), DropReason::ProofRefused).expect("drop");

        let listed: Vec<&str> = registry.peers().map(|record| record.name.as_str()).collect();
        assert_eq!(listed, vec!["alpha", "bravo", "charlie"], "listed in name order, all of them");
        assert_eq!(registry.linked_count(), 1);
        let descriptions: Vec<String> = registry.peers().map(PeerRecord::describe).collect();
        assert_eq!(descriptions[0], "this node has never connected");
        assert_eq!(descriptions[1], "linked");
        assert_eq!(descriptions[2], "the node's enrolment proof was refused");
    }

    #[test]
    fn undeclaring_removes_a_peer() {
        let mut registry = Registry::new();
        registry.declare(node("gone"));
        assert!(registry.is_declared(&node("gone")));
        assert!(registry.undeclare(&node("gone")));
        assert!(!registry.undeclare(&node("gone")));
        assert!(!registry.is_declared(&node("gone")));
    }

    #[test]
    fn dropping_everything_at_once_touches_only_what_was_linked() {
        let mut registry = Registry::new();
        registry.declare(node("up-one"));
        registry.declare(node("up-two"));
        registry.declare(node("never"));
        registry.linked(&node("up-one"), at(1)).expect("link");
        registry.linked(&node("up-two"), at(2)).expect("link");

        let changed = registry.drop_all(at(99), DropReason::LocalShutdown);
        assert_eq!(changed, vec![node("up-one"), node("up-two")]);
        assert_eq!(registry.linked_count(), 0);
        assert_eq!(
            registry.get(&node("never")).expect("record").liveness,
            Liveness::NeverLinked,
            "a peer that was never up did not just fail"
        );
        assert_eq!(registry.get(&node("never")).expect("record").consecutive_failures, 0);
    }

    #[test]
    fn a_reload_does_not_forget_a_live_link() {
        // Config is reloaded and re-applied; declaring again must be a no-op.
        let mut registry = Registry::new();
        let name = node("alex-desktop");
        registry.declare(name.clone());
        registry.linked(&name, at(50)).expect("link");
        assert!(!registry.declare(name.clone()));
        assert_eq!(registry.get(&name).expect("record").liveness, Liveness::Linked { since: at(50) });
    }

    #[test]
    fn drop_reasons_read_as_sentences() {
        assert!(DropReason::VersionMismatch { offered: 9 }.to_string().contains('9'));
        assert!(DropReason::Timeout.to_string().contains("quiet"));
        assert!(DropReason::LocalShutdown.to_string().contains("this machine"));
        assert!(DropReason::ProtocolError.to_string().contains("frame"));
        assert!(DropReason::TransportFailed.to_string().contains("connection"));
        assert!(RegistryError::Undeclared(node("x")).to_string().contains('x'));
    }
}
