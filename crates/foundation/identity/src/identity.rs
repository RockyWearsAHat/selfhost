//! Who the caller is: the owner, the box's own automation, or a named person.
//!
//! # Why the machine is not the owner
//!
//! The bearer token in `<data_dir>/admin.token` used to answer
//! [`Identity::Owner`], and that was one sentence too generous. The token is not
//! a person and has never stood for one: it is presented by the CLI running on
//! this box, by the native console over an SSH tunnel, and by an unattended
//! webhook relay. Calling it the owner meant the audit trail could not
//! distinguish "the operator did this at a keyboard" from "something on this box
//! did this at three in the morning", which is the one question an append-only
//! record exists to answer, and it meant a leaked token held every power the
//! deployment has rather than the ones the two programs that carry it actually
//! use.
//!
//! So it has its own identity, [`Identity::Machine`], and its authority is an
//! explicit list rather than a blanket allow — see [`crate::Policy::decide`].
//! What it may not do is create or alter *people*: the registry, the
//! invitations, and the enrolment of a new credential. Nothing that holds the
//! token has ever needed to, and a credential that lives in a file should not be
//! able to mint a person who will still be there after it is rotated.
//!
//! # Why the owner is a variant and not a string
//!
//! Until now the deployment had exactly one identity and it was spelled
//! `"owner"` — a `const OWNER: &str` in `crates/admin/src/lib.rs`, compared by
//! equality in one place, written into a session by another, and defaulted to
//! by a third when a passkey file predated names. That worked while the string
//! only ever *labelled* a session. It stops working the moment the string is
//! also the key that decides what a session may do, because then every place
//! that produces the string is a place that can mint authority.
//!
//! The concrete danger is not hypothetical: a passkey's holder name arrives in
//! the registration body (`webauthn.rs`, the `user` field), so whoever can
//! register a passkey chooses the name it is stored under. If a policy keyed on
//! that name treated `"owner"` — or `"Owner"`, or `"owner "` — as the
//! deployment's root identity, registering a passkey would be a way to *become*
//! the root identity. So the string is parsed exactly once, here, into a closed
//! enum, and the parse is deliberately unforgiving:
//!
//! - only the exact lowercase byte string `"owner"` is [`Identity::Owner`];
//! - every case variant of it (`"Owner"`, `"OWNER"`) is a hard error, not a
//!   near-miss that becomes a person — because a passkey registered as
//!   `"Owner"` that silently became a *person* called `Owner` would be a
//!   convincing impersonation in the console's people list and in the audit
//!   log, and one that quietly became the *owner* would be a privilege
//!   escalation;
//! - a person's name is a [`PersonName`], and a `PersonName` cannot spell
//!   `"owner"` in any casing, cannot carry surrounding whitespace that would
//!   trim into it, and cannot carry a character that could break out of a log
//!   line or a wire field.
//!
//! # What a name is allowed to contain, and why the rule is that shape
//!
//! A person's name is displayed in two consoles, written into an append-only
//! audit line, and stored in a JSON file. Each of those is a context with a
//! character that means "this field ends here" — a newline, a space, a quote,
//! an equals sign. Rather than escape defensively at every one of those three
//! boundaries and hope none is ever added, the name is constrained once at the
//! point it becomes a `PersonName`, to a set that has no such character in it:
//! Unicode letters and digits, plus a small set of interior separators
//! (`' '`, `'-'`, `'_'`, `'.'`, `'\''`) that real names actually use. A name
//! must begin and end with a letter or digit, and no two separators may sit
//! next to each other.
//!
//! Three consequences fall out of that, all of them wanted. Control characters
//! are impossible, so no name can forge a line break. Unicode format
//! characters — the bidirectional overrides and zero-width joiners a spoofing
//! attempt reaches for — are impossible, because they are neither alphanumeric
//! nor separators. And `"Alex"` and `"Alex "` cannot both exist to be
//! confused with each other, because the second is not a name at all.

use std::fmt;

/// The name behind the console password.
///
/// The console password is the deployment's credential rather than any person's,
/// and a session opened with it belongs to [`Identity::Owner`]. This constant
/// exists so the spelling lives in exactly one crate: `crates/admin` compares
/// against it and writes it into sessions, and nothing else needs to know the
/// literal at all — [`Identity::as_str`] answers it.
pub const OWNER_NAME: &str = "owner";

/// The name behind the bearer token.
///
/// Reserved on exactly the same terms as [`OWNER_NAME`] and for a sharper
/// reason: a passkey's holder name arrives in the registration body, so if a
/// person could be called `machine` they would authenticate into the identity
/// the box's own automation wears, and every line the token wrote in the audit
/// trail would be deniable — "that was the other machine".
pub const MACHINE_NAME: &str = "machine";

/// The longest agent's name accepted, in characters.
///
/// Matched to [`MAX_PERSON_NAME_CHARS`] for the same reason that constant is
/// matched to the passkey holder-name cap: an agent name ends up in the same
/// audit line and the same JSON shape a person's does, so the two grammars
/// should not be able to drift into "a name valid for one identity kind and
/// not the other".
pub const MAX_AGENT_NAME_CHARS: usize = MAX_PERSON_NAME_CHARS;

/// The longest person's name accepted, in characters.
///
/// Matched deliberately to the cap `crates/admin/src/webauthn.rs` already puts
/// on a passkey's holder name, so every name a passkey can carry is a name this
/// crate can represent. If the two ever drift, a passkey could be registered
/// under a name no policy could key on, and the holder would authenticate into
/// an identity the registry cannot describe.
pub const MAX_PERSON_NAME_CHARS: usize = 32;

/// Characters allowed *inside* a person's name, between letters and digits.
///
/// Deliberately short: these are the marks that appear in names people actually
/// have (`Mary-Anne`, `O'Neill`, `J. Alex`), and not one of them can terminate
/// a field in any format this crate writes.
const SEPARATORS: [char; 5] = [' ', '-', '_', '.', '\''];

/// Why a string is not a usable person's name.
///
/// Every variant names the specific rule that refused it. Nothing here is shown
/// to an unauthenticated caller — the API answers its one uninformative 401 —
/// but an operator adding a person to the registry deserves to be told which
/// rule they tripped rather than being told "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPersonName {
    /// The name was empty.
    Empty,
    /// The name was longer than [`MAX_PERSON_NAME_CHARS`] characters.
    TooLong {
        /// How many characters were offered.
        chars: usize,
    },
    /// The name was [`OWNER_NAME`], or a differently-cased spelling of it.
    ///
    /// Refused rather than folded, because a person called `Owner` is either an
    /// attempt to impersonate the deployment's root identity in a list a human
    /// reads, or an accident that would look exactly like one.
    ReservedOwnerName,
    /// The name was [`MACHINE_NAME`], or a differently-cased spelling of it.
    ///
    /// Its own variant rather than a shared "reserved" one so the message names
    /// the credential the operator has collided with: `owner` and `machine` are
    /// reserved for different reasons and an operator who trips one deserves to
    /// be told which.
    ReservedMachineName,
    /// The name did not begin and end with a letter or a digit.
    ///
    /// This is what refuses `" Alex"`, `"Alex "`, `"-Alex"` and `"Alex."`: a
    /// name that only differs from another by decoration on its edges is a name
    /// built to be mistaken for it.
    Edge,
    /// The name contained a character that is neither alphanumeric nor one of
    /// the permitted separators.
    Forbidden {
        /// The first offending character, so the message can quote it.
        character: char,
    },
    /// Two separators sat next to each other, as in `"Alex  Waldmann"`.
    ///
    /// Refused because a run of separators is invisible padding: it renders
    /// almost identically to a single one and produces a second name that looks
    /// like the first. The single exception is a full stop followed by a space,
    /// which is how an initial is written and which is perfectly visible.
    AdjacentSeparators,
}

impl fmt::Display for InvalidPersonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "a person's name may not be empty"),
            Self::TooLong { chars } => write!(
                f,
                "a person's name may be at most {MAX_PERSON_NAME_CHARS} characters ({chars} given)"
            ),
            Self::ReservedOwnerName => write!(
                f,
                "\"{OWNER_NAME}\" names the deployment's own credentials and may not name a person"
            ),
            Self::ReservedMachineName => write!(
                f,
                "\"{MACHINE_NAME}\" names this box's own bearer token and may not name a person"
            ),
            Self::Edge => {
                write!(f, "a person's name must begin and end with a letter or a digit")
            }
            Self::Forbidden { character } => write!(
                f,
                "a person's name may not contain {character:?}; \
                 letters, digits, and the marks {SEPARATORS:?} are allowed"
            ),
            Self::AdjacentSeparators => {
                write!(f, "a person's name may not put two of {SEPARATORS:?} side by side")
            }
        }
    }
}

impl std::error::Error for InvalidPersonName {}

/// A validated person's name.
///
/// The only way to build one is [`PersonName::parse`], so holding a
/// `PersonName` is proof that the rules in this module's documentation were
/// applied to it. That is what lets every downstream format — the audit line,
/// the JSON registry, both consoles — interpolate the name without escaping it
/// and without wondering whether this particular name is the one that breaks
/// the format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersonName(String);

impl PersonName {
    /// Validates `text` as a person's name.
    ///
    /// Refuses, in this order: emptiness, over-length, the reserved owner name
    /// in any casing, edges that are not alphanumeric, forbidden characters,
    /// and adjacent separators. The order matters only for which error a caller
    /// is shown first; every rule is checked before any name is accepted.
    ///
    /// Note that no trimming happens. A name is accepted exactly as written or
    /// not at all: silently trimming would mean `"Alex"` and `"Alex "` name the
    /// same person while comparing unequal everywhere the raw string survives.
    pub fn parse(text: &str) -> Result<Self, InvalidPersonName> {
        if text.is_empty() {
            return Err(InvalidPersonName::Empty);
        }
        let chars = text.chars().count();
        if chars > MAX_PERSON_NAME_CHARS {
            return Err(InvalidPersonName::TooLong { chars });
        }
        if text.eq_ignore_ascii_case(OWNER_NAME) {
            return Err(InvalidPersonName::ReservedOwnerName);
        }
        if text.eq_ignore_ascii_case(MACHINE_NAME) {
            return Err(InvalidPersonName::ReservedMachineName);
        }

        let mut previous_separator = None;
        let mut last_was_separator = false;
        for (index, character) in text.chars().enumerate() {
            let separator = SEPARATORS.contains(&character);
            if !separator && !character.is_alphanumeric() {
                return Err(InvalidPersonName::Forbidden { character });
            }
            if index == 0 && separator {
                return Err(InvalidPersonName::Edge);
            }
            // One pair of adjacent separators is allowed and it is the one
            // people actually write: a full stop followed by a space, as in
            // "J. Alex". It is not the thing this rule guards against — the
            // full stop is visible, so the name cannot be mistaken for a
            // shorter one padded out with blanks.
            if separator && previous_separator.is_some_and(|previous| (previous, character) != ('.', ' '))
            {
                return Err(InvalidPersonName::AdjacentSeparators);
            }
            previous_separator = separator.then_some(character);
            last_was_separator = separator;
        }
        if last_was_separator {
            return Err(InvalidPersonName::Edge);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PersonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a string is not a usable agent's name.
///
/// A near-copy of [`InvalidPersonName`] rather than a shared type, because the
/// two names are validated for the same reasons but belong to different
/// registries — a `PersonName` is looked up in `console.people`, an
/// `AgentName` in `console.agents` — and collapsing them into one type would
/// let a future change to one grammar silently reach the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidAgentName {
    /// The name was empty.
    Empty,
    /// The name was longer than [`MAX_AGENT_NAME_CHARS`] characters.
    TooLong {
        /// How many characters were offered.
        chars: usize,
    },
    /// The name was [`OWNER_NAME`], or a differently-cased spelling of it.
    ReservedOwnerName,
    /// The name was [`MACHINE_NAME`], or a differently-cased spelling of it.
    ReservedMachineName,
    /// The name did not begin and end with a letter or a digit.
    Edge,
    /// The name contained a character that is neither alphanumeric nor one of
    /// the permitted separators.
    Forbidden {
        /// The first offending character, so the message can quote it.
        character: char,
    },
    /// Two separators sat next to each other.
    AdjacentSeparators,
}

impl fmt::Display for InvalidAgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "an agent's name may not be empty"),
            Self::TooLong { chars } => write!(
                f,
                "an agent's name may be at most {MAX_AGENT_NAME_CHARS} characters ({chars} given)"
            ),
            Self::ReservedOwnerName => write!(
                f,
                "\"{OWNER_NAME}\" names the deployment's own credentials and may not name an agent"
            ),
            Self::ReservedMachineName => write!(
                f,
                "\"{MACHINE_NAME}\" names this box's own bearer token and may not name an agent"
            ),
            Self::Edge => {
                write!(f, "an agent's name must begin and end with a letter or a digit")
            }
            Self::Forbidden { character } => write!(
                f,
                "an agent's name may not contain {character:?}; \
                 letters, digits, and the marks {SEPARATORS:?} are allowed"
            ),
            Self::AdjacentSeparators => {
                write!(f, "an agent's name may not put two of {SEPARATORS:?} side by side")
            }
        }
    }
}

impl std::error::Error for InvalidAgentName {}

/// A validated agent's name — a machine Alex has explicitly trusted with a
/// scoped, revocable credential (`selfhost agent add <name>`), never a person
/// and never this box's own automation.
///
/// # Why this is a fourth identity and not a fourth shape of [`Identity::Person`]
///
/// A person is proved by a passkey — hardware, a biometric, a human at a
/// keyboard at the moment of the request. An agent is a headless process that
/// cannot perform that ceremony on every call, so it is given a different kind
/// of credential ([`crate::Credential::Agent`]) with different properties
/// (unattended, like the bearer token — see [`crate::Credential::is_unattended`]).
/// Folding it into `Person` would let an agent's audit lines read as though a
/// human had proved presence at the keyboard, which is exactly the confusion
/// [`Identity::Machine`] already exists to prevent for the box's own
/// automation. An agent is neither that automation (its capability list is not
/// fixed and not one of the two programs [`Identity::Machine`]'s doc names) nor
/// the owner (whose grants are never even consulted, see
/// [`crate::Policy::decide`]) — it needs its own variant so its authority can be
/// exactly, and only, what was explicitly granted to it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentName(String);

impl AgentName {
    /// Validates `text` as an agent's name. Same grammar as [`PersonName::parse`]
    /// — see this module's documentation for the reasoning, which applies
    /// unchanged: no trimming, the owner/machine sentinels are refused in any
    /// casing, and the character set is bounded to what cannot break a log line,
    /// a JSON field, or an `Authorization` header (an agent's name travels in a
    /// wire token, `agent:<name>:<secret>`, which a person's name never does —
    /// one more reason a colon can never appear in either grammar).
    pub fn parse(text: &str) -> Result<Self, InvalidAgentName> {
        if text.is_empty() {
            return Err(InvalidAgentName::Empty);
        }
        let chars = text.chars().count();
        if chars > MAX_AGENT_NAME_CHARS {
            return Err(InvalidAgentName::TooLong { chars });
        }
        if text.eq_ignore_ascii_case(OWNER_NAME) {
            return Err(InvalidAgentName::ReservedOwnerName);
        }
        if text.eq_ignore_ascii_case(MACHINE_NAME) {
            return Err(InvalidAgentName::ReservedMachineName);
        }

        let mut previous_separator = None;
        let mut last_was_separator = false;
        for (index, character) in text.chars().enumerate() {
            let separator = SEPARATORS.contains(&character);
            if !separator && !character.is_alphanumeric() {
                return Err(InvalidAgentName::Forbidden { character });
            }
            if index == 0 && separator {
                return Err(InvalidAgentName::Edge);
            }
            if separator && previous_separator.is_some_and(|previous| (previous, character) != ('.', ' '))
            {
                return Err(InvalidAgentName::AdjacentSeparators);
            }
            previous_separator = separator.then_some(character);
            last_was_separator = separator;
        }
        if last_was_separator {
            return Err(InvalidAgentName::Edge);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who a request is from.
///
/// Deliberately closed and deliberately small. Four kinds of caller exist: the
/// operator holding the deployment's own password, this box's own automation
/// holding its token, a person holding a credential of their own, and a
/// trusted machine holding a scoped agent credential. *How* each one proved it
/// is a separate axis — [`crate::Credential`] — precisely so that "who" and
/// "how they proved it" never collapse into one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The deployment itself: whoever holds the console password. Not a person —
    /// there is one console password, it names nobody, and its authority narrows
    /// to reading and enrolment the moment a credential that *does* name
    /// somebody exists on this deployment. See [`crate::Policy::decide`].
    Owner,
    /// This box's own automation: whatever presents the bearer token from
    /// `<data_dir>/admin.token`.
    ///
    /// Its own identity rather than the owner's because it is not a person and
    /// never was — see this module's documentation — and because an audit line
    /// reading `machine` is a fact, while the same line reading `owner` was a
    /// guess that happened to be wrong every time the CLI ran unattended. Its
    /// authority is an explicit list, not a blanket allow.
    Machine,
    /// A named person, proved by their own passkey.
    Person(PersonName),
    /// A trusted machine — an AI agent, a script, a second box of Alex's —
    /// holding a scoped, revocable credential minted by `selfhost agent add`.
    ///
    /// See [`AgentName`]'s documentation for why this is not folded into
    /// [`Identity::Person`] or [`Identity::Machine`]. Its authority is never a
    /// blanket allow and is never read from the people registry: it comes
    /// solely from the grants recorded for this name in `console.agents` (see
    /// `selfhost_admin::agent_store`), looked up fresh on every request by the
    /// same discipline `crates/app/admin::device_password` already uses for a
    /// credential store whose writer is a different process from its reader.
    Agent(AgentName),
}

impl Identity {
    /// Reads an identity out of a stored or presented name.
    ///
    /// Exactly one string is [`Identity::Owner`]: the lowercase [`OWNER_NAME`].
    /// Every other string must be a valid [`PersonName`], which by construction
    /// rules out every other spelling of the owner. This asymmetry is the
    /// point — see this module's documentation. It means a caller who can
    /// choose the stored name (today, anyone who can register a passkey) can
    /// choose to be *a* person, but can never choose to be *the* owner and
    /// can never choose a name that reads as the owner's.
    pub fn parse(name: &str) -> Result<Self, InvalidPersonName> {
        if name == OWNER_NAME {
            return Ok(Self::Owner);
        }
        if name == MACHINE_NAME {
            return Ok(Self::Machine);
        }
        PersonName::parse(name).map(Self::Person)
    }

    /// The name this identity is stored and displayed under.
    ///
    /// Round-trips through [`Identity::parse`] for every value that can exist
    /// *except* [`Identity::Agent`] — an agent is never produced by parsing a
    /// bare string against this registry's rules, it is produced by
    /// `selfhost_admin::agent_store` looking a presented token up in
    /// `console.agents`, so there is no `Identity::parse` round trip to keep for
    /// it. This is still the right place to render its name: every other
    /// identity's storage/display string lives here, and one function per
    /// identity kind that formats itself is how a future variant is guaranteed
    /// to be added here too, rather than growing a second `match` elsewhere that
    /// can drift.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Owner => OWNER_NAME,
            Self::Machine => MACHINE_NAME,
            Self::Person(name) => name.as_str(),
            Self::Agent(name) => name.as_str(),
        }
    }

    /// Whether this is the deployment's own identity.
    ///
    /// Deliberately false for [`Identity::Machine`] and [`Identity::Agent`].
    /// Every caller of this asks it in order to decide something a person
    /// should decide — may this hand out authority, may this read the record of
    /// everybody else — and the answer for a token in a file, or a credential
    /// minted for a trusted machine, is no. The places that genuinely mean "the
    /// box itself is allowed here too" say so by naming [`Identity::Machine`]
    /// beside this, which is one word longer and impossible to write by
    /// accident.
    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    /// Whether this is the box's own automation.
    ///
    /// Deliberately false for [`Identity::Agent`] — the two are different
    /// identities with different provenance (a fixed, non-extensible list of
    /// the box's own programs versus an operator-minted, revocable, per-machine
    /// credential) and the whole point of separating them is that a check
    /// written for one must not accidentally admit the other. See
    /// [`Policy::decide`](crate::Policy::decide)'s `the_machine_may`, which
    /// [`Identity::Agent`] never reaches.
    pub fn is_machine(&self) -> bool {
        matches!(self, Self::Machine)
    }

    /// Whether this is a trusted machine holding a scoped agent credential.
    pub fn is_agent(&self) -> bool {
        matches!(self, Self::Agent(_))
    }

    /// Whether this identity names one person.
    ///
    /// The predicate a per-person credential is checked against. Written here
    /// rather than as a `matches!` at each call site because the interesting
    /// property is what it is *not*: neither the owner nor the machine, both of
    /// which are the deployment rather than somebody — and, as of
    /// [`Identity::Agent`], not a trusted machine either. A `DevicePassword`
    /// names a person and only a person; an agent token names a machine and
    /// goes through [`Identity::is_agent`] instead.
    pub fn is_person(&self) -> bool {
        matches!(self, Self::Person(_))
    }

    /// The word the audit log uses for this identity's *kind*.
    ///
    /// Written as its own field beside the name, so a person whose name merely
    /// *looks* like the owner's in some script cannot be misread as the owner:
    /// the kind field says `person` and no amount of clever naming changes it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Machine => "machine",
            Self::Person(_) => "person",
            Self::Agent(_) => "agent",
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_are_accepted_exactly_as_written() {
        for name in ["Alex", "Mom", "Mary-Anne", "O'Neill", "J. Alex", "alex_2", "José", "米"] {
            let parsed = PersonName::parse(name).unwrap_or_else(|error| {
                panic!("{name:?} should be a name: {error}");
            });
            assert_eq!(parsed.as_str(), name, "names are stored verbatim");
        }
    }

    #[test]
    fn the_owner_sentinel_cannot_be_worn_by_a_person_in_any_casing() {
        for spelling in ["owner", "Owner", "OWNER", "oWnEr"] {
            assert_eq!(
                PersonName::parse(spelling),
                Err(InvalidPersonName::ReservedOwnerName),
                "{spelling:?} must not become a person"
            );
        }
        // And only the exact lowercase spelling is the owner: the rest are
        // errors, never a person and never a quiet promotion.
        assert_eq!(Identity::parse("owner"), Ok(Identity::Owner));
        for spelling in ["Owner", "OWNER", "oWnEr"] {
            assert_eq!(
                Identity::parse(spelling),
                Err(InvalidPersonName::ReservedOwnerName),
                "{spelling:?} is neither the owner nor a person"
            );
        }
    }

    #[test]
    fn the_machine_sentinel_cannot_be_worn_by_a_person_in_any_casing() {
        // The same rule as the owner's, for the sharper reason: a person called
        // `machine` would authenticate into the identity the bearer token wears,
        // and every line that token wrote in the audit trail would become
        // deniable.
        for spelling in ["machine", "Machine", "MACHINE", "mAcHiNe"] {
            assert_eq!(
                PersonName::parse(spelling),
                Err(InvalidPersonName::ReservedMachineName),
                "{spelling:?} must not become a person"
            );
        }
        assert_eq!(Identity::parse("machine"), Ok(Identity::Machine));
        for spelling in ["Machine", "MACHINE"] {
            assert_eq!(
                Identity::parse(spelling),
                Err(InvalidPersonName::ReservedMachineName),
                "{spelling:?} is neither the machine nor a person"
            );
        }
    }

    #[test]
    fn the_machine_is_not_the_owner_and_says_so_in_the_audit_line() {
        // The whole point of the variant. `is_owner` gates handing out authority
        // and reading the record of everybody else; the box's own token answers
        // no to both, and the trail says which of the two acted.
        assert!(!Identity::Machine.is_owner(), "a token in a file is not the operator");
        assert!(Identity::Machine.is_machine());
        assert!(!Identity::Owner.is_machine());
        assert_eq!(Identity::Machine.kind(), "machine");
        assert_ne!(Identity::Machine.kind(), Identity::Owner.kind());
    }

    #[test]
    fn a_name_that_would_trim_into_the_owner_is_refused_before_trimming_could_matter() {
        for spelling in [" owner", "owner ", "\towner", "owner\n"] {
            assert!(
                PersonName::parse(spelling).is_err(),
                "{spelling:?} must not be a name at all"
            );
        }
    }

    #[test]
    fn no_name_can_carry_a_character_that_ends_a_field() {
        // Every one of these is a character that means "this field is over" in
        // at least one format this crate writes into.
        let dangerous = [
            "Alex\nadmin", "Alex\radmin", "Alex\tadmin", "Alex\0admin", "Alex=admin",
            "Alex\"admin", "Alex\\admin", "Alex%20", "a\u{202e}b", "a\u{200b}b", "a\u{7f}b",
        ];
        for name in dangerous {
            assert!(PersonName::parse(name).is_err(), "{name:?} must be refused");
        }
    }

    #[test]
    fn edges_and_runs_of_separators_are_refused() {
        for name in [" Alex", "Alex ", "-Alex", "Alex.", "_Alex", "Alex'"] {
            assert_eq!(PersonName::parse(name), Err(InvalidPersonName::Edge), "{name:?}");
        }
        for name in ["Alex  W", "Alex--W", "Alex-_W", "A. .B", "A .B", "A._B"] {
            assert_eq!(
                PersonName::parse(name),
                Err(InvalidPersonName::AdjacentSeparators),
                "{name:?}"
            );
        }
        // The one permitted pair: an initial. Visible, so it cannot pad a name
        // out to look like a different one.
        assert!(PersonName::parse("J. Alex").is_ok());
        assert!(PersonName::parse("A. B. Smith").is_ok());
    }

    #[test]
    fn length_is_bounded_at_the_same_place_a_passkey_bounds_it() {
        let longest = "a".repeat(MAX_PERSON_NAME_CHARS);
        assert!(PersonName::parse(&longest).is_ok());
        let over = "a".repeat(MAX_PERSON_NAME_CHARS + 1);
        assert_eq!(
            PersonName::parse(&over),
            Err(InvalidPersonName::TooLong { chars: MAX_PERSON_NAME_CHARS + 1 })
        );
        assert_eq!(PersonName::parse(""), Err(InvalidPersonName::Empty));
        // Counted in characters, not bytes: a 32-character name of 3-byte
        // characters is still a 32-character name.
        assert!(PersonName::parse(&"米".repeat(MAX_PERSON_NAME_CHARS)).is_ok());
    }

    #[test]
    fn an_identity_round_trips_through_its_stored_name() {
        for identity in [
            Identity::Owner,
            Identity::Machine,
            Identity::Person(PersonName::parse("Mary-Anne").unwrap()),
        ] {
            assert_eq!(Identity::parse(identity.as_str()), Ok(identity.clone()));
        }
        assert!(Identity::Owner.is_owner());
        assert!(!Identity::parse("Alex").unwrap().is_owner());
        assert_eq!(Identity::Owner.kind(), "owner");
        assert_eq!(Identity::parse("Alex").unwrap().kind(), "person");
    }

    #[test]
    fn an_agent_name_follows_the_same_grammar_as_a_persons() {
        assert!(AgentName::parse("claude-mac").is_ok());
        assert!(AgentName::parse("Claude on ALEX-DESKTOP").is_ok());
        for spelling in ["owner", "Owner", "OWNER"] {
            assert_eq!(AgentName::parse(spelling), Err(InvalidAgentName::ReservedOwnerName));
        }
        for spelling in ["machine", "Machine", "MACHINE"] {
            assert_eq!(AgentName::parse(spelling), Err(InvalidAgentName::ReservedMachineName));
        }
        assert_eq!(AgentName::parse(""), Err(InvalidAgentName::Empty));
        assert_eq!(AgentName::parse(" claude"), Err(InvalidAgentName::Edge));
        assert!(AgentName::parse("claude:mac").is_err(), "a colon must never be a valid character — it is the token's own field separator");
        let over = "a".repeat(MAX_AGENT_NAME_CHARS + 1);
        assert!(matches!(AgentName::parse(&over), Err(InvalidAgentName::TooLong { .. })));
    }

    #[test]
    fn an_agent_is_neither_the_owner_nor_the_machine() {
        let agent = Identity::Agent(AgentName::parse("claude-mac").unwrap());
        assert!(!agent.is_owner());
        assert!(!agent.is_machine());
        assert!(agent.is_agent());
        assert!(!Identity::Owner.is_agent());
        assert!(!Identity::Machine.is_agent());
        assert_eq!(agent.kind(), "agent");
        assert_eq!(agent.as_str(), "claude-mac");
    }
}
