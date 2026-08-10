//! Who the caller is: the owner, or a named person.
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

/// The name behind the deployment's root credentials.
///
/// The console password and the bearer token are the deployment's credentials
/// rather than any person's, and a session opened with either one belongs to
/// [`Identity::Owner`]. This constant exists so the spelling lives in exactly
/// one crate: `crates/admin` compares against it and writes it into sessions,
/// and nothing else needs to know the literal at all — [`Identity::as_str`]
/// answers it.
pub const OWNER_NAME: &str = "owner";

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

/// Who a request is from.
///
/// Deliberately closed and deliberately small. There are two kinds of caller a
/// deployment can have: the operator holding the deployment's own credentials,
/// and a person holding one of their own. Everything else — automation, the
/// native console, a peer node's daemon — is one of those two wearing a
/// particular [`crate::Credential`], which is tracked separately precisely so
/// that "who" and "how they proved it" never collapse into one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The deployment itself: whoever holds the console password or the bearer
    /// token. Not a person — the two credentials behind this identity are the
    /// deployment's root credentials, and they are held by whoever installed it.
    Owner,
    /// A named person, proved by their own passkey.
    Person(PersonName),
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
        PersonName::parse(name).map(Self::Person)
    }

    /// The name this identity is stored and displayed under.
    ///
    /// Round-trips through [`Identity::parse`] for every value that can exist,
    /// which is what lets the session store keep holding a plain string without
    /// that string being a second source of truth.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Owner => OWNER_NAME,
            Self::Person(name) => name.as_str(),
        }
    }

    /// Whether this is the deployment's own identity.
    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    /// The word the audit log uses for this identity's *kind*.
    ///
    /// Written as its own field beside the name, so a person whose name merely
    /// *looks* like the owner's in some script cannot be misread as the owner:
    /// the kind field says `person` and no amount of clever naming changes it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Person(_) => "person",
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
        for identity in
            [Identity::Owner, Identity::Person(PersonName::parse("Mary-Anne").unwrap())]
        {
            assert_eq!(Identity::parse(identity.as_str()), Ok(identity.clone()));
        }
        assert!(Identity::Owner.is_owner());
        assert!(!Identity::parse("Alex").unwrap().is_owner());
        assert_eq!(Identity::Owner.kind(), "owner");
        assert_eq!(Identity::parse("Alex").unwrap().kind(), "person");
    }
}
