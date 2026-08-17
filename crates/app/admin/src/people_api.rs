//! The people plane: who this deployment knows, and what each of them may do.
//!
//! # The gap this closes
//!
//! `crates/identity` has held the whole permission model since it was written —
//! a closed capability vocabulary, a durable per-person registry
//! ([`People`], `<data_dir>/console.people`), and a pure
//! [`Policy::decide`](selfhost_identity::Policy::decide) over every triple. What
//! it never had was a *writer*. `People::set_grants` and `People::remove`
//! existed with nothing outside the crate's own tests calling them, so a
//! deployment could describe a second person and could not create one. Half the
//! vocabulary — `site.admin`, `dns.admin`, `mail.admin`, `node.admin` — was
//! declared power that no route consumed. This module is the seam that makes the
//! model reachable: three owner-only routes that read and write the registry,
//! and one route behind the wall that tells any caller what they themselves
//! hold.
//!
//! # Why `whoami` is not owner-only, and demands no capability
//!
//! Every other route here is the owner's. `whoami` is deliberately the
//! opposite — it answers to *anyone the wall already admitted*, including a
//! person holding nothing at all. That is what makes a permission-shaped
//! interface possible: a client cannot draw only the screens a person may use
//! until it can ask what they may use, and a person with an empty grant set must
//! get an honest empty answer rather than a `401`. It reveals nothing a caller
//! does not already possess: their own name, their own credential kind, and
//! their own capabilities.
//!
//! # Whole sets, never increments
//!
//! `PUT /api/people/<name>` carries the complete grant set and replaces what was
//! there, for the reason [`People::set_grants`] gives in its own contract: the
//! console renders a person as a set of toggles and submits the set, and a
//! permission change applied as a sequence of increments is one that can be
//! half-applied. A body that fails to parse changes nothing — the grants are
//! built and validated in full before the registry is touched.

use selfhost_identity::{Capability, Caller, Grants, People, Person};
use selfhost_json::Json;

/// Why a submitted grant set was refused.
///
/// One refusal per way the body can be wrong, because each has a different
/// remedy and an operator editing permissions deserves to be told which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadGrants {
    /// The body was not JSON at all.
    NotJson,
    /// The body parsed but carried no `grants` array.
    NoGrantsArray,
    /// An entry in the array was not a string.
    NotAString,
    /// A capability this deployment does not have a word for, or one written
    /// with a target it does not take. Carries the text as submitted.
    Unknown(String),
    /// More capabilities than [`selfhost_identity::policy::MAX_GRANTS`].
    TooMany,
}

impl BadGrants {
    /// A sentence naming what is wrong and what would fix it.
    pub fn message(&self) -> String {
        match self {
            Self::NotJson => "the body is not JSON".to_owned(),
            Self::NoGrantsArray => {
                "the body needs a \"grants\" array of capability words".to_owned()
            }
            Self::NotAString => "every entry in \"grants\" must be a string".to_owned(),
            // The submitted text is echoed because a typo is the overwhelmingly
            // likely cause and naming it is the whole of the fix. It is a JSON
            // string on the way out, so it is escaped by the serialiser.
            Self::Unknown(text) => format!(
                "\"{text}\" is not a capability this deployment knows; \
                 see /api/people/capabilities for every word and whether it takes a target"
            ),
            Self::TooMany => "too many capabilities for one person".to_owned(),
        }
    }
}

/// Reads a submitted grant set, whole, or refuses it whole.
///
/// Pure, so the rules about what a permission change may say are asserted rather
/// than trusted. Nothing here touches the registry.
pub fn grants_from_body(body: &[u8]) -> Result<Grants, BadGrants> {
    let text = std::str::from_utf8(body).map_err(|_| BadGrants::NotJson)?;
    let document = selfhost_json::parse(text).map_err(|_| BadGrants::NotJson)?;
    let entries = document.get("grants").and_then(Json::as_array).ok_or(BadGrants::NoGrantsArray)?;
    let mut capabilities = Vec::with_capacity(entries.len());
    for entry in entries {
        let word = entry.as_str().ok_or(BadGrants::NotAString)?;
        let capability = Capability::parse(word).ok_or_else(|| BadGrants::Unknown(word.to_owned()))?;
        capabilities.push(capability);
    }
    Grants::new(capabilities).map_err(|_| BadGrants::TooMany)
}

/// One person as the console reads them.
pub fn person_json(person: &Person) -> Json {
    Json::object([
        ("name", Json::string(person.name.as_str())),
        ("added_unix", Json::Number(person.added_unix as f64)),
        ("grants", grants_json(&person.grants)),
    ])
}

/// A grant set as the wire words the console submits back.
///
/// The same spelling [`Capability::parse`] reads, so a set that is fetched,
/// toggled and submitted round-trips exactly.
pub fn grants_json(grants: &Grants) -> Json {
    Json::array(grants.iter().map(|capability| Json::string(wire_word(capability))))
}

/// A capability as one string: the word, and its target after a colon.
pub fn wire_word(capability: &Capability) -> String {
    match capability.target() {
        Some(target) => format!("{}:{target}", capability.name()),
        None => capability.name().to_owned(),
    }
}

/// The whole roster, for the owner.
pub fn roster_json(people: &People) -> Json {
    let entries = people.list();
    Json::object([
        ("people", Json::array(entries.iter().map(person_json))),
        ("count", Json::Number(entries.len() as f64)),
    ])
}

/// What the caller themselves is and holds.
///
/// The owner is reported with `owner: true` and an empty grant list, which is
/// the truth rather than an omission: [`Policy::decide`](selfhost_identity::Policy::decide)
/// never consults a grant set for the owner, so an owner's authority is their
/// identity and not a list that could be edited away. A client must read the
/// flag, not the list, to decide whether to draw everything.
pub fn whoami_json(caller: &Caller) -> Json {
    Json::object([
        ("name", Json::string(caller.identity().to_string())),
        ("owner", Json::Bool(caller.identity().is_owner())),
        // Its own flag rather than folded into `owner`, and this is the whole
        // reason the bearer token stopped answering `owner: true`: a client that
        // could not tell the operator from the box's own automation drew the
        // same console for both, and the audit trail wrote the same line for
        // both. A client reads this to know it is the machine talking; it does
        // not read it to know what the machine may do, because — like the
        // owner's — the machine's authority is an identity and not a grant list,
        // so `grants` below is empty for it and is meant to be.
        ("machine", Json::Bool(caller.identity().is_machine())),
        ("credential", Json::string(caller.credential().as_str())),
        ("grants", grants_json(caller.grants())),
    ])
}

/// Every capability word this deployment understands, and whether it takes a
/// target.
///
/// Served so that a console — or a person writing a `selfhost people grant`
/// command — never has to keep its own copy of a vocabulary that lives in
/// `crates/identity`. A word added there and forgotten here would be invisible
/// in every interface, so this list is derived from the same parse function that
/// enforces it: each entry below is round-tripped through [`Capability::parse`]
/// in this module's tests.
pub const VOCABULARY: [(&str, Option<&str>); 12] = [
    ("console.read", None),
    ("service.control", None),
    ("files.read", Some("share")),
    ("files.write", Some("share")),
    ("files.admin", None),
    ("desktop.view", Some("node")),
    ("desktop.control", Some("node")),
    ("clipboard.read", Some("node")),
    ("node.admin", None),
    ("site.admin", None),
    ("dns.admin", None),
    ("mail.admin", None),
];

/// [`VOCABULARY`] as JSON.
pub fn vocabulary_json() -> Json {
    Json::array(VOCABULARY.iter().map(|(word, target)| {
        Json::object([
            ("word", Json::string(*word)),
            ("target", target.map_or(Json::Null, Json::string)),
        ])
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::{NodeName, ShareId};

    #[test]
    fn a_whole_set_is_read_or_none_of_it_is() {
        let grants = grants_from_body(br#"{"grants":["console.read","files.read:vault"]}"#).unwrap();
        assert_eq!(grants.len(), 2);
        assert!(grants.holds(&Capability::ConsoleRead));
        assert!(grants.holds(&Capability::FilesRead(ShareId::parse("vault").unwrap())));
    }

    #[test]
    fn one_bad_word_refuses_the_whole_change() {
        // The failure this prevents: a submitted set applied minus the entry
        // that did not parse, leaving a person holding something nobody chose.
        let refusal = grants_from_body(br#"{"grants":["console.read","files.read"]}"#).unwrap_err();
        assert_eq!(refusal, BadGrants::Unknown("files.read".into()), "a share target is required");
        assert!(refusal.message().contains("files.read"));
    }

    #[test]
    fn a_body_that_is_not_a_grant_set_says_which_way_it_is_wrong() {
        assert_eq!(grants_from_body(b"not json").unwrap_err(), BadGrants::NotJson);
        assert_eq!(grants_from_body(br#"{"caps":[]}"#).unwrap_err(), BadGrants::NoGrantsArray);
        assert_eq!(grants_from_body(br#"{"grants":[7]}"#).unwrap_err(), BadGrants::NotAString);
    }

    #[test]
    fn an_empty_set_is_a_legal_change_and_not_an_error() {
        // "Hold nothing" is a permission decision an operator makes on purpose,
        // and it must not be spelled the same as a malformed body.
        assert!(grants_from_body(br#"{"grants":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn every_word_the_vocabulary_advertises_parses() {
        // The guard on the copy: this list lives beside the enum it describes,
        // so it is checked against the parser that enforces the real one.
        for (word, target) in VOCABULARY {
            let spelling = match target {
                Some("share") => format!("{word}:vault"),
                Some(_) => format!("{word}:alex-desktop"),
                None => word.to_owned(),
            };
            assert!(Capability::parse(&spelling).is_some(), "{spelling} did not parse");
        }
    }

    #[test]
    fn a_grant_set_round_trips_through_its_wire_words() {
        // What the console does: fetch, toggle, submit. A spelling that did not
        // round-trip would silently drop a person's capability on every save.
        let original = Grants::new([
            Capability::DesktopControl(NodeName::parse("alex-desktop").unwrap()),
            Capability::FilesWrite(ShareId::parse("vault").unwrap()),
            Capability::MailAdmin,
        ])
        .unwrap();
        let body = format!(r#"{{"grants":{}}}"#, grants_json(&original).to_text());
        assert_eq!(grants_from_body(body.as_bytes()).unwrap(), original);
    }
}
