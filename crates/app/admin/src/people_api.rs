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

use selfhost_identity::{Capability, Caller, Grants, People, Person, PersonEmail, PersonName, VpnLocationId};
use selfhost_json::Json;
use std::path::{Path, PathBuf};

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
    /// A real word from the vocabulary that no route in this deployment
    /// consumes yet — see [`Capability::is_honoured`]. Carries the word.
    ///
    /// Refused rather than stored, because a stored one is a **promise**: the
    /// operator reads the console row as "she can manage the DNS", stops doing
    /// it themselves, and the person they delegated to finds that nothing
    /// happens — with no error and no audit line, because no code path is
    /// involved at all. A refusal at the moment of granting is the only place
    /// that misunderstanding can be caught.
    NotYetHonoured(String),
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
            Self::NotYetHonoured(word) => format!(
                "\"{word}\" is a real capability that nothing in this deployment honours yet: \
                 no route asks for it, so granting it would record a power its holder cannot \
                 use and you would believe you had delegated something you had not. \
                 It becomes grantable in the release that ships the routes behind it"
            ),
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
        if !capability.is_honoured() {
            return Err(BadGrants::NotYetHonoured(word.to_owned()));
        }
        capabilities.push(capability);
    }
    Grants::new(capabilities).map_err(|_| BadGrants::TooMany)
}

/// Whether `grants` holds a console capability with no route to it, because
/// the console's own HTTP surface is reachable only through a VPN tunnel and
/// this set holds `vpn.access` for none of the deployment's `relays`.
///
/// A deployment with no relay has no tunnel to be missing, so it never warns.
/// A Grant on a Site (`site.access`, `site.admin:<site>`) is not a console
/// capability: a Site is reached at its own hostname, behind its own Exposure.
///
/// # Why this warns rather than granting or refusing
///
/// [`Capability::VpnAccess`] is independent of every other capability by
/// design: being able to reach a location says nothing about being able to
/// administer it. Auto-granting it alongside a console capability would break
/// that in the dangerous direction, so this never writes anything. It is the
/// sibling of [`BadGrants::NotYetHonoured`] for a route that exists in general
/// but is unreachable *for this person*.
pub fn unreachable_without_vpn(grants: &Grants, relays: &[&str]) -> Option<String> {
    if relays.is_empty() {
        return None;
    }
    let holds_console_capability = grants.iter().any(|capability| {
        !matches!(
            capability,
            Capability::VpnAccess(_) | Capability::SiteAccess(_) | Capability::SiteAdminOf(_)
        )
    });
    let holds_a_relay = grants.iter().any(
        |capability| matches!(capability, Capability::VpnAccess(location) if relays.contains(&location.as_str())),
    );
    (holds_console_capability && !holds_a_relay).then(|| {
        let words: Vec<String> = relays.iter().map(|relay| format!("vpn.access:{relay}")).collect();
        format!(
            "holds a console capability, but none of {} — the admin console's HTTP surface is \
             reachable only through the VPN tunnel, so none of it is usable until they hold one",
            words.join(", ")
        )
    })
}

/// The optional `"peer"` and `"public_key"` fields a `PUT /api/people/<name>`
/// body may carry alongside `"grants"`, needed to actually provision a roster
/// entry for a newly granted `vpn.access:<location>` — the same two values
/// `selfhost people grant --peer --pubkey` supplies on the CLI side of
/// [`vpn_side_effects`].
///
/// Absent fields are `None`, not a refusal: a grant with no peer/key yet is
/// legal (see [`vpn_side_effects`]'s own doc comment), so this only refuses
/// when a field is *present* and fails the same shape check
/// [`selfhost_config::vpn::peer_name_problem`] / `public_key_problem` apply to
/// a `[[vpn.peers]]` config entry or the CLI's own flags — a typo caught here
/// rather than written and discovered at the next handshake.
pub fn vpn_fields_from_body(body: &[u8]) -> Result<(Option<String>, Option<String>), String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not JSON".to_owned())?;
    let document = selfhost_json::parse(text).map_err(|_| "the body is not JSON".to_owned())?;
    let field = |name: &str| -> Result<Option<String>, String> {
        match document.get(name) {
            None | Some(Json::Null) => Ok(None),
            Some(value) => {
                let text = value.as_str().ok_or_else(|| format!("\"{name}\" must be a string"))?;
                Ok(Some(text.to_owned()))
            }
        }
    };
    let peer = field("peer")?;
    if let Some(peer) = &peer {
        if let Some(problem) = selfhost_config::vpn::peer_name_problem(peer) {
            return Err(format!("\"{peer}\" is not a usable roster name: {problem}"));
        }
    }
    let public_key = field("public_key")?;
    if let Some(public_key) = &public_key {
        if let Some(problem) = selfhost_config::vpn::public_key_problem(public_key) {
            return Err(format!("that public_key is not usable: {problem}"));
        }
    }
    Ok((peer, public_key))
}

/// The optional `"email"` and `"password"` fields a `PUT /api/people/<name>`
/// body may carry alongside `"grants"`, letting the owner give this person a
/// real sign-in — an address and a password checked at the login form —
/// in the same call that grants them something to do once they are in.
///
/// Absent or `null` fields are `None`, not a refusal, on the same grounds as
/// [`vpn_fields_from_body`]'s pair: a grant with no email or password set yet
/// is legal, it just leaves this person unable to use this particular door
/// until one is set, through this call or a later one. This route only ever
/// *sets* — clearing either field is not yet a shape this body can express,
/// which is a deliberate, narrower first cut rather than an oversight; see
/// this module's own commentary on `NotYetHonoured` for why a promise this
/// deployment cannot yet keep is worse than a gap that is simply absent.
///
/// A field that is *present* and malformed is refused before anything is
/// written: an email [`PersonEmail::parse`] refuses, or a password shorter
/// than [`crate::person_password::MIN_PASSWORD_LENGTH`].
pub fn identity_fields_from_body(body: &[u8]) -> Result<(Option<PersonEmail>, Option<String>), String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not JSON".to_owned())?;
    let document = selfhost_json::parse(text).map_err(|_| "the body is not JSON".to_owned())?;
    let email = match document.get("email") {
        None | Some(Json::Null) => None,
        Some(value) => {
            let text = value.as_str().ok_or_else(|| "\"email\" must be a string".to_owned())?;
            let email = PersonEmail::parse(text)
                .map_err(|error| format!("\"email\" is not usable: {error}"))?;
            Some(email)
        }
    };
    let password = match document.get("password") {
        None | Some(Json::Null) => None,
        Some(value) => {
            let text = value.as_str().ok_or_else(|| "\"password\" must be a string".to_owned())?;
            if text.chars().count() < crate::person_password::MIN_PASSWORD_LENGTH {
                return Err(format!(
                    "a login password must be at least {} characters",
                    crate::person_password::MIN_PASSWORD_LENGTH
                ));
            }
            Some(text.to_owned())
        }
    };
    Ok((email, password))
}

/// Enrols or revokes a roster entry for every `vpn.access:<location>` a grant
/// diff added or removed, and returns one line per location describing what
/// happened.
///
/// The shared side effect behind both doors that can change a person's grants
/// — `PUT /api/people/<name>` and `selfhost people grant/allow/deny` — so a
/// peer provisioned through one is provisioned exactly the same way through
/// the other, and a fix here reaches both without being written twice.
///
/// # Why a missing `peer`/`public_key` is not a refusal
///
/// A `vpn.access:<location>` grant with no roster entry yet is the same kind
/// of "granted before usable" state this deployment already lives with for a
/// missing passkey — worth saying, not worth blocking, since provisioning
/// later (a second call, from either door) is a legitimate order to do things
/// in.
///
/// # Why a missing `peer` on revoke leaves the roster entry alone
///
/// Neither door records which roster name a person's grant was provisioned
/// under — a person may hold several devices, or none — so there is nothing
/// to look up. Revoking without `peer` still revokes the capability; it just
/// cannot also guess which file to remove.
pub fn vpn_side_effects(
    relays: &[selfhost_config::vpn::Relay],
    data_dir: &Path,
    subject: &str,
    before: &Grants,
    after: &Grants,
    peer: Option<&str>,
    public_key: Option<&str>,
) -> Vec<String> {
    let held = |grants: &Grants, location: &VpnLocationId| {
        grants
            .iter()
            .any(|capability| matches!(capability, Capability::VpnAccess(here) if here == location))
    };
    let mut locations: Vec<VpnLocationId> = Vec::new();
    for capability in before.iter().chain(after.iter()) {
        if let Capability::VpnAccess(location) = capability {
            if !locations.contains(location) {
                locations.push(location.clone());
            }
        }
    }

    let mut lines = Vec::new();
    for location in locations {
        let now_held = held(after, &location);
        let previously_held = held(before, &location);
        if now_held == previously_held {
            continue;
        }
        let Some(relay) = relays.iter().find(|relay| relay.name == location.as_str()) else {
            lines.push(format!(
                "vpn.access:{location} names no `[[vpn]]` relay in this config, so no roster \
                 entry was touched"
            ));
            continue;
        };
        let key_dir = selfhost_vpn::keys::key_dir(relay, data_dir);
        if now_held {
            match (peer, public_key) {
                (Some(peer), Some(public_key)) => {
                    match selfhost_vpn::enrol(&key_dir, peer, public_key) {
                        Ok(()) => lines.push(format!(
                            "vpn.access:{location}: enrolled roster entry \"{peer}\", live, no \
                             restart"
                        )),
                        Err(error) => lines.push(format!(
                            "vpn.access:{location}: granted, but the roster entry was NOT \
                             written: {error}"
                        )),
                    }
                }
                _ => lines.push(format!(
                    "vpn.access:{location}: granted, but no roster entry was written — a peer \
                     name and public key are needed (this call or a later one) before {subject} \
                     can actually connect"
                )),
            }
        } else if let Some(peer) = peer {
            match selfhost_vpn::revoke(&key_dir, peer) {
                Ok(()) => lines.push(format!(
                    "vpn.access:{location}: removed roster entry \"{peer}\", live, no restart"
                )),
                Err(error) => lines.push(format!(
                    "vpn.access:{location}: revoked, but roster entry \"{peer}\" was NOT \
                     removed: {error}"
                )),
            }
        } else {
            lines.push(format!(
                "vpn.access:{location}: revoked, but no peer name was given, so no roster entry \
                 was removed"
            ));
        }
    }
    lines
}

/// What `PUT /api/people/<name>` needs to run [`vpn_side_effects`]: the relays
/// this deployment declares, and the data directory their key directories are
/// resolved relative to.
///
/// Held on [`crate::Api`] rather than re-read from configuration per request,
/// on the same grounds as [`crate::site_api::Wiring`] — a daemon's `[[vpn]]`
/// blocks and data directory are fixed for the life of the process, and a test
/// builds this from parts it controls rather than a file on disk.
#[derive(Clone)]
pub struct VpnWiring {
    relays: Vec<selfhost_config::vpn::Relay>,
    data_dir: PathBuf,
}

impl VpnWiring {
    /// `relays` is `config.vpn` as loaded at start-up; `data_dir` is the same
    /// data directory [`crate::Api::with_console_auth`] was given.
    pub fn new(relays: Vec<selfhost_config::vpn::Relay>, data_dir: PathBuf) -> Self {
        Self { relays, data_dir }
    }

    /// Whether `location` names a `[[vpn]]` relay this deployment actually
    /// declares.
    ///
    /// Used ahead of minting a sign-in code: a code for a location with no
    /// relay behind it would only ever produce the same "no roster entry was
    /// touched" note [`vpn_side_effects`] already gives a grant for one, and
    /// refusing it up front gives the desktop app a reason to show
    /// immediately rather than a code that redeems into a no-op.
    pub fn has_relay(&self, location: &str) -> bool {
        self.relays.iter().any(|relay| relay.name == location)
    }

    /// The data directory relay key directories, and the Peer bindings, live
    /// under.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The name of every `[[vpn]]` relay this deployment declares, in
    /// configuration order.
    pub fn relay_names(&self) -> Vec<&str> {
        self.relays.iter().map(|relay| relay.name.as_str()).collect()
    }

    /// Runs [`vpn_side_effects`] against the relays and data directory this
    /// was built with.
    pub fn side_effects(
        &self,
        subject: &str,
        before: &Grants,
        after: &Grants,
        peer: Option<&str>,
        public_key: Option<&str>,
    ) -> Vec<String> {
        vpn_side_effects(&self.relays, &self.data_dir, subject, before, after, peer, public_key)
    }

    /// Every peer this deployment's relays know about, for `GET /api/vpn/peers`.
    ///
    /// A static entry comes straight from `[[vpn.peers]]` — reviewed and
    /// committed like any other access decision, `person` required by the
    /// schema itself. A dynamic entry was enrolled through a relay's roster
    /// file with no config edit and no restart (see [`selfhost_vpn::enrol`]'s
    /// module documentation for why that file exists at all); its `person`
    /// comes from [`crate::peer_binding::owner_of`], the one record of who a
    /// roster name belongs to, and is `null` for a name nothing has bound yet.
    /// A roster name that also appears in `[[vpn.peers]]` is reported only
    /// once, as the static entry — the config already speaks for it.
    pub fn peers_json(&self) -> Json {
        let mut peers = Vec::new();
        for relay in &self.relays {
            for peer in &relay.peers {
                peers.push(Json::object([
                    ("relay".to_owned(), Json::string(relay.name.as_str())),
                    ("name".to_owned(), Json::string(peer.name.as_str())),
                    ("person".to_owned(), Json::string(peer.person.as_str())),
                    ("static".to_owned(), Json::Bool(true)),
                    (
                        "forwardPort".to_owned(),
                        peer.forward_port.map_or(Json::Null, |port| Json::Number(port as f64)),
                    ),
                ]));
            }

            let key_dir = selfhost_vpn::keys::key_dir(relay, &self.data_dir);
            let dynamic_names = selfhost_vpn::enrol::roster(&key_dir).unwrap_or_default();
            for name in &dynamic_names {
                if relay.peers.iter().any(|peer| &peer.name == name) {
                    continue;
                }
                let person = crate::peer_binding::owner_of(&self.data_dir, name);
                peers.push(Json::object([
                    ("relay".to_owned(), Json::string(relay.name.as_str())),
                    ("name".to_owned(), Json::string(name.as_str())),
                    ("person".to_owned(), person.map_or(Json::Null, Json::string)),
                    ("static".to_owned(), Json::Bool(false)),
                    ("forwardPort".to_owned(), Json::Null),
                ]));
            }
        }
        Json::array(peers)
    }
}

/// One person as the console reads them.
///
/// `warning` carries [`unreachable_without_vpn`]'s answer for the grant set
/// just written, when the caller has one to attach — `None` leaves the object
/// exactly as it was before this field existed, so a reader that does not know
/// about warnings yet sees nothing new. `notes` carries [`vpn_side_effects`]'s
/// report lines the same way — an empty slice leaves the object exactly as it
/// was before this field existed. `has_password` answers whether the
/// email-and-password door has anything to check for this person, since the
/// registry itself does not hold that credential — see
/// [`crate::person_password::PersonPasswords`].
pub fn person_json(person: &Person, warning: Option<String>, notes: &[String], has_password: bool) -> Json {
    let mut fields = vec![
        ("name".to_owned(), Json::string(person.name.as_str())),
        ("added_unix".to_owned(), Json::Number(person.added_unix as f64)),
        ("grants".to_owned(), grants_json(&person.grants)),
        (
            "email".to_owned(),
            person.email.as_ref().map_or(Json::Null, |email| Json::string(email.as_str())),
        ),
        ("has_password".to_owned(), Json::Bool(has_password)),
    ];
    if let Some(reason) = warning {
        fields.push(("warning".to_owned(), Json::string(reason)));
    }
    if !notes.is_empty() {
        fields.push(("notes".to_owned(), Json::array(notes.iter().map(Json::string))));
    }
    Json::object(fields)
}

/// A grant set as the wire words the console submits back.
///
/// The same spelling [`Capability::parse`] reads, so a set that is fetched,
/// toggled and submitted round-trips exactly.
pub fn grants_json(grants: &Grants) -> Json {
    Json::array(grants.iter().map(|capability| Json::string(wire_word(capability))))
}

/// A grant set as one comma-separated field, for an audit line.
///
/// The same wire words [`grants_json`] renders, joined — so what the trail says
/// somebody was given is spelled identically to what the console shows them
/// holding, and an operator comparing the two is comparing strings rather than
/// interpreting two formats. An empty set is the word `nothing`, because
/// `now:` followed by the end of the field reads as a truncated line.
pub fn spell_grants(grants: &Grants) -> String {
    if grants.is_empty() {
        return "nothing".to_owned();
    }
    grants.iter().map(wire_word).collect::<Vec<_>>().join(",")
}

/// A capability as one string: the word, and its target after a colon.
pub fn wire_word(capability: &Capability) -> String {
    match capability.target() {
        Some(target) => format!("{}:{target}", capability.name()),
        None => capability.name().to_owned(),
    }
}

/// The whole roster, for the owner.
///
/// `password_holders` names everybody the email-and-password door already has
/// a credential for — see [`person_json`]'s `has_password`. Passed in rather
/// than looked up here because [`crate::person_password::PersonPasswords`] is
/// a store this module does not otherwise know about; the caller already read
/// it once to build this list.
pub fn roster_json(people: &People, password_holders: &[PersonName]) -> Json {
    let entries = people.list();
    Json::object([
        (
            "people",
            Json::array(entries.iter().map(|person| {
                let has_password = password_holders.contains(&person.name);
                person_json(person, None, &[], has_password)
            })),
        ),
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
pub fn whoami_json(caller: &Caller, agents: Option<&crate::agent_store::AgentStore>) -> Json {
    let mut fields = vec![
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
    ];

    // If this is an agent, include the person it belongs to by looking up the
    // agent in the store and extracting its person association.
    if let selfhost_identity::Identity::Agent(name) = caller.identity() {
        if let Some(agent_store) = agents {
            for (agent_name, _, _, person) in agent_store.list() {
                if agent_name == *name {
                    fields.push(("person", Json::string(&person)));
                    break;
                }
            }
        }
    }

    Json::object(fields)
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
/// Every capability word, its target if it takes one, and whether any route in
/// this deployment honours it yet.
///
/// The third column exists so a console can render an ungrantable word as
/// exactly that — greyed, with the reason — rather than offering a toggle the
/// `PUT` will refuse. Kept beside the other two rather than derived at runtime
/// because this table is what a client draws from before it has a
/// [`Capability`] to ask, and `honoured_word` below is what stops the two
/// disagreeing.
pub const VOCABULARY: [(&str, Option<&str>, bool); 14] = [
    ("console.read", None, true),
    ("service.control", None, true),
    ("services.admin", None, true),
    ("files.read", Some("share"), true),
    ("files.write", Some("share"), true),
    ("files.admin", None, true),
    ("desktop.view", Some("node"), true),
    ("desktop.control", Some("node"), true),
    ("clipboard.read", Some("node"), true),
    ("node.admin", None, true),
    // `site.admin` gained real routes in `crates/app/admin::site_api`; the other
    // two remain real words with no route. See `Capability::is_honoured`.
    ("site.admin", None, true),
    ("dns.admin", None, false),
    ("mail.admin", None, false),
    ("vpn.access", Some("location"), true),
];

/// [`VOCABULARY`] as JSON.
pub fn vocabulary_json() -> Json {
    Json::array(VOCABULARY.iter().map(|(word, target, honoured)| {
        Json::object([
            ("word", Json::string(*word)),
            ("target", target.map_or(Json::Null, Json::string)),
            // False means the word exists and nothing consumes it: a console
            // should show it and refuse to offer it, so an operator learns why
            // rather than finding the toggle rejected on submit.
            ("grantable", Json::Bool(*honoured)),
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
        for (word, target, grantable) in VOCABULARY {
            let spelling = match target {
                Some("share") => format!("{word}:vault"),
                Some(_) => format!("{word}:alex-desktop"),
                None => word.to_owned(),
            };
            let capability = Capability::parse(&spelling).expect("{spelling} did not parse");
            // The third column is the same fact `Capability::is_honoured`
            // states, not a second opinion about it. Two tables that could
            // disagree is how a console ends up offering a toggle the `PUT`
            // refuses.
            assert_eq!(
                capability.is_honoured(),
                grantable,
                "{word}: the vocabulary and the capability disagree about whether \
                 anything honours it",
            );
        }
    }

    #[test]
    fn a_word_nothing_honours_is_refused_rather_than_stored() {
        // A promise is worse than an absence: the operator reads the row as a
        // delegation, stops doing the job, and the holder finds that nothing
        // happens — with no error anywhere, because no code path is involved.
        // `site.admin` is deliberately absent from this list now: it has a real
        // route behind it (`crates/app/admin::site_api`) and belongs in the
        // round-trip test below instead — this test is only for the words that
        // remain promises.
        for word in ["dns.admin", "mail.admin"] {
            let body = format!(r#"{{"grants":["console.read","{word}"]}}"#);
            let refusal = grants_from_body(body.as_bytes()).unwrap_err();
            assert_eq!(refusal, BadGrants::NotYetHonoured(word.to_owned()));
            // Whole set or none of it, exactly as an unknown word behaves: a
            // set applied minus one entry leaves somebody holding what nobody
            // chose.
            assert!(refusal.message().contains(word));
        }
    }

    #[test]
    fn site_admin_is_a_kept_promise_and_may_be_granted() {
        // The other half of the story above: `site.admin` used to belong in
        // `a_word_nothing_honours_is_refused_rather_than_stored`'s list and now
        // belongs here instead, because `crates/app/admin::site_api` gave it a
        // real route.
        let grants = grants_from_body(br#"{"grants":["site.admin"]}"#).expect("a kept promise grants");
        assert!(grants.holds(&Capability::SiteAdmin));
    }

    #[test]
    fn a_console_capability_with_no_vpn_access_warns() {
        let grants = Grants::new([Capability::ConsoleRead]).unwrap();
        let warning = unreachable_without_vpn(&grants, &["console"]).expect("must warn");
        assert!(warning.contains("vpn.access:console"));
    }

    #[test]
    fn a_console_capability_with_console_vpn_access_is_silent() {
        let grants = Grants::new([
            Capability::ConsoleRead,
            Capability::VpnAccess(VpnLocationId::parse("console").unwrap()),
        ])
        .unwrap();
        assert_eq!(unreachable_without_vpn(&grants, &["console"]), None);
    }

    #[test]
    fn vpn_access_to_a_different_location_still_warns() {
        // `ssh`'s relay does not front the console's HTTP surface, so holding
        // only that grant leaves a console capability exactly as unreachable.
        let grants = Grants::new([
            Capability::ConsoleRead,
            Capability::VpnAccess(VpnLocationId::parse("ssh").unwrap()),
        ])
        .unwrap();
        assert!(unreachable_without_vpn(&grants, &["console"]).is_some());
    }

    #[test]
    fn vpn_access_alone_never_warns() {
        // Nothing here is a console capability, so there is nothing to be
        // unreachable.
        let grants =
            Grants::new([Capability::VpnAccess(VpnLocationId::parse("console").unwrap())])
                .unwrap();
        assert_eq!(unreachable_without_vpn(&grants, &["console"]), None);
    }

    #[test]
    fn a_grant_set_round_trips_through_its_wire_words() {
        // What the console does: fetch, toggle, submit. A spelling that did not
        // round-trip would silently drop a person's capability on every save.
        let original = Grants::new([
            Capability::DesktopControl(NodeName::parse("alex-desktop").unwrap()),
            Capability::FilesWrite(ShareId::parse("vault").unwrap()),
            Capability::NodeAdmin,
        ])
        .unwrap();
        let body = format!(r#"{{"grants":{}}}"#, grants_json(&original).to_text());
        assert_eq!(grants_from_body(body.as_bytes()).unwrap(), original);
    }

    fn console_relay() -> selfhost_config::vpn::Relay {
        selfhost_config::vpn::Relay::new("console", "127.0.0.1:9999", "127.0.0.1:443")
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-admin-people-vpn-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn granting_vpn_access_through_the_api_enrols_a_roster_entry_once_the_grant_is_saved() {
        let data_dir = scratch_dir("wiring-enrol");
        let wiring = VpnWiring::new(vec![console_relay()], data_dir.clone());
        let location = VpnLocationId::parse("console").unwrap();
        let after = Grants::new([Capability::VpnAccess(location)]).unwrap();
        let key = "gjD2KgdBYIQo0WmUvud9pnNFdNmtBcMbh5QLnTLBKW4=";
        let lines =
            wiring.side_effects("dad", &Grants::none(), &after, Some("dad-phone"), Some(key));
        assert!(lines.iter().any(|line| line.contains("enrolled roster entry \"dad-phone\"")));
    }

    #[test]
    fn revoking_vpn_access_through_the_api_removes_the_roster_entry() {
        let data_dir = scratch_dir("wiring-revoke");
        let wiring = VpnWiring::new(vec![console_relay()], data_dir.clone());
        let location = VpnLocationId::parse("console").unwrap();
        let before = Grants::new([Capability::VpnAccess(location)]).unwrap();
        let key = "gjD2KgdBYIQo0WmUvud9pnNFdNmtBcMbh5QLnTLBKW4=";
        wiring.side_effects("dad", &Grants::none(), &before, Some("dad-phone"), Some(key));
        let lines =
            wiring.side_effects("dad", &before, &Grants::none(), Some("dad-phone"), None);
        assert!(lines.iter().any(|line| line.contains("removed roster entry \"dad-phone\"")));
    }

    #[test]
    fn a_put_body_with_no_peer_or_public_key_provisions_nothing_but_is_not_refused() {
        assert_eq!(vpn_fields_from_body(br#"{"grants":[]}"#).unwrap(), (None, None));
    }

    #[test]
    fn a_put_body_may_carry_peer_and_public_key_beside_the_grant_set() {
        let body = br#"{"grants":[],"peer":"dad-phone","public_key":"gjD2KgdBYIQo0WmUvud9pnNFdNmtBcMbh5QLnTLBKW4="}"#;
        let (peer, public_key) = vpn_fields_from_body(body).unwrap();
        assert_eq!(peer.as_deref(), Some("dad-phone"));
        assert_eq!(public_key.as_deref(), Some("gjD2KgdBYIQo0WmUvud9pnNFdNmtBcMbh5QLnTLBKW4="));
    }

    #[test]
    fn a_malformed_peer_or_public_key_is_refused_before_anything_is_written() {
        // The same shape check a `[[vpn.peers]]` config entry and the CLI's own
        // `--peer`/`--pubkey` flags are held to — a typo caught here rather than
        // written and discovered at the next handshake.
        assert!(vpn_fields_from_body(br#"{"grants":[],"peer":"Not Valid!"}"#).is_err());
        assert!(vpn_fields_from_body(br#"{"grants":[],"public_key":"not-base64-32-bytes"}"#).is_err());
    }

    #[test]
    fn a_put_body_with_no_email_or_password_sets_neither() {
        // Absent, same as `vpn_fields_from_body`'s pair: a grant change with no
        // identity fields is legal and leaves this person's login door alone.
        assert_eq!(identity_fields_from_body(br#"{"grants":[]}"#).unwrap(), (None, None));
        assert_eq!(
            identity_fields_from_body(br#"{"grants":[],"email":null,"password":null}"#).unwrap(),
            (None, None)
        );
    }

    #[test]
    fn a_put_body_may_carry_email_and_password_beside_the_grant_set() {
        let body = br#"{"grants":[],"email":"Mom@Example.com","password":"correct horse battery"}"#;
        let (email, password) = identity_fields_from_body(body).unwrap();
        // Lower-cased on the way in, the same normalisation `PersonEmail::parse`
        // gives every other caller, so two spellings of one address can never
        // both be "the" email on file.
        assert_eq!(email.unwrap().as_str(), "mom@example.com");
        assert_eq!(password.as_deref(), Some("correct horse battery"));
    }

    #[test]
    fn a_malformed_email_is_refused_before_anything_is_written() {
        let refusal = identity_fields_from_body(br#"{"grants":[],"email":"not-an-email"}"#).unwrap_err();
        assert!(refusal.contains("email"), "{refusal}");
    }

    #[test]
    fn a_password_shorter_than_the_minimum_is_refused() {
        let refusal = identity_fields_from_body(br#"{"grants":[],"password":"short"}"#).unwrap_err();
        assert!(
            refusal.contains(&crate::person_password::MIN_PASSWORD_LENGTH.to_string()),
            "{refusal}"
        );
    }

    #[test]
    fn a_password_at_exactly_the_minimum_length_is_accepted() {
        let password = "x".repeat(crate::person_password::MIN_PASSWORD_LENGTH);
        let body = format!(r#"{{"grants":[],"password":"{password}"}}"#);
        let (_, parsed_password) = identity_fields_from_body(body.as_bytes()).unwrap();
        assert_eq!(parsed_password.as_deref(), Some(password.as_str()));
    }

    #[test]
    fn a_non_string_email_or_password_is_refused_rather_than_silently_dropped() {
        assert!(identity_fields_from_body(br#"{"grants":[],"email":7}"#).is_err());
        assert!(identity_fields_from_body(br#"{"grants":[],"password":7}"#).is_err());
    }
}
