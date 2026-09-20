//! The peer set a relay will actually admit, read from enrolment state.
//!
//! A Peer exists only because a signed-in account enrolled it. Three files say
//! so, and this module is where they meet: `<key_dir>/roster` lists the name,
//! `<key_dir>/<peer>.pub` pins the key, and [`crate::peer_binding`] names the
//! Person. `server.py` reads the first two itself on every handshake; nothing
//! here is handed to it.
//!
//! A listed name with no Person, or no readable key, lands in
//! [`Roster::rejected`] and is reported by name. The role names
//! ([`RESERVED_PEER_NAMES`]) are never a Peer and are never listed.
//!
//! [`Roster::unregistered`] reports a Person the registry no longer holds. It
//! reports rather than refuses: a person with no grants is already refused
//! everything by `Policy::decide`.

use crate::{enrol, keys, peer_binding};
use selfhost_config::vpn::{Backend, RESERVED_PEER_NAMES, Relay};
use selfhost_identity::{People, PersonName};
use selfhost_json::Json;
use std::path::Path;

/// A peer this relay will admit, with its holder named in the permission model's
/// own type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The roster key — what `--identity` carries, and the stem of the peer's
    /// public key file under the relay's key directory.
    pub peer: String,
    /// Who holds it. A [`PersonName`] rather than a `String`, so that holding one
    /// is proof the registry could be asked about it.
    pub person: PersonName,
}

/// A roster entry that names nobody, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// The roster name.
    pub peer: String,
    /// What is wrong with it, phrased for the operator.
    pub reason: String,
}

/// One relay's usable peer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    relay: String,
    backend: Backend,
    enrolled: Vec<Enrolled>,
    rejected: Vec<Rejected>,
}

impl Roster {
    /// Reads a relay's roster as it stands on disk now.
    ///
    /// Total: it never fails, because a relay with an unusable entry is still a
    /// relay with usable ones and the caller has to be able to see both.
    pub fn read(relay: &Relay, key_dir: &Path, data_dir: &Path) -> Self {
        let mut enrolled = Vec::new();
        let mut rejected = Vec::new();

        for peer in enrol::roster(key_dir).unwrap_or_default() {
            if RESERVED_PEER_NAMES.contains(&peer.as_str()) {
                continue;
            }
            match Self::holder(&peer, key_dir, data_dir) {
                Ok(person) => enrolled.push(Enrolled { peer, person }),
                Err(reason) => rejected.push(Rejected { peer, reason }),
            }
        }

        Self { relay: relay.name.clone(), backend: relay.backend, enrolled, rejected }
    }

    /// Who holds `peer`, or why nobody usable does.
    fn holder(peer: &str, key_dir: &Path, data_dir: &Path) -> Result<PersonName, String> {
        let owner = peer_binding::owner_of(data_dir, peer)
            .ok_or("no account enrolled it; sign in on that device, or forget it")?;
        let person = PersonName::parse(&owner).map_err(|why| {
            format!("person \"{owner}\" is not a name this deployment can look up: {why}")
        })?;
        if !keys::peer_key_file(key_dir, peer).is_file() {
            return Err(format!("{peer}.pub is missing; sign in on that device again"));
        }
        Ok(person)
    }

    /// The relay this roster belongs to.
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// Which backend carries this relay. One member today; see
    /// `selfhost_config::vpn::Backend` for why it is still an enum.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Every peer that will be admitted.
    pub fn enrolled(&self) -> &[Enrolled] {
        &self.enrolled
    }

    /// Every peer that will not be, with the reason.
    pub fn rejected(&self) -> &[Rejected] {
        &self.rejected
    }

    /// The enrolled entry with this roster name.
    pub fn enrolled_peer(&self, peer: &str) -> Option<&Enrolled> {
        self.enrolled.iter().find(|entry| entry.peer == peer)
    }

    /// Why this roster name was rejected, if it was.
    pub fn rejection(&self, peer: &str) -> Option<&str> {
        self.rejected.iter().find(|entry| entry.peer == peer).map(|entry| entry.reason.as_str())
    }

    /// Everyone this roster names, deduplicated, in roster order.
    ///
    /// A person with a laptop and a phone holds two keys and appears once here.
    pub fn people(&self) -> Vec<PersonName> {
        let mut people: Vec<PersonName> = Vec::new();
        for entry in &self.enrolled {
            if !people.contains(&entry.person) {
                people.push(entry.person.clone());
            }
        }
        people
    }

    /// The people this roster names who have no entry in the registry.
    /// Reported, never enforced: see the module documentation.
    pub fn unregistered(&self, people: &People) -> Vec<PersonName> {
        self.people().into_iter().filter(|person| people.find(person).is_none()).collect()
    }

    /// The roster as it goes over the wire.
    ///
    /// A rejected entry is sent as well as an enrolled one, and with its reason,
    /// because a console that showed only the peers that work would render a
    /// relay that quietly stopped admitting somebody as a relay in perfect
    /// health.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("relay", Json::string(&self.relay)),
            ("backend", Json::string(self.backend.tag())),
            (
                "peers",
                Json::array(self.enrolled.iter().map(|entry| {
                    Json::object([
                        ("peer", Json::string(&entry.peer)),
                        ("person", Json::string(entry.person.as_str())),
                    ])
                })),
            ),
            (
                "rejected",
                Json::array(self.rejected.iter().map(|entry| {
                    Json::object([
                        ("peer", Json::string(&entry.peer)),
                        ("reason", Json::string(&entry.reason)),
                    ])
                })),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{A_KEY, Scratch};

    #[test]
    fn a_peer_an_account_enrolled_is_admitted_under_that_person() {
        let scratch = Scratch::new("roster-enrolled");
        scratch.enrol("alex-mac", "Alex");
        let roster = scratch.roster();
        assert!(roster.rejected().is_empty());
        assert_eq!(roster.enrolled_peer("alex-mac").map(|e| e.person.as_str()), Some("Alex"));
    }

    #[test]
    fn a_listed_name_no_account_enrolled_is_rejected_and_named() {
        let scratch = Scratch::new("roster-unbound");
        scratch.enrol("alex-mac", "Alex");
        enrol::enrol(&scratch.key_dir(), "stray", A_KEY).unwrap();
        let roster = scratch.roster();
        assert_eq!(roster.enrolled().len(), 1, "one bad entry does not take the good one with it");
        assert!(roster.rejection("stray").is_some());
    }

    #[test]
    fn a_listed_peer_with_no_key_file_is_rejected() {
        let scratch = Scratch::new("roster-keyless");
        scratch.enrol("alex-mac", "Alex");
        std::fs::remove_file(keys::peer_key_file(&scratch.key_dir(), "alex-mac")).unwrap();
        assert!(scratch.roster().rejection("alex-mac").unwrap().contains("alex-mac.pub"));
    }

    #[test]
    fn the_role_names_are_never_listed_even_when_the_roster_file_names_them() {
        let scratch = Scratch::new("roster-roles");
        std::fs::create_dir_all(scratch.key_dir()).unwrap();
        std::fs::write(enrol::roster_file(&scratch.key_dir()), "client\nserver\n").unwrap();
        let roster = scratch.roster();
        assert!(roster.enrolled().is_empty());
        assert!(roster.rejected().is_empty());
    }

    #[test]
    fn a_person_with_two_devices_is_listed_once() {
        let scratch = Scratch::new("roster-two");
        scratch.enrol("alex-mac", "Alex");
        scratch.enrol("alex-phone", "Alex");
        let roster = scratch.roster();
        assert_eq!(roster.enrolled().len(), 2);
        assert_eq!(roster.people().len(), 1, "two keys, one holder");
    }

    #[test]
    fn a_roster_naming_nobody_in_the_registry_reports_it_rather_than_refusing() {
        let scratch = Scratch::new("roster-registry");
        scratch.enrol("alex-mac", "Alex");
        let people = People::load(scratch.data_dir());
        let roster = scratch.roster();
        assert_eq!(
            roster.unregistered(&people).iter().map(PersonName::as_str).collect::<Vec<_>>(),
            vec!["Alex"],
        );
        assert_eq!(roster.enrolled().len(), 1);
    }

    #[test]
    fn a_rejected_peer_is_visible_on_the_wire_rather_than_silently_absent() {
        let scratch = Scratch::new("roster-wire");
        enrol::enrol(&scratch.key_dir(), "stray", A_KEY).unwrap();
        let text = scratch.roster().to_json().to_text();
        assert!(text.contains(r#""rejected""#), "{text}");
        assert!(text.contains("stray"), "{text}");
    }
}
