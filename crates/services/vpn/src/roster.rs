//! The peer set a relay will actually admit, and the two truths it reconciles.
//!
//! `crates/foundation/config/src/vpn.rs` checks a roster entry for what an
//! operator can fix by reading their own file: a non-empty person, no whitespace
//! padding, not `"owner"`, a key of the right shape. It deliberately stops there,
//! because *what a legal person's name is* belongs to `identity::PersonName` and
//! restating it in the config crate would be a second opinion that could drift
//! from the first. This module is where the two meet.
//!
//! # Why an unnameable peer is dropped rather than passed through
//!
//! A roster entry whose `person` is not a legal [`PersonName`] cannot be looked up
//! in the people registry, so nothing above the tunnel could ever decide what that
//! peer may do. Admitting it anyway would put a key on the network whose holder
//! the audit record cannot name — which is precisely the state
//! `docs/labs/vpn-identity-lab.dx` found and this subsystem exists to end. So such
//! an entry lands in [`Roster::rejected`], is **not** handed to the tunnel as a
//! `--peer`, and is reported by name: the peer loses access loudly rather than
//! keeping it anonymously.
//!
//! # The registry check that has to live here
//!
//! `docs/labs/vpn-lab.dx` names this as an open question: `person` is not checked
//! against the people registry at load, because the registry is a data file the
//! daemon owns and `config` cannot read it. [`Roster::unregistered`] is that
//! check, run where both inputs exist. It **reports** rather than refuses, and
//! that direction is deliberate — a person removed from the registry should not
//! silently take the console's only door down with them, and a peer whose person
//! holds no grants is already refused everything by `Policy::decide`. What the
//! deployment must not do is fail to notice, so the names come back to be shown.

use selfhost_config::vpn::{Backend, Relay};
use selfhost_identity::{People, PersonName};
use selfhost_json::Json;
use std::net::SocketAddr;

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
    /// The peer's public key, base64, exactly as the config spells it.
    pub public_key: String,
    /// The loopback socket **this peer alone** lands on, when the roster gave it
    /// one.
    ///
    /// `None` when the peer shares the relay's `forward` with everyone else who
    /// has no port of its own — which is not the same as "unknown". A peer here
    /// is a peer nothing downstream can name, and saying so is the whole point
    /// of the field being an `Option` rather than a socket that is always
    /// filled in with the shared one.
    pub forward: Option<SocketAddr>,
}

/// A roster entry that will not be admitted, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// The roster key that was refused.
    pub peer: String,
    /// What `identity` said was wrong with the person's name, phrased for the
    /// operator who has to edit the block.
    pub reason: String,
}

/// One relay's usable peer set.
///
/// Built purely from a [`Relay`], so every rule in it is exercised without a
/// config file, a supervisor or a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    relay: String,
    backend: Backend,
    enrolled: Vec<Enrolled>,
    rejected: Vec<Rejected>,
}

impl Roster {
    /// Reads a relay's roster, separating the entries that name a person from
    /// the entries that do not.
    ///
    /// Total: it never fails, because a relay with an unusable entry is still a
    /// relay with usable ones and the caller has to be able to see both. Whether
    /// what is left is enough to start is [`Roster::is_startable`]'s question.
    pub fn build(relay: &Relay) -> Self {
        let mut enrolled = Vec::new();
        let mut rejected = Vec::new();

        for peer in &relay.peers {
            match PersonName::parse(&peer.person) {
                Ok(person) => enrolled.push(Enrolled {
                    peer: peer.name.clone(),
                    person,
                    public_key: peer.public_key.clone(),
                    // Deliberately the peer's *own* socket or nothing. Falling
                    // back to the relay's shared forward here would hand every
                    // caller a socket that looks like an identity and is not.
                    forward: peer.forward_port.and_then(|_| relay.forward_for(peer)),
                }),
                Err(why) => rejected.push(Rejected {
                    peer: peer.name.clone(),
                    reason: format!("person \"{}\" is not a name this deployment can look up: {why}", peer.person),
                }),
            }
        }

        Self { relay: relay.name.clone(), backend: relay.backend, enrolled, rejected }
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

    /// Whether any enrolled peer can be named from the socket it lands on.
    ///
    /// The fact everything above the tunnel reasons about, answered from the
    /// roster rather than from the transport: with one backend left, what
    /// decides attribution is whether an operator has given anybody a
    /// `forward_port`, not which program holds the socket.
    pub fn attributes(&self) -> bool {
        self.enrolled.iter().any(|entry| entry.forward.is_some())
    }

    /// The enrolled entry whose own loopback socket this is.
    ///
    /// Never matches a peer that shares the relay's `forward`: those have no
    /// socket of their own, and answering with one of them would be inventing an
    /// identity out of a socket several people use.
    pub fn enrolled_at(&self, landed: SocketAddr) -> Option<&Enrolled> {
        self.enrolled.iter().find(|entry| entry.forward == Some(landed))
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

    /// Whether this relay has anybody to admit.
    ///
    /// The same rule the loader applies to an enabled relay with an empty
    /// `peers` list, applied one step later: a relay whose every entry was
    /// rejected is also a bound port that can admit nobody, and it is an inbound
    /// surface with no purpose whichever way it got that way.
    pub fn is_startable(&self) -> bool {
        !self.enrolled.is_empty()
    }

    /// Everyone this roster names, deduplicated, in roster order.
    ///
    /// A person with a laptop and a phone holds two keys and appears once here —
    /// that is the model working, and it is why this is not simply a map over
    /// [`Roster::enrolled`].
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
    ///
    /// The drift check `docs/labs/vpn-lab.dx` says has to run here, because this
    /// is the one place both truths exist. Reported, never enforced: see the
    /// module documentation for why refusing would be the worse failure.
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
            ("attributable", Json::Bool(self.attributes())),
            (
                "peers",
                Json::array(self.enrolled.iter().map(|entry| {
                    Json::object([
                        ("peer", Json::string(&entry.peer)),
                        ("person", Json::string(entry.person.as_str())),
                        (
                            "forward",
                            entry
                                .forward
                                .map(|socket| Json::string(socket.to_string()))
                                .unwrap_or(Json::Null),
                        ),
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
    use crate::tests::{attributing_relay, forwarding_relay};
    use selfhost_config::vpn::Peer;

    #[test]
    fn a_well_formed_roster_enrols_every_peer_and_rejects_none() {
        let roster = Roster::build(&forwarding_relay());
        assert_eq!(roster.enrolled().len(), 1);
        assert!(roster.rejected().is_empty());
        assert!(roster.is_startable());
        assert_eq!(roster.enrolled()[0].person.as_str(), "Alex");
        assert_eq!(
            roster.enrolled()[0].forward, None,
            "a peer sharing the relay's forward has no socket of its own"
        );
        assert!(!roster.attributes());
    }

    #[test]
    fn a_peer_with_its_own_port_carries_the_socket_it_alone_lands_on() {
        let roster = Roster::build(&attributing_relay());
        let socket = "127.0.0.1:9443".parse().unwrap();
        assert_eq!(roster.enrolled()[0].forward, Some(socket));
        assert!(roster.attributes());
        assert_eq!(roster.enrolled_at(socket).map(|e| e.person.as_str()), Some("Alex"));
        // The relay's shared forward is not anybody's own socket, and asking
        // about it must not walk into the roster and pick somebody.
        assert!(roster.enrolled_at("127.0.0.1:443".parse().unwrap()).is_none());
    }

    #[test]
    fn a_person_the_permission_model_cannot_look_up_is_dropped_and_named() {
        // `config` accepts all of these; `identity::PersonName` does not. Each
        // one would otherwise be a key on the network whose holder no audit
        // record could name.
        for person in ["Alex/Bob", "-Alex", "Alex-", "Alex  Bob", "machine"] {
            let mut relay = forwarding_relay();
            relay.peers[0].person = person.into();
            let roster = Roster::build(&relay);

            assert!(roster.enrolled().is_empty(), "{person:?} was enrolled");
            assert!(!roster.is_startable(), "{person:?}");
            assert_eq!(roster.rejected().len(), 1, "{person:?}");
            assert_eq!(roster.rejected()[0].peer, "alex-mac", "{person:?}");
            assert!(
                roster.rejected()[0].reason.contains(person),
                "the refusal must quote the name that has to be fixed: {:?}",
                roster.rejected()[0].reason
            );
        }
    }

    #[test]
    fn one_bad_entry_does_not_take_the_good_ones_with_it() {
        // The failure this prevents: a typo in one person's name locking every
        // other peer out of the console, which is the only door.
        let mut relay = forwarding_relay();
        relay.peers.push(Peer::new("dad-mac", "Dad!", "B".repeat(43)));
        relay.peers.push(Peer::new("mum-mac", "Mum", "C".repeat(43)));

        let roster = Roster::build(&relay);
        assert_eq!(roster.enrolled().len(), 2);
        assert_eq!(roster.rejected().len(), 1);
        assert!(roster.is_startable());
        assert!(roster.enrolled_peer("dad-mac").is_none());
        assert!(roster.rejection("dad-mac").is_some());
    }

    #[test]
    fn a_person_with_two_devices_is_listed_once() {
        let mut relay = forwarding_relay();
        relay.peers.push(Peer::new("alex-phone", "Alex", "B".repeat(43)));
        let roster = Roster::build(&relay);
        assert_eq!(roster.enrolled().len(), 2);
        assert_eq!(roster.people().len(), 1, "two keys, one holder");
    }

    #[test]
    fn a_roster_naming_nobody_in_the_registry_reports_it_rather_than_refusing() {
        let directory = std::env::temp_dir()
            .join(format!("selfhost-vpn-registry-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        let people = People::load(&directory);

        let roster = Roster::build(&forwarding_relay());
        assert_eq!(
            roster.unregistered(&people).iter().map(PersonName::as_str).collect::<Vec<_>>(),
            vec!["Alex"],
            "an empty registry means every peer's person is unknown"
        );
        // And the relay is still startable: a registry that has lost an entry
        // must not take the deployment's only door down with it.
        assert!(roster.is_startable());

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_rejected_peer_is_visible_on_the_wire_rather_than_silently_absent() {
        let mut relay = forwarding_relay();
        relay.peers[0].person = "Alex/Bob".into();
        let text = Roster::build(&relay).to_json().to_text();
        assert!(text.contains(r#""rejected""#), "{text}");
        assert!(text.contains("alex-mac"), "{text}");
        assert!(text.contains(r#""attributable":false"#), "{text}");
    }

    #[test]
    fn the_wire_carries_the_socket_that_names_a_peer_and_null_when_none_does() {
        let text = Roster::build(&attributing_relay()).to_json().to_text();
        assert!(text.contains(r#""forward":"127.0.0.1:9443""#), "{text}");
        assert!(text.contains(r#""attributable":true"#), "{text}");

        let shared = Roster::build(&forwarding_relay()).to_json().to_text();
        assert!(shared.contains(r#""forward":null"#), "{shared}");
    }
}
