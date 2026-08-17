//! Turning the socket a session landed on back into the person who holds the
//! key — and saying "nobody", out loud, when the relay cannot.
//!
//! This module is the reason the subsystem exists. `docs/labs/vpn-identity-lab.dx`
//! confirmed on 2026-08-17 that the tunnel already knows which peer connected and
//! throws that away before anything above it can ask, so every peer is identical
//! to the proxy and the only remaining wall is a password that mints ownership.
//! [`who_arrived_at`] is the question that was previously unaskable.
//!
//! # Why the question is about the *destination*, not the source
//!
//! The Secure-VPN server is a stream forwarder: it opens a loopback connection
//! and copies bytes, so a session's *source* address is `127.0.0.1` for every
//! peer alive and cannot be made to be anything else. That is the finding, and no
//! amount of care with source addresses gets around it.
//!
//! What the server *chooses* is where the loopback connection goes.
//! `scripts/securevpn/app/protocol.py` proves which Ed25519 identity completed the
//! handshake before a byte of payload moves — `CLIENT_AUTH` is checked against the
//! roster entry's key — so at the moment the forward is opened, the peer is known
//! exactly. Giving each peer a `forward_port` of its own makes that knowledge
//! survive: the socket the local service accepted on **is** the roster entry.
//! [`who_arrived_at`] therefore takes the connection's **local** address, which is
//! a fact the kernel reports rather than a claim carried in bytes a stranger could
//! have written.
//!
//! # What an answer is worth, stated before anybody acts on one
//!
//! A destination port is **evidence, not authentication**. Any process already
//! executing on this box can connect to a peer's port and be taken for that peer —
//! `docs/SECURITY.md` VPN-02 is explicit that the loopback gate admits everything
//! local, including a co-hosted application with an SSRF. What the port buys over
//! an in-band preamble is narrower and worth having anyway: the identity is known
//! from the accept, before a byte is parsed, so no new parser is fed
//! unauthenticated input inside a process that builds with `panic = "abort"` and
//! also serves 80, 443, mail and the certificate store. A caller that needs proof
//! of *who* must still use a credential that names a person; this names the door.
//!
//! # Why the answer is not an `Option`
//!
//! An `Option<Peer>` would be a lie by omission in the case that matters most. A
//! session that landed on the relay's **shared** `forward` is one of however many
//! peers have no port of their own, and `None` from that socket reads exactly like
//! `None` from a socket no relay forwards to at all — one means "this deployment
//! cannot tell these peers apart" and the other means "this connection did not
//! come through a tunnel", which are opposite conclusions for whoever reads an
//! audit record.
//!
//! So the answer is [`Attribution`], a three-variant enum with no `Default`, no
//! `unwrap_or`, and no conversion into an [`Identity`] that succeeds on anything
//! but [`Attribution::Peer`]. A caller who wants a person has to match, and the
//! variant they would have to match to get one is named for what it is.
//!
//! One thing this module cannot do anything about, restated because an attributed
//! session is easy to over-read: carrying identity into the HTTP layer makes
//! attribution possible, it does not make a shared credential less than root.

use selfhost_config::vpn::Relay;
use selfhost_identity::{Identity, PersonName};
use selfhost_json::Json;
use std::fmt;
use std::net::SocketAddr;

use crate::roster::Roster;

/// A landed session resolved all the way to a person.
///
/// Every field is here because an audit line needs all four: the relay is which
/// door, the peer is which device, the person is who holds it, and the socket is
/// what was actually observed. Dropping the socket would make the record
/// unverifiable against the proxy's own log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attributed {
    /// The relay whose roster answered.
    pub relay: String,
    /// The roster entry — the value `--identity` carries, one per device.
    pub peer: String,
    /// Who holds that device, as the people registry spells it.
    pub person: PersonName,
    /// The loopback socket the session was accepted on, which is the evidence.
    pub landed: SocketAddr,
}

impl Attributed {
    /// This peer's holder as the permission model's own type.
    ///
    /// The one route from a landed socket to an [`Identity`] in this crate, and
    /// it exists only on this struct — which is the point. There is no method
    /// anywhere here that turns a failed attribution into an identity, so a
    /// caller cannot reach the policy layer without having matched the variant
    /// that actually named somebody.
    pub fn identity(&self) -> Identity {
        Identity::Person(self.person.clone())
    }

    /// The attribution as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("relay", Json::string(&self.relay)),
            ("peer", Json::string(&self.peer)),
            ("person", Json::string(self.person.as_str())),
            ("landed", Json::string(self.landed.to_string())),
        ])
    }
}

/// Why a landed socket named nobody.
///
/// A closed set, and each variant is a different thing for an operator to do
/// about it. Collapsing them into one "unknown" is how a deployment that
/// *structurally cannot* attribute a session ends up looking like a deployment
/// that merely has not seen this socket before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unanswered {
    /// No relay is declared at all, so there is nothing to ask.
    NoRelay,
    /// The session landed on a relay's **shared** `forward`.
    ///
    /// **This is the shape a roster takes before anybody has been given a port
    /// of their own**, and it is the finding the audit recorded: every peer
    /// without a `forward_port` exits on the same socket and the proxy sees one
    /// destination for all of them. Nothing downstream may read this as "unknown
    /// person"; it means "this deployment cannot tell these peers apart".
    Shared {
        /// The relays whose shared forward this is, by name.
        relays: Vec<String>,
    },
    /// No relay forwards anything to this socket.
    ///
    /// Worth reacting to rather than shrugging at: a connection that arrived
    /// somewhere no tunnel sends anything did not come through a tunnel.
    NotAForward {
        /// The relays that were asked, by name.
        relays: Vec<String>,
    },
    /// A peer does own this socket, and its roster entry could not be turned
    /// into a person.
    ///
    /// Deliberately not an attribution. The name in the config is not a legal
    /// [`PersonName`], so the permission model could never look it up, and
    /// answering with the raw string would hand a caller something it would then
    /// compare against registry entries and never match.
    PeerCannotBeNamed {
        /// The relay whose roster holds the entry.
        relay: String,
        /// The roster entry that owns the socket.
        peer: String,
        /// What `identity` said was wrong with the name.
        reason: String,
    },
}

impl Unanswered {
    /// The wire discriminant, which is also the console's label source.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoRelay => "no-relay",
            Self::Shared { .. } => "shared",
            Self::NotAForward { .. } => "not-a-forward",
            Self::PeerCannotBeNamed { .. } => "unnameable-peer",
        }
    }
}

impl fmt::Display for Unanswered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRelay => write!(
                formatter,
                "no relay is declared on this deployment, so no socket names anybody"
            ),
            Self::Shared { relays } => write!(
                formatter,
                "this is the shared forward of {}: every peer with no forward_port of its own \
                 lands here, so the socket cannot tell peers apart. This is not \"unknown \
                 person\" — it is \"this deployment cannot tell these peers apart\"; give each \
                 peer a forward_port and see docs/labs/vpn-identity-lab.dx",
                describe(relays, "relay", "relays")
            ),
            Self::NotAForward { relays } => write!(
                formatter,
                "no peer on {} is forwarded to this socket, and it is not any relay's shared \
                 forward either. A connection that arrived where no tunnel sends anything did \
                 not come through one",
                describe(relays, "relay", "relays")
            ),
            Self::PeerCannotBeNamed { relay, peer, reason } => write!(
                formatter,
                "peer \"{peer}\" on relay \"{relay}\" owns this socket, and its person cannot \
                 be named: {reason}. Fix the person on that roster entry — an entry the \
                 permission model cannot look up is a key with nobody behind it"
            ),
        }
    }
}

/// Who was at a landed socket, or why nobody was.
///
/// Three variants and no fourth: somebody, more than one somebody, or nobody
/// with a reason. See the module documentation for why this is not an `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// Exactly one roster peer owns this socket, and it names a person.
    Peer(Attributed),
    /// Two relays name **different** people at this socket.
    ///
    /// Validation refuses two relays claiming one per-peer socket, so a document
    /// that loaded cannot produce this. It is kept because this crate is handed
    /// relays rather than a validated `Config`, and because the alternative to
    /// reporting an ambiguity is picking the first — and "whichever relay was
    /// listed first" is not a fact about who connected.
    Ambiguous {
        /// The socket that was asked about.
        landed: SocketAddr,
        /// Every relay's answer, so the operator can see which blocks overlap.
        claims: Vec<Attributed>,
    },
    /// Nobody, and why.
    Nobody {
        /// The socket that was asked about.
        landed: SocketAddr,
        /// The reason, which is not interchangeable with the other reasons.
        why: Unanswered,
    },
}

impl Attribution {
    /// The person this socket belongs to, or `None`.
    ///
    /// `None` on **both** non-attributing variants on purpose. A caller reaching
    /// for a shortcut gets an `Option` that is honest; a caller that needs to
    /// know *why* has to match, which is the point at which they find out that
    /// "shared" and "not a forward" are different facts.
    pub fn person(&self) -> Option<&PersonName> {
        match self {
            Self::Peer(attributed) => Some(&attributed.person),
            Self::Ambiguous { .. } | Self::Nobody { .. } => None,
        }
    }

    /// Whether this answer named exactly one person.
    pub fn is_attributed(&self) -> bool {
        matches!(self, Self::Peer(_))
    }

    /// The wire discriminant.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Peer(_) => "peer",
            Self::Ambiguous { .. } => "ambiguous",
            Self::Nobody { .. } => "nobody",
        }
    }

    /// The answer as it goes over the wire.
    ///
    /// `attributed` is a boolean at the top of the object rather than something a
    /// console has to infer from which other keys are present, because a
    /// front-end that infers it will one day infer it wrongly and render a
    /// refusal as a name.
    pub fn to_json(&self) -> Json {
        let mut fields: Vec<(&str, Json)> = vec![
            ("result", Json::string(self.tag())),
            ("attributed", Json::Bool(self.is_attributed())),
        ];
        match self {
            Self::Peer(attributed) => fields.push(("peer", attributed.to_json())),
            Self::Ambiguous { landed, claims } => {
                fields.push(("landed", Json::string(landed.to_string())));
                fields.push(("claims", Json::array(claims.iter().map(Attributed::to_json))));
                fields.push(("why", Json::string(self.to_string())));
            }
            Self::Nobody { landed, why } => {
                fields.push(("landed", Json::string(landed.to_string())));
                fields.push(("reason", Json::string(why.tag())));
                fields.push(("why", Json::string(why.to_string())));
            }
        }
        Json::object(fields)
    }
}

impl fmt::Display for Attribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(attributed) => write!(
                formatter,
                "{} holds \"{}\" on relay \"{}\"",
                attributed.person, attributed.peer, attributed.relay
            ),
            Self::Ambiguous { landed, claims } => {
                let people: Vec<String> =
                    claims.iter().map(|claim| format!("{} ({})", claim.person, claim.relay)).collect();
                write!(
                    formatter,
                    "{landed} is claimed by more than one person — {} — so this deployment has no \
                     single answer to who connected. Two [[vpn]] blocks forward a peer to one \
                     socket; give one of them a port nothing else uses",
                    people.join(", ")
                )
            }
            Self::Nobody { landed, why } => write!(formatter, "{landed}: {why}"),
        }
    }
}

/// Who arrived at this loopback socket on **one** relay.
///
/// `landed` is the **local** address of the accepted connection — the socket the
/// local service was listening on — and not the address the connection came
/// from. A source address would be `127.0.0.1` for every peer alive, which is the
/// finding this whole subsystem exists to answer.
///
/// The whole "does this socket name anybody" question is delegated to
/// [`Relay::peer_forwarded_to`], which answers `None` for the relay's shared
/// forward rather than guessing. That refusal is the config model's, is tested
/// there, and is not re-implemented here; what this function adds is the roster
/// step from a peer to a [`PersonName`].
pub fn who_arrived_at(relay: &Relay, roster: &Roster, landed: SocketAddr) -> Attribution {
    let Some(peer) = relay.peer_forwarded_to(landed) else {
        let why = if relay.forward_addr() == Some(landed) {
            Unanswered::Shared { relays: vec![relay.name.clone()] }
        } else {
            Unanswered::NotAForward { relays: vec![relay.name.clone()] }
        };
        return Attribution::Nobody { landed, why };
    };

    match roster.enrolled_peer(&peer.name) {
        Some(entry) => Attribution::Peer(Attributed {
            relay: relay.name.clone(),
            peer: entry.peer.clone(),
            person: entry.person.clone(),
            landed,
        }),
        // The socket belongs to a roster entry whose person is not a name the
        // permission model can look up. Answering with the raw string would hand
        // the caller something that matches no registry entry, so this refuses
        // and says which entry to fix.
        None => Attribution::Nobody {
            landed,
            why: Unanswered::PeerCannotBeNamed {
                relay: relay.name.clone(),
                peer: peer.name.clone(),
                reason: roster
                    .rejection(&peer.name)
                    .map(str::to_owned)
                    .unwrap_or_else(|| "not in this relay's usable roster".to_owned()),
            },
        },
    }
}

/// Folds one answer per relay into the deployment's single answer.
///
/// Pure and separate from the thing that holds the relays, so the interesting
/// cases — two relays naming two people, one relay sharing while another
/// attributes — are tested without a supervisor or a config file.
///
/// The precedence is not arbitrary. A named person wins, because a relay that
/// *can* answer has answered. Two different people is an ambiguity that is
/// reported rather than resolved. Failing that, the most specific refusal is
/// carried: an entry that cannot be named is a bug in the operator's file and
/// beats "this is a shared forward", which in turn beats "no relay forwards
/// here", because a reader learns more from the first than from the last.
pub fn combine(landed: SocketAddr, answers: Vec<Attribution>) -> Attribution {
    if answers.is_empty() {
        return Attribution::Nobody { landed, why: Unanswered::NoRelay };
    }

    let mut named: Vec<Attributed> = Vec::new();
    let mut unnameable: Option<Unanswered> = None;
    let mut shared: Vec<String> = Vec::new();
    let mut not_a_forward: Vec<String> = Vec::new();

    for answer in answers {
        match answer {
            Attribution::Peer(attributed) => named.push(attributed),
            // A relay cannot itself produce an ambiguity — `peer_forwarded_to`
            // finds at most one entry — so this arm only ever sees an
            // already-folded answer, which is flattened rather than nested.
            Attribution::Ambiguous { claims, .. } => named.extend(claims),
            Attribution::Nobody { why, .. } => match why {
                Unanswered::PeerCannotBeNamed { .. } => unnameable = Some(why),
                Unanswered::Shared { relays } => shared.extend(relays),
                Unanswered::NotAForward { relays } => not_a_forward.extend(relays),
                Unanswered::NoRelay => {}
            },
        }
    }

    // Two roster entries naming the *same* person is not an ambiguity — a person
    // may legitimately appear on two relays, and both answers agree about who
    // connected.
    let distinct: Vec<&Attributed> = {
        let mut seen: Vec<&PersonName> = Vec::new();
        named
            .iter()
            .filter(|claim| {
                let fresh = !seen.contains(&&claim.person);
                if fresh {
                    seen.push(&claim.person);
                }
                fresh
            })
            .collect()
    };

    match distinct.len() {
        0 => {}
        1 => return Attribution::Peer(named[0].clone()),
        _ => return Attribution::Ambiguous { landed, claims: named },
    }

    if let Some(why) = unnameable {
        return Attribution::Nobody { landed, why };
    }
    if !shared.is_empty() {
        return Attribution::Nobody { landed, why: Unanswered::Shared { relays: shared } };
    }
    if !not_a_forward.is_empty() {
        return Attribution::Nobody {
            landed,
            why: Unanswered::NotAForward { relays: not_a_forward },
        };
    }
    Attribution::Nobody { landed, why: Unanswered::NoRelay }
}

/// "relay \"a\"" or "relays \"a\", \"b\"", so a message reads as a sentence
/// whether one relay was asked or four.
fn describe(relays: &[String], singular: &str, plural: &str) -> String {
    let quoted: Vec<String> = relays.iter().map(|name| format!("\"{name}\"")).collect();
    let word = if relays.len() == 1 { singular } else { plural };
    format!("{word} {}", quoted.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{attributing_relay, forwarding_relay};

    fn socket(text: &str) -> SocketAddr {
        text.parse().expect("a literal socket in a test")
    }

    #[test]
    fn a_peers_own_socket_names_the_person_holding_the_key() {
        let relay = attributing_relay();
        let roster = Roster::build(&relay);
        let answer = who_arrived_at(&relay, &roster, socket("127.0.0.1:9443"));

        let Attribution::Peer(attributed) = &answer else {
            panic!("expected an attribution, got {answer}");
        };
        assert_eq!(attributed.person.as_str(), "Alex");
        assert_eq!(attributed.peer, "alex-mac");
        assert_eq!(attributed.relay, "console");
        assert_eq!(attributed.landed, socket("127.0.0.1:9443"));
        assert_eq!(attributed.identity(), Identity::Person(attributed.person.clone()));
        assert!(answer.is_attributed());
    }

    #[test]
    fn a_shared_forward_refuses_to_attribute_anything() {
        // The whole point of the subsystem, asserted rather than described. The
        // deployed relay forwards every peer to 127.0.0.1:443, so if any socket
        // were going to be wrongly attributed it would be this one.
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);

        let answer = who_arrived_at(&relay, &roster, socket("127.0.0.1:443"));
        assert!(!answer.is_attributed(), "{answer}");
        assert_eq!(answer.person(), None);
        match answer {
            Attribution::Nobody { why: Unanswered::Shared { .. }, .. } => {}
            other => panic!("expected a shared-forward refusal, got {other:?}"),
        }

        // And a relay that *does* attribute somebody still refuses its own
        // shared socket, which is where everybody without a port lands.
        let mut mixed = attributing_relay();
        mixed.peers.push(selfhost_config::vpn::Peer::new("dad-mac", "Dad", "B".repeat(43)));
        let roster = Roster::build(&mixed);
        assert!(matches!(
            who_arrived_at(&mixed, &roster, socket("127.0.0.1:443")),
            Attribution::Nobody { why: Unanswered::Shared { .. }, .. }
        ));
    }

    #[test]
    fn a_shared_refusal_says_it_is_structural_rather_than_unknown() {
        // The failure this wording prevents: an operator reading "unknown" and
        // concluding a stranger connected, when the truth is that this
        // deployment cannot tell those peers apart.
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let text = who_arrived_at(&relay, &roster, socket("127.0.0.1:443")).to_string();
        assert!(text.contains("cannot tell peers apart"), "{text}");
        assert!(text.contains("vpn-identity-lab"), "{text}");
        assert!(text.contains("forward_port"), "the refusal must say what to write: {text}");
    }

    #[test]
    fn a_socket_no_relay_forwards_to_is_a_different_answer_from_a_shared_one() {
        let relay = attributing_relay();
        let roster = Roster::build(&relay);
        for elsewhere in ["127.0.0.1:9444", "[::1]:9443", "192.168.1.8:9443"] {
            let answer = who_arrived_at(&relay, &roster, socket(elsewhere));
            match &answer {
                Attribution::Nobody { why: Unanswered::NotAForward { relays }, .. } => {
                    assert_eq!(relays, &["console".to_owned()], "{elsewhere}");
                }
                other => panic!("{elsewhere}: expected a not-a-forward refusal, got {other:?}"),
            }
        }
        assert_ne!(
            who_arrived_at(&relay, &roster, socket("127.0.0.1:9444")).tag_reason(),
            who_arrived_at(&relay, &roster, socket("127.0.0.1:443")).tag_reason(),
            "the two refusals must not be interchangeable"
        );
    }

    #[test]
    fn a_peer_whose_person_is_not_a_legal_name_is_not_attributed() {
        // `config` accepts this person (non-empty, not "owner", short enough);
        // `identity::PersonName` does not. Answering with the raw string would
        // give the policy layer a key it can never look up.
        let mut relay = attributing_relay();
        relay.peers[0].person = "Alex//Bob".into();
        let roster = Roster::build(&relay);

        let answer = who_arrived_at(&relay, &roster, socket("127.0.0.1:9443"));
        assert!(!answer.is_attributed(), "{answer}");
        match &answer {
            Attribution::Nobody { why: Unanswered::PeerCannotBeNamed { peer, .. }, .. } => {
                assert_eq!(peer, "alex-mac");
            }
            other => panic!("expected an unnameable-peer refusal, got {other:?}"),
        }
        assert!(answer.to_string().contains("alex-mac"), "{answer}");
    }

    #[test]
    fn no_relay_at_all_is_its_own_answer() {
        let answer = combine(socket("127.0.0.1:9443"), Vec::new());
        assert!(matches!(answer, Attribution::Nobody { why: Unanswered::NoRelay, .. }));
    }

    #[test]
    fn one_relay_answering_wins_over_every_other_relays_silence() {
        let attributing = attributing_relay();
        let forwarding = forwarding_relay();
        let landed = socket("127.0.0.1:9443");
        let answer = combine(
            landed,
            vec![
                who_arrived_at(&forwarding, &Roster::build(&forwarding), landed),
                who_arrived_at(&attributing, &Roster::build(&attributing), landed),
            ],
        );
        assert_eq!(answer.person().map(PersonName::as_str), Some("Alex"));
    }

    #[test]
    fn two_relays_naming_two_people_is_reported_rather_than_resolved() {
        // Validation refuses this document; this crate is handed relays rather
        // than a validated Config, so it still has to answer honestly.
        let first = attributing_relay();
        let mut second = attributing_relay();
        second.name = "private".into();
        second.peers[0].person = "Dad".into();
        second.peers[0].name = "dad-mac".into();

        let landed = socket("127.0.0.1:9443");
        let answer = combine(
            landed,
            vec![
                who_arrived_at(&first, &Roster::build(&first), landed),
                who_arrived_at(&second, &Roster::build(&second), landed),
            ],
        );
        match &answer {
            Attribution::Ambiguous { claims, .. } => assert_eq!(claims.len(), 2),
            other => panic!("expected an ambiguity, got {other:?}"),
        }
        assert_eq!(answer.person(), None, "an ambiguous answer names nobody");
        assert!(answer.to_string().contains("one socket"), "{answer}");
    }

    #[test]
    fn one_person_on_two_relays_is_the_model_working_not_an_ambiguity() {
        // A laptop that reaches two services is exactly what several relays are
        // for; both answers agree about who connected.
        let first = attributing_relay();
        let mut second = attributing_relay();
        second.name = "private".into();

        let landed = socket("127.0.0.1:9443");
        let answer = combine(
            landed,
            vec![
                who_arrived_at(&first, &Roster::build(&first), landed),
                who_arrived_at(&second, &Roster::build(&second), landed),
            ],
        );
        assert_eq!(answer.person().map(PersonName::as_str), Some("Alex"));
    }

    #[test]
    fn a_refusal_never_carries_an_identity_over_the_wire() {
        let relay = forwarding_relay();
        let text =
            who_arrived_at(&relay, &Roster::build(&relay), socket("127.0.0.1:443")).to_json().to_text();
        assert!(text.contains(r#""attributed":false"#), "{text}");
        assert!(!text.contains("Alex"), "a refusal must not name anybody: {text}");
        assert!(text.contains(r#""reason":"shared""#), "{text}");
    }

    #[test]
    fn an_attribution_carries_all_four_facts_over_the_wire() {
        let relay = attributing_relay();
        let text = who_arrived_at(&relay, &Roster::build(&relay), socket("127.0.0.1:9443"))
            .to_json()
            .to_text();
        for expected in [
            r#""attributed":true"#,
            r#""person":"Alex""#,
            r#""peer":"alex-mac""#,
            r#""relay":"console""#,
            r#""landed":"127.0.0.1:9443""#,
        ] {
            assert!(text.contains(expected), "{expected} missing from {text}");
        }
    }

    impl Attribution {
        /// The reason discriminant, for tests that assert two refusals are not
        /// the same refusal.
        fn tag_reason(&self) -> &'static str {
            match self {
                Self::Nobody { why, .. } => why.tag(),
                other => other.tag(),
            }
        }
    }
}
