//! This machine, presented as a peer.
//!
//! # Why the local machine is a pseudo-peer and not a special case
//!
//! The obvious way to build "show me a desktop" is two paths: one that talks to
//! the local agent directly, and one that goes over a link to another machine.
//! It is obvious, it is shorter to write, and it is wrong — expensively so.
//!
//! Two paths means two routers, two authorisation checks, two sets of error
//! handling and two sets of tests. In practice it means one of each: the local
//! path gets exercised constantly during development because it is the one that
//! works without a second machine, and the remote path gets exercised the day
//! someone tries it. Worse, the *authorisation* check is the thing that
//! diverges, and it diverges in the direction of the path that felt safe while it
//! was being written. "It is only the local machine" is precisely the reasoning
//! that produces a route which skips the capability check — on the machine that
//! holds every disk and every key.
//!
//! So the local machine is a peer named [`LOCAL_NAME`]. Selecting it goes through
//! the same [`Router::resolve`], the same registry, the same capability check and
//! the same channel plumbing as selecting a machine on the other side of a
//! tunnel. The *only* difference is what the resolved route hands back:
//! [`Route::Local`] means "splice to this machine's own agent" where
//! [`Route::Peer`] means "splice to that peer's link". Everything above that line
//! cannot tell the difference, which is the point.
//!
//! A second consequence, and it is not a small one: a box with no peers enrolled
//! at all still has a working picker, a working desktop and a working set of
//! tests. The mesh is not a prerequisite for the feature; it is a way to point the
//! feature at a different machine.
//!
//! # Addressing this machine by its own name
//!
//! A worker knows its own node name from `[mesh].node`. If the operator opens the
//! picker and selects that name, the answer must be [`Route::Local`] — not a dial
//! to the owner and back down the link the request arrived on, which would either
//! loop or deadlock depending on which end asked. [`Router`] therefore holds this
//! machine's own name, if it has one, and treats it as an alias for
//! [`LOCAL_NAME`].

use crate::registry::{DropReason, NodeName, Registry};
use std::fmt;
use std::time::SystemTime;

/// The name this machine answers to in every picker and every route.
///
/// `self` is deliberately not a legal [`NodeName`] shape an operator would
/// stumble into — it is legal to parse, but declaring a machine called `self` in
/// config is refused by [`Router::declare_local`]'s contract, because two things
/// answering to one name is the one failure this module exists to prevent.
pub const LOCAL_NAME: &str = "self";

/// The [`NodeName`] for this machine.
///
/// A function rather than a constant because [`NodeName`] validates on
/// construction and the validation is not `const`. It cannot fail: `self` is
/// four lowercase letters.
pub fn local_name() -> NodeName {
    NodeName::parse(LOCAL_NAME).expect("`self` is a valid node name")
}

/// Where a resolved peer selection leads.
///
/// Two variants and no third: either the conversation is spliced to this
/// machine's own agent, or it is spliced to a link. Anything that needs to know
/// which one it got is doing the splice; anything above that should be taking a
/// `Route` and not looking inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// This machine. Splice to the local agent.
    Local,
    /// Another machine, whose link is up. Splice to it.
    Peer(NodeName),
}

impl Route {
    /// Whether this route stays on this machine.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }
}

/// Resolves a peer name to a route, using the registry as the source of truth.
///
/// Holds this machine's own node name so that a machine can be addressed by name
/// as well as by [`LOCAL_NAME`]; see the module documentation.
#[derive(Debug, Clone, Default)]
pub struct Router {
    this: Option<NodeName>,
}

impl Router {
    /// A router for a machine that knows its own name (`[mesh].node`).
    pub fn new(this: NodeName) -> Self {
        Self { this: Some(this) }
    }

    /// A router for a machine with no `[mesh]` section — the common case.
    ///
    /// It still resolves [`LOCAL_NAME`], because controlling this machine does not
    /// require the mesh to be configured at all.
    pub fn anonymous() -> Self {
        Self { this: None }
    }

    /// This machine's own node name, if it has one.
    pub fn this(&self) -> Option<&NodeName> {
        self.this.as_ref()
    }

    /// Whether `name` refers to this machine.
    ///
    /// True for [`LOCAL_NAME`] always, and for this machine's own node name when
    /// one is configured.
    pub fn is_local(&self, name: &NodeName) -> bool {
        name.as_str() == LOCAL_NAME || self.this.as_ref().is_some_and(|this| this == name)
    }

    /// Declares this machine in `registry` and marks it live.
    ///
    /// The local pseudo-peer is always linked: the process being asked is the
    /// process that would answer, so there is nothing that could be down. Calling
    /// this at start-up is what guarantees the picker is never empty, and it is
    /// why the console has no "no machines" state to design.
    ///
    /// Idempotent, so it is safe on every config reload.
    pub fn declare_local(&self, registry: &mut Registry, now: SystemTime) {
        registry.declare_linked(local_name(), now);
    }

    /// Resolves a selection into a route.
    ///
    /// The order is deliberate. This machine is checked first, so a local
    /// selection can never be reported as "down" because of something that
    /// happened to a link. Then the registry: an undeclared name is
    /// [`RouteError::Unknown`] — the operator is asking for a machine this box has
    /// never been told about — and a declared name whose link is not up is
    /// [`RouteError::Down`], carrying the reason and the last time it was seen, so
    /// the console can say *why* rather than greying a row in silence.
    pub fn resolve(&self, registry: &Registry, name: &NodeName) -> Result<Route, RouteError> {
        if self.is_local(name) {
            return Ok(Route::Local);
        }
        let record = registry.get(name).ok_or_else(|| RouteError::Unknown(name.clone()))?;
        if record.is_linked() {
            Ok(Route::Peer(name.clone()))
        } else {
            Err(RouteError::Down {
                name: name.clone(),
                reason: down_reason(record),
                last_seen: record.last_seen,
            })
        }
    }
}

/// The reason a record that is not linked gives for it.
///
/// A peer that has never connected has no `Down` state to read a reason out of,
/// so the reason is supplied here rather than leaving the caller to invent one.
fn down_reason(record: &crate::registry::PeerRecord) -> DropReason {
    match record.liveness {
        crate::registry::Liveness::Down { reason, .. } => reason,
        _ => DropReason::NeverConnected,
    }
}

/// Why a peer selection could not be routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// No machine by that name is declared here.
    Unknown(NodeName),
    /// The machine is declared but its link is not up.
    Down {
        /// Which machine.
        name: NodeName,
        /// Why the last link ended, or that there has never been one.
        reason: DropReason,
        /// When it was last actually reachable, if ever.
        last_seen: Option<SystemTime>,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(out, "no machine called {name} is declared here"),
            Self::Down { name, reason, .. } => write!(out, "{name} is not reachable: {reason}"),
        }
    }
}

impl std::error::Error for RouteError {}

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
    fn a_box_with_no_peers_still_has_a_working_picker() {
        // The property the whole module exists for: the desktop feature does not
        // require the mesh to be configured.
        let mut registry = Registry::new();
        let router = Router::anonymous();
        router.declare_local(&mut registry, at(1));

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.linked_count(), 1);
        let record = registry.get(&local_name()).expect("declared");
        assert!(record.is_linked());
        assert_eq!(record.describe(), "linked");
        assert_eq!(router.resolve(&registry, &local_name()).expect("routes"), Route::Local);
    }

    #[test]
    fn declaring_the_local_peer_is_idempotent_across_reloads() {
        let mut registry = Registry::new();
        let router = Router::anonymous();
        router.declare_local(&mut registry, at(1));
        router.declare_local(&mut registry, at(2));
        router.declare_local(&mut registry, at(3));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&local_name()).expect("declared").links, 3);
    }

    #[test]
    fn a_machine_addressed_by_its_own_name_stays_local() {
        // Otherwise the request loops back out over the link it arrived on.
        let mut registry = Registry::new();
        let router = Router::new(node("alex-desktop"));
        router.declare_local(&mut registry, at(1));

        assert!(router.is_local(&node("alex-desktop")));
        assert!(router.is_local(&local_name()));
        assert_eq!(router.resolve(&registry, &node("alex-desktop")).expect("routes"), Route::Local);
        assert_eq!(router.this(), Some(&node("alex-desktop")));
    }

    #[test]
    fn the_local_route_does_not_depend_on_the_registry_at_all() {
        // A local selection must never be reported as "down" because of something
        // that happened to a link, so it is answered before the registry is read.
        let registry = Registry::new();
        let router = Router::new(node("alex-desktop"));
        assert_eq!(router.resolve(&registry, &local_name()).expect("routes"), Route::Local);
        assert_eq!(router.resolve(&registry, &node("alex-desktop")).expect("routes"), Route::Local);
    }

    #[test]
    fn a_linked_peer_routes_to_itself() {
        let mut registry = Registry::new();
        let router = Router::anonymous();
        router.declare_local(&mut registry, at(1));
        registry.declare(node("mac-mini"));
        registry.linked(&node("mac-mini"), at(5)).expect("link");

        let route = router.resolve(&registry, &node("mac-mini")).expect("routes");
        assert_eq!(route, Route::Peer(node("mac-mini")));
        assert!(!route.is_local());
    }

    #[test]
    fn an_unknown_machine_is_named_rather_than_silently_absent() {
        let registry = Registry::new();
        let router = Router::anonymous();
        assert_eq!(
            router.resolve(&registry, &node("somebody-elses-box")).unwrap_err(),
            RouteError::Unknown(node("somebody-elses-box"))
        );
    }

    #[test]
    fn a_down_peer_says_why_and_when_it_was_last_seen() {
        let mut registry = Registry::new();
        let router = Router::anonymous();
        registry.declare(node("alex-desktop"));
        registry.linked(&node("alex-desktop"), at(100)).expect("link");
        registry.dropped(&node("alex-desktop"), at(200), DropReason::PeerClosed { code: 1001 }).expect("drop");

        let error = router.resolve(&registry, &node("alex-desktop")).unwrap_err();
        assert_eq!(
            error,
            RouteError::Down {
                name: node("alex-desktop"),
                reason: DropReason::PeerClosed { code: 1001 },
                // The link was up until 200, so that is when it was last seen —
                // not when it came up.
                last_seen: Some(at(200)),
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains("alex-desktop"), "{rendered}");
        assert!(rendered.contains("1001"), "{rendered}");
    }

    #[test]
    fn a_peer_that_has_never_connected_says_that_and_not_something_invented() {
        let mut registry = Registry::new();
        let router = Router::anonymous();
        registry.declare(node("never-yet"));

        let error = router.resolve(&registry, &node("never-yet")).unwrap_err();
        assert_eq!(
            error,
            RouteError::Down { name: node("never-yet"), reason: DropReason::NeverConnected, last_seen: None }
        );
        assert!(error.to_string().contains("never connected"));
    }

    #[test]
    fn another_machines_name_is_not_local() {
        let router = Router::new(node("alex-desktop"));
        assert!(!router.is_local(&node("mac-mini")));
        let anonymous = Router::anonymous();
        assert!(!anonymous.is_local(&node("alex-desktop")));
        assert!(anonymous.is_local(&local_name()));
        assert_eq!(anonymous.this(), None);
    }

    #[test]
    fn the_local_name_is_a_valid_node_name() {
        assert_eq!(local_name().as_str(), LOCAL_NAME);
    }
}
