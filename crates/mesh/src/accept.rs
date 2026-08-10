//! The owner side of a link: admitting a worker that dialled in.
//!
//! The owner's admin API answers the upgrade on `/api/mesh/link`; this module
//! takes it from the `101` onward. Read the link-control `OPEN` on channel 0,
//! look the node up in the registry, verify its proof constant-time against that
//! node's token, admit the handshake through the replay ledger, mark the peer
//! linked, and hand back a live link.
//!
//! Nothing here binds a socket, and nothing here can. The stream arrives already
//! upgraded, from a route the daemon already serves on loopback: the owner opens
//! no port for the mesh, which is the same property [`crate::dial`] preserves
//! from the other end.
//!
//! # The refusals, and why they are all the same refusal
//!
//! Every failure on this path does exactly one thing on the wire: **close with a
//! bare code and nothing else.** No reason string, no `REJECT`, no hint about
//! which check failed.
//!
//! That is not terseness for its own sake. An owner that answered *"unknown
//! node"* to one name and *"bad proof"* to another has published a way to
//! enumerate which machines it knows, to anyone who can reach the console site.
//! The node names are not secret in any formal sense, but they are the operator's
//! own list of their own machines, and handing it out one guess at a time is
//! exactly the sort of small leak that turns into a target list. So the refusals
//! are indistinguishable from outside, and the detail lives in [`Refused`], which
//! goes to the owner's log and nowhere else.
//!
//! The same reasoning drives one further step: an unknown node is verified
//! against a decoy token rather than refused early, so that the *time* an
//! admission takes does not answer the question the close code refuses to. See
//! [`admit`].
//!
//! # The failure counter is per node, and it is not the login gate
//!
//! Failures are recorded in [`crate::registry`], per node. They must never reach
//! `crates/admin`'s `FailureGate`: that gate locks the console's login door after
//! five failures in a minute, which is right for a password guess and catastrophic
//! for a worker whose token is stale — the operator would be locked out of their
//! own console by their own laptop, and the more the laptop retried the longer it
//! would last.
//!
//! # Why the accept value is computed here rather than passed in
//!
//! The enrolment proof is bound to the handshake's `Sec-WebSocket-Key` *and* the
//! `Sec-WebSocket-Accept` derived from it. Only the key is a parameter; the
//! accept value is recomputed from it with the same function the route used to
//! answer. A caller that passed both could pass a mismatched pair, and the
//! failure would be a credential that binds to nothing while still verifying.

use crate::channel::{ChannelId, Open, Role};
use crate::enroll::{Admission, Binding, NodeToken, NonceLedger};
use crate::link::{Hello, HelloError, LINK_CONTROL_SERVICE, Link, LinkControl, LinkHandle};
use crate::mux::{self, FrameError, Kind, VERSION};
use crate::registry::{DropReason, NodeName, SharedRegistry};
use selfhost_ws::{CloseCode, Duplex, Event, Limits, StreamError};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};

/// How long a dialler has to present its greeting after the upgrade.
///
/// A connection that completes a handshake and then says nothing costs the owner
/// a task and a buffer for as long as it likes. Ten seconds is generous for a
/// greeting the worker has already computed before it connected.
pub const GREETING_TIMEOUT: Duration = Duration::from_secs(10);

/// The close code every refusal uses.
///
/// One code for every reason; see the module documentation. `1008 Policy
/// Violation` is the honest one — the peer's message was understood and was not
/// permitted — and using a single code is what keeps the refusal from being an
/// oracle.
pub const REFUSAL_CODE: CloseCode = CloseCode::PolicyViolation;

/// How long a refused connection is held open for the closing handshake.
///
/// See [`linger`]. Long enough for a peer on a slow tunnel to answer, short
/// enough that this cannot be turned into a way to accumulate tasks on the
/// owner.
pub const REFUSAL_LINGER: Duration = Duration::from_secs(2);

/// Where the owner keeps each enrolled node's secret.
///
/// A trait rather than a map, because the daemon reads these from files written
/// by `selfhost node invite` and a test should not need a filesystem to assert
/// that a stale token is refused. The only question it answers is *what is this
/// node's token* — deciding whether the node may link at all is the registry's
/// job, and keeping the two separate is what stops a store from quietly becoming
/// a second, divergent list of who is enrolled.
pub trait TokenStore {
    /// This node's enrolment secret, if it has one.
    fn token(&self, node: &NodeName) -> Option<NodeToken>;
}

/// An in-memory [`TokenStore`].
///
/// For tests, and for a daemon that has already read its tokens off disk and
/// would rather not touch the filesystem on every dial — which matters more than
/// it sounds, because a dial is the one operation an unauthenticated caller can
/// provoke.
#[derive(Debug, Clone, Default)]
pub struct MemoryTokens {
    tokens: BTreeMap<String, NodeToken>,
}

impl MemoryTokens {
    /// An empty store: no node can link.
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding these nodes' tokens.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (NodeName, NodeToken)>) -> Self {
        Self {
            tokens: pairs.into_iter().map(|(name, token)| (name.as_str().to_owned(), token)).collect(),
        }
    }

    /// Adds or replaces one node's token, returning the one it displaced.
    pub fn insert(&mut self, node: &NodeName, token: NodeToken) -> Option<NodeToken> {
        self.tokens.insert(node.as_str().to_owned(), token)
    }

    /// Forgets a node's token, so it can no longer link.
    pub fn remove(&mut self, node: &NodeName) -> Option<NodeToken> {
        self.tokens.remove(node.as_str())
    }

    /// How many nodes have a token here.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether no node has a token here.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl TokenStore for MemoryTokens {
    fn token(&self, node: &NodeName) -> Option<NodeToken> {
        self.tokens.get(node.as_str()).cloned()
    }
}

/// A worker that has proved who it is, and the link to it.
///
/// The three link halves arrive together for the reason [`crate::dial::Session`]
/// gives: run the driver, write through the handle, read control traffic from
/// the control queue.
pub struct Admitted<S> {
    /// Which machine this is. Proved, not claimed.
    pub node: NodeName,
    /// The driver. Run it, usually on a task of its own.
    pub link: Link<S>,
    /// The writer and channel-claiming half.
    pub handle: LinkHandle,
    /// Channel 0, and frames for channels nobody holds.
    pub control: LinkControl,
}

impl<S> fmt::Debug for Admitted<S> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Admitted").field("node", &self.node).finish()
    }
}

/// Admits a dialler, or refuses it.
///
/// `handshake_key` is the `Sec-WebSocket-Key` from the request the route just
/// answered; the accept value the proof is also bound to is recomputed here from
/// it. `io` is the stream after the `101`.
///
/// On success the peer is marked linked in `registry` and a live [`Link`] comes
/// back. On failure the stream is closed with [`REFUSAL_CODE`] and nothing else,
/// the node's own failure counter is incremented if it is a node this owner has
/// declared, and the reason is returned for the owner's log.
///
/// # The order of the checks, and the decoy
///
/// The registry is asked first, because a name nobody declared is the cheapest
/// possible refusal and because the registry is the authority on who exists.
/// But the answer is not acted on immediately: an unknown or token-less node is
/// verified against a **decoy token** it cannot possibly match, so that every
/// admission performs exactly one HMAC and the refusal for a name the owner has
/// never heard of takes the same work as the refusal for a name it knows.
/// Without that, the close code refuses to say which machines exist and the
/// clock says it anyway.
pub async fn admit<S, T>(
    io: S,
    handshake_key: &str,
    tokens: &T,
    ledger: &Mutex<NonceLedger>,
    registry: &SharedRegistry,
    limits: Limits,
) -> Result<Admitted<S>, Refused>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TokenStore + ?Sized,
{
    let mut duplex = Duplex::server(io, limits);
    match verify(&mut duplex, handshake_key, tokens, ledger, registry).await {
        Ok(node) => {
            let accepted = mux::encode_frame(Kind::Accept, ChannelId::CONTROL, &[])
                .map_err(Refused::Framing)?;
            duplex.send(&accepted).await.map_err(Refused::Stream)?;
            registry.declare_linked(&node, SystemTime::now());
            let (link, handle, control) = Link::new(duplex, Role::Accepter);
            Ok(Admitted { node, link, handle, control })
        }
        Err(refusal) => {
            if let Some(node) = refusal.node() {
                registry.declare_dropped(node, SystemTime::now(), refusal.drop_reason());
            }
            // One code, no prose, on every path. See the module documentation.
            let _closed = duplex.close(REFUSAL_CODE, "").await;
            linger(&mut duplex).await;
            Err(refusal)
        }
    }
}

/// Holds a refused connection open just long enough for the close to land.
///
/// Without this the socket is gone the instant [`admit`] returns, and the peer's
/// answering close — which RFC 6455 asks it to send — fails to write. The worker
/// then reads a transport error where a refusal was sent, and its own console
/// says *"the connection could not be established"* instead of *"the node's
/// enrolment proof was refused"*. Those two sentences send an operator to two
/// completely different places, so the two seconds are worth paying.
///
/// Strictly bounded, because this is the path an unauthenticated caller reaches:
/// a refusal may cost this process a task for [`REFUSAL_LINGER`] and not one
/// moment more.
async fn linger<S>(duplex: &mut Duplex<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _finished = tokio::time::timeout(REFUSAL_LINGER, duplex.recv()).await;
}

/// Reads the greeting and decides whether it proves anything.
///
/// Split from [`admit`] so that the refusal behaviour — one close code, one
/// counter, no prose — is written once at the single place every failure passes
/// through, rather than at each `return`.
async fn verify<S, T>(
    duplex: &mut Duplex<S>,
    handshake_key: &str,
    tokens: &T,
    ledger: &Mutex<NonceLedger>,
    registry: &SharedRegistry,
) -> Result<NodeName, Refused>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TokenStore + ?Sized,
{
    let greeting = read_greeting(duplex).await?;
    if greeting.version != VERSION {
        return Err(Refused::VersionMismatch { node: greeting.node, offered: greeting.version });
    }

    let accept = selfhost_ws::accept_key(handshake_key);
    let binding = Binding::new(handshake_key, &accept, greeting.node.clone())
        .map_err(|_| Refused::BadHandshake)?;

    // Declared *and* holding a token is the condition. The two are asked
    // together so that neither answer can be read off the timing of the other.
    let declared = registry.is_declared(&greeting.node);
    let token = tokens.token(&greeting.node);
    let genuine = token.is_some() && declared;
    let candidate = token.unwrap_or_else(decoy_token);

    // Always exactly one constant-time verification, whatever the answer above.
    let proved = binding.verify(&candidate, &greeting.proof);
    if !(genuine && proved) {
        return Err(if declared {
            Refused::ProofFailed(greeting.node)
        } else {
            Refused::Undeclared(greeting.node)
        });
    }

    let admission = {
        let mut ledger = ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.admit(binding.key(), Instant::now())
    };
    match admission {
        Admission::Fresh => Ok(greeting.node),
        Admission::Replay => Err(Refused::Replay(greeting.node)),
    }
}

/// Reads the link-control `OPEN` that must be the first thing on the link.
///
/// Bounded by [`GREETING_TIMEOUT`], and required to be exactly one mux frame in
/// one WebSocket message. A peer packing several frames into its greeting is
/// speaking before it has been admitted, and there is nothing it could usefully
/// say there.
async fn read_greeting<S>(duplex: &mut Duplex<S>) -> Result<Hello, Refused>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let event = match tokio::time::timeout(GREETING_TIMEOUT, duplex.recv()).await {
        Ok(event) => event.map_err(Refused::Stream)?,
        Err(_) => return Err(Refused::Silent),
    };
    let message = match event {
        Event::Message(message) => message,
        Event::Closed(_) => return Err(Refused::NoGreeting),
    };

    let (frame, rest) = mux::parse_frame(&message).map_err(Refused::Framing)?;
    if !rest.is_empty() {
        return Err(Refused::Framing(FrameError::TooLong { declared: 0 }));
    }
    if !frame.header.channel.is_control() || frame.header.kind != Kind::Open {
        return Err(Refused::NotAGreeting);
    }
    let open = Open::parse(frame.payload).map_err(|_| Refused::NotAGreeting)?;
    if open.service != LINK_CONTROL_SERVICE {
        return Err(Refused::NotAGreeting);
    }
    Hello::parse(open.params).map_err(Refused::BadGreeting)
}

/// A token no proof can match, for the paths where there is no real one.
///
/// Zeroes are fine: the value is never compared to anything a peer knows, it
/// exists only so that the verification runs, and a peer that could somehow
/// produce an HMAC under it would still be refused by the `genuine` flag in
/// [`verify`]. Two conditions, not one, so a mistake in either is not a bypass.
fn decoy_token() -> NodeToken {
    NodeToken::from_bytes([0u8; 32])
}

/// Why a dialler was refused. **For the owner's log, never for the peer.**
///
/// Every variant produces the same bytes on the wire; see the module
/// documentation. If a future change ever makes one of these into a message the
/// peer receives, it has turned this list into an enumeration oracle.
#[derive(Debug)]
pub enum Refused {
    /// The peer said nothing within [`GREETING_TIMEOUT`].
    Silent,
    /// The peer closed the link instead of greeting.
    NoGreeting,
    /// The first frame was not a link-control `OPEN` on channel 0.
    NotAGreeting,
    /// The greeting's parameters were malformed.
    BadGreeting(HelloError),
    /// The first message was not well-framed.
    Framing(FrameError),
    /// The stream failed before anything could be decided.
    Stream(StreamError),
    /// The handshake fields could not be bound to a proof.
    ///
    /// Ours, not theirs: the key came from the route that already validated it.
    BadHandshake,
    /// The node is not declared on this machine, or has no token here.
    Undeclared(NodeName),
    /// The node is declared, and its proof did not verify.
    ProofFailed(NodeName),
    /// The proof was genuine and this handshake has already been honoured.
    Replay(NodeName),
    /// The node speaks a mux version this build does not.
    VersionMismatch {
        /// Which node.
        node: NodeName,
        /// The version it offered.
        offered: u8,
    },
}

impl Refused {
    /// Which node this refusal is about, when the greeting named one.
    ///
    /// `None` for the failures that happen before a name has been read, and —
    /// deliberately — for a name this owner has never declared: the registry
    /// never learns a peer from the wire, so an undeclared name gets no counter
    /// and no row. Letting it create one would make the operator's own list of
    /// their own machines writable by anything that can reach the link route.
    pub fn node(&self) -> Option<&NodeName> {
        match self {
            Self::ProofFailed(node) | Self::Replay(node) | Self::VersionMismatch { node, .. } => {
                Some(node)
            }
            Self::Undeclared(_)
            | Self::Silent
            | Self::NoGreeting
            | Self::NotAGreeting
            | Self::BadGreeting(_)
            | Self::Framing(_)
            | Self::Stream(_)
            | Self::BadHandshake => None,
        }
    }

    /// The reason to record against a declared node.
    pub fn drop_reason(&self) -> DropReason {
        match self {
            Self::ProofFailed(_) | Self::Replay(_) | Self::Undeclared(_) => DropReason::ProofRefused,
            Self::VersionMismatch { offered, .. } => DropReason::VersionMismatch { offered: *offered },
            Self::Silent | Self::NoGreeting => DropReason::Timeout,
            Self::Stream(_) => DropReason::TransportFailed,
            Self::NotAGreeting | Self::BadGreeting(_) | Self::Framing(_) | Self::BadHandshake => {
                DropReason::ProtocolError
            }
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Silent => write!(out, "the dialler sent no greeting within {GREETING_TIMEOUT:?}"),
            Self::NoGreeting => out.write_str("the dialler closed the link without greeting"),
            Self::NotAGreeting => {
                out.write_str("the dialler's first frame was not a link-control open on channel 0")
            }
            Self::BadGreeting(error) => write!(out, "{error}"),
            Self::Framing(error) => write!(out, "{error}"),
            Self::Stream(error) => write!(out, "{error}"),
            Self::BadHandshake => out.write_str("the handshake fields could not be bound to a proof"),
            Self::Undeclared(node) => write!(out, "node {node} is not enrolled on this machine"),
            Self::ProofFailed(node) => write!(out, "node {node} presented a proof that did not verify"),
            Self::Replay(node) => {
                write!(out, "node {node} replayed a handshake that has already been honoured")
            }
            Self::VersionMismatch { node, offered } => {
                write!(out, "node {node} speaks mesh protocol version {offered}, which this build does not")
            }
        }
    }
}

impl std::error::Error for Refused {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dial::{self, Attempts, DialConfig, Session, Target};
    use crate::link::Hello;
    use crate::registry::Registry;
    use std::io;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn node(text: &str) -> NodeName {
        NodeName::parse(text).expect("valid name")
    }

    fn token() -> NodeToken {
        NodeToken::from_bytes([7u8; 32])
    }

    /// An owner with one enrolled machine, ready to admit it.
    struct Owner {
        tokens: MemoryTokens,
        registry: SharedRegistry,
        ledger: Arc<Mutex<NonceLedger>>,
    }

    impl Owner {
        fn new() -> Self {
            let mut registry = Registry::new();
            registry.declare(node("alex-desktop"));
            Self {
                tokens: MemoryTokens::from_pairs([(node("alex-desktop"), token())]),
                registry: SharedRegistry::from_registry(registry),
                ledger: Arc::new(Mutex::new(NonceLedger::new())),
            }
        }

        async fn admit(&self, io: DuplexStream, key: &str) -> Result<Admitted<DuplexStream>, Refused> {
            admit(io, key, &self.tokens, &self.ledger, &self.registry, Limits::default()).await
        }
    }

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const OTHER_KEY: &str = "b3RoZXIgY29ubmVjdGlvbg==";

    /// The greeting a worker sends for `key`, under `token`, naming `name`.
    fn greeting(name: &NodeName, key: &str, secret: &NodeToken) -> Vec<u8> {
        let binding = Binding::new(key, &selfhost_ws::accept_key(key), name.clone()).expect("binding");
        let hello = Hello { node: name.clone(), version: VERSION, proof: binding.prove(secret) };
        let params = hello.encode();
        let payload = Open { service: LINK_CONTROL_SERVICE, params: &params }.encode().expect("open");
        mux::encode_frame(Kind::Open, ChannelId::CONTROL, &payload).expect("frame")
    }

    /// Runs one admission attempt and returns the owner's verdict together with
    /// what the dialler saw.
    async fn attempt(
        owner: &Owner,
        key: &str,
        frame: Vec<u8>,
    ) -> (Result<NodeName, Refused>, Option<selfhost_ws::CloseFrame>) {
        let (worker_io, owner_io) = tokio::io::duplex(64 * 1024);
        let dialler = tokio::spawn(async move {
            let mut peer = Duplex::client(worker_io, Limits::default());
            peer.send(&frame).await.expect("send");
            loop {
                match peer.recv().await {
                    Ok(Event::Message(_)) => {}
                    Ok(Event::Closed(selfhost_ws::Closed::Peer(close))) => return Some(close),
                    Ok(Event::Closed(_)) | Err(_) => return None,
                }
            }
        });

        let verdict = owner.admit(owner_io, key).await;
        let verdict = match verdict {
            Ok(admitted) => {
                let name = admitted.node.clone();
                drop(admitted);
                Ok(name)
            }
            Err(refusal) => Err(refusal),
        };
        let seen = dialler.await.expect("dialler task");
        (verdict, seen)
    }

    #[tokio::test]
    async fn an_enrolled_node_with_a_good_proof_is_admitted_and_marked_linked() {
        let owner = Owner::new();
        let (verdict, _) = attempt(&owner, KEY, greeting(&node("alex-desktop"), KEY, &token())).await;
        assert_eq!(verdict.expect("admitted"), node("alex-desktop"));
        let record = owner.registry.get(&node("alex-desktop")).expect("record");
        assert!(record.is_linked());
        assert_eq!(record.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn a_replayed_proof_is_refused_even_though_it_still_verifies() {
        // The arithmetic cannot tell a replay from the original — that is
        // precisely why the ledger exists.
        let owner = Owner::new();
        let frame = greeting(&node("alex-desktop"), KEY, &token());
        let (first, _) = attempt(&owner, KEY, frame.clone()).await;
        assert!(first.is_ok());

        let (second, seen) = attempt(&owner, KEY, frame).await;
        assert!(matches!(second, Err(Refused::Replay(_))), "{second:?}");
        assert_eq!(seen.expect("a close").code, Some(REFUSAL_CODE));
        assert_eq!(
            owner.registry.get(&node("alex-desktop")).expect("record").consecutive_failures,
            1,
            "the failure is counted against this node and nowhere else"
        );
    }

    #[tokio::test]
    async fn the_same_proof_on_a_different_handshake_does_not_transfer() {
        // Channel binding: a captured greeting is worthless on a connection the
        // attacker actually has, because the key names one handshake.
        let owner = Owner::new();
        let captured = greeting(&node("alex-desktop"), KEY, &token());
        let (verdict, seen) = attempt(&owner, OTHER_KEY, captured).await;
        assert!(matches!(verdict, Err(Refused::ProofFailed(_))), "{verdict:?}");
        assert_eq!(seen.expect("a close").code, Some(REFUSAL_CODE));
    }

    #[tokio::test]
    async fn an_unenrolled_node_and_a_stale_token_are_indistinguishable_from_outside() {
        // The property that keeps the refusal from being a way to enumerate the
        // operator's own machines: the two answers are the same bytes.
        let owner = Owner::new();
        let (unknown, unknown_seen) =
            attempt(&owner, KEY, greeting(&node("somebody-elses-box"), KEY, &token())).await;
        let (stale, stale_seen) = attempt(
            &owner,
            KEY,
            greeting(&node("alex-desktop"), KEY, &NodeToken::from_bytes([9u8; 32])),
        )
        .await;

        assert!(matches!(unknown, Err(Refused::Undeclared(_))), "{unknown:?}");
        assert!(matches!(stale, Err(Refused::ProofFailed(_))), "{stale:?}");
        let unknown_seen = unknown_seen.expect("a close");
        let stale_seen = stale_seen.expect("a close");
        assert_eq!(unknown_seen.code, stale_seen.code);
        assert_eq!(unknown_seen.reason, stale_seen.reason);
        assert!(unknown_seen.reason.is_empty(), "a refusal says nothing at all");
    }

    #[tokio::test]
    async fn an_undeclared_node_writes_nothing_into_the_registry() {
        // The registry never learns a peer from the wire; a refusal must not be
        // a way to insert rows into the operator's list of their own machines.
        let owner = Owner::new();
        let stranger = node("somebody-elses-box");
        let (refused, _) = attempt(&owner, KEY, greeting(&stranger, KEY, &token())).await;
        assert!(matches!(refused, Err(Refused::Undeclared(_))), "{refused:?}");
        assert_eq!(owner.registry.get(&stranger), None);
        assert_eq!(owner.registry.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn a_declared_node_with_no_token_is_refused_like_any_other() {
        let mut registry = Registry::new();
        registry.declare(node("alex-desktop"));
        let owner = Owner {
            tokens: MemoryTokens::new(),
            registry: SharedRegistry::from_registry(registry),
            ledger: Arc::new(Mutex::new(NonceLedger::new())),
        };
        assert!(owner.tokens.is_empty());
        let (verdict, seen) =
            attempt(&owner, KEY, greeting(&node("alex-desktop"), KEY, &token())).await;
        assert!(matches!(verdict, Err(Refused::ProofFailed(_))), "{verdict:?}");
        assert_eq!(seen.expect("a close").code, Some(REFUSAL_CODE));
    }

    #[tokio::test]
    async fn a_future_protocol_version_is_named_rather_than_misread() {
        let owner = Owner::new();
        let name = node("alex-desktop");
        let binding =
            Binding::new(KEY, &selfhost_ws::accept_key(KEY), name.clone()).expect("binding");
        let hello = Hello { node: name.clone(), version: 9, proof: binding.prove(&token()) };
        let params = hello.encode();
        let payload = Open { service: LINK_CONTROL_SERVICE, params: &params }.encode().expect("open");
        let frame = mux::encode_frame(Kind::Open, ChannelId::CONTROL, &payload).expect("frame");

        let (verdict, _) = attempt(&owner, KEY, frame).await;
        assert!(matches!(verdict, Err(Refused::VersionMismatch { offered: 9, .. })), "{verdict:?}");
        assert_eq!(
            owner.registry.get(&name).expect("record").describe(),
            DropReason::VersionMismatch { offered: 9 }.to_string()
        );
    }

    #[tokio::test]
    async fn something_that_is_not_a_greeting_is_refused_without_a_hint() {
        let owner = Owner::new();
        for frame in [
            mux::encode_frame(Kind::Data, ChannelId::CONTROL, b"hello?").expect("frame"),
            mux::encode_frame(Kind::Open, ChannelId::new(2), b"\x00{}").expect("frame"),
            mux::encode_frame(Kind::Open, ChannelId::CONTROL, b"\x09{}").expect("frame"),
            mux::encode_frame(Kind::Open, ChannelId::CONTROL, b"\x00not json").expect("frame"),
        ] {
            let (verdict, seen) = attempt(&owner, KEY, frame).await;
            assert!(verdict.is_err(), "{verdict:?}");
            let close = seen.expect("a close");
            assert_eq!(close.code, Some(REFUSAL_CODE));
            assert!(close.reason.is_empty());
        }
    }

    #[tokio::test]
    async fn a_dialler_that_says_nothing_is_let_go_rather_than_held() {
        let owner = Owner::new();
        let (worker_io, owner_io) = tokio::io::duplex(64 * 1024);
        tokio::time::pause();
        let admitting = tokio::spawn({
            let tokens = owner.tokens.clone();
            let registry = owner.registry.clone();
            let ledger = Arc::clone(&owner.ledger);
            async move {
                admit(owner_io, KEY, &tokens, &ledger, &registry, Limits::default())
                    .await
                    .map(|admitted| admitted.node)
            }
        });
        // Hold the connection open and say nothing at all.
        let mut held = Duplex::client(worker_io, Limits::default());
        tokio::time::advance(GREETING_TIMEOUT + Duration::from_secs(1)).await;
        let verdict = admitting.await.expect("task");
        assert!(matches!(verdict, Err(Refused::Silent)), "{verdict:?}");
        let _ = held.close(CloseCode::Normal, "").await;
    }

    #[test]
    fn a_refusal_names_a_node_only_when_the_owner_declared_it() {
        assert_eq!(Refused::ProofFailed(node("a")).node(), Some(&node("a")));
        assert_eq!(Refused::Replay(node("a")).node(), Some(&node("a")));
        assert_eq!(Refused::VersionMismatch { node: node("a"), offered: 2 }.node(), Some(&node("a")));
        assert_eq!(Refused::Undeclared(node("a")).node(), None, "an undeclared name gets no row");
        assert_eq!(Refused::Silent.node(), None);
        assert_eq!(Refused::BadHandshake.node(), None);
    }

    #[test]
    fn every_refusal_maps_to_a_reason_the_console_can_render() {
        assert_eq!(Refused::ProofFailed(node("a")).drop_reason(), DropReason::ProofRefused);
        assert_eq!(Refused::Replay(node("a")).drop_reason(), DropReason::ProofRefused);
        assert_eq!(Refused::Silent.drop_reason(), DropReason::Timeout);
        assert_eq!(Refused::NotAGreeting.drop_reason(), DropReason::ProtocolError);
        assert_eq!(
            Refused::VersionMismatch { node: node("a"), offered: 3 }.drop_reason(),
            DropReason::VersionMismatch { offered: 3 }
        );
        assert!(Refused::Undeclared(node("mystery")).to_string().contains("mystery"));
    }

    #[test]
    fn a_token_store_holds_and_forgets() {
        let mut tokens = MemoryTokens::new();
        assert!(tokens.is_empty());
        assert_eq!(tokens.insert(&node("a"), token()), None);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens.token(&node("a")), Some(token()));
        assert_eq!(tokens.token(&node("b")), None);
        assert!(tokens.remove(&node("a")).is_some());
        assert!(tokens.is_empty());
    }

    /// A connector handing out one end of an in-memory pipe, so a dial and an
    /// admission can meet with no socket between them.
    struct PipeConnector {
        owner: Arc<Mutex<Vec<DuplexStream>>>,
    }

    impl dial::Connector for PipeConnector {
        type Stream = DuplexStream;

        async fn connect(&self, _target: &Target) -> io::Result<Self::Stream> {
            let (worker, owner) = tokio::io::duplex(64 * 1024);
            self.owner.lock().unwrap_or_else(PoisonError::into_inner).push(owner);
            Ok(worker)
        }
    }

    #[tokio::test]
    async fn a_worker_refused_at_the_proof_backs_off_rather_than_hammering() {
        // The two sides against each other, with the wrong token: the worker
        // learns only that it was refused, and the registry on *its* side says
        // so in words the operator can act on.
        let owner = Owner::new();
        let slot: Arc<Mutex<Vec<DuplexStream>>> = Arc::new(Mutex::new(Vec::new()));
        let connector = PipeConnector { owner: Arc::clone(&slot) };
        let worker_registry = SharedRegistry::new();

        let owner_side = tokio::spawn({
            let tokens = owner.tokens.clone();
            let registry = owner.registry.clone();
            let ledger = Arc::clone(&owner.ledger);
            let slot = Arc::clone(&slot);
            async move {
                let mut refusals = 0u32;
                while refusals < 1 {
                    let Some(end) = slot.lock().unwrap_or_else(PoisonError::into_inner).pop() else {
                        tokio::task::yield_now().await;
                        continue;
                    };
                    let mut end = end;
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match end.read(&mut byte).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let request = selfhost_http::Request::parse(&head).expect("a request").request;
                    let upgrade = selfhost_ws::handshake::validate(&request).expect("a handshake");
                    let response = selfhost_ws::handshake::response_head(&upgrade.accept, None)
                        .expect("a head");
                    end.write_all(&response).await.expect("write");
                    end.flush().await.expect("flush");
                    let verdict =
                        admit(end, &upgrade.key, &tokens, &ledger, &registry, Limits::default())
                            .await;
                    assert!(matches!(verdict, Err(Refused::ProofFailed(_))), "{verdict:?}");
                    refusals += 1;
                }
                refusals
            }
        });

        let config = DialConfig::new(
            Target::parse("wss://owner.example/api/mesh/link").expect("url"),
            node("alex-desktop"),
            NodeToken::from_bytes([9u8; 32]),
        );
        let made = dial::maintain(
            &config,
            &connector,
            &worker_registry,
            Attempts::Limited(1),
            |session: Session<DuplexStream>| async move {
                drop(session);
                DropReason::LocalShutdown
            },
        )
        .await;

        assert_eq!(made, 1);
        assert_eq!(owner_side.await.expect("owner task"), 1);
        assert_eq!(
            worker_registry.get(&node("alex-desktop")).expect("record").describe(),
            DropReason::ProofRefused.to_string(),
            "the worker's own console must say why, not merely that it is down"
        );
    }
}
