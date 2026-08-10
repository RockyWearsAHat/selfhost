//! A live link: one WebSocket, many channels, and the demultiplexer between them.
//!
//! [`crate::dial`] establishes a link, [`crate::accept`] admits one, and
//! [`crate::splice`] joins two of them. All three need the same thing in the
//! middle: something that owns the WebSocket, turns each message back into the
//! mux frames it carries, and hands each frame to whoever is holding that
//! channel. That is this module, and it is the only place in the crate where a
//! frame and a socket are in scope at the same time.
//!
//! # What it deliberately does not do
//!
//! **It does not interpret payloads, and it does not do credit accounting.**
//!
//! Those two refusals are the same refusal. The owner's daemon runs the
//! supervisor, the authoritative DNS server, the firewall manager, the mail
//! server and the self-updater in one process with `panic = "abort"`, and it
//! relays desktop traffic for machines it does not control. Every byte it reads
//! from a peer is therefore a byte an attacker may have chosen. So the link
//! reads exactly eight of them — the header — and moves the rest without
//! looking. A `DATA` payload is a `Vec<u8>` here and nothing else; the meaning
//! is the agent's business, in a process the daemon spawns and can watch die.
//!
//! Credit is the same argument from the other end. A relay that keeps its own
//! send and receive windows is a relay that must *decide* when to grant, and a
//! middle box that grants credit it cannot honour becomes the queue — which is
//! exactly the unbounded memory commitment [`crate::credit`] exists to prevent.
//! So `CREDIT` frames cross a link like any other: forwarded, never authored.
//! The accounting in [`crate::credit`] runs at the two *ends* of a channel, in
//! the agent and in the browser, where somebody is actually consuming bytes.
//!
//! # The shape: one driver, many handles
//!
//! [`Link::run`] is a future that owns the stream and must be driven — usually
//! by a task of its own. Everything else talks to the link through
//! [`LinkHandle`], which is cheap to clone, and reads from it through a
//! [`ChannelInbox`] obtained by [`LinkHandle::attach`]. That is the same
//! single-owner shape `selfhost_ws::Duplex` uses, for the same reason: the
//! socket has one owner, and everyone else has a queue.
//!
//! Inboxes are **bounded** ([`CHANNEL_INBOX`]) and so is the control queue.
//! A full inbox stops the link's reader, which is real backpressure and also
//! real head-of-line blocking: one stalled channel holds up the others. That is
//! a deliberate trade. Credit is what keeps a well-behaved channel from ever
//! filling its inbox, and a channel that fills it anyway is one whose consumer
//! has stopped — a case where stopping the link is better than growing a queue
//! on the machine that holds every disk and every key.

use crate::channel::{Allocator, ChannelError, ChannelId, Role};
use crate::enroll::{EnrollError, Proof};
use crate::mux::{self, Frame, FrameError, Header, Kind};
use crate::registry::{DropReason, NameError, NodeName};
use selfhost_json::Json;
use selfhost_ws::{Closed, Duplex, Event, StreamError};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// The service id of the link-control conversation on channel 0.
///
/// Named rather than written as `0` at three call sites, because the enrolment
/// `OPEN` a worker sends and the `OPEN` an owner expects have to agree about it
/// and there is no negotiation that would catch a disagreement.
pub const LINK_CONTROL_SERVICE: u8 = 0;

/// The first thing a worker says on a link, and the only thing said before it
/// is trusted.
///
/// It rides the parameters of an `OPEN` for [`LINK_CONTROL_SERVICE`] on channel
/// 0, immediately after the WebSocket handshake. Encoding and decoding live
/// together here — not one in [`crate::dial`] and one in [`crate::accept`] —
/// because the two ends have no way to negotiate this and no way to discover a
/// disagreement except as an enrolment that mysteriously never verifies.
///
/// The proof travels as hex rather than raw bytes because `OPEN` parameters are
/// compact ASCII JSON by construction: [`crate::channel::Open`] refuses anything
/// that is not printable ASCII, which is what keeps a malformed `OPEN` from
/// travelling further into the system as bytes nobody has looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Which machine claims to be dialling.
    pub node: NodeName,
    /// The mux protocol version it speaks.
    pub version: u8,
    /// The handshake-bound proof it offers. See [`crate::enroll`].
    pub proof: Proof,
}

impl Hello {
    /// The `OPEN` parameter bytes for this greeting.
    pub fn encode(&self) -> Vec<u8> {
        Json::object([
            ("node", Json::string(self.node.as_str())),
            ("version", Json::Number(f64::from(self.version))),
            ("proof", Json::string(self.proof.to_hex())),
        ])
        .to_text()
        .into_bytes()
    }

    /// Reads a greeting from `OPEN` parameter bytes.
    ///
    /// Every field is refused rather than defaulted. A missing version would
    /// otherwise be read as version 1 by a build that has moved on, and a
    /// missing node name would be read as the empty string — which is a name no
    /// registry declares, so the failure would surface as an unenrolled node
    /// rather than as the malformed greeting it is.
    pub fn parse(params: &[u8]) -> Result<Self, HelloError> {
        let text = std::str::from_utf8(params).map_err(|_| HelloError::NotUtf8)?;
        let json = selfhost_json::parse(text).map_err(|_| HelloError::NotJson)?;
        let node = json.get("node").and_then(Json::as_str).ok_or(HelloError::MissingField("node"))?;
        let node = NodeName::parse(node).map_err(HelloError::BadNode)?;
        let version = json
            .get("version")
            .and_then(Json::as_u64)
            .and_then(|version| u8::try_from(version).ok())
            .ok_or(HelloError::MissingField("version"))?;
        let proof = json.get("proof").and_then(Json::as_str).ok_or(HelloError::MissingField("proof"))?;
        let proof = Proof::from_hex(proof).map_err(HelloError::BadProof)?;
        Ok(Self { node, version, proof })
    }
}

/// Why a link greeting could not be read.
///
/// Carried for the owner's own log line and never for the peer: every refusal on
/// the admission path closes with the same bare code, so that an unenrolled node
/// and a node with a stale token are indistinguishable from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// The parameters were not valid UTF-8.
    NotUtf8,
    /// The parameters were not valid JSON.
    NotJson,
    /// A required field was absent or the wrong type.
    MissingField(&'static str),
    /// The node name was not a legal one.
    BadNode(NameError),
    /// The proof was not the right number of hex characters.
    BadProof(EnrollError),
}

impl fmt::Display for HelloError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => out.write_str("link greeting parameters are not UTF-8"),
            Self::NotJson => out.write_str("link greeting parameters are not JSON"),
            Self::MissingField(field) => write!(out, "link greeting has no usable {field} field"),
            Self::BadNode(error) => write!(out, "link greeting names an unusable node: {error}"),
            Self::BadProof(error) => write!(out, "link greeting carries an unusable proof: {error}"),
        }
    }
}

impl std::error::Error for HelloError {}

/// How many frames may wait in one channel's inbox.
///
/// Small on purpose; see the module documentation. Four frames is enough that a
/// consumer which takes a moment to write a frame to disk does not stall the
/// whole link on every frame, and small enough that sixty-four open channels
/// commit a bounded and unremarkable amount of memory.
pub const CHANNEL_INBOX: usize = 4;

/// How many frames may wait on the link's control queue.
///
/// The control channel carries opens, closes and liveness probes — a trickle. A
/// peer that floods it is refused by the ceilings in [`crate::channel`], not by
/// this number.
pub const CONTROL_INBOX: usize = 16;

/// One frame, owning its payload.
///
/// [`Frame`](crate::mux::Frame) borrows, which is right for the parser and wrong
/// for a queue: a frame handed to another task outlives the buffer it was parsed
/// from. The payload is copied exactly once, here, on the way into the inbox.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    /// The frame's header, as it arrived.
    pub header: Header,
    /// Exactly `header.length` bytes, copied out of the read buffer.
    pub payload: Vec<u8>,
}

impl OwnedFrame {
    /// Copies a borrowed frame so it can outlive the buffer it was parsed from.
    pub fn from_frame(frame: Frame<'_>) -> Self {
        Self { header: frame.header, payload: frame.payload.to_vec() }
    }

    /// The channel this frame belongs to.
    pub fn channel(&self) -> ChannelId {
        self.header.channel
    }

    /// What the frame is for.
    pub fn kind(&self) -> Kind {
        self.header.kind
    }
}

impl fmt::Debug for OwnedFrame {
    /// Prints the header and the payload's *size*, never its contents.
    ///
    /// The same rule [`Frame`](crate::mux::Frame) follows, and for the same
    /// reason: a payload can be a megabyte of somebody's screen or the password
    /// they just typed into it, and a derived `Debug` puts that into the first
    /// log line anybody adds while debugging the router.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("OwnedFrame")
            .field("kind", &self.header.kind.name())
            .field("channel", &self.header.channel.get())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Where a link's reader delivers each frame.
///
/// A plain map behind a lock rather than a command channel into the reader: the
/// reader holds it for the length of a lookup and never across an `await`, and
/// attaching a channel from another task is then a lock and an insert instead of
/// a round trip through a queue the reader also has to poll.
#[derive(Debug, Default)]
struct Routes {
    table: Mutex<BTreeMap<u16, mpsc::Sender<OwnedFrame>>>,
}

impl Routes {
    /// Claims `channel`, or reports that something already holds it.
    fn insert(&self, channel: ChannelId, sink: mpsc::Sender<OwnedFrame>) -> Result<(), LinkError> {
        let mut table = self.lock();
        if table.contains_key(&channel.get()) {
            return Err(LinkError::ChannelBusy(channel));
        }
        table.insert(channel.get(), sink);
        Ok(())
    }

    /// Releases `channel`, so its id stops being routed.
    fn remove(&self, channel: ChannelId) {
        self.lock().remove(&channel.get());
    }

    /// The sink for `channel`, cloned so the lock is released before any send.
    fn sink(&self, channel: ChannelId) -> Option<mpsc::Sender<OwnedFrame>> {
        self.lock().get(&channel.get()).cloned()
    }

    /// Drops every sink, so every inbox on this link reports the link's end.
    ///
    /// Called when the [`Link`] itself is dropped, which is the *only* way an
    /// inbox can learn that its link has gone: the sinks live here, and a
    /// [`LinkHandle`] keeps this table alive for as long as anybody holds one.
    /// Without this, a link whose socket died would leave every consumer waiting
    /// on a channel nothing will ever arrive on — which is exactly the "it just
    /// hangs" failure a remote desktop must not have.
    fn close_all(&self) {
        self.lock().clear();
    }

    /// The routing table, treating a poisoned lock as usable.
    ///
    /// A panic elsewhere in the process is not a reason to make every link stop
    /// routing: the map is a plain container with no invariant a partial update
    /// could have broken, and under `panic = "abort"` in release there is no
    /// poisoning to observe in the first place.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u16, mpsc::Sender<OwnedFrame>>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The driver half of a link: it owns the socket and must be run.
///
/// Created by [`crate::dial::connect`] or [`crate::accept::admit`], never
/// directly, because a `Link` that has not exchanged an enrolment proof is a
/// link to nobody in particular. Run it — `tokio::spawn(link.run())` — and use
/// the [`LinkHandle`] it came with for everything else.
pub struct Link<S> {
    duplex: Duplex<S>,
    routes: Arc<Routes>,
    control: mpsc::Sender<OwnedFrame>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Link<S> {
    /// Wraps an upgraded, authenticated stream as a link.
    ///
    /// Returns the three halves together because they are useless apart: the
    /// driver to run, the handle to send and attach with, and the control queue
    /// carrying channel 0 and anything addressed to a channel nobody holds.
    ///
    /// `role` decides which half of the channel-id space this side allocates
    /// from — the dialler takes odd ids and the accepter even ones — so it must
    /// be the role this side actually played. Getting it wrong does not fail
    /// here; it fails as [`crate::channel::ChannelError::WrongParity`] at the
    /// peer, which is why both constructors in this crate set it themselves.
    pub fn new(duplex: Duplex<S>, role: Role) -> (Self, LinkHandle, LinkControl) {
        let routes = Arc::new(Routes::default());
        let (control_tx, control_rx) = mpsc::channel(CONTROL_INBOX);
        let handle = LinkHandle {
            out: duplex.sender(),
            routes: Arc::clone(&routes),
            role,
            allocator: Arc::new(Mutex::new(Allocator::new(role))),
        };
        let link = Self { duplex, routes, control: control_tx };
        (link, handle, LinkControl { frames: control_rx })
    }

    /// Runs the link until it ends, and reports why.
    ///
    /// The reason is a [`DropReason`] rather than an error because every way a
    /// link can end is a fact the operator is entitled to read in the console —
    /// including the ordinary ones. "It is not connected" is a useless thing to
    /// find at two in the morning; "the peer closed the link (code 1001)" is
    /// something to act on.
    pub async fn run(mut self) -> DropReason {
        loop {
            match self.duplex.recv().await {
                Ok(Event::Message(message)) => {
                    if let Some(reason) = self.deliver(&message).await {
                        return reason;
                    }
                }
                Ok(Event::Closed(closed)) => return reason_for(&closed),
                Err(StreamError::Protocol(_)) => return DropReason::ProtocolError,
                Err(StreamError::Io(_)) => return DropReason::TransportFailed,
            }
        }
    }

    /// Splits one WebSocket message into frames and routes each of them.
    ///
    /// Returns `Some` when the link must end. A message that does not divide
    /// exactly into whole frames is [`DropReason::ProtocolError`]: a trailing
    /// partial frame cannot be completed by the next message, because the next
    /// message starts at its own frame boundary, so continuing would mean
    /// reading a header out of the middle of somebody's payload.
    async fn deliver(&mut self, message: &[u8]) -> Option<DropReason> {
        let mut rest = message;
        while !rest.is_empty() {
            let (frame, remainder) = match mux::parse_frame(rest) {
                Ok(parsed) => parsed,
                Err(FrameError::UnsupportedVersion(offered)) => {
                    return Some(DropReason::VersionMismatch { offered });
                }
                Err(_) => return Some(DropReason::ProtocolError),
            };
            rest = remainder;
            self.route(OwnedFrame::from_frame(frame)).await;
        }
        None
    }

    /// Hands one frame to whoever holds its channel.
    ///
    /// A frame for a channel nobody holds goes to the control queue, where the
    /// link's supervisor can answer it — a `DATA` for a channel that has just
    /// closed is normal on a spliced path, and closing the whole link over one
    /// would make every ordinary teardown a fault.
    ///
    /// A sink whose receiver has been dropped is removed and its frame
    /// discarded: the conversation on that channel is over, and its remaining
    /// frames are for nobody. A full control queue drops the frame rather than
    /// stalling the link, because the control queue's reader is this process's
    /// own supervisor and a supervisor that has stopped reading is not a reason
    /// to stop relaying somebody's desktop.
    async fn route(&mut self, frame: OwnedFrame) {
        let channel = frame.channel();
        let Some(sink) = self.routes.sink(channel) else {
            let _ = self.control.try_send(frame);
            return;
        };
        if sink.send(frame).await.is_err() {
            self.routes.remove(channel);
        }
    }
}

impl<S> Drop for Link<S> {
    /// Closes every inbox on this link.
    ///
    /// In `Drop` rather than at the end of [`Link::run`] on purpose: a link most
    /// often ends by having its task cancelled — the daemon shutting down, a
    /// session being torn down, a `select!` losing a race — and a cancelled
    /// future never reaches the end of its body. Everything that was waiting on
    /// a channel of this link must wake up in *all* of those cases, or a
    /// disappearing machine looks to its viewer exactly like a slow one.
    fn drop(&mut self) {
        self.routes.close_all();
    }
}

/// Why a `selfhost_ws` stream ending is the link ending.
///
/// One place, so the console reads the same word for the same event whichever
/// end of the link reported it.
fn reason_for(closed: &Closed) -> DropReason {
    match closed {
        Closed::Peer(frame) => {
            DropReason::PeerClosed { code: frame.code.map_or(0, |code| code.value()) }
        }
        Closed::PongTimeout => DropReason::Timeout,
        Closed::LifetimeReached => DropReason::LocalShutdown,
        Closed::Abrupt => DropReason::TransportFailed,
    }
}

/// A cheap, cloneable way to write to a link and to claim channels on it.
///
/// Holds no lifetime tied to the driver: a handle outliving its link is normal
/// (the link ended, the holder has not noticed yet) and every method reports
/// [`LinkError::Gone`] rather than pretending the write happened.
#[derive(Clone, Debug)]
pub struct LinkHandle {
    out: selfhost_ws::Sender,
    routes: Arc<Routes>,
    role: Role,
    allocator: Arc<Mutex<Allocator>>,
}

impl LinkHandle {
    /// Which end of the link this side is.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Writes one frame as one WebSocket message.
    ///
    /// One frame per message, deliberately. Packing several would save a header
    /// on a busy link and would mean a stalled channel's frames could be stuck
    /// behind another channel's inside a message this side has already
    /// committed to — which is the head-of-line blocking the mux exists to
    /// remove, reintroduced one layer down.
    ///
    /// Waits when the stream's outbound queue is full: that wait *is* the
    /// backpressure from the socket, and a caller that must not wait should
    /// hold a [`crate::credit::LatestOnly`] and decide for itself what to drop.
    pub async fn send_frame(
        &self,
        kind: Kind,
        channel: ChannelId,
        payload: &[u8],
    ) -> Result<(), LinkError> {
        let bytes = mux::encode_frame(kind, channel, payload)?;
        self.out.send(bytes).await.map_err(|_| LinkError::Gone)
    }

    /// Claims `channel`, so its frames arrive on the returned inbox.
    ///
    /// Refuses a channel something already holds rather than replacing it: a
    /// second holder would silently take delivery of a conversation the first
    /// one is still having, and the failure would look like frames going
    /// missing.
    ///
    /// The claim is released when the inbox is dropped, so a channel's
    /// bookkeeping cannot outlive the code that was reading it.
    pub fn attach(&self, channel: ChannelId) -> Result<ChannelInbox, LinkError> {
        let (sink, frames) = mpsc::channel(CHANNEL_INBOX);
        self.routes.insert(channel, sink)?;
        ChannelInbox::new(channel, frames, Arc::clone(&self.routes))
    }

    /// Allocates the next channel id from this side's half of the space.
    ///
    /// Both ends allocate at once without negotiating because the halves cannot
    /// collide; see [`crate::channel`]. Exhaustion ends the link, and at 32,767
    /// channels that is a link which has been up long enough that re-dialling
    /// costs nothing.
    pub fn allocate(&self) -> Result<ChannelId, LinkError> {
        let mut allocator = self.allocator.lock().unwrap_or_else(PoisonError::into_inner);
        allocator.allocate().map_err(LinkError::Channel)
    }
}

/// One channel's frames, in arrival order.
///
/// Releases its claim on the channel when dropped, which is why it is not
/// `Clone`: two holders of one channel is the failure [`LinkHandle::attach`]
/// refuses, and a clone would be a way around the refusal.
pub struct ChannelInbox {
    channel: ChannelId,
    frames: mpsc::Receiver<OwnedFrame>,
    routes: Arc<Routes>,
}

impl ChannelInbox {
    /// Builds an inbox, refusing the control channel.
    ///
    /// Channel 0 belongs to the link itself and is delivered on
    /// [`LinkControl`]; letting a caller attach to it would give a conversation
    /// the power to intercept the link's own enrolment and liveness traffic.
    fn new(
        channel: ChannelId,
        frames: mpsc::Receiver<OwnedFrame>,
        routes: Arc<Routes>,
    ) -> Result<Self, LinkError> {
        if channel.is_control() {
            routes.remove(channel);
            return Err(LinkError::Channel(ChannelError::ControlReserved));
        }
        Ok(Self { channel, frames, routes })
    }

    /// Which channel this inbox is for.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// The next frame, or `None` once the link has ended.
    ///
    /// Cancel-safe: dropping the future loses nothing, because a frame is only
    /// removed from the queue when it is returned. That is what lets a splice
    /// wait on two inboxes and a shutdown signal in one `select!`.
    pub async fn recv(&mut self) -> Option<OwnedFrame> {
        self.frames.recv().await
    }

    /// The next frame if one is already waiting, without blocking.
    ///
    /// For the pattern a well-behaved channel consumer has to follow: drain what
    /// has arrived before doing anything that might block on *writing* to the
    /// same link. A link's reader stops while an inbox is full, so a task that
    /// blocks on a write to a link it has stopped reading is a task waiting for
    /// itself. Draining first is what keeps that from being possible.
    ///
    /// `None` covers both "nothing waiting" and "the link has ended", which is
    /// right for a caller that is only topping up: the ended case is reported by
    /// the next [`ChannelInbox::recv`], which is where it can be acted on.
    pub fn try_recv(&mut self) -> Option<OwnedFrame> {
        self.frames.try_recv().ok()
    }
}

impl fmt::Debug for ChannelInbox {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ChannelInbox").field("channel", &self.channel.get()).finish()
    }
}

impl Drop for ChannelInbox {
    fn drop(&mut self) {
        self.routes.remove(self.channel);
    }
}

/// The link's own control traffic: channel 0, and frames for channels nobody
/// holds.
///
/// The second half of that is the part worth knowing about. A `DATA` frame
/// arriving for a channel that closed a moment ago is not a fault — on a
/// spliced path, where frames cross a relay hop, late is normal — so it is
/// delivered here for the supervisor to answer with a `CLOSE` rather than
/// treated as a reason to end the link.
#[derive(Debug)]
pub struct LinkControl {
    frames: mpsc::Receiver<OwnedFrame>,
}

impl LinkControl {
    /// The next control frame, or `None` once the link has ended.
    pub async fn recv(&mut self) -> Option<OwnedFrame> {
        self.frames.recv().await
    }
}

/// Why a link operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The link has ended; nothing further will be written on it.
    Gone,
    /// The frame could not be encoded — a payload over the mux ceiling. Ours,
    /// not theirs.
    Frame(FrameError),
    /// Something already holds that channel.
    ChannelBusy(ChannelId),
    /// The channel table refused the operation.
    Channel(ChannelError),
}

impl From<FrameError> for LinkError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone => out.write_str("the link has ended"),
            Self::Frame(error) => write!(out, "the frame could not be encoded: {error}"),
            Self::ChannelBusy(id) => write!(out, "channel {id} is already held on this link"),
            Self::Channel(error) => write!(out, "{error}"),
        }
    }
}

impl std::error::Error for LinkError {}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_ws::Limits;
    use std::time::Duration;

    /// A pair of links over one in-memory pipe: a dialler and an accepter,
    /// speaking real WebSocket frames to each other with no socket in sight.
    ///
    /// Returned as the two halves each side needs, which is every test's first
    /// three lines otherwise.
    struct Pair {
        dialler: LinkHandle,
        accepter: LinkHandle,
        /// Held rather than read by most tests: dropping it would close the
        /// dialler's control queue, and a link whose control queue is gone
        /// discards the frames this crate's supervisor would answer.
        #[allow(dead_code, reason = "held to keep the dialler's control queue open")]
        dialler_control: LinkControl,
        accepter_control: LinkControl,
        dialler_driver: tokio::task::JoinHandle<DropReason>,
        accepter_driver: tokio::task::JoinHandle<DropReason>,
    }

    fn pair() -> Pair {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (dial_link, dialler, dialler_control) =
            Link::new(Duplex::client(client, Limits::default()), Role::Dialler);
        let (accept_link, accepter, accepter_control) =
            Link::new(Duplex::server(server, Limits::default()), Role::Accepter);
        Pair {
            dialler,
            accepter,
            dialler_control,
            accepter_control,
            dialler_driver: tokio::spawn(dial_link.run()),
            accepter_driver: tokio::spawn(accept_link.run()),
        }
    }

    #[tokio::test]
    async fn a_frame_reaches_the_inbox_that_claimed_its_channel() {
        let pair = pair();
        let channel = ChannelId::new(3);
        let mut inbox = pair.accepter.attach(channel).expect("attach");

        pair.dialler.send_frame(Kind::Data, channel, b"pixels").await.expect("send");
        let frame = inbox.recv().await.expect("a frame");
        assert_eq!(frame.kind(), Kind::Data);
        assert_eq!(frame.channel(), channel);
        assert_eq!(frame.payload, b"pixels");

        pair.dialler_driver.abort();
        pair.accepter_driver.abort();
    }

    #[tokio::test]
    async fn a_frame_for_a_channel_nobody_holds_reaches_the_control_queue() {
        // Not an error: on a spliced path a frame for a channel that has just
        // closed is ordinary, and ending the link over one would make every
        // teardown a fault.
        let mut pair = pair();
        pair.dialler.send_frame(Kind::Data, ChannelId::new(9), b"late").await.expect("send");
        let frame = pair.accepter_control.recv().await.expect("a control frame");
        assert_eq!(frame.channel(), ChannelId::new(9));
        assert_eq!(frame.payload, b"late");
    }

    #[tokio::test]
    async fn channel_zero_is_never_attachable_and_always_reaches_control() {
        let pair = pair();
        assert_eq!(
            pair.accepter.attach(ChannelId::CONTROL).unwrap_err(),
            LinkError::Channel(ChannelError::ControlReserved)
        );
        // And the refused attach left no route behind that would swallow the
        // link's own control traffic.
        let mut control = pair.accepter_control;
        pair.dialler.send_frame(Kind::Echo, ChannelId::CONTROL, &[0; 8]).await.expect("send");
        let frame = control.recv().await.expect("a control frame");
        assert_eq!(frame.kind(), Kind::Echo);
    }

    #[tokio::test]
    async fn two_holders_of_one_channel_are_refused() {
        let pair = pair();
        let first = pair.accepter.attach(ChannelId::new(4)).expect("attach");
        assert_eq!(
            pair.accepter.attach(ChannelId::new(4)).unwrap_err(),
            LinkError::ChannelBusy(ChannelId::new(4))
        );
        // Dropping the first releases the claim, so the channel can be re-taken.
        drop(first);
        pair.accepter.attach(ChannelId::new(4)).expect("re-attach after release");
    }

    #[tokio::test]
    async fn several_channels_are_delivered_independently() {
        let pair = pair();
        let mut left = pair.accepter.attach(ChannelId::new(1)).expect("attach");
        let mut right = pair.accepter.attach(ChannelId::new(3)).expect("attach");

        pair.dialler.send_frame(Kind::Data, ChannelId::new(3), b"second").await.expect("send");
        pair.dialler.send_frame(Kind::Data, ChannelId::new(1), b"first").await.expect("send");

        assert_eq!(right.recv().await.expect("frame").payload, b"second");
        assert_eq!(left.recv().await.expect("frame").payload, b"first");
    }

    #[tokio::test]
    async fn a_link_that_ends_closes_every_inbox() {
        // The property a splice depends on: when the far end vanishes, a task
        // waiting on a channel wakes up rather than waiting forever.
        let pair = pair();
        let mut inbox = pair.accepter.attach(ChannelId::new(5)).expect("attach");
        pair.dialler_driver.abort();
        drop(pair.dialler);

        let ended = tokio::time::timeout(Duration::from_secs(5), inbox.recv())
            .await
            .expect("the inbox must close rather than hang");
        assert_eq!(ended, None);
        let reason = tokio::time::timeout(Duration::from_secs(5), pair.accepter_driver)
            .await
            .expect("the accepter must notice")
            .expect("driver");
        assert_eq!(reason, DropReason::TransportFailed);
    }

    #[tokio::test]
    async fn a_message_carrying_several_frames_delivers_all_of_them() {
        // The wire permits it even though this crate never writes it, so the
        // reader has to handle it — and a message that does not divide into
        // whole frames has to be refused rather than half-read.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (link, handle, _control) =
            Link::new(Duplex::server(server, Limits::default()), Role::Accepter);
        let mut inbox = handle.attach(ChannelId::new(1)).expect("attach");
        let driver = tokio::spawn(link.run());

        let mut packed = Vec::new();
        mux::write_frame(&mut packed, Kind::Data, ChannelId::new(1), b"one").expect("write");
        mux::write_frame(&mut packed, Kind::Data, ChannelId::new(1), b"two").expect("write");
        let mut peer = Duplex::client(client, Limits::default());
        peer.send(&packed).await.expect("send");

        assert_eq!(inbox.recv().await.expect("frame").payload, b"one");
        assert_eq!(inbox.recv().await.expect("frame").payload, b"two");
        drop(peer);
        let _ = driver.await;
    }

    #[tokio::test]
    async fn a_message_that_does_not_divide_into_whole_frames_ends_the_link() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (link, _handle, _control) =
            Link::new(Duplex::server(server, Limits::default()), Role::Accepter);
        let driver = tokio::spawn(link.run());

        let mut truncated =
            mux::encode_frame(Kind::Data, ChannelId::new(1), b"whole").expect("encode");
        truncated.pop();
        let mut peer = Duplex::client(client, Limits::default());
        peer.send(&truncated).await.expect("send");

        let reason = tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .expect("the link must end")
            .expect("driver");
        assert_eq!(reason, DropReason::ProtocolError);
    }

    #[tokio::test]
    async fn a_peer_speaking_a_future_version_is_named_rather_than_guessed_at() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (link, _handle, _control) =
            Link::new(Duplex::server(server, Limits::default()), Role::Accepter);
        let driver = tokio::spawn(link.run());

        let mut future = mux::encode_frame(Kind::Data, ChannelId::new(1), b"x").expect("encode");
        future[0] = 2;
        let mut peer = Duplex::client(client, Limits::default());
        peer.send(&future).await.expect("send");

        let reason = tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .expect("the link must end")
            .expect("driver");
        assert_eq!(reason, DropReason::VersionMismatch { offered: 2 });
    }

    #[tokio::test]
    async fn allocation_follows_the_role_the_link_was_built_with() {
        let pair = pair();
        assert_eq!(pair.dialler.allocate().expect("odd").get(), 1);
        assert_eq!(pair.dialler.allocate().expect("odd").get(), 3);
        assert_eq!(pair.accepter.allocate().expect("even").get(), 2);
        assert_eq!(pair.dialler.role(), Role::Dialler);
        assert_eq!(pair.accepter.role(), Role::Accepter);
    }

    #[tokio::test]
    async fn sending_on_a_dead_link_is_reported_and_not_swallowed() {
        let pair = pair();
        pair.accepter_driver.abort();
        pair.dialler_driver.abort();
        // Awaited, not merely signalled: `abort` schedules the cancellation, and
        // a send issued before the task has actually stopped would still be
        // queued. The property is about a link that is gone, not one that is
        // going.
        let _cancelled = pair.dialler_driver.await;

        // The stream's own task is gone, so the queue behind the handle is
        // closed and the send has nowhere to go.
        let outcome = pair.dialler.send_frame(Kind::Data, ChannelId::new(1), b"x").await;
        assert_eq!(outcome, Err(LinkError::Gone));
    }

    #[tokio::test]
    async fn an_over_ceiling_payload_is_refused_by_the_encoder_not_the_socket() {
        let pair = pair();
        let huge = vec![0u8; mux::MAX_PAYLOAD + 1];
        assert_eq!(
            pair.dialler.send_frame(Kind::Data, ChannelId::new(1), &huge).await,
            Err(LinkError::Frame(FrameError::PayloadTooLong { length: mux::MAX_PAYLOAD + 1 }))
        );
    }

    /// A greeting for `alex-desktop`, proved over a fixed handshake.
    fn hello() -> Hello {
        use crate::enroll::{Binding, NodeToken};
        let node = NodeName::parse("alex-desktop").expect("valid name");
        let binding = Binding::new("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", node.clone())
            .expect("binding");
        Hello { node, version: mux::VERSION, proof: binding.prove(&NodeToken::from_bytes([7u8; 32])) }
    }

    #[test]
    fn a_greeting_round_trips_and_is_printable_ascii() {
        let greeting = hello();
        let encoded = greeting.encode();
        // The `OPEN` decoder refuses anything else, so this is not a formality.
        assert!(encoded.iter().all(|byte| (0x20..=0x7e).contains(byte)), "must be printable ASCII");
        crate::channel::Open::parse(&[&[LINK_CONTROL_SERVICE][..], &encoded].concat())
            .expect("a legal OPEN payload");
        assert_eq!(Hello::parse(&encoded).expect("parse"), greeting);
    }

    #[test]
    fn a_greeting_missing_a_field_is_refused_rather_than_defaulted() {
        // A missing version read as 1 would let a future peer be misread as this
        // one; a missing node read as "" would surface as an unenrolled node
        // rather than as the malformed greeting it is.
        assert_eq!(Hello::parse(b"{}").unwrap_err(), HelloError::MissingField("node"));
        assert_eq!(
            Hello::parse(br#"{"node":"alex-desktop"}"#).unwrap_err(),
            HelloError::MissingField("version")
        );
        assert_eq!(
            Hello::parse(br#"{"node":"alex-desktop","version":1}"#).unwrap_err(),
            HelloError::MissingField("proof")
        );
        assert_eq!(Hello::parse(b"not json").unwrap_err(), HelloError::NotJson);
        assert_eq!(Hello::parse(&[0xff, 0xfe]).unwrap_err(), HelloError::NotUtf8);
        assert!(matches!(
            Hello::parse(br#"{"node":"ALEX","version":1,"proof":"00"}"#),
            Err(HelloError::BadNode(_))
        ));
        assert!(matches!(
            Hello::parse(br#"{"node":"alex","version":1,"proof":"zz"}"#),
            Err(HelloError::BadProof(_))
        ));
    }

    #[test]
    fn arbitrary_greeting_bytes_never_panic() {
        // Under `panic = "abort"` this decoder runs in the owner's daemon on
        // bytes a stranger chose, before anything has been verified.
        let mut state = 0x51e1_10c0_ffee_0001u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 60) as usize;
            let bytes: Vec<u8> = (0..len).map(|index| (state >> (index % 8 * 8)) as u8).collect();
            let _ = Hello::parse(&bytes);
        }
    }

    #[test]
    fn a_frame_never_prints_its_payload() {
        let header = Header::new(Kind::Data, ChannelId::new(1), 4).expect("header");
        let frame = OwnedFrame { header, payload: b"pass".to_vec() };
        let rendered = format!("{frame:?}");
        assert!(rendered.contains("payload_len"), "{rendered}");
        assert!(!rendered.contains("pass"), "{rendered}");
    }

    #[test]
    fn every_way_a_stream_can_end_maps_to_a_reason_the_console_can_render() {
        use selfhost_ws::{CloseCode, CloseFrame};
        assert_eq!(
            reason_for(&Closed::Peer(CloseFrame::new(CloseCode::GoingAway, "bye"))),
            DropReason::PeerClosed { code: 1001 }
        );
        assert_eq!(reason_for(&Closed::Peer(CloseFrame::empty())), DropReason::PeerClosed { code: 0 });
        assert_eq!(reason_for(&Closed::PongTimeout), DropReason::Timeout);
        assert_eq!(reason_for(&Closed::LifetimeReached), DropReason::LocalShutdown);
        assert_eq!(reason_for(&Closed::Abrupt), DropReason::TransportFailed);
    }

    #[test]
    fn errors_render_something_an_operator_can_act_on() {
        assert!(LinkError::Gone.to_string().contains("ended"));
        assert!(LinkError::ChannelBusy(ChannelId::new(7)).to_string().contains("#7"));
        assert!(
            LinkError::Frame(FrameError::PayloadTooLong { length: 9 }).to_string().contains('9')
        );
        assert!(
            LinkError::Channel(ChannelError::ControlReserved).to_string().contains("channel 0")
        );
    }
}
