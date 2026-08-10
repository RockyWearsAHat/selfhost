//! The server-side session driver: the one impure module in this crate.
//!
//! Everything else here is a pure function of its arguments — the codec, the
//! tile grid, the cursor policy, the state machine, the ticket store. This
//! module is what turns all of them into a running session: it owns one
//! viewer's stream from the moment the upgrade succeeds until the moment the
//! socket is dropped, and it is the only place in `selfhost-desk` that awaits
//! anything.
//!
//! # The shape of the seam
//!
//! The driver never links a platform and never opens a socket. Everything it
//! touches arrives as a trait:
//!
//! - [`FrameSource`] — pixels, or the named reason there are none. `selfhost-screen`'s
//!   `Capture` supervisor implements it; a test implements it with a script.
//! - [`PointerSource`] — the pointer's position and, once per distinct shape,
//!   its bitmap. Separate from the frame source for the same reason it is
//!   separate in `selfhost-screen`: the pointer is captured separately on every
//!   platform, and a suspended session still knows where it is.
//! - [`InputSink`] — synthesised keys and pointer events. Not wired to anything
//!   yet, which is precisely why [`NoInput`] exists and why the authorisation
//!   check in front of it is written and tested *now*: the guard must predate
//!   the capability it guards.
//! - [`Outbound`] / [`Inbound`] — the mux channel, as two halves. They carry
//!   **bytes**, not messages: the driver owns the codec, and the mesh layer
//!   forwards a payload it never interprets. That is not a convenience, it is
//!   the property that keeps a malicious peer's tile payload from being parsed
//!   in the process that also serves 80/443, mail and the certificate store.
//! - [`SessionDirectory`] — the console's session store, read-only. The only
//!   seam here that is *not* an `async fn`, because it is a map lookup rather
//!   than an act of I/O, and the contrast is deliberate.
//!
//! The reading half is handed to [`Viewer::run`] as an argument rather than
//! stored in the struct, because the loop must await a read and a write in the
//! same `select!`, and one object holding both halves could not be borrowed
//! twice.
//!
//! # The lifetime rules, which are security properties
//!
//! 1. **The session id is captured at the handshake and re-read, never
//!    refreshed.** [`SessionDirectory::standing`] must not touch `last_seen`.
//!    A long-lived stream that re-validated through the console's ordinary
//!    `validate` call would keep its own session alive forever and defeat the
//!    two-hour idle expiry that exists precisely so that a console left open on
//!    an unlocked machine stops being a way in.
//! 2. **Stream lifetime is `min(session absolute expiry, max_session)`,**
//!    computed once at the handshake and enforced as a wall — every await in
//!    the driver is bounded by it, including the capture call, so neither a
//!    hung screen source nor a silent socket can outlive it.
//! 3. **A close is enforced, never requested.** When the deadline passes the
//!    driver sends what it can and returns; it does not wait for the peer to
//!    agree. A peer that keeps answering after its session died gets no say.
//! 4. **[`Capabilities::CONTROL`] is re-checked per input message**, against
//!    the directory, and never inferred from the handshake — so a viewer can be
//!    downgraded mid-session and the very next keystroke is refused. The 60-second
//!    timer exists for the *idle* stream that sends no input at all; between them
//!    a revocation is felt immediately if the viewer is typing and within a minute
//!    if it is only watching.
//!
//! # Credit
//!
//! At zero credit the driver **drops the frame and keeps the previous surface**,
//! so the damage merges into the next one it can afford. A remote desktop must
//! show the present, not a backlog, and merging is free: the next
//! [`crate::tiles::diff`] is taken against the last surface the client actually
//! received, so it necessarily contains everything that has changed since. Each
//! drop is counted in [`Stats::credit_stalls`] so an operator can see a starved
//! link rather than guess at one.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::time::{sleep_until, timeout_at};

use crate::cursor::{CursorPolicy, Pointer, ShapeId, DEFAULT_CAPACITY};
use crate::grant::{Capabilities, Redemption, SessionId};
use crate::keys::{HeldKeys, Usage};
use crate::state::{Action, Limits, Observation, Phase, Session, Surrender, Suspension};
use crate::tiles::{diff, Surface, TileSize};
use crate::wire::{
    Button, CursorPos, CursorShape, Direction, FrameBegin, Hello, Message, Monitor, Refusal,
    TileMessage, WireError, MAX_CURSOR_EDGE, MAX_MONITORS, PROTOCOL_VERSION,
};

/// How often a live stream re-reads its session's standing.
///
/// A minute is short enough that a revoked session cannot watch a screen for
/// long and long enough that the lookup is free. It is not the only revocation
/// path — an input message re-checks immediately — it is the one that covers a
/// viewer that is merely watching.
pub const REVALIDATE_INTERVAL: Duration = Duration::from_secs(60);

/// How long the close sequence may take in total before the stream is simply
/// abandoned.
///
/// Bounded because the close path runs *after* something already went wrong,
/// and the failure that most often triggers it — a tunnel dropping — is exactly
/// the one that makes a write hang.
pub const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// The default frame ceiling, matching `[desktop].max_fps`.
pub const DEFAULT_MAX_FPS: u8 = 30;

/// The default hard stream ceiling, matching `[desktop].max_session`.
pub const DEFAULT_MAX_SESSION: Duration = Duration::from_secs(4 * 60 * 60);

/// The shortest the driver will ever wait before looking for another frame.
///
/// The delays come from [`Limits`], which a caller supplies; a zero in a config
/// would make the frame arm of the loop permanently ready, which starves the
/// deadline and the input arms and pins a core. One millisecond is far below any
/// frame interval and is therefore invisible in every legitimate configuration.
const MIN_TICK: Duration = Duration::from_millis(1);

/// A boxed future returned by one of the impure seams.
///
/// Boxed so the traits are dyn-compatible — the driver holds `&mut dyn` rather
/// than five type parameters — and `Send` so a stream may run on the daemon's
/// multi-threaded runtime. The same shape `selfhost-acme`'s `Http` trait uses,
/// for the same reason and with no dependency added to do it.
pub type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a byte could not be written to, or read from, the channel.
///
/// Deliberately thin: the mux layer's own error vocabulary is its business, and
/// the driver's only two decisions are *"the peer is gone"* and *"the link
/// broke, and here is what to write in the log"*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// The peer closed, or the channel was torn down under us.
    Closed,
    /// The link failed, with whatever the transport had to say about it.
    Failed(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => out.write_str("the channel is closed"),
            Self::Failed(detail) => write!(out, "the channel failed: {detail}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// The writing half of one viewer's mux channel.
///
/// Carries encoded bytes rather than [`Message`]s so that the layer underneath
/// never parses what a peer sent. Implementations must be cancel-tolerant in the
/// weak sense only: the driver never drops a `send` future once it has been
/// polled, except when the stream deadline expires, at which point the channel
/// is being abandoned anyway.
pub trait Outbound: Send {
    /// Writes one complete protocol message.
    fn send<'a>(&'a mut self, frame: &'a [u8]) -> Task<'a, Result<(), StreamError>>;

    /// How many payload bytes the peer has authorised and this end has not yet
    /// spent.
    ///
    /// Read before a frame is offered, never after: the driver's whole flow
    /// policy is to decline to produce what it cannot afford, rather than to
    /// queue it and let the buffer grow.
    fn credit(&self) -> u32;

    /// Closes the channel, carrying the reason for the peer's log.
    ///
    /// Best-effort by contract: the driver bounds this call and returns whether
    /// or not it succeeds, because a close that waits on a peer is not a close.
    fn close<'a>(&'a mut self, ending: &'a Ending) -> Task<'a, Result<(), StreamError>>;
}

/// The reading half of one viewer's mux channel.
pub trait Inbound: Send {
    /// The next complete protocol message, or `None` once the peer is done.
    ///
    /// # Must be cancel-safe
    ///
    /// The driver polls this inside a `select!` alongside three timers and drops
    /// the future whenever another arm wins, which happens on every frame. An
    /// implementation that consumes bytes before yielding them therefore loses
    /// input — a dropped keystroke that arrives as a stuck modifier. Reading
    /// from a channel that owns its own reassembly (which is what the mux
    /// provides) satisfies this; reading directly from a socket does not.
    fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>>;
}

/// What a capture attempt reported when it produced no pixels.
///
/// The closed set of things a *screen source* can say — which deliberately
/// excludes [`Observation::Frame`] (a frame is the `Ok` arm and cannot be
/// claimed without pixels) and [`Observation::Resume`] (an operator's act, not
/// an observation). `selfhost-screen`'s `CaptureError` maps onto this; the
/// mapping lives there because the platform codes are platform knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Nothing new yet. A still desktop reports this indefinitely and it counts
    /// against no budget.
    Retry,
    /// The capture object must be torn down and rebuilt.
    Reinitialise,
    /// The secure desktop is in front: never captured, and input suspends.
    SecureDesktop,
    /// The interactive session moved — fast user switching, or RDP.
    SessionDisconnected,
    /// Nobody is logged in.
    NoSession,
    /// The operating system refuses this process the screen or the input device.
    PermissionDenied,
    /// The agent process is gone.
    AgentExited,
    /// The operator's kill switch is present.
    Stopped,
    /// Something unrecoverable.
    Fatal,
}

impl Condition {
    /// The same fact, in the vocabulary [`Session::observe`] reasons about.
    pub const fn observation(self) -> Observation {
        match self {
            Self::Retry => Observation::Retry,
            Self::Reinitialise => Observation::Reinitialise,
            Self::SecureDesktop => Observation::SecureDesktop,
            Self::SessionDisconnected => Observation::SessionDisconnected,
            Self::NoSession => Observation::NoSession,
            Self::PermissionDenied => Observation::PermissionDenied,
            Self::AgentExited => Observation::AgentExited,
            Self::Stopped => Observation::KillSwitch,
            Self::Fatal => Observation::Fatal,
        }
    }
}

/// One captured frame, owned.
///
/// Owned rather than borrowed because the platform buffer has to be unpacked
/// anyway — row padding is per-surface and never `width * 4` — so the copy the
/// borrow would save has already happened inside
/// [`crate::tiles::unpack`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Which display these pixels belong to, in the ids [`Hello`] advertised.
    pub monitor: u8,
    /// The pixels, tight BGRA.
    pub surface: Surface,
}

/// What the state machine asked to have rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restore {
    /// The capture object itself — a display mode changed, or the duplication
    /// was lost.
    Capture,
    /// The agent process, which is gone.
    Agent,
}

/// A source of frames.
///
/// Every method is an `async fn` in boxed form because on a real machine each
/// one is served by a thread that blocks on a platform call. A synchronous
/// signature would make the driver block a runtime worker for up to a frame
/// interval, on a daemon that is also serving 80/443.
pub trait FrameSource: Send {
    /// The displays this source can produce frames for.
    ///
    /// Read once, at the handshake, and advertised in [`Hello`]. A display
    /// appearing or disappearing arrives as [`Condition::Reinitialise`], not as
    /// a silently different slice.
    fn monitors(&self) -> &[Monitor];

    /// The next frame, or the named state the source is in instead.
    ///
    /// Waits at most `budget`. Returning [`Condition::Retry`] and simply taking
    /// the whole budget are the same answer.
    fn next_frame(&mut self, budget: Duration) -> Task<'_, Result<CapturedFrame, Condition>>;

    /// Rebuilds what the state machine says is broken.
    fn restore(&mut self, what: Restore) -> Task<'_, Result<(), Condition>>;
}

/// A cursor bitmap as the platform reported it.
///
/// Validated by the driver before it is put on the wire — a shape wider than
/// [`MAX_CURSOR_EDGE`], or one whose pixel count does not match its extent,
/// would encode into a message the far end refuses to decode, which would end
/// the session over a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerShape {
    /// The hotspot's x offset within the bitmap.
    pub hotspot_x: u16,
    /// The hotspot's y offset within the bitmap.
    pub hotspot_y: u16,
    /// Bitmap width in pixels.
    pub width: u16,
    /// Bitmap height in pixels.
    pub height: u16,
    /// `width * height * 4` bytes of premultiplied BGRA.
    pub pixels: Vec<u8>,
}

/// A source of pointer position and shape.
pub trait PointerSource: Send {
    /// Where the pointer is, or `None` if the platform will not say right now.
    fn pointer(&mut self) -> Task<'_, Option<Pointer>>;

    /// The bitmap for a shape the client has not been sent yet.
    fn shape(&mut self, id: ShapeId) -> Task<'_, Option<PointerShape>>;
}

/// A sink for synthesised keyboard and pointer events.
///
/// `Ok(())` means *posted*, never *delivered*: `CGEventPost` returns `void`, and
/// Windows' UIPI silently discards injection into any window at a higher
/// integrity level while `SendInput` still reports success. An implementation
/// must never infer delivery from a return value, and the driver never tells the
/// console that an event landed.
pub trait InputSink: Send {
    /// Injects one already-authorised input message.
    ///
    /// The driver guarantees the message travels [`Direction::ToAgent`] and is
    /// one of the five input kinds; an implementation that is handed anything
    /// else must return a [`Refusal`] rather than panic, because this process
    /// aborts on panic.
    fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>>;
}

/// An input sink for a deployment where injection is not built, or not allowed.
///
/// Refuses everything with [`Refusal::InputDisabled`], which is exactly what a
/// console should show while the injection path is unwired: the viewer learns
/// the truth instead of watching its keystrokes vanish.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoInput;

impl InputSink for NoInput {
    fn deliver<'a>(&'a mut self, _message: &'a Message) -> Task<'a, Result<(), Refusal>> {
        Box::pin(async { Err(Refusal::InputDisabled) })
    }
}

/// A pointer source for a build with no cursor capture.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPointer;

impl PointerSource for NoPointer {
    fn pointer(&mut self) -> Task<'_, Option<Pointer>> {
        Box::pin(async { None })
    }

    fn shape(&mut self, _id: ShapeId) -> Task<'_, Option<PointerShape>> {
        Box::pin(async { None })
    }
}

/// What the console's session store says about a session right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    /// The session's **absolute** expiry — the wall its own idle timer cannot
    /// move.
    pub expires: Instant,
    /// What the session may still do. Intersected with what the ticket granted,
    /// so revoking a permission in the console downgrades a running stream.
    pub capabilities: Capabilities,
}

/// A read-only view of the console's session store.
///
/// # Why this is a read and not a validation
///
/// The obvious implementation — call the console's `validate` — is a security
/// bug, and the name of this method exists to make it hard to write by accident.
/// `validate` refreshes `last_seen`; a stream that called it every sixty seconds
/// would keep its own session alive for as long as it stayed connected, and the
/// two-hour idle expiry would never fire on the one session that matters — the
/// one attached to a console left open on an unlocked machine.
///
/// An implementation must therefore look the session up and report it,
/// unchanged, or report that it is gone.
pub trait SessionDirectory: Send + Sync {
    /// The session's standing, or `None` if it no longer exists.
    fn standing(&self, session: &SessionId) -> Option<Standing>;
}

/// The ledger of how many streams each peer is running.
///
/// Pure, and not internally synchronised — the same shape as
/// [`crate::grant::Grants`], and for the same reason: the policy is testable
/// without a lock, and the lock belongs to whoever owns the store. Wrap it in a
/// [`Gate`] to share it.
#[derive(Debug, Clone, Default)]
pub struct Viewers {
    limit: usize,
    streams: HashMap<String, usize>,
}

impl Viewers {
    /// A ledger admitting at most `limit` concurrent streams per peer.
    ///
    /// A limit of zero admits nothing, which is a legitimate way for an operator
    /// to switch desktop streaming off without touching the ticket path.
    pub fn new(limit: usize) -> Self {
        Self { limit, streams: HashMap::new() }
    }

    /// The per-peer ceiling.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// How many streams a peer is running.
    pub fn streams(&self, peer: &str) -> usize {
        self.streams.get(peer).copied().unwrap_or(0)
    }

    /// Takes a seat for `peer`, or says why not.
    pub fn admit(&mut self, peer: &str) -> Result<(), AtCapacity> {
        let running = self.streams(peer);
        if running >= self.limit {
            return Err(AtCapacity { running, limit: self.limit });
        }
        // `saturating_add` rather than `+`: this counter is incremented once per
        // upgrade and the process aborts on overflow.
        self.streams.insert(peer.to_owned(), running.saturating_add(1));
        Ok(())
    }

    /// Gives a seat back. A release for a peer holding none is ignored rather
    /// than counted negative, because the alternative is an underflow.
    pub fn release(&mut self, peer: &str) {
        let Some(running) = self.streams.get_mut(peer) else { return };
        *running = running.saturating_sub(1);
        if *running == 0 {
            self.streams.remove(peer);
        }
    }
}

/// A peer is already running as many streams as it is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtCapacity {
    /// How many streams it is already running.
    pub running: usize,
    /// The ceiling, from `[desktop].max_viewers`.
    pub limit: usize,
}

impl fmt::Display for AtCapacity {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "already streaming {} of {} permitted sessions", self.running, self.limit)
    }
}

impl std::error::Error for AtCapacity {}

/// A shared [`Viewers`] ledger.
#[derive(Debug, Clone)]
pub struct Gate(Arc<Mutex<Viewers>>);

impl Gate {
    /// A gate admitting at most `limit` concurrent streams per peer.
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Mutex::new(Viewers::new(limit))))
    }

    /// Takes a seat, or refuses.
    pub fn admit(&self, peer: &str) -> Result<Seat, AtCapacity> {
        lock(&self.0).admit(peer)?;
        Ok(Seat { gate: Arc::clone(&self.0), peer: peer.to_owned() })
    }

    /// How many streams a peer is running.
    pub fn streams(&self, peer: &str) -> usize {
        lock(&self.0).streams(peer)
    }
}

/// A held seat, released when it is dropped.
///
/// [`Viewer`] takes one by value and holds it for the life of the stream, so a
/// stream cannot exist without one and no exit path — including a transport
/// error thrown from the middle of the close sequence — can forget to give it
/// back.
#[derive(Debug)]
pub struct Seat {
    gate: Arc<Mutex<Viewers>>,
    peer: String,
}

impl Seat {
    /// The peer this seat is held against.
    pub fn peer(&self) -> &str {
        &self.peer
    }
}

impl Drop for Seat {
    fn drop(&mut self) {
        lock(&self.gate).release(&self.peer);
    }
}

/// Locks the ledger without a path that panics.
///
/// A poisoned mutex means a thread panicked while holding it — under
/// `panic = "abort"` that thread took the process with it, so this branch is
/// unreachable in production. It is still written out rather than unwrapped,
/// because a lock that can abort the daemon in a *test* build is a lock that can
/// hide a real bug behind a second failure.
fn lock(ledger: &Mutex<Viewers>) -> std::sync::MutexGuard<'_, Viewers> {
    ledger.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The ceilings and budgets one stream runs under.
///
/// Supplied by the caller rather than read from config, because this crate does
/// not depend on `selfhost-config` — and because a ceiling passed in is a
/// ceiling a test can set to a millisecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceilings {
    /// `[desktop].max_fps`. Clamped to at least one frame per second when it is
    /// used: a zero interval is a busy loop that pins a core.
    pub max_fps: u8,
    /// `[desktop].max_session`. The stream's own wall; the console session's
    /// absolute expiry still wins when it is earlier.
    pub max_session: Duration,
    /// The tile edge advertised in [`Hello`] and used for every diff.
    pub tile: TileSize,
    /// `[desktop].allow_input`, the deployment-wide switch. Re-read on every
    /// input message rather than folded into the grant, so the refusal names the
    /// config rather than the ticket.
    pub allow_input: bool,
    /// How often the session's standing is re-read.
    pub revalidate_every: Duration,
    /// How long the whole close sequence may take.
    pub close_grace: Duration,
    /// The state machine's recovery budgets.
    pub limits: Limits,
    /// How many distinct cursor shapes the client is assumed to hold.
    pub cursor_cache: usize,
}

impl Default for Ceilings {
    /// The documented defaults: thirty frames a second, a four-hour wall,
    /// 64-pixel tiles, no input, a minute between re-reads.
    fn default() -> Self {
        Self {
            max_fps: DEFAULT_MAX_FPS,
            max_session: DEFAULT_MAX_SESSION,
            tile: TileSize::DEFAULT,
            allow_input: false,
            revalidate_every: REVALIDATE_INTERVAL,
            close_grace: CLOSE_GRACE,
            limits: Limits::default(),
            cursor_cache: DEFAULT_CAPACITY,
        }
    }
}

/// Why a stream ended.
///
/// Every variant is a decision the *server* made, except [`Ending::PeerClosed`]:
/// there is no variant meaning "the viewer asked to stop and we agreed", because
/// the driver never waits for the far end to agree to anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// `min(session expiry, max_session)` passed.
    Deadline,
    /// The session's absolute expiry passed while the stream was running.
    SessionExpired,
    /// The session is no longer in the store — logged out, idled out, or
    /// revoked.
    SessionGone,
    /// The session lost [`Capabilities::VIEW`]; there is nothing left to show.
    ViewRevoked,
    /// The operator's kill switch appeared.
    Stopped,
    /// The state machine stopped trying.
    GaveUp(Surrender),
    /// The peer closed its half.
    PeerClosed,
    /// The peer sent something that does not decode.
    PeerMisbehaved(WireError),
    /// The peer sent a message that only the server may send.
    WrongDirection {
        /// The kind byte it sent.
        kind: u8,
    },
    /// The channel failed.
    Transport(StreamError),
    /// A message this end produced could not be encoded — a bug on this side,
    /// reported rather than papered over.
    Encoding(WireError),
}

impl Ending {
    /// The stable close code carried in the mux `CLOSE` frame.
    ///
    /// `selfhost-desk`'s own numbering: the mux's code space belongs to the mux,
    /// and a desktop stream's reasons are not the link's reasons.
    pub const fn code(&self) -> u16 {
        match self {
            Self::Deadline => 1,
            Self::SessionExpired => 2,
            Self::SessionGone => 3,
            Self::ViewRevoked => 4,
            Self::Stopped => 5,
            Self::GaveUp(_) => 6,
            Self::PeerClosed => 7,
            Self::PeerMisbehaved(_) => 8,
            Self::WrongDirection { .. } => 9,
            Self::Transport(_) => 10,
            Self::Encoding(_) => 11,
        }
    }

    /// Whether it is worth trying to tell the peer.
    ///
    /// False exactly when the channel is already gone, so the close path does
    /// not spend its grace period writing into a socket that has hung up.
    pub const fn peer_is_listening(&self) -> bool {
        !matches!(self, Self::PeerClosed | Self::Transport(_))
    }
}

impl fmt::Display for Ending {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadline => out.write_str("the session reached its time limit"),
            Self::SessionExpired => out.write_str("the console session expired"),
            Self::SessionGone => out.write_str("the console session ended"),
            Self::ViewRevoked => out.write_str("permission to view was withdrawn"),
            Self::Stopped => out.write_str("desktop access is switched off on this machine"),
            Self::GaveUp(surrender) => match surrender {
                Surrender::TooManyReinitialisations => {
                    out.write_str("the screen source could not be kept alive")
                }
                Surrender::AgentUnrecoverable => out.write_str("the agent could not be restarted"),
                Surrender::Fatal => out.write_str("the screen source failed unrecoverably"),
            },
            Self::PeerClosed => out.write_str("the viewer disconnected"),
            Self::PeerMisbehaved(error) => write!(out, "the viewer sent something unreadable: {error}"),
            Self::WrongDirection { kind } => {
                write!(out, "the viewer sent a server-only message ({kind:#04x})")
            }
            Self::Transport(error) => write!(out, "{error}"),
            Self::Encoding(error) => write!(out, "a message could not be encoded: {error}"),
        }
    }
}

/// What one stream did, for the diagnostics plate and the log line it ends with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames put on the wire.
    pub frames_sent: u64,
    /// Tiles put on the wire.
    pub tiles_sent: u64,
    /// Payload bytes written.
    pub bytes_sent: u64,
    /// Frames dropped because the peer had granted no credit for them. Damage
    /// merged into the next frame; this counts how often that happened.
    pub credit_stalls: u64,
    /// Cursor updates dropped for want of credit.
    pub cursor_stalls: u64,
    /// Cursor bitmaps the platform reported in a shape the protocol cannot
    /// express.
    pub unusable_shapes: u64,
    /// Input messages handed to the sink.
    pub inputs_delivered: u64,
    /// Input messages refused, whether by policy or by the sink.
    pub inputs_refused: u64,
    /// Key-ups for keys that were never held, which are dropped rather than
    /// forwarded.
    pub inputs_ignored: u64,
    /// How many times the session's standing was re-read on the timer.
    pub revalidations: u64,
    /// Keys and buttons released by the server when the stream ended.
    pub released_on_close: u64,
}

/// The outcome of one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Why it ended.
    pub ending: Ending,
    /// What it did.
    pub stats: Stats,
}

/// The interval between frames for a ceiling of `max_fps`.
///
/// Clamped to at least one frame per second. Zero is not merely a silly value:
/// a zero interval makes the frame arm of the driver's `select!` always ready,
/// which starves every other arm — including the deadline — and pins a core.
pub fn frame_interval(max_fps: u8) -> Duration {
    Duration::from_secs(1) / u32::from(max_fps.max(1))
}

/// The wall a stream may not outlive: the earlier of the session's own absolute
/// expiry and `max_session` from now.
///
/// Both halves matter and neither is redundant. `max_session` bounds a stream
/// opened one second after a fresh login; the session's expiry bounds one opened
/// one second before an old session lapses.
pub fn stream_deadline(started: Instant, session_expires: Instant, max_session: Duration) -> Instant {
    // `checked_add` because a `max_session` read from config is a number an
    // operator typed, and `Instant + Duration` panics on overflow — which under
    // `panic = "abort"` is the daemon dying because someone wrote `max_session =
    // "99999999h"`.
    let own = started.checked_add(max_session).unwrap_or(session_expires);
    own.min(session_expires)
}

/// Whether an input message must be refused, and with which reason.
///
/// The order is the order an operator can act on. The deployment-wide switch is
/// named first because it is the one an operator changes in config; the grant is
/// named next because it is the one they change in the console; the platform
/// state is named last because it is the one nobody chose.
pub fn input_refusal(live: Capabilities, allow_input: bool, phase: Phase) -> Option<Refusal> {
    if !allow_input {
        return Some(Refusal::InputDisabled);
    }
    if !live.contains(Capabilities::CONTROL) {
        return Some(Refusal::NotPermitted);
    }
    match phase {
        Phase::Live => None,
        Phase::Suspended(Suspension::SecureDesktop) => Some(Refusal::SecureDesktop),
        _ => Some(Refusal::NotLive),
    }
}

/// The capabilities a stream may exercise right now: what the ticket granted,
/// narrowed by what the session still holds.
///
/// An intersection rather than either side alone, because the two are revoked in
/// different places — the ticket by reconnecting, the session by an operator —
/// and a stream must lose the capability the moment *either* does.
pub fn effective(granted: Capabilities, standing: Capabilities) -> Capabilities {
    Capabilities::from_bits(granted.bits() & standing.bits()).unwrap_or_else(Capabilities::none)
}

/// Turns a platform cursor bitmap into a wire message, or refuses it.
///
/// Refuses rather than clips: a bitmap whose pixel count disagrees with its
/// extent is a bug in the capture layer, and sending a message the peer will
/// refuse to decode would end the whole session over a pointer.
fn cursor_message(id: ShapeId, shape: &PointerShape) -> Option<Message> {
    if shape.width == 0 || shape.height == 0 {
        return None;
    }
    if shape.width > MAX_CURSOR_EDGE || shape.height > MAX_CURSOR_EDGE {
        return None;
    }
    let expected = usize::from(shape.width).checked_mul(usize::from(shape.height))?.checked_mul(4)?;
    if shape.pixels.len() != expected {
        return None;
    }
    Some(Message::CursorShape(CursorShape {
        shape: id.0,
        hotspot_x: shape.hotspot_x,
        hotspot_y: shape.hotspot_y,
        width: shape.width,
        height: shape.height,
        pixels: shape.pixels.clone(),
    }))
}

/// Which pointer buttons the far machine is currently holding down because of
/// us.
///
/// A five-bit set rather than a `HashSet`, because it is touched once per
/// pointer event and because the whole point of tracking it is to be able to
/// undo it on a link that has already failed. [`crate::keys::HeldKeys`] covers
/// the keyboard; a held mouse button is just as effective at making the far
/// machine unusable to the person sitting in front of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct HeldButtons(u8);

impl HeldButtons {
    /// The bit for one button.
    ///
    /// Written out rather than derived from [`Button::code`] by shifting: a
    /// shift by a value that came from an enum is a shift that a later variant
    /// can push past the width of the word, and an overflowing shift under
    /// `panic = "abort"` is the daemon dying over a mouse button.
    const fn bit(button: Button) -> u8 {
        match button {
            Button::Left => 0b0000_0001,
            Button::Middle => 0b0000_0010,
            Button::Right => 0b0000_0100,
            Button::Back => 0b0000_1000,
            Button::Forward => 0b0001_0000,
        }
    }

    /// Records a press.
    fn press(&mut self, button: Button) {
        self.0 |= Self::bit(button);
    }

    /// Records a release, reporting whether it had been held.
    fn release(&mut self, button: Button) -> bool {
        let held = self.0 & Self::bit(button) != 0;
        self.0 &= !Self::bit(button);
        held
    }

    /// Empties the set and returns everything that was held.
    fn drain(&mut self) -> Vec<Button> {
        let held = [Button::Left, Button::Middle, Button::Right, Button::Back, Button::Forward]
            .into_iter()
            .filter(|button| self.0 & Self::bit(*button) != 0)
            .collect();
        self.0 = 0;
        held
    }
}

/// Everything one stream is plugged into.
///
/// Grouped so that constructing a [`Viewer`] does not take ten arguments in an
/// order nobody can remember. The reading half is absent on purpose: see the
/// module documentation.
pub struct Wiring<'a> {
    /// The writing half of the mux channel.
    pub outbound: &'a mut dyn Outbound,
    /// Where pixels come from.
    pub frames: &'a mut dyn FrameSource,
    /// Where the pointer comes from.
    pub pointer: &'a mut dyn PointerSource,
    /// Where input goes.
    pub input: &'a mut dyn InputSink,
}

impl fmt::Debug for Wiring<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Wiring").finish_non_exhaustive()
    }
}

/// One viewer's stream.
///
/// Holds the [`Seat`] for its whole life, so the concurrency ceiling is enforced
/// by construction rather than by remembering to decrement a counter on every
/// exit path.
pub struct Viewer<'a> {
    wiring: Wiring<'a>,
    sessions: &'a dyn SessionDirectory,
    ceilings: Ceilings,
    session: SessionId,
    granted: Capabilities,
    /// Held, never read: dropping it releases the seat.
    _seat: Seat,
    machine: Session,
    cursor: CursorPolicy,
    held: HeldKeys,
    buttons: HeldButtons,
    previous: Option<Surface>,
    previous_monitor: Option<u8>,
    sequence: u64,
    pending_restore: Option<Restore>,
    stats: Stats,
}

impl fmt::Debug for Viewer<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Viewer")
            .field("session", &self.session)
            .field("granted", &self.granted)
            .field("phase", &self.machine.phase())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<'a> Viewer<'a> {
    /// Prepares a stream for a redeemed ticket.
    ///
    /// Nothing happens until [`run`](Viewer::run) is awaited; in particular the
    /// session is not looked up here, because the handshake's first act is to
    /// look it up and the answer must be the one the deadline is computed from.
    pub fn new(
        wiring: Wiring<'a>,
        sessions: &'a dyn SessionDirectory,
        seat: Seat,
        redemption: &Redemption,
        ceilings: Ceilings,
    ) -> Self {
        Self {
            wiring,
            sessions,
            ceilings,
            session: redemption.session.clone(),
            granted: redemption.capabilities,
            _seat: seat,
            machine: Session::new(ceilings.limits),
            cursor: CursorPolicy::new(ceilings.cursor_cache),
            held: HeldKeys::new(),
            buttons: HeldButtons::default(),
            previous: None,
            previous_monitor: None,
            sequence: 0,
            pending_restore: None,
            stats: Stats::default(),
        }
    }

    /// What this stream has done so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Drives the stream until it ends, then releases everything it was holding.
    ///
    /// Returns rather than errors: every way a desktop session can end is an
    /// [`Ending`], and the caller's job is the same in all of them — log it and
    /// let the seat go.
    pub async fn run(mut self, inbound: &mut dyn Inbound) -> Outcome {
        let started = tokio::time::Instant::now();

        // The handshake reads the session once. Everything after this point is a
        // re-read: the absolute expiry does not move, so the wall is computed
        // here and never recomputed, while the session *disappearing* is caught
        // by the timer and by every input message.
        let standing = match self.sessions.standing(&self.session) {
            Some(standing) => standing,
            None => return self.finish(Ending::SessionGone).await,
        };
        let mut live = effective(self.granted, standing.capabilities);
        if !live.contains(Capabilities::VIEW) {
            return self.finish(Ending::ViewRevoked).await;
        }
        let deadline = tokio::time::Instant::from_std(stream_deadline(
            started.into_std(),
            standing.expires,
            self.ceilings.max_session,
        ));

        if let Err(ending) = self.greet(live, deadline).await {
            return self.finish(ending).await;
        }

        let mut next_revalidate = started + self.ceilings.revalidate_every;
        let mut next_frame = started;

        let ending = loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break Ending::Deadline;
            }

            // # Overdue work runs before the select, and that is a security
            // property rather than a tidiness one
            //
            // [`Inbound::recv`] reads from a channel the socket pump has
            // already filled, so a peer sending input faster than this loop
            // consumes it makes that future **ready on every poll**. A `biased`
            // select polls its arms in order and stops at the first ready one,
            // so such a peer wins every pass — and the arm it starves is the
            // capture arm, which is the only place the operator's kill switch,
            // the secure desktop and the agent's death are ever observed. The
            // stream then keeps injecting keystrokes until its own wall, which
            // is hours.
            //
            // Running an arm whose moment has already passed *before* offering
            // the peer another turn removes the starvation without inverting
            // the priority: input still outranks pixels whenever both are
            // merely available, and a peer that floods still starves only its
            // own picture — but it can no longer outrun the checks that revoke
            // it. Both branches move their instant strictly forward (the frame
            // one by at least [`MIN_TICK`]), so neither can spin.
            if now >= next_revalidate {
                self.stats.revalidations = self.stats.revalidations.saturating_add(1);
                next_revalidate = now + self.ceilings.revalidate_every.max(MIN_TICK);
                match self.standing_now() {
                    Ok(current) => live = current,
                    Err(ending) => break ending,
                }
                continue;
            }
            if now >= next_frame {
                match self.pump(live, deadline).await {
                    Ok(wait) => {
                        next_frame = tokio::time::Instant::now() + wait.max(MIN_TICK);
                    }
                    Err(ending) => break ending,
                }
                continue;
            }

            tokio::select! {
                // Biased, and the order is the priority order. The wall comes
                // first because an unbiased select would let a viewer that
                // floods the channel keep winning the race against its own
                // deadline. Input comes before pixels because a keystroke is
                // useless late and a frame is merely stale; a peer that floods
                // input therefore starves only its own picture.
                //
                // The two timers are pure wake-ups: the work they name is done
                // at the head of the loop, so there is one place that decides
                // what a lapsed deadline means and it is the same place whether
                // the loop arrived there by sleeping or by being busy.
                biased;

                () = sleep_until(deadline) => break Ending::Deadline,

                () = sleep_until(next_revalidate) => {}

                received = inbound.recv() => {
                    match received {
                        Ok(Some(bytes)) => {
                            if let Err(ending) = self.receive(&bytes, deadline).await {
                                break ending;
                            }
                        }
                        Ok(None) => break Ending::PeerClosed,
                        Err(error) => break Ending::Transport(error),
                    }
                }

                () = sleep_until(next_frame) => {}
            }
        };

        self.finish(ending).await
    }

    /// Sends the opening [`Hello`].
    ///
    /// The capability set it advertises is the *effective* one, not the one the
    /// ticket asked for, so a console displays what it actually has. The monitor
    /// list is clipped to [`MAX_MONITORS`] rather than refused: a machine with
    /// seventeen displays should stream sixteen of them, not fail to start.
    async fn greet(
        &mut self,
        live: Capabilities,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let monitors: Vec<Monitor> =
            self.wiring.frames.monitors().iter().take(MAX_MONITORS).copied().collect();
        let hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: self.ceilings.tile,
            max_fps: self.ceilings.max_fps.max(1),
            capabilities: live,
            monitors,
        });
        self.emit(&hello, deadline).await
    }

    /// Re-reads the session's standing and reports what may still be done.
    ///
    /// The one function that talks to [`SessionDirectory`], so the rule that it
    /// must never refresh `last_seen` has exactly one call site to audit.
    fn standing_now(&self) -> Result<Capabilities, Ending> {
        let Some(standing) = self.sessions.standing(&self.session) else {
            return Err(Ending::SessionGone);
        };
        if standing.expires <= moment() {
            return Err(Ending::SessionExpired);
        }
        let live = effective(self.granted, standing.capabilities);
        if !live.contains(Capabilities::VIEW) {
            return Err(Ending::ViewRevoked);
        }
        Ok(live)
    }

    /// One turn of the capture loop: observe, tell the state machine, act on
    /// what it says, and report how long to wait before the next turn.
    async fn pump(
        &mut self,
        live: Capabilities,
        deadline: tokio::time::Instant,
    ) -> Result<Duration, Ending> {
        let budget = frame_interval(self.ceilings.max_fps);
        let mut captured = None;

        let observation = match self.pending_restore.take() {
            Some(what) => match timeout_at(deadline, self.wiring.frames.restore(what)).await {
                Err(_elapsed) => return Err(Ending::Deadline),
                Ok(Err(condition)) => condition.observation(),
                Ok(Ok(())) => {
                    // A rebuilt source shares no history with the client: the
                    // next frame must be a keyframe and the pointer must be
                    // re-sent, because what the client is holding was produced
                    // by an object that no longer exists.
                    self.previous = None;
                    self.previous_monitor = None;
                    self.cursor.forget();
                    Observation::Retry
                }
            },
            None => {
                // Bounded by the wall as well as by the frame budget: a platform
                // call that never returns must not be able to outlive the
                // session it was capturing for.
                let until = deadline.min(tokio::time::Instant::now() + budget);
                match timeout_at(until, self.wiring.frames.next_frame(budget)).await {
                    Err(_elapsed) => Observation::Retry,
                    Ok(Ok(frame)) => {
                        captured = Some(frame);
                        Observation::Frame
                    }
                    Ok(Err(condition)) => condition.observation(),
                }
            }
        };

        let step = self.machine.observe(observation, moment());
        if let Some(notice) = step.notice {
            let detail = notice_detail(step.phase);
            self.emit(&Message::Status { notice, detail }, deadline).await?;
        }

        if let Some(frame) = captured {
            if self.machine.phase() == Phase::Live && live.contains(Capabilities::VIEW) {
                self.send_frame(frame, deadline).await?;
                self.send_pointer(deadline).await?;
            }
        }

        Ok(match step.action {
            // The state machine has no idea what a frame rate is, so the pacing
            // is ours: it says "capture again", `max_fps` says how soon.
            Action::Capture => budget,
            Action::WaitThen(wait) => wait,
            Action::Suspend { poll_after } => poll_after,
            Action::Reinitialise(wait) => {
                self.pending_restore = Some(Restore::Capture);
                wait
            }
            Action::RespawnAgent(wait) => {
                self.pending_restore = Some(Restore::Agent);
                wait
            }
            Action::CloseStreams => {
                return Err(match self.machine.phase() {
                    Phase::GaveUp(surrender) => Ending::GaveUp(surrender),
                    _ => Ending::Stopped,
                })
            }
        })
    }

    /// Diffs one frame against what the client is holding and sends the result,
    /// or drops it for want of credit.
    ///
    /// Dropping keeps [`Viewer::previous`] exactly where it was, which is what
    /// makes the damage merge: the next diff is taken against the last surface
    /// the client actually received, so it contains everything that changed
    /// while the link was starved.
    async fn send_frame(
        &mut self,
        frame: CapturedFrame,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let same_shape = self
            .previous
            .as_ref()
            .is_some_and(|held| held.width() == frame.surface.width() && held.height() == frame.surface.height());
        if !same_shape || self.previous_monitor != Some(frame.monitor) {
            // A resolution change or a different display: nothing the client
            // holds describes these pixels, so the next frame is a keyframe.
            self.previous = None;
        }

        let keyframe = self.previous.is_none();
        let updates = match diff(self.previous.as_ref(), &frame.surface, self.ceilings.tile) {
            Ok(updates) => updates,
            Err(_) => {
                // A surface the grid cannot describe is not a reason to end a
                // session: drop the frame, forget the history, and let the next
                // capture try as a keyframe.
                self.previous = None;
                self.previous_monitor = None;
                return Ok(());
            }
        };
        if updates.is_empty() && !keyframe {
            // A still desktop costs nothing at all — not even a frame marker.
            return Ok(());
        }

        let sequence = self.sequence.wrapping_add(1);
        let tiles = updates.len();
        let mut encoded = Vec::with_capacity(tiles.saturating_add(2));
        encoded.push(encode(&Message::FrameBegin(FrameBegin {
            monitor: frame.monitor,
            sequence,
            width: frame.surface.width(),
            height: frame.surface.height(),
            keyframe,
        }))?);
        for update in updates {
            encoded.push(encode(&Message::Tile(TileMessage {
                monitor: frame.monitor,
                col: update.coord.col,
                row: update.coord.row,
                encoding: update.encoding,
                payload: update.payload,
            }))?);
        }
        encoded.push(encode(&Message::FrameEnd { sequence })?);

        let total: u64 = encoded.iter().map(|frame| frame.len() as u64).sum();
        if u64::from(self.wiring.outbound.credit()) < total {
            self.stats.credit_stalls = self.stats.credit_stalls.saturating_add(1);
            return Ok(());
        }

        for bytes in &encoded {
            self.write(bytes, deadline).await?;
        }
        self.sequence = sequence;
        self.previous = Some(frame.surface);
        self.previous_monitor = Some(frame.monitor);
        self.stats.frames_sent = self.stats.frames_sent.saturating_add(1);
        self.stats.tiles_sent = self.stats.tiles_sent.saturating_add(tiles as u64);
        Ok(())
    }

    /// Sends whatever the pointer policy says the client is missing.
    ///
    /// The bitmap goes first: a [`Message::CursorShape`] carries no position, so
    /// a client that received the position first would draw the old shape at the
    /// new place for one frame.
    async fn send_pointer(&mut self, deadline: tokio::time::Instant) -> Result<(), Ending> {
        let pointer = match timeout_at(deadline, self.wiring.pointer.pointer()).await {
            Err(_elapsed) => return Err(Ending::Deadline),
            Ok(None) => return Ok(()),
            Ok(Some(pointer)) => pointer,
        };
        let emission = self.cursor.observe(pointer);
        if emission.is_empty() {
            return Ok(());
        }

        let mut messages = Vec::new();
        if let Some(id) = emission.shape {
            match timeout_at(deadline, self.wiring.pointer.shape(id)).await {
                Err(_elapsed) => return Err(Ending::Deadline),
                Ok(Some(shape)) => match cursor_message(id, &shape) {
                    Some(message) => messages.push(message),
                    None => {
                        // Dropped once and deliberately not retried: the cache
                        // now holds the id, so a platform that keeps reporting a
                        // malformed bitmap costs one refusal rather than the
                        // pointer's whole bandwidth budget every frame.
                        self.stats.unusable_shapes = self.stats.unusable_shapes.saturating_add(1);
                    }
                },
                Ok(None) => {
                    self.stats.unusable_shapes = self.stats.unusable_shapes.saturating_add(1);
                }
            }
        }
        if let Some(position) = emission.position {
            messages.push(Message::CursorPos(CursorPos {
                x: position.x,
                y: position.y,
                visible: position.visible,
            }));
        }

        let mut encoded = Vec::with_capacity(messages.len());
        for message in &messages {
            encoded.push(encode(message)?);
        }
        let total: u64 = encoded.iter().map(|frame| frame.len() as u64).sum();
        if u64::from(self.wiring.outbound.credit()) < total {
            // Unlike a frame, a skipped cursor update does not merge on its own:
            // the policy has already recorded the shape as sent. Forgetting puts
            // both back on the wire the next time there is credit for them.
            self.cursor.forget();
            self.stats.cursor_stalls = self.stats.cursor_stalls.saturating_add(1);
            return Ok(());
        }
        for bytes in &encoded {
            self.write(bytes, deadline).await?;
        }
        Ok(())
    }

    /// Handles one message from the viewer.
    async fn receive(
        &mut self,
        bytes: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let message = Message::decode(bytes).map_err(Ending::PeerMisbehaved)?;
        if message.direction() != Direction::ToAgent {
            // Not pedantry: a peer that can inject a `Status` or a `Tile` into
            // the server's own inbox is a peer probing for a parser that treats
            // the two directions as one.
            return Err(Ending::WrongDirection { kind: message.kind() });
        }

        match &message {
            // Never refused, at any capability, in any phase. It only ever
            // *undoes* — refusing it would leave a modifier held on the far
            // machine, which is the worst ordinary outcome this subsystem has.
            Message::ReleaseAll => self.release_everything(deadline).await,

            Message::RequestFullFrame { .. } => {
                self.previous = None;
                self.previous_monitor = None;
                self.cursor.forget();
                Ok(())
            }

            Message::Key { .. }
            | Message::Text { .. }
            | Message::PointerMove { .. }
            | Message::Button { .. }
            | Message::Scroll { .. } => self.drive(&message, deadline).await,

            // Unreachable: every remaining kind travels `ToViewer` and was
            // refused above. Written as a refusal rather than an `unreachable!`
            // because this process aborts on panic and a wrong `match` arm must
            // cost a session, not the box.
            _ => Err(Ending::WrongDirection { kind: message.kind() }),
        }
    }

    /// Authorises one input message and, if it passes, injects it.
    ///
    /// The authorisation is re-derived here, from the directory, on **every**
    /// message. Nothing is remembered from the handshake, so a capability
    /// revoked in the console is felt by the very next keystroke.
    async fn drive(
        &mut self,
        message: &Message,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let live = self.standing_now()?;
        if let Some(reason) = input_refusal(live, self.ceilings.allow_input, self.machine.phase()) {
            self.stats.inputs_refused = self.stats.inputs_refused.saturating_add(1);
            return self.emit(&Message::InputRefused { reason }, deadline).await;
        }

        // Recorded *before* the injection, so that a link dying between the two
        // still leaves the close path with something to release.
        if !self.track(message) {
            self.stats.inputs_ignored = self.stats.inputs_ignored.saturating_add(1);
            return Ok(());
        }

        match timeout_at(deadline, self.wiring.input.deliver(message)).await {
            Err(_elapsed) => Err(Ending::Deadline),
            Ok(Ok(())) => {
                self.stats.inputs_delivered = self.stats.inputs_delivered.saturating_add(1);
                Ok(())
            }
            Ok(Err(reason)) => {
                self.stats.inputs_refused = self.stats.inputs_refused.saturating_add(1);
                self.emit(&Message::InputRefused { reason }, deadline).await
            }
        }
    }

    /// Records what one input does to the far machine's held state, and says
    /// whether it is worth forwarding at all.
    ///
    /// A release for something that was never held is dropped rather than
    /// passed on: some platforms treat a spurious key-up as a key-down, and a
    /// viewer reconnecting mid-chord sends exactly that.
    fn track(&mut self, message: &Message) -> bool {
        match message {
            Message::Key { usage, down: true } => {
                self.held.press(*usage);
                true
            }
            Message::Key { usage, down: false } => self.held.release(*usage),
            Message::Button { button, down: true } => {
                self.buttons.press(*button);
                true
            }
            Message::Button { button, down: false } => self.buttons.release(*button),
            _ => true,
        }
    }

    /// Lifts everything this stream is holding down on the far machine.
    ///
    /// Keys first and in usage order, which puts modifiers last: releasing
    /// Control before `C` can be observed by the far machine as a bare `C`
    /// arriving in whatever window has focus.
    async fn release_everything(&mut self, deadline: tokio::time::Instant) -> Result<(), Ending> {
        let keys: Vec<Usage> = self.held.drain();
        let buttons = self.buttons.drain();
        for usage in keys {
            self.lift(&Message::Key { usage, down: false }, deadline).await;
        }
        for button in buttons {
            self.lift(&Message::Button { button, down: false }, deadline).await;
        }
        Ok(())
    }

    /// Injects one release, ignoring a refusal.
    ///
    /// A release is the one event whose failure is not worth reporting to
    /// anybody: the alternative to trying is leaving the key down, and the
    /// console cannot act on the difference.
    async fn lift(&mut self, message: &Message, deadline: tokio::time::Instant) {
        if timeout_at(deadline, self.wiring.input.deliver(message)).await.is_ok() {
            self.stats.released_on_close = self.stats.released_on_close.saturating_add(1);
        }
    }

    /// Encodes and writes one message.
    async fn emit(
        &mut self,
        message: &Message,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let bytes = encode(message)?;
        self.write(&bytes, deadline).await
    }

    /// Writes bytes, bounded by the wall.
    ///
    /// The bound is what makes the deadline a deadline: a peer that stops
    /// reading would otherwise hold a write open indefinitely and keep a dead
    /// session's stream alive by doing nothing at all.
    async fn write(&mut self, bytes: &[u8], deadline: tokio::time::Instant) -> Result<(), Ending> {
        match timeout_at(deadline, self.wiring.outbound.send(bytes)).await {
            Err(_elapsed) => Err(Ending::Deadline),
            Ok(Err(error)) => Err(Ending::Transport(error)),
            Ok(Ok(())) => {
                self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(bytes.len() as u64);
                Ok(())
            }
        }
    }

    /// The close sequence: release, tell, hang up — all of it inside one grace
    /// period, and none of it waiting for the peer.
    async fn finish(mut self, ending: Ending) -> Outcome {
        let grace = tokio::time::Instant::now() + self.ceilings.close_grace;
        // The whole sequence shares one deadline rather than one each, because
        // the thing that makes a close hang — a tunnel that has already dropped
        // — makes every step of it hang, and three grace periods in series is
        // three times as long as intended.
        let _ = timeout_at(grace, async {
            // Released first, and unconditionally: this is the failure the far
            // machine actually feels, and it does not depend on the peer still
            // being there.
            let _ = self.release_everything(grace).await;
            if ending.peer_is_listening() {
                let status = Message::Status {
                    notice: self.machine.phase().notice(),
                    detail: ending.to_string(),
                };
                if let Ok(bytes) = status.encode() {
                    let _ = self.wiring.outbound.send(&bytes).await;
                }
                let _ = self.wiring.outbound.close(&ending).await;
            }
        })
        .await;

        Outcome { ending, stats: self.stats }
    }
}

/// Now, in the clock the pure modules compare against.
///
/// Taken from the runtime rather than from `std::time::Instant::now` so that
/// every wall in the driver moves together: the stream deadline, the session's
/// expiry and the state machine's healthy window are compared against one
/// clock. Under a paused test clock a real `Instant::now` would sit still while
/// the deadline advanced, and the two would disagree about what "now" means —
/// which is exactly the class of bug these tests exist to catch.
fn moment() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Encodes a message, turning an encoding failure into an [`Ending`].
///
/// A failure here is a bug on this side rather than anything a peer did, so it
/// ends the stream loudly instead of being dropped: silently omitting a tile
/// leaves the client displaying pixels that are no longer there.
fn encode(message: &Message) -> Result<Vec<u8>, Ending> {
    message.encode().map_err(Ending::Encoding)
}

/// The extra detail sent alongside a [`Notice`], for the diagnostics plate.
///
/// Empty for the phases whose notice already says everything. The console
/// renders the notice code; this is only ever prose.
fn notice_detail(phase: Phase) -> String {
    match phase {
        Phase::Recovering { attempt } => format!("rebuild attempt {attempt}"),
        Phase::GaveUp(Surrender::TooManyReinitialisations) => "the screen source kept failing".into(),
        Phase::GaveUp(Surrender::AgentUnrecoverable) => "the agent kept exiting".into(),
        Phase::GaveUp(Surrender::Fatal) => "unrecoverable".into(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Notice;
    use crate::tiles::{apply, Decoded, Encoding};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::mpsc;

    /// A monitor to advertise; the numbers are arbitrary and only their
    /// round-trip matters.
    fn monitor(id: u8) -> Monitor {
        Monitor {
            id,
            origin_x: 0,
            origin_y: 0,
            width: 128,
            height: 64,
            scale_permille: 1000,
            primary: id == 0,
        }
    }

    /// A 128×64 surface — two 64-pixel tiles wide, one tall — painted with a
    /// per-tile constant so a diff has something unambiguous to find.
    fn surface(left: u8, right: u8) -> Surface {
        let mut pixels = vec![0u8; 128 * 64 * 4];
        for row in 0..64usize {
            for col in 0..128usize {
                let value = if col < 64 { left } else { right };
                let at = (row * 128 + col) * 4;
                pixels[at] = value;
                pixels[at + 1] = value;
                pixels[at + 2] = value;
                pixels[at + 3] = 0xFF;
            }
        }
        Surface::new(128, 64, pixels).expect("a tight buffer")
    }

    /// One step of a scripted capture source.
    enum Beat {
        /// Hand out these pixels.
        Frame(Surface),
        /// Report this instead.
        Condition(Condition),
        /// Grant the peer's credit window, and report nothing this turn.
        Grant(u32),
        /// Never answer at all.
        Hang,
    }

    /// A capture source that reads from a script and then reports `Retry`
    /// forever.
    struct ScriptedFrames {
        monitors: Vec<Monitor>,
        script: VecDeque<Beat>,
        credit: Arc<AtomicU32>,
        restores: Vec<Restore>,
    }

    impl ScriptedFrames {
        fn new(script: Vec<Beat>, credit: Arc<AtomicU32>) -> Self {
            Self {
                monitors: vec![monitor(0)],
                script: script.into(),
                credit,
                restores: Vec::new(),
            }
        }
    }

    impl FrameSource for ScriptedFrames {
        fn monitors(&self) -> &[Monitor] {
            &self.monitors
        }

        fn next_frame(&mut self, _budget: Duration) -> Task<'_, Result<CapturedFrame, Condition>> {
            let beat = self.script.pop_front();
            let credit = Arc::clone(&self.credit);
            Box::pin(async move {
                match beat {
                    Some(Beat::Frame(surface)) => Ok(CapturedFrame { monitor: 0, surface }),
                    Some(Beat::Condition(condition)) => Err(condition),
                    Some(Beat::Grant(bytes)) => {
                        credit.store(bytes, Ordering::SeqCst);
                        Err(Condition::Retry)
                    }
                    Some(Beat::Hang) => std::future::pending().await,
                    None => Err(Condition::Retry),
                }
            })
        }

        fn restore(&mut self, what: Restore) -> Task<'_, Result<(), Condition>> {
            self.restores.push(what);
            Box::pin(async { Ok(()) })
        }
    }

    /// A writing half that records everything, with a settable credit window.
    struct Recorder {
        sent: Vec<Message>,
        credit: Arc<AtomicU32>,
        closed: Option<Ending>,
        broken: bool,
    }

    impl Recorder {
        fn new(credit: Arc<AtomicU32>) -> Self {
            Self { sent: Vec::new(), credit, closed: None, broken: false }
        }

        /// Every tile message, in order.
        fn tiles(&self) -> Vec<&TileMessage> {
            self.sent
                .iter()
                .filter_map(|message| match message {
                    Message::Tile(tile) => Some(tile),
                    _ => None,
                })
                .collect()
        }

        fn refusals(&self) -> Vec<Refusal> {
            self.sent
                .iter()
                .filter_map(|message| match message {
                    Message::InputRefused { reason } => Some(*reason),
                    _ => None,
                })
                .collect()
        }
    }

    impl Outbound for Recorder {
        fn send<'a>(&'a mut self, frame: &'a [u8]) -> Task<'a, Result<(), StreamError>> {
            Box::pin(async move {
                if self.broken {
                    return Err(StreamError::Closed);
                }
                // Decoding what we just encoded keeps the fake honest: a
                // message the driver cannot round-trip fails the test rather
                // than being asserted on in a shape the peer never sees.
                let message = Message::decode(frame).expect("the driver encodes decodable messages");
                let spent = frame.len() as u32;
                let held = self.credit.load(Ordering::SeqCst);
                self.credit.store(held.saturating_sub(spent), Ordering::SeqCst);
                self.sent.push(message);
                Ok(())
            })
        }

        fn credit(&self) -> u32 {
            self.credit.load(Ordering::SeqCst)
        }

        fn close<'a>(&'a mut self, ending: &'a Ending) -> Task<'a, Result<(), StreamError>> {
            Box::pin(async move {
                self.closed = Some(ending.clone());
                Ok(())
            })
        }
    }

    /// A reading half over a channel, which is cancel-safe as the trait
    /// requires.
    struct Channel(mpsc::UnboundedReceiver<Vec<u8>>);

    impl Inbound for Channel {
        fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }

    /// A reading half that answers instantly and forever: the peer that ignores
    /// a close.
    struct Relentless;

    impl Inbound for Relentless {
        fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
            Box::pin(async {
                // A yield rather than nothing at all, so the runtime can still
                // reach its timers — a peer that spins without yielding is a
                // different failure, and one the runtime, not the driver, owns.
                tokio::task::yield_now().await;
                Ok(Some(Message::ReleaseAll.encode().expect("release-all encodes")))
            })
        }
    }

    /// A reading half with a fixed number of messages already buffered, handed
    /// over as fast as the driver will take them, and silent afterwards.
    ///
    /// Not a contrivance: this is exactly the shape of the real inbound half —
    /// [`crate::viewer::Inbound`] is required to be cancel-safe precisely
    /// because it reads from a channel the socket pump has already filled, so a
    /// peer that sends input faster than the driver consumes it makes `recv`
    /// ready on every poll.
    struct Flood {
        /// Never completes on the first poll, so the driver's capture arm runs
        /// once and the session reaches [`Phase::Live`] — the state a viewer
        /// that has been watching a screen is in by the time it starts typing.
        /// The select drops that future; every call after it is ready at once.
        primed: bool,
        bytes: Vec<u8>,
    }

    impl Inbound for Flood {
        fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
            Box::pin(async move {
                if !self.primed {
                    self.primed = true;
                    std::future::pending::<()>().await;
                }
                Ok(Some(self.bytes.clone()))
            })
        }
    }

    /// A reading half that never speaks.
    struct Silent;

    impl Inbound for Silent {
        fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
            Box::pin(std::future::pending())
        }
    }

    /// A pointer that stays where it is, with a shape the test chooses.
    struct FixedPointer {
        pointer: Option<Pointer>,
        shape: Option<PointerShape>,
        shapes_asked: usize,
    }

    impl FixedPointer {
        fn none() -> Self {
            Self { pointer: None, shape: None, shapes_asked: 0 }
        }

        fn at(x: i32, y: i32, shape: ShapeId, bitmap: Option<PointerShape>) -> Self {
            Self {
                pointer: Some(Pointer { x, y, visible: true, shape }),
                shape: bitmap,
                shapes_asked: 0,
            }
        }
    }

    impl PointerSource for FixedPointer {
        fn pointer(&mut self) -> Task<'_, Option<Pointer>> {
            let pointer = self.pointer;
            Box::pin(async move { pointer })
        }

        fn shape(&mut self, _id: ShapeId) -> Task<'_, Option<PointerShape>> {
            self.shapes_asked = self.shapes_asked.saturating_add(1);
            let shape = self.shape.clone();
            Box::pin(async move { shape })
        }
    }

    /// An injector that records what it was handed.
    #[derive(Default)]
    struct Recording {
        delivered: Vec<Message>,
        refuse: Option<Refusal>,
    }

    impl InputSink for Recording {
        fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>> {
            Box::pin(async move {
                if let Some(reason) = self.refuse {
                    return Err(reason);
                }
                self.delivered.push(message.clone());
                Ok(())
            })
        }
    }

    /// A session store a test can revoke or expire under a running stream.
    struct Store(Mutex<Option<Standing>>);

    impl Store {
        fn holding(capabilities: Capabilities, for_how_long: Duration) -> Self {
            Self(Mutex::new(Some(Standing {
                expires: Instant::now() + for_how_long,
                capabilities,
            })))
        }

        fn set(&self, standing: Option<Standing>) {
            *self.0.lock().expect("uncontended") = standing;
        }
    }

    impl SessionDirectory for Store {
        fn standing(&self, _session: &SessionId) -> Option<Standing> {
            *self.0.lock().expect("uncontended")
        }
    }

    fn redemption(capabilities: Capabilities) -> Redemption {
        Redemption {
            session: SessionId::new("s-1"),
            peer: "self".into(),
            capabilities,
        }
    }

    /// Ceilings that make a test finish in milliseconds of virtual time.
    fn quick() -> Ceilings {
        Ceilings {
            max_fps: 60,
            max_session: Duration::from_secs(30),
            revalidate_every: Duration::from_secs(60),
            close_grace: Duration::from_millis(50),
            ..Ceilings::default()
        }
    }

    /// A gate with room to spare, and its seat.
    fn seat() -> Seat {
        Gate::new(4).admit("self").expect("an empty gate admits")
    }

    // ---- the pure halves ------------------------------------------------

    #[test]
    fn a_frame_interval_is_never_zero() {
        // A zero interval makes the frame arm of the select always ready, which
        // starves the deadline arm — the bug this clamp exists to prevent.
        assert_eq!(frame_interval(0), Duration::from_secs(1));
        assert_eq!(frame_interval(1), Duration::from_secs(1));
        assert_eq!(frame_interval(30), Duration::from_secs(1) / 30);
        assert_eq!(frame_interval(255), Duration::from_secs(1) / 255);
    }

    #[test]
    fn the_deadline_is_the_earlier_of_the_two_walls() {
        let started = Instant::now();
        let session_wall = started + Duration::from_secs(600);

        // The ceiling bites first.
        assert_eq!(
            stream_deadline(started, session_wall, Duration::from_secs(60)),
            started + Duration::from_secs(60)
        );
        // The session's own expiry bites first.
        assert_eq!(
            stream_deadline(started, session_wall, Duration::from_secs(6000)),
            session_wall
        );
        // A ceiling nobody could have meant does not abort the daemon.
        assert_eq!(stream_deadline(started, session_wall, Duration::MAX), session_wall);
    }

    #[test]
    fn input_is_refused_for_the_reason_an_operator_can_act_on() {
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);

        // The config switch is named before the grant, because that is where
        // the fix is.
        assert_eq!(input_refusal(control, false, Phase::Live), Some(Refusal::InputDisabled));
        assert_eq!(
            input_refusal(Capabilities::VIEW, true, Phase::Live),
            Some(Refusal::NotPermitted)
        );
        assert_eq!(
            input_refusal(control, true, Phase::Suspended(Suspension::SecureDesktop)),
            Some(Refusal::SecureDesktop)
        );
        assert_eq!(
            input_refusal(control, true, Phase::Suspended(Suspension::NoUser)),
            Some(Refusal::NotLive)
        );
        assert_eq!(input_refusal(control, true, Phase::Recovering { attempt: 1 }), Some(Refusal::NotLive));
        assert_eq!(input_refusal(control, true, Phase::Live), None);
    }

    #[test]
    fn capabilities_are_the_intersection_of_ticket_and_session() {
        let full = Capabilities::VIEW.with(Capabilities::CONTROL).with(Capabilities::CLIPBOARD);
        assert_eq!(effective(full, Capabilities::VIEW), Capabilities::VIEW);
        assert_eq!(effective(Capabilities::VIEW, full), Capabilities::VIEW);
        // A session that lost VIEW leaves nothing at all, not "control only",
        // which `Capabilities::from_bits` would refuse anyway.
        assert_eq!(effective(full, Capabilities::none()), Capabilities::none());
    }

    #[test]
    fn the_gate_admits_up_to_the_limit_and_releases_on_drop() {
        let gate = Gate::new(2);
        let first = gate.admit("box").expect("first");
        let second = gate.admit("box").expect("second");
        assert_eq!(gate.streams("box"), 2);
        assert_eq!(gate.admit("box").unwrap_err(), AtCapacity { running: 2, limit: 2 });
        // A different peer has its own budget.
        let other = gate.admit("worker").expect("a different peer");
        drop(other);

        drop(second);
        assert_eq!(gate.streams("box"), 1);
        let third = gate.admit("box").expect("a seat came free");
        drop(third);
        drop(first);
        assert_eq!(gate.streams("box"), 0);
    }

    #[test]
    fn a_limit_of_zero_admits_nothing() {
        let gate = Gate::new(0);
        assert!(gate.admit("box").is_err());
    }

    #[test]
    fn a_cursor_bitmap_that_cannot_be_expressed_is_refused_rather_than_sent() {
        let id = ShapeId(7);
        let good = PointerShape {
            hotspot_x: 1,
            hotspot_y: 1,
            width: 2,
            height: 2,
            pixels: vec![0; 16],
        };
        assert!(cursor_message(id, &good).is_some());

        let short = PointerShape { pixels: vec![0; 15], ..good.clone() };
        assert!(cursor_message(id, &short).is_none());
        let huge = PointerShape {
            width: MAX_CURSOR_EDGE + 1,
            height: 1,
            pixels: vec![0; usize::from(MAX_CURSOR_EDGE + 1) * 4],
            ..good.clone()
        };
        assert!(cursor_message(id, &huge).is_none());
        let empty = PointerShape { width: 0, height: 0, pixels: Vec::new(), ..good };
        assert!(cursor_message(id, &empty).is_none());
    }

    #[test]
    fn held_buttons_round_trip_and_release_in_a_stable_order() {
        let mut held = HeldButtons::default();
        held.press(Button::Right);
        held.press(Button::Left);
        assert!(held.release(Button::Right));
        assert!(!held.release(Button::Right));
        held.press(Button::Forward);
        assert_eq!(held.drain(), vec![Button::Left, Button::Forward]);
        assert_eq!(held.drain(), Vec::new());
    }

    // ---- the driver -----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn the_handshake_advertises_what_the_session_actually_has() {
        // The ticket asked for control; the session holds only view. The
        // console must be told the truth rather than what it asked for.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Condition(Condition::Fatal)], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW.with(Capabilities::CONTROL)),
            quick(),
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.ending, Ending::GaveUp(Surrender::Fatal));
        match out.sent.first() {
            Some(Message::Hello(hello)) => {
                assert_eq!(hello.protocol, PROTOCOL_VERSION);
                assert_eq!(hello.capabilities, Capabilities::VIEW);
                assert_eq!(hello.monitors, vec![monitor(0)]);
                assert_eq!(hello.max_fps, 60);
            }
            other => panic!("the first message must be HELLO, got {other:?}"),
        }
        assert_eq!(out.closed, Some(Ending::GaveUp(Surrender::Fatal)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_still_desktop_sends_one_keyframe_and_then_nothing() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(
            vec![
                Beat::Frame(surface(1, 2)),
                Beat::Frame(surface(1, 2)),
                Beat::Frame(surface(1, 2)),
                Beat::Condition(Condition::Fatal),
            ],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.stats.frames_sent, 1, "only the keyframe costs anything");
        assert_eq!(outcome.stats.tiles_sent, 2, "two tiles across a 128-pixel row");
        let begins = out
            .sent
            .iter()
            .filter(|message| matches!(message, Message::FrameBegin(_)))
            .count();
        assert_eq!(begins, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_starved_viewer_drops_frames_and_merges_the_damage() {
        // No credit at all for two changed frames, then a window big enough for
        // one. What arrives must describe the *latest* picture, not a backlog:
        // that is the whole reason the driver drops rather than queues.
        let credit = Arc::new(AtomicU32::new(0));
        let mut frames = ScriptedFrames::new(
            vec![
                Beat::Frame(surface(1, 1)),
                Beat::Frame(surface(2, 2)),
                Beat::Frame(surface(3, 4)),
                Beat::Grant(1 << 20),
                Beat::Frame(surface(3, 4)),
                Beat::Condition(Condition::Fatal),
            ],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.stats.credit_stalls, 3, "three frames declined for want of credit");
        assert_eq!(outcome.stats.frames_sent, 1);

        // Reconstruct what the client is holding and compare it to the last
        // thing that was captured. The merge is correct exactly when they match.
        let mut client = Surface::blank(128, 64).expect("a blank client surface");
        for tile in out.tiles() {
            apply(
                &mut client,
                TileSize::DEFAULT,
                &crate::tiles::TileUpdate {
                    coord: tile.coord(),
                    encoding: tile.encoding,
                    payload: tile.payload.clone(),
                },
            )
            .expect("every tile the driver sent applies");
        }
        assert_eq!(client, surface(3, 4));
    }

    #[tokio::test(start_paused = true)]
    async fn the_secure_desktop_shows_nothing_and_refuses_input() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        // One frame, then the secure desktop for the rest of the stream: an
        // exhausted script reports `Retry`, which leaves the phase exactly
        // where it was.
        let mut frames = ScriptedFrames::new(
            vec![Beat::Frame(surface(1, 1)), Beat::Condition(Condition::SecureDesktop)],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let store = Store::holding(
            Capabilities::VIEW.with(Capabilities::CONTROL),
            Duration::from_secs(600),
        );
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.allow_input = true;
        ceilings.max_session = Duration::from_millis(400);

        let key = Message::Key { usage: Usage::from_code("KeyA").expect("KeyA exists"), down: true };
        // Sent late enough that the secure desktop is already in front. The
        // driver is paced at 60 fps, so two frames have gone by.
        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let _ = sender.send(key.encode().expect("a key encodes"));
            // Hold the channel open so the stream ends on its deadline rather
            // than on the peer hanging up.
            tokio::time::sleep(Duration::from_millis(600)).await;
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW.with(Capabilities::CONTROL)),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");

        assert_eq!(outcome.ending, Ending::Deadline);
        assert_eq!(out.refusals(), vec![Refusal::SecureDesktop]);
        assert!(input.delivered.is_empty(), "nothing is injected on the secure desktop");
        // Exactly one frame: the one captured before the secure desktop came up.
        assert_eq!(outcome.stats.frames_sent, 1);
        assert!(
            out.sent.iter().any(|message| matches!(
                message,
                Message::Status { notice: Notice::SecureDesktop, .. }
            )),
            "the console is told why the picture stopped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_expires_mid_stream_is_closed_by_the_server() {
        // The session outlives the handshake but not the first re-read. Note
        // that nothing the peer does can extend it: the driver never refreshes
        // `last_seen`.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Frame(surface(1, 1))], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Arc::new(Store::holding(Capabilities::VIEW, Duration::from_secs(600)));

        let mut ceilings = quick();
        ceilings.revalidate_every = Duration::from_millis(50);
        ceilings.max_session = Duration::from_secs(3600);

        // Brought forward under the running stream, so the wall computed at the
        // handshake is not what catches it — the re-read is.
        let expirer = Arc::clone(&store);
        let clock = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            expirer.set(Some(Standing {
                expires: Instant::now(),
                capabilities: Capabilities::VIEW,
            }));
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            store.as_ref(),
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        let outcome = viewer.run(&mut Silent).await;
        clock.await.expect("the clock task finishes");

        assert_eq!(outcome.ending, Ending::SessionExpired);
        assert!(outcome.stats.revalidations >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_disappears_mid_stream_ends_the_stream_on_the_timer() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.revalidate_every = Duration::from_millis(50);
        store.set(None);

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        assert_eq!(viewer.run(&mut Silent).await.ending, Ending::SessionGone);
    }

    #[tokio::test(start_paused = true)]
    async fn control_revoked_mid_stream_refuses_the_very_next_key() {
        // The 60-second timer is not what catches this: the per-message check
        // is, which is the whole point of re-deriving the capability rather
        // than remembering the handshake's answer.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Frame(surface(1, 1))], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);
        let store = Arc::new(Store::holding(control, Duration::from_secs(600)));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.allow_input = true;
        // Long enough that the timer never fires during the test.
        ceilings.revalidate_every = Duration::from_secs(3600);
        ceilings.max_session = Duration::from_millis(300);

        let key = Message::Key { usage: Usage::from_code("KeyA").expect("KeyA exists"), down: true };
        let bytes = key.encode().expect("a key encodes");

        let revoker = Arc::clone(&store);
        let feeder = tokio::spawn(async move {
            // After the first frame, so the session is Live and the key is
            // judged on its capability rather than on the phase.
            tokio::time::sleep(Duration::from_millis(40)).await;
            sender.send(bytes.clone()).expect("the stream is listening");
            tokio::time::sleep(Duration::from_millis(40)).await;
            revoker.set(Some(Standing {
                expires: Instant::now() + Duration::from_secs(600),
                capabilities: Capabilities::VIEW,
            }));
            sender.send(bytes).expect("the stream is still listening");
            // Held open so the stream ends on its own wall rather than on the
            // peer hanging up.
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            store.as_ref(),
            seat(),
            &redemption(control),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");
        assert_eq!(outcome.ending, Ending::Deadline);
        assert_eq!(outcome.stats.inputs_delivered, 1, "the first key was permitted");
        assert_eq!(out.refusals(), vec![Refusal::NotPermitted], "the second was not");
        // The press, and the release the server made on its own at the close —
        // a key held by a downgraded viewer is still a key held down.
        let usage = Usage::from_code("KeyA").expect("KeyA exists");
        assert_eq!(
            input.delivered,
            vec![
                Message::Key { usage, down: true },
                Message::Key { usage, down: false },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn view_revoked_mid_stream_ends_the_stream() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.revalidate_every = Duration::from_millis(50);
        store.set(Some(Standing {
            expires: Instant::now() + Duration::from_secs(600),
            capabilities: Capabilities::none(),
        }));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        assert_eq!(viewer.run(&mut Silent).await.ending, Ending::ViewRevoked);
    }

    #[tokio::test]
    async fn a_peer_that_ignores_the_close_does_not_keep_the_stream_alive() {
        // Real time, small numbers: the peer answers instantly and forever, so
        // the only thing that can end this stream is the server's own wall.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.max_session = Duration::from_millis(60);
        ceilings.close_grace = Duration::from_millis(20);

        let began = std::time::Instant::now();
        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        let outcome = viewer.run(&mut Relentless).await;
        let took = began.elapsed();

        assert_eq!(outcome.ending, Ending::Deadline);
        assert!(took < Duration::from_secs(2), "the wall held: {took:?}");
        assert_eq!(out.closed, Some(Ending::Deadline));
    }

    #[tokio::test(start_paused = true)]
    async fn a_capture_that_never_answers_does_not_outlive_the_deadline() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Hang], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.max_session = Duration::from_millis(200);

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        assert_eq!(viewer.run(&mut Silent).await.ending, Ending::Deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn everything_held_is_released_when_the_stream_ends() {
        // The failure this exists for: a link that drops mid-drag. Nothing asks
        // for the release and the peer is already gone when it happens.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Frame(surface(1, 1))], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);
        let store = Store::holding(control, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.allow_input = true;

        let meta = Usage::from_code("MetaLeft").expect("MetaLeft exists");
        let letter = Usage::from_code("KeyC").expect("KeyC exists");
        let feeder = tokio::spawn(async move {
            // After the first frame: input before a session is live is refused,
            // and a refused key is not a held key.
            tokio::time::sleep(Duration::from_millis(40)).await;
            for message in [
                Message::Key { usage: meta, down: true },
                Message::Key { usage: letter, down: true },
                Message::Button { button: Button::Left, down: true },
            ] {
                sender.send(message.encode().expect("encodes")).expect("listening");
            }
            // Dropping the sender is the link vanishing mid-drag.
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(control),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");

        assert_eq!(outcome.ending, Ending::PeerClosed);
        assert_eq!(outcome.stats.released_on_close, 3);
        let tail: Vec<&Message> = input.delivered.iter().rev().take(3).collect();
        // Ordinary keys before modifiers, then the button: releasing Control
        // before `C` can be observed as a bare `C` in whatever has focus.
        assert_eq!(tail[2], &Message::Key { usage: letter, down: false });
        assert_eq!(tail[1], &Message::Key { usage: meta, down: false });
        assert_eq!(tail[0], &Message::Button { button: Button::Left, down: false });
    }

    #[tokio::test]
    async fn a_flood_of_input_cannot_outrun_the_operators_kill_switch() {
        // The one thing an operator can do when the console itself is the
        // surface an attacker holds is put a file on the disk. That decision
        // reaches a running stream through exactly one path — the capture arm
        // observing [`Condition::Stopped`] — so a peer that can keep the
        // capture arm from ever running is a peer that keeps its keyboard after
        // the switch is engaged. Input arrives on a channel the socket pump
        // fills, so "always another message ready" is not exotic: it is what a
        // client streaming pointer samples at any rate above the frame rate
        // looks like from here.
        // Real time, deliberately: the failure is a scheduling one, and a paused
        // clock cannot express it — virtual time does not advance while a task
        // has work to do, so the arm that never gets to run also never becomes
        // overdue.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        // One frame — the session goes live and the peer starts typing — and
        // then the switch, reported on every capture from that moment on.
        let mut frames = ScriptedFrames::new(
            vec![Beat::Frame(surface(1, 1)), Beat::Condition(Condition::Stopped)],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);
        let store = Store::holding(control, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.allow_input = true;
        // The wall is the *other* way this stream could end. If the switch is
        // what closes it, it closes one frame interval after the flood starts;
        // if only the wall closes it, the peer kept its keyboard for the whole
        // of this.
        ceilings.max_session = Duration::from_millis(400);

        let usage = Usage::from_code("KeyA").expect("KeyA exists");
        let mut inbound = Flood {
            primed: false,
            bytes: Message::Key { usage, down: true }.encode().expect("a key encodes"),
        };

        let began = std::time::Instant::now();
        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(control),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        let took = began.elapsed();

        assert_eq!(
            outcome.ending,
            Ending::Stopped,
            "the peer kept a keyboard the operator had revoked: {:?} after {took:?}, \
             {} input(s) delivered",
            outcome.ending,
            outcome.stats.inputs_delivered,
        );
        assert!(took < Duration::from_millis(300), "the switch was slow to land: {took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn release_all_is_honoured_even_with_no_capability_at_all() {
        // It only ever undoes, so refusing it would be strictly worse than
        // obeying it.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        sender.send(Message::ReleaseAll.encode().expect("encodes")).expect("listening");
        drop(sender);

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut inbound).await;

        assert_eq!(outcome.ending, Ending::PeerClosed);
        assert!(out.refusals().is_empty(), "RELEASE_ALL is never refused");
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_only_the_server_may_send_ends_the_stream() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let forged = Message::FrameEnd { sequence: 1 }.encode().expect("encodes");
        sender.send(forged).expect("listening");

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut inbound).await;

        assert!(matches!(outcome.ending, Ending::WrongDirection { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_that_does_not_decode_ends_the_stream() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        sender.send(vec![0xFE, 0x00, 0x00]).expect("listening");

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut inbound).await;

        assert!(matches!(outcome.ending, Ending::PeerMisbehaved(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_rebuilt_capture_source_starts_again_with_a_keyframe() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(
            vec![
                Beat::Frame(surface(1, 1)),
                Beat::Condition(Condition::Reinitialise),
                Beat::Frame(surface(1, 1)),
                Beat::Condition(Condition::Fatal),
            ],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.limits.base_delay = Duration::from_millis(5);

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.ending, Ending::GaveUp(Surrender::Fatal));
        assert_eq!(frames.restores, vec![Restore::Capture]);
        // Identical pixels, but the client's history died with the old capture
        // object, so the second frame is a keyframe rather than an empty diff.
        let keyframes = out
            .sent
            .iter()
            .filter(|message| matches!(message, Message::FrameBegin(frame) if frame.keyframe))
            .count();
        assert_eq!(keyframes, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_frame_request_resends_everything() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        // The same picture over and over: without the request, exactly one
        // keyframe would ever be sent.
        let mut frames = ScriptedFrames::new(
            (0..10).map(|_| Beat::Frame(surface(1, 1))).collect(),
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.max_fps = 20;
        ceilings.max_session = Duration::from_millis(300);

        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            sender
                .send(Message::RequestFullFrame { monitor: 0 }.encode().expect("encodes"))
                .expect("listening");
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");

        assert_eq!(outcome.ending, Ending::Deadline);
        assert_eq!(outcome.stats.frames_sent, 2, "the keyframe, then the one that was asked for");
    }

    #[tokio::test(start_paused = true)]
    async fn the_pointer_travels_once_per_shape_and_position_follows_it() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(
            vec![
                Beat::Frame(surface(1, 1)),
                Beat::Frame(surface(2, 2)),
                Beat::Condition(Condition::Fatal),
            ],
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let bitmap = PointerShape {
            hotspot_x: 0,
            hotspot_y: 0,
            width: 2,
            height: 2,
            pixels: vec![0xAB; 16],
        };
        let mut pointer = FixedPointer::at(10, 20, ShapeId(3), Some(bitmap));
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.ending, Ending::GaveUp(Surrender::Fatal));
        let shapes = out
            .sent
            .iter()
            .filter(|message| matches!(message, Message::CursorShape(_)))
            .count();
        let positions = out
            .sent
            .iter()
            .filter(|message| matches!(message, Message::CursorPos(_)))
            .count();
        assert_eq!(shapes, 1, "a bitmap the client already holds is never re-sent");
        assert_eq!(positions, 1, "a pointer that has not moved costs nothing");
        // The bitmap precedes the position it belongs to.
        let shape_at = out
            .sent
            .iter()
            .position(|message| matches!(message, Message::CursorShape(_)))
            .expect("a shape was sent");
        let position_at = out
            .sent
            .iter()
            .position(|message| matches!(message, Message::CursorPos(_)))
            .expect("a position was sent");
        assert!(shape_at < position_at);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transport_that_fails_ends_the_stream_without_writing_to_it() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(Vec::new(), Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        out.broken = true;
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            quick(),
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.ending, Ending::Transport(StreamError::Closed));
        assert!(out.closed.is_none(), "a dead channel is not written to on the way out");
    }

    #[tokio::test(start_paused = true)]
    async fn an_input_sink_that_refuses_is_reported_rather_than_hidden() {
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Frame(surface(1, 1))], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording { delivered: Vec::new(), refuse: Some(Refusal::ElevatedWindow) };
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);
        let store = Store::holding(control, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.allow_input = true;

        // Sent after the first frame, so the phase is Live and the refusal can
        // only have come from the sink.
        let key = Message::Key { usage: Usage::from_code("KeyA").expect("KeyA exists"), down: true };
        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            sender.send(key.encode().expect("encodes")).expect("listening");
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(control),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");

        assert_eq!(outcome.ending, Ending::PeerClosed);
        assert_eq!(out.refusals(), vec![Refusal::ElevatedWindow]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_viewer_that_never_reads_is_ended_by_its_own_wall() {
        // The stalling viewer: it grants no credit and never says anything. The
        // stream must neither queue frames nor live forever waiting for it.
        let credit = Arc::new(AtomicU32::new(0));
        let mut frames = ScriptedFrames::new(
            (0..200).map(|step| Beat::Frame(surface(step as u8, 0))).collect(),
            Arc::clone(&credit),
        );
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = NoInput;
        let store = Store::holding(Capabilities::VIEW, Duration::from_secs(600));

        let mut ceilings = quick();
        ceilings.max_session = Duration::from_millis(200);

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(Capabilities::VIEW),
            ceilings,
        );
        let outcome = viewer.run(&mut Silent).await;

        assert_eq!(outcome.ending, Ending::Deadline);
        assert_eq!(outcome.stats.frames_sent, 0);
        assert!(outcome.stats.credit_stalls > 1, "every frame was declined, not queued");
        assert!(out.tiles().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_release_for_something_that_was_never_held_is_dropped() {
        // Some platforms treat a spurious key-up as a key-down, and a viewer
        // that reconnects mid-chord sends exactly that.
        let credit = Arc::new(AtomicU32::new(1 << 20));
        let mut frames = ScriptedFrames::new(vec![Beat::Frame(surface(1, 1))], Arc::clone(&credit));
        let mut out = Recorder::new(Arc::clone(&credit));
        let mut pointer = FixedPointer::none();
        let mut input = Recording::default();
        let control = Capabilities::VIEW.with(Capabilities::CONTROL);
        let store = Store::holding(control, Duration::from_secs(600));
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut inbound = Channel(receiver);

        let mut ceilings = quick();
        ceilings.allow_input = true;

        let usage = Usage::from_code("KeyA").expect("KeyA exists");
        let feeder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            for message in [
                Message::Key { usage, down: false },
                Message::Button { button: Button::Right, down: false },
            ] {
                sender.send(message.encode().expect("encodes")).expect("listening");
            }
        });

        let viewer = Viewer::new(
            Wiring {
                outbound: &mut out,
                frames: &mut frames,
                pointer: &mut pointer,
                input: &mut input,
            },
            &store,
            seat(),
            &redemption(control),
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        feeder.await.expect("the feeder finishes");

        assert_eq!(outcome.stats.inputs_ignored, 2);
        assert_eq!(outcome.stats.inputs_delivered, 0);
        assert!(input.delivered.is_empty());
        assert!(out.refusals().is_empty(), "dropping is not refusing: nothing was denied");
    }

    #[test]
    fn every_ending_has_a_distinct_code_and_a_sentence() {
        let endings = [
            Ending::Deadline,
            Ending::SessionExpired,
            Ending::SessionGone,
            Ending::ViewRevoked,
            Ending::Stopped,
            Ending::GaveUp(Surrender::Fatal),
            Ending::PeerClosed,
            Ending::PeerMisbehaved(WireError::Empty),
            Ending::WrongDirection { kind: 0x03 },
            Ending::Transport(StreamError::Closed),
            Ending::Encoding(WireError::Empty),
        ];
        let mut codes: Vec<u16> = endings.iter().map(Ending::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), endings.len(), "close codes must be distinct");
        for ending in &endings {
            assert!(!ending.to_string().is_empty(), "{ending:?} has no sentence");
        }
        assert!(!Ending::PeerClosed.peer_is_listening());
        assert!(!Ending::Transport(StreamError::Closed).peer_is_listening());
        assert!(Ending::Deadline.peer_is_listening());
    }

    #[test]
    fn a_tile_the_driver_sends_decodes_to_the_pixels_it_captured() {
        // Belt and braces for the reconstruction the credit test relies on:
        // the encoding the driver picks is one `decode_tile` accepts.
        let painted = surface(5, 6);
        let updates = diff(None, &painted, TileSize::DEFAULT).expect("a keyframe diffs");
        assert_eq!(updates.len(), 2);
        for update in &updates {
            let decoded = crate::tiles::decode_tile(
                update.encoding,
                &update.payload,
                TileSize::DEFAULT.pixels(),
            )
            .expect("the driver's own encoding decodes");
            assert!(matches!(decoded, Decoded::Pixels(_)));
            assert_ne!(update.encoding, Encoding::Unchanged);
        }
    }
}
