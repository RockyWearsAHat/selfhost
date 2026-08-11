//! The agent's body: what it says about itself, and the loop that streams a screen.
//!
//! The agent is a second process. On the production box the daemon runs as a
//! service in session 0, which has no interactive display and cannot capture the
//! user's desktop by any method, so it spawns this — inside the console session, as
//! the console user, at medium integrity — and talks to it over a pipe whose
//! access-control list is the authentication. [`crate::windows`] builds that spawn;
//! this module is what the spawned process does once it is running.
//!
//! Three things live here, and the split between them is the point of the file.
//!
//! **What the agent states about itself** ([`AgentReport`]). One line, sent once,
//! carrying the session id, the window station and desktop it landed on, the
//! displays it can see, its DPI awareness and its integrity level. Every one of
//! those has been the cause of a whole class of "it runs and captures nothing"
//! failure, and none of them is visible from the daemon's side of the fence. An
//! agent that reports them turns a silent black screen into a sentence naming the
//! reason.
//!
//! **The streaming loop** ([`Streamer`]). Pure: it holds no handle, no socket and
//! no clock. It is handed a [`Capture`], a [`CursorSource`] and a [`FrameSink`],
//! and the time, and it decides what to send. That is what lets the whole of the
//! behaviour below — the credit stall, the dropped frame, the merged damage, the
//! secure desktop arriving as prose, the still desktop costing nothing — be tested
//! on a laptop with no display attached and no agent running.
//!
//! **The process body** (`run`, on Windows only). The thin part: declare DPI
//! awareness, gather the report, connect the pipe, turn the crank — and perform the
//! input the daemon forwards, through [`crate::Injector`], releasing whatever is
//! left held the moment the link closes.
//!
//! **How it was asked to run** ([`AgentOptions`], [`InputPolicy`],
//! [`agent_arguments`]). The agent is a separate process and cannot read the
//! daemon's config, so `[desktop].allow_input` travels to it on its command line
//! and is honoured at the layer that would otherwise create the injector. That is
//! the whole of the mechanism, and [`InputPolicy`] says why it is the command line
//! and not the pipe.
//!
//! # Credit, and why a remote desktop drops frames rather than queueing them
//!
//! The link underneath is credit-controlled end to end — the browser grants the
//! owner, the owner forwards to the worker, the worker forwards to this agent — and
//! at some point on a tunnelled link the grant stops arriving for a while. There are
//! only two things a screen source can do about that.
//!
//! It can queue, which is what a file transfer would do, and which is wrong here in
//! a way that gets worse the longer it lasts: the operator ends up watching a
//! recording of a window they finished dragging four seconds ago, and the backlog
//! never drains because the screen keeps producing frames.
//!
//! Or it can **drop the frame and merge its damage into the next one**, which is
//! what this loop does. The merge is not an extra mechanism: the loop holds a model
//! of the surface *the client is actually holding* ([`Streamer::client_surface`]),
//! and every frame is a difference against that rather than against the previous
//! capture. A frame that was never sent therefore leaves the model untouched, and
//! its changes reappear in the next difference automatically — for one dropped
//! frame or for four hundred. Where the platform reports its own dirty rectangles,
//! those are merged too, in [`DamageHint`], so a future DXGI backend does not have
//! to diff a whole screen to find out what a dropped frame changed.
//!
//! Dropping is *counted*, in [`AgentStats::credit_stalls`], and the count is on the
//! diagnostics plate. An operator whose desktop feels sluggish must be able to see
//! whether the link is starving the agent or the machine is busy; a subsystem that
//! silently does the right thing here produces a bug report that says "it feels
//! laggy sometimes" and nothing else.
//!
//! # A still desktop costs nothing at all
//!
//! When nothing on screen has changed, the difference is empty and **no frame
//! message is sent** — not a `FrameBegin`, not an empty `FrameEnd`. The plan's
//! acceptance test for this phase is a static screen costing near zero bytes a
//! second, which proves the difference is real rather than the capture merely
//! working.

use crate::{Capture, CaptureError, CursorSource, Fault, Grant};
use selfhost_desk::cursor::{CursorPolicy, Pointer, ShapeId};
use selfhost_desk::state::{Action, Limits, Notice, Observation, Session};
use selfhost_desk::tiles::{self, Damage, Grid, Surface, TileSize, TileUpdate};
use selfhost_desk::wire::{
    CursorPos, CursorShape, FrameBegin, Hello, Message, Monitor, TileMessage, MAX_CURSOR_EDGE,
    MAX_DETAIL_BYTES, PROTOCOL_VERSION,
};
use selfhost_desk::Capabilities;
use std::time::{Duration, Instant};

/// The most dirty rectangles a merged damage hint will carry before it gives up
/// and says "check everything".
///
/// A hint exists to save work; a hint with ten thousand rectangles in it costs more
/// to consult than the full comparison it was meant to avoid. Past this many, the
/// hint collapses to the whole frame, which is always correct and merely slower.
const MAX_HINT_RECTS: usize = 256;

/// How long the loop is willing to wait inside a single capture call.
///
/// Short, because the loop has other things to do — the pointer moves at thirty
/// times the rate the picture usefully changes, and a long block inside the capture
/// is a pointer that stops moving.
const CAPTURE_TIMEOUT: Duration = Duration::from_millis(16);

/// What the agent declared to Windows about DPI, and therefore what its pixel
/// coordinates mean.
///
/// The agent's **first statement**, before it captures or enumerates anything.
/// Without per-monitor awareness `GetSystemMetrics` reports virtualised extents
/// while the pixels the capture produces are physical, and the pointer drifts
/// progressively toward the bottom-right of a scaled display — a bug that gets
/// diagnosed as a rounding error in `crate::coords`, which will be innocent.
///
/// It is reported rather than assumed because the call that sets it is resolved at
/// run time: the manifest route Microsoft recommends needs a build script, and
/// there is no `build.rs` anywhere in this workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiAwareness {
    /// `PER_MONITOR_AWARE_V2`: physical pixels everywhere, per display, and the
    /// only value under which coordinates on a scaled display are correct.
    PerMonitorV2,
    /// System-wide awareness, the pre-8.1 fallback. Correct on a single display and
    /// wrong on a second one at a different scale.
    System,
    /// Neither call was available or either failed. Coordinates on a scaled display
    /// will be wrong, and the console says so rather than leaving an operator to
    /// discover it by watching their pointer drift.
    Unaware,
}

impl DpiAwareness {
    /// The short form the report line carries.
    pub const fn label(self) -> &'static str {
        match self {
            Self::PerMonitorV2 => "per-monitor-v2",
            Self::System => "system-dpi",
            Self::Unaware => "dpi-unaware",
        }
    }
}

/// The integrity level the agent is running at.
///
/// Reported because it is the thing that explains a whole class of behaviour nobody
/// can see: User Interface Privilege Isolation silently ignores input injected into
/// any window at a higher level, and a medium-integrity agent — which is what this
/// one is, deliberately — cannot type into an elevated window. Capture is
/// unaffected, so the screen keeps arriving while the keyboard is refused, and the
/// refusal is *reported* rather than hidden: see
/// [`crate::windows::uipi_verdict`], which also explains why raising this level to
/// fix it would turn the feature into a remote privilege-escalation channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// Below low. Effectively nothing works.
    Untrusted,
    /// Low integrity, as a sandboxed browser tab runs.
    Low,
    /// Medium: an ordinary interactive process, and where this agent belongs.
    Medium,
    /// High: elevated. The agent must not be here.
    High,
    /// System. The agent must **certainly** not be here: a screen source running as
    /// SYSTEM that can also be driven remotely is a privilege-escalation channel.
    System,
    /// A level this build has no name for, carried as its own number.
    Other(u32),
}

impl Integrity {
    /// The level a mandatory-label relative identifier names.
    pub const fn from_rid(rid: u32) -> Self {
        match rid {
            0x0000 => Self::Untrusted,
            0x1000 => Self::Low,
            0x2000 => Self::Medium,
            0x3000 => Self::High,
            0x4000 => Self::System,
            other => Self::Other(other),
        }
    }

    /// The relative identifier this level is, which is also its order.
    ///
    /// The inverse of [`Self::from_rid`], and the reason it exists is comparison:
    /// User Interface Privilege Isolation is a question about *which of two levels
    /// is higher*, and the mandatory-label identifiers are assigned in increasing
    /// order precisely so that they can be compared as numbers. An unnamed level
    /// therefore compares correctly too, rather than needing a place in an
    /// enumeration nobody has updated.
    pub const fn rid(self) -> u32 {
        match self {
            Self::Untrusted => 0x0000,
            Self::Low => 0x1000,
            Self::Medium => 0x2000,
            Self::High => 0x3000,
            Self::System => 0x4000,
            Self::Other(rid) => rid,
        }
    }

    /// The short form the report line carries.
    pub fn label(self) -> String {
        match self {
            Self::Untrusted => "untrusted-integrity".to_owned(),
            Self::Low => "low-integrity".to_owned(),
            Self::Medium => "medium-integrity".to_owned(),
            Self::High => "high-integrity".to_owned(),
            Self::System => "system-integrity".to_owned(),
            Self::Other(rid) => format!("integrity-{rid:#x}"),
        }
    }
}

/// Everything the agent states about itself, once, on connecting.
///
/// This is the diagnostic that makes the session-0 class of failure legible. A
/// daemon can tell that it started a process; it cannot tell which desktop that
/// process landed on, and a process on the wrong desktop runs perfectly, reports
/// nothing wrong, and captures a blank screen forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReport {
    /// The session the agent is running in. Compared against the console session by
    /// both sides, because they disagree exactly when a user switch has happened.
    pub session: u32,
    /// Who the agent is running as, for the console's own line. Read from the
    /// environment the spawn built from the user's token, so a wrong value here is
    /// itself the symptom of a skipped `CreateEnvironmentBlock`.
    pub user: String,
    /// The window station, which must be `WinSta0` for anything to be visible.
    pub window_station: String,
    /// The desktop currently receiving input, as `crate::windows::classify_desktop`
    /// named it.
    pub desktop: String,
    /// Every display, as the protocol describes them.
    pub monitors: Vec<Monitor>,
    /// What the agent declared about DPI.
    pub dpi: DpiAwareness,
    /// What it is running at.
    pub integrity: Integrity,
}

impl AgentReport {
    /// The report as the one line the console shows.
    ///
    /// Deliberately dense and deliberately in this order: the session and the user
    /// answer "did the spawn land where it was aimed", the window station and
    /// desktop answer "can this process see anything at all", and the rest answers
    /// "will what it sees be correct".
    pub fn sentence(&self) -> String {
        format!(
            "agent live in session {} as {} · {}\\{} · {} monitor{} · {} · {}",
            self.session,
            self.user,
            self.window_station,
            self.desktop,
            self.monitors.len(),
            if self.monitors.len() == 1 { "" } else { "s" },
            self.dpi.label(),
            self.integrity.label(),
        )
    }
}

/// Why a message did not go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The link is gone. Terminal for the agent: it exits and the daemon respawns
    /// it, which is a shorter and better-tested path than reconnecting by hand.
    Closed,
    /// The message could not be encoded or written.
    Failed(Fault),
}

/// What happened to one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// It went out, costing this many bytes of the send window.
    Sent(u32),
    /// It did not go out, and nothing was written: the far end has not granted
    /// enough credit. **Not an error** — the caller drops what it was doing and
    /// tries again with fresher pixels.
    NoCredit,
}

/// Somewhere for the agent's messages to go.
///
/// A trait rather than a socket because the credit window, the framing and the
/// transport all belong to the layer that owns the link, and because a fake one is
/// what makes the loop above testable. The two methods are deliberately the whole
/// interface: *may I*, and *here*.
pub trait FrameSink {
    /// Sends one message, or reports that there is no credit for it.
    ///
    /// An implementation must be all-or-nothing: a `NoCredit` answer must leave
    /// nothing on the wire, because a half-written message is a desynchronised
    /// channel rather than a dropped frame.
    ///
    /// # Errors
    ///
    /// [`SendError::Closed`] when the link has gone away, which ends the agent.
    fn send(&mut self, message: &Message) -> Result<Delivery, SendError>;
}

/// What a session has done since it started.
///
/// Every counter here answers a question an operator actually asks when a remote
/// desktop feels wrong, and none of them can be reconstructed from the outside.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentStats {
    /// Frames the platform produced.
    pub frames_captured: u64,
    /// Frames that produced at least one tile on the wire.
    pub frames_sent: u64,
    /// Frames dropped for want of credit.
    pub frames_dropped: u64,
    /// Frames that changed nothing and cost nothing. On a still desktop this is
    /// the number that climbs, and it is what proves the difference is working.
    pub frames_unchanged: u64,
    /// How many times the link ran out of credit mid-flight. **The** number for
    /// telling a starved link apart from a busy machine.
    pub credit_stalls: u64,
    /// Tiles sent.
    pub tiles_sent: u64,
    /// Tiles a frame could not afford, which the next difference re-offers.
    pub tiles_deferred: u64,
    /// Full frames sent — the first one, and every one a client asked for.
    pub keyframes: u64,
    /// Cursor bitmaps sent. Should be a tiny fraction of the position updates.
    pub cursor_shapes: u64,
    /// Payload bytes handed to the sink.
    pub bytes_sent: u64,
    /// How many times the screen source asked to be rebuilt.
    pub rebuilds: u64,
}

/// The merged damage of every frame that has not been sent yet.
///
/// Where a platform reports its own dirty rectangles, dropping a frame would throw
/// them away — and the next frame's rectangles describe only what changed since the
/// *drop*, not since the last thing the client saw. So they are accumulated here
/// and consulted together.
///
/// Collapsing to "the whole frame" is always a legal answer, and this type reaches
/// for it whenever the alternative would be expensive or uncertain: an empty
/// damage report (which is what GDI gives, every frame, because it cannot know),
/// or more rectangles than [`MAX_HINT_RECTS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DamageHint {
    /// The accumulated rectangles, empty when the hint is the whole frame.
    damage: Damage,
    /// Whether the hint has given up on being specific.
    whole_frame: bool,
}

impl DamageHint {
    /// A hint that says nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether every tile must be compared.
    pub fn is_whole_frame(&self) -> bool {
        self.whole_frame
    }

    /// Folds one frame's damage in.
    ///
    /// An empty report means "assume everything changed", which is what a source
    /// with no dirty-rectangle support reports on every frame — so it collapses the
    /// hint rather than being mistaken for "nothing changed".
    pub fn merge(&mut self, damage: &Damage) {
        if self.whole_frame {
            return;
        }
        if damage.dirty.is_empty() && damage.moves.is_empty() {
            self.whole_frame = true;
            self.damage = Damage::default();
            return;
        }
        if self.damage.dirty.len() + damage.dirty.len() > MAX_HINT_RECTS
            || self.damage.moves.len() + damage.moves.len() > MAX_HINT_RECTS
        {
            self.whole_frame = true;
            self.damage = Damage::default();
            return;
        }
        self.damage.moves.extend_from_slice(&damage.moves);
        self.damage.dirty.extend_from_slice(&damage.dirty);
    }

    /// Forgets everything, after a frame has been sent.
    pub fn clear(&mut self) {
        self.whole_frame = false;
        self.damage = Damage::default();
    }

    /// The accumulated damage, meaningful only when the hint is not whole-frame.
    pub fn damage(&self) -> &Damage {
        &self.damage
    }
}

/// A sender's view of how many bytes it may still put on the link.
///
/// Deliberately **not** `selfhost_mesh::credit::SendWindow`: this crate does not
/// depend on the mesh, on purpose, because an agent that linked the peer-to-peer
/// layer would be an agent that could open a link of its own. What the agent needs
/// is the sender's half of one channel's window, which is a counter and two rules,
/// and duplicating that is cheaper than duplicating the reason it must not have the
/// rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditWindow {
    /// Bytes that may still be sent.
    available: u32,
    /// How many times a send was refused for want of them.
    stalls: u64,
}

impl CreditWindow {
    /// A window with an initial grant.
    pub const fn new(initial: u32) -> Self {
        Self { available: initial, stalls: 0 }
    }

    /// Bytes that may still be sent.
    pub const fn available(&self) -> u32 {
        self.available
    }

    /// How many sends have been refused.
    pub const fn stalls(&self) -> u64 {
        self.stalls
    }

    /// Adds a grant, saturating.
    ///
    /// Saturating rather than checked because a peer that grants more than the
    /// window can hold is a peer with a bug, and the safe response to it is to stop
    /// counting rather than to stop sending — the receiver's own window is what
    /// actually bounds memory at the far end.
    pub fn grant(&mut self, bytes: u32) {
        self.available = self.available.saturating_add(bytes);
    }

    /// Spends `bytes` if they are there, answering whether they were.
    pub fn spend(&mut self, bytes: u32) -> bool {
        match self.available.checked_sub(bytes) {
            Some(left) => {
                self.available = left;
                true
            }
            None => {
                self.stalls = self.stalls.saturating_add(1);
                false
            }
        }
    }
}

/// What a session streams under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// The tile edge. 64 unless an operator has a reason.
    pub tile: TileSize,
    /// The frame rate the agent will not exceed.
    pub max_fps: u8,
    /// What the redeemed ticket actually granted, echoed to the client so the
    /// console displays the truth rather than what it asked for.
    pub capabilities: Capabilities,
    /// How many pointer shapes the client is assumed to cache.
    pub shape_cache: usize,
    /// The session state machine's budgets.
    pub limits: Limits,
}

impl Default for StreamConfig {
    /// View-only at thirty frames a second with 64-pixel tiles.
    ///
    /// View-only is the default even though both platforms can now inject, because
    /// the capability a session actually holds is granted by its ticket and echoed
    /// here — never assumed. A default that could drive the machine would mean a
    /// session which failed to state its capabilities got the dangerous one.
    fn default() -> Self {
        Self {
            tile: TileSize::default(),
            max_fps: 30,
            capabilities: Capabilities::VIEW,
            shape_cache: selfhost_desk::cursor::DEFAULT_CAPACITY,
            limits: Limits::default(),
        }
    }
}

/// One tick's outcome: what the driver should do next, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tick {
    /// What the session state machine says to do.
    pub action: Action,
    /// The notice that was sent, present only when the phase changed.
    pub notice: Option<Notice>,
}

/// The streaming loop, with no handles in it.
///
/// Holds the model of what the client is looking at, the pointer policy, the
/// session state machine and the counters. Everything that touches the world is
/// passed in per tick, which is why the whole of this file's behaviour is tested
/// without a screen.
#[derive(Debug)]
pub struct Streamer {
    config: StreamConfig,
    session: Session,
    pointer: CursorPolicy,
    /// What the far end is holding, tile for tile. The centre of the design: every
    /// difference is taken against this rather than against the previous capture,
    /// which is what makes a dropped frame cost nothing and need no bookkeeping.
    client_surface: Option<Surface>,
    /// Which display `client_surface` describes.
    client_monitor: u8,
    /// Merged damage from frames that were captured and not sent.
    hint: DamageHint,
    /// The last shape id seen from the platform, so a position-only observation
    /// still knows which shape it belongs to.
    last_shape: Option<u64>,
    /// Whether the next frame must be a full one.
    keyframe: bool,
    /// The permission the screen source last said it was missing.
    ///
    /// Remembered rather than derived, because the state machine's notice carries
    /// only *that* permission was refused and the operator needs to be told *which
    /// one and what to do about it* — two panes of System Settings, two independent
    /// grants, and a sentence naming the wrong one sends them to the wrong place.
    denial: Option<Grant>,
    stats: AgentStats,
}

impl Streamer {
    /// A streamer that has sent nothing.
    pub fn new(config: StreamConfig) -> Self {
        Self {
            session: Session::new(config.limits),
            pointer: CursorPolicy::new(config.shape_cache),
            client_surface: None,
            client_monitor: 0,
            hint: DamageHint::new(),
            last_shape: None,
            keyframe: true,
            denial: None,
            stats: AgentStats::default(),
            config,
        }
    }

    /// The opening statement for a report.
    pub fn hello(&self, report: &AgentReport) -> Message {
        Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: self.config.tile,
            max_fps: self.config.max_fps,
            capabilities: self.config.capabilities,
            monitors: report.monitors.clone(),
        })
    }

    /// The counters, for the diagnostics plate.
    pub fn stats(&self) -> &AgentStats {
        &self.stats
    }

    /// The session state machine, for a caller that wants the phase.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// The interval between frames at the configured rate.
    ///
    /// A `max_fps` of zero means "as fast as the link allows", which is the only
    /// sensible reading of a ceiling of none, and produces no delay rather than a
    /// division by zero.
    pub fn frame_interval(&self) -> Duration {
        match u32::from(self.config.max_fps) {
            0 => Duration::ZERO,
            fps => Duration::from_secs(1) / fps,
        }
    }

    /// Asks for the next frame to be a complete one.
    ///
    /// Called when a client attaches, reconnects, or says it has lost track. It
    /// also forgets what the client is holding, because a client that asks for a
    /// full frame is telling us our model of it is wrong.
    pub fn request_full_frame(&mut self) {
        self.keyframe = true;
        self.client_surface = None;
        self.hint.clear();
        self.pointer.forget();
        self.last_shape = None;
    }

    /// One turn of the loop: capture, send what fits, and fold the outcome into the
    /// session state.
    ///
    /// # Errors
    ///
    /// Only [`SendError`], and only from the link. Everything the *screen* can do
    /// wrong is a state rather than an error, which is what lets a UAC prompt, a
    /// locked machine and a user switch each reach the console as a sentence
    /// instead of stopping the session.
    pub fn tick(
        &mut self,
        capture: &mut dyn Capture,
        cursor: &mut dyn CursorSource,
        sink: &mut dyn FrameSink,
        now: Instant,
    ) -> Result<Tick, SendError> {
        // The pointer first, always. When the link is tight this is the difference
        // between a session that feels slow and one that feels dead: the pointer
        // keeps tracking while the picture waits for credit.
        self.pump_cursor(cursor, sink)?;

        let observation = match capture.next_frame(CAPTURE_TIMEOUT) {
            Ok(Some(frame)) => {
                self.stats.frames_captured = self.stats.frames_captured.saturating_add(1);
                match Self::adopt(&frame) {
                    Ok(surface) => {
                        self.hint.merge(&frame.damage);
                        self.send_frame(frame.monitor, &surface, sink)?;
                        Observation::Frame
                    }
                    // A frame whose stride, extent and buffer do not agree is a
                    // driver's mistake rather than ours. Rebuilding is bounded and
                    // usually works; treating it as fatal would end a session over
                    // one bad frame during a mode change.
                    Err(_) => {
                        self.stats.rebuilds = self.stats.rebuilds.saturating_add(1);
                        Observation::Reinitialise
                    }
                }
            }
            Ok(None) => Observation::Retry,
            Err(condition) => {
                if let CaptureError::PermissionDenied(grant) = &condition {
                    self.denial = Some(*grant);
                }
                if matches!(condition, CaptureError::Reinitialise | CaptureError::TooManyDuplications)
                {
                    self.stats.rebuilds = self.stats.rebuilds.saturating_add(1);
                }
                // Everything the client holds belongs to a screen that is no longer
                // in front. Forgetting it now means the frame after the state
                // clears is a keyframe rather than a difference against a picture
                // that is no longer true.
                if !matches!(condition, CaptureError::Retry) {
                    self.client_surface = None;
                    self.keyframe = true;
                }
                condition.observation()
            }
        };

        let step = self.session.observe(observation, now);
        if let Some(notice) = step.notice {
            // The transition speaks, never the observation: a still desktop
            // produces `Retry` thirty times a second, and a status message per
            // observation would be thirty messages a second saying nothing changed.
            let detail = detail_for(notice, observation, self.denial);
            self.deliver(&Message::Status { notice, detail }, sink)?;
        }
        Ok(Tick { action: step.action, notice: step.notice })
    }

    /// Turns a borrowed platform frame into a tight surface.
    ///
    /// This is the one copy per frame in the whole path, and it buys the comparison
    /// with what the client holds — there is no way to diff against a previous
    /// frame without keeping one. On Windows the copy is a straight memcpy, because
    /// a 32-bit DIB has no row padding; on macOS the same call is what unshears a
    /// padded surface.
    fn adopt(frame: &crate::Frame<'_>) -> Result<Surface, tiles::TileError> {
        tiles::unpack(frame.width, frame.height, frame.stride, frame.pixels)
    }

    /// Sends whatever of this frame the credit window will take.
    ///
    /// The frame is *not* recorded as delivered unless its tiles were: the client
    /// model is updated tile by tile, so a frame cut short by a stall leaves the
    /// tiles it could not afford still marked as different, and the next difference
    /// offers them again.
    fn send_frame(
        &mut self,
        monitor: u8,
        current: &Surface,
        sink: &mut dyn FrameSink,
    ) -> Result<(), SendError> {
        // A display change, a monitor switch or a client asking for a full frame
        // all arrive here as "the model does not describe this picture".
        let reusable = self
            .client_surface
            .as_ref()
            .is_some_and(|held| {
                self.client_monitor == monitor
                    && held.width() == current.width()
                    && held.height() == current.height()
            })
            && !self.keyframe;
        if !reusable {
            self.client_surface = None;
            self.client_monitor = monitor;
            self.keyframe = true;
        }

        let previous = self.client_surface.as_ref();
        let Ok(updates) = changed_tiles(previous, current, self.config.tile, &self.hint) else {
            // A tile grid this surface cannot be divided into is a surface we
            // should not have accepted; the rebuild is charged by the caller.
            return Ok(());
        };

        if updates.is_empty() {
            // The whole point of the difference: a still desktop puts nothing at
            // all on the wire, not even an empty frame.
            self.stats.frames_unchanged = self.stats.frames_unchanged.saturating_add(1);
            self.hint.clear();
            return Ok(());
        }

        let keyframe = self.keyframe;
        let sequence = self.stats.frames_sent.saturating_add(1);
        let begin = Message::FrameBegin(FrameBegin {
            monitor,
            sequence,
            width: current.width(),
            height: current.height(),
            keyframe,
        });
        if !self.deliver(&begin, sink)? {
            // Not even the frame header fits. Nothing has been written, the model
            // is untouched, and the damage stays merged for the next attempt.
            self.stats.frames_dropped = self.stats.frames_dropped.saturating_add(1);
            return Ok(());
        }

        let mut model = match self.client_surface.take() {
            Some(held) => held,
            // A keyframe's difference is every tile, so the starting surface does
            // not matter — but it must exist, or there is nowhere to record what
            // was delivered.
            None => match Surface::blank(current.width(), current.height()) {
                Ok(blank) => blank,
                Err(_) => return Ok(()),
            },
        };

        let grid = match Grid::new(self.config.tile, current.width(), current.height()) {
            Ok(grid) => grid,
            Err(_) => return Ok(()),
        };
        let mut deferred = 0usize;
        let mut delivered = 0usize;
        for update in &updates {
            let message = Message::Tile(TileMessage {
                monitor,
                col: update.coord.col,
                row: update.coord.row,
                encoding: update.encoding,
                payload: update.payload.clone(),
            });
            if !self.deliver(&message, sink)? {
                // Out of credit mid-frame. Everything from here on stays different
                // as far as the model is concerned, so it is re-offered next time
                // with fresher pixels — which is exactly what a remote desktop
                // should show.
                deferred = updates.len().saturating_sub(delivered);
                break;
            }
            delivered = delivered.saturating_add(1);
            self.stats.tiles_sent = self.stats.tiles_sent.saturating_add(1);
            // The model advances only for tiles that actually went out. A tile the
            // grid or the surface refuses is left as it was, which re-offers it on
            // the next difference — the same recovery a stall gets. Written as
            // nested `if let`s rather than a let-chain because the workspace
            // declares `rust-version = "1.85"` and chains landed in 1.88.
            if let Ok(bounds) = grid.bounds(update.coord) {
                if let Ok(pixels) = current.tile(bounds) {
                    let _ = model.put_tile(bounds, &pixels);
                }
            }
        }

        self.stats.tiles_deferred =
            self.stats.tiles_deferred.saturating_add(deferred as u64);
        self.deliver(&Message::FrameEnd { sequence }, sink)?;

        self.client_surface = Some(model);
        self.client_monitor = monitor;
        self.stats.frames_sent = sequence;
        if keyframe {
            self.stats.keyframes = self.stats.keyframes.saturating_add(1);
            self.keyframe = false;
        }
        if deferred == 0 {
            self.hint.clear();
        } else {
            // Some of the picture is still owed. The hint stays whole-frame so the
            // next difference looks everywhere rather than at the rectangles of a
            // frame that was only half delivered.
            self.hint = DamageHint { damage: Damage::default(), whole_frame: true };
        }
        Ok(())
    }

    /// Sends the pointer, if anything about it has changed.
    fn pump_cursor(
        &mut self,
        cursor: &mut dyn CursorSource,
        sink: &mut dyn FrameSink,
    ) -> Result<(), SendError> {
        // A cursor source that is refused tells us nothing the frame path will not
        // tell us a moment later, in a variant the state machine already handles.
        let Ok(state) = cursor.cursor() else { return Ok(()) };

        let shape_id = match state.shape.as_ref().map(|image| image.id).or(self.last_shape) {
            Some(id) => id,
            // No shape has ever been observed, so there is nothing to draw and no
            // identity to send a position under. Asking the source to forget makes
            // the next observation carry one.
            None => {
                cursor.forget_shape();
                return Ok(());
            }
        };
        self.last_shape = Some(shape_id);

        let x = i32::try_from(state.position.x).unwrap_or(i32::MAX);
        let y = i32::try_from(state.position.y).unwrap_or(i32::MAX);
        let emission = self
            .pointer
            .observe(Pointer { x, y, visible: state.visible, shape: ShapeId(shape_id) });

        if emission.shape.is_some() {
            match state.shape.as_ref().and_then(shape_message) {
                Some(message) => {
                    if !self.deliver(&message, sink)? {
                        // The client will not have the bitmap, so it must not be
                        // told the position under a shape it cannot draw.
                        self.pointer.forget();
                        return Ok(());
                    }
                    self.stats.cursor_shapes = self.stats.cursor_shapes.saturating_add(1);
                }
                // The client's cache has evicted a shape this source believes it
                // already sent. Forget on both sides and the next observation
                // carries the bitmap.
                None => {
                    cursor.forget_shape();
                    self.pointer.forget();
                    return Ok(());
                }
            }
        }

        if let Some(pointer) = emission.position {
            let message = Message::CursorPos(CursorPos {
                x: pointer.x,
                y: pointer.y,
                visible: pointer.visible,
            });
            if !self.deliver(&message, sink)? {
                self.pointer.forget();
            }
        }
        Ok(())
    }

    /// Hands one message to the sink, counting what it cost or that it stalled.
    ///
    /// Answers `false` for a stall, which every caller treats as "stop what you were
    /// doing" rather than as a failure.
    fn deliver(&mut self, message: &Message, sink: &mut dyn FrameSink) -> Result<bool, SendError> {
        match sink.send(message)? {
            Delivery::Sent(bytes) => {
                self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64::from(bytes));
                Ok(true)
            }
            Delivery::NoCredit => {
                self.stats.credit_stalls = self.stats.credit_stalls.saturating_add(1);
                Ok(false)
            }
        }
    }
}

/// The tiles that differ between what the client holds and what the screen shows.
///
/// Consults the merged damage hint where there is one, and compares the whole grid
/// where there is not. Both paths use `selfhost_desk::tiles` — the diff and the RLE
/// codec live there, are fuzz-tested there, and are deliberately not reimplemented
/// here.
fn changed_tiles(
    previous: Option<&Surface>,
    current: &Surface,
    size: TileSize,
    hint: &DamageHint,
) -> Result<Vec<TileUpdate>, tiles::TileError> {
    let Some(previous) = previous else {
        // No model of the client at all: every tile is new by definition.
        return tiles::diff(None, current, size);
    };
    if hint.is_whole_frame() {
        return tiles::diff(Some(previous), current, size);
    }

    let grid = Grid::new(size, current.width(), current.height())?;
    let mut updates = Vec::new();
    for coord in hint.damage().tiles(grid) {
        let bounds = grid.bounds(coord)?;
        let tile = current.tile(bounds)?;
        if previous.tile(bounds)? == tile {
            continue;
        }
        let (encoding, payload) = tiles::encode_tile(&tile)?;
        updates.push(TileUpdate { coord, encoding, payload });
    }
    Ok(updates)
}

/// A cursor bitmap as the wire carries it, or `None` if it cannot be carried.
///
/// A shape too large for the protocol, or one whose buffer does not match its own
/// extent, is dropped rather than sent: the client keeps drawing the shape it had,
/// which is a wrong pointer nobody notices, where a refused message would be a
/// session that stops.
fn shape_message(image: &crate::CursorImage) -> Option<Message> {
    let width = u16::try_from(image.width).ok()?;
    let height = u16::try_from(image.height).ok()?;
    if width == 0 || height == 0 || width > MAX_CURSOR_EDGE || height > MAX_CURSOR_EDGE {
        return None;
    }
    let expected = usize::from(width).checked_mul(usize::from(height))?.checked_mul(4)?;
    if image.bgra.len() != expected {
        return None;
    }
    Some(Message::CursorShape(CursorShape {
        shape: image.id,
        hotspot_x: u16::try_from(image.hotspot_x).ok()?,
        hotspot_y: u16::try_from(image.hotspot_y).ok()?,
        width,
        height,
        pixels: image.bgra.clone(),
    }))
}

/// The detail line that travels with a notice.
///
/// The notice itself is a stable wire code both consoles render in their own words;
/// this is the extra sentence for the diagnostics plate, and it is bounded because
/// the wire bounds it.
fn detail_for(notice: Notice, observation: Observation, denial: Option<Grant>) -> String {
    // The one notice whose detail is not a fixed sentence. A permission refusal is a
    // **product surface**: the operator can fix it in thirty seconds if they are told
    // which pane, which binary and that it takes a fresh launch, and cannot fix it at
    // all from "the operating system refuses this process the screen". The sentence
    // is built to fit the wire's own cap so the framing below never cuts it short.
    if notice == Notice::PermissionDenied {
        if let Some(grant) = denial {
            return truncate(&grant.remediation(&crate::this_executable()), MAX_DETAIL_BYTES);
        }
    }
    let text = match (notice, observation) {
        (Notice::SecureDesktop, _) => {
            "Windows has switched to the secure desktop — a consent prompt, the lock \
             screen, or the sign-in provider. This session deliberately cannot see it \
             or type into it; it resumes by itself when the prompt is answered at the \
             machine."
        }
        (Notice::SessionMoved, _) => {
            "The console session moved — a fast user switch, or a remote desktop \
             connection taking the console. Capture resumes when it comes back."
        }
        (Notice::NoUser, _) => {
            "Nobody is signed in, so there is no desktop to capture. This is an \
             ordinary state for a machine that has rebooted and not been signed into."
        }
        (Notice::Recovering, _) => {
            "The screen source is being rebuilt — a resolution change, a display being \
             connected or disconnected, or a scale change."
        }
        (Notice::Live, _) => "Frames are arriving.",
        (Notice::Starting, _) => "The screen source is starting.",
        // Only reachable before any refusal has named a grant — a state machine
        // that was told about a permission problem by something other than the
        // screen source.
        (Notice::PermissionDenied, _) => {
            "The operating system refuses this process the screen."
        }
        (Notice::GaveUp, _) => {
            "The screen source demanded rebuilding more times than the budget allows, \
             so this session has stopped trying. It restarts on request."
        }
        (Notice::Stopped, _) => {
            "The operator's kill switch is in place: desktop.disabled exists in the \
             data directory."
        }
    };
    truncate(text, MAX_DETAIL_BYTES)
}

/// Truncates on a character boundary, so a bounded field never carries half a
/// character.
fn truncate(text: &str, bytes: usize) -> String {
    if text.len() <= bytes {
        return text.to_owned();
    }
    let mut end = bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_owned()
}

// ══ The agent's link framing ══════════════════════════════════════════════════

/// The kind byte of a desk protocol message travelling to the daemon.
pub const LINK_MESSAGE: u8 = 0x01;
/// The kind byte of a credit grant travelling from the daemon.
pub const LINK_CREDIT: u8 = 0x02;
/// The most a single link frame may carry, matching the wire's own message
/// ceiling.
pub const MAX_LINK_FRAME: usize = selfhost_desk::wire::MAX_MESSAGE;

/// One frame on the agent's own link.
///
/// The pipe between the daemon and the agent is a **byte** pipe — deliberately, so
/// that it never invents message boundaries for a protocol that has its own — and
/// something has to say where one message ends. That something is five bytes: a
/// kind and a big-endian length.
///
/// It is not the mux header from `selfhost_mesh`, and that is a deliberate
/// omission rather than an oversight: this crate does not depend on the mesh, an
/// agent has exactly one channel, and the only thing travelling the other way that
/// is not a desk message is the credit grant this hop must honour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrame {
    /// A desk protocol message, in either direction.
    Message(Vec<u8>),
    /// A grant of this many further payload bytes, from the daemon.
    Credit(u32),
}

/// Frames a payload for the link.
///
/// # Errors
///
/// A payload larger than [`MAX_LINK_FRAME`] is refused rather than truncated: a
/// truncated message is a desynchronised channel, and every later frame on it is
/// garbage that parses.
pub fn encode_link(frame: &LinkFrame) -> Result<Vec<u8>, Fault> {
    let grant;
    let (kind, payload): (u8, &[u8]) = match frame {
        LinkFrame::Message(bytes) => (LINK_MESSAGE, bytes),
        LinkFrame::Credit(bytes) => {
            grant = bytes.to_be_bytes();
            (LINK_CREDIT, &grant[..])
        }
    };
    if payload.len() > MAX_LINK_FRAME {
        return Err(Fault::refused(
            "the agent link",
            format!("refused a {}-byte frame; the ceiling is {MAX_LINK_FRAME}", payload.len()),
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| Fault::refused("the agent link", "frame length does not fit"))?;
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(kind);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Takes one whole frame off the front of a buffer.
///
/// Answers `Ok(None)` when the buffer does not hold a whole frame yet, which on a
/// stream is the ordinary case and not a failure. Every length is checked against
/// the ceiling **before** anything is reserved, so a peer cannot make this allocate
/// by claiming a size it never sends — the property the whole crate graph depends
/// on under `panic = "abort"`.
pub fn decode_link(buffer: &[u8]) -> Result<Option<(LinkFrame, usize)>, Fault> {
    let Some(header) = buffer.get(..5) else { return Ok(None) };
    let kind = *header.first().ok_or_else(|| Fault::refused("the agent link", "empty header"))?;
    let length_bytes: [u8; 4] = header
        .get(1..5)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| Fault::refused("the agent link", "short header"))?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_LINK_FRAME {
        return Err(Fault::refused(
            "the agent link",
            format!("a peer claimed a {length}-byte frame; the ceiling is {MAX_LINK_FRAME}"),
        ));
    }
    let end = length.checked_add(5).ok_or_else(|| {
        Fault::refused("the agent link", "a frame length that overflows an offset")
    })?;
    let Some(payload) = buffer.get(5..end) else { return Ok(None) };

    match kind {
        LINK_MESSAGE => Ok(Some((LinkFrame::Message(payload.to_vec()), end))),
        LINK_CREDIT => {
            let grant: [u8; 4] = payload.try_into().map_err(|_| {
                Fault::refused("the agent link", "a credit grant that is not four bytes")
            })?;
            Ok(Some((LinkFrame::Credit(u32::from_be_bytes(grant)), end)))
        }
        other => Err(Fault::refused(
            "the agent link",
            format!("a frame of unknown kind {other:#04x}"),
        )),
    }
}

// ══ The deployment-wide input switch, and how it reaches a separate process ══

/// The subcommand the daemon starts the agent with.
///
/// Spelled here rather than in the command-line crate because the daemon builds
/// the whole argument vector with [`agent_arguments`], and the two halves of that
/// contract — what is written and what is read — belong in one file or they drift.
/// A stopped agent: which kind of stop, and the fault behind it.
///
/// Two fields because the exit code and the sentence answer different readers.
/// The code is all a parent process can see and is therefore the whole of the
/// diagnosis on the machine this ships to; the fault is what a person reads when
/// the agent was run somewhere its output goes anywhere at all.
#[derive(Debug)]
pub struct AgentStop {
    /// Which step fell over, and so which exit code this becomes.
    pub departure: Departure,
    /// What the platform said.
    pub fault: Fault,
}

impl std::fmt::Display for AgentStop {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}", self.fault.sentence())
    }
}

impl From<Fault> for AgentStop {
    /// Anything that is not classified at its own call site is a stream failure.
    ///
    /// Which is honest: by the time `?` is reached on an unclassified fault the
    /// link is up — the one step before it is classified explicitly — so the
    /// agent connected and then something else went wrong, and that is exactly
    /// what [`Departure::StreamFailed`] says.
    fn from(fault: Fault) -> Self {
        Self { departure: Departure::StreamFailed, fault }
    }
}

/// Why an agent process stopped, in the one thing a parent can read.
///
/// # Why this exists
///
/// The agent runs in another session with no console, no log file and no pipe
/// to the daemon until it has already succeeded at the one thing most likely to
/// fail. Everything it could say about a failure before that point is written to
/// a stderr nobody is holding. So the *number* has to carry it.
///
/// This was not theoretical. On the first live deployment the supervisor
/// reported `exited with code 1` nine times in a row, which is true, useless,
/// and indistinguishable between "the console changed hands underneath me",
/// "the daemon's pipe would not have me" and "the screen would not open" —
/// three faults with three different remedies. Diagnosing it took a hand-driven
/// pipe client and an afternoon; the sentence below would have taken a glance.
///
/// The vocabulary lives here, beside [`agent_arguments`], because the process
/// that *chooses* a code and the supervisor that *reads* one must not hold two
/// copies of it. `1` is deliberately absent: it is what every other failure in
/// the binary exits with, so it has to keep meaning "something else".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Departure {
    /// Nothing was wrong; the link closed and the agent stopped.
    Done,
    /// It was run by a person, or with an argv this build does not understand.
    NotSpawned,
    /// Windows would not say which session this process is in.
    UnknownSession,
    /// It started in a different session from the one it was aimed at.
    WrongSession,
    /// The daemon's pipe would not have it inside its connect deadline.
    LinkRefused,
    /// It ran, and the streaming loop stopped with a fault.
    StreamFailed,
}

impl Departure {
    /// The process exit code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::NotSpawned => 2,
            Self::UnknownSession => 3,
            Self::WrongSession => 4,
            Self::LinkRefused => 5,
            Self::StreamFailed => 6,
        }
    }

    /// What a given exit code meant, or `None` for one this build did not write.
    ///
    /// Total over every `i32` a process can exit with, because the supervisor
    /// hands it whatever Windows reports — including the codes a crash produces,
    /// which are none of these and must stay unnamed rather than be guessed at.
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Done),
            2 => Some(Self::NotSpawned),
            3 => Some(Self::UnknownSession),
            4 => Some(Self::WrongSession),
            5 => Some(Self::LinkRefused),
            6 => Some(Self::StreamFailed),
            _ => None,
        }
    }

    /// What an operator should read, and what to do about it.
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Done => "the agent stopped normally",
            Self::NotSpawned => {
                "the agent was started without the arguments the daemon gives it, so it refused \
                 to run. Nothing spawned it, or this build and the daemon's disagree about the \
                 argument vector"
            }
            Self::UnknownSession => {
                "the agent could not read which session it was in, so it could not prove it \
                 belonged in the one it was sent to, and refused to capture anything"
            }
            Self::WrongSession => {
                "the agent started in a different session from the one it was aimed at \
                 — the console changed hands while it was starting. Ordinary during a fast \
                 user switch; the next attempt is aimed at wherever the console is now"
            }
            Self::LinkRefused => {
                "the agent could not reach the daemon's pipe inside its connect deadline. The \
                 pipe exists and permits this user, or the agent would have said something \
                 else — this is the instance being busy, which means one is still held by an \
                 agent that did not exit"
            }
            Self::StreamFailed => {
                "the agent connected and then its streaming loop stopped with a fault; the \
                 fault it reported is on the last status it sent"
            }
        }
    }
}

/// The subcommand the daemon spawns the agent with.
///
/// Named here, beside [`agent_arguments`] which writes it and
/// [`AgentOptions::from_arguments`] which reads it, so the daemon and the agent
/// cannot come to disagree about the one word that starts the process.
pub const AGENT_SUBCOMMAND: &str = "desk-agent";

/// The flag naming the session the daemon aimed the agent at.
pub const SESSION_FLAG: &str = "--session";

/// The flag that grants the agent an injector, and the whole of the mechanism.
///
/// Exact and valueless: `--allow-input` grants, and **every other spelling
/// refuses**, including `--allow-input=true`, `--allow-inputs` and a bare `true`
/// following it. A switch whose off position is "anything I did not recognise" is
/// the only shape of switch that stays off when a caller is upgraded, truncated
/// or wrong.
pub const ALLOW_INPUT_FLAG: &str = "--allow-input";

/// Whether this deployment permits the machine to be driven, carried from the
/// daemon's `[desktop].allow_input` into the agent process.
///
/// # Why a whole type for one bit
///
/// Because the bit crosses a process boundary and has to survive the crossing
/// with its meaning intact. `selfhost_desk`'s `Policy` already refuses to mint a
/// control ticket when the switch is off, and `selfhost_desk::viewer` already
/// refuses each input message on the daemon's side — but the agent is a *separate
/// process* that cannot read the daemon's config, and until this type existed the
/// agent built an injector unconditionally and relied entirely on the daemon
/// never forwarding it anything. That is a gate made of wiring: correct only for
/// as long as every caller upstream stays correct. With this, a deployment that
/// says `allow_input = false` has **no injector anywhere in the console session**,
/// which is a property of the process rather than of the code that talks to it.
///
/// # How it reaches the agent, and why not over the pipe
///
/// On the agent's **command line**, fixed by `CreateProcessAsUserW` at the moment
/// the daemon spawns it, read once by [`InputPolicy::from_arguments`] before the
/// link is opened, and never re-read. Deliberately *not* a message on the pipe:
/// the pipe's DACL admits `SYSTEM` and the console user's own SID (Windows cannot
/// distinguish two processes of one user on a named object), so a switch that
/// arrived as a frame would be a switch anything that can talk to the pipe could
/// assert. Nothing that can talk to the pipe can alter the argv of a process that
/// has already parsed it.
///
/// It is not a secret and does not need to be — a command line is readable by
/// every process on the machine, which is exactly why the *pipe's ACL* and not a
/// token is what authenticates the link. This value is a capability the parent
/// grants, and the two gates are independent: the daemon forwards no input when
/// its config says no, and the agent holds no injector when its argv says no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPolicy {
    /// The agent streams pixels and builds no injector at all.
    ViewOnly,
    /// The agent may build an injector and perform the input the daemon forwards.
    AllowInput,
}

impl InputPolicy {
    /// The policy `[desktop].allow_input` describes.
    pub const fn from_config(allow_input: bool) -> Self {
        if allow_input {
            Self::AllowInput
        } else {
            Self::ViewOnly
        }
    }

    /// Whether an injector may exist.
    pub const fn allows(self) -> bool {
        matches!(self, Self::AllowInput)
    }

    /// The policy an agent started with `arguments` runs under.
    ///
    /// **Fail-closed by construction**: this looks for one exact word and answers
    /// [`InputPolicy::ViewOnly`] for its absence, for a misspelling, for an empty
    /// vector, and for arguments this build has never heard of. There is no
    /// parse error to mishandle, because the only two outcomes are "the daemon
    /// asked for input" and "nothing here asked for input".
    ///
    /// `arguments` is the whole argv tail as the command-line crate hands it
    /// around, `arguments[0]` being [`AGENT_SUBCOMMAND`].
    pub fn from_arguments(arguments: &[String]) -> Self {
        if arguments.iter().any(|argument| argument == ALLOW_INPUT_FLAG) {
            Self::AllowInput
        } else {
            Self::ViewOnly
        }
    }
}

/// The argument vector the daemon spawns the agent with.
///
/// The inverse of [`InputPolicy::from_arguments`] and of the command-line crate's
/// `--session` parsing, and the only supported way to build one: an argv assembled
/// by hand somewhere else is an argv that will still be granting input a year after
/// the flag's spelling changed.
///
/// The result is the tail **excluding the program name**, which is the shape
/// `crate::windows::spawn::AgentCommand` takes — Windows is handed the executable
/// separately as `lpApplicationName`, and `crate::windows::command_line` repeats it
/// as `argv[0]`.
pub fn agent_arguments(session: u32, input: InputPolicy) -> Vec<String> {
    let mut arguments =
        vec![AGENT_SUBCOMMAND.to_owned(), SESSION_FLAG.to_owned(), session.to_string()];
    if input.allows() {
        arguments.push(ALLOW_INPUT_FLAG.to_owned());
    }
    arguments
}

/// How the agent was asked to run.
///
/// Built on every platform, though only Windows has a `run` to hand it to, so
/// that the argv contract above is exercised by the tests in this file on a
/// developer's Mac rather than only on the machine it ships to.
#[derive(Debug, Clone)]
pub struct AgentOptions {
    /// The session whose pipe to connect to. Checked against the agent's own
    /// session, because a mismatch means the daemon aimed at a session that has
    /// since been replaced and the agent must not answer for it.
    pub session: u32,
    /// What to stream under.
    pub config: StreamConfig,
    /// Whether an injector may be built at all. See [`InputPolicy`].
    pub input: InputPolicy,
}

impl AgentOptions {
    /// The options an agent invoked with `arguments` runs under.
    ///
    /// `session` is passed separately because the command-line crate has already
    /// parsed and cross-checked it — an agent must prove it is *in* the session it
    /// was aimed at before it captures anything, and that check needs the number
    /// long before this is called.
    pub fn from_arguments(session: u32, arguments: &[String]) -> Self {
        Self {
            session,
            config: StreamConfig::default(),
            input: InputPolicy::from_arguments(arguments),
        }
    }
}

#[cfg(windows)]
pub use self::windows_body::run;

/// The Windows process body: everything that only the machine itself can do.
#[cfg(windows)]
mod windows_body {
    use super::{
        decode_link, encode_link, AgentOptions, AgentReport, AgentStop, CreditWindow, Delivery,
        Departure, FrameSink, InputPolicy, LinkFrame, SendError, Streamer,
    };
    use crate::windows::{
        cursor::GdiCursor, gdi::GdiCapture, identity, inject::WinInjector, pipe::DaemonLink,
    };
    use crate::{Capture, Fault, InjectError, Injector};
    use selfhost_desk::keys::HeldKeys;
    use selfhost_desk::state::Action;
    use selfhost_desk::wire::{Message, Monitor, Refusal};
    use std::time::{Duration, Instant};

    /// The initial send window, matching the mesh's own initial grant so the two
    /// hops agree about how much may be in flight before anybody has spoken.
    const INITIAL_CREDIT: u32 = 256 * 1024;

    /// How long the agent will keep trying to reach the daemon's pipe.
    ///
    /// The agent is spawned *by* the daemon and normally finds the pipe already
    /// there; this covers the case where it wins the race. Bounded, because an
    /// agent that waits forever for a daemon that has gone away is a process
    /// nothing will ever clean up.
    const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

    /// How long one turn of the loop will wait for the daemon to say something.
    ///
    /// Short on purpose: what arrives here is credit, and a loop that waits a long
    /// time for a grant is a loop that is not capturing while it waits.
    const READ_TIMEOUT: Duration = Duration::from_millis(1);

    /// The agent's whole life.
    ///
    /// Runs until the daemon closes the link or the session state machine says to
    /// close the streams, then returns. It never retries the link by itself: the
    /// daemon is a supervisor that can watch this process die, and a process that
    /// reconnects on its own is a second recovery path that has to agree with the
    /// first one.
    ///
    /// # Errors
    ///
    /// A [`Fault`] naming the call that failed, for the exit code and the log. A
    /// closed link is **not** one: it is how the agent is asked to stop.
    pub fn run(options: AgentOptions) -> Result<(), AgentStop> {
        // The first statement, before anything asks the size of anything. Without
        // it `GetSystemMetrics` reports virtualised extents while the captured
        // pixels are physical.
        let dpi = identity::declare_dpi_awareness();

        let report = AgentReport {
            session: options.session,
            user: std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_owned()),
            window_station: identity::window_station_name()
                .unwrap_or_else(|_| "unknown".to_owned()),
            desktop: identity::input_desktop_name(),
            monitors: Vec::new(),
            dpi,
            integrity: identity::process_integrity(),
        };

        let mut screen = Screen::open();
        let report = AgentReport { monitors: screen.monitors().to_vec(), ..report };

        // Classified here rather than by the caller inspecting the fault, because
        // this is the only line that knows the failure was the *link*. A caller
        // matching on a Win32 call name would be reading an implementation
        // detail of the pipe, and would go quietly wrong the day the pipe used a
        // different call.
        let mut link = DaemonLink::connect(options.session, CONNECT_DEADLINE)
            .map_err(|fault| AgentStop { departure: Departure::LinkRefused, fault })?;
        let mut cursor = GdiCursor::new();
        let mut streamer = Streamer::new(options.config);
        let mut sink = LinkSink { link: &mut link, window: CreditWindow::new(INITIAL_CREDIT) };

        // The report is prose, not a message kind of its own: it goes as the detail
        // of the opening status so that a console too old to know about it still
        // shows the sentence.
        let hello = streamer.hello(&report);
        send_or_exit(&mut sink, &hello)?;

        let mut detail = report.sentence();
        if !options.input.allows() {
            // Said in the opening line for the same reason the desktop is: an
            // operator whose keystrokes do nothing needs the reason at the moment
            // they look, and "the config says view-only" is a thirty-second fix
            // where "nothing happens when I type" is an afternoon.
            detail.push_str(" — view-only: [desktop].allow_input is false, so this agent \
                             holds no injector at all");
        }
        if !identity::landed_interactively(&report.window_station, &report.desktop) {
            // The two failures that produce a process which runs perfectly and shows
            // nothing. Said in the opening line, because by the time anybody looks at
            // a black rectangle the useful moment to say it has passed.
            detail.push_str(
                " — NOT on the interactive desktop, so nothing here will be visible",
            );
        }
        send_or_exit(
            &mut sink,
            &Message::Status {
                notice: selfhost_desk::state::Notice::Starting,
                detail: super::truncate(&detail, selfhost_desk::wire::MAX_DETAIL_BYTES),
            },
        )?;

        // The deployment's own switch, consulted **here**, where the injector is
        // created, rather than only at the layers that forward input to it: a
        // view-only deployment must have no injector in the console session, not
        // an injector nobody currently sends anything to. Built after the link is
        // up so that a machine which cannot inject at all still streams its screen
        // — viewing and driving are separate capabilities everywhere else in this
        // subsystem and they are separate here too.
        let mut hands = Hands::open(options.input);

        loop {
            match sink.pump_incoming(&mut streamer, &mut hands)? {
                Incoming::Open => {}
                // Returning drops `hands`, which releases every key and button this
                // session left down. That is the autonomous `RELEASE_ALL`: the client
                // that would have sent one is exactly what has just disappeared.
                Incoming::Closed => return Ok(()),
            }

            let now = Instant::now();
            let tick = match streamer.tick(&mut screen, &mut cursor, &mut sink, now) {
                Ok(tick) => tick,
                Err(SendError::Closed) => return Ok(()),
                Err(SendError::Failed(fault)) => return Err(fault.into()),
            };

            // A rebuild and a suspension are the two answers that mean "the screen
            // source you have is not the one you need", and they are the only
            // moments a new one is worth building.
            if matches!(tick.action, Action::Reinitialise(_) | Action::Suspend { .. }) {
                screen.rebuild();
                // The same cause invalidates both: a display that appeared, moved or
                // changed resolution leaves the injector normalising against a
                // virtual desktop that no longer exists, and a pointer mapped against
                // a stale one lands on the wrong screen.
                hands.rebuild();
            }

            let pause = match tick.action {
                Action::Capture => streamer.frame_interval(),
                Action::WaitThen(delay)
                | Action::Reinitialise(delay)
                | Action::RespawnAgent(delay) => delay,
                Action::Suspend { poll_after } => poll_after,
                // The session is over. The agent exits and lets the daemon decide
                // whether there should be another one.
                Action::CloseStreams => return Ok(()),
            };
            if !pause.is_zero() {
                sleep(pause);
            }
        }
    }

    /// The agent's keyboard and pointer.
    ///
    /// # The deployment's switch is enforced here, not upstream of here
    ///
    /// [`InputPolicy::ViewOnly`] means [`Hands::open`] never calls
    /// `WinInjector::new` at all, so a view-only deployment has no injector
    /// anywhere in the console session — no display enumeration for pointer
    /// normalisation, no held-key record that could be posted, nothing. Every
    /// input message is answered with [`Refusal::InputDisabled`], which is the
    /// same word `selfhost_desk`'s policy uses when it refuses to mint the ticket,
    /// so the console's sentence is identical whichever gate the operator ran into.
    ///
    /// This is deliberately redundant with the daemon, which already refuses to
    /// forward input under the same config. Redundant is the point: the daemon's
    /// refusal is a property of the code that talks to this process, and this one
    /// is a property of the process.
    ///
    /// # Why the injector is optional
    ///
    /// For exactly the same reason [`Screen`] is: a session with no displays cannot
    /// build one, and that is an ordinary state a machine can spend a week in rather
    /// than a reason for the agent to exit and be respawned into the same condition
    /// forever. An absent injector refuses input with a named reason, which reaches
    /// the console, and the next rebuild tries again.
    ///
    /// # Two records of what is held, on purpose
    ///
    /// [`HeldKeys`] here is the *session's* view — what the client has asked for —
    /// and it is what [`crate::input::lower`] updates and what a `RELEASE_ALL`
    /// message drains. The injector keeps its own record of what it actually posted.
    /// They agree in the ordinary case and are allowed to disagree exactly when a
    /// batch was refused halfway through, which is the case where believing the
    /// wrong one leaves a key down on somebody else's machine.
    ///
    /// # Nothing is left held when this goes away
    ///
    /// Dropping the injector applies its release plan. That happens when the link
    /// closes and [`run`] returns, when the agent is torn down, and when a rebuild
    /// replaces it — which covers the failure the plan cares most about: the tunnel
    /// dropping mid-drag, where the client that would have sent `RELEASE_ALL` is the
    /// thing that vanished.
    struct Hands {
        /// The injector, absent when the deployment forbids one or the session
        /// could not produce one.
        injector: Option<WinInjector>,
        /// What the client believes is held.
        held: HeldKeys,
        /// Why there is no injector, for the refusal that goes back.
        absent: Option<InjectError>,
        /// Whether this deployment permits an injector at all. Kept so that
        /// [`Hands::rebuild`] cannot quietly grant one that start-up refused.
        policy: InputPolicy,
    }

    impl Hands {
        /// Builds an injector if the deployment allows one, or remembers why there
        /// is none.
        ///
        /// A refused deployment is answered before `WinInjector::new` is reached,
        /// so the view-only case is not "an injector that is never used" but no
        /// injector at all.
        fn open(policy: InputPolicy) -> Self {
            if !policy.allows() {
                return Self {
                    injector: None,
                    held: HeldKeys::new(),
                    absent: Some(InjectError::Refused(Refusal::InputDisabled)),
                    policy,
                };
            }
            match WinInjector::new() {
                Ok(injector) => {
                    Self { injector: Some(injector), held: HeldKeys::new(), absent: None, policy }
                }
                Err(reason) => {
                    Self { injector: None, held: HeldKeys::new(), absent: Some(reason), policy }
                }
            }
        }

        /// Rebuilds after the display layout changed.
        ///
        /// Called from the same place the screen source is rebuilt, because the two
        /// share a cause: a display that appeared, moved or changed resolution
        /// invalidates the coordinate mapping the injector normalises against, and a
        /// pointer mapped against a stale virtual desktop lands on the wrong screen.
        ///
        /// The old injector is dropped **before** the new one is built, so anything
        /// it left held is released first — and that is precisely why the held set
        /// is **not** carried across.
        ///
        /// The keys really are up: the outgoing injector's release plan posted an
        /// up-event for every one of them on its way out. Carrying the session's
        /// belief forward would leave this describing a keyboard that no longer
        /// exists, and the two records would then disagree in the direction that
        /// costs the operator something rather than the direction that costs them
        /// nothing. Concretely: [`crate::input::blocks_text`] would go on refusing
        /// text for a modifier nobody is holding, and the next chord would be posted
        /// by a fresh injector whose own state carries no modifier mask — so `Ctrl+C`
        /// would arrive on the far machine as a bare `C`, silently, because a monitor
        /// was unplugged mid-chord.
        ///
        /// The policy *is* carried across, because it is not session state: a
        /// display being plugged in is not a change of what the deployment
        /// permits, and a rebuild that re-derived the answer from anywhere else
        /// would be a second route to an injector.
        fn rebuild(&mut self) {
            *self = Self::open(self.policy);
        }

        /// Performs one message, or answers why it will not be.
        ///
        /// Answers `None` for a message that is not input at all — the agent's own
        /// messages arriving back, which the lowering refuses and which are not worth
        /// telling the daemon about — and for input that was performed.
        fn perform(&mut self, message: &Message) -> Option<Refusal> {
            if !is_input(message) {
                return None;
            }
            let Some(injector) = self.injector.as_mut() else {
                // No injector at all, for one of two reasons that must not be
                // confused: the deployment forbids one, which is
                // `Refusal::InputDisabled` and is permanent until an operator
                // changes the config; or the session has no displays to point at,
                // which is `NotLive` and comes back by itself. Both are already
                // recorded in `absent`, and the fallback is the second because an
                // injector that vanished without a recorded reason is a session
                // that is not live.
                return Some(
                    self.absent
                        .as_ref()
                        .and_then(InjectError::refusal)
                        .unwrap_or(Refusal::NotLive),
                );
            };
            let events = match crate::input::lower(message, injector.monitors(), &mut self.held) {
                Ok(events) => events,
                Err(reason) => return Some(reason),
            };
            match injector.inject(&events) {
                Ok(()) => None,
                // The refusals a client can act on — an elevated window, the secure
                // desktop, a missing permission — travel back. A platform fault does
                // not: it tells a remote viewer nothing and tells an attacker
                // something about the machine.
                Err(failure) => failure.refusal(),
            }
        }
    }

    /// Whether a message is input the agent should perform.
    ///
    /// Spelled out rather than inferred from the lowering's refusal, because the two
    /// answers mean different things: a `FrameEnd` arriving from the daemon is
    /// confusion and is ignored, while a `Key` that cannot be lowered is a refusal
    /// the console must see.
    fn is_input(message: &Message) -> bool {
        matches!(
            message,
            Message::Key { .. }
                | Message::Text { .. }
                | Message::PointerMove { .. }
                | Message::Button { .. }
                | Message::Scroll { .. }
                | Message::ReleaseAll
        )
    }

    /// The screen source, which may not exist yet.
    ///
    /// A session can perfectly well have no displays: it has been switched away
    /// from, it is a remote session that has disconnected, or the agent started
    /// during a mode change. An agent that exited over that would be respawned into
    /// the same condition, over and over, until the supervisor gave up and told the
    /// operator their machine was broken — which it is not.
    ///
    /// So "there is no screen source" is a screen source that answers with the state
    /// it is in. The loop above then treats it exactly like a display that has been
    /// unplugged mid-session, which is a path the state machine already handles, and
    /// the console shows the sentence instead of a dead session.
    enum Screen {
        /// A working GDI capture.
        Live(GdiCapture),
        /// None yet, and the reason.
        Absent(crate::CaptureError),
    }

    impl Screen {
        /// Builds one, or remembers why it could not.
        fn open() -> Self {
            match GdiCapture::new() {
                Ok(capture) => Self::Live(capture),
                Err(condition) => Self::Absent(condition),
            }
        }

        /// Tries again, after the session state machine asked for a rebuild.
        ///
        /// A live source is dropped and rebuilt as well, because the conditions that
        /// produce a rebuild — a resolution change, a display appearing, a driver
        /// restart — are exactly the ones whose surfaces and monitor list are now
        /// describing a screen that no longer exists.
        fn rebuild(&mut self) {
            *self = Self::open();
        }
    }

    impl Capture for Screen {
        fn monitors(&self) -> &[Monitor] {
            match self {
                Self::Live(capture) => capture.monitors(),
                Self::Absent(_) => &[],
            }
        }

        fn next_frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<crate::Frame<'_>>, crate::CaptureError> {
            match self {
                Self::Live(capture) => capture.next_frame(timeout),
                Self::Absent(condition) => Err(condition.clone()),
            }
        }
    }

    /// Whether the link is still there.
    enum Incoming {
        /// Still connected.
        Open,
        /// The daemon has gone.
        Closed,
    }

    /// The pipe, as the streamer's sink.
    struct LinkSink<'a> {
        link: &'a mut DaemonLink,
        window: CreditWindow,
    }

    impl LinkSink<'_> {
        /// Reads whatever the daemon has said and acts on it.
        ///
        /// Two things arrive here: credit grants, which are the whole reason the
        /// loop can be honest about backpressure, and desk messages — a request for
        /// a full frame, and input.
        ///
        /// **Authorisation happened before this point.** Whether this session may
        /// drive the machine at all, whether its control ticket is still fresh, and
        /// whether the deployment's kill switch is in place are the daemon's
        /// questions, asked per message on the other side of the pipe; the pipe's
        /// own ACL is what makes "the daemon said so" trustworthy. What is left to
        /// the agent is the half only the agent can answer: whether the operating
        /// system will actually deliver what it is asked to inject. Those refusals
        /// travel straight back as [`Message::InputRefused`], so a keystroke that
        /// did nothing always has a reason attached to it.
        fn pump_incoming(
            &mut self,
            streamer: &mut Streamer,
            hands: &mut Hands,
        ) -> Result<Incoming, Fault> {
            if !self.link.poll(READ_TIMEOUT)? {
                return Ok(Incoming::Closed);
            }

            // Parsed out of the link's buffer first and acted on second, so the
            // buffer is not borrowed while anything else is touched.
            let mut frames = Vec::new();
            let mut offset = 0usize;
            while let Some((frame, used)) =
                decode_link(self.link.buffered().get(offset..).unwrap_or_default())?
            {
                offset = offset.saturating_add(used);
                frames.push(frame);
            }
            self.link.consume(offset);

            for frame in frames {
                match frame {
                    LinkFrame::Credit(bytes) => self.window.grant(bytes),
                    LinkFrame::Message(bytes) => {
                        let Ok(message) = Message::decode(&bytes) else {
                            // A message this build cannot parse is the daemon
                            // speaking a newer protocol. Ignored rather than fatal:
                            // the version was agreed at the handshake, and killing a
                            // live session over one unknown frame is a worse answer
                            // than skipping it.
                            continue;
                        };
                        match message {
                            Message::RequestFullFrame { .. } => streamer.request_full_frame(),
                            other => {
                                if let Some(reason) = hands.perform(&other) {
                                    // Deliberately not `send_or_exit`: a refusal that
                                    // cannot be sent because the link has gone is not
                                    // worth failing over, and the loop's next read
                                    // notices the closure anyway.
                                    let _ = self.send(&Message::InputRefused { reason });
                                }
                            }
                        }
                    }
                }
            }
            Ok(Incoming::Open)
        }
    }

    impl FrameSink for LinkSink<'_> {
        fn send(&mut self, message: &Message) -> Result<Delivery, SendError> {
            let encoded = message
                .encode()
                .map_err(|error| SendError::Failed(Fault::refused("the desk codec", error.to_string())))?;
            let framed = encode_link(&LinkFrame::Message(encoded)).map_err(SendError::Failed)?;
            let cost = u32::try_from(framed.len())
                .map_err(|_| SendError::Failed(Fault::refused("the agent link", "frame too long")))?;
            // Asked before a byte is written, so a refusal leaves nothing on the
            // wire and the caller can drop the frame whole.
            if !self.window.spend(cost) {
                return Ok(Delivery::NoCredit);
            }
            self.link.write_all(&framed).map_err(|fault| {
                if fault.code() == Some(crate::windows::sys::ERROR_BROKEN_PIPE) {
                    SendError::Closed
                } else {
                    SendError::Failed(fault)
                }
            })?;
            Ok(Delivery::Sent(cost))
        }
    }

    /// Sends one message during start-up, where a stall cannot happen and a closed
    /// link means the daemon changed its mind before the agent finished starting.
    fn send_or_exit(sink: &mut LinkSink<'_>, message: &Message) -> Result<(), Fault> {
        match sink.send(message) {
            Ok(_) => Ok(()),
            Err(SendError::Closed) => Ok(()),
            Err(SendError::Failed(fault)) => Err(fault),
        }
    }

    /// Sleeps, on a thread that has nothing else to do.
    ///
    /// The agent's capture loop is a dedicated thread by construction — it is the
    /// process's main thread — and never a runtime worker, because
    /// `SetThreadDesktop` fails on any thread that has owned a window or a hook and
    /// a runtime worker may have run anything at all.
    fn sleep(duration: Duration) {
        let milliseconds = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
        unsafe { crate::windows::sys::Sleep(milliseconds) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::tiles::Rect;
    use selfhost_desk::wire::Refusal;
    use std::cell::RefCell;

    /// One scripted answer from a capture: pixels with their damage, nothing yet,
    /// or a state.
    type Scripted = Result<Option<(Vec<u8>, Damage)>, CaptureError>;

    /// A capture that replays a script, so every state the console must render is
    /// produced on demand on a machine with no screen.
    #[derive(Debug)]
    struct Script {
        monitors: Vec<Monitor>,
        frames: Vec<Scripted>,
        width: u32,
        height: u32,
        buffer: Vec<u8>,
        damage: Damage,
        sequence: u64,
    }

    impl Script {
        fn new(width: u32, height: u32) -> Self {
            Self {
                monitors: vec![Monitor {
                    id: 0,
                    origin_x: 0,
                    origin_y: 0,
                    width,
                    height,
                    scale_permille: 1000,
                    primary: true,
                }],
                frames: Vec::new(),
                width,
                height,
                buffer: Vec::new(),
                damage: Damage::default(),
                sequence: 0,
            }
        }

        fn frame(mut self, pixels: Vec<u8>) -> Self {
            self.frames.push(Ok(Some((pixels, Damage::default()))));
            self
        }

        fn condition(mut self, condition: CaptureError) -> Self {
            self.frames.push(Err(condition));
            self
        }
    }

    impl Capture for Script {
        fn monitors(&self) -> &[Monitor] {
            &self.monitors
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
            if self.frames.is_empty() {
                return Ok(None);
            }
            match self.frames.remove(0) {
                Ok(Some((pixels, damage))) => {
                    self.buffer = pixels;
                    self.damage = damage;
                    self.sequence += 1;
                    Ok(Some(Frame {
                        monitor: 0,
                        sequence: self.sequence,
                        width: self.width,
                        height: self.height,
                        stride: self.width as usize * 4,
                        pixels: &self.buffer,
                        damage: self.damage.clone(),
                    }))
                }
                Ok(None) => Ok(None),
                Err(condition) => Err(condition),
            }
        }
    }

    use crate::Frame;

    /// A cursor that answers whatever the test set.
    #[derive(Debug, Default)]
    struct FakeCursor {
        state: Option<CursorState>,
        forgotten: usize,
    }

    impl CursorSource for FakeCursor {
        fn cursor(&mut self) -> Result<CursorState, CaptureError> {
            self.state.clone().ok_or(CaptureError::Retry)
        }

        fn forget_shape(&mut self) {
            self.forgotten += 1;
        }
    }

    use crate::{CursorImage, CursorState, VirtualPoint};

    /// A sink with a credit budget and a log.
    #[derive(Debug, Default)]
    struct Recorder {
        credit: u32,
        unlimited: bool,
        sent: RefCell<Vec<Message>>,
        closed: bool,
    }

    impl Recorder {
        fn unlimited() -> Self {
            Self { unlimited: true, ..Self::default() }
        }

        fn with_credit(bytes: u32) -> Self {
            Self { credit: bytes, ..Self::default() }
        }

        fn tiles(&self) -> usize {
            self.sent.borrow().iter().filter(|message| matches!(message, Message::Tile(_))).count()
        }
    }

    impl FrameSink for Recorder {
        fn send(&mut self, message: &Message) -> Result<Delivery, SendError> {
            if self.closed {
                return Err(SendError::Closed);
            }
            let cost = u32::try_from(message.encode().expect("encodable").len()).unwrap_or(u32::MAX);
            if !self.unlimited {
                match self.credit.checked_sub(cost) {
                    Some(left) => self.credit = left,
                    None => return Ok(Delivery::NoCredit),
                }
            }
            self.sent.borrow_mut().push(message.clone());
            Ok(Delivery::Sent(cost))
        }
    }

    /// A solid-colour frame.
    fn solid(width: u32, height: u32, colour: [u8; 4]) -> Vec<u8> {
        colour.iter().copied().cycle().take(width as usize * height as usize * 4).collect()
    }

    /// A frame with one tile painted a different colour.
    fn one_tile_changed(width: u32, height: u32) -> Vec<u8> {
        let mut pixels = solid(width, height, [0, 0, 0, 255]);
        for y in 0..64usize {
            for x in 0..64usize {
                let at = (y * width as usize + x) * 4;
                if let Some(pixel) = pixels.get_mut(at..at + 4) {
                    pixel.copy_from_slice(&[255, 255, 255, 255]);
                }
            }
        }
        pixels
    }

    #[test]
    fn a_still_desktop_puts_nothing_at_all_on_the_wire() {
        // The plan's acceptance number for this phase: a static screen costs near
        // zero bytes a second. Not "a small frame" — nothing, not even a frame
        // header, because the difference is empty.
        let black = solid(128, 128, [0, 0, 0, 255]);
        let mut capture =
            Script::new(128, 128).frame(black.clone()).frame(black.clone()).frame(black);
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("first frame");
        let after_keyframe = sink.sent.borrow().len();
        assert!(after_keyframe > 1, "the first frame must be a full one");

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("second");
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("third");
        assert_eq!(
            sink.sent.borrow().len(),
            after_keyframe,
            "an unchanged screen must send nothing, not even an empty frame"
        );
        assert_eq!(streamer.stats().frames_unchanged, 2);
    }

    #[test]
    fn a_changed_tile_costs_one_tile_and_not_a_screen() {
        // A dragged window costs roughly its own area, which starts with one
        // changed tile costing one tile.
        let width = 256;
        let height = 128;
        let mut capture = Script::new(width, height)
            .frame(solid(width, height, [0, 0, 0, 255]))
            .frame(one_tile_changed(width, height));
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("keyframe");
        let keyframe_tiles = sink.tiles();
        assert_eq!(keyframe_tiles, 8, "a 256×128 screen is eight 64-pixel tiles");

        sink.sent.borrow_mut().clear();
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("difference");
        assert_eq!(sink.tiles(), 1, "one changed tile must cost one tile");
    }

    #[test]
    fn a_frame_that_cannot_be_afforded_is_dropped_whole_and_counted() {
        // The rule the plan states in one line: at zero credit the loop drops
        // frames rather than queueing them, and says so in its stats.
        let mut capture = Script::new(128, 128).frame(solid(128, 128, [1, 2, 3, 255]));
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::with_credit(0);
        let mut streamer = Streamer::new(StreamConfig::default());

        streamer.tick(&mut capture, &mut cursor, &mut sink, Instant::now()).expect("tick");
        assert!(sink.sent.borrow().is_empty(), "nothing may be written when nothing fits");
        assert_eq!(streamer.stats().frames_dropped, 1);
        assert!(streamer.stats().credit_stalls >= 1, "a stall must be visible to the operator");
    }

    #[test]
    fn a_dropped_frame_is_merged_rather_than_queued() {
        // Four frames captured with no credit, then credit arrives. The client must
        // be sent the *latest* picture once, not four frames of history.
        let width = 128;
        let height = 128;
        let mut capture = Script::new(width, height)
            .frame(solid(width, height, [1, 0, 0, 255]))
            .frame(solid(width, height, [2, 0, 0, 255]))
            .frame(solid(width, height, [3, 0, 0, 255]))
            .frame(solid(width, height, [4, 0, 0, 255]));
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::with_credit(0);
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        for _ in 0..3 {
            streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("starved tick");
        }
        assert_eq!(streamer.stats().frames_dropped, 3);
        assert!(sink.sent.borrow().is_empty());

        sink.unlimited = true;
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("funded tick");
        let frames = sink
            .sent
            .borrow()
            .iter()
            .filter(|message| matches!(message, Message::FrameBegin(_)))
            .count();
        assert_eq!(frames, 1, "the backlog must not be replayed, only the present sent");
        // The pixels that arrived are the last frame's, not the first's.
        let tile = sink
            .sent
            .borrow()
            .iter()
            .find_map(|message| match message {
                Message::Tile(tile) => Some(tile.payload.clone()),
                _ => None,
            })
            .expect("a tile");
        assert_eq!(tile.first(), Some(&4), "the present, not the backlog");
    }

    #[test]
    fn a_frame_cut_short_by_a_stall_re_offers_the_tiles_it_could_not_afford() {
        // The merge mechanism, stated as an invariant: the model advances only for
        // tiles that went out, so the rest come back on the next difference.
        let width = 256;
        let height = 128;
        let mut capture = Script::new(width, height)
            .frame(solid(width, height, [9, 9, 9, 255]))
            .frame(solid(width, height, [9, 9, 9, 255]));
        let mut cursor = FakeCursor::default();
        // Enough for a frame header and a couple of tiles, not for eight.
        let mut sink = Recorder::with_credit(120);
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("partial frame");
        let first = sink.tiles();
        assert!(first > 0 && first < 8, "the frame must be cut short, not dropped or complete");
        assert!(streamer.stats().tiles_deferred > 0);

        sink.unlimited = true;
        sink.sent.borrow_mut().clear();
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("the rest");
        assert_eq!(
            sink.tiles(),
            8 - first,
            "exactly the tiles that were never delivered must be re-offered"
        );
    }

    #[test]
    fn the_secure_desktop_reaches_the_console_as_a_sentence() {
        // The failure this is designed against is a frozen frame. A UAC prompt must
        // produce prose, and the prose must name what the operator has to do.
        let mut capture = Script::new(64, 64).condition(CaptureError::SecureDesktop);
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());

        let tick = streamer.tick(&mut capture, &mut cursor, &mut sink, Instant::now()).expect("tick");
        assert_eq!(tick.notice, Some(Notice::SecureDesktop));
        let status = sink
            .sent
            .borrow()
            .iter()
            .find_map(|message| match message {
                Message::Status { notice, detail } => Some((*notice, detail.clone())),
                _ => None,
            })
            .expect("a status message");
        assert_eq!(status.0, Notice::SecureDesktop);
        assert!(status.1.contains("secure desktop"), "{}", status.1);
        assert!(status.1.len() <= MAX_DETAIL_BYTES);
    }

    #[test]
    fn every_state_the_screen_can_be_in_produces_a_notice_and_never_an_error() {
        // No user logged in, a session switch, a rebuild, a locked screen: each is
        // a sentence, and none of them stops the loop.
        for condition in [
            CaptureError::NoSession,
            CaptureError::SessionDisconnected,
            CaptureError::Reinitialise,
            CaptureError::SecureDesktop,
            CaptureError::TooManyDuplications,
        ] {
            let mut capture = Script::new(64, 64).condition(condition.clone());
            let mut cursor = FakeCursor::default();
            let mut sink = Recorder::unlimited();
            let mut streamer = Streamer::new(StreamConfig::default());
            let tick = streamer
                .tick(&mut capture, &mut cursor, &mut sink, Instant::now())
                .unwrap_or_else(|_| panic!("{condition:?} must not stop the loop"));
            assert!(tick.notice.is_some(), "{condition:?} produced no notice");
            let detail = sink
                .sent
                .borrow()
                .iter()
                .find_map(|message| match message {
                    Message::Status { detail, .. } => Some(detail.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            assert!(detail.ends_with('.'), "{condition:?} did not read as a sentence: {detail}");
        }
    }

    #[test]
    fn a_permission_refusal_reaches_the_console_as_the_remediation_itself() {
        // The failure this closes: a console that says "permission denied" sends an
        // operator looking, and a console that shows a picture of the wallpaper
        // sends them nowhere at all. What travels is the sentence they can act on.
        let mut capture = Script::new(64, 64)
            .condition(CaptureError::PermissionDenied(Grant::ScreenRecording));
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let tick = streamer
            .tick(&mut capture, &mut cursor, &mut sink, Instant::now())
            .expect("a refused permission is a state, not an error");
        assert_eq!(tick.notice, Some(Notice::PermissionDenied));

        let detail = sink
            .sent
            .borrow()
            .iter()
            .find_map(|message| match message {
                Message::Status { detail, .. } => Some(detail.clone()),
                _ => None,
            })
            .expect("a status message");
        assert!(
            detail.contains("System Settings › Privacy & Security › Screen Recording"),
            "the pane must be named exactly: {detail}"
        );
        assert!(detail.contains("relaunch"), "the fresh-launch requirement: {detail}");
        assert!(detail.len() <= MAX_DETAIL_BYTES);
        assert!(detail.ends_with('.'), "{detail}");
    }

    #[test]
    fn the_two_grants_produce_two_different_remediations() {
        // They are two panes and two independent grants; one sentence for both would
        // send half the operators to the wrong place.
        let screen = detail_for(
            Notice::PermissionDenied,
            Observation::PermissionDenied,
            Some(Grant::ScreenRecording),
        );
        let input = detail_for(
            Notice::PermissionDenied,
            Observation::PermissionDenied,
            Some(Grant::Accessibility),
        );
        assert_ne!(screen, input);
        assert!(input.contains("Accessibility"));
        // And with nothing recorded there is still a sentence rather than a blank.
        let unknown = detail_for(Notice::PermissionDenied, Observation::PermissionDenied, None);
        assert!(unknown.ends_with('.'));
    }

    #[test]
    fn a_state_forgets_what_the_client_holds_so_the_next_frame_is_whole() {
        // A picture from before a UAC prompt is not a picture of what is on screen
        // after it, and a difference against it would leave the console holding a
        // composite of two moments.
        let pixels = solid(64, 64, [7, 7, 7, 255]);
        let mut capture = Script::new(64, 64)
            .frame(pixels.clone())
            .condition(CaptureError::SecureDesktop)
            .frame(pixels);
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("first");
        assert_eq!(streamer.stats().keyframes, 1);
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("secure desktop");
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("back again");
        assert_eq!(streamer.stats().keyframes, 2, "the frame after a state must be a whole one");
    }

    #[test]
    fn the_pointer_moves_without_the_picture_moving() {
        // The perceived-latency win, as an assertion: a pointer that moves over a
        // still desktop costs one small message and no tiles.
        let black = solid(64, 64, [0, 0, 0, 255]);
        let mut capture = Script::new(64, 64).frame(black.clone()).frame(black);
        let mut cursor = FakeCursor {
            state: Some(CursorState {
                visible: true,
                position: VirtualPoint { x: 10, y: 10 },
                shape: Some(CursorImage {
                    id: 42,
                    width: 2,
                    height: 2,
                    hotspot_x: 0,
                    hotspot_y: 0,
                    bgra: vec![255; 16],
                }),
            }),
            forgotten: 0,
        };
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("first");
        assert_eq!(streamer.stats().cursor_shapes, 1, "the bitmap goes once");

        sink.sent.borrow_mut().clear();
        cursor.state = Some(CursorState {
            visible: true,
            position: VirtualPoint { x: 11, y: 10 },
            shape: None,
        });
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("moved");
        let sent = sink.sent.borrow();
        assert_eq!(sent.len(), 1, "a moved pointer over a still screen is one message");
        assert!(matches!(sent.first(), Some(Message::CursorPos(_))));
    }

    #[test]
    fn a_still_pointer_costs_nothing_and_the_bitmap_goes_once() {
        let black = solid(64, 64, [0, 0, 0, 255]);
        let mut capture = Script::new(64, 64).frame(black.clone()).frame(black.clone()).frame(black);
        let mut cursor = FakeCursor {
            state: Some(CursorState {
                visible: true,
                position: VirtualPoint { x: 3, y: 4 },
                shape: Some(CursorImage {
                    id: 7,
                    width: 1,
                    height: 1,
                    hotspot_x: 0,
                    hotspot_y: 0,
                    bgra: vec![0; 4],
                }),
            }),
            forgotten: 0,
        };
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("first");
        cursor.state = Some(CursorState {
            visible: true,
            position: VirtualPoint { x: 3, y: 4 },
            shape: None,
        });
        sink.sent.borrow_mut().clear();
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("still");
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("still again");
        assert!(sink.sent.borrow().is_empty(), "a motionless pointer must cost nothing");
        assert_eq!(streamer.stats().cursor_shapes, 1);
    }

    #[test]
    fn an_evicted_shape_asks_the_source_to_send_the_bitmap_again() {
        // The two caches — the platform source's and the client's — drift exactly
        // here, and this is the mechanism that puts them back in step.
        let black = solid(64, 64, [0, 0, 0, 255]);
        let mut capture = Script::new(64, 64).frame(black);
        let mut cursor = FakeCursor {
            state: Some(CursorState {
                visible: true,
                position: VirtualPoint { x: 0, y: 0 },
                // The source says "you already have this shape" by sending no
                // bitmap, while the policy has evicted it.
                shape: None,
            }),
            forgotten: 0,
        };
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        streamer.tick(&mut capture, &mut cursor, &mut sink, Instant::now()).expect("tick");
        assert!(cursor.forgotten >= 1, "the source must be asked to resend the bitmap");
    }

    #[test]
    fn a_closed_link_ends_the_tick_rather_than_being_swallowed() {
        let mut capture = Script::new(64, 64).frame(solid(64, 64, [0, 0, 0, 255]));
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder { closed: true, ..Recorder::unlimited() };
        let mut streamer = Streamer::new(StreamConfig::default());
        assert_eq!(
            streamer.tick(&mut capture, &mut cursor, &mut sink, Instant::now()),
            Err(SendError::Closed)
        );
    }

    #[test]
    fn a_full_frame_request_forgets_the_client_model() {
        let black = solid(64, 64, [0, 0, 0, 255]);
        let mut capture = Script::new(64, 64).frame(black.clone()).frame(black);
        let mut cursor = FakeCursor::default();
        let mut sink = Recorder::unlimited();
        let mut streamer = Streamer::new(StreamConfig::default());
        let now = Instant::now();

        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("first");
        streamer.request_full_frame();
        sink.sent.borrow_mut().clear();
        streamer.tick(&mut capture, &mut cursor, &mut sink, now).expect("second");
        assert_eq!(sink.tiles(), 1, "the identical screen must be sent again in full");
        assert_eq!(streamer.stats().keyframes, 2);
    }

    #[test]
    fn a_damage_hint_collapses_rather_than_growing_without_bound() {
        // A hint that has to be consulted rectangle by rectangle costs more than the
        // comparison it replaces, past a point.
        let mut hint = DamageHint::new();
        for index in 0..(MAX_HINT_RECTS + 10) {
            let mut damage = Damage::default();
            damage.dirty.push(Rect::new(index as i32, 0, 8, 8));
            hint.merge(&damage);
        }
        assert!(hint.is_whole_frame(), "an unbounded hint must collapse to the whole frame");
        assert!(hint.damage().dirty.is_empty(), "and must hold nothing once it has");
    }

    #[test]
    fn an_empty_damage_report_means_everything_changed_not_nothing() {
        // GDI reports no rectangles on every frame because it cannot know. Reading
        // that as "nothing changed" would freeze the picture permanently.
        let mut hint = DamageHint::new();
        hint.merge(&Damage::default());
        assert!(hint.is_whole_frame());
    }

    #[test]
    fn a_damage_hint_narrows_the_comparison_when_the_platform_reports_one() {
        // The path a DXGI backend would take: only the tiles the platform named are
        // compared, and a change outside them is deliberately not looked for.
        let previous = Surface::blank(128, 128).expect("blank");
        let current = Surface::new(128, 128, solid(128, 128, [5, 5, 5, 255])).expect("solid");
        let mut hint = DamageHint::new();
        let mut damage = Damage::default();
        damage.dirty.push(Rect::new(0, 0, 8, 8));
        hint.merge(&damage);

        let updates = changed_tiles(Some(&previous), &current, TileSize::default(), &hint)
            .expect("a difference");
        assert_eq!(updates.len(), 1, "only the hinted tile is compared");

        // And with no hint, the whole grid is compared.
        let mut whole = DamageHint::new();
        whole.merge(&Damage::default());
        let updates = changed_tiles(Some(&previous), &current, TileSize::default(), &whole)
            .expect("a difference");
        assert_eq!(updates.len(), 4, "a 128×128 screen is four 64-pixel tiles");
    }

    #[test]
    fn a_report_reads_as_one_line_naming_everything_that_can_be_wrong() {
        let report = AgentReport {
            session: 1,
            user: "ALEX".to_owned(),
            window_station: "WinSta0".to_owned(),
            desktop: "Default".to_owned(),
            monitors: vec![
                Monitor {
                    id: 0,
                    origin_x: 0,
                    origin_y: 0,
                    width: 2560,
                    height: 1440,
                    scale_permille: 1500,
                    primary: true,
                },
                Monitor {
                    id: 1,
                    origin_x: 2560,
                    origin_y: 0,
                    width: 1920,
                    height: 1080,
                    scale_permille: 1000,
                    primary: false,
                },
            ],
            dpi: DpiAwareness::PerMonitorV2,
            integrity: Integrity::Medium,
        };
        let line = report.sentence();
        assert!(line.contains("session 1"), "{line}");
        assert!(line.contains("as ALEX"), "{line}");
        assert!(line.contains("WinSta0\\Default"), "{line}");
        assert!(line.contains("2 monitors"), "{line}");
        assert!(line.contains("per-monitor-v2"), "{line}");
        assert!(line.contains("medium-integrity"), "{line}");
    }

    #[test]
    fn one_monitor_is_not_reported_as_one_monitors() {
        let report = AgentReport {
            session: 2,
            user: "A".to_owned(),
            window_station: "WinSta0".to_owned(),
            desktop: "Default".to_owned(),
            monitors: vec![Monitor {
                id: 0,
                origin_x: 0,
                origin_y: 0,
                width: 800,
                height: 600,
                scale_permille: 1000,
                primary: true,
            }],
            dpi: DpiAwareness::Unaware,
            integrity: Integrity::Other(0x1234),
        };
        let line = report.sentence();
        assert!(line.contains("1 monitor ·"), "{line}");
        assert!(line.contains("dpi-unaware"), "{line}");
        assert!(line.contains("integrity-0x1234"), "{line}");
    }

    #[test]
    fn an_integrity_level_is_named_where_windows_has_a_name_for_it() {
        assert_eq!(Integrity::from_rid(0x2000), Integrity::Medium);
        assert_eq!(Integrity::from_rid(0x3000), Integrity::High);
        assert_eq!(Integrity::from_rid(0x4000), Integrity::System);
        assert_eq!(Integrity::from_rid(0x2100), Integrity::Other(0x2100));
    }

    #[test]
    fn a_credit_window_never_lets_more_out_than_it_holds() {
        let mut window = CreditWindow::new(100);
        assert!(window.spend(60));
        assert_eq!(window.available(), 40);
        assert!(!window.spend(41), "a window must refuse rather than wrap");
        assert_eq!(window.stalls(), 1);
        assert_eq!(window.available(), 40, "a refused send must cost nothing");
        window.grant(u32::MAX);
        assert_eq!(window.available(), u32::MAX, "a grant that overflows saturates");
    }

    #[test]
    fn a_link_frame_survives_the_round_trip() {
        let message = LinkFrame::Message(vec![1, 2, 3, 4]);
        let bytes = encode_link(&message).expect("encodable");
        assert_eq!(bytes.len(), 9);
        let (decoded, used) = decode_link(&bytes).expect("valid").expect("whole");
        assert_eq!(decoded, message);
        assert_eq!(used, bytes.len());

        let credit = LinkFrame::Credit(65_536);
        let bytes = encode_link(&credit).expect("encodable");
        let (decoded, _) = decode_link(&bytes).expect("valid").expect("whole");
        assert_eq!(decoded, credit);
    }

    #[test]
    fn a_partial_link_frame_is_not_yet_a_frame() {
        let bytes = encode_link(&LinkFrame::Message(vec![9; 40])).expect("encodable");
        for cut in 0..bytes.len() {
            assert_eq!(
                decode_link(bytes.get(..cut).unwrap_or_default()).expect("no error"),
                None,
                "a short buffer is not an error, it is a read that has not finished"
            );
        }
    }

    #[test]
    fn a_link_frame_cannot_make_the_agent_allocate_by_lying() {
        // The property the whole crate graph depends on under `panic = "abort"`: a
        // claimed length is checked before anything is reserved.
        let mut hostile = vec![LINK_MESSAGE];
        hostile.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_link(&hostile).is_err());

        let mut unknown = vec![0xEE];
        unknown.extend_from_slice(&0u32.to_be_bytes());
        assert!(decode_link(&unknown).is_err());

        let mut short_credit = vec![LINK_CREDIT];
        short_credit.extend_from_slice(&1u32.to_be_bytes());
        short_credit.push(0);
        assert!(decode_link(&short_credit).is_err());
    }

    #[test]
    fn a_cursor_too_large_for_the_wire_is_dropped_rather_than_refused() {
        let huge = CursorImage {
            id: 1,
            width: 256,
            height: 256,
            hotspot_x: 0,
            hotspot_y: 0,
            bgra: vec![0; 256 * 256 * 4],
        };
        assert!(shape_message(&huge).is_none());

        let lying = CursorImage {
            id: 2,
            width: 8,
            height: 8,
            hotspot_x: 0,
            hotspot_y: 0,
            bgra: vec![0; 4],
        };
        assert!(shape_message(&lying).is_none(), "a buffer that does not match its extent");
    }

    #[test]
    fn a_detail_line_is_bounded_on_a_character_boundary() {
        let long = "é".repeat(500);
        let cut = truncate(&long, MAX_DETAIL_BYTES);
        assert!(cut.len() <= MAX_DETAIL_BYTES);
        assert!(cut.chars().all(|character| character == 'é'), "no half characters");
    }

    #[test]
    fn a_frame_rate_of_zero_is_a_ceiling_of_none_rather_than_a_division_by_zero() {
        let streamer = Streamer::new(StreamConfig { max_fps: 0, ..StreamConfig::default() });
        assert_eq!(streamer.frame_interval(), Duration::ZERO);
        let streamer = Streamer::new(StreamConfig { max_fps: 30, ..StreamConfig::default() });
        assert!(streamer.frame_interval() > Duration::from_millis(30));
    }

    #[test]
    fn a_refusal_is_never_confused_with_a_capture_state() {
        // Guards the seam between the two error vocabularies: an input refusal is
        // the client's business and a capture state is the console's.
        assert_eq!(Refusal::NotPermitted.code(), Refusal::NotPermitted.code());
        assert!(!CaptureError::SecureDesktop.is_fatal());
    }

    #[test]
    fn the_switch_survives_the_process_boundary_in_both_positions() {
        // The whole contract in one test: what the daemon writes is what the
        // agent reads, for both answers, so neither half can be changed alone.
        for (configured, expected) in
            [(false, InputPolicy::ViewOnly), (true, InputPolicy::AllowInput)]
        {
            let policy = InputPolicy::from_config(configured);
            let argv = agent_arguments(7, policy);
            assert_eq!(argv.first().map(String::as_str), Some(AGENT_SUBCOMMAND));
            assert!(argv.contains(&"7".to_owned()), "the session travels too: {argv:?}");
            assert_eq!(InputPolicy::from_arguments(&argv), expected, "{argv:?}");
            assert_eq!(AgentOptions::from_arguments(7, &argv).input, expected);
        }
    }

    #[test]
    fn a_view_only_deployment_puts_no_grant_anywhere_in_the_argv() {
        // Not merely "the parser answers ViewOnly": the word must not be on the
        // command line at all, because the command line is what a later reader —
        // a log, an operator, a different parser — will believe.
        let argv = agent_arguments(3, InputPolicy::ViewOnly);
        assert!(
            !argv.iter().any(|argument| argument.contains("allow-input")),
            "a view-only spawn must not mention input at all: {argv:?}"
        );
    }

    #[test]
    fn anything_that_is_not_the_exact_flag_leaves_input_off() {
        // The fail-closed property, stated as the cases that have actually gone
        // wrong elsewhere: a value-taking spelling, a plural, a stray `true`, a
        // flag for something else, and nothing at all.
        let refused = [
            vec![],
            vec!["desk-agent".to_owned()],
            vec!["--allow-input=true".to_owned()],
            vec!["--allow-inputs".to_owned()],
            vec!["--allow".to_owned(), "input".to_owned()],
            vec!["--session".to_owned(), "true".to_owned()],
            vec!["allow-input".to_owned()],
            vec![" --allow-input".to_owned()],
        ];
        for argv in refused {
            assert_eq!(
                InputPolicy::from_arguments(&argv),
                InputPolicy::ViewOnly,
                "{argv:?} must not grant an injector"
            );
        }
    }

    #[test]
    fn only_the_configured_switch_can_open_the_door() {
        // `from_config` is the single place the daemon's boolean becomes a policy,
        // and `allows` is the single question the agent asks before it builds an
        // injector. Both directions are pinned so a later refactor cannot invert
        // one of them silently.
        assert!(!InputPolicy::from_config(false).allows());
        assert!(InputPolicy::from_config(true).allows());
        assert!(!InputPolicy::ViewOnly.allows());
        assert!(InputPolicy::AllowInput.allows());
    }
}
