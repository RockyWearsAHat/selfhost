//! Keeping a capture agent alive in the session a person is sitting in.
//!
//! # The problem this module exists for
//!
//! On the production box the daemon is a Scheduled Task running as `SYSTEM` at
//! system startup, which is **session 0**: a session with no interactive
//! display, where `DuplicateOutput` fails and `GetDC(NULL)` hands back a device
//! context for session 0's own blank desktop. No amount of care inside that
//! process reaches the screen somebody is looking at. The pixels have to be
//! captured by a second process running *inside* the console session, started
//! with `CreateProcessAsUserW` and reached over
//! `\\.\pipe\selfhost-desk-<session>`.
//!
//! `selfhost-screen` owns both halves of that — the supervision state machine
//! ([`Agent`](selfhost_screen::supervisor::Agent)), the spawn (`WindowsHost`) and the
//! pipe with its explicit DACL
//! (`AgentPipe`) — and until this module existed **the daemon called none of
//! them**. The agent was written, tested and unreachable: nothing in
//! `crates/cli` mentioned the supervisor, so no agent was ever started and no
//! pipe was ever created. This file is the join.
//!
//! # What is joined, and in what order
//!
//! 1. **The pipe first.** `AgentPipe::for_console_session` resolves the console
//!    user's token, reads the SID off it and builds a descriptor naming only
//!    `SYSTEM` and that user. It is readied *before* the tick that spawns,
//!    because the agent's own connect deadline is ten seconds and a pipe that
//!    arrives late costs a whole spawn out of the hour's budget. The one
//!    exception is the very first turn of a supervisor's life, when nothing has
//!    yet observed which session the console is in; that single race is the one
//!    the agent's own ten-second connect retry exists for, and it is covered by
//!    the driver's second readying, which runs microseconds after the spawn.
//! 2. **The spawn.** [`Agent::tick`](selfhost_screen::supervisor::Agent::tick)
//!    decides; `WindowsHost` performs. The
//!    argument vector is built by the host from the session and the deployment's
//!    [`InputPolicy`], never assembled here — see the note on `allow_input`
//!    below, which is the most consequential paragraph in this file.
//! 3. **The connect.** The first framed message that arrives on the pipe is the
//!    agent's `Hello`, and it is the cue for
//!    [`Agent::connected`](selfhost_screen::supervisor::Agent::connected). Without that
//!    call the supervisor kills the agent at its start deadline as
//!    `NeverConnected` and charges it a failure — so a supervisor that spawns and
//!    never pumps is worse than one that never spawns at all.
//!
//! Everything that is not a failure is a *state*: nobody logged in, a console
//! mid-attach, a fast user switch, RDP taking the session away. None of them
//! count against the respawn budget and all of them are rendered as prose, because
//! a machine at its login screen is a machine working correctly.
//!
//! # How the agent's frames reach a viewer
//!
//! This module supervises the agent and pumps its pipe; it does not interpret
//! what comes off it. A session attaches with [`CaptureAgent::attach`] and is
//! handed the two ends of that pipe as channels — the agent's whole encoded
//! messages coming out, and messages going in — and
//! [`selfhost_desk::relay::Relay`] is the driver that carries them, applying
//! this session's own deadline, capability re-check and kill switch to a byte
//! stream it never decodes.
//!
//! Exactly one session attaches at a time, and that is a property of the agent
//! rather than a limit chosen here: the agent holds a model of *the* client's
//! surface and sends the difference against it, so a second viewer on one agent
//! would be sent the difference against somebody else's picture. The refusal
//! says so.
//!
//! Two things are deliberately *not* in this file. The relay never blocks this
//! thread — a session that stops reading is detached, because this thread is
//! also what keeps the supervisor's belief that the agent is alive true. And
//! nothing here decides what a missing message means: a quiet pipe on a still
//! desktop, a dead agent and an engaged kill switch are three different answers
//! and [`crate::desk_task`] is where they are told apart.
//!
//! # `allow_input = false` cannot produce an injector by this route
//!
//! The policy is read **once**, from `[desktop].allow_input`, at
//! [`CaptureAgent::start`], and handed to `WindowsHost::new`. Nothing here builds
//! an argument vector: the host derives one per spawn from
//! [`selfhost_screen::agent::agent_arguments`], which appends `--allow-input`
//! only for [`InputPolicy::AllowInput`]. A view-only deployment therefore starts
//! an agent that never calls `WinInjector::new` at all — not an injector that is
//! asked to refuse, but no injector in the console session in the first place.
//! [`CaptureAgent::input_policy`] exposes what was actually handed over, and the
//! tests below assert it against the argv a spawn really produces.
//!
//! # Nothing here binds a socket
//!
//! A named pipe is a kernel object with a security descriptor, not a listener:
//! no port, no address, and nothing off the machine can reach it. The admin API
//! stays on `127.0.0.1:9191` and the only public surface remains the proxy on
//! 80/443.

use selfhost_desk::state::Notice;
use selfhost_desk::wire::Monitor;
use selfhost_screen::agent::InputPolicy;
use selfhost_screen::supervisor::Limits;
// The supervisor and its fault type are the driver's, and the driver is compiled
// where it runs (Windows) and where it is exercised (any platform's tests). See
// the section header below for why that split is the honest one.
#[cfg(any(windows, test))]
use selfhost_screen::supervisor::Agent;
#[cfg(any(windows, test))]
use selfhost_screen::Fault;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the daemon can say about the capture agent right now.
///
/// One value, published by the supervision thread and read by everything that
/// reports — the startup banner, the console's agent report, `doctor` through the
/// admin API. It is prose plus the two facts a machine wants (the wire [`Notice`]
/// and the session id), because every consumer renders a sentence and inventing a
/// second vocabulary per consumer is how two parts of one program come to
/// disagree about the same machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    /// Whether this deployment supervises an agent at all.
    ///
    /// False is the ordinary answer nearly everywhere: a Mac has no session-0
    /// problem, and a Windows daemon started from a signed-in session is already
    /// in the session it wants to capture.
    pub supervised: bool,
    /// Whether an agent is running and has identified itself.
    pub live: bool,
    /// The session it is in, or the one it is being started in.
    pub session: Option<u32>,
    /// The state as the protocol names it, for a console.
    pub notice: Notice,
    /// The state in words, for a person.
    pub sentence: String,
    /// How many displays the agent reported, once it has said.
    pub monitors: u32,
    /// The last thing that went wrong, if anything has.
    ///
    /// Kept rather than logged and dropped: "no agent is running" without a
    /// reason is what sends an operator to reboot a machine.
    pub fault: Option<String>,
    /// How many agents have been started in the last hour, against the cap.
    pub spawns_last_hour: u32,
}

impl AgentStatus {
    /// The status of a deployment that supervises nothing, and why.
    ///
    /// Not an error and not an absence: a machine that captures its own screen
    /// directly has no agent by design, and saying so is the difference between a
    /// feature that is off and one that is broken.
    pub fn not_supervised(why: impl Into<String>) -> Self {
        Self {
            supervised: false,
            live: false,
            session: None,
            // Nothing is wrong here, which is what this notice says. Every
            // consumer reads `supervised` first — a machine with no agent has no
            // agent phase to render — and a code meaning "recovering" or "gave
            // up" would draw an alarm on a deployment that is working exactly as
            // designed.
            notice: Notice::Live,
            sentence: why.into(),
            monitors: 0,
            fault: None,
            spawns_last_hour: 0,
        }
    }

    /// The whole thing as one line for a banner or a status plate.
    ///
    /// Built here so the daemon's banner, the console's agent report and
    /// `doctor` cannot drift into three different sentences about one machine.
    pub fn line(&self) -> String {
        match self.fault.as_deref() {
            Some(fault) if !self.live => format!("{} (last fault: {fault})", self.sentence),
            _ => self.sentence.clone(),
        }
    }
}

/// The daemon's half of the capture agent's life.
///
/// Held in the [`Arc`] the daemon keeps the desktop subsystem in. Every mutable
/// part is behind the one lock the supervision thread holds for the microsecond
/// it takes to publish a status, so a console request never waits on a platform
/// call.
#[derive(Debug)]
pub struct CaptureAgent {
    shared: Arc<Shared>,
    /// The policy that was handed to the spawner, kept so it can be asserted.
    ///
    /// Not consulted by the loop — the host holds the authoritative copy — and
    /// deliberately so: two places deciding whether input is allowed is how one
    /// of them comes to be wrong.
    input: InputPolicy,
}

/// How many of the agent's messages may wait for the session that is relaying
/// them.
///
/// Deep enough that one keyframe — about fifteen hundred tiles for a Retina
/// panel — does not stall the pipe reader mid-frame, and no deeper: the queue is
/// not the flow control. That is [`selfhost_desk::relay`]'s credit, which the
/// agent honours by dropping and merging whole frames rather than by letting a
/// backlog build here. A queue that could hold *two* keyframes would be a queue
/// that can show the operator a picture two frames old, which is the outcome the
/// whole drop-and-merge design exists to prevent.
const RELAY_DEPTH: usize = 2048;

/// How many input messages may wait for the pipe.
///
/// Small, and small on purpose: input is keystrokes and pointer samples, both
/// worthless late. A deep queue here would deliver a burst of clicks to a
/// desktop that has moved on. The one thing that must never be dropped is a key
/// *release*, and the relay's close path sends
/// [`selfhost_desk::wire::Message::ReleaseAll`] rather than replaying a queue,
/// so a full queue cannot leave a modifier held.
const INPUT_DEPTH: usize = 64;

/// The two ends of one relayed session, as the supervision thread holds them.
///
/// Exactly one exists at a time — see [`CaptureAgent::attach`] — because the
/// agent holds a model of *the* client's surface and diffs against it. Two
/// sessions sharing one agent would each be sent the difference against the
/// other's picture.
//
// Read by the supervision loop, which only Windows has. The type is not gated,
// because [`AgentStream`] and [`CaptureAgent::attach`] are the seam a session
// driver is written and tested against on any platform, and a slot that existed
// only on Windows would make that seam untestable on the machine it is developed
// on.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Debug)]
struct Attachment {
    /// The agent's messages, on their way to the console.
    frames: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Messages on their way to the agent, drained by the supervision thread.
    input: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

/// One relayed session's handle on the agent.
///
/// Held by the session driver; dropping it detaches, which is what frees the
/// agent for the next session. The [`selfhost_desk::relay::Upstream`]
/// implementation over it lives in [`crate::desk_task`], because what a missing
/// message *means* — a still desktop, a dead agent, an engaged kill switch — is
/// the daemon's knowledge and not this module's.
#[derive(Debug)]
pub struct AgentStream {
    /// The agent's messages, whole and unparsed.
    pub frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Where an input message goes.
    pub input: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Released on drop, so the next session can attach.
    held: Arc<Shared>,
}

impl Drop for AgentStream {
    fn drop(&mut self) {
        detach(&self.held);
    }
}

/// Clears the attachment slot.
///
/// A free function rather than a method on [`Shared`] so that [`AgentStream`]'s
/// `Drop` and the supervision thread's own give-up path are visibly the same
/// act.
fn detach(shared: &Arc<Shared>) {
    match shared.attached.lock() {
        Ok(mut held) => *held = None,
        Err(poisoned) => *poisoned.into_inner() = None,
    }
}

/// Everything the supervision thread and the daemon both touch.
///
/// `pub(crate)` only because the driver's constructor takes one and the driver is
/// `pub(crate)` for its tests; nothing outside this module builds or reads it.
#[derive(Debug)]
pub(crate) struct Shared {
    /// The published status, replaced whole on every turn.
    status: Mutex<AgentStatus>,
    /// The displays the agent named in its `Hello`.
    ///
    /// Kept whole rather than counted, because a relayed session advertises this
    /// list to the console verbatim: the ids in it are the ids the agent's own
    /// frames and the console's pointer coordinates are expressed in, and a
    /// count cannot carry them.
    displays: Mutex<Vec<Monitor>>,
    /// The one relayed session, when a session has attached.
        attached: Mutex<Option<Attachment>>,
    /// Whether the operator's kill switch is in place, as the daemon last read
    /// it. A flag rather than a second filesystem check, so the streams and the
    /// agent can never hold different beliefs about a switch that exists
    /// precisely to be believed immediately.
    kill_switch: AtomicBool,
    /// Set by the console's start button, cleared by the turn that consumes it.
    ///
    /// A request rather than a call, because pressing start must reach a thread
    /// that may be inside a fifty-millisecond pipe wait, and a lock held across
    /// that wait would make the button feel broken.
    operator_start: AtomicBool,
}

impl Shared {
    /// The published status.
    ///
    /// The lock cannot be poisoned — this workspace builds with `panic = "abort"`,
    /// so no thread can unwind while holding it — but the recovery is written
    /// anyway rather than an `expect`, because a status line is not worth ending
    /// a daemon over under any future build profile.
    fn status(&self) -> AgentStatus {
        match self.status.lock() {
            Ok(status) => status.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replaces the published status.
    ///
    /// Only the supervision thread writes, and only Windows has one.
    #[cfg(windows)]
    fn publish(&self, status: AgentStatus) {
        match self.status.lock() {
            Ok(mut held) => *held = status,
            Err(poisoned) => *poisoned.into_inner() = status,
        }
    }

    /// The displays the agent last named.
    fn displays(&self) -> Vec<Monitor> {
        match self.displays.lock() {
            Ok(held) => held.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl CaptureAgent {
    /// Starts supervising an agent, or publishes why this machine needs none.
    ///
    /// Called once, by the daemon, when `[desktop]` is present and enabled.
    /// Whether an agent is needed is decided **at run time**, because both
    /// Windows deployments are real: a daemon installed as a service is in
    /// session 0 and must have an agent, and the same binary run from a terminal
    /// is already in the console user's session and must not — that would be a
    /// second capture of a desktop the daemon can reach itself.
    ///
    /// `respawn_cap` is `[desktop].agent_respawn_cap`.
    pub fn start(allow_input: bool, respawn_cap: u32) -> Self {
        let input = InputPolicy::from_config(allow_input);
        let limits = Limits { spawns_per_hour: respawn_cap, ..Limits::default() };
        Self { shared: begin(input, limits), input }
    }

    /// What this deployment can say about its agent right now.
    pub fn status(&self) -> AgentStatus {
        self.shared.status()
    }

    /// The input policy that was handed to the spawner.
    ///
    /// Exposed for one reason: `allow_input = false` must be unable to produce an
    /// injector by *any* route, and the route this module adds is the argument
    /// vector of a process running as the console user.
    pub fn input_policy(&self) -> InputPolicy {
        self.input
    }

    /// Tells the supervisor whether the operator's kill switch is in place.
    pub fn set_kill_switch(&self, present: bool) {
        self.shared.kill_switch.store(present, Ordering::Relaxed);
    }

    /// The displays the agent named in its `Hello`, empty until it has spoken.
    pub fn displays(&self) -> Vec<Monitor> {
        self.shared.displays()
    }

    /// Attaches one session to the agent's message stream, or refuses.
    ///
    /// `None` means **another session already holds it**, and it is a refusal
    /// rather than a queue for a reason that is not a limitation: the agent holds
    /// a model of the client's surface and sends the difference against it. Two
    /// sessions on one agent would each be sent the difference against the
    /// other's picture, so the second viewer would see a shredded desktop rather
    /// than a slow one. A machine two people must watch at once needs one capture
    /// broadcast to both, which is a change above this seam.
    ///
    /// Dropping the returned [`AgentStream`] frees the agent for the next
    /// session.
        pub fn attach(&self) -> Option<AgentStream> {
        let (to_console, frames) = tokio::sync::mpsc::channel(RELAY_DEPTH);
        let (input, from_console) = tokio::sync::mpsc::channel(INPUT_DEPTH);
        let mut held = match self.shared.attached.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        if held.is_some() {
            return None;
        }
        *held = Some(Attachment { frames: to_console, input: from_console });
        drop(held);
        Some(AgentStream { frames, input, held: Arc::clone(&self.shared) })
    }

    /// Records that the operator asked for a fresh start.
    ///
    /// Clears the surrender, the backoff and the hour's spawn budget on the next
    /// turn. Nothing else does: an agent that has exhausted its cap stays stopped
    /// until a person says otherwise, which is the difference between a system
    /// that heals and one that hides a permanent fault behind an infinite retry.
    pub fn operator_start(&self) {
        self.shared.operator_start.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// The driver: pure but for two traits, so the whole of it is exercised on a Mac
// ---------------------------------------------------------------------------
//
// Compiled where it is used — the Windows loop — and under `cfg(test)`
// everywhere, which is what lets a developer's machine drive the transitions
// that cannot be produced on the machine this ships to: an agent dying, a fast
// user switch, a spawn that Windows refuses, an hour's budget running out.

/// The channel an agent talks back on, as the supervision loop needs it.
///
/// A trait rather than the concrete pipe because the ordering this module is
/// responsible for — created before the spawn, recycled when the agent dies,
/// dropped when the session moves — is the whole of what can be got wrong here
/// and none of it is observable on the platform it ships to.
#[cfg(any(windows, test))]
pub(crate) trait AgentChannel {
    /// Creates the channel for `session`.
    ///
    /// `Ok(false)` means **nobody is signed into that session**: an ordinary
    /// state, not a failure, and the caller must not treat it as one.
    fn open(&mut self, session: u32) -> Result<bool, Fault>;

    /// The session the open channel belongs to, if one is open.
    fn session(&self) -> Option<u32>;

    /// Forgets the client that was on the channel, leaving it ready for the next
    /// agent. Cheaper and less racy than tearing the channel down: the pipe's
    /// name is exclusive, and one closed and reopened in the same turn is a
    /// window in which the replacement agent's connect fails as busy.
    fn recycle(&mut self);

    /// Tears the channel down entirely.
    fn close(&mut self);

    /// Takes whatever the agent has said, as whole protocol messages.
    ///
    /// `Ok(None)` is the ordinary answer: nobody has connected yet, or nothing
    /// arrived inside this turn's short wait. It never means the agent is gone —
    /// only the supervisor knows that, because only it holds the process handle.
    fn pump(&mut self) -> Result<Option<Vec<u8>>, Fault>;

    /// Hands one already-encoded protocol message to the agent.
    ///
    /// The framing is the channel's, which is why this takes a message and not a
    /// frame: the relay above is forbidden to know how the pipe delimits things,
    /// and this is where that boundary is drawn.
    ///
    /// A channel with no agent on it answers `Ok(())` and drops the message. That
    /// is not swallowing an error — an input event for an agent that has just
    /// died is an event with nowhere to go, and the state machine, which holds
    /// the process handle, is the thing that decides what a dead agent means.
    fn send(&mut self, message: &[u8]) -> Result<(), Fault>;
}

/// The supervision loop's state, with the platform behind two traits.
#[cfg(any(windows, test))]
pub(crate) struct Supervised<H: selfhost_screen::AgentHost, C: AgentChannel> {
    agent: Agent<H>,
    channel: C,
    /// The cell the daemon reads status from and a session attaches through.
    shared: Arc<Shared>,
    /// The phase the last turn ended in, so the channel can be readied *before*
    /// the tick that spawns rather than a turn behind it.
    phase: selfhost_screen::AgentPhase,
    /// The console session as last observed. [`AgentPhase::Backoff`] carries none
    /// and the channel still has to be readied for the session the next attempt
    /// will land in.
    console: selfhost_screen::ConsoleSession,
    /// Whether an agent has identified itself on the open channel.
    connected: bool,
    /// The agent's own opening statement — session, user, window station,
    /// desktop, monitor count, DPI mode, integrity level. Only the agent can say
    /// any of it.
    said: Option<String>,
    /// How many displays the agent reported.
    monitors: u32,
    /// The last channel-side fault, which the supervisor's own record cannot
    /// carry because it never sees the channel.
    fault: Option<Fault>,
}

/// What the daemon knows at the top of a turn that the supervisor does not.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Orders {
    /// Whether `<data_dir>/desktop.disabled` is in place.
    pub(crate) kill_switch: bool,
    /// Whether the operator pressed start since the last turn.
    pub(crate) operator_start: bool,
}

#[cfg(any(windows, test))]
impl<H: selfhost_screen::AgentHost, C: AgentChannel> Supervised<H, C> {
    /// A loop that has observed nothing yet.
    pub(crate) fn new(agent: Agent<H>, channel: C, shared: Arc<Shared>) -> Self {
        Self {
            agent,
            channel,
            shared,
            phase: selfhost_screen::AgentPhase::Waiting(
                selfhost_screen::ConsoleSession::Attaching,
            ),
            console: selfhost_screen::ConsoleSession::Attaching,
            connected: false,
            said: None,
            monitors: 0,
            fault: None,
        }
    }

    /// One turn: ready the channel, decide, act, listen, report.
    ///
    /// The channel is readied twice — before the tick with what the last turn
    /// saw, and again after it — and both are needed. The first is what puts the
    /// pipe in place ahead of an ordinary spawn; the second covers the one turn
    /// where the tick itself discovers the session, which is the first turn of a
    /// supervisor's life and is exactly the race the agent's ten-second connect
    /// retry was written for.
    pub(crate) fn turn(
        &mut self,
        now: std::time::Instant,
        orders: Orders,
    ) -> AgentStatus {
        self.agent.set_kill_switch(orders.kill_switch, now);
        if orders.operator_start {
            self.agent.operator_start(now);
            // The operator has dealt with whatever was wrong; a stale reason left
            // on the plate after they pressed start reads as the press not
            // working.
            self.fault = None;
        }

        self.ready_channel();
        let phase = self.agent.tick(now);
        self.console = observed_console(phase, self.console);
        self.phase = phase;
        self.ready_channel();

        self.forward_input();
        self.listen(now);
        // An agent that is no longer running cannot serve the session that was
        // relaying it. Detaching here rather than waiting for the session to
        // notice is what lets the *next* session attach as soon as a replacement
        // agent is up, instead of finding the slot held by a stream that is
        // already ending.
        if !self.connected {
            detach(&self.shared);
        }
        self.status(now)
    }

    /// Writes whatever the attached session has queued for the agent.
    ///
    /// Non-blocking, and bounded by what is already in the queue: this runs on
    /// the supervision thread, between a spawn decision and a pipe read, and a
    /// blocking drain here would delay both.
    fn forward_input(&mut self) {
        loop {
            let next = {
                let mut held = match self.shared.attached.lock() {
                    Ok(held) => held,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match held.as_mut() {
                    Some(attached) => attached.input.try_recv().ok(),
                    None => return,
                }
            };
            let Some(message) = next else { return };
            if let Err(fault) = self.channel.send(&message) {
                self.fault = Some(fault);
                return;
            }
        }
    }

    /// Hands one of the agent's messages to the attached session, if any.
    ///
    /// A full queue detaches rather than blocks. The alternative — waiting for a
    /// session to consume — would stall the pipe reader, and the pipe reader is
    /// also the thing that keeps the supervisor's `connected` belief true; a
    /// session that stopped reading would therefore get the agent killed as
    /// `NeverConnected`.
    fn relay(&mut self, payload: &[u8]) {
        let mut held = match self.shared.attached.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(attached) = held.as_ref() else { return };
        if attached.frames.try_send(payload.to_vec()).is_err() {
            *held = None;
        }
    }

    /// Creates, recycles or drops the channel so it matches the phase.
    fn ready_channel(&mut self) {
        let want = channel_target(self.phase, self.console);
        // An agent that has gone leaves a client attached to the pipe. Forget it
        // now, or the replacement's connect fails as busy, which looks exactly
        // like a squatter and never recovers.
        if self.connected && !holds_process(self.phase) {
            self.channel.recycle();
            self.forget_agent();
        }
        match (want, self.channel.session()) {
            (Some(wanted), Some(open)) if wanted == open => {}
            (Some(wanted), _) => {
                self.channel.close();
                self.forget_agent();
                match self.channel.open(wanted) {
                    // `Ok(false)` is nobody signed into that session: not a
                    // failure, not charged to anything, asked again next turn.
                    Ok(_) => {}
                    Err(fault) => self.fault = Some(fault),
                }
            }
            (None, Some(_)) => {
                self.channel.close();
                self.forget_agent();
            }
            (None, None) => {}
        }
    }

    /// Forgets everything that was true of the agent that was on the channel.
    fn forget_agent(&mut self) {
        self.connected = false;
        self.said = None;
        self.monitors = 0;
    }

    /// Takes whatever the agent has said this turn.
    ///
    /// The first whole message is the cue for [`Agent::connected`], and it is not
    /// optional: without it the supervisor kills the agent at its start deadline
    /// as `NeverConnected` and charges it a failure, so an unpumped channel turns
    /// a working agent into a crash loop.
    fn listen(&mut self, now: std::time::Instant) {
        loop {
            match self.channel.pump() {
                Ok(Some(payload)) => {
                    if !self.connected {
                        self.connected = true;
                        self.agent.connected(now);
                        self.phase = self.agent.supervision().phase(now);
                    }
                    self.absorb(&payload);
                }
                Ok(None) => return,
                Err(fault) => {
                    // A channel that faults is a channel with nothing on it. The
                    // process handle decides whether the agent is gone, so this
                    // is recorded and the supervisor is left to conclude.
                    self.fault = Some(fault);
                    self.channel.recycle();
                    self.forget_agent();
                    return;
                }
            }
        }
    }

    /// Reads what a message from the agent adds to the report, and ignores the
    /// rest.
    ///
    /// The daemon deliberately interprets almost nothing the agent sends: under
    /// `panic = "abort"` a parser in the process that also serves 80/443, mail and
    /// the certificate store is a parser that can take all of them down, and the
    /// design forwards these payloads rather than consuming them. The two
    /// exceptions earn their place — the display count, which a node picker needs
    /// before any session exists, and the agent's opening statement, which is the
    /// only place the session, window station, desktop and integrity level are
    /// ever stated.
    fn absorb(&mut self, payload: &[u8]) {
        // Forwarded first, and whole: a session relaying this agent must get the
        // bytes whether or not this end finds anything in them worth reading.
        self.relay(payload);

        let Ok(message) = selfhost_desk::wire::Message::decode(payload) else {
            return;
        };
        match message {
            selfhost_desk::wire::Message::Hello(hello) => {
                self.monitors = u32::try_from(hello.monitors.len()).unwrap_or(u32::MAX);
                // Kept whole as well as counted: a relayed session advertises this
                // list to the console, and the ids in it are what the agent's
                // frames and the console's pointer coordinates both mean.
                match self.shared.displays.lock() {
                    Ok(mut held) => *held = hello.monitors.clone(),
                    Err(poisoned) => *poisoned.into_inner() = hello.monitors.clone(),
                }
            }
            selfhost_desk::wire::Message::Status { detail, .. } if !detail.is_empty() => {
                self.said = Some(detail);
            }
            _ => {}
        }
    }

    /// The status this turn ended in.
    fn status(&self, now: std::time::Instant) -> AgentStatus {
        use selfhost_screen::AgentPhase;

        let mut sentence = self.phase.sentence();
        if let (AgentPhase::Live { .. }, Some(said)) = (self.phase, self.said.as_deref()) {
            sentence.push_str(" · ");
            sentence.push_str(said);
        }
        // The supervisor's own record first: it knows why a spawn failed, and the
        // channel only ever knows why a pipe did.
        let fault = self
            .agent
            .supervision()
            .last_fault()
            .map(Fault::sentence)
            .or_else(|| self.fault.as_ref().map(Fault::sentence));
        AgentStatus {
            supervised: true,
            live: matches!(self.phase, AgentPhase::Live { .. }),
            session: phase_session(self.phase),
            notice: self.phase.notice(),
            sentence,
            monitors: self.monitors,
            fault,
            spawns_last_hour: u32::try_from(self.agent.supervision().spawns_in_last_hour(now))
                .unwrap_or(u32::MAX),
        }
    }
}

/// Which session the channel should be ready for, if any.
///
/// Pure, because both ways of getting it wrong are silent. Readying no channel
/// while an agent is starting costs that agent its whole start deadline and a
/// spawn out of the hour's budget; readying one for a session nobody is in leaves
/// a pipe named after a session that has gone, which the next agent cannot use
/// and which reports as busy.
#[cfg(any(windows, test))]
fn channel_target(
    phase: selfhost_screen::AgentPhase,
    console: selfhost_screen::ConsoleSession,
) -> Option<u32> {
    use selfhost_screen::AgentPhase;

    match phase {
        // A running or starting agent's own session, whatever the console has
        // since become: the pipe belongs to that agent until the supervisor stops
        // it.
        AgentPhase::Live { session } | AgentPhase::Starting { session } => Some(session),
        // Nothing is running and nothing will be until an operator acts.
        AgentPhase::Stopped | AgentPhase::GaveUp(_) => None,
        // Between attempts, and about to make another: ready the pipe for the
        // session that attempt will land in, which is whatever the console is now.
        AgentPhase::Backoff { .. } => console.id(),
        AgentPhase::Waiting(session) => session.id(),
    }
}

/// Whether the supervisor believes a process exists in this phase.
#[cfg(any(windows, test))]
fn holds_process(phase: selfhost_screen::AgentPhase) -> bool {
    matches!(
        phase,
        selfhost_screen::AgentPhase::Live { .. } | selfhost_screen::AgentPhase::Starting { .. }
    )
}

/// The session a phase names, for the status line.
#[cfg(any(windows, test))]
fn phase_session(phase: selfhost_screen::AgentPhase) -> Option<u32> {
    use selfhost_screen::AgentPhase;

    match phase {
        AgentPhase::Live { session } | AgentPhase::Starting { session } => Some(session),
        AgentPhase::Waiting(session) => session.id(),
        AgentPhase::Backoff { .. } | AgentPhase::Stopped | AgentPhase::GaveUp(_) => None,
    }
}

/// What a phase says about the console session, keeping the last answer when it
/// says nothing.
///
/// [`AgentPhase::Backoff`] carries no session and [`AgentPhase::Stopped`] is about
/// the operator rather than the machine, so neither may erase the knowledge that
/// somebody is signed in — which is exactly what the next attempt needs.
#[cfg(any(windows, test))]
fn observed_console(
    phase: selfhost_screen::AgentPhase,
    previous: selfhost_screen::ConsoleSession,
) -> selfhost_screen::ConsoleSession {
    use selfhost_screen::{AgentPhase, ConsoleSession};

    match phase {
        AgentPhase::Waiting(session) => session,
        AgentPhase::Live { session } | AgentPhase::Starting { session } => {
            ConsoleSession::User(session)
        }
        AgentPhase::Backoff { .. } | AgentPhase::Stopped | AgentPhase::GaveUp(_) => previous,
    }
}

// ---------------------------------------------------------------------------
// The platform half
// ---------------------------------------------------------------------------

/// How often the supervision loop takes a turn.
///
/// A second is ample and deliberately unhurried: [`Agent::tick`] is cheap and
/// idempotent, the fastest thing it has to notice is a session switch, and a
/// tighter loop would spend the machine's power watching a login screen. The
/// waits inside one turn are shorter than this, so an agent's `Hello` is seen
/// within a fraction of a turn rather than at the end of one.
#[cfg(windows)]
const TURN: Duration = Duration::from_secs(1);

/// How long one turn waits for an agent to connect to the pipe.
#[cfg(windows)]
const ACCEPT_WAIT: Duration = Duration::from_millis(50);

/// How long one turn waits for bytes from a connected agent.
#[cfg(windows)]
const READ_WAIT: Duration = Duration::from_millis(50);

/// How long a write to the agent may block the supervision thread.
///
/// The same short wait the read uses, and for the same reason: this thread also
/// decides whether to spawn and whether the agent is alive, and a write that
/// parked on a full pipe would stop it doing either. An agent that is not
/// draining its pipe is an agent that has stopped, which the state machine
/// discovers by holding the process handle rather than by waiting here.
#[cfg(windows)]
const WRITE_WAIT: Duration = Duration::from_millis(50);

/// How much of the agent's stream one turn will take in.
#[cfg(windows)]
const READ_BUFFER: usize = 64 * 1024;

/// The most bytes of a partly-arrived frame kept between reads.
///
/// A frame is at most [`selfhost_screen::agent::MAX_LINK_FRAME`]; anything past
/// that is a stream this build cannot be in step with, and the channel faults
/// rather than growing. Bounded arithmetic in one place beats a buffer that only
/// ever gets longer.
#[cfg(windows)]
const MAX_PENDING: usize = selfhost_screen::agent::MAX_LINK_FRAME + 8;

/// Starts the supervision thread for this machine, or publishes why there is
/// none.
///
/// A dedicated `std::thread` and never a tokio task: every call inside a turn is
/// a blocking platform call — `WTSGetActiveConsoleSessionId`,
/// `CreateProcessAsUserW`, an overlapped wait on a pipe — and the runtime this
/// daemon shares also serves the reverse proxy, the authoritative DNS server and
/// the mail server.
#[cfg(windows)]
fn begin(input: InputPolicy, limits: Limits) -> Arc<Shared> {
    use selfhost_screen::windows::gdi;
    use selfhost_screen::windows::spawn::WindowsHost;

    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return published(AgentStatus::not_supervised(format!(
                "this process cannot read its own path ({error}), so it cannot start an agent — \
                 the agent is this same binary's `desk-agent` subcommand and is started by \
                 absolute path, never searched for"
            )));
        }
    };

    match gdi::current_session() {
        // The service deployment: session 0 has no interactive desktop, so an
        // agent in the console session is the only way to a pixel.
        Some(0) => {}
        Some(session) => {
            return published(AgentStatus::not_supervised(format!(
                "this daemon is already in interactive session {session}, so it captures the \
                 desktop directly and needs no agent"
            )));
        }
        None => {
            return published(AgentStatus::not_supervised(
                "Windows will not say which session this process is in, so the daemon cannot \
                 prove it needs an agent. It supervises none rather than starting a second \
                 capture of a desktop it may already be sitting on.",
            ));
        }
    }

    let shared = published(AgentStatus {
        supervised: true,
        live: false,
        session: None,
        notice: Notice::Starting,
        sentence: "The agent supervisor has started and has not looked at the console yet."
            .to_owned(),
        monitors: 0,
        fault: None,
        spawns_last_hour: 0,
    });
    let host = WindowsHost::new(executable, input);
    let thread = Arc::clone(&shared);
    std::thread::spawn(move || {
        let mut supervised =
            Supervised::new(Agent::new(host, limits), PipeChannel::default(), Arc::clone(&thread));
        loop {
            let orders = Orders {
                kill_switch: thread.kill_switch.load(Ordering::Relaxed),
                operator_start: thread.operator_start.swap(false, Ordering::Relaxed),
            };
            thread.publish(supervised.turn(std::time::Instant::now(), orders));
            std::thread::sleep(TURN);
        }
    });
    shared
}

/// Everywhere else there is no agent, because there is no session-0 problem.
///
/// Stated as a sentence rather than left as an absence: a console plate showing
/// nothing here would be indistinguishable from one whose supervisor had died.
#[cfg(not(windows))]
fn begin(input: InputPolicy, limits: Limits) -> Arc<Shared> {
    // Both are the deployment's settings and are consumed on Windows; named
    // rather than dropped from the signature so there is one shape of this
    // function to read.
    let _ = (input, limits);
    let _ = Duration::from_secs(0);
    published(AgentStatus::not_supervised(format!(
        "there is no capture agent on {}: the agent exists so a Windows service in session 0 can \
         reach an interactive desktop, and nothing here has that problem — this daemon captures \
         its own screen",
        std::env::consts::OS
    )))
}

/// Wraps a status in the shared cell the daemon reads it from.
fn published(status: AgentStatus) -> Arc<Shared> {
    Arc::new(Shared {
        status: Mutex::new(status),
        displays: Mutex::new(Vec::new()),
        attached: Mutex::new(None),
        kill_switch: AtomicBool::new(false),
        operator_start: AtomicBool::new(false),
    })
}

/// The Windows channel: one named pipe whose DACL names `SYSTEM` and the console
/// user and nobody else.
///
/// The pipe **is** the authentication. There is no shared secret anywhere in this
/// path: a token in the environment block is readable by any process of the same
/// user, one on a command line is readable by every process on the machine, and
/// the security descriptor on a named object is the mechanism Windows actually
/// provides for this.
#[cfg(windows)]
#[derive(Default)]
struct PipeChannel {
    pipe: Option<selfhost_screen::windows::pipe::AgentPipe>,
    /// Whether an agent has connected to it.
    accepted: bool,
    /// Bytes of a frame that has not finished arriving.
    pending: Vec<u8>,
}

#[cfg(windows)]
impl AgentChannel for PipeChannel {
    fn open(&mut self, session: u32) -> Result<bool, Fault> {
        use selfhost_screen::windows::pipe::AgentPipe;

        self.close();
        match AgentPipe::for_console_session(session)? {
            Some(pipe) => {
                self.pipe = Some(pipe);
                Ok(true)
            }
            // Nobody is signed into that session: do not spawn, do not count it
            // against anything, ask again next turn.
            None => Ok(false),
        }
    }

    fn session(&self) -> Option<u32> {
        self.pipe.as_ref().map(selfhost_screen::windows::pipe::AgentPipe::session)
    }

    fn recycle(&mut self) {
        if let Some(pipe) = self.pipe.as_mut() {
            pipe.disconnect();
        }
        self.accepted = false;
        self.pending.clear();
    }

    fn close(&mut self) {
        self.pipe = None;
        self.accepted = false;
        self.pending.clear();
    }

    fn send(&mut self, message: &[u8]) -> Result<(), Fault> {
        use selfhost_screen::agent::{encode_link, LinkFrame};

        // No pipe, or nobody on it: the message has nowhere to go and that is an
        // ordinary state, not a fault. See the trait's contract.
        let Some(pipe) = self.pipe.as_mut() else {
            return Ok(());
        };
        if !self.accepted {
            return Ok(());
        }
        let frame = encode_link(&LinkFrame::Message(message.to_vec()))?;
        pipe.write_all(&frame, WRITE_WAIT)
    }

    fn pump(&mut self) -> Result<Option<Vec<u8>>, Fault> {
        let Some(pipe) = self.pipe.as_mut() else {
            return Ok(None);
        };
        if !self.accepted {
            if !pipe.accept(ACCEPT_WAIT)? {
                return Ok(None);
            }
            self.accepted = true;
        }

        // A whole frame may already be in hand from the last read.
        if let Some(payload) = take_frame(&mut self.pending)? {
            return Ok(Some(payload));
        }

        let mut buffer = [0u8; READ_BUFFER];
        let read = pipe.read(&mut buffer, READ_WAIT)?;
        if read == 0 {
            // A timeout, not an end: `Ok(0)` from this pipe means nothing arrived.
            return Ok(None);
        }
        let arrived = buffer.get(..read).ok_or_else(|| {
            Fault::refused("ReadFile", "reported more bytes than the buffer can hold")
        })?;
        if self.pending.len().saturating_add(read) > MAX_PENDING {
            return Err(Fault::refused(
                "the agent pipe",
                "sent a frame larger than this build can be in step with",
            ));
        }
        self.pending.extend_from_slice(arrived);
        take_frame(&mut self.pending)
    }
}

/// Takes one whole message off the front of a partly-arrived stream.
///
/// `Ok(None)` means *not a whole frame yet*, which is the ordinary case on a
/// stream and never an error. Credit travels the other way — the daemon grants,
/// the agent spends — so a credit frame arriving here is one this end has nothing
/// to do with and is dropped rather than reported.
#[cfg(windows)]
fn take_frame(pending: &mut Vec<u8>) -> Result<Option<Vec<u8>>, Fault> {
    use selfhost_screen::agent::{decode_link, LinkFrame};

    loop {
        let Some((frame, used)) = decode_link(pending)? else {
            return Ok(None);
        };
        if used > pending.len() {
            return Err(Fault::refused("decode_link", "consumed more than it was given"));
        }
        pending.drain(..used);
        match frame {
            LinkFrame::Message(payload) => return Ok(Some(payload)),
            LinkFrame::Credit(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_screen::supervisor::{AgentHost, AgentProcess};
    use selfhost_screen::{AgentPhase, ConsoleSession};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Instant;

    /// The scripted machine both fakes speak for, so the order in which they were
    /// called is observable.
    ///
    /// One log rather than two vectors, because the property that matters most in
    /// this file is an *ordering* — the pipe exists before the agent that has ten
    /// seconds to find it — and two separate records cannot state it.
    #[derive(Debug)]
    struct Machine {
        /// What the console says, changed by the test.
        console: ConsoleSession,
        /// Whether the next spawn fails, and with what.
        refuse_spawn: Option<Fault>,
        /// Whether a spawned agent is dead the moment it is looked at.
        stillborn: bool,
        /// Whether the running agent has exited, and with what code.
        exit: Option<i32>,
        /// Sessions nobody is signed into.
        empty: Vec<u32>,
        /// Everything that happened, in order.
        log: Vec<String>,
        /// The argument vector each spawn produced.
        arguments: Vec<Vec<String>>,
    }

    impl Machine {
        fn new() -> Self {
            Self {
                console: ConsoleSession::Attaching,
                refuse_spawn: None,
                stillborn: false,
                exit: None,
                empty: Vec::new(),
                log: Vec::new(),
                arguments: Vec::new(),
            }
        }

        /// Every session an agent was started in, in order.
        fn spawned(&self) -> Vec<String> {
            self.log.iter().filter(|line| line.starts_with("spawn")).cloned().collect()
        }

        /// Every session a channel was opened for, in order.
        fn opened(&self) -> Vec<String> {
            self.log.iter().filter(|line| line.starts_with("open")).cloned().collect()
        }
    }

    #[derive(Debug, Clone)]
    struct FakeHost {
        machine: Rc<RefCell<Machine>>,
        input: InputPolicy,
    }

    #[derive(Debug)]
    struct FakeProcess {
        machine: Rc<RefCell<Machine>>,
        session: u32,
    }

    impl AgentProcess for FakeProcess {
        fn session(&self) -> u32 {
            self.session
        }

        fn finished(&mut self) -> Result<Option<i32>, Fault> {
            Ok(self.machine.borrow().exit)
        }

        fn terminate(&mut self) {
            self.machine.borrow_mut().log.push(format!("terminate {}", self.session));
        }
    }

    impl AgentHost for FakeHost {
        fn console_session(&mut self) -> Result<ConsoleSession, Fault> {
            Ok(self.machine.borrow().console)
        }

        fn spawn(&mut self, session: u32) -> Result<Box<dyn AgentProcess>, Fault> {
            let mut machine = self.machine.borrow_mut();
            if let Some(fault) = machine.refuse_spawn.clone() {
                machine.log.push(format!("spawn-refused {session}"));
                return Err(fault);
            }
            machine.log.push(format!("spawn {session}"));
            machine.arguments.push(selfhost_screen::agent::agent_arguments(session, self.input));
            machine.exit = if machine.stillborn { Some(9) } else { None };
            drop(machine);
            Ok(Box::new(FakeProcess { machine: Rc::clone(&self.machine), session }))
        }
    }

    /// A scripted channel that records every transition this module is
    /// responsible for getting right.
    #[derive(Debug)]
    struct FakeChannel {
        machine: Rc<RefCell<Machine>>,
        open_for: Option<u32>,
        /// How many times a client was forgotten without the channel going away.
        recycled: usize,
        /// Messages waiting to be handed over.
        inbox: Vec<Vec<u8>>,
        /// Everything the driver wrote towards the agent, in order.
        sent: Vec<Vec<u8>>,
    }

    impl AgentChannel for FakeChannel {
        fn open(&mut self, session: u32) -> Result<bool, Fault> {
            if self.machine.borrow().empty.contains(&session) {
                self.machine.borrow_mut().log.push(format!("open-empty {session}"));
                return Ok(false);
            }
            self.open_for = Some(session);
            self.machine.borrow_mut().log.push(format!("open {session}"));
            Ok(true)
        }

        fn session(&self) -> Option<u32> {
            self.open_for
        }

        fn recycle(&mut self) {
            self.recycled = self.recycled.saturating_add(1);
            self.inbox.clear();
        }

        fn close(&mut self) {
            if self.open_for.take().is_some() {
                self.machine.borrow_mut().log.push("close".to_owned());
            }
            self.inbox.clear();
        }

        fn send(&mut self, message: &[u8]) -> Result<(), Fault> {
            if self.open_for.is_none() {
                return Ok(());
            }
            self.sent.push(message.to_vec());
            Ok(())
        }

        fn pump(&mut self) -> Result<Option<Vec<u8>>, Fault> {
            if self.open_for.is_none() || self.inbox.is_empty() {
                return Ok(None);
            }
            Ok(Some(self.inbox.remove(0)))
        }
    }

    /// A driver over a scripted machine, plus the handle a test changes it with.
    fn driver(
        input: InputPolicy,
        cap: u32,
    ) -> (Supervised<FakeHost, FakeChannel>, Rc<RefCell<Machine>>) {
        let machine = Rc::new(RefCell::new(Machine::new()));
        let host = FakeHost { machine: Rc::clone(&machine), input };
        let channel = FakeChannel {
            machine: Rc::clone(&machine),
            open_for: None,
            recycled: 0,
            inbox: Vec::new(),
            sent: Vec::new(),
        };
        let limits = Limits { spawns_per_hour: cap, ..Limits::default() };
        let shared = published(AgentStatus::not_supervised("under test"));
        (Supervised::new(Agent::new(host, limits), channel, shared), machine)
    }

    /// The orders of an ordinary turn: nothing revoked, nobody pressing anything.
    fn quiet() -> Orders {
        Orders { kill_switch: false, operator_start: false }
    }

    /// The agent's opening statement, encoded exactly as it travels.
    fn hello(displays: u8) -> Vec<u8> {
        use selfhost_desk::grant::Capabilities;
        use selfhost_desk::tiles::TileSize;
        use selfhost_desk::wire::{Hello, Message, Monitor, PROTOCOL_VERSION};

        let monitors = (0..displays)
            .map(|index| Monitor {
                id: index,
                origin_x: 0,
                origin_y: 0,
                width: 1920,
                height: 1080,
                scale_permille: 1000,
                primary: index == 0,
            })
            .collect();
        Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: TileSize::DEFAULT,
            max_fps: 30,
            capabilities: Capabilities::VIEW,
            monitors,
        })
        .encode()
        .expect("the agent's own hello encodes")
    }

    #[test]
    fn a_machine_at_its_login_screen_starts_nothing_and_is_not_an_error() {
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::NoUser;

        let status = supervised.turn(Instant::now(), quiet());
        assert!(machine.borrow().spawned().is_empty(), "nobody is logged in, so nothing is started");
        assert_eq!(status.notice, Notice::NoUser);
        assert_eq!(status.spawns_last_hour, 0, "and no budget is spent waiting");
        assert!(status.fault.is_none(), "a login screen is a state, not a failure");
        assert!(status.sentence.contains("No user is logged in"), "{}", status.sentence);
    }

    #[test]
    fn every_started_agent_has_a_pipe_and_the_steady_state_has_it_first() {
        // The ordering contract. A pipe that arrives after the agent costs a
        // whole attempt out of the hour's budget, since the agent's own connect
        // deadline is ten seconds.
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(3);
        supervised.turn(now, quiet());
        assert_eq!(machine.borrow().spawned(), ["spawn 3"]);
        assert_eq!(machine.borrow().opened(), ["open 3"], "the first turn readies it either way");

        // A session switch is the steady state, and there the pipe must be in
        // place *before* the spawn — which the single ordered log can state.
        machine.borrow_mut().console = ConsoleSession::User(4);
        supervised.turn(now + Duration::from_secs(1), quiet());
        supervised.turn(now + Duration::from_secs(2), quiet());
        let log = machine.borrow().log.clone();
        let opened = log.iter().position(|line| line == "open 4").expect("the pipe moved");
        let spawned = log.iter().position(|line| line == "spawn 4").expect("the agent followed");
        assert!(opened < spawned, "the pipe is created before the agent that must find it: {log:?}");
    }

    #[test]
    fn a_session_nobody_is_signed_into_is_not_charged_to_anything() {
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(2);
        machine.borrow_mut().empty.push(2);

        let status = supervised.turn(Instant::now(), quiet());
        assert!(supervised.channel.session().is_none(), "no channel exists for an empty session");
        assert!(status.fault.is_none(), "and it is not reported as a fault");
    }

    #[test]
    fn the_first_message_is_what_makes_the_agent_live() {
        // Without this the supervisor kills the agent at its start deadline as
        // `NeverConnected` and charges it a failure, so an unpumped channel turns
        // a working agent into a crash loop.
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);

        let starting = supervised.turn(now, quiet());
        assert_eq!(starting.notice, Notice::Recovering, "started, not yet connected");
        assert!(!starting.live);

        supervised.channel.inbox.push(hello(2));
        let live = supervised.turn(now + Duration::from_millis(200), quiet());
        assert!(live.live, "the agent's first message is what proves it arrived");
        assert_eq!(live.notice, Notice::Live);
        assert_eq!(live.session, Some(1));
        assert_eq!(live.monitors, 2, "and its own report says how many displays it has");
    }

    #[test]
    fn a_dead_agent_leaves_a_pipe_ready_for_its_replacement() {
        // The failure this prevents is silent and total: a pipe left in a
        // connected state refuses the replacement agent's connect as busy, which
        // looks exactly like a squatter and never recovers.
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);
        supervised.turn(now, quiet());
        supervised.channel.inbox.push(hello(1));
        assert!(supervised.turn(now + Duration::from_millis(100), quiet()).live);

        machine.borrow_mut().exit = Some(3);
        let backoff = supervised.turn(now + Duration::from_millis(200), quiet());
        assert_eq!(backoff.notice, Notice::Recovering);
        assert!(backoff.sentence.contains("failed 1 time"), "{}", backoff.sentence);
        assert_eq!(supervised.channel.recycled, 1, "the client is forgotten, the pipe is kept");
        assert_eq!(machine.borrow().opened(), ["open 1"], "and the pipe is not recreated");
        // The *sentence* the code stands for, not the number. Code 3 is
        // `Departure::UnknownSession`, and what an operator needs on the plate is
        // what that means — the number is the transport, and asserting it here
        // would let the vocabulary drift away from the thing that reads it.
        assert!(
            backoff
                .fault
                .as_deref()
                .unwrap_or_default()
                .contains(selfhost_screen::Departure::UnknownSession.sentence()),
            "the reason travels with the phase: {backoff:?}"
        );
    }

    #[test]
    fn a_session_switch_moves_the_pipe_and_costs_no_budget() {
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);
        supervised.turn(now, quiet());
        supervised.channel.inbox.push(hello(1));
        supervised.turn(now + Duration::from_millis(100), quiet());

        machine.borrow_mut().console = ConsoleSession::User(2);
        // One turn stops the agent, the next starts it in the session that took
        // over — the supervisor's own two-step, which this loop must not skip.
        supervised.turn(now + Duration::from_millis(200), quiet());
        let after = supervised.turn(now + Duration::from_millis(300), quiet());
        assert_eq!(machine.borrow().spawned(), ["spawn 1", "spawn 2"]);
        assert_eq!(machine.borrow().opened(), ["open 1", "open 2"], "the pipe follows the session");
        assert_eq!(after.session, Some(2));
        assert_eq!(after.spawns_last_hour, 2, "a switch is not a failure, but it is a spawn");
    }

    #[test]
    fn the_kill_switch_stops_the_agent_and_takes_the_pipe_away() {
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);
        supervised.turn(now, quiet());
        supervised.channel.inbox.push(hello(1));
        supervised.turn(now + Duration::from_millis(100), quiet());

        let stopped = supervised.turn(
            now + Duration::from_millis(200),
            Orders { kill_switch: true, operator_start: false },
        );
        assert_eq!(stopped.notice, Notice::Stopped);
        assert!(!stopped.live);
        assert!(supervised.channel.session().is_none(), "nothing is left listening for an agent");
        assert!(stopped.sentence.contains("kill switch"), "{}", stopped.sentence);
        assert!(
            machine.borrow().log.contains(&"terminate 1".to_owned()),
            "and the agent that was running is ended, not merely ignored"
        );

        // Released, and the machine comes back by itself: the switch is a state,
        // not a one-way door.
        let back = supervised.turn(now + Duration::from_millis(300), quiet());
        assert_eq!(back.notice, Notice::Recovering);
        assert_eq!(machine.borrow().spawned(), ["spawn 1", "spawn 1"]);
    }

    #[test]
    fn a_crash_loop_gives_up_at_the_cap_and_stays_given_up() {
        // An agent that starts and dies forever must eventually say so in the
        // console instead of respawning silently until somebody reboots.
        let mut now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 2);
        machine.borrow_mut().console = ConsoleSession::User(1);
        machine.borrow_mut().stillborn = true;

        let mut status = supervised.turn(now, quiet());
        for _ in 0..10 {
            now += Duration::from_secs(60);
            status = supervised.turn(now, quiet());
        }
        assert_eq!(status.notice, Notice::GaveUp);
        assert_eq!(machine.borrow().spawned().len(), 2, "the hour's budget is two and it is spent");
        assert!(
            status.fault.as_deref().unwrap_or_default().contains("exited with code 9"),
            "the surrender carries the reason: {status:?}"
        );
        assert!(supervised.channel.session().is_none(), "a surrendered supervisor holds no pipe");

        // And nothing retries on its own.
        now += Duration::from_secs(60);
        assert_eq!(supervised.turn(now, quiet()).notice, Notice::GaveUp);

        // Only the operator clears it.
        machine.borrow_mut().stillborn = false;
        let restarted =
            supervised.turn(now, Orders { kill_switch: false, operator_start: true });
        assert_ne!(restarted.notice, Notice::GaveUp);
        assert_eq!(machine.borrow().spawned().len(), 3, "pressing start is what starts one");
    }

    #[test]
    fn a_spawn_windows_refuses_backs_off_and_says_which_call_failed() {
        let now = Instant::now();
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);
        machine.borrow_mut().refuse_spawn = Some(Fault::os("CreateProcessAsUserW", 1314));

        let status = supervised.turn(now, quiet());
        assert_eq!(status.notice, Notice::Recovering);
        assert_eq!(status.spawns_last_hour, 0, "a spawn that failed was never a spawn");
        assert!(
            status.fault.as_deref().unwrap_or_default().contains("CreateProcessAsUserW"),
            "the operator is told which call refused: {status:?}"
        );
        assert!(status.sentence.contains("next attempt"), "{}", status.sentence);
    }

    #[test]
    fn a_view_only_deployment_never_hands_an_agent_the_input_flag() {
        // The property the default-off posture rests on, asserted against the
        // argument vector a spawned agent actually receives — not against a config
        // field, which was already true before anything was wired.
        let (mut supervised, machine) = driver(InputPolicy::ViewOnly, 5);
        machine.borrow_mut().console = ConsoleSession::User(1);
        supervised.turn(Instant::now(), quiet());

        let arguments = machine.borrow().arguments.clone();
        assert_eq!(arguments.len(), 1, "one spawn, one argument vector");
        for argv in &arguments {
            assert!(
                !argv.iter().any(|word| word == selfhost_screen::agent::ALLOW_INPUT_FLAG),
                "a view-only deployment must start an agent that builds no injector: {argv:?}"
            );
            // Fail-closed the other way too: the agent reconstructs its policy
            // from this vector, and it must read as view-only.
            assert!(!InputPolicy::from_arguments(argv).allows());
        }
    }

    #[test]
    fn an_armed_deployment_hands_it_over_exactly_once() {
        let (mut supervised, machine) = driver(InputPolicy::AllowInput, 5);
        machine.borrow_mut().console = ConsoleSession::User(4);
        supervised.turn(Instant::now(), quiet());

        let arguments = machine.borrow().arguments.clone();
        let argv = arguments.first().expect("one spawn").clone();
        assert_eq!(
            argv.iter().filter(|word| *word == selfhost_screen::agent::ALLOW_INPUT_FLAG).count(),
            1
        );
        assert!(InputPolicy::from_arguments(&argv).allows());
        assert!(argv.contains(&"4".to_owned()), "and it names the session it was aimed at");
    }

    #[test]
    fn the_channel_target_is_decided_by_the_phase_and_never_by_a_guess() {
        let console = ConsoleSession::User(7);
        assert_eq!(channel_target(AgentPhase::Live { session: 2 }, console), Some(2));
        assert_eq!(channel_target(AgentPhase::Starting { session: 2 }, console), Some(2));
        assert_eq!(
            channel_target(
                AgentPhase::Backoff { remaining: Duration::from_secs(1), failures: 1 },
                console
            ),
            Some(7),
            "between attempts the pipe is readied for the session the next one lands in"
        );
        assert_eq!(channel_target(AgentPhase::Waiting(ConsoleSession::NoUser), console), None);
        assert_eq!(channel_target(AgentPhase::Waiting(ConsoleSession::Attaching), console), None);
        assert_eq!(channel_target(AgentPhase::Stopped, console), None);
        assert_eq!(
            channel_target(
                AgentPhase::GaveUp(selfhost_desk::state::Surrender::AgentUnrecoverable),
                console
            ),
            None
        );
    }

    #[test]
    fn a_phase_that_names_no_session_does_not_erase_the_one_we_know() {
        assert_eq!(
            observed_console(
                AgentPhase::Backoff { remaining: Duration::from_secs(1), failures: 2 },
                ConsoleSession::User(5)
            ),
            ConsoleSession::User(5),
        );
        assert_eq!(
            observed_console(AgentPhase::Live { session: 9 }, ConsoleSession::NoUser),
            ConsoleSession::User(9),
        );
        assert_eq!(
            observed_console(AgentPhase::Waiting(ConsoleSession::NoUser), ConsoleSession::User(5)),
            ConsoleSession::NoUser,
            "a logout is observed, not remembered away",
        );
    }

    #[test]
    fn a_platform_with_no_agent_says_so_rather_than_showing_nothing() {
        let agent = CaptureAgent::start(false, 10);
        let status = agent.status();
        if status.supervised {
            // A Windows service running these tests: the supervisor exists and
            // has not looked at the console yet.
            assert_eq!(status.notice, Notice::Starting);
        } else {
            assert!(
                !status.sentence.is_empty(),
                "an unexplained absence is the failure this prevents"
            );
            assert!(!status.live);
        }
        assert!(!status.line().is_empty());
        assert!(!agent.input_policy().allows(), "the deployment's switch is what was handed over");
    }

    #[test]
    fn an_armed_deployment_carries_its_policy_to_the_spawner() {
        assert!(CaptureAgent::start(true, 10).input_policy().allows());
    }
}
