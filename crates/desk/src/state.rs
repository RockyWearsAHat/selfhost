//! The session state machine: what a desktop is doing, and what to do next.
//!
//! # Why the states are named rather than counted as errors
//!
//! Almost everything that goes wrong with screen capture is not a fault. A user
//! locks the screen; a UAC prompt takes the desktop; somebody switches users;
//! an RDP session steals the console; the machine is sitting at the login screen
//! with nobody logged in at all. A capture API reports every one of those as a
//! failure code, and a program that treats failure codes as failures shows the
//! operator a black rectangle and a retry counter.
//!
//! So the observations this module accepts name **states**, and the phases it
//! produces name them back. That is what lets the console say *"secure desktop —
//! screen and input suspended"* or *"no user is logged in — nothing to capture"*
//! instead of *"capture failed (0x887A0026)"*, and it is why [`Notice`] carries a
//! sentence: the sentence is part of the protocol, decided once here, rather than
//! composed differently by each of the two consoles.
//!
//! # Why it backs off
//!
//! The other half of the job is the crash loop. Desktop duplication genuinely
//! does need to be torn down and rebuilt — on a mode change, on a resolution
//! change, when the desktop switches — and the rebuild genuinely can fail again
//! immediately. A loop that reacts to "rebuild me" by rebuilding at once is a
//! loop that pegs a core and fills a log, on a machine whose whole purpose is to
//! be running something else. The delay therefore doubles, is capped, and is
//! never zero, and a budget eventually turns the loop into an honest
//! [`Phase::GaveUp`] that the console displays. The 400-observation test in this
//! file exists because that is exactly the length of run nobody tries by hand.
//!
//! This is the same argument `selfhost_supervisor`'s `policy` module makes about
//! restarting a service, and the shape is deliberately familiar. It is not shared
//! code: that module's decision is expressed in terms of a `RestartPolicy` from
//! `selfhost-config`, and this crate does not — and must not — depend on the
//! box's configuration.
//!
//! # What this module does not do
//!
//! It does not capture, spawn, sleep, or send. It converts an observation and a
//! clock reading into a phase and an [`Action`], and the driver in
//! [`crate::viewer`] performs the action. Everything hard about this subsystem is
//! therefore testable with no display, no agent and no socket.

use std::fmt;
use std::time::{Duration, Instant};

/// The shortest delay before anything is retried.
///
/// A quarter of a second is below the threshold at which a person watching the
/// console notices a pause, and far above the rate at which a retry loop costs
/// anything.
pub const BASE_DELAY: Duration = Duration::from_millis(250);

/// The longest delay before anything is retried.
///
/// A ceiling exists for the same reason the supervisor's does: unbounded
/// doubling reaches delays measured in days, and the operator's fix then appears
/// not to work because nothing tries again for a very long time.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// How long frames must keep arriving before the failure counters reset.
///
/// Without a floor, a capture that produces one frame and then demands a rebuild
/// would clear its own history every cycle and loop forever at [`BASE_DELAY`],
/// with the budget never running out — the precise bug this counter exists to
/// catch.
pub const HEALTHY_WINDOW: Duration = Duration::from_secs(30);

/// What the far end reported, in the vocabulary this module reasons about.
///
/// `selfhost-screen`'s `CaptureError` maps onto this; the mapping lives there
/// because the platform codes are platform knowledge. Keeping the vocabulary
/// here is what lets a fake capture replay a scripted sequence — including the
/// crash loop — with no display attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// A frame arrived.
    Frame,
    /// Nothing new yet — the platform call waited its own window and nothing
    /// arrived. Not a failure: a still desktop produces this indefinitely, it
    /// must not be counted against any budget, and it must not cost an extra
    /// delay on top of the wait the platform call already did. See
    /// [`Action::Capture`] on this observation, below.
    Retry,
    /// The capture object must be torn down and rebuilt before it will produce
    /// anything again.
    Reinitialise,
    /// The secure desktop is in front — a UAC consent dialog, the lock screen,
    /// or the credential provider. Never captured, and input suspends. See
    /// [`Session::input_permitted`].
    SecureDesktop,
    /// The interactive session moved: fast user switching, or RDP taking the
    /// console away.
    SessionDisconnected,
    /// Nobody is logged in. There is no desktop to capture, and that is a
    /// perfectly ordinary state for a server.
    NoSession,
    /// The operating system refuses this process the screen — macOS screen
    /// recording consent, or accessibility consent for input. Recoverable
    /// without a restart once the operator grants it, which is why it polls
    /// rather than giving up.
    PermissionDenied,
    /// The agent process is gone.
    AgentExited,
    /// Something unrecoverable. The last resort, and deliberately rare: almost
    /// everything else has a named state above.
    Fatal,
    /// `<data_dir>/desktop.disabled` appeared. The operator's kill switch, and
    /// deliberately not part of the console — an operator with filesystem access
    /// must be able to revoke this capability without going through the surface
    /// an attacker would already hold.
    KillSwitch,
    /// The operator asked for the session to start, or restart after giving up.
    Resume,
}

/// Why a session is suspended: showing nothing and accepting nothing, but not
/// broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspension {
    /// The secure desktop is in front.
    SecureDesktop,
    /// The interactive session moved elsewhere.
    SessionMoved,
    /// Nobody is logged in.
    NoUser,
}

/// Why a session stopped trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surrender {
    /// The capture object demanded rebuilding more times than the budget allows.
    TooManyReinitialisations,
    /// The agent process could not be kept alive.
    AgentUnrecoverable,
    /// An unrecoverable failure was reported.
    Fatal,
}

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing has been observed yet.
    Starting,
    /// Frames are arriving.
    Live,
    /// Rebuilding, after this many consecutive attempts.
    Recovering {
        /// Consecutive recovery attempts, counting from one.
        attempt: u32,
    },
    /// Not broken, but showing nothing.
    Suspended(Suspension),
    /// The operating system refuses this process the screen or the input device.
    Denied,
    /// Stopped trying, and saying so.
    GaveUp(Surrender),
    /// Shut down by the operator's kill switch.
    Stopped,
}

impl Phase {
    /// The notice a console should display for this phase.
    pub fn notice(self) -> Notice {
        match self {
            Self::Starting => Notice::Starting,
            Self::Live => Notice::Live,
            Self::Recovering { .. } => Notice::Recovering,
            Self::Suspended(Suspension::SecureDesktop) => Notice::SecureDesktop,
            Self::Suspended(Suspension::SessionMoved) => Notice::SessionMoved,
            Self::Suspended(Suspension::NoUser) => Notice::NoUser,
            Self::Denied => Notice::PermissionDenied,
            Self::GaveUp(_) => Notice::GaveUp,
            Self::Stopped => Notice::Stopped,
        }
    }
}

/// What a console is told, and the words it is told in.
///
/// This is a wire enum: the codes are stable and travel in
/// [`Message::Status`](crate::wire::Message::Status). The sentence travels with
/// it as well, so a console that is older than the server still has something to
/// display, but both consoles are expected to render the code rather than the
/// string when they recognise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// The session is being established.
    Starting,
    /// Frames are arriving.
    Live,
    /// The screen source is being rebuilt.
    Recovering,
    /// The secure desktop is in front.
    SecureDesktop,
    /// The interactive session moved.
    SessionMoved,
    /// Nobody is logged in.
    NoUser,
    /// The operating system refuses this process the screen or the input device.
    PermissionDenied,
    /// The session stopped trying.
    GaveUp,
    /// The kill switch is in place.
    Stopped,
}

impl Notice {
    /// The stable wire code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Starting => 0x01,
            Self::Live => 0x02,
            Self::Recovering => 0x03,
            Self::SecureDesktop => 0x04,
            Self::SessionMoved => 0x05,
            Self::NoUser => 0x06,
            Self::PermissionDenied => 0x07,
            Self::GaveUp => 0x08,
            Self::Stopped => 0x09,
        }
    }

    /// Reads a notice from its wire code; `None` for a code this build does not
    /// know, which the caller reports rather than guessing at.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Starting),
            0x02 => Some(Self::Live),
            0x03 => Some(Self::Recovering),
            0x04 => Some(Self::SecureDesktop),
            0x05 => Some(Self::SessionMoved),
            0x06 => Some(Self::NoUser),
            0x07 => Some(Self::PermissionDenied),
            0x08 => Some(Self::GaveUp),
            0x09 => Some(Self::Stopped),
            _ => None,
        }
    }

    /// The sentence a console shows.
    ///
    /// Written here, once, because the two consoles share no code and a
    /// difference in wording between them is a difference an operator will
    /// eventually read as a difference in behaviour.
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Starting => "connecting to the desktop agent",
            Self::Live => "live",
            Self::Recovering => "rebuilding the screen source",
            Self::SecureDesktop => "secure desktop — screen and input suspended",
            Self::SessionMoved => "the interactive session moved — waiting for it to come back",
            Self::NoUser => "no user is logged in — nothing to capture",
            Self::PermissionDenied => "the operating system has not granted screen or input access",
            Self::GaveUp => "stopped trying — see the daemon log",
            Self::Stopped => "disabled by desktop.disabled",
        }
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.sentence())
    }
}

/// What the driver should do next.
///
/// Every waiting variant carries its delay explicitly, and no variant means
/// "immediately try the same thing again". That is the property the crash-loop
/// test asserts: there is no way to express a spin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Ask for the next frame.
    Capture,
    /// Nothing to do until this much time has passed, then ask again.
    WaitThen(Duration),
    /// Tear the screen source down, wait, and build a new one.
    Reinitialise(Duration),
    /// The agent is gone; wait, then spawn it again.
    RespawnAgent(Duration),
    /// Stop sending pixels and refuse input, but hold the stream open — this is
    /// not an error and the far end will come back.
    Suspend {
        /// How long before asking again whether the suspension has lifted.
        poll_after: Duration,
    },
    /// Close every stream on this session. Terminal until [`Observation::Resume`].
    CloseStreams,
}

/// The budgets and delays a session runs under.
///
/// Supplied by the caller rather than read from config, because this crate does
/// not depend on `selfhost-config`, and because a budget passed in is a budget a
/// test can set to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The first delay, doubled on each consecutive attempt.
    pub base_delay: Duration,
    /// The ceiling the doubling stops at.
    pub max_delay: Duration,
    /// How many consecutive rebuilds are allowed before the session gives up.
    /// `None` is unlimited, which is useful for a test and questionable in
    /// production.
    pub reinit_budget: Option<u32>,
    /// How many consecutive agent respawns are allowed. Corresponds to
    /// `[desktop].agent_respawn_cap`.
    pub respawn_budget: Option<u32>,
    /// How long frames must keep arriving before the counters reset.
    pub healthy_window: Duration,
}

impl Default for Limits {
    /// The documented defaults: a quarter-second base, a thirty-second ceiling,
    /// ten rebuilds and ten respawns, and thirty seconds of frames to call it
    /// healthy.
    fn default() -> Self {
        Self {
            base_delay: BASE_DELAY,
            max_delay: MAX_DELAY,
            reinit_budget: Some(10),
            respawn_budget: Some(10),
            healthy_window: HEALTHY_WINDOW,
        }
    }
}

/// One transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// Where the session is now.
    pub phase: Phase,
    /// What the driver should do.
    pub action: Action,
    /// The notice to send, present **only** when the phase changed.
    ///
    /// A still desktop produces [`Observation::Retry`] thirty times a second; a
    /// status message per observation would be thirty messages a second saying
    /// nothing changed. So the transition, not the observation, is what speaks.
    pub notice: Option<Notice>,
}

/// The state machine for one desktop session.
#[derive(Debug, Clone)]
pub struct Session {
    phase: Phase,
    limits: Limits,
    reinit_failures: u32,
    respawns: u32,
    live_since: Option<Instant>,
}

impl Session {
    /// A session that has not observed anything yet.
    pub fn new(limits: Limits) -> Self {
        Self { phase: Phase::Starting, limits, reinit_failures: 0, respawns: 0, live_since: None }
    }

    /// Where the session is.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Consecutive rebuild attempts since the last healthy stretch. Displayed on
    /// the diagnostics plate, because a number that climbs while the picture
    /// looks fine is the earliest sign of a display driver in trouble.
    pub fn reinit_failures(&self) -> u32 {
        self.reinit_failures
    }

    /// Consecutive agent respawns since the last healthy stretch.
    pub fn respawns(&self) -> u32 {
        self.respawns
    }

    /// Whether input may be injected right now.
    ///
    /// True in exactly one phase. In particular it is false on the secure
    /// desktop, and that is a security decision rather than a limitation: a
    /// channel that can both render and drive the UAC consent dialog is by
    /// construction a remote privilege-escalation channel. It is also false
    /// while recovering, because a keystroke delivered to a screen the operator
    /// cannot see goes to whatever window happens to have focus.
    pub fn input_permitted(&self) -> bool {
        matches!(self.phase, Phase::Live)
    }

    /// Folds one observation in and says what to do next.
    ///
    /// `now` is passed rather than read so that a four-hundred-observation crash
    /// loop takes microseconds to drive in a test.
    pub fn observe(&mut self, observation: Observation, now: Instant) -> Step {
        // Both terminal phases answer everything except `Resume` the same way,
        // and answer it without a delay of zero — a driver that keeps polling a
        // stopped session must not be handed a busy-wait.
        if matches!(self.phase, Phase::Stopped | Phase::GaveUp(_)) {
            return match observation {
                Observation::Resume => self.enter(Phase::Starting, Action::Capture),
                _ => self.stay(Action::CloseStreams),
            };
        }

        match observation {
            Observation::KillSwitch => self.enter(Phase::Stopped, Action::CloseStreams),

            Observation::Resume => match self.phase {
                Phase::Live => self.stay(Action::Capture),
                _ => self.enter(Phase::Starting, Action::Capture),
            },

            Observation::Frame => {
                let live_since = *self.live_since.get_or_insert(now);
                if now.saturating_duration_since(live_since) >= self.limits.healthy_window {
                    self.reinit_failures = 0;
                    self.respawns = 0;
                }
                self.enter(Phase::Live, Action::Capture)
            }

            // Not a failure and not a state change: no counter moves, and the
            // phase is left exactly where it was so a suspended session polling
            // for its desktop to come back does not announce itself as live.
            //
            // `Action::Capture`, not `WaitThen(base_delay)`: the platform call
            // already spent its own wait finding nothing, so tacking a further
            // quarter-second on top does not make the loop calmer, it makes it
            // four times slower than `max_fps` on any content whose changes
            // don't land in every single poll window — which is most content,
            // not just a genuinely still desktop. Each driver already paces
            // `Action::Capture` at its own frame budget (`frame_interval` in
            // `selfhost_screen::agent`, `budget` in this crate's `viewer` and
            // `relay`), so retrying promptly here does not busy-spin: the next
            // platform call blocks again for its own window before the loop is
            // back here.
            Observation::Retry => self.stay(Action::Capture),

            Observation::Reinitialise => {
                self.live_since = None;
                self.reinit_failures = self.reinit_failures.saturating_add(1);
                if over_budget(self.reinit_failures, self.limits.reinit_budget) {
                    return self.enter(
                        Phase::GaveUp(Surrender::TooManyReinitialisations),
                        Action::CloseStreams,
                    );
                }
                let delay = backoff(self.limits, self.reinit_failures - 1);
                self.enter(
                    Phase::Recovering { attempt: self.reinit_failures },
                    Action::Reinitialise(delay),
                )
            }

            Observation::AgentExited => {
                self.live_since = None;
                self.respawns = self.respawns.saturating_add(1);
                if over_budget(self.respawns, self.limits.respawn_budget) {
                    return self
                        .enter(Phase::GaveUp(Surrender::AgentUnrecoverable), Action::CloseStreams);
                }
                let delay = backoff(self.limits, self.respawns - 1);
                self.enter(Phase::Recovering { attempt: self.respawns }, Action::RespawnAgent(delay))
            }

            Observation::SecureDesktop => self.suspend(Suspension::SecureDesktop),
            Observation::SessionDisconnected => self.suspend(Suspension::SessionMoved),
            Observation::NoSession => self.suspend(Suspension::NoUser),

            // Consent can be granted while the daemon runs, so this polls at the
            // ceiling delay instead of giving up: the operator ticks the box in
            // System Settings and the session recovers without a restart.
            Observation::PermissionDenied => {
                self.live_since = None;
                self.enter(Phase::Denied, Action::WaitThen(self.limits.max_delay))
            }

            Observation::Fatal => {
                self.live_since = None;
                self.enter(Phase::GaveUp(Surrender::Fatal), Action::CloseStreams)
            }
        }
    }

    /// Moves to a suspended phase, polling at the base delay so the session
    /// notices promptly when the desktop comes back.
    fn suspend(&mut self, reason: Suspension) -> Step {
        self.live_since = None;
        self.enter(
            Phase::Suspended(reason),
            Action::Suspend { poll_after: self.limits.base_delay },
        )
    }

    /// Transitions, emitting a notice only if the phase actually changed.
    fn enter(&mut self, phase: Phase, action: Action) -> Step {
        let changed = phase != self.phase;
        if changed {
            if phase == Phase::Starting {
                self.reinit_failures = 0;
                self.respawns = 0;
                self.live_since = None;
            }
            self.phase = phase;
        }
        Step { phase, action, notice: changed.then(|| phase.notice()) }
    }

    /// Stays where it is, saying nothing.
    fn stay(&self, action: Action) -> Step {
        Step { phase: self.phase, action, notice: None }
    }
}

/// Whether a counter has passed its budget. `None` is an unlimited budget.
fn over_budget(count: u32, budget: Option<u32>) -> bool {
    matches!(budget, Some(limit) if count > limit)
}

/// The delay before attempt number `attempt`, counting from zero.
///
/// Doubles each time and stops at [`Limits::max_delay`]. The shift is guarded
/// because `1u64 << 64` is undefined rather than saturating, and a session that
/// has been rebuilding since last night is exactly the case that reaches it —
/// under `panic = "abort"` an arithmetic overflow here is not a wrong delay, it
/// is the daemon dying.
pub fn backoff(limits: Limits, attempt: u32) -> Duration {
    let multiplier = 1u64.checked_shl(attempt.min(32)).unwrap_or(u64::MAX);
    let scaled = limits.base_delay.saturating_mul(multiplier.min(u32::MAX as u64) as u32);
    scaled.min(limits.max_delay).max(limits.base_delay.min(limits.max_delay))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    fn unlimited() -> Limits {
        Limits { reinit_budget: None, respawn_budget: None, ..Limits::default() }
    }

    #[test]
    fn every_notice_round_trips_through_its_wire_code_and_says_something() {
        let all = [
            Notice::Starting,
            Notice::Live,
            Notice::Recovering,
            Notice::SecureDesktop,
            Notice::SessionMoved,
            Notice::NoUser,
            Notice::PermissionDenied,
            Notice::GaveUp,
            Notice::Stopped,
        ];
        for notice in all {
            assert_eq!(Notice::from_code(notice.code()), Some(notice));
            assert!(!notice.sentence().is_empty());
        }
        // Codes must be distinct, or two states display as one.
        let mut codes: Vec<u8> = all.iter().map(|notice| notice.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert_eq!(Notice::from_code(0x00), None);
        assert_eq!(Notice::from_code(0xFF), None);
    }

    #[test]
    fn a_first_frame_goes_live_and_says_so_once() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        let step = session.observe(Observation::Frame, now);
        assert_eq!(step.phase, Phase::Live);
        assert_eq!(step.action, Action::Capture);
        assert_eq!(step.notice, Some(Notice::Live));

        // A thousand more frames say nothing at all: the console is told about
        // transitions, not about every frame.
        for tick in 1..1000 {
            let step = session.observe(Observation::Frame, now + Duration::from_millis(tick));
            assert_eq!(step.notice, None);
            assert_eq!(step.action, Action::Capture);
        }
        assert!(session.input_permitted());
    }

    #[test]
    fn a_still_desktop_retries_at_capture_pace_and_counts_nothing() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        session.observe(Observation::Frame, now);
        for tick in 0..500 {
            let step = session.observe(Observation::Retry, now + Duration::from_millis(tick));
            // The state machine adds no delay of its own: the platform call
            // already blocked for its own window before reporting nothing, and
            // the caller paces the next `Action::Capture` at its frame budget.
            assert_eq!(step.action, Action::Capture);
            assert_eq!(step.phase, Phase::Live, "a retry is not a state change");
            assert_eq!(step.notice, None);
        }
        assert_eq!(session.reinit_failures(), 0);
    }

    #[test]
    fn four_hundred_consecutive_reinitialisations_back_off_and_never_spin() {
        // The crash-loop case, driven at the length nobody drives by hand. With
        // no budget the session never gives up, so this asserts the property
        // that matters on its own: the delay grows, is capped, and is never
        // zero.
        let now = moment();
        let limits = unlimited();
        let mut session = Session::new(limits);
        let mut previous = Duration::ZERO;
        let mut reached_ceiling = false;

        for round in 0..400u32 {
            let step = session.observe(Observation::Reinitialise, now);
            let Action::Reinitialise(delay) = step.action else {
                panic!("round {round}: expected a rebuild, got {:?}", step.action);
            };
            assert!(delay >= limits.base_delay, "round {round}: {delay:?} would be a busy-wait");
            assert!(delay <= limits.max_delay, "round {round}: {delay:?} exceeds the ceiling");
            assert!(delay >= previous, "round {round}: backoff went backwards");
            if delay == limits.max_delay {
                reached_ceiling = true;
            }
            previous = delay;
            assert_eq!(step.phase, Phase::Recovering { attempt: round + 1 });
            assert!(!session.input_permitted(), "input must not be injected while recovering");
        }

        assert_eq!(session.reinit_failures(), 400);
        assert!(reached_ceiling, "the backoff never reached its ceiling in 400 attempts");
        assert_eq!(previous, limits.max_delay, "the last delay should be the ceiling");
    }

    #[test]
    fn the_first_few_delays_double_exactly() {
        let now = moment();
        let mut session = Session::new(unlimited());
        let expected = [
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(1000),
            Duration::from_millis(2000),
            Duration::from_millis(4000),
        ];
        for want in expected {
            let step = session.observe(Observation::Reinitialise, now);
            assert_eq!(step.action, Action::Reinitialise(want));
        }
    }

    #[test]
    fn a_budgeted_session_gives_up_and_then_stays_given_up() {
        let now = moment();
        let mut session = Session::new(Limits { reinit_budget: Some(3), ..Limits::default() });
        for attempt in 1..=3 {
            let step = session.observe(Observation::Reinitialise, now);
            assert_eq!(step.phase, Phase::Recovering { attempt });
        }

        let step = session.observe(Observation::Reinitialise, now);
        assert_eq!(step.phase, Phase::GaveUp(Surrender::TooManyReinitialisations));
        assert_eq!(step.action, Action::CloseStreams);
        assert_eq!(step.notice, Some(Notice::GaveUp));

        // Everything afterwards is answered without a delay of zero and without
        // repeating the announcement.
        for observation in [Observation::Reinitialise, Observation::Frame, Observation::Retry] {
            let step = session.observe(observation, now);
            assert_eq!(step.phase, Phase::GaveUp(Surrender::TooManyReinitialisations));
            assert_eq!(step.action, Action::CloseStreams);
            assert_eq!(step.notice, None);
        }
        assert!(!session.input_permitted());
    }

    #[test]
    fn an_operator_resume_clears_a_surrender() {
        let now = moment();
        let mut session = Session::new(Limits { reinit_budget: Some(1), ..Limits::default() });
        session.observe(Observation::Reinitialise, now);
        session.observe(Observation::Reinitialise, now);
        assert!(matches!(session.phase(), Phase::GaveUp(_)));

        let step = session.observe(Observation::Resume, now);
        assert_eq!(step.phase, Phase::Starting);
        assert_eq!(step.action, Action::Capture);
        assert_eq!(session.reinit_failures(), 0, "resume must not inherit the old budget");
    }

    #[test]
    fn a_capture_that_produces_one_frame_per_rebuild_still_runs_out_of_budget() {
        // The bug the healthy window exists for: without it, the single frame
        // between rebuilds resets the counter and the loop never ends.
        let now = moment();
        let mut session = Session::new(Limits { reinit_budget: Some(5), ..Limits::default() });
        for round in 0..5u32 {
            session.observe(Observation::Frame, now + Duration::from_millis(u64::from(round)));
            session.observe(Observation::Reinitialise, now + Duration::from_millis(u64::from(round)));
        }
        let step = session.observe(Observation::Reinitialise, now + Duration::from_secs(1));
        assert_eq!(step.phase, Phase::GaveUp(Surrender::TooManyReinitialisations));
    }

    #[test]
    fn a_real_stretch_of_frames_clears_the_counters() {
        let now = moment();
        let limits = Limits::default();
        let mut session = Session::new(limits);
        session.observe(Observation::Reinitialise, now);
        session.observe(Observation::Reinitialise, now);
        assert_eq!(session.reinit_failures(), 2);

        session.observe(Observation::Frame, now);
        assert_eq!(session.reinit_failures(), 2, "one frame is not a healthy stretch");
        session.observe(Observation::Frame, now + limits.healthy_window - Duration::from_millis(1));
        assert_eq!(session.reinit_failures(), 2);
        session.observe(Observation::Frame, now + limits.healthy_window);
        assert_eq!(session.reinit_failures(), 0);
    }

    #[test]
    fn the_secure_desktop_suspends_input_without_counting_as_a_failure() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        session.observe(Observation::Frame, now);

        let step = session.observe(Observation::SecureDesktop, now);
        assert_eq!(step.phase, Phase::Suspended(Suspension::SecureDesktop));
        assert_eq!(step.action, Action::Suspend { poll_after: BASE_DELAY });
        assert_eq!(step.notice, Some(Notice::SecureDesktop));
        assert_eq!(
            step.notice.map(Notice::sentence),
            Some("secure desktop — screen and input suspended")
        );
        assert!(!session.input_permitted(), "a UAC prompt must not be typeable");
        assert_eq!(session.reinit_failures(), 0);

        // ...and it recovers by itself when the desktop comes back.
        let step = session.observe(Observation::Frame, now);
        assert_eq!(step.phase, Phase::Live);
        assert!(session.input_permitted());
    }

    #[test]
    fn a_logged_out_machine_is_a_state_and_not_an_error() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        let step = session.observe(Observation::NoSession, now);
        assert_eq!(step.phase, Phase::Suspended(Suspension::NoUser));
        assert_eq!(step.notice.map(Notice::sentence), Some("no user is logged in — nothing to capture"));

        // Repeating it says nothing more, and still never spins.
        for _ in 0..100 {
            let step = session.observe(Observation::NoSession, now);
            assert_eq!(step.notice, None);
            assert_eq!(step.action, Action::Suspend { poll_after: BASE_DELAY });
        }
    }

    #[test]
    fn a_session_moving_away_is_distinguished_from_nobody_being_there() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        let step = session.observe(Observation::SessionDisconnected, now);
        assert_eq!(step.phase, Phase::Suspended(Suspension::SessionMoved));
        assert_ne!(step.notice, Some(Notice::NoUser));
    }

    #[test]
    fn denied_permission_polls_slowly_instead_of_giving_up() {
        // macOS consent is granted in System Settings while the daemon runs, so
        // giving up here would mean a restart for every first-time setup.
        let now = moment();
        let limits = Limits::default();
        let mut session = Session::new(limits);
        let step = session.observe(Observation::PermissionDenied, now);
        assert_eq!(step.phase, Phase::Denied);
        assert_eq!(step.action, Action::WaitThen(limits.max_delay));
        assert!(!session.input_permitted());

        let step = session.observe(Observation::Frame, now);
        assert_eq!(step.phase, Phase::Live);
    }

    #[test]
    fn a_dead_agent_is_respawned_with_backoff_and_its_own_budget() {
        let now = moment();
        let mut session = Session::new(Limits { respawn_budget: Some(2), ..Limits::default() });
        assert_eq!(
            session.observe(Observation::AgentExited, now).action,
            Action::RespawnAgent(BASE_DELAY)
        );
        assert_eq!(
            session.observe(Observation::AgentExited, now).action,
            Action::RespawnAgent(BASE_DELAY * 2)
        );
        let step = session.observe(Observation::AgentExited, now);
        assert_eq!(step.phase, Phase::GaveUp(Surrender::AgentUnrecoverable));
        assert_eq!(session.respawns(), 3);
    }

    #[test]
    fn the_kill_switch_closes_everything_and_outranks_every_other_observation() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        session.observe(Observation::Frame, now);

        let step = session.observe(Observation::KillSwitch, now);
        assert_eq!(step.phase, Phase::Stopped);
        assert_eq!(step.action, Action::CloseStreams);
        assert_eq!(step.notice, Some(Notice::Stopped));

        // A frame arriving after the switch does not reopen the session — the
        // whole point of a kill switch outside the console is that the console
        // cannot argue with it.
        for observation in
            [Observation::Frame, Observation::Retry, Observation::SecureDesktop, Observation::Fatal]
        {
            let step = session.observe(observation, now);
            assert_eq!(step.phase, Phase::Stopped, "{observation:?} reopened a killed session");
            assert_eq!(step.action, Action::CloseStreams);
        }
        assert!(!session.input_permitted());

        // Removing the file resumes it.
        assert_eq!(session.observe(Observation::Resume, now).phase, Phase::Starting);
    }

    #[test]
    fn a_fatal_report_gives_up_immediately() {
        let now = moment();
        let mut session = Session::new(Limits::default());
        let step = session.observe(Observation::Fatal, now);
        assert_eq!(step.phase, Phase::GaveUp(Surrender::Fatal));
        assert_eq!(step.action, Action::CloseStreams);
    }

    #[test]
    fn backoff_is_bounded_at_absurd_attempt_counts() {
        let limits = Limits::default();
        for attempt in [31, 32, 33, 1000, u32::MAX] {
            let delay = backoff(limits, attempt);
            assert_eq!(delay, limits.max_delay, "attempt {attempt}");
        }
        // And never below the base, even if an operator sets a ceiling under it.
        let odd = Limits {
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(1),
            ..limits
        };
        assert_eq!(backoff(odd, 0), Duration::from_secs(1));
        assert!(backoff(odd, 0) > Duration::ZERO);
    }

    #[test]
    fn no_observation_in_any_phase_ever_asks_for_a_zero_delay() {
        // The blanket statement of "back off rather than spin", asserted across
        // the whole cross product rather than in the one case that prompted it.
        let now = moment();
        let observations = [
            Observation::Frame,
            Observation::Retry,
            Observation::Reinitialise,
            Observation::SecureDesktop,
            Observation::SessionDisconnected,
            Observation::NoSession,
            Observation::PermissionDenied,
            Observation::AgentExited,
            Observation::Fatal,
            Observation::KillSwitch,
            Observation::Resume,
        ];
        for first in observations {
            for second in observations {
                let mut session = Session::new(Limits::default());
                session.observe(first, now);
                let step = session.observe(second, now);
                let delay = match step.action {
                    Action::WaitThen(delay)
                    | Action::Reinitialise(delay)
                    | Action::RespawnAgent(delay)
                    | Action::Suspend { poll_after: delay } => Some(delay),
                    Action::Capture | Action::CloseStreams => None,
                };
                if let Some(delay) = delay {
                    assert!(delay > Duration::ZERO, "{first:?} then {second:?} would busy-wait");
                }
            }
        }
    }
}
