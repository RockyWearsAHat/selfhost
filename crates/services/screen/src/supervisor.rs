//! Keeping an agent alive in the session a person is actually sitting in.
//!
//! On the production box the daemon is a Scheduled Task running as `SYSTEM` at
//! system startup — which means **session 0**, which has no interactive display.
//! A session-0 process cannot capture the user's desktop by any method: DXGI's
//! `DuplicateOutput` fails outright and `GetDC(NULL)` hands back a device context
//! for session 0's own blank desktop. This is not a permissions tweak that can be
//! applied later; it is a property of the process, and the only way past it is to
//! run a second process inside the console session and talk to it. That second
//! process is the agent, and this module is the half of its life the daemon owns.
//!
//! # The decision is pure; the process handling is the thin part
//!
//! [`Supervision`] is a state machine over explicit inputs with an explicit
//! clock. It never spawns anything, never reads a file and never asks what time
//! it is. That is the same argument `selfhost_supervisor::policy` makes about
//! restarting services, and it applies here with more force: the hazards this
//! machine has to survive — the operator logging out, fast user switching, an RDP
//! session stealing the console, a UAC prompt, the agent being killed from Task
//! Manager — cannot be produced on demand in CI at all, and several of them
//! cannot be produced on the developer's machine either. Feeding them in as
//! values is the only way they are ever exercised before the day they happen.
//!
//! This module deliberately does **not** depend on `selfhost-supervisor`. That
//! crate's policy is shaped by `selfhost-config`'s `RestartPolicy`, which would
//! drag the whole config crate under `screen` and invert the dependency the plan
//! draws. The backoff here is modelled on it — doubling, ceilinged, reset only
//! after a real stretch of uptime — and adds the thing a service supervisor does
//! not need: **a cap per hour**, so an agent that can start and die forever
//! eventually says so in the console instead of respawning silently until the
//! machine is rebooted.
//!
//! # Everything that is not a failure is a state
//!
//! Nobody logged in, the console session mid-attach, a session switch: none of
//! these are errors and none of them count against any budget. They are the
//! ordinary life of a machine that spends most of its time at a login screen. A
//! supervisor that counted them would exhaust its budget overnight and refuse to
//! start the agent in the morning.

use crate::fault::Fault;
use selfhost_desk::state::{Notice, Surrender};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The window the per-hour respawn cap is measured over.
const CAP_WINDOW: Duration = Duration::from_secs(3600);

/// What the machine says about the session on its physical console.
///
/// Three answers rather than two, because "the session id could not be read
/// yet" and "nobody is logged in" are different states with different sentences,
/// and collapsing them makes a booting machine indistinguishable from an empty
/// one. On Windows the first is `WTSGetActiveConsoleSessionId` answering
/// `0xFFFFFFFF` — documented as *retry*, not as an error — and the second is
/// `WTSQueryUserToken` answering `ERROR_NO_TOKEN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleSession {
    /// Somebody is signed in on the physical console, in this session.
    User(u32),
    /// A console session exists but nobody has signed in: the machine is sitting
    /// at its login screen. Perfectly ordinary, and not a failure of anything.
    NoUser,
    /// The console session is between attachments and the platform is asking to
    /// be asked again. Happens during boot, during a session switch, and while
    /// the console is being redirected.
    Attaching,
}

impl ConsoleSession {
    /// Whether this is a signed-in session with the given id.
    pub const fn is_user(self, session: u32) -> bool {
        matches!(self, Self::User(id) if id == session)
    }

    /// The session id, for a session somebody is signed into.
    pub const fn id(self) -> Option<u32> {
        match self {
            Self::User(id) => Some(id),
            Self::NoUser | Self::Attaching => None,
        }
    }
}

/// The ceilings and delays that shape an agent's life.
///
/// Every field has a default that is sane for the production box; the operator's
/// `[desktop].agent_respawn_cap` maps onto [`Limits::spawns_per_hour`] and is the
/// only one exposed in config, because the others are properties of the failure
/// mode rather than of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The delay before the first respawn after a failure.
    pub base_delay: Duration,
    /// The longest a respawn is ever delayed. Without a ceiling, an agent that
    /// has been failing overnight is not retried for days and the operator's fix
    /// appears not to work.
    pub max_delay: Duration,
    /// How long an agent must stay connected before its failure count resets.
    /// Below this an agent that starts, dies and starts again would clear its own
    /// history every cycle and loop at the base delay forever.
    pub healthy_window: Duration,
    /// How many spawns are allowed in any one hour before the supervisor stops
    /// trying and says so. This is the difference between a self-healing system
    /// and one that hides a permanent fault behind an infinite retry.
    pub spawns_per_hour: u32,
    /// How long a spawned agent has to connect back before it is presumed dead.
    /// `CreateProcessAsUserW` can succeed and hand back a process that then fails
    /// to initialise, in which case nothing ever arrives on the pipe and without
    /// this the supervisor waits forever.
    pub start_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            healthy_window: Duration::from_secs(60),
            spawns_per_hour: 10,
            start_deadline: Duration::from_secs(20),
        }
    }
}

/// Something that happened to the agent or to the session it lives in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    /// The console session was polled and this is what it said.
    Session(ConsoleSession),
    /// The agent connected its pipe and identified itself.
    Connected,
    /// The agent process ended.
    Exited {
        /// Its exit code, where the platform reported one.
        code: Option<i32>,
    },
    /// The agent could not be started.
    SpawnFailed(Fault),
    /// The operator's kill switch — `<data_dir>/desktop.disabled` — appeared or
    /// was removed. Deliberately not part of the console: an operator with
    /// filesystem access must be able to revoke this capability without going
    /// through the surface an attacker would already hold.
    KillSwitch(bool),
    /// The operator asked for the agent to start again.
    OperatorStart,
}

/// What the daemon should do about the agent right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAction {
    /// Nothing; poll again.
    Idle,
    /// Start the agent in this console session.
    Spawn {
        /// The session to start it in.
        session: u32,
    },
    /// End the agent that is running.
    Stop(StopReason),
}

/// Why a running agent is being stopped.
///
/// Distinguished because only one of them counts as a failure: an agent stopped
/// because the operator logged out did nothing wrong, and charging it against the
/// respawn budget would mean a machine that is switched between two users all day
/// eventually refuses to start an agent at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The interactive session is no longer the one the agent runs in.
    SessionChanged,
    /// The kill switch is in place.
    KillSwitch,
    /// It was started but never connected within [`Limits::start_deadline`].
    NeverConnected,
}

/// Where the agent is, in words the console can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPhase {
    /// There is nothing to run an agent in.
    Waiting(ConsoleSession),
    /// Waiting out a backoff before the next attempt.
    Backoff {
        /// How much of the delay is left. Rendered, so the operator watches the
        /// retry approach instead of wondering whether anything is happening.
        remaining: Duration,
        /// How many consecutive failures got us here.
        failures: u32,
    },
    /// Started, waiting for it to connect.
    Starting {
        /// The session it was started in.
        session: u32,
    },
    /// Connected and healthy.
    Live {
        /// The session it is running in.
        session: u32,
    },
    /// Stopped by the operator's kill switch.
    Stopped,
    /// Stopped trying.
    GaveUp(Surrender),
}

impl AgentPhase {
    /// The protocol notice this phase presents to a console.
    pub const fn notice(self) -> Notice {
        match self {
            Self::Waiting(ConsoleSession::NoUser) => Notice::NoUser,
            Self::Waiting(_) => Notice::Starting,
            Self::Backoff { .. } | Self::Starting { .. } => Notice::Recovering,
            Self::Live { .. } => Notice::Live,
            Self::Stopped => Notice::Stopped,
            Self::GaveUp(_) => Notice::GaveUp,
        }
    }

    /// The phase as one sentence, for the desktop plate.
    pub fn sentence(self) -> String {
        match self {
            Self::Waiting(ConsoleSession::NoUser) => {
                "No user is logged in — there is nothing to capture yet. The agent starts \
                 by itself when somebody signs in."
                    .to_owned()
            }
            Self::Waiting(ConsoleSession::Attaching) => {
                "The machine has not attached a console session yet; waiting for it.".to_owned()
            }
            Self::Waiting(ConsoleSession::User(session)) => {
                format!("Somebody is signed in to session {session}; the agent is about to start.")
            }
            Self::Backoff { remaining, failures } => format!(
                "The agent has failed {failures} time(s) in a row; the next attempt is in {} second(s).",
                remaining.as_secs().max(1)
            ),
            Self::Starting { session } => {
                format!("The agent has been started in session {session} and has not connected yet.")
            }
            Self::Live { session } => format!("The agent is live in session {session}."),
            Self::Stopped => {
                "The kill switch is in place: no agent runs and no session is accepted."
                    .to_owned()
            }
            Self::GaveUp(surrender) => format!(
                "The agent stopped being started ({surrender:?}). Clear whatever is wrong and \
                 press start; nothing will retry on its own."
            ),
        }
    }
}

/// What the supervisor is doing internally.
///
/// Private because every transition between these is this module's business, and
/// [`AgentPhase`] is the whole of what a caller needs to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nothing running and nothing scheduled.
    Idle,
    /// Waiting out a delay before spawning into `session`.
    Backoff { session: u32, until: Instant },
    /// Spawned into `session`, waiting for it to connect by `deadline`.
    Starting { session: u32, deadline: Instant },
    /// Connected in `session` since this moment.
    Live { session: u32, since: Instant },
    /// Stopped trying.
    GaveUp(Surrender),
}

/// The pure decision: when to start an agent, when to stop it, and when to stop
/// trying.
///
/// Drive it by calling [`Supervision::observe`] with everything that happens and
/// [`Supervision::act`] to ask what to do. The two are separate so that
/// observations can arrive from several sources — a session poll, a process
/// handle, a filesystem check — without any of them having to know what the
/// others saw.
#[derive(Debug)]
pub struct Supervision {
    limits: Limits,
    state: State,
    session: ConsoleSession,
    disabled: bool,
    failures: u32,
    /// When each spawn happened, pruned to the last hour. A `VecDeque` because
    /// the only operations are "push newest" and "drop oldest", and the cap keeps
    /// it to a handful of entries.
    spawns: VecDeque<Instant>,
    last_fault: Option<Fault>,
}

impl Supervision {
    /// A supervisor that has observed nothing yet.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: State::Idle,
            session: ConsoleSession::Attaching,
            disabled: false,
            failures: 0,
            spawns: VecDeque::new(),
            last_fault: None,
        }
    }

    /// Records something that happened.
    pub fn observe(&mut self, event: AgentEvent, now: Instant) {
        match event {
            AgentEvent::Session(session) => self.session = session,
            AgentEvent::Connected => {
                if let State::Starting { session, .. } = self.state {
                    self.state = State::Live { session, since: now };
                }
            }
            AgentEvent::Exited { code } => {
                // A code this build wrote becomes the sentence it stands for.
                // `exited with code 1` is true and useless: it cannot tell a
                // console that changed hands from a pipe that would not have the
                // agent from a screen that would not open, and those are three
                // different remedies. See [`crate::agent::Departure`].
                self.last_fault = code.map(|code| match crate::agent::Departure::from_code(code) {
                    Some(departure) => Fault::refused("the desktop agent", departure.sentence()),
                    None => Fault::refused(
                        "the desktop agent",
                        format!(
                            "exited with code {code}, which this build never writes deliberately \
                             — it is a crash or a kill rather than a refusal"
                        ),
                    ),
                });
                self.note_failure(now);
            }
            AgentEvent::SpawnFailed(fault) => {
                self.last_fault = Some(fault);
                self.note_failure(now);
            }
            AgentEvent::KillSwitch(present) => self.disabled = present,
            AgentEvent::OperatorStart => {
                // Pressing start is a statement that the operator has dealt with
                // whatever was wrong, so it must not inherit the old backoff or
                // the old hour's spawns and appear to do nothing.
                self.failures = 0;
                self.spawns.clear();
                self.last_fault = None;
                if matches!(self.state, State::GaveUp(_) | State::Backoff { .. }) {
                    self.state = State::Idle;
                }
            }
        }
    }

    /// What to do right now.
    ///
    /// Takes `&mut self` because the decision can itself be a conclusion: when
    /// the hour's spawn budget is spent, asking what to do is what discovers it,
    /// and the supervisor records the surrender rather than rediscovering it on
    /// every later call.
    pub fn act(&mut self, now: Instant) -> AgentAction {
        if self.disabled {
            return if self.is_running() { AgentAction::Stop(StopReason::KillSwitch) } else { AgentAction::Idle };
        }

        match self.state {
            State::GaveUp(_) => AgentAction::Idle,
            State::Live { session, .. } | State::Starting { session, .. }
                if !self.session.is_user(session) =>
            {
                // Fast user switching, a logout, or RDP taking the console away.
                // Not a failure of the agent, and deliberately not charged to it.
                AgentAction::Stop(StopReason::SessionChanged)
            }
            State::Starting { deadline, .. } if now >= deadline => {
                AgentAction::Stop(StopReason::NeverConnected)
            }
            State::Live { .. } | State::Starting { .. } => AgentAction::Idle,
            State::Backoff { session, until } => {
                if !self.session.is_user(session) {
                    // The session we were going to spawn into has gone; wait for
                    // whatever comes next rather than spawning into nothing.
                    self.state = State::Idle;
                    return AgentAction::Idle;
                }
                if now < until {
                    AgentAction::Idle
                } else {
                    self.spawn_or_surrender(session, now)
                }
            }
            State::Idle => match self.session {
                ConsoleSession::User(session) => self.spawn_or_surrender(session, now),
                ConsoleSession::NoUser | ConsoleSession::Attaching => AgentAction::Idle,
            },
        }
    }

    /// Records that the spawn [`Supervision::act`] asked for was performed.
    pub fn spawned(&mut self, session: u32, now: Instant) {
        self.spawns.push_back(now);
        self.state =
            State::Starting { session, deadline: now + self.limits.start_deadline };
    }

    /// Records that the agent [`Supervision::act`] asked to stop is gone.
    ///
    /// A stop is never a failure: it happened because the session moved, because
    /// the kill switch appeared, or because the agent never connected — and the
    /// last of those was already counted when the deadline passed.
    pub fn stopped(&mut self, reason: StopReason, now: Instant) {
        match reason {
            StopReason::NeverConnected => {
                self.last_fault = Some(Fault::refused(
                    "the desktop agent",
                    "was started but never connected to its pipe",
                ));
                self.note_failure(now);
            }
            StopReason::SessionChanged | StopReason::KillSwitch => self.state = State::Idle,
        }
    }

    /// Where the agent is, for the console.
    pub fn phase(&self, now: Instant) -> AgentPhase {
        if self.disabled {
            return AgentPhase::Stopped;
        }
        match self.state {
            State::Idle => AgentPhase::Waiting(self.session),
            State::Backoff { until, .. } => AgentPhase::Backoff {
                remaining: until.saturating_duration_since(now),
                failures: self.failures,
            },
            State::Starting { session, .. } => AgentPhase::Starting { session },
            State::Live { session, .. } => AgentPhase::Live { session },
            State::GaveUp(surrender) => AgentPhase::GaveUp(surrender),
        }
    }

    /// The last thing that went wrong, if anything has.
    ///
    /// Kept rather than logged and dropped, because the console's whole job on
    /// this plate is to say *why* — and "the agent is not running" without a
    /// reason is what sends an operator to reboot a machine.
    pub fn last_fault(&self) -> Option<&Fault> {
        self.last_fault.as_ref()
    }

    /// How many times the agent has been started in the last hour.
    pub fn spawns_in_last_hour(&self, now: Instant) -> usize {
        self.spawns.iter().filter(|at| within_window(**at, now)).count()
    }

    /// Whether a process is believed to exist.
    fn is_running(&self) -> bool {
        matches!(self.state, State::Starting { .. } | State::Live { .. })
    }

    /// Decides between spawning and giving up, applying the per-hour cap.
    fn spawn_or_surrender(&mut self, session: u32, now: Instant) -> AgentAction {
        while self.spawns.front().is_some_and(|at| !within_window(*at, now)) {
            self.spawns.pop_front();
        }
        let cap = self.limits.spawns_per_hour as usize;
        if cap != 0 && self.spawns.len() >= cap {
            self.state = State::GaveUp(Surrender::AgentUnrecoverable);
            return AgentAction::Idle;
        }
        AgentAction::Spawn { session }
    }

    /// Counts a failure and schedules the next attempt.
    fn note_failure(&mut self, now: Instant) {
        // An agent that stayed connected for a real stretch proved it can, so its
        // history does not follow it into the next attempt.
        if let State::Live { since, .. } = self.state {
            if now.saturating_duration_since(since) >= self.limits.healthy_window {
                self.failures = 0;
            }
        }
        let delay = backoff(self.limits.base_delay, self.limits.max_delay, self.failures);
        self.failures = self.failures.saturating_add(1);
        self.state = match self.session.id() {
            Some(session) => State::Backoff { session, until: now + delay },
            // Nothing to go back to yet; the next session observation starts the
            // cycle again, and the failure count is preserved.
            None => State::Idle,
        };
    }
}

/// Whether a moment is inside the cap's one-hour window ending at `now`.
///
/// `checked_duration_since` rather than subtraction: a caller that hands in a
/// `now` earlier than a recorded spawn — a clock that jumped, a test that
/// rewound — would otherwise abort the process on the underflow.
fn within_window(at: Instant, now: Instant) -> bool {
    match now.checked_duration_since(at) {
        Some(age) => age < CAP_WINDOW,
        // `at` is in the future relative to `now`, so it is certainly recent.
        None => true,
    }
}

/// The delay before attempt number `attempt`, counting from zero.
///
/// Doubles each time and stops at `max`. The shift is guarded because `1u64 << 64`
/// is undefined rather than saturating, and an agent that has failed sixty-four
/// times is exactly the case that reaches it.
pub fn backoff(base: Duration, max: Duration, attempt: u32) -> Duration {
    let multiplier = 1u64.checked_shl(attempt.min(32)).unwrap_or(u64::MAX);
    let scaled = base.saturating_mul(u32::try_from(multiplier).unwrap_or(u32::MAX));
    scaled.min(max)
}

/// What the daemon must be able to do, on this platform, to keep an agent alive.
///
/// A trait rather than a `cfg` cascade because it is the seam the whole restart
/// path is tested through: a fake host on a developer's Mac drives the agent
/// dying, the session switching and the spawn failing, none of which can be
/// arranged on the machine this actually ships to.
pub trait AgentHost {
    /// The session on the physical console, right now.
    fn console_session(&mut self) -> Result<ConsoleSession, Fault>;

    /// Starts the agent inside `session`.
    fn spawn(&mut self, session: u32) -> Result<Box<dyn AgentProcess>, Fault>;
}

/// A running agent process, from the daemon's side.
pub trait AgentProcess: std::fmt::Debug {
    /// The session it was started in.
    fn session(&self) -> u32;

    /// Its exit code if it has ended, `None` if it is still running.
    fn finished(&mut self) -> Result<Option<i32>, Fault>;

    /// Ends it, and does not fail: a supervisor that cannot give up on a process
    /// has no way back to a working state.
    fn terminate(&mut self);
}

/// The thin impure half: polls the host, applies [`Supervision`]'s decisions.
///
/// Deliberately small. Everything that could be wrong in an interesting way is in
/// the state machine above; what is left here is calling three methods in the
/// order the state machine asked for.
#[derive(Debug)]
pub struct Agent<H: AgentHost> {
    host: H,
    supervision: Supervision,
    process: Option<Box<dyn AgentProcess>>,
}

impl<H: AgentHost> Agent<H> {
    /// An agent supervisor over this host.
    pub fn new(host: H, limits: Limits) -> Self {
        Self { host, supervision: Supervision::new(limits), process: None }
    }

    /// Tells the supervisor the agent has connected and identified itself.
    pub fn connected(&mut self, now: Instant) {
        self.supervision.observe(AgentEvent::Connected, now);
    }

    /// Tells the supervisor whether the operator's kill switch is in place.
    pub fn set_kill_switch(&mut self, present: bool, now: Instant) {
        self.supervision.observe(AgentEvent::KillSwitch(present), now);
    }

    /// Tells the supervisor the operator asked for a fresh start.
    pub fn operator_start(&mut self, now: Instant) {
        self.supervision.observe(AgentEvent::OperatorStart, now);
    }

    /// One turn of the loop: observe, decide, act.
    ///
    /// Returns the phase afterwards, which is what the console renders.
    pub fn tick(&mut self, now: Instant) -> AgentPhase {
        self.observe_process(now);
        self.observe_session(now);

        match self.supervision.act(now) {
            AgentAction::Idle => {}
            AgentAction::Spawn { session } => match self.host.spawn(session) {
                Ok(process) => {
                    self.process = Some(process);
                    self.supervision.spawned(session, now);
                }
                Err(fault) => self.supervision.observe(AgentEvent::SpawnFailed(fault), now),
            },
            AgentAction::Stop(reason) => {
                if let Some(process) = self.process.as_mut() {
                    process.terminate();
                }
                self.process = None;
                self.supervision.stopped(reason, now);
            }
        }

        self.supervision.phase(now)
    }

    /// The pure state machine, for a caller that wants the detail behind the
    /// phase — the last fault, the hour's spawn count.
    pub fn supervision(&self) -> &Supervision {
        &self.supervision
    }

    /// Notices an agent that has ended.
    fn observe_process(&mut self, now: Instant) {
        let Some(process) = self.process.as_mut() else { return };
        match process.finished() {
            Ok(None) => {}
            Ok(Some(code)) => {
                self.process = None;
                self.supervision.observe(AgentEvent::Exited { code: Some(code) }, now);
            }
            Err(fault) => {
                // We can no longer tell whether it is alive, which is the same
                // situation as it being dead — and pretending otherwise leaves a
                // supervisor waiting on a handle it cannot read.
                self.process = None;
                self.supervision.observe(AgentEvent::SpawnFailed(fault), now);
            }
        }
    }

    /// Notices which session the console is in.
    fn observe_session(&mut self, now: Instant) {
        match self.host.console_session() {
            Ok(session) => self.supervision.observe(AgentEvent::Session(session), now),
            Err(fault) => {
                // Failing to read the session is transient — the platform is
                // mid-switch, or a service has not started yet. Treated as
                // "ask again", never as a failure of the agent, but kept so the
                // operator can see it happening rather than seeing nothing.
                self.supervision.last_fault = Some(fault);
                self.supervision
                    .observe(AgentEvent::Session(ConsoleSession::Attaching), now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A clock that starts somewhere and moves when a test says so.
    fn origin() -> Instant {
        Instant::now()
    }

    fn limits() -> Limits {
        Limits {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            healthy_window: Duration::from_secs(60),
            spawns_per_hour: 5,
            start_deadline: Duration::from_secs(20),
        }
    }

    #[test]
    fn nothing_is_started_while_nobody_is_logged_in() {
        // The ordinary state of a rebooted server, and it must cost nothing: no
        // spawn, no failure, no budget spent.
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::NoUser), now);
        assert_eq!(supervision.act(now), AgentAction::Idle);
        assert_eq!(supervision.phase(now), AgentPhase::Waiting(ConsoleSession::NoUser));
        assert_eq!(supervision.spawns_in_last_hour(now), 0);
    }

    #[test]
    fn an_attaching_console_is_asked_again_rather_than_treated_as_empty() {
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::Attaching), now);
        assert_eq!(supervision.act(now), AgentAction::Idle);
        assert_eq!(supervision.phase(now).notice(), Notice::Starting);
    }

    #[test]
    fn a_signed_in_session_gets_an_agent() {
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        assert_eq!(supervision.act(now), AgentAction::Spawn { session: 1 });
        supervision.spawned(1, now);
        assert_eq!(supervision.phase(now), AgentPhase::Starting { session: 1 });
        supervision.observe(AgentEvent::Connected, now);
        assert_eq!(supervision.phase(now), AgentPhase::Live { session: 1 });
        assert_eq!(supervision.act(now), AgentAction::Idle);
    }

    #[test]
    fn a_session_switch_stops_the_agent_without_counting_it_as_a_failure() {
        // Fast user switching all day must not exhaust the respawn budget.
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        supervision.spawned(1, now);
        supervision.observe(AgentEvent::Connected, now);

        supervision.observe(AgentEvent::Session(ConsoleSession::User(2)), now);
        assert_eq!(supervision.act(now), AgentAction::Stop(StopReason::SessionChanged));
        supervision.stopped(StopReason::SessionChanged, now);
        // And immediately starts again in the session that took over.
        assert_eq!(supervision.act(now), AgentAction::Spawn { session: 2 });
    }

    #[test]
    fn logging_out_stops_the_agent_and_waits() {
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        supervision.spawned(1, now);
        supervision.observe(AgentEvent::Connected, now);

        supervision.observe(AgentEvent::Session(ConsoleSession::NoUser), now);
        assert_eq!(supervision.act(now), AgentAction::Stop(StopReason::SessionChanged));
        supervision.stopped(StopReason::SessionChanged, now);
        assert_eq!(supervision.act(now), AgentAction::Idle);
        assert_eq!(supervision.phase(now).notice(), Notice::NoUser);
    }

    #[test]
    fn an_agent_that_dies_is_restarted_after_a_visible_backoff() {
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        supervision.spawned(1, now);
        supervision.observe(AgentEvent::Connected, now);

        supervision.observe(AgentEvent::Exited { code: Some(1) }, now);
        match supervision.phase(now) {
            AgentPhase::Backoff { remaining, failures } => {
                assert_eq!(failures, 1);
                assert!(remaining <= Duration::from_secs(1));
            }
            other => panic!("expected a backoff, got {other:?}"),
        }
        assert_eq!(supervision.act(now), AgentAction::Idle, "too early to retry");
        let later = now + Duration::from_secs(1);
        assert_eq!(supervision.act(later), AgentAction::Spawn { session: 1 });
    }

    #[test]
    fn the_backoff_doubles_and_stops_at_the_ceiling() {
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(30), 0), Duration::from_secs(1));
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(30), 1), Duration::from_secs(2));
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(30), 4), Duration::from_secs(16));
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(30), 5), Duration::from_secs(30));
        // `1u64 << 64` is undefined rather than saturating, and an agent failing
        // for long enough gets there.
        for attempt in [31, 32, 33, u32::MAX] {
            assert_eq!(
                backoff(Duration::from_secs(1), Duration::from_secs(30), attempt),
                Duration::from_secs(30),
                "attempt {attempt}"
            );
        }
    }

    #[test]
    fn a_crash_loop_gives_up_within_the_hour_instead_of_respawning_forever() {
        // The whole reason for a per-hour cap: an agent that can start and die
        // forever must end up saying so in the console rather than hiding a
        // permanent fault behind an infinite retry.
        let mut now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);

        for attempt in 0..5 {
            assert_eq!(
                supervision.act(now),
                AgentAction::Spawn { session: 1 },
                "attempt {attempt} should still be allowed"
            );
            supervision.spawned(1, now);
            supervision.observe(AgentEvent::Exited { code: Some(3) }, now);
            now += Duration::from_secs(60);
        }

        assert_eq!(supervision.act(now), AgentAction::Idle);
        assert_eq!(
            supervision.phase(now),
            AgentPhase::GaveUp(Surrender::AgentUnrecoverable)
        );
        assert!(supervision.last_fault().is_some(), "the reason must survive");
    }

    #[test]
    fn the_hourly_budget_refills_as_the_hour_passes() {
        let mut now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        for _ in 0..5 {
            supervision.spawned(1, now);
            supervision.observe(AgentEvent::Exited { code: Some(3) }, now);
            now += Duration::from_secs(1);
        }
        assert_eq!(supervision.spawns_in_last_hour(now), 5);
        let much_later = now + Duration::from_secs(3601);
        assert_eq!(supervision.spawns_in_last_hour(much_later), 0);
        assert_eq!(supervision.act(much_later), AgentAction::Spawn { session: 1 });
    }

    #[test]
    fn an_agent_that_stayed_up_a_while_does_not_inherit_the_old_backoff() {
        let mut now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);

        // Two quick failures, then one that ran for long enough to count.
        for _ in 0..2 {
            supervision.spawned(1, now);
            supervision.observe(AgentEvent::Exited { code: Some(1) }, now);
            now += Duration::from_secs(30);
        }
        supervision.spawned(1, now);
        supervision.observe(AgentEvent::Connected, now);
        now += Duration::from_secs(120);
        supervision.observe(AgentEvent::Exited { code: Some(1) }, now);

        match supervision.phase(now) {
            AgentPhase::Backoff { failures, remaining } => {
                assert_eq!(failures, 1, "the healthy stretch cleared the history");
                assert!(remaining <= Duration::from_secs(1));
            }
            other => panic!("expected a backoff, got {other:?}"),
        }
    }

    #[test]
    fn an_agent_that_never_connects_is_stopped_and_counted() {
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        supervision.spawned(1, now);

        assert_eq!(supervision.act(now), AgentAction::Idle, "still inside the deadline");
        let past = now + Duration::from_secs(21);
        assert_eq!(supervision.act(past), AgentAction::Stop(StopReason::NeverConnected));
        supervision.stopped(StopReason::NeverConnected, past);
        assert!(matches!(supervision.phase(past), AgentPhase::Backoff { failures: 1, .. }));
    }

    #[test]
    fn the_kill_switch_stops_everything_and_refuses_to_start_anything() {
        // An operator with filesystem access must be able to revoke this without
        // going through the console an attacker would already hold.
        let now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        supervision.spawned(1, now);
        supervision.observe(AgentEvent::Connected, now);

        supervision.observe(AgentEvent::KillSwitch(true), now);
        assert_eq!(supervision.act(now), AgentAction::Stop(StopReason::KillSwitch));
        supervision.stopped(StopReason::KillSwitch, now);
        assert_eq!(supervision.act(now), AgentAction::Idle);
        assert_eq!(supervision.phase(now), AgentPhase::Stopped);

        supervision.observe(AgentEvent::KillSwitch(false), now);
        assert_eq!(supervision.act(now), AgentAction::Spawn { session: 1 });
    }

    #[test]
    fn an_operator_start_clears_the_surrender_and_the_hours_budget() {
        let mut now = origin();
        let mut supervision = Supervision::new(limits());
        supervision.observe(AgentEvent::Session(ConsoleSession::User(1)), now);
        for _ in 0..5 {
            supervision.act(now);
            supervision.spawned(1, now);
            supervision.observe(AgentEvent::Exited { code: Some(3) }, now);
            now += Duration::from_secs(60);
        }
        supervision.act(now);
        assert!(matches!(supervision.phase(now), AgentPhase::GaveUp(_)));

        supervision.observe(AgentEvent::OperatorStart, now);
        assert_eq!(supervision.act(now), AgentAction::Spawn { session: 1 });
    }

    #[test]
    fn every_phase_has_a_sentence_and_a_notice() {
        let phases = [
            AgentPhase::Waiting(ConsoleSession::NoUser),
            AgentPhase::Waiting(ConsoleSession::Attaching),
            AgentPhase::Waiting(ConsoleSession::User(1)),
            AgentPhase::Backoff { remaining: Duration::from_secs(4), failures: 2 },
            AgentPhase::Starting { session: 1 },
            AgentPhase::Live { session: 1 },
            AgentPhase::Stopped,
            AgentPhase::GaveUp(Surrender::AgentUnrecoverable),
        ];
        for phase in phases {
            assert!(!phase.sentence().is_empty(), "{phase:?} has no sentence");
            let _ = phase.notice();
        }
    }

    /// A host a test drives: the session it reports and whether spawning works.
    #[derive(Debug, Default)]
    struct FakeState {
        session: Option<ConsoleSession>,
        spawn_fails: bool,
        spawned: u32,
        terminated: u32,
        exit: Option<i32>,
    }

    #[derive(Debug, Clone)]
    struct FakeHost(Rc<RefCell<FakeState>>);

    #[derive(Debug)]
    struct FakeProcess {
        session: u32,
        state: Rc<RefCell<FakeState>>,
    }

    impl AgentHost for FakeHost {
        fn console_session(&mut self) -> Result<ConsoleSession, Fault> {
            self.0
                .borrow()
                .session
                .ok_or_else(|| Fault::os("WTSGetActiveConsoleSessionId", 5))
        }

        fn spawn(&mut self, session: u32) -> Result<Box<dyn AgentProcess>, Fault> {
            let mut state = self.0.borrow_mut();
            if state.spawn_fails {
                return Err(Fault::os("CreateProcessAsUserW", 1314));
            }
            state.spawned += 1;
            drop(state);
            Ok(Box::new(FakeProcess { session, state: Rc::clone(&self.0) }))
        }
    }

    impl AgentProcess for FakeProcess {
        fn session(&self) -> u32 {
            self.session
        }

        fn finished(&mut self) -> Result<Option<i32>, Fault> {
            Ok(self.state.borrow().exit)
        }

        fn terminate(&mut self) {
            self.state.borrow_mut().terminated += 1;
        }
    }

    #[test]
    fn the_driver_starts_an_agent_when_somebody_signs_in() {
        let state = Rc::new(RefCell::new(FakeState {
            session: Some(ConsoleSession::NoUser),
            ..FakeState::default()
        }));
        let mut agent = Agent::new(FakeHost(Rc::clone(&state)), limits());
        let now = origin();

        assert_eq!(agent.tick(now), AgentPhase::Waiting(ConsoleSession::NoUser));
        assert_eq!(state.borrow().spawned, 0);

        state.borrow_mut().session = Some(ConsoleSession::User(1));
        assert_eq!(agent.tick(now), AgentPhase::Starting { session: 1 });
        assert_eq!(state.borrow().spawned, 1);

        agent.connected(now);
        assert_eq!(agent.tick(now), AgentPhase::Live { session: 1 });
    }

    #[test]
    fn the_driver_notices_the_agent_dying_and_brings_it_back() {
        let state = Rc::new(RefCell::new(FakeState {
            session: Some(ConsoleSession::User(1)),
            ..FakeState::default()
        }));
        let mut agent = Agent::new(FakeHost(Rc::clone(&state)), limits());
        let mut now = origin();

        agent.tick(now);
        agent.connected(now);
        assert_eq!(agent.tick(now), AgentPhase::Live { session: 1 });

        // Killed from Task Manager.
        state.borrow_mut().exit = Some(1);
        assert!(matches!(agent.tick(now), AgentPhase::Backoff { failures: 1, .. }));

        state.borrow_mut().exit = None;
        now += Duration::from_secs(2);
        assert_eq!(agent.tick(now), AgentPhase::Starting { session: 1 });
        assert_eq!(state.borrow().spawned, 2);
    }

    #[test]
    fn the_driver_terminates_the_agent_when_the_session_moves() {
        let state = Rc::new(RefCell::new(FakeState {
            session: Some(ConsoleSession::User(1)),
            ..FakeState::default()
        }));
        let mut agent = Agent::new(FakeHost(Rc::clone(&state)), limits());
        let now = origin();

        agent.tick(now);
        agent.connected(now);
        state.borrow_mut().session = Some(ConsoleSession::User(2));

        agent.tick(now);
        assert_eq!(state.borrow().terminated, 1);
        assert_eq!(agent.tick(now), AgentPhase::Starting { session: 2 });
    }

    #[test]
    fn a_host_that_cannot_answer_is_retried_rather_than_treated_as_a_failure() {
        // A session query failing mid-switch must not spend the respawn budget,
        // and it must not be swallowed either — the fault is kept.
        let state = Rc::new(RefCell::new(FakeState { session: None, ..FakeState::default() }));
        let mut agent = Agent::new(FakeHost(Rc::clone(&state)), limits());
        let now = origin();

        assert_eq!(agent.tick(now), AgentPhase::Waiting(ConsoleSession::Attaching));
        assert!(agent.supervision().last_fault().is_some());
        assert_eq!(agent.supervision().spawns_in_last_hour(now), 0);
    }

    #[test]
    fn a_spawn_that_fails_backs_off_and_keeps_the_reason() {
        let state = Rc::new(RefCell::new(FakeState {
            session: Some(ConsoleSession::User(1)),
            spawn_fails: true,
            ..FakeState::default()
        }));
        let mut agent = Agent::new(FakeHost(Rc::clone(&state)), limits());
        let now = origin();

        assert!(matches!(agent.tick(now), AgentPhase::Backoff { failures: 1, .. }));
        let fault = agent.supervision().last_fault().expect("the reason must survive");
        assert_eq!(fault.call(), "CreateProcessAsUserW");
    }
}
