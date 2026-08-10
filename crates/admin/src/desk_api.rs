//! Where the remote-desktop subsystem meets the control API.
//!
//! This module routes four things: what the deployment's desktop settings are,
//! which machines can be reached, what the capture agent on one of them is
//! doing, and — the one that matters — the handshake that turns a request into a
//! live desktop session.
//!
//! # What this module does and does not own
//!
//! It owns **authorisation and hand-off**. It does not own a pixel. The screen,
//! the pointer, and the session driver that turns a mux channel into a desktop
//! all live in `selfhost-screen` and `selfhost-desk`, driven by the daemon: the
//! admin API is the process that decides *who may*, and the daemon is the
//! process that owns the hardware. So the last act of a successful handshake is
//! [`Fleet::serve`] — the socket, the redeemed grant and the seat, handed to
//! whoever the daemon wired in, which returns when the session ends.
//!
//! This crate does link `selfhost-mesh`, but for the *other* half of the mesh:
//! [`crate::mesh_api`] answers `GET /api/mesh/link`, because a worker's
//! credential is a proof over the handshake and can only be checked by the
//! process that answered it. Nothing about a desktop session's pixels or
//! keystrokes comes through here, and this module still knows nothing about a
//! link.
//!
//! That seam is why `crates/admin` can be tested for every refusal without a
//! display, and why a machine with no capture backend at all still exercises the
//! whole authorisation path.
//!
//! # The four rules a desktop session is held to
//!
//! 1. **Viewing, driving and the clipboard are three separate capabilities.** A
//!    ticket carrying control is refused unless
//!    [`selfhost_identity::Capability::DesktopControl`] is held for that
//!    node, and one carrying the clipboard unless
//!    [`ClipboardRead`](selfhost_identity::Capability::ClipboardRead) is —
//!    decided by the same [`Policy`](selfhost_identity::Policy) every
//!    other route uses.
//! 2. **The decision is made three times, and the last one is per input
//!    message.** At the mint, per requested ability; at the handshake, by
//!    [`upgrade::still_permitted`](crate::upgrade::still_permitted), which
//!    *downgrades* rather than refuses; and on every single input message, by
//!    the session driver in the daemon reading [`Standings`]. A grant revoked
//!    mid-session therefore stops the next keystroke, not the next reconnect —
//!    which matters because a stream lives for hours and a mint takes
//!    milliseconds.
//! 3. **Control needs a fresh credential, not a live session.** A twelve-hour
//!    cookie in a browser left open on an unlocked laptop is not a keyboard, and
//!    is not a clipboard either. See [`fresh_enough`].
//! 4. **The console gate is not authentication.** The tunnel exits on loopback,
//!    so every process on this box — including the three co-hosted web apps —
//!    reaches these routes. Nothing here treats having arrived as meaning
//!    anything at all.

use selfhost_config::Desktop;
use selfhost_desk::grant::{Capabilities, Redemption, SessionId};
use selfhost_desk::tiles::TileSize;
use selfhost_desk::viewer::{Ceilings, Gate, Seat, SessionDirectory, Standing};
use selfhost_identity::{Caller, Credential, Identity, NodeName, Opening};
use selfhost_json::Json;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

/// The pseudo-peer naming this machine.
///
/// **The mesh's own constant**, not a copy of it. This was a mirrored literal
/// while `crates/admin` did not link `selfhost-mesh`; it does now, for
/// [`crate::mesh_api`], so the two spellings are collapsed into the one
/// definition — a name that means "this machine" in one crate and something else
/// in the other would route a desktop session to the wrong box, silently.
///
/// Controlling the box you are logged into and controlling another one are one
/// code path, one authorisation check and one set of tests, and this is the name
/// that makes them so.
pub const LOCAL_NODE: &str = selfhost_mesh::LOCAL_NAME;

/// A boxed future, in the shape `selfhost-desk` and `selfhost-acme` already use
/// for a trait a caller implements.
pub type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An upgraded connection, whatever it is underneath.
///
/// A trait object rather than a generic because [`Fleet`] is itself a trait
/// object held on the [`Api`](crate::Api): the daemon wires one implementation
/// and the route does not get to know which socket type it was built over.
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}

/// One machine this deployment can reach.
///
/// Absence is never the answer: a peer that is down is reported with the reason
/// it dropped and when it was last seen, because a picker that silently omits a
/// machine tells an operator their configuration is wrong when the truth is that
/// a laptop is asleep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReport {
    /// The node's declared name, which is also what a ticket names.
    pub node: String,
    /// Whether a link to it is up right now.
    pub live: bool,
    /// Seconds since it was last seen, when it has ever been seen.
    pub last_seen_secs: Option<u64>,
    /// Why the last link ended, for a node that is not live.
    pub reason: Option<String>,
}

impl NodeReport {
    /// This machine, always reachable, never dropped.
    pub fn local() -> Self {
        Self { node: LOCAL_NODE.to_owned(), live: true, last_seen_secs: Some(0), reason: None }
    }

    /// The wire shape the console draws.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("node", Json::string(&self.node)),
            ("live", Json::Bool(self.live)),
            (
                "lastSeenSecs",
                self.last_seen_secs.map_or(Json::Null, |secs| Json::Number(secs as f64)),
            ),
            ("reason", self.reason.as_deref().map_or(Json::Null, Json::string)),
        ])
    }
}

/// What the capture agent on one node is doing.
///
/// `sentence` is the agent's own one-line statement of where it landed — the
/// session, the window station, the desktop, the monitor count, the DPI mode and
/// the integrity level. It is a sentence rather than a structure because the
/// thing an operator needs to see is *"agent live in session 1 as ALEX ·
/// WinSta0\\Default · 2 monitors"*, and every field of that is a fact only the
/// agent can state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReport {
    /// The node this describes.
    pub node: String,
    /// Whether an agent is running and answering.
    pub live: bool,
    /// The agent's own statement, or why there is not one.
    pub sentence: String,
    /// How many displays it can see.
    pub monitors: u32,
    /// How many times it has been respawned since the daemon started, which is
    /// what a crash loop looks like from the outside.
    pub respawns: u32,
}

impl AgentReport {
    /// A node with no agent, saying so.
    ///
    /// The honest answer for a machine where nobody is logged in, where the
    /// platform has no capture backend, or where `[desktop].enabled` is false —
    /// and it is a report rather than an error for the reason the state machine
    /// names states rather than failures: "no user logged in" is not a fault.
    pub fn absent(node: &str, why: &str) -> Self {
        Self { node: node.to_owned(), live: false, sentence: why.to_owned(), monitors: 0, respawns: 0 }
    }

    /// The wire shape the console draws.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("node", Json::string(&self.node)),
            ("live", Json::Bool(self.live)),
            ("sentence", Json::string(&self.sentence)),
            ("monitors", Json::Number(f64::from(self.monitors))),
            ("respawns", Json::Number(f64::from(self.respawns))),
        ])
    }
}

/// Everything one admitted desktop session is handed.
///
/// Owns its [`Seat`] by value, so a session cannot exist without a place in the
/// concurrency ceiling and no exit path — including a transport error thrown out
/// of the middle of a close sequence — can forget to give one back.
///
/// # What the daemon must supply that this does not carry
///
/// The session driver also needs a
/// [`SessionDirectory`](selfhost_desk::viewer::SessionDirectory) — the thing it
/// asks, on **every input message**, whether this session may still type. The
/// real one is [`Api::standings`](crate::Api::standings), and a daemon that
/// drives a session with anything else has turned a per-message check into a
/// per-handshake one: what the ticket said, repeated. It is reached through an
/// accessor rather than carried here so that this struct stays the *socket and
/// the grant*, and so the daemon holds one directory for every session instead
/// of one per handover.
pub struct Handover {
    /// The upgraded connection, with whatever arrived past the request head
    /// already delivered first.
    pub io: Box<dyn Connection>,
    /// What the ticket authorised, in `selfhost-desk`'s own vocabulary: the
    /// session it was minted by, the node it names, and the capability bits.
    pub redemption: Redemption,
    /// The ceilings, mapped from `[desktop]`.
    pub ceilings: Ceilings,
    /// This session's place in the per-node ceiling.
    pub seat: Seat,
    /// Who is watching, for the audit line the daemon writes.
    pub identity: Identity,
}

impl fmt::Debug for Handover {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Handover")
            .field("peer", &self.redemption.peer)
            .field("capabilities", &self.redemption.capabilities.bits())
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// The machines this daemon can reach, and what it can do with them.
///
/// Implemented by the daemon, which owns `selfhost-screen` and the session
/// driver; held here as a trait object so that `crates/admin` can decide who may
/// watch a screen without linking anything that touches one. Three methods, and
/// the third is the whole subsystem:
///
/// - [`Fleet::nodes`] and [`Fleet::agent`] answer the console's panels and must
///   be cheap — they are polled.
/// - [`Fleet::serve`] takes an admitted session and returns when it ends. It is
///   handed the socket because everything past the `101` is the desktop
///   protocol, not HTTP, and there is no response to return.
pub trait Fleet: Send + Sync + 'static {
    /// Every machine this deployment can reach, this one included.
    fn nodes(&self) -> Vec<NodeReport>;

    /// What the capture agent on `node` is doing, or why there is not one.
    fn agent(&self, node: &str) -> AgentReport;

    /// Runs one admitted session to its end, and says how it ended.
    ///
    /// The returned sentence is written to the daemon's log. It must not name a
    /// path, a keystroke or a pixel — a desktop session's contents are the most
    /// sensitive bytes this box moves.
    fn serve<'a>(&'a self, session: Handover) -> Task<'a, String>;
}

/// The desktop subsystem as the API holds it.
///
/// Absent unless the daemon wired one, and absent is not a special case: with no
/// wiring the routes answer the same uninformative 401 an unauthenticated caller
/// gets, which is exactly what a deployment with `[desktop]` unset should look
/// like from outside.
#[derive(Clone)]
pub struct Wiring {
    /// The operator's settings, verbatim.
    config: Desktop,
    /// The per-node concurrency ceiling, shared across every clone of the API.
    gate: Gate,
    /// The daemon's own hardware.
    fleet: Arc<dyn Fleet>,
}

impl fmt::Debug for Wiring {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Wiring").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Wiring {
    /// Wires the subsystem over an operator's settings and a daemon's hardware.
    pub fn new(config: Desktop, fleet: Arc<dyn Fleet>) -> Self {
        let gate = Gate::new(config.max_viewers as usize);
        Self { config, gate, fleet }
    }

    /// The operator's settings.
    pub fn config(&self) -> &Desktop {
        &self.config
    }

    /// Whether the subsystem is switched on at all.
    ///
    /// `[desktop].enabled = false` is not a soft default: with it false there is
    /// no ticket, no handshake and no node list, and every desktop route is
    /// indistinguishable from one this deployment does not serve.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The ceilings one session runs under.
    pub fn ceilings(&self) -> Ceilings {
        ceilings_from(&self.config)
    }

    /// Takes a seat in the per-node ceiling, or refuses.
    pub fn admit(&self, node: &str) -> Option<Seat> {
        self.gate.admit(node).ok()
    }

    /// How many sessions are running against `node`.
    pub fn streams(&self, node: &str) -> usize {
        self.gate.streams(node)
    }

    /// The machines this deployment can reach.
    pub fn nodes(&self) -> Vec<NodeReport> {
        self.fleet.nodes()
    }

    /// What the agent on `node` is doing.
    pub fn agent(&self, node: &str) -> AgentReport {
        self.fleet.agent(node)
    }

    /// Runs an admitted session to its end.
    pub async fn serve(&self, session: Handover) -> String {
        self.fleet.serve(session).await
    }
}

/// Maps `[desktop]` onto the session driver's ceilings.
///
/// Pure, and the one place the two vocabularies meet. `max_viewers` is
/// deliberately absent: it is a property of the *gate*, not of a session, and a
/// stream that carried its own copy of a concurrency limit would be a stream
/// that could disagree with the thing enforcing it.
///
/// An illegal tile edge cannot reach here — `Desktop::check` refuses anything
/// outside `[16, 32, 64, 128]` at config load — but the fallback is written
/// rather than unwrapped, because under `panic = "abort"` an unwrap in the
/// daemon's start-up path is the whole box.
pub fn ceilings_from(config: &Desktop) -> Ceilings {
    Ceilings {
        max_fps: config.max_fps,
        max_session: config.max_session(),
        tile: TileSize::new(config.tile).unwrap_or(TileSize::DEFAULT),
        allow_input: config.allow_input,
        ..Ceilings::default()
    }
}

/// Whether this caller authenticated recently enough to be handed a keyboard.
///
/// # The rule
///
/// A control ticket is minted only when the caller's **session** was opened by a
/// password or a passkey within `[desktop].reauth_window`. Three consequences,
/// all deliberate:
///
/// - A twelve-hour cookie is not a keyboard. The console prompts for the
///   biometric at the moment CONNECT is clicked, and that login is what this
///   reads.
/// - A **bearer** credential has no login moment, so freshness cannot be asked
///   of it and is not. That is not a hole: an unattended credential is refused
///   [`Capability::DesktopControl`](selfhost_identity::Capability) outright by
///   [`Policy::decide`](selfhost_identity::Policy::decide) unless the operator
///   set `[desktop].bearer_may_control`, and once they have, they have said in
///   configuration that this credential may drive the machine unattended.
/// - A session opened by anything that is not a login — there is no such
///   opening today, and the match is exhaustive so there cannot quietly be one —
///   is refused.
///
/// Pure, so every boundary of it is a unit test rather than a wait.
pub fn fresh_enough(caller: &Caller, window: Duration, now: Instant) -> bool {
    match caller.credential() {
        Credential::Session(session) => match session.opened_by {
            Opening::Password | Opening::Passkey => session.age(now) <= window,
        },
        // Presented on this very request: nothing is fresher than that.
        Credential::Password | Credential::Passkey => true,
        // No login moment to be recent. Armed in config or refused by policy.
        Credential::Bearer => true,
    }
}

/// The capability bits a redeemed set of abilities amounts to.
///
/// [`Capabilities::CONTROL`] and [`Capabilities::CLIPBOARD`] are never granted
/// without [`Capabilities::VIEW`],
/// which the desk crate's own `from_bits` also refuses: a session that may type
/// but not see is a session typing blind into whatever window has focus, which
/// is worse than the refusal, and a session that may read a clipboard but not
/// see a screen is a stream whose only purpose is exfiltration.
pub fn capabilities_for(view: bool, control: bool, clipboard: bool) -> Capabilities {
    let mut bits = Capabilities::none();
    if view || control || clipboard {
        bits = bits.with(Capabilities::VIEW);
    }
    if control {
        bits = bits.with(Capabilities::CONTROL);
    }
    if clipboard {
        bits = bits.with(Capabilities::CLIPBOARD);
    }
    bits
}

/// What one caller may do on one machine, in the session driver's vocabulary.
///
/// Pure, and the single translation between [`Policy::decide`] and the bitset
/// that travels on the wire. Both the handshake and every re-read of a running
/// stream go through this one function, so there is no second opinion about
/// what a grant means: the three capabilities are asked separately, in the same
/// order, against the same node, every time.
pub fn decided_for(policy: &selfhost_identity::Policy, caller: &Caller, node: &NodeName) -> Capabilities {
    use selfhost_identity::Capability;
    let allowed = |capability: Capability| policy.decide(caller, &capability).is_allowed();
    capabilities_for(
        allowed(Capability::DesktopView(node.clone())),
        allowed(Capability::DesktopControl(node.clone())),
        allowed(Capability::ClipboardRead(node.clone())),
    )
}

/// The console's live session store, as a running desktop stream may read it.
///
/// # Why this type exists at all
///
/// [`selfhost_desk::viewer::Viewer`] re-derives what a stream may do on **every
/// input message**, by asking a [`SessionDirectory`] rather than by remembering
/// what the handshake decided. That machinery is only as good as the directory
/// behind it: a directory that answers *"still fine"* forever turns a
/// per-message check into a per-handshake one wearing a per-message coat. This
/// is the real one — the console's own session store, the people registry the
/// grants come from, and [`Policy::decide`](selfhost_identity::Policy::decide),
/// consulted afresh at every read.
///
/// What that buys, concretely: signing out of the console, letting the session
/// idle out, or having `DesktopControl` taken away in the people registry stops
/// the keyboard on the **next keystroke**, not at the next reconnect. Losing
/// `DesktopView` ends the stream outright, because there is nothing left to
/// show.
///
/// **This is worth exactly nothing until the daemon drives its sessions with
/// it.** At the time of writing `crates/cli/src/desk_task.rs` still builds its
/// own stand-in, which reports the standing the *ticket* established, so a
/// revocation is felt at the stream's ceiling rather than at once. The gap is
/// named here, in `docs/SECURITY.md` §3.7 SCR-01, and at the stand-in itself
/// rather than papered over, because a directory that quietly answered "still
/// fine, forever" without saying so would be the worst of the three.
///
/// # Three rules this type is written around
///
/// 1. **It reads; it never validates.** [`Sessions::authenticated`] does not
///    touch `last_seen`, so a stream cannot keep its own session alive by
///    existing. That is the whole reason the console's two-hour idle expiry
///    means anything to a desktop session: a browser left open on an unlocked
///    machine, streaming a screen and touching nothing else, stops being a way
///    in exactly on schedule.
/// 2. **Freshness is a mint-time rule and is deliberately not re-applied.**
///    [`fresh_enough`] refuses to *hand out* a keyboard to a stale login; it is
///    not re-asked here, because a stream that lost its keyboard two minutes
///    after CONNECT would be a re-authentication prompt every two minutes for
///    the whole session. The bound on how long control may last is
///    `[desktop].max_session` and the session's own absolute expiry, both
///    enforced by the driver's deadline.
/// 3. **The deployment's own switches are enforced here too.** A build where
///    `[desktop].allow_input` is false masks [`Capabilities::CONTROL`] and one
///    where `allow_clipboard` is false masks [`Capabilities::CLIPBOARD`], so the
///    config switch and the grant cannot disagree about what a stream holds.
#[derive(Clone)]
pub struct Standings {
    sessions: crate::session::Sessions,
    people: Option<selfhost_identity::People>,
    policy: selfhost_identity::Policy,
    switches: Switches,
}

/// The deployment-wide switches a standing is masked by.
///
/// A copy of two `[desktop]` booleans rather than a borrow of the whole
/// configuration, because these are the only two a running stream's authority
/// depends on and a type that carried the rest would invite a third rule to be
/// written somewhere other than [`Standings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switches {
    /// `[desktop].allow_input`.
    pub allow_input: bool,
    /// `[desktop].allow_clipboard`.
    pub allow_clipboard: bool,
}

impl Switches {
    /// The switches a `[desktop]` block amounts to.
    pub fn of(config: &Desktop) -> Self {
        Self { allow_input: config.allow_input, allow_clipboard: config.allow_clipboard }
    }

    /// `granted` with everything this deployment has switched off removed.
    ///
    /// Pure. Masking rather than refusing, because the driver states the
    /// surviving set in its `Hello` and names the switch in its refusal: a
    /// console that is told *"input is off in configuration"* can say so, where
    /// one handed a silent failure can only show keystrokes vanishing.
    pub fn mask(self, granted: Capabilities) -> Capabilities {
        let mut off = Capabilities::none();
        if !self.allow_input {
            off = off.with(Capabilities::CONTROL);
        }
        if !self.allow_clipboard {
            off = off.with(Capabilities::CLIPBOARD);
        }
        granted.without(off)
    }
}

impl fmt::Debug for Standings {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Standings").field("switches", &self.switches).finish_non_exhaustive()
    }
}

impl Standings {
    /// Builds the directory over the stores the API already holds.
    ///
    /// Every argument is a cheap-clone handle onto shared state, so this is the
    /// same store the login route writes and the same registry the people route
    /// edits — not a snapshot that could disagree with either.
    pub fn new(
        sessions: crate::session::Sessions,
        people: Option<selfhost_identity::People>,
        policy: selfhost_identity::Policy,
        switches: Switches,
    ) -> Self {
        Self { sessions, people, policy, switches }
    }

    /// The directory one admitted stream should be driven by.
    ///
    /// Node-bound, because the capabilities it reports are per-node and
    /// [`SessionDirectory::standing`] is handed only a session id — so the
    /// machine has to be fixed when the directory is built, at the one place
    /// that knows which machine the stream is for.
    ///
    /// A `peer` that is not a legal node name yields a directory that answers
    /// `None` to everything, which ends the stream at its first read. That
    /// cannot happen through this crate's own routes — the name was parsed
    /// before the ticket was minted — and if it ever does, the safe reading of a
    /// machine that cannot be named is a machine nobody may drive.
    pub fn for_redemption(&self, redemption: &Redemption) -> Arc<dyn SessionDirectory> {
        match NodeName::parse(&redemption.peer) {
            Ok(node) => Arc::new(OnOneMachine { standings: self.clone(), node }),
            Err(_) => Arc::new(NoStanding),
        }
    }

    /// What the holder of `session` may do on `node` right now, or `None` if
    /// there is no such session any more.
    ///
    /// The bearer token is the one credential with no session to look up: it is
    /// a file on the box, it does not log in, and it does not expire. A stream
    /// it opened carries the empty session id that [`redemption`] gives it, and
    /// is answered from the policy alone, bounded by `[desktop].max_session`
    /// through the driver's own deadline arithmetic rather than by an expiry
    /// this type could invent.
    fn standing_on(&self, node: &NodeName, session: &SessionId) -> Option<Standing> {
        if session.as_str().is_empty() {
            let caller = Caller::bearer();
            return Some(Standing {
                expires: far_future(),
                capabilities: self.switches.mask(decided_for(&self.policy, &caller, node)),
            });
        }
        let held = self.sessions.authenticated(session.as_str())?;
        let caller = held.caller(self.people.as_ref())?;
        Some(Standing {
            // The absolute expiry, which the store's own idle purge in
            // `authenticated` has already applied on top of. `checked_add`
            // because the lifetime is a constant and an overflow here would be a
            // daemon that aborts rather than a stream that ends.
            expires: held
                .opened_at
                .checked_add(self.sessions.absolute_lifetime())
                .unwrap_or_else(Instant::now),
            capabilities: self.switches.mask(decided_for(&self.policy, &caller, node)),
        })
    }
}

/// A [`Standings`] bound to the machine one stream is watching.
struct OnOneMachine {
    standings: Standings,
    node: NodeName,
}

impl SessionDirectory for OnOneMachine {
    fn standing(&self, session: &SessionId) -> Option<Standing> {
        self.standings.standing_on(&self.node, session)
    }
}

/// A directory with nothing in it, for a stream whose machine cannot be named.
struct NoStanding;

impl SessionDirectory for NoStanding {
    fn standing(&self, _session: &SessionId) -> Option<Standing> {
        None
    }
}

/// An instant far enough ahead to stand for "this credential does not expire".
///
/// Used only for the bearer token, and deliberately a bounded number rather than
/// something clever: the stream's real wall is
/// `min(this, started + [desktop].max_session)`, computed by
/// [`selfhost_desk::viewer::stream_deadline`], so what this value has to be is
/// *larger than any configured `max_session`* and nothing more. Saturating,
/// because a platform whose `Instant` cannot represent a century must yield a
/// short stream rather than an aborted daemon.
fn far_future() -> Instant {
    Instant::now().checked_add(Duration::from_secs(100 * 365 * 24 * 60 * 60)).unwrap_or_else(Instant::now)
}

/// Builds the grant a session driver runs on.
///
/// The session id is the browser's own cookie value, which is what the driver
/// re-reads on its timer to notice a revoked login — through
/// `Sessions::authenticated`, never `validate`, because `validate` refreshes the
/// idle timer and a stream re-validating on a timer would keep its own session
/// alive for ever.
pub fn redemption(session: Option<&str>, node: &NodeName, capabilities: Capabilities) -> Redemption {
    Redemption {
        session: SessionId::new(session.unwrap_or_default()),
        peer: node.as_str().to_owned(),
        capabilities,
    }
}

/// The body of `GET /api/desktop`.
///
/// The operator's own switches, so the console can say *"input is off in
/// configuration"* rather than offering a keyboard that will refuse every key.
/// Nothing here is a secret: every value is one the operator typed.
pub fn settings(wiring: &Wiring) -> Json {
    let config = wiring.config();
    Json::object([
        ("enabled", Json::Bool(config.enabled)),
        ("allowInput", Json::Bool(config.allow_input)),
        ("allowClipboard", Json::Bool(config.allow_clipboard)),
        ("bearerMayControl", Json::Bool(config.bearer_may_control)),
        ("maxViewers", Json::Number(f64::from(config.max_viewers))),
        ("maxFps", Json::Number(f64::from(config.max_fps))),
        ("tile", Json::Number(f64::from(config.tile))),
        ("reauthWindowSecs", Json::Number(config.reauth_window_secs as f64)),
        ("maxSessionSecs", Json::Number(config.max_session_secs as f64)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::{Grants, Session};

    /// A login instant offset forward so a test may subtract from it without
    /// underflowing a monotonic clock in a freshly-started process.
    fn login_moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    fn session_caller(opening: Opening, at: Instant) -> Caller {
        Caller::session(Identity::Owner, Session::new(opening, at), Grants::none())
    }

    #[test]
    fn a_stale_login_is_not_a_keyboard() {
        let now = login_moment();
        let window = Duration::from_secs(120);
        let fresh = session_caller(Opening::Passkey, now - Duration::from_secs(30));
        let stale = session_caller(Opening::Password, now - Duration::from_secs(300));
        assert!(fresh_enough(&fresh, window, now));
        assert!(!fresh_enough(&stale, window, now));
    }

    #[test]
    fn the_boundary_of_the_window_is_inclusive() {
        let now = login_moment();
        let window = Duration::from_secs(120);
        let exactly = session_caller(Opening::Password, now - window);
        assert!(fresh_enough(&exactly, window, now));
        let just_past = session_caller(Opening::Password, now - window - Duration::from_millis(1));
        assert!(!fresh_enough(&just_past, window, now));
    }

    #[test]
    fn a_bearer_credential_has_no_login_to_be_recent_and_is_left_to_the_policy() {
        let caller = Caller::bearer();
        assert!(fresh_enough(&caller, Duration::from_secs(1), login_moment()));
    }

    #[test]
    fn control_always_implies_view_and_view_never_implies_control() {
        assert_eq!(capabilities_for(false, false, false), Capabilities::none());
        assert_eq!(capabilities_for(true, false, false), Capabilities::VIEW);
        let both = capabilities_for(false, true, false);
        assert!(both.contains(Capabilities::VIEW));
        assert!(both.contains(Capabilities::CONTROL));
        assert!(!capabilities_for(true, false, false).contains(Capabilities::CONTROL));
    }

    #[test]
    fn the_clipboard_implies_view_and_is_never_implied_by_control() {
        let clipboard = capabilities_for(false, false, true);
        assert!(clipboard.contains(Capabilities::VIEW));
        assert!(clipboard.contains(Capabilities::CLIPBOARD));
        assert!(!clipboard.contains(Capabilities::CONTROL));
        assert!(!capabilities_for(true, true, false).contains(Capabilities::CLIPBOARD));
        // Everything this crate can produce is a set the wire accepts.
        for view in [false, true] {
            for control in [false, true] {
                for clipboard in [false, true] {
                    let bits = capabilities_for(view, control, clipboard).bits();
                    assert_eq!(
                        Capabilities::from_bits(bits).map(Capabilities::bits),
                        Some(bits),
                        "{view}/{control}/{clipboard}"
                    );
                }
            }
        }
    }

    /// A registry-free policy over a caller who is not the owner, so the
    /// standing tests exercise the grant path rather than the owner's blanket
    /// allow.
    fn person(grants: Grants) -> Caller {
        let name = selfhost_identity::PersonName::parse("Mary-Anne").expect("a valid name");
        Caller::session(
            Identity::Person(name),
            Session::new(Opening::Passkey, Instant::now()),
            grants,
        )
    }

    fn a_node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a valid node name")
    }

    #[test]
    fn a_grant_becomes_exactly_the_bits_it_names() {
        let policy = selfhost_identity::Policy::locked_down();
        let node = a_node();
        let watcher =
            person(Grants::new([selfhost_identity::Capability::DesktopView(node.clone())]).unwrap());
        assert_eq!(decided_for(&policy, &watcher, &node), Capabilities::VIEW);

        let driver = person(
            Grants::new([
                selfhost_identity::Capability::DesktopView(node.clone()),
                selfhost_identity::Capability::DesktopControl(node.clone()),
            ])
            .unwrap(),
        );
        let bits = decided_for(&policy, &driver, &node);
        assert!(bits.contains(Capabilities::CONTROL));
        assert!(!bits.contains(Capabilities::CLIPBOARD));
    }

    #[test]
    fn a_grant_on_one_machine_is_nothing_on_another() {
        let policy = selfhost_identity::Policy::locked_down();
        let elsewhere = NodeName::parse("study-mac").expect("a valid node name");
        let driver = person(
            Grants::new([
                selfhost_identity::Capability::DesktopView(a_node()),
                selfhost_identity::Capability::DesktopControl(a_node()),
            ])
            .unwrap(),
        );
        assert_eq!(decided_for(&policy, &driver, &elsewhere), Capabilities::none());
    }

    #[test]
    fn the_deployment_switches_remove_what_a_grant_would_have_given() {
        let everything =
            Capabilities::VIEW.with(Capabilities::CONTROL).with(Capabilities::CLIPBOARD);
        let off = Switches { allow_input: false, allow_clipboard: false };
        assert_eq!(off.mask(everything), Capabilities::VIEW);
        let input_only = Switches { allow_input: true, allow_clipboard: false };
        assert_eq!(input_only.mask(everything), Capabilities::VIEW.with(Capabilities::CONTROL));
        let both = Switches { allow_input: true, allow_clipboard: true };
        assert_eq!(both.mask(everything), everything);
        // Masking never invents a capability, and never takes VIEW away: a
        // stream with nothing left to show ends, and that decision belongs to
        // the driver rather than to a switch.
        assert_eq!(off.mask(Capabilities::VIEW), Capabilities::VIEW);
        assert_eq!(both.mask(Capabilities::none()), Capabilities::none());
    }

    #[test]
    fn a_stream_reads_the_store_it_was_opened_against_and_ends_when_the_session_goes() {
        let sessions = crate::session::Sessions::new();
        let id = sessions.create("owner", Opening::Password).expect("entropy");
        let standings = Standings::new(
            sessions.clone(),
            None,
            selfhost_identity::Policy::locked_down(),
            Switches { allow_input: true, allow_clipboard: false },
        );
        let node = a_node();
        let directory = standings.for_redemption(&redemption(
            Some(&id),
            &node,
            Capabilities::VIEW.with(Capabilities::CONTROL),
        ));

        let live = directory.standing(&SessionId::new(&id)).expect("the session is live");
        assert!(live.capabilities.contains(Capabilities::CONTROL));
        // The clipboard switch is off, so no grant can produce the bit.
        assert!(!live.capabilities.contains(Capabilities::CLIPBOARD));

        // Signing out is felt by the next read — which the driver performs on
        // every input message, not only on its timer.
        sessions.revoke(&id);
        assert_eq!(directory.standing(&SessionId::new(&id)), None);
    }

    #[test]
    fn one_browsers_session_id_is_not_another_browsers_standing() {
        let sessions = crate::session::Sessions::new();
        let mine = sessions.create("owner", Opening::Password).expect("entropy");
        let standings = Standings::new(
            sessions,
            None,
            selfhost_identity::Policy::locked_down(),
            Switches { allow_input: true, allow_clipboard: true },
        );
        let directory =
            standings.for_redemption(&redemption(Some(&mine), &a_node(), Capabilities::VIEW));
        assert!(directory.standing(&SessionId::new(&mine)).is_some());
        assert_eq!(directory.standing(&SessionId::new("not a session")), None);
    }

    #[test]
    fn the_bearer_token_has_no_session_to_look_up_and_is_decided_by_the_policy_alone() {
        let sessions = crate::session::Sessions::new();
        let switches = Switches { allow_input: true, allow_clipboard: true };
        let node = a_node();
        let locked = Standings::new(
            sessions.clone(),
            None,
            selfhost_identity::Policy::locked_down(),
            switches,
        );
        let empty = SessionId::new("");
        let watching = locked
            .for_redemption(&redemption(None, &node, Capabilities::VIEW))
            .standing(&empty)
            .expect("a bearer stream has a standing");
        // `[desktop].bearer_may_control` unset: the token may watch and may not
        // drive, exactly as `Policy::decide` says.
        assert_eq!(watching.capabilities, Capabilities::VIEW);

        let armed = Standings::new(sessions, None, selfhost_identity::Policy::new(true), switches);
        let driving = armed
            .for_redemption(&redemption(None, &node, Capabilities::VIEW))
            .standing(&empty)
            .expect("a bearer stream has a standing");
        assert!(driving.capabilities.contains(Capabilities::CONTROL));
    }

    #[test]
    fn a_machine_that_cannot_be_named_is_a_machine_nobody_may_drive() {
        let sessions = crate::session::Sessions::new();
        let id = sessions.create("owner", Opening::Password).expect("entropy");
        let standings = Standings::new(
            sessions,
            None,
            selfhost_identity::Policy::locked_down(),
            Switches { allow_input: true, allow_clipboard: true },
        );
        let redemption = Redemption {
            session: SessionId::new(&id),
            peer: "Not A Node".to_owned(),
            capabilities: Capabilities::VIEW,
        };
        assert_eq!(standings.for_redemption(&redemption).standing(&SessionId::new(&id)), None);
    }

    #[test]
    fn a_streams_expiry_is_the_stores_own_and_not_a_second_copy_of_it() {
        let sessions = crate::session::Sessions::new();
        let id = sessions.create("owner", Opening::Password).expect("entropy");
        let standings = Standings::new(
            sessions.clone(),
            None,
            selfhost_identity::Policy::locked_down(),
            Switches { allow_input: false, allow_clipboard: false },
        );
        let directory =
            standings.for_redemption(&redemption(Some(&id), &a_node(), Capabilities::VIEW));
        let standing = directory.standing(&SessionId::new(&id)).expect("the session is live");
        let remaining = standing.expires.saturating_duration_since(Instant::now());
        assert!(remaining <= sessions.absolute_lifetime());
        assert!(remaining + Duration::from_secs(5) >= sessions.absolute_lifetime());
    }

    #[test]
    fn an_idle_session_stops_a_stream_because_the_stream_never_refreshed_it() {
        // The store's own idle rule, which `Sessions::authenticated` applies and
        // this directory therefore inherits: a stream that reads the store
        // cannot keep itself alive by reading it.
        let sessions =
            crate::session::Sessions::with_expiry(Duration::from_secs(3600), Duration::ZERO);
        let id = sessions.create("owner", Opening::Password).expect("entropy");
        let standings = Standings::new(
            sessions,
            None,
            selfhost_identity::Policy::locked_down(),
            Switches { allow_input: true, allow_clipboard: true },
        );
        let directory =
            standings.for_redemption(&redemption(Some(&id), &a_node(), Capabilities::VIEW));
        assert_eq!(directory.standing(&SessionId::new(&id)), None);
    }

    #[test]
    fn the_ceilings_are_the_operators_settings_and_never_the_viewer_count() {
        let config = Desktop {
            max_fps: 12,
            tile: 128,
            allow_input: true,
            max_viewers: 7,
            ..Desktop::default()
        };
        let ceilings = ceilings_from(&config);
        assert_eq!(ceilings.max_fps, 12);
        assert_eq!(ceilings.tile.edge(), 128);
        assert!(ceilings.allow_input);
        // `max_viewers` belongs to the gate; a session carrying its own copy
        // could disagree with the thing enforcing it.
        assert_eq!(ceilings.max_session, config.max_session());
    }

    #[test]
    fn an_absent_agent_reports_a_state_rather_than_an_error() {
        let report = AgentReport::absent("self", "no user is logged in");
        assert!(!report.live);
        assert_eq!(report.to_json().get("sentence").and_then(Json::as_str), Some("no user is logged in"));
    }
}
