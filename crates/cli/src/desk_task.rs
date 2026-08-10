//! The remote-desktop subsystem, as the daemon holds it.
//!
//! # Absent config means the subsystem does not exist
//!
//! [`start`] answers `None` unless `[desktop]` is present **and**
//! `enabled = true`. On `None` the daemon wires no [`Fleet`] into the admin API,
//! so every desktop route answers with the same uninformative 401 an
//! unauthenticated caller gets; no task is started, nothing polls, nothing is
//! spawned, and `selfhost doctor` says the subsystem is switched off rather than
//! reporting a healthy nothing. That is the default posture and it is the one a
//! box gets by writing no config at all.
//!
//! # What this module owns, and what it deliberately does not
//!
//! It owns three things:
//!
//! 1. **The kill switch.** [`crate::kill_switch`] is polled on a timer and the
//!    answer is published in one flag. A running stream reads it on every frame
//!    and ends; a new one is refused before the socket is even framed.
//! 2. **The daemon's answer to "what machines can I reach, and what is on
//!    them"** — [`Fleet::nodes`] and [`Fleet::agent`], which the console polls.
//! 3. **Driving one admitted session** — [`Fleet::serve`], which wraps the
//!    upgraded socket in the WebSocket codec and hands it to
//!    [`selfhost_desk::viewer::Viewer`], the session driver that owns the
//!    protocol, the deadlines, the re-validation and the release-everything
//!    close.
//!
//! It does **not** own pixels. Where the frames come from is
//! [`selfhost_screen`]'s problem, reached through the [`FrameSource`] seam and
//! joined to it by [`crate::desk_local`], which puts the platform's blocking
//! calls on threads of their own. Whether that join actually reaches a screen on
//! *this* machine is asked at run time — see [`Backend`] — and when it does not,
//! a console that connects is told so in the protocol's own vocabulary: it is
//! not shown a black rectangle and it is not left waiting on a socket that will
//! never speak.
//!
//! # Why there is still no agent process
//!
//! On Windows a daemon installed as a service runs as `SYSTEM` in session 0 and
//! cannot capture the console user's screen by any method, so the pixels would
//! have to come from an agent process spawned into that session and reached over
//! `\\.\pipe\selfhost-desk-<session>`. Both halves exist in `selfhost-screen`
//! and both are exercised by its own tests. What is missing is one thing the
//! daemon needs and this crate cannot obtain: **the console user's SID**, which
//! is what the pipe's DACL is built around. `selfhost_screen::windows::desktop`
//! keeps it `pub(crate)`, and `crates/cli` forbids `unsafe`, so there is no
//! second way to ask.
//!
//! Spawning an agent without that pipe would not be a partial feature — it would
//! be an agent that starts, fails to connect within its ten-second deadline,
//! exits, and is respawned until the hour's budget is spent. So it is not done,
//! and [`Backend::here`] states the gap in one sentence that both the console
//! and `doctor` print. A Windows daemon started from a signed-in session is in
//! that session already and captures directly, which is the path this build
//! wires; the fix for the service case is one exported function in
//! `selfhost-screen`.

use selfhost_admin::desk_api::LOCAL_NODE;
use selfhost_admin::{AgentReport, Fleet, Handover, NodeReport};
use selfhost_config::{Config, Desktop};
use selfhost_desk::grant::{Capabilities, SessionId};
use selfhost_desk::viewer::{
    CLOSE_GRACE, CapturedFrame, Condition, Ending, FrameSource, Inbound, InputSink, NoInput,
    NoPointer, Outbound, PointerSource, Restore, SessionDirectory, Standing, StreamError, Task,
    Viewer, Wiring,
};
use selfhost_desk::wire::{Message, Monitor, Refusal};
use selfhost_ws::{CloseCode, Duplex, Event, Limits};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub use crate::desk_local::Backend;

/// How deep the queue of messages waiting for the socket is allowed to get.
///
/// Two, and small on purpose. A desktop stream must show the present, not a
/// backlog: past a couple of messages in flight the right answer is for the
/// session driver to stop producing and merge the damage into the next frame it
/// can afford, which is exactly what it does when [`Outbound::credit`] reads
/// zero.
const OUTBOUND_DEPTH: usize = 2;

/// How deep the queue of messages arriving from the console is allowed to get.
///
/// Deeper than the outbound side because what arrives here is input — key and
/// pointer events, which are small, ordered and must not be dropped: a lost key
/// release is a modifier stuck down on somebody's machine.
const INBOUND_DEPTH: usize = 64;

/// The send window reported to the session driver while a frame can still be
/// queued.
///
/// # There is no credit protocol on this hop, and that is stated rather than
/// hidden
///
/// The mux's `CREDIT` frame runs between the owner daemon and a worker's agent.
/// A browser on the far end of the console relay speaks plain WebSocket and
/// grants nothing, so the only backpressure available on this hop is the
/// socket's own. This constant is therefore not a measurement — it is "a frame
/// still fits", and the real signal is [`OUTBOUND_DEPTH`]: when the queue is
/// full the credit reported is zero, the driver declines to produce the frame,
/// and the damage merges forward.
const FRAME_WINDOW: u32 = 256 * 1024;

/// The remote-desktop subsystem, held by the daemon and shared with the API.
///
/// Cheap to clone through the [`Arc`] the daemon keeps it in; every mutable part
/// is either atomic or behind the lock that owns it, because the admin API calls
/// [`Fleet`] from whatever runtime worker is serving a request.
#[derive(Debug)]
pub struct Desk {
    /// The operator's settings, verbatim.
    config: Desktop,
    /// Where the kill switch lives.
    data_dir: PathBuf,
    /// Every node this deployment declares, this machine included, in the order
    /// the config declares them.
    nodes: Vec<String>,
    /// Whether the operator's kill switch is engaged right now.
    stopped: Arc<AtomicBool>,
    /// The peer mesh, when this machine has one.
    ///
    /// Read-only here: the dialler owns the link and writes the registry, and
    /// this end only reports what it says. That is what keeps the node picker's
    /// answer and the daemon's own link state from being two separate beliefs.
    peers: Option<Arc<crate::mesh_task::Peers>>,
    /// Where every control action this subsystem takes is written down.
    audit: crate::audit::Auditor,
}

/// Builds the subsystem, or answers `None` because it was not asked for.
///
/// `None` is the ordinary answer and the safe one: no `[desktop]` block, or one
/// with `enabled = false`, means this deployment has no remote desktop at all
/// and the daemon must not start anything on its behalf.
pub fn start(
    config: &Config,
    data_dir: &Path,
    peers: Option<Arc<crate::mesh_task::Peers>>,
) -> Option<Desk> {
    let desktop = config.desktop.filter(|desktop| desktop.enabled)?;
    let mut nodes: Vec<String> = vec![LOCAL_NODE.to_owned()];
    for node in &config.nodes {
        if node.name != LOCAL_NODE {
            nodes.push(node.name.clone());
        }
    }
    Some(Desk {
        config: desktop,
        data_dir: data_dir.to_path_buf(),
        nodes,
        stopped: Arc::new(AtomicBool::new(crate::kill_switch::present(data_dir))),
        peers,
        audit: crate::audit::Auditor::in_dir(data_dir),
    })
}

impl Desk {
    /// The operator's settings.
    pub fn config(&self) -> &Desktop {
        &self.config
    }

    /// Whether the kill switch is engaged right now.
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// What the daemon prints at startup, so an operator reading the banner
    /// learns the posture without opening a console.
    ///
    /// Says the dangerous things out loud — whether input is allowed, and
    /// whether the kill switch is currently holding the subsystem down —
    /// because those are the two facts somebody scrolling a log is looking for.
    pub fn summary(&self) -> String {
        let mut sentence = format!(
            "desktop: enabled · {viewers} viewer(s) · {fps} fps · {tile}px tiles · input {input}",
            viewers = self.config.max_viewers,
            fps = self.config.max_fps,
            tile = self.config.tile,
            input = if self.config.allow_input { "allowed" } else { "refused" },
        );
        let backend = Backend::here();
        sentence.push_str(&format!("\n  capture      {}", backend.name));
        if !backend.wired {
            // The reason, not merely the fact: an operator reading a banner that
            // says "not wired" and nothing else has to go and find out why, and
            // the answer is usually one they can act on in a minute.
            sentence.push_str(&format!("\n               unavailable — {}", backend.why));
        }
        sentence.push_str(&format!(
            "\n  kill switch  {} ({})",
            if self.stopped() { "ENGAGED — no stream will run" } else { "clear" },
            crate::kill_switch::path_in(&self.data_dir).display(),
        ));
        sentence
    }

    /// Watches the kill switch for as long as the daemon runs.
    ///
    /// One arm of the daemon's `select!`, and it never returns. Each tick reads
    /// one path and publishes the answer; a change is logged both ways, because
    /// an operator who engaged the switch needs to see the daemon agree, and one
    /// who removed it needs to see that too.
    ///
    /// # This is the *only* writer of a kill-switch audit line
    ///
    /// Deliberately, and it is why `selfhost desktop disable` writes none. The
    /// switch is a file, and the whole point of it being a file is that it can
    /// appear without this deployment's software being involved at all — a
    /// Finder window, an SMB mount, a recovery shell, another admin's `touch`.
    /// A command that logged its own act would record the one case that was
    /// already visible and miss every case the mechanism exists for, and when
    /// both wrote, one engagement produced two lines and the log stopped being
    /// countable. So the process that *observes* the change is the one that
    /// records it, whatever caused it.
    ///
    /// The first observation is recorded when — and only when — the switch is
    /// already engaged. A daemon that spends its whole life with the desktop
    /// revoked is a fact an auditor needs and a transition nobody was running to
    /// see; a daemon that starts with the switch clear has nothing to report.
    pub async fn watch(&self) {
        let mut ticker = tokio::time::interval(crate::kill_switch::POLL_INTERVAL);
        // `None` until the first tick: the first reading is a change only if it
        // is the dangerous one. See the note above.
        let mut recorded: Option<bool> = None;
        loop {
            ticker.tick().await;
            let engaged = crate::kill_switch::present(&self.data_dir);
            let changed = self.stopped.swap(engaged, Ordering::Relaxed) != engaged;
            let first_and_engaged = recorded.is_none() && engaged;
            if !changed && !first_and_engaged {
                recorded = Some(engaged);
                continue;
            }
            recorded = Some(engaged);
            self.audit.kill_switch(engaged, "observed by the daemon");
            let path = crate::kill_switch::path_in(&self.data_dir);
            // The banner already stated the startup posture, so the log only
            // narrates an actual change; the audit line above is written either
            // way, because the two have different readers.
            if !changed {
                continue;
            }
            if engaged {
                eprintln!(
                    "desktop: kill switch engaged ({}) — every stream is closing and no new one \
                     will be admitted",
                    path.display()
                );
            } else {
                eprintln!("desktop: kill switch released ({}) — streaming is possible again", path.display());
            }
        }
    }

    /// What this daemon can say about a node that is not this machine.
    ///
    /// Three answers, and which one applies is a fact about this deployment
    /// rather than about the node: a worker knows only about its own link to its
    /// owner, and an owner with no `[mesh]` section knows about no links at all.
    /// Saying which of the three is why an operator whose picker is greyed out
    /// can tell "the laptop is asleep" from "this box was never going to reach
    /// it".
    fn peer_report(&self, name: &str) -> NodeReport {
        let Some(peers) = self.peers.as_ref() else {
            return NodeReport {
                node: name.to_owned(),
                live: false,
                last_seen_secs: None,
                reason: Some(
                    "this daemon has no [mesh] section, so it neither dials a peer nor accepts a \
                     link from one"
                        .to_owned(),
                ),
            };
        };
        let Some(record) = peers.record().filter(|record| record.name.as_str() == name) else {
            return NodeReport {
                node: name.to_owned(),
                live: false,
                last_seen_secs: None,
                reason: Some(format!(
                    "this machine is the worker {}, which dials its owner and accepts links from \
                     nobody — reaching {name} is the owner's to do",
                    peers.node()
                )),
            };
        };
        NodeReport {
            node: name.to_owned(),
            live: record.is_linked(),
            last_seen_secs: record.last_seen.map(|seen| {
                std::time::SystemTime::now()
                    .duration_since(seen)
                    .map(|gap| gap.as_secs())
                    .unwrap_or(0)
            }),
            reason: (!record.is_linked()).then(|| record.describe()),
        }
    }

    /// Drives one admitted session to its end and says how it ended.
    async fn run_session(&self, handover: Handover) -> String {
        if self.stopped() {
            // Belt and braces: the route already asked, but the switch can be
            // engaged between the handshake and here, and a stream that starts
            // after the operator said stop is the one case this whole mechanism
            // exists to prevent.
            return format!(
                "refused: the kill switch at {} is in place",
                crate::kill_switch::path_in(&self.data_dir).display()
            );
        }

        let Handover { io, redemption, ceilings, seat, identity } = handover;
        let limits = Limits { max_lifetime: ceilings.max_session, ..Limits::default() };
        let (mut outbound, mut inbound, pump) = split(Duplex::server(io, limits));
        let mut pump = tokio::spawn(pump);

        // Written before a single pixel leaves the machine, not after. A session
        // that is admitted and then hangs, or whose daemon is killed while it
        // runs, must still have left a line saying who was let in and what they
        // were allowed to do — an audit trail that is only written on the way out
        // is missing precisely the entries an incident is about.
        self.audit.admitted(&identity, &redemption);

        let Machine { mut screen, cursor, keys } =
            Machine::open(Arc::clone(&self.stopped), self.config.allow_input).await;
        // A machine whose pointer and keyboard could not be opened still
        // streams: watching is authorised separately from driving, and refusing
        // the whole session because Accessibility was not granted would take the
        // screen away to punish the keyboard.
        let mut cursor = cursor;
        let mut keys = keys.map(|keys| Audited {
            keys,
            audit: self.audit.clone(),
            identity: identity.clone(),
            node: redemption.peer.clone(),
            stopped: Arc::clone(&self.stopped),
        });
        let mut no_pointer = NoPointer;
        let mut no_input = NoInput;
        let directory = TicketStanding::new(&redemption.session, ceilings.max_session);

        let outcome = {
            let pointer: &mut dyn PointerSource = match cursor.as_mut() {
                Some(cursor) => cursor,
                None => &mut no_pointer,
            };
            let input: &mut dyn InputSink = match keys.as_mut() {
                Some(keys) => keys,
                None => &mut no_input,
            };
            let viewer = Viewer::new(
                Wiring { outbound: &mut outbound, frames: &mut screen, pointer, input },
                &directory,
                seat,
                &redemption,
                ceilings,
            );
            viewer.run(&mut inbound).await
        };

        // The driver's last act is to queue a close, so the pump is given the
        // same grace the driver gives the peer to write it and hear the answer
        // — and no more. A pump that is still waiting after that is waiting on
        // a socket nobody is reading, and it must not outlive the session that
        // owns it.
        if tokio::time::timeout(CLOSE_GRACE, &mut pump).await.is_err() {
            pump.abort();
        }

        format!(
            "{ending} · {who} · {frames} frame(s), {bytes} byte(s), {stalls} credit stall(s), \
             {refused} input(s) refused",
            ending = outcome.ending,
            who = identity,
            frames = outcome.stats.frames_sent,
            bytes = outcome.stats.bytes_sent,
            stalls = outcome.stats.credit_stalls,
            refused = outcome.stats.inputs_refused,
        )
    }
}

impl Fleet for Desk {
    fn nodes(&self) -> Vec<NodeReport> {
        self.nodes
            .iter()
            .map(|name| {
                if name == LOCAL_NODE {
                    return NodeReport::local();
                }
                // Absence is never the answer: a declared node with no link is
                // reported with the reason rather than left out of the picker,
                // which would make an operator go looking at their config.
                self.peer_report(name)
            })
            .collect()
    }

    fn agent(&self, node: &str) -> AgentReport {
        if self.stopped() {
            return AgentReport::absent(
                node,
                &format!(
                    "stopped by the operator's kill switch at {}",
                    crate::kill_switch::path_in(&self.data_dir).display()
                ),
            );
        }
        if node != LOCAL_NODE {
            return AgentReport::absent(
                node,
                "this daemon has no link to that node, so it cannot say what is running on it",
            );
        }
        let backend = Backend::here();
        if backend.wired {
            return AgentReport {
                node: node.to_owned(),
                live: true,
                sentence: backend.why,
                monitors: backend.displays,
                respawns: 0,
            };
        }
        AgentReport::absent(node, &backend.why)
    }

    fn serve<'a>(&'a self, session: Handover) -> Task<'a, String> {
        Box::pin(self.run_session(session))
    }
}

/// Everything one session drives on this machine: the screen, the pointer and
/// the hands.
///
/// Opened together because they fail together in the ways that matter — a
/// machine nobody is logged into has none of the three — and because the
/// pointer's coordinate mapping has to be built against the same display layout
/// the pixels come from.
struct Machine {
    screen: LocalScreen,
    cursor: Option<crate::desk_local::Pointer>,
    keys: Option<crate::desk_local::Keys>,
}

impl Machine {
    /// Opens what this machine will let the session have.
    ///
    /// Never fails as a whole. A screen that cannot be opened becomes a
    /// [`LocalScreen`] that reports the condition it failed with, so the console
    /// is told *"macOS does not grant this binary Screen Recording…"* rather
    /// than watching a viewport that never fills; and hands that cannot be
    /// opened are simply absent, which the caller wires as
    /// [`NoInput`] so a viewer learns its keystrokes are going nowhere.
    ///
    /// `allow_input` is the deployment-wide switch. When it is off the injector
    /// is **never built**: not built and then refused, but never brought into
    /// existence, so a deployment that has not asked for input has no object in
    /// it that could inject any. The driver still refuses each message with
    /// `input-disabled`, which is the sentence the console shows.
    ///
    /// # One capture per session, and what that costs
    ///
    /// Each session opens its own platform capture, so `[desktop].max_viewers`
    /// — two by default — means two simultaneous captures of the same display.
    /// Windows GDI is happy to do that. macOS is entitled to refuse a second
    /// `CGDisplayStream` on a display, and observed to: two of this crate's own
    /// tests opening a stream at once produced a platform fault on the second.
    /// The second viewer is then told a named condition rather than shown
    /// nothing, so the failure is honest, but it is a failure — a machine that
    /// two people watch at once wants **one** capture broadcast to both, and
    /// that is a follow-up in `selfhost-desk` rather than a change here, because
    /// the sharing has to happen above the platform seam and below the session.
    /// An operator who needs it today sets `max_viewers = 1`.
    async fn open(stopped: Arc<AtomicBool>, allow_input: bool) -> Self {
        // Asked before the platform is touched: an operator who engaged the kill
        // switch gets a session that opens no capture at all, rather than one
        // that opens a screen and then declines to send it.
        if stopped.load(Ordering::Relaxed) {
            return Self {
                screen: LocalScreen { screen: Err(Condition::Stopped), stopped },
                cursor: None,
                keys: None,
            };
        }
        let screen = crate::desk_local::Screen::start().await;
        let monitors = screen.as_ref().map(|screen| {
            selfhost_desk::viewer::FrameSource::monitors(screen).to_vec()
        });
        let hands = match (allow_input, monitors) {
            (true, Ok(monitors)) => match crate::desk_local::open_hands(monitors).await {
                Ok((cursor, keys)) => (Some(cursor), Some(keys)),
                Err(error) => {
                    // Reported once, here, where the reason is still specific.
                    // The remote viewer is told only `input-refused`; the
                    // remediation is for the person at this machine.
                    eprintln!("desktop: no input on this machine — {}", error.sentence());
                    (None, None)
                }
            },
            _ => (None, None),
        };
        Self { screen: LocalScreen { screen, stopped }, cursor: hands.0, keys: hands.1 }
    }
}

/// The screen of the machine this daemon runs on, as the session driver sees it.
///
/// Holds the kill-switch flag rather than asking the filesystem, so the check
/// costs an atomic load per frame and an engaged switch is observed by every
/// running stream within one poll of [`Desk::watch`] — comfortably inside the
/// one ping interval the plan requires.
struct LocalScreen {
    /// The live capture, or the condition that stopped one being opened.
    ///
    /// A `Result` rather than an `Option` because *why* there is no screen is
    /// the whole of what a viewer needs to be told, and an `Option` would throw
    /// it away at exactly the moment it became interesting.
    screen: Result<crate::desk_local::Screen, Condition>,
    stopped: Arc<AtomicBool>,
}

impl LocalScreen {
    /// The kill switch's answer, when it has one.
    ///
    /// Asked **first** on every path, deliberately: an operator who engaged it
    /// wants every stream to stop for that reason and to be told that reason,
    /// not to be told about a capture backend that also happens to be missing.
    fn halted(&self) -> Option<Condition> {
        self.stopped.load(Ordering::Relaxed).then_some(Condition::Stopped)
    }
}

impl FrameSource for LocalScreen {
    fn monitors(&self) -> &[Monitor] {
        match self.screen.as_ref() {
            Ok(screen) => screen.monitors(),
            // `Hello` clips an empty list rather than refusing it, so a console
            // connecting to a machine with no capture sees a session with no
            // displays and the state sentence explaining why.
            Err(_) => &[],
        }
    }

    fn next_frame(&mut self, budget: Duration) -> Task<'_, Result<CapturedFrame, Condition>> {
        if let Some(halted) = self.halted() {
            return Box::pin(async move { Err(halted) });
        }
        match self.screen.as_mut() {
            Ok(screen) => screen.next_frame(budget),
            Err(condition) => {
                let condition = *condition;
                Box::pin(async move { Err(condition) })
            }
        }
    }

    fn restore(&mut self, what: Restore) -> Task<'_, Result<(), Condition>> {
        if let Some(halted) = self.halted() {
            return Box::pin(async move { Err(halted) });
        }
        Box::pin(async move {
            match self.screen.as_mut() {
                Ok(screen) => screen.restore(what).await,
                // The screen was never opened, so a restore is a fresh attempt
                // at opening it: a Mac whose grant was given while the session
                // was running comes back here rather than at the next login.
                Err(condition) => {
                    let condition = *condition;
                    match crate::desk_local::Screen::start().await {
                        Ok(screen) => {
                            self.screen = Ok(screen);
                            Ok(())
                        }
                        Err(fresh) => {
                            let _ = condition;
                            Err(fresh)
                        }
                    }
                }
            }
        })
    }
}

/// An input sink that writes down what it performed.
///
/// A wrapper rather than a branch inside [`crate::desk_local::Keys`], because
/// auditing is the daemon's concern and injecting is the platform's: the
/// platform half is used by the Windows agent too, in a process that has no data
/// directory to write a log into. Composing the two here keeps each one able to
/// exist without the other.
struct Audited {
    keys: crate::desk_local::Keys,
    audit: crate::audit::Auditor,
    /// Who is driving, for the line.
    identity: selfhost_identity::Identity,
    /// Which machine is being driven.
    node: String,
    /// The operator's kill switch, as [`Desk::watch`] last read it.
    ///
    /// # Why the switch is enforced here as well as on the screen
    ///
    /// [`LocalScreen`] asks it before every frame, and the session driver ends
    /// a stream the moment a capture answers [`Condition::Stopped`]. That is
    /// the path that closes the session — and it is a path the *peer* schedules,
    /// because it runs between frames. Between two frames the driver is willing
    /// to inject, and a peer with a message always ready is a peer that decides
    /// how long "between two frames" lasts.
    ///
    /// The driver no longer lets it decide that. This is the second wall
    /// anyway, and it is the one that does not depend on scheduling at all: an
    /// engaged switch refuses the very next keystroke, whatever the capture arm
    /// is doing and however long the state machine asked to wait before looking
    /// again.
    stopped: Arc<AtomicBool>,
}

/// Whether an engaged kill switch must refuse this message.
///
/// Pure, so the one rule that matters here — **a release is never refused** —
/// is asserted rather than believed. Refusing a release would be the worst
/// possible reading of the operator's intent: they revoked the desktop, and the
/// answer would be a modifier left held down on the machine they were revoking
/// it from, turning every keystroke by the person sitting at it into a
/// shortcut. What the switch stops is new input; what it must never stop is
/// putting down what is already held.
fn refuse_while_stopped(stopped: bool, message: &Message) -> Option<Refusal> {
    if !stopped {
        return None;
    }
    match message {
        Message::ReleaseAll
        | Message::Key { down: false, .. }
        | Message::Button { down: false, .. } => None,
        _ => Some(Refusal::NotLive),
    }
}

impl InputSink for Audited {
    /// Performs one message and writes exactly one line about it.
    ///
    /// The line is written **after** the platform has answered, so it can carry
    /// what the machine did rather than only what was asked — an elevated window
    /// swallowing a keystroke is the single most confusing thing this feature
    /// does, and the log is where it stops being confusing. One line either way:
    /// see [`crate::audit`] for the enumeration that makes that checkable.
    ///
    /// A message refused by the kill switch is written down like any other,
    /// with the refusal named, because "the operator revoked this machine and
    /// somebody kept typing at it" is precisely the entry an incident is about.
    fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>> {
        Box::pin(async move {
            let halted = self.stopped.load(Ordering::Relaxed);
            if let Some(refusal) = refuse_while_stopped(halted, message) {
                self.audit.performed(&self.identity, &self.node, message, Some(refusal));
                return Err(refusal);
            }
            let outcome = self.keys.deliver(message).await;
            self.audit.performed(&self.identity, &self.node, message, outcome.err());
            outcome
        })
    }
}

/// What the daemon can say about a console session while it is streaming.
///
/// # This is a stand-in, and the gap it leaves is named rather than hidden
///
/// [`SessionDirectory`] exists so a running stream re-reads the console session
/// every sixty seconds and downgrades or ends when the session is revoked, logs
/// out, or loses a capability. The real answer lives in `crates/admin`'s session
/// store, and [`Handover`] does not carry a handle to it — so the daemon cannot
/// consult it, and this reports the standing the **ticket** established instead.
///
/// Concretely, what still holds and what does not:
///
/// - The stream is still bounded. Its deadline is `min(this expiry,
///   [desktop].max_session)`, both computed at the handshake, and every await in
///   the driver is bounded by it. A session cannot outlive its ceiling.
/// - The capabilities are still the ticket's, which were decided by
///   `Policy::decide` at the mint and re-checked per input message against this
///   same standing.
/// - What is **lost** is mid-stream revocation: signing out of the console, or
///   having a capability taken away, does not end a stream that is already
///   running. It ends at its ceiling instead.
///
/// The fix is one field on [`Handover`] — an `Arc<dyn SessionDirectory>` the
/// admin API already has the store for — and it is recorded as a follow-up
/// rather than papered over here, because a directory that quietly answered
/// "still fine, forever" without saying so would be the worst of the three.
struct TicketStanding {
    session: SessionId,
    standing: Standing,
}

impl TicketStanding {
    fn new(session: &SessionId, max_session: Duration) -> Self {
        Self {
            session: session.clone(),
            standing: Standing {
                // `checked_add` because a silly `max_session` must not abort a
                // daemon that runs unattended; the fallback is the shortest
                // possible life rather than the longest.
                expires: Instant::now().checked_add(max_session).unwrap_or_else(Instant::now),
                capabilities: Capabilities::VIEW
                    .with(Capabilities::CONTROL)
                    .with(Capabilities::CLIPBOARD),
            },
        }
    }
}

impl SessionDirectory for TicketStanding {
    fn standing(&self, session: &SessionId) -> Option<Standing> {
        (session == &self.session).then_some(self.standing)
    }
}

/// The writing half of a plain WebSocket, as the session driver wants it.
struct SocketOut {
    outgoing: mpsc::Sender<Outward>,
}

/// One thing to put on the socket.
enum Outward {
    /// An encoded protocol message.
    Message(Vec<u8>),
    /// The stream is over, for this reason.
    Close(String),
}

impl Outbound for SocketOut {
    fn send<'a>(&'a mut self, frame: &'a [u8]) -> Task<'a, Result<(), StreamError>> {
        let payload = frame.to_vec();
        Box::pin(async move {
            self.outgoing.send(Outward::Message(payload)).await.map_err(|_| StreamError::Closed)
        })
    }

    fn credit(&self) -> u32 {
        // Zero when the queue is full, which is how the driver learns to drop
        // this frame and merge its damage into the next one it can afford. See
        // [`FRAME_WINDOW`] for why this is a switch rather than a measurement.
        if self.outgoing.capacity() == 0 { 0 } else { FRAME_WINDOW }
    }

    fn close<'a>(&'a mut self, ending: &'a Ending) -> Task<'a, Result<(), StreamError>> {
        let reason = ending.to_string();
        Box::pin(async move {
            self.outgoing.send(Outward::Close(reason)).await.map_err(|_| StreamError::Closed)
        })
    }
}

/// The reading half of a plain WebSocket, as the session driver wants it.
///
/// A channel rather than the socket, because [`Inbound::recv`] **must** be
/// cancel-safe — the driver drops this future on every frame tick — and
/// [`Duplex::recv`] is documented as not being. The pump task owns the stream
/// and loops on it; this end only takes what the pump has already reassembled.
struct SocketIn {
    incoming: mpsc::Receiver<Vec<u8>>,
}

impl Inbound for SocketIn {
    fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
        Box::pin(async move { Ok(self.incoming.recv().await) })
    }
}

/// Splits a live stream into the two halves the session driver takes, plus the
/// task that must be run to move bytes between them.
///
/// The pump owns the [`Duplex`] outright. That is the shape the codec asks for —
/// one task looping on `recv`, everything else talking to it through channels —
/// and it is what makes the reading half cancel-safe.
fn split<S>(
    mut duplex: Duplex<S>,
) -> (SocketOut, SocketIn, impl std::future::Future<Output = ()> + Send)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Outward>(OUTBOUND_DEPTH);
    let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(INBOUND_DEPTH);

    let pump = async move {
        let sender = duplex.sender();
        // Queued sends go through the stream's own outbound channel, which it
        // drains inside `recv`; that is why this task can loop on `recv` alone
        // and still write.
        let forward = async move {
            while let Some(outward) = outgoing_rx.recv().await {
                let sent = match outward {
                    Outward::Message(payload) => sender.send(payload).await,
                    Outward::Close(reason) => sender.close(CloseCode::Normal, reason).await,
                };
                if sent.is_err() {
                    return;
                }
            }
        };
        let read = async move {
            loop {
                match duplex.recv().await {
                    Ok(Event::Message(payload)) => {
                        if incoming_tx.send(payload).await.is_err() {
                            return;
                        }
                    }
                    // Either end of the stream closes this half; dropping the
                    // sender is what tells the driver its peer is done.
                    Ok(Event::Closed(_)) | Err(_) => return,
                }
            }
        };
        tokio::join!(forward, read);
    };

    (SocketOut { outgoing: outgoing_tx }, SocketIn { incoming: incoming_rx }, pump)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A two-node config with `[desktop]` in the state the test wants.
    ///
    /// Parsed from TOML rather than built by literal so that the test exercises
    /// the same loader the daemon does — a struct literal would keep passing on
    /// the day a new required field appears.
    fn config_with(desktop: Option<Desktop>) -> Config {
        let base = "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

[[nodes]]
name = \"home\"
role = \"owner\"

[[nodes]]
name = \"alex-desktop\"
role = \"worker\"
";
        let mut config = Config::parse(base).expect("the base config parses");
        config.desktop = desktop;
        config
    }

    /// A fresh, empty data directory named after the test that asked for it.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-desk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp data dir");
        dir
    }

    #[test]
    fn absent_config_starts_nothing() {
        let dir = std::env::temp_dir();
        assert!(
            start(&config_with(None), &dir, None).is_none(),
            "no [desktop] block, no subsystem"
        );
    }

    #[test]
    fn a_disabled_block_starts_nothing() {
        let dir = std::env::temp_dir();
        let disabled = Desktop { enabled: false, ..Desktop::default() };
        assert!(
            start(&config_with(Some(disabled)), &dir, None).is_none(),
            "enabled = false is as absent as no block at all"
        );
    }

    #[test]
    fn an_enabled_block_reports_every_declared_node() {
        let dir = temp_dir("nodes");
        let enabled = Desktop { enabled: true, ..Desktop::default() };
        let desk = start(&config_with(Some(enabled)), &dir, None).expect("the subsystem starts");

        let nodes = desk.nodes();
        let names: Vec<&str> = nodes.iter().map(|node| node.node.as_str()).collect();
        assert_eq!(names, [LOCAL_NODE, "home", "alex-desktop"]);
        assert!(nodes[0].live, "this machine is always reachable");
        let reason = nodes[1].reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("[mesh]"),
            "a node with no link is reported with the reason, never omitted: {reason}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_kill_switch_is_what_the_agent_report_names() {
        let dir = temp_dir("kill");
        let enabled = Desktop { enabled: true, ..Desktop::default() };

        let desk = start(&config_with(Some(enabled)), &dir, None).expect("starts");
        assert!(!desk.stopped());
        assert!(
            !desk.agent(LOCAL_NODE).sentence.contains("kill switch"),
            "with no switch engaged the report is about the capture backend instead"
        );

        crate::kill_switch::engage(&dir).expect("engage");
        let desk = start(&config_with(Some(enabled)), &dir, None).expect("starts");
        assert!(desk.stopped(), "the switch is read at startup, not only on the timer");
        assert!(
            desk.agent(LOCAL_NODE).sentence.contains("kill switch"),
            "an engaged switch is the reason reported, ahead of everything else"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The kill switch's first requirement: a stream that is already running
    /// must end, and it must end saying *why*.
    ///
    /// Asserted against the real [`FrameSource`] the daemon wires, driven the
    /// way the session driver drives it — ask for a frame, engage the switch,
    /// ask again — rather than against a flag somewhere. The distinction matters
    /// because the flag is the easy half; that the *screen* consults it on every
    /// frame is the half that actually closes a session.
    /// Also the one test that opens a *real* capture, and therefore the one that
    /// proves the daemon reaches this machine's screen at all.
    ///
    /// Deliberately the only one: two of these running in parallel would be two
    /// captures of one display, which macOS may refuse — see [`Machine::open`].
    #[tokio::test]
    async fn an_engaged_switch_stops_a_live_screen_on_its_next_frame() {
        let stopped = Arc::new(AtomicBool::new(false));
        let mut screen = Machine::open(Arc::clone(&stopped), false).await.screen;

        // On a machine that can capture, this is the whole feature: pixels, of
        // the size the session was told to expect, through the daemon's own
        // seam. On one that cannot, it is a named condition and never a wait.
        let before = screen.next_frame(Duration::from_millis(500)).await;
        if Backend::here().wired {
            match before {
                Ok(frame) => {
                    let monitor = screen
                        .monitors()
                        .iter()
                        .find(|monitor| monitor.id == frame.monitor)
                        .copied()
                        .expect("the frame names a display the session was told about");
                    assert_eq!(
                        (frame.surface.width(), frame.surface.height()),
                        (monitor.width, monitor.height),
                        "the unpacked frame is the display's own size, so no row padding leaked"
                    );
                    assert_eq!(
                        frame.surface.pixels().len() as u64,
                        u64::from(monitor.width) * u64::from(monitor.height) * 4,
                        "and it is tight BGRA, which is what the tile encoder assumes"
                    );
                }
                // A still desktop, a display being re-enumerated, a locked
                // screen: all ordinary, none of them the end of a session.
                Err(condition) => assert_ne!(condition, Condition::Stopped),
            }
        } else {
            assert_ne!(before.err(), Some(Condition::Stopped));
        }

        stopped.store(true, Ordering::Relaxed);
        assert_eq!(
            screen.next_frame(Duration::from_millis(1)).await.err(),
            Some(Condition::Stopped),
            "an engaged switch reaches a running stream on its very next frame"
        );
        assert_eq!(
            screen.restore(Restore::Capture).await.err(),
            Some(Condition::Stopped),
            "and it is not worked around by asking for a rebuild"
        );

        // Released, and the screen is allowed to try again — the switch is a
        // state, not a one-way door.
        stopped.store(false, Ordering::Relaxed);
        assert_ne!(
            screen.next_frame(Duration::from_millis(1)).await.err(),
            Some(Condition::Stopped)
        );
    }

    /// The kill switch's second requirement: a new stream is refused before
    /// anything is opened.
    #[tokio::test]
    async fn an_engaged_switch_opens_no_capture_at_all() {
        let stopped = Arc::new(AtomicBool::new(true));
        let machine = Machine::open(Arc::clone(&stopped), true).await;
        assert!(machine.cursor.is_none(), "no pointer is opened while the switch is engaged");
        assert!(machine.keys.is_none(), "and no injector is built at all");
        assert!(
            machine.screen.monitors().is_empty(),
            "a session admitted under the switch is told about no displays"
        );
    }

    /// The switch must work when the config is unreadable and the API is
    /// unreachable, because that is exactly when an operator reaches for it.
    ///
    /// So this test never loads a config and never starts a daemon: it creates
    /// the file the way a person with a shell, a Finder window or an SMB mount
    /// would, and asserts the daemon's own poll notices — which is the whole
    /// mechanism, end to end, with nothing else working.
    #[tokio::test(start_paused = true)]
    async fn the_switch_is_honoured_with_nothing_else_working() {
        let dir = temp_dir("nothing-else");
        let enabled = Desktop { enabled: true, ..Desktop::default() };
        let desk =
            Arc::new(start(&config_with(Some(enabled)), &dir, None).expect("the subsystem starts"));
        assert!(!desk.stopped());

        let watching = tokio::spawn({
            let desk = Arc::clone(&desk);
            async move { desk.watch().await }
        });

        // No config is read, no API is called: a file appears in the directory.
        std::fs::write(dir.join(crate::kill_switch::FILE_NAME), "stop").expect("touch the marker");
        // One poll interval, plus a tick of slack for the timer's own edge.
        tokio::time::sleep(crate::kill_switch::POLL_INTERVAL * 2).await;
        assert!(desk.stopped(), "the daemon noticed within one poll");
        assert!(
            desk.agent(LOCAL_NODE).sentence.contains("kill switch"),
            "and says so to anything that asks what it can do"
        );

        std::fs::remove_file(dir.join(crate::kill_switch::FILE_NAME)).expect("remove the marker");
        tokio::time::sleep(crate::kill_switch::POLL_INTERVAL * 2).await;
        assert!(!desk.stopped(), "removing the file is as immediate as creating it");

        // Two transitions, two audit lines — and not four, which is what two
        // writers observing the same two events would have produced.
        let log = std::fs::read_to_string(dir.join("audit.log")).expect("the log exists");
        let switch_lines: Vec<&str> =
            log.lines().filter(|line| line.contains("detail=kill-switch:")).collect();
        assert_eq!(switch_lines.len(), 2, "one line per transition, no more:\n{log}");
        assert!(switch_lines[0].contains("kill-switch:engaged"), "{}", switch_lines[0]);
        assert!(switch_lines[1].contains("kill-switch:released"), "{}", switch_lines[1]);

        watching.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A daemon that starts with the switch already engaged must say so, once.
    ///
    /// This is the case nobody was running to observe: the operator revoked the
    /// desktop while the daemon was down, and without this the whole of that
    /// daemon's life would look, in the log, like an ordinary one.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_starts_revoked_records_it_once() {
        let dir = temp_dir("starts-revoked");
        crate::kill_switch::engage(&dir).expect("engage before anything starts");
        let enabled = Desktop { enabled: true, ..Desktop::default() };
        let desk =
            Arc::new(start(&config_with(Some(enabled)), &dir, None).expect("the subsystem starts"));

        let watching = tokio::spawn({
            let desk = Arc::clone(&desk);
            async move { desk.watch().await }
        });
        tokio::time::sleep(crate::kill_switch::POLL_INTERVAL * 4).await;

        let log = std::fs::read_to_string(dir.join("audit.log")).expect("the log exists");
        assert_eq!(
            log.lines().filter(|line| line.contains("kill-switch:engaged")).count(),
            1,
            "recorded once, not once per poll:\n{log}"
        );
        watching.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The switch's third requirement, and the one the screen path cannot
    /// carry: it must reach the **hands**, not only the eyes.
    ///
    /// A session driver observes the switch when it asks for a frame, which is
    /// between keystrokes rather than before each one. So the injector is asked
    /// as well, and this is the rule it is asked by — including the half that
    /// would be a disaster to get backwards.
    #[test]
    fn an_engaged_switch_refuses_new_input_and_never_refuses_a_release() {
        use selfhost_desk::keys::Usage;
        use selfhost_desk::wire::Button;

        let key = Usage::from_code("KeyA").expect("KeyA is in the vocabulary");

        // Clear: nothing is this rule's business.
        for message in [
            Message::Key { usage: key, down: true },
            Message::Text { text: "hello".to_owned() },
            Message::PointerMove { monitor: 0, x: 1, y: 1 },
            Message::Button { button: Button::Left, down: true },
            Message::Scroll { dx: 0, dy: 120 },
            Message::ReleaseAll,
        ] {
            assert_eq!(refuse_while_stopped(false, &message), None, "{message:?}");
        }

        // Engaged: everything that would press, type, point or scroll is
        // refused, and the console is told which refusal it was.
        for message in [
            Message::Key { usage: key, down: true },
            Message::Text { text: "hello".to_owned() },
            Message::PointerMove { monitor: 0, x: 1, y: 1 },
            Message::Button { button: Button::Left, down: true },
            Message::Scroll { dx: 0, dy: 120 },
        ] {
            assert_eq!(
                refuse_while_stopped(true, &message),
                Some(Refusal::NotLive),
                "an engaged switch let {message:?} through"
            );
        }

        // ...and everything that only ever *undoes* still goes through, or the
        // operator's revocation would be the thing that left a modifier held
        // down on the machine they revoked.
        for message in [
            Message::ReleaseAll,
            Message::Key { usage: key, down: false },
            Message::Button { button: Button::Left, down: false },
        ] {
            assert_eq!(
                refuse_while_stopped(true, &message),
                None,
                "an engaged switch refused to let go of {message:?}"
            );
        }
    }

    /// One poll is well inside one WebSocket ping interval, which is the bound
    /// the plan states. Asserted rather than assumed, because it is a claim
    /// about two constants that live in two different crates.
    #[test]
    fn the_poll_closes_a_stream_well_inside_one_ping_interval() {
        assert!(
            crate::kill_switch::POLL_INTERVAL < selfhost_ws::Limits::default().ping_interval,
            "an engaged switch must reach a stream before its next ping"
        );
    }

    /// A machine that cannot capture must answer with the *reason* it reports
    /// everywhere else, rather than leaving the driver waiting on a frame that
    /// is not coming.
    ///
    /// Only asserted for the unwired case. On a machine that *can* capture this
    /// opens a real screen stream, and several tests running in parallel would
    /// then be several streams of one display — which macOS is entitled to
    /// refuse, and does. That refusal is a genuine property of the platform, not
    /// of this code, and it is recorded at [`Machine::open`] rather than papered
    /// over with a test that asserts whatever happened to come back.
    #[tokio::test]
    async fn a_screen_that_cannot_open_answers_with_the_reason() {
        let backend = Backend::here();
        if backend.wired {
            return;
        }
        let mut screen = Machine::open(Arc::new(AtomicBool::new(false)), false).await.screen;
        assert!(
            screen.monitors().is_empty(),
            "a machine with no capture advertises no displays rather than inventing one"
        );
        assert_eq!(
            screen.next_frame(Duration::from_millis(1)).await.err(),
            Some(backend.condition),
            "an unwired backend answers a session with the condition it reports to doctor"
        );
    }
}
