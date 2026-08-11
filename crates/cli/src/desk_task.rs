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
//! # The agent process, and the half of it that is wired
//!
//! On Windows a daemon installed as a service runs as `SYSTEM` in session 0 and
//! cannot capture the console user's screen by any method, so the pixels have to
//! come from an agent process spawned into that session and reached over
//! `\\.\pipe\selfhost-desk-<session>`. [`crate::desk_supervisor`] is the daemon's
//! half of that agent's life and is wired here: it creates the pipe with its
//! explicit DACL, starts the agent into the console session, watches it die,
//! respawns it with visible backoff under the hour's cap, gives up out loud when
//! the cap is spent, and publishes every one of those states as a sentence that
//! this module's [`Fleet::agent`], the daemon's banner and the console all print.
//!
//! What is **not** wired is the agent's frames reaching a viewer. A session here
//! is driven by [`Viewer`] over a [`FrameSource`], and the agent instead produces
//! an encoded message stream that the daemon is meant to *forward* rather than
//! consume — a splice, with credit carried end to end, which lives above this
//! crate's seam. Until that exists [`Backend::here`] tells a session-0 daemon's
//! console that it cannot reach the desktop **and why**, which is the honesty
//! this subsystem is built around: a backend that cannot produce a pixel never
//! claims it can. A Windows daemon started from a signed-in session is in that
//! session already and captures directly, which is the path this build serves in
//! full.

use selfhost_admin::desk_api::LOCAL_NODE;
use selfhost_admin::{AgentReport, Fleet, Handover, NodeReport};
use selfhost_config::{Config, Desktop};
use selfhost_desk::grant::{Capabilities, SessionId};
use selfhost_desk::viewer::{
    CLOSE_GRACE, CapturedFrame, Condition, DEFAULT_SEND_WINDOW, Ending, FrameSource, Inbound,
    InputSink, NoInput, NoPointer, Outbound, PointerSource, Restore, SessionDirectory, Standing,
    StreamError, Task, Viewer, Wiring,
};
use selfhost_desk::wire::{Message, Monitor, Refusal};
use selfhost_ws::{CloseCode, Duplex, Event, Limits};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub use crate::desk_local::Backend;

/// How deep the queue of messages waiting for the socket is allowed to get.
///
/// # This is not the flow control, and the first release made it so by accident
///
/// It used to be two, on the reasoning that a desktop stream must show the
/// present rather than a backlog. That reasoning is right and this is the wrong
/// place to enforce it: a *frame* is a set of tiles, and a keyframe for a Retina
/// panel is about fifteen hundred of them. A queue two messages deep makes the
/// queue itself the window, and a window two messages wide cannot deliver a
/// frame that is fifteen hundred messages long without the driver stopping
/// after every second tile.
///
/// So the flow control is [`SEND_WINDOW`], measured in bytes, and this is only
/// deep enough that the pump and the session driver can run at the same time.
/// The window still bounds the bytes sitting here — it is spent when a message
/// is accepted and returned when the pump takes it — so this depth costs nothing
/// beyond the window's own ceiling.
const OUTBOUND_DEPTH: usize = 64;

/// How deep the queue of messages arriving from the console is allowed to get.
///
/// Deeper than the outbound side because what arrives here is input — key and
/// pointer events, which are small, ordered and must not be dropped: a lost key
/// release is a modifier stuck down on somebody's machine.
const INBOUND_DEPTH: usize = 64;

/// How many payload bytes may be waiting for the socket at one time.
///
/// # What the number means, and what it emphatically does not
///
/// It is the protocol's initial window — [`DEFAULT_SEND_WINDOW`] — used here for
/// what a window is: a bound on the bytes in flight at one instant. It is spent
/// as [`SocketOut::send`] accepts a message and returned as the pump hands that
/// message to the WebSocket writer, so [`Outbound::credit`] answers with the
/// link's real instantaneous headroom.
///
/// It is **not** a ceiling on the size of a frame. The first release read it as
/// one — the driver summed a whole frame's bytes and dropped the frame if the
/// total did not fit — and since the first frame of every session is a keyframe,
/// and a keyframe for a 3024×1964 panel is about fifteen hundred tiles, no frame
/// was ever deliverable at all. A frame far larger than this window is delivered
/// by spending the window, having it returned, and spending it again.
///
/// # There is no credit *protocol* on this hop unless the client asks for one
///
/// The mux's `CREDIT` frame runs between the owner daemon and a worker's agent.
/// A browser on the far end of the console relay speaks plain WebSocket, so
/// unless it sends [`selfhost_desk::wire::Message::Credit`] the only backpressure
/// on this hop is this socket's own — which, being a genuine measurement rather
/// than a switch, is enough.
const SEND_WINDOW: u32 = DEFAULT_SEND_WINDOW;

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
    /// The capture agent's supervisor.
    ///
    /// Always present, because "there is no agent on this machine and here is
    /// why" is itself an answer the console has to be given: an `Option` would
    /// make an absent supervisor indistinguishable from a dead one. On every
    /// platform but a Windows service it publishes exactly that sentence and
    /// starts no thread.
    agent: Arc<crate::desk_supervisor::CaptureAgent>,
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
    let engaged = crate::kill_switch::present(data_dir);
    // Built with the deployment's own switch, which is read from the config
    // exactly once and never re-derived downstream: `allow_input = false` must
    // mean an agent that holds no injector, and the way it means that is the
    // argument vector this policy produces.
    let agent = Arc::new(crate::desk_supervisor::CaptureAgent::start(
        desktop.allow_input,
        desktop.agent_respawn_cap,
    ));
    // The switch is handed over before the first turn rather than at the first
    // poll, so a daemon that starts with the desktop already revoked never starts
    // an agent at all — the case nobody is watching, and the one where a
    // supervisor that learned a second later would have spawned one.
    agent.set_kill_switch(engaged);
    Some(Desk {
        config: desktop,
        data_dir: data_dir.to_path_buf(),
        nodes,
        stopped: Arc::new(AtomicBool::new(engaged)),
        peers,
        audit: crate::audit::Auditor::in_dir(data_dir),
        agent,
    })
}

impl Desk {
    /// The operator's settings.
    pub fn config(&self) -> &Desktop {
        &self.config
    }

    /// Whether the kill switch is engaged as of the last poll.
    ///
    /// This is the *cheap* answer, and it is the right one for a running stream:
    /// a frame loop reads it several times a second, and [`Self::halted`]'s
    /// `stat` at that rate would be a syscall per frame to learn something that
    /// cannot have changed since the poll by more than [`POLL_INTERVAL`].
    ///
    /// It is the wrong answer at the door — see [`Self::halted`].
    ///
    /// [`POLL_INTERVAL`]: crate::kill_switch::POLL_INTERVAL
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Whether the kill switch is engaged *at this instant*, asked of the disk.
    ///
    /// The distinction from [`Self::stopped`] is not fastidiousness; it was a
    /// measured hole. Admitting a session on the polled flag alone let a
    /// complete 3024×1964 keyframe — a legible photograph of the whole screen —
    /// reach a viewer that connected 2.5 seconds after an operator engaged the
    /// switch, because the flag was still carrying the previous poll's answer.
    /// Waiting the full interval instead produced zero tiles, which is how the
    /// race was identified as a race rather than a bypass.
    ///
    /// An operator who touches that file believes it is instant, so at the one
    /// point where believing otherwise costs a screen, we pay one `stat` of a
    /// path this process already holds — on a route that has already passed the
    /// console gate, so it is not a surface anyone can spin. Everywhere the
    /// answer is merely *reported* rather than *acted on*, the polled flag still
    /// serves.
    ///
    /// The two are OR-ed rather than the file simply replacing the flag:
    /// [`crate::kill_switch::present`] fails closed, so a volume that cannot be
    /// read answers `true`, and a flag that is already set must not be talked
    /// out of it by a filesystem that has started returning errors.
    pub fn halted(&self) -> bool {
        self.stopped() || crate::kill_switch::present(&self.data_dir)
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
            // Read back from the value that was actually handed to the agent
            // spawner rather than from the config field beside it. They agree —
            // one is built from the other — and asking the object that holds the
            // consequence is what keeps them agreeing: a banner that said
            // "refused" while an armed policy had already reached a process in
            // somebody's session would be the one lie this subsystem cannot
            // afford.
            input = if self.agent.input_policy().allows() { "allowed" } else { "refused" },
        );
        let backend = Backend::here();
        sentence.push_str(&format!("\n  capture      {}", backend.name));
        if !backend.wired {
            // The reason, not merely the fact: an operator reading a banner that
            // says "not wired" and nothing else has to go and find out why, and
            // the answer is usually one they can act on in a minute.
            sentence.push_str(&format!("\n               unavailable — {}", backend.why));
        }
        // The agent's own line, always: on a machine that needs none it says so,
        // and on the one deployment that does it is the difference between "the
        // desktop does not work" and "nobody is signed in yet".
        sentence.push_str(&format!("\n  agent        {}", self.agent.status().line()));
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
            // One reader of the filesystem, two consumers of the answer. The
            // streams and the agent supervisor must never hold different beliefs
            // about a switch whose whole purpose is to be believed immediately,
            // and a second poll would be a second belief.
            self.agent.set_kill_switch(engaged);
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
                // Removing the switch is the operator's "start". It is the only
                // such signal this daemon has, and it is the right one: an agent
                // that exhausted its hourly cap stays surrendered until a person
                // says otherwise, and a person who has just deleted the file that
                // was holding the desktop down has said otherwise as plainly as
                // this deployment can be told. Without this, clearing the switch
                // would revive the streams and leave the agent permanently given
                // up, which reads as the switch not working.
                self.agent.operator_start();
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
        if self.halted() {
            // Asked of the disk, not of the poll. The route already checked, but
            // the switch can be engaged between the handshake and here, and a
            // stream that starts after the operator said stop is the one case
            // this whole mechanism exists to prevent — so this is the reading
            // that must be current, whatever it costs.
            return format!(
                "refused: the kill switch at {} is in place",
                crate::kill_switch::path_in(&self.data_dir).display()
            );
        }

        let Handover { io, redemption, ceilings, seat, identity, directory } = handover;
        let limits = Limits { max_lifetime: ceilings.max_session, ..Limits::default() };
        let (mut outbound, mut inbound, pump) = split(Duplex::server(io, limits));
        let mut pump = tokio::spawn(pump);

        // Written before a single pixel leaves the machine, not after. A session
        // that is admitted and then hangs, or whose daemon is killed while it
        // runs, must still have left a line saying who was let in and what they
        // were allowed to do — an audit trail that is only written on the way out
        // is missing precisely the entries an incident is about.
        self.audit.admitted(&identity, &redemption);

        // Two drivers, one decision, made here because this is the only place
        // that holds both the socket and the supervisor. A daemon that cannot
        // capture but has an agent relays; everything else captures. The probe is
        // live rather than cached: a Windows service does not become an
        // interactive session while it runs, but a console session it is
        // relaying can go away and come back, and the agent's own state machine
        // is what handles that.
        // The real directory when the admin API had a session store to build one
        // over, and the ticket-shaped stand-in when it did not. Chosen once, so
        // both drivers are held to the same standing by construction.
        let stand_in;
        let directory: &dyn SessionDirectory = match directory.as_deref() {
            Some(real) => real,
            None => {
                stand_in = TicketStanding::new(&redemption.session, ceilings.max_session);
                &stand_in
            }
        };

        if crate::desk_local::Backend::here().relayed {
            let outcome = self
                .relay_session(&mut outbound, &mut inbound, &redemption, ceilings, seat, directory)
                .await;
            if tokio::time::timeout(CLOSE_GRACE, &mut pump).await.is_err() {
                pump.abort();
            }
            return match outcome {
                Some(outcome) => format!(
                    "{ending} · {who} · relayed · {frames} frame(s), {bytes} byte(s), \
                     {refused} input(s) refused",
                    ending = outcome.ending,
                    who = identity,
                    frames = outcome.stats.frames_sent,
                    bytes = outcome.stats.bytes_sent,
                    refused = outcome.stats.inputs_refused,
                ),
                None => format!(
                    "refused: {identity} · this machine's screen is already being served to \
                     another session. One agent holds the model of one client's picture, so a \
                     second viewer would be sent the difference against somebody else's screen."
                ),
            };
        }

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
                directory,
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

        // Both flow-control counters, because they mean different things to
        // whoever reads this line: stalls are frames the link could not begin,
        // deferrals are tiles a frame could not finish in one pass. A line that
        // reported only the first would have said "0 frame(s), 6 credit
        // stall(s)" for a link that was in fact perfectly healthy and merely
        // being asked the wrong question.
        format!(
            "{ending} · {who} · {frames} frame(s), {bytes} byte(s), {stalls} credit stall(s), \
             {deferred} tile(s) deferred, {refused} input(s) refused",
            ending = outcome.ending,
            who = identity,
            frames = outcome.stats.frames_sent,
            bytes = outcome.stats.bytes_sent,
            stalls = outcome.stats.credit_stalls,
            deferred = outcome.stats.tiles_deferred,
            refused = outcome.stats.inputs_refused,
        )
    }
}

impl Desk {
    /// Drives one session whose pixels come from the supervised agent.
    ///
    /// `None` means the agent is already serving another session — see
    /// [`crate::desk_supervisor::CaptureAgent::attach`] for why that is a refusal
    /// and not a queue.
    ///
    /// The seat is taken by value and dropped with the driver, exactly as the
    /// capture path does, so `[desktop].max_viewers` is enforced by construction
    /// on both paths.
    async fn relay_session(
        &self,
        outbound: &mut dyn Outbound,
        inbound: &mut dyn Inbound,
        redemption: &selfhost_desk::grant::Redemption,
        ceilings: selfhost_desk::viewer::Ceilings,
        seat: selfhost_desk::viewer::Seat,
        directory: &dyn SessionDirectory,
    ) -> Option<selfhost_desk::viewer::Outcome> {
        let stream = self.agent.attach()?;
        let mut screen = AgentScreen {
            stream: Some(stream),
            agent: Arc::clone(&self.agent),
            monitors: self.agent.displays(),
            stopped: Arc::clone(&self.stopped),
        };
        let relay = selfhost_desk::relay::Relay::new(
            outbound,
            &mut screen,
            directory,
            seat,
            redemption,
            ceilings,
        );
        Some(relay.run(inbound).await)
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
        if self.halted() {
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
        // The daemon cannot capture in its own process. On the one deployment
        // where that is expected rather than broken — a Windows service in
        // session 0 — the supervisor is the thing that knows what is happening,
        // and its sentence is the one worth showing: "nobody is signed in yet"
        // and "the agent has failed three times, next attempt in eight seconds"
        // are different machines, and the backend probe can tell neither.
        let agent = self.agent.status();
        if agent.supervised {
            return AgentReport {
                node: node.to_owned(),
                live: agent.live,
                sentence: format!("{} · {}", agent.line(), backend.why),
                monitors: agent.monitors,
                respawns: agent.spawns_last_hour,
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
        let hands = match monitors {
            Ok(monitors) if injector_wanted(allow_input, false, true) => {
                match crate::desk_local::open_hands(monitors).await {
                    Ok((cursor, keys)) => (Some(cursor), Some(keys)),
                    Err(error) => {
                        // Reported once, here, where the reason is still
                        // specific. The remote viewer is told only
                        // `input-refused`; the remediation is for the person at
                        // this machine.
                        eprintln!("desktop: no input on this machine — {}", error.sentence());
                        (None, None)
                    }
                }
            }
            _ => (None, None),
        };
        Self { screen: LocalScreen { screen, stopped }, cursor: hands.0, keys: hands.1 }
    }
}

/// Whether this session may build an injector at all.
///
/// Pure and total, so the one property the whole default-off posture rests on is
/// **asserted** rather than believed: `allow_input = false` yields `false` for
/// every combination of everything else. It is one expression, and it is written
/// as its own function precisely because a condition spelled inline inside a
/// `match` arm is a condition that gains a second arm one day.
///
/// The other two arguments are not redundant with it. A session admitted while
/// the kill switch is engaged must build nothing, and a machine whose capture
/// could not be opened has no display layout to normalise a pointer against — the
/// coordinate mapping is built from the monitors, so an injector without them
/// would map every click onto a desktop that was never read.
fn injector_wanted(allow_input: bool, stopped: bool, screen_opened: bool) -> bool {
    allow_input && !stopped && screen_opened
}

/// The agent's message stream, as [`selfhost_desk::relay::Relay`] wants it.
///
/// # The one deployment this exists for
///
/// A Windows daemon installed as a service runs as `SYSTEM` in session 0 and
/// cannot capture the console user's desktop by any method. The pixels come from
/// an agent process in that session, over a named pipe whose access-control list
/// is the authentication, and this is the daemon's end of that pipe wearing the
/// shape a session driver can use.
///
/// It **decodes nothing**. What crosses is whole encoded messages the supervisor
/// took off the pipe; the relay above reads one byte of each and copies the rest.
/// See [`selfhost_desk::relay`] for why a parser here would be a way to take down
/// the reverse proxy, the DNS authority and the mail server at once.
///
/// # What a missing message means is decided here
///
/// The relay asks for the next message and is told either a message or a
/// [`Condition`]. Which condition is the daemon's knowledge and not the pipe's: a
/// quiet pipe on a still desktop is [`Condition::Retry`] and costs nothing, a
/// closed channel is [`Condition::AgentExited`] and starts the state machine's
/// recovery, and an engaged kill switch outranks both — asked first, before
/// anything is read, so an operator who stopped the subsystem is told *that* and
/// not something about an agent.
struct AgentScreen {
    /// The live attachment, or `None` once the agent that owned it has gone.
    stream: Option<crate::desk_supervisor::AgentStream>,
    /// Where a replacement attachment comes from.
    agent: Arc<crate::desk_supervisor::CaptureAgent>,
    /// The displays the agent named, taken at the handshake.
    monitors: Vec<Monitor>,
    stopped: Arc<AtomicBool>,
}

impl AgentScreen {
    /// The kill switch's answer, when it has one.
    ///
    /// Asked first on every path, for the same reason [`LocalScreen::halted`] is.
    fn halted(&self) -> Option<Condition> {
        self.stopped.load(Ordering::Relaxed).then_some(Condition::Stopped)
    }
}

impl selfhost_desk::relay::Upstream for AgentScreen {
    fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    fn next_message(&mut self, budget: Duration) -> Task<'_, Result<Vec<u8>, Condition>> {
        if let Some(halted) = self.halted() {
            return Box::pin(async move { Err(halted) });
        }
        Box::pin(async move {
            let Some(stream) = self.stream.as_mut() else {
                return Err(Condition::AgentExited);
            };
            match tokio::time::timeout(budget, stream.frames.recv()).await {
                // The supervisor closed the attachment: the agent it belonged to
                // is gone, and a new one needs a new attachment.
                Ok(None) => {
                    self.stream = None;
                    Err(Condition::AgentExited)
                }
                Ok(Some(message)) => Ok(message),
                // Nothing inside the budget. A still desktop sends nothing at
                // all, by design, and this is what that looks like from here.
                Err(_elapsed) => Err(Condition::Retry),
            }
        })
    }

    fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>> {
        Box::pin(async move {
            let Some(stream) = self.stream.as_ref() else {
                return Err(Refusal::NotLive);
            };
            let encoded = message.encode().map_err(|_| Refusal::Unmappable)?;
            // Never blocking. A full queue is an agent that has stopped draining
            // its pipe, and holding a keystroke for it would only deliver that
            // keystroke to a desktop that has moved on.
            stream.input.try_send(encoded).map_err(|_| Refusal::NotLive)
        })
    }

    fn restore(&mut self) -> Task<'_, Result<(), Condition>> {
        Box::pin(async move {
            if let Some(halted) = self.halted() {
                return Err(halted);
            }
            // Dropped before the next is asked for: the slot holds one session,
            // and asking for a second while still holding the first refuses
            // itself.
            self.stream = None;
            let Some(stream) = self.agent.attach() else {
                // The supervisor has not brought a replacement up yet. Not a
                // failure — the state machine's backoff is what paces this — so
                // the honest answer is the state the machine is in.
                return Err(Condition::AgentExited);
            };
            self.monitors = self.agent.displays();
            self.stream = Some(stream);
            Ok(())
        })
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
    /// Payload bytes accepted here and not yet handed to the WebSocket writer.
    ///
    /// Shared with the pump, which is the half that gives them back. An atomic
    /// rather than a lock because it is read once per message on the driver's hot
    /// path and written once per message on the pump's, and the two never need to
    /// agree about anything else.
    in_flight: Arc<AtomicU64>,
}

/// One thing to put on the socket.
enum Outward {
    /// An encoded protocol message.
    Message(Vec<u8>),
    /// The stream is over, for this reason.
    Close(String),
}

impl Outbound for SocketOut {
    /// Accepts one message, charging its bytes to the window until the pump
    /// takes them.
    ///
    /// Charged **before** the queue is offered the message rather than after, so
    /// that a driver writing a long frame sees the window shrink as it goes even
    /// while the pump is running behind it. This may still park on a full queue —
    /// [`SocketOut::credit`] reports zero once the queue is full precisely so the
    /// driver does not walk into that, but the queue can fill between the two —
    /// and such a park costs at most one message and is bounded anyway by the
    /// stream's deadline, which the driver wraps every write in.
    fn send<'a>(&'a mut self, frame: &'a [u8]) -> Task<'a, Result<(), StreamError>> {
        let payload = frame.to_vec();
        let charged = payload.len() as u64;
        Box::pin(async move {
            // The handoff is cooperative, and saying so costs a nanosecond.
            //
            // The driver writes a whole frame without awaiting anything else, and
            // the queue below is deep enough that pushing to it never parks. On a
            // multi-threaded runtime the pump is meanwhile draining on another
            // worker, so the window returns as fast as it is spent; on a
            // single-threaded one it would never be polled at all, the window
            // would run out part-way through the first frame, and the picture
            // would arrive a few hundred tiles per second. Yielding here is what
            // makes the two behave the same, which is the difference between a
            // transport that works and one that works on the machine it was
            // written on.
            tokio::task::yield_now().await;
            self.in_flight.fetch_add(charged, Ordering::AcqRel);
            match self.outgoing.send(Outward::Message(payload)).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Never handed over, so never given back by the pump. Undone
                    // here or the window shrinks permanently on every failed
                    // write of a stream that is closing anyway.
                    self.in_flight.fetch_sub(charged, Ordering::AcqRel);
                    Err(StreamError::Closed)
                }
            }
        })
    }

    /// The window's real remaining headroom, in bytes.
    ///
    /// A measurement, not a switch: the driver re-reads this between the tiles of
    /// one frame, and it must fall as bytes pile up here and rise as the pump
    /// drains them. Answering a constant would make a frame larger than the
    /// window undeliverable — the defect this replaced — and answering zero for
    /// anything short of a full window would stop the picture.
    ///
    /// # Two honest bounds, and the smaller one wins
    ///
    /// The byte window is the one that normally binds. A full queue is the other,
    /// and it exists so the driver **never parks inside a write**: a viewer that
    /// has stopped reading backs the pump up, the queue fills, and a driver that
    /// walked into `send` anyway would sit there until the stream's own wall —
    /// hours — with the capture arm suspended, which is the arm that observes the
    /// operator's kill switch. Reporting zero instead sends it round the loop to
    /// decline the frame and merge the damage, which is where it can still be
    /// stopped.
    fn credit(&self) -> u32 {
        if self.outgoing.capacity() == 0 {
            return 0;
        }
        let waiting = self.in_flight.load(Ordering::Acquire);
        let waiting = u32::try_from(waiting).unwrap_or(u32::MAX);
        SEND_WINDOW.saturating_sub(waiting)
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
    let in_flight = Arc::new(AtomicU64::new(0));
    let returning = Arc::clone(&in_flight);

    let pump = async move {
        let sender = duplex.sender();
        // Queued sends go through the stream's own outbound channel, which it
        // drains inside `recv`; that is why this task can loop on `recv` alone
        // and still write.
        let forward = async move {
            while let Some(outward) = outgoing_rx.recv().await {
                let sent = match outward {
                    Outward::Message(payload) => {
                        // The window is returned as the bytes leave, which is
                        // what lets the driver spend it, get it back, and spend
                        // it again inside a single frame. Measured before the
                        // send because it consumes the payload, and returned
                        // after it because until then the bytes are still here.
                        let carried = payload.len() as u64;
                        let sent = sender.send(payload).await;
                        returning.fetch_sub(carried, Ordering::AcqRel);
                        sent
                    }
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

    (
        SocketOut { outgoing: outgoing_tx, in_flight },
        SocketIn { incoming: incoming_rx },
        pump,
    )
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

    /// Five seconds of this machine's real screen, through the real transport,
    /// reported as the numbers an operator would see.
    ///
    /// # Why this is `#[ignore]`d rather than run with the suite
    ///
    /// It opens a genuine platform capture. That needs the host to have a
    /// display, to have granted this binary Screen Recording, and to not already
    /// be running another stream of the same display — none of which a test suite
    /// may assume, and the last of which macOS is entitled to refuse outright.
    /// The properties this feature must hold are asserted by the doubles in
    /// `selfhost-desk`, which run everywhere; this exists so a person can
    /// *measure* the thing on the machine in front of them:
    ///
    /// ```text
    /// cargo test -p selfhost-cli -- --ignored --nocapture five_seconds
    /// ```
    ///
    /// It asserts only what is true of any working link — that pixels arrived —
    /// and prints the rest, because frame and byte counts are properties of the
    /// screen's content and of the machine, not of this code.
    #[ignore = "opens a real platform capture; run by hand with --ignored"]
    #[tokio::test]
    async fn five_seconds_of_this_machines_real_screen() {
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut outbound, mut inbound, pump) =
            split(Duplex::server(near, Limits::default()));
        let mut client = Duplex::client(far, Limits::default());
        let pumping = tokio::spawn(pump);
        // A viewer that reads everything, which is what makes the send window
        // return and therefore what the measurement is of.
        let reading = tokio::spawn(async move {
            let mut messages = 0u64;
            while let Ok(Event::Message(_)) = client.recv().await {
                messages += 1;
            }
            messages
        });

        let stopped = Arc::new(AtomicBool::new(false));
        let Machine { mut screen, .. } = Machine::open(Arc::clone(&stopped), false).await;
        let monitors = FrameSource::monitors(&screen).to_vec();
        println!("displays: {monitors:?}");

        let mut pointer = NoPointer;
        let mut input = NoInput;
        let session = selfhost_desk::grant::SessionId::new("live-measurement");
        let ceilings = selfhost_desk::viewer::Ceilings {
            max_session: Duration::from_secs(5),
            ..selfhost_desk::viewer::Ceilings::default()
        };
        let directory = TicketStanding::new(&session, ceilings.max_session);
        let redemption = selfhost_desk::grant::Redemption {
            session,
            peer: LOCAL_NODE.to_owned(),
            capabilities: Capabilities::VIEW,
        };
        let seat = selfhost_desk::viewer::Gate::new(1)
            .admit(LOCAL_NODE)
            .expect("an empty gate admits");

        let started = Instant::now();
        let viewer = Viewer::new(
            Wiring {
                outbound: &mut outbound,
                frames: &mut screen,
                pointer: &mut pointer,
                input: &mut input,
            },
            &directory,
            seat,
            &redemption,
            ceilings,
        );
        let outcome = viewer.run(&mut inbound).await;
        let elapsed = started.elapsed();

        drop(outbound);
        let delivered = tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .map(|joined| joined.unwrap_or(0))
            .unwrap_or(0);
        pumping.abort();

        println!(
            "{:.1}s · {} · {} frame(s), {} tile(s), {} byte(s), {} credit stall(s), \
             {} tile(s) deferred, {delivered} message(s) reached the viewer",
            elapsed.as_secs_f64(),
            outcome.ending,
            outcome.stats.frames_sent,
            outcome.stats.tiles_sent,
            outcome.stats.bytes_sent,
            outcome.stats.credit_stalls,
            outcome.stats.tiles_deferred,
        );

        if monitors.is_empty() {
            println!("no capture on this host; nothing to measure");
            return;
        }
        assert!(outcome.stats.frames_sent > 0, "a working capture must deliver frames");
        assert!(outcome.stats.bytes_sent > u64::from(SEND_WINDOW), "and real pixels with them");
    }

    /// The transport's window must be a measurement the driver can spend, get
    /// back, and spend again — which is the whole reason a frame bigger than the
    /// window is deliverable at all.
    ///
    /// Written against a real [`Duplex`] over a real socket pair rather than
    /// against the accounting alone, because the half that was missing was the
    /// *return*: an implementation that only ever counts down passes any test of
    /// `credit()` in isolation and still delivers nothing.
    #[tokio::test]
    async fn the_send_window_is_spent_by_queued_bytes_and_returned_as_they_leave() {
        let (near, far) = tokio::io::duplex(64 * 1024);
        let (mut out, _incoming, pump) = split(Duplex::server(near, Limits::default()));
        let mut client = Duplex::client(far, Limits::default());

        assert_eq!(out.credit(), SEND_WINDOW, "a fresh link has its whole window");

        // The pump has not been polled yet, so this message is still here.
        let tile = vec![0xA5u8; 8 * 1024];
        out.send(&tile).await.expect("an empty queue takes a message");
        assert_eq!(
            out.credit(),
            SEND_WINDOW - 8 * 1024,
            "bytes waiting for the socket are bytes in flight"
        );

        // Six times the window, in messages the size of a busy tile. If the
        // window did not reopen, this would deadlock rather than fail — which is
        // why the whole test is bounded below.
        const ROUNDS: usize = 200;
        let pumping = tokio::spawn(pump);
        let reader = tokio::spawn(async move {
            let mut seen = 0usize;
            while seen < ROUNDS + 1 {
                match client.recv().await {
                    Ok(Event::Message(bytes)) => {
                        assert_eq!(bytes.len(), 8 * 1024, "a message arrived truncated");
                        seen += 1;
                    }
                    // A ping or a close is not what this test is about; anything
                    // that is not a message means the stream ended early.
                    other => panic!("the stream stopped after {seen} messages: {other:?}"),
                }
            }
            seen
        });

        for _ in 0..ROUNDS {
            out.send(&tile).await.expect("the link keeps taking messages");
        }
        let seen = tokio::time::timeout(Duration::from_secs(10), reader)
            .await
            .expect("the whole stream arrives well inside ten seconds")
            .expect("the reader finishes");
        assert_eq!(seen, ROUNDS + 1);

        // Everything has left, so the window is whole again. This is the
        // property the driver's per-tile re-read depends on.
        assert_eq!(out.credit(), SEND_WINDOW, "the window is returned in full");
        assert!(
            u64::try_from(ROUNDS + 1).expect("a small count") * 8 * 1024
                > u64::from(SEND_WINDOW),
            "the fixture must exceed the window, or this proves nothing"
        );
        drop(out);
        let _ = tokio::time::timeout(Duration::from_secs(2), pumping).await;
    }

    /// A viewer that has stopped reading must make the window read **zero**, not
    /// make the driver park inside a write.
    ///
    /// This is the security half of the flow control rather than the performance
    /// half. The driver's capture arm is the only place the operator's kill
    /// switch, the secure desktop and the agent's death are ever observed; a
    /// write that blocks until the stream's own wall suspends that arm for hours.
    /// So a queue with nothing leaving it answers zero, and the driver goes round
    /// its loop declining the frame instead.
    #[tokio::test]
    async fn a_backed_up_queue_reads_as_no_credit_rather_than_parking_the_driver() {
        let (near, _far) = tokio::io::duplex(1024);
        // The pump is never polled, so nothing ever leaves: the exact shape of a
        // viewer that has stopped reading.
        let (mut out, _incoming, _pump) = split(Duplex::server(near, Limits::default()));

        // Messages small enough that the byte window cannot possibly be what
        // runs out — sixty-four of these are a kilobyte against a 256 KiB window,
        // so a zero here can only be the queue's doing.
        let crumb = vec![0x5Au8; 16];
        for filled in 0..OUTBOUND_DEPTH {
            assert!(
                out.credit() > 0,
                "the queue still had room after {filled} of {OUTBOUND_DEPTH} messages"
            );
            out.send(&crumb).await.expect("a queue with room takes a message");
        }
        assert_eq!(out.credit(), 0, "a queue nothing is leaving grants nothing");
    }

    /// A machine that cannot capture must answer with the *reason* it reports
    /// everywhere else, rather than leaving the driver waiting on a frame that
    /// is not coming.
    ///
    /// # The case is built, not waited for
    ///
    /// This test used to open a real [`Machine`] and return early when the host
    /// had a working backend — which on the development Mac it does, so the test
    /// asserted nothing at all on the machine it ran on most. A test that is
    /// vacuous on the developer's own hardware is a test that reports green
    /// while the property rots.
    ///
    /// So the failed screen is constructed directly. That is not a weaker test:
    /// [`LocalScreen`] holding `Err(condition)` is *exactly* what
    /// [`Machine::open`] produces when the platform refuses, and it is the object
    /// the session driver actually talks to. What it stops being is
    /// host-dependent — every condition is exercised on every machine, including
    /// the ones that cannot reach that state locally, and no real capture is
    /// opened, so this test can never be the second concurrent stream of one
    /// display that macOS is entitled to refuse.
    #[tokio::test]
    async fn a_screen_that_cannot_open_answers_with_the_reason() {
        // Every reason a platform can decline, not merely the one this host
        // happens to give.
        for reason in [
            Condition::PermissionDenied,
            Condition::NoSession,
            Condition::SessionDisconnected,
            Condition::AgentExited,
            Condition::Fatal,
        ] {
            let mut screen = LocalScreen {
                screen: Err(reason),
                stopped: Arc::new(AtomicBool::new(false)),
            };
            assert!(
                screen.monitors().is_empty(),
                "a machine with no capture advertises no displays rather than inventing one"
            );
            assert_eq!(
                screen.next_frame(Duration::from_millis(1)).await.err(),
                Some(reason),
                "a screen that could not be opened must answer with the reason it failed"
            );
        }

        // And the kill switch outranks all of them, because an operator who
        // engaged it wants to be told *that*, not about a capture backend that
        // also happens to be missing.
        let mut halted = LocalScreen {
            screen: Err(Condition::PermissionDenied),
            stopped: Arc::new(AtomicBool::new(true)),
        };
        assert_eq!(
            halted.next_frame(Duration::from_millis(1)).await.err(),
            Some(Condition::Stopped)
        );

        // Finally, the tie to the real thing: on a host that cannot capture, the
        // screen [`Machine::open`] builds must report the same condition the
        // backend probe shows in `doctor`. Skipped where the host *can* capture,
        // since opening a second real stream of this display is a platform
        // refusal rather than a property of this code — but the rules above were
        // all asserted regardless.
        let backend = Backend::here();
        if !backend.wired {
            let mut screen = Machine::open(Arc::new(AtomicBool::new(false)), false).await.screen;
            assert_eq!(
                screen.next_frame(Duration::from_millis(1)).await.err(),
                Some(backend.condition),
                "an unwired backend answers a session with the condition it reports to doctor"
            );
        }
    }

    /// The property the whole default-off posture rests on, walked end to end:
    /// with `allow_input = false` there is **no route** by which an injector
    /// comes into being.
    ///
    /// It is walked rather than asserted once because wiring the agent spawn
    /// added a new route — an argument vector handed to a process running as the
    /// console user — and the previous pass's version of this property held only
    /// because that route did not exist. Each step below is a different place the
    /// answer could have been re-derived, and re-deriving it is how they come to
    /// disagree.
    #[test]
    fn a_view_only_deployment_arms_nothing_by_any_route() {
        let dir = temp_dir("view-only");
        let desktop = Desktop { enabled: true, allow_input: false, ..Desktop::default() };
        let desk = start(&config_with(Some(desktop)), &dir, None).expect("the subsystem starts");

        // 1. The deployment's own statement.
        assert!(!desk.config().allow_input);
        // 2. The value handed to the agent spawner, which is what decides the
        //    argv of a process inside somebody's session.
        assert!(
            !desk.agent.input_policy().allows(),
            "a view-only deployment must hand the spawner a view-only policy"
        );
        // 3. The banner reads back from that same value, so the two cannot
        //    disagree in the one place an operator would look.
        assert!(desk.summary().contains("input refused"), "{}", desk.summary());
        // 4. And in this process, no injector is built under any conditions.
        for stopped in [false, true] {
            for screen in [false, true] {
                assert!(
                    !injector_wanted(false, stopped, screen),
                    "view-only built an injector with stopped={stopped} screen={screen}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same predicate from the other side: an armed deployment still refuses
    /// to build an injector when the operator has revoked the desktop, or when
    /// there is no display layout to map a pointer against.
    #[test]
    fn an_armed_deployment_still_refuses_where_it_must() {
        assert!(injector_wanted(true, false, true), "armed, clear, and a screen: the one yes");
        assert!(!injector_wanted(true, true, true), "the kill switch refuses the hands too");
        assert!(
            !injector_wanted(true, false, false),
            "no capture means no display layout, and a pointer with no layout lands anywhere"
        );
    }

    /// A deployment that never asked for a desktop supervises nothing, spawns
    /// nothing and holds no policy at all — because the subsystem does not exist.
    #[test]
    fn the_default_deployment_has_no_agent_to_arm() {
        let dir = temp_dir("default-off");
        assert!(start(&config_with(None), &dir, None).is_none());
        assert!(
            start(&config_with(Some(Desktop::default())), &dir, None).is_none(),
            "the config's own default is disabled, and disabled means absent"
        );
        assert!(!Desktop::default().allow_input, "and input is off in that default as well");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A daemon that starts with the desktop already revoked must not start an
    /// agent while it waits for its first poll.
    #[test]
    fn a_daemon_that_starts_revoked_hands_the_switch_over_before_the_first_turn() {
        let dir = temp_dir("revoked-agent");
        crate::kill_switch::engage(&dir).expect("engage before anything starts");
        let desktop = Desktop { enabled: true, ..Desktop::default() };
        let desk = start(&config_with(Some(desktop)), &dir, None).expect("the subsystem starts");
        assert!(desk.stopped());
        // The agent's own status is what the console reads; on a machine that
        // supervises none it says so, and on one that does the switch was handed
        // over before the supervisor's first turn.
        let status = desk.agent.status();
        assert!(!status.live, "nothing is live under an engaged switch");
        assert!(!status.sentence.is_empty(), "and the reason is never blank");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
