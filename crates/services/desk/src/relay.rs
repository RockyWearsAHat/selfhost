//! A session whose pixels are produced by an agent process, not by this one.
//!
//! # The gap this closes
//!
//! [`crate::viewer::Viewer`] drives a session from a [`FrameSource`]: it asks for
//! raw pixels, diffs them against what the client is holding, tiles the
//! difference and writes it. That is the whole of the story on a machine whose
//! daemon can see the screen — macOS, and a Windows daemon started from a
//! signed-in session.
//!
//! On the production box the daemon is a service running as `SYSTEM` in
//! **session 0**, which has no interactive display and cannot capture the
//! console user's desktop by any method. The pixels come from an agent process
//! spawned into that session ([`crate::viewer`]'s counterpart in
//! `selfhost-screen`), and that agent does not produce raw pixels: it produces
//! an already-encoded [`Message`] stream, because it holds the model of what the
//! client is displaying and does its own diffing, tiling and damage merging.
//!
//! Two drivers therefore exist and neither is redundant. The [`Viewer`] is the
//! encoder; this is the **relay**, and the difference between them is exactly one
//! thing: where a frame comes from. Everything a session is held to — the wall,
//! the per-message capability re-check, the state machine, the kill switch, the
//! seat, the release-everything close — is the same code in both, because it is
//! the same policy and a second copy of it would be a second thing to revoke a
//! capability in.
//!
//! # The daemon does not parse what it forwards
//!
//! This is the load-bearing rule and it is why [`Upstream`] hands over bytes
//! rather than a [`Message`]. The workspace sets `panic = "abort"` for release
//! and the daemon that would do the parsing is also the reverse proxy, the
//! authoritative DNS server, the mail server, the certificate store and the
//! self-updater. A decoder in this path is a way to end all of that at a time of
//! somebody else's choosing.
//!
//! So the relay reads **one byte** — the kind — and copies the rest. That is
//! enough, because [`Message::direction`] is decidable from the kind alone, and
//! the three decisions this end has to make are all decisions about direction:
//!
//! - A kind that travels `ToAgent` must never arrive *from* the agent. That is
//!   a compromised or confused agent trying to type into the console, and it
//!   ends the stream.
//! - [`kind::HELLO`](crate::wire::kind::HELLO) is swallowed. The agent's `Hello`
//!   describes the agent; the one the client must see describes *this viewer's*
//!   effective capabilities, which the agent cannot know, and it is written by
//!   [`Relay::greet`] from the monitor list the supervisor already holds.
//! - Everything else that travels `ToViewer` is copied to the socket untouched.
//!
//! # Credit is a measurement here, not a claim
//!
//! The agent stops sending when its window is spent, and drops-and-merges rather
//! than queueing while it waits — that is what keeps a starved link showing the
//! present instead of a recording. Somebody has to return that window, and on
//! this hop the honest number is **how many bytes actually reached the socket**.
//!
//! So the relay grants the agent exactly what it has written, after it has
//! written it. [`Outbound::send`] does not return until the transport accepted
//! the bytes, so a slow console delays the grant, which stalls the agent, which
//! makes it merge — end to end, with no window invented in the middle. A middle
//! box that granted credit it could not honour would become the queue, on the
//! machine that holds every disk and every key.
//!
//! A console's own [`Message::Credit`] is deliberately **not** forwarded on top
//! of that. Two grants for one hop is double-counting, and the socket's drain is
//! a genuine measurement where the console's number is a claim.
//!
//! [`FrameSource`]: crate::viewer::FrameSource
//! [`Viewer`]: crate::viewer::Viewer

use std::fmt;
use std::time::Duration;

use tokio::time::timeout_at;

use crate::grant::{Capabilities, Redemption, SessionId};
use crate::state::{Action, Observation, Phase, Session};
use crate::viewer::{
    encode, moment, notice_detail, Ceilings, Condition, Ending, Inbound, Outbound, Outcome, Seat,
    SessionDirectory, Stats, Task, MIN_TICK,
};
use crate::viewer::{effective, input_refusal, stream_deadline};
use crate::wire::{kind, Direction, Hello, Message, Monitor, Refusal, MAX_MONITORS, PROTOCOL_VERSION};

/// How many bytes the relay will let accumulate before returning credit.
///
/// Credit is returned in batches rather than after every message because a tile
/// is a couple of kilobytes and a keyframe is fifteen hundred of them: one
/// `Credit` message per tile would put a second message on the pipe for every
/// message taken off it, and the pipe is the thing under pressure. The batch is
/// small enough that the agent's window — [`crate::viewer::DEFAULT_SEND_WINDOW`]
/// — never runs dry waiting for it, and large enough that the return traffic is
/// a rounding error against the frames it is pacing.
const CREDIT_BATCH: u64 = 64 * 1024;

/// The window this end opens the conversation with.
///
/// # A refund cannot start a stream, and this is what that cost
///
/// The agent begins life with a window of its own and spends it on whatever it
/// can see, whether or not anybody is watching — it has no idea a viewer exists.
/// By the time the first session attaches, that window is gone, and a relay that
/// only ever *refunds* what it forwards has nothing to refund: no bytes arrive,
/// so no credit is returned, so no bytes arrive. On ALEX-DESKTOP that deadlock
/// looked like a session that opened cleanly, announced a 2560x1440 display, and
/// then sent twenty-eight bytes in six seconds.
///
/// So a session *opens* a window as well as refunding one, and this is not
/// credit invented in the middle: it is the console socket's own initial
/// headroom, the same [`DEFAULT_SEND_WINDOW`] the capture path's driver is
/// bounded by, granted to the one producer now writing into it.
///
/// [`DEFAULT_SEND_WINDOW`]: crate::viewer::DEFAULT_SEND_WINDOW
const OPENING_WINDOW: u32 = crate::viewer::DEFAULT_SEND_WINDOW;

/// Where an agent's already-encoded messages come from, and where input goes.
///
/// The seam between this crate and the process that owns the pipe. Async in
/// boxed form for the same reason [`crate::viewer::FrameSource`] is: on a real
/// machine every one of these is served by a thread blocking on a platform call,
/// and a synchronous signature would stall a runtime worker that is also serving
/// 80 and 443.
///
/// # What an implementation must guarantee
///
/// [`Upstream::next_message`] returns **one whole encoded message** or a
/// [`Condition`]. Framing belongs to the implementation, because the framing is
/// the pipe's, and a relay that had to find message boundaries would be a relay
/// that parses.
pub trait Upstream: Send {
    /// The displays the agent reported, in the ids its frames use.
    ///
    /// Read at the handshake and advertised in [`Hello`]. A display appearing or
    /// disappearing arrives as [`Condition::Reinitialise`], never as a silently
    /// different slice.
    fn monitors(&self) -> &[Monitor];

    /// The next encoded message from the agent, or the state it is in instead.
    ///
    /// Waits at most `budget`. Returning [`Condition::Retry`] and simply taking
    /// the whole budget are the same answer, and a still desktop legitimately
    /// answers `Retry` for ever.
    fn next_message(&mut self, budget: Duration) -> Task<'_, Result<Vec<u8>, Condition>>;

    /// Hands one message to the agent: an input event, or a credit grant.
    ///
    /// Refusing is normal — a view-only agent has no injector at all — and a
    /// refusal is reported to the console rather than ending the stream.
    fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>>;

    /// Rebuilds the agent link after the state machine asked for it.
    ///
    /// Answers `Ok` once a *new* agent is connected. The client shares no history
    /// with it, so the relay forgets nothing on its own behalf — it holds no
    /// model of the client's surface — but it does re-request a full frame, which
    /// is the one thing the new agent cannot know.
    fn restore(&mut self) -> Task<'_, Result<(), Condition>>;
}

/// One viewer's stream, fed by an agent.
///
/// Holds the [`Seat`] for its whole life, so the concurrency ceiling is enforced
/// by construction rather than by remembering to decrement a counter on every
/// exit path — the same reason [`Viewer`](crate::viewer::Viewer) holds one.
pub struct Relay<'a> {
    outbound: &'a mut dyn Outbound,
    upstream: &'a mut dyn Upstream,
    sessions: &'a dyn SessionDirectory,
    ceilings: Ceilings,
    session: SessionId,
    granted: Capabilities,
    /// Held, never read: dropping it releases the seat.
    _seat: Seat,
    machine: Session,
    /// Bytes written to the socket that the agent has not yet been credited for.
    uncredited: u64,
    /// Set when the agent link was rebuilt and the new agent has not yet been
    /// asked for the full picture.
    pending_restore: bool,
    stats: Stats,
}

impl fmt::Debug for Relay<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Relay")
            .field("session", &self.session)
            .field("granted", &self.granted)
            .field("phase", &self.machine.phase())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<'a> Relay<'a> {
    /// Prepares a relayed stream for a redeemed ticket.
    ///
    /// Nothing happens until [`run`](Relay::run) is awaited, for the same reason
    /// [`Viewer::new`](crate::viewer::Viewer::new) defers: the session must be
    /// looked up by the act that computes the deadline from it.
    pub fn new(
        outbound: &'a mut dyn Outbound,
        upstream: &'a mut dyn Upstream,
        sessions: &'a dyn SessionDirectory,
        seat: Seat,
        redemption: &Redemption,
        ceilings: Ceilings,
    ) -> Self {
        Self {
            outbound,
            upstream,
            sessions,
            ceilings,
            session: redemption.session.clone(),
            granted: redemption.capabilities,
            _seat: seat,
            machine: Session::new(ceilings.limits),
            uncredited: 0,
            pending_restore: false,
            stats: Stats::default(),
        }
    }

    /// What this stream has done so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Drives the stream until it ends, then releases everything it was holding.
    ///
    /// The loop is [`Viewer::run`](crate::viewer::Viewer::run)'s, arm for arm and
    /// with the same bias and the same reasons — overdue work first so a peer
    /// that floods input cannot outrun the checks that revoke it, then the wall,
    /// then input, then pixels. Only the pixel arm differs.
    pub async fn run(mut self, inbound: &mut dyn Inbound) -> Outcome {
        let started = tokio::time::Instant::now();

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
        if let Err(ending) = self.open_upstream(deadline).await {
            return self.finish(ending).await;
        }

        let mut next_revalidate = started + self.ceilings.revalidate_every;
        let mut next_pump = started;

        let ending = loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break Ending::Deadline;
            }

            if now >= next_revalidate {
                self.stats.revalidations = self.stats.revalidations.saturating_add(1);
                next_revalidate = now + self.ceilings.revalidate_every.max(MIN_TICK);
                match self.standing_now() {
                    Ok(current) => live = current,
                    Err(ending) => break ending,
                }
                continue;
            }
            if now >= next_pump {
                match self.pump(live, deadline).await {
                    Ok(wait) => next_pump = tokio::time::Instant::now() + wait.max(MIN_TICK),
                    Err(ending) => break ending,
                }
                continue;
            }

            tokio::select! {
                biased;

                () = tokio::time::sleep_until(deadline) => break Ending::Deadline,

                () = tokio::time::sleep_until(next_revalidate) => {}

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

                () = tokio::time::sleep_until(next_pump) => {}
            }
        };

        self.finish(ending).await
    }

    /// Sends the opening [`Hello`], written here rather than forwarded.
    ///
    /// The agent sends a `Hello` of its own and it is the wrong one: it states
    /// what the *agent* can do, and what the client must be told is what **this
    /// viewer** may do, which depends on a ticket the agent has never seen. The
    /// monitor list is the only part that is the agent's to know, and it is the
    /// only part taken from it.
    async fn greet(
        &mut self,
        live: Capabilities,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let monitors: Vec<Monitor> =
            self.upstream.monitors().iter().take(MAX_MONITORS).copied().collect();
        let hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: self.ceilings.tile,
            max_fps: self.ceilings.max_fps.max(1),
            capabilities: live,
            monitors,
        });
        let bytes = encode(&hello)?;
        self.write(&bytes, deadline).await
    }

    /// Opens the conversation with the agent: a full picture, and a window to
    /// send it in.
    ///
    /// Both halves are needed and neither is optional.
    ///
    /// **A full frame**, because the agent holds a model of the surface *a*
    /// client is displaying and sends the difference against it — and this client
    /// has never displayed anything. Without it the first thing this console
    /// receives is the difference against somebody else's screen, which is a
    /// picture of nothing.
    ///
    /// **A window**, because the agent spends its opening credit long before a
    /// viewer arrives, and a relay that only refunds what it forwards can never
    /// start: nothing arrives, so nothing is refunded, so nothing arrives. See
    /// [`OPENING_WINDOW`].
    ///
    /// Refusals are not fatal here. An agent that has just died refuses
    /// everything, and what a dead agent means is the state machine's to decide
    /// on the next turn, not this function's.
    async fn open_upstream(&mut self, deadline: tokio::time::Instant) -> Result<(), Ending> {
        let opening = [
            Message::Credit { bytes: OPENING_WINDOW },
            Message::RequestFullFrame { monitor: 0 },
        ];
        for message in &opening {
            // The refusal is discarded and the lapse is not: a refusal means the
            // agent would not take it, which the state machine decides about on
            // its next turn, and a lapse means the wall passed while trying.
            if timeout_at(deadline, self.upstream.deliver(message)).await.is_err() {
                return Err(Ending::Deadline);
            }
        }
        Ok(())
    }

    /// Re-reads the session's standing and reports what may still be done.
    ///
    /// The one function here that talks to [`SessionDirectory`], so the rule that
    /// it must never refresh `last_seen` has exactly one call site to audit.
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

    /// One turn: take a message from the agent, tell the state machine what that
    /// was, forward it if it may be forwarded, and say how long to wait.
    async fn pump(
        &mut self,
        live: Capabilities,
        deadline: tokio::time::Instant,
    ) -> Result<Duration, Ending> {
        let budget = crate::viewer::frame_interval(self.ceilings.max_fps);
        let mut arrived = None;

        let observation = if self.pending_restore {
            match timeout_at(deadline, self.upstream.restore()).await {
                Err(_elapsed) => return Err(Ending::Deadline),
                Ok(Err(condition)) => condition.observation(),
                Ok(Ok(())) => {
                    self.pending_restore = false;
                    // The new agent holds no model of what this client is
                    // displaying, and the client is still displaying the old
                    // agent's last frame. Only a full frame reconciles the two.
                    let _ = self.upstream.deliver(&Message::RequestFullFrame { monitor: 0 }).await;
                    Observation::Retry
                }
            }
        } else {
            let until = deadline.min(tokio::time::Instant::now() + budget);
            match timeout_at(until, self.upstream.next_message(budget)).await {
                Err(_elapsed) => Observation::Retry,
                Ok(Ok(bytes)) => {
                    arrived = Some(bytes);
                    Observation::Frame
                }
                Ok(Err(condition)) => condition.observation(),
            }
        };

        let step = self.machine.observe(observation, moment());
        if let Some(notice) = step.notice {
            let detail = notice_detail(step.phase);
            let bytes = encode(&Message::Status { notice, detail })?;
            self.write(&bytes, deadline).await?;
        }

        match arrived {
            Some(bytes) => {
                if self.machine.phase() == Phase::Live && live.contains(Capabilities::VIEW) {
                    self.forward(&bytes, deadline).await?;
                }
                // Whether or not it was forwarded, the agent spent its window on
                // it, so the window is returned. Dropping a message the client
                // may not see is not a reason to stall the machine that produced
                // it.
                self.credit(bytes.len(), deadline).await?;
            }
            // **Nothing arrived, so whatever is owed is flushed.** The batch
            // exists to keep one grant from riding behind every tile; it must
            // never become a threshold that strands credit. A frame's tail is
            // almost always smaller than the batch, so without this the last few
            // kilobytes of every burst are never returned — the agent spends its
            // window down to a remainder and stops, and the picture stops with
            // the bottom four-fifths of the screen never drawn. Observed on
            // ALEX-DESKTOP as a desktop that filled its top strip and stayed
            // there.
            //
            // A quiet moment is exactly when this costs nothing: there is no
            // message to ride behind, and the agent is by definition not busy.
            None => self.flush_credit(deadline).await?,
        }

        Ok(match step.action {
            // Unlike the capture loop, this one is not pacing anything: the agent
            // paces itself against `max_fps` and this end is only as fast as the
            // pipe hands messages over. Asking again immediately is correct, and
            // the ask itself blocks for up to `budget` when nothing is there.
            Action::Capture => Duration::ZERO,
            Action::WaitThen(wait) => wait,
            Action::Suspend { poll_after } => poll_after,
            Action::Reinitialise(wait) | Action::RespawnAgent(wait) => {
                // One branch for two actions, and deliberately: on this path the
                // capture object *is* the agent process, so "rebuild the capture"
                // and "respawn the agent" name the same act.
                self.pending_restore = true;
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

    /// Copies one agent message to the client, after checking its kind — and only
    /// its kind.
    ///
    /// See the module documentation for why this reads a single byte and forwards
    /// the rest without decoding it.
    async fn forward(&mut self, bytes: &[u8], deadline: tokio::time::Instant) -> Result<(), Ending> {
        let Some(&first) = bytes.first() else {
            // A zero-length message is a framing bug in the pipe reader, not
            // something a client should be shown.
            return Ok(());
        };
        if Direction::of_kind(first) != Direction::ToViewer {
            // The agent is trying to send the console something only a console
            // may send. Nothing legitimate does this.
            return Err(Ending::WrongDirection { kind: first });
        }
        if first == kind::HELLO {
            // The agent's own greeting. `greet` already wrote the one the client
            // must act on; forwarding this one would tell the client it holds
            // capabilities no ticket granted it.
            return Ok(());
        }

        if first == kind::FRAME_END {
            self.stats.frames_sent = self.stats.frames_sent.saturating_add(1);
        } else if first == kind::TILE {
            self.stats.tiles_sent = self.stats.tiles_sent.saturating_add(1);
        }
        self.write(bytes, deadline).await
    }

    /// Returns to the agent the window the socket has actually drained.
    ///
    /// Batched: see [`CREDIT_BATCH`]. A refusal is ignored rather than fatal —
    /// an agent that has just died refuses everything, and the state machine is
    /// the thing that decides what a dead agent means.
    async fn credit(&mut self, written: usize, deadline: tokio::time::Instant) -> Result<(), Ending> {
        self.uncredited = self.uncredited.saturating_add(written as u64);
        if self.uncredited < CREDIT_BATCH {
            return Ok(());
        }
        self.flush_credit(deadline).await
    }

    /// Returns everything owed, however little that is.
    ///
    /// Called when the batch is full and again whenever nothing arrived, which is
    /// what keeps [`CREDIT_BATCH`] a batching rule rather than a minimum. See the
    /// idle arm of [`Relay::pump`] for what treating it as a minimum cost.
    async fn flush_credit(&mut self, deadline: tokio::time::Instant) -> Result<(), Ending> {
        if self.uncredited == 0 {
            return Ok(());
        }
        let grant = u32::try_from(self.uncredited).unwrap_or(u32::MAX);
        self.uncredited = 0;
        if timeout_at(deadline, self.upstream.deliver(&Message::Credit { bytes: grant }))
            .await
            .is_err()
        {
            return Err(Ending::Deadline);
        }
        Ok(())
    }

    /// Reads one message from the console and acts on it.
    ///
    /// This direction **is** decoded, and the asymmetry is the point: these bytes
    /// come from a client and are the ones an authorisation decision is made
    /// about, so they have to be understood. They are also small, fixed-shape and
    /// bounded, where the agent's are megabytes of pixels.
    async fn receive(
        &mut self,
        bytes: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let message = Message::decode(bytes).map_err(Ending::PeerMisbehaved)?;
        if message.direction() != Direction::ToAgent {
            return Err(Ending::WrongDirection { kind: message.kind() });
        }

        match &message {
            // Never refused, at any capability, in any phase: it only ever
            // undoes. A refused release is a modifier left held on somebody
            // else's machine.
            Message::ReleaseAll => {
                let _ = timeout_at(deadline, self.upstream.deliver(&message)).await;
                Ok(())
            }

            // Passed through: the client has lost its picture and only the agent
            // can rebuild it, because only the agent knows what it last sent.
            Message::RequestFullFrame { .. } => {
                let _ = timeout_at(deadline, self.upstream.deliver(&message)).await;
                Ok(())
            }

            // Swallowed rather than forwarded. On this hop the window is the
            // socket's own drain, which `credit` measures; forwarding this as
            // well would grant the agent the same headroom twice.
            Message::Credit { .. } => Ok(()),

            Message::Key { .. }
            | Message::Text { .. }
            | Message::PointerMove { .. }
            | Message::Button { .. }
            | Message::Scroll { .. } => self.drive(&message, deadline).await,

            // Unreachable: every remaining kind travels `ToViewer` and was
            // refused above. A refusal rather than an `unreachable!` because this
            // process aborts on panic, and a wrong match arm must cost a session
            // rather than the box.
            _ => Err(Ending::WrongDirection { kind: message.kind() }),
        }
    }

    /// Authorises one input message and, if it passes, hands it to the agent.
    ///
    /// Re-derived from the directory on **every** message, exactly as
    /// [`Viewer`](crate::viewer::Viewer) does: a capability revoked in the
    /// console is felt by the very next keystroke, not by the next reconnect.
    async fn drive(
        &mut self,
        message: &Message,
        deadline: tokio::time::Instant,
    ) -> Result<(), Ending> {
        let live = self.standing_now()?;
        if let Some(reason) = input_refusal(live, self.ceilings.allow_input, self.machine.phase()) {
            self.stats.inputs_refused = self.stats.inputs_refused.saturating_add(1);
            let bytes = encode(&Message::InputRefused { reason })?;
            return self.write(&bytes, deadline).await;
        }

        match timeout_at(deadline, self.upstream.deliver(message)).await {
            Err(_elapsed) => Err(Ending::Deadline),
            Ok(Ok(())) => {
                self.stats.inputs_delivered = self.stats.inputs_delivered.saturating_add(1);
                Ok(())
            }
            Ok(Err(reason)) => {
                self.stats.inputs_refused = self.stats.inputs_refused.saturating_add(1);
                let bytes = encode(&Message::InputRefused { reason })?;
                self.write(&bytes, deadline).await
            }
        }
    }

    /// Writes bytes, bounded by the wall.
    ///
    /// The bound is what makes the deadline a deadline: a peer that stops reading
    /// would otherwise hold a write open indefinitely and keep a dead session's
    /// stream alive by doing nothing at all.
    async fn write(&mut self, bytes: &[u8], deadline: tokio::time::Instant) -> Result<(), Ending> {
        match timeout_at(deadline, self.outbound.send(bytes)).await {
            Err(_elapsed) => Err(Ending::Deadline),
            Ok(Err(error)) => Err(Ending::Transport(error)),
            Ok(Ok(())) => {
                self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(bytes.len() as u64);
                Ok(())
            }
        }
    }

    /// The close sequence: release, tell, hang up — all inside one grace period,
    /// and none of it waiting for the peer.
    ///
    /// The release is a single [`Message::ReleaseAll`] to the agent rather than a
    /// replay of tracked keys, because on this path the agent is what holds them:
    /// it performed every injection and it knows what is still down. It releases
    /// on its own when the pipe closes too, so this is the fast path rather than
    /// the only one.
    async fn finish(self, ending: Ending) -> Outcome {
        let grace = tokio::time::Instant::now() + self.ceilings.close_grace;
        let _ = timeout_at(grace, async {
            let _ = self.upstream.deliver(&Message::ReleaseAll).await;
            if ending.peer_is_listening() {
                let status = Message::Status {
                    notice: self.machine.phase().notice(),
                    detail: ending.to_string(),
                };
                if let Ok(bytes) = status.encode() {
                    let _ = self.outbound.send(&bytes).await;
                }
                let _ = self.outbound.close(&ending).await;
            }
        })
        .await;

        Outcome { ending, stats: self.stats }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::SessionId;
    use crate::state::Limits;
    use crate::tiles::TileSize;
    use crate::viewer::{Gate, Standing, StreamError};
    use crate::keys::Usage;
    use crate::state::Notice;
    use crate::wire::FrameBegin;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// An upstream that hands over a scripted list of encoded messages.
    #[derive(Default)]
    struct FakeAgent {
        monitors: Vec<Monitor>,
        script: Vec<Result<Vec<u8>, Condition>>,
        /// Everything the relay handed back towards the agent.
        delivered: Arc<Mutex<Vec<Message>>>,
        /// What `deliver` answers.
        refuse: Option<Refusal>,
        restores: usize,
    }

    impl FakeAgent {
        fn with(script: Vec<Result<Vec<u8>, Condition>>) -> Self {
            Self {
                monitors: vec![Monitor {
                    id: 0,
                    origin_x: 0,
                    origin_y: 0,
                    width: 1920,
                    height: 1080,
                    scale_permille: 1000,
                    primary: true,
                }],
                script,
                ..Self::default()
            }
        }
    }

    impl Upstream for FakeAgent {
        fn monitors(&self) -> &[Monitor] {
            &self.monitors
        }

        fn next_message(&mut self, _budget: Duration) -> Task<'_, Result<Vec<u8>, Condition>> {
            let next = if self.script.is_empty() {
                Err(Condition::Retry)
            } else {
                self.script.remove(0)
            };
            Box::pin(async move { next })
        }

        fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>> {
            self.delivered.lock().expect("not poisoned").push(message.clone());
            let refuse = self.refuse;
            Box::pin(async move { refuse.map_or(Ok(()), Err) })
        }

        fn restore(&mut self) -> Task<'_, Result<(), Condition>> {
            self.restores += 1;
            Box::pin(async move { Ok(()) })
        }
    }

    /// Collects everything written towards the console.
    #[derive(Default)]
    struct Recorder {
        written: Arc<Mutex<Vec<Vec<u8>>>>,
        closed: Arc<Mutex<Option<Ending>>>,
    }

    impl Outbound for Recorder {
        fn send<'a>(&'a mut self, frame: &'a [u8]) -> Task<'a, Result<(), StreamError>> {
            self.written.lock().expect("not poisoned").push(frame.to_vec());
            Box::pin(async { Ok(()) })
        }

        /// Always roomy: this recorder is the socket, and it never backs up. The
        /// relay does not consult it — its flow control is what it has actually
        /// written — so a real number here would only look like it mattered.
        fn credit(&self) -> u32 {
            u32::MAX
        }

        fn close<'a>(&'a mut self, ending: &'a Ending) -> Task<'a, Result<(), StreamError>> {
            *self.closed.lock().expect("not poisoned") = Some(ending.clone());
            Box::pin(async { Ok(()) })
        }
    }

    /// A console that sends a scripted list of messages.
    ///
    /// Two endings, and which one a test wants is the whole reason this is
    /// configurable: `hangs_up` makes the console close once its script is spent,
    /// which is how a test ends a stream *from the console side*; a silent one
    /// never resolves, which leaves the agent's script the only thing that can
    /// end the stream. A console that returned `None` when it merely had nothing
    /// to say would end every stream on its first idle moment, and every test of
    /// an agent-side ending would silently be a test of `PeerClosed`.
    struct FakeConsole {
        script: Vec<Vec<u8>>,
        hangs_up: bool,
    }

    impl FakeConsole {
        /// Sends nothing, ever, and never hangs up.
        fn silent() -> Self {
            Self { script: Vec::new(), hangs_up: false }
        }

        /// Sends these, then closes.
        fn sends(script: Vec<Vec<u8>>) -> Self {
            Self { script, hangs_up: true }
        }
    }

    impl Inbound for FakeConsole {
        fn recv<'a>(&'a mut self) -> Task<'a, Result<Option<Vec<u8>>, StreamError>> {
            if !self.script.is_empty() {
                let next = self.script.remove(0);
                return Box::pin(async move { Ok(Some(next)) });
            }
            if self.hangs_up {
                return Box::pin(async { Ok(None) });
            }
            Box::pin(std::future::pending())
        }
    }

    /// A directory holding one standing that the test can rewrite.
    struct Directory(Mutex<Option<Standing>>);

    impl SessionDirectory for Directory {
        fn standing(&self, _session: &SessionId) -> Option<Standing> {
            *self.0.lock().expect("not poisoned")
        }
    }

    fn ceilings() -> Ceilings {
        Ceilings {
            max_fps: 30,
            max_session: Duration::from_secs(60),
            tile: TileSize::DEFAULT,
            allow_input: true,
            revalidate_every: Duration::from_secs(30),
            close_grace: Duration::from_secs(1),
            limits: Limits::default(),
            cursor_cache: 8,
        }
    }

    fn redemption(capabilities: Capabilities) -> Redemption {
        Redemption { session: SessionId::new("s"), capabilities, peer: "self".into() }
    }

    fn granted(capabilities: Capabilities) -> Directory {
        Directory(Mutex::new(Some(Standing {
            capabilities,
            expires: Instant::now() + Duration::from_secs(3600),
        })))
    }

    fn frame_bytes() -> Vec<u8> {
        Message::FrameBegin(FrameBegin {
            monitor: 0,
            sequence: 1,
            width: 1920,
            height: 1080,
            keyframe: true,
        })
        .encode()
        .expect("encodes")
    }

    /// The relay writes its own `Hello`, not the agent's.
    ///
    /// The defect this pins: forwarding the agent's greeting tells the console it
    /// holds whatever the agent holds, which is every capability the deployment
    /// allows rather than the ones this ticket was granted.
    #[tokio::test]
    async fn the_hello_the_console_sees_states_this_tickets_capabilities() {
        let agent_hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: TileSize::DEFAULT,
            max_fps: 60,
            capabilities: Capabilities::VIEW.with(Capabilities::CONTROL).with(Capabilities::CLIPBOARD),
            monitors: Vec::new(),
        })
        .encode()
        .expect("encodes");

        let mut agent = FakeAgent::with(vec![Ok(agent_hello), Err(Condition::Stopped)]);
        let mut out = Recorder::default();
        let written = Arc::clone(&out.written);
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let _ = relay.run(&mut FakeConsole::silent()).await;

        let frames = written.lock().expect("not poisoned");
        let first = Message::decode(&frames[0]).expect("decodes");
        let Message::Hello(hello) = first else { panic!("the first message is a Hello") };
        assert_eq!(hello.capabilities, Capabilities::VIEW, "the ticket's capabilities, not the agent's");
        assert_eq!(hello.max_fps, 30, "the deployment's ceiling, not the agent's");
        assert_eq!(hello.monitors.len(), 1, "the agent's monitor list is the one part taken from it");

        // And the agent's own Hello never reached the console.
        let hellos = frames
            .iter()
            .filter(|frame| frame.first() == Some(&kind::HELLO))
            .count();
        assert_eq!(hellos, 1, "exactly the one this end wrote");
    }

    /// A frame from the agent reaches the console byte for byte.
    #[tokio::test]
    async fn a_frame_crosses_without_being_re_encoded() {
        let frame = frame_bytes();
        let mut agent = FakeAgent::with(vec![Ok(frame.clone()), Err(Condition::Stopped)]);
        let mut out = Recorder::default();
        let written = Arc::clone(&out.written);
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::silent()).await;

        let frames = written.lock().expect("not poisoned");
        assert!(frames.contains(&frame), "the agent's bytes, unchanged");
        assert_eq!(outcome.ending, Ending::Stopped, "the kill switch ended it");
    }

    /// An agent that sends a console-only message ends the stream.
    ///
    /// The defect this pins: a compromised agent typing into the console. The
    /// check is one byte and it is the only thing standing between the two
    /// directions.
    #[tokio::test]
    async fn an_agent_that_sends_input_ends_the_stream() {
        let typed = Message::Key { usage: Usage::from_hid(0x04).expect("a"), down: true }
            .encode()
            .expect("encodes");
        let mut agent = FakeAgent::with(vec![Ok(typed)]);
        let mut out = Recorder::default();
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::silent()).await;

        assert_eq!(
            outcome.ending,
            Ending::WrongDirection { kind: kind::KEY },
            "an agent may not send what only a console may send"
        );
    }

    /// Input is refused when the ticket carries no control, and the refusal is
    /// reported rather than silently dropped.
    #[tokio::test]
    async fn a_view_only_ticket_cannot_drive() {
        let key = Message::Key { usage: Usage::from_hid(0x04).expect("a"), down: true }
            .encode()
            .expect("encodes");
        // A frame first: input is refused outright until the session is live, so
        // a test that skipped this would pass on the wrong reason.
        let mut agent = FakeAgent::with(vec![Ok(frame_bytes())]);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let written = Arc::clone(&out.written);
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::sends(vec![key])).await;

        assert_eq!(outcome.stats.inputs_refused, 1, "refused");
        assert_eq!(outcome.stats.inputs_delivered, 0, "and not delivered");
        let refusals = written
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|frame| frame.first() == Some(&kind::INPUT_REFUSED))
            .count();
        assert_eq!(refusals, 1, "the console is told why");
        assert!(
            handed
                .lock()
                .expect("not poisoned")
                .iter()
                .any(|message| matches!(message, Message::RequestFullFrame { .. })),
            "and the stream still opened by asking for a whole picture"
        );
        let keys = handed
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|message| matches!(message, Message::Key { .. }))
            .count();
        assert_eq!(keys, 0, "nothing reached the agent");
    }

    /// A control ticket's keystroke reaches the agent.
    #[tokio::test]
    async fn a_control_ticket_drives_the_agent() {
        let key = Message::Key { usage: Usage::from_hid(0x04).expect("a"), down: true }
            .encode()
            .expect("encodes");
        let mut agent = FakeAgent::with(vec![Ok(frame_bytes())]);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let directory = granted(Capabilities::VIEW.with(Capabilities::CONTROL));
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW.with(Capabilities::CONTROL)),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::sends(vec![key])).await;

        assert_eq!(outcome.stats.inputs_delivered, 1, "delivered");
        let keys = handed
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|message| matches!(message, Message::Key { .. }))
            .count();
        assert_eq!(keys, 1, "exactly one keystroke crossed");
    }

    /// The close path releases whatever the agent is still holding.
    #[tokio::test]
    async fn the_close_releases_everything_on_the_far_machine() {
        let mut agent = FakeAgent::with(vec![Err(Condition::Stopped)]);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let closed = Arc::clone(&out.closed);
        let directory = granted(Capabilities::VIEW.with(Capabilities::CONTROL));
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW.with(Capabilities::CONTROL)),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::silent()).await;

        assert_eq!(outcome.ending, Ending::Stopped);
        assert!(
            handed.lock().expect("not poisoned").iter().any(|m| matches!(m, Message::ReleaseAll)),
            "the agent is told to let go"
        );
        assert_eq!(closed.lock().expect("not poisoned").as_ref(), Some(&Ending::Stopped));
    }

    /// A session that disappears mid-stream ends the stream at the next check.
    #[tokio::test]
    async fn a_revoked_session_ends_the_stream() {
        let mut agent = FakeAgent::with(Vec::new());
        let mut out = Recorder::default();
        let directory = Directory(Mutex::new(None));
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let outcome = relay.run(&mut FakeConsole::silent()).await;

        assert_eq!(outcome.ending, Ending::SessionGone);
    }

    /// Credit is returned to the agent once enough bytes have actually reached
    /// the socket, and not before.
    ///
    /// The defect this pins: an agent whose window is never returned stops
    /// sending after its first window and the picture freezes with no error
    /// anywhere.
    #[tokio::test]
    async fn the_agent_gets_its_window_back_as_the_socket_drains() {
        // One message just over the batch, so exactly one grant is due.
        let big = Message::Status { notice: Notice::Live, detail: "x".repeat(200) }
            .encode()
            .expect("encodes");
        let repeats = (CREDIT_BATCH as usize / big.len()) + 1;
        let mut script: Vec<Result<Vec<u8>, Condition>> =
            std::iter::repeat_with(|| Ok(big.clone())).take(repeats).collect();
        script.push(Err(Condition::Stopped));

        let mut agent = FakeAgent::with(script);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let _ = relay.run(&mut FakeConsole::silent()).await;

        let grants: Vec<u32> = handed
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|message| match message {
                Message::Credit { bytes } => Some(*bytes),
                _ => None,
            })
            .collect();
        // The first is the window this end opened the conversation with; the
        // second is the refund, and only the refund is what this test is about.
        assert_eq!(grants.first(), Some(&OPENING_WINDOW), "the opening window comes first");
        let refunds = &grants[1..];
        assert_eq!(refunds.len(), 1, "one batch, once the batch was full: {grants:?}");
        assert!(refunds[0] >= CREDIT_BATCH as u32, "and it returns what was written: {grants:?}");
    }

    /// A remainder smaller than the batch is still returned.
    ///
    /// The defect this pins: the batch was acting as a *minimum*, so the tail of
    /// every burst — which is nearly always under 64 KiB — was never granted
    /// back. The agent spent its window down to a remainder and stopped, and on
    /// ALEX-DESKTOP that looked like a desktop that drew its top strip and then
    /// nothing at all.
    #[tokio::test]
    async fn a_remainder_under_the_batch_is_returned_when_the_agent_goes_quiet() {
        // One small message, then silence, then the kill switch to end it.
        let small = Message::Status { notice: Notice::Live, detail: "x".into() }
            .encode()
            .expect("encodes");
        assert!((small.len() as u64) < CREDIT_BATCH, "the point of the test");
        let mut agent = FakeAgent::with(vec![
            Ok(small.clone()),
            Err(Condition::Retry),
            Err(Condition::Stopped),
        ]);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let _ = relay.run(&mut FakeConsole::silent()).await;

        let grants: Vec<u32> = handed
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|message| match message {
                Message::Credit { bytes } => Some(*bytes),
                _ => None,
            })
            .collect();
        assert_eq!(grants.first(), Some(&OPENING_WINDOW), "the opening window");
        assert_eq!(
            grants.get(1),
            Some(&(small.len() as u32)),
            "and the remainder, exactly, once the agent went quiet: {grants:?}"
        );
    }

    /// A console's own credit grant is not passed on.
    ///
    /// Two grants for one hop is double-counting, and the one that is a
    /// measurement wins over the one that is a claim.
    #[tokio::test]
    async fn a_consoles_credit_is_not_forwarded_to_the_agent() {
        let grant = Message::Credit { bytes: 1 << 20 }.encode().expect("encodes");
        let mut agent = FakeAgent::with(vec![Err(Condition::Retry)]);
        let handed = Arc::clone(&agent.delivered);
        let mut out = Recorder::default();
        let directory = granted(Capabilities::VIEW);
        let gate = Gate::new(2);

        let relay = Relay::new(
            &mut out,
            &mut agent,
            &directory,
            gate.admit("self").expect("a seat"),
            &redemption(Capabilities::VIEW),
            ceilings(),
        );
        let _ = relay.run(&mut FakeConsole::sends(vec![grant])).await;

        let grants: Vec<u32> = handed
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|message| match message {
                Message::Credit { bytes } => Some(*bytes),
                _ => None,
            })
            .collect();
        // The opening window, and nothing else: the console claimed a megabyte
        // and not one byte of that claim reached the agent.
        assert_eq!(grants, vec![OPENING_WINDOW], "only this end's own window: {grants:?}");
    }
}
