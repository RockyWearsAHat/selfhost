//! The seam where a route stops answering requests and starts owning a socket.
//!
//! [`Api::handle`](crate::Api::handle) turns a request into a response and
//! touches no sockets. That property is the reason every route in this crate —
//! including every way of getting authorisation wrong — is tested by
//! constructing a `Request` and reading a `Response`, and it is not negotiable.
//! A stream cannot be expressed that way: after the `101` there is no response,
//! there is a connection, and it lives for hours.
//!
//! So the split is drawn here rather than inside `handle`. The socket layer asks
//! [`crate::Api::upgrade_for`] — a pure function over the request head — whether
//! this caller may have a stream, and only if the answer is yes does it hand the
//! socket over to one of the loops in this module. Everything that *decides* is
//! still pure and still tested without a port; everything that *moves bytes*
//! lives in this file and is tested here against `tokio::io::duplex`. Nothing in
//! this crate binds an address it did not already bind.
//!
//! The pipe is not the whole story, and pretending it was is how a duplicated
//! handshake survived three thousand tests. `tests/wire.rs` binds a loopback
//! port, speaks a real handshake and asserts on the bytes that come back; the
//! duplex tests below cover the loop, and that file covers the wire.
//!
//! # What a stream owes that a request does not
//!
//! A request is answered and forgotten. A stream is a standing authorisation,
//! and three things follow from that, all of them implemented below:
//!
//! - **Its credential can go stale while it is open.** A session expires after
//!   two idle hours precisely so that a console left open on an unlocked machine
//!   stops being a way in; a stream that ignored that would be the exception
//!   that erases the rule. So the loop re-checks, every minute, with
//!   [`Sessions::authenticated`](crate::Sessions::authenticated) and **never**
//!   `Sessions::validate` — `validate` refreshes the idle timer, and a stream
//!   re-validating on a timer would keep its own session alive for ever, which
//!   is the opposite of the check. When the check fails the stream is **ended**,
//!   not asked to end; see [`CLOSE_GRACE`].
//! - **Its liveness is nobody else's job.** The proxy's head and idle timeouts
//!   both stop at the end of a request head, and after an upgrade it is moving
//!   opaque bytes with no deadline at all. A half-open tunnel — a slept laptop,
//!   a forgetful NAT — looks exactly like a quiet one from here. `selfhost_ws`
//!   pings and enforces the pong deadline; this module simply must not defeat it
//!   by parking the task somewhere the deadlines cannot fire.
//! - **It has a hard end.** `Limits::max_lifetime` closes it whatever else is
//!   true, so no bug in the checks above can produce an immortal connection.
//!
//! # One handshake, written in one place
//!
//! [`Upgraded`] is the only value in this crate that names a connection which
//! has stopped being HTTP, and [`Upgraded::answer`] is the only function that
//! writes a `101`. That is not tidiness either: this route layer once wrote the
//! handshake response twice on the desktop path — once generically for every
//! stream and once again inside the desktop arm — and two complete `HTTP/1.1
//! 101 Switching Protocols` heads back to back is not a cosmetic duplicate. The
//! second head *is* the first thing the client reads as frame data: its leading
//! `H` is `0x48`, so RSV1 is set and the opcode is `8`, and every RFC 6455
//! client in existence — including this repository's own native console —
//! closes the connection on it. The stream was therefore dead on arrival for
//! every viewer, on every platform.
//!
//! Deleting the second write would have fixed that afternoon and nothing else,
//! because the next route added would have been written the same way. So the
//! write is gone from the routes entirely: a route cannot be *handed* a
//! connection until the handshake has been answered, because answering it is
//! what produces the [`Upgraded`] the route takes. There is one head-writing
//! call site, it consumes the raw stream, and it hands back something that is
//! no longer a raw stream. This is the same shape the two duplicated upgrade
//! sniffs were collapsed into: one definition, and no way to spell it twice.
//!
//! What differs between the two kinds of stream this daemon serves is *who* the
//! `101` is written for, and that is the [`Answering`] parameter rather than a
//! second function. A console stream is authorised **before** the handshake is
//! answered, by a redeemed ticket, so it answers from an [`Admission`]. A peer
//! link's credential does not exist yet at that moment — a worker proves its
//! enrolment in the first frame *after* the `101`, against the very handshake
//! key that head was derived from — so it answers from a [`PeerKey`]. Both go
//! through the same door.
//!
//! # The shape, and why it is two tasks rather than one `select!`
//!
//! `Duplex::recv` is documented as not cancel-safe: a `select!` that drops it
//! mid-read loses whatever that read had not yet returned. It is meant to be
//! owned by a task that loops on it, and that is where the pings and all three
//! deadlines live. So the reader loop owns the stream and does nothing else, and
//! everything that *produces* — the snapshot sweep, the credential re-check —
//! runs in a second task holding a cloneable `Sender` whose queue is bounded, so
//! a producer faster than the socket feels backpressure here rather than by
//! growing a queue until the box runs out of memory.

use crate::upgrade::{Admission, Holder};
use crate::Api;
use selfhost_json::Json;
use selfhost_ws::{Closed, Duplex, Event, Limits, Sender, StreamError, handshake};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// How often a live stream re-reads the daemon's own state looking for a change.
///
/// The supervisor has no change notification to subscribe to, so "push whenever
/// it changes" is implemented as a cheap in-process comparison on a fast timer.
/// The distinction that matters is that the *wire* is silent unless something
/// actually changed: the console's old 500 ms poll cost a TCP connection, a
/// relay hop, three JSON responses and a render every half second whether or not
/// anything had happened, and this costs one clone of a small structure and a
/// string comparison, inside the process that already owns the data.
///
/// A hundred milliseconds is chosen so that a `selfhost service restart` typed
/// in a terminal reaches the plate within about a tenth of a second, which reads
/// to a human as *immediately*. Replacing the sweep with a notification from the
/// supervisor is the right end state and is written down in the report rather
/// than pretended away.
const SWEEP: Duration = Duration::from_millis(100);

/// How often a live stream re-checks that its credential is still good.
///
/// A minute is short enough that a revoked session loses its stream while the
/// operator is still watching, and long enough that the check is free.
const CREDENTIAL_RECHECK: Duration = Duration::from_secs(60);

/// The two deadlines a standing authorisation is kept honest by.
///
/// A parameter rather than a pair of constants read where they are used, for the
/// same reason `Sessions::with_expiry` and `Tickets::with_lifetime` exist: the
/// properties worth asserting here are "a stream whose session ended is closed"
/// and "closed by this end, on this end's schedule", and a test that had to wait
/// a real minute to assert either would be a test nobody runs. Production goes
/// through [`Watch::default`], which is the constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    /// How often the credential that opened the stream is re-checked.
    pub credential_recheck: Duration,
    /// How long the peer is given to acknowledge a server-decided close before
    /// the connection is dropped underneath it. See [`CLOSE_GRACE`].
    pub close_grace: Duration,
}

impl Default for Watch {
    fn default() -> Self {
        Self { credential_recheck: CREDENTIAL_RECHECK, close_grace: CLOSE_GRACE }
    }
}

/// The `1008 Policy Violation` reason sent when a stream's credential goes away
/// underneath it. Named so the console can show the same words the daemon logged.
const CREDENTIAL_GONE: &str = "the session that opened this stream has ended";

/// How long a peer is given to acknowledge a close the *server* decided on
/// before the connection is dropped underneath it.
///
/// # Why a deadline rather than a request
///
/// `Sender::close` queues a close frame; `Duplex::recv` writes it and carries on
/// reading, and having sent a close it stops sending pings — so from that moment
/// the only liveness check left is a pong deadline measured from the last byte
/// the *peer* sent, and the peer decides that. A client that answers nothing but
/// the occasional pong therefore holds the socket, both tasks and the connection
/// open until `Limits::max_lifetime`, which is twelve hours in production. That
/// makes "a stream whose session has ended is closed" a request the peer may
/// decline, which is not what the sentence says and not what a revoked session
/// is owed.
///
/// So the server keeps the decision. Once the producer has queued the close,
/// this is how long the reader is allowed to keep going — enough for the frame
/// to reach the wire and for a well-behaved peer to answer, and no longer. When
/// it elapses the stream is dropped, which closes the socket whatever the peer
/// would have preferred.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The `1003` reason sent to a client that speaks on a route that only listens.
const ONE_WAY: &str = "this stream is one-way";

/// An upgraded connection with bytes already read off it.
///
/// # The stranding trap
///
/// The reader that parsed the request head almost certainly read past it: a
/// small body — and the first frame after a handshake — arrives in the same TCP
/// segment as the headers far more often than not. Those bytes are in this
/// process, and the socket has nothing more to give until the peer sends again,
/// which a peer waiting for an answer never does.
///
/// `crates/proxy/src/server.rs` documents this trap for request bodies, and it
/// applies again, twice, after an upgrade — once for what the client already
/// sent to the proxy, and once here for what reached this listener. Handing the
/// bare socket to the frame codec and dropping the buffered prefix means a
/// stream that deadlocks on its first message, and no timeout will explain it:
/// the pong deadline will fire, forty-five seconds later, and report a peer that
/// is not answering when the truth is that we ate what it said.
///
/// So the prefix is not dropped. It is delivered first, in order, and only when
/// it is exhausted does a read reach the socket underneath.
pub struct Prefixed<S> {
    /// Bytes read before the hand-over, delivered before any from `inner`.
    prefix: Vec<u8>,
    /// How much of `prefix` has been handed out.
    at: usize,
    /// The connection itself.
    inner: S,
}

impl<S> Prefixed<S> {
    /// Wraps `inner`, delivering `prefix` before anything the socket produces.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at < this.prefix.len() {
            let available = &this.prefix[this.at..];
            let taken = available.len().min(buf.remaining());
            buf.put_slice(&available[..taken]);
            this.at += taken;
            if this.at == this.prefix.len() {
                // Released rather than kept: the prefix is at most one read's
                // worth, but a stream lives for hours and there is no reason to
                // hold it for all of them.
                this.prefix = Vec::new();
                this.at = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Whoever a `101 Switching Protocols` is being written for, and the head they
/// are owed.
///
/// The one abstraction [`Upgraded::answer`] is generic over, and the reason
/// there is a single handshake writer rather than one per route. See the module
/// note: the two kinds of stream this daemon serves differ only in *what the
/// accept value is derived from*, and expressing that as an implementation of
/// this trait is what keeps the difference from becoming a second copy of the
/// write.
///
/// Every head is serialised by `selfhost_ws::handshake::response_head` rather
/// than through [`crate::Api`]'s ordinary response path, for the same reason the
/// proxy forwards it verbatim: the general path derives framing from a body this
/// response does not have, and the proxy splices security headers into anything
/// it writes as a response — fields that mean nothing to a connection that has
/// stopped being HTTP, in a message a browser checks strictly before it hands
/// the socket to the page.
pub trait Answering {
    /// The complete `101` head, blank line included.
    ///
    /// An error here is a header that could not be serialised, which for values
    /// this server chose cannot happen — and is reported rather than swallowed
    /// anyway, because a handshake that half-wrote is a connection nobody can
    /// diagnose from either end.
    fn response_head(&self) -> io::Result<Vec<u8>>;
}

impl Answering for Admission {
    /// The head that answers a ticketed console handshake.
    ///
    /// The subprotocol comes from [`Admission`], which only ever carries a token
    /// this server chose from a fixed list; the header layer's CR/LF check
    /// stands behind that anyway.
    fn response_head(&self) -> io::Result<Vec<u8>> {
        handshake::response_head(&self.accept, self.subprotocol.as_deref()).map_err(into_io)
    }
}

/// The `Sec-WebSocket-Key` a peer link's handshake carried.
///
/// # Why the key survives the handshake, when nothing else does
///
/// A worker's credential is not presented in the request head. It arrives in the
/// first frame after the `101`, as an HMAC over — among other things — this key
/// and the `Sec-WebSocket-Accept` derived from it. That binding is what makes a
/// captured proof worthless on any connection but the one it was computed for,
/// so the key has to outlive the head it was read from and reach
/// `selfhost_mesh::accept::admit`, which recomputes the accept value from it
/// rather than being handed both and risking a mismatched pair.
///
/// It is not a secret: RFC 6455 sends it in the clear, and a proxy may log it.
/// It is a *nonce*, and the replay ledger on the other side of the admission is
/// what makes a repeat of one worthless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey(String);

impl PeerKey {
    /// The key from a handshake `selfhost_ws` has already validated.
    pub fn new(key: &str) -> Self {
        Self(key.to_owned())
    }

    /// The key itself, for the proof that binds to it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Answering for PeerKey {
    /// The head that answers a peer link's handshake.
    ///
    /// No subprotocol is echoed, because the dialler offers none: a link is one
    /// protocol with a version in its greeting, negotiated by the mux layer
    /// rather than by a header, and echoing a token nobody offered is a protocol
    /// error on this side.
    fn response_head(&self) -> io::Result<Vec<u8>> {
        handshake::response_head(&selfhost_ws::accept_key(&self.0), None).map_err(into_io)
    }
}

/// Reports a header that could not be serialised as an I/O failure.
fn into_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// A connection whose handshake has been answered — exactly once, here.
///
/// # What this type is for
///
/// It is the only thing a stream route is given, and the only way to obtain one
/// is [`Upgraded::answer`], which consumes the raw stream and writes the `101`.
/// A route therefore cannot be reached before the handshake is answered, and
/// cannot answer it a second time, because it never holds the thing a second
/// answer would be written to. That is the whole point; see the module note for
/// the bug that made it necessary.
///
/// `W` is whoever the handshake was answered for — an [`Admission`] for a
/// console stream, a [`PeerKey`] for a peer link — so a loop that needs one
/// cannot be handed the other, and the check is the compiler's rather than a
/// `match` arm somebody has to remember to write.
pub struct Upgraded<S, W> {
    /// The connection, with whatever arrived alongside the request head
    /// delivered before anything the socket produces. See [`Prefixed`].
    io: Prefixed<S>,
    /// Whoever the `101` was written for.
    whom: W,
}

impl<S, W> Upgraded<S, W>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: Answering,
{
    /// Writes the `101` and hands back the upgraded connection.
    ///
    /// `leftover` is everything the request-head reader took past the blank
    /// line; it is delivered before the socket rather than dropped, which is the
    /// difference between a stream that works and one that deadlocks on its
    /// first message with no error anywhere to explain it — see [`Prefixed`].
    pub async fn answer(mut stream: S, leftover: Vec<u8>, whom: W) -> io::Result<Self> {
        let head = whom.response_head()?;
        stream.write_all(&head).await?;
        stream.flush().await?;
        Ok(Self { io: Prefixed::new(leftover, stream), whom })
    }

    /// Whoever the handshake was answered for, for a log line taken before the
    /// stream is consumed.
    pub fn whom(&self) -> &W {
        &self.whom
    }

    /// The connection and the credential it was opened on, for the loop that
    /// will now drive them.
    pub fn into_parts(self) -> (Prefixed<S>, W) {
        (self.io, self.whom)
    }
}

impl<S, W: std::fmt::Debug> std::fmt::Debug for Upgraded<S, W> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Upgraded").field("whom", &self.whom).finish_non_exhaustive()
    }
}

/// The console's live snapshot, in the shape the SPA already knows how to draw.
///
/// `services` is the very array `GET /api/services` puts under its `services`
/// key, and `firewall` is the whole body `GET /api/firewall` answers with, so
/// the console renders a pushed snapshot with the renderers it already has and a
/// stream and a poll cannot disagree about what the machine looks like. A daemon
/// with no firewall backend sends `null`, which is the same absence a `404`
/// means on the REST route; the console hides that panel either way.
///
/// `kind` is present so a later message on this stream — a log line, a desktop
/// tile — can be told apart without guessing from shape, and so a console that
/// meets a kind it does not know can ignore it rather than misread it.
///
/// Pure, so the shape is tested without a supervisor.
pub fn snapshot_message(services: Json, firewall: Option<Json>) -> Json {
    Json::object([
        ("kind", Json::string("snapshot")),
        ("services", services),
        ("firewall", firewall.unwrap_or(Json::Null)),
    ])
}

/// Runs an events stream until it ends, and reports how it ended.
///
/// The reader loop, and the whole of this task's job: own the stream, let
/// `selfhost_ws` answer pings and enforce its three deadlines, and stop when it
/// says so. The producing is done by `sweep` in a second task.
///
/// A client that *sends* on this route is closed with `1003`: `/api/events` is
/// one-way by design, and a console that has something to say has ordinary
/// CSRF-protected routes to say it on. Accepting and ignoring inbound messages
/// would mean a page could keep a stream busy with traffic nothing reads.
///
/// Takes the [`Upgraded`] connection rather than a socket and an [`Admission`]
/// side by side, so that this loop cannot be started on a connection whose
/// handshake was never answered — or answered twice.
pub async fn events<S>(
    upgraded: Upgraded<S, Admission>,
    api: Api,
    watch: Watch,
) -> Result<Closed, StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (io, admission) = upgraded.into_parts();
    let limits = Limits::default();
    let mut duplex = Duplex::server(io, limits);
    let mut producer =
        tokio::spawn(sweep(api, duplex.sender(), admission.holder.clone(), limits, watch));

    // The reader arm is what drives the entire stream. `recv` returns only when
    // an application message arrives or the stream ends; while it is pending it
    // is doing everything else — sending the ping schedule, watching the pong
    // deadline and the lifetime ceiling, answering the peer's control frames,
    // and draining the producer's queue onto the socket. On this route an
    // inbound message is itself terminal, so there is nothing to come back for.
    //
    // The second arm is the producer *finishing*, which it only does when it has
    // decided this stream is over — see [`Produced`]. Racing the two is what
    // makes a server-decided close a close rather than a request: without it the
    // reader would keep running after the close frame went out, for as long as
    // the peer cared to answer pongs.
    let mut ended_by_producer = None;
    let outcome = tokio::select! {
        event = duplex.recv() => match event {
            Ok(Event::Message(_)) => {
                let code = selfhost_ws::CloseCode::UnacceptableData;
                duplex.close(code, ONE_WAY).await?;
                Ok(Closed::Peer(selfhost_ws::CloseFrame::new(code, ONE_WAY)))
            }
            Ok(Event::Closed(reason)) => Ok(reason),
            Err(error) => Err(error),
        },
        finished = &mut producer => {
            // A panic in the producer is not swallowed: it ends the stream and
            // says so, rather than leaving a reader running with nothing behind
            // it.
            ended_by_producer = Some(match finished {
                Ok(reason) => reason,
                Err(join) => {
                    eprintln!("admin: a stream's producer task failed: {join}");
                    Produced::ViewerGone
                }
            });
            Ok(Closed::Abrupt)
        }
    };

    if let Some(Produced::CredentialGone) = ended_by_producer {
        // The producer queued a close frame that nothing has written yet: the
        // writer is driven from inside `recv`, and the arm above dropped the
        // `recv` that would have driven it. So the reader is run once more,
        // under a deadline this end owns, and then the stream is dropped
        // whatever the peer thinks.
        //
        // That second `recv` may have lost whatever the dropped read was holding
        // — `Duplex::recv` is documented as not cancel-safe in exactly that way
        // — and here that is both acceptable and irrelevant: the only thing
        // wanted from this window is the outbound close reaching the wire, and
        // nothing will be read from this connection again.
        let _ = tokio::time::timeout(watch.close_grace, duplex.recv()).await;
        // The producer holds a `Sender`, and a send to an ended stream reports
        // `Gone` rather than blocking — but it may be parked in its sweep at this
        // instant, and leaving it to notice on its own would mean a task per
        // finished stream, alive for up to one sweep, doing work for a viewer who
        // has gone.
        producer.abort();
        return Ok(Closed::Peer(selfhost_ws::CloseFrame::new(
            selfhost_ws::CloseCode::PolicyViolation,
            CREDENTIAL_GONE,
        )));
    }

    producer.abort();
    outcome
}

/// Why the producing half of a stream stopped.
///
/// The reader races this, so it is the producer's way of ending the stream
/// rather than merely asking the peer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Produced {
    /// The credential that opened the stream is no longer live. A close frame
    /// has been queued; the reader must now enforce it on a deadline.
    CredentialGone,
    /// The stream had already ended underneath the sender, or the message grew
    /// past what one frame may carry and there is nothing further to say.
    ViewerGone,
}

/// Produces snapshots, and re-checks the credential that opened the stream.
///
/// Runs as its own task holding a bounded [`Sender`]; see the module note on why
/// the *reading* is not a `select!` arm around this. Every exit path is a
/// `return`, and each one is the answer to a question an operator would ask: the
/// viewer left, or the session ended.
async fn sweep(
    api: Api,
    sender: Sender,
    holder: Holder,
    limits: Limits,
    watch: Watch,
) -> Produced {
    let mut previous = String::new();
    let mut last_check = Instant::now();

    loop {
        if last_check.elapsed() >= watch.credential_recheck {
            last_check = Instant::now();
            if !api.credential_is_live(&holder) {
                // Queued rather than dropped, so the console can say *your
                // session ended* instead of showing a link that simply died.
                // Returning is what ends the stream: the reader is racing this
                // task and enforces the close once it sees it finish.
                let _ = sender.close(selfhost_ws::CloseCode::PolicyViolation, CREDENTIAL_GONE).await;
                return Produced::CredentialGone;
            }
        }

        let snapshot = api.console_snapshot().await.to_text();
        if snapshot != previous {
            if snapshot.len() > limits.max_frame {
                // Refused here rather than by the codec, which would close the
                // stream. A machine with enough services to overflow a megabyte
                // of JSON deserves a log line and a stream that keeps working
                // for everything else, not a console that mysteriously drops.
                eprintln!(
                    "admin: the console snapshot is {} bytes, past the {} byte frame ceiling; \
                     not sending it",
                    snapshot.len(),
                    limits.max_frame
                );
            } else if sender.send(snapshot.clone().into_bytes()).await.is_err() {
                return Produced::ViewerGone;
            }
            previous = snapshot;
        }
        tokio::time::sleep(SWEEP).await;
    }
}

impl Api {
    /// Whether the credential that opened a stream is still good.
    ///
    /// Uses [`Sessions::authenticated`](crate::Sessions::authenticated),
    /// **never** `validate` — see the module note. The bearer token cannot expire
    /// and has no store to consult, so a bearer stream is bounded only by
    /// `Limits::max_lifetime`, which is stated here rather than discovered later.
    pub(crate) fn credential_is_live(&self, holder: &Holder) -> bool {
        match holder {
            Holder::Bearer => true,
            Holder::Session(id) => self
                .console
                .as_ref()
                .is_some_and(|console| console.sessions.authenticated(id).is_some()),
        }
    }

    /// The console's live snapshot, read from the same handles the REST routes
    /// read.
    ///
    /// Not a second view of the machine: `statuses()` and `firewall.state()` are
    /// the very calls `GET /api/services` and `GET /api/firewall` make, so a
    /// stream and a poll cannot report different things about the same instant.
    pub(crate) async fn console_snapshot(&self) -> Json {
        let statuses = self.supervisor.statuses().await;
        let services = Json::array(statuses.iter().map(|status| status.to_json()));
        snapshot_message(services, Some(self.firewall.state().await.to_json()))
    }

    /// Whose stream an admission opens, for the log line.
    ///
    /// A separate accessor rather than reading through to the identity, because
    /// the log line wants one string and the model is an enum: the owner's name
    /// is [`OWNER`](crate::OWNER), and a person's is their own.
    pub(crate) fn stream_identity(admission: &Admission) -> &str {
        admission.identity().as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// An admission with no meaning beyond the fields `answer` reads.
    ///
    /// It reserves a real place in a throwaway ceiling, because an `Admission`
    /// cannot be built without one — which is the point of putting the slot in
    /// the type rather than leaving the socket layer to remember it.
    fn admission(subprotocol: Option<&str>) -> Admission {
        let streams = crate::Streams::new();
        Admission {
            holder: Holder::Bearer,
            caller: selfhost_identity::Caller::bearer(),
            abilities: vec![crate::upgrade::Ability::Events],
            accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_owned(),
            subprotocol: subprotocol.map(str::to_owned),
            slot: streams.reserve(&Holder::Bearer).expect("an empty ceiling"),
        }
    }

    /// The head an [`Answering`] value produces, as text.
    fn head_of(whom: &impl Answering) -> String {
        String::from_utf8(whom.response_head().expect("a serialisable head")).expect("ASCII")
    }

    /// Reads one HTTP head off a stream, and not one byte past it.
    ///
    /// A byte at a time, deliberately: everything after the blank line belongs
    /// to the new protocol, and a test that over-read would eat the very frame
    /// it is about to assert on — the same trap [`Prefixed`] exists for.
    async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("the head");
            assert_ne!(read, 0, "the stream ended mid-head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ASCII")
    }

    /// Answers a handshake on `io` and runs the events loop over it.
    ///
    /// The two halves the socket layer performs in that order, in one call, so
    /// that a test drives the real sequence — including the `101` — rather than
    /// a loop started on a connection no client could have completed.
    async fn serve_events<S>(io: S, api: Api, watch: Watch) -> Result<Closed, StreamError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let upgraded =
            Upgraded::answer(io, Vec::new(), admission(None)).await.expect("the handshake");
        events(upgraded, api, watch).await
    }

    #[tokio::test]
    async fn the_hundred_and_one_is_a_complete_head_and_nothing_more() {
        let head = head_of(&admission(Some("selfhost.events.1")));

        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
        assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
        assert!(head.contains("Connection: Upgrade\r\n"), "{head}");
        assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "{head}");
        assert!(head.contains("Sec-WebSocket-Protocol: selfhost.events.1\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
        // The two fields that would break a handshake if the general response
        // path had written it.
        assert!(!head.to_ascii_lowercase().contains("content-length"), "{head}");
        assert!(!head.to_ascii_lowercase().contains("x-frame-options"), "{head}");
    }

    #[tokio::test]
    async fn a_client_that_offered_no_protocol_gets_no_protocol_back() {
        let head = head_of(&admission(None));
        assert!(!head.contains("Sec-WebSocket-Protocol"), "{head}");
    }

    #[tokio::test]
    async fn a_peer_link_is_answered_from_its_handshake_key_and_offered_no_protocol() {
        // The dialler sends no `Sec-WebSocket-Protocol`, so echoing one would be
        // a token nobody offered — and the accept value is the one the worker's
        // enrolment proof is bound to, which is why it is derived here from the
        // key rather than passed in beside it.
        let head = head_of(&PeerKey::new("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
        assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "{head}");
        assert!(!head.contains("Sec-WebSocket-Protocol"), "{head}");
    }

    #[tokio::test]
    async fn answering_writes_exactly_one_head_and_then_the_protocol_begins() {
        // The regression this type exists for: two `101` heads back to back,
        // where the second is read by every RFC 6455 client as a frame with RSV1
        // set and opcode 8. Asserted on the raw bytes, because that is the only
        // place the duplicate was ever visible.
        let (mut far, near) = tokio::io::duplex(4096);
        let upgraded = Upgraded::answer(near, Vec::new(), admission(Some("selfhost.events.1")))
            .await
            .expect("the handshake is answered");

        let head = read_head(&mut far).await;
        assert_eq!(head.matches("HTTP/1.1").count(), 1, "{head}");

        // Nothing follows the head until the loop behind it says something, and
        // what it says is a frame rather than a second head.
        let (mut io, _whom) = upgraded.into_parts();
        io.write_all(b"\x82\x02hi").await.expect("a frame");
        io.flush().await.expect("flush");
        let mut frame = [0u8; 4];
        far.read_exact(&mut frame).await.expect("the first frame");
        assert_eq!(&frame, b"\x82\x02hi", "the first bytes after the head were not the frame");
    }

    #[tokio::test]
    async fn buffered_bytes_are_delivered_before_the_socket_and_in_order() {
        let (mut far, near) = tokio::io::duplex(64);
        far.write_all(b"from the socket").await.expect("write");

        let mut prefixed = Prefixed::new(b"already read".to_vec(), near);
        let mut got = vec![0u8; b"already readfrom the socket".len()];
        prefixed.read_exact(&mut got).await.expect("read");
        assert_eq!(got, b"already readfrom the socket");
    }

    #[tokio::test]
    async fn a_prefix_survives_being_read_a_byte_at_a_time() {
        // The failure this guards against is a prefix delivered only on a read
        // large enough to take all of it, which would strand the remainder for
        // exactly as long as the peer stayed quiet.
        let (mut far, near) = tokio::io::duplex(64);
        far.write_all(b"XY").await.expect("write");
        let mut prefixed = Prefixed::new(b"abc".to_vec(), near);

        let mut collected = Vec::new();
        for _ in 0..5 {
            let mut one = [0u8; 1];
            prefixed.read_exact(&mut one).await.expect("read");
            collected.push(one[0]);
        }
        assert_eq!(collected, b"abcXY");
    }

    #[tokio::test]
    async fn an_empty_prefix_is_simply_the_socket() {
        let (mut far, near) = tokio::io::duplex(64);
        far.write_all(b"plain").await.expect("write");
        let mut prefixed = Prefixed::new(Vec::new(), near);
        let mut got = [0u8; 5];
        prefixed.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"plain");
    }

    #[tokio::test]
    async fn writes_reach_the_socket_untouched() {
        let (mut far, near) = tokio::io::duplex(64);
        let mut prefixed = Prefixed::new(b"ignored on the way out".to_vec(), near);
        prefixed.write_all(b"outbound").await.expect("write");
        prefixed.flush().await.expect("flush");

        let mut got = [0u8; 8];
        far.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"outbound");
    }

    #[test]
    fn a_snapshot_names_itself_and_carries_both_halves() {
        let services = Json::array([Json::object([("name", Json::string("mail"))])]);
        let firewall = Json::object([("backend", Json::string("pf"))]);
        let message = snapshot_message(services.clone(), Some(firewall));

        assert_eq!(message.get("kind").and_then(Json::as_str), Some("snapshot"));
        assert_eq!(message.get("services").and_then(Json::as_array).map(<[Json]>::len), Some(1));
        assert_eq!(
            message.get("firewall").and_then(|f| f.get("backend")).and_then(Json::as_str),
            Some("pf")
        );

        // A daemon without a firewall backend says so explicitly. The console
        // must be able to tell "no firewall" from "no news", and a missing key
        // would read as the second.
        let absent = snapshot_message(services, None);
        assert!(absent.get("firewall").is_some_and(Json::is_null));
    }

    /// An `Api` over a scratch directory, and the directory that removes itself.
    ///
    /// Built here rather than reusing `tests/api.rs`'s helper because an
    /// integration test cannot reach `stream::events`'s internals and this test
    /// is about the loop rather than about a route.
    fn api_for_streaming(name: &str) -> (Api, Scratch) {
        let scratch = Scratch::new(name);
        let config = selfhost_config::Config::parse(
            "version = 1\n\
             [server]\n\
             http_bind = \"127.0.0.1:8080\"\n\
             https_bind = \"127.0.0.1:8443\"\n\
             acme_email = \"a@b.com\"\n\
             acme = \"self-signed\"\n\
             data_dir = \"./data\"\n\
             [[nodes]]\n\
             name = \"home\"\n\
             role = \"owner\"\n",
        )
        .expect("a minimal valid config");
        let api = Api::new(
            selfhost_supervisor::Supervisor::new(scratch.path()),
            crate::Store::new(scratch.path()),
            crate::Token::load_or_create(scratch.path()).expect("a token"),
            selfhost_git::Watches::default(),
            selfhost_firewall::Manager::for_config(&config),
        );
        (api, scratch)
    }

    /// A directory that removes itself when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("selfhost-stream-{name}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn a_live_stream_pushes_a_snapshot_and_then_stays_quiet() {
        // The whole point of the route in one test: the first snapshot arrives
        // unasked, and nothing follows it while nothing changes. A stream that
        // re-sent an unchanged snapshot every sweep would be the 500 ms poll
        // again with extra steps.
        let (api, _scratch) = api_for_streaming("pushes-a-snapshot");
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let serving = tokio::spawn(serve_events(server, api, Watch::default()));
        let head = read_head(&mut client).await;
        assert_eq!(head.matches("HTTP/1.1").count(), 1, "{head}");
        let mut peer = selfhost_ws::Duplex::client(client, Limits::default());

        let first = peer.recv().await.expect("a snapshot");
        let selfhost_ws::Event::Message(payload) = first else {
            panic!("the stream ended instead of sending a snapshot");
        };
        let text = String::from_utf8(payload).expect("UTF-8 JSON");
        let value = selfhost_json::parse(&text).expect("JSON");
        assert_eq!(value.get("kind").and_then(Json::as_str), Some("snapshot"));
        assert!(value.get("services").is_some());

        // Several sweeps' worth of silence. `recv` is left pending rather than
        // polled once, so a stray message would arrive inside the timeout.
        let quiet = tokio::time::timeout(SWEEP * 5, peer.recv()).await;
        assert!(quiet.is_err(), "an unchanged machine sent a second snapshot");

        serving.abort();
    }

    #[tokio::test]
    async fn a_client_that_speaks_on_a_one_way_stream_is_closed() {
        let (api, _scratch) = api_for_streaming("one-way");
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let serving = tokio::spawn(serve_events(server, api, Watch::default()));
        read_head(&mut client).await;
        let mut peer = selfhost_ws::Duplex::client(client, Limits::default());
        // Drain the opening snapshot so the send below is unambiguous.
        peer.recv().await.expect("a snapshot");
        peer.send(b"i have opinions").await.expect("send");

        let ended = serving.await.expect("the task finished").expect("a clean end");
        let selfhost_ws::Closed::Peer(close) = ended else {
            panic!("expected a deliberate close, got {ended}");
        };
        assert_eq!(close.code, Some(selfhost_ws::CloseCode::UnacceptableData));
    }

    #[tokio::test]
    async fn a_viewer_that_hangs_up_ends_the_stream() {
        let (api, _scratch) = api_for_streaming("hang-up");
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn(serve_events(server, api, Watch::default()));
        read_head(&mut client).await;

        // The peer is kept alive across the await on purpose. A real browser
        // half-closes: the close frame goes out and the socket stays writable
        // long enough for the server's answering close, and `tokio::io::duplex`
        // only behaves that way while both halves are still held.
        let mut peer = selfhost_ws::Duplex::client(client, Limits::default());
        peer.recv().await.expect("a snapshot");
        peer.close(selfhost_ws::CloseCode::Normal, "closing the tab").await.expect("close");

        let ended = serving.await.expect("the task finished").expect("a clean end");
        assert!(
            matches!(ended, selfhost_ws::Closed::Peer(_) | selfhost_ws::Closed::Abrupt),
            "expected the peer's departure, got {ended}"
        );
    }

    #[test]
    fn the_same_state_serialises_to_the_same_text() {
        // The change detection in `sweep` is a string comparison, so this is the
        // property it rests on: equal state must produce equal bytes, or the
        // stream would push a snapshot every hundred milliseconds for ever.
        let build = || {
            snapshot_message(
                Json::array([Json::string("a"), Json::string("b")]),
                Some(Json::object([("managed", Json::Bool(true))])),
            )
            .to_text()
        };
        assert_eq!(build(), build());
    }
}
