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
//! lives in this file and is tested against `tokio::io::duplex` rather than a
//! listener. Nothing in this crate binds an address it did not already bind.
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

/// Writes the `101 Switching Protocols` that completes a handshake.
///
/// Serialised by `selfhost_ws::handshake::response_head` rather than through
/// [`crate::Api`]'s ordinary response path, for the same reason the proxy
/// forwards it verbatim: the general path derives framing from a body this
/// response does not have, and the proxy splices security headers into anything
/// it writes as a response — fields that mean nothing to a connection that has
/// stopped being HTTP, in a message a browser checks strictly before it hands
/// the socket to the page.
///
/// The subprotocol comes from [`Admission`], which only ever carries a token
/// this server chose from a fixed list; the header layer's CR/LF check stands
/// behind that anyway, and a failure there is reported rather than swallowed.
pub async fn answer<S>(stream: &mut S, admission: &Admission) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = handshake::response_head(&admission.accept, admission.subprotocol.as_deref())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    stream.write_all(&head).await?;
    stream.flush().await
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
pub async fn events<S>(
    io: S,
    api: Api,
    admission: Admission,
    watch: Watch,
) -> Result<Closed, StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

    #[tokio::test]
    async fn the_hundred_and_one_is_a_complete_head_and_nothing_more() {
        let mut out = Vec::new();
        answer(&mut out, &admission(Some("selfhost.events.1"))).await.expect("write");
        let head = String::from_utf8(out).expect("ASCII");

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
        let mut out = Vec::new();
        answer(&mut out, &admission(None)).await.expect("write");
        let head = String::from_utf8(out).expect("ASCII");
        assert!(!head.contains("Sec-WebSocket-Protocol"), "{head}");
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
        let (client, server) = tokio::io::duplex(64 * 1024);

        let serving = tokio::spawn(events(server, api, admission(None), Watch::default()));
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
        let (client, server) = tokio::io::duplex(64 * 1024);

        let serving = tokio::spawn(events(server, api, admission(None), Watch::default()));
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
        let (client, server) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn(events(server, api, admission(None), Watch::default()));

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
