//! The only file in this crate that touches a socket.
//!
//! Everything else here is a function from bytes to a decision. This module is
//! where those decisions meet a stream: it reads, it parses what it has, it
//! answers control frames on its own, it sends pings, it notices a peer that has
//! stopped answering, and it closes. It is generic over `AsyncRead + AsyncWrite`
//! rather than written against `TcpStream` for the usual reason — the tests below
//! drive a real one over `tokio::io::duplex`, with no socket, no port, and no
//! listener, which is the only way an assertion about a *timeout* can be made
//! without a machine that has to wait forty-five seconds to find out.
//!
//! # Why liveness lives here and could not live anywhere else
//!
//! Once a connection is upgraded, every timeout in the stack above has already
//! fired or been cancelled: the proxy's head timeout ended at the blank line, its
//! idle timeout applies between requests, and the copy loop that carries the
//! upgraded bytes is untimed by construction because it has no idea what a
//! message is. Above us, a route waiting for the next message cannot tell a quiet
//! peer from a dead one — those are the same thing to a socket that has not been
//! closed, and a laptop that slept, a NAT that forgot the mapping, or a VPN that
//! dropped will all produce exactly that. The connection sits there, holding a
//! session and a capture pipeline, until the process restarts.
//!
//! So this layer asks. A ping goes out every `ping_interval`; any frame at all
//! coming back is proof of life; `pong_deadline` of silence ends the stream. And
//! because a healthy stream can also be a stream that has simply been open too
//! long, `max_lifetime` ends it regardless — an authorisation with no expiry is
//! the difference between a console left open on Friday and an unattended door on
//! Monday.
//!
//! # The single-owner shape, and the channel that follows from it
//!
//! One task owns the stream. It is parked in [`Duplex::recv`] almost all of the
//! time, which is also where the timers live, so anything else that wants to send
//! — the service watcher pushing a snapshot, the capture loop pushing a tile —
//! cannot simply call a method on it. That is what [`Sender`] is for: a cloneable
//! handle onto a bounded queue that [`Duplex::recv`] drains as one of the things
//! it waits on. Bounded, not unbounded, because a producer that can outrun the
//! socket must be made to feel it here rather than by growing a queue until the
//! box runs out of memory; a remote desktop must show the present, not a backlog.

use crate::close::{self, CloseCode, CloseFrame};
use crate::frame::{self, Assembler, Frame, Opcode, ParsedFrame, ProtocolError, Role};
use crate::limits::Limits;
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

/// How many bytes one read may deliver.
///
/// Sixteen kilobytes is a compromise between syscall count and the memory a
/// mostly-idle stream holds: a desktop session at a few megabytes per second
/// costs a few hundred reads a second, and ten idle streams cost 160 KiB in
/// total. The frame ceiling, not this, is what bounds a single frame.
const READ_CHUNK: usize = 16 * 1024;

/// How many messages may be queued for sending before a producer blocks.
///
/// Small on purpose. See the module documentation: the queue exists to decouple
/// producers from the socket for a moment, not to absorb a producer that is
/// permanently faster than the link.
const OUTBOUND_QUEUE: usize = 32;

/// Something the caller asked to be written to the peer.
#[derive(Debug)]
enum Outgoing {
    /// A binary message.
    Binary(Vec<u8>),
    /// A close frame, after which nothing more will be written.
    Close(CloseCode, String),
}

/// A cloneable handle for sending on a stream another task owns.
///
/// Every method reports failure rather than swallowing it: a send to a stream
/// that has ended is exactly the event a producer needs to hear about, because it
/// means the viewer is gone and the work being done for it should stop.
#[derive(Debug, Clone)]
pub struct Sender(mpsc::Sender<Outgoing>);

impl Sender {
    /// Queues a binary message, waiting if the queue is full.
    ///
    /// Waiting is the point: it is how backpressure from the socket reaches the
    /// producer. A caller that must not block should use [`Sender::try_send`] and
    /// decide for itself what to drop.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), Gone> {
        self.0.send(Outgoing::Binary(payload)).await.map_err(|_| Gone)
    }

    /// Queues a binary message if there is room, without waiting.
    ///
    /// For producers that would rather drop a frame than fall behind — a capture
    /// loop should send the newest picture, not the oldest one it still owes.
    pub fn try_send(&self, payload: Vec<u8>) -> Result<(), Gone> {
        self.0.try_send(Outgoing::Binary(payload)).map_err(|_| Gone)
    }

    /// Asks the stream to close with this code and reason.
    ///
    /// The close is queued behind whatever is already waiting, so messages
    /// already handed over are still delivered — a viewer that is being told
    /// *your session ended* should receive the last frame before the reason.
    pub async fn close(&self, code: CloseCode, reason: impl Into<String>) -> Result<(), Gone> {
        self.0.send(Outgoing::Close(code, reason.into())).await.map_err(|_| Gone)
    }
}

/// The stream this handle referred to has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone;

impl fmt::Display for Gone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the websocket stream has ended")
    }
}

impl std::error::Error for Gone {}

/// Why a stream ended without anyone doing anything wrong.
///
/// Kept separate from [`StreamError`] because these are outcomes an operator
/// should see reported as facts, not as failures. *The peer closed* and *the peer
/// stopped answering* are both normal events in the life of a console on a
/// laptop, and logging them at the same severity as a protocol violation is how a
/// log stops being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// The peer sent a close frame. Its code and reason are carried through.
    Peer(CloseFrame),
    /// The peer stopped answering pings for longer than `pong_deadline`.
    PongTimeout,
    /// The stream reached `max_lifetime` and was ended on purpose.
    LifetimeReached,
    /// The connection ended without a close frame — a process that died, a
    /// cable, a tunnel that dropped.
    Abrupt,
}

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(close) => match close.code {
                Some(code) if close.reason.is_empty() => write!(f, "peer closed ({})", code.value()),
                Some(code) => write!(f, "peer closed ({}): {}", code.value(), close.reason),
                None => write!(f, "peer closed without a status"),
            },
            Self::PongTimeout => write!(f, "peer stopped answering pings"),
            Self::LifetimeReached => write!(f, "stream reached its maximum lifetime"),
            Self::Abrupt => write!(f, "connection ended without a close frame"),
        }
    }
}

/// What [`Duplex::recv`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete binary message, reassembled from however many frames carried it.
    Message(Vec<u8>),
    /// The stream is over. No further call will produce anything.
    Closed(Closed),
}

/// Why a stream ended badly.
#[derive(Debug)]
pub enum StreamError {
    /// The peer's framing was unacceptable. A close frame carrying the matching
    /// code has already been sent before this is returned.
    Protocol(ProtocolError),
    /// The underlying transport failed.
    Io(std::io::Error),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Io(error) => write!(f, "transport error: {error}"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for StreamError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// One thing the stream woke up to do.
///
/// Naming the wake-up rather than acting inside the `select!` is what keeps every
/// handler able to take `&mut self`: by the time the action is matched on, the
/// futures that borrowed individual fields are gone.
#[derive(Debug)]
enum Wakeup {
    /// Bytes arrived, this many of them.
    Read(usize),
    /// The peer closed the connection at the transport level.
    Eof,
    /// It is time to send a ping.
    Ping,
    /// The peer has been silent past its deadline.
    Silent,
    /// The stream has lived long enough.
    Expired,
    /// Another task wants something sent.
    Outgoing(Outgoing),
}

/// A framed, live WebSocket stream over any byte transport.
///
/// Created after the handshake has been validated and answered; this type knows
/// nothing about HTTP and never sees a header. Drive it by calling
/// [`Duplex::recv`] in a loop until it yields [`Event::Closed`] or an error, and
/// send either directly with [`Duplex::send`] or from elsewhere through
/// [`Duplex::sender`].
pub struct Duplex<S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    role: Role,
    limits: Limits,
    scratch: Vec<u8>,
    buffered: Vec<u8>,
    assembler: Assembler,
    outbound_tx: mpsc::Sender<Outgoing>,
    outbound_rx: mpsc::Receiver<Outgoing>,
    /// When the stream opened, which fixes its hard expiry.
    opened: Instant,
    /// When the peer last proved it was alive.
    heard_from: Instant,
    /// When the next unsolicited ping is due.
    ping_due: Instant,
    /// Counts pings, so a pong's payload identifies which ping it answers.
    pings_sent: u64,
    /// Whether a close frame has already gone out, so we never send two.
    close_sent: bool,
    /// Whether the stream has finished, so a caller looping on `recv` after the
    /// end gets a clean answer rather than a read on a dead socket.
    finished: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Duplex<S> {
    /// Wraps an upgraded connection as the **server** side of a stream.
    ///
    /// The role decides the masking rule in both directions: frames arriving must
    /// be masked, frames sent must not be. Getting this backwards is not a subtle
    /// bug — nothing interoperates at all — which is why it is a constructor
    /// choice rather than a flag.
    pub fn server(io: S, limits: Limits) -> Self {
        Self::new(io, Role::Server, limits)
    }

    /// Wraps a connection we opened as the **client** side of a stream.
    ///
    /// Used by the outbound dialler, where this box is the one connecting to
    /// another. The tests use it to play the far end honestly rather than by
    /// hand-writing frames.
    pub fn client(io: S, limits: Limits) -> Self {
        Self::new(io, Role::Client, limits)
    }

    fn new(io: S, role: Role, limits: Limits) -> Self {
        let (reader, writer) = tokio::io::split(io);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let now = Instant::now();
        Self {
            reader,
            writer,
            role,
            limits,
            scratch: vec![0; READ_CHUNK],
            buffered: Vec::new(),
            assembler: Assembler::new(limits),
            outbound_tx,
            outbound_rx,
            opened: now,
            heard_from: now,
            ping_due: now + limits.ping_interval,
            pings_sent: 0,
            close_sent: false,
            finished: false,
        }
    }

    /// A handle other tasks can send on.
    ///
    /// The stream keeps a sender of its own, so this channel is never observed to
    /// close from the receiving end. That is deliberate: a stream's life is
    /// decided by the protocol and by its deadlines, not by whether anyone
    /// happens to be holding a handle at this instant.
    pub fn sender(&self) -> Sender {
        Sender(self.outbound_tx.clone())
    }

    /// The limits this stream runs under.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Waits for the next message, answering control frames and deadlines along
    /// the way.
    ///
    /// Returns [`Event::Message`] for each complete application message, and
    /// [`Event::Closed`] once — after which every further call returns the same
    /// `Closed::Abrupt` rather than reading a socket that is finished. Pings,
    /// pongs, queued outbound messages and the three deadlines are all handled
    /// inside; a caller sees none of them.
    ///
    /// **Cancellation.** This is *not* cancel-safe in the strict sense: bytes read
    /// into the internal buffer are kept across calls, but a `select!` that drops
    /// this future mid-read loses whatever that one read had not yet returned.
    /// The stream is meant to be owned by a task that loops on it, which is the
    /// shape everything above it uses.
    pub async fn recv(&mut self) -> Result<Event, StreamError> {
        if self.finished {
            return Ok(Event::Closed(Closed::Abrupt));
        }
        loop {
            if let Some(event) = self.drain_buffer().await? {
                return Ok(event);
            }
            match self.wait().await {
                Wakeup::Read(count) => {
                    self.heard_from = Instant::now();
                    let chunk = &self.scratch[..count];
                    self.buffered.extend_from_slice(chunk);
                }
                Wakeup::Eof => return Ok(self.finish(Closed::Abrupt)),
                Wakeup::Ping => {
                    self.ping_due = Instant::now() + self.limits.ping_interval;
                    if !self.close_sent {
                        self.pings_sent += 1;
                        let payload = self.pings_sent.to_be_bytes();
                        self.write_frame(Opcode::Ping, &payload).await?;
                    }
                }
                Wakeup::Silent => {
                    self.send_close(CloseCode::GoingAway, "no pong").await?;
                    return Ok(self.finish(Closed::PongTimeout));
                }
                Wakeup::Expired => {
                    self.send_close(CloseCode::GoingAway, "stream lifetime reached").await?;
                    return Ok(self.finish(Closed::LifetimeReached));
                }
                Wakeup::Outgoing(Outgoing::Binary(payload)) => {
                    self.write_frame(Opcode::Binary, &payload).await?;
                }
                Wakeup::Outgoing(Outgoing::Close(code, reason)) => {
                    self.send_close(code, &reason).await?;
                }
            }
        }
    }

    /// Sends one binary message from the task that owns the stream.
    ///
    /// The message goes out as a single frame. Fragmenting is the sender's choice
    /// in this protocol and we never need it: everything we send is a complete
    /// unit of its own, and a message larger than the frame ceiling is a bug in
    /// the layer above rather than something to paper over here — hence the
    /// refusal rather than an automatic split.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        if payload.len() > self.limits.max_frame {
            return Err(StreamError::Protocol(ProtocolError::FrameTooLarge(payload.len() as u64)));
        }
        self.write_frame(Opcode::Binary, payload).await
    }

    /// Sends a close frame, if one has not gone out already.
    ///
    /// This does not wait for the peer's answering close. A caller that wants the
    /// full closing handshake keeps calling [`Duplex::recv`] until it yields
    /// [`Event::Closed`]; a caller that is closing because something went wrong
    /// drops the stream immediately, which is usually the right thing.
    pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), StreamError> {
        self.send_close(code, reason).await
    }

    /// Parses whatever is already buffered, acting on every frame it finds.
    ///
    /// Returns the first application message or terminal event the buffer
    /// contains, leaving anything after it for the next call. Control frames are
    /// answered here, which is why this is `async` despite being the parsing half
    /// — a ping must be answered promptly, not when the caller next asks for a
    /// message.
    async fn drain_buffer(&mut self) -> Result<Option<Event>, StreamError> {
        loop {
            let ParsedFrame { frame, consumed } =
                match frame::parse(&self.buffered, self.role, &self.limits) {
                    Ok(parsed) => parsed,
                    Err(ProtocolError::Incomplete) => return Ok(None),
                    Err(error) => return Err(self.fail(error).await),
                };
            self.buffered.drain(..consumed);
            self.heard_from = Instant::now();

            match frame.opcode {
                Opcode::Ping => self.write_frame(Opcode::Pong, &frame.payload).await?,
                Opcode::Pong => {}
                Opcode::Close => {
                    let closing = match close::parse_body(&frame.payload) {
                        Ok(closing) => closing,
                        Err(error) => return Err(self.fail(error).await),
                    };
                    self.send_close(CloseCode::Normal, "").await?;
                    return Ok(Some(self.finish(Closed::Peer(closing))));
                }
                Opcode::Binary | Opcode::Continuation => match self.accept_data(frame).await? {
                    Some(message) => return Ok(Some(Event::Message(message))),
                    None => continue,
                },
            }
        }
    }

    /// Feeds a data frame to the reassembler, closing the stream if it refuses.
    async fn accept_data(&mut self, frame: Frame) -> Result<Option<Vec<u8>>, StreamError> {
        match self.assembler.accept(frame) {
            Ok(message) => Ok(message),
            Err(error) => Err(self.fail(error).await),
        }
    }

    /// Waits for whichever of the five things happens first.
    ///
    /// Each branch borrows a different field, and the result is a plain value, so
    /// the handler in [`Duplex::recv`] gets `&mut self` back the moment this
    /// returns. `sleep_until` rather than an interval, because both deadlines move
    /// when the peer proves it is alive, and an interval would have to be rebuilt
    /// every time it did.
    ///
    /// The branches are deliberately **not** `biased`. A fixed order reads like
    /// the safer choice — deadlines first — but it would mean that a peer sending
    /// continuously starves the outbound queue, and a viewer that types while the
    /// screen streams is exactly that peer. `select!`'s random polling gives every
    /// branch a turn; the two deadlines lose nothing by it, because an elapsed
    /// `sleep_until` stays ready forever and so is taken within a few iterations
    /// rather than at the first opportunity.
    async fn wait(&mut self) -> Wakeup {
        let silent_at = self.heard_from + self.limits.pong_deadline;
        let expires_at = self.opened + self.limits.max_lifetime;
        tokio::select! {
            _ = sleep_until(expires_at) => Wakeup::Expired,
            _ = sleep_until(silent_at) => Wakeup::Silent,
            read = self.reader.read(&mut self.scratch) => match read {
                Ok(0) => Wakeup::Eof,
                Ok(count) => Wakeup::Read(count),
                // A transport error and a closed transport are the same event to
                // everything above: the peer is gone. Reporting it as EOF keeps
                // one ending rather than two that mean the same thing.
                Err(_) => Wakeup::Eof,
            },
            _ = sleep_until(self.ping_due) => Wakeup::Ping,
            queued = self.outbound_rx.recv() => match queued {
                Some(item) => Wakeup::Outgoing(item),
                // Unreachable: the stream holds a sender of its own, so the
                // channel cannot be observed closed from this end. It is mapped
                // to the end of the stream rather than to "nothing to send"
                // because a closed channel is *permanently* ready — anything that
                // returns to the loop would spin at full speed. Ending is the
                // failure mode that cannot burn a core.
                None => Wakeup::Eof,
            },
        }
    }

    /// Sends a close frame carrying the code that explains `error`, then reports
    /// the error.
    ///
    /// Telling the peer *why* is worth the one extra write: a browser that is
    /// refused with 1009 can say "message too large" to its user, where a socket
    /// that simply vanishes can only say "connection lost". A failure to send the
    /// close is deliberately discarded — the connection is already ending, and
    /// replacing the protocol error with a write error would lose the interesting
    /// half of the story.
    async fn fail(&mut self, error: ProtocolError) -> StreamError {
        let code = close::code_for(&error);
        let _ = self.send_close(code, &error.to_string()).await;
        self.finished = true;
        StreamError::Protocol(error)
    }

    /// Marks the stream finished and wraps the reason as an event.
    fn finish(&mut self, closed: Closed) -> Event {
        self.finished = true;
        Event::Closed(closed)
    }

    /// Writes a close frame unless one has already gone out.
    async fn send_close(&mut self, code: CloseCode, reason: &str) -> Result<(), StreamError> {
        if self.close_sent {
            return Ok(());
        }
        self.close_sent = true;
        self.write_frame(Opcode::Close, &close::encode_body(code, reason)).await
    }

    /// Encodes and writes one frame, masking only if our role requires it.
    ///
    /// The write is bounded by the same deadline that governs silence, and this
    /// is not belt-and-braces — it closes a real hole. A peer that opens a stream
    /// and then simply stops *reading* fills the socket's send buffer, and an
    /// unbounded `write_all` parks this task inside the write rather than inside
    /// [`Duplex::wait`], where every deadline lives. Without a bound here, the
    /// pong deadline and the maximum lifetime would both be unreachable for
    /// exactly the peer most likely to be abusing them.
    async fn write_frame(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), StreamError> {
        let mask = match self.role {
            Role::Server => None,
            Role::Client => Some(self.mask_key()),
        };
        let mut bytes = Vec::with_capacity(payload.len() + 14);
        frame::encode(&mut bytes, true, opcode, payload, mask);

        let write = async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        };
        match tokio::time::timeout(self.limits.pong_deadline, write).await {
            Ok(result) => result.map_err(StreamError::Io),
            Err(_) => Err(StreamError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer stopped reading",
            ))),
        }
    }

    /// A masking key for the client role.
    ///
    /// Masking is not a secret: the key travels in the frame, and RFC 6455 asks
    /// for it so that a *cache or proxy* in the middle cannot be steered into
    /// interpreting attacker-chosen bytes as a request of its own. What the
    /// property needs is that the key differ from frame to frame, which a counter
    /// mixed into the clock gives without pulling a random source into a codec —
    /// and this crate is the server in every deployment we ship today, so this
    /// path exists for the dialler and for the tests rather than for production
    /// traffic.
    fn mask_key(&self) -> [u8; 4] {
        let nonce = self.pings_sent.wrapping_mul(0x9e37_79b9) ^ self.buffered.len() as u64;
        let stamp = self.opened.elapsed().subsec_nanos() as u64;
        ((nonce ^ stamp).rotate_left(17) as u32).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::DuplexStream;

    /// Timings small enough that a test finishes in milliseconds, in the same
    /// proportions as the real ones: the deadline is three ping intervals.
    fn brisk() -> Limits {
        Limits {
            ping_interval: Duration::from_millis(20),
            pong_deadline: Duration::from_millis(60),
            max_lifetime: Duration::from_secs(30),
            ..Limits::default()
        }
    }

    /// A server-side stream and the raw far end a test speaks as a client on.
    fn pair(limits: Limits) -> (Duplex<DuplexStream>, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        (Duplex::server(ours, limits), theirs)
    }

    async fn write_client_frame(
        peer: &mut DuplexStream,
        fin: bool,
        opcode: Opcode,
        payload: &[u8],
    ) {
        let mut bytes = Vec::new();
        frame::encode(&mut bytes, fin, opcode, payload, Some([1, 2, 3, 4]));
        peer.write_all(&bytes).await.expect("write");
    }

    /// Reads one frame the server sent, as a client would.
    async fn read_server_frame(peer: &mut DuplexStream) -> Frame {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match frame::parse(&buffer, Role::Client, &Limits::default()) {
                Ok(parsed) => return parsed.frame,
                Err(ProtocolError::Incomplete) => {}
                Err(error) => panic!("the server sent a frame we cannot parse: {error}"),
            }
            let count = peer.read(&mut chunk).await.expect("read");
            assert!(count > 0, "the server closed without sending the expected frame");
            buffer.extend_from_slice(&chunk[..count]);
        }
    }

    #[tokio::test]
    async fn a_message_from_the_client_arrives_whole() {
        let (mut server, mut peer) = pair(brisk());
        write_client_frame(&mut peer, true, Opcode::Binary, b"hello box").await;
        assert_eq!(server.recv().await.expect("recv"), Event::Message(b"hello box".to_vec()));
    }

    #[tokio::test]
    async fn a_fragmented_message_is_reassembled() {
        let (mut server, mut peer) = pair(brisk());
        write_client_frame(&mut peer, false, Opcode::Binary, b"one ").await;
        write_client_frame(&mut peer, false, Opcode::Continuation, b"two ").await;
        write_client_frame(&mut peer, true, Opcode::Continuation, b"three").await;
        assert_eq!(server.recv().await.expect("recv"), Event::Message(b"one two three".to_vec()));
    }

    #[tokio::test]
    async fn several_messages_in_one_read_are_delivered_in_order() {
        let (mut server, mut peer) = pair(brisk());
        write_client_frame(&mut peer, true, Opcode::Binary, b"first").await;
        write_client_frame(&mut peer, true, Opcode::Binary, b"second").await;
        assert_eq!(server.recv().await.expect("recv"), Event::Message(b"first".to_vec()));
        assert_eq!(server.recv().await.expect("recv"), Event::Message(b"second".to_vec()));
    }

    #[tokio::test]
    async fn what_the_server_sends_is_unmasked_and_parses_as_binary() {
        let (mut server, mut peer) = pair(brisk());
        server.send(b"a snapshot").await.expect("send");
        let frame = read_server_frame(&mut peer).await;
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, b"a snapshot");
    }

    #[tokio::test]
    async fn another_task_can_send_while_the_owner_is_parked_in_recv() {
        let (mut server, mut peer) = pair(brisk());
        let sender = server.sender();
        let pump = tokio::spawn(async move { server.recv().await });

        sender.send(b"pushed from elsewhere".to_vec()).await.expect("queue");
        let frame = read_server_frame(&mut peer).await;
        assert_eq!(frame.payload, b"pushed from elsewhere");

        // Let the parked recv finish so the test does not leak the task.
        write_client_frame(&mut peer, true, Opcode::Binary, b"done").await;
        assert_eq!(pump.await.expect("join").expect("recv"), Event::Message(b"done".to_vec()));
    }

    #[tokio::test]
    async fn a_ping_from_the_client_is_answered_with_the_same_payload() {
        let (mut server, mut peer) = pair(brisk());
        write_client_frame(&mut peer, true, Opcode::Ping, b"beat").await;
        let pump = tokio::spawn(async move { server.recv().await });
        let frame = read_server_frame(&mut peer).await;
        assert_eq!(frame.opcode, Opcode::Pong);
        assert_eq!(frame.payload, b"beat");
        pump.abort();
    }

    #[tokio::test]
    async fn the_server_pings_on_its_own_schedule() {
        let (mut server, mut peer) = pair(brisk());
        let pump = tokio::spawn(async move { server.recv().await });
        let frame = read_server_frame(&mut peer).await;
        assert_eq!(frame.opcode, Opcode::Ping, "an idle stream must ask");
        pump.abort();
    }

    #[tokio::test]
    async fn a_peer_that_never_answers_is_closed_at_the_pong_deadline() {
        // The far end stays connected and silent: the exact shape of a laptop
        // that slept or a tunnel that dropped without a FIN. The pipe is large
        // enough to swallow every ping, so nothing but the deadline can end this.
        let (mut server, _peer) = pair(brisk());
        let ended = server.recv().await.expect("recv");
        assert_eq!(ended, Event::Closed(Closed::PongTimeout));
    }

    #[tokio::test]
    async fn a_pong_keeps_the_stream_alive_past_the_deadline() {
        let (mut server, mut peer) = pair(brisk());
        let pump = tokio::spawn(async move { server.recv().await });

        // Answer with a pong every ten milliseconds for a quarter of a second —
        // four deadlines' worth — then send a real message. Its arrival is the
        // assertion: the stream was never declared dead.
        for _ in 0..25 {
            write_client_frame(&mut peer, true, Opcode::Pong, b"alive").await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        write_client_frame(&mut peer, true, Opcode::Binary, b"still here").await;
        assert_eq!(
            pump.await.expect("join").expect("recv"),
            Event::Message(b"still here".to_vec()),
            "answering pings must keep the stream open"
        );
    }

    #[tokio::test]
    async fn the_stream_ends_at_its_maximum_lifetime_however_healthy_it_is() {
        let limits = Limits {
            ping_interval: Duration::from_millis(10),
            pong_deadline: Duration::from_secs(30),
            max_lifetime: Duration::from_millis(40),
            ..Limits::default()
        };
        let (mut server, mut peer) = pair(limits);
        let pump = tokio::spawn(async move { server.recv().await });

        // Keep talking the whole time; it must not matter. The writes are
        // allowed to fail once the server has gone, which is the outcome under
        // test rather than a problem with the test.
        for _ in 0..10 {
            let mut bytes = Vec::new();
            frame::encode(&mut bytes, true, Opcode::Pong, b"", Some([1, 2, 3, 4]));
            if peer.write_all(&bytes).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        assert_eq!(pump.await.expect("join").expect("recv"), Event::Closed(Closed::LifetimeReached));
    }

    #[tokio::test]
    async fn a_close_from_the_peer_is_reported_with_its_code_and_echoed() {
        let (mut server, mut peer) = pair(brisk());
        let body = close::encode_body(CloseCode::GoingAway, "tab closed");
        write_client_frame(&mut peer, true, Opcode::Close, &body).await;

        let event = server.recv().await.expect("recv");
        assert_eq!(
            event,
            Event::Closed(Closed::Peer(CloseFrame::new(CloseCode::GoingAway, "tab closed")))
        );
        let echo = read_server_frame(&mut peer).await;
        assert_eq!(echo.opcode, Opcode::Close, "a close is answered with a close");
    }

    #[tokio::test]
    async fn a_transport_that_vanishes_is_reported_as_abrupt() {
        let (mut server, peer) = pair(brisk());
        drop(peer);
        assert_eq!(server.recv().await.expect("recv"), Event::Closed(Closed::Abrupt));
    }

    #[tokio::test]
    async fn recv_after_the_end_keeps_answering_rather_than_reading_a_dead_socket() {
        let (mut server, peer) = pair(brisk());
        drop(peer);
        assert!(matches!(server.recv().await.expect("recv"), Event::Closed(_)));
        assert!(matches!(server.recv().await.expect("recv"), Event::Closed(Closed::Abrupt)));
    }

    #[tokio::test]
    async fn a_text_frame_is_refused_with_1003() {
        let (mut server, mut peer) = pair(brisk());
        // Opcode 0x1 cannot be built through `Opcode`, which is the point; write
        // the bytes by hand as a browser calling `send("text")` would.
        let mut bytes = vec![0x81, 0x84, 1, 2, 3, 4];
        bytes.extend_from_slice(&[b't' ^ 1, b'e' ^ 2, b'x' ^ 3, b't' ^ 4]);
        peer.write_all(&bytes).await.expect("write");

        let error = server.recv().await.expect_err("a text frame must end the stream");
        assert!(matches!(error, StreamError::Protocol(ProtocolError::TextFrame)));
        let closing = read_server_frame(&mut peer).await;
        assert_eq!(closing.opcode, Opcode::Close);
        assert_eq!(
            close::parse_body(&closing.payload).expect("close body").code,
            Some(CloseCode::UnacceptableData)
        );
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_with_1009_before_its_payload_arrives() {
        let limits = Limits { max_frame: 1024, max_message: 4096, ..brisk() };
        let (mut server, mut peer) = pair(limits);
        // A header declaring 64 MiB, and not one byte of payload behind it.
        let mut bytes = vec![0x82, 0xff];
        bytes.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        peer.write_all(&bytes).await.expect("write");

        let error = server.recv().await.expect_err("an oversized frame must end the stream");
        assert!(matches!(error, StreamError::Protocol(ProtocolError::FrameTooLarge(_))));
        let closing = read_server_frame(&mut peer).await;
        assert_eq!(
            close::parse_body(&closing.payload).expect("close body").code,
            Some(CloseCode::MessageTooBig)
        );
    }

    #[tokio::test]
    async fn an_unmasked_client_frame_ends_the_stream() {
        let (mut server, mut peer) = pair(brisk());
        let mut bytes = Vec::new();
        frame::encode(&mut bytes, true, Opcode::Binary, b"unmasked", None);
        peer.write_all(&bytes).await.expect("write");
        let error = server.recv().await.expect_err("client frames must be masked");
        assert!(matches!(error, StreamError::Protocol(ProtocolError::UnmaskedClientFrame)));
    }

    #[tokio::test]
    async fn a_message_over_the_ceiling_is_refused_during_reassembly() {
        let limits = Limits { max_frame: 64, max_message: 100, ..brisk() };
        let (mut server, mut peer) = pair(limits);
        write_client_frame(&mut peer, false, Opcode::Binary, &[7u8; 60]).await;
        write_client_frame(&mut peer, true, Opcode::Continuation, &[7u8; 60]).await;
        let error = server.recv().await.expect_err("the message ceiling must fire");
        assert!(matches!(error, StreamError::Protocol(ProtocolError::MessageTooLarge(120))));
    }

    #[tokio::test]
    async fn a_message_larger_than_the_frame_ceiling_is_refused_rather_than_split() {
        let (mut server, _peer) = pair(Limits { max_frame: 16, ..brisk() });
        let error = server.send(&[0u8; 17]).await.expect_err("too large to frame");
        assert!(matches!(error, StreamError::Protocol(ProtocolError::FrameTooLarge(17))));
    }

    #[tokio::test]
    async fn the_two_sides_talk_to_each_other() {
        // The most honest end-to-end check available without a network: our
        // client role and our server role, over one in-memory pipe.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut server = Duplex::server(a, brisk());
        let mut client = Duplex::client(b, brisk());

        client.send(b"from the client").await.expect("send");
        assert_eq!(server.recv().await.expect("recv"), Event::Message(b"from the client".to_vec()));

        server.send(b"from the server").await.expect("send");
        assert_eq!(client.recv().await.expect("recv"), Event::Message(b"from the server".to_vec()));
    }

    #[tokio::test]
    async fn a_sender_on_a_finished_stream_reports_that_it_is_gone() {
        let (server, peer) = pair(brisk());
        let sender = server.sender();
        drop(peer);
        drop(server);
        assert_eq!(sender.send(b"nobody home".to_vec()).await, Err(Gone));
    }
}
