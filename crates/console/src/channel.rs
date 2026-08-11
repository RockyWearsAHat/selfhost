//! The desktop stream: one long-lived socket carrying a machine's screen into
//! this window, and this window's keyboard back.
//!
//! # Why this is not [`crate::client`]
//!
//! That client's entire design is one request per connection with a ten-second
//! deadline, which is right for a control API answering a poll every half
//! second and wrong for everything here. A desktop session is one connection
//! held open for hours, carrying megabytes a second in one direction and a
//! keystroke at a time in the other, and it has to be readable while the frame
//! loop draws. So this is a second, separate thread, shaped on
//! [`crate::tunnel`]'s supervised long-lived connection rather than on the
//! poller's.
//!
//! # Two locks, not one, and why
//!
//! Everything else this console knows lives behind one [`Snapshot`] lock,
//! because the interface reads it and the poller writes it and both are brief.
//! A screen is not brief. A 1920×1080 frame is eight megabytes, it arrives up to
//! thirty times a second, and fitting it to the pane costs a millisecond and a
//! half — so putting it behind that lock would make the SERVICES rail wait on a
//! video stream. The picture therefore has a lock of its own
//! ([`Session::picture`]), held only across a `memcpy`, and the session's *state*
//! — which is small, and which the plate reads beside everything else — has
//! another ([`Session::live`]).
//!
//! # Where the fitting happens, and why it is here
//!
//! [`rui::Canvas::blit_bgra`] is a one-to-one copy by design: it will not
//! resample, and it says so. A far screen is almost never the size of the pane
//! showing it, so somebody has to. Doing it in the frame loop would charge every
//! repaint — a hover, a keystroke, a poll landing — for a resample of the whole
//! screen. Doing it here charges each *arriving frame* once, on the thread that
//! is already holding the pixels, and the frame loop is left with a copy. The
//! interface states the size it wants through [`Session::fit_handle`] and this
//! thread meets it.
//!
//! # Nothing here binds a socket
//!
//! It dials out, to the same `127.0.0.1:9191` the poller already dials, over the
//! same SSH forward and with the same bearer credential. There is no listener,
//! no port, and no second authentication scheme: the ticket is minted through
//! the control API this console is already authorised on, and it is spent
//! immediately on a handshake that cannot be replayed.

use crate::client::{Answer, Client, Method};
use crate::remote::{ControlRefusal, LOCAL_NODE};
use rui::Redraw;
use selfhost_desk::grant::Capabilities;
use selfhost_desk::state::Notice;
use selfhost_desk::tiles::{Grid, Surface, TileSize};
use selfhost_desk::wire::{Message, Monitor, Refusal};
use selfhost_http::{IncomingResponse, ParseError};
use selfhost_json::Json;
use selfhost_ws::frame::{self, Assembler, Opcode, Role};
use selfhost_ws::Limits;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The subprotocol token both ends offer for a desktop stream.
///
/// Mirrors `Ability::protocol` in `crates/admin/src/upgrade.rs`. Versioned in
/// the name rather than negotiated in a field: a console that spoke a different
/// revision of the message shape would offer a different token and be answered
/// with no subprotocol at all, which it can notice.
const PROTOCOL: &str = "selfhost.desktop.1";

/// The prefix marking a subprotocol token as a ticket.
///
/// Mirrors `upgrade::TICKET_PREFIX`. `Sec-WebSocket-Protocol` is the one header
/// a browser may set on a handshake, so that is where the ticket travels — and
/// this console uses the same door rather than a second one, so there is one
/// path through the server's admission code and not two.
const TICKET_PREFIX: &str = "tkt.";

/// How long to wait for the socket to accept, and for the handshake to answer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a read blocks before the loop looks at its outgoing queue.
///
/// Short, because this is the delay between pressing a key and the message
/// leaving. It costs nothing: a timed-out read is one syscall.
const READ_TIMEOUT: Duration = Duration::from_millis(15);

/// How many input messages may be queued before further ones are dropped.
///
/// Small deliberately. The queue exists so a keystroke does not wait on a frame
/// being read, not so input can buffer: a person cannot generate sixty-four
/// meaningful events while the socket is blocked, so a full queue means the far
/// end has stopped taking them and holding more would only replay a burst of
/// stale pointer moves at whatever comes back.
const OUTGOING_DEPTH: usize = 64;

/// The pace the interface is asked to keep while a session is live.
///
/// A ceiling on how long a delivered frame may wait for a repaint, not a frame
/// rate — see [`rui::Redraw::within`]. Sixteen milliseconds is one refresh of an
/// ordinary display; a stream arriving at thirty frames a second is then never
/// more than one frame behind, and a stream that stops draws nothing at all.
const STREAM_LATENCY: Duration = Duration::from_millis(16);

/// The largest message this console will read off the wire.
///
/// The desktop protocol's own ceiling, restated as the framing limit so a peer
/// cannot make this process allocate by claiming a larger frame than the codec
/// above it could ever parse.
const MAX_FRAME: usize = selfhost_desk::wire::MAX_MESSAGE + 8;

/// Where a session is, from this end.
///
/// Separate from [`Notice`], which is the *far machine's* account of itself: a
/// stream that never opened has no notice to show, and a notice from a session
/// whose socket has since died would be a fact with no clock on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    /// The ticket is being minted and the socket opened.
    Dialling,
    /// Frames are arriving, or would be.
    Open,
    /// It ended, and this is why.
    ///
    /// Ended rather than failed: an operator pressing DISCONNECT and a socket
    /// that died land here alike, because what the plate has to say next —
    /// "there is no session, and here is the reason" — is the same either way.
    Ended(String),
}

impl LinkState {
    /// Whether a session is still worth drawing a viewport for.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

/// Everything the plate needs that is not pixels.
///
/// Small, and copied out under the lock in one go, so the interface never holds
/// this while it draws.
#[derive(Debug, Clone)]
pub struct Live {
    /// Where the session is from this end.
    pub state: LinkState,
    /// The far machine's own account of itself, once it has said anything.
    pub notice: Option<Notice>,
    /// Whatever detail came with the notice.
    pub detail: String,
    /// What the redeemed ticket actually granted — echoed by the agent, so this
    /// is the truth rather than what was asked for.
    pub capabilities: Capabilities,
    /// Every display the agent advertised.
    pub monitors: Vec<Monitor>,
    /// Which one is being watched.
    pub monitor: u8,
    /// The last input refusal and how many events it has swallowed.
    pub refusal: Option<(Refusal, u32)>,
    /// Why the daemon would not mint what this session asked for.
    ///
    /// Kept in its structured form rather than as the sentence
    /// [`LinkState::Ended`] carries, because the plate has to tell a stale
    /// login from a switch that is off from a plain refusal, and only one of
    /// the three is worth suggesting anything about.
    pub control_refusal: Option<ControlRefusal>,
    /// Whole frames presented.
    pub frames: u64,
    /// Bytes read off the socket.
    pub bytes: u64,
    /// When the session opened.
    pub since: Instant,
}

impl Live {
    /// A session that has not opened yet.
    ///
    /// Public because the plate's own rules — which mode a session is in,
    /// whether a keystroke is forwarded — are asserted against a `Live` built
    /// by hand, and a test that had to open a socket to reach them is a test
    /// nobody runs.
    pub fn opening() -> Self {
        Self {
            state: LinkState::Dialling,
            notice: None,
            detail: String::new(),
            capabilities: Capabilities::none(),
            monitors: Vec::new(),
            monitor: 0,
            refusal: None,
            control_refusal: None,
            frames: 0,
            bytes: 0,
            since: Instant::now(),
        }
    }

    /// Whether this session was granted a keyboard.
    pub fn may_control(&self) -> bool {
        self.capabilities.contains(Capabilities::CONTROL)
    }

    /// Whether the far machine is taking input right now.
    ///
    /// Both halves are required: a session whose socket has died is not live
    /// however recently the agent said it was, and an agent that has suspended
    /// itself is not live however healthy the socket is.
    pub fn far_end_is_live(&self) -> bool {
        self.state.is_open() && self.notice == Some(Notice::Live)
    }

}

/// One fitted frame, ready to be blitted.
///
/// The picture is stored at the size the pane asked for and in the byte order
/// the canvas takes, so drawing it is a copy and nothing else.
#[derive(Debug, Default)]
pub struct Picture {
    /// Tight BGRA, `width * height * 4` bytes.
    bytes: Vec<u8>,
    /// Its width in device pixels.
    width: u32,
    /// Its height in device pixels.
    height: u32,
    /// The far display's own width, so a pointer position can be mapped back.
    source_width: u32,
    /// The far display's own height.
    source_height: u32,
}

impl Picture {
    /// The pixels, with their size, or `None` before the first frame.
    pub fn bgra(&self) -> Option<(&[u8], u32, u32)> {
        (!self.bytes.is_empty()).then_some((&self.bytes, self.width, self.height))
    }

    /// Where a point inside the drawn picture lands on the far display.
    ///
    /// `across` and `down` are fractions of the drawn picture, which is what the
    /// viewport has: it knows where the pointer is within the rectangle it drew
    /// and nothing about the far machine's geometry. Answers `None` before there
    /// is a picture, because a click that landed on an empty pane names no
    /// pixel and guessing at one would move a real pointer somewhere arbitrary.
    pub fn remote_point(&self, across: f32, down: f32) -> Option<(i32, i32)> {
        if self.source_width == 0 || self.source_height == 0 {
            return None;
        }
        let x = (across.clamp(0.0, 1.0) * (self.source_width - 1) as f32).round() as i32;
        let y = (down.clamp(0.0, 1.0) * (self.source_height - 1) as f32).round() as i32;
        Some((x, y))
    }
}

/// A live desktop session, from the console's side.
///
/// Dropping it stops the thread: the flag is cleared and the socket's read
/// deadline expires within [`READ_TIMEOUT`], so a window closing does not leave
/// a stream open on the daemon holding a place in its ceiling.
pub struct Session {
    live: Arc<Mutex<Live>>,
    picture: Arc<Mutex<Picture>>,
    /// The size the interface wants the picture fitted to, in device pixels.
    fit: Arc<Mutex<(u32, u32)>>,
    outgoing: SyncSender<Message>,
    running: Arc<AtomicBool>,
    /// Which machine this session is watching.
    peer: String,
    /// Whether it asked for a keyboard.
    asked_for_control: bool,
}

impl Session {
    /// Opens a session against `peer`, asking for control only if `control`.
    ///
    /// **Control is a separate, explicitly authorised action, exactly as it is
    /// in the browser.** A viewing session asks for `desktop.view` alone; taking
    /// the keyboard closes that session and opens a new one asking for
    /// `desktop.control`, which the daemon decides against its own freshness
    /// rule. There is no path through this function that turns a viewing session
    /// into a driving one without a mint the daemon can refuse.
    pub fn open(client: Client, peer: &str, control: bool, redraw: Redraw) -> Self {
        let live = Arc::new(Mutex::new(Live::opening()));
        let picture = Arc::new(Mutex::new(Picture::default()));
        let fit = Arc::new(Mutex::new((0, 0)));
        let running = Arc::new(AtomicBool::new(true));
        let (outgoing, inbox) = std::sync::mpsc::sync_channel(OUTGOING_DEPTH);

        let thread = Stream {
            client,
            peer: peer.to_owned(),
            control,
            live: Arc::clone(&live),
            picture: Arc::clone(&picture),
            fit: Arc::clone(&fit),
            inbox,
            running: Arc::clone(&running),
            redraw,
        };
        // A stream that cannot get a thread is a session that never opens, and
        // the plate must say so rather than sit on `Dialling` for ever.
        if let Err(error) =
            std::thread::Builder::new().name("selfhost-console-desktop".into()).spawn(move || {
                thread.run();
            })
        {
            end(&live, format!("could not start the stream thread: {error}"));
        }

        Self {
            live,
            picture,
            fit,
            outgoing,
            running,
            peer: peer.to_owned(),
            asked_for_control: control,
        }
    }

    /// Whether this session asked for a keyboard when it was opened.
    ///
    /// What the plate reads to tell "watching" from "control was asked for and
    /// refused": [`Live::may_control`] answers what was *granted*, and the
    /// difference between the two is the sentence worth showing.
    pub fn asked_for_control(&self) -> bool {
        self.asked_for_control
    }

    /// Everything the plate needs that is not pixels.
    pub fn live(&self) -> Live {
        self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// The picture, for the one element that draws it.
    pub fn picture(&self) -> MutexGuard<'_, Picture> {
        self.picture.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A handle on the picture that outlives a borrow of this session.
    ///
    /// The viewport draws through a closure `rui` keeps for the frame, and a
    /// closure cannot borrow the console it was built from. This is the one
    /// thing it captures: not the session, not the snapshot, just the pixels,
    /// behind the lock that is held only across the copy that draws them.
    pub fn picture_handle(&self) -> Arc<Mutex<Picture>> {
        Arc::clone(&self.picture)
    }

    /// A handle on the size the picture should be fitted to.
    ///
    /// Paired with [`Session::picture_handle`] and captured by the same closure,
    /// so the element that knows how big it was drawn is the one that says so.
    pub fn fit_handle(&self) -> Arc<Mutex<(u32, u32)>> {
        Arc::clone(&self.fit)
    }

    /// Sends one message to the far machine, dropping it if the queue is full.
    ///
    /// Dropped rather than blocked: this is called from the frame loop, and a
    /// loop that waits on a socket is a window that has stopped repainting at
    /// exactly the moment the operator wants to know why. A dropped message is
    /// visible — the far pointer does not move — and a frozen window is not.
    pub fn send(&self, message: Message) {
        match self.outgoing.try_send(message) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            // The thread has gone. Nothing to report here: it published its own
            // reason into `live` on the way out, which is what the plate draws.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Asks for a full frame of the display being watched.
    pub fn request_full_frame(&self) {
        let monitor = self.live().monitor;
        self.send(Message::RequestFullFrame { monitor });
    }

    /// Watches a different display.
    pub fn watch(&self, monitor: u8) {
        {
            let mut live = self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            live.monitor = monitor;
        }
        // The surface being held is the old display's; asking for a keyframe is
        // what makes the next picture the new one rather than a tile-by-tile
        // dissolve between two screens.
        self.send(Message::RequestFullFrame { monitor });
    }

    /// Lets go of every key the far machine is holding for this session.
    ///
    /// Sent whenever the keyboard leaves this window, and again on the way out.
    /// Without it a modifier that went down here stays down there — the failure
    /// [`selfhost_desk::keys::HeldKeys`] exists to insist on.
    pub fn release_all(&self) {
        self.send(Message::ReleaseAll);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.release_all();
        self.running.store(false, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Session")
            .field("peer", &self.peer)
            .field("asked_for_control", &self.asked_for_control)
            .field("state", &self.live().state)
            .finish()
    }
}

/// The thread's own half of a session.
struct Stream {
    client: Client,
    peer: String,
    control: bool,
    live: Arc<Mutex<Live>>,
    picture: Arc<Mutex<Picture>>,
    fit: Arc<Mutex<(u32, u32)>>,
    inbox: Receiver<Message>,
    running: Arc<AtomicBool>,
    redraw: Redraw,
}

impl Stream {
    /// Mints, dials, and pumps until something ends it.
    fn run(self) {
        let reason = match self.pump() {
            Ok(()) => "the session was closed".to_owned(),
            Err(reason) => reason,
        };
        // The window goes back to its idle pace the moment pixels stop, so a
        // dead stream does not keep a laptop's core awake sixty times a second.
        self.redraw.within(Duration::ZERO);
        self.redraw.request();
        end(&self.live, reason);
    }

    /// The session proper, up to whatever ends it.
    fn pump(&self) -> Result<(), String> {
        let ticket = self.mint()?;
        let mut socket = self.dial(&ticket)?;
        {
            let mut live = self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            live.state = LinkState::Open;
            live.since = Instant::now();
        }
        self.redraw.within(STREAM_LATENCY);

        let limits = Limits { max_message: MAX_FRAME, ..Limits::default() };
        let mut assembler = Assembler::new(limits);
        let mut masks = Masks::new();
        let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut scratch = [0u8; 64 * 1024];
        let mut screen = Screen::default();

        while self.running.load(Ordering::Relaxed) {
            // Outgoing first: a keystroke waiting behind a frame read is the
            // one latency a person actually feels.
            while let Ok(message) = self.inbox.try_recv() {
                let payload = message
                    .encode()
                    .map_err(|error| format!("could not encode an input message: {error}"))?;
                let mut framed = Vec::with_capacity(payload.len() + 14);
                frame::encode(&mut framed, true, Opcode::Binary, &payload, Some(masks.next()));
                socket
                    .write_all(&framed)
                    .map_err(|error| format!("the session's socket failed: {error}"))?;
            }

            match socket.read(&mut scratch) {
                Ok(0) => return Err("the daemon closed the session".into()),
                Ok(read) => {
                    buffer.extend_from_slice(scratch.get(..read).unwrap_or_default());
                    let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                    live.bytes = live.bytes.saturating_add(read as u64);
                }
                Err(error) if would_block(&error) => {}
                Err(error) => return Err(format!("the session's socket failed: {error}")),
            }

            while let Some((payload, consumed)) = next_message(&buffer, &limits, &mut assembler)? {
                buffer.drain(..consumed);
                let Some(payload) = payload else {
                    continue;
                };
                match Message::decode(&payload) {
                    Ok(message) => self.apply(message, &mut screen, &mut socket, &mut masks)?,
                    // A message this build cannot read is not a reason to drop a
                    // session: the codec is versioned by subprotocol, so an
                    // unreadable one is a defect worth reporting once and not a
                    // stream to abandon mid-frame.
                    Err(error) => {
                        let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                        live.detail = format!("unreadable message: {error}");
                    }
                }
            }
        }
        Ok(())
    }

    /// Asks the control API for a ticket, and answers its value.
    ///
    /// The abilities are named explicitly and each is decided separately by the
    /// daemon. A refusal keeps its status and body, because the difference
    /// between "your login is too old", "a switch on the box is off" and "you
    /// may not" is the whole of what the plate has to say next — see
    /// [`crate::remote::ControlRefusal`], which is what turns this back into a
    /// sentence.
    fn mint(&self) -> Result<String, String> {
        let mut want = vec![Json::string("desktop.view")];
        if self.control {
            want.push(Json::string("desktop.control"));
        }
        let body = Json::object([
            ("want", Json::array(want)),
            ("peer", Json::string(self.peer.as_str())),
        ]);
        match self.client.ask(Method::Post, "/api/desktop/ticket", Some(&body)) {
            Answer::Ok(value) => value
                .get("ticket")
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "the daemon minted a ticket with no value in it".to_owned()),
            Answer::Refused { status, body } => {
                let refusal = ControlRefusal::of(status.code(), Some(&body));
                let sentence = refusal.sentence();
                self.live.lock().unwrap_or_else(|p| p.into_inner()).control_refusal =
                    Some(refusal);
                Err(sentence)
            }
            Answer::Failed(error) => Err(error.to_string()),
        }
    }

    /// Opens the socket and completes the handshake.
    fn dial(&self, ticket: &str) -> Result<TcpStream, String> {
        let address = self.client.address();
        let mut socket = TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT)
            .map_err(|error| format!("cannot reach the daemon: {error}"))?;
        socket
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .and_then(|()| socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT)))
            .and_then(|()| socket.set_nodelay(true))
            .map_err(|error| format!("the session's socket refused a deadline: {error}"))?;

        let key = nonce();
        let request = handshake_request(&address, &self.peer, ticket, &key, self.client.token());
        socket
            .write_all(request.as_bytes())
            .map_err(|error| format!("the handshake could not be sent: {error}"))?;

        let head = read_head(&mut socket)?;
        check_handshake(&head, &key)?;
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|error| format!("the session's socket refused a deadline: {error}"))?;
        Ok(socket)
    }

    /// Folds one decoded message into the session.
    fn apply(
        &self,
        message: Message,
        screen: &mut Screen,
        socket: &mut TcpStream,
        masks: &mut Masks,
    ) -> Result<(), String> {
        match message {
            Message::Hello(hello) => {
                let monitor = hello
                    .monitors
                    .iter()
                    .find(|monitor| monitor.primary)
                    .or_else(|| hello.monitors.first())
                    .map_or(0, |monitor| monitor.id);
                screen.tile = hello.tile;
                let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                live.capabilities = hello.capabilities;
                live.monitors = hello.monitors;
                live.monitor = monitor;
            }
            Message::Status { notice, detail } => {
                let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                live.notice = Some(notice);
                live.detail = detail;
            }
            Message::FrameBegin(begin) => {
                if begin.monitor != self.watching() {
                    screen.frame = None;
                    return Ok(());
                }
                screen.begin(&begin)?;
            }
            Message::Tile(tile) => screen.tile(&tile)?,
            Message::FrameEnd { .. } => {
                if screen.frame.is_some() {
                    self.present(screen);
                }
            }
            Message::CursorPos(_) | Message::CursorShape(_) => {
                // The far machine's own pointer is drawn into the frame it
                // sends; a separate cursor layer is what the browser adds to
                // track at the *browser's* frame rate, and this console has no
                // sub-frame layer to put one on. Recorded here as a deliberate
                // absence rather than a message silently ignored.
            }
            Message::InputRefused { reason } => {
                let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                live.refusal = Some(match live.refusal {
                    Some((held, count)) if held == reason => (reason, count.saturating_add(1)),
                    _ => (reason, 1),
                });
            }
            // Everything else on this wire travels the other way. The agent
            // never sends one, so one arriving is a peer that is not the agent.
            other => {
                let _ = (socket, masks);
                return Err(format!("the far end sent {}, which only a console sends", other.name()));
            }
        }
        Ok(())
    }

    /// Which display the operator has chosen.
    fn watching(&self) -> u8 {
        self.live.lock().unwrap_or_else(|p| p.into_inner()).monitor
    }

    /// Fits the completed frame to the pane and publishes it.
    fn present(&self, screen: &mut Screen) {
        let Some(surface) = screen.frame.as_ref() else {
            return;
        };
        let (want_width, want_height) =
            *self.fit.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fitted = fit(surface, want_width, want_height);
        {
            let mut picture = self.picture.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *picture = fitted;
        }
        {
            let mut live = self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            live.frames = live.frames.saturating_add(1);
        }
        self.redraw.request();
    }
}

/// The surface being assembled, and the grid it is assembled on.
#[derive(Debug, Default)]
struct Screen {
    /// The tile edge the agent said it would use.
    tile: TileSize,
    /// The picture as it stands, or `None` before the first frame begins.
    frame: Option<Surface>,
    /// The grid the current frame's tiles are placed on.
    grid: Option<Grid>,
}

impl Screen {
    /// Starts a frame, rebuilding the surface when the display has changed size.
    fn begin(&mut self, begin: &selfhost_desk::wire::FrameBegin) -> Result<(), String> {
        let rebuild = match &self.frame {
            Some(surface) => surface.width() != begin.width || surface.height() != begin.height,
            None => true,
        };
        if rebuild {
            self.frame = Some(
                Surface::blank(begin.width, begin.height)
                    .map_err(|error| format!("the far display's size is unusable: {error}"))?,
            );
        }
        self.grid = Some(
            Grid::new(self.tile, begin.width, begin.height)
                .map_err(|error| format!("the far display's size is unusable: {error}"))?,
        );
        Ok(())
    }

    /// Places one tile, resolving its claimed coordinate against the grid.
    ///
    /// The coordinate arrives unvalidated and across its full numeric range —
    /// [`selfhost_desk::wire::TileMessage`] says so in as many words — and
    /// [`Grid::bounds`] is the one function that knows the extent. A tile
    /// outside it is dropped rather than ending the session: a resolution change
    /// in flight produces exactly that, and it is corrected by the keyframe the
    /// agent sends with it.
    fn tile(&mut self, tile: &selfhost_desk::wire::TileMessage) -> Result<(), String> {
        let (Some(surface), Some(grid)) = (self.frame.as_mut(), self.grid) else {
            return Ok(());
        };
        let Ok(rect) = grid.bounds(tile.coord()) else {
            return Ok(());
        };
        let pixels = rect.width as usize * rect.height as usize;
        let decoded = selfhost_desk::tiles::decode_tile(tile.encoding, &tile.payload, pixels)
            .map_err(|error| format!("a tile would not decode: {error}"))?;
        if let selfhost_desk::tiles::Decoded::Pixels(pixels) = decoded {
            surface
                .put_tile(rect, &pixels)
                .map_err(|error| format!("a tile would not land: {error}"))?;
        }
        Ok(())
    }
}

/// Fits a captured surface into a device rectangle, preserving its shape.
///
/// # Nearest-neighbour, deliberately
///
/// The two honest choices for a moving picture are nearest-neighbour, which
/// shimmers, and a weighted filter, which blurs text. A remote desktop is mostly
/// *text*, and blurred text is unreadable in a way a shimmering edge is not — so
/// this takes the sharp one. It is also four times cheaper, which is what keeps
/// the whole fit inside a millisecond and a half at 1920×1080.
///
/// A picture smaller than the pane is left at its own size rather than magnified:
/// one remote pixel per device pixel is the sharpest a screen can be shown, and
/// stretching it would trade that for filling a rectangle.
fn fit(surface: &Surface, want_width: u32, want_height: u32) -> Picture {
    let (source_width, source_height) = (surface.width(), surface.height());
    if want_width == 0 || want_height == 0 || source_width == 0 || source_height == 0 {
        return Picture::default();
    }
    // The larger of the two ratios, so the whole picture fits inside the pane on
    // its tighter axis; capped at one so a small screen is never magnified.
    let across = want_width as f64 / source_width as f64;
    let down = want_height as f64 / source_height as f64;
    let scale = across.min(down).min(1.0);
    let width = ((source_width as f64 * scale).round() as u32).max(1);
    let height = ((source_height as f64 * scale).round() as u32).max(1);

    let mut bytes = vec![0u8; width as usize * height as usize * 4];
    let source = surface.pixels();
    for y in 0..height as usize {
        let source_y = (y * source_height as usize) / height as usize;
        let row = source_y * source_width as usize * 4;
        let target = y * width as usize * 4;
        for x in 0..width as usize {
            let source_x = (x * source_width as usize) / width as usize;
            let from = row + source_x * 4;
            let (Some(pixel), Some(cell)) =
                (source.get(from..from + 4), bytes.get_mut(target + x * 4..target + x * 4 + 4))
            else {
                continue;
            };
            cell.copy_from_slice(pixel);
        }
    }
    Picture { bytes, width, height, source_width, source_height }
}

/// Records why a session ended, leaving everything else it said in place.
fn end(live: &Arc<Mutex<Live>>, reason: String) {
    let mut live = live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    live.state = LinkState::Ended(reason);
}

/// Whether a read timed out rather than failed.
///
/// A socket with a read deadline reports one of two errors depending on the
/// platform, and treating either as a failure would end a session every fifteen
/// milliseconds.
fn would_block(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
    )
}

/// A whole application message read off the wire, and how many bytes it took.
///
/// The payload is an `Option` because a frame can be a ping or a continuation,
/// which carries no message and is still consumed like any other.
type Framed = (Option<Vec<u8>>, usize);

/// The next whole application message in `buffer`, and how much it consumed.
///
/// `Ok(None)` means "not a whole frame yet", which is the ordinary case on a
/// stream. `Ok(Some((None, n)))` is a frame that carried no application message
/// — a continuation, a pong — and is consumed like any other.
fn next_message(
    buffer: &[u8],
    limits: &Limits,
    assembler: &mut Assembler,
) -> Result<Option<Framed>, String> {
    match frame::parse(buffer, Role::Client, limits) {
        Ok(parsed) => {
            let consumed = parsed.consumed;
            match parsed.frame.opcode {
                // A close from the far end is the session ending politely, and
                // it is reported as an end rather than as a failure.
                Opcode::Close => Err("the daemon closed the session".into()),
                // Nothing here answers a ping. The daemon's own duplex sends
                // one only to detect a peer that has gone, and a console that
                // is reading frames has already proved it has not.
                Opcode::Ping | Opcode::Pong => Ok(Some((None, consumed))),
                _ => {
                    let message = assembler
                        .accept(parsed.frame)
                        .map_err(|error| format!("the far end broke framing: {error}"))?;
                    Ok(Some((message, consumed)))
                }
            }
        }
        Err(frame::ProtocolError::Incomplete) => Ok(None),
        Err(error) => Err(format!("the far end broke framing: {error}")),
    }
}

/// The handshake request, in full.
///
/// Written out rather than built through the response helpers because this is
/// the *client* side, which nothing else in this workspace has ever needed. The
/// header set is exactly RFC 6455 §4.1 plus the two this deployment adds: the
/// bearer credential, and the ticket riding in the subprotocol list.
///
/// There is no `Origin`. `crates/admin`'s [`origin_permitted`] accepts an absent
/// one from a non-browser credential and refuses it from a cookie, which is the
/// rule this console satisfies by holding a bearer token — inventing an origin
/// would be claiming to be a page.
///
/// [`origin_permitted`]: https://docs.rs/
fn handshake_request(
    address: &std::net::SocketAddr,
    peer: &str,
    ticket: &str,
    key: &str,
    token: &str,
) -> String {
    let target = if peer == LOCAL_NODE {
        "/api/desktop/session".to_owned()
    } else {
        format!("/api/desktop/session?peer={peer}")
    };
    format!(
        "GET {target} HTTP/1.1\r\n\
         Host: {address}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {PROTOCOL}, {TICKET_PREFIX}{ticket}\r\n\
         Authorization: Bearer {token}\r\n\
         \r\n"
    )
}

/// Reads the response head, and nothing past it.
///
/// A successful handshake is answered with a head and no body, so anything the
/// daemon sent after it is the first WebSocket frame. This reads one byte at a
/// time once the head is nearly complete — it must not swallow those bytes,
/// because there is no way to give them back to the socket.
fn read_head(socket: &mut TcpStream) -> Result<IncomingResponse, String> {
    /// The most a refusal's head may be before this gives up on it.
    const MAX_HEAD: usize = 16 * 1024;
    let mut buffer = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => return Ok(parsed.response),
            Err(ParseError::Incomplete) => {}
            Err(error) => return Err(format!("the daemon's answer was unreadable: {error}")),
        }
        let read = socket
            .read(&mut byte)
            .map_err(|error| format!("the handshake was not answered: {error}"))?;
        if read == 0 {
            return Err("the daemon closed the connection during the handshake".into());
        }
        buffer.extend_from_slice(&byte);
        if buffer.len() > MAX_HEAD {
            return Err("the daemon's answer to the handshake is too large".into());
        }
    }
}

/// Whether the daemon actually agreed to speak this protocol on this socket.
///
/// All three checks are refusals and none is cosmetic. A status that is not
/// `101` is the authorisation answer and carries the words the plate shows. An
/// accept key that does not match the nonce means whatever answered did not read
/// the request — a proxy, or a cached response — and continuing would be reading
/// frames from something that never agreed to send any. A missing or different
/// subprotocol means the far end is not speaking this revision of the message
/// shape, which is the whole reason the token is versioned in its name.
fn check_handshake(head: &IncomingResponse, key: &str) -> Result<(), String> {
    if head.status.code() != 101 {
        return Err(refusal_reason(head.status.code(), head.status.reason()));
    }
    // Absent and wrong are told apart, because they mean different things: no
    // header at all is something that is not a WebSocket server answering on
    // this path, and a header that disagrees with the nonce is something that
    // answered without reading the request — a proxy, or a cached response.
    // Collapsing the two into one message sends the reader looking for the
    // wrong fault.
    let Some(accepted) = head.headers.get_str("sec-websocket-accept") else {
        return Err("the answer carried no Sec-WebSocket-Accept, so whatever is on that port is \
                    not this daemon"
            .into());
    };
    if accepted != selfhost_ws::accept_key(key) {
        return Err("the answer did not come from something that read the handshake".into());
    }
    match head.headers.get_str("sec-websocket-protocol") {
        Some(offered) if offered.trim() == PROTOCOL => Ok(()),
        _ => Err(format!(
            "the daemon does not speak {PROTOCOL} — this console and that box are different \
             versions"
        )),
    }
}

/// A refusal's status turned into words a person can act on.
///
/// The three legible refusals keep the daemon's own message, because
/// [`crate::remote::ControlRefusal`] re-reads them; everything else says what
/// happened rather than repeating a number.
fn refusal_reason(status: u16, message: &str) -> String {
    match status {
        401 => "the daemon refused this session — the credential may not watch that machine".into(),
        404 => "this deployment serves no desktop".into(),
        409 => "too many streams are already open on that machine".into(),
        _ => format!("the daemon refused the session ({status}): {message}"),
    }
}

/// Sixteen random bytes, base64, as `Sec-WebSocket-Key` requires.
///
/// Random and not a counter: RFC 6455 §4.1 requires the nonce to be
/// unpredictable, and the accept key computed from it is the only proof the
/// answer came from something that read the request rather than from a cache.
fn nonce() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    // A random source that will not answer is a machine that cannot open a TLS
    // connection either; the fallback is a nonce derived from the clock, which
    // is weaker and is still a value this process has not used before.
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos() as u64);
        bytes[..8].copy_from_slice(&now.to_le_bytes());
        bytes[8..].copy_from_slice(&(now.rotate_left(17)).to_le_bytes());
    }
    base64(&bytes)
}

/// Standard padded base64 (RFC 4648 §4).
///
/// Written here because `selfhost-ws`'s own encoder is private to the module
/// that computes the accept key, and the alternative — making it public — would
/// widen a crate's surface for one caller. Total: it indexes the alphabet only
/// with six-bit values and reads a short final chunk through `get`.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    /// One six-bit group of `bits`, as its alphabet character.
    fn digit(bits: u32, shift: u32) -> char {
        let index = ((bits >> shift) & 0x3f) as usize;
        ALPHABET.get(index).copied().unwrap_or(b'A') as char
    }
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let first = u32::from(chunk.first().copied().unwrap_or(0));
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let bits = (first << 16) | (second << 8) | third;
        out.push(digit(bits, 18));
        out.push(digit(bits, 12));
        match chunk.len() {
            1 => out.push_str("=="),
            2 => {
                out.push(digit(bits, 6));
                out.push('=');
            }
            _ => {
                out.push(digit(bits, 6));
                out.push(digit(bits, 0));
            }
        }
    }
    out
}

/// The masks a client frames with.
///
/// Every frame a client sends must be masked with a fresh, unpredictable value —
/// RFC 6455 §5.3, and the reason is a proxy that can be made to cache a
/// response it was tricked into parsing out of the payload. Seeded once from the
/// system's random source and advanced with SplitMix64, so the per-frame cost is
/// a multiply rather than a syscall and the sequence is still unguessable from
/// the outside.
struct Masks(u64);

impl Masks {
    /// A generator seeded from the system's random source.
    fn new() -> Self {
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 8];
        if ring::rand::SystemRandom::new().fill(&mut seed).is_err() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |since| since.as_nanos() as u64);
            seed.copy_from_slice(&now.to_le_bytes());
        }
        Self(u64::from_le_bytes(seed))
    }

    /// The next mask.
    fn next(&mut self) -> [u8; 4] {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((z ^ (z >> 31)) as u32).to_le_bytes()
    }
}

/// Constructors that stand a session up without a socket.
///
/// Test-only on purpose, and the reason is the reference frames: the viewport is
/// the one part of this console whose *drawing* cannot be photographed without a
/// live daemon, and a screen nobody has looked at is a screen with no design
/// review. These build a session holding one picture and no thread, so
/// `reference_frames` puts the real blit path — [`Picture::bgra`] through
/// [`rui::Canvas::blit_bgra`] — into an image a person can inspect.
#[cfg(test)]
impl Session {
    /// Re-fits `surface` to whatever the viewport last asked to be given.
    ///
    /// The settling a resized window does, driven by hand: the first frame
    /// states the pane's device size into the fit cell and this puts a picture
    /// of that size behind it, so the second frame draws a screen fitted to the
    /// pane rather than one cropped to it.
    pub fn settle(&self, surface: &Surface) {
        let (width, height) = *self.fit.lock().unwrap_or_else(|p| p.into_inner());
        *self.picture.lock().unwrap_or_else(|p| p.into_inner()) = fit(surface, width, height);
    }

    /// A session that never opens a socket but keeps what is sent to it.
    ///
    /// The other half of a still life, and what the pointer and keyboard tests
    /// cannot do without: what a viewport *sends* is the whole of what driving
    /// a far machine means, and [`Session::still_life`] deliberately drops its
    /// receiver so nothing it is told is remembered. The queue is deep enough
    /// that a test never blocks on it.
    pub fn recorded(
        peer: &str,
        control: bool,
        live: Live,
        picture: Picture,
    ) -> (Self, std::sync::mpsc::Receiver<Message>) {
        let (outgoing, incoming) = std::sync::mpsc::sync_channel(256);
        let mut session = Self::still_life(peer, control, live, picture);
        session.outgoing = outgoing;
        (session, incoming)
    }

    /// A session that never opens a socket, showing `picture`.
    pub fn still_life(peer: &str, control: bool, live: Live, picture: Picture) -> Self {
        // The receiver is dropped straight away, so every `send` on this
        // session reports `Disconnected` and does nothing — which is exactly
        // what a session with no far end should do.
        let (outgoing, _) = std::sync::mpsc::sync_channel(1);
        Self {
            live: Arc::new(Mutex::new(live)),
            picture: Arc::new(Mutex::new(picture)),
            fit: Arc::new(Mutex::new((0, 0))),
            outgoing,
            running: Arc::new(AtomicBool::new(false)),
            peer: peer.to_owned(),
            asked_for_control: control,
        }
    }
}

#[cfg(test)]
impl Picture {
    /// A picture fitted from `surface` into a rectangle of device pixels.
    ///
    /// The real fitting path, so what a frame photographs is what a stream would
    /// have produced rather than a hand-built buffer.
    pub fn fitted(surface: &Surface, width: u32, height: u32) -> Self {
        fit(surface, width, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A surface of one colour, for the fitting tests.
    fn surface(width: u32, height: u32) -> Surface {
        Surface::new(width, height, vec![0x40; width as usize * height as usize * 4])
            .expect("a surface")
    }

    #[test]
    fn a_picture_larger_than_the_pane_is_fitted_inside_it_whole() {
        let fitted = fit(&surface(1920, 1080), 1000, 1000);
        assert_eq!(fitted.width, 1000, "the tighter axis decides");
        assert_eq!(fitted.height, 563);
        assert!(fitted.height <= 1000);
        assert_eq!(fitted.bytes.len(), 1000 * 563 * 4);
    }

    #[test]
    fn a_picture_smaller_than_the_pane_is_never_magnified() {
        // One remote pixel per device pixel is the sharpest a screen can be
        // shown; filling the rectangle would trade that away.
        let fitted = fit(&surface(320, 200), 1000, 1000);
        assert_eq!((fitted.width, fitted.height), (320, 200));
    }

    #[test]
    fn the_shape_of_the_far_screen_survives_the_fit() {
        let fitted = fit(&surface(1600, 900), 400, 900);
        let source = 1600.0 / 900.0;
        let drawn = fitted.width as f32 / fitted.height as f32;
        assert!((source - drawn).abs() < 0.02, "{drawn} is not {source}");
    }

    #[test]
    fn a_pane_with_no_room_produces_no_picture_rather_than_an_empty_one() {
        assert!(fit(&surface(64, 64), 0, 100).bgra().is_none());
        assert!(fit(&surface(64, 64), 100, 0).bgra().is_none());
        assert!(Picture::default().bgra().is_none());
    }

    #[test]
    fn a_point_on_the_drawn_picture_lands_on_the_far_display() {
        let picture = fit(&surface(1920, 1080), 960, 1080);
        assert_eq!(picture.remote_point(0.0, 0.0), Some((0, 0)));
        assert_eq!(picture.remote_point(1.0, 1.0), Some((1919, 1079)));
        assert_eq!(picture.remote_point(0.5, 0.5), Some((960, 540)));
    }

    #[test]
    fn a_click_on_an_empty_pane_names_no_pixel() {
        // Guessing at one would move a real pointer on somebody's machine to an
        // arbitrary place.
        assert_eq!(Picture::default().remote_point(0.5, 0.5), None);
    }

    #[test]
    fn a_point_outside_the_picture_is_held_at_its_edge() {
        let picture = fit(&surface(100, 100), 100, 100);
        assert_eq!(picture.remote_point(-4.0, 9.0), Some((0, 99)));
    }

    #[test]
    fn the_handshake_carries_the_ticket_in_the_one_header_a_page_may_set() {
        let address = "127.0.0.1:9191".parse().expect("an address");
        let request = handshake_request(&address, "alex-desktop", "abc123", "AAA=", "tok");
        assert!(request.contains("GET /api/desktop/session?peer=alex-desktop HTTP/1.1\r\n"));
        assert!(request.contains("Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.abc123\r\n"));
        assert!(request.contains("Authorization: Bearer tok\r\n"));
        assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
        // A bearer credential does not claim to be a page, and `admin`'s own
        // rule accepts an absent Origin from exactly that.
        assert!(!request.contains("Origin:"));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_local_machine_is_named_by_leaving_the_peer_out() {
        // `desk_api::LOCAL_NODE` is what the route defaults to, so naming it
        // explicitly and leaving it out must reach the same session.
        let address = "127.0.0.1:9191".parse().expect("an address");
        let request = handshake_request(&address, LOCAL_NODE, "t", "k", "tok");
        assert!(request.contains("GET /api/desktop/session HTTP/1.1\r\n"));
    }

    #[test]
    fn a_nonce_is_a_legal_client_key_and_never_the_same_twice() {
        let first = nonce();
        assert!(selfhost_ws::accept::client_key_is_well_formed(&first), "{first} is not a key");
        assert_ne!(first, nonce());
    }

    #[test]
    fn base64_matches_the_encoding_the_accept_key_is_computed_over() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn every_mask_is_a_different_one() {
        let mut masks = Masks::new();
        let taken: Vec<[u8; 4]> = (0..8).map(|_| masks.next()).collect();
        for (index, mask) in taken.iter().enumerate() {
            assert!(
                !taken.iter().skip(index + 1).any(|other| other == mask),
                "a mask repeated inside eight frames"
            );
        }
    }

    #[test]
    fn an_answer_that_did_not_read_the_handshake_is_refused() {
        let mut head = IncomingResponse {
            status: selfhost_http::Status(101),
            minor_version: 1,
            headers: selfhost_http::Headers::new(),
            framing: selfhost_http::ResponseFraming::None,
        };
        let key = nonce();
        head.headers.set("sec-websocket-accept", "not-the-key").expect("a header");
        head.headers.set("sec-websocket-protocol", PROTOCOL).expect("a header");
        assert!(check_handshake(&head, &key).is_err(), "a wrong accept key must not pass");

        head.headers.set("sec-websocket-accept", selfhost_ws::accept_key(&key)).expect("a header");
        assert!(check_handshake(&head, &key).is_ok());
    }

    #[test]
    fn a_daemon_speaking_another_revision_is_refused_rather_than_read() {
        let mut head = IncomingResponse {
            status: selfhost_http::Status(101),
            minor_version: 1,
            headers: selfhost_http::Headers::new(),
            framing: selfhost_http::ResponseFraming::None,
        };
        let key = nonce();
        head.headers.set("sec-websocket-accept", selfhost_ws::accept_key(&key)).expect("a header");
        head.headers.set("sec-websocket-protocol", "selfhost.desktop.2").expect("a header");
        let refusal = check_handshake(&head, &key).expect_err("a refusal");
        assert!(refusal.contains("different"), "{refusal}");
    }

    #[test]
    fn a_refused_handshake_says_what_can_be_done_about_it() {
        let head = IncomingResponse {
            status: selfhost_http::Status(401),
            minor_version: 1,
            headers: selfhost_http::Headers::new(),
            framing: selfhost_http::ResponseFraming::None,
        };
        let refusal = check_handshake(&head, "key").expect_err("a refusal");
        assert!(refusal.contains("may not watch"), "{refusal}");
        assert!(refusal_reason(404, "").contains("no desktop"));
        assert!(refusal_reason(409, "").contains("too many streams"));
    }

    #[test]
    fn a_close_frame_ends_the_session_rather_than_being_read_as_a_message() {
        let mut framed = Vec::new();
        frame::encode(&mut framed, true, Opcode::Close, &[], None);
        let limits = Limits::default();
        let mut assembler = Assembler::new(limits);
        assert!(next_message(&framed, &limits, &mut assembler).is_err());
    }

    #[test]
    fn a_partial_frame_is_not_a_message_yet_and_is_not_an_error() {
        let limits = Limits::default();
        let mut assembler = Assembler::new(limits);
        assert_eq!(next_message(&[0x82], &limits, &mut assembler).expect("no error"), None);
    }

    #[test]
    fn a_whole_message_is_read_and_its_bytes_accounted_for() {
        let payload = Message::ReleaseAll.encode().expect("a message");
        let mut framed = Vec::new();
        frame::encode(&mut framed, true, Opcode::Binary, &payload, None);
        let sent = framed.len();
        framed.extend_from_slice(b"leftover");

        let limits = Limits::default();
        let mut assembler = Assembler::new(limits);
        let (message, consumed) =
            next_message(&framed, &limits, &mut assembler).expect("no error").expect("a frame");
        assert_eq!(consumed, sent, "the tail of the buffer is left for the next frame");
        assert_eq!(Message::decode(&message.expect("a payload")), Ok(Message::ReleaseAll));
    }

    #[test]
    fn a_session_holds_a_keyboard_only_when_both_ends_agree_it_is_live() {
        let mut live = Live::opening();
        live.capabilities = Capabilities::VIEW.with(Capabilities::CONTROL);
        live.notice = Some(Notice::Live);
        assert!(live.may_control());
        assert!(!live.far_end_is_live(), "the socket has not opened yet");

        live.state = LinkState::Open;
        assert!(live.far_end_is_live());

        live.notice = Some(Notice::SecureDesktop);
        assert!(!live.far_end_is_live(), "a suspended agent is not taking keys");
    }
}
