//! This machine's own screen, pointer and hands, as the session driver wants
//! them.
//!
//! # What this module is for
//!
//! `selfhost-screen` owns the platform: three synchronous traits — [`Capture`],
//! [`CursorSource`] and [`Injector`] — with every `unsafe` block in the
//! subsystem underneath them. `selfhost-desk` owns the session: three
//! asynchronous traits — [`FrameSource`], [`PointerSource`] and [`InputSink`] —
//! which the driver polls inside a `select!` alongside three timers.
//!
//! Those two sets do not meet by themselves, and until this module existed they
//! did not meet at all: the daemon reported *"no capture backend"* on a machine
//! whose capture backend was written, tested and exported. This file is the
//! join, and the join is not a wrapper — it is a thread boundary, because the
//! platform half **must not run on a tokio worker**:
//!
//! - A `BitBlt` of a 4K screen is single-digit milliseconds of blocking work,
//!   and `CGDisplayStream`'s delivery wait is *deliberately* a blocking wait —
//!   the whole point of that API is that a still desktop costs one parked thread
//!   and no frames. Doing either on a runtime worker would stall the reverse
//!   proxy, the DNS authority and the mail server that share this runtime.
//! - [`Capture`]'s own documentation requires a dedicated `std::thread`, because
//!   Windows' `SetThreadDesktop` fails on any thread that has ever owned a
//!   window or a hook, and a tokio worker may have run anything at all.
//!
//! So each of the two platform objects lives on a thread of its own, is built
//! there, and is spoken to through a channel carrying a `oneshot` for the reply.
//! Nothing platform-shaped crosses the boundary: what crosses is a request, a
//! [`CapturedFrame`], a [`CursorState`] or a `Vec<InjectedEvent>` — all owned,
//! all `Send`, none of them holding a handle.
//!
//! # Why two threads and not one
//!
//! Because a capture call blocks for up to a frame interval by design, and input
//! queued behind it would wait exactly that long. At thirty frames a second that
//! is thirty-three milliseconds added to every keystroke and every pointer
//! sample — enough to make a drag feel like it is being dragged through
//! treacle. The pointer and the injector make microsecond calls, so they share
//! the second thread and never wait for a frame.
//!
//! # What is tested here, and what is tested against the real machine
//!
//! The pure half is tested here and needs no hardware: [`condition_of`] and
//! [`refusal_of`] — the two vocabulary translations, the first of which is
//! asserted to preserve the observation the state machine reasons about —
//! [`to_pointer_shape`], [`clamp32`], and [`Backend`]'s reporting shape on
//! whatever machine the tests are run on.
//!
//! The thread boundary itself is **not** faked. It is exercised against the real
//! platform by exactly one test, in `crate::desk_task`, which opens a capture,
//! takes a frame and asserts its size against the display the session was told
//! about. One, deliberately: two of these in parallel are two captures of one
//! display, which macOS is entitled to refuse. A fake platform here would prove
//! the channels work and prove nothing about the thing that was actually broken
//! — that the daemon never reached the screen at all.
//!
//! # The kill switch is not enforced here
//!
//! Deliberately. [`crate::desk_task::LocalScreen`] asks the switch *before* it
//! asks this module for anything, so an engaged switch is answered without a
//! platform call at all. Putting the check here as well would mean two places
//! deciding the same thing, and the one that ran first would be the one that
//! mattered.

use selfhost_desk::keys::HeldKeys;
use selfhost_desk::viewer::{
    CapturedFrame, Condition, InputSink, PointerShape, PointerSource, Restore, Task,
};
use selfhost_desk::wire::{Message, Monitor, Refusal};
use selfhost_screen::input::InjectedEvent;
use selfhost_screen::{CaptureError, CursorState, InjectError};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How deep the queue of work waiting for a platform thread is allowed to get.
///
/// One. Both threads answer a request before the next is sent — the driver
/// awaits every reply — so a queue exists only to hold the request that is being
/// handed over. A deeper one could only store work whose reply nobody is waiting
/// for any more.
const JOB_DEPTH: usize = 1;

/// Which capture backend this build has for the machine it is running on, and
/// whether the daemon can actually reach it **right now**.
///
/// Three fields rather than an enum of platforms, because the question an
/// operator asks is not "which platform is this" — they know — but "is there a
/// screen behind this feature, and if not, why not". Both consoles and `doctor`
/// print [`Backend::why`] verbatim.
///
/// # Why this is a live probe and not a constant
///
/// Everything that decides the answer can change while the daemon runs and
/// without the daemon being restarted: a macOS Screen Recording grant is revoked
/// in System Settings (and is revoked by *every* deployment on a self-updating
/// tree, because each build is a new code identity), a Mac's last display is
/// unplugged, a Windows console session is switched away from. A constant
/// compiled in at build time would answer for the machine the code was written
/// on rather than the machine it is running on, and the specific lie this seam
/// exists to prevent is the word "GDI" appearing on a status line above a
/// viewport that will never show a pixel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// What this platform's capture path is called, for a reader who wants to
    /// go and look at it.
    pub name: &'static str,
    /// Whether the daemon can obtain frames through it, on this machine, now.
    pub wired: bool,
    /// The whole sentence: what is there, or what is missing and why.
    ///
    /// Owned rather than borrowed because the interesting answers are built from
    /// the machine's own state — the session id, the remediation naming this
    /// binary's path — and a `&'static str` could carry none of them.
    pub why: String,
    /// What a capture attempt reports while the backend is in this state.
    ///
    /// Carried rather than derived from [`Backend::wired`] because the states an
    /// unwired backend can be in are not interchangeable to a viewer: a missing
    /// macOS grant is [`Condition::PermissionDenied`], which the console renders
    /// as the remediation sentence, while a platform with no backend at all is
    /// [`Condition::Fatal`], which stops the session instead of retrying
    /// something that cannot begin to work. Answering `Fatal` for a revoked
    /// grant would send an operator looking for a broken build.
    pub condition: Condition,
    /// How many displays this machine has, as the platform reports them now.
    ///
    /// Zero whenever there is nothing to capture, which is the same number a
    /// machine with no backend reports — deliberately, because a console that
    /// draws a display picker should draw an empty one in both cases rather than
    /// offer a screen that cannot be produced.
    pub displays: u32,
    /// Whether the frames come from a supervised agent rather than from this
    /// process.
    ///
    /// True on exactly one deployment: a Windows daemon in session 0, which
    /// cannot capture anything itself and relays what an agent in the console
    /// session produces ([`selfhost_desk::relay`]). The distinction is not
    /// cosmetic — it decides which of the two session drivers
    /// [`crate::desk_task`] builds, and the two take their pixels from different
    /// places — so it is carried rather than re-derived from the sentence.
    pub relayed: bool,
}

impl Backend {
    /// What this build can capture on the machine it is running on, asked now.
    pub fn here() -> Self {
        probe()
    }

    /// A backend that is present and reachable, with the displays it can see.
    fn wired(name: &'static str, why: impl Into<String>, displays: usize) -> Self {
        Self {
            name,
            wired: true,
            why: why.into(),
            condition: Condition::Retry,
            // Saturating rather than wrapping: a machine cannot have four
            // billion displays, and a cast that could disagree with the list it
            // came from is not worth the byte it saves.
            displays: u32::try_from(displays).unwrap_or(u32::MAX),
            relayed: false,
        }
    }

    /// A backend whose pixels arrive from a supervised agent.
    ///
    /// `wired` is true because the daemon **can** serve a picture — that is the
    /// whole point of the agent — and the displays are left at zero because only
    /// the agent knows them and it has not necessarily spoken yet. The agent's
    /// own report carries the count once it has.
    // Built by the Windows probe alone, because session 0 is the only place a
    // daemon cannot capture what it is nonetheless able to serve. Named rather
    // than `cfg`-gated so that every platform's build type-checks the one
    // constructor whose field values decide which session driver runs.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn relayed(name: &'static str, why: impl Into<String>) -> Self {
        Self {
            name,
            wired: true,
            why: why.into(),
            condition: Condition::Retry,
            displays: 0,
            relayed: true,
        }
    }

    /// A backend that is not reachable, and the reason, in the state that
    /// reason puts a capture attempt in.
    fn unwired(name: &'static str, why: impl Into<String>, condition: Condition) -> Self {
        Self { name, wired: false, why: why.into(), condition, displays: 0, relayed: false }
    }
}

/// The one-line summary of the machine's capture state, for a banner or a
/// status line.
///
/// Split from [`probe`] so that `doctor`, the daemon's banner and the console's
/// agent report cannot drift into three different sentences about the same
/// machine.
#[cfg(target_os = "macos")]
fn probe() -> Backend {
    use selfhost_screen::macos::grant::Grants;
    use selfhost_screen::macos::sys;

    let grants = Grants::read();
    if !grants.screen_recording {
        // The single most confusing failure this subsystem can have is a
        // *successful* capture of an empty desktop, which is precisely what
        // macOS hands an ungranted process. So a missing grant is reported
        // before anything asks for a pixel, and the sentence carries the pane,
        // this binary's own path and the relaunch requirement.
        return Backend::unwired(
            "CGDisplayStream",
            grants.line(),
            Condition::PermissionDenied,
        );
    }
    match sys::monitors() {
        Ok(monitors) if !monitors.is_empty() => Backend::wired(
            "CGDisplayStream",
            format!(
                "macOS grants this binary Screen Recording and {} display(s) are attached, so this \
                 machine can be viewed. Driving it additionally needs Accessibility, which is {}.",
                monitors.len(),
                if grants.accessibility { "granted" } else { "not granted" },
            ),
            monitors.len(),
        ),
        // A Mac with no display is a state, not a fault: a headless server, or a
        // laptop whose lid is shut on an external screen that has been unplugged.
        Ok(_) => Backend::unwired(
            "CGDisplayStream",
            "macOS grants this binary Screen Recording but reports no attached display, so there \
             is nothing to capture yet",
            Condition::NoSession,
        ),
        Err(error) => Backend::unwired("CGDisplayStream", error.sentence(), condition_of(&error)),
    }
}

/// The Windows probe. See [`probe`] on macOS for the shape; the question this
/// one answers is *which session is this daemon in*.
///
/// # Session 0 is the whole story on this platform
///
/// Installed as a service, the daemon runs as `SYSTEM` in session 0: a session
/// with no interactive display, where `GetDC(NULL)` hands back a device context
/// for session 0's own blank desktop. No amount of care inside this process
/// fixes that — the pixels have to be captured by a process running *inside* the
/// session a person is sitting in, reached over
/// `\\.\pipe\selfhost-desk-<session>`. [`crate::desk_supervisor`] creates that
/// pipe and keeps that agent alive, and [`selfhost_desk::relay`] carries its
/// messages into a viewer session, so this probe reports a **relayed** backend:
/// wired, because a picture can be served, and named as relayed, because the
/// driver that serves it is not the one that captures.
///
/// Run by hand from a terminal, the same daemon is in the console user's own
/// session, and then GDI works in-process with nothing between it and the
/// screen. Both are real deployments, so the probe distinguishes them at run
/// time rather than at build time.
#[cfg(windows)]
fn probe() -> Backend {
    use selfhost_screen::windows::gdi;

    const NAME: &str = "GDI";
    let Some(session) = gdi::current_session() else {
        return Backend::unwired(
            NAME,
            "Windows will not say which session this process is in, so the daemon cannot prove it \
             is in one with a desktop. It refuses to capture rather than guess.",
            Condition::NoSession,
        );
    };
    if session == 0 {
        return Backend::relayed(
            NAME,
            "the daemon is running as a service in session 0, which has no interactive desktop, so \
             nothing in this process captures anything. The pixels come from an agent supervised \
             in the console user's session and reached over a named pipe whose DACL names that \
             user; the daemon forwards its messages without reading them, and applies this \
             session's own permissions to every keystroke going the other way. See the agent's own \
             line for whether one is running.",
        );
    }
    match gdi::monitors() {
        Ok(monitors) if !monitors.is_empty() => Backend::wired(
            NAME,
            format!(
                "this daemon is in interactive session {session} with {} display(s), so it \
                 captures the desktop directly with no agent in between.",
                monitors.len(),
            ),
            monitors.len(),
        ),
        Ok(_) => Backend::unwired(
            NAME,
            format!(
                "this daemon is in session {session} and Windows reports no display there — the \
                 session has been switched away from, or it is a remote session that has \
                 disconnected. It comes back by itself."
            ),
            Condition::SessionDisconnected,
        ),
        Err(error) => Backend::unwired(NAME, error.sentence(), condition_of(&error)),
    }
}

/// Every other platform: there is no capture backend, and saying so is the whole
/// job.
#[cfg(not(any(windows, target_os = "macos")))]
fn probe() -> Backend {
    Backend::unwired(
        "none",
        format!(
            "this build has no capture backend for {}; the two that exist are Windows GDI and \
             macOS CGDisplayStream",
            std::env::consts::OS
        ),
        Condition::Fatal,
    )
}

/// The state a platform capture condition puts a session in.
///
/// Pure and total, and the only translation between the two vocabularies. The
/// property that makes it correct is asserted in this module's tests: the
/// [`Observation`](selfhost_desk::state::Observation) reached through this
/// function is always the one `selfhost-screen` itself would have reported, so
/// the state machine's recovery budgets are spent on the condition that actually
/// occurred.
pub fn condition_of(error: &CaptureError) -> Condition {
    match error {
        CaptureError::Retry => Condition::Retry,
        // A duplication-slot exhaustion is a rebuild, not a surrender: the
        // program holding the slot may well exit in a second.
        CaptureError::Reinitialise | CaptureError::TooManyDuplications => Condition::Reinitialise,
        CaptureError::SecureDesktop => Condition::SecureDesktop,
        CaptureError::SessionDisconnected => Condition::SessionDisconnected,
        CaptureError::NoSession => Condition::NoSession,
        CaptureError::PermissionDenied(_) => Condition::PermissionDenied,
        CaptureError::Unsupported { .. } | CaptureError::Fatal(_) => Condition::Fatal,
    }
}

/// What the client is told when the platform would not perform an event.
///
/// A platform fault deliberately becomes [`Refusal::NotLive`] rather than
/// travelling as itself: the refusals a viewer can *act on* — an elevated
/// window, the secure desktop, a missing permission — are worth sending, and a
/// `HRESULT` tells a remote viewer nothing while telling an attacker something
/// about the machine.
pub fn refusal_of(error: &InjectError) -> Refusal {
    error.refusal().unwrap_or(Refusal::NotLive)
}

/// One request to the capture thread.
enum ScreenJob {
    /// Wait up to this long for a frame.
    Frame {
        budget: Duration,
        reply: oneshot::Sender<Result<CapturedFrame, Condition>>,
    },
    /// Tear the platform object down and build it again, answering with the
    /// display layout the new one sees.
    Rebuild { reply: oneshot::Sender<Result<Vec<Monitor>, Condition>> },
}

/// One request to the pointer-and-hands thread.
enum HandsJob {
    /// Where the pointer is, and what it looks like if that is new.
    Cursor { reply: oneshot::Sender<Result<CursorState, CaptureError>> },
    /// Perform these events, in order.
    Inject {
        events: Vec<InjectedEvent>,
        reply: oneshot::Sender<Result<(), InjectError>>,
    },
    /// The display layout changed, so the coordinate mapping must be rebuilt.
    Relayout { reply: oneshot::Sender<Vec<Monitor>> },
}

/// This machine's screen, as the session driver sees it.
///
/// Owns the capture thread: dropping this ends it, because the thread's loop
/// ends when its job channel closes, and the platform object is dropped there —
/// which is where it must be dropped, since it was built there.
pub struct Screen {
    monitors: Vec<Monitor>,
    jobs: mpsc::Sender<ScreenJob>,
}

impl Screen {
    /// Starts the capture thread and waits for it to say what it can see.
    ///
    /// # Errors
    ///
    /// The condition the platform reported when it refused to build a capture —
    /// a missing grant, no logged-in session, no display. Every one of those is
    /// a *state* the caller reports to the console verbatim rather than a
    /// failure to be retried blindly.
    pub async fn start() -> Result<Self, Condition> {
        let (jobs, inbox) = mpsc::channel(JOB_DEPTH);
        let (ready, started) = oneshot::channel();
        spawn_capture_thread(inbox, ready);
        // A thread that died before answering is reported as `Fatal`: it cannot
        // be retried, because whatever killed it will kill the next one too.
        let monitors = started.await.map_err(|_| Condition::Fatal)??;
        Ok(Self { monitors, jobs })
    }
}

impl selfhost_desk::viewer::FrameSource for Screen {
    fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    fn next_frame(&mut self, budget: Duration) -> Task<'_, Result<CapturedFrame, Condition>> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            self.jobs
                .send(ScreenJob::Frame { budget, reply })
                .await
                .map_err(|_| Condition::Fatal)?;
            answer.await.map_err(|_| Condition::Fatal)?
        })
    }

    fn restore(&mut self, _what: Restore) -> Task<'_, Result<(), Condition>> {
        // Both kinds of restore are the same act here, and that is a fact about
        // this deployment rather than a shortcut: `Restore::Agent` asks for the
        // agent process to be replaced, and in-process capture *is* the agent,
        // so replacing the platform object is exactly what there is to replace.
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            self.jobs.send(ScreenJob::Rebuild { reply }).await.map_err(|_| Condition::Fatal)?;
            let monitors = answer.await.map_err(|_| Condition::Fatal)??;
            // The driver reads `monitors()` again after a restore to build the
            // fresh `HELLO`; a stale list here would advertise a display that is
            // no longer there and every pointer coordinate would land on the
            // wrong screen.
            self.monitors = monitors;
            Ok(())
        })
    }
}

/// Starts the pointer-and-hands thread and hands back the two halves.
///
/// Two objects rather than one, because the session driver holds
/// [`PointerSource`] and [`InputSink`] as two separate `&mut` borrows and one
/// object cannot be both at once. They share the thread and the channel to it,
/// which is the part that matters: there is one injector on this machine, and
/// the record of what it has posted is kept in one place.
///
/// # Errors
///
/// The reason the platform would not produce an injector at all — a Mac without
/// Accessibility, a build with no backend. The caller then wires
/// [`selfhost_desk::viewer::NoInput`] and the console is told plainly, rather
/// than holding a sink that refuses everything for a reason it cannot name.
pub async fn open_hands(monitors: Vec<Monitor>) -> Result<(Pointer, Keys), InjectError> {
    let (jobs, inbox) = mpsc::channel(JOB_DEPTH);
    let (ready, started) = oneshot::channel();
    spawn_hands_thread(inbox, ready);
    started.await.map_err(|_| InjectError::Unsupported { platform: std::env::consts::OS })??;
    Ok((
        Pointer { jobs: jobs.clone(), shape: None },
        Keys { jobs, monitors, held: HeldKeys::new() },
    ))
}

/// This machine's pointer, as the session driver sees it.
pub struct Pointer {
    jobs: mpsc::Sender<HandsJob>,
    /// The last shape the platform handed over, kept so
    /// [`PointerSource::shape`] can answer for it.
    ///
    /// Exactly one, not a cache. The platform's own cursor source already
    /// suppresses a shape the caller has been given, so what arrives here is
    /// always the shape that is on screen now, and that is the only one the
    /// driver ever asks for.
    shape: Option<(u64, PointerShape)>,
}

/// This machine's keyboard and pointer buttons, as the session driver sees them.
pub struct Keys {
    jobs: mpsc::Sender<HandsJob>,
    /// The display layout, for the pure lowering that turns a protocol message
    /// into platform events. Refreshed on every relayout.
    monitors: Vec<Monitor>,
    /// What this session believes is held down on the far keyboard.
    ///
    /// Held on *this* side rather than in the injector because it is the record
    /// of what the **client** asked for, and it is what makes `RELEASE_ALL`
    /// possible. The injector keeps its own record of what it actually posted
    /// and releases that when it is dropped; the two are deliberately separate,
    /// and between them a key cannot be left down whether the client vanished or
    /// the thread did.
    held: HeldKeys,
}

impl Keys {
    /// Re-reads the display layout after the screen was rebuilt.
    ///
    /// Called from the same place the capture is rebuilt, because the two share
    /// a cause: a display that appeared, moved or changed resolution invalidates
    /// the coordinate mapping, and a pointer mapped against a stale virtual
    /// desktop lands on the wrong screen.
    pub async fn relayout(&mut self) {
        let (reply, answer) = oneshot::channel();
        if self.jobs.send(HandsJob::Relayout { reply }).await.is_err() {
            return;
        }
        if let Ok(monitors) = answer.await {
            self.monitors = monitors;
        }
    }
}

impl PointerSource for Pointer {
    fn pointer(&mut self) -> Task<'_, Option<selfhost_desk::cursor::Pointer>> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            self.jobs.send(HandsJob::Cursor { reply }).await.ok()?;
            let state = answer.await.ok()?.ok()?;
            // A new shape is remembered rather than sent from here: the driver
            // decides whether the client already holds it, and asks for the
            // bitmap only when it does not.
            if let Some(image) = state.shape {
                match to_pointer_shape(&image) {
                    Some(shape) => self.shape = Some((image.id, shape)),
                    // A shape the protocol cannot carry — larger than the wire's
                    // maximum edge, or whose pixel count does not match its
                    // extent — is dropped rather than sent, because encoding it
                    // would end the session over a pointer.
                    None => self.shape = None,
                }
            }
            Some(selfhost_desk::cursor::Pointer {
                // Clamped rather than wrapped. A virtual-desktop coordinate is
                // sixty-four bits at the platform seam and thirty-two on the
                // wire; a value outside that range cannot describe any display
                // this protocol can carry, and saturating puts the pointer at
                // the far edge instead of teleporting it to the other one.
                x: clamp32(state.position.x),
                y: clamp32(state.position.y),
                visible: state.visible,
                shape: selfhost_desk::cursor::ShapeId(self.shape.as_ref().map_or(0, |(id, _)| *id)),
            })
        })
    }

    fn shape(&mut self, id: selfhost_desk::cursor::ShapeId) -> Task<'_, Option<PointerShape>> {
        Box::pin(async move {
            match self.shape.as_ref() {
                Some((held, shape)) if *held == id.0 => Some(shape.clone()),
                // The driver asked for a shape this side no longer has. Answering
                // `None` costs the client one frame of the wrong pointer; the
                // platform source is told to forget what it thinks the caller
                // holds, so the next observation carries the bitmap again.
                _ => None,
            }
        })
    }
}

impl InputSink for Keys {
    /// Performs one already-authorised input message.
    ///
    /// The lowering — which events a message becomes, whether a coordinate is on
    /// a display, what `RELEASE_ALL` has to undo — is pure and happens here, on
    /// the async side, so the only thing that crosses to the platform thread is
    /// a vector of owned events. That is what keeps the thread boundary free of
    /// anything platform-shaped and lets the whole decision be tested with no
    /// hardware attached.
    ///
    /// # Authorisation is the driver's, and this is not a second opinion
    ///
    /// `selfhost_desk`'s session driver checks `[desktop].allow_input` and the
    /// session's `CONTROL` capability **per message** before it calls this, and
    /// re-reads the session's standing every minute. This sink deliberately adds
    /// no check of its own: two places deciding the same thing means the one
    /// that runs first is the one that matters, and the other rots. What this
    /// enforces instead is what only the operating system can answer — the
    /// secure desktop, an elevated window, a revoked grant — and it enforces it
    /// by asking, not by remembering.
    ///
    /// # A coordinate that does not map is a stale layout, once
    ///
    /// `Refusal::Unmappable` from a pointer message means the client aimed at a
    /// display this side does not have, and the overwhelmingly likely cause is
    /// that the layout changed underneath both of them — a monitor unplugged, a
    /// resolution changed, a laptop undocked. The screen rebuilds on its own
    /// signal; the injector has no such signal, so it re-reads the layout here
    /// and tries **exactly once** more. Once, and only for a pointer: a retry
    /// loop on a coordinate a client keeps sending would be a way to make this
    /// daemon re-enumerate displays as fast as a socket can deliver.
    fn deliver<'a>(&'a mut self, message: &'a Message) -> Task<'a, Result<(), Refusal>> {
        Box::pin(async move {
            let events = match selfhost_screen::input::lower(
                message,
                &self.monitors,
                &mut self.held,
            ) {
                Ok(events) => events,
                Err(Refusal::Unmappable) if matches!(message, Message::PointerMove { .. }) => {
                    self.relayout().await;
                    selfhost_screen::input::lower(message, &self.monitors, &mut self.held)?
                }
                Err(refusal) => return Err(refusal),
            };
            if events.is_empty() {
                // `RELEASE_ALL` with nothing held. Performed, trivially.
                return Ok(());
            }
            let (reply, answer) = oneshot::channel();
            self.jobs
                .send(HandsJob::Inject { events, reply })
                .await
                .map_err(|_| Refusal::NotLive)?;
            match answer.await.map_err(|_| Refusal::NotLive)? {
                Ok(()) => Ok(()),
                Err(error) => Err(refusal_of(&error)),
            }
        })
    }
}

/// A virtual-desktop coordinate as the protocol carries it.
///
/// Saturating, never wrapping: `as i32` on a value that does not fit turns the
/// left edge of the desktop into the right one, and a pointer that jumps to the
/// opposite screen is a bug nobody would attribute to a cast.
fn clamp32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// A platform cursor image as the protocol carries it, or `None` for one it
/// cannot.
///
/// Pure, and refusing rather than clamping: a bitmap whose byte count does not
/// match its extent is a platform inconsistency, and sending it would produce a
/// message the far end refuses to decode — which ends the session over a
/// pointer.
fn to_pointer_shape(image: &selfhost_screen::CursorImage) -> Option<PointerShape> {
    let width = u16::try_from(image.width).ok()?;
    let height = u16::try_from(image.height).ok()?;
    let expected = (image.width as usize).checked_mul(image.height as usize)?.checked_mul(4)?;
    if image.bgra.len() != expected {
        return None;
    }
    Some(PointerShape {
        hotspot_x: u16::try_from(image.hotspot_x).ok()?,
        hotspot_y: u16::try_from(image.hotspot_y).ok()?,
        width,
        height,
        pixels: image.bgra.clone(),
    })
}

/// Turns one platform frame into an owned one, or says what the source is doing
/// instead.
///
/// The platform's own damage rectangles are deliberately **discarded**. The
/// session driver diffs tiles itself against the frame it last sent, which is
/// the only comparison that knows what the *client* is holding; a damage list
/// describes what changed since the previous capture, which is a different
/// question whenever a frame was dropped for want of credit. Trusting it there
/// would leave stale pixels on screen that nothing would ever repair.
fn take_frame(
    source: &mut dyn selfhost_screen::Capture,
    budget: Duration,
) -> Result<CapturedFrame, Condition> {
    match source.next_frame(budget) {
        Ok(Some(frame)) => {
            let monitor = frame.monitor;
            match selfhost_desk::tiles::unpack(frame.width, frame.height, frame.stride, frame.pixels)
            {
                Ok(surface) => Ok(CapturedFrame { monitor, surface }),
                // A frame whose stride, extent and buffer length disagree is a
                // driver's mistake rather than ours. It is a rebuild, not a
                // fault: the next capture object gets a consistent buffer, and
                // the state machine's own budget is what eventually gives up.
                Err(_) => Err(Condition::Reinitialise),
            }
        }
        Ok(None) => Err(Condition::Retry),
        Err(error) => Err(condition_of(&error)),
    }
}

/// The capture thread's body: build the platform object here, then serve.
///
/// Every platform object is constructed **on this thread** and dropped here too.
/// That is not tidiness — a GDI device context belongs to the thread that made
/// it, and `CGDisplayStream`'s stop handshake has to be awaited by somebody.
fn spawn_capture_thread(
    mut inbox: mpsc::Receiver<ScreenJob>,
    ready: oneshot::Sender<Result<Vec<Monitor>, Condition>>,
) {
    std::thread::spawn(move || {
        let mut source = match new_capture() {
            Ok(source) => source,
            Err(condition) => {
                let _ = ready.send(Err(condition));
                return;
            }
        };
        if ready.send(Ok(source.monitors().to_vec())).is_err() {
            // Nobody is waiting for this any more: the session was abandoned
            // between asking and answering. Drop the platform object rather
            // than hold a screen open for a viewer that has gone.
            return;
        }
        // `blocking_recv` is correct here and would panic on a runtime worker,
        // which is one more reason this is a thread of its own.
        while let Some(job) = inbox.blocking_recv() {
            match job {
                ScreenJob::Frame { budget, reply } => {
                    let _ = reply.send(take_frame(source.as_mut(), budget));
                }
                ScreenJob::Rebuild { reply } => {
                    // Dropped before the replacement is built, so the platform
                    // is never holding two duplications of one display — which
                    // on Windows is exactly how a rebuild turns into
                    // `TooManyDuplications` against itself.
                    drop(source);
                    match new_capture() {
                        Ok(fresh) => {
                            source = fresh;
                            let _ = reply.send(Ok(source.monitors().to_vec()));
                        }
                        Err(condition) => {
                            let _ = reply.send(Err(condition));
                            return;
                        }
                    }
                }
            }
        }
    });
}

/// The pointer-and-hands thread's body.
fn spawn_hands_thread(
    mut inbox: mpsc::Receiver<HandsJob>,
    ready: oneshot::Sender<Result<(), InjectError>>,
) {
    std::thread::spawn(move || {
        let mut injector = match new_injector() {
            Ok(injector) => injector,
            Err(error) => {
                let _ = ready.send(Err(error));
                return;
            }
        };
        let mut cursor = new_cursor();
        if ready.send(Ok(())).is_err() {
            return;
        }
        while let Some(job) = inbox.blocking_recv() {
            match job {
                HandsJob::Cursor { reply } => {
                    let answer = match cursor.as_mut() {
                        Ok(cursor) => cursor.cursor(),
                        Err(error) => Err(error.clone()),
                    };
                    let _ = reply.send(answer);
                }
                HandsJob::Inject { events, reply } => {
                    let _ = reply.send(injector.inject(&events));
                }
                HandsJob::Relayout { reply } => {
                    // The pointer source is rebuilt rather than told: its
                    // coordinate mapping is built at construction on both
                    // platforms, and `CursorSource` deliberately carries no
                    // relayout method for one caller's benefit.
                    cursor = new_cursor();
                    let _ = reply.send(injector.relayout());
                }
            }
        }
        // Falling out of the loop drops the injector, and dropping the injector
        // is what releases every key and button it posted. That is the path
        // taken when the tunnel drops mid-drag: the client that would have sent
        // `RELEASE_ALL` is the thing that vanished.
    });
}

/// A cursor source, or the reason there is not one.
///
/// A `Result` rather than an `Option` so that a session with no pointer can say
/// *why* the pointer is missing instead of drawing nothing and leaving the
/// operator to wonder.
type CursorSlot = Result<Box<dyn selfhost_screen::CursorSource>, CaptureError>;

/// The injector, plus the one thing this crate needs from it that
/// [`selfhost_screen::Injector`] does not carry: the display layout it maps
/// against.
///
/// A local trait rather than a change to `selfhost-screen`, because the two
/// platform injectors already expose exactly this and only their concrete types
/// say so. Composition over inheritance in the plainest sense: the daemon
/// composes the behaviour it needs from what the platform already offers,
/// instead of the platform crate growing a method for one caller.
trait PlatformInjector: selfhost_screen::Injector {
    /// Re-reads the display layout, and answers what it now sees.
    fn relayout(&mut self) -> Vec<Monitor>;
}

#[cfg(windows)]
impl PlatformInjector for selfhost_screen::windows::inject::WinInjector {
    /// A refusal to re-enumerate leaves the previous layout in place, and the
    /// list returned is whatever the injector now holds — which is then the
    /// previous one.
    ///
    /// Discarded rather than propagated because there is nothing above this
    /// worth telling: the caller asked for a refresh because a coordinate did
    /// not map, and if the refresh failed the coordinate still does not map, so
    /// the very next lowering refuses it with `unmappable` and the console says
    /// so. Turning a failed refresh into its own error would produce a second
    /// way to say the same thing one step earlier.
    fn relayout(&mut self) -> Vec<Monitor> {
        let _ = selfhost_screen::windows::inject::WinInjector::relayout(self);
        self.monitors().to_vec()
    }
}

#[cfg(target_os = "macos")]
impl PlatformInjector for selfhost_screen::macos::MacInjector {
    /// See the Windows implementation for why a failed refresh is not an error
    /// here. The layout is read from the platform rather than from the injector
    /// because `MacInjector` keeps its mapping private.
    fn relayout(&mut self) -> Vec<Monitor> {
        let _ = selfhost_screen::macos::MacInjector::relayout(self);
        selfhost_screen::macos::sys::monitors().unwrap_or_default()
    }
}

/// This machine's capture, built on the thread that will use it.
#[cfg(target_os = "macos")]
fn new_capture() -> Result<Box<dyn selfhost_screen::Capture>, Condition> {
    selfhost_screen::macos::MacCapture::new()
        .map(|capture| Box::new(capture) as Box<dyn selfhost_screen::Capture>)
        .map_err(|error| condition_of(&error))
}

#[cfg(windows)]
fn new_capture() -> Result<Box<dyn selfhost_screen::Capture>, Condition> {
    selfhost_screen::windows::gdi::GdiCapture::new()
        .map(|capture| Box::new(capture) as Box<dyn selfhost_screen::Capture>)
        .map_err(|error| condition_of(&error))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn new_capture() -> Result<Box<dyn selfhost_screen::Capture>, Condition> {
    Err(Condition::Fatal)
}

/// This machine's injector, built on the thread that will use it.
#[cfg(target_os = "macos")]
fn new_injector() -> Result<Box<dyn PlatformInjector>, InjectError> {
    selfhost_screen::macos::MacInjector::new()
        .map(|injector| Box::new(injector) as Box<dyn PlatformInjector>)
}

#[cfg(windows)]
fn new_injector() -> Result<Box<dyn PlatformInjector>, InjectError> {
    selfhost_screen::windows::inject::WinInjector::new()
        .map(|injector| Box::new(injector) as Box<dyn PlatformInjector>)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn new_injector() -> Result<Box<dyn PlatformInjector>, InjectError> {
    Err(InjectError::Unsupported { platform: std::env::consts::OS })
}

/// This machine's pointer, built on the thread that will use it.
#[cfg(target_os = "macos")]
fn new_cursor() -> CursorSlot {
    selfhost_screen::macos::MacCursor::new()
        .map(|cursor| Box::new(cursor) as Box<dyn selfhost_screen::CursorSource>)
}

#[cfg(windows)]
fn new_cursor() -> CursorSlot {
    Ok(Box::new(selfhost_screen::windows::cursor::GdiCursor::new()))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn new_cursor() -> CursorSlot {
    Err(CaptureError::Unsupported { platform: std::env::consts::OS })
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::state::Observation;
    use selfhost_screen::Grant;

    /// The translation must not change which recovery budget a condition spends.
    ///
    /// Both crates map their own vocabulary onto `Observation`; this asserts the
    /// two routes agree for every condition the platform can report, which is
    /// the property that makes the translation invisible to the state machine.
    #[test]
    fn every_capture_condition_keeps_its_observation() {
        let conditions = [
            CaptureError::Retry,
            CaptureError::Reinitialise,
            CaptureError::TooManyDuplications,
            CaptureError::SecureDesktop,
            CaptureError::SessionDisconnected,
            CaptureError::NoSession,
            CaptureError::PermissionDenied(Grant::ScreenRecording),
            CaptureError::PermissionDenied(Grant::Accessibility),
            CaptureError::Unsupported { platform: "haiku" },
            CaptureError::Fatal(selfhost_screen::Fault::os("BitBlt", 6)),
        ];
        for condition in &conditions {
            assert_eq!(
                condition_of(condition).observation(),
                condition.observation(),
                "{condition:?} loses its meaning in translation"
            );
        }
    }

    /// A stalled or secure screen must never be reported as the end of the
    /// session: all of them pass by themselves, and a `Fatal` here would tear
    /// down a stream because somebody locked their screen.
    #[test]
    fn only_the_unrecoverable_conditions_translate_to_fatal() {
        assert_eq!(condition_of(&CaptureError::SecureDesktop), Condition::SecureDesktop);
        assert_eq!(condition_of(&CaptureError::NoSession), Condition::NoSession);
        assert_eq!(
            condition_of(&CaptureError::Unsupported { platform: "haiku" }),
            Condition::Fatal
        );
        assert_eq!(
            condition_of(&CaptureError::PermissionDenied(Grant::ScreenRecording)),
            Condition::PermissionDenied,
            "a revoked grant is a permission, not a broken build"
        );
    }

    /// A platform fault must not travel to a remote viewer as itself.
    #[test]
    fn a_platform_fault_reaches_the_client_as_not_live() {
        assert_eq!(
            refusal_of(&InjectError::Failed(selfhost_screen::Fault::os("SendInput", 5))),
            Refusal::NotLive
        );
        assert_eq!(
            refusal_of(&InjectError::Refused(Refusal::ElevatedWindow)),
            Refusal::ElevatedWindow,
            "the one refusal an operator can act on must travel as itself"
        );
        assert_eq!(
            refusal_of(&InjectError::PermissionDenied(Grant::Accessibility)),
            Refusal::NotPermitted
        );
    }

    /// The probe must read as a whole sentence in every state, because both the
    /// console and `doctor` print it verbatim and a fragment reads as a bug.
    #[test]
    fn the_probe_answers_this_machine_in_prose() {
        let backend = Backend::here();
        assert!(!backend.name.is_empty());
        assert!(!backend.why.is_empty(), "an unexplained backend is the failure this prevents");
        if backend.wired {
            assert_eq!(backend.condition, Condition::Retry);
        } else {
            assert_ne!(
                backend.condition,
                Condition::Retry,
                "an unwired backend that says 'retry' is a session that waits forever"
            );
        }
    }

    /// A pointer shape whose bytes and extent disagree is dropped rather than
    /// sent: encoding it would end the session over a pointer.
    #[test]
    fn an_inconsistent_cursor_bitmap_is_refused() {
        let image = selfhost_screen::CursorImage {
            id: 7,
            width: 32,
            height: 32,
            hotspot_x: 0,
            hotspot_y: 0,
            bgra: vec![0; 10],
        };
        assert!(to_pointer_shape(&image).is_none());

        let whole = selfhost_screen::CursorImage { bgra: vec![0; 32 * 32 * 4], ..image };
        let shape = to_pointer_shape(&whole).expect("a consistent bitmap travels");
        assert_eq!((shape.width, shape.height), (32, 32));
    }

    /// The observation the state machine sees for a fatal condition must end the
    /// session rather than spend a rebuild budget.
    #[test]
    fn the_fatal_condition_is_the_one_the_state_machine_ends_on() {
        assert_eq!(Condition::Fatal.observation(), Observation::Fatal);
    }
}

