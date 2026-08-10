//! This machine's pixels and this machine's input devices.
//!
//! `selfhost-desk` owns the protocol two consoles have to agree on; this crate
//! owns the half of the conversation that only the machine being controlled can
//! hold up. It is the only new crate in this branch with FFI, and every `unsafe`
//! block in the subsystem lives underneath the three traits below — so the code
//! that streams a desktop, decides what to draw and decides who may drive it is
//! ordinary safe Rust that is tested on a laptop with nothing plugged into it.
//!
//! # The seam, and why it is three traits rather than one object
//!
//! [`Capture`], [`CursorSource`] and [`Injector`] are separate because they fail
//! separately and are *authorised* separately. A session may be permitted to see
//! a screen and forbidden from touching it — that is the difference between
//! `DesktopView` and `DesktopControl`, and the plan is emphatic that the second
//! is re-checked per input message rather than inferred once at the handshake.
//! Three traits make the forbidden case a value that was never constructed
//! rather than a boolean somebody has to remember to test. They are also
//! deliberately **synchronous**: the async belongs to the task that drives them,
//! not to a `BitBlt`.
//!
//! # `CaptureError` names states, not failures
//!
//! This is the design decision the rest of the subsystem leans on. A remote
//! desktop spends a great deal of its life in conditions that are perfectly
//! ordinary and are not errors in any useful sense: nobody is logged in yet, a
//! UAC prompt has taken the screen, the operator switched users, macOS has not
//! been told to allow screen recording. A capture layer that reports those as
//! `Err(io::Error)` produces a console that says "capture failed" — and an
//! operator who reboots the machine to fix a login screen. So every one of them
//! is a named variant with [`CaptureError::sentence`] attached, and the console
//! renders the sentence.
//!
//! The same enum is also the input to `selfhost_desk::state`, through
//! [`CaptureError::observation`]. That is what makes the entire recovery path —
//! the crash loop, the secure desktop, the user logging out, four hundred
//! consecutive rebuild demands — testable with no display attached: a fake
//! capture replays a scripted sequence of these values and the state machine is
//! driven through hazards that cannot be produced on demand in CI at all.
//!
//! # What is here, and what is deliberately not here yet
//!
//! Built: the traits, the error vocabulary, the pure coordinate mapping
//! ([`coords`]), the pure input-lowering plan ([`input`]), the two platform key
//! tables ([`keymap`]) and the pure synthetic-event plan built on them
//! ([`synth`]), the agent supervisor ([`supervisor`]), the Windows session-0
//! agent spawn ([`windows`]), **Windows GDI screen and cursor capture**,
//! **macOS `CGDisplayStream` capture**, **input injection on both platforms**,
//! and the agent's own streaming loop ([`agent`]).
//!
//! Not built, on purpose:
//!
//! - **There is no DXGI Desktop Duplication backend**, and there may never be.
//!   GDI ships first because it is two hundred lines with no COM in them and it
//!   works in desktop modes DXGI refuses outright; Desktop Duplication is nine
//!   hundred lines of hand-bound vtables in which a wrong slot index is silent
//!   memory corruption rather than a compile error. [`Capture`] is written so it
//!   can drop in beside the GDI one, and the plan is explicit that it is optional
//!   forever.
//! - **There is no ScreenCaptureKit backend.** `CGDisplayStream` is deprecated in
//!   the SDK and works perfectly from Rust — the `obsoleted` attribute is a C
//!   availability gate the Rust compiler does not honour — and it needs no
//!   Objective-C messaging at all beyond one block. ScreenCaptureKit is the same
//!   trait with a great deal more Objective-C runtime behind it, and it can be
//!   added later without touching anything above [`Capture`].
//!
//! # What injection deliberately cannot do
//!
//! Two refusals are designed in rather than missing, and both are documented at
//! the code that implements them so that nobody later "fixes" them:
//!
//! - **The secure desktop is never captured and never typed into**, on either
//!   platform. A channel that can render *and drive* a consent dialog is by
//!   construction a remote privilege-escalation channel.
//! - **The Windows agent runs at medium integrity and cannot type into an
//!   elevated window.** That is User Interface Privilege Isolation working
//!   correctly. The console reports `input-refused (elevated window)` as a state;
//!   the fix an operator is tempted to reach for — running the agent as `SYSTEM` —
//!   would convert this feature into exactly the escalation channel above.
//!
//! # Modules
//!
//! - [`coords`] — **pure.** Virtual-desktop ↔ normalised, and pixels ↔ points.
//!   Every sign, every `- 1`, and every scale factor in the subsystem is here and
//!   nowhere else, because a pointer that drifts is diagnosed as a rounding error
//!   in exactly one file or it is diagnosed nowhere.
//! - [`input`] — **pure.** Which mechanism a piece of input must use, and the
//!   held-key bookkeeping that makes `RELEASE_ALL` possible.
//! - [`keymap`] — **pure.** The HID vocabulary as Win32 virtual keys and
//!   scancodes, and as macOS `CGKeyCode`s. Both tables compile and are proven
//!   total on every platform, so neither can rot on the machine it is not for.
//! - [`synth`] — **pure.** Which synthetic events a given input event becomes,
//!   with the flags spelled out: the absolute virtual-desktop pointer, the drag
//!   that is not a move, the modifier mask macOS will not derive by itself, and
//!   the held set that makes an autonomous `RELEASE_ALL` possible.
//! - [`agent`] — **pure, apart from the process body.** What the agent states
//!   about itself, and the loop that turns frames into tiles: the credit stall,
//!   the dropped frame, the merged damage and the states-as-prose all live here
//!   and are driven in tests by a scripted capture with no screen behind it.
//! - [`supervisor`] — the daemon side of the agent's life. The restart decision
//!   is pure and exhaustively tested; the process handling is the thin part.
//! - [`windows`] — the session-0 spawn, GDI capture, cursor capture, and the
//!   agent's end of the pipe. Its pure half compiles everywhere so it is tested on
//!   a developer machine; its FFI half compiles only on Windows.
//! - `macos` — display enumeration, the permission gate, `CGDisplayStream`
//!   capture, the pointer, and `CGEvent` injection. Compiled only there, which is
//!   why this entry is not a link: on the production box it does not exist.
//! - [`stub`] — every other platform, answering with a typed refusal rather than
//!   failing to compile.

pub mod agent;
pub mod coords;
pub mod fault;
pub mod input;
pub mod keymap;
pub mod supervisor;
pub mod synth;
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod stub;

pub use agent::{
    AgentReport, AgentStats, CreditWindow, DamageHint, Delivery, DpiAwareness, FrameSink, Integrity,
    SendError, StreamConfig, Streamer, Tick,
};
pub use coords::{Bounds, CoordError, Normalised, Point, PointOrigin, VirtualPoint};
pub use fault::Fault;
pub use input::{InjectedEvent, Mechanism};
pub use supervisor::{AgentHost, AgentPhase, AgentProcess, ConsoleSession, Supervision};

use selfhost_desk::state::Observation;
use selfhost_desk::wire::Monitor;
use selfhost_desk::Damage;
use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

/// A permission the operating system grants to a process, one dialog at a time.
///
/// Named rather than folded into a generic "denied" because the two are granted
/// in two different panes of System Settings, are revoked independently, and one
/// of them (accessibility) is not needed at all by a session that only watches.
/// A console that says "permission denied" without saying which one sends the
/// operator to the wrong pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// macOS Screen Recording consent. Without it the process is handed a
    /// picture of the wallpaper rather than an error, which is precisely why the
    /// check is a preflight and never an inspection of the pixels.
    ScreenRecording,
    /// macOS Accessibility consent, which is what synthesised input needs.
    Accessibility,
}

impl Grant {
    /// One sentence naming the permission and where the operator grants it.
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::ScreenRecording => {
                "macOS has not granted this process Screen Recording. Grant it in \
                 System Settings › Privacy & Security › Screen Recording, then restart \
                 the agent — the permission is read once at launch."
            }
            Self::Accessibility => {
                "macOS has not granted this process Accessibility, which is what lets it \
                 synthesise keyboard and pointer events. Grant it in System Settings › \
                 Privacy & Security › Accessibility."
            }
        }
    }

    /// The permission's own name, as the settings pane spells it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ScreenRecording => "Screen Recording",
            Self::Accessibility => "Accessibility",
        }
    }

    /// The exact pane of System Settings the operator has to open.
    ///
    /// Spelled out rather than described because "the privacy settings" sends
    /// somebody to a list of thirty panes, and the two grants this subsystem needs
    /// are in two different ones that are revoked independently.
    pub const fn panel(self) -> &'static str {
        match self {
            Self::ScreenRecording => "System Settings › Privacy & Security › Screen Recording",
            Self::Accessibility => "System Settings › Privacy & Security › Accessibility",
        }
    }

    /// The remediation sentence the console renders verbatim, naming the binary.
    ///
    /// This is a **product surface, not an error path**, and it is written that way
    /// on purpose. macOS does not fail a capture it has not consented to: it
    /// succeeds and hands the process a picture of the desktop wallpaper with every
    /// window missing. A console that renders "permission denied" — or worse, that
    /// picture — leaves an operator staring at a remote desktop that looks broken
    /// in a way nothing on screen explains. So the sentence carries all three facts
    /// somebody needs and none they do not:
    ///
    /// 1. **Which pane**, spelled exactly as macOS spells it.
    /// 2. **Which binary**, because the grant is per code identity and this
    ///    workspace has several executables in one directory. An operator who
    ///    granted the wrong one sees no change at all.
    /// 3. **That it takes a fresh launch.** macOS reads the decision when the
    ///    process starts; granting it while the agent is running changes nothing
    ///    until the agent is restarted, which is the single most common way this
    ///    remediation is followed correctly and appears not to work.
    ///
    /// It also says that a rebuild revokes it, which on this deployment is not a
    /// footnote: every `cargo build` produces a new ad-hoc code signature with a new
    /// cdhash, macOS keys the grant to that identity, and **this tree rebuilds
    /// itself on every push** through `[self_update]`. The honest expectation is
    /// that the grant dies on each deploy and is re-given by hand. Nothing in this
    /// crate can avoid that; pretending otherwise would make the console's own
    /// advice wrong.
    ///
    /// The result is bounded to [`selfhost_desk::wire::MAX_DETAIL_BYTES`] by eliding
    /// the *middle* of the path — the tail identifies the binary and the head is the
    /// part an operator can guess — so the sentence that reaches the wire is always
    /// a whole sentence rather than one cut off mid-word by the framing layer.
    pub fn remediation(self, executable: &std::path::Path) -> String {
        let head = format!("macOS has not granted this process {}. Add and enable ", self.name());
        let tail = format!(
            " in {}, then relaunch it: the grant is read at launch only, and each rebuild \
             revokes it.",
            self.panel()
        );
        let budget = selfhost_desk::wire::MAX_DETAIL_BYTES
            .saturating_sub(head.len())
            .saturating_sub(tail.len());
        format!("{head}{}{tail}", elide_head(&executable.to_string_lossy(), budget))
    }
}

/// Keeps the last `budget` bytes of a path, marking what was dropped.
///
/// The *tail* is kept because that is what identifies a binary —
/// `…/target/release/selfhost` answers the operator's question where
/// `/Users/alexwaldmann/Desktop/…` does not. Cuts on a character boundary, because
/// a path is not necessarily ASCII and half a character on the wire is a decoding
/// error at the far end rather than a shortened sentence.
fn elide_head(text: &str, budget: usize) -> String {
    if text.len() <= budget {
        return text.to_owned();
    }
    const MARK: &str = "…";
    let room = budget.saturating_sub(MARK.len());
    let mut start = text.len().saturating_sub(room);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("{MARK}{}", text.get(start..).unwrap_or_default())
}

/// The binary this process is running from, for a remediation sentence.
///
/// Answers a placeholder rather than failing when the platform will not say: the
/// sentence is still worth rendering without the path, because the pane it names is
/// where the operator will see the binary listed anyway.
pub fn this_executable() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("the agent binary"))
}

/// What a screen source is doing, when it is not handing over a frame.
///
/// Most of these are **states**, not failures. See the module documentation for
/// why that distinction is the load-bearing one in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// Nothing has changed since the last frame. A still desktop produces this
    /// indefinitely, and it must never be counted against any budget.
    Retry,
    /// The screen source must be torn down and rebuilt before it will produce
    /// anything again — a resolution change, a display plugged in, a graphics
    /// driver restart, or a desktop switch.
    Reinitialise,
    /// The secure desktop is in front: a UAC consent dialog, the lock screen, or
    /// the credential provider. Never captured, and input suspends here. That is
    /// a security decision rather than an omission — a channel that can both
    /// render and drive the consent dialog is by construction a remote
    /// privilege-escalation channel.
    SecureDesktop,
    /// The interactive session moved: fast user switching, or an RDP connection
    /// taking the console away.
    SessionDisconnected,
    /// Nobody is logged in. There is no desktop to capture, and for a server that
    /// is an entirely ordinary way to spend a week.
    NoSession,
    /// Every screen-duplication slot this display has is already held by another
    /// program. Recoverable without a restart once that program lets go, so it is
    /// reported as a rebuild rather than as a failure.
    TooManyDuplications,
    /// The operating system refuses this process the screen or the input device.
    PermissionDenied(Grant),
    /// This build has no screen source for this platform at all.
    Unsupported {
        /// The platform that has no implementation, as `std::env::consts::OS`
        /// spells it.
        platform: &'static str,
    },
    /// Something unrecoverable. Deliberately the last resort: nearly everything
    /// that goes wrong with a screen has a named state above, and reaching for
    /// this variant when one of those fits is how a recoverable condition becomes
    /// a session that never comes back.
    Fatal(Fault),
}

impl CaptureError {
    /// The observation this condition presents to `selfhost_desk::state`.
    ///
    /// The mapping is the whole reason the two crates can be developed and tested
    /// apart: the state machine never learns what a `HRESULT` is, and this crate
    /// never learns what a backoff is.
    pub fn observation(&self) -> Observation {
        match self {
            Self::Retry => Observation::Retry,
            // A duplication-slot exhaustion is a rebuild, not a surrender: the
            // program holding the slot may well exit in a second. The state
            // machine's own reinitialisation budget is what eventually gives up,
            // and it does so with a sentence rather than a spin.
            Self::Reinitialise | Self::TooManyDuplications => Observation::Reinitialise,
            Self::SecureDesktop => Observation::SecureDesktop,
            Self::SessionDisconnected => Observation::SessionDisconnected,
            Self::NoSession => Observation::NoSession,
            Self::PermissionDenied(_) => Observation::PermissionDenied,
            Self::Unsupported { .. } | Self::Fatal(_) => Observation::Fatal,
        }
    }

    /// Whether this condition ends the session rather than pausing it.
    ///
    /// Everything that is merely a state answers `false`, including the ones an
    /// operator would describe as "broken" in the moment — a locked screen, a
    /// logged-out machine — because the session recovers from all of them by
    /// itself the instant the condition passes.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Unsupported { .. } | Self::Fatal(_))
    }

    /// The condition as one sentence, for the console to display verbatim.
    ///
    /// Borrowed for every state, so the polling paths that produce one of these
    /// per frame allocate nothing.
    pub fn sentence(&self) -> Cow<'static, str> {
        match self {
            Self::Retry => Cow::Borrowed("Nothing on screen has changed yet."),
            Self::Reinitialise => Cow::Borrowed(
                "The screen source is being rebuilt — usually a resolution change, a \
                 display being connected, or the graphics driver restarting.",
            ),
            Self::SecureDesktop => Cow::Borrowed(
                "The secure desktop is in front — a consent prompt or the lock screen. \
                 Screen and input are suspended until it is answered at the machine \
                 itself; this session deliberately cannot see it or type into it.",
            ),
            Self::SessionDisconnected => Cow::Borrowed(
                "The interactive session moved to another user or to a remote desktop \
                 connection. Nothing is being captured until it comes back.",
            ),
            Self::NoSession => Cow::Borrowed(
                "No user is logged in, so there is no desktop to capture. This is a \
                 normal state for a machine that has been rebooted and not signed into.",
            ),
            Self::TooManyDuplications => Cow::Borrowed(
                "Another program is already holding every screen-duplication slot this \
                 display has. Capture resumes when it lets go.",
            ),
            Self::PermissionDenied(grant) => Cow::Borrowed(grant.sentence()),
            Self::Unsupported { platform } => {
                Cow::Owned(format!("This build has no screen source for {platform}."))
            }
            Self::Fatal(fault) => {
                Cow::Owned(format!("The screen source failed for good: {}.", fault.sentence()))
            }
        }
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for CaptureError {}

/// Why an input event was not injected.
///
/// Separate from [`CaptureError`] because the two are not the same question and
/// answering them with one type invites the mistake of suspending a viewer's
/// screen because their keyboard was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectError {
    /// A refusal the protocol already has words for, forwarded to the client so
    /// the console can say why the keystroke did nothing.
    Refused(selfhost_desk::wire::Refusal),
    /// The operating system has not granted this process the input device.
    PermissionDenied(Grant),
    /// There is no interactive session to type into.
    NoSession,
    /// This build has no injector for this platform.
    Unsupported {
        /// The platform, as `std::env::consts::OS` spells it.
        platform: &'static str,
    },
    /// The platform call itself failed.
    Failed(Fault),
}

impl InjectError {
    /// The wire refusal a client should be told about, where one fits.
    ///
    /// `None` means the failure is the agent's own and is not the client's
    /// business — a fault code from a platform call tells a remote viewer
    /// nothing and tells an attacker something.
    pub fn refusal(&self) -> Option<selfhost_desk::wire::Refusal> {
        use selfhost_desk::wire::Refusal;
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::PermissionDenied(_) => Some(Refusal::NotPermitted),
            Self::NoSession => Some(Refusal::NotLive),
            Self::Unsupported { .. } | Self::Failed(_) => None,
        }
    }

    /// The condition as one sentence, for the agent's own log and the operator's
    /// diagnostics plate — not for the remote client.
    pub fn sentence(&self) -> Cow<'static, str> {
        match self {
            Self::Refused(refusal) => Cow::Owned(format!("Input refused: {refusal:?}.")),
            Self::PermissionDenied(grant) => Cow::Borrowed(grant.sentence()),
            Self::NoSession => Cow::Borrowed("There is no interactive session to type into."),
            Self::Unsupported { platform } => {
                Cow::Owned(format!("This build has no input injector for {platform}."))
            }
            Self::Failed(fault) => Cow::Owned(fault.sentence()),
        }
    }
}

impl fmt::Display for InjectError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for InjectError {}

/// One captured frame, borrowing the platform's own memory.
///
/// The lifetime is the point of this type. Every platform hands over pixels the
/// same way: a mapped staging texture, a DIB section, an `IOSurface` — memory
/// that stays valid exactly until the capture object is told to release it. By
/// borrowing rather than copying, "used the pixels after unmapping" becomes a
/// borrow-check error at the call site instead of a frame of garbage that looks
/// almost right, which is the shape of bug that survives a smoke test and shows
/// up in the field.
///
/// It also means the streaming path can encode straight out of the platform's
/// buffer: at 1080p a copy per frame is half a gigabyte a second of pure waste.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Which display this frame belongs to, matching [`Monitor::id`].
    pub monitor: u8,
    /// A monotonically increasing frame number, so a client can detect a gap.
    pub sequence: u64,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// Bytes between the start of one row and the start of the next.
    ///
    /// **Never assume `width * 4`.** Row padding is real and per-surface — a
    /// 3024-pixel macOS `CGImage` reports 12160 bytes per row where the tight
    /// value is 12096. Assuming the tight value produces a sheared image that
    /// still looks like a picture, so it passes a smoke test and fails in the
    /// field. Use [`Frame::row`].
    pub stride: usize,
    /// The pixels, BGRA, top-down, `stride` bytes per row.
    pub pixels: &'a [u8],
    /// What changed since the previous frame, as the platform described it.
    ///
    /// Empty is a legitimate answer meaning "the whole frame is new"; the
    /// encoder above decides whether to trust it or to diff, and that decision is
    /// `selfhost_desk::tiles`' business rather than this crate's.
    pub damage: Damage,
}

impl Frame<'_> {
    /// The pixels of one row, or `None` if the row is not in the buffer.
    ///
    /// Bounds-checked rather than sliced directly because `stride`, `width` and
    /// `pixels.len()` all come from the platform and a mismatch between them is a
    /// driver's mistake rather than ours — under `panic = "abort"` an
    /// out-of-bounds slice here would take the whole daemon down with it.
    pub fn row(&self, y: u32) -> Option<&[u8]> {
        let start = (y as usize).checked_mul(self.stride)?;
        let tight = (self.width as usize).checked_mul(4)?;
        let end = start.checked_add(tight)?;
        if y >= self.height || end > self.pixels.len() {
            return None;
        }
        self.pixels.get(start..end)
    }
}

/// The pointer, as the platform currently has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorState {
    /// Whether the pointer is being drawn at all.
    pub visible: bool,
    /// Position in virtual-desktop pixels; negative on a display left of or
    /// above the primary.
    pub position: VirtualPoint,
    /// The shape, present only when it is one the caller has not been given yet.
    ///
    /// `None` is the overwhelmingly common answer: the shape changes when the
    /// pointer crosses a text field, and the position changes sixty times a
    /// second. Sending the shape only when it is new is what lets a client
    /// composite the pointer at *its* frame rate rather than the capture rate —
    /// the single largest perceived-latency win available in this subsystem.
    pub shape: Option<CursorImage>,
}

/// One pointer shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorImage {
    /// The platform's own identity for this shape, used as the cache key.
    pub id: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The hotspot's x offset from the image's left edge.
    pub hotspot_x: u32,
    /// The hotspot's y offset from the image's top edge.
    pub hotspot_y: u32,
    /// The image, BGRA, top-down, tightly packed.
    pub bgra: Vec<u8>,
}

/// A source of frames for one machine's displays.
///
/// Object-safe and synchronous on purpose: the implementation runs on a
/// dedicated `std::thread` rather than a tokio worker, because Windows'
/// `SetThreadDesktop` fails if the calling thread has ever owned a window or a
/// hook and a tokio worker may have run anything at all.
pub trait Capture {
    /// The displays this source can produce frames for.
    ///
    /// Borrowed rather than returned by value because a caller asks once per
    /// frame to map coordinates, and the list changes only when a display is
    /// plugged in — which arrives as [`CaptureError::Reinitialise`], not as a
    /// silently different slice.
    fn monitors(&self) -> &[Monitor];

    /// The next frame, or the state the source is in instead.
    ///
    /// Waits up to `timeout` for something to change. `Ok(None)` and
    /// [`CaptureError::Retry`] both mean "nothing yet"; the distinction is that
    /// `Ok(None)` is the timeout expiring normally and `Retry` is the platform
    /// telling us so. Neither is a failure and neither counts against any budget.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError>;
}

/// A source of pointer position and shape.
///
/// Separate from [`Capture`] because the pointer is captured separately on every
/// platform this project targets, and because a session may show a pointer while
/// the screen itself is suspended.
pub trait CursorSource {
    /// The pointer's current state.
    fn cursor(&mut self) -> Result<CursorState, CaptureError>;

    /// Forgets which shape the caller was last given, so the next [`Self::cursor`]
    /// carries the bitmap again.
    ///
    /// There are **two** caches of pointer shapes in a live session, and this
    /// method is the only thing that keeps them in step. The implementation holds
    /// one, so that a shape is decoded from the platform once rather than thirty
    /// times a second; `selfhost_desk::cursor::ShapeCache` holds the other, which
    /// models what the far end is holding and is bounded and least-recently-used
    /// because an application that creates cursors would otherwise drive an
    /// unbounded allocation in the client.
    ///
    /// A bounded cache evicts. When it evicts the shape that is currently on
    /// screen, the client no longer has a bitmap for it and this source — believing
    /// it already handed that shape over — would never send one again, leaving the
    /// pointer drawn with whichever shape the client happened to keep. Calling this
    /// resolves it in one frame.
    ///
    /// Defaulted to nothing, because a source that decodes the shape every time is
    /// wasteful rather than wrong, and a platform backend should not have to
    /// implement a cache it does not have.
    fn forget_shape(&mut self) {}
}

/// A sink for synthesised keyboard and pointer events.
pub trait Injector {
    /// Injects a batch of events, in order.
    ///
    /// # `Ok(())` means *posted*, never *delivered*
    ///
    /// This is not a hedge; it is the literal truth on both platforms and it is
    /// load-bearing. `CGEventPost` returns `void`. Windows' `SendInput` returns
    /// the number of events it accepted, and User Interface Privilege Isolation
    /// silently discards injection into any window at a higher integrity level
    /// than the caller — the agent runs as the console user at medium integrity
    /// *deliberately*, so this is the ordinary case whenever an elevated window
    /// has focus, and neither the return value nor `GetLastError` says a word
    /// about it. An implementation must therefore never infer success from a full
    /// return count, and the console reports `input-refused` rather than claiming
    /// delivery it cannot observe.
    fn inject(&mut self, events: &[InjectedEvent]) -> Result<(), InjectError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_answers_with_a_sentence_and_an_observation() {
        // The console renders `sentence()` verbatim, so an empty one is a blank
        // status line that an operator reads as "hung".
        let conditions = [
            CaptureError::Retry,
            CaptureError::Reinitialise,
            CaptureError::SecureDesktop,
            CaptureError::SessionDisconnected,
            CaptureError::NoSession,
            CaptureError::TooManyDuplications,
            CaptureError::PermissionDenied(Grant::ScreenRecording),
            CaptureError::PermissionDenied(Grant::Accessibility),
            CaptureError::Unsupported { platform: "haiku" },
            CaptureError::Fatal(Fault::os("BitBlt", 6)),
        ];
        for condition in &conditions {
            let sentence = condition.sentence();
            assert!(!sentence.is_empty(), "{condition:?} has no sentence");
            assert!(
                sentence.ends_with('.'),
                "{condition:?} does not read as a sentence: {sentence}"
            );
            // Every condition must map somewhere the state machine understands.
            let _ = condition.observation();
        }
    }

    #[test]
    fn only_the_two_unrecoverable_conditions_are_fatal() {
        // A locked screen and a logged-out machine look broken to an operator and
        // are not: the session recovers from both by itself.
        assert!(!CaptureError::SecureDesktop.is_fatal());
        assert!(!CaptureError::NoSession.is_fatal());
        assert!(!CaptureError::SessionDisconnected.is_fatal());
        assert!(!CaptureError::PermissionDenied(Grant::ScreenRecording).is_fatal());
        assert!(!CaptureError::TooManyDuplications.is_fatal());
        assert!(CaptureError::Unsupported { platform: "haiku" }.is_fatal());
        assert!(CaptureError::Fatal(Fault::refused("x", "y")).is_fatal());
    }

    #[test]
    fn a_duplication_slot_exhaustion_asks_for_a_rebuild_rather_than_surrendering() {
        // The program holding the slot may exit a second later. Surrendering here
        // would mean a session that never comes back from a transient condition.
        assert_eq!(CaptureError::TooManyDuplications.observation(), Observation::Reinitialise);
    }

    #[test]
    fn an_injection_fault_is_not_forwarded_to_the_client() {
        // A platform error number tells a remote viewer nothing and tells an
        // attacker something about the machine.
        assert_eq!(InjectError::Failed(Fault::os("SendInput", 5)).refusal(), None);
        assert_eq!(
            InjectError::NoSession.refusal(),
            Some(selfhost_desk::wire::Refusal::NotLive)
        );
    }

    #[test]
    fn a_remediation_names_the_pane_the_binary_and_the_relaunch() {
        // The three facts an operator needs. Dropping any one of them produces a
        // remediation that is followed correctly and appears not to work.
        let sentence = Grant::ScreenRecording.remediation(std::path::Path::new("/opt/selfhost"));
        assert!(sentence.contains("System Settings › Privacy & Security › Screen Recording"));
        assert!(sentence.contains("/opt/selfhost"));
        assert!(sentence.contains("relaunch"), "{sentence}");
        assert!(sentence.contains("rebuild"), "the grant dies on every deploy: {sentence}");
        assert!(sentence.ends_with('.'));
    }

    #[test]
    fn the_two_grants_send_the_operator_to_two_different_panes() {
        // They are granted and revoked independently, and a viewer that only
        // watches never needs the second one at all.
        assert_ne!(Grant::ScreenRecording.panel(), Grant::Accessibility.panel());
        assert!(Grant::Accessibility
            .remediation(std::path::Path::new("/opt/selfhost"))
            .contains("Accessibility"));
    }

    #[test]
    fn an_absurdly_long_path_still_leaves_a_whole_sentence_on_the_wire() {
        // The framing layer truncates at `MAX_DETAIL_BYTES` without knowing where a
        // sentence ends, so the sentence is built to fit rather than cut to fit.
        let long = std::path::PathBuf::from(format!("/{}/selfhost", "directory/".repeat(40)));
        let sentence = Grant::ScreenRecording.remediation(&long);
        assert!(
            sentence.len() <= selfhost_desk::wire::MAX_DETAIL_BYTES,
            "{} bytes is over the wire's cap",
            sentence.len()
        );
        assert!(sentence.ends_with('.'));
        assert!(sentence.contains("selfhost"), "the tail identifies the binary: {sentence}");
    }

    #[test]
    fn eliding_a_path_cuts_on_a_character_boundary() {
        // A path is not necessarily ASCII, and half a character on the wire is a
        // decode failure at the far end rather than a shortened sentence.
        let text = "/Users/ünïcødé/target/release/selfhost";
        for budget in 0..text.len() + 2 {
            let cut = elide_head(text, budget);
            assert!(cut.is_char_boundary(0));
            assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
        }
    }

    #[test]
    fn a_row_is_read_through_the_stride_and_never_past_the_buffer() {
        // Row padding is real and per-surface; a tight-packing assumption shears
        // the image in a way that still looks like a picture.
        let pixels = vec![0u8; 3 * 40]; // 3 rows of 40 bytes, 8 pixels used per row
        let frame = Frame {
            monitor: 0,
            sequence: 1,
            width: 8,
            height: 3,
            stride: 40,
            pixels: &pixels,
            damage: Damage::default(),
        };
        assert_eq!(frame.row(0).map(<[u8]>::len), Some(32));
        assert_eq!(frame.row(2).map(<[u8]>::len), Some(32));
        assert!(frame.row(3).is_none(), "a row past the height is not a row");
    }

    #[test]
    fn a_lying_stride_is_refused_rather_than_panicking() {
        // The stride comes from a driver. Under `panic = "abort"` an out-of-bounds
        // slice here would take the daemon down, so every read is checked.
        let pixels = vec![0u8; 16];
        let frame = Frame {
            monitor: 0,
            sequence: 1,
            width: 4_000_000,
            height: 4,
            stride: usize::MAX,
            pixels: &pixels,
            damage: Damage::default(),
        };
        for y in 0..8 {
            assert!(frame.row(y).is_none());
        }
    }
}
