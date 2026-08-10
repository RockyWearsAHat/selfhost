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
//! ([`coords`]), the pure input-lowering plan ([`input`]), the agent supervisor
//! ([`supervisor`]), and the Windows session-0 agent spawn ([`windows`]).
//!
//! Not built, on purpose: **there is no capture code and no injection code in
//! this crate yet.** The session-0 problem — a daemon running as a Windows
//! service in session 0 cannot capture the interactive desktop by any method — is
//! the single fact that sinks this project if it is discovered late, so the agent
//! spawn is proven first, with nothing dangerous attached to it. A screen that
//! cannot be reached is a bug; a keyboard that can be reached before the plumbing
//! is trustworthy is an incident.
//!
//! # Modules
//!
//! - [`coords`] — **pure.** Virtual-desktop ↔ normalised, and pixels ↔ points.
//!   Every sign, every `- 1`, and every scale factor in the subsystem is here and
//!   nowhere else, because a pointer that drifts is diagnosed as a rounding error
//!   in exactly one file or it is diagnosed nowhere.
//! - [`input`] — **pure.** Which mechanism a piece of input must use, and the
//!   held-key bookkeeping that makes `RELEASE_ALL` possible.
//! - [`supervisor`] — the daemon side of the agent's life. The restart decision
//!   is pure and exhaustively tested; the process handling is the thin part.
//! - [`windows`] — the session-0 spawn. Its pure half compiles everywhere so it
//!   is tested on a developer machine; its FFI half compiles only on Windows.
//! - `macos` — display enumeration and the permission preflight, so the traits
//!   have a second implementor and the seam is proven platform-neutral. Compiled
//!   only there, which is why this entry is not a link: on the production box it
//!   does not exist.
//! - [`stub`] — every other platform, answering with a typed refusal rather than
//!   failing to compile.

pub mod coords;
pub mod fault;
pub mod input;
pub mod supervisor;
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod stub;

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
