//! macOS: this machine's screen, its pointer, and its keyboard.
//!
//! The whole seam, implemented a second time. That is what this half is *for*
//! beyond the Macs it serves: a trait with one implementation is a trait shaped
//! like that implementation, and a Windows-shaped [`crate::Capture`] would have
//! been discovered on the day somebody tried to make a Mac speak it — by which
//! time the protocol, the session driver and both consoles would have been built
//! on the wrong shape. Every question the two platforms answer differently is
//! forced here: coordinates in **points** rather than pixels, a scale factor that
//! is genuinely per-display, frames that arrive on somebody else's thread rather
//! than being asked for, and a permission model where the operating system answers
//! a separate question from the one that returns the pixels.
//!
//! # The modules
//!
//! - [`sys`] — display enumeration and the two consent queries.
//! - [`grant`] — the TCC gate as a product surface: which pane, which binary, and
//!   the fact that the grant dies on every rebuild of a self-updating tree.
//! - [`stream`] — `CGDisplayStream` capture, including the hand-built
//!   Objective-C block and the padded-row arithmetic.
//! - [`cursor`] — the pointer's position, and the honest reason its bitmap is
//!   never sent.
//! - [`inject`] — `CGEvent` injection, the secure-input refusal, and the
//!   autonomous release of everything held.
//!
//! # Permission is a preflight, never an inspection of the frame
//!
//! macOS does not fail a screen capture that has not been granted Screen
//! Recording. It succeeds, and hands the process a picture of the desktop
//! wallpaper with every window missing. So there is no frame anybody can look at
//! that answers "am I allowed?"; the only answer is
//! `CGPreflightScreenCaptureAccess`, asked before the first capture, and
//! `AXIsProcessTrusted` for input. Getting this backwards produces a remote
//! desktop that appears to work and shows an empty desktop, which is the single
//! most confusing failure this subsystem could have.

pub mod cursor;
pub mod grant;
pub mod inject;
pub mod stream;
pub mod sys;

pub use cursor::MacCursor;
pub use grant::{gate, gate_input, remediation, Grants};
pub use inject::MacInjector;
pub use stream::MacCapture;
pub use sys::{accessibility_allowed, displays, monitors, preflight, screen_recording_allowed, Display};
