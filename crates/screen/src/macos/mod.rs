//! macOS: the displays this machine has, and whether we are allowed to look.
//!
//! Only two things live here in this phase, and both exist to prove something
//! rather than to deliver a picture: **display enumeration** and the
//! **permission preflight**. Capture and injection come later.
//!
//! The point of building this half now is that it is the seam's second
//! implementor. A trait with one implementation is a trait shaped like that
//! implementation, and a Windows-shaped `Capture` would be discovered on the day
//! somebody tried to make a Mac speak it — by which time the protocol, the
//! session driver and both consoles would all be built on top of the wrong
//! shape. Enumerating displays here forces the questions that differ:
//! coordinates in **points** rather than pixels, a scale factor that is genuinely
//! per-display, and a permission model where the operating system answers a
//! separate question from the one that returns the pixels.
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

pub mod sys;

pub use sys::{accessibility_allowed, displays, monitors, preflight, screen_recording_allowed, Display};
