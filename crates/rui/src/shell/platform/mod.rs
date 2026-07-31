//! The per-platform backends, and the choice between them.
//!
//! Exactly one is compiled, and each implements the same
//! [`Backend`](crate::shell::Backend) — whatever that trait currently asks for,
//! which is the point of naming it in one place. `unsafe` is confined to these
//! files: the run loop above them and the toolkit beneath them contain none.
//!
//! # Where a platform cannot do what the seam asks
//!
//! It says so, in its own module header, and returns the honest empty answer —
//! not a plausible-looking one. The X11 backend has no input method and says
//! that in place of pretending to compose; `unsupported.rs` does the same for
//! every method at once. A gap someone can read is a gap someone can close; a
//! silent one is a bug report from a person who thought their keyboard was
//! broken.

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
#[allow(unsafe_code, reason = "AppKit and Core Graphics are C and Objective-C")]
mod backend;

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
#[allow(unsafe_code, reason = "the Win32 window and bitmap calls are C")]
mod backend;

#[cfg(all(unix, not(target_os = "macos")))]
#[path = "x11.rs"]
#[allow(unsafe_code, reason = "Xlib is C")]
mod backend;

#[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
#[path = "unsupported.rs"]
mod backend;

pub(crate) use backend::Window;
