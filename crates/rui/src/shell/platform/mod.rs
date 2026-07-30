//! The per-platform backends, and the choice between them.
//!
//! Exactly one is compiled, and each implements the same four-method
//! [`Backend`](crate::Backend). `unsafe` is confined to these files: the run
//! loop above them and the toolkit beneath them contain none.

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
