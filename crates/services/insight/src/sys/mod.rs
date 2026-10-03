//! Platform-specific system sampling.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{sample, sample_processes, read_windows_events};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{sample, sample_processes, read_windows_events};

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
pub use unix::{sample, sample_processes, read_windows_events};
