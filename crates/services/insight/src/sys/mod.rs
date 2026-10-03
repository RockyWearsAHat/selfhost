//! Platform-specific system sampling.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::sample;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::sample;

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
pub use unix::sample;
