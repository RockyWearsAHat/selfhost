//! Platform-specific reboot implementations.
//!
//! The reboot module provides a single public function, `reboot()`,
//! which delegates to the appropriate platform-specific implementation.
//! New platforms can be added by creating conditional compilation blocks.

use std::fmt;

/// Error type for reboot operations.
#[derive(Debug)]
pub enum RebootError {
    /// The reboot command failed with a system error or message.
    Failed(String),
    /// Reboot is not implemented on this platform.
    NotImplemented,
}

impl fmt::Display for RebootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(msg) => write!(f, "reboot failed: {}", msg),
            Self::NotImplemented => write!(f, "reboot not implemented on this platform"),
        }
    }
}

impl std::error::Error for RebootError {}

/// Trigger an immediate OS reboot.
///
/// On Windows, this calls the Win32 API to reboot immediately.
/// On other platforms, this returns `NotImplemented` (stubs for future).
/// The function does not return on success (the OS terminates the process).
pub fn reboot() -> Result<(), RebootError> {
    #[cfg(windows)]
    {
        windows_reboot()
    }

    #[cfg(not(windows))]
    {
        Err(RebootError::NotImplemented)
    }
}

#[cfg(windows)]
fn windows_reboot() -> Result<(), RebootError> {
    use std::process::Command;

    // Shell out to the built-in shutdown utility rather than calling the
    // Win32 API directly: this crate forbids unsafe code workspace-wide,
    // and ExitWindowsEx has no safe wrapper.
    let status = Command::new("shutdown")
        .args(["/r", "/t", "0"])
        .status()
        .map_err(|e| RebootError::Failed(e.to_string()))?;

    // The OS terminates the process on a successful reboot request; if we
    // get here, the request itself failed.
    Err(RebootError::Failed(format!(
        "shutdown command exited with status {status}"
    )))
}
