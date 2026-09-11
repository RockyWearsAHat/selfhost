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
    use windows::Win32::System::Shutdown::ExitWindowsEx;
    use windows::Win32::System::Shutdown::EWX_REBOOT;

    unsafe {
        // Call the Windows API to request an immediate reboot.
        // EWX_REBOOT = 2 (reboot)
        if ExitWindowsEx(EWX_REBOOT, 0).as_bool() {
            // Does not return on success; if we get here, something went wrong
            Err(RebootError::Failed(
                "ExitWindowsEx returned true but process still running".to_string(),
            ))
        } else {
            Err(RebootError::Failed(
                format!("ExitWindowsEx failed with error code"),
            ))
        }
    }
}
