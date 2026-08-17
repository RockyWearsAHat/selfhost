//! What the agent can only learn about itself from inside its own session.
//!
//! Everything here answers a question the daemon cannot answer on the agent's
//! behalf, and every one of them has been the cause of a "it starts, reports
//! nothing wrong, and captures a blank screen" failure:
//!
//! - **DPI awareness** is a process-wide declaration that must be made before
//!   anything asks the size of anything. Get it wrong and `GetSystemMetrics`
//!   reports virtualised extents while the captured pixels are physical, so the
//!   pointer drifts progressively toward the bottom-right of a scaled display —
//!   which is diagnosed as a rounding error in `crate::coords`, which is innocent.
//! - **The window station** must be `WinSta0`. A process on any other one runs
//!   perfectly and is invisible; there is no error to read anywhere.
//! - **The desktop** must be `Default`. `Winlogon` means the secure desktop has
//!   the input, and a screen source that does not notice shows a frozen picture.
//! - **The integrity level** explains a whole class of behaviour nobody can see
//!   from the outside: User Interface Privilege Isolation silently discards input
//!   injected into any window above the caller's level.
//!
//! None of these is fatal on its own, which is exactly why each is *reported*
//! rather than asserted. An agent that refuses to start because it cannot read its
//! own integrity level is worse than one that says `integrity-unknown` and streams
//! a screen.

use super::sys::{self, Handle, OwnedHandle};
use super::{classify_desktop, desktop, InputDesktop};
use crate::agent::{DpiAwareness, Integrity};
use crate::Fault;

/// The longest window station name this build will read back.
const MAX_STATION_NAME: u32 = 256;

/// Declares this process per-monitor DPI aware, and reports what it achieved.
///
/// Called **first**, before any capture, any enumeration and any coordinate. The
/// declaration is irreversible for the life of the process, which is a feature
/// here: there is no path by which a later call can quietly change what every
/// coordinate in the session means.
///
/// `SetProcessDpiAwarenessContext` is resolved at run time rather than imported.
/// A statically imported symbol that is missing stops the process from *starting*,
/// so on a Windows too old to have it the agent would fail with a loader error
/// naming a DPI function — on a machine where somebody is trying to find out why
/// their screen is blank. The documented manifest route is unavailable for a
/// different reason: it needs a build script, and there is no `build.rs` anywhere
/// in this workspace.
pub fn declare_dpi_awareness() -> DpiAwareness {
    let context: Option<sys::SetProcessDpiAwarenessContextFn> = unsafe {
        sys::optional_export::<sys::SetProcessDpiAwarenessContextFn>(
            "user32.dll",
            b"SetProcessDpiAwarenessContext\0",
        )
    };
    if let Some(declare) = context {
        if unsafe { declare(sys::DPI_PER_MONITOR_AWARE_V2) } != 0 {
            return DpiAwareness::PerMonitorV2;
        }
        // A failure here is very often `ERROR_ACCESS_DENIED`, which means awareness
        // was already set — by a manifest, or by a host process. The fallback below
        // then also fails, and `System` is the honest answer for "somebody already
        // declared something and it was not us".
    }
    if unsafe { sys::SetProcessDPIAware() } != 0 {
        return DpiAwareness::System;
    }
    DpiAwareness::Unaware
}

/// The window station this process is attached to.
///
/// Expected to be `WinSta0`, which is the only interactive one. The handle is
/// borrowed rather than owned: `GetProcessWindowStation` hands back the station the
/// process already belongs to, and closing it would close something the process is
/// still using.
///
/// # Errors
///
/// A [`Fault`] naming the call, which the caller renders as `unknown` in the report
/// line rather than treating as a reason not to run.
pub fn window_station_name() -> Result<String, Fault> {
    let station = unsafe { sys::GetProcessWindowStation() };
    if station.is_null() {
        return Err(Fault::last_os_error("GetProcessWindowStation"));
    }
    let mut buffer = vec![0u16; MAX_STATION_NAME as usize];
    let mut needed: u32 = 0;
    let bytes = MAX_STATION_NAME * u32::try_from(size_of::<u16>()).unwrap_or(2);
    let ok = unsafe {
        sys::GetUserObjectInformationW(
            station,
            sys::UOI_NAME,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("GetUserObjectInformationW"));
    }
    Ok(unsafe { sys::from_wide(buffer.as_ptr(), buffer.len()) })
}

/// The desktop currently receiving input, named for the report line.
///
/// Never fails: a desktop that cannot be opened is the secure one, which is a state
/// with a name, and a query that fails for any other reason is reported as
/// `unknown` rather than stopping an agent that may be perfectly able to capture a
/// moment later.
pub fn input_desktop_name() -> String {
    match desktop::input_desktop() {
        Ok(InputDesktop::Default) => "Default".to_owned(),
        Ok(InputDesktop::Secure) => "Winlogon".to_owned(),
        Ok(InputDesktop::ScreenSaver) => "Screen-saver".to_owned(),
        Ok(InputDesktop::Other(name)) => name,
        Err(_) => "unknown".to_owned(),
    }
}

/// The integrity level this process is running at.
///
/// Read from the token's mandatory label, whose SID's **last** sub-authority is the
/// level. The count is read first and the index derived from it, because reading a
/// fixed index would read past the end of a shorter SID — which is a read of
/// whatever follows it in the buffer, and under `panic = "abort"` there is no
/// recovering from what that produces.
///
/// Answers [`Integrity::Other`] with a zero when the level cannot be read at all, so
/// that a report line always has something in it. An agent that refused to start
/// over an unreadable label would be trading a working screen for a diagnostic.
pub fn process_integrity() -> Integrity {
    match read_integrity_rid() {
        Ok(rid) => Integrity::from_rid(rid),
        Err(_) => Integrity::Other(0),
    }
}

/// The relative identifier at the end of this process's mandatory label.
fn read_integrity_rid() -> Result<u32, Fault> {
    let mut raw: Handle = std::ptr::null_mut();
    let ok = unsafe {
        sys::OpenProcessToken(sys::GetCurrentProcess(), sys::TOKEN_QUERY, &mut raw)
    };
    if ok == 0 {
        return Err(Fault::last_os_error("OpenProcessToken"));
    }
    let token = OwnedHandle::new(raw)
        .ok_or_else(|| Fault::refused("OpenProcessToken", "succeeded but produced no token"))?;
    token_integrity(&token)
}

/// The integrity level at the end of **any** token's mandatory label.
///
/// Shared with the injector, which asks the same question about the process owning
/// the foreground window rather than about itself. One copy of this walk exists on
/// purpose: it reads a variable-length SID out of a buffer the system filled in,
/// and the index it reads is derived from the count rather than fixed — a second,
/// slightly different copy of that is how a read past the end of a shorter SID gets
/// written.
pub(crate) fn token_integrity(token: &OwnedHandle) -> Result<u32, Fault> {
    let mut needed: u32 = 0;
    // The first call is expected to fail: it exists to report the length.
    unsafe {
        sys::GetTokenInformation(
            token.raw(),
            sys::TOKEN_INTEGRITY_LEVEL_CLASS,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 || needed as usize > 64 * 1024 {
        return Err(Fault::refused(
            "GetTokenInformation",
            format!("reported an implausible mandatory label size of {needed} bytes"),
        ));
    }

    // Allocated as `u64` so the buffer is eight-byte aligned: the structure starts
    // with a pointer, and reading one out of an under-aligned buffer is undefined
    // behaviour that happens to work on x86 until it does not.
    let words = (needed as usize).div_ceil(size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let ok = unsafe {
        sys::GetTokenInformation(
            token.raw(),
            sys::TOKEN_INTEGRITY_LEVEL_CLASS,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("GetTokenInformation"));
    }

    // Sound: the buffer is aligned, is at least `needed` bytes, and Windows has
    // just written a `TOKEN_MANDATORY_LABEL` into it.
    let label = unsafe { &*buffer.as_ptr().cast::<sys::TokenMandatoryLabel>() };
    if label.label.sid.is_null() {
        return Err(Fault::refused("GetTokenInformation", "returned a label with no SID"));
    }

    let count = unsafe { sys::GetSidSubAuthorityCount(label.label.sid) };
    if count.is_null() {
        return Err(Fault::refused("GetSidSubAuthorityCount", "answered with no count"));
    }
    let last = unsafe { *count };
    if last == 0 {
        return Err(Fault::refused("GetSidSubAuthorityCount", "reported a SID with no authorities"));
    }
    let index = u32::from(last).saturating_sub(1);
    let authority = unsafe { sys::GetSidSubAuthority(label.label.sid, index) };
    if authority.is_null() {
        return Err(Fault::refused("GetSidSubAuthority", "answered with no authority"));
    }
    Ok(unsafe { *authority })
}

/// Whether the agent landed where the spawn aimed it.
///
/// Both halves matter and they fail differently: the wrong window station is a
/// process nobody can see, and the wrong desktop is a process that captures the
/// desktop nobody is looking at. Neither reports an error anywhere, which is why
/// this is checked and stated rather than assumed.
pub fn landed_interactively(window_station: &str, desktop_name: &str) -> bool {
    window_station.eq_ignore_ascii_case("WinSta0")
        && matches!(classify_desktop(desktop_name), InputDesktop::Default)
}
