//! Which session is on the console, who is signed into it, and which desktop is
//! in front.
//!
//! Two questions that look like one and are answered by two different processes.
//!
//! **The daemon** asks [`active_console_session`]. Running as `SYSTEM` in session
//! 0, it can see *which* session owns the physical console and *whether* somebody
//! is signed into it, and it needs both to decide whether to start an agent and
//! where.
//!
//! **The agent** asks [`input_desktop`]. `OpenInputDesktop` answers about the
//! window station of the **calling process's own session**, so a daemon in
//! session 0 asking it learns only about session 0's blank desktop. The secure
//! desktop — a UAC consent dialog, the lock screen, the credential provider — can
//! therefore only be detected from inside the interactive session, which is one
//! more reason the agent exists.
//!
//! # The secure desktop is detected by being refused
//!
//! The agent runs as the console user at medium integrity, deliberately not as
//! `SYSTEM` and deliberately without `uiAccess`. When `Winlogon` takes the input
//! desktop, an ordinary user process cannot open it: `OpenInputDesktop` answers
//! null with `ERROR_ACCESS_DENIED`. That refusal *is* the signal, and it is a
//! better one than the name would be, because it also covers the case where the
//! desktop switched between the open and the name query.

use super::sys::{self, Handle, OwnedHandle};
use super::{classify_desktop, InputDesktop};
use crate::supervisor::ConsoleSession;
use crate::Fault;

/// The longest desktop name this build will read back.
///
/// Desktop names are short; the bound exists so a hostile or corrupt answer
/// cannot make this allocate without limit.
const MAX_DESKTOP_NAME: u32 = 256;

/// The session on the physical console, and whether anybody is signed into it.
///
/// Never reports a failure for either of the two ordinary conditions:
/// `0xFFFFFFFF` from `WTSGetActiveConsoleSessionId` is *ask again* (the console
/// is mid-attach — during boot, during a session switch, while being redirected),
/// and `ERROR_NO_TOKEN` from `WTSQueryUserToken` is *nobody is signed in*. Both
/// are states the console renders as sentences.
///
/// # Errors
///
/// A [`Fault`] here means the query itself could not be performed — most usefully
/// `ERROR_ACCESS_DENIED`, which means the daemon is not running as `LocalSystem`
/// and the whole session-0 plan is inoperative. That is worth reporting loudly
/// rather than treating as "nobody is logged in", which would look exactly like a
/// machine sitting at its login screen forever.
pub fn active_console_session() -> Result<ConsoleSession, Fault> {
    let session = unsafe { sys::WTSGetActiveConsoleSessionId() };
    if session == sys::NO_ACTIVE_SESSION {
        return Ok(ConsoleSession::Attaching);
    }
    match console_user_token(session)? {
        Some(_token) => Ok(ConsoleSession::User(session)),
        None => Ok(ConsoleSession::NoUser),
    }
}

/// The primary access token of whoever is signed into `session`.
///
/// `Ok(None)` means nobody is — an ordinary state, not a failure. The token is
/// returned owned, so the caller cannot forget to close it; the probe in
/// [`active_console_session`] drops it immediately, which is the cheapest way to
/// ask "is anybody there?" without a second API.
///
/// Requires the caller to hold `SE_TCB_NAME`, which `LocalSystem` does. Any other
/// account gets `ERROR_ACCESS_DENIED` and this is reported rather than
/// interpreted.
pub(crate) fn console_user_token(session: u32) -> Result<Option<OwnedHandle>, Fault> {
    let mut raw: Handle = std::ptr::null_mut();
    let ok = unsafe { sys::WTSQueryUserToken(session, &mut raw) };
    if ok == 0 {
        let fault = Fault::last_os_error("WTSQueryUserToken");
        if fault.code() == Some(sys::ERROR_NO_TOKEN) {
            return Ok(None);
        }
        return Err(fault.noting(format!("session {session}")));
    }
    match OwnedHandle::new(raw) {
        Some(token) => Ok(Some(token)),
        // Success with no handle should be impossible; treating it as "nobody is
        // logged in" would hide a broken platform behind an ordinary state.
        None => Err(Fault::refused("WTSQueryUserToken", "succeeded but produced no token")),
    }
}

/// The string form of the security identifier a token belongs to.
///
/// This is what the agent pipe's access-control entry is built around, so it is
/// the one value in this module that ends up inside a security descriptor. It is
/// validated again by [`super::pipe_descriptor`] before it gets there — not
/// because `ConvertSidToStringSidW` is untrusted, but because the concatenation
/// is the kind of place where a later change could start passing something else.
pub(crate) fn token_user_sid(token: &OwnedHandle) -> Result<String, Fault> {
    let mut needed: u32 = 0;
    // The first call is expected to fail: it exists to report the length.
    unsafe {
        sys::GetTokenInformation(
            token.raw(),
            sys::TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 || needed as usize > 64 * 1024 {
        return Err(Fault::refused(
            "GetTokenInformation",
            format!("reported an implausible TOKEN_USER size of {needed} bytes"),
        ));
    }

    // Allocated as `u64` so the buffer is eight-byte aligned: `TOKEN_USER` starts
    // with a pointer, and reading one out of an under-aligned buffer is undefined
    // behaviour that happens to work on x86 until it does not.
    let words = (needed as usize).div_ceil(size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let ok = unsafe {
        sys::GetTokenInformation(
            token.raw(),
            sys::TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("GetTokenInformation"));
    }

    // Safe by construction: the buffer is aligned, is at least `needed` bytes,
    // and Windows has just written a `TOKEN_USER` into it.
    let user = unsafe { &*buffer.as_ptr().cast::<sys::TokenUser>() };
    if user.user.sid.is_null() {
        return Err(Fault::refused("GetTokenInformation", "returned a TOKEN_USER with no SID"));
    }

    let mut text: *mut u16 = std::ptr::null_mut();
    let ok = unsafe { sys::ConvertSidToStringSidW(user.user.sid, &mut text) };
    if ok == 0 {
        return Err(Fault::last_os_error("ConvertSidToStringSidW"));
    }
    let owned = sys::LocalBuffer::new(text.cast())
        .ok_or_else(|| Fault::refused("ConvertSidToStringSidW", "succeeded but produced no text"))?;
    // A string-form SID cannot exceed 184 characters; the bound is a guard
    // against a buffer that is somehow not terminated, not an expectation.
    Ok(unsafe { sys::from_wide(owned.raw().cast::<u16>(), 256) })
}

/// Which desktop is currently receiving input, **in this process's session**.
///
/// Called from the agent. A daemon in session 0 calling this learns about session
/// 0 and nothing else, which is the trap this function's placement is meant to
/// prevent somebody walking into.
///
/// `ERROR_ACCESS_DENIED` is translated to [`InputDesktop::Secure`] rather than
/// reported: the agent runs at medium integrity as the console user, and the one
/// desktop it cannot open is `Winlogon`'s. That is precisely the state we want to
/// name, and naming it here means the caller never has to know the error code.
pub fn input_desktop() -> Result<InputDesktop, Fault> {
    let raw = unsafe { sys::OpenInputDesktop(0, 0, sys::DESKTOP_READOBJECTS) };
    let Some(desktop) = OwnedDesktop::new(raw) else {
        let fault = Fault::last_os_error("OpenInputDesktop");
        return if fault.code() == Some(sys::ERROR_ACCESS_DENIED) {
            Ok(InputDesktop::Secure)
        } else {
            Err(fault)
        };
    };

    let mut buffer = vec![0u16; MAX_DESKTOP_NAME as usize];
    let mut needed: u32 = 0;
    let bytes = MAX_DESKTOP_NAME * u32::try_from(size_of::<u16>()).unwrap_or(2);
    let ok = unsafe {
        sys::GetUserObjectInformationW(
            desktop.raw(),
            sys::UOI_NAME,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("GetUserObjectInformationW"));
    }
    let name = unsafe { sys::from_wide(buffer.as_ptr(), buffer.len()) };
    Ok(classify_desktop(&name))
}

/// A desktop handle that closes itself.
///
/// Deliberately **not** built on [`OwnedHandle`]: an `HDESK` is released with
/// `CloseDesktop`, not `CloseHandle`, and a type that could be dropped through
/// either path is a handle closed twice by two different functions — which
/// corrupts an unrelated handle later, somewhere that has nothing to do with
/// desktops. It holds the raw value and has exactly one destructor.
#[derive(Debug)]
struct OwnedDesktop(Handle);

impl OwnedDesktop {
    /// Takes ownership of an `HDESK`, refusing the two values that mean failure.
    fn new(handle: Handle) -> Option<Self> {
        if handle.is_null() || handle == sys::invalid_handle() {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// The raw handle, for passing back into Win32.
    fn raw(&self) -> Handle {
        self.0
    }
}

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        unsafe { sys::CloseDesktop(self.0) };
    }
}
