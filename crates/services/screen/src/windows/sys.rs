//! Raw Win32 declarations. No logic lives here, deliberately.
//!
//! This workspace links no Windows crate — the dependency policy in the root
//! `Cargo.toml` permits the async runtime, the TLS implementation and our own
//! config serialisation and nothing else, and `crates/admin/src/token.rs` and
//! `crates/rui/src/shell/platform/windows.rs` already bind what they need this
//! way. So every symbol, structure and constant used by the session-0 spawn is
//! spelled out below, once, in a file with no branches in it. Everything that
//! *decides* something lives in a sibling module, which is what makes a mistake
//! here a wrong declaration rather than a wrong declaration tangled up with a
//! wrong decision.
//!
//! # The shared calling convention
//!
//! Unless a function's own comment says otherwise, every `Bool` here answers
//! zero for failure and non-zero for success, and the reason is in
//! `GetLastError`, which must be read **immediately** — any intervening call,
//! including an allocation, may overwrite it. Every `Handle` returned as
//! `INVALID_HANDLE_VALUE` (which is `-1`, not null) or as null is a failure with
//! the same rule.
//!
//! # Structure layout is not a detail
//!
//! Several of these calls take a structure whose first field is its own size, and
//! reject the call outright when it disagrees — silently, in the case of
//! `SendInput`, where a `cbSize` mismatch makes the whole batch vanish with a
//! success return. The `const _: () = assert!(…)` lines below turn a layout
//! mistake into a compile error on the machine that builds this, rather than a
//! runtime mystery on the machine that runs it. They are guarded on a 64-bit
//! pointer width because that is the only Windows this deployment has.

use std::ffi::c_void;

/// A Win32 `HANDLE`.
pub(crate) type Handle = *mut c_void;

/// A Win32 `BOOL`: zero is failure.
pub(crate) type Bool = i32;

/// `INVALID_HANDLE_VALUE`, which is `-1` rather than null. Several calls return
/// this and others return null for the same condition, so both are checked.
pub(crate) fn invalid_handle() -> Handle {
    -1isize as Handle
}

// ── Access rights and creation flags ──────────────────────────────────────────

/// `TOKEN_ALL_ACCESS`, needed because `CreateProcessAsUserW` uses the token for
/// several things at once and a narrower mask fails in ways that name none of
/// them.
pub(crate) const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
/// `TOKEN_QUERY`, enough to read the user out of an impersonation token.
pub(crate) const TOKEN_QUERY: u32 = 0x0008;
/// `SecurityImpersonation` — the impersonation level a primary token is
/// duplicated at.
pub(crate) const SECURITY_IMPERSONATION: i32 = 2;
/// `TokenPrimary`. `CreateProcessAsUserW` refuses an impersonation token, which
/// is exactly what `WTSQueryUserToken` hands back, so the duplication step is
/// mandatory rather than defensive.
pub(crate) const TOKEN_PRIMARY: i32 = 1;
/// `TokenUser`, the information class that yields the token's own SID.
pub(crate) const TOKEN_USER_CLASS: i32 = 1;
/// `CREATE_UNICODE_ENVIRONMENT`. Mandatory whenever the environment block came
/// from `CreateEnvironmentBlock`, which produces UTF-16; without it Windows reads
/// the block as ANSI and the child gets a garbled environment.
pub(crate) const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
/// `CREATE_NO_WINDOW`, so the agent does not flash a console window on the
/// user's desktop every time it is respawned.
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// `STARTF_USESHOWWINDOW`, paired with `SW_HIDE` below.
pub(crate) const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
/// `SW_HIDE`.
pub(crate) const SW_HIDE: u16 = 0;

// ── Named pipes ───────────────────────────────────────────────────────────────

/// `PIPE_ACCESS_DUPLEX`.
pub(crate) const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`. The whole anti-squatting defence: with it,
/// creating a pipe name somebody else already holds fails instead of quietly
/// adding an instance beside theirs.
pub(crate) const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
/// `FILE_FLAG_OVERLAPPED`, so waiting for the agent to connect can have a
/// deadline. A blocking `ConnectNamedPipe` would park the supervisor thread
/// forever on an agent that never starts.
pub(crate) const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// `PIPE_TYPE_BYTE`: the protocol above this has its own framing and does not
/// want the pipe inventing message boundaries.
pub(crate) const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
/// `PIPE_READMODE_BYTE`.
pub(crate) const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
/// `PIPE_WAIT`.
pub(crate) const PIPE_WAIT: u32 = 0x0000_0000;
/// `PIPE_REJECT_REMOTE_CLIENTS`. Belt and braces beside the `\\.\` name: a pipe
/// that drives a keyboard must not be openable across SMB.
pub(crate) const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;

// ── Wait results and error numbers ────────────────────────────────────────────

/// `WAIT_OBJECT_0`.
pub(crate) const WAIT_OBJECT_0: u32 = 0;
/// `WAIT_TIMEOUT`.
pub(crate) const WAIT_TIMEOUT: u32 = 258;
/// `ERROR_NO_TOKEN` — `WTSQueryUserToken`'s way of saying nobody is signed in.
pub(crate) const ERROR_NO_TOKEN: i32 = 1008;
/// `ERROR_IO_PENDING`, the ordinary answer from an overlapped operation.
pub(crate) const ERROR_IO_PENDING: i32 = 997;
/// `ERROR_PIPE_CONNECTED`: the client got there between creation and the connect
/// call. A success, spelled as a failure.
pub(crate) const ERROR_PIPE_CONNECTED: i32 = 535;
/// `ERROR_ACCESS_DENIED`.
pub(crate) const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_PIPE_BUSY`, which `FILE_FLAG_FIRST_PIPE_INSTANCE` produces when the
/// name is already taken.
pub(crate) const ERROR_PIPE_BUSY: i32 = 231;
/// The session id `WTSGetActiveConsoleSessionId` returns when no session is
/// currently attached to the console. Documented as *retry*, and treating it as
/// an error is the classic way to make a machine appear permanently broken for
/// the few seconds either side of a session switch.
pub(crate) const NO_ACTIVE_SESSION: u32 = 0xFFFF_FFFF;
/// `SDDL_REVISION_1`.
pub(crate) const SDDL_REVISION_1: u32 = 1;
/// `UOI_NAME`, the `GetUserObjectInformationW` class that yields a desktop's
/// name.
pub(crate) const UOI_NAME: i32 = 2;
/// `DESKTOP_READOBJECTS`, the least `OpenInputDesktop` will take.
pub(crate) const DESKTOP_READOBJECTS: u32 = 0x0001;

// ── Structures ────────────────────────────────────────────────────────────────

/// `SECURITY_ATTRIBUTES`.
///
/// `n_length` must equal this structure's size or the call is rejected.
#[repr(C)]
pub(crate) struct SecurityAttributes {
    /// Size of this structure, in bytes.
    pub(crate) n_length: u32,
    /// A self-relative security descriptor, or null for the default.
    pub(crate) security_descriptor: *mut c_void,
    /// Whether a child process inherits the handle. Always zero here: handles
    /// cannot be inherited across sessions at all, which is why the agent is
    /// reached through a named object rather than an inherited pipe.
    pub(crate) inherit_handle: Bool,
}

/// `STARTUPINFOW`.
#[repr(C)]
pub(crate) struct StartupInfoW {
    /// Size of this structure, in bytes.
    pub(crate) cb: u32,
    /// Reserved; must be null.
    pub(crate) reserved: *mut u16,
    /// The window station and desktop, as `"winsta0\\default"`. Leaving this
    /// null starts the process on a desktop nobody can see.
    pub(crate) desktop: *mut u16,
    /// The console title.
    pub(crate) title: *mut u16,
    /// Ignored unless `STARTF_USEPOSITION`.
    pub(crate) x: u32,
    /// Ignored unless `STARTF_USEPOSITION`.
    pub(crate) y: u32,
    /// Ignored unless `STARTF_USESIZE`.
    pub(crate) x_size: u32,
    /// Ignored unless `STARTF_USESIZE`.
    pub(crate) y_size: u32,
    /// Ignored unless `STARTF_USECOUNTCHARS`.
    pub(crate) x_count_chars: u32,
    /// Ignored unless `STARTF_USECOUNTCHARS`.
    pub(crate) y_count_chars: u32,
    /// Ignored unless `STARTF_USEFILLATTRIBUTE`.
    pub(crate) fill_attribute: u32,
    /// Which of the other fields are meaningful.
    pub(crate) flags: u32,
    /// The initial window state, meaningful under `STARTF_USESHOWWINDOW`.
    pub(crate) show_window: u16,
    /// Reserved; must be zero.
    pub(crate) cb_reserved2: u16,
    /// Reserved; must be null.
    pub(crate) reserved2: *mut u8,
    /// Standard input, meaningful under `STARTF_USESTDHANDLES`.
    pub(crate) std_input: Handle,
    /// Standard output.
    pub(crate) std_output: Handle,
    /// Standard error.
    pub(crate) std_error: Handle,
}

/// `PROCESS_INFORMATION`. Both handles are owned by the caller and both must be
/// closed — the thread handle immediately, the process handle when the
/// supervisor is finished watching it.
#[repr(C)]
pub(crate) struct ProcessInformation {
    /// The new process.
    pub(crate) process: Handle,
    /// Its initial thread.
    pub(crate) thread: Handle,
    /// Its process id.
    pub(crate) process_id: u32,
    /// Its thread id.
    pub(crate) thread_id: u32,
}

/// `OVERLAPPED`, used only for the connect wait.
#[repr(C)]
pub(crate) struct Overlapped {
    /// Status, written by the system.
    pub(crate) internal: usize,
    /// Transferred bytes, written by the system.
    pub(crate) internal_high: usize,
    /// File offset, unused for a pipe.
    pub(crate) offset: u32,
    /// High half of the offset, unused for a pipe.
    pub(crate) offset_high: u32,
    /// The event signalled on completion.
    pub(crate) event: Handle,
}

/// `SID_AND_ATTRIBUTES`.
#[repr(C)]
pub(crate) struct SidAndAttributes {
    /// The security identifier, pointing into the same buffer.
    pub(crate) sid: *mut c_void,
    /// Attribute flags, unused for a token user.
    pub(crate) attributes: u32,
}

/// `TOKEN_USER`. The SID it points at lives inside the buffer the whole
/// structure was read into, so the buffer must outlive every use of the pointer.
#[repr(C)]
pub(crate) struct TokenUser {
    /// The token's user.
    pub(crate) user: SidAndAttributes,
}

// A layout mistake here is a call that fails for a reason no error code names.
// Checked at compile time on the only Windows this deployment has.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<SecurityAttributes>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<StartupInfoW>() == 104);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<ProcessInformation>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Overlapped>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<SidAndAttributes>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<TokenUser>() == 16);

// ── kernel32 ──────────────────────────────────────────────────────────────────

#[link(name = "kernel32")]
unsafe extern "system" {
    /// Closes any kernel handle. Never called twice on one handle — the owning
    /// wrappers in the sibling modules exist to make that structural.
    pub(crate) fn CloseHandle(object: Handle) -> Bool;

    /// Waits for an object, in milliseconds. Answers [`WAIT_OBJECT_0`],
    /// [`WAIT_TIMEOUT`], or `WAIT_FAILED` (`0xFFFFFFFF`).
    pub(crate) fn WaitForSingleObject(object: Handle, milliseconds: u32) -> u32;

    /// Reads a process's exit code. Answers `STILL_ACTIVE` (259) while the
    /// process runs — a value that is also a perfectly legal exit code, which is
    /// why every caller waits on the handle first rather than reading meaning
    /// into it.
    pub(crate) fn GetExitCodeProcess(process: Handle, code: *mut u32) -> Bool;

    /// Ends a process with the given exit code.
    pub(crate) fn TerminateProcess(process: Handle, exit_code: u32) -> Bool;

    /// Creates the server end of a named pipe. Answers
    /// [`invalid_handle`] on failure.
    pub(crate) fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *const SecurityAttributes,
    ) -> Handle;

    /// Waits for a client to connect. With an overlapped handle this returns
    /// zero with [`ERROR_IO_PENDING`] as the ordinary case, and zero with
    /// [`ERROR_PIPE_CONNECTED`] when the client beat us to it — which is a
    /// success.
    pub(crate) fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> Bool;

    /// Drops the connected client, leaving the pipe ready for the next one.
    pub(crate) fn DisconnectNamedPipe(pipe: Handle) -> Bool;

    /// Creates an event object for the overlapped connect wait.
    pub(crate) fn CreateEventW(
        security_attributes: *const SecurityAttributes,
        manual_reset: Bool,
        initial_state: Bool,
        name: *const u16,
    ) -> Handle;

    /// Collects the result of an overlapped operation.
    pub(crate) fn GetOverlappedResult(
        file: Handle,
        overlapped: *mut Overlapped,
        transferred: *mut u32,
        wait: Bool,
    ) -> Bool;

    /// Cancels outstanding overlapped operations on a handle, so a timed-out
    /// connect does not leave the system writing into an `OVERLAPPED` that is
    /// about to go out of scope. Skipping this is a use-after-free that only
    /// shows up under load.
    pub(crate) fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> Bool;

    /// Reads from an overlapped handle. Answers zero with [`ERROR_IO_PENDING`]
    /// as the ordinary case; the byte count arrives through
    /// [`GetOverlappedResult`].
    pub(crate) fn ReadFile(
        file: Handle,
        buffer: *mut u8,
        to_read: u32,
        read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> Bool;

    /// Writes to an overlapped handle, under the same convention as
    /// [`ReadFile`].
    pub(crate) fn WriteFile(
        file: Handle,
        buffer: *const u8,
        to_write: u32,
        written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> Bool;

    /// Frees memory allocated by the SDDL and SID conversion helpers.
    pub(crate) fn LocalFree(memory: *mut c_void) -> *mut c_void;

    /// A pseudo-handle for the calling thread. Does not need closing.
    pub(crate) fn GetCurrentThread() -> Handle;
}

// ── advapi32 ──────────────────────────────────────────────────────────────────

#[link(name = "advapi32")]
unsafe extern "system" {
    /// Duplicates a token, which is how an impersonation token becomes the
    /// primary token `CreateProcessAsUserW` requires.
    pub(crate) fn DuplicateTokenEx(
        existing: Handle,
        desired_access: u32,
        attributes: *const SecurityAttributes,
        impersonation_level: i32,
        token_type: i32,
        duplicated: *mut Handle,
    ) -> Bool;

    /// Reads one class of information out of a token. Called twice: once with a
    /// null buffer to learn the length, once to read it.
    pub(crate) fn GetTokenInformation(
        token: Handle,
        class: i32,
        information: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> Bool;

    /// Renders a SID as its `S-1-…` string form, allocated with `LocalAlloc`.
    pub(crate) fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> Bool;

    /// Turns an SDDL string into a security descriptor Windows will accept.
    pub(crate) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> Bool;

    /// Starts a process as another user, in that user's session.
    pub(crate) fn CreateProcessAsUserW(
        token: Handle,
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const SecurityAttributes,
        thread_attributes: *const SecurityAttributes,
        inherit_handles: Bool,
        creation_flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> Bool;

    /// Takes on the identity of the client at the other end of a pipe, for the
    /// duration of the call to [`RevertToSelf`]. Every path that calls this must
    /// revert on every branch, or the thread keeps running as the client.
    pub(crate) fn ImpersonateNamedPipeClient(pipe: Handle) -> Bool;

    /// Drops an impersonation.
    pub(crate) fn RevertToSelf() -> Bool;

    /// Opens the token a thread is currently impersonating with.
    pub(crate) fn OpenThreadToken(
        thread: Handle,
        desired_access: u32,
        open_as_self: Bool,
        token: *mut Handle,
    ) -> Bool;
}

// ── userenv ───────────────────────────────────────────────────────────────────

#[link(name = "userenv")]
unsafe extern "system" {
    /// Builds the environment block for a user's token. Skipping this leaves the
    /// agent with `SYSTEM`'s `APPDATA`, `TEMP` and `USERPROFILE` while appearing
    /// to run as the user — which corrupts the service profile and makes every
    /// path in the agent's own logs a lie.
    pub(crate) fn CreateEnvironmentBlock(
        environment: *mut *mut c_void,
        token: Handle,
        inherit: Bool,
    ) -> Bool;

    /// Frees a block from [`CreateEnvironmentBlock`].
    pub(crate) fn DestroyEnvironmentBlock(environment: *mut c_void) -> Bool;
}

// ── wtsapi32 ──────────────────────────────────────────────────────────────────

#[link(name = "wtsapi32")]
unsafe extern "system" {
    /// The session currently attached to the physical console, or
    /// [`NO_ACTIVE_SESSION`] while none is. Never fails, so there is no error to
    /// read; the sentinel is the whole answer.
    pub(crate) fn WTSGetActiveConsoleSessionId() -> u32;

    /// The primary access token of the user signed into a session. Requires
    /// `LocalSystem` and `SE_TCB_NAME`; answers zero with [`ERROR_NO_TOKEN`] when
    /// nobody is signed in, which is a state rather than a failure.
    pub(crate) fn WTSQueryUserToken(session: u32, token: *mut Handle) -> Bool;
}

// ── user32 ────────────────────────────────────────────────────────────────────

#[link(name = "user32")]
unsafe extern "system" {
    /// Opens the desktop currently receiving input **in the caller's own
    /// session**. That qualifier is the whole reason this call lives in the agent
    /// and not in the daemon: asked from session 0, it answers about session 0.
    pub(crate) fn OpenInputDesktop(flags: u32, inherit: Bool, desired_access: u32) -> Handle;

    /// Closes a desktop handle.
    pub(crate) fn CloseDesktop(desktop: Handle) -> Bool;

    /// Reads information about a window station or desktop — here, its name.
    pub(crate) fn GetUserObjectInformationW(
        object: Handle,
        index: i32,
        information: *mut c_void,
        length: u32,
        length_needed: *mut u32,
    ) -> Bool;
}

// ── Owned resources ───────────────────────────────────────────────────────────

/// A kernel handle that closes itself.
///
/// Every function in this module's siblings has several error branches, and a
/// `CloseHandle` written once per branch is a `CloseHandle` that is eventually
/// missed on one of them. A token or process handle leaked from a daemon that
/// runs for months is not a diagnosable bug; it is a machine that slowly stops
/// being able to open things.
#[derive(Debug)]
pub(crate) struct OwnedHandle(Handle);

impl OwnedHandle {
    /// Takes ownership of a handle a Win32 call produced, refusing the two
    /// values that mean failure.
    ///
    /// Returning `None` rather than a `Fault` keeps this free of any opinion
    /// about which call produced it — the caller knows that and says so.
    pub(crate) fn new(handle: Handle) -> Option<Self> {
        if handle.is_null() || handle == invalid_handle() {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// The raw handle, for passing back into Win32. Borrowed, never consumed, so
    /// the value cannot outlive the close.
    ///
    /// There is deliberately **no `into_raw`**. Every handle in this crate is held
    /// by exactly one owner for its whole life — the process handle a
    /// `SpawnedAgent` keeps, the token a spawn drops the moment the child exists,
    /// the pipe and its event — and none is ever handed to another structure to
    /// close. An escape hatch that gives up ownership without closing would be a
    /// leak waiting for its first caller, in a daemon that runs for months.
    pub(crate) fn raw(&self) -> Handle {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // A failing close means the handle was already invalid, which is a bug
        // we cannot do anything about here and must not abort the process for.
        unsafe { CloseHandle(self.0) };
    }
}

/// A `LocalAlloc`-owned buffer, freed on drop.
///
/// The SDDL and SID conversion helpers allocate with `LocalAlloc` and hand the
/// pointer over; forgetting `LocalFree` on an error branch is the same slow leak
/// as a missed `CloseHandle`, in a daemon that never restarts.
#[derive(Debug)]
pub(crate) struct LocalBuffer(*mut c_void);

impl LocalBuffer {
    /// Takes ownership of a `LocalAlloc` pointer, refusing null.
    pub(crate) fn new(pointer: *mut c_void) -> Option<Self> {
        if pointer.is_null() { None } else { Some(Self(pointer)) }
    }

    /// The raw pointer.
    pub(crate) fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

/// A path or string as a NUL-terminated UTF-16 sequence.
///
/// An interior NUL is refused rather than silently truncated: a truncated path is
/// a different file and a truncated pipe name is a different object, and this
/// module's whole job is making sure the agent reaches exactly the one intended.
pub(crate) fn wide(text: &std::ffi::OsStr) -> Result<Vec<u16>, crate::Fault> {
    use std::os::windows::ffi::OsStrExt;
    let mut units: Vec<u16> = text.encode_wide().collect();
    if units.contains(&0) {
        return Err(crate::Fault::refused("a Win32 wide string", "contains an interior NUL"));
    }
    units.push(0);
    Ok(units)
}

/// The same, for a string this code produced itself.
pub(crate) fn wide_str(text: &str) -> Result<Vec<u16>, crate::Fault> {
    if text.contains('\0') {
        return Err(crate::Fault::refused("a Win32 wide string", "contains an interior NUL"));
    }
    Ok(text.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Reads a NUL-terminated wide string the platform allocated.
///
/// Bounded by `limit` so a buffer that is somehow not terminated cannot walk off
/// the end of the allocation — under `panic = "abort"` that read is the whole
/// daemon rather than a segmentation fault somebody can debug.
///
/// # Safety
///
/// `text` must point to at least `limit` readable `u16`s, or to a NUL-terminated
/// sequence shorter than that.
pub(crate) unsafe fn from_wide(text: *const u16, limit: usize) -> String {
    let mut units = Vec::new();
    for index in 0..limit {
        let unit = unsafe { *text.add(index) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

// ══ Capture ═══════════════════════════════════════════════════════════════════
//
// Everything below serves the screen rather than the spawn: the device contexts
// and DIB section GDI capture blits into, the display enumeration that says what
// there is to capture, the cursor and icon calls, and the two process-wide facts
// (DPI awareness, integrity level) the agent states about itself on the way past.
//
// The same rules apply as above — no logic, `Bool` is zero for failure, and
// `GetLastError` is read immediately. Two rules are specific to this half and are
// worth stating where the declarations are, because both are silent when broken:
//
// 1. **Every GDI object the caller is handed, the caller destroys.** `GetIconInfo`
//    returns two bitmaps that belong to the caller; the per-process GDI handle
//    quota is 10,000 and a cursor poll at 20 Hz exhausts it in about a minute.
//    The owning types at the bottom of this file exist so that the release cannot
//    be attached to one branch of a function that has five.
// 2. **A DIB section is selected into a device context.** Deleting a bitmap that
//    is still selected fails silently and leaks it, so the ordering
//    (deselect → delete the bitmap → delete the context) lives in exactly one
//    destructor rather than being reconstructed at each call site.

// ── Blit, bitmap and device-context constants ─────────────────────────────────

/// `SRCCOPY`: copy the source rectangle as-is.
pub(crate) const SRCCOPY: u32 = 0x00CC_0020;
/// `CAPTUREBLT`: include layered (transparent, per-pixel-alpha) windows in the
/// copy. Without it a desktop with any modern translucent window on it captures
/// holes where those windows are, which reads as a corrupt frame rather than as a
/// missing flag.
pub(crate) const CAPTUREBLT: u32 = 0x4000_0000;
/// `BI_RGB`: uncompressed. The only compression this code will accept, because
/// every other value means the bits are not the pixels.
pub(crate) const BI_RGB: u32 = 0;
/// `DIB_RGB_COLORS`: the (absent) colour table holds literal RGB values. At 32
/// bits per pixel there is no palette, so this is a formality the call still
/// requires.
pub(crate) const DIB_RGB_COLORS: u32 = 0;

// ── System metrics ────────────────────────────────────────────────────────────

/// `SM_XVIRTUALSCREEN`: the left edge of the virtual desktop, which is negative
/// when a display sits left of the primary.
pub(crate) const SM_XVIRTUALSCREEN: i32 = 76;
/// `SM_YVIRTUALSCREEN`.
pub(crate) const SM_YVIRTUALSCREEN: i32 = 77;
/// `SM_CXVIRTUALSCREEN`.
pub(crate) const SM_CXVIRTUALSCREEN: i32 = 78;
/// `SM_CYVIRTUALSCREEN`.
pub(crate) const SM_CYVIRTUALSCREEN: i32 = 79;
/// `SM_CMONITORS`: how many displays make up the virtual desktop.
pub(crate) const SM_CMONITORS: i32 = 80;
/// `MONITORINFOF_PRIMARY`.
pub(crate) const MONITORINFOF_PRIMARY: u32 = 1;

// ── Cursor ────────────────────────────────────────────────────────────────────

/// `CURSOR_SHOWING`: the pointer is being drawn.
pub(crate) const CURSOR_SHOWING: u32 = 0x0000_0001;
/// `CURSOR_SUPPRESSED`: the pointer exists but is hidden because the user is
/// working by touch. Reported as *not visible* rather than as an error — a client
/// that draws a pointer here shows one the person at the machine cannot see.
pub(crate) const CURSOR_SUPPRESSED: u32 = 0x0000_0002;

// ── DPI ───────────────────────────────────────────────────────────────────────

/// `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2`, which is the *value* `-4` rather
/// than a pointer to anything. Passed as an `isize` because that is what the
/// opaque handle type is on a 64-bit build.
pub(crate) const DPI_PER_MONITOR_AWARE_V2: isize = -4;
/// `MDT_EFFECTIVE_DPI`, the only monitor DPI type this code asks for: it is the
/// one that includes the user's scaling choice, which is what a console needs to
/// label a display.
pub(crate) const MDT_EFFECTIVE_DPI: i32 = 0;
/// The DPI Windows calls 100%. Every scale factor here is a ratio to this.
pub(crate) const USER_DEFAULT_SCREEN_DPI: u32 = 96;

// ── Integrity ─────────────────────────────────────────────────────────────────

/// `TokenIntegrityLevel`, the information class holding the mandatory label.
///
/// The level itself is the last sub-authority of the label's SID, and the names
/// for its values (`SECURITY_MANDATORY_MEDIUM_RID` and the rest) live in
/// [`crate::agent::Integrity`] rather than here: they are the vocabulary the
/// report line speaks, they are needed on platforms this file does not compile
/// on, and one spelling of a constant is better than two.
pub(crate) const TOKEN_INTEGRITY_LEVEL_CLASS: i32 = 25;

// ── Opening the pipe from the agent's side ────────────────────────────────────

/// `GENERIC_READ`.
pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE`.
pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
/// `OPEN_EXISTING`: the agent opens a pipe the daemon has already created, and
/// must never create one itself — an agent that could create the name could be
/// beaten to it, which is the squatting case the daemon's
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` exists to make loud.
pub(crate) const OPEN_EXISTING: u32 = 3;
/// `ERROR_FILE_NOT_FOUND`: the daemon has not created the pipe yet. A state
/// while the agent is racing its own supervisor, not a failure.
pub(crate) const ERROR_FILE_NOT_FOUND: i32 = 2;
/// `ERROR_BROKEN_PIPE`: the daemon closed its end. The agent's cue to exit
/// quietly rather than to report a fault nobody will read.
pub(crate) const ERROR_BROKEN_PIPE: i32 = 109;

// ── Structures ────────────────────────────────────────────────────────────────

/// `RECT`. Right and bottom are exclusive.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Rect {
    /// Left edge, negative on a display left of the primary.
    pub(crate) left: i32,
    /// Top edge, negative on a display above the primary.
    pub(crate) top: i32,
    /// Right edge, exclusive.
    pub(crate) right: i32,
    /// Bottom edge, exclusive.
    pub(crate) bottom: i32,
}

/// `POINT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Point {
    /// Horizontal position.
    pub(crate) x: i32,
    /// Vertical position.
    pub(crate) y: i32,
}

/// `MONITORINFOEXW`. `cb_size` must equal this structure's size, and the device
/// name array is what distinguishes it from a plain `MONITORINFO`.
#[repr(C)]
pub(crate) struct MonitorInfoExW {
    /// Size of this structure, in bytes.
    pub(crate) cb_size: u32,
    /// The display's rectangle in virtual-desktop coordinates.
    pub(crate) monitor: Rect,
    /// The part of it not covered by the taskbar. Unused here, but part of the
    /// layout and therefore declared.
    pub(crate) work: Rect,
    /// [`MONITORINFOF_PRIMARY`], or zero.
    pub(crate) flags: u32,
    /// `\\.\DISPLAY1` and friends, NUL-terminated.
    pub(crate) device: [u16; 32],
}

/// `BITMAPINFOHEADER`.
///
/// A **negative** `height` is the whole reason this structure is spelled out
/// rather than defaulted: it asks for a top-down DIB, which is the row order
/// every other layer in this project uses. A bottom-up DIB is not an error and
/// not visibly broken at a glance — it is the picture upside down, discovered by
/// a person looking at their own desktop.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BitmapInfoHeader {
    /// Size of this structure, in bytes.
    pub(crate) size: u32,
    /// Width in pixels.
    pub(crate) width: i32,
    /// Height in pixels; negative for top-down.
    pub(crate) height: i32,
    /// Colour planes; must be 1.
    pub(crate) planes: u16,
    /// Bits per pixel; 32 here, which makes the rows implicitly DWORD-aligned
    /// and the stride exactly `width * 4`.
    pub(crate) bit_count: u16,
    /// [`BI_RGB`].
    pub(crate) compression: u32,
    /// Image size in bytes; may be zero for `BI_RGB`.
    pub(crate) size_image: u32,
    /// Horizontal resolution, unused.
    pub(crate) x_pels_per_meter: i32,
    /// Vertical resolution, unused.
    pub(crate) y_pels_per_meter: i32,
    /// Palette entries used; zero at 32 bits per pixel.
    pub(crate) clr_used: u32,
    /// Palette entries required; zero at 32 bits per pixel.
    pub(crate) clr_important: u32,
}

/// `BITMAPINFO` as the 32-bit `BI_RGB` case needs it.
///
/// The trailing colour array is never read at this bit depth, but the structure
/// the call is documented to take has it, and handing a call a buffer shorter
/// than the structure it will read is the kind of mistake that works until a
/// driver reads one field further.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BitmapInfo {
    /// The header.
    pub(crate) header: BitmapInfoHeader,
    /// The colour table, unused at 32 bits per pixel.
    pub(crate) colours: [u32; 3],
}

/// `CURSORINFO`. `cb_size` must be 24 or the call fails.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CursorInfo {
    /// Size of this structure, in bytes.
    pub(crate) cb_size: u32,
    /// [`CURSOR_SHOWING`] and/or [`CURSOR_SUPPRESSED`], or zero.
    pub(crate) flags: u32,
    /// The current shape, or null when the pointer is hidden.
    pub(crate) cursor: Handle,
    /// The hotspot's position in virtual-desktop pixels.
    pub(crate) screen_pos: Point,
}

/// `ICONINFO`.
///
/// **Both bitmaps belong to the caller.** `GetIconInfo` creates them per call —
/// including for a cursor whose shape has not changed — and a caller that does
/// not destroy them exhausts the 10,000-handle GDI quota in minutes at 20 polls a
/// second. That is what `cursor::IconBitmaps` exists for.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct IconInfo {
    /// Non-zero for an icon, zero for a cursor.
    pub(crate) is_icon: Bool,
    /// The hotspot's x offset within the bitmap.
    pub(crate) hotspot_x: u32,
    /// The hotspot's y offset within the bitmap.
    pub(crate) hotspot_y: u32,
    /// The AND mask. Always present; twice the height of the cursor when there
    /// is no colour bitmap, because it then holds the AND and XOR masks stacked.
    pub(crate) mask: Handle,
    /// The colour bitmap, or null for a monochrome cursor.
    pub(crate) colour: Handle,
}

/// `BITMAP`, as `GetObjectW` fills it in for an `HBITMAP`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Bitmap {
    /// Always zero.
    pub(crate) bm_type: i32,
    /// Width in pixels.
    pub(crate) width: i32,
    /// Height in pixels.
    pub(crate) height: i32,
    /// Bytes per row, as the bitmap itself is stored.
    pub(crate) width_bytes: i32,
    /// Colour planes.
    pub(crate) planes: u16,
    /// Bits per pixel.
    pub(crate) bits_pixel: u16,
    /// The bits, for a DIB section; null otherwise.
    pub(crate) bits: *mut c_void,
}

/// `TOKEN_MANDATORY_LABEL`: the integrity level, as a SID whose last
/// sub-authority is the level.
#[repr(C)]
pub(crate) struct TokenMandatoryLabel {
    /// The label SID, pointing into the same buffer the structure was read into.
    pub(crate) label: SidAndAttributes,
}

// The same argument as the block above: a layout mistake is a call that fails
// for a reason no error code names, and `CURSORINFO` in particular is rejected
// outright on a `cbSize` mismatch.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Rect>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Point>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<MonitorInfoExW>() == 104);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<BitmapInfoHeader>() == 40);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<BitmapInfo>() == 52);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<CursorInfo>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<IconInfo>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Bitmap>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<TokenMandatoryLabel>() == 16);

/// The callback `EnumDisplayMonitors` invokes once per display.
///
/// It runs on our own thread, inside the call, so it may touch caller state
/// through the `lparam` — but it must not unwind, which under `panic = "abort"`
/// is guaranteed by the build rather than by care.
pub(crate) type MonitorEnumProc =
    unsafe extern "system" fn(monitor: Handle, dc: Handle, rect: *mut Rect, data: isize) -> Bool;

/// `SetProcessDpiAwarenessContext`, resolved at run time.
///
/// Not imported statically: it arrived in Windows 10 1703, and a statically
/// imported symbol that is missing stops the process from *starting* — the agent
/// would fail with a loader error naming a DPI function, on a machine where the
/// operator is trying to find out why their screen is blank.
pub(crate) type SetProcessDpiAwarenessContextFn =
    unsafe extern "system" fn(context: isize) -> Bool;

/// `GetDpiForMonitor` from `shcore.dll`, resolved at run time for the same
/// reason and because linking `shcore` would need an import library this
/// workspace does not carry.
pub(crate) type GetDpiForMonitorFn = unsafe extern "system" fn(
    monitor: Handle,
    dpi_type: i32,
    dpi_x: *mut u32,
    dpi_y: *mut u32,
) -> i32;

// ── gdi32 ─────────────────────────────────────────────────────────────────────

#[link(name = "gdi32")]
unsafe extern "system" {
    /// Creates a memory device context compatible with `dc`, or with the screen
    /// when `dc` is null.
    pub(crate) fn CreateCompatibleDC(dc: Handle) -> Handle;

    /// Destroys a memory device context. Never called on a screen DC, which is
    /// released rather than deleted — the two are different calls on the same
    /// C type, which is exactly why they get different owning types here.
    pub(crate) fn DeleteDC(dc: Handle) -> Bool;

    /// Creates a DIB section: a bitmap whose bits the caller can read directly.
    ///
    /// The pointer written to `bits` stays valid until the bitmap is deleted,
    /// which is what makes frame-to-frame reuse possible — the capture loop
    /// blits into the same memory rather than allocating a megabyte per frame.
    pub(crate) fn CreateDIBSection(
        dc: Handle,
        info: *const BitmapInfo,
        usage: u32,
        bits: *mut *mut c_void,
        section: Handle,
        offset: u32,
    ) -> Handle;

    /// Selects an object into a device context, answering the one it replaced.
    /// The replaced object must be selected back before the new one is deleted.
    pub(crate) fn SelectObject(dc: Handle, object: Handle) -> Handle;

    /// Destroys a GDI object. **The** call this whole subsystem's handle
    /// discipline is about.
    pub(crate) fn DeleteObject(object: Handle) -> Bool;

    /// Copies pixels between device contexts.
    pub(crate) fn BitBlt(
        destination: Handle,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        source: Handle,
        source_x: i32,
        source_y: i32,
        rop: u32,
    ) -> Bool;

    /// Reads a bitmap's bits into a caller-supplied buffer, converting to the
    /// format the header describes. Answers the number of scan lines copied, so
    /// zero is the failure.
    pub(crate) fn GetDIBits(
        dc: Handle,
        bitmap: Handle,
        start: u32,
        lines: u32,
        bits: *mut c_void,
        info: *mut BitmapInfo,
        usage: u32,
    ) -> i32;

    /// Reads a GDI object's descriptor — here, a `BITMAP` for an `HBITMAP`.
    /// Answers the bytes written, so zero is the failure.
    pub(crate) fn GetObjectW(object: Handle, size: i32, buffer: *mut c_void) -> i32;
}

// ── user32, capture half ──────────────────────────────────────────────────────

#[link(name = "user32")]
unsafe extern "system" {
    /// A device context for a window, or **for the whole virtual desktop** when
    /// the window is null. Released with [`ReleaseDC`], never `DeleteDC`.
    pub(crate) fn GetDC(window: Handle) -> Handle;

    /// Releases a device context obtained from [`GetDC`].
    pub(crate) fn ReleaseDC(window: Handle, dc: Handle) -> i32;

    /// Enumerates the displays intersecting a rectangle, or all of them when
    /// both the device context and the rectangle are null.
    pub(crate) fn EnumDisplayMonitors(
        dc: Handle,
        clip: *const Rect,
        callback: MonitorEnumProc,
        data: isize,
    ) -> Bool;

    /// Reads a display's rectangle, work area, flags and device name.
    pub(crate) fn GetMonitorInfoW(monitor: Handle, info: *mut MonitorInfoExW) -> Bool;

    /// One system metric. Never fails in a way this code can distinguish from a
    /// legitimate zero, so every caller treats an implausible answer as a state
    /// rather than reading an error.
    pub(crate) fn GetSystemMetrics(index: i32) -> i32;

    /// The pointer's position and current shape. Fails with
    /// `ERROR_ACCESS_DENIED` while the secure desktop is in front, which is the
    /// signal rather than a failure.
    pub(crate) fn GetCursorInfo(info: *mut CursorInfo) -> Bool;

    /// The hotspot and bitmaps of a cursor. **Both bitmaps become the caller's
    /// to destroy, on every call, including for a shape seen a thousand times.**
    pub(crate) fn GetIconInfo(cursor: Handle, info: *mut IconInfo) -> Bool;

    /// The pre-Windows-8.1 DPI declaration: system-wide awareness only, and
    /// irreversible for the life of the process. The fallback when the
    /// per-monitor context call is not present.
    pub(crate) fn SetProcessDPIAware() -> Bool;

    /// The window station this process is attached to. Not closed: it is a
    /// borrowed handle to an object the process already belongs to.
    pub(crate) fn GetProcessWindowStation() -> Handle;
}

// ── kernel32, capture half ────────────────────────────────────────────────────

#[link(name = "kernel32")]
unsafe extern "system" {
    /// A pseudo-handle for the calling process. Does not need closing.
    pub(crate) fn GetCurrentProcess() -> Handle;

    /// This process's id, for the session lookup below.
    pub(crate) fn GetCurrentProcessId() -> u32;

    /// Which session a process belongs to. The agent's own answer is what it
    /// compares against the console session, so that a fast user switch is
    /// recognised from inside the agent rather than only from the daemon.
    pub(crate) fn ProcessIdToSessionId(process_id: u32, session: *mut u32) -> Bool;

    /// A handle to an already-loaded module, without taking a reference.
    pub(crate) fn GetModuleHandleW(name: *const u16) -> Handle;

    /// Loads a module, taking a reference that is deliberately never released:
    /// the two libraries resolved this way live for the life of the process and
    /// freeing one while a resolved pointer is still held is a call into
    /// unmapped memory.
    pub(crate) fn LoadLibraryW(name: *const u16) -> Handle;

    /// Resolves an exported symbol. The name is ANSI even in the wide API.
    pub(crate) fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;

    /// Opens a file or named pipe. The agent's side of the pipe.
    pub(crate) fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SecurityAttributes,
        creation_disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;

    /// Waits for an instance of a named pipe to become available.
    pub(crate) fn WaitNamedPipeW(name: *const u16, timeout: u32) -> Bool;

    /// Suspends the calling thread. Used only by the agent's own pacing, which
    /// is a dedicated thread with nothing else to do.
    pub(crate) fn Sleep(milliseconds: u32);
}

// ── advapi32, integrity half ──────────────────────────────────────────────────

#[link(name = "advapi32")]
unsafe extern "system" {
    /// Opens a process's access token.
    pub(crate) fn OpenProcessToken(
        process: Handle,
        desired_access: u32,
        token: *mut Handle,
    ) -> Bool;

    /// A pointer to a SID's sub-authority count. Never null for a valid SID.
    pub(crate) fn GetSidSubAuthorityCount(sid: *mut c_void) -> *mut u8;

    /// A pointer to one sub-authority. The **last** one of an integrity label is
    /// the level, and reading past the count is a read of whatever follows the
    /// SID, so every caller reads the count first.
    pub(crate) fn GetSidSubAuthority(sid: *mut c_void, index: u32) -> *mut u32;
}

/// A screen device context, released on drop.
///
/// Deliberately a different type from [`MemoryDc`]: both are `HDC`, and the two
/// are released by two different calls. Releasing a memory DC with `ReleaseDC`
/// leaks it silently; deleting a screen DC with `DeleteDC` is worse. One type
/// each makes the wrong call unspellable.
#[derive(Debug)]
pub(crate) struct ScreenDc(Handle);

impl ScreenDc {
    /// The device context for the whole virtual desktop.
    ///
    /// Acquired per frame rather than held for the session: a display topology
    /// change invalidates what a held one describes, and `GetDC` is cheap next to
    /// the blit it precedes.
    pub(crate) fn desktop() -> Option<Self> {
        let dc = unsafe { GetDC(std::ptr::null_mut()) };
        if dc.is_null() { None } else { Some(Self(dc)) }
    }

    /// The raw handle.
    pub(crate) fn raw(&self) -> Handle {
        self.0
    }
}

impl Drop for ScreenDc {
    fn drop(&mut self) {
        unsafe { ReleaseDC(std::ptr::null_mut(), self.0) };
    }
}

/// A memory device context, deleted on drop.
#[derive(Debug)]
pub(crate) struct MemoryDc(Handle);

impl MemoryDc {
    /// A memory device context compatible with the screen.
    pub(crate) fn compatible_with(dc: &ScreenDc) -> Option<Self> {
        let memory = unsafe { CreateCompatibleDC(dc.raw()) };
        if memory.is_null() { None } else { Some(Self(memory)) }
    }

    /// The raw handle.
    pub(crate) fn raw(&self) -> Handle {
        self.0
    }
}

impl Drop for MemoryDc {
    fn drop(&mut self) {
        unsafe { DeleteDC(self.0) };
    }
}

/// A GDI object — a bitmap, a brush, a pen — destroyed on drop.
///
/// This is the type the ten-minute flat-handle-count acceptance test rests on.
/// The two bitmaps `GetIconInfo` hands back are wrapped in one of these each, at
/// the moment they arrive, so that every `?` and every early return between there
/// and the end of the function still destroys them.
#[derive(Debug)]
pub(crate) struct GdiObject(Handle);

impl GdiObject {
    /// Takes ownership of a GDI handle, refusing null.
    ///
    /// Null is the ordinary answer for a monochrome cursor's absent colour
    /// bitmap, so `None` here is frequently not an error at all — which is why
    /// this returns an `Option` rather than a `Result` with an opinion in it.
    pub(crate) fn new(handle: Handle) -> Option<Self> {
        if handle.is_null() { None } else { Some(Self(handle)) }
    }

    /// The raw handle.
    pub(crate) fn raw(&self) -> Handle {
        self.0
    }
}

impl Drop for GdiObject {
    fn drop(&mut self) {
        unsafe { DeleteObject(self.0) };
    }
}

// ══ Input injection ═══════════════════════════════════════════════════════════
//
// One rule dominates this half and it is the reason the layout assertions below
// exist at all: **`SendInput` validates `cbSize` and fails the whole batch when it
// disagrees** — returning zero, with `ERROR_INVALID_PARAMETER`, having injected
// nothing. A structure that is one field or one padding byte wrong therefore
// produces a keyboard that does nothing, on a remote machine, with a plausible
// error number that names no field. The `const _: () = assert!(…)` lines turn that
// into a compile error here.
//
// The second rule is that a full return count is **not** success. See
// `windows/inject.rs`: User Interface Privilege Isolation discards injection into
// any window above the caller's integrity level and reports nothing at all.

/// `INPUT_MOUSE`.
pub(crate) const INPUT_MOUSE: u32 = 0;
/// `INPUT_KEYBOARD`.
pub(crate) const INPUT_KEYBOARD: u32 = 1;

/// `PROCESS_QUERY_LIMITED_INFORMATION`.
///
/// The right chosen deliberately over `PROCESS_QUERY_INFORMATION`: it is the one
/// Windows grants a medium-integrity process against a *higher*-integrity process
/// of the same user, which is precisely the case this code needs to be able to
/// examine. Asking for more would be denied on exactly the windows worth asking
/// about.
pub(crate) const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;

/// `MOUSEINPUT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MouseInput {
    /// Absolute x as a 16-bit fraction of the virtual desktop, under
    /// `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
    pub(crate) dx: i32,
    /// Absolute y, under the same flags.
    pub(crate) dy: i32,
    /// The wheel delta, or the thumb-button selector.
    pub(crate) mouse_data: i32,
    /// Which of the above are meaningful, and what the event is.
    pub(crate) flags: u32,
    /// Zero for "now". A timestamp here that is not from the same clock the
    /// system is using makes events arrive out of order.
    pub(crate) time: u32,
    /// An application-defined value, retrievable with `GetMessageExtraInfo`. Zero:
    /// marking our events would let any application single them out, and the
    /// events are not a secret but the marking would be a fingerprint.
    pub(crate) extra_info: usize,
}

/// `KEYBDINPUT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KeyboardInput {
    /// The virtual-key code, or **zero** on the unicode path — a non-zero value
    /// there is taken as a key and the code unit is ignored.
    pub(crate) virtual_key: u16,
    /// The set-1 scancode, or the UTF-16 code unit under `KEYEVENTF_UNICODE`.
    pub(crate) scancode: u16,
    /// `KEYEVENTF_*`.
    pub(crate) flags: u32,
    /// Zero for "now".
    pub(crate) time: u32,
    /// As [`MouseInput::extra_info`].
    pub(crate) extra_info: usize,
}

/// The union inside `INPUT`.
///
/// `HARDWAREINPUT` is declared as well even though nothing here sends one: it is
/// part of the union's size on paper, and a union that is missing its largest
/// member is a union of the wrong size — which is the `cbSize` failure above.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union InputUnion {
    /// A mouse event.
    pub(crate) mouse: MouseInput,
    /// A keyboard event.
    pub(crate) keyboard: KeyboardInput,
    /// `HARDWAREINPUT`: a message and its two halves of `wParam`.
    pub(crate) hardware: [u32; 2],
}

/// `INPUT`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Input {
    /// [`INPUT_MOUSE`] or [`INPUT_KEYBOARD`].
    pub(crate) kind: u32,
    /// The event itself.
    pub(crate) event: InputUnion,
}

// The assertion the whole injection path depends on: `SendInput` compares the size
// it is given against this and silently injects nothing on a mismatch.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Input>() == 40);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<MouseInput>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<KeyboardInput>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<InputUnion>() == 32);

// ── user32, injection half ────────────────────────────────────────────────────

#[link(name = "user32")]
unsafe extern "system" {
    /// Synthesises input. Answers the number of events **inserted into the input
    /// stream**, which is not the number delivered: UIPI discards injection into a
    /// higher-integrity window afterwards and says nothing.
    ///
    /// `size` must be `size_of::<Input>()` exactly.
    pub(crate) fn SendInput(count: u32, inputs: *const Input, size: i32) -> u32;

    /// The window with the keyboard focus, or null when no window in this session
    /// has it — which happens during a desktop switch and is a state rather than a
    /// failure.
    pub(crate) fn GetForegroundWindow() -> Handle;

    /// The thread and, through the out-parameter, the process that owns a window.
    /// Answers zero for an invalid window.
    pub(crate) fn GetWindowThreadProcessId(window: Handle, process_id: *mut u32) -> u32;
}

// ── kernel32, injection half ──────────────────────────────────────────────────

#[link(name = "kernel32")]
unsafe extern "system" {
    /// Opens a process for querying. Answers null on failure, and
    /// [`ERROR_ACCESS_DENIED`] is itself informative here — see
    /// `windows::inject`.
    pub(crate) fn OpenProcess(
        desired_access: u32,
        inherit_handle: Bool,
        process_id: u32,
    ) -> Handle;
}

// ── DXGI Desktop Duplication, and the Direct3D 11 device it needs ─────────────
//
// The only COM in this workspace. Everything above is a flat C export whose
// signature a wrong guess merely fails to link; a COM interface is a pointer to a
// pointer to an array of function pointers, and a method named at the wrong index
// is a call to a *different function* with the wrong argument list — undefined
// behaviour that usually survives long enough to be diagnosed somewhere else
// entirely. `gdi.rs` names that risk as the reason Desktop Duplication was left
// unwritten for so long.
//
// So the slot order below is not remembered, guessed, or copied from an example.
// It was extracted from this deployment's own SDK headers — `dxgi.h`, `dxgi1_2.h`
// and `d3d11.h` under `Windows Kits\10\Include\10.0.19041.0`, the same headers the
// operating system on ALEX-DESKTOP was built against — by walking each
// `typedef struct I…Vtbl` and listing its members in declaration order. Every slot
// is written out, including the ones this crate never calls, because a vtable with
// a *hole* in it silently renumbers everything below the hole. The unused ones are
// [`Slot`], and they carry the method's real name so the next reader can check the
// table against the header without running anything.
//
// The inheritance is flattened deliberately. `IDXGIOutput1` is written as its
// twenty-three slots rather than as `IDXGIOutput` plus three, because COM
// inheritance *is* prefix layout and spelling it out is what makes the file
// checkable line-by-line against the header.

/// A COM `HRESULT`. Negative is failure; [`S_OK`] is the only success this crate
/// accepts, because every call here either produced its out-parameter or did not.
pub(crate) type Hresult = i32;

/// The one success code.
pub(crate) const S_OK: Hresult = 0;

/// `E_ACCESSDENIED`. From `DuplicateOutput` this is the secure desktop — a UAC
/// prompt or the lock screen — and not a permission the operator can grant.
pub(crate) const E_ACCESSDENIED: Hresult = 0x8007_0005u32 as Hresult;

/// `DXGI_ERROR_INVALID_CALL`: a frame acquired twice without a release. A defect
/// in this file rather than a condition of the machine.
pub(crate) const DXGI_ERROR_INVALID_CALL: Hresult = 0x887A_0001u32 as Hresult;

/// `DXGI_ERROR_NOT_FOUND`: the end of an enumeration.
pub(crate) const DXGI_ERROR_NOT_FOUND: Hresult = 0x887A_0002u32 as Hresult;

/// `DXGI_ERROR_UNSUPPORTED`: this adapter cannot duplicate an output at all.
pub(crate) const DXGI_ERROR_UNSUPPORTED: Hresult = 0x887A_0004u32 as Hresult;

/// `DXGI_ERROR_DEVICE_REMOVED`: the graphics driver restarted or the GPU was
/// reset. Everything built on the device is gone and must be built again.
pub(crate) const DXGI_ERROR_DEVICE_REMOVED: Hresult = 0x887A_0005u32 as Hresult;

/// `DXGI_ERROR_DEVICE_RESET`, the other half of a driver restart.
pub(crate) const DXGI_ERROR_DEVICE_RESET: Hresult = 0x887A_0007u32 as Hresult;

/// `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`: every duplication slot this output has
/// is held by somebody else. Recoverable the moment they let go.
pub(crate) const DXGI_ERROR_NOT_CURRENTLY_AVAILABLE: Hresult = 0x887A_0022u32 as Hresult;

/// `DXGI_ERROR_ACCESS_LOST`: the duplication is void — a mode change, a desktop
/// switch, or a game taking the output exclusively. Rebuild, do not fail.
pub(crate) const DXGI_ERROR_ACCESS_LOST: Hresult = 0x887A_0026u32 as Hresult;

/// `DXGI_ERROR_WAIT_TIMEOUT`: nothing changed within the timeout. The single most
/// common answer on a still desktop, and never a failure.
pub(crate) const DXGI_ERROR_WAIT_TIMEOUT: Hresult = 0x887A_0027u32 as Hresult;

/// `DXGI_ERROR_SESSION_DISCONNECTED`: the session this duplication belongs to is
/// no longer on the console.
pub(crate) const DXGI_ERROR_SESSION_DISCONNECTED: Hresult = 0x887A_0028u32 as Hresult;

/// `D3D_DRIVER_TYPE_HARDWARE`.
pub(crate) const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;

/// `D3D11_SDK_VERSION`. A different value is refused outright by the runtime.
pub(crate) const D3D11_SDK_VERSION: u32 = 7;

/// `D3D11_USAGE_STAGING`: GPU-to-CPU transfer, the only usage that can be mapped
/// for reading.
pub(crate) const D3D11_USAGE_STAGING: u32 = 3;

/// `D3D11_CPU_ACCESS_READ`.
pub(crate) const D3D11_CPU_ACCESS_READ: u32 = 0x0002_0000;

/// `D3D11_MAP_READ`.
pub(crate) const D3D11_MAP_READ: u32 = 1;

/// `DXGI_FORMAT_B8G8R8A8_UNORM` — the desktop's own format, and the byte order
/// this project's wire already speaks, so the staging copy needs no conversion.
pub(crate) const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;

/// A `GUID`, as an interface id.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Guid {
    /// First four bytes.
    pub(crate) data1: u32,
    /// Next two.
    pub(crate) data2: u16,
    /// Next two.
    pub(crate) data3: u16,
    /// The remaining eight, already in wire order.
    pub(crate) data4: [u8; 8],
}

/// `IID_IDXGIDevice`.
pub(crate) const IID_IDXGI_DEVICE: Guid = Guid {
    data1: 0x54ec_77fa,
    data2: 0x1377,
    data3: 0x44e6,
    data4: [0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c],
};

/// `IID_IDXGIOutput1`, the interface that carries `DuplicateOutput`.
pub(crate) const IID_IDXGI_OUTPUT1: Guid = Guid {
    data1: 0x00cd_dea8,
    data2: 0x939b,
    data3: 0x4b83,
    data4: [0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc],
};

/// `IID_ID3D11Texture2D`.
pub(crate) const IID_ID3D11_TEXTURE2D: Guid = Guid {
    data1: 0x6f15_aaf2,
    data2: 0xd208,
    data3: 0x4e89,
    data4: [0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c],
};

/// A vtable entry this crate never calls.
///
/// Present so the slots below it keep their indices. Never transmuted and never
/// called; the name in the field is the header's name for the method.
pub(crate) type Slot = *const c_void;

/// Any COM interface pointer: a pointer to a pointer to a vtable.
///
/// Written as one type because [`Unknown::release`] and `QueryInterface` are the
/// same three slots on every interface in this file, so the reference counting is
/// written once rather than per interface.
#[repr(C)]
pub(crate) struct Unknown {
    /// The vtable, whose first three entries are `IUnknown`'s.
    pub(crate) vtable: *const UnknownVtbl,
}

/// `IUnknownVtbl` — the three slots every interface below begins with.
#[repr(C)]
pub(crate) struct UnknownVtbl {
    /// `QueryInterface`.
    pub(crate) query_interface:
        unsafe extern "system" fn(this: *mut Unknown, iid: *const Guid, out: *mut *mut c_void) -> Hresult,
    /// `AddRef`.
    pub(crate) add_ref: unsafe extern "system" fn(this: *mut Unknown) -> u32,
    /// `Release`.
    pub(crate) release: unsafe extern "system" fn(this: *mut Unknown) -> u32,
}

/// `IDXGIDeviceVtbl`, slots 0–11.
#[repr(C)]
pub(crate) struct DxgiDeviceVtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `SetPrivateData`.
    pub(crate) set_private_data: Slot,
    /// `SetPrivateDataInterface`.
    pub(crate) set_private_data_interface: Slot,
    /// `GetPrivateData`.
    pub(crate) get_private_data: Slot,
    /// `GetParent`.
    pub(crate) get_parent: Slot,
    /// `GetAdapter` — slot 7.
    pub(crate) get_adapter:
        unsafe extern "system" fn(this: *mut Unknown, adapter: *mut *mut Unknown) -> Hresult,
    /// `CreateSurface`.
    pub(crate) create_surface: Slot,
    /// `QueryResourceResidency`.
    pub(crate) query_resource_residency: Slot,
    /// `SetGPUThreadPriority`.
    pub(crate) set_gpu_thread_priority: Slot,
    /// `GetGPUThreadPriority`.
    pub(crate) get_gpu_thread_priority: Slot,
}

/// `IDXGIAdapterVtbl`, slots 0–9.
#[repr(C)]
pub(crate) struct DxgiAdapterVtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `SetPrivateData`.
    pub(crate) set_private_data: Slot,
    /// `SetPrivateDataInterface`.
    pub(crate) set_private_data_interface: Slot,
    /// `GetPrivateData`.
    pub(crate) get_private_data: Slot,
    /// `GetParent`.
    pub(crate) get_parent: Slot,
    /// `EnumOutputs` — slot 7. Answers [`DXGI_ERROR_NOT_FOUND`] past the end.
    pub(crate) enum_outputs: unsafe extern "system" fn(
        this: *mut Unknown,
        index: u32,
        output: *mut *mut Unknown,
    ) -> Hresult,
    /// `GetDesc`.
    pub(crate) get_desc: Slot,
    /// `CheckInterfaceSupport`.
    pub(crate) check_interface_support: Slot,
}

/// `IDXGIOutput1Vtbl`, slots 0–22. The first nineteen are `IDXGIOutput`'s.
#[repr(C)]
pub(crate) struct DxgiOutput1Vtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `SetPrivateData`.
    pub(crate) set_private_data: Slot,
    /// `SetPrivateDataInterface`.
    pub(crate) set_private_data_interface: Slot,
    /// `GetPrivateData`.
    pub(crate) get_private_data: Slot,
    /// `GetParent`.
    pub(crate) get_parent: Slot,
    /// `GetDesc` — slot 7, which is how an output is matched to a display.
    pub(crate) get_desc:
        unsafe extern "system" fn(this: *mut Unknown, desc: *mut DxgiOutputDesc) -> Hresult,
    /// `GetDisplayModeList`.
    pub(crate) get_display_mode_list: Slot,
    /// `FindClosestMatchingMode`.
    pub(crate) find_closest_matching_mode: Slot,
    /// `WaitForVBlank`.
    pub(crate) wait_for_vblank: Slot,
    /// `TakeOwnership`.
    pub(crate) take_ownership: Slot,
    /// `ReleaseOwnership`.
    pub(crate) release_ownership: Slot,
    /// `GetGammaControlCapabilities`.
    pub(crate) get_gamma_control_capabilities: Slot,
    /// `SetGammaControl`.
    pub(crate) set_gamma_control: Slot,
    /// `GetGammaControl`.
    pub(crate) get_gamma_control: Slot,
    /// `SetDisplaySurface`.
    pub(crate) set_display_surface: Slot,
    /// `GetDisplaySurfaceData`.
    pub(crate) get_display_surface_data: Slot,
    /// `GetFrameStatistics`.
    pub(crate) get_frame_statistics: Slot,
    /// `GetDisplayModeList1`.
    pub(crate) get_display_mode_list1: Slot,
    /// `FindClosestMatchingMode1`.
    pub(crate) find_closest_matching_mode1: Slot,
    /// `GetDisplaySurfaceData1`.
    pub(crate) get_display_surface_data1: Slot,
    /// `DuplicateOutput` — slot 22, the whole point of this interface.
    pub(crate) duplicate_output: unsafe extern "system" fn(
        this: *mut Unknown,
        device: *mut Unknown,
        duplication: *mut *mut Unknown,
    ) -> Hresult,
}

/// `IDXGIOutputDuplicationVtbl`, slots 0–14.
#[repr(C)]
pub(crate) struct DxgiOutputDuplicationVtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `SetPrivateData`.
    pub(crate) set_private_data: Slot,
    /// `SetPrivateDataInterface`.
    pub(crate) set_private_data_interface: Slot,
    /// `GetPrivateData`.
    pub(crate) get_private_data: Slot,
    /// `GetParent`.
    pub(crate) get_parent: Slot,
    /// `GetDesc`.
    pub(crate) get_desc: Slot,
    /// `AcquireNextFrame` — slot 8.
    pub(crate) acquire_next_frame: unsafe extern "system" fn(
        this: *mut Unknown,
        timeout_ms: u32,
        info: *mut DxgiOutduplFrameInfo,
        resource: *mut *mut Unknown,
    ) -> Hresult,
    /// `GetFrameDirtyRects`.
    pub(crate) get_frame_dirty_rects: Slot,
    /// `GetFrameMoveRects`.
    pub(crate) get_frame_move_rects: Slot,
    /// `GetFramePointerShape`.
    pub(crate) get_frame_pointer_shape: Slot,
    /// `MapDesktopSurface`.
    pub(crate) map_desktop_surface: Slot,
    /// `UnMapDesktopSurface`.
    pub(crate) unmap_desktop_surface: Slot,
    /// `ReleaseFrame` — slot 14. Owed for every acquire that succeeded.
    pub(crate) release_frame: unsafe extern "system" fn(this: *mut Unknown) -> Hresult,
}

/// `ID3D11DeviceVtbl`, slots 0–5. Everything past `CreateTexture3D` is unused and
/// unwritten: this is the one vtable in the file that is *truncated*, which is
/// sound only because no slot after the last one named here is ever called.
#[repr(C)]
pub(crate) struct D3d11DeviceVtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `CreateBuffer`.
    pub(crate) create_buffer: Slot,
    /// `CreateTexture1D`.
    pub(crate) create_texture_1d: Slot,
    /// `CreateTexture2D` — slot 5, which builds the staging surface.
    pub(crate) create_texture_2d: unsafe extern "system" fn(
        this: *mut Unknown,
        desc: *const D3d11Texture2dDesc,
        initial: *const c_void,
        texture: *mut *mut Unknown,
    ) -> Hresult,
}

/// `ID3D11DeviceContextVtbl`, slots 0–47, truncated after `CopyResource` for the
/// same reason as [`D3d11DeviceVtbl`].
#[repr(C)]
pub(crate) struct D3d11DeviceContextVtbl {
    /// `QueryInterface`, `AddRef`, `Release`.
    pub(crate) unknown: UnknownVtbl,
    /// `GetDevice`.
    pub(crate) get_device: Slot,
    /// `GetPrivateData`.
    pub(crate) get_private_data: Slot,
    /// `SetPrivateData`.
    pub(crate) set_private_data: Slot,
    /// `SetPrivateDataInterface`.
    pub(crate) set_private_data_interface: Slot,
    /// `VSSetConstantBuffers`.
    pub(crate) vs_set_constant_buffers: Slot,
    /// `PSSetShaderResources`.
    pub(crate) ps_set_shader_resources: Slot,
    /// `PSSetShader`.
    pub(crate) ps_set_shader: Slot,
    /// `PSSetSamplers`.
    pub(crate) ps_set_samplers: Slot,
    /// `VSSetShader`.
    pub(crate) vs_set_shader: Slot,
    /// `DrawIndexed`.
    pub(crate) draw_indexed: Slot,
    /// `Draw`.
    pub(crate) draw: Slot,
    /// `Map` — slot 14.
    pub(crate) map: unsafe extern "system" fn(
        this: *mut Unknown,
        resource: *mut Unknown,
        subresource: u32,
        map_type: u32,
        flags: u32,
        mapped: *mut D3d11MappedSubresource,
    ) -> Hresult,
    /// `Unmap` — slot 15.
    pub(crate) unmap: unsafe extern "system" fn(
        this: *mut Unknown,
        resource: *mut Unknown,
        subresource: u32,
    ),
    /// `PSSetConstantBuffers`.
    pub(crate) ps_set_constant_buffers: Slot,
    /// `IASetInputLayout`.
    pub(crate) ia_set_input_layout: Slot,
    /// `IASetVertexBuffers`.
    pub(crate) ia_set_vertex_buffers: Slot,
    /// `IASetIndexBuffer`.
    pub(crate) ia_set_index_buffer: Slot,
    /// `DrawIndexedInstanced`.
    pub(crate) draw_indexed_instanced: Slot,
    /// `DrawInstanced`.
    pub(crate) draw_instanced: Slot,
    /// `GSSetConstantBuffers`.
    pub(crate) gs_set_constant_buffers: Slot,
    /// `GSSetShader`.
    pub(crate) gs_set_shader: Slot,
    /// `IASetPrimitiveTopology`.
    pub(crate) ia_set_primitive_topology: Slot,
    /// `VSSetShaderResources`.
    pub(crate) vs_set_shader_resources: Slot,
    /// `VSSetSamplers`.
    pub(crate) vs_set_samplers: Slot,
    /// `Begin`.
    pub(crate) begin: Slot,
    /// `End`.
    pub(crate) end: Slot,
    /// `GetData`.
    pub(crate) get_data: Slot,
    /// `SetPredication`.
    pub(crate) set_predication: Slot,
    /// `GSSetShaderResources`.
    pub(crate) gs_set_shader_resources: Slot,
    /// `GSSetSamplers`.
    pub(crate) gs_set_samplers: Slot,
    /// `OMSetRenderTargets`.
    pub(crate) om_set_render_targets: Slot,
    /// `OMSetRenderTargetsAndUnorderedAccessViews`.
    pub(crate) om_set_render_targets_and_unordered_access_views: Slot,
    /// `OMSetBlendState`.
    pub(crate) om_set_blend_state: Slot,
    /// `OMSetDepthStencilState`.
    pub(crate) om_set_depth_stencil_state: Slot,
    /// `SOSetTargets`.
    pub(crate) so_set_targets: Slot,
    /// `DrawAuto`.
    pub(crate) draw_auto: Slot,
    /// `DrawIndexedInstancedIndirect`.
    pub(crate) draw_indexed_instanced_indirect: Slot,
    /// `DrawInstancedIndirect`.
    pub(crate) draw_instanced_indirect: Slot,
    /// `Dispatch`.
    pub(crate) dispatch: Slot,
    /// `DispatchIndirect`.
    pub(crate) dispatch_indirect: Slot,
    /// `RSSetState`.
    pub(crate) rs_set_state: Slot,
    /// `RSSetViewports`.
    pub(crate) rs_set_viewports: Slot,
    /// `RSSetScissorRects`.
    pub(crate) rs_set_scissor_rects: Slot,
    /// `CopySubresourceRegion` — slot 46.
    pub(crate) copy_subresource_region: Slot,
    /// `CopyResource` — slot 47, the whole GPU-side cost of a frame.
    pub(crate) copy_resource: unsafe extern "system" fn(
        this: *mut Unknown,
        destination: *mut Unknown,
        source: *mut Unknown,
    ),
}

/// `DXGI_OUTPUT_DESC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DxgiOutputDesc {
    /// `DeviceName`, e.g. `\\.\DISPLAY1`, NUL-padded.
    pub(crate) device_name: [u16; 32],
    /// The output's place on the virtual desktop, which is what identifies it.
    pub(crate) desktop_coordinates: Rect,
    /// Whether this output is part of the desktop at all.
    pub(crate) attached_to_desktop: Bool,
    /// `DXGI_MODE_ROTATION`.
    pub(crate) rotation: u32,
    /// `HMONITOR`.
    pub(crate) monitor: Handle,
}

/// `DXGI_OUTDUPL_POINTER_POSITION`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct DxgiOutduplPointerPosition {
    /// Where the pointer is.
    pub(crate) position: Point,
    /// Whether it is being drawn.
    pub(crate) visible: Bool,
}

/// `DXGI_OUTDUPL_FRAME_INFO`.
///
/// `last_present_time` of zero is the field this crate reads most: it means the
/// acquire returned a *pointer* update and no new desktop image, which is a frame
/// that must be released and not encoded.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct DxgiOutduplFrameInfo {
    /// When the desktop image was last presented; zero means it was not.
    pub(crate) last_present_time: i64,
    /// When the pointer last moved.
    pub(crate) last_mouse_update_time: i64,
    /// How many frames were coalesced into this one.
    pub(crate) accumulated_frames: u32,
    /// Whether the dirty rectangles were merged.
    pub(crate) rects_coalesced: Bool,
    /// Whether protected content was blacked out of this frame.
    pub(crate) protected_content_masked_out: Bool,
    /// The pointer's position and visibility.
    pub(crate) pointer_position: DxgiOutduplPointerPosition,
    /// Bytes of metadata waiting.
    pub(crate) total_metadata_buffer_size: u32,
    /// Bytes of pointer shape waiting.
    pub(crate) pointer_shape_buffer_size: u32,
}

/// `DXGI_SAMPLE_DESC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DxgiSampleDesc {
    /// Samples per pixel; one, for a surface that is only ever copied.
    pub(crate) count: u32,
    /// Quality level.
    pub(crate) quality: u32,
}

/// `D3D11_TEXTURE2D_DESC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct D3d11Texture2dDesc {
    /// Width in pixels.
    pub(crate) width: u32,
    /// Height in pixels.
    pub(crate) height: u32,
    /// Mip levels; one.
    pub(crate) mip_levels: u32,
    /// Array size; one.
    pub(crate) array_size: u32,
    /// `DXGI_FORMAT`.
    pub(crate) format: u32,
    /// Multisampling.
    pub(crate) sample_desc: DxgiSampleDesc,
    /// `D3D11_USAGE`.
    pub(crate) usage: u32,
    /// Bind flags; none, because this surface is never bound to the pipeline.
    pub(crate) bind_flags: u32,
    /// CPU access flags.
    pub(crate) cpu_access_flags: u32,
    /// Misc flags.
    pub(crate) misc_flags: u32,
}

/// `D3D11_MAPPED_SUBRESOURCE`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct D3d11MappedSubresource {
    /// The pixels.
    pub(crate) data: *mut c_void,
    /// Bytes per row, which is **not** width × 4: the driver pads it.
    pub(crate) row_pitch: u32,
    /// Bytes per depth slice.
    pub(crate) depth_pitch: u32,
}

// The layouts these calls reject a mismatch on, checked at compile time on the
// machine that builds this rather than at run time on the machine that runs it.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<DxgiOutduplFrameInfo>() == 48);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<DxgiOutputDesc>() == 96);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<D3d11Texture2dDesc>() == 44);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<D3d11MappedSubresource>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Guid>() == 16);

/// `D3D11CreateDevice`, resolved at run time.
///
/// Not imported statically, for the reason [`SetProcessDpiAwarenessContextFn`]
/// gives and one more: a static import of `d3d11.dll` would make the *agent* fail
/// to start on a machine with no Direct3D at all, where the whole point of this
/// module is that such a machine quietly keeps the GDI capture it already had.
pub(crate) type D3d11CreateDeviceFn = unsafe extern "system" fn(
    adapter: *mut Unknown,
    driver_type: u32,
    software: Handle,
    flags: u32,
    feature_levels: *const u32,
    feature_level_count: u32,
    sdk_version: u32,
    device: *mut *mut Unknown,
    feature_level: *mut u32,
    context: *mut *mut Unknown,
) -> Hresult;

/// Resolves an optional export, or `None` if this Windows does not have it.
///
/// # Safety
///
/// `T` must be the exact signature the export has. Getting it wrong is a call
/// through a pointer with the wrong argument list, which is undefined behaviour
/// that usually survives long enough to be diagnosed somewhere else entirely —
/// so every caller of this passes one of the function types declared above and
/// nothing constructed at the call site.
pub(crate) unsafe fn optional_export<T: Copy>(library: &str, symbol: &[u8]) -> Option<T> {
    const _: () = assert!(size_of::<*const c_void>() == size_of::<usize>());
    if size_of::<T>() != size_of::<*const c_void>() {
        return None;
    }
    // `GetProcAddress` takes a C string; a symbol without its NUL would be read
    // past its own end.
    if symbol.last().is_none_or(|last| *last != 0) {
        return None;
    }
    let name = wide_str(library).ok()?;
    // Already-loaded first: `user32` is always in the process and taking a
    // reference to it would be a reference nothing releases.
    let mut module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        module = unsafe { LoadLibraryW(name.as_ptr()) };
    }
    if module.is_null() {
        return None;
    }
    let address = unsafe { GetProcAddress(module, symbol.as_ptr()) };
    if address.is_null() {
        return None;
    }
    // Sound by the size check above plus the caller's obligation about `T`.
    Some(unsafe { std::mem::transmute_copy::<*const c_void, T>(&address) })
}
