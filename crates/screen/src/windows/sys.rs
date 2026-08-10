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
    pub(crate) fn raw(&self) -> Handle {
        self.0
    }

    /// Gives up ownership without closing, for a handle another structure is
    /// taking over.
    pub(crate) fn into_raw(self) -> Handle {
        let raw = self.0;
        std::mem::forget(self);
        raw
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
