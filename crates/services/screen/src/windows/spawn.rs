//! Starting the agent inside the session a person is sitting in.
//!
//! This is the sequence the module documentation of [`super`] lists, written out
//! once. Every step of it is mandatory and every one of them fails in a way that
//! is hard to recognise if it is skipped:
//!
//! - skip the token duplication and `CreateProcessAsUserW` refuses an
//!   impersonation token, with an error that names neither;
//! - skip `CreateEnvironmentBlock` and the agent runs with `SYSTEM`'s `APPDATA`,
//!   `TEMP` and `USERPROFILE` while appearing to be the user, so everything it
//!   writes goes to the service profile and every path in its own log is a lie;
//! - skip `lpDesktop` and the process starts, runs, reports nothing wrong, and is
//!   invisible on a desktop nobody is looking at;
//! - pass `bInheritHandles = TRUE` and nothing happens, because handles cannot be
//!   inherited across sessions at all — which is *why* the agent is reached
//!   through a named pipe rather than an inherited one.
//!
//! Nothing here captures anything or injects anything. The plan puts the spawn
//! first deliberately: the session-0 problem is the fact that sinks this project
//! if it is discovered late, so it is proven with nothing dangerous attached.

use super::sys::{self, Handle, OwnedHandle};
use super::{command_line, desktop, INTERACTIVE_DESKTOP};
use crate::agent::{agent_arguments, InputPolicy};
use crate::supervisor::{AgentHost, AgentProcess, ConsoleSession};
use crate::Fault;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

/// What to start, and with what arguments.
///
/// The executable is this same binary in production — `selfhost desk-agent` — and
/// is passed as an explicit path rather than discovered, because
/// `CreateProcessAsUserW`'s path search is one of the classic Windows
/// privilege-escalation surfaces and the safe answer is to never invoke it.
#[derive(Debug, Clone)]
pub struct AgentCommand {
    /// The absolute path of the agent executable.
    pub executable: PathBuf,
    /// Its arguments, not including the program name.
    pub arguments: Vec<String>,
}

/// A running agent, from the daemon's side of the fence.
#[derive(Debug)]
pub struct SpawnedAgent {
    process: OwnedHandle,
    session: u32,
}

impl AgentProcess for SpawnedAgent {
    fn session(&self) -> u32 {
        self.session
    }

    /// Whether it has ended, and with what.
    ///
    /// The wait comes **before** `GetExitCodeProcess` on purpose: that call
    /// reports `STILL_ACTIVE` (259) for a running process, and 259 is also a
    /// perfectly legal exit code. A supervisor that only reads the exit code
    /// treats an agent that exited with 259 as permanently running and never
    /// restarts it. A zero-millisecond wait is the authoritative answer.
    fn finished(&mut self) -> Result<Option<i32>, Fault> {
        let waited = unsafe { sys::WaitForSingleObject(self.process.raw(), 0) };
        match waited {
            sys::WAIT_TIMEOUT => Ok(None),
            sys::WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                let ok = unsafe { sys::GetExitCodeProcess(self.process.raw(), &mut code) };
                if ok == 0 {
                    return Err(Fault::last_os_error("GetExitCodeProcess"));
                }
                Ok(Some(code as i32))
            }
            _ => Err(Fault::last_os_error("WaitForSingleObject")),
        }
    }

    /// Ends it.
    ///
    /// Returns nothing, and that is deliberate: a supervisor that cannot give up
    /// on a process has no route back to a working state, so a failure here is
    /// recorded by the *next* [`SpawnedAgent::finished`] and never blocks the
    /// decision to move on. The handle is closed by this value being dropped
    /// either way.
    fn terminate(&mut self) {
        unsafe { sys::TerminateProcess(self.process.raw(), 1) };
    }
}

/// The daemon's Windows implementation of [`AgentHost`].
///
/// Holds the executable and the deployment's input policy, and **nothing about a
/// session**: which session and who is signed into it are asked freshly on every
/// spawn, because a cached session id is an agent started into a session that has
/// since gone away.
///
/// The arguments are built here rather than accepted from the caller, by
/// [`agent_arguments`], so that the session the supervisor decided on and the
/// switch the operator configured are the two things that reach the agent — and
/// so that no caller can assemble an argv that grants input by accident.
#[derive(Debug, Clone)]
pub struct WindowsHost {
    executable: PathBuf,
    input: InputPolicy,
}

impl WindowsHost {
    /// A host that starts `executable` under `input`.
    ///
    /// `executable` must be the absolute path of the selfhost binary — the same
    /// one this daemon is running from, in production, since the agent is a
    /// subcommand of it. It is passed as `lpApplicationName` and never searched
    /// for; see [`spawn_into_session`].
    ///
    /// `input` is [`InputPolicy::from_config`] of `[desktop].allow_input`, read at
    /// the moment the host is built. An operator who changes that switch gets the
    /// new answer when the daemon re-reads its config and rebuilds the host, which
    /// is the same rule every other config value in this deployment follows.
    pub fn new(executable: PathBuf, input: InputPolicy) -> Self {
        Self { executable, input }
    }

    /// The command this host would spawn into `session`.
    ///
    /// Exposed for the daemon's own diagnostics — a console plate that shows what
    /// is about to be started — and used by [`AgentHost::spawn`] itself, so the
    /// line an operator reads is the line that runs.
    pub fn command_for(&self, session: u32) -> AgentCommand {
        AgentCommand {
            executable: self.executable.clone(),
            arguments: agent_arguments(session, self.input),
        }
    }

    /// The executable this host starts.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Whether agents started by this host may build an injector.
    pub fn input_policy(&self) -> InputPolicy {
        self.input
    }
}

impl AgentHost for WindowsHost {
    fn console_session(&mut self) -> Result<ConsoleSession, Fault> {
        desktop::active_console_session()
    }

    fn spawn(&mut self, session: u32) -> Result<Box<dyn AgentProcess>, Fault> {
        Ok(Box::new(spawn_into_session(&self.command_for(session), session)?))
    }
}

/// Starts `command` inside `session`, as whoever is signed into it.
///
/// # Errors
///
/// Every failure is a [`Fault`] naming the Win32 call that produced it, because
/// the same error number means entirely different things from different steps of
/// this sequence: `ERROR_ACCESS_DENIED` from `WTSQueryUserToken` means the daemon
/// is not `LocalSystem`, and from `CreateProcessAsUserW` it usually means the
/// user cannot read the executable.
///
/// A session whose user signed out between the decision to spawn and this call
/// produces a fault rather than a state. The window is a few milliseconds wide
/// and the supervisor charges it against the respawn budget, which is a small
/// price for not having a second "nobody is logged in" path that has to agree
/// with the first one.
pub fn spawn_into_session(command: &AgentCommand, session: u32) -> Result<SpawnedAgent, Fault> {
    let token = desktop::console_user_token(session)?.ok_or_else(|| {
        Fault::refused(
            "WTSQueryUserToken",
            format!("nobody is signed into session {session} any more"),
        )
    })?;

    let primary = duplicate_as_primary(&token)?;
    let environment = EnvironmentBlock::for_token(&primary)?;

    let application = sys::wide(command.executable.as_os_str())?;
    let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
    let line = command_line(&command.executable, &arguments)
        .map_err(|error| Fault::refused("the agent command line", error.sentence()))?;
    // `lpCommandLine` is documented as writable and Windows does write to it, so
    // the buffer is owned and mutable rather than pointing at a literal.
    let mut line = sys::wide_str(&line)?;
    let mut desktop_name = sys::wide_str(INTERACTIVE_DESKTOP)?;

    let startup = sys::StartupInfoW {
        cb: u32::try_from(size_of::<sys::StartupInfoW>()).unwrap_or(0),
        reserved: std::ptr::null_mut(),
        desktop: desktop_name.as_mut_ptr(),
        title: std::ptr::null_mut(),
        x: 0,
        y: 0,
        x_size: 0,
        y_size: 0,
        x_count_chars: 0,
        y_count_chars: 0,
        fill_attribute: 0,
        flags: sys::STARTF_USESHOWWINDOW,
        show_window: sys::SW_HIDE,
        cb_reserved2: 0,
        reserved2: std::ptr::null_mut(),
        std_input: std::ptr::null_mut(),
        std_output: std::ptr::null_mut(),
        std_error: std::ptr::null_mut(),
    };
    let mut information = sys::ProcessInformation {
        process: std::ptr::null_mut(),
        thread: std::ptr::null_mut(),
        process_id: 0,
        thread_id: 0,
    };

    let ok = unsafe {
        sys::CreateProcessAsUserW(
            primary.raw(),
            application.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            // Handles cannot cross a session boundary, so inheriting them is not
            // merely unnecessary here — it cannot work, and asking for it hands
            // the child handles it has no way to use.
            0,
            sys::CREATE_UNICODE_ENVIRONMENT | sys::CREATE_NO_WINDOW,
            environment.raw(),
            std::ptr::null(),
            &startup,
            &mut information,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("CreateProcessAsUserW")
            .noting(format!("session {session}")));
    }

    // The thread handle is of no use to a supervisor and leaks a kernel object
    // per spawn if it is not closed — over months, on a machine that respawns on
    // every session switch, that is a real leak.
    drop(OwnedHandle::new(information.thread));

    let process = OwnedHandle::new(information.process).ok_or_else(|| {
        Fault::refused("CreateProcessAsUserW", "succeeded but produced no process handle")
    })?;
    Ok(SpawnedAgent { process, session })
}

/// Duplicates an impersonation token into the primary token a process needs.
fn duplicate_as_primary(token: &OwnedHandle) -> Result<OwnedHandle, Fault> {
    let mut raw: Handle = std::ptr::null_mut();
    let ok = unsafe {
        sys::DuplicateTokenEx(
            token.raw(),
            sys::TOKEN_ALL_ACCESS,
            std::ptr::null(),
            sys::SECURITY_IMPERSONATION,
            sys::TOKEN_PRIMARY,
            &mut raw,
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("DuplicateTokenEx"));
    }
    OwnedHandle::new(raw)
        .ok_or_else(|| Fault::refused("DuplicateTokenEx", "succeeded but produced no token"))
}

/// The user's environment block, freed on drop.
///
/// Owned rather than freed by hand because every error branch between its
/// creation and `CreateProcessAsUserW` would otherwise need its own
/// `DestroyEnvironmentBlock`, and the one that gets missed leaks the user's whole
/// environment on every failed spawn.
#[derive(Debug)]
struct EnvironmentBlock(*mut c_void);

impl EnvironmentBlock {
    /// Builds the environment for whoever this token belongs to.
    fn for_token(token: &OwnedHandle) -> Result<Self, Fault> {
        let mut block: *mut c_void = std::ptr::null_mut();
        // `inherit = FALSE`: the daemon's own environment is `SYSTEM`'s, and
        // merging it into the agent's is how a service profile's `TEMP` ends up
        // in an interactive process.
        let ok = unsafe { sys::CreateEnvironmentBlock(&mut block, token.raw(), 0) };
        if ok == 0 {
            return Err(Fault::last_os_error("CreateEnvironmentBlock"));
        }
        if block.is_null() {
            return Err(Fault::refused("CreateEnvironmentBlock", "succeeded but produced no block"));
        }
        Ok(Self(block))
    }

    /// The raw block, for `CreateProcessAsUserW`.
    fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        unsafe { sys::DestroyEnvironmentBlock(self.0) };
    }
}
