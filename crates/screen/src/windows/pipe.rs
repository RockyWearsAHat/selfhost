//! The channel between the daemon and its agent, and the ACL that guards it.
//!
//! Handles cannot be inherited across a session boundary, so the daemon in
//! session 0 and the agent in the console session cannot share a pipe by passing
//! one to `CreateProcessAsUserW`. They have to meet at a **named** object, which
//! means the object's name is public and its security descriptor is the only
//! thing standing between an unprivileged local process and a channel that drives
//! a keyboard.
//!
//! # There is no agent secret, and that is the design
//!
//! **The pipe's ACL is the authentication.** No token is generated, passed or
//! stored, because every alternative is worse on this platform: a token in the
//! environment block is readable by any process of the same user, a token on the
//! command line is readable by every process on the machine through `ps`-shaped
//! APIs, and a token in a file is one more secret with one more lifetime. A
//! loopback TCP socket was considered and rejected outright — a loopback listener
//! is reachable by every local process, and the console site's own gate is
//! loopback, so "behind the gate" already means "reachable by anything executing
//! on this box".
//!
//! Three things together make the meeting safe:
//!
//! 1. **The descriptor** ([`super::pipe_descriptor`]) names `SYSTEM` and the
//!    console user's own SID and nobody else. Never a NULL DACL, which grants
//!    everyone everything and is the default a careless `CreateNamedPipeW` gets.
//! 2. **`FILE_FLAG_FIRST_PIPE_INSTANCE`** means creation *fails* if the name is
//!    already taken, rather than quietly adding a second instance beside a
//!    squatter's. Any local process can create a pipe name; this turns that from
//!    a silent hijack into a loud refusal.
//! 3. **The client's identity is checked** after it connects, by impersonating it
//!    and comparing its SID with the one the descriptor was built around. The ACL
//!    already restricts *who may open*, and this confirms *who did*, which is
//!    what catches the case where the descriptor was built around the wrong
//!    session's user.
//!
//! What none of this can do is distinguish two processes of the same user at the
//! same integrity level. Windows has no such notion on a pipe, and pretending
//! otherwise would be the most dangerous kind of comment. The honest statement is
//! that a process already running as the console user can reach this pipe — and a
//! process already running as the console user can also read that user's screen
//! and drive that user's keyboard directly, so it gains nothing by doing so.

use super::sys::{self, Handle, OwnedHandle};
use super::{desktop, pipe_descriptor, pipe_name};
use crate::Fault;
use std::ffi::c_void;
use std::time::{Duration, Instant};

/// The kernel buffer, each way, in bytes.
///
/// One tile message comfortably fits, which keeps a well-behaved agent from
/// blocking on every write; the flow control that actually matters lives in the
/// mux layer's credit window, not here.
const PIPE_BUFFER: u32 = 64 * 1024;

/// The server end of an agent pipe.
///
/// One instance only, by construction: a second connection to the same name would
/// be a second agent claiming to be this session's screen.
#[derive(Debug)]
pub struct AgentPipe {
    handle: OwnedHandle,
    /// A manual-reset event, reused for every overlapped operation on this pipe.
    /// One per pipe rather than one per operation, because operations on it are
    /// strictly sequential.
    event: OwnedHandle,
    name: String,
    session: u32,
    expected_sid: String,
    connected: bool,
}

impl AgentPipe {
    /// Creates the pipe for `session`, admitting only `SYSTEM` and `user_sid`.
    ///
    /// # Errors
    ///
    /// A malformed SID is refused before anything is created. `ERROR_PIPE_BUSY`
    /// or `ERROR_ACCESS_DENIED` from the creation itself means **somebody else
    /// already holds this name** — which is either a stale agent that has not
    /// exited or a local process squatting the name to become the screen source,
    /// and either way is reported with those words rather than as a generic
    /// failure.
    pub fn create(session: u32, user_sid: &str) -> Result<Self, Fault> {
        let sddl = pipe_descriptor(user_sid)
            .map_err(|error| Fault::refused("the agent pipe descriptor", error.sentence()))?;
        let descriptor = parse_descriptor(&sddl)?;
        let attributes = sys::SecurityAttributes {
            n_length: u32::try_from(size_of::<sys::SecurityAttributes>()).unwrap_or(0),
            security_descriptor: descriptor.raw(),
            inherit_handle: 0,
        };

        let name = pipe_name(session);
        let wide_name = sys::wide_str(&name)?;
        let raw = unsafe {
            sys::CreateNamedPipeW(
                wide_name.as_ptr(),
                sys::PIPE_ACCESS_DUPLEX
                    | sys::FILE_FLAG_FIRST_PIPE_INSTANCE
                    | sys::FILE_FLAG_OVERLAPPED,
                sys::PIPE_TYPE_BYTE
                    | sys::PIPE_READMODE_BYTE
                    | sys::PIPE_WAIT
                    | sys::PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                &attributes,
            )
        };
        let handle = OwnedHandle::new(raw).ok_or_else(|| {
            let fault = Fault::last_os_error("CreateNamedPipeW");
            match fault.code() {
                Some(sys::ERROR_PIPE_BUSY | sys::ERROR_ACCESS_DENIED) => fault.noting(format!(
                    "{name} already exists — a previous agent has not exited, or another \
                     process on this machine is squatting the name"
                )),
                _ => fault.noting(name.clone()),
            }
        })?;

        // Manual reset: an auto-reset event consumed by a wait that then fails
        // its result check would leave the next operation waiting on an event
        // that has already fired and been cleared.
        let event = OwnedHandle::new(unsafe {
            sys::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
        })
        .ok_or_else(|| Fault::last_os_error("CreateEventW"))?;

        Ok(Self {
            handle,
            event,
            name,
            session,
            expected_sid: user_sid.to_owned(),
            connected: false,
        })
    }

    /// The pipe's name, for a diagnostics line.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The session this pipe belongs to.
    pub fn session(&self) -> u32 {
        self.session
    }

    /// Waits up to `timeout` for the agent to connect, then checks who it is.
    ///
    /// `Ok(false)` means the timeout expired with nobody there — an ordinary
    /// answer while an agent is still starting, and the supervisor's own start
    /// deadline is what eventually decides it never will.
    ///
    /// A client that connects but is **not** the expected user is disconnected
    /// and reported as a fault. That is the one case here worth being noisy
    /// about: it means either the descriptor was built around the wrong session
    /// or something on this machine is trying to become the screen source.
    pub fn accept(&mut self, timeout: Duration) -> Result<bool, Fault> {
        if self.connected {
            return Ok(true);
        }
        let mut overlapped = self.overlapped();
        let started = unsafe { sys::ConnectNamedPipe(self.handle.raw(), &mut overlapped) };
        if started == 0 {
            let fault = Fault::last_os_error("ConnectNamedPipe");
            match fault.code() {
                // The ordinary case for an overlapped handle.
                Some(sys::ERROR_IO_PENDING) => {
                    if !self.await_overlapped(&mut overlapped, timeout, "ConnectNamedPipe")? {
                        return Ok(false);
                    }
                }
                // The client arrived between creation and this call. A success,
                // spelled as a failure.
                Some(sys::ERROR_PIPE_CONNECTED) => {}
                _ => return Err(fault),
            }
        }

        self.verify_client()?;
        self.connected = true;
        Ok(true)
    }

    /// Reads what the agent has sent, up to `buffer`'s length.
    ///
    /// `Ok(0)` means the timeout expired with nothing to read; the caller decides
    /// whether that is a still agent or a dead one, because only the supervisor
    /// knows whether the process is still there.
    pub fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize, Fault> {
        if !self.connected {
            return Err(Fault::refused("the agent pipe", "nothing is connected to it yet"));
        }
        let wanted = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        if wanted == 0 {
            return Ok(0);
        }
        let mut overlapped = self.overlapped();
        let mut immediate: u32 = 0;
        let ok = unsafe {
            sys::ReadFile(
                self.handle.raw(),
                buffer.as_mut_ptr(),
                wanted,
                &mut immediate,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(immediate as usize);
        }
        let fault = Fault::last_os_error("ReadFile");
        if fault.code() != Some(sys::ERROR_IO_PENDING) {
            return Err(fault);
        }
        if !self.await_overlapped(&mut overlapped, timeout, "ReadFile")? {
            return Ok(0);
        }
        Ok(self.transferred(&mut overlapped, "ReadFile")? as usize)
    }

    /// Writes the whole buffer, or fails.
    ///
    /// Loops because a pipe write can complete short when the kernel buffer is
    /// full and the agent is slow, and a partial write of a framed protocol is a
    /// desynchronised channel rather than a lost byte.
    pub fn write_all(&mut self, mut buffer: &[u8], timeout: Duration) -> Result<(), Fault> {
        if !self.connected {
            return Err(Fault::refused("the agent pipe", "nothing is connected to it yet"));
        }
        while !buffer.is_empty() {
            let wanted = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            let mut overlapped = self.overlapped();
            let mut immediate: u32 = 0;
            let ok = unsafe {
                sys::WriteFile(
                    self.handle.raw(),
                    buffer.as_ptr(),
                    wanted,
                    &mut immediate,
                    &mut overlapped,
                )
            };
            let written = if ok != 0 {
                immediate
            } else {
                let fault = Fault::last_os_error("WriteFile");
                if fault.code() != Some(sys::ERROR_IO_PENDING) {
                    return Err(fault);
                }
                if !self.await_overlapped(&mut overlapped, timeout, "WriteFile")? {
                    return Err(Fault::refused("WriteFile", "the agent stopped reading"));
                }
                self.transferred(&mut overlapped, "WriteFile")?
            };
            if written == 0 {
                return Err(Fault::refused("WriteFile", "the pipe accepted no bytes"));
            }
            buffer = buffer.get(written as usize..).ok_or_else(|| {
                Fault::refused("WriteFile", "reported writing more bytes than it was given")
            })?;
        }
        Ok(())
    }

    /// Drops the connected agent, leaving the pipe ready for the next one.
    ///
    /// Called when the agent dies or the session moves. Without it the pipe stays
    /// in a connected state and the replacement agent's `CreateFileW` fails with
    /// a busy pipe, which looks exactly like a squatter.
    pub fn disconnect(&mut self) {
        if self.connected {
            unsafe { sys::DisconnectNamedPipe(self.handle.raw()) };
            self.connected = false;
        }
    }

    /// An `OVERLAPPED` pointing at this pipe's own event.
    fn overlapped(&self) -> sys::Overlapped {
        sys::Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: self.event.raw(),
        }
    }

    /// Waits for an overlapped operation, cancelling it cleanly on a timeout.
    ///
    /// `Ok(false)` is a timeout. The cancellation is not optional: an `OVERLAPPED`
    /// that goes out of scope while the kernel still owns it is a write into freed
    /// stack, which under `panic = "abort"` is not even a panic — it is whatever
    /// happens to be there. So the timeout path cancels and then waits for the
    /// cancellation to be acknowledged before returning.
    fn await_overlapped(
        &self,
        overlapped: &mut sys::Overlapped,
        timeout: Duration,
        call: &'static str,
    ) -> Result<bool, Fault> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        match unsafe { sys::WaitForSingleObject(self.event.raw(), milliseconds) } {
            sys::WAIT_OBJECT_0 => Ok(true),
            sys::WAIT_TIMEOUT => {
                unsafe { sys::CancelIoEx(self.handle.raw(), overlapped) };
                let mut transferred: u32 = 0;
                // `wait = TRUE`: this returns once the kernel has finished with
                // the structure, which is the whole point of cancelling.
                unsafe {
                    sys::GetOverlappedResult(
                        self.handle.raw(),
                        overlapped,
                        &mut transferred,
                        1,
                    )
                };
                Ok(false)
            }
            _ => Err(Fault::last_os_error("WaitForSingleObject").noting(call)),
        }
    }

    /// How many bytes a completed overlapped operation moved.
    fn transferred(
        &self,
        overlapped: &mut sys::Overlapped,
        call: &'static str,
    ) -> Result<u32, Fault> {
        let mut transferred: u32 = 0;
        let ok = unsafe {
            sys::GetOverlappedResult(self.handle.raw(), overlapped, &mut transferred, 0)
        };
        if ok == 0 {
            return Err(Fault::last_os_error("GetOverlappedResult").noting(call));
        }
        Ok(transferred)
    }

    /// Confirms the connected client is the user the descriptor was built for.
    ///
    /// Impersonates, reads the thread's token, compares the SID, and reverts —
    /// on every branch, which is what [`Impersonation`] is for. A thread left
    /// impersonating a client is a thread whose every later call runs as somebody
    /// else, and in a daemon that also serves the admin API that is far worse
    /// than the pipe check it was doing.
    fn verify_client(&mut self) -> Result<(), Fault> {
        let sid = {
            let _impersonating = Impersonation::begin(self.handle.raw())?;
            let mut raw: Handle = std::ptr::null_mut();
            // `open_as_self = TRUE`: the access check for opening the token is
            // made against the *process's* own context rather than the client's,
            // which is what lets a `SYSTEM` daemon read the token of a client
            // whose own rights would not permit it.
            let ok = unsafe {
                sys::OpenThreadToken(sys::GetCurrentThread(), sys::TOKEN_QUERY, 1, &mut raw)
            };
            if ok == 0 {
                return Err(Fault::last_os_error("OpenThreadToken"));
            }
            let token = OwnedHandle::new(raw).ok_or_else(|| {
                Fault::refused("OpenThreadToken", "succeeded but produced no token")
            })?;
            desktop::token_user_sid(&token)?
        };

        if sid != self.expected_sid {
            self.disconnect();
            return Err(Fault::refused(
                "the agent pipe",
                format!(
                    "was connected to by {sid}, but only {} is admitted — a stale agent from \
                     another session, or something on this machine trying to become the \
                     screen source",
                    self.expected_sid
                ),
            ));
        }
        Ok(())
    }
}

impl Drop for AgentPipe {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// An impersonation that ends when it goes out of scope.
#[derive(Debug)]
struct Impersonation;

impl Impersonation {
    /// Takes on the identity of the pipe's client.
    fn begin(pipe: Handle) -> Result<Self, Fault> {
        let ok = unsafe { sys::ImpersonateNamedPipeClient(pipe) };
        if ok == 0 {
            return Err(Fault::last_os_error("ImpersonateNamedPipeClient"));
        }
        Ok(Self)
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        // A failure here would leave the thread running as the client, which is
        // unrecoverable and must not be silent — but there is nothing this
        // destructor can return to, and aborting the daemon would be worse. The
        // one honest thing available is to say so on the way past.
        if unsafe { sys::RevertToSelf() } == 0 {
            eprintln!(
                "selfhost-screen: RevertToSelf failed after impersonating the agent pipe client; \
                 this thread is still running as that client"
            );
        }
    }
}

/// Turns an SDDL string into a security descriptor Windows will accept.
///
/// Modelled on `crates/admin/src/token.rs`, which does the same for the file the
/// deployment's root credential lives in.
fn parse_descriptor(sddl: &str) -> Result<sys::LocalBuffer, Fault> {
    let text = sys::wide_str(sddl)?;
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    let ok = unsafe {
        sys::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            sys::SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(Fault::last_os_error("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
    }
    sys::LocalBuffer::new(descriptor).ok_or_else(|| {
        Fault::refused(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            "succeeded but produced no descriptor",
        )
    })
}

/// The most the agent will hold of a daemon that is talking faster than it reads.
///
/// The link is credit-controlled in the outbound direction; inbound there is only
/// this, because what arrives here is grants and small control messages and nothing
/// that should ever approach a megabyte. Exceeding it is a fault rather than a
/// growing buffer: the far end of this pipe is the process that spawned us, so a
/// flood is a bug worth seeing rather than a load to absorb.
const MAX_INBOUND: usize = 1024 * 1024;

/// How much is read from the pipe in one go.
const READ_CHUNK: usize = 64 * 1024;

/// How long a write to the daemon may take before it is treated as a dead reader.
///
/// Generous, because the daemon may be busy; bounded, because an agent blocked
/// forever on a write is an agent that has stopped capturing and will never say so.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The agent's end of the daemon pipe.
///
/// The mirror image of [`AgentPipe`], and deliberately a separate type rather than
/// a mode on that one: the two ends have different jobs, different lifetimes and
/// different failure meanings. The daemon *creates* the object and is loud when the
/// name is taken; the agent only ever **opens** an existing one, and an agent that
/// could create the name would be an agent something could beat to it.
///
/// There is no authentication here beyond the pipe's own access-control list, and
/// none is possible: see [`super::pipe`]'s module documentation for why every
/// alternative on this platform is worse.
#[derive(Debug)]
pub struct DaemonLink {
    handle: OwnedHandle,
    /// One manual-reset event, reused: operations on this pipe are strictly
    /// sequential, and an auto-reset event consumed by a wait whose result check
    /// then fails would leave the next operation waiting on an event that has
    /// already fired.
    event: OwnedHandle,
    /// Bytes read but not yet parsed into whole frames.
    inbound: Vec<u8>,
}

impl DaemonLink {
    /// Opens the pipe for `session`, waiting up to `deadline` for it to exist.
    ///
    /// The agent is normally spawned *by* the daemon and finds the pipe already
    /// there; the wait covers the case where it wins that race. It is bounded
    /// because an agent waiting forever for a daemon that has gone away is a
    /// process nothing will ever clean up.
    ///
    /// # Errors
    ///
    /// A [`Fault`] naming the call. `ERROR_ACCESS_DENIED` here is worth reading
    /// closely: it means the pipe exists and this process is **not** the user its
    /// access-control list names, which is either a session mix-up or something on
    /// this machine trying to reach a channel it should not have.
    pub fn connect(session: u32, deadline: Duration) -> Result<Self, Fault> {
        let name = pipe_name(session);
        let wide = sys::wide_str(&name)?;
        let started = Instant::now();

        loop {
            let raw = unsafe {
                sys::CreateFileW(
                    wide.as_ptr(),
                    sys::GENERIC_READ | sys::GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    // Never `CREATE_ALWAYS`: the agent opens the daemon's object or
                    // it fails. Creating one would make it possible for an agent to
                    // be the thing a squatter connects to.
                    sys::OPEN_EXISTING,
                    sys::FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            };
            if let Some(handle) = OwnedHandle::new(raw) {
                let event = OwnedHandle::new(unsafe {
                    sys::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
                })
                .ok_or_else(|| Fault::last_os_error("CreateEventW"))?;
                return Ok(Self { handle, event, inbound: Vec::new() });
            }

            let fault = Fault::last_os_error("CreateFileW").noting(name.clone());
            let waitable = matches!(
                fault.code(),
                Some(sys::ERROR_FILE_NOT_FOUND | sys::ERROR_PIPE_BUSY)
            );
            if !waitable || started.elapsed() >= deadline {
                return Err(fault);
            }
            // `WaitNamedPipeW` waits for an *instance* rather than for the name to
            // appear, so it answers immediately when the pipe does not exist yet;
            // the sleep is what keeps that from being a spin.
            unsafe { sys::WaitNamedPipeW(wide.as_ptr(), 250) };
            unsafe { sys::Sleep(50) };
        }
    }

    /// Bytes read and not yet consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.inbound
    }

    /// Drops the first `bytes` of the buffer, after they have been parsed.
    pub fn consume(&mut self, bytes: usize) {
        if bytes >= self.inbound.len() {
            self.inbound.clear();
        } else {
            self.inbound.drain(..bytes);
        }
    }

    /// Reads whatever the daemon has sent, waiting at most `timeout`.
    ///
    /// Answers `false` when the daemon has closed its end, which is how the agent
    /// is asked to stop. That is not a failure and must never be reported as one:
    /// the daemon closes this pipe on a kill switch, on a session change, and on
    /// its own shutdown.
    pub fn poll(&mut self, timeout: Duration) -> Result<bool, Fault> {
        if self.inbound.len() >= MAX_INBOUND {
            return Err(Fault::refused(
                "the daemon link",
                format!("held {MAX_INBOUND} unparsed bytes; the daemon is sending faster than \
                         the agent can parse"),
            ));
        }

        let start = self.inbound.len();
        self.inbound.resize(start + READ_CHUNK, 0);
        let mut overlapped = self.overlapped();
        let mut immediate: u32 = 0;
        let ok = unsafe {
            sys::ReadFile(
                self.handle.raw(),
                self.inbound.as_mut_ptr().add(start),
                u32::try_from(READ_CHUNK).unwrap_or(u32::MAX),
                &mut immediate,
                &mut overlapped,
            )
        };

        let read = if ok != 0 {
            immediate
        } else {
            let fault = Fault::last_os_error("ReadFile");
            match fault.code() {
                Some(sys::ERROR_BROKEN_PIPE) => {
                    self.inbound.truncate(start);
                    return Ok(false);
                }
                Some(sys::ERROR_IO_PENDING) => {
                    if self.await_overlapped(&mut overlapped, timeout)? {
                        self.transferred(&mut overlapped)?
                    } else {
                        0
                    }
                }
                _ => {
                    self.inbound.truncate(start);
                    return Err(fault);
                }
            }
        };

        self.inbound.truncate(start + read as usize);
        Ok(true)
    }

    /// Writes the whole buffer, or fails.
    ///
    /// Loops because a pipe write can complete short when the kernel buffer is full
    /// and the daemon is slow, and a partial write of a framed protocol is a
    /// desynchronised channel rather than a lost byte.
    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), Fault> {
        while !buffer.is_empty() {
            let wanted = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            let mut overlapped = self.overlapped();
            let mut immediate: u32 = 0;
            let ok = unsafe {
                sys::WriteFile(
                    self.handle.raw(),
                    buffer.as_ptr(),
                    wanted,
                    &mut immediate,
                    &mut overlapped,
                )
            };
            let written = if ok != 0 {
                immediate
            } else {
                let fault = Fault::last_os_error("WriteFile");
                if fault.code() != Some(sys::ERROR_IO_PENDING) {
                    return Err(fault);
                }
                if !self.await_overlapped(&mut overlapped, WRITE_TIMEOUT)? {
                    return Err(Fault::refused("WriteFile", "the daemon stopped reading"));
                }
                self.transferred(&mut overlapped)?
            };
            if written == 0 {
                return Err(Fault::refused("WriteFile", "the pipe accepted no bytes"));
            }
            buffer = buffer.get(written as usize..).ok_or_else(|| {
                Fault::refused("WriteFile", "reported writing more bytes than it was given")
            })?;
        }
        Ok(())
    }

    /// An `OVERLAPPED` pointing at this link's own event.
    fn overlapped(&self) -> sys::Overlapped {
        sys::Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: self.event.raw(),
        }
    }

    /// Waits for an overlapped operation, cancelling it cleanly on a timeout.
    ///
    /// The cancellation is not optional. An `OVERLAPPED` that goes out of scope
    /// while the kernel still owns it is a write into freed stack, which under
    /// `panic = "abort"` is not a panic — it is whatever happens to be there.
    fn await_overlapped(
        &self,
        overlapped: &mut sys::Overlapped,
        timeout: Duration,
    ) -> Result<bool, Fault> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        match unsafe { sys::WaitForSingleObject(self.event.raw(), milliseconds) } {
            sys::WAIT_OBJECT_0 => Ok(true),
            sys::WAIT_TIMEOUT => {
                unsafe { sys::CancelIoEx(self.handle.raw(), overlapped) };
                let mut transferred: u32 = 0;
                // `wait = TRUE`: returns once the kernel has finished with the
                // structure, which is the whole point of cancelling.
                unsafe {
                    sys::GetOverlappedResult(self.handle.raw(), overlapped, &mut transferred, 1)
                };
                Ok(false)
            }
            _ => Err(Fault::last_os_error("WaitForSingleObject")),
        }
    }

    /// How many bytes a completed overlapped operation moved.
    fn transferred(&self, overlapped: &mut sys::Overlapped) -> Result<u32, Fault> {
        let mut transferred: u32 = 0;
        let ok =
            unsafe { sys::GetOverlappedResult(self.handle.raw(), overlapped, &mut transferred, 0) };
        if ok == 0 {
            let fault = Fault::last_os_error("GetOverlappedResult");
            if fault.code() == Some(sys::ERROR_BROKEN_PIPE) {
                return Ok(0);
            }
            return Err(fault);
        }
        Ok(transferred)
    }
}
