//! Starting one process, capturing its output, and stopping it without losing data.
//!
//! # Stopping is the part that is not portable
//!
//! Unix has `SIGTERM`: a request the process can catch, flush on, and honour.
//! Windows has no equivalent that reaches a process running without a console —
//! `GenerateConsoleCtrlEvent` needs a console the service does not have, and
//! `TerminateProcess` is not a request but an execution, with no chance to write
//! anything to disk. For a database that is a way to corrupt it.
//!
//! So the ladder is, in order, and the first rung is the portable one:
//!
//! 1. [`ServiceSpec::stop_command`] if the operator named one — `mongod --shutdown`,
//!    `nginx -s quit`. Works identically on every platform because it is just a
//!    program, and it is the *only* rung a Windows database should ever need.
//! 2. `SIGTERM` on Unix.
//! 3. Kill, once `stop_timeout_secs` has passed with the process still alive.
//!
//! # Owning the tree, not the process
//!
//! Every rung above addresses a *tree*, because a service is rarely one
//! process: `npm start` forks node, a script forks the program that binds the
//! port. A process group (Unix) or a [`Job`](crate::job) object (Windows) makes
//! the whole tree addressable as one thing.
//!
//! # What happens when the daemon is killed outright
//!
//! Stopping children tidily is not the same promise as children being unable to
//! outlive us, and only the second one holds when the daemon dies without
//! running any code — `kill -9`, `TerminateProcess`, a power cut. `kill_on_drop`
//! and the shutdown path both need the daemon to still be alive to run, so
//! neither covers that case. What does, per platform, and measured rather than
//! assumed:
//!
//! - **Windows — covered.** The job object carries
//!   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and the kernel closes the handle when
//!   the process ends however it ends. This is a guarantee, not a teardown path.
//! - **Linux — covered.** [`die_with_parent`] arms `PR_SET_PDEATHSIG` in the
//!   child between `fork` and `exec`, so the kernel signals it when its parent
//!   goes. It reaches the direct child; a grandchild that has been reparented
//!   away is out of its scope.
//! - **macOS — not covered.** There is no `PDEATHSIG` and no job object. A
//!   `kill -9` of the daemon leaves the tree running, verified by experiment,
//!   and the next start then fails to bind a port that something invisible is
//!   holding. The deployment target is Windows and macOS is the development
//!   box, so this is stated rather than worked around: a watchdog process to
//!   cover it would reintroduce the second process that unifying everything
//!   into one just removed.

use selfhost_config::ServiceSpec;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use crate::job::Job;
use crate::logs::Stream;

/// A line of output read from a running service.
#[derive(Debug)]
pub struct Captured {
    /// Which stream it came from.
    pub stream: Stream,
    /// The text, newline already stripped.
    pub text: String,
}

/// A running process and when it started.
#[derive(Debug)]
pub struct Running {
    /// The child handle, used to wait for and stop it.
    pub child: Child,
    /// Operating-system process id, for display.
    pub pid: u32,
    /// When it was spawned, for uptime.
    pub started: Instant,
    /// The job object owning this service's whole process tree, on Windows.
    ///
    /// Held here, beside the child, because dropping it is what kills the tree:
    /// the guarantee is a property of *ownership*, so the value has to live
    /// exactly as long as the service should. Inert on Unix, where the process
    /// group set at spawn is the mechanism.
    pub job: Job,
}

/// Why a service could not be started.
#[derive(Debug)]
pub enum SpawnError {
    /// The executable could not be run.
    Failed {
        /// The program that was attempted.
        program: String,
        /// The reason, from the operating system.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { program, source } => match source.kind() {
                std::io::ErrorKind::NotFound => write!(
                    f,
                    "{program} was not found — check the path, and note that a bare name is \
                     not looked up on PATH here so the service starts the same way whoever \
                     starts it"
                ),
                std::io::ErrorKind::PermissionDenied => {
                    write!(f, "{program} is not executable by the account running the daemon")
                }
                _ => write!(f, "could not start {program}: {source}"),
            },
        }
    }
}

impl std::error::Error for SpawnError {}

/// Starts a service, streaming its output to `sink`.
///
/// `base_dir` resolves a relative working directory, so a service's location does
/// not depend on where the daemon happened to be launched from.
pub fn spawn(
    spec: &ServiceSpec,
    base_dir: &Path,
    sink: mpsc::UnboundedSender<Captured>,
) -> Result<Running, SpawnError> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(cwd) = &spec.cwd {
        command.current_dir(base_dir.join(cwd));
    } else {
        command.current_dir(base_dir);
    }

    // Without this, killing the daemon leaves orphaned children holding the ports
    // their replacements are about to bind, and the next start fails for a reason
    // that points at the wrong thing.
    command.kill_on_drop(true);
    isolate_process_group(&mut command);
    die_with_parent(&mut command);

    // Created before the spawn so the window between the process existing and
    // being owned is as short as it can be without suspending it — see
    // [`Job::adopt`] for why it is not zero.
    let job = Job::kill_on_drop();

    let mut child = command.spawn().map_err(|source| SpawnError::Failed {
        program: spec.program.display().to_string(),
        source,
    })?;

    // A child the job would not take still runs; it is just cleaned up by the
    // process-group path alone. Said once, per service, rather than silently
    // downgrading a guarantee the operator was told they had.
    if job.is_active() && !job.adopt(&child) {
        eprintln!(
            "supervisor: {} could not be put in its job object ({}); it will be stopped \
             directly, so a wrapper's grandchildren may survive",
            spec.name,
            std::io::Error::last_os_error()
        );
    }

    let pid = child.id().unwrap_or(0);
    let started = Instant::now();

    if let Some(stdout) = child.stdout.take() {
        pump(stdout, Stream::Stdout, sink.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        pump(stderr, Stream::Stderr, sink);
    }

    Ok(Running { child, pid, started, job })
}

/// Forwards every line of one stream into the log sink until it closes.
///
/// Lines are read lossily: a service that emits invalid UTF-8 — which a program
/// writing raw bytes to stderr will — must not silently stop being logged from
/// that point on.
fn pump<R>(reader: R, stream: Stream, sink: mpsc::UnboundedSender<Captured>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).split(b'\n');
        while let Ok(Some(line)) = lines.next_segment().await {
            let text = String::from_utf8_lossy(&line).trim_end_matches('\r').to_owned();
            if sink.send(Captured { stream, text }).is_err() {
                break;
            }
        }
    });
}

/// Asks a process to stop, escalating to a kill if it will not.
///
/// Returns how it went, for the log — an operator seeing "killed after 10s"
/// knows to give the service a `stop_command`, whereas a silent kill teaches
/// them nothing.
pub async fn stop(running: &mut Running, spec: &ServiceSpec, base_dir: &Path) -> StopOutcome {
    let deadline = Duration::from_secs(spec.stop_timeout_secs.max(1));

    if let Some(command) = &spec.stop_command
        && let Some(program) = command.first()
    {
        let mut stopper = Command::new(program);
        stopper
            .args(&command[1..])
            .envs(&spec.env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(spec.cwd.as_ref().map_or_else(|| base_dir.to_path_buf(), |c| base_dir.join(c)));

        if let Ok(mut stopper) = stopper.spawn() {
            let _ = stopper.wait().await;
            if wait_for_exit(running, deadline).await {
                return StopOutcome::StopCommand;
            }
        }
    }

    if request_termination(running.pid) && wait_for_exit(running, deadline).await {
        return StopOutcome::Signalled;
    }

    // Kill the whole tree before the direct child: `child.kill()` reaps only the
    // process we spawned, and for anything started through a wrapper — a shell
    // script, `npm start` — the program that actually holds the port is a
    // grandchild. Killing the parent alone reparents it to init, still listening,
    // so the next start fails to bind and blames the wrong thing.
    //
    // The job is tried first because on Windows it is the only thing that
    // reaches a grandchild; `kill_process_group` is the Unix mechanism and a
    // no-op there. Exactly one of the two does the work on any given platform,
    // and neither is trusted to have worked — the direct kill below runs
    // regardless.
    running.job.terminate();
    kill_process_group(running.pid);
    let _ = running.child.kill().await;
    let _ = running.child.wait().await;
    StopOutcome::Killed
}

/// How a service came to a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// It honoured the configured stop command.
    StopCommand,
    /// It honoured a termination signal.
    Signalled,
    /// It had to be killed, and may not have flushed anything to disk.
    Killed,
}

impl std::fmt::Display for StopOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StopCommand => write!(f, "stopped via its stop command"),
            Self::Signalled => write!(f, "stopped on request"),
            Self::Killed => write!(
                f,
                "did not stop when asked and was killed; give it a stop_command if it \
                 needs to flush state"
            ),
        }
    }
}

/// Waits up to `deadline` for the process to exit. Returns whether it did.
async fn wait_for_exit(running: &mut Running, deadline: Duration) -> bool {
    tokio::time::timeout(deadline, running.child.wait()).await.is_ok()
}

// The platform's own signal call, declared rather than depended on, for the same
// reason as the rest of this project: libc is the operating system, and a single
// symbol is a smaller surface than a crate with its own release cadence.
//
// A negative `pid` addresses the whole process group, which is the entire point
// of using it here.
#[cfg(unix)]
#[allow(unsafe_code)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

/// Puts the child in a process group of its own, so its descendants can be
/// signalled together.
///
/// Nearly every real service is started through something: a shell script, a
/// language launcher, `npm start`. Those wrappers `fork` the program that
/// actually binds the port, so signalling the child we spawned kills the wrapper
/// and reparents the real process to init — still running, still holding the
/// port. Its own group makes the whole tree addressable as one thing.
#[cfg(unix)]
fn isolate_process_group(command: &mut Command) {
    // Group id zero means "use the child's own pid", so the child becomes the
    // group leader and `kill(-pid, …)` reaches everything it starts.
    command.process_group(0);
}

/// Windows equivalent: a new process group, set at creation.
///
/// This alone is weaker than the Unix path — a new process group on Windows
/// scopes console control events, it does not make a tree killable — which is
/// why the tree is owned by a [`Job`](crate::job) object instead. Both are set:
/// the group keeps a Ctrl-C aimed at the daemon's console from reaching
/// services that never asked for one, and the job is what actually ends them.
#[cfg(windows)]
fn isolate_process_group(command: &mut Command) {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(not(any(unix, windows)))]
fn isolate_process_group(_command: &mut Command) {}

/// Asks the kernel to kill this child when the daemon dies, on the one Unix
/// that offers it.
///
/// `PR_SET_PDEATHSIG` is armed in the child itself, in the window between
/// `fork` and `exec`, which is the only moment it can be set — it is a property
/// of the process, not something a parent can confer from outside.
///
/// This covers what no shutdown path can: a daemon killed with `SIGKILL` runs
/// no code, so anything relying on `Drop` or a stop sequence has already lost.
/// It reaches the direct child only; a grandchild whose parent has already
/// exited is not covered, which is why the process group above still exists for
/// every stop that *does* get to run.
///
/// # Safety
///
/// The closure runs in the forked child, where only async-signal-safe calls are
/// allowed. `prctl` is one syscall and allocates nothing, which is the whole
/// reason this is expressed as a bare FFI call rather than anything friendlier.
#[cfg(target_os = "linux")]
fn die_with_parent(command: &mut Command) {
    /// `PR_SET_PDEATHSIG` from `linux/prctl.h`.
    const PR_SET_PDEATHSIG: i32 = 1;

    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn prctl(option: i32, arg2: u64, ...) -> i32;
    }

    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(|| {
            // A failure here is not worth refusing to start the service over:
            // it degrades to exactly the macOS behaviour, which is a documented
            // and survivable state rather than a broken one.
            prctl(PR_SET_PDEATHSIG, SIGKILL as u64);
            Ok(())
        });
    }
}

/// No equivalent exists on macOS or the BSDs, and Windows uses a job object
/// instead. See the module docs for what that leaves uncovered.
#[cfg(not(target_os = "linux"))]
fn die_with_parent(_command: &mut Command) {}

/// Asks the operating system to deliver a polite termination request to the
/// service and everything it started.
///
/// Returns whether such a request could be sent at all — on Windows it cannot,
/// so the caller proceeds straight to the kill.
#[cfg(unix)]
fn request_termination(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Negative: the group, not just the leader.
    #[allow(unsafe_code)]
    unsafe {
        kill(-(pid as i32), SIGTERM) == 0
    }
}

/// Windows has no signal that reaches a process without a console.
///
/// Rather than pretend, this reports that no polite request is possible, and the
/// caller kills. A service that must flush before stopping needs a
/// [`ServiceSpec::stop_command`] on this platform — which is why that field exists.
#[cfg(not(unix))]
fn request_termination(_pid: u32) -> bool {
    false
}

/// Kills the service and every process it started.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    if pid == 0 {
        return;
    }
    #[allow(unsafe_code)]
    unsafe {
        kill(-(pid as i32), SIGKILL);
    }
}

/// Off Unix the tree is owned by a [`Job`](crate::job), which [`stop`] has
/// already terminated by the time this is reached. Nothing to do here.
#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {}
