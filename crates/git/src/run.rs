//! Running one command to completion and reporting what it said.
//!
//! The thin, impure half of this crate: everything that decides *what* to run
//! lives in [`plan`](crate::plan), and everything that decides what to do about
//! the answer lives in [`deploy`](crate::deploy). This module owns only the
//! process.
//!
//! # Why every invocation is given a deadline and a muzzle
//!
//! A deployment runs unattended. Two failure modes therefore matter more than
//! they would at a terminal:
//!
//! - **A command that asks a question never gets one.** `git` prompts for a
//!   username on a private HTTPS repository and `ssh` prompts for a passphrase,
//!   and with no terminal attached both wait forever — which looks exactly like
//!   a slow network. `GIT_TERMINAL_PROMPT=0` and `ssh -o BatchMode=yes` turn each
//!   of those into an immediate, readable failure.
//! - **A command that hangs holds the service down.** Every run has a deadline,
//!   after which it is killed and reported as having timed out.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// How long a remote-ref check may take.
///
/// Short: it is one small request, and a poll that hangs on it delays every
/// later poll of the same branch.
pub const LS_REMOTE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a clone, fetch, or reset may take.
///
/// Generous, because the first clone of a real repository over a home connection
/// is measured in minutes.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long a post-pull build step may take.
///
/// The longest of the three: `npm ci` and `cargo build --release` are both here.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The largest amount of output kept from one command.
///
/// A build that prints a gigabyte would otherwise be held in memory in full, on
/// the way to a log ring that keeps five thousand lines of it.
const MAX_OUTPUT: usize = 256 * 1024;

/// What happened when a command ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// Its exit code, or `None` if a signal ended it.
    pub code: Option<i32>,
    /// Everything it wrote to standard output.
    pub stdout: String,
    /// Everything it wrote to standard error.
    pub stderr: String,
}

impl Ran {
    /// Whether the command reported success.
    pub fn succeeded(&self) -> bool {
        self.code == Some(0)
    }

    /// The most useful line it printed, for a one-line report.
    ///
    /// Prefers standard error, since that is where both `git` and a build step
    /// put the reason, and falls back to standard output so a command that
    /// explains itself there is not reported as having said nothing.
    pub fn complaint(&self) -> String {
        let text = if self.stderr.trim().is_empty() { &self.stdout } else { &self.stderr };
        match text.lines().map(str::trim).find(|line| !line.is_empty()) {
            Some(line) => line.to_owned(),
            None => match self.code {
                Some(code) => format!("exited with code {code}"),
                None => "was killed".to_owned(),
            },
        }
    }
}

/// Why a command produced no answer at all.
#[derive(Debug)]
pub enum RunError {
    /// The program is not installed, or not on the daemon's `PATH`.
    Missing {
        /// The program that could not be started.
        program: PathBuf,
        /// What the operating system said.
        reason: std::io::Error,
    },
    /// It was still running when its deadline passed, and was killed.
    TimedOut {
        /// How long it was given.
        after: Duration,
    },
    /// It started, but could not be waited for or read.
    Io(std::io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { program, reason } => write!(
                formatter,
                "cannot run {}: {reason}. Install it, or put it on the daemon's PATH",
                program.display()
            ),
            Self::TimedOut { after } => {
                write!(formatter, "gave up after {}s and killed it", after.as_secs())
            }
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Runs `git` with the given arguments and waits for it.
///
/// `in_dir` is where the process runs; the arguments built by
/// [`plan`](crate::plan) name their own working copy with `-C`, so this matters
/// only for a clone, which has none yet.
pub async fn git(args: &[String], in_dir: &Path, deadline: Duration) -> Result<Ran, RunError> {
    let mut command = Command::new("git");
    command.args(args).current_dir(in_dir);
    // Nothing here may ask a question: there is no terminal to answer it on.
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("GIT_ASKPASS", "");
    command.env("SSH_ASKPASS", "");
    command.env("GIT_SSH_COMMAND", ssh_command(std::env::var("GIT_SSH_COMMAND").ok().as_deref()));
    run(command, PathBuf::from("git"), deadline).await
}

/// The `GIT_SSH_COMMAND` a spawned `git` runs with.
///
/// The daemon's own environment is the operator's channel for ssh details a
/// deployment needs — a deploy key, a pinned `known_hosts` — so an inherited
/// value must survive, not be replaced. Batch mode is *appended* as a default:
/// ssh keeps the first value it reads for an option, so anything the operator
/// set explicitly, including `BatchMode=no`, still wins. Only when nothing is
/// inherited does plain `ssh` in batch mode stand alone.
fn ssh_command(inherited: Option<&str>) -> String {
    match inherited {
        Some(own) if !own.trim().is_empty() => format!("{own} -o BatchMode=yes"),
        _ => "ssh -o BatchMode=yes".to_string(),
    }
}

/// Runs a post-pull build step in the working copy.
///
/// Takes the program and its arguments already split, for the reason
/// [`ServiceSpec::args`](selfhost_config::ServiceSpec::args) gives: a single
/// string has to be word-split by somebody, and every implementation splits
/// quoting differently.
pub async fn build_step(
    command_line: &[String],
    in_dir: &Path,
    deadline: Duration,
) -> Result<Ran, RunError> {
    let (program, arguments) = match command_line.split_first() {
        Some(split) => split,
        // Refused at validation, so reaching this means a catalogue was edited by
        // hand past its own rules. Saying so beats running nothing and calling it
        // a successful build.
        None => {
            return Err(RunError::Io(std::io::Error::other(
                "the post-pull step names no program",
            )));
        }
    };

    let mut command = Command::new(program);
    command.args(arguments).current_dir(in_dir);
    command.env("GIT_TERMINAL_PROMPT", "0");
    run(command, PathBuf::from(program), deadline).await
}

/// Spawns a prepared command, captures its output, and enforces its deadline.
async fn run(
    mut command: Command,
    program: PathBuf,
    deadline: Duration,
) -> Result<Ran, RunError> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // The whole tree is killed on timeout, not just the direct child: a build
    // step is usually a wrapper, and killing `npm` while `node` keeps building
    // leaves the deployment racing a process nobody is waiting for any more.
    command.kill_on_drop(true);

    let mut child = command.spawn().map_err(|reason| RunError::Missing { program, reason })?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let collected = tokio::time::timeout(deadline, async {
        // Both pipes are drained while waiting. Waiting first would deadlock the
        // moment a command fills a pipe buffer, which a verbose build does in
        // well under a second.
        let (out, err, status) = tokio::join!(
            read_capped(&mut stdout),
            read_capped(&mut stderr),
            child.wait()
        );
        status.map(|status| (status.code(), out, err))
    })
    .await;

    match collected {
        Ok(Ok((code, stdout, stderr))) => Ok(Ran { code, stdout, stderr }),
        Ok(Err(error)) => Err(RunError::Io(error)),
        Err(_) => {
            let _ = child.kill().await;
            Err(RunError::TimedOut { after: deadline })
        }
    }
}

/// Reads a pipe to its end, keeping at most [`MAX_OUTPUT`] bytes of it.
///
/// Reading continues past the cap rather than stopping, because a reader that
/// stops leaves the writer blocked on a full pipe forever — the deadlock this
/// function exists to avoid.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(source: &mut Option<R>) -> String {
    let Some(source) = source.as_mut() else {
        return String::new();
    };

    let mut kept: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        match source.read(&mut scratch).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if kept.len() < MAX_OUTPUT {
                    let room = MAX_OUTPUT - kept.len();
                    kept.extend_from_slice(&scratch[..read.min(room)]);
                }
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ran(code: i32, stdout: &str, stderr: &str) -> Ran {
        Ran { code: Some(code), stdout: stdout.into(), stderr: stderr.into() }
    }

    #[test]
    fn success_is_exit_code_zero_and_nothing_else() {
        assert!(ran(0, "", "").succeeded());
        assert!(!ran(1, "", "").succeeded());
        assert!(!Ran { code: None, stdout: String::new(), stderr: String::new() }.succeeded());
    }

    #[test]
    fn an_inherited_ssh_command_survives_with_batch_mode_appended_after_it() {
        let key = "ssh -i /keys/deploy -o UserKnownHostsFile=/keys/known_hosts";
        assert_eq!(ssh_command(Some(key)), format!("{key} -o BatchMode=yes"));
        // ssh keeps the first value it reads, so an operator's explicit
        // BatchMode=no outranks the appended default.
        assert_eq!(
            ssh_command(Some("ssh -o BatchMode=no")),
            "ssh -o BatchMode=no -o BatchMode=yes"
        );
    }

    #[test]
    fn nothing_inherited_means_plain_ssh_in_batch_mode() {
        assert_eq!(ssh_command(None), "ssh -o BatchMode=yes");
        assert_eq!(ssh_command(Some("   ")), "ssh -o BatchMode=yes");
    }

    #[test]
    fn the_reason_comes_from_standard_error_when_there_is_one() {
        let failure = ran(128, "", "fatal: repository not found\nhint: check the URL\n");
        assert_eq!(failure.complaint(), "fatal: repository not found");
    }

    #[test]
    fn a_command_that_explains_itself_on_stdout_is_still_quoted() {
        assert_eq!(ran(1, "error: no such branch\n", "   \n").complaint(), "error: no such branch");
    }

    #[test]
    fn a_silent_failure_is_reported_by_its_code_rather_than_as_nothing() {
        assert_eq!(ran(3, "", "").complaint(), "exited with code 3");
        let killed = Ran { code: None, stdout: String::new(), stderr: String::new() };
        assert_eq!(killed.complaint(), "was killed");
    }

    #[tokio::test]
    async fn a_program_that_is_not_installed_says_so_and_says_where_to_put_it() {
        let error = build_step(
            &["selfhost-no-such-program".into()],
            Path::new("."),
            Duration::from_secs(5),
        )
        .await
        .expect_err("should not have started");
        assert!(matches!(error, RunError::Missing { .. }));
        assert!(error.to_string().contains("PATH"), "{error}");
    }

    #[tokio::test]
    async fn output_is_captured_from_both_streams() {
        let (program, args) = selfhost_supervisor::shell_command("echo out; echo err >&2; exit 2");
        let mut line = vec![program.display().to_string()];
        line.extend(args);

        let ran = build_step(&line, Path::new("."), Duration::from_secs(30))
            .await
            .expect("it ran");
        assert_eq!(ran.code, Some(2));
        assert!(ran.stdout.contains("out"), "{ran:?}");
        assert!(ran.stderr.contains("err"), "{ran:?}");
        assert!(!ran.succeeded());
    }

    #[tokio::test]
    async fn a_command_that_hangs_is_killed_rather_than_holding_the_service_down() {
        let (program, args) = selfhost_supervisor::shell_command("sleep 30");
        let mut line = vec![program.display().to_string()];
        line.extend(args);

        let error = build_step(&line, Path::new("."), Duration::from_millis(300))
            .await
            .expect_err("should have timed out");
        assert!(matches!(error, RunError::TimedOut { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_command_writing_far_more_than_the_cap_still_finishes() {
        // The deadlock this guards: a reader that stops at the cap leaves the
        // writer blocked on a full pipe, and the command never exits.
        let (program, args) = selfhost_supervisor::shell_command(
            "i=0; while [ $i -lt 4000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done",
        );
        let mut line = vec![program.display().to_string()];
        line.extend(args);

        let ran = build_step(&line, Path::new("."), Duration::from_secs(60))
            .await
            .expect("it ran");
        assert!(ran.succeeded());
        assert!(ran.stdout.len() <= MAX_OUTPUT, "kept {} bytes", ran.stdout.len());
    }

    #[tokio::test]
    async fn a_post_pull_step_naming_no_program_is_refused_rather_than_called_a_success() {
        let error = build_step(&[], Path::new("."), Duration::from_secs(5))
            .await
            .expect_err("nothing to run");
        assert!(matches!(error, RunError::Io(_)));
    }
}
