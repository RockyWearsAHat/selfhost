//! Running one SMB tool to completion and reporting what it said.
//!
//! The thin, impure floor the three backends stand on. Everything that decides
//! *what* to run lives in [`plan`](crate::smb::plan) and in each backend's pure
//! argument builder; this module owns only the process, and it is deliberately a
//! copy of [`selfhost_firewall::run`](../../../../selfhost_firewall/run/index.html)
//! rather than a shared crate — the two subsystems run different tools with
//! different denial wording, and the thing worth sharing between them is the
//! discipline, which is three lines long:
//!
//! - **a deadline on every invocation**, because `sharing` waiting on the
//!   `opendirectoryd` that is wedged, or a PowerShell that decided to load a
//!   profile off a dead network drive, would otherwise hold daemon start-up down
//!   for as long as the machine stays up;
//! - **`kill_on_drop`**, so a cancelled reconcile does not leave a half-run
//!   `New-SmbShare` behind;
//! - **`Stdio::null()` on standard input**, because a tool that asks a question
//!   at a terminal that is not there waits forever rather than failing.
//!
//! The one addition over the firewall's copy is [`Ran::ok_or_error`]'s
//! `privilege` argument: an SMB tool that refuses for want of privilege needs to
//! name *which* privilege, because the answer differs per platform — root on
//! macOS, an elevated shell on Windows, write access to `/etc/samba` on Linux —
//! and "run it as an administrator" is not advice a Linux operator can act on.

use crate::smb::SmbError;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// How long any one SMB command may take.
///
/// The same twenty seconds the firewall allows, and for the same reason: each
/// invocation is a single local operation on a share table. A command still
/// running after this is treated as hung and killed, because an SMB export that
/// could not be read or set is better reported than waited on.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// The largest amount of output kept from one command.
///
/// `Get-SmbShare | ConvertTo-Json` on a file server with many shares is the only
/// output here that grows with the deployment, and 64 KiB is far past any real
/// share table.
const MAX_OUTPUT: usize = 64 * 1024;

/// What happened when an SMB command ran.
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

    /// Turns a non-success into the SMB error that best explains it.
    ///
    /// A refusal for want of privilege becomes [`SmbError::Denied`] carrying
    /// `privilege` — the platform's own word for what is missing — because that
    /// is by far the most common way an SMB reconcile fails on a daemon that
    /// runs unprivileged, and it is the one failure with a specific fix. Every
    /// other refusal becomes [`SmbError::Command`] carrying the tool's own most
    /// useful line, never a sentence invented here.
    pub fn ok_or_error(self, program: &str, privilege: &'static str) -> Result<Ran, SmbError> {
        if self.succeeded() {
            return Ok(self);
        }
        let detail = self.complaint();
        if looks_denied(&detail) {
            Err(SmbError::Denied { program: program.to_owned(), privilege })
        } else {
            Err(SmbError::Command { program: program.to_owned(), code: self.code, detail })
        }
    }
}

/// Whether a tool's complaint reads as "you lack the privilege for this".
///
/// The macOS list is longer than the firewall's because `sharing` reports a
/// privilege failure through `opendirectoryd`, whose wording is neither
/// `errno`'s nor its own; the Windows list covers both `icacls` and the
/// `SmbShare` cmdlets, which disagree with each other.
fn looks_denied(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "permission denied",
        "operation not permitted",
        "not permitted",
        "must be run as root",
        "must be root",
        "requires root",
        "insufficient privileges",
        "access is denied",
        "access denied",
        "requires elevation",
        "run as administrator",
        "requested operation requires elevation",
        "administrator privilege",
        "authorizationexecutewithprivileges",
        "eaccess",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Runs an SMB tool with a deadline, returning what it said.
///
/// `env` carries the values that must **not** appear in the command text. On
/// Windows every mutating step is a fixed PowerShell script that reads its share
/// name and directory from the environment, so no operator-supplied string is
/// ever concatenated into a script; see [`crate::smb::windows`]. On the other two
/// platforms it is empty, because their tools take real arguments.
///
/// Standard input is `/dev/null` unconditionally: nothing this module runs has
/// anything to read, and a tool that decides to prompt should fail rather than
/// hang.
pub async fn run(
    program: &str,
    args: &[impl AsRef<OsStr>],
    env: &[(&str, &OsStr)],
    deadline: Duration,
) -> Result<Ran, SmbError> {
    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    let mut child = command.spawn().map_err(|reason| {
        if reason.kind() == std::io::ErrorKind::NotFound {
            SmbError::ToolMissing { program: PathBuf::from(program), reason }
        } else {
            SmbError::Io(reason)
        }
    })?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let collected = tokio::time::timeout(deadline, async {
        let (out, err, status) =
            tokio::join!(read_capped(&mut stdout), read_capped(&mut stderr), child.wait());
        status.map(|status| (status.code(), out, err))
    })
    .await;

    match collected {
        Ok(Ok((code, stdout, stderr))) => Ok(Ran { code, stdout, stderr }),
        Ok(Err(error)) => Err(SmbError::Io(error)),
        Err(_) => {
            // The child is killed explicitly rather than left to `kill_on_drop`,
            // so the process is gone before this function returns and a caller
            // that immediately retries cannot race its predecessor.
            let _ = child.kill().await;
            Err(SmbError::Command {
                program: program.to_owned(),
                code: None,
                detail: format!("timed out after {}s and was killed", deadline.as_secs()),
            })
        }
    }
}

/// Reads a pipe to its end, keeping at most [`MAX_OUTPUT`] bytes.
///
/// Reading continues past the cap rather than stopping, so the writer is never
/// left blocked on a full pipe — the deadlock this exists to avoid.
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
    fn a_privilege_refusal_names_the_privilege_the_platform_actually_wants() {
        let error = ran(1, "", "sharing: Operation not permitted")
            .ok_or_error("sharing", "root")
            .expect_err("a refusal");
        match &error {
            SmbError::Denied { privilege, .. } => assert_eq!(*privilege, "root"),
            other => panic!("expected a denial, got {other}"),
        }
        assert!(error.to_string().contains("root"), "{error}");
    }

    #[test]
    fn windows_and_linux_denials_are_recognised_too() {
        for text in ["Access is denied.", "Requested operation requires elevation."] {
            let error =
                ran(1, "", text).ok_or_error("powershell", "an elevated shell").expect_err("denial");
            assert!(matches!(error, SmbError::Denied { .. }), "{text}: {error}");
        }
    }

    #[test]
    fn any_other_refusal_carries_the_tools_own_line() {
        let error = ran(255, "", "sharing: no such share point 'Vault'")
            .ok_or_error("sharing", "root")
            .expect_err("a refusal");
        match error {
            SmbError::Command { detail, .. } => {
                assert!(detail.contains("no such share point"), "{detail}");
            }
            other => panic!("expected a command error, got {other}"),
        }
    }

    #[test]
    fn a_clean_run_is_passed_through() {
        assert!(ran(0, "{}", "").ok_or_error("sharing", "root").is_ok());
    }

    #[tokio::test]
    async fn a_tool_that_is_not_installed_says_so_rather_than_hanging() {
        let error = run(
            "selfhost-no-such-smb-tool",
            &[] as &[&str],
            &[],
            Duration::from_secs(5),
        )
        .await
        .expect_err("should not have started");
        assert!(matches!(error, SmbError::ToolMissing { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_tool_that_hangs_is_killed_at_the_deadline_rather_than_waited_on() {
        // `sleep 30` against a 200 ms deadline: the point is that this test
        // finishes, and that the error says the command was killed rather than
        // pretending it succeeded.
        let program = if cfg!(windows) { "timeout" } else { "sleep" };
        let outcome = run(program, &["30"], &[], Duration::from_millis(200)).await;
        match outcome {
            Err(SmbError::Command { detail, .. }) => {
                assert!(detail.contains("timed out"), "{detail}");
            }
            // A host without the sleep tool at all is a missing-tool error, which
            // is also an honest answer and must not fail the suite.
            Err(SmbError::ToolMissing { .. }) => {}
            other => panic!("expected a timeout or a missing tool, got {other:?}"),
        }
    }
}
