//! Running one firewall command to completion and reporting what it said.
//!
//! The thin, impure floor the backends stand on — everything that decides *what*
//! to run lives in [`rule`](crate::rule) and each backend's pure script builder;
//! this module owns only the process. It copies [`selfhost_git`](../../selfhost_git/index.html)'s
//! `run` deliberately: a deadline and a muzzle on every invocation, because a
//! `pfctl`/`nft`/`netsh` that hangs would hold daemon start-up down, and one that
//! asks a question at a terminal that is not there would hang forever.

use crate::backend::FirewallError;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// How long any one firewall command may take.
///
/// Short: each is a single local operation on a ruleset. A command still running
/// after this is treated as hung and killed, because a firewall that could not be
/// read or set is better reported than waited on.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// The largest amount of output kept from one command.
const MAX_OUTPUT: usize = 64 * 1024;

/// What happened when a firewall command ran.
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

    /// Turns a non-success into the firewall error that best explains it.
    ///
    /// A refusal for want of privilege is reported as [`FirewallError::Denied`] —
    /// the daemon's most common firewall failure, and one with a specific fix
    /// (run it with the privilege to set the firewall) — and every other refusal
    /// as [`FirewallError::Command`] carrying the tool's own most useful line.
    pub fn ok_or_error(self, program: &str) -> Result<Ran, FirewallError> {
        if self.succeeded() {
            return Ok(self);
        }
        let detail = self.complaint();
        if looks_denied(&detail) {
            Err(FirewallError::Denied { program: program.to_owned() })
        } else {
            Err(FirewallError::Command { program: program.to_owned(), code: self.code, detail })
        }
    }
}

/// Whether a tool's complaint reads as "you lack the privilege for this".
fn looks_denied(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "permission denied",
        "operation not permitted",
        "must be run as root",
        "must be root",
        "requires root",
        "access is denied",
        "requires elevation",
        "run as administrator",
        "requested operation requires elevation",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Runs a firewall tool, optionally feeding it a ruleset on standard input.
///
/// `stdin_body` is how `pfctl -f -` and `nft -f -` receive a ruleset: the whole
/// small script is written and the pipe closed so the tool sees end-of-input.
/// Bodies are a handful of rules, well under a pipe buffer, so writing before
/// draining output cannot deadlock the way a streamed build could.
pub async fn run(
    program: &str,
    args: &[String],
    stdin_body: Option<&str>,
    deadline: Duration,
) -> Result<Ran, FirewallError> {
    let mut command = Command::new(program);
    command.args(args);
    command.stdin(if stdin_body.is_some() { Stdio::piped() } else { Stdio::null() });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    let mut child = command.spawn().map_err(|reason| {
        if reason.kind() == std::io::ErrorKind::NotFound {
            FirewallError::ToolMissing { program: PathBuf::from(program), reason }
        } else {
            FirewallError::Io(reason)
        }
    })?;

    if let Some(body) = stdin_body
        && let Some(mut stdin) = child.stdin.take()
    {
        // Ignoring a broken pipe here is deliberate: a tool that rejected its
        // input and exited before reading it all still has a complaint to
        // capture below, which is more useful than a write error here.
        let _ = stdin.write_all(body.as_bytes()).await;
        // Dropped at the end of this block, closing the pipe so the tool reads EOF.
    }

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
        Ok(Err(error)) => Err(FirewallError::Io(error)),
        Err(_) => {
            let _ = child.kill().await;
            Err(FirewallError::Command {
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
    fn a_privilege_refusal_is_reported_as_denied_with_its_fix() {
        let error = ran(1, "", "pfctl: Operation not permitted").ok_or_error("pfctl").unwrap_err();
        assert!(matches!(error, FirewallError::Denied { .. }), "{error}");
        assert!(error.to_string().contains("privilege"), "{error}");
    }

    #[test]
    fn any_other_refusal_carries_the_tools_own_line() {
        let error = ran(1, "", "nft: syntax error, unexpected newline").ok_or_error("nft").unwrap_err();
        match error {
            FirewallError::Command { detail, .. } => assert!(detail.contains("syntax error"), "{detail}"),
            other => panic!("expected a command error, got {other}"),
        }
    }

    #[test]
    fn a_clean_run_is_passed_through() {
        assert!(ran(0, "ok", "").ok_or_error("pfctl").is_ok());
    }

    #[tokio::test]
    async fn a_tool_that_is_not_installed_says_so_rather_than_hanging() {
        let error = run("selfhost-no-such-firewall-tool", &[], None, Duration::from_secs(5))
            .await
            .expect_err("should not have started");
        assert!(matches!(error, FirewallError::ToolMissing { .. }), "{error}");
    }
}
