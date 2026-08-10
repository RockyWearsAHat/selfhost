//! The Windows session-0 plan: the pure half here, the FFI in the submodules.
//!
//! # The problem this module exists to solve
//!
//! On the production box the daemon is a Scheduled Task running as `SYSTEM` at
//! system startup, which puts it in **session 0** — a session with no
//! interactive display, created for services precisely so that services cannot
//! be reached by the person at the keyboard. Nothing running there can capture
//! the user's desktop. `DuplicateOutput` fails; `GetDC(NULL)` returns a device
//! context for session 0's own blank desktop and blits black pixels from it all
//! day without reporting an error. The fix is not a privilege or a flag: it is a
//! second process, running inside the console session, that the daemon starts and
//! talks to. Building that first, before any capture code exists, is the whole
//! shape of this phase.
//!
//! The sequence, each step of which is load-bearing:
//!
//! 1. `WTSGetActiveConsoleSessionId` — which session is on the physical console.
//!    `0xFFFFFFFF` means *ask again*, not *error*.
//! 2. `WTSQueryUserToken` — the console user's token. Needs `LocalSystem` and
//!    `SE_TCB_NAME`, which the daemon has. `ERROR_NO_TOKEN` means nobody is
//!    logged in, which is a state and not a failure.
//! 3. `DuplicateTokenEx` to a *primary* token, because `CreateProcessAsUserW`
//!    will not take an impersonation token.
//! 4. `CreateEnvironmentBlock` — **mandatory**. Without it the agent inherits
//!    `SYSTEM`'s `APPDATA`, `TEMP` and `USERPROFILE` and writes into the service
//!    profile while appearing to run as the user.
//! 5. `STARTUPINFOW.lpDesktop = "winsta0\\default"` — **mandatory**. Without it
//!    the process lands on a non-interactive desktop where it is running, is
//!    invisible, and can capture nothing.
//! 6. `CreateProcessAsUserW` with `bInheritHandles = FALSE`, because handles
//!    cannot be inherited across sessions — which is *why* the IPC has to be a
//!    named object rather than an inherited pipe.
//!
//! # Why the pure half lives up here
//!
//! Three of the decisions in that sequence are strings, and all three are
//! security-critical: the pipe's name, the pipe's DACL, and the command line. A
//! wrong DACL is a keyboard that any local process can drive. So they are built
//! by pure functions in this file, which compiles on **every** platform and is
//! therefore tested on the developer's Mac, where the rest of this module cannot
//! even be compiled. The submodules below hold the `unsafe` and are Windows-only.
//!
//! # The pipe's ACL is the authentication
//!
//! There is no shared secret between daemon and agent, and deliberately so.
//! `\\.\pipe\selfhost-desk-<sessionId>` is created with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` and an explicit DACL naming only `SYSTEM` and
//! the console user's own SID — never a NULL DACL, which grants everyone
//! everything. A loopback TCP socket with a token in the environment block was
//! considered and rejected outright: a loopback listener is reachable by every
//! local process, a same-user process can read another process's environment
//! block, and the resulting exposure is the operator's remote keystrokes plus a
//! race to become the screen source.

use std::fmt;
use std::path::Path;

#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod spawn;
#[cfg(windows)]
pub(crate) mod sys;

/// The prefix every agent pipe name shares.
///
/// Local (`\\.\`) rather than a network path: a pipe reachable over SMB would be
/// a keyboard reachable from the LAN, which no ACL should be the only thing
/// standing in front of.
pub const PIPE_PREFIX: &str = r"\\.\pipe\selfhost-desk-";

/// The window station and desktop an interactive process must be started on.
///
/// Spelled here rather than at the call site because getting it wrong produces a
/// process that starts, runs, reports no error and is invisible — the single
/// hardest failure in this module to recognise from a log.
pub const INTERACTIVE_DESKTOP: &str = r"winsta0\default";

/// Something the plan refused to build.
///
/// All three are refusals of *input* rather than platform failures, which is why
/// they are not [`crate::Fault`]: nothing was called yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A security identifier that is not in the form `S-1-…`.
    ///
    /// The SID reaching this function comes from `ConvertSidToStringSidW` and is
    /// therefore already trustworthy — the check is defence in depth. It matters
    /// because the SID is *concatenated into an SDDL string*: a value containing
    /// `)(A;;FA;;;WD` would append an access-control entry granting Everyone full
    /// access to the pipe that drives the keyboard, and the resulting descriptor
    /// would parse perfectly.
    MalformedSid {
        /// What was offered, so the operator can see it.
        offered: String,
    },
    /// A string destined for a Win32 wide string contained a NUL.
    ///
    /// Refused rather than truncated: a truncated path is a different file, and a
    /// truncated command line is different arguments.
    InteriorNul {
        /// Which string it was.
        field: &'static str,
    },
    /// An executable path with nothing in it.
    NoExecutable,
}

impl PlanError {
    /// The refusal as one sentence.
    pub fn sentence(&self) -> String {
        match self {
            Self::MalformedSid { offered } => format!(
                "Refusing to build a security descriptor around {offered:?}, which is not a \
                 well-formed security identifier."
            ),
            Self::InteriorNul { field } => {
                format!("The {field} contains a NUL character and cannot be passed to Windows.")
            }
            Self::NoExecutable => "No agent executable was given to start.".to_owned(),
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for PlanError {}

/// The pipe the agent for `session` connects to.
///
/// Named per session rather than once per machine, so that two sessions — the
/// console and an RDP session mid-switch — cannot collide on one object, and so
/// that a stale agent from the previous session cannot answer for the new one.
pub fn pipe_name(session: u32) -> String {
    format!("{PIPE_PREFIX}{session}")
}

/// The security descriptor the agent pipe is created under.
///
/// `D:P(A;;FA;;;SY)(A;;FRFW;;;<user>)`:
///
/// - `D:` a discretionary ACL, and `P` for **protected** — no access-control
///   entry is inherited from anywhere, so the descriptor says exactly what it
///   says and nothing the containing object grants leaks in.
/// - `(A;;FA;;;SY)` full access for `LocalSystem`, which is what the daemon runs
///   as and therefore what has to create, listen on and tear down the pipe.
/// - `(A;;FRFW;;;<user>)` read and write — and nothing else — for the console
///   user's own SID. Not `FA`: full access includes `WRITE_DAC`, and an agent
///   that can rewrite the descriptor of its own channel can open that channel to
///   anybody. The agent needs to read and write bytes; that is all it gets.
///
/// Nobody else is named, and the absence of a `WD` (Everyone) entry is the whole
/// security property: a same-user process at the same integrity level *is* still
/// admitted, which is inherent — Windows has no way to distinguish two processes
/// of one user on a pipe — and is why `FILE_FLAG_FIRST_PIPE_INSTANCE` and the
/// client-identity check in the `pipe` submodule both exist alongside this.
///
/// Modelled on `crates/admin/src/token.rs`'s `SECRET_DACL`, which protects the
/// deployment's root credential with the same protected-DACL shape.
pub fn pipe_descriptor(user_sid: &str) -> Result<String, PlanError> {
    if !is_well_formed_sid(user_sid) {
        return Err(PlanError::MalformedSid { offered: user_sid.to_owned() });
    }
    Ok(format!("D:P(A;;FA;;;SY)(A;;FRFW;;;{user_sid})"))
}

/// The longest a string-form SID can be, from the format's own limits.
///
/// A SID holds at most 15 sub-authorities; the string form is `S-1-` plus a
/// 48-bit identifier authority plus those, each up to ten digits with a
/// separator. 184 is the documented ceiling and is used here so that a
/// pathologically long value is refused before it is measured against a pattern.
const MAX_SID_TEXT: usize = 184;

/// Whether a string is a well-formed string-form security identifier.
///
/// Strict on purpose: `S-1-` then decimal components separated by single hyphens,
/// nothing else, no leading or trailing hyphen, no empty component, no letters.
/// Windows also accepts a hexadecimal identifier authority and two-letter
/// abbreviations such as `BA`, and this function accepts neither — the value we
/// pass always comes from `ConvertSidToStringSidW`, which produces the decimal
/// form, and every character we do not accept is a character that cannot appear
/// inside an SDDL access-control entry we did not write.
pub fn is_well_formed_sid(text: &str) -> bool {
    if text.len() > MAX_SID_TEXT || !text.is_ascii() {
        return false;
    }
    let Some(rest) = text.strip_prefix("S-1-") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('-').all(|component| {
        !component.is_empty()
            && component.len() <= 20
            && component.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Builds the writable `lpCommandLine` `CreateProcessAsUserW` needs.
///
/// Windows does not take an argument vector: it takes one string that the child
/// parses back apart, and the rules for doing so are the ones `CommandLineToArgvW`
/// implements — quotes around anything containing whitespace, backslashes doubled
/// only where they precede a quote. Getting them wrong does not fail; it starts
/// the agent with different arguments than intended, which for a process that is
/// handed a session id and a pipe name means it connects to the wrong object or
/// to none.
///
/// The executable is repeated as the first element, as `argv[0]`, because
/// `lpApplicationName` is passed separately and non-NULL — the documented way to
/// avoid Windows' path-searching heuristics, which will happily run
/// `C:\Program.exe` for an unquoted `C:\Program Files\…`.
pub fn command_line(executable: &Path, arguments: &[&str]) -> Result<String, PlanError> {
    let program = executable.to_string_lossy();
    if program.is_empty() {
        return Err(PlanError::NoExecutable);
    }
    if program.contains('\0') {
        return Err(PlanError::InteriorNul { field: "agent executable path" });
    }

    let mut line = String::new();
    append_argument(&mut line, &program);
    for argument in arguments {
        if argument.contains('\0') {
            return Err(PlanError::InteriorNul { field: "agent argument" });
        }
        line.push(' ');
        append_argument(&mut line, argument);
    }
    Ok(line)
}

/// Appends one argument, quoted by `CommandLineToArgvW`'s rules.
fn append_argument(line: &mut String, argument: &str) {
    let needs_quotes = argument.is_empty()
        || argument.chars().any(|character| matches!(character, ' ' | '\t' | '"'));
    if !needs_quotes {
        line.push_str(argument);
        return;
    }

    line.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                line.push('\\');
            }
            '"' => {
                // A quote is escaped by one backslash, and every backslash
                // immediately before it must itself be doubled — so the run of
                // `backslashes` already written needs that many more, plus one.
                for _ in 0..=backslashes {
                    line.push('\\');
                }
                line.push('"');
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                line.push(other);
            }
        }
    }
    // Backslashes at the very end sit immediately before the closing quote and
    // must be doubled too, or the quote is escaped and the argument runs on.
    for _ in 0..backslashes {
        line.push('\\');
    }
    line.push('"');
}

/// Which desktop is receiving input in the interactive session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDesktop {
    /// The ordinary interactive desktop, where the user's programs live.
    Default,
    /// `Winlogon`: the secure desktop. A UAC consent dialog, the lock screen, or
    /// the credential provider. Never captured and input suspends here — a
    /// channel that could both render and drive the consent dialog would be a
    /// remote privilege-escalation channel by construction.
    Secure,
    /// The screen saver's own desktop.
    ScreenSaver,
    /// A desktop this build does not recognise, named so the operator can see it
    /// rather than being told "unknown".
    Other(String),
}

impl InputDesktop {
    /// Whether the screen may be captured and input performed here.
    pub fn is_capturable(&self) -> bool {
        matches!(self, Self::Default)
    }
}

/// Classifies a desktop by the name `GetUserObjectInformationW` reported.
///
/// Case-insensitive because the platform's own spelling has varied across
/// releases and a comparison that depends on it would break silently — into
/// "unrecognised desktop", which suspends a session that should be live.
pub fn classify_desktop(name: &str) -> InputDesktop {
    if name.eq_ignore_ascii_case("Default") {
        InputDesktop::Default
    } else if name.eq_ignore_ascii_case("Winlogon") {
        InputDesktop::Secure
    } else if name.eq_ignore_ascii_case("Screen-saver") || name.eq_ignore_ascii_case("Screensaver")
    {
        InputDesktop::ScreenSaver
    } else {
        InputDesktop::Other(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_pipe_is_named_per_session() {
        // Per session so a stale agent from the session that just went away
        // cannot answer for the one that replaced it.
        assert_eq!(pipe_name(1), r"\\.\pipe\selfhost-desk-1");
        assert_ne!(pipe_name(1), pipe_name(2));
        assert!(pipe_name(0).starts_with(r"\\.\pipe\"), "must be a local pipe, never a UNC path");
    }

    #[test]
    fn the_descriptor_names_system_and_the_console_user_and_nobody_else() {
        let sddl = pipe_descriptor("S-1-5-21-1004336348-1177238915-682003330-1001").unwrap();
        assert_eq!(
            sddl,
            "D:P(A;;FA;;;SY)(A;;FRFW;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
        );
        assert!(sddl.starts_with("D:P"), "the DACL must be protected against inheritance");
        assert!(!sddl.contains(";;;WD"), "Everyone must never appear");
        assert!(!sddl.contains(";;;AU"), "Authenticated Users must never appear");
        assert!(!sddl.contains("(A;;FA;;;S-1-5-21"), "the user gets read and write, not full access");
    }

    #[test]
    fn a_sid_that_could_smuggle_an_extra_ace_is_refused() {
        // The attack this check exists for: the SID is concatenated into SDDL, so
        // a value carrying its own access-control entry would be granted.
        let hostile = "S-1-5-21-1)(A;;FA;;;WD";
        assert_eq!(
            pipe_descriptor(hostile),
            Err(PlanError::MalformedSid { offered: hostile.to_owned() })
        );
        for bad in [
            "",
            "BA",
            "S-1-",
            "S-1--5",
            "S-1-5-",
            "-S-1-5-21-1",
            "S-1-0x5-21",
            "s-1-5-21-1",
            "S-1-5-21-1 ",
            "S-1-5-21-1;;",
            "S-1-5-21-99999999999999999999999",
        ] {
            assert!(
                pipe_descriptor(bad).is_err(),
                "{bad:?} should not have produced a descriptor"
            );
        }
    }

    #[test]
    fn ordinary_sids_are_accepted() {
        for good in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-1004336348-1177238915-682003330-1001",
        ] {
            assert!(is_well_formed_sid(good), "{good} should be well formed");
        }
    }

    #[test]
    fn an_absurdly_long_sid_is_refused_before_it_is_parsed() {
        let long = format!("S-1-5-21-{}", "1-".repeat(200));
        assert!(!is_well_formed_sid(&long));
    }

    #[test]
    fn a_plain_command_line_repeats_the_executable_as_argv_zero() {
        // `lpApplicationName` is non-NULL, so the first token of the command line
        // is argv[0] and not the thing Windows runs — but it still has to be
        // there or the agent reads its own first argument as its program name.
        let line = command_line(&PathBuf::from(r"C:\Selfhost\selfhost.exe"), &["desk-agent"])
            .unwrap();
        assert_eq!(line, r"C:\Selfhost\selfhost.exe desk-agent");
    }

    #[test]
    fn a_path_with_spaces_is_quoted() {
        // Unquoted, Windows would try `C:\Program.exe` first. That is a
        // privilege-escalation classic and it is why `lpApplicationName` is also
        // passed separately.
        let line =
            command_line(&PathBuf::from(r"C:\Program Files\Selfhost\selfhost.exe"), &["desk-agent"])
                .unwrap();
        assert_eq!(line, "\"C:\\Program Files\\Selfhost\\selfhost.exe\" desk-agent");
    }

    #[test]
    fn arguments_are_quoted_by_the_rules_the_child_parses_them_by() {
        let exe = PathBuf::from(r"C:\a.exe");
        assert_eq!(command_line(&exe, &["a b"]).unwrap(), r#"C:\a.exe "a b""#);
        assert_eq!(command_line(&exe, &[""]).unwrap(), r#"C:\a.exe """#);
        assert_eq!(command_line(&exe, &[r#"a"b"#]).unwrap(), r#"C:\a.exe "a\"b""#);
        // A trailing backslash inside quotes must be doubled or it escapes the
        // closing quote and the argument swallows the next one.
        assert_eq!(command_line(&exe, &[r"a b\"]).unwrap(), r#"C:\a.exe "a b\\""#);
        // Backslashes not before a quote are left alone.
        assert_eq!(command_line(&exe, &[r"C:\x\y"]).unwrap(), r"C:\a.exe C:\x\y");
        assert_eq!(command_line(&exe, &[r#"C:\x\"y"#]).unwrap(), r#"C:\a.exe "C:\x\\\"y""#);
    }

    #[test]
    fn a_nul_anywhere_is_refused_rather_than_truncating_the_command_line() {
        let exe = PathBuf::from(r"C:\a.exe");
        assert_eq!(
            command_line(&exe, &["desk-agent\0--pipe"]),
            Err(PlanError::InteriorNul { field: "agent argument" })
        );
        assert_eq!(command_line(&PathBuf::from(""), &[]), Err(PlanError::NoExecutable));
    }

    #[test]
    fn the_secure_desktop_is_recognised_however_windows_spells_it() {
        assert_eq!(classify_desktop("Winlogon"), InputDesktop::Secure);
        assert_eq!(classify_desktop("WINLOGON"), InputDesktop::Secure);
        assert!(!classify_desktop("Winlogon").is_capturable());
        assert_eq!(classify_desktop("Default"), InputDesktop::Default);
        assert!(classify_desktop("default").is_capturable());
        assert_eq!(classify_desktop("Screen-saver"), InputDesktop::ScreenSaver);
        assert!(!classify_desktop("Screen-saver").is_capturable());
    }

    #[test]
    fn an_unrecognised_desktop_is_named_rather_than_called_unknown() {
        assert_eq!(
            classify_desktop("Some-Other-Desktop"),
            InputDesktop::Other("Some-Other-Desktop".to_owned())
        );
        assert!(!classify_desktop("Some-Other-Desktop").is_capturable());
    }
}
