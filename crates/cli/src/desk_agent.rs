//! `selfhost desk-agent` — the process the daemon spawns into the console
//! session. **Not a command an operator runs.**
//!
//! # Why it is a subcommand of this binary at all
//!
//! On Windows the daemon is a Scheduled Task running as `SYSTEM` at system
//! startup, which puts it in session 0: a session with no interactive display,
//! where `DuplicateOutput` fails and `GetDC(NULL)` hands back a device context
//! for session 0's own blank desktop. Nothing the daemon can do to itself fixes
//! that. The pixels have to be captured by a process running *inside* the
//! session a person is sitting in, and the daemon starts one with
//! `CreateProcessAsUserW`.
//!
//! That process is this binary, invoked with this subcommand, for two reasons
//! that are both about deployment rather than taste: the box self-updates by
//! rebuilding one executable, so a second one would be a second thing that can
//! be stale or missing; and `CreateProcessAsUserW` is given an absolute
//! `lpApplicationName` — never a path search, which is a classic Windows
//! privilege-escalation surface — so the path it needs is one this process
//! already knows about itself.
//!
//! # Why it is not in `selfhost --help`
//!
//! Because there is nothing an operator can usefully do with it. It is a
//! machine-to-machine entry point whose whole contract is "the daemon started
//! me, in that session, and it is holding the other end of that pipe". Listing
//! it beside `doctor` and `site add` would invite somebody to run it, and the
//! honest outcome of running it by hand is a refusal — so the refusal is what it
//! prints, and it names the thing to run instead.
//!
//! # What actually stops it doing anything useful when it is run by hand
//!
//! **The pipe, and only the pipe.** `\\.\pipe\selfhost-desk-<session>` is
//! created by the daemon with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL naming
//! `SYSTEM` and the console user's SID, and the agent's first act is to open it.
//! No daemon, no pipe, and the agent exits within its connect deadline having
//! captured nothing and injected nothing. There is deliberately **no shared
//! secret** to check instead: a token in the environment block is readable by
//! any process of the same user, one on the command line is readable by every
//! process on the machine, and the ACL on a named object is the mechanism
//! Windows actually provides for this.
//!
//! Two cheaper refusals come first, so a person who ran this by mistake gets a
//! sentence rather than a ten-second wait: a missing `--session`, and a
//! `--session` that is not the one this process is actually in.
//!
//! # `--allow-input` is a capability the parent grants, not a secret
//!
//! The daemon puts `--allow-input` on this command line when
//! `[desktop].allow_input` is true, and without it the agent builds no injector
//! at all. That does not contradict the paragraph above: the flag authenticates
//! nothing and grants nothing on its own. Somebody who runs this by hand with the
//! flag gets a process that cannot reach the daemon's pipe, so nothing ever asks
//! it to type; and were it somehow handed input, it would be typing into its own
//! user's session as its own user, which is what a person at that keyboard can do
//! anyway. What the flag rules out is the case that matters — a *daemon-spawned*
//! agent holding an injector inside the console session in a deployment whose
//! operator switched input off.

/// The refusal every path here ends with, so the sentence exists once.
///
/// Names what to run instead. An operator who reached this line was looking for
/// the daemon, or for the switch that turns the desktop off.
const NOT_FOR_HUMANS: &str = "\
`selfhost desk-agent` is started by the selfhost daemon, inside the session a
person is signed into, and it talks to the daemon over a named pipe that only
the daemon can create. Running it by hand does nothing.

  selfhost daemon           start the daemon, which starts this when it needs to
  selfhost desktop status   whether remote desktop is on, and what it can see";

/// Runs the agent, or explains why it will not.
///
/// `arguments` is the whole argv tail, `arguments[0]` being `desk-agent`, which
/// is the shape every other command in this binary takes.
pub fn run(arguments: &[String]) -> Result<(), String> {
    let session = match crate::value_of(arguments, "--session") {
        Some(given) => given
            .parse::<u32>()
            .map_err(|error| format!("--session {given}: {error}\n\n{NOT_FOR_HUMANS}"))?,
        // No session means nobody chose one, which means nobody spawned this.
        None => return Err(NOT_FOR_HUMANS.to_owned()),
    };
    run_in_session(session, arguments)
}

/// The Windows body: check the session, then hand over to the agent itself.
///
/// The session check is not redundant with the pipe. The daemon aims an agent at
/// the session that was on the console when it decided to spawn, and a fast user
/// switch between that decision and this process starting would leave an agent
/// answering for a session it is not in — capturing one person's screen under
/// another person's name. The pipe cannot catch that: its DACL is built around
/// the *intended* session's user, and after a switch this process may still be
/// that user.
///
/// The rest of the argument vector is carried through rather than discarded
/// because `[desktop].allow_input` reaches this process on it, and only on it:
/// `selfhost_screen::agent::AgentOptions::from_arguments` reads the one flag that
/// grants an injector — fail-closed, so an argv this build does not recognise is a
/// view-only agent. See `selfhost_screen::agent::InputPolicy` for why the switch
/// travels here and not over the pipe.
#[cfg(windows)]
fn run_in_session(session: u32, arguments: &[String]) -> Result<(), String> {
    use selfhost_screen::agent::{run, AgentOptions};

    match selfhost_screen::windows::gdi::current_session() {
        Some(mine) if mine == session => {}
        Some(mine) => {
            return Err(format!(
                "the daemon aimed this agent at session {session} and it started in session \
                 {mine}, so the console changed hands while it was starting. Exiting rather \
                 than capturing a session it was not sent to."
            ));
        }
        // Not knowing which session this is means not being able to prove the
        // agent belongs where it was sent, and this is the one process in the
        // deployment that must never guess.
        None => {
            return Err(
                "cannot read which session this process is in, so it cannot prove it belongs \
                 in the one the daemon aimed it at. Exiting."
                    .to_owned(),
            );
        }
    }

    run(AgentOptions::from_arguments(session, arguments))
        .map_err(|fault| format!("the desktop agent stopped: {fault}"))
}

/// Everywhere else there is no agent, because there is no session-0 problem to
/// solve and no capture backend to solve it with.
///
/// A refusal rather than a silent success: a daemon that somehow spawned this on
/// a platform it was never meant for must see a non-zero exit and stop trying,
/// not a process that returns cleanly and looks like it worked.
#[cfg(not(windows))]
fn run_in_session(session: u32, _arguments: &[String]) -> Result<(), String> {
    Err(format!(
        "there is no desktop agent on this platform: the agent exists to reach an interactive \
         session from a service running in Windows session 0, and nothing here has that problem. \
         (asked for session {session})\n\n{NOT_FOR_HUMANS}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_session_argument_is_refused_without_touching_anything() {
        let arguments = vec!["desk-agent".to_owned()];
        let refusal = run(&arguments).expect_err("a bare invocation is refused");
        assert!(
            refusal.contains("selfhost daemon"),
            "the refusal names what to run instead: {refusal}"
        );
    }

    #[test]
    fn a_session_that_is_not_a_number_is_refused() {
        let arguments = vec!["desk-agent".to_owned(), "--session".to_owned(), "console".to_owned()];
        let refusal = run(&arguments).expect_err("a malformed session is refused");
        assert!(refusal.contains("--session console"), "the refusal quotes what was given");
    }

    /// On a platform with no agent the refusal must be a refusal, whatever
    /// session was asked for — a clean exit would look to a supervisor like a
    /// run that finished.
    #[cfg(not(windows))]
    #[test]
    fn a_platform_without_an_agent_refuses_rather_than_succeeding() {
        let arguments = vec!["desk-agent".to_owned(), "--session".to_owned(), "1".to_owned()];
        let refusal = run(&arguments).expect_err("there is no agent here");
        assert!(refusal.contains("session 1"));
    }
}
