//! A platform call that did not do what it was asked.
//!
//! Every `unsafe` block in this crate ends in one of two places: a value, or a
//! [`Fault`]. There is no third option and deliberately no `unwrap`, because the
//! workspace builds with `panic = "abort"` and this crate's code runs inside the
//! daemon that also serves 80/443, mail and the certificate store on a machine
//! that rebuilds and restarts itself from a `git push` with nobody watching. A
//! panic here is not a stack trace in a terminal; it is the whole box going away
//! until somebody notices.
//!
//! # Why the type carries the call name
//!
//! `io::Error` alone answers *what went wrong* and never *what we were doing*.
//! `ERROR_ACCESS_DENIED` from `WTSQueryUserToken` means the daemon is not running
//! as `LocalSystem`; the identical code from `CreateNamedPipeW` means somebody
//! else already owns the pipe name. Those are two entirely different operator
//! actions, and a diagnostic that collapses them into "Access is denied (os error
//! 5)" sends the operator looking in the wrong place. So the call's own name
//! travels with the code, and [`Fault::sentence`] renders both.
//!
//! This module is compiled on every platform, is free of `unsafe` and of any
//! platform-conditional item, and is the one type the pure half and the FFI half
//! of this crate share. That is also what makes the Windows arm type-checkable on
//! a machine that cannot build it: the extraction harness needs this file and
//! nothing else from the crate root.

use std::borrow::Cow;
use std::fmt;

/// A named platform call that failed, with whatever the platform said about it.
///
/// Cheap to build from a `&'static str` and only allocates when a caller has
/// something to add that is not known at compile time — which matters because
/// the retry paths in this crate build one of these per poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The platform function that was called, spelled exactly as the platform
    /// spells it, so the operator can search for it.
    call: &'static str,
    /// The platform's own error number, where the call produced one. `None` for
    /// a call that failed a check of ours rather than the system's.
    code: Option<i32>,
    /// What we can add that the code cannot say by itself.
    note: Cow<'static, str>,
}

impl Fault {
    /// A fault with no platform error number — our own refusal, not the system's.
    ///
    /// Used where a call technically succeeded but returned something we will not
    /// build on: a null pointer where a pointer was promised, a length that does
    /// not match the structure it describes.
    pub fn refused(call: &'static str, note: impl Into<Cow<'static, str>>) -> Self {
        Self { call, code: None, note: note.into() }
    }

    /// A fault carrying a platform error number.
    ///
    /// On Windows this is `GetLastError`'s value; on unix it is `errno`. Both are
    /// rendered by the operating system's own strings through [`Self::sentence`],
    /// so the number is kept rather than pre-formatted.
    pub fn os(call: &'static str, code: i32) -> Self {
        Self { call, code: Some(code), note: Cow::Borrowed("") }
    }

    /// The last operating-system error for `call`, read from the platform.
    ///
    /// A thin wrapper over `io::Error::last_os_error` that exists so no caller
    /// has to remember that the error must be read *immediately* after the failed
    /// call — any intervening allocation can overwrite it.
    pub fn last_os_error(call: &'static str) -> Self {
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) => Self::os(call, code),
            None => Self::refused(call, error.to_string()),
        }
    }

    /// Adds detail that only the caller knows — a session id, a pipe name.
    ///
    /// Consumes and returns so it reads as one expression at the call site,
    /// which is where the temptation to drop the context lives.
    #[must_use]
    pub fn noting(mut self, note: impl Into<Cow<'static, str>>) -> Self {
        self.note = note.into();
        self
    }

    /// The platform function that failed.
    pub fn call(&self) -> &'static str {
        self.call
    }

    /// The platform's error number, if the call produced one.
    ///
    /// Callers compare this against a specific constant to turn a fault into a
    /// *state* — `ERROR_NO_TOKEN` is "nobody is logged in", which the console
    /// renders as a sentence rather than as a failure.
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// The whole thing as one sentence, for the console.
    ///
    /// Never returns an empty string and never ends without naming the call,
    /// because a status line that says only "Access is denied" has told the
    /// operator nothing they can act on.
    pub fn sentence(&self) -> String {
        let mut out = format!("{} failed", self.call);
        if let Some(code) = self.code {
            let described = std::io::Error::from_raw_os_error(code);
            out.push_str(&format!(": {described} (code {code})"));
        }
        if !self.note.is_empty() {
            out.push_str(" — ");
            out.push_str(&self.note);
        }
        out
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for Fault {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fault_always_names_the_call_that_produced_it() {
        // The whole reason this type exists rather than a bare io::Error: the
        // same error number means different things from different calls.
        let fault = Fault::os("WTSQueryUserToken", 5);
        assert!(fault.sentence().starts_with("WTSQueryUserToken failed"));
        assert!(fault.sentence().contains("code 5"));
    }

    #[test]
    fn a_refusal_of_ours_carries_no_platform_code() {
        let fault = Fault::refused("CreateEnvironmentBlock", "returned a null block");
        assert_eq!(fault.code(), None);
        assert!(fault.sentence().contains("null block"));
    }

    #[test]
    fn a_note_survives_into_the_sentence() {
        let fault = Fault::os("CreateNamedPipeW", 231).noting("session 1");
        let sentence = fault.sentence();
        assert!(sentence.contains("CreateNamedPipeW"));
        assert!(sentence.contains("session 1"));
    }

    #[test]
    fn the_code_is_readable_so_a_caller_can_turn_it_into_a_state() {
        // ERROR_NO_TOKEN is not a failure to report; it is "nobody is logged in".
        let fault = Fault::os("WTSQueryUserToken", 1008);
        assert_eq!(fault.code(), Some(1008));
    }
}
