//! The TCC gate: asked before the pixels, answered as a product surface.
//!
//! # Why this is a module and not two `if`s
//!
//! macOS does not fail a screen capture it has not consented to. It **succeeds**,
//! and hands the process a picture of the desktop wallpaper with every window
//! missing. There is therefore no frame anybody can inspect that answers "am I
//! allowed to see this machine?", and a capture layer that tries to infer consent
//! from the pixels will infer it wrongly forever. The only answer is
//! `CGPreflightScreenCaptureAccess`, asked *before* the capture starts, and
//! `AXIsProcessTrusted` for input — both of which [`crate::macos::sys`] binds.
//!
//! What this module adds on top of those two booleans is the half that makes them
//! useful: the **refusal an operator can act on**. A remote desktop that shows a
//! picture of the wallpaper is the worst failure this subsystem can have, because
//! it looks like a working session of an empty machine. A refusal that says
//! "permission denied" is only marginally better: it is true, and it does not tell
//! anybody what to do. So the gate returns a typed
//! [`CaptureError::PermissionDenied`], and the sentence attached to it names the
//! pane, the binary and the relaunch — see [`crate::Grant::remediation`], where
//! that wording and its length budget live because both consoles and the agent's
//! own status line share it.
//!
//! # The grant will not survive a deploy, and the documentation says so
//!
//! macOS keys a TCC grant to the *code identity* of the binary that asked. This
//! workspace ships ad-hoc-signed binaries: every `cargo build` produces a new
//! cdhash, so every build is, to TCC, a different program that has never been
//! granted anything. On the production box that is not an occasional
//! inconvenience — `[self_update]` rebuilds the tree **on every push** — so the
//! honest expectation, stated here so nobody spends an afternoon looking for the
//! bug, is:
//!
//! > Screen Recording is revoked by every deployment and must be re-given by hand,
//! > at the machine, after the binary has been rebuilt.
//!
//! There is no way around it from inside this crate. Developer ID signing with a
//! stable identity would fix it and is a distribution decision, not a code one.
//! Until then the doctor check exists precisely so the loss is *reported* the
//! moment it happens rather than discovered by an operator watching a wallpaper.
//!
//! # Viewing and driving are gated separately
//!
//! Screen Recording and Accessibility are two grants, in two panes, revoked
//! independently. A session that only watches must never be blocked by the
//! permission it will never use, which is why [`gate`] takes `with_input` rather
//! than checking both and refusing.

use crate::macos::sys;
use crate::{CaptureError, Grant, InjectError};

/// Checks the consents a session needs, before anything looks at a pixel.
///
/// `with_input` also demands Accessibility, so a view-only session is not refused
/// over the permission that only injection needs.
///
/// # Errors
///
/// [`CaptureError::PermissionDenied`] naming *which* grant is missing. Never a
/// generic failure: the two are granted in two different panes and a refusal that
/// does not say which one sends the operator to the wrong place.
pub fn gate(with_input: bool) -> Result<(), CaptureError> {
    sys::preflight(with_input)
}

/// The same check for the injector, in the injector's own error vocabulary.
///
/// # Errors
///
/// [`InjectError::PermissionDenied`] with [`Grant::Accessibility`], which the
/// session forwards to the client as `not-permitted` and logs locally with the
/// remediation sentence.
pub fn gate_input() -> Result<(), InjectError> {
    if sys::accessibility_allowed() {
        return Ok(());
    }
    Err(InjectError::PermissionDenied(Grant::Accessibility))
}

/// The remediation sentence for this process, with this binary's own path in it.
///
/// The path matters more here than it looks: this workspace builds several
/// executables into one directory, TCC grants are per binary, and an operator who
/// grants the wrong one sees no change at all and reasonably concludes the feature
/// is broken.
pub fn remediation(grant: Grant) -> String {
    grant.remediation(&crate::this_executable())
}

/// The remediation for a condition, or `None` for one that is not a permission.
///
/// Exists so a status line can be built without matching on [`CaptureError`] in
/// three places and getting a different sentence in each.
pub fn remediation_for(condition: &CaptureError) -> Option<String> {
    match condition {
        CaptureError::PermissionDenied(grant) => Some(remediation(*grant)),
        _ => None,
    }
}

/// What the machine currently grants, for the doctor check and the console's
/// diagnostics plate.
///
/// Both booleans are pure queries: neither prompts, so this is safe to poll and
/// safe to run in a test. The prompting call —
/// [`sys::request_screen_recording`] — is deliberately not reachable from here,
/// because macOS shows that prompt once per process and a supervisor that asked on
/// every attempt would burn the one prompt the operator was going to see on a
/// machine nobody is sitting at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    /// Whether this process may capture the screen.
    pub screen_recording: bool,
    /// Whether this process may synthesise keyboard and pointer events.
    pub accessibility: bool,
}

impl Grants {
    /// Asks the operating system what it currently allows.
    pub fn read() -> Self {
        Self {
            screen_recording: sys::screen_recording_allowed(),
            accessibility: sys::accessibility_allowed(),
        }
    }

    /// One line for the doctor's output, naming what is missing and what to do.
    ///
    /// Reads as a whole sentence in every combination, including the happy one,
    /// because a diagnostic that only speaks when something is wrong leaves an
    /// operator unable to tell "granted" from "not checked".
    pub fn line(self) -> String {
        match (self.screen_recording, self.accessibility) {
            (true, true) => {
                "macOS grants this binary both Screen Recording and Accessibility, so this \
                 machine can be viewed and driven."
                    .to_owned()
            }
            (true, false) => format!(
                "macOS grants this binary Screen Recording but not Accessibility, so this \
                 machine can be viewed and not driven. {}",
                remediation(Grant::Accessibility)
            ),
            (false, _) => format!(
                "macOS does not grant this binary Screen Recording, so a capture would \
                 return a picture of the wallpaper rather than the desktop. {}",
                remediation(Grant::ScreenRecording)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_answers_without_prompting_and_names_the_grant_it_refuses() {
        // Runs against the real TCC state of whatever machine this is built on. The
        // assertion is that the refusal is *specific*: a generic denial would send
        // an operator to the wrong pane.
        match gate(false) {
            Ok(()) => assert!(Grants::read().screen_recording),
            Err(CaptureError::PermissionDenied(Grant::ScreenRecording)) => {
                assert!(!Grants::read().screen_recording);
            }
            Err(other) => panic!("the gate answered something it should not: {other}"),
        }
    }

    #[test]
    fn a_viewer_is_never_refused_over_the_permission_only_a_driver_needs() {
        let grants = Grants::read();
        if grants.screen_recording && !grants.accessibility {
            assert!(gate(false).is_ok(), "watching must not need Accessibility");
            assert!(matches!(
                gate(true),
                Err(CaptureError::PermissionDenied(Grant::Accessibility))
            ));
        }
    }

    #[test]
    fn the_input_gate_speaks_the_injectors_own_vocabulary() {
        match gate_input() {
            Ok(()) => assert!(Grants::read().accessibility),
            Err(InjectError::PermissionDenied(Grant::Accessibility)) => {
                assert!(!Grants::read().accessibility);
                // The client is told *that* it was refused; the remediation is for
                // the machine's own operator, who is the only person who can act on
                // it and the only person who should learn the binary's path.
                assert_eq!(
                    InjectError::PermissionDenied(Grant::Accessibility).refusal(),
                    Some(selfhost_desk::wire::Refusal::NotPermitted)
                );
            }
            Err(other) => panic!("unexpected refusal: {other}"),
        }
    }

    #[test]
    fn the_remediation_names_this_binary_rather_than_a_binary() {
        let sentence = remediation(Grant::ScreenRecording);
        assert!(sentence.contains("Screen Recording"));
        assert!(sentence.ends_with('.'));
        // The test binary's own path, elided from the front if it is long. The
        // stable part is the file name, which is what identifies it in the pane.
        let executable = crate::this_executable();
        let name = executable
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(!name.is_empty());
        assert!(sentence.contains(&name), "{sentence} does not name {name}");
    }

    #[test]
    fn every_combination_of_grants_reads_as_a_sentence() {
        for screen_recording in [false, true] {
            for accessibility in [false, true] {
                let line = Grants { screen_recording, accessibility }.line();
                assert!(line.ends_with('.'), "{line}");
                assert!(!line.is_empty());
            }
        }
    }

    #[test]
    fn a_condition_that_is_not_a_permission_has_no_remediation() {
        assert!(remediation_for(&CaptureError::SecureDesktop).is_none());
        assert!(remediation_for(&CaptureError::PermissionDenied(Grant::ScreenRecording)).is_some());
    }
}
