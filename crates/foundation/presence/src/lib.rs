//! Is a person at this machine, right now?
//!
//! # The question this crate exists to ask
//!
//! Every other credential in this workspace answers *who*: a passkey names a
//! person, the console password names the deployment's owner, the bearer token
//! names the box's own automation. None of them answers *whether anybody is
//! there* — a token in a file and a password in a keychain are both replayed by
//! software with nobody present, which is why
//! [`selfhost_identity::Credential::is_unattended`] exists and why the desktop's
//! control ticket demands a fresh login before it will hand over a keyboard.
//!
//! The desktop console had the same hole, one layer further out. It reads the
//! machine's own token — from a file here, or over `ssh` from the far side — and
//! opens straight onto a running deployment. Anybody who could reach the
//! keyboard of an unlocked laptop could open the Dock icon and be operating the
//! server a second later, having proved nothing at all.
//!
//! [`demand`] is the question that closes it: *prove a person is here*. On macOS
//! that is `LocalAuthentication`'s device-owner policy — the Touch ID sheet, with
//! the account password as its own fallback, which is exactly the "fingerprint or
//! password" a person expects of a Mac. The sheet is drawn by the system, so no
//! password ever passes through this process.
//!
//! # What it does not prove
//!
//! That the person is *the owner of the deployment*. It proves the operating
//! system recognised whoever is sitting here as the owner of **this computer**,
//! which is a different claim and a weaker one. It is nonetheless the claim that
//! was missing: the credential for the server already lives on this machine, and
//! what had no gate at all was its *use*. A stronger answer — a passkey the
//! server itself verifies — is a separate piece of work, and this crate does not
//! pretend to be it.
//!
//! # Failing closed
//!
//! [`Presence::Unavailable`] is not a pass. A machine that cannot be asked is a
//! machine where nobody can be proved to be present, and the caller is expected
//! to stay shut rather than open on the grounds that the lock is broken. That
//! includes every platform but macOS today: see [`demand`].

#![warn(missing_docs)]

#[cfg(target_os = "macos")]
mod macos;

/// What came back from asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Somebody proved they are here — a fingerprint, or the account password.
    ///
    /// Which of the two it was is deliberately not reported: the system does not
    /// say, and a caller that treated them differently would be inventing a
    /// distinction the sheet did not make.
    Proved,
    /// The sheet was dismissed. Nobody proved anything, and nothing is wrong.
    ///
    /// Separated from [`Presence::Refused`] because they are different events for
    /// the person reading the screen: one is "I changed my mind", the other is
    /// "that was not you", and a console that says the second when it means the
    /// first accuses its operator of something.
    Declined,
    /// A credential was presented and the system did not recognise it.
    Refused,
    /// This machine cannot be asked, and says why.
    ///
    /// A sensor that is missing, a lockout after too many failures, an account
    /// with no password to fall back on — and every platform for which this crate
    /// has no implementation yet. **Never treat it as a pass.**
    Unavailable(String),
}

impl Presence {
    /// Whether this answer opens the door. Exactly one of them does.
    pub fn proved(&self) -> bool {
        matches!(self, Self::Proved)
    }

    /// What to put on screen underneath a lock that is still shut.
    ///
    /// Written here rather than at the window, so that the four answers cannot
    /// come to be described two different ways by two different callers — and so
    /// that the wording of a refusal is reviewable in the crate that knows what
    /// actually happened.
    pub fn trouble(&self) -> Option<String> {
        match self {
            Self::Proved => None,
            Self::Declined => Some("Locked. Unlock to reach this machine.".to_owned()),
            Self::Refused => Some("That was not recognised. Try again.".to_owned()),
            Self::Unavailable(why) => Some(why.clone()),
        }
    }
}

/// Asks the operating system to prove a person is at this machine.
///
/// **Blocks** until the person answers the system's sheet, so it must be called
/// off the thread drawing the window: the sheet is presented by the system over
/// the application's own window, and a caller that blocks the main thread waiting
/// for it hangs the very interface the sheet is drawn on. On macOS that mistake
/// is caught rather than deadlocked — see the guard in [`macos`].
///
/// `reason` is shown to the person, in the system's own sheet, after "Selfhost
/// Console is trying to". Write it as the thing they are about to do.
///
/// # Every platform but macOS
///
/// Answers [`Presence::Unavailable`] — there is no Windows Hello or `polkit`
/// implementation here yet. That is a refusal, not a pass: a console on such a
/// machine stays locked and says so, which is a visible gap rather than a silent
/// one.
pub fn demand(reason: &str) -> Presence {
    #[cfg(target_os = "macos")]
    {
        macos::demand(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Presence::Unavailable(
            "This computer has no presence check this program knows how to ask. \
             Only macOS is implemented — Touch ID, or the account password behind it."
                .to_owned(),
        )
    }
}

/// Whether this machine can be asked at all, without asking.
///
/// For a window that wants to say "locked — Touch ID" versus "locked — this
/// computer cannot be asked" *before* anybody presses anything. It shows no
/// sheet and proves nothing, so it is never a substitute for [`demand`].
pub fn askable() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::askable()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("no presence check is implemented for this platform".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_answer_opens_the_door() {
        let every = [
            Presence::Proved,
            Presence::Declined,
            Presence::Refused,
            Presence::Unavailable("no sensor".into()),
        ];
        assert_eq!(every.iter().filter(|answer| answer.proved()).count(), 1);
    }

    #[test]
    fn an_unaskable_machine_is_a_refusal_and_not_a_pass() {
        // The whole point of the type. A lock that opens when it breaks is not a
        // lock, and this is the assertion that says so out loud.
        let broken = Presence::Unavailable("the sensor is not there".into());
        assert!(!broken.proved());
        assert_eq!(broken.trouble().as_deref(), Some("the sensor is not there"));
    }

    #[test]
    fn every_shut_answer_has_something_to_say_and_the_open_one_does_not() {
        assert_eq!(Presence::Proved.trouble(), None);
        for shut in [Presence::Declined, Presence::Refused] {
            assert!(shut.trouble().is_some(), "{shut:?} must explain itself");
        }
    }
}
