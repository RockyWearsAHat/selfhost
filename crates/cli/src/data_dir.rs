//! Creating the deployment's data directory so that only this account can read it.
//!
//! Everything that makes this deployment *this* deployment lives in one
//! directory: the bearer token that skips every browser-side defence at once,
//! the TLS private keys the proxy serves 443 with, the PBKDF2 hash of the
//! console password, and the passkey registry that says which hardware may sign
//! its way in. The directory is therefore a credential in its own right —
//! anything that can read it is the deployment — and until this module existed
//! every caller created it with a bare `create_dir_all`, which is the one call
//! that states nothing about who may read the result.
//!
//! `create_dir_all` inherits. On unix the mode is whatever `0o777` minus the
//! process umask happens to be, which on a normal login shell is `0755`: every
//! account on the machine can list the directory and read any file in it whose
//! own mode is loose. On Windows a directory created inside a user profile tree
//! takes that tree's inheritable ACEs, which include the interactive user and,
//! on a machine with a second account, that account too. Neither is a boundary,
//! and both are silent.
//!
//! # What this module does, and the half it cannot do yet
//!
//! On unix the whole story is here: the directory is created `0700` and an
//! existing one that is wider is narrowed, because the deployed boxes have data
//! directories that predate this rule and a fix nobody runs is not a fix.
//!
//! On Windows the directory is created and then **inspected and reported**, but
//! its DACL is not written, and that is a deliberate, temporary shape rather
//! than an oversight. The workspace already has exactly one Windows ACL
//! implementation — `selfhost_admin::token`'s `write_private`, which creates
//! files under `D:P(A;;FA;;;SY)(A;;FA;;;BA)` — and its FFI is private to that
//! module. A second implementation here would be a second thing to get right,
//! a second thing to audit, and a second thing to drift. So this module reuses
//! the half of that seam which *is* public, [`privacy_of`], and says loudly
//! what the ACL actually admits; promoting a directory-creating counterpart of
//! `write_private` into `selfhost_admin::token` is the follow-up that closes
//! the gap, and it belongs in that crate beside the code it shares its
//! descriptor with.
//!
//! # Why the observation is returned rather than logged here
//!
//! A library that prints is a library that prints in the middle of a test, and
//! the two callers want different renderings of the same fact: the daemon wants
//! a startup line, `selfhost doctor` wants a [`Check`](crate::doctor) with a
//! verdict and a fix. So [`prepare`] returns what it found and changed, and the
//! caller decides how to say it. Nothing is swallowed: a directory that could
//! not be created is an `Err`, and a directory that is readable by somebody
//! else is a [`Privacy::Exposed`] the caller is expected to surface.

use selfhost_admin::token::{Privacy, privacy_of};
use std::io;
use std::path::Path;

/// The mode the data directory is held at on unix: everything for its owner,
/// nothing at all for anybody else.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;

/// What [`prepare`] found, and what it had to change to get there.
#[derive(Debug)]
pub struct Prepared {
    /// The mode the directory was found at, when it was not owner-only and
    /// this call reset it to `0700` — for example `"mode 0755"`. `None` means
    /// nothing was changed: either the directory was already correct, or it was
    /// just created, or the platform gives this module no way to set it (see
    /// the module docs).
    pub changed_from: Option<String>,
    /// Who can read the directory now, as observed after any change.
    pub privacy: Privacy,
}

impl Prepared {
    /// Everything worth telling an operator about this directory, one line each.
    ///
    /// Empty when the directory was already private and stayed that way, which
    /// is the ordinary case and deserves no output — a startup that narrates
    /// its successes teaches the reader to skim past the one line that matters.
    /// A change and an exposure are reported independently rather than as a
    /// match on the pair, so a platform where the mode was reset *and* the
    /// result is still not private says both instead of only the first.
    pub fn notes(&self, path: &Path) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(previous) = &self.changed_from {
            notes.push(format!(
                "data directory {}: was {previous}, reset to mode 0700 — it holds the bearer \
                 token, the TLS private keys and the console password hash, and no other \
                 account on this machine has any reason to read them",
                path.display()
            ));
        }
        match &self.privacy {
            Privacy::Private(_) => {}
            Privacy::Exposed(detail) => notes.push(format!(
                "warning: the data directory {} is readable beyond this account ({detail}); it \
                 holds the bearer token, the TLS private keys and the console password hash. \
                 Run `selfhost doctor` for the exact command that repairs it",
                path.display()
            )),
            Privacy::Unanswerable(why) => notes.push(format!(
                "warning: cannot tell who may read the data directory {} ({why}); treat the \
                 bearer token and the TLS keys in it as readable by this machine's other \
                 accounts until it can be checked",
                path.display()
            )),
        }
        notes
    }
}

/// Creates the data directory privately if it is absent, corrects it if it is
/// wider than it should be, and reports who can read the result.
///
/// This is the call for anything that is about to *write* a secret there — the
/// daemon, `selfhost run`, and the mail task, all of which create files under
/// it. It repairs rather than merely observes, because the directories on the
/// two live boxes were created before this rule existed and will otherwise stay
/// `0755` forever.
///
/// An `Err` means the directory could not be brought into existence at all, and
/// the caller should treat that as fatal for whatever wanted to write there: a
/// deployment that cannot create its data directory cannot hold a token, a
/// certificate, or a mailbox.
pub fn prepare(path: &Path) -> io::Result<Prepared> {
    create_if_absent(path)?;
    let changed_from = make_private(path)?;
    Ok(Prepared { changed_from, privacy: privacy_of(path)? })
}

/// Creates the data directory and every missing parent with owner-only access,
/// and leaves an existing directory exactly as it is (unix).
///
/// This is the call for a diagnostic. `selfhost doctor` has one rule about
/// itself — it reports what to do and never does it — so it must not silently
/// re-mode a directory the operator is about to be told about. Creating a
/// missing one is not the same kind of act: doctor has always done it (a
/// deployment that has never run has no data directory, and refusing to check
/// the rest of it would be useless), and creating it `0700` rather than `0755`
/// only means the thing doctor creates is not itself a new exposure.
///
/// `DirBuilder::mode` applies to each directory this call creates, parents
/// included. That is deliberate: a parent that exists only to hold the data
/// directory — `/var/lib/selfhost` in front of `/var/lib/selfhost/data` — is
/// part of the same secret and gains nothing from being world-listable. A
/// parent that already exists is untouched, because it is the operator's
/// directory and not ours to re-mode.
///
/// The existence check is `is_dir` rather than `exists` so that a *file* at the
/// path falls through to `create` and fails loudly, instead of being quietly
/// accepted as a data directory that will refuse every write afterwards.
#[cfg(unix)]
pub fn create_if_absent(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if path.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new().recursive(true).mode(PRIVATE_DIR_MODE).create(path)
}

/// Creates the data directory and every missing parent, and leaves an existing
/// directory exactly as it is (Windows and elsewhere).
///
/// No descriptor is attached, for the reason the module docs give: the one
/// audited Windows ACL implementation in this workspace is private to
/// `selfhost_admin::token`, and a second one written here would be a second one
/// to get right. What this platform gets instead is the truth — [`prepare`]
/// reads the DACL back through [`privacy_of`] and hands the caller an
/// [`Privacy::Exposed`] naming whoever else the profile tree let in — so the
/// gap is visible in `selfhost doctor` and in the daemon's own startup output
/// rather than being invisible in both.
#[cfg(not(unix))]
pub fn create_if_absent(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Resets an existing directory's mode to [`PRIVATE_DIR_MODE`] when it differs,
/// returning what it was (unix).
///
/// Reading the mode back after creation rather than trusting the create is not
/// belt-and-braces: `mkdir` subtracts the process umask from the mode it is
/// given, so the same call that asks for `0700` produces something else under
/// an unusual umask, and the directories on the live boxes were created by an
/// older build that asked for nothing at all.
#[cfg(unix)]
fn make_private(path: &Path) -> io::Result<Option<String>> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode();
    if !needs_correcting(mode) {
        return Ok(None);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    Ok(Some(format!("mode {:04o}", mode & 0o7777)))
}

/// Nothing to reset where the mode bits do not exist (Windows and elsewhere).
#[cfg(not(unix))]
fn make_private(_path: &Path) -> io::Result<Option<String>> {
    Ok(None)
}

/// Whether an observed unix mode is anything other than exactly owner-only.
///
/// Pure, so the rule that decides whether the deployment's secrets are behind a
/// wall is testable without a filesystem. The comparison is against the whole
/// twelve-bit mode rather than a mask of the group and other triads, which
/// matters for one bit in particular: `setgid` on a directory makes everything
/// created inside it inherit the directory's group, so a `2700` data directory
/// quietly hands a group ownership of every certificate and mailbox written
/// afterwards. Demanding the exact mode also means the rule cannot rot — there
/// is no list of bits to keep in step with a list of bits somewhere else.
#[cfg(unix)]
fn needs_correcting(mode: u32) -> bool {
    mode & 0o7777 != PRIVATE_DIR_MODE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch path unique to one test, with nothing at it yet.
    ///
    /// Named per test rather than per process because these tests run
    /// concurrently and each one asserts on the mode of its own directory.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-data-dir-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("the directory exists").permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn a_created_data_directory_admits_nobody_else() {
        let dir = scratch("create");
        let prepared = prepare(&dir).expect("created");
        assert_eq!(mode_of(&dir), PRIVATE_DIR_MODE, "a fresh data directory is owner-only");
        assert_eq!(prepared.changed_from, None, "nothing pre-existed to correct");
        assert!(
            matches!(prepared.privacy, Privacy::Private(_)),
            "creation and inspection must agree: {:?}",
            prepared.privacy
        );
        assert!(prepared.notes(&dir).is_empty(), "an ordinary start says nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_parent_is_created_private_too() {
        // A parent that exists only to hold the data directory is part of the
        // same secret; leaving it 0755 would let anyone list what is inside.
        let root = scratch("parents");
        let nested = root.join("selfhost").join("data");
        prepare(&nested).expect("created");
        assert_eq!(mode_of(&nested), PRIVATE_DIR_MODE);
        assert_eq!(mode_of(&root.join("selfhost")), PRIVATE_DIR_MODE);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_directory_is_narrowed_and_says_so() {
        // The live boxes: a data directory created by an older build, holding a
        // bearer token, at the umask's 0755. Repairing it silently would be a
        // permission change nobody could account for afterwards.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("narrow");
        std::fs::create_dir_all(&dir).expect("a directory to start from");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("loosened");

        let prepared = prepare(&dir).expect("prepared");
        assert_eq!(mode_of(&dir), PRIVATE_DIR_MODE);
        assert_eq!(prepared.changed_from.as_deref(), Some("mode 0755"));
        let notes = prepared.notes(&dir);
        assert_eq!(notes.len(), 1, "one line, about the change: {notes:?}");
        assert!(notes[0].contains("0700"), "{}", notes[0]);

        // And again: idempotent, and now silent.
        let again = prepare(&dir).expect("prepared");
        assert_eq!(again.changed_from, None);
        assert!(again.notes(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_diagnostic_creates_a_missing_directory_but_never_re_modes_one() {
        // `selfhost doctor` reports what to do; it does not do it. A doctor run
        // that repaired the mode would erase the very finding it printed.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("doctor");
        create_if_absent(&dir).expect("created");
        assert_eq!(mode_of(&dir), PRIVATE_DIR_MODE);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("loosened");
        create_if_absent(&dir).expect("left alone");
        assert_eq!(mode_of(&dir), 0o755, "an existing directory is observed, not rewritten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_where_the_data_directory_should_be_is_an_error_not_a_shrug() {
        // Accepting it would mean every later write fails with a confusing
        // error somewhere else — a certificate that cannot be stored, a token
        // that cannot be minted — instead of one clear failure here.
        let dir = scratch("file");
        std::fs::create_dir_all(dir.parent().expect("a temp dir has a parent")).expect("parent");
        std::fs::write(&dir, b"not a directory").expect("wrote a file at the path");
        assert!(prepare(&dir).is_err(), "a file is not a data directory");
        let _ = std::fs::remove_file(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn only_exactly_owner_only_is_left_alone() {
        assert!(!needs_correcting(0o700));
        for wider in [0o755, 0o750, 0o777, 0o701, 0o710] {
            assert!(needs_correcting(wider), "{wider:04o} lets somebody else in");
        }
        // Not about breadth: a directory nobody including us can use is wrong
        // too, and so is a setgid bit that hands new files to a group.
        for other in [0o000, 0o500, 0o600, 0o2700, 0o1700] {
            assert!(needs_correcting(other), "{other:04o} is not exactly 0700");
        }
    }

    #[test]
    fn an_exposed_directory_is_reported_even_when_nothing_was_changed() {
        // The Windows shape, asserted on every platform: this module cannot
        // write a DACL, so the one thing it must never do is stay quiet about
        // one that admits somebody else.
        let prepared = Prepared {
            changed_from: None,
            privacy: Privacy::Exposed("readable by S-1-5-21-1-2-3-1001".into()),
        };
        let notes = prepared.notes(Path::new("C:\\Users\\Alex\\Self-Host\\data"));
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("S-1-5-21-1-2-3-1001"), "{}", notes[0]);
        assert!(notes[0].contains("bearer token"), "{}", notes[0]);

        let unknown = Prepared {
            changed_from: None,
            privacy: Privacy::Unanswerable("this platform is not modelled".into()),
        };
        assert_eq!(unknown.notes(Path::new("/data")).len(), 1, "not modelled is not fine");
    }

    #[test]
    fn a_change_and_a_remaining_exposure_are_both_reported() {
        // Collapsing these into one match would let the louder half hide the
        // other: "we tightened it" is not an answer to "who can still read it".
        let prepared = Prepared {
            changed_from: Some("mode 0755".into()),
            privacy: Privacy::Exposed("readable by BUILTIN\\Users".into()),
        };
        assert_eq!(prepared.notes(Path::new("/data")).len(), 2);
    }
}
