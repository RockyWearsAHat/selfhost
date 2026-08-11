//! Where the running daemon is, for a program that was not started beside it.
//!
//! # The problem
//!
//! The daemon writes its token into `data/admin.token`, *relative to the
//! directory it was started in*, and the console reads it from the same place.
//! That works perfectly when both are run from a terminal sitting in the
//! project, and not at all when the console is opened from the Dock: an
//! application launched by the Finder has no meaningful working directory, so
//! the relative path resolves against the root of the disk and the console
//! reports that it cannot find a token — which is true, and useless.
//!
//! # The answer
//!
//! A running daemon leaves a note saying where it is running, and a console
//! that cannot find a token beside itself reads the note. The daemon is the
//! only thing that knows the answer and the only thing that knows when it stops
//! being true, so the daemon is what writes it and what removes it.
//!
//! This is a *hint and never an authority*. It names a directory; it carries no
//! token, no key, and no permission. A console still has to read a file the
//! daemon wrote with mode `0600`, which is the actual proof of being allowed to
//! connect, and a stale or wrong note therefore fails as a missing token rather
//! than as access to anything.

use std::io;
use std::path::{Path, PathBuf};

/// The directory the note lives in, per platform.
///
/// The state directory rather than the config directory: this is something a
/// program wrote about a running process, not something a person configured,
/// and it is meaningless once the machine has restarted.
///
/// Public because the note is no longer the only thing that belongs here — the
/// console keeps its paired-machine list beside it — and a second copy of this
/// platform logic is exactly the kind of duplication that drifts. Callers place
/// their own file inside; nothing here decides what that file is.
pub fn state_directory() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")?;
        Some(Path::new(&home).join("Library/Application Support/selfhost"))
    } else if cfg!(target_os = "windows") {
        let local = std::env::var_os("LOCALAPPDATA")?;
        Some(Path::new(&local).join("selfhost"))
    } else {
        match std::env::var_os("XDG_STATE_HOME") {
            Some(state) => Some(Path::new(&state).join("selfhost")),
            None => {
                let home = std::env::var_os("HOME")?;
                Some(Path::new(&home).join(".local/state/selfhost"))
            }
        }
    }
}

/// The note's full path, or `None` on a machine with no home directory.
pub fn note_path() -> Option<PathBuf> {
    Some(state_directory()?.join(NOTE_NAME))
}

/// What the note is called.
const NOTE_NAME: &str = "daemon-directory";

/// Records `directory` as where the daemon is running.
///
/// Overwrites any previous note: there is one daemon per machine as far as this
/// is concerned, and a note from a daemon that is no longer running is worse
/// than no note at all.
pub fn record(directory: &Path) -> io::Result<()> {
    let path = note_path().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "this account has no home directory")
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict(parent)?;
    }
    std::fs::write(&path, resolved(directory).to_string_lossy().as_bytes())
}

/// Removes the note, if it is still the one `directory` wrote.
///
/// The check is not fussiness. A daemon shutting down runs after stopping every
/// service it supervises, which takes as long as the slowest of them; a second
/// daemon started in another directory meanwhile will have written its own
/// note, and an unconditional delete here would remove *that* one. The console
/// would then report no daemon while a daemon was running — observed, not
/// imagined, while testing this.
///
/// Succeeds when there is nothing to remove: a daemon that crashed before
/// writing one, and a daemon shutting down twice, are both ordinary.
pub fn forget(directory: &Path) -> io::Result<()> {
    match note_path() {
        Some(path) => forget_note(&path, directory),
        None => Ok(()),
    }
}

/// The removal itself, with the note's location supplied.
///
/// Split from [`forget`] for the same reason [`read_note`] is split from
/// [`recorded`]: the interesting behaviour is a comparison, and a test of it
/// must not depend on where this machine's real note is or what it says.
fn forget_note(path: &Path, directory: &Path) -> io::Result<()> {
    // Both sides are resolved before being compared. `record` writes a resolved
    // path, but a note may predate that, and on macOS the temporary directory
    // alone is enough to make the same place spell itself two ways — `/var/...`
    // against `/private/var/...`. Comparing as written would make every daemon
    // conclude the note belongs to somebody else and leave it behind for ever.
    let ours = resolved(directory);
    match read_note(path) {
        // Somebody else's note, or none. Either way, not ours to remove.
        None => Ok(()),
        Some(recorded) if resolved(&recorded) != ours => Ok(()),
        Some(_) => match std::fs::remove_file(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        },
    }
}

/// A path with every link and relative step resolved, where that is possible.
///
/// Falls back to the path as given, since a path that cannot be resolved is one
/// that does not exist, and two of those are equal exactly when they are spelt
/// the same.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}

/// The directory a daemon last recorded, if it named one that still exists.
///
/// A note pointing at a directory that has been deleted or renamed is treated
/// as no note, so the caller's own "I looked here and here" message stays true
/// rather than naming somewhere that cannot be looked at.
pub fn recorded() -> Option<PathBuf> {
    read_note(&note_path()?)
}

/// The directory named by the note at `path`, if it names one that exists.
///
/// Split from [`recorded`] so it can be asserted on against a note this test
/// wrote, rather than against whatever this machine's daemon last did.
fn read_note(path: &Path) -> Option<PathBuf> {
    let contents = std::fs::read_to_string(path).ok()?;
    let directory = PathBuf::from(contents.trim());
    directory.is_dir().then_some(directory)
}

/// Narrows a directory to its owner, where the platform has such a concept.
///
/// Nothing secret is kept here — the note holds a path and no more. It is
/// narrowed anyway because this directory is the obvious place for something
/// secret to be put later, and a directory that starts out world-readable
/// tends to stay that way.
#[cfg(unix)]
fn restrict(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
}

/// The same, on platforms whose permissions do not work that way.
#[cfg(not(unix))]
fn restrict(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_note_lives_beside_other_state_and_not_beside_the_config() {
        let Some(path) = note_path() else {
            return; // A machine with no home directory has nowhere to put it.
        };
        assert!(path.ends_with(NOTE_NAME));
        assert!(
            path.parent().is_some_and(|parent| parent.ends_with("selfhost")),
            "the note belongs in this program's own directory, not loose in a shared one"
        );
    }

    /// A path in the temporary directory that no other test will collide with.
    fn scratch(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("selfhost-home-{name}-{unique}"))
    }

    #[test]
    fn a_note_answers_the_directory_it_names() {
        let note = scratch("present");
        let directory = std::env::temp_dir();
        std::fs::write(&note, directory.to_string_lossy().as_bytes()).expect("writable");
        assert_eq!(read_note(&note), Some(directory));
        let _ = std::fs::remove_file(&note);
    }

    #[test]
    fn surrounding_whitespace_does_not_change_the_directory_named() {
        // A note written by anything that appends a newline — including a
        // person with an editor — must still name the directory it names.
        let note = scratch("whitespace");
        let directory = std::env::temp_dir();
        std::fs::write(&note, format!("  {}\n", directory.display())).expect("writable");
        assert_eq!(read_note(&note), Some(directory));
        let _ = std::fs::remove_file(&note);
    }

    #[test]
    fn a_note_naming_somewhere_that_is_not_there_is_treated_as_no_note() {
        // The case that matters: a daemon recorded a directory and the project
        // was then moved or deleted. Answering the stale path would make the
        // console report that it could not find a token in a directory that
        // does not exist, instead of that no daemon is running.
        let note = scratch("stale");
        std::fs::write(&note, b"/no/such/directory/anywhere").expect("writable");
        assert_eq!(read_note(&note), None);
        let _ = std::fs::remove_file(&note);
    }

    #[test]
    fn no_note_at_all_is_not_an_error() {
        assert_eq!(read_note(&scratch("absent")), None);
    }

    #[test]
    fn a_note_naming_a_file_rather_than_a_directory_is_refused() {
        // Otherwise the console would go on to look for `data/admin.token`
        // underneath something that cannot contain it.
        let note = scratch("not-a-directory");
        std::fs::write(&note, note.to_string_lossy().as_bytes()).expect("writable");
        assert_eq!(read_note(&note), None);
        let _ = std::fs::remove_file(&note);
    }

    #[test]
    fn forgetting_a_note_that_was_never_written_succeeds() {
        // A daemon that crashed before recording one, and a daemon shutting
        // down twice, are both ordinary and neither is a failure to report.
        // The temporary directory is certainly not what any note names.
        assert!(forget(&std::env::temp_dir()).is_ok());
    }

    #[test]
    fn a_daemon_shutting_down_leaves_a_newer_daemons_note_alone() {
        // The race this exists for, and it was observed rather than imagined:
        // shutting down runs after every supervised service has been stopped,
        // which is slow, and a second daemon started meanwhile has already
        // written its own note. Removing it leaves a running daemon that no
        // console can find.
        let note = scratch("handover");
        let newer = std::env::temp_dir();
        let older = scratch("older-daemon");
        std::fs::create_dir_all(&older).expect("writable");
        std::fs::write(&note, newer.to_string_lossy().as_bytes()).expect("writable");

        forget_note(&note, &older).expect("not an error to find someone else's note");
        assert!(note.exists(), "the newer daemon's note must survive the older one's shutdown");
        assert_eq!(read_note(&note), Some(newer), "and must still name the newer daemon");

        let _ = std::fs::remove_file(&note);
        let _ = std::fs::remove_dir_all(&older);
    }

    #[test]
    fn a_daemon_shutting_down_removes_its_own_note() {
        let note = scratch("own");
        let ours = std::env::temp_dir();
        std::fs::write(&note, ours.to_string_lossy().as_bytes()).expect("writable");

        forget_note(&note, &ours).expect("removable");
        assert!(!note.exists(), "a daemon must not leave a note behind saying it is running");
    }
}
