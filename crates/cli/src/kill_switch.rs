//! The desktop kill switch: `<data_dir>/desktop.disabled`.
//!
//! # What it is for
//!
//! Remote desktop is the only capability in this repository that *drives the
//! machine* rather than serving data from it. Every other way to switch it off
//! goes through something that could itself be the problem: the config file is
//! read at start-up so turning `enabled` off needs a restart, and the console is
//! reachable by whoever is already inside the tunnel — which, on this box, is
//! anything executing on it at all, because the console gate is loopback.
//!
//! So there is one more way, and it is deliberately the dumbest one that could
//! possibly work: **an empty file whose presence means stop**. An operator who
//! can reach a shell, a Finder window, an SMB mount or a recovery boot can
//! create it, and nothing they need in order to do so — not the daemon, not the
//! admin API, not the config, not a password — has to still be working.
//!
//! ```text
//! touch  <data_dir>/desktop.disabled      # every stream ends, no new one starts
//! rm     <data_dir>/desktop.disabled      # streaming is possible again
//! ```
//!
//! `selfhost desktop disable` and `selfhost desktop enable` are the same two
//! acts spelled as commands, and they say the path out loud precisely so that
//! the file — not the command — is what an operator remembers.
//!
//! # How the daemon honours it
//!
//! The daemon polls [`POLL_INTERVAL`] and holds the answer in one flag. A stream
//! reads that flag on every frame, so an engaged switch ends every running
//! session inside one poll — comfortably under the WebSocket ping interval the
//! plan requires — and [`crate::desk_task`] refuses to open a new one while it
//! is set. Nothing is cached across the poll and nothing is remembered: removing
//! the file is as immediate as creating it.
//!
//! # Failing closed, on purpose
//!
//! [`present`] answers `true` for anything that is not a clean "there is no such
//! file". A permission error, a broken symlink, an I/O failure on the volume:
//! all of them mean *this process cannot prove the switch is off*, and a kill
//! switch that fails open is not a kill switch. The cost of being wrong in this
//! direction is that the desktop stays off until somebody looks, which is the
//! outcome an operator who reached for this file wanted anyway.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The marker's name inside `data_dir`.
///
/// Public because it is an operator-facing path, quoted by `doctor`, by the
/// daemon's banner and by the config template: three places that must all name
/// the same file, and one constant is how they cannot drift.
pub const FILE_NAME: &str = "desktop.disabled";

/// How often the daemon re-checks for the marker.
///
/// Five seconds, chosen against the requirement rather than by taste: the plan
/// says an engaged switch must close every open stream "within one ping
/// interval", the WebSocket ping interval is fifteen seconds, and a poll that is
/// a third of that leaves room for a stream that is mid-frame when the file
/// appears. A `stat` of one path on a local disk costs nothing at this rate.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What the marker file is given as contents.
///
/// A zero-byte file would work identically — presence is the whole protocol —
/// but an operator who finds this in six months deserves to be told what it does
/// and how to undo it by the file itself, without a search through documentation
/// that may not be on the machine.
const EXPLANATION: &str = "\
selfhost — remote desktop is switched off.

While this file exists the daemon closes every desktop stream and refuses to
open a new one. Nothing else is affected: websites, mail, DNS, the file shares
and the admin console all keep running.

Delete this file to allow desktop streaming again, or run:

  selfhost desktop enable

The daemon notices within a few seconds either way; no restart is needed.
";

/// Where the marker lives for this deployment.
pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Whether the kill switch is engaged.
///
/// Answers `true` for anything but a clean "no such file", for the reason the
/// module documentation gives: an answer this process cannot establish is not
/// permission to carry on driving somebody's machine.
pub fn present(data_dir: &Path) -> bool {
    // `symlink_metadata` rather than `exists`: a broken symlink placed at this
    // path is somebody asking for the desktop to stop, and `exists` follows the
    // link and reports `false` for it.
    match std::fs::symlink_metadata(path_in(data_dir)) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Creates the marker, so the desktop stops.
///
/// Idempotent: engaging a switch that is already engaged rewrites the same
/// explanation and reports success, because "make sure this is off" is the
/// request being made and answering it with an error would send an operator
/// looking for a second problem during the one they already have.
pub fn engage(data_dir: &Path) -> io::Result<()> {
    std::fs::write(path_in(data_dir), EXPLANATION)
}

/// Removes the marker, so the desktop may run again.
///
/// Reports whether there was one to remove, so a caller can tell "switched back
/// on" from "was never off" instead of printing a success message for an act
/// that did nothing.
pub fn release(data_dir: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path_in(data_dir)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh empty directory, named after the test that asked for it.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-killswitch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp dir");
        dir
    }

    #[test]
    fn an_absent_marker_is_not_engaged() {
        let dir = temp_dir("absent");
        assert!(!present(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engaging_and_releasing_round_trips() {
        let dir = temp_dir("roundtrip");

        engage(&dir).expect("engage");
        assert!(present(&dir), "the marker is there, so the switch reads engaged");

        // Engaging twice is a statement, not an error.
        engage(&dir).expect("engage again");
        assert!(present(&dir));

        assert!(release(&dir).expect("release"), "there was one to remove");
        assert!(!present(&dir));
        assert!(!release(&dir).expect("release again"), "nothing left to remove");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_marker_explains_itself() {
        let dir = temp_dir("explains");
        engage(&dir).expect("engage");
        let text = std::fs::read_to_string(path_in(&dir)).expect("read the marker");
        assert!(
            text.contains("selfhost desktop enable"),
            "an operator who finds this file is told how to undo it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_symlink_still_reads_as_engaged() {
        // The `exists`-follows-links trap: a marker that points nowhere is still
        // an operator saying stop.
        #[cfg(unix)]
        {
            let dir = temp_dir("symlink");
            std::os::unix::fs::symlink(dir.join("nowhere"), path_in(&dir))
                .expect("place a dangling symlink");
            assert!(present(&dir));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
