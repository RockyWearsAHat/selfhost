//! Adding and removing a peer from a relay's roster, without ever generating
//! or parsing a key.
//!
//! [`keys`](crate::keys) already draws the line: this crate resolves paths and
//! reads what is on disk, and generating a keypair is the tunnel
//! implementation's job. This module is the other half of writing — a peer's
//! `.pub` file and the roster file both — held to that same line: the caller
//! hands this module a public key it already has (typed by an operator, or
//! generated on the person's own machine by `key_manager.py`), and this module
//! never does anything with it but write it down.
//!
//! # Why the roster file, not `[[vpn.peers]]`
//!
//! A config edit is a restart: `server.py`'s own docstring on
//! [`crate::roster::Roster`] (the config-side reconciliation) is that a config
//! peer becomes a `--peer` flag baked into the argv a relay was launched with.
//! `~/Secure-VPN/server.py`'s *own* `Roster` class is the other half of that
//! story and the reason this module can exist at all: it resolves `--roster`,
//! when the flag is omitted, to `<key-dir>/roster` by default — so every relay
//! `crates/services/vpn/src/runner.rs::plan` has ever started is *already*
//! watching that file, re-read on every handshake attempt. Writing a name into
//! it and a key into the directory beside it is therefore enrolment with no
//! restart and no dropped tunnels, using a mechanism this deployment was
//! already running and not exercising.
//!
//! A permanent, reviewed key — the operator's own — still belongs in
//! `[[vpn.peers]]`, diffed and committed like any other access decision. This
//! module is the fast lane for a capability grant made through the console or
//! the CLI, with the people registry's `vpn.access:<location>` grant serving as
//! the audited record of *why* the name is there.

use selfhost_config::vpn::{peer_name_problem, public_key_problem};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::keys::{PEER_KEY_TAG, peer_key_file};

/// The file `server.py` reads a roster from when none is passed on its command
/// line — see the module documentation. Named here so a caller never has to
/// spell `"roster"` themselves.
pub const ROSTER_FILE: &str = "roster";

/// Where a relay's roster file lives, inside its key directory.
pub fn roster_file(key_dir: &Path) -> PathBuf {
    key_dir.join(ROSTER_FILE)
}

/// The names currently enrolled through this relay's roster file — the
/// dynamic peers `[[vpn.peers]]` does not know about, because they never went
/// through a config edit (see the module documentation). A missing roster
/// file reads as no dynamic peers, matching [`revoke`] and [`enrol`]'s own
/// treatment of one.
pub fn roster(key_dir: &Path) -> io::Result<Vec<String>> {
    read_roster(&roster_file(key_dir))
}

/// Why a peer could not be enrolled or revoked.
#[derive(Debug)]
pub enum EnrolError {
    /// The peer name is not one `--identity`, a filename and the roster file
    /// can all safely carry. Carries [`selfhost_config::vpn`]'s own reason.
    BadName(String),
    /// The public key is not the shape a peer key ever is. Carries
    /// [`selfhost_config::vpn`]'s own reason. Only returned by [`enrol`] —
    /// [`revoke`] does not need a key to remove somebody.
    BadKey(String),
    /// The key directory or the roster file could not be read or written.
    Io(io::Error),
}

impl fmt::Display for EnrolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadName(reason) => write!(formatter, "not a usable peer name: {reason}"),
            Self::BadKey(reason) => write!(formatter, "not a usable public key: {reason}"),
            Self::Io(error) => write!(formatter, "could not write the key directory: {error}"),
        }
    }
}

impl std::error::Error for EnrolError {}

impl From<io::Error> for EnrolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Enrols a peer: writes `<key_dir>/<peer>.pub` in the format
/// `key_manager.py` writes and reads, and adds `peer` to `<key_dir>/roster` if
/// it is not already there.
///
/// `public_key` is base64, exactly what a `[[vpn.peers]].public_key` line
/// holds — checked against the same shape rule that field is, so a value that
/// would be rejected in the config is rejected here before it touches disk.
/// Idempotent: enrolling an already-enrolled peer overwrites its key file with
/// the one given (the operator's own re-enrolment after a lost device) and
/// leaves the roster line as it was.
///
/// Creates the key directory if it does not exist. On a platform with POSIX
/// modes, the directory and every file this writes are `0700`/`0600` — the
/// private key that will eventually sit beside them is this relay's whole
/// perimeter, and a name written into the roster is the same kind of secret
/// the invite system's codes are: worth the tighter mode from the first write
/// rather than after an operator notices `chmod 700` in a log line.
pub fn enrol(key_dir: &Path, peer: &str, public_key: &str) -> Result<(), EnrolError> {
    if let Some(problem) = peer_name_problem(peer) {
        return Err(EnrolError::BadName(problem));
    }
    if let Some(problem) = public_key_problem(public_key) {
        return Err(EnrolError::BadKey(problem));
    }

    create_private_dir(key_dir)?;

    let key_path = peer_key_file(key_dir, peer);
    write_private_file(&key_path, format!("{PEER_KEY_TAG} {} {peer}\n", public_key.trim()))?;

    let roster_path = roster_file(key_dir);
    let mut names = read_roster(&roster_path)?;
    if !names.iter().any(|name| name == peer) {
        names.push(peer.to_owned());
        write_roster(&roster_path, &names)?;
    }

    Ok(())
}

/// Revokes a peer: removes it from `<key_dir>/roster` and deletes its `.pub`
/// file.
///
/// A peer never enrolled through this module — one only in `[[vpn.peers]]`, or
/// already gone — is not an error: revoking twice, or revoking somebody who
/// was only ever a config peer, both leave the roster in the state the caller
/// wanted. Peer name is checked for shape so a caller cannot be tricked into
/// touching a path outside the key directory, but a name that is well-formed
/// and simply absent is silently a no-op.
pub fn revoke(key_dir: &Path, peer: &str) -> Result<(), EnrolError> {
    if let Some(problem) = peer_name_problem(peer) {
        return Err(EnrolError::BadName(problem));
    }

    let roster_path = roster_file(key_dir);
    let names = read_roster(&roster_path)?;
    let remaining: Vec<String> = names.iter().filter(|name| *name != peer).cloned().collect();
    if remaining.len() != names.len() {
        write_roster(&roster_path, &remaining)?;
    }

    let key_path = peer_key_file(key_dir, peer);
    match std::fs::remove_file(&key_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

/// The names currently in the roster file, parsed the way `server.py`'s own
/// `Roster._names_now` parses them: `#` starts a comment, blank lines are
/// skipped. A missing file is an empty roster, matching `server.py` treating a
/// deleted roster as "nobody enrolled through it yet" rather than an error.
fn read_roster(path: &Path) -> io::Result<Vec<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    Ok(text
        .lines()
        .filter_map(|line| {
            let entry = line.split('#').next().unwrap_or("").trim();
            (!entry.is_empty()).then(|| entry.to_owned())
        })
        .collect())
}

/// Writes the roster file, one name per line, replacing whatever was there.
///
/// This module is the only writer `selfhost` has for this file, so replacing
/// it wholesale (rather than editing in place) cannot lose a hand-written
/// comment it did not itself add — there is no such comment, because nothing
/// here ever reads one back out.
fn write_roster(path: &Path, names: &[String]) -> Result<(), EnrolError> {
    let mut text = String::new();
    for name in names {
        text.push_str(name);
        text.push('\n');
    }
    write_private_file(path, text)
}

/// Writes a file at `0600` on a platform with POSIX modes, atomically enough
/// for this purpose: the content is short, local, and this is the only writer.
fn write_private_file(path: &Path, contents: String) -> Result<(), EnrolError> {
    std::fs::write(path, contents)?;
    set_private_mode(path, 0o600)?;
    Ok(())
}

/// Creates a directory at `0700` on a platform with POSIX modes.
fn create_private_dir(path: &Path) -> Result<(), EnrolError> {
    std::fs::create_dir_all(path)?;
    set_private_mode(path, 0o700)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    // ACLs on this platform are the installer's job — see `keys.rs`'s own
    // `directory_too_open`, which is `None` here for the same reason.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("selfhost-vpn-enrol-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    const A_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn enrolling_writes_a_key_file_server_py_can_load() {
        let dir = scratch("write");
        enrol(&dir, "dad", A_KEY).expect("enrol");

        let text = std::fs::read_to_string(peer_key_file(&dir, "dad")).expect("read");
        assert_eq!(text, format!("{PEER_KEY_TAG} {A_KEY} dad\n"));

        let roster = std::fs::read_to_string(roster_file(&dir)).expect("read");
        assert_eq!(roster, "dad\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrolling_twice_does_not_duplicate_the_roster_line() {
        let dir = scratch("dedup");
        enrol(&dir, "dad", A_KEY).expect("enrol");
        enrol(&dir, "dad", A_KEY).expect("enrol again");

        let roster = std::fs::read_to_string(roster_file(&dir)).expect("read");
        assert_eq!(roster, "dad\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrolling_a_second_peer_keeps_the_first() {
        let dir = scratch("two");
        enrol(&dir, "dad", A_KEY).expect("enrol");
        enrol(&dir, "mom", A_KEY).expect("enrol");

        let roster = std::fs::read_to_string(roster_file(&dir)).expect("read");
        assert_eq!(roster, "dad\nmom\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoking_removes_the_roster_line_and_the_key_file() {
        let dir = scratch("revoke");
        enrol(&dir, "dad", A_KEY).expect("enrol");
        enrol(&dir, "mom", A_KEY).expect("enrol");

        revoke(&dir, "dad").expect("revoke");

        let roster = std::fs::read_to_string(roster_file(&dir)).expect("read");
        assert_eq!(roster, "mom\n");
        assert!(!peer_key_file(&dir, "dad").exists());
        assert!(peer_key_file(&dir, "mom").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoking_a_peer_never_enrolled_is_not_an_error() {
        let dir = scratch("revoke-absent");
        revoke(&dir, "nobody").expect("revoke of an absent peer is a no-op");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoking_leaves_a_hand_written_comment_alone() {
        let dir = scratch("comment");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(roster_file(&dir), "# operator note\ndad\nmom\n").expect("seed");

        revoke(&dir, "dad").expect("revoke");

        let roster = std::fs::read_to_string(roster_file(&dir)).expect("read");
        assert_eq!(roster, "mom\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_name_is_refused_before_anything_is_written() {
        let dir = scratch("bad-name");
        let error = enrol(&dir, "Dad Smith", A_KEY).expect_err("bad name");
        assert!(matches!(error, EnrolError::BadName(_)));
        assert!(!dir.exists(), "nothing should be written on a rejected name");
    }

    #[test]
    fn a_bad_key_is_refused_before_anything_is_written() {
        let dir = scratch("bad-key");
        let error = enrol(&dir, "dad", "not-a-key").expect_err("bad key");
        assert!(matches!(error, EnrolError::BadKey(_)));
        assert!(!dir.exists(), "nothing should be written on a rejected key");
    }

    #[cfg(unix)]
    #[test]
    fn the_key_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("modes");
        enrol(&dir, "dad", A_KEY).expect("enrol");

        let dir_mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let key_mode =
            std::fs::metadata(peer_key_file(&dir, "dad")).expect("stat").permissions().mode()
                & 0o777;
        assert_eq!(key_mode, 0o600);
        let roster_mode =
            std::fs::metadata(roster_file(&dir)).expect("stat").permissions().mode() & 0o777;
        assert_eq!(roster_mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
