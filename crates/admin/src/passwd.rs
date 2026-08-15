//! The console login password, stored as a PBKDF2 hash on disk.
//!
//! The stored format is `pbkdf2-sha256$<iterations>$<salt>$<derived>` (base64), the same format
//! `selfhost-reports`' accounts subsystem uses. Both crates hash and verify through
//! `selfhost_login::password` rather than each carrying its own copy — see that crate's
//! documentation for why the two were mirrored by hand until now.
//!
//! A missing or empty password file is not an error: it means nobody has run
//! `selfhost console-password` yet, so console login simply always fails —
//! logged once at load, never per attempt — while the bearer-token path keeps
//! working. Failing closed here is what makes shipping the feature safe before
//! every deployment has set a password.

use std::io;
use std::path::{Path, PathBuf};

/// The name of the console password file inside the data directory.
pub const CONSOLE_PASSWORD_FILENAME: &str = "console.passwd";

/// The console login password, as loaded from the data directory.
///
/// Holds only the stored hash — a plaintext password never lives in this type.
/// When no password has been set, [`ConsolePassword::verify`] always answers
/// `false`, so an unconfigured deployment fails closed rather than open.
pub struct ConsolePassword {
    /// The stored `pbkdf2-sha256$...` line, or `None` when no password is set.
    stored: Option<String>,
}

impl ConsolePassword {
    /// Loads the password hash from `<data_dir>/console.passwd`.
    ///
    /// A missing, empty, or unreadable file loads as "no password set" — logged
    /// here, once, so every subsequent failed login stays silent and a log
    /// reader is not left guessing why the console refuses everyone.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => Self { stored: Some(text.trim().to_owned()) },
            Ok(_) => {
                eprintln!(
                    "admin: {} is empty; console login is disabled until \
                     `selfhost console-password` sets one",
                    path.display()
                );
                Self { stored: None }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!(
                    "admin: no console password at {}; console login is disabled until \
                     `selfhost console-password` sets one",
                    path.display()
                );
                Self { stored: None }
            }
            Err(error) => {
                eprintln!(
                    "admin: could not read {}: {error}; console login is disabled",
                    path.display()
                );
                Self { stored: None }
            }
        }
    }

    /// Where the password file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(CONSOLE_PASSWORD_FILENAME)
    }

    /// Whether a presented password matches the stored hash.
    ///
    /// Constant-time in the comparison (`selfhost_login::password::verify`). With no password
    /// set this is always `false` — never a panic, never an error a caller could accidentally
    /// treat as a success.
    pub fn verify(&self, password: &str) -> bool {
        match &self.stored {
            Some(stored) => selfhost_login::password::verify(stored, password),
            None => false,
        }
    }

    /// Hashes a password as `pbkdf2-sha256$<iterations>$<salt>$<derived>`.
    ///
    /// The one place a plaintext console password becomes a stored hash. The
    /// salt is random per call, so two deployments with the same password store
    /// different hashes. Errors only if the system's random source refuses.
    pub fn hash(password: &str) -> io::Result<String> {
        selfhost_login::password::hash(password)
    }

    /// Hashes `password` and writes it to `<data_dir>/console.passwd`.
    ///
    /// Written owner-only (0600) via a temporary file and rename, like the
    /// token: the rename is atomic within the directory, so a crash mid-write
    /// leaves the previous password intact rather than a truncated file that
    /// would silently disable login.
    pub fn write(data_dir: &Path, password: &str) -> io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let hashed = Self::hash(password)?;
        let path = Self::path_in(data_dir);
        let temporary = path.with_extension("passwd.new");
        crate::token::write_private(&temporary, &hashed)?;
        std::fs::rename(&temporary, &path)
    }
}

// Deliberately not `Display` or a revealing `Debug`: even a hash in a log line
// is a head start for an offline guesser.
impl std::fmt::Debug for ConsolePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsolePassword(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to one test.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-passwd-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_written_password_verifies_and_a_wrong_one_does_not() {
        let dir = scratch("roundtrip");
        ConsolePassword::write(&dir, "hunter2").expect("written");
        let password = ConsolePassword::load(&dir);
        assert!(password.verify("hunter2"));
        assert!(!password.verify("wrong"));
        assert!(!password.verify(""), "an empty guess is still a guess");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_fails_every_login_rather_than_panicking() {
        let dir = scratch("missing");
        let password = ConsolePassword::load(&dir);
        assert!(!password.verify("anything"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_fails_closed() {
        let dir = scratch("empty");
        std::fs::write(ConsolePassword::path_in(&dir), "  \n").unwrap();
        assert!(!ConsolePassword::load(&dir).verify("anything"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_stored_format_matches_selfhost_login() {
        // The contract this module now delegates to entirely: four `$`-separated fields with a
        // fixed algorithm tag, so a hash set by either `selfhost-admin` or `selfhost-reports`
        // verifies in both.
        let hashed = ConsolePassword::hash("pw").unwrap();
        let parts: Vec<&str> = hashed.split('$').collect();
        assert_eq!(parts.len(), 4, "{hashed}");
        assert_eq!(parts[0], "pbkdf2-sha256");
        assert_eq!(parts[1], selfhost_login::password::ITERATIONS.to_string());
        assert_eq!(
            selfhost_login::password::b64_decode(parts[3]).unwrap().len(),
            selfhost_login::password::KEY_LEN
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_password_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        ConsolePassword::write(&dir, "pw").expect("written");
        let mode =
            std::fs::metadata(ConsolePassword::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_temporary_file_is_left_behind_after_a_write() {
        let dir = scratch("atomic");
        ConsolePassword::write(&dir, "pw").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_password_does_not_print_itself() {
        let dir = scratch("debug");
        ConsolePassword::write(&dir, "supersecret").unwrap();
        let password = ConsolePassword::load(&dir);
        assert!(!format!("{password:?}").contains("pbkdf2"), "even the hash stays out of logs");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
