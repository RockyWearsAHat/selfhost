//! The console login password, stored as a PBKDF2 hash on disk.
//!
//! The stored format is `pbkdf2-sha256$<iterations>$<salt>$<derived>` (base64),
//! deliberately identical to the mailbox password format in
//! `selfhost-mail`'s submission module. The logic is mirrored rather than
//! imported: the admin API must not pull the whole mail stack — SMTP, TLS,
//! queues — into its dependency graph to verify one password, and the format is
//! small enough that the duplication is a dozen lines against an entire crate.
//!
//! A missing or empty password file is not an error: it means nobody has run
//! `selfhost console-password` yet, so console login simply always fails —
//! logged once at load, never per attempt — while the bearer-token path keeps
//! working. Failing closed here is what makes shipping the feature safe before
//! every deployment has set a password.

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// The PBKDF2 iteration count for newly hashed passwords.
///
/// High enough to make offline guessing expensive, low enough to verify a login
/// without a perceptible delay. The stored hash records the count it was made
/// with, so this can be raised later without invalidating existing hashes.
const PBKDF2_ITERATIONS: u32 = 600_000;

/// The derived-key length, in bytes (SHA-256 output).
const PBKDF2_KEY_LEN: usize = 32;

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
    /// Constant-time in the comparison (ring's `pbkdf2::verify`). With no
    /// password set this is always `false` — never a panic, never an error a
    /// caller could accidentally treat as a success.
    pub fn verify(&self, password: &str) -> bool {
        match &self.stored {
            Some(stored) => verify_pbkdf2(stored, password),
            None => false,
        }
    }

    /// Hashes a password as `pbkdf2-sha256$<iterations>$<salt>$<derived>`.
    ///
    /// The one place a plaintext console password becomes a stored hash. The
    /// salt is random per call, so two deployments with the same password store
    /// different hashes. Errors only if the system's random source refuses.
    pub fn hash(password: &str) -> io::Result<String> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; 16];
        rng.fill(&mut salt)
            .map_err(|_| io::Error::other("the system random source was unavailable"))?;
        let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).expect("iteration count is non-zero");

        let mut derived = [0u8; PBKDF2_KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            password.as_bytes(),
            &mut derived,
        );
        Ok(format!(
            "pbkdf2-sha256${PBKDF2_ITERATIONS}${}${}",
            b64_encode(&salt),
            b64_encode(&derived)
        ))
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

/// Verifies a password against a stored `pbkdf2-sha256$...` hash, constant-time.
///
/// A hash in any other format returns `false` rather than erroring: an
/// unverifiable stored value must fail closed, never be treated as a match.
fn verify_pbkdf2(stored: &str, password: &str) -> bool {
    let mut parts = stored.split('$');
    if parts.next() != Some("pbkdf2-sha256") {
        return false;
    }
    let (Some(iterations), Some(salt_b64), Some(derived_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(iterations), Ok(salt), Ok(derived)) =
        (iterations.parse::<u32>(), b64_decode(salt_b64), b64_decode(derived_b64))
    else {
        return false;
    };
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    // ring's verify is constant-time in the comparison.
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &derived)
        .is_ok()
}

/// Encodes bytes as padded standard base64.
///
/// Mirrored from the mail crate for the same hash format; see the module
/// documentation for why it is copied rather than imported.
fn b64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(bits >> 6 & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(bits & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Decodes padded or unpadded standard base64.
///
/// The decode counterpart to [`b64_encode`], accepting hashes written by hand
/// or by other tools that omit padding.
fn b64_decode(text: &str) -> Result<Vec<u8>, ()> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut symbols = Vec::new();
    for byte in text.bytes() {
        match byte {
            b'=' => {}
            other => symbols.push(value(other).ok_or(())?),
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
        if group.len() == 1 {
            return Err(()); // a lone symbol cannot encode any byte
        }
        let bits = group.iter().enumerate().fold(0u32, |acc, (i, s)| acc | (s << (18 - 6 * i)));
        out.push((bits >> 16) as u8);
        if group.len() > 2 {
            out.push((bits >> 8) as u8);
        }
        if group.len() > 3 {
            out.push(bits as u8);
        }
    }
    Ok(out)
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
    fn an_unrecognised_hash_format_fails_closed() {
        // A stored value that is not a pbkdf2-sha256 hash must never match.
        assert!(!verify_pbkdf2("plaintextpassword", "plaintextpassword"));
        assert!(!verify_pbkdf2("md5$deadbeef", "anything"));
        assert!(!verify_pbkdf2("pbkdf2-sha256$notanumber$AA==$AA==", "anything"));
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        // A per-call random salt means identical passwords never share a hash.
        let a = ConsolePassword::hash("secret").unwrap();
        let b = ConsolePassword::hash("secret").unwrap();
        assert_ne!(a, b);
        assert!(verify_pbkdf2(&a, "secret") && verify_pbkdf2(&b, "secret"));
    }

    #[test]
    fn the_hash_matches_the_mail_crates_stored_format() {
        // The contract this module mirrors: four `$`-separated fields with a
        // fixed algorithm tag, so a hash set by either tool verifies in both.
        let hashed = ConsolePassword::hash("pw").unwrap();
        let parts: Vec<&str> = hashed.split('$').collect();
        assert_eq!(parts.len(), 4, "{hashed}");
        assert_eq!(parts[0], "pbkdf2-sha256");
        assert_eq!(parts[1], PBKDF2_ITERATIONS.to_string());
        assert_eq!(b64_decode(parts[3]).unwrap().len(), PBKDF2_KEY_LEN);
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
