//! The shared secret that authorises control of the deployment.
//!
//! Whoever holds this token can start and stop everything on the machine, so it
//! is generated from the operating system's entropy — never from a clock, a
//! process id, or a hash of them, all of which are guessable by someone who knows
//! roughly when the daemon started.
//!
//! It lives in a file only the service account can read. That is the same trust
//! model as an SSH private key: the file permissions *are* the security boundary,
//! and anyone who can already read arbitrary files as that account can control
//! the services anyway.

use std::io;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a token. 256 bits, rendered as 64 hex characters.
const TOKEN_BYTES: usize = 32;

/// The name of the token file inside the data directory.
pub const TOKEN_FILENAME: &str = "admin.token";

/// A bearer token authorising control of the deployment.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Loads the token from the data directory, generating one if absent.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        let path = Self::path_in(data_dir);
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                return Ok(Self(trimmed.to_owned()));
            }
        }

        std::fs::create_dir_all(data_dir)?;
        let token = Self(hex(&random_bytes(TOKEN_BYTES)?));
        write_private(&path, &token.0)?;
        Ok(token)
    }

    /// Where the token file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(TOKEN_FILENAME)
    }

    /// The token as it appears in an `Authorization: Bearer` header.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a presented credential matches.
    ///
    /// Compared in constant time. A short-circuiting comparison leaks how many
    /// leading characters were right, which turns guessing the token from
    /// infeasible into a few thousand requests against a local port.
    pub fn matches(&self, presented: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), presented.as_bytes())
    }
}

/// Whether two byte strings are equal, in constant time for equal lengths.
///
/// Shared by every credential comparison in this crate — the bearer token and
/// the session ids — so the no-short-circuit property lives in one place. A
/// length mismatch returns early, which is fine: the length of our secrets is
/// public (64 hex characters).
pub(crate) fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(actual) {
        difference |= a ^ b;
    }
    difference == 0
}

// Deliberately not `Display` or a revealing `Debug`: a token that formats itself
// ends up in a log line eventually, and a secret in a log is a secret no longer.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(<redacted>)")
    }
}

/// Writes a secret so only its owner can read it.
///
/// Shared with [`crate::passwd`], which stores the console password hash under
/// the same trust model as the token: the file permissions are the boundary.
#[cfg(unix)]
pub(crate) fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Created 0600 from the outset rather than written and then chmod-ed: between
    // those two steps the secret is world-readable, and that window is exactly
    // when a shared machine gets to read it.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

/// Windows has no mode bits; the file inherits the directory's ACL.
///
/// The data directory belongs to the service account, so this is equivalent in
/// practice for a single-operator deployment. Tightening the ACL explicitly needs
/// `SetNamedSecurityInfo`, and is worth doing once there is a Windows machine to
/// verify it on.
#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    std::fs::write(path, contents)
}

/// Renders bytes as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Fills a buffer with entropy from the operating system.
///
/// Shared with [`crate::session`], whose session ids need the same
/// unguessability as the token itself.
#[cfg(unix)]
pub(crate) fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buffer = vec![0u8; count];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Windows equivalent, via the system's own generator.
///
/// `RtlGenRandom` is the long-standing entry point for this and needs no
/// initialisation, which keeps the declaration to a single symbol.
#[cfg(windows)]
pub(crate) fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    #[allow(unsafe_code)]
    #[link(name = "advapi32")]
    unsafe extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buffer: *mut u8, length: u32) -> u8;
    }

    let mut buffer = vec![0u8; count];
    #[allow(unsafe_code)]
    let ok = unsafe { RtlGenRandom(buffer.as_mut_ptr(), buffer.len() as u32) };
    if ok == 0 {
        return Err(io::Error::other("the system random number generator refused"));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to one test.
    ///
    /// Named per test rather than per process: tests run concurrently, and a
    /// shared directory means one test deletes the file another is asserting on.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-token-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_generated_token_is_long_and_unpredictable() {
        let bytes = random_bytes(TOKEN_BYTES).expect("system entropy");
        assert_eq!(bytes.len(), TOKEN_BYTES);
        // Two draws matching would mean the source is not random at all.
        let again = random_bytes(TOKEN_BYTES).expect("system entropy");
        assert_ne!(bytes, again);
        assert!(bytes.iter().any(|&b| b != 0), "entropy should not be all zeroes");
    }

    #[test]
    fn the_token_survives_a_restart_rather_than_being_regenerated() {
        // Regenerating on every start would log the console out each time the
        // daemon restarted, which trains the operator to ignore auth failures.
        let dir = scratch("restart");
        let first = Token::load_or_create(&dir).expect("created");
        let second = Token::load_or_create(&dir).expect("loaded");
        assert_eq!(first.as_str(), second.as_str());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn comparison_rejects_wrong_credentials_including_prefixes() {
        let token = Token("abcdef".to_owned());
        assert!(token.matches("abcdef"));
        assert!(!token.matches("abcdeg"));
        assert!(!token.matches("abcde"), "a prefix is not a match");
        assert!(!token.matches("abcdefg"), "nor is an extension");
        assert!(!token.matches(""));
    }

    #[test]
    fn the_token_does_not_print_itself() {
        // A token that formats itself reaches a log file eventually.
        let token = Token("supersecret".to_owned());
        assert!(!format!("{token:?}").contains("supersecret"));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        Token::load_or_create(&dir).expect("created");
        let mode = std::fs::metadata(Token::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
