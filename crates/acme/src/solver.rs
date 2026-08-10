//! HTTP-01 challenge solver — the write side of ACME domain validation.
//!
//! RFC 8555 §8.3. To prove control of a domain, the certificate authority fetches
//! `http://<domain>/.well-known/acme-challenge/<token>` over plain HTTP and
//! expects the body to be the challenge's *key authorization*. This module writes
//! that file; `selfhost_proxy`'s cleartext path serves it (redirect-exempt) and
//! this module deletes it once the order is validated.
//!
//! The two sides share no type — only the directory path and the filename
//! convention, both fixed by this crate's integration contract. The charset gate
//! below is byte-for-byte the one `selfhost_proxy::server` enforces on the read
//! side, so a hostile response from a CA can never write outside the challenge
//! directory.

use std::io;
use std::path::Path;

/// The key authorization for an HTTP-01 challenge (RFC 8555 §8.1).
///
/// It is `token || "." || account_thumbprint`, where `account_thumbprint` is the
/// unpadded base64url SHA-256 of the account key's canonical JWK. The CA computes
/// the same string and compares it against the served file's body, so both halves
/// must be exactly as the account key produced them — this function only joins
/// them and adds no encoding of its own.
pub fn key_authorization(token: &str, account_thumbprint: &str) -> String {
    format!("{token}.{account_thumbprint}")
}

/// Whether a token is a single safe filename.
///
/// Identical to the gate in `selfhost_proxy::server::serve_acme_challenge`:
/// non-empty, at most 128 bytes, and `[A-Za-z0-9_-]` only. Holding the two in
/// lockstep is what keeps the shared directory safe from both directions — the
/// proxy rejects a hostile request path, and this rejects a hostile CA token
/// before it can become a path.
fn token_is_safe(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Writes `<challenge_dir>/<token>` with the key authorization as its body.
///
/// Creates `challenge_dir` if it does not exist. A token failing the shared
/// charset gate is refused with [`io::ErrorKind::InvalidInput`] rather than
/// written, so the join can never escape the directory.
pub async fn place(challenge_dir: &Path, token: &str, key_authorization: &str) -> io::Result<()> {
    if !token_is_safe(token) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe ACME challenge token"));
    }
    tokio::fs::create_dir_all(challenge_dir).await?;
    tokio::fs::write(challenge_dir.join(token), key_authorization).await
}

/// Removes a previously placed token file.
///
/// Cleanup runs unconditionally once an order settles — valid or invalid — so a
/// token that is already gone is not an error. Any other I/O failure is returned,
/// because a token left behind is a stale proof of control that must not linger
/// silently. The charset gate is applied here too, so a malformed token cannot be
/// turned into a delete outside the directory.
pub async fn remove(challenge_dir: &Path, token: &str) -> io::Result<()> {
    if !token_is_safe(token) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe ACME challenge token"));
    }
    match tokio::fs::remove_file(challenge_dir.join(token)).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-acme-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn key_authorization_joins_token_and_thumbprint() {
        // RFC 8555 §8.1: exactly one dot, no extra encoding.
        assert_eq!(key_authorization("tok3n", "th4mb"), "tok3n.th4mb");
    }

    #[test]
    fn the_charset_gate_matches_the_proxy() {
        // Mirror of proxy::server's challenge-token check.
        assert!(token_is_safe("LoqXcYV8q1ONbJls-hint7"));
        assert!(!token_is_safe("../../../etc/passwd"));
        assert!(!token_is_safe("a/b"));
        assert!(!token_is_safe("a.b"));
        assert!(!token_is_safe(""));
        assert!(!token_is_safe(&"a".repeat(129)));
    }

    #[tokio::test]
    async fn place_then_serveable_then_remove() {
        let dir = temp_dir("place");
        let token = "LoqXcYV8q1ONbJls-hint7";
        let authorization = key_authorization(token, "thumbprint");

        // place creates the directory and writes the exact body the CA fetches.
        place(&dir, token, &authorization).await.unwrap();
        let served = tokio::fs::read_to_string(dir.join(token)).await.unwrap();
        assert_eq!(served, authorization);

        // remove deletes it; a second remove is a no-op, not an error.
        remove(&dir, token).await.unwrap();
        assert!(!dir.join(token).exists());
        remove(&dir, token).await.unwrap();
    }

    #[tokio::test]
    async fn a_traversing_token_is_refused_not_written() {
        let dir = temp_dir("traverse");
        let error = place(&dir, "../escape", "x").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
