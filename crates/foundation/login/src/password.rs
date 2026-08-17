//! PBKDF2-HMAC-SHA256 password hashing, in the one stored format every password door in this
//! workspace agrees on: `pbkdf2-sha256$<iterations>$<salt>$<derived>`, each field base64.
//!
//! Extracted from what used to be two byte-identical copies (`crates/admin/src/passwd.rs` and
//! `crates/reports/src/accounts.rs`) — see the crate-level documentation for why they were
//! mirrored instead of shared until now, and why a dependency-light crate removes the reason.

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::num::NonZeroU32;

/// The PBKDF2 iteration count for newly hashed passwords.
///
/// High enough to make offline guessing expensive, low enough to verify a login without a
/// perceptible delay. The stored hash records the count it was made with, so this can be raised
/// later without invalidating existing hashes.
pub const ITERATIONS: u32 = 600_000;

/// The derived-key length, in bytes (SHA-256 output).
pub const KEY_LEN: usize = 32;

/// Hashes `password` as `pbkdf2-sha256$<iterations>$<salt>$<derived>`.
///
/// The salt is random per call, so two hashes of the same password never match byte-for-byte.
/// Errors only if the system's random source refuses.
pub fn hash(password: &str) -> io::Result<String> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| io::Error::other("the system random source was unavailable"))?;
    let iterations = NonZeroU32::new(ITERATIONS).expect("iteration count is non-zero");

    let mut derived = [0u8; KEY_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &mut derived);
    Ok(format!("pbkdf2-sha256${ITERATIONS}${}${}", b64_encode(&salt), b64_encode(&derived)))
}

/// Verifies `password` against a stored `pbkdf2-sha256$...` hash, constant-time in the
/// comparison (`ring::pbkdf2::verify`).
///
/// A hash in any other format returns `false` rather than erroring: an unverifiable stored value
/// must fail closed, never be treated as a match.
pub fn verify(stored: &str, password: &str) -> bool {
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
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &derived).is_ok()
}

/// Encodes bytes as padded standard base64.
pub fn b64_encode(data: &[u8]) -> String {
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
/// The error carries nothing because every caller only ever asks "did this decode," never why —
/// [`verify`] folds any decode failure into its own uniform `false`, and the only other callers
/// are format-roundtrip checks in tests.
#[allow(clippy::result_unit_err)]
pub fn b64_decode(text: &str) -> Result<Vec<u8>, ()> {
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

    #[test]
    fn a_hashed_password_verifies_and_a_wrong_one_does_not() {
        let hashed = hash("hunter2").unwrap();
        assert!(verify(&hashed, "hunter2"));
        assert!(!verify(&hashed, "wrong"));
        assert!(!verify(&hashed, ""), "an empty guess is still a guess");
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let a = hash("secret").unwrap();
        let b = hash("secret").unwrap();
        assert_ne!(a, b);
        assert!(verify(&a, "secret") && verify(&b, "secret"));
    }

    #[test]
    fn the_stored_format_is_four_dollar_separated_fields() {
        let hashed = hash("pw").unwrap();
        let parts: Vec<&str> = hashed.split('$').collect();
        assert_eq!(parts.len(), 4, "{hashed}");
        assert_eq!(parts[0], "pbkdf2-sha256");
        assert_eq!(parts[1], ITERATIONS.to_string());
        assert_eq!(b64_decode(parts[3]).unwrap().len(), KEY_LEN);
    }

    #[test]
    fn an_unrecognised_hash_format_fails_closed() {
        assert!(!verify("plaintextpassword", "plaintextpassword"));
        assert!(!verify("md5$deadbeef", "anything"));
        assert!(!verify("pbkdf2-sha256$notanumber$AA==$AA==", "anything"));
    }

    #[test]
    fn base64_round_trips_arbitrary_bytes() {
        for len in 0..8 {
            let bytes: Vec<u8> = (0..len).map(|n| n as u8 * 37).collect();
            let encoded = b64_encode(&bytes);
            assert_eq!(b64_decode(&encoded).unwrap(), bytes, "len={len}");
        }
    }
}
