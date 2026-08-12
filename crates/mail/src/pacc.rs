//! The digest that vouches for the PACC configuration document.
//!
//! `selfhost_config::pacc` derives the document — the exact JSON bytes the proxy
//! serves at `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`
//! — and this module hashes them, because the `config` crate is the schema and
//! links no crypto provider. A client fetches the document, computes this same
//! digest, and compares it against the `_ua-auto-config` `TXT` record; a
//! mismatch means the configuration is discarded, so the two must be produced
//! from one set of bytes and this function is the only thing that turns those
//! bytes into a record value.
//!
//! `draft-ietf-mailmaint-pacc` fixes the algorithm at SHA-256 and the encoding
//! at standard base64 — the same pair DKIM's `bh=` uses, so the same two
//! primitives in [`crate::dkim`] serve both, and this crate still links exactly
//! one crypto provider.

use crate::dkim::{b64_encode, sha256};

/// The base64 SHA-256 digest of a PACC configuration document.
///
/// `document` must be the exact string `selfhost_config::pacc::document`
/// produced and the proxy serves — hashing anything else (a re-serialised copy,
/// a pretty-printed variant) publishes a digest no client can reproduce.
///
/// The result is the `d=` tag of `selfhost_config::pacc::txt_value`.
pub fn digest(document: &str) -> String {
    b64_encode(&sha256(document.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_base64_sha256_of_the_served_bytes() {
        // The published SHA-256 of "abc", the canonical test vector.
        assert_eq!(digest("abc"), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    }

    #[test]
    fn a_changed_document_changes_the_digest() {
        let one = selfhost_config::pacc::document("example.com");
        let other = selfhost_config::pacc::document("example.net");
        assert_ne!(digest(&one), digest(&other));
    }
}
