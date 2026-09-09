//! Authenticating as a GitHub App and minting short-lived installation tokens.
//!
//! This crate is increment (a) of a Netlify-style deploy bot: it gives the
//! workspace the ability to sign a GitHub App JWT ([`jwt::app_jwt`]) and
//! exchange it for an installation access token ([`token::InstallationTokenCache`]).
//! Nothing here is wired into the proxy, the admin console, or
//! `crates/foundation/config` yet — a later increment adds the webhook
//! receiver and wires deploys to it. This crate is unused by the rest of the
//! workspace and adds no listener; it only ever makes outbound requests to
//! `api.github.com`, and only when a caller asks it to.
//!
//! # No secret ever touches disk here
//!
//! [`AppCredentials::load`] reads the App's private key *from* disk (the
//! operator's own PEM file, outside this crate's control), but every token
//! this crate mints is held only in [`token::InstallationTokenCache`]'s
//! in-memory map. Nothing in this crate writes a token, a JWT, or the private
//! key to disk, a log, or anywhere else.
//!
//! # Transport
//!
//! See [`transport`] module docs for why this crate carries its own small
//! HTTPS client rather than reusing `crates/net/acme`'s.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod jwt;
pub mod store;
pub mod token;
pub mod transport;
pub mod webhook;

use std::path::PathBuf;

pub use store::{
    Installation, InstallationState, Store, StoreError, TrackedRepo, parse_owner_repo, repository_matches,
    store_path,
};
pub use token::{CachedToken, InstallationTokenCache};
pub use webhook::{
    DeliveryOutcome, GithubEvent, InstallationEvent, InstallationRepositoriesEvent, PushEvent, RepoRef,
    WebhookDelivery, WebhookParseError,
};

/// A GitHub App's identity and where to find its private key.
///
/// The key is never held as bytes in this struct — only its path — so an
/// `AppCredentials` can be logged or debug-printed without leaking secret
/// material; [`Self::load`] is the one place the key is actually read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCredentials {
    /// The GitHub App's numeric id (the `iss` claim of every JWT it signs).
    pub app_id: u64,
    /// Path to the App's private key, PEM-encoded PKCS#8 (the format GitHub's
    /// "Generate a private key" button downloads).
    pub private_key_pkcs8_pem_path: PathBuf,
}

impl AppCredentials {
    /// Reads and decodes the App's private key into raw PKCS#8 DER.
    ///
    /// Uses `rustls-pemfile` (already a workspace dependency) to strip the PEM
    /// armor rather than hand-rolling base64 parsing.
    pub fn load(&self) -> Result<Vec<u8>, GithubAppError> {
        let pem = std::fs::read(&self.private_key_pkcs8_pem_path)
            .map_err(|error| GithubAppError::KeyUnreadable(error.to_string()))?;
        let mut reader = pem.as_slice();
        let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .next()
            .ok_or_else(|| GithubAppError::InvalidKey("no PKCS#8 private key found in file".into()))?
            .map_err(|error| GithubAppError::InvalidKey(error.to_string()))?;
        Ok(key.secret_pkcs8_der().to_vec())
    }
}

/// Everything that can go wrong authenticating as a GitHub App or minting an
/// installation token.
#[derive(Debug)]
pub enum GithubAppError {
    /// The private key file could not be read (missing, permissions, ...).
    KeyUnreadable(String),
    /// The file's contents were not a valid PKCS#8 PEM/RSA key.
    InvalidKey(String),
    /// Signing the JWT itself failed.
    JwtSigning(String),
    /// The TCP connection, TLS handshake, or HTTP framing to GitHub failed.
    Transport(String),
    /// GitHub answered with a non-2xx status; carries the status and raw body
    /// so a caller can log or interpret GitHub's error object.
    Api {
        /// The HTTP status GitHub returned.
        status: u16,
        /// The raw response body GitHub returned alongside it.
        body: String,
    },
    /// GitHub's response body was not the JSON shape expected.
    InvalidResponse(String),
}

impl std::fmt::Display for GithubAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GithubAppError::KeyUnreadable(detail) => write!(f, "could not read App private key: {detail}"),
            GithubAppError::InvalidKey(detail) => write!(f, "invalid App private key: {detail}"),
            GithubAppError::JwtSigning(detail) => write!(f, "failed to sign App JWT: {detail}"),
            GithubAppError::Transport(detail) => write!(f, "GitHub request failed: {detail}"),
            GithubAppError::Api { status, body } => {
                write!(f, "GitHub API returned {status}: {body}")
            }
            GithubAppError::InvalidResponse(detail) => write!(f, "unexpected GitHub response: {detail}"),
        }
    }
}

impl std::error::Error for GithubAppError {}

impl From<jwt::JwtError> for GithubAppError {
    fn from(error: jwt::JwtError) -> Self {
        GithubAppError::JwtSigning(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loading_a_missing_key_file_reports_key_unreadable() {
        let credentials = AppCredentials {
            app_id: 4606064,
            private_key_pkcs8_pem_path: "/nonexistent/does-not-exist.pem".into(),
        };
        assert!(matches!(credentials.load(), Err(GithubAppError::KeyUnreadable(_))));
    }

    #[test]
    fn loading_a_file_with_no_pkcs8_key_reports_invalid_key() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("github-app-test-{}.pem", std::process::id()));
        std::fs::write(&path, b"not a pem file at all").unwrap();

        let credentials = AppCredentials { app_id: 1, private_key_pkcs8_pem_path: path.clone() };
        let result = credentials.load();
        std::fs::remove_file(&path).ok();

        assert!(matches!(result, Err(GithubAppError::InvalidKey(_))));
    }

    #[test]
    fn display_renders_the_api_error_status_and_body() {
        let error = GithubAppError::Api { status: 401, body: "{\"message\":\"Bad credentials\"}".into() };
        let text = error.to_string();
        assert!(text.contains("401"));
        assert!(text.contains("Bad credentials"));
    }
}
