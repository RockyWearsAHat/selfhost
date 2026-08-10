//! Per-host certificate selection by SNI.
//!
//! One shared certificate cannot serve several domains that each want their own
//! trusted name, and the ACME client issues one certificate per site. This
//! resolver holds a [`CertifiedKey`] per hostname and picks by the SNI name in the
//! TLS `ClientHello`. An unknown or absent name falls back to the self-signed
//! certificate, so a connection is never dropped for want of a match — a probe or
//! a not-yet-issued host still gets a handshake.
//!
//! The map is behind an [`RwLock`], not swapped wholesale: reads are the hot path
//! (one per handshake) and writes are rare (one per issuance or renewal). A single
//! [`refresh`](SniResolver::refresh) re-reads one host after its certificate lands,
//! so a fresh certificate takes effect without restarting the listener. An
//! `arc-swap`-style crate would be lighter for the read side, but the dependency
//! policy admits no such crate and the lock is not a measured bottleneck.

use crate::tls::{CertificateStore, TlsError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Chooses a certificate per connection from the SNI name.
///
/// Keys are stored lowercased and looked up lowercased, because SNI names are
/// case-insensitive and a browser may send either.
#[derive(Debug)]
pub struct SniResolver {
    by_host: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback: Arc<CertifiedKey>,
}

impl SniResolver {
    /// Builds a resolver seeded from the pairs `store` already holds for `hosts`.
    ///
    /// `fallback_host` must have a usable pair on disk — the daemon ensures a
    /// self-signed one exists before calling this — and answers every SNI name
    /// with no certificate of its own. A host in `hosts` whose pair cannot be
    /// loaded is skipped rather than fatal: the fallback still serves it, and the
    /// issuance task will install and [`refresh`](Self::refresh) it shortly.
    pub fn new(
        store: &CertificateStore,
        hosts: &[String],
        fallback_host: &str,
    ) -> Result<Arc<Self>, TlsError> {
        let fallback = load_certified_key(store, fallback_host)?;

        let mut by_host = HashMap::new();
        for host in hosts {
            match load_certified_key(store, host) {
                Ok(certified) => {
                    by_host.insert(host.to_ascii_lowercase(), certified);
                }
                // A missing or unreadable pair is expected before first issuance.
                Err(_) => continue,
            }
        }

        Ok(Arc::new(Self { by_host: RwLock::new(by_host), fallback }))
    }

    /// Re-reads one host's pair after it is (re)issued, replacing any prior entry.
    ///
    /// Called from the issuance task the moment a certificate is installed, so the
    /// next handshake for that host serves the new certificate.
    pub fn refresh(&self, store: &CertificateStore, host: &str) -> Result<(), TlsError> {
        let certified = load_certified_key(store, host)?;
        let mut map = self.by_host.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        map.insert(host.to_ascii_lowercase(), certified);
        Ok(())
    }

    /// The certificate to serve for a given SNI name, or the fallback.
    ///
    /// Split out from [`ResolvesServerCert::resolve`] so the selection can be
    /// exercised without constructing a `ClientHello`, which rustls does not let
    /// callers build.
    fn select(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        if let Some(name) = server_name {
            let map = self.by_host.read().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(certified) = map.get(&name.to_ascii_lowercase()) {
                return Arc::clone(certified);
            }
        }
        Arc::clone(&self.fallback)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.select(hello.server_name()))
    }
}

/// Loads a host's stored pair and binds it to a ring signing key.
fn load_certified_key(store: &CertificateStore, host: &str) -> Result<Arc<CertifiedKey>, TlsError> {
    let (chain, key) = store.load(host)?;
    certified_key(chain, key)
}

/// Pairs a certificate chain with a private key rustls can sign with.
///
/// The signing key comes from the ring provider the daemon installs at startup;
/// no other provider is compiled in, so this is the one that matches the socket.
fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_data(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-sni-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store_with(label: &str, hosts: &[&str]) -> CertificateStore {
        let store = CertificateStore::open(&temp_data(label)).unwrap();
        for host in hosts {
            store.load_or_generate_self_signed(host, &[]).unwrap();
        }
        store
    }

    #[test]
    fn a_known_host_gets_its_own_certificate() {
        let store = store_with("known", &["a.example", "b.example", "fallback.example"]);
        let resolver = SniResolver::new(
            &store,
            &["a.example".to_owned(), "b.example".to_owned()],
            "fallback.example",
        )
        .unwrap();

        // Its own certificate, not the fallback.
        let chosen = resolver.select(Some("a.example"));
        assert!(!Arc::ptr_eq(&chosen, &resolver.fallback));
    }

    #[test]
    fn sni_names_match_case_insensitively() {
        let store = store_with("case", &["a.example", "fallback.example"]);
        let resolver =
            SniResolver::new(&store, &["a.example".to_owned()], "fallback.example").unwrap();

        let lower = resolver.select(Some("a.example"));
        let upper = resolver.select(Some("A.EXAMPLE"));
        assert!(Arc::ptr_eq(&lower, &upper), "SNI lookup must be case-insensitive");
    }

    #[test]
    fn an_unknown_or_absent_name_falls_back() {
        let store = store_with("fallback", &["a.example", "fallback.example"]);
        let resolver =
            SniResolver::new(&store, &["a.example".to_owned()], "fallback.example").unwrap();

        assert!(Arc::ptr_eq(&resolver.select(Some("stranger.example")), &resolver.fallback));
        assert!(Arc::ptr_eq(&resolver.select(None), &resolver.fallback));
    }

    #[test]
    fn a_host_without_a_pair_is_skipped_not_fatal() {
        // Before first issuance a site has no certificate; the resolver must
        // still build and fall back rather than refuse to start.
        let store = store_with("missing", &["fallback.example"]);
        let resolver =
            SniResolver::new(&store, &["not-yet.example".to_owned()], "fallback.example").unwrap();

        assert!(Arc::ptr_eq(&resolver.select(Some("not-yet.example")), &resolver.fallback));
    }

    #[test]
    fn refresh_installs_a_newly_issued_certificate() {
        let store = store_with("refresh", &["fallback.example"]);
        let resolver =
            SniResolver::new(&store, &[], "fallback.example").unwrap();
        // Unknown until issued.
        assert!(Arc::ptr_eq(&resolver.select(Some("late.example")), &resolver.fallback));

        let issued = rcgen::generate_simple_self_signed(vec!["late.example".to_owned()]).unwrap();
        store
            .install("late.example", &issued.cert.pem(), &issued.key_pair.serialize_pem())
            .unwrap();
        resolver.refresh(&store, "late.example").unwrap();

        assert!(!Arc::ptr_eq(&resolver.select(Some("late.example")), &resolver.fallback));
    }
}
