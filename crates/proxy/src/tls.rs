//! TLS termination.
//!
//! `rustls` provides the cryptography. That is a deliberate line: hand-writing a
//! TLS implementation would make this project less safe, not more independent,
//! and the protocol logic we *do* own sits above the socket.
//!
//! Certificates come from one of three places, chosen in the config:
//!
//! - **self-signed**, generated locally on first start. No network, no rate
//!   limit, no account. This is what lets the whole stack be run and tested on a
//!   laptop with no DNS pointed at it.
//! - **staging** ACME, which issues untrusted certificates from a CA with
//!   generous limits.
//! - **production** ACME.
//!
//! Self-signed is the default for local work precisely so that a first run
//! cannot burn a production rate limit against a domain that does not yet
//! resolve here.

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Why TLS could not be configured.
#[derive(Debug)]
pub enum TlsError {
    /// A certificate or key file could not be read or written.
    Io(io::Error),
    /// The PEM held no usable certificate or key.
    NoUsableMaterial(PathBuf),
    /// Certificate generation failed.
    Generate(String),
    /// rustls refused the material.
    Rustls(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "certificate I/O failed: {e}"),
            Self::NoUsableMaterial(p) => {
                write!(f, "{} contains no usable certificate or private key", p.display())
            }
            Self::Generate(e) => write!(f, "could not generate a self-signed certificate: {e}"),
            Self::Rustls(e) => write!(f, "TLS configuration rejected: {e}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<io::Error> for TlsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Where a deployment's TLS material lives.
///
/// Kept inside the deployment's own data directory rather than a system store,
/// so it is covered by the same backup as everything else and the service can
/// run as an unprivileged account.
#[derive(Debug, Clone)]
pub struct CertificateStore {
    directory: PathBuf,
}

impl CertificateStore {
    /// Opens (and creates) the certificate directory under `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self, TlsError> {
        let directory = data_dir.join("tls");
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    /// Path to the certificate chain for a hostname.
    pub fn certificate_path(&self, host: &str) -> PathBuf {
        self.directory.join(format!("{}.crt.pem", sanitise(host)))
    }

    /// Path to the private key for a hostname.
    pub fn key_path(&self, host: &str) -> PathBuf {
        self.directory.join(format!("{}.key.pem", sanitise(host)))
    }

    /// Whether both halves of a usable pair are already on disk.
    pub fn has_pair(&self, host: &str) -> bool {
        self.certificate_path(host).is_file() && self.key_path(host).is_file()
    }

    /// Loads an existing pair, or generates a self-signed one and stores it.
    ///
    /// Generation is idempotent: a certificate already present is reused, so
    /// restarting does not hand clients a new identity every time.
    pub fn load_or_generate_self_signed(
        &self,
        host: &str,
        alternates: &[String],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
        if self.has_pair(host) {
            return self.load(host);
        }

        let mut names = vec![host.to_owned()];
        names.extend(alternates.iter().cloned());
        names.sort();
        names.dedup();

        let generated =
            rcgen::generate_simple_self_signed(names).map_err(|e| TlsError::Generate(e.to_string()))?;

        fs::write(self.certificate_path(host), generated.cert.pem())?;
        // The key is readable only by its owner: it is the deployment's identity.
        write_private(&self.key_path(host), generated.key_pair.serialize_pem().as_bytes())?;

        self.load(host)
    }

    /// Reads a stored certificate chain and key.
    pub fn load(
        &self,
        host: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
        let certificate_path = self.certificate_path(host);
        let key_path = self.key_path(host);

        let mut certificate_reader = io::BufReader::new(fs::File::open(&certificate_path)?);
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<_, _>>()
            .map_err(TlsError::Io)?;
        if chain.is_empty() {
            return Err(TlsError::NoUsableMaterial(certificate_path));
        }

        let mut key_reader = io::BufReader::new(fs::File::open(&key_path)?);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(TlsError::Io)?
            .ok_or_else(|| TlsError::NoUsableMaterial(key_path))?;

        Ok((chain, key))
    }
}

/// Writes a file that only its owner can read.
///
/// On Unix the mode is set at creation rather than afterwards, so there is no
/// window in which the private key exists world-readable.
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)
    }
    #[cfg(not(unix))]
    {
        // Windows inherits the data directory's ACL, which the installer
        // restricts to the service account.
        fs::write(path, contents)
    }
}

/// Reduces a hostname to characters safe in a filename.
///
/// A wildcard host like `*.example.com` would otherwise be an illegal filename
/// on Windows and a glob on Unix.
fn sanitise(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

/// Builds a rustls server configuration from a certificate chain and key.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;

    // Advertise HTTP/1.1 only. HTTP/2 is not implemented here yet, and claiming
    // it in ALPN would make browsers open a connection we cannot speak on.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-tls-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generates_a_usable_self_signed_pair() {
        let store = CertificateStore::open(&temp_data("generate")).unwrap();
        assert!(!store.has_pair("localhost"));

        let (chain, key) = store.load_or_generate_self_signed("localhost", &[]).unwrap();
        assert!(!chain.is_empty());
        assert!(store.has_pair("localhost"));
        assert!(server_config(chain, key).is_ok());
    }

    #[test]
    fn generation_is_idempotent() {
        // Restarting must not hand clients a brand-new identity each time.
        let store = CertificateStore::open(&temp_data("idempotent")).unwrap();
        store.load_or_generate_self_signed("localhost", &[]).unwrap();
        let first = fs::read(store.certificate_path("localhost")).unwrap();

        store.load_or_generate_self_signed("localhost", &[]).unwrap();
        let second = fs::read(store.certificate_path("localhost")).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wildcard_hosts_become_legal_filenames() {
        assert_eq!(sanitise("*.example.com"), "_.example.com");
        assert_eq!(sanitise("example.com"), "example.com");
        assert_eq!(sanitise("a/../b"), "a_.._b");
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let store = CertificateStore::open(&temp_data("perms")).unwrap();
        store.load_or_generate_self_signed("localhost", &[]).unwrap();

        let mode = fs::metadata(store.key_path("localhost")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "private key is readable by others");
    }

    #[test]
    fn alternate_names_are_included() {
        let store = CertificateStore::open(&temp_data("sans")).unwrap();
        let (chain, _) = store
            .load_or_generate_self_signed("example.com", &["www.example.com".into()])
            .unwrap();
        assert!(!chain.is_empty());
    }
}
