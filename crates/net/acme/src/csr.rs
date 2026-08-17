//! The finalize CSR — a PKCS#10 request over the ordered domains.
//!
//! ACME finalize (RFC 8555 §7.4) sends a PKCS#10 CSR whose SANs are the order's
//! identifiers. The leaf keypair generated here is the certificate's private key
//! and is returned as PEM for installation; it is deliberately **separate** from
//! the account key — the account key authenticates the ACME account and must
//! never sign the CSR.
//!
//! `rcgen` builds and signs the CSR (it is already a dependency, and roadmap #1
//! settles that we do not hand-roll ASN.1). Its default keypair is P-256 over the
//! `ring` backend, matching the rest of the crate's crypto choice.

use crate::AcmeError;
use rcgen::{CertificateParams, KeyPair};

/// A finalize CSR and the leaf private key that matches the certificate it yields.
pub struct CertMaterial {
    /// The PKCS#10 CSR in DER form, ready to be base64url'd into `finalize`.
    pub csr_der: Vec<u8>,
    /// The leaf private key in PEM form — the certificate's key, not the account's.
    pub key_pem: String,
}

/// Builds a fresh-keyed PKCS#10 CSR over `domains` (SANs; `domains[0]` is the CN).
///
/// A new P-256 keypair is generated for every call, so each issued certificate
/// gets its own key. Fails with [`AcmeError::Crypto`] if `domains` is empty or if
/// `rcgen` rejects a name.
pub fn build_csr(domains: &[String]) -> Result<CertMaterial, AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::Crypto("cannot build a CSR with no domains".to_owned()));
    }
    let key = KeyPair::generate()
        .map_err(|error| AcmeError::Crypto(format!("leaf key generation failed: {error}")))?;
    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|error| AcmeError::Crypto(format!("invalid certificate name: {error}")))?;
    // `CertificateParams::new` sets the SANs from `domains` but leaves the
    // subject at rcgen's own default — a literal "rcgen self signed cert"
    // common name, which is not a domain name at all and CAs reject on
    // finalize. A CA-facing CSR carries its identity in the SANs; the subject
    // is cleared rather than populated, the same shape a modern ACME client
    // (certbot, acme.sh) sends.
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params
        .serialize_request(&key)
        .map_err(|error| AcmeError::Crypto(format!("CSR construction failed: {error}")))?;
    Ok(CertMaterial { csr_der: csr.der().to_vec(), key_pem: key.serialize_pem() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_csr_carries_der_and_a_leaf_key() {
        let material = build_csr(&["example.test".to_owned(), "www.example.test".to_owned()])
            .expect("CSR builds");
        // PKCS#10 DER begins with a SEQUENCE (0x30); the key is a PEM block.
        assert_eq!(material.csr_der.first(), Some(&0x30));
        assert!(material.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn each_csr_gets_a_fresh_key() {
        let a = build_csr(&["example.test".to_owned()]).unwrap();
        let b = build_csr(&["example.test".to_owned()]).unwrap();
        assert_ne!(a.key_pem, b.key_pem);
    }

    #[test]
    fn zero_domains_is_refused() {
        assert!(matches!(build_csr(&[]), Err(AcmeError::Crypto(_))));
    }

    #[test]
    fn the_subject_carries_no_placeholder_name() {
        // Regression: `CertificateParams::new` leaves rcgen's own default
        // subject in place unless cleared, which stamps every CSR with the
        // literal string "rcgen self signed cert" — not a domain, and a CA
        // rejects finalize on it. The requested domain must appear only in
        // the SANs, and that placeholder must appear nowhere in the DER.
        let material = build_csr(&["example.test".to_owned()]).expect("CSR builds");
        let text = String::from_utf8_lossy(&material.csr_der);
        assert!(!text.contains("rcgen self signed cert"), "the default subject was not cleared");
    }
}
