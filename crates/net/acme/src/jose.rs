//! Account key and JSON Web Signature — the ES256 half of RFC 8555.
//!
//! Every ACME request after the directory fetch is a flattened JWS (RFC 8555
//! §6.2) signed by the account key. The key is P-256 and the signature is
//! ES256, which is `ring`'s `ECDSA_P256_SHA256_FIXED_SIGNING`: it emits the raw
//! `r || s` pair JOSE wants, not the ASN.1 DER a general-purpose signer would.
//!
//! `base64url` here is URL-safe and **unpadded**, the only encoding JOSE and
//! ACME use. It is fifteen lines and lives here rather than pulling a crate, in
//! keeping with the dependency policy — the base64 crate is only a transitive
//! dependency and must not become a direct one.

use crate::AcmeError;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use ring::digest;
use selfhost_json::Json;

/// Encodes bytes as unpadded URL-safe base64 (RFC 4648 §5, no `=`).
///
/// This is the encoding used everywhere in JOSE and ACME: the JWS fields, the
/// JWK coordinates, the key-authorization thumbprint, and the finalize CSR. It
/// never emits `+`, `/`, or `=`, so an encoded value is always safe in a URL and
/// in a JSON string without further escaping.
pub(crate) fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(bits >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(bits >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(bits >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(bits & 0x3f) as usize] as char);
        }
    }
    out
}

/// A P-256 ECDSA account key, held alongside the PKCS#8 bytes that persist it.
///
/// The PKCS#8 encoding is what is written to `<data_dir>/acme/account.key`
/// (mode 0600); the parsed [`EcdsaKeyPair`] does the signing. The two are kept
/// together so a loaded key and a freshly generated one are indistinguishable to
/// the rest of the crate.
pub struct AccountKey {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl AccountKey {
    /// Generates a fresh account key.
    pub fn generate() -> Result<Self, AcmeError> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|error| AcmeError::Crypto(format!("account key generation failed: {error}")))?;
        Self::from_pkcs8(document.as_ref())
    }

    /// Reconstructs an account key from its PKCS#8 encoding.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, AcmeError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|error| AcmeError::Crypto(format!("account key was not valid PKCS#8: {error}")))?;
        Ok(Self { pkcs8: der.to_vec(), pair })
    }

    /// The PKCS#8 bytes to persist. Secret material — write it mode 0600.
    pub fn to_pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public JWK for this key: `{crv, kty, x, y}` for P-256.
    pub fn jwk(&self) -> Jwk {
        // ring returns the public key uncompressed: 0x04 || X(32) || Y(32).
        let point = self.pair.public_key().as_ref();
        Jwk {
            crv: "P-256",
            kty: "EC",
            x: base64url(&point[1..33]),
            y: base64url(&point[33..65]),
        }
    }

    /// The account key thumbprint: `base64url(SHA-256(canonical JWK))`.
    ///
    /// The canonical JWK is the required members in lexicographic order with no
    /// whitespace (RFC 7638 §3.2 / RFC 8555 §8.1): exactly `crv,kty,x,y`. The
    /// string is built by hand rather than via [`Json`] serialisation so the
    /// member set is guaranteed to be only those four — an extra field would
    /// change the hash and break every key authorization.
    pub fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk.crv, jwk.kty, jwk.x, jwk.y
        );
        base64url(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref())
    }

    /// Signs `message`, returning the 64-byte `r || s` ES256 signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AcmeError> {
        let rng = SystemRandom::new();
        self.pair
            .sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|error| AcmeError::Crypto(format!("ES256 signing failed: {error}")))
    }
}

/// A JSON Web Key for a P-256 key: the public half, as it appears on the wire.
pub struct Jwk {
    /// The curve, always `"P-256"` here.
    pub crv: &'static str,
    /// The key type, always `"EC"` here.
    pub kty: &'static str,
    /// The unpadded-base64url big-endian X coordinate.
    pub x: String,
    /// The unpadded-base64url big-endian Y coordinate.
    pub y: String,
}

impl Jwk {
    /// This JWK as a [`Json`] object, for embedding in a JWS protected header.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("crv", Json::string(self.crv)),
            ("kty", Json::string(self.kty)),
            ("x", Json::string(self.x.clone())),
            ("y", Json::string(self.y.clone())),
        ])
    }
}

/// Signs a request as a flattened JWS (RFC 8555 §6.2).
///
/// `protected_header` is built by the caller and already carries `alg` (`ES256`),
/// `nonce`, `url`, and exactly one of `jwk` (newAccount) or `kid` (every later
/// request). `payload` is the raw request JSON, or an empty slice for a
/// POST-as-GET. The signing input is `base64url(protected) . base64url(payload)`
/// and the result is `{"protected":…,"payload":…,"signature":…}`.
pub fn sign_jws(
    key: &AccountKey,
    protected_header: &Json,
    payload: &[u8],
) -> Result<Vec<u8>, AcmeError> {
    let protected_b64 = base64url(protected_header.to_text().as_bytes());
    let payload_b64 = base64url(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = key.sign(signing_input.as_bytes())?;
    let jws = Json::object([
        ("protected", Json::string(protected_b64)),
        ("payload", Json::string(payload_b64)),
        ("signature", Json::string(base64url(&signature))),
    ]);
    Ok(jws.to_text().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_known_foobar_vectors() {
        // RFC 4648 §10, minus the padding JOSE forbids.
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_never_emits_padding_or_unsafe_characters() {
        let encoded = base64url(&[0xff, 0xff, 0xfe, 0xff]);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn a_jwk_has_two_thirty_two_byte_coordinates() {
        // 32 bytes encode to exactly 43 unpadded base64url characters.
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.x.len(), 43);
        assert_eq!(jwk.y.len(), 43);
    }

    #[test]
    fn a_persisted_key_round_trips_to_the_same_jwk_and_thumbprint() {
        // Loading the stored PKCS#8 must reproduce the identical public key, or
        // an account registered with one key could not be used with the reload.
        let key = AccountKey::generate().unwrap();
        let reloaded = AccountKey::from_pkcs8(key.to_pkcs8()).unwrap();
        assert_eq!(key.jwk().x, reloaded.jwk().x);
        assert_eq!(key.jwk().y, reloaded.jwk().y);
        assert_eq!(key.thumbprint(), reloaded.thumbprint());
    }

    #[test]
    fn the_thumbprint_is_base64url_sha256_of_the_canonical_jwk() {
        // Recompute independently: the members in lexicographic order, no spaces.
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        let canonical =
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, jwk.x, jwk.y);
        let expected = base64url(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref());
        assert_eq!(key.thumbprint(), expected);
        // A thumbprint is a SHA-256 hash: 32 bytes -> 43 base64url characters.
        assert_eq!(key.thumbprint().len(), 43);
    }

    #[test]
    fn a_jws_encodes_its_three_fields_deterministically() {
        let key = AccountKey::generate().unwrap();
        let protected = Json::object([
            ("alg", Json::string("ES256")),
            ("nonce", Json::string("abc")),
            ("url", Json::string("https://example.test/acme/new-order")),
        ]);
        let payload = br#"{"identifiers":[]}"#;
        let jws = sign_jws(&key, &protected, payload).unwrap();

        let value = selfhost_json::parse(std::str::from_utf8(&jws).unwrap()).unwrap();
        // protected and payload are deterministic base64url of the exact bytes.
        assert_eq!(
            value.get("protected").and_then(Json::as_str).unwrap(),
            base64url(protected.to_text().as_bytes())
        );
        assert_eq!(
            value.get("payload").and_then(Json::as_str).unwrap(),
            base64url(payload)
        );
        // ES256 is a 64-byte r||s pair -> 86 unpadded base64url characters.
        assert_eq!(value.get("signature").and_then(Json::as_str).unwrap().len(), 86);
    }

    #[test]
    fn a_post_as_get_signs_an_empty_payload() {
        // POST-as-GET carries payload "" whose base64url is the empty string.
        let key = AccountKey::generate().unwrap();
        let protected = Json::object([("alg", Json::string("ES256"))]);
        let jws = sign_jws(&key, &protected, b"").unwrap();
        let value = selfhost_json::parse(std::str::from_utf8(&jws).unwrap()).unwrap();
        assert_eq!(value.get("payload").and_then(Json::as_str).unwrap(), "");
    }
}
