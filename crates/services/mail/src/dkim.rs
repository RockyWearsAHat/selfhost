//! DKIM signing (RFC 6376, RFC 8463) over `ring`.
//!
//! DKIM lets a receiver confirm that a message really came from the domain it
//! claims and was not altered in transit: the sender signs selected headers and
//! a hash of the body with a private key, and publishes the matching public key
//! in DNS at `<selector>._domainkey.<domain>`. Without a valid DKIM signature
//! most large providers refuse mail outright or file it as spam, so for a server
//! on shared IP space DKIM is not optional — it is most of what earns delivery.
//!
//! # What is hand-written here, and what is not
//!
//! The **cryptography is `ring`'s** — key generation, RSA-PKCS#1-v1.5, and
//! Ed25519 all come from the same vetted implementation the ACME and TLS code
//! already link. Hand-rolling a signature primitive would defeat the point of
//! signing at all. What lives here is the DKIM *construction*: canonicalization,
//! header selection, the body hash, and the `DKIM-Signature` field — protocol on
//! the wire, which this project owns by policy.
//!
//! # Algorithm choice
//!
//! [`Dkim::generate`] produces an **Ed25519** key (`a=ed25519-sha256`, RFC 8463):
//! it is what `ring` can generate as well as sign, the key and its DNS record are
//! tiny, and no second crypto provider is pulled in to make RSA keys `ring`
//! cannot. An existing **RSA** key is still honoured — [`Dkim::load`] detects and
//! signs with either — because many verifiers predate Ed25519 and dual-signing is
//! the interoperable path; only *generation* is Ed25519-only.

use crate::message::Message;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};
use std::fmt;
use std::path::Path;

/// The header fields signed when present, in the order they are listed in `h=`.
///
/// `From` is mandatory under RFC 6376 §5.4 and always leads. The rest are the
/// fields whose alteration would change the meaning of the message; unlisted
/// headers a relay may add or reorder without breaking the signature.
const SIGNED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
];

/// Why a DKIM key could not be loaded, generated, or persisted.
#[derive(Debug)]
pub enum DkimError {
    /// The key file could not be read or written.
    Io(std::io::Error),
    /// The PEM wrapper was malformed (missing markers, bad base64).
    Pem(String),
    /// `ring` rejected the key material.
    Key(String),
    /// Signing failed inside `ring`.
    Sign(String),
}

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Pem(m) => write!(f, "malformed PEM: {m}"),
            Self::Key(m) => write!(f, "invalid DKIM key: {m}"),
            Self::Sign(m) => write!(f, "DKIM signing failed: {m}"),
        }
    }
}

impl std::error::Error for DkimError {}

impl From<std::io::Error> for DkimError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// A loaded DKIM signing key and the algorithm it signs with.
///
/// Holds the parsed `ring` key pair; the PKCS#8 bytes are not retained after
/// loading because signing never needs them again and secret material is best
/// not kept in memory longer than required.
pub struct Dkim {
    key: SigningKey,
}

/// The two signing algorithms DKIM defines that `ring` provides.
enum SigningKey {
    /// `a=ed25519-sha256` (RFC 8463). Generated and signed by `ring`.
    Ed25519(Ed25519KeyPair),
    /// `a=rsa-sha256` (RFC 6376). Loaded from an existing key; `ring` cannot
    /// generate RSA keys, so this arm is never produced by [`Dkim::generate`].
    Rsa(Box<RsaKeyPair>),
}

impl Dkim {
    /// Loads a signing key from a PEM PKCS#8 file, detecting Ed25519 or RSA.
    ///
    /// The algorithm is read from the key itself rather than configured
    /// separately, so a mismatched setting cannot produce a signature the
    /// published record will not verify.
    pub fn load(private_key: &Path) -> Result<Self, DkimError> {
        let pem = std::fs::read_to_string(private_key)?;
        let der = pem_to_der(&pem)?;
        // Ed25519 PKCS#8 is a fixed 48/85 bytes and its OID differs from RSA's,
        // so trying it first and falling back never mis-parses one as the other.
        if let Ok(pair) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der) {
            return Ok(Self { key: SigningKey::Ed25519(pair) });
        }
        let pair = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| DkimError::Key(format!("neither a usable Ed25519 nor RSA key: {e}")))?;
        Ok(Self { key: SigningKey::Rsa(Box::new(pair)) })
    }

    /// Generates a fresh Ed25519 key and persists it to `private_key`, mode 0600.
    ///
    /// Creates the parent directory if needed. The private key is secret
    /// material and is written unreadable to other users from the first byte —
    /// never created world-readable and tightened afterwards.
    pub fn generate(private_key: &Path) -> Result<Self, DkimError> {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| DkimError::Key(format!("Ed25519 key generation failed: {e}")))?;
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|e| DkimError::Key(format!("generated key did not re-parse: {e}")))?;

        if let Some(parent) = private_key.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        write_private(private_key, der_to_pem(document.as_ref()).as_bytes())?;
        Ok(Self { key: SigningKey::Ed25519(pair) })
    }

    /// Loads the key at `private_key`, generating and persisting one if absent.
    ///
    /// The common startup path: on first run there is no key, so one is made and
    /// its public record can be published; on every run after, the same key is
    /// reused so already-published records keep verifying.
    pub fn load_or_generate(private_key: &Path) -> Result<Self, DkimError> {
        if private_key.exists() {
            Self::load(private_key)
        } else {
            Self::generate(private_key)
        }
    }

    /// The `a=` tag value for this key's algorithm.
    fn algorithm(&self) -> &'static str {
        match self.key {
            SigningKey::Ed25519(_) => "ed25519-sha256",
            SigningKey::Rsa(_) => "rsa-sha256",
        }
    }

    /// The `DKIM-Signature` header **value** for `msg`, signed for `domain`.
    ///
    /// Returns only the value; the caller prepends it with
    /// [`Message::with_prepended_header`] under the name `DKIM-Signature`. Relaxed
    /// canonicalization is used for both header and body (`c=relaxed/relaxed`) —
    /// the tolerant form that survives the whitespace and folding changes a
    /// forwarding hop commonly makes.
    ///
    /// `timestamp` is the `t=` value (seconds since the Unix epoch); taking it as
    /// an argument rather than reading the clock keeps signing deterministic and
    /// therefore testable.
    pub fn sign(&self, msg: &Message, domain: &str, selector: &str, timestamp: u64) -> Result<String, DkimError> {
        let body_hash = b64_encode(&sha256(&canonicalize_body_relaxed(msg.body())));
        let fields = header_fields(header_block(msg));

        // Choose the signed set and the exact instance of each: bottom-up, as a
        // verifier consumes them, so a message with two of a header signs the
        // lower one and the `h=` list still names it once.
        let mut chosen: Vec<(&str, &str)> = Vec::new();
        let mut names: Vec<&str> = Vec::new();
        for wanted in SIGNED_HEADERS {
            if let Some((name, value)) = fields.iter().rev().find(|(n, _)| n.eq_ignore_ascii_case(wanted)) {
                chosen.push((name.as_str(), value.as_str()));
                names.push(wanted);
            }
        }
        let h_tag = names.join(":");

        // The signing input: each chosen header canonicalized and CRLF-terminated,
        // then the DKIM-Signature header itself with an empty b= and no trailing
        // CRLF (RFC 6376 §3.7).
        let mut input = String::new();
        for (name, value) in &chosen {
            input.push_str(&canonicalize_header_relaxed(name, value));
            input.push_str("\r\n");
        }
        let unsigned = signature_value(self.algorithm(), domain, selector, timestamp, &h_tag, &body_hash, "");
        input.push_str(&canonicalize_header_relaxed("DKIM-Signature", &unsigned));

        let signature = self.sign_bytes(input.as_bytes())?;
        let b_tag = b64_encode(&signature);
        Ok(signature_value(self.algorithm(), domain, selector, timestamp, &h_tag, &body_hash, &b_tag))
    }

    /// Signs the canonicalized header input with the held key.
    ///
    /// For RSA, `ring`'s `RSA_PKCS1_SHA256` hashes the input itself. For Ed25519,
    /// RFC 8463 signs the SHA-256 digest of the same input with PureEdDSA, so the
    /// digest is taken here and handed to `ring` as the message.
    fn sign_bytes(&self, input: &[u8]) -> Result<Vec<u8>, DkimError> {
        match &self.key {
            SigningKey::Ed25519(pair) => Ok(pair.sign(&sha256(input)).as_ref().to_vec()),
            SigningKey::Rsa(pair) => {
                let rng = SystemRandom::new();
                let mut signature = vec![0u8; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, input, &mut signature)
                    .map_err(|e| DkimError::Sign(e.to_string()))?;
                Ok(signature)
            }
        }
    }

    /// The DNS TXT record value publishing this key: `v=DKIM1; k=...; p=<base64>`.
    ///
    /// Published at `<selector>._domainkey.<domain>`. For Ed25519 `p` is the raw
    /// 32-byte public key; for RSA it is the DER `SubjectPublicKeyInfo`, each
    /// standard-base64 encoded as the record format requires.
    pub fn public_txt(&self) -> String {
        match &self.key {
            SigningKey::Ed25519(pair) => {
                format!("v=DKIM1; k=ed25519; p={}", b64_encode(pair.public_key().as_ref()))
            }
            SigningKey::Rsa(pair) => {
                let spki = rsa_spki(pair.public().as_ref());
                format!("v=DKIM1; k=rsa; p={}", b64_encode(&spki))
            }
        }
    }
}

/// Assembles a `DKIM-Signature` value with the given `b=` (empty while signing).
fn signature_value(
    algorithm: &str,
    domain: &str,
    selector: &str,
    timestamp: u64,
    h_tag: &str,
    body_hash: &str,
    b_tag: &str,
) -> String {
    format!(
        "v=1; a={algorithm}; c=relaxed/relaxed; d={domain}; s={selector}; t={timestamp}; h={h_tag}; bh={body_hash}; b={b_tag}"
    )
}

/// The header block of a message: the bytes before the body.
fn header_block(msg: &Message) -> &[u8] {
    let raw = msg.as_bytes();
    &raw[..raw.len() - msg.body().len()]
}

/// Splits a header block into `(name, raw-value)` fields, folding preserved.
///
/// The raw value keeps its internal CRLF+WSP so relaxed canonicalization can
/// unfold and compress it exactly as a verifier will; the trailing CRLF of the
/// last physical line is trimmed. Continuation lines (leading WSP) belong to the
/// field above them.
fn header_fields(block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(block);
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut current: Option<String> = None;

    for line in text.split_inclusive('\n') {
        let folded = line.starts_with(' ') || line.starts_with('\t');
        if folded {
            if let Some(field) = current.as_mut() {
                field.push_str(line);
            }
            continue;
        }
        if let Some(done) = current.take() {
            push_field(&mut fields, done);
        }
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            break; // the blank line that ends the header block
        }
        current = Some(line.to_owned());
    }
    if let Some(done) = current.take() {
        push_field(&mut fields, done);
    }
    fields
}

/// Records one raw field, split into name and value at the first colon.
fn push_field(fields: &mut Vec<(String, String)>, raw: String) {
    if let Some(colon) = raw.find(':') {
        let name = raw[..colon].trim().to_owned();
        let value = raw[colon + 1..].trim_end_matches(['\r', '\n']).to_owned();
        fields.push((name, value));
    }
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2).
///
/// Lowercase the name; unfold; compress each run of whitespace to one space;
/// drop whitespace around the colon and at the end of the value.
fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let unfolded: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let compressed = compress_wsp(&unfolded);
    format!("{}:{}", name.trim().to_ascii_lowercase(), compressed.trim())
}

/// Relaxed body canonicalization (RFC 6376 §3.4.4).
///
/// Compress whitespace and strip trailing whitespace on each line, then drop all
/// trailing empty lines, leaving a single terminating CRLF — or nothing at all
/// for an empty body, so its hash is the SHA-256 of zero bytes.
fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            // `compress_wsp` already collapses a leading WSP run to one space
            // and drops a trailing run entirely — exactly what relaxed body
            // canonicalization wants, unlike the header form which trims the
            // single leading space `compress_wsp` leaves behind.
            compress_wsp(line)
        })
        .collect();
    while lines.last().map(String::is_empty).unwrap_or(false) {
        lines.pop();
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out.into_bytes()
}

/// Collapses runs of space/tab to a single space; leading and trailing runs vanish.
fn compress_wsp(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_wsp = false;
    for c in text.chars() {
        if c == ' ' || c == '\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(' ');
                in_wsp = false;
            }
            out.push(c);
        }
    }
    out
}

/// SHA-256 of `data`.
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

/// Wraps a PKCS#1 `RSAPublicKey` DER (as `ring` emits it) in a `SubjectPublicKeyInfo`.
///
/// DKIM's `p=` for RSA is the `SubjectPublicKeyInfo` form (RFC 6376 §3.6.1 via
/// RFC 5280), while `ring` returns the bare `RSAPublicKey`; the fixed
/// `rsaEncryption` algorithm identifier and a BIT STRING wrapper bridge the two.
/// This is DER assembly, not cryptography.
fn rsa_spki(pkcs1: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier { rsaEncryption (1.2.840.113549.1.1.1), NULL }.
    const RSA_ENCRYPTION_ALG_ID: &[u8] =
        &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let mut bit_string_content = Vec::with_capacity(pkcs1.len() + 1);
    bit_string_content.push(0x00); // zero unused bits
    bit_string_content.extend_from_slice(pkcs1);
    let bit_string = der(0x03, &bit_string_content);

    let mut body = Vec::with_capacity(RSA_ENCRYPTION_ALG_ID.len() + bit_string.len());
    body.extend_from_slice(RSA_ENCRYPTION_ALG_ID);
    body.extend_from_slice(&bit_string);
    der(0x30, &body)
}

/// Emits one DER TLV: `tag`, a definite length, and `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// Wraps DER bytes as a PKCS#8 `PRIVATE KEY` PEM block, lines wrapped at 64.
fn der_to_pem(der: &[u8]) -> String {
    let encoded = b64_encode(der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

/// Extracts the DER body from a PEM block, ignoring the marker lines.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, DkimError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    if body.is_empty() {
        return Err(DkimError::Pem("no base64 content between markers".into()));
    }
    b64_decode(body.trim())
}

/// Standard base64 alphabet with padding (RFC 4648 §4) — the encoding DKIM's
/// `b=`, `bh=`, and `p=` tags and PEM bodies all use, distinct from the URL-safe
/// unpadded form JOSE requires.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes as padded standard base64.
pub(crate) fn b64_encode(data: &[u8]) -> String {
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

/// Decodes padded (or unpadded) standard base64, ignoring embedded whitespace.
///
/// `pub(crate)` beyond this module's own PEM parsing: `crate::ews` reuses it
/// for `MimeContent`, the one place EWS's XML carries base64 rather than
/// text, and `DkimError::Pem`'s message is generic enough ("not base64") to
/// serve there too rather than inventing a second base64 codec.
pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>, DkimError> {
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
            b'=' | b' ' | b'\t' | b'\r' | b'\n' => {}
            other => symbols.push(value(other).ok_or_else(|| DkimError::Pem(format!("byte {other:#x} is not base64")))?),
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
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

/// Writes secret bytes mode 0600 on Unix; elsewhere inherits the directory ACL.
///
/// Mirrors `proxy::tls::write_private` and `acme`'s account-key writer: a DKIM
/// private key must never exist even briefly in a world-readable state.
fn write_private(path: &Path, contents: &[u8]) -> Result<(), DkimError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ED25519};

    fn message(raw: &str) -> Message {
        Message::parse(raw.as_bytes().to_vec()).unwrap()
    }

    // ---- base64 -------------------------------------------------------------

    #[test]
    fn base64_round_trips_and_matches_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        for sample in [b"".as_slice(), b"f", b"fo", b"foo", b"foobar", &[0u8, 255, 128, 1, 2, 3]] {
            assert_eq!(b64_decode(&b64_encode(sample)).unwrap(), sample);
        }
    }

    // ---- canonicalization: RFC 6376 §3.4.5 worked example -------------------

    #[test]
    fn relaxed_header_matches_the_rfc_example() {
        // "A: X" -> "a:X"; "B : Y\t\r\n\tZ  " -> "b:Y Z".
        assert_eq!(canonicalize_header_relaxed("A", " X"), "a:X");
        assert_eq!(canonicalize_header_relaxed("B ", " Y\t\r\n\tZ  "), "b:Y Z");
    }

    #[test]
    fn relaxed_body_matches_the_rfc_example() {
        // The RFC's input body canonicalizes to " C\r\nD E\r\n".
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(canonicalize_body_relaxed(body), b" C\r\nD E\r\n");
    }

    #[test]
    fn an_empty_body_hashes_the_empty_string() {
        // The well-known relaxed empty-body hash.
        assert_eq!(canonicalize_body_relaxed(b""), b"");
        assert_eq!(b64_encode(&sha256(&canonicalize_body_relaxed(b""))), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    // ---- signing ------------------------------------------------------------

    #[test]
    fn a_signature_carries_the_expected_tags() {
        let dir = std::env::temp_dir().join(format!("dkim-tags-{}", std::process::id()));
        let key = dir.join("k.pem");
        let dkim = Dkim::generate(&key).unwrap();
        let msg = message("From: dave@example.com\r\nSubject: hi\r\nDate: now\r\n\r\nhello\r\n");

        let value = dkim.sign(&msg, "example.com", "s1", 1_700_000_000).unwrap();
        assert!(value.starts_with("v=1; a=ed25519-sha256; c=relaxed/relaxed;"));
        assert!(value.contains("d=example.com;"));
        assert!(value.contains("s=s1;"));
        assert!(value.contains("t=1700000000;"));
        assert!(value.contains("h=from:subject:date;"));
        assert!(value.contains("bh="));
        assert!(value.contains("; b="));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_generated_signature_verifies_against_the_published_key() {
        // End to end: reconstruct the exact signed input, pull `p=` from the DNS
        // record, and check the `b=` signature with ring — exactly what a
        // receiving verifier does. A canonicalization or hashing mistake here
        // would make real mail fail DKIM, so this proves the whole construction.
        let dir = std::env::temp_dir().join(format!("dkim-verify-{}", std::process::id()));
        let key = dir.join("k.pem");
        let dkim = Dkim::generate(&key).unwrap();
        let msg = message("From: dave@example.com\r\nTo: friend@other.com\r\nSubject: hi\r\n\r\nbody line\r\n");

        let value = dkim.sign(&msg, "example.com", "s1", 1_700_000_000).unwrap();
        let (signed_input, signature) = reconstruct(&msg, &value);

        // The digest ring signs for ed25519-sha256 is SHA-256 of the input.
        let public = extract_p(&dkim.public_txt());
        let verifier = UnparsedPublicKey::new(&ED25519, &public);
        verifier.verify(&sha256(&signed_input), &signature).expect("signature must verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reloaded_key_signs_identically() {
        // Persistence must reproduce the same key, or mail signed after a restart
        // would fail against the record published before it.
        let dir = std::env::temp_dir().join(format!("dkim-reload-{}", std::process::id()));
        let key = dir.join("k.pem");
        let first = Dkim::generate(&key).unwrap();
        let reloaded = Dkim::load(&key).unwrap();
        assert_eq!(first.public_txt(), reloaded.public_txt());

        let msg = message("From: a@example.com\r\nSubject: s\r\n\r\nb\r\n");
        assert_eq!(
            first.sign(&msg, "example.com", "s1", 42).unwrap(),
            reloaded.sign(&msg, "example.com", "s1", 42).unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_written_unreadable_to_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dkim-perm-{}", std::process::id()));
        let key = dir.join("k.pem");
        Dkim::generate(&key).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "key must not be group- or world-accessible");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_generate_reuses_an_existing_key() {
        let dir = std::env::temp_dir().join(format!("dkim-reuse-{}", std::process::id()));
        let key = dir.join("k.pem");
        let made = Dkim::load_or_generate(&key).unwrap();
        let again = Dkim::load_or_generate(&key).unwrap();
        assert_eq!(made.public_txt(), again.public_txt());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- test helpers: mirror a verifier well enough to check one signature ---

    /// Rebuilds the signed input and decodes `b=` from a DKIM-Signature value.
    fn reconstruct(msg: &Message, value: &str) -> (Vec<u8>, Vec<u8>) {
        let h_tag = tag(value, "; h=");
        // b= is the final tag; only the real boundary contains "; b=".
        let signature = b64_decode(value.rsplit_once("; b=").unwrap().1).unwrap();
        let fields = header_fields(header_block(msg));

        let mut input = String::new();
        for name in h_tag.split(':') {
            if let Some((n, v)) = fields.iter().rev().find(|(fname, _)| fname.eq_ignore_ascii_case(name)) {
                input.push_str(&canonicalize_header_relaxed(n, v));
                input.push_str("\r\n");
            }
        }
        // The DKIM-Signature header with b= emptied, as the verifier reconstructs.
        let emptied = blank_b(value);
        input.push_str(&canonicalize_header_relaxed("DKIM-Signature", &emptied));
        (input.into_bytes(), signature)
    }

    /// The value of a delimited tag (pass the leading `"; key="`) up to the next `;`.
    fn tag(value: &str, key: &str) -> String {
        let start = value.find(key).map(|i| i + key.len()).unwrap();
        let rest = &value[start..];
        rest.split(';').next().unwrap().trim().to_owned()
    }

    /// Removes everything after `b=`, as a verifier blanks the signature tag.
    fn blank_b(value: &str) -> String {
        let at = value.find("; b=").unwrap();
        format!("{}; b=", &value[..at])
    }

    fn extract_p(txt: &str) -> Vec<u8> {
        b64_decode(&tag(txt, "; p=")).unwrap()
    }
}
