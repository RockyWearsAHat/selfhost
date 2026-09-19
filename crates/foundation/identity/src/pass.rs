//! The Pass: a short-lived, signed statement of *who signed in*, for one Site.
//!
//! # What it is, and what it is not
//!
//! `v1.<base64url payload>.<base64url Ed25519 signature>`. The payload names a
//! Person (or the owner), the one Site the Pass is for, when it was issued,
//! when it stops, and an id for the audit trail. The daemon signs it; the proxy
//! verifies it on every request to a `people` or `private` Site.
//!
//! A Pass proves identity and nothing else. It carries no Grant: whether the
//! Person it names may reach the Site is asked of the people registry on each
//! request, by the caller of [`PassKey::verify`]. That split is the whole
//! revocation story — take the Grant away, or forget the Person, and every
//! Pass they hold is void on the next request, with no list of revoked ids to
//! keep, distribute, or forget to consult.
//!
//! # Why the audience is inside the signature
//!
//! The cookie a Pass rides in is host-only, but a Site's upstream sees every
//! header its visitors send, the cookie included. Without an audience, the
//! application behind one Site could replay a visitor's Pass at another. With
//! it, a Pass lifted from `blog` verifies only at `blog`, where its holder
//! could already go.
//!
//! # Why our own format
//!
//! There is exactly one issuer and one verifier, both this daemon, so none of
//! what a general token format negotiates is needed — and the negotiation
//! (`alg`, key ids, optional claims) is where those formats have historically
//! been broken. One version word, one algorithm, every field required.

use crate::capability::SiteName;
use crate::identity::Identity;
use crate::registry::PrivateWrite;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};

/// The file the signing key lives in, under the data directory.
const KEY_FILENAME: &str = "pass.key";

/// The only version this build issues or accepts.
const VERSION: &str = "v1";

/// The longest a Pass may live: twelve hours, the console session's own cap.
pub const MAX_PASS_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// The longest token [`PassKey::verify`] will look at, in bytes.
///
/// A real Pass is under 300. The cap is checked before anything is decoded, so
/// a hostile cookie costs a length comparison and not a base64 pass over
/// kilobytes of it.
pub const MAX_PASS_BYTES: usize = 1024;

/// An Ed25519 signature's length.
const SIGNATURE_BYTES: usize = 64;

/// The entropy behind a pass id.
const PASS_ID_BYTES: usize = 12;

/// A verified Pass: who signed in, for which Site, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    /// Who signed in.
    pub person: Identity,
    /// The one Site this Pass is good for.
    pub site: SiteName,
    /// When it was issued, in seconds since the Unix epoch.
    pub issued_unix: u64,
    /// When it stops being accepted, in seconds since the Unix epoch.
    pub expires_unix: u64,
    /// An id for the audit trail. Not a secret and not looked up anywhere.
    pub id: String,
}

/// Why a presented token is not a Pass for this Site, right now.
///
/// For logs and tests. A caller answering a request treats every variant the
/// same way — as no Pass at all — so a stranger learns nothing from which one
/// they hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassRefused {
    /// Longer than [`MAX_PASS_BYTES`].
    Oversized,
    /// Not three dot-separated parts, or a part that is not what it should be.
    Malformed,
    /// A version this build does not speak.
    UnknownVersion,
    /// The signature does not match the payload under this daemon's key.
    BadSignature,
    /// A genuine Pass, for some other Site.
    WrongSite,
    /// A genuine Pass whose time is over, or whose stated lifetime is longer
    /// than this build would ever have issued.
    Expired,
}

/// The daemon's Pass-signing key.
///
/// Generated once, kept in `<data_dir>/pass.key` readable only by its owner,
/// and never rendered: [`std::fmt::Debug`] prints nothing of it.
pub struct PassKey {
    pair: Ed25519KeyPair,
}

impl PassKey {
    /// Where the key lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(KEY_FILENAME)
    }

    /// Loads the key, generating and storing it on first use.
    ///
    /// A file that is present and unreadable as a key is an error rather than
    /// a reason to mint a fresh one: silently replacing it would sign every
    /// visitor out and hide whatever damaged the file.
    pub fn load_or_create(data_dir: &Path, write_private: PrivateWrite) -> io::Result<Self> {
        let path = Self::path_in(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let pkcs8 = b64url_decode(text.trim())
                    .ok_or_else(|| io::Error::other("the pass signing key file is not base64url"))?;
                Self::from_pkcs8(&pkcs8)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|_| io::Error::other("could not generate a pass signing key"))?;
                write_private(&path, &b64url_encode(pkcs8.as_ref()))?;
                Self::from_pkcs8(pkcs8.as_ref())
            }
            Err(error) => Err(error),
        }
    }

    /// A key that exists only in this process, for tests.
    pub fn ephemeral() -> io::Result<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| io::Error::other("could not generate a pass signing key"))?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    fn from_pkcs8(pkcs8: &[u8]) -> io::Result<Self> {
        Ed25519KeyPair::from_pkcs8(pkcs8)
            .map(|pair| Self { pair })
            .map_err(|_| io::Error::other("the pass signing key file does not hold an Ed25519 key"))
    }

    /// Issues a Pass naming `person`, good at `site` for `lifetime_secs` from
    /// `now_unix` — capped at [`MAX_PASS_LIFETIME_SECS`] whatever was asked.
    pub fn issue(
        &self,
        person: &Identity,
        site: &SiteName,
        now_unix: u64,
        lifetime_secs: u64,
    ) -> io::Result<String> {
        let mut id = [0u8; PASS_ID_BYTES];
        ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut id)
            .map_err(|_| io::Error::other("could not generate a pass id"))?;
        let expires = now_unix.saturating_add(lifetime_secs.min(MAX_PASS_LIFETIME_SECS));
        let payload = Json::object([
            ("person", Json::string(person.as_str())),
            ("site", Json::string(site.as_str())),
            ("issued", Json::Number(now_unix as f64)),
            ("expires", Json::Number(expires as f64)),
            ("id", Json::string(b64url_encode(&id))),
        ])
        .to_text();
        let body = format!("{VERSION}.{}", b64url_encode(payload.as_bytes()));
        let signature = self.pair.sign(body.as_bytes());
        Ok(format!("{body}.{}", b64url_encode(signature.as_ref())))
    }

    /// Verifies `token` as a Pass for `site` at `now_unix`.
    ///
    /// The signature is checked before the payload is parsed, so nothing an
    /// attacker wrote reaches the JSON parser. Ed25519 verification works on
    /// public values only; there is no secret-dependent comparison here to
    /// time.
    pub fn verify(&self, token: &str, site: &SiteName, now_unix: u64) -> Result<Pass, PassRefused> {
        if token.len() > MAX_PASS_BYTES {
            return Err(PassRefused::Oversized);
        }
        let mut parts = token.split('.');
        let (Some(version), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PassRefused::Malformed);
        };
        if version != VERSION {
            return Err(PassRefused::UnknownVersion);
        }
        let signature = b64url_decode(signature).ok_or(PassRefused::Malformed)?;
        if signature.len() != SIGNATURE_BYTES {
            return Err(PassRefused::Malformed);
        }
        let signed = &token[..version.len() + 1 + payload.len()];
        signature::UnparsedPublicKey::new(&signature::ED25519, self.pair.public_key().as_ref())
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| PassRefused::BadSignature)?;

        let payload = b64url_decode(payload).ok_or(PassRefused::Malformed)?;
        let text = std::str::from_utf8(&payload).map_err(|_| PassRefused::Malformed)?;
        let document = selfhost_json::parse(text).map_err(|_| PassRefused::Malformed)?;
        let word = |key: &str| document.get(key).and_then(Json::as_str).ok_or(PassRefused::Malformed);
        let number = |key: &str| document.get(key).and_then(Json::as_u64).ok_or(PassRefused::Malformed);
        let pass = Pass {
            person: Identity::parse(word("person")?).map_err(|_| PassRefused::Malformed)?,
            site: SiteName::parse(word("site")?).map_err(|_| PassRefused::Malformed)?,
            issued_unix: number("issued")?,
            expires_unix: number("expires")?,
            id: word("id")?.to_owned(),
        };
        if &pass.site != site {
            return Err(PassRefused::WrongSite);
        }
        let lifetime = pass.expires_unix.saturating_sub(pass.issued_unix);
        if now_unix >= pass.expires_unix || lifetime > MAX_PASS_LIFETIME_SECS {
            return Err(PassRefused::Expired);
        }
        Ok(pass)
    }
}

impl std::fmt::Debug for PassKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PassKey(..)")
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url, as a Pass spells its two binary parts.
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let group = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..=chunk.len() {
            out.push(B64URL[((group >> (18 - 6 * index)) & 63) as usize] as char);
        }
    }
    out
}

/// Decodes unpadded base64url; `None` for anything else, padding included.
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut group = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = B64URL.iter().position(|symbol| symbol == byte)? as u32;
            group |= value << (18 - 6 * index);
        }
        for index in 0..chunk.len() - 1 {
            out.push((group >> (16 - 8 * index)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn site(name: &str) -> SiteName {
        SiteName::parse(name).expect("a valid site name")
    }

    fn mom() -> Identity {
        Identity::parse("mom").expect("a valid person name")
    }

    #[test]
    fn base64url_round_trips_every_length_and_refuses_what_is_not_it() {
        for length in 0..20usize {
            let data: Vec<u8> = (0..length as u8).map(|byte| byte.wrapping_mul(37)).collect();
            assert_eq!(b64url_decode(&b64url_encode(&data)), Some(data));
        }
        for bad in ["a", "ab=", "a+b/", "ab cd", "abcde"] {
            assert_eq!(b64url_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_issued_pass_verifies_for_its_site_until_it_expires() {
        let key = PassKey::ephemeral().unwrap();
        let token = key.issue(&mom(), &site("blog"), NOW, 3600).unwrap();
        let pass = key.verify(&token, &site("blog"), NOW + 3599).expect("a live pass");
        assert_eq!(pass.person, mom());
        assert_eq!(pass.site, site("blog"));
        assert_eq!((pass.issued_unix, pass.expires_unix), (NOW, NOW + 3600));
        assert_eq!(key.verify(&token, &site("blog"), NOW + 3600), Err(PassRefused::Expired));
    }

    #[test]
    fn a_lifetime_is_capped_at_twelve_hours_whatever_was_asked() {
        let key = PassKey::ephemeral().unwrap();
        let token = key.issue(&mom(), &site("blog"), NOW, u64::MAX).unwrap();
        let pass = key.verify(&token, &site("blog"), NOW).unwrap();
        assert_eq!(pass.expires_unix, NOW + MAX_PASS_LIFETIME_SECS);
    }

    #[test]
    fn a_pass_for_one_site_is_refused_at_another() {
        let key = PassKey::ephemeral().unwrap();
        let token = key.issue(&mom(), &site("blog"), NOW, 3600).unwrap();
        assert_eq!(key.verify(&token, &site("shop"), NOW), Err(PassRefused::WrongSite));
    }

    #[test]
    fn a_pass_signed_by_another_key_is_a_forgery() {
        let ours = PassKey::ephemeral().unwrap();
        let theirs = PassKey::ephemeral().unwrap();
        let token = theirs.issue(&mom(), &site("blog"), NOW, 3600).unwrap();
        assert_eq!(ours.verify(&token, &site("blog"), NOW), Err(PassRefused::BadSignature));
    }

    #[test]
    fn a_payload_swapped_under_a_genuine_signature_is_refused() {
        let key = PassKey::ephemeral().unwrap();
        let token = key.issue(&mom(), &site("blog"), NOW, 3600).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let forged = b64url_encode(
            br#"{"person":"owner","site":"blog","issued":1800000000,"expires":1800003600,"id":"x"}"#,
        );
        let tampered = format!("v1.{forged}.{}", parts[2]);
        assert_eq!(key.verify(&tampered, &site("blog"), NOW), Err(PassRefused::BadSignature));

        // One flipped signature character, too.
        let mut flipped = token.clone().into_bytes();
        let last = flipped.len() - 2;
        flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
        let flipped = String::from_utf8(flipped).unwrap();
        assert!(key.verify(&flipped, &site("blog"), NOW).is_err());
    }

    #[test]
    fn a_lifetime_longer_than_this_build_issues_is_refused_even_when_signed() {
        // Not reachable through `issue`; this is the verifier refusing to trust
        // a field merely because the signature over it is good.
        let key = PassKey::ephemeral().unwrap();
        let payload = b64url_encode(
            br#"{"person":"mom","site":"blog","issued":1800000000,"expires":1900000000,"id":"x"}"#,
        );
        let body = format!("v1.{payload}");
        let token = format!("{body}.{}", b64url_encode(key.pair.sign(body.as_bytes()).as_ref()));
        assert_eq!(key.verify(&token, &site("blog"), NOW), Err(PassRefused::Expired));
    }

    #[test]
    fn shapes_that_are_not_a_pass_are_refused_before_any_crypto() {
        let key = PassKey::ephemeral().unwrap();
        let token = key.issue(&mom(), &site("blog"), NOW, 3600).unwrap();
        let rest = token.strip_prefix("v1.").unwrap();
        assert_eq!(key.verify(&format!("v2.{rest}"), &site("blog"), NOW), Err(PassRefused::UnknownVersion));
        assert_eq!(key.verify("", &site("blog"), NOW), Err(PassRefused::Malformed));
        assert_eq!(key.verify("v1.only", &site("blog"), NOW), Err(PassRefused::Malformed));
        assert_eq!(key.verify(&format!("{token}.extra"), &site("blog"), NOW), Err(PassRefused::Malformed));
        assert_eq!(key.verify("v1.e30.c2ln", &site("blog"), NOW), Err(PassRefused::Malformed));
        assert_eq!(
            key.verify(&"a".repeat(MAX_PASS_BYTES + 1), &site("blog"), NOW),
            Err(PassRefused::Oversized)
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_key_is_generated_once_kept_private_and_reloaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("selfhost-pass-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = PassKey::load_or_create(&dir, crate::write_owner_only).unwrap();
        let mode = std::fs::metadata(PassKey::path_in(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let token = first.issue(&mom(), &site("blog"), NOW, 60).unwrap();
        let second = PassKey::load_or_create(&dir, crate::write_owner_only).unwrap();
        assert!(second.verify(&token, &site("blog"), NOW).is_ok(), "the same key after a restart");

        std::fs::write(PassKey::path_in(&dir), "not a key").unwrap();
        assert!(PassKey::load_or_create(&dir, crate::write_owner_only).is_err(), "never silently replaced");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
