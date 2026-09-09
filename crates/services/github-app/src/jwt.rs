//! Signing the GitHub App JWT: `RS256`, a fixed 9-minute lifetime.
//!
//! GitHub authenticates an App itself (as opposed to one of its installations)
//! by a JWT signed with the App's RSA private key (App Manifest flow, see
//! GitHub's "Authenticating as a GitHub App"). The claims are minimal — `iat`,
//! `exp`, `iss` — and the encoding is the same base64url-of-JSON-parts shape
//! `crates/net/acme/src/jose.rs` already uses for JOSE, reused here rather than
//! reinvented: unpadded, URL-safe, no third-party JWT crate (the dependency
//! policy forbids `jsonwebtoken`).
//!
//! `now` is always supplied by the caller (never read from the clock in this
//! module), so every test below is deterministic.

use std::time::{Duration, SystemTime, SystemTimeError};

use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use selfhost_json::Json;

/// Backward clock-skew tolerance baked into `iat`.
///
/// GitHub's own docs recommend backdating `iat` by up to a minute so a JWT
/// minted a moment before the request is not rejected by a server clock that
/// runs slightly ahead of this one.
const BACKDATE: Duration = Duration::from_secs(60);

/// The JWT lifetime from `iat`, kept under GitHub's ten-minute ceiling.
const LIFETIME: Duration = Duration::from_secs(600 - BACKDATE.as_secs());

/// Everything that can go wrong signing a GitHub App JWT.
#[derive(Debug)]
pub enum JwtError {
    /// `key_pkcs8_der` was not a valid PKCS#8-encoded RSA key.
    InvalidKey(String),
    /// Signing itself failed (an RSA/`ring` internal error).
    SigningFailed(String),
    /// `now` was earlier than [`BACKDATE`] before the Unix epoch — never true
    /// in practice, but `SystemTime` arithmetic is fallible and must be handled.
    ClockError(SystemTimeError),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::InvalidKey(detail) => write!(f, "invalid PKCS#8 RSA key: {detail}"),
            JwtError::SigningFailed(detail) => write!(f, "RS256 signing failed: {detail}"),
            JwtError::ClockError(error) => write!(f, "clock error: {error}"),
        }
    }
}

impl std::error::Error for JwtError {}

/// Encodes bytes as unpadded URL-safe base64 (RFC 4648 §5, no `=`).
///
/// Identical alphabet and packing to `crates/net/acme/src/jose.rs::base64url` —
/// duplicated rather than shared because that helper is private to the `acme`
/// crate and pulling in a whole ACME dependency for fifteen lines of encoding
/// would be the wrong trade. See the crate-level docs for the fuller note on
/// what is and is not shared with `acme`.
fn base64url(data: &[u8]) -> String {
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

/// Builds and signs a GitHub App JWT for `app_id`, valid from `now`.
///
/// `key_pkcs8_der` is the App's private key (PKCS#8 DER — see
/// [`crate::AppCredentials::load`] for turning the PEM GitHub hands out into
/// this shape). The result is `base64url(header).base64url(claims).base64url(signature)`,
/// ready to send as `Authorization: Bearer <token>`.
pub fn app_jwt(app_id: u64, key_pkcs8_der: &[u8], now: SystemTime) -> Result<String, JwtError> {
    let key_pair =
        RsaKeyPair::from_pkcs8(key_pkcs8_der).map_err(|error| JwtError::InvalidKey(error.to_string()))?;

    let iat = now
        .checked_sub(BACKDATE)
        .unwrap_or(now)
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(JwtError::ClockError)?
        .as_secs();
    let exp = iat + LIFETIME.as_secs();

    let header = Json::object([("alg", Json::string("RS256")), ("typ", Json::string("JWT"))]);
    let claims = Json::object([
        ("iat", Json::Number(iat as f64)),
        ("exp", Json::Number(exp as f64)),
        ("iss", Json::Number(app_id as f64)),
    ]);

    let header_b64 = base64url(header.to_text().as_bytes());
    let claims_b64 = base64url(claims.to_text().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let mut signature = vec![0_u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), signing_input.as_bytes(), &mut signature)
        .map_err(|error| JwtError::SigningFailed(error.to_string()))?;

    Ok(format!("{signing_input}.{}", base64url(&signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A throwaway 2048-bit RSA key generated for these tests only
    /// (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`). It
    /// signs nothing but test fixtures and is not the real App's key, which
    /// lives outside the repository under `secrets/` and is never referenced
    /// from test code.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDUncQhQhJqi3j7\n\
DDaUC4iHp7cxC8KeD5SfK0/M+J90rPhVm/sQjE2epEYDXxz2QC8BxLh3BD16fDeN\n\
nPlfU09DUClK4SVhNj8gBOVJ1E69u+g4+vi46ISW8kI9U+qPWeR3gjFcLf4y2BdS\n\
Sbq+NIoFBw/FntZviG2et1EB31gD44DwCp9BdTWjZXcxd46cdFFQ8uSOJOsEUbXV\n\
PrpC+b3r++72Q/G4oJkIIi2K7r7tmJ309RYwWrvti/u713eWStilEpfT9wyr+S1A\n\
P6IZdceInL5wvp9wd2ZKW64STfujj2smDjsabTgSPvJWFL8B/TjtHSKni18KTW2M\n\
HTTf4KFNAgMBAAECggEAIdDIet7+qCzFRxhq2HelH/46vUrjidlsh+GO8EiyrmSR\n\
nVFmSFF9nuJTCFeToaQVAIZV2F1iRx2D2xAWUWT3UaYUNdvtOAg1WKsD/2QMSfzy\n\
3ZfSVdvACsnpDcak+GZnAeLrutTN0y8Ei9/ncDem+U8QNnF20DJgokJXA0yPERRO\n\
2NRbvtzX34xKwbTPSczt8tyLSSgVLyPPJ/CqCEEASfmBn2/8wbjqfaagqt/GK9co\n\
i/aW/KwyvPY9Wgzg9Kh9C48b9W9wZ/6aSuK2o75YfY1km5KTUJX+4Ee63M1I94dm\n\
FvFVtpLSBsKrhpVilLd01WblCBEcq9eNmA7NKnrW+QKBgQD99PpXyxB0ZJrzhvy4\n\
ui+iM4hbrVd/KyyqCutLul00VUBd9xLctgre2yruYbrkAbfFJDPWGNhaH+z27zKe\n\
HDeWFdqn6ifrattGSpKcPRMhOywdh0WMGVYLP/rXNkEgw1LE3u3cHgNHDiulgLJr\n\
ZKWjTMF6lE8JIbd/NYfS6j3ZBwKBgQDWU6XBWYdqeO3sOi87Gzn3Lg5QvZ1n30bZ\n\
oMY6Kjm57qWrI3f5gnyKHy9Asif9znSGzkErclILpmYhIoR0UPVm6FHFId7WA/xt\n\
exAHY4ZJ/bhbZik3alp2m1Wk/Tgm+feUOdACk3qtRcgW6uBj+CHj762UOSMJZ4Yp\n\
KVVyXffCCwKBgGH8z0dms7+lPeBvGj4QoOZ96cQt2w/XUdF+ixFaJDJYHpDjD2UX\n\
3JPmjucR0HG/c+/eKx4V0gzcOquA2dAF5TDE1+xoPeTpAxhZF76vFh2BXmE6W4xW\n\
Dkwi8J9vcKu6kcoiljaTYgJdpluij7U+TWb368NnTCOi3dF4jyLDfP+rAoGAa+ac\n\
0mSiWiYbkgwQ7y7b1edn6ZosfrjX0ISyh2Huwf61hR1ML19UF61veqC2pX6lB6Eb\n\
CiZ5y8ewLwpTqMOBaJeZYyeUKibDlNKZ1T5zwxhrEgiyw2VVudSmH3QkKus5i3Q3\n\
lrRs1IMHIxKIeYvYdAqcVr0VOIzX7C0VCYjpTNUCgYBM8U8VM7CX+83k4Lg6zoFK\n\
hy+gFyAkYuCFGmZfefrI44R1nmrrTe0tmTuqoVGgqoWvNXYgr6gnxdqP40RgsEH/\n\
Iyzl0CUR5KJWbWkzb6+FrzKFaps0FKssxHeENt+IVK4emn+R8oUqEnzssggAf+/p\n\
6Fb5BJ6goBYRAcjuN62mcQ==\n\
-----END PRIVATE KEY-----\n";

    /// Decodes the fixture PEM to PKCS#8 DER via `rustls-pemfile`, the same
    /// path [`crate::AppCredentials::load`] uses for a real key file.
    fn test_key_der() -> Vec<u8> {
        let mut reader = TEST_KEY_PEM.as_bytes();
        let item = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .next()
            .expect("fixture PEM has one PKCS#8 key")
            .expect("fixture PEM parses");
        item.secret_pkcs8_der().to_vec()
    }

    /// Decodes one base64url part back to bytes, for asserting on the claims.
    fn decode_part(part: &str) -> Vec<u8> {
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut bits = 0u32;
        let mut count = 0u32;
        let mut out = Vec::new();
        for c in part.chars() {
            let value = ALPHABET.find(c).expect("valid base64url char") as u32;
            bits = (bits << 6) | value;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
    }

    #[test]
    fn produces_three_dot_separated_base64url_parts() {
        let der = test_key_der();
        let jwt = app_jwt(4606064, &der, SystemTime::now()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        for part in &parts {
            assert!(part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        }
    }

    #[test]
    fn header_and_claims_match_the_expected_shape() {
        let der = test_key_der();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let jwt = app_jwt(4606064, &der, now).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();

        let header_text = String::from_utf8(decode_part(parts[0])).unwrap();
        let header = selfhost_json::parse(&header_text).unwrap();
        assert_eq!(header.get("alg").and_then(Json::as_str), Some("RS256"));
        assert_eq!(header.get("typ").and_then(Json::as_str), Some("JWT"));

        let claims_text = String::from_utf8(decode_part(parts[1])).unwrap();
        let claims = selfhost_json::parse(&claims_text).unwrap();
        let iat = claims.get("iat").and_then(Json::as_u64).unwrap();
        let exp = claims.get("exp").and_then(Json::as_u64).unwrap();
        let iss = claims.get("iss").and_then(Json::as_u64).unwrap();

        assert_eq!(iss, 4606064);
        assert_eq!(iat, 1_700_000_000 - 60);
        assert_eq!(exp - iat, 540);
    }

    #[test]
    fn an_invalid_key_is_reported_rather_than_panicking() {
        let result = app_jwt(1, b"not a key", SystemTime::now());
        assert!(matches!(result, Err(JwtError::InvalidKey(_))));
    }
}
