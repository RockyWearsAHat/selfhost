//! Signing a Person in to a gated Site: the hand-off between the sign-in site
//! and the proxy.
//!
//! # The shape
//!
//! A `people` or `private` Site wants a [`selfhost_identity::Pass`] in a
//! host-only cookie, and only the Site's own hostname can set one. The session
//! that proves who somebody is lives at the sign-in site, a different hostname.
//! So the proof crosses in a one-time code, exactly as [`crate::vpn_enroll`]
//! carries a console session across to the desktop app:
//!
//! 1. The proxy sends a visitor with no Pass to the sign-in site, with the URL
//!    they wanted.
//! 2. Signed in there, the page calls `POST /api/pass/authorize`. The handler
//!    checks the Grant and calls [`SitePasses::mint_code`].
//! 3. The browser follows the returned link to `https://<site>/.selfhost/pass`;
//!    the proxy calls [`SitePasses::redeem`] in-process, sets the cookie and
//!    sends the visitor on to where they were going.
//!
//! # Why a code and not the Pass itself in the URL
//!
//! A URL is written to browser history and access logs. The code is dead after
//! one use or [`CODE_TTL_SECS`]; a Pass would be live for hours. The store keeps
//! only a digest, for the reason [`crate::invite`] gives.
//!
//! # Why one value is shared rather than two built
//!
//! The admin API mints and the proxy redeems, and they are the same process.
//! One [`SitePasses`], cloned into both, is what makes "in-process" true: no
//! loopback call, no second copy of the key, nothing on disk but the key.

use crate::token::{constant_time_eq, random_bytes};
use ring::digest;
use selfhost_identity::{Identity, MAX_PASS_LIFETIME_SECS, Pass, PassKey, PassRefused, SiteName};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long a minted code is redeemable: one browser redirect.
pub const CODE_TTL_SECS: u64 = 60;

/// The most codes outstanding at once. Bounds a burst, as
/// [`crate::vpn_enroll`]'s cap does.
const MAX_CODES: usize = 256;

/// 192 bits, the size every one-time code in this crate uses.
const CODE_BYTES: usize = 24;

/// The longest path a code will carry back to the Site.
pub const MAX_RETURN_PATH_BYTES: usize = 2048;

/// One outstanding sign-in.
struct Pending {
    /// SHA-256 of the code; the code itself is never stored.
    code_digest: Vec<u8>,
    person: Identity,
    site: SiteName,
    return_path: String,
    expires_unix: u64,
}

/// What a redeemed code yields: the cookie value, and where to send the
/// visitor next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    /// The signed Pass, ready to be a cookie value.
    pub pass: String,
    /// Who it names, for the log line.
    pub person: Identity,
    /// A path on the Site — validated by [`is_safe_return_path`] at mint.
    pub return_path: String,
}

/// The Pass-signing key and the one-time codes that carry a sign-in to a Site.
#[derive(Clone)]
pub struct SitePasses {
    key: Arc<PassKey>,
    pending: Arc<Mutex<Vec<Pending>>>,
}

impl SitePasses {
    /// Wraps the daemon's signing key.
    pub fn new(key: PassKey) -> Self {
        Self { key: Arc::new(key), pending: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Mints a code that will sign `person` in to `site` and return them to
    /// `return_path`.
    ///
    /// The caller has already decided `person` may reach `site`. This refuses
    /// only what it owns: a return path that is not a plain path on the Site,
    /// and a full store.
    pub fn mint_code(&self, person: &Identity, site: &SiteName, return_path: &str) -> Result<String, String> {
        if !is_safe_return_path(return_path) {
            return Err("the return path is not a path on that site".to_owned());
        }
        let code = crate::webauthn::b64url_encode(
            &random_bytes(CODE_BYTES).map_err(|error| format!("could not generate a code: {error}"))?,
        );
        let now = now_unix();
        let mut pending = self.pending.lock().expect("the site pass lock was poisoned");
        pending.retain(|entry| entry.expires_unix > now);
        if pending.len() >= MAX_CODES {
            return Err("too many sign-ins are in flight; try again in a moment".to_owned());
        }
        pending.push(Pending {
            code_digest: sha256(&code),
            person: person.clone(),
            site: site.clone(),
            return_path: return_path.to_owned(),
            expires_unix: now.saturating_add(CODE_TTL_SECS),
        });
        Ok(code)
    }

    /// Redeems `code` at `site`, issuing the Pass. Single use; a code minted
    /// for another Site is as unknown here as one never minted, and is not
    /// spent by the attempt.
    pub fn redeem(&self, code: &str, site: &SiteName) -> Option<Redeemed> {
        let presented = sha256(code);
        let now = now_unix();
        let entry = {
            let mut pending = self.pending.lock().expect("the site pass lock was poisoned");
            let position = pending.iter().enumerate().fold(None, |found, (index, entry)| {
                let hit = entry.expires_unix > now
                    && &entry.site == site
                    && constant_time_eq(&entry.code_digest, &presented);
                if hit { Some(index) } else { found }
            })?;
            pending.remove(position)
        };
        let pass = self.key.issue(&entry.person, site, now, MAX_PASS_LIFETIME_SECS).ok()?;
        Some(Redeemed { pass, person: entry.person, return_path: entry.return_path })
    }

    /// Verifies a cookie value as a Pass for `site`, now.
    pub fn verify(&self, token: &str, site: &SiteName) -> Result<Pass, PassRefused> {
        self.key.verify(token, site, now_unix())
    }
}

// Says nothing of the key, and nothing of who is mid-sign-in.
impl std::fmt::Debug for SitePasses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.pending.lock().expect("the site pass lock was poisoned").len();
        write!(f, "SitePasses({count} in flight)")
    }
}

/// Whether `path` can only ever mean "a path on this same Site".
///
/// The open-redirect check. It must start with exactly one `/`: `//host` and
/// `/\host` are both read by browsers as another origin. No control character
/// may appear, so nothing here can split the `Location` header it ends up in.
pub fn is_safe_return_path(path: &str) -> bool {
    path.len() <= MAX_RETURN_PATH_BYTES
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.starts_with("/.selfhost/")
        && path.bytes().all(|byte| byte > 0x20 && byte < 0x7f)
}

/// Splits `https://<host>/<path>` into its host and path.
///
/// Refuses any other scheme, a port, userinfo, and an empty host, so the host
/// that comes back is exactly what a browser would connect to. The path is
/// `/` when the URL has none; [`is_safe_return_path`] judges it at mint.
pub fn split_return_url(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    let (host, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, "/"),
    };
    let plain = !host.is_empty()
        && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
    plain.then_some((host, path))
}

fn sha256(code: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, code.as_bytes()).as_ref().to_vec()
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passes() -> SitePasses {
        SitePasses::new(PassKey::ephemeral().unwrap())
    }

    fn site(name: &str) -> SiteName {
        SiteName::parse(name).unwrap()
    }

    fn mom() -> Identity {
        Identity::parse("mom").unwrap()
    }

    #[test]
    fn a_code_redeems_once_into_a_pass_for_that_person_and_site() {
        let passes = passes();
        let code = passes.mint_code(&mom(), &site("blog"), "/drafts?x=1").unwrap();
        let redeemed = passes.redeem(&code, &site("blog")).expect("redeems");
        assert_eq!(redeemed.return_path, "/drafts?x=1");
        let pass = passes.verify(&redeemed.pass, &site("blog")).expect("a live pass");
        assert_eq!(pass.person, mom());
        assert!(passes.redeem(&code, &site("blog")).is_none(), "a code is single-use");
    }

    #[test]
    fn a_code_for_one_site_is_unknown_at_another_and_survives_the_attempt() {
        let passes = passes();
        let code = passes.mint_code(&mom(), &site("blog"), "/").unwrap();
        assert!(passes.redeem(&code, &site("shop")).is_none());
        assert!(passes.redeem(&code, &site("blog")).is_some());
    }

    #[test]
    fn an_expired_or_unknown_code_is_refused() {
        let passes = passes();
        let code = passes.mint_code(&mom(), &site("blog"), "/").unwrap();
        passes.pending.lock().unwrap()[0].expires_unix = now_unix().saturating_sub(1);
        assert!(passes.redeem(&code, &site("blog")).is_none());
        assert!(passes.redeem("", &site("blog")).is_none());
        assert!(passes.redeem("not-a-code", &site("blog")).is_none());
    }

    #[test]
    fn only_a_plain_path_on_the_same_site_may_be_returned_to() {
        for good in ["/", "/a/b?c=d&e=f", "/a%20b", "/.well-known/x"] {
            assert!(is_safe_return_path(good), "{good:?}");
        }
        for bad in [
            "",
            "a",
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            "/a b",
            "/a\r\nSet-Cookie: x=y",
            "/a\u{e9}",
            "/.selfhost/pass?code=x",
        ] {
            assert!(!is_safe_return_path(bad), "{bad:?}");
            assert!(passes().mint_code(&mom(), &site("blog"), bad).is_err(), "{bad:?}");
        }
        assert!(!is_safe_return_path(&format!("/{}", "a".repeat(MAX_RETURN_PATH_BYTES))));
    }

    #[test]
    fn a_return_url_is_https_with_a_bare_host_or_nothing() {
        assert_eq!(split_return_url("https://blog.example.com/a?b=c"), Some(("blog.example.com", "/a?b=c")));
        assert_eq!(split_return_url("https://blog.example.com"), Some(("blog.example.com", "/")));
        for bad in [
            "http://blog.example.com/",
            "//blog.example.com/",
            "https:///x",
            "https://blog.example.com:8443/",
            "https://blog.example.com@evil.example/",
            "https://evil.example\\@blog.example.com/",
            "https://blog.example.com?x",
            "javascript:alert(1)",
        ] {
            assert_eq!(split_return_url(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn outstanding_codes_are_capped() {
        let passes = passes();
        for _ in 0..MAX_CODES {
            passes.mint_code(&mom(), &site("blog"), "/").expect("under the cap");
        }
        assert!(passes.mint_code(&mom(), &site("blog"), "/").is_err());
    }
}
