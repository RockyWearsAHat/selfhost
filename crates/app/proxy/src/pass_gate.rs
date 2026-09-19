//! The identity gate in front of a `people` or `private` Site.
//!
//! A Site whose Exposure asks for a Person is served only to a request
//! carrying a valid [`selfhost_identity::Pass`] for that Site, held by
//! somebody who holds a Grant on it *now*. Everything the proxy needs to
//! decide that is here, free of sockets, so it can be tested as a table.
//!
//! # Revocation is a lookup, not a list
//!
//! A Pass proves who somebody is for up to twelve hours. Whether they may
//! still come in is asked of the People registry on every request, so taking
//! a Grant away takes effect on the next one and there is nothing to expire.

use selfhost_admin::site_pass::{Redeemed, SitePasses};
use selfhost_config::Site;
use selfhost_identity::{Capability, Identity, People, PersonName, SiteName};

/// The cookie a Pass travels in. The `__Host-` prefix makes the browser
/// itself refuse it unless it is `Secure`, has `Path=/` and names no
/// `Domain` — host-only, so a sibling Site can neither read nor plant it.
pub const COOKIE: &str = "__Host-selfhost-pass";

/// The path prefix the proxy answers itself and never forwards upstream.
pub const RESERVED_PREFIX: &str = "/.selfhost/";

/// Where a one-time sign-in code is redeemed.
pub const REDEEM_PATH: &str = "/.selfhost/pass";

/// The header the upstream reads the verified Person from. Any copy the
/// client sent is stripped before this one is added.
pub const PERSON_HEADER: &str = "X-Selfhost-Person";

/// What the gate makes of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A valid Pass, and its Person holds a Grant on the Site.
    Open(Identity),
    /// No Pass, or one that does not verify: send them to sign in.
    SignIn,
    /// A valid Pass whose Person holds no Grant on the Site: a plain 403.
    NoGrant,
}

/// The Pass key (shared with the admin API) and the live People registry.
#[derive(Debug, Clone)]
pub struct PassGate {
    passes: SitePasses,
    people: People,
}

impl PassGate {
    /// `passes` must be a clone of the value the admin API mints codes into.
    pub fn new(passes: SitePasses, people: People) -> Self {
        Self { passes, people }
    }

    /// Judges a request to `site` by its `Cookie` header.
    pub fn judge(&self, site: &Site, cookie_header: Option<&str>) -> Verdict {
        let Ok(name) = SiteName::parse(&site.name) else {
            return Verdict::SignIn;
        };
        let Some(pass) = cookie_header
            .and_then(|header| cookie_value(header, COOKIE))
            .and_then(|token| self.passes.verify(token, &name).ok())
        else {
            return Verdict::SignIn;
        };
        if self.holds_a_grant(&pass.person, site, &name) {
            Verdict::Open(pass.person)
        } else {
            Verdict::NoGrant
        }
    }

    /// Redeems a one-time code presented at `site`'s [`REDEEM_PATH`].
    pub fn redeem(&self, site: &Site, code: &str) -> Option<Redeemed> {
        let name = SiteName::parse(&site.name).ok()?;
        self.passes.redeem(code, &name)
    }

    /// The owner, the Site's own `owner`, or a Person who holds
    /// `site.access:<site>` in the registry as it stands this instant.
    fn holds_a_grant(&self, person: &Identity, site: &Site, name: &SiteName) -> bool {
        if person.is_owner() || site.owner.as_deref() == Some(person.as_str()) {
            return true;
        }
        PersonName::parse(person.as_str())
            .ok()
            .and_then(|person| self.people.find(&person))
            .is_some_and(|entry| entry.grants.holds(&Capability::SiteAccess(name.clone())))
    }
}

/// The `Set-Cookie` value that stores `pass`.
///
/// `SameSite=Lax` and not `Strict`: the cookie is set on the response to a
/// redirect *from* the sign-in site, and the visitor's very next request is
/// the top-level navigation that redirect causes — which `Strict` would send
/// without it, looping them back to sign in.
pub fn set_cookie(pass: &str) -> String {
    format!(
        "{COOKIE}={pass}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
        selfhost_identity::MAX_PASS_LIFETIME_SECS
    )
}

/// The sign-in URL for a visitor turned away from `wanted` (an absolute
/// `https` URL on the gated Site), at the sign-in site's `authority`.
pub fn sign_in_url(authority: &str, wanted: &str) -> String {
    format!("https://{authority}/?return={}", percent_encode(wanted))
}

/// The `code` parameter of a [`REDEEM_PATH`] request target.
pub fn code_in(target: &str) -> Option<&str> {
    let (_, query) = target.split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix("code="))
}

/// One cookie's value out of a `Cookie` header.
fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

/// Encodes everything but RFC 3986 unreserved characters.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_is_found_by_exact_name_among_others() {
        let header = "a=1; __Host-selfhost-pass=v1.x.y; selfhost-pass=no";
        assert_eq!(cookie_value(header, COOKIE), Some("v1.x.y"));
        assert_eq!(cookie_value("x__Host-selfhost-pass=no", COOKIE), None);
        assert_eq!(cookie_value("", COOKIE), None);
    }

    #[test]
    fn the_cookie_is_host_only_secure_and_unreadable_by_script() {
        let cookie = set_cookie("v1.a.b");
        assert!(cookie.starts_with("__Host-selfhost-pass=v1.a.b; Path=/;"));
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attribute), "{cookie}");
        }
        assert!(!cookie.contains("Domain"), "{cookie}");
    }

    #[test]
    fn the_return_url_is_carried_as_one_opaque_parameter() {
        assert_eq!(
            sign_in_url("auth.example.com", "https://blog.example.com/a?b=c&d"),
            "https://auth.example.com/?return=https%3A%2F%2Fblog.example.com%2Fa%3Fb%3Dc%26d"
        );
    }

    #[test]
    fn the_code_is_read_from_the_query() {
        assert_eq!(code_in("/.selfhost/pass?code=abc"), Some("abc"));
        assert_eq!(code_in("/.selfhost/pass?x=1&code=abc"), Some("abc"));
        assert_eq!(code_in("/.selfhost/pass"), None);
        assert_eq!(code_in("/.selfhost/pass?barcode=abc"), None);
    }
}
