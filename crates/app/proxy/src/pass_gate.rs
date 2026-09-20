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
use selfhost_identity::{Capability, Credential, Identity, People, Policy, SiteName};

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

    /// The legacy console owner, the Site's own `owner`, or somebody who
    /// holds `site.access:<site>` — through [`Policy::decide`], never a
    /// direct `.grants.holds()`, so a Person holding [`Capability::Owner`]
    /// is let in here exactly the same way `vpn_api.rs::check_access` lets
    /// one onto their own VPN: through the ordinary grants rule, now
    /// satisfied by an owner grant for any `want` (see
    /// `crate::policy::satisfies` in `selfhost_identity`).
    fn holds_a_grant(&self, person: &Identity, site: &Site, name: &SiteName) -> bool {
        if person.is_owner() || site.owner.as_ref().is_some_and(|owner| owner.as_str() == person.as_str()) {
            return true;
        }
        let caller = self.people.caller(person.clone(), Credential::Passkey);
        Policy::locked_down().decide(&caller, &Capability::SiteAccess(name.clone())).is_allowed()
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
    use selfhost_admin::site_pass::SitePasses;
    use selfhost_identity::{Grants, PassKey, People, PersonName};
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-pass-gate-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn ordinary_site(name: &str) -> Site {
        Site {
            name: name.to_owned(),
            domains: vec![format!("{name}.example.com")],
            static_root: Some(std::path::PathBuf::from("./sites").join(name)),
            spa: false,
            app_paths: Vec::new(),
            instances: Vec::new(),
            health: selfhost_config::Health::default(),
            canonical_redirect: true,
            allowed_cidrs: Vec::new(),
            console: false,
            public_api_paths: vec![],
            exposure: None,
            owner: None,
            relay: None,
        }
    }

    #[test]
    fn an_owner_grant_is_let_through_a_site_the_person_was_never_named_on() {
        // The named bug's sibling: an owner is a Person who holds
        // `Capability::Owner`, not `site.access:<site>` for any particular
        // site. Before routing this through `Policy::decide`, such a Person
        // was refused every site's Pass gate unless they were that site's
        // named `owner` field or the legacy `Identity::Owner`.
        let dir = scratch("owner-any-site");
        let people = People::load(&dir);
        let owner_grants = Grants::new([Capability::Owner]).unwrap();
        people.set_grants(&PersonName::parse("alex").unwrap(), owner_grants).expect("register alex");
        let passes = SitePasses::new(PassKey::ephemeral().expect("a key"));
        let gate = PassGate::new(passes, people);
        let site = ordinary_site("blog");
        let name = SiteName::parse(&site.name).unwrap();
        let alex = Identity::Person(PersonName::parse("alex").unwrap());
        assert!(
            gate.holds_a_grant(&alex, &site, &name),
            "a holder of Capability::Owner is let onto any site's Pass gate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_person_with_no_grant_at_all_is_refused_the_site() {
        let dir = scratch("no-grant");
        let people = People::load(&dir);
        people.set_grants(&PersonName::parse("alex").unwrap(), Grants::none()).expect("register alex");
        let passes = SitePasses::new(PassKey::ephemeral().expect("a key"));
        let gate = PassGate::new(passes, people);
        let site = ordinary_site("blog");
        let name = SiteName::parse(&site.name).unwrap();
        let alex = Identity::Person(PersonName::parse("alex").unwrap());
        assert!(!gate.holds_a_grant(&alex, &site, &name), "no grant must not open the gate");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
