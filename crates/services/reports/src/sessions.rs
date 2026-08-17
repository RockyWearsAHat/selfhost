//! The cookie that lets a browser come back as the account it registered.
//!
//! A thin, reports-specific preset over `selfhost_login::session` — see that module's
//! documentation for why sessions are persisted rather than kept in memory (unlike
//! `crates/admin`'s console sessions) and for the two-clock lifetime shape. This module supplies
//! only what makes this door's sessions *this door's*: the cookie name, the file they live in,
//! and the lifetimes — `report_session`, `sessions.json`, thirty days absolute / fourteen idle,
//! unchanged from before this crate depended on `selfhost-login`.
//!
//! `SameSite=Lax` rather than `Strict`, deliberately unlike the admin console's cookie: this
//! account is reached from links this box does not control — a verification email, an OAuth
//! provider's redirect back — and `Strict` would drop the cookie on exactly the top-level
//! navigation those are. `Lax` still refuses the cookie on a cross-site `POST` or a subresource
//! load, which is what actually matters for CSRF.

use selfhost_login::session::SessionConfig;
use std::io;
use std::path::{Path, PathBuf};

/// The name of the session file inside `<data_dir>/reports/`.
pub const SESSIONS_FILENAME: &str = "sessions.json";

/// The cookie a browser is asked to hold.
pub const COOKIE_NAME: &str = "report_session";

/// How long a session lives at most, regardless of activity. Thirty days: this is a public
/// bug-tracker account, not a banking session, and asking a reporter to sign in every visit
/// buys nothing.
pub const SESSION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// How long a session survives with no authenticated request before it is treated as
/// abandoned, refreshed on every successful lookup.
pub const IDLE_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

/// The most sessions this box will hold at once.
pub const MAX_SESSIONS: usize = 50_000;

const CONFIG: SessionConfig = SessionConfig {
    cookie_name: COOKIE_NAME,
    filename: SESSIONS_FILENAME,
    lifetime_secs: SESSION_LIFETIME_SECS,
    idle_secs: IDLE_LIFETIME_SECS,
    max_sessions: MAX_SESSIONS,
};

/// The durable session store: `<data_dir>/reports/sessions.json`, this door's `CONFIG` applied
/// to `selfhost_login::session::Sessions`.
#[derive(Clone)]
pub struct Sessions(selfhost_login::session::Sessions);

impl Sessions {
    /// Loads the store from `<data_dir>/sessions.json`.
    pub fn load(data_dir: &Path) -> Self {
        Self(selfhost_login::session::Sessions::load(data_dir, CONFIG))
    }

    /// Where the session file lives for a given data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        selfhost_login::session::Sessions::path_in(data_dir, &CONFIG)
    }

    /// Mints a session for `account_id`, persists, and returns the cookie value.
    pub fn create(&self, account_id: &str) -> io::Result<String> {
        self.0.create(account_id)
    }

    /// The account id a presented cookie value authenticates as, if the session is live.
    #[must_use]
    pub fn account_of(&self, presented: &str) -> Option<String> {
        self.0.account_of(presented)
    }

    /// Ends the session named by `presented`, if it exists.
    pub fn end(&self, presented: &str) {
        self.0.end(presented)
    }

    /// Ends every session belonging to `account_id`.
    pub fn end_all_for(&self, account_id: &str) {
        self.0.end_all_for(account_id)
    }
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, out)
    }
}

/// The `Set-Cookie` line for a freshly minted session. `Secure` is omitted only over plain
/// loopback, exactly as the admin console's cookie does, because the public door is always the
/// proxy's TLS.
#[must_use]
pub fn set_cookie_header(value: &str, route: &str, secure: bool) -> String {
    selfhost_login::session::set_cookie_header(&CONFIG, value, route, secure)
}

/// The `Set-Cookie` line that clears the session cookie on logout.
#[must_use]
pub fn clear_cookie_header(route: &str, secure: bool) -> String {
    selfhost_login::session::clear_cookie_header(&CONFIG, route, secure)
}

/// Reads the session cookie's value out of a request's `Cookie` header, if present.
#[must_use]
pub fn cookie_value(header: Option<&str>) -> Option<String> {
    selfhost_login::session::cookie_value(&CONFIG, header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-reports-sessions-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// The session lifecycle itself (expiry, the cap, reload-from-disk, end-all-for-an-account)
    /// is proven once, generically, in `selfhost_login::session`'s own tests. What is worth
    /// proving here is only that this door's preset — the cookie name, the filename, the fact
    /// that `service.rs` reaches these functions through this exact API — actually delegates.
    #[test]
    fn a_minted_session_round_trips_through_this_doors_preset() {
        let dir = scratch("roundtrip");
        let sessions = Sessions::load(&dir);
        let cookie = sessions.create("acct-1").expect("minted");
        assert_eq!(sessions.account_of(&cookie), Some("acct-1".to_string()));
        sessions.end(&cookie);
        assert!(sessions.account_of(&cookie).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_file_is_named_and_placed_as_documented() {
        let dir = scratch("path");
        assert_eq!(Sessions::path_in(&dir), dir.join(SESSIONS_FILENAME));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cookie_header_carries_this_doors_name_and_expected_attributes() {
        let header = set_cookie_header("abc123", "/report", true);
        assert!(header.starts_with(&format!("{COOKIE_NAME}=abc123;")));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/report"));

        let insecure = set_cookie_header("abc123", "/report", false);
        assert!(!insecure.contains("Secure"), "{insecure}");

        let cleared = clear_cookie_header("/report", true);
        assert!(cleared.contains("Max-Age=0"));
    }

    #[test]
    fn the_session_cookie_is_picked_out_of_a_header_carrying_others() {
        let header = format!("other=1; {COOKIE_NAME}=the-value; third=2");
        assert_eq!(cookie_value(Some(&header)), Some("the-value".to_string()));
        assert_eq!(cookie_value(Some("other=1")), None);
        assert_eq!(cookie_value(None), None);
    }
}
