//! The cookie that lets a browser come back as the account it registered — mint, look up, end,
//! end-all-for-an-account, and the `Set-Cookie`/clear-cookie builders. Depends on nothing else in
//! this crate, and (deliberately) needs nothing from a caller but a config: no notion of what an
//! "account" is beyond the `&str` id it was minted for.
//!
//! # Persisted, unlike an in-memory session table
//!
//! Sessions are written to `<data_dir>/<config.filename>`, the same temp-file-and-rename shape
//! every other store in this workspace uses, and reloaded on the next start — so a door whose
//! process restarts often (a self-updating daemon rebuilding on every push, say) does not sign
//! out every visitor on every deploy.
//!
//! # Two clocks
//!
//! A session dies at the sooner of an absolute lifetime (`config.lifetime_secs`) and an idle one
//! (`config.idle_secs`) that resets on each authenticated request: an absolute cap bounds how
//! long a stolen cookie is worth anything, and the idle cap ends a session nobody is actually
//! using sooner than that.
//!
//! # One config, many doors
//!
//! Extracted from `crates/reports/src/sessions.rs`, which used to hardcode its cookie name,
//! filename, and lifetimes as module constants. [`SessionConfig`] is what lets a second door
//! (a different cookie name, a different `Path` scope, different lifetimes) reuse this logic
//! without copying it — each caller supplies its own preset rather than this crate guessing one.

use ring::rand::{SecureRandom, SystemRandom};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bytes of entropy in a session id: 256 bits, the same size this workspace's other credential
/// tokens use.
const SESSION_ID_BYTES: usize = 32;

/// What one door needs to say about its own sessions: the cookie name, where the store file
/// lives inside `<data_dir>`, how long a session lives, and how many this box will hold at once.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// The `Set-Cookie` name this door mints and reads.
    pub cookie_name: &'static str,
    /// The filename the session store is written as, inside a data directory.
    pub filename: &'static str,
    /// How long a session lives at most, regardless of activity.
    pub lifetime_secs: u64,
    /// How long a session survives with no authenticated request before it is treated as
    /// abandoned, refreshed on every successful lookup.
    pub idle_secs: u64,
    /// The most sessions this door will hold at once. Past this, the session that has gone
    /// longest without being used is evicted to make room — whoever is displaced can sign in
    /// again.
    pub max_sessions: usize,
}

/// One outstanding session.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    id: String,
    account_id: String,
    created_unix: u64,
    last_seen_unix: u64,
}

/// The durable session store for one door's [`SessionConfig`].
///
/// A cheap-clone handle over shared state: a session minted through one handle must be found by
/// a lookup through another in the same process.
#[derive(Clone)]
pub struct Sessions {
    config: SessionConfig,
    path: PathBuf,
    entries: Arc<Mutex<Vec<Session>>>,
}

impl Sessions {
    /// Loads the store from `<data_dir>/<config.filename>`. A missing or malformed file loads
    /// empty — a session store nobody can read is the same as everybody being signed out, which
    /// is the fail-closed direction.
    pub fn load(data_dir: &Path, config: SessionConfig) -> Self {
        let path = Self::path_in(data_dir, &config);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => parse_sessions(&text).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Self { config, path, entries: Arc::new(Mutex::new(entries)) }
    }

    /// Where the session file lives for a given data directory and config.
    #[must_use]
    pub fn path_in(data_dir: &Path, config: &SessionConfig) -> PathBuf {
        data_dir.join(config.filename)
    }

    /// Mints a session for `account_id`, persists, and returns the cookie value.
    ///
    /// # Errors
    /// An [`io::Error`] naming what could not be written, or what the system's random source
    /// refused.
    pub fn create(&self, account_id: &str) -> io::Result<String> {
        let id = fresh_id()?;
        let now = now_unix();
        let mut entries = self.lock();
        self.sweep(&mut entries, now);
        while entries.len() >= self.config.max_sessions {
            if let Some(index) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, session)| session.last_seen_unix)
                .map(|(index, _)| index)
            {
                entries.remove(index);
            } else {
                break;
            }
        }
        entries.push(Session {
            id: id.clone(),
            account_id: account_id.to_string(),
            created_unix: now,
            last_seen_unix: now,
        });
        self.persist(&entries)?;
        Ok(id)
    }

    /// The account id a presented cookie value authenticates as, if the session is live —
    /// refreshing its idle clock on the way out.
    ///
    /// Constant-time comparison, and the walk visits every entry rather than short-circuiting,
    /// like every other credential lookup in this workspace.
    #[must_use]
    pub fn account_of(&self, presented: &str) -> Option<String> {
        let now = now_unix();
        let mut entries = self.lock();
        self.sweep(&mut entries, now);
        let mut found = None;
        for session in entries.iter_mut() {
            if constant_time_eq(session.id.as_bytes(), presented.as_bytes()) {
                session.last_seen_unix = now;
                found = Some(session.account_id.clone());
            }
        }
        if found.is_some() {
            let _ = self.persist(&entries);
        }
        found
    }

    /// Ends the session named by `presented`, if it exists. Never an error: logging out of a
    /// session that has already expired or never existed reaches the same signed-out state.
    pub fn end(&self, presented: &str) {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|session| !constant_time_eq(session.id.as_bytes(), presented.as_bytes()));
        if entries.len() != before {
            let _ = self.persist(&entries);
        }
    }

    /// Ends every session belonging to `account_id` — used when a password changes, so a
    /// credential rotation actually signs out whoever else was using the old one.
    pub fn end_all_for(&self, account_id: &str) {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|session| session.account_id != account_id);
        if entries.len() != before {
            let _ = self.persist(&entries);
        }
    }

    /// Drops every session past its absolute or idle lifetime.
    fn sweep(&self, entries: &mut Vec<Session>, now: u64) {
        entries.retain(|session| {
            now.saturating_sub(session.created_unix) < self.config.lifetime_secs
                && now.saturating_sub(session.last_seen_unix) < self.config.idle_secs
        });
    }

    fn persist(&self, entries: &[Session]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = sessions_to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Session>> {
        self.entries.lock().expect("the session store lock was poisoned")
    }
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Sessions({} live)", self.lock().len())
    }
}

/// The `Set-Cookie` line for a freshly minted session, per `config`.
///
/// `SameSite=Lax` or `Strict` is the caller's call, encoded into how it built `config` and
/// whether it wants this exact attribute set — this crate itself always writes `SameSite=Lax`,
/// `HttpOnly`, and `Secure` only when asked, matching the union of both current callers; a door
/// needing `Strict` builds its own header, or this function grows a parameter once a second real
/// caller needs it.
#[must_use]
pub fn set_cookie_header(config: &SessionConfig, value: &str, route: &str, secure: bool) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!(
        "{}={value}; HttpOnly{secure_attribute}; SameSite=Lax; Path={route}; Max-Age={}",
        config.cookie_name, config.lifetime_secs
    )
}

/// The `Set-Cookie` line that clears the session cookie on logout, per `config`.
#[must_use]
pub fn clear_cookie_header(config: &SessionConfig, route: &str, secure: bool) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!("{}=; HttpOnly{secure_attribute}; SameSite=Lax; Path={route}; Max-Age=0", config.cookie_name)
}

/// Reads `config`'s session cookie's value out of a request's `Cookie` header, if present.
///
/// A `Cookie` header carries every cookie the browser holds for this origin, `;`-separated; this
/// picks out the one named by `config.cookie_name` and ignores the rest, whoever else set them.
#[must_use]
pub fn cookie_value(config: &SessionConfig, header: Option<&str>) -> Option<String> {
    let header = header?;
    header.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == config.cookie_name).then(|| value.trim().to_string())
    })
}

fn fresh_id() -> io::Result<String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; SESSION_ID_BYTES];
    rng.fill(&mut bytes).map_err(|_| io::Error::other("the system random source was unavailable"))?;
    Ok(hex(&bytes))
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    })
}

/// Constant-time comparison, shared by every credential check in this crate.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |differences, (a, b)| differences | (a ^ b)) == 0
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn sessions_to_json(entries: &[Session]) -> Json {
    Json::object([(
        "sessions",
        Json::array(entries.iter().map(|session| {
            Json::object([
                ("id", Json::string(&session.id)),
                ("accountId", Json::string(&session.account_id)),
                ("createdUnix", Json::Number(session.created_unix as f64)),
                ("lastSeenUnix", Json::Number(session.last_seen_unix as f64)),
            ])
        })),
    )])
}

fn parse_sessions(text: &str) -> Option<Vec<Session>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("sessions")?.as_array()?;
    let mut entries = Vec::new();
    for item in items {
        entries.push(Session {
            id: item.get("id")?.as_str()?.to_owned(),
            account_id: item.get("accountId")?.as_str()?.to_owned(),
            created_unix: item.get("createdUnix")?.as_u64()?,
            last_seen_unix: item.get("lastSeenUnix")?.as_u64()?,
        });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: SessionConfig = SessionConfig {
        cookie_name: "report_session",
        filename: "sessions.json",
        lifetime_secs: 30 * 24 * 60 * 60,
        idle_secs: 14 * 24 * 60 * 60,
        max_sessions: 50_000,
    };

    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("selfhost-login-session-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_minted_session_resolves_to_the_account_it_was_minted_for() {
        let dir = scratch("basic");
        let sessions = Sessions::load(&dir, CONFIG);
        let cookie = sessions.create("acct-1").expect("minted");
        assert_eq!(sessions.account_of(&cookie), Some("acct-1".to_string()));
        assert!(sessions.account_of("not-a-real-session").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ending_a_session_signs_it_out_immediately() {
        let dir = scratch("logout");
        let sessions = Sessions::load(&dir, CONFIG);
        let cookie = sessions.create("acct-1").expect("minted");
        sessions.end(&cookie);
        assert!(sessions.account_of(&cookie).is_none());
        sessions.end("never-issued");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ending_every_session_for_an_account_leaves_others_alone() {
        let dir = scratch("end-all");
        let sessions = Sessions::load(&dir, CONFIG);
        let mine = sessions.create("acct-1").expect("minted");
        let also_mine = sessions.create("acct-1").expect("minted");
        let someone_elses = sessions.create("acct-2").expect("minted");
        sessions.end_all_for("acct-1");
        assert!(sessions.account_of(&mine).is_none());
        assert!(sessions.account_of(&also_mine).is_none());
        assert_eq!(sessions.account_of(&someone_elses), Some("acct-2".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sessions_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let cookie = Sessions::load(&dir, CONFIG).create("acct-1").expect("minted");
        let reloaded = Sessions::load(&dir, CONFIG);
        assert_eq!(reloaded.account_of(&cookie), Some("acct-1".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cookie_header_carries_the_expected_attributes() {
        let header = set_cookie_header(&CONFIG, "abc123", "/report", true);
        assert!(header.starts_with("report_session=abc123;"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/report"));

        let insecure = set_cookie_header(&CONFIG, "abc123", "/report", false);
        assert!(!insecure.contains("Secure"), "{insecure}");
    }

    #[test]
    fn a_cleared_cookie_expires_immediately() {
        let header = clear_cookie_header(&CONFIG, "/report", true);
        assert!(header.contains("Max-Age=0"));
    }

    #[test]
    fn the_session_cookie_is_picked_out_of_a_header_carrying_others() {
        let header = "other=1; report_session=the-value; third=2";
        assert_eq!(cookie_value(&CONFIG, Some(header)), Some("the-value".to_string()));
        assert_eq!(cookie_value(&CONFIG, Some("other=1")), None);
        assert_eq!(cookie_value(&CONFIG, None), None);
    }

    #[test]
    fn an_expired_session_stops_resolving() {
        let dir = scratch("expired");
        let sessions = Sessions::load(&dir, CONFIG);
        let cookie = sessions.create("acct-1").expect("minted");
        {
            let mut entries = sessions.lock();
            for session in entries.iter_mut() {
                session.created_unix = 0;
                session.last_seen_unix = 0;
            }
            let snapshot = entries.clone();
            sessions.persist(&snapshot).expect("persists");
        }
        assert!(sessions.account_of(&cookie).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_table_never_grows_past_its_cap() {
        let dir = scratch("cap");
        // Seeded directly at the cap, for the same reason `accounts::tests` seeds rather than
        // loops to the cap: `create` rewrites the whole file on every call, and a tight loop to
        // 50,000 pays for that thousands of times over just to reach the boundary this test
        // cares about.
        let sessions = Sessions::load(&dir, CONFIG);
        let now = now_unix();
        let seeded = (0..CONFIG.max_sessions).map(|nth| Session {
            id: format!("seed-{nth:040x}"),
            account_id: format!("acct-{nth}"),
            created_unix: now,
            last_seen_unix: now,
        });
        sessions.lock().extend(seeded);

        sessions.create("acct-overflow").expect("minted");
        assert!(sessions.lock().len() <= CONFIG.max_sessions);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_doors_with_different_configs_never_collide_on_the_same_directory() {
        // The whole point of a per-door config: two callers pointed at the same data directory
        // with different filenames/cookie names must not see each other's sessions.
        let dir = scratch("two-doors");
        const OTHER: SessionConfig = SessionConfig {
            cookie_name: "other_session",
            filename: "other-sessions.json",
            ..CONFIG
        };
        let a = Sessions::load(&dir, CONFIG);
        let b = Sessions::load(&dir, OTHER);
        let cookie = a.create("acct-1").expect("minted");
        assert!(b.account_of(&cookie).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
