//! In-memory console sessions and the login failure gate.
//!
//! A session is what a browser holds after a successful password login: an
//! unguessable id in an `HttpOnly` cookie, checked on every request the same
//! way the bearer token is. Sessions live only in memory — a daemon restart
//! logs every browser out, which for a control surface is the right default:
//! nothing durable to steal from disk, nothing to invalidate on rotation.
//!
//! Both types here are cheap-clone handles over shared state, because [`crate::Api`]
//! is `Clone` and every connection handler gets its own copy: a login accepted
//! by one clone must be visible to all of them, and a failure counted by one
//! must count against the same gate the others consult.

use crate::token::{constant_time_eq, hex, random_bytes};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bytes of entropy in a session id. 256 bits, rendered as 64 hex characters —
/// the same strength as the bearer token, because it grants the same power.
const SESSION_ID_BYTES: usize = 32;

/// How long a session may live in total, however active. Matches the cookie's
/// `Max-Age` ([`SESSION_LIFETIME_SECS`]) so the browser and the store expire
/// together.
const ABSOLUTE_LIFETIME: Duration = Duration::from_secs(SESSION_LIFETIME_SECS);

/// The session's absolute lifetime in seconds: 12 hours, exported for the
/// `Set-Cookie` header so the two limits cannot drift apart.
pub const SESSION_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// How long a session survives without being used. A console left open on an
/// unlocked machine stops being a way in after two idle hours.
const IDLE_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

/// The most sessions kept at once. One operator with a handful of browsers
/// never approaches this; a login loop evicting its own oldest session cannot
/// balloon memory.
const MAX_SESSIONS: usize = 32;

/// One logged-in browser.
struct Entry {
    /// The 64-hex-character id the cookie carries.
    id: String,
    /// Who logged in: `"owner"` for the password (and the bearer token's
    /// implicit identity), or the passkey holder's own name. Identity, not
    /// authority — every session opens the same console today, and this field
    /// is where per-user permissions will attach when they arrive.
    user: String,
    /// When the session was created; drives the absolute expiry.
    created: Instant,
    /// When the session last authenticated a request; drives the idle expiry.
    last_seen: Instant,
}

/// The shared in-memory session store.
///
/// Cloning shares the store: every clone of the [`crate::Api`] sees the same
/// sessions. Expired entries are purged lazily on every create and validate,
/// so no background task is needed to keep the store from growing.
#[derive(Clone)]
pub struct Sessions {
    entries: Arc<Mutex<Vec<Entry>>>,
    absolute: Duration,
    idle: Duration,
}

impl Sessions {
    /// A store with the production lifetimes: 12 hours absolute, 2 hours idle.
    pub fn new() -> Self {
        Self::with_expiry(ABSOLUTE_LIFETIME, IDLE_LIFETIME)
    }

    /// A store with explicit lifetimes.
    ///
    /// The seam that makes expiry testable without a 12-hour test: production
    /// goes through [`Sessions::new`], a test passes `Duration::ZERO` to get a
    /// session that is expired the moment it is created.
    pub fn with_expiry(absolute: Duration, idle: Duration) -> Self {
        Self { entries: Arc::new(Mutex::new(Vec::new())), absolute, idle }
    }

    /// Creates a session for `user` and returns its id, evicting the oldest
    /// if at capacity.
    ///
    /// The id comes from the operating system's entropy — the same source as
    /// the bearer token — and an entropy failure is an error, never a weaker id.
    pub fn create(&self, user: &str) -> io::Result<String> {
        let id = hex(&random_bytes(SESSION_ID_BYTES)?);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| !self.expired(entry, now));
        // Entries are pushed in creation order, so the front is always oldest.
        while entries.len() >= MAX_SESSIONS {
            entries.remove(0);
        }
        entries.push(Entry { id: id.clone(), user: user.to_owned(), created: now, last_seen: now });
        Ok(id)
    }

    /// Who holds the live session named by `presented`, if anyone.
    ///
    /// Answers identity only — [`Sessions::validate`] remains the door check
    /// and the idle-timer refresh; this walk touches nothing. Compared in
    /// constant time and never returning early, like every credential here.
    pub fn identity(&self, presented: &str) -> Option<String> {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| !self.expired(entry, now));
        let mut found = None;
        for entry in entries.iter() {
            if constant_time_eq(entry.id.as_bytes(), presented.as_bytes()) {
                found = Some(entry.user.clone());
            }
        }
        found
    }

    /// Whether `presented` names a live session, refreshing its idle timer.
    ///
    /// Compared in constant time, like every credential in this crate. The
    /// walk always visits every live entry rather than returning early, so a
    /// match and a miss cost the same.
    pub fn validate(&self, presented: &str) -> bool {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| !self.expired(entry, now));
        let mut found = false;
        for entry in entries.iter_mut() {
            if constant_time_eq(entry.id.as_bytes(), presented.as_bytes()) {
                entry.last_seen = now;
                found = true;
            }
        }
        found
    }

    /// Forgets the session named by `presented`, if it exists.
    ///
    /// Revoking an unknown id is a no-op, not an error: logout must succeed
    /// whether or not the cookie was still valid.
    pub fn revoke(&self, presented: &str) {
        self.lock().retain(|entry| !constant_time_eq(entry.id.as_bytes(), presented.as_bytes()));
    }

    /// Whether an entry has outlived either limit at `now`.
    fn expired(&self, entry: &Entry, now: Instant) -> bool {
        now.duration_since(entry.created) >= self.absolute
            || now.duration_since(entry.last_seen) >= self.idle
    }

    /// The entries, with lock poisoning treated as fatal.
    ///
    /// A poisoned lock means a panic happened while the session list was held;
    /// limping on with credentials in an unknown state is worse than stopping.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().expect("the session store lock was poisoned")
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

/// How many failed logins are tolerated per [`FAILURE_WINDOW`] before the
/// login route answers 429.
const FAILURE_LIMIT: usize = 5;

/// The sliding window over which login failures are counted.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// The login rate limiter: after [`FAILURE_LIMIT`] failures within
/// [`FAILURE_WINDOW`], logins are refused for the remainder of the window.
///
/// Deliberately global rather than per-IP: the admin API binds loopback, so
/// every request arrives from the reverse proxy (or an SSH tunnel) and the
/// source address distinguishes nothing. At one operator's scale, locking the
/// single login door for under a minute is the right trade against an online
/// password guesser; the PBKDF2 cost covers the offline one.
#[derive(Clone)]
pub struct FailureGate {
    failures: Arc<Mutex<Vec<Instant>>>,
}

impl FailureGate {
    /// A gate with no failures recorded.
    pub fn new() -> Self {
        Self { failures: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Whether logins are currently refused.
    ///
    /// Prunes failures older than the window as it answers, so the gate
    /// reopens by itself once the window slides past the burst.
    pub fn locked(&self) -> bool {
        let now = Instant::now();
        let mut failures = self.lock();
        failures.retain(|at| now.duration_since(*at) < FAILURE_WINDOW);
        failures.len() >= FAILURE_LIMIT
    }

    /// Records one failed login attempt.
    pub fn record_failure(&self) {
        self.lock().push(Instant::now());
    }

    /// Clears the count after a successful login.
    pub fn reset(&self) {
        self.lock().clear();
    }

    /// The failure times, with lock poisoning treated as fatal, as in
    /// [`Sessions::lock`].
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Instant>> {
        self.failures.lock().expect("the failure gate lock was poisoned")
    }
}

impl Default for FailureGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_created_session_validates_and_an_invented_one_does_not() {
        let sessions = Sessions::new();
        let id = sessions.create("owner").expect("system entropy");
        assert_eq!(id.len(), SESSION_ID_BYTES * 2, "64 hex characters");
        assert!(sessions.validate(&id));
        assert!(!sessions.validate("0".repeat(64).as_str()));
        assert!(!sessions.validate(&id[..32]), "a prefix is not a match");
        assert!(!sessions.validate(""));
    }

    #[test]
    fn clones_share_one_store() {
        // Api is Clone; a login accepted by one clone must hold on another.
        let sessions = Sessions::new();
        let clone = sessions.clone();
        let id = sessions.create("owner").unwrap();
        assert!(clone.validate(&id));
        clone.revoke(&id);
        assert!(!sessions.validate(&id));
    }

    #[test]
    fn a_revoked_session_stops_validating() {
        let sessions = Sessions::new();
        let id = sessions.create("owner").unwrap();
        sessions.revoke(&id);
        assert!(!sessions.validate(&id));
        sessions.revoke(&id); // revoking again is a no-op, not a panic
    }

    #[test]
    fn an_expired_session_is_rejected_and_purged() {
        let sessions = Sessions::with_expiry(Duration::ZERO, Duration::ZERO);
        let id = sessions.create("owner").unwrap();
        assert!(!sessions.validate(&id), "zero lifetime expires immediately");
    }

    #[test]
    fn an_idle_session_expires_even_inside_its_absolute_lifetime() {
        let sessions = Sessions::with_expiry(Duration::from_secs(3600), Duration::ZERO);
        let id = sessions.create("owner").unwrap();
        assert!(!sessions.validate(&id), "the idle limit binds on its own");
    }

    #[test]
    fn the_store_is_capped_by_evicting_the_oldest() {
        let sessions = Sessions::new();
        let first = sessions.create("owner").unwrap();
        for _ in 0..MAX_SESSIONS {
            sessions.create("owner").unwrap();
        }
        assert!(!sessions.validate(&first), "the oldest session is evicted at capacity");
        let held = sessions.lock().len();
        assert!(held <= MAX_SESSIONS, "{held} sessions held");
    }

    #[test]
    fn the_gate_locks_at_the_limit_and_reopens_on_reset() {
        let gate = FailureGate::new();
        for _ in 0..FAILURE_LIMIT - 1 {
            gate.record_failure();
        }
        assert!(!gate.locked(), "under the limit stays open");
        gate.record_failure();
        assert!(gate.locked(), "the fifth failure locks the gate");
        gate.reset();
        assert!(!gate.locked(), "a successful login clears the count");
    }

    #[test]
    fn clones_share_one_gate() {
        let gate = FailureGate::new();
        let clone = gate.clone();
        for _ in 0..FAILURE_LIMIT {
            clone.record_failure();
        }
        assert!(gate.locked(), "failures recorded on a clone count everywhere");
    }
}
