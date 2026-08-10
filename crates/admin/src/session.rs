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
use selfhost_identity::Opening;
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
    /// authority — the authority is
    /// [`People`](selfhost_identity::People)'s, keyed on this name, and
    /// [`Api::caller`](crate::Api::caller) is where the two are joined.
    user: String,
    /// What was presented at the login this session stands for.
    ///
    /// Recorded because a cookie on its own answers *that* somebody logged in
    /// and never *how*, and the desktop's freshness rule is written in terms of
    /// how: a password or a passkey is an act of authentication with a person
    /// behind it, and the difference is what decides whether this session may
    /// later be handed a keyboard.
    opened_by: Opening,
    /// When the session was created; drives the absolute expiry, and is the
    /// moment the login happened for the freshness rule.
    created: Instant,
    /// When the session last authenticated a request; drives the idle expiry.
    last_seen: Instant,
}

/// A live session, as the authorisation seam needs to see it.
///
/// Returned rather than a bare name because every caller that wants the holder
/// also wants the login it stands for, and two lookups over a credential store
/// is two walks that can disagree about which entry they found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Who holds the session: `"owner"`, or a person's own name.
    pub user: String,
    /// What was presented at the login.
    pub opened_by: Opening,
    /// When the login happened.
    pub opened_at: Instant,
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

    /// Creates a session for `user`, opened by `opened_by`, and returns its id,
    /// evicting the oldest if at capacity.
    ///
    /// The id comes from the operating system's entropy — the same source as
    /// the bearer token — and an entropy failure is an error, never a weaker id.
    /// `opened_by` is taken rather than defaulted because the two login doors
    /// are not interchangeable to the freshness rule that reads it later, and a
    /// default would be a guess made in the one place that knows the answer.
    pub fn create(&self, user: &str, opened_by: Opening) -> io::Result<String> {
        let id = hex(&random_bytes(SESSION_ID_BYTES)?);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| !self.expired(entry, now));
        // Entries are pushed in creation order, so the front is always oldest.
        while entries.len() >= MAX_SESSIONS {
            entries.remove(0);
        }
        entries.push(Entry {
            id: id.clone(),
            user: user.to_owned(),
            opened_by,
            created: now,
            last_seen: now,
        });
        Ok(id)
    }

    /// Who holds the live session named by `presented`, and how they logged in.
    ///
    /// Answers identity only — [`Sessions::validate`] remains the door check
    /// and the idle-timer refresh; this walk touches nothing. Compared in
    /// constant time and never returning early, like every credential here.
    pub fn authenticated(&self, presented: &str) -> Option<Authenticated> {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| !self.expired(entry, now));
        let mut found = None;
        for entry in entries.iter() {
            if constant_time_eq(entry.id.as_bytes(), presented.as_bytes()) {
                found = Some(Authenticated {
                    user: entry.user.clone(),
                    opened_by: entry.opened_by,
                    opened_at: entry.created,
                });
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
/// login route answers 429 to a *wrong* credential.
pub const FAILURE_LIMIT: usize = 5;

/// The sliding window over which login failures are counted.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// The most failures kept in the window.
///
/// The gate answers the same once it is locked, so counting past this buys
/// nothing and an unbounded vector fed by an attacker is a way to grow the
/// process. Held well above [`FAILURE_LIMIT`] so the window still slides
/// honestly rather than being truncated at the limit itself.
const MAX_FAILURES_HELD: usize = 64;

/// How long a wrong credential waits for its refusal once the gate is locked.
///
/// The lockout's remaining cost to a guesser after the rule below took away its
/// ability to refuse a *correct* credential. Long enough to be felt on every
/// attempt, short enough that an operator who genuinely mistyped their password
/// during a burst is not left staring at a spinner.
pub const LOCKED_PENALTY: Duration = Duration::from_millis(750);

/// The login rate limiter.
///
/// # The rule, and the finding that changed it
///
/// The gate counts failed logins across both login doors and, once
/// [`FAILURE_LIMIT`] have landed inside [`FAILURE_WINDOW`], it is *locked*. It
/// used to refuse everything while locked, correct credentials included. That is
/// the textbook lockout and on this box it is a weapon pointed the wrong way.
///
/// This API binds loopback, and the console site's `allowed_cidrs` gate is
/// loopback too, because the operator's VPN tunnel exits there. "Behind the
/// gate" therefore means "reachable by anything already executing on this box,
/// including three co-hosted web apps". Any one of them with a server-side
/// request forgery can `POST /api/session` with one custom header, five times,
/// and hold the console's login shut. The desktop design routes the operator
/// back through this exact door to be handed a keyboard, so a lockout is not an
/// inconvenience — it is a remotely-triggered denial of the operator's own
/// machine.
///
/// So the rule is now:
///
/// > **A lockout may refuse a wrong credential. It may never refuse a right
/// > one.**
///
/// An attempt is verified whether or not the gate is locked. A correct one is
/// admitted and clears the count. An incorrect one is refused, and while the
/// gate is locked it waits [`LOCKED_PENALTY`] first ([`FailureGate::penalise`]),
/// which is what the lockout costs a guesser now that it cannot cost the
/// operator anything.
///
/// # What this defends, and what it does not
///
/// It defends the operator's access: no sequence of failures by anybody can
/// stop somebody who knows the password or holds a passkey from logging in.
///
/// It does **not** identify the source of an attempt. Every request arrives from
/// loopback and the source address distinguishes nothing, so per-source counting
/// is not implementable here and this rule does not pretend otherwise. It does
/// not stop a neighbour from keeping the gate perpetually locked; it only makes
/// that state harmless to the operator. And it does not bound a *parallel*
/// guesser's CPU cost: the penalty delays one attempt, not the number of
/// attempts in flight, so the real ceiling on online guessing remains the PBKDF2
/// work factor in [`crate::ConsolePassword`] — which is also what makes each of
/// those attempts expensive to the attacker.
#[derive(Clone)]
pub struct FailureGate {
    failures: Arc<Mutex<Vec<Instant>>>,
    penalty: Duration,
}

impl FailureGate {
    /// A gate with no failures recorded and the production penalty.
    pub fn new() -> Self {
        Self::with_penalty(LOCKED_PENALTY)
    }

    /// A gate with an explicit penalty — the seam that keeps the tests of a
    /// locked gate from spending real seconds asleep.
    pub fn with_penalty(penalty: Duration) -> Self {
        Self { failures: Arc::new(Mutex::new(Vec::new())), penalty }
    }

    /// Whether the gate is currently locked.
    ///
    /// Prunes failures older than the window as it answers, so the gate
    /// reopens by itself once the window slides past the burst. A locked gate
    /// refuses a credential that turned out to be wrong; it never decides
    /// whether a credential is checked at all — see the type's documentation.
    pub fn locked(&self) -> bool {
        let now = Instant::now();
        let mut failures = self.lock();
        failures.retain(|at| now.duration_since(*at) < FAILURE_WINDOW);
        failures.len() >= FAILURE_LIMIT
    }

    /// Records one failed login attempt.
    pub fn record_failure(&self) {
        let now = Instant::now();
        let mut failures = self.lock();
        failures.retain(|at| now.duration_since(*at) < FAILURE_WINDOW);
        if failures.len() < MAX_FAILURES_HELD {
            failures.push(now);
        }
    }

    /// Clears the count after a successful login.
    pub fn reset(&self) {
        self.lock().clear();
    }

    /// Waits out the penalty a wrong credential owes a locked gate.
    ///
    /// Awaited on the refusal path only, after the credential has been checked
    /// and found wrong, so it is never a cost to somebody who can log in.
    pub async fn penalise(&self) {
        tokio::time::sleep(self.penalty).await;
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

    /// A session opened the way the console password door opens one.
    fn create(sessions: &Sessions, user: &str) -> io::Result<String> {
        sessions.create(user, Opening::Password)
    }

    #[test]
    fn a_created_session_validates_and_an_invented_one_does_not() {
        let sessions = Sessions::new();
        let id = create(&sessions, "owner").expect("system entropy");
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
        let id = create(&sessions, "owner").unwrap();
        assert!(clone.validate(&id));
        clone.revoke(&id);
        assert!(!sessions.validate(&id));
    }

    #[test]
    fn a_revoked_session_stops_validating() {
        let sessions = Sessions::new();
        let id = create(&sessions, "owner").unwrap();
        sessions.revoke(&id);
        assert!(!sessions.validate(&id));
        sessions.revoke(&id); // revoking again is a no-op, not a panic
    }

    #[test]
    fn an_expired_session_is_rejected_and_purged() {
        let sessions = Sessions::with_expiry(Duration::ZERO, Duration::ZERO);
        let id = create(&sessions, "owner").unwrap();
        assert!(!sessions.validate(&id), "zero lifetime expires immediately");
    }

    #[test]
    fn an_idle_session_expires_even_inside_its_absolute_lifetime() {
        let sessions = Sessions::with_expiry(Duration::from_secs(3600), Duration::ZERO);
        let id = create(&sessions, "owner").unwrap();
        assert!(!sessions.validate(&id), "the idle limit binds on its own");
    }

    #[test]
    fn the_store_is_capped_by_evicting_the_oldest() {
        let sessions = Sessions::new();
        let first = create(&sessions, "owner").unwrap();
        for _ in 0..MAX_SESSIONS {
            create(&sessions, "owner").unwrap();
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

    #[test]
    fn the_failure_window_is_bounded_however_long_a_neighbour_keeps_pushing() {
        // The gate is fed by anything that can reach loopback, which on this box
        // includes three co-hosted web apps. It answers the same once locked, so
        // holding more than the cap buys nothing and would be a way to grow the
        // process one failed login at a time.
        let gate = FailureGate::new();
        for _ in 0..(MAX_FAILURES_HELD * 4) {
            gate.record_failure();
        }
        assert!(gate.locked());
        assert!(gate.lock().len() <= MAX_FAILURES_HELD, "the window grew without limit");
    }

    #[tokio::test]
    async fn the_penalty_is_paid_by_the_refusal_path_and_is_configurable_for_tests() {
        // The penalty is what a locked gate costs a guesser now that it costs a
        // correct credential nothing. The seam exists so no test sleeps for
        // three quarters of a second to prove it.
        let gate = FailureGate::with_penalty(Duration::ZERO);
        let started = Instant::now();
        gate.penalise().await;
        assert!(started.elapsed() < Duration::from_millis(200), "the seam was ignored");
        assert_eq!(FailureGate::new().penalty, LOCKED_PENALTY, "production keeps the real cost");
    }

    #[test]
    fn a_session_reports_who_holds_it_and_how_they_logged_in() {
        let sessions = Sessions::new();
        let id = sessions.create("Mom", Opening::Passkey).expect("system entropy");
        let held = sessions.authenticated(&id).expect("a live session");
        assert_eq!(held.user, "Mom");
        assert_eq!(held.opened_by, Opening::Passkey, "a cookie must answer how, not only who");
        assert!(held.opened_at.elapsed() < Duration::from_secs(5), "the login moment is this one");
        assert_eq!(sessions.authenticated("0".repeat(64).as_str()), None);
        // And reading identity never refreshes the idle timer: that is
        // `validate`'s job, and a stream re-checking on a timer must not be able
        // to keep its own session alive.
        let expiring = Sessions::with_expiry(Duration::from_secs(3600), Duration::ZERO);
        let id = expiring.create("owner", Opening::Password).unwrap();
        assert_eq!(expiring.authenticated(&id), None, "an idle-expired session holds nobody");
    }
}
