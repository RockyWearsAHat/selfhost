//! Basic-over-TLS for WebDAV clients, and the verified-credential cache that
//! makes it usable.
//!
//! # Why Basic, and why not Digest
//!
//! WebDAV clients do not do cookie logins: Finder, the Windows Mini-Redirector
//! and every CLI client speak HTTP authentication or nothing. Digest is not
//! available to us — it requires the server to hold a reversible derivation of
//! the password, and the console credential is PBKDF2-SHA256, which is the whole
//! point of it. So Basic, over TLS, on a site that validation already forces to
//! carry a non-empty `allowed_cidrs`.
//!
//! That gate is not authentication and nothing here treats it as such. It is
//! loopback, which is where the Secure-VPN tunnel exits, and the same loopback
//! is shared by three co-hosted web applications whose bugs would issue
//! requests from inside it. Every `/dav` request authenticates.
//!
//! # The cache is mandatory, not an optimisation
//!
//! `ConsolePassword::verify` runs 600,000 PBKDF2 iterations — roughly 70 ms of
//! blocking CPU, deliberately. WebDAV re-authenticates on essentially every
//! request, so a 500-file copy from Finder is 500 verifications: about 35
//! seconds of a core spent proving the same password 500 times, during which
//! the daemon is not serving the console. Finder will do exactly that, on the
//! first mount, before anybody has copied anything.
//!
//! Six properties make the cache safe to have, and each of them is enforced
//! here rather than described:
//!
//! 1. **The plaintext is never stored.** [`Credentials`] holds an HMAC-SHA256
//!    fingerprint under a key drawn from the system random source at startup —
//!    so the table is useless to anything that reads it, and useless *between
//!    processes*, since the key dies with the process.
//! 2. **Bounded.** [`MAX_ENTRIES`] of them, evicting the least recently decided.
//!    An unbounded cache keyed on attacker-supplied credentials is a memory
//!    exhaustion primitive that needs no authentication at all to drive.
//! 3. **Short-lived.** [`ENTRY_TTL`], after which the password is proved again.
//! 4. **Compared in constant time**, by a comparison that does not
//!    short-circuit, so the fingerprint table cannot be walked one byte at a
//!    time.
//! 5. **Discardable on rotation, and today discarded by the process ending.**
//!    [`Credentials::invalidate`] empties the table at once. It is deliberately
//!    *not* called from anywhere in this deployment, and the reason is worth
//!    stating rather than leaving as an apparent omission: the console password
//!    is read from disk once, when the daemon builds its API, so
//!    `selfhost console-password` takes effect at the next restart — and a
//!    restart takes the whole table with it, along with the key that made its
//!    fingerprints mean anything. There is therefore no window in which this
//!    cache can answer for a password the running process no longer holds. The
//!    method exists for the day a rotation route lands in the daemon, which is
//!    the day this sentence has to change with it.
//! 6. **Bounded in the CPU it can be made to spend.** The table stops a
//!    *repeated* credential costing 70 ms twice, and [`Credentials::throttled`]
//!    stops one wrong credential costing it ten times. Neither bounds an
//!    attacker who simply never repeats himself: every distinct credential is a
//!    cache miss, and a cache miss is a PBKDF2 run. So the ceiling that actually
//!    holds is [`MAX_CONCURRENT_VERIFICATIONS`], which is per *process* and
//!    cannot be evicted, rate-limited around, or spread across user names — see
//!    [`Credentials::verification_slot`].
//! 7. **Never logged.** [`Presented`]'s `Debug` prints the user name and the
//!    word `<redacted>`; there is no `Display`, no field accessor for the
//!    password other than the one the verifier consumes, and nothing here
//!    formats one.
//!
//! # WebDAV 401s must never reach the console's failure gate
//!
//! `admin/src/session.rs:169-182` locks out *all* console logins after five
//! failures in sixty seconds. That gate is deliberately global and it is right
//! for a login form. It is catastrophic here: **every WebDAV client's first
//! request is unauthenticated by protocol design** — the client sends the
//! request, collects the `401` and the realm, and only then authenticates. So
//! mounting a single share would trip the gate and lock the operator out of the
//! console they would use to unmount it.
//!
//! WebDAV therefore gets [`Credentials::throttled`], a counter of its own, and
//! three things are true of it by construction: it is per-credential rather
//! than global, so one client's bad password cannot affect another's; it
//! refuses only the credential that failed, never a login; and it lives in this
//! crate, which `crates/admin`'s session code does not call. It is a brake on
//! PBKDF2 burn, not a lockout.
//!
//! And being per-credential, it is a brake an attacker steps around by changing
//! credentials: sixty-four wrong passwords evict each other's counters and none
//! of them is ever throttled. That is not a hole in the throttle, it is the
//! wrong tool being asked to hold a different rule, so the rule has its own tool
//! — [`MAX_CONCURRENT_VERIFICATIONS`], below, which is what actually bounds the
//! CPU an unauthenticated caller can make this process spend.
//!
//! # What this credential is allowed to do, which is not everything
//!
//! A successful check produces [`selfhost_identity::Caller::password`] —
//! `Credential::Password`, whose documentation in `crates/identity` says why it
//! counts as **unattended**: an operating system's keychain stores it at mount
//! time and replays it on every request for the life of the mount, with nobody
//! present. The policy therefore refuses it the capabilities that drive the
//! machine. That is not a rule this module implements; it is a rule this module
//! must not quietly route around by minting some other caller, which is why
//! [`authenticated`] returns the one constructor and takes no argument that
//! could change it.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_identity::Caller;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

/// How many verified-or-rejected credentials are remembered at once.
///
/// Sixty-four. A deployment has one console password and a handful of clients,
/// so the working set is one or two entries; the rest of the room is there so
/// that a client retrying with several spellings does not evict the entry that
/// is making the mount usable.
pub const MAX_ENTRIES: usize = 64;

/// How long a decision about a credential stands before it is made again.
///
/// One minute. Long enough that a 500-file Finder copy — which takes seconds —
/// costs one PBKDF2 verification rather than five hundred, and short enough
/// that a password removed from the box stops working while the operator is
/// still watching. Rotation does not wait for it: [`Credentials::invalidate`]
/// is immediate.
pub const ENTRY_TTL: Duration = Duration::from_secs(60);

/// How many failures against one credential are answered before it is refused
/// without being verified.
pub const MAX_FAILURES: u32 = 10;

/// How many cold PBKDF2 verifications this process will run at once.
///
/// # What goes wrong without it
///
/// Every check that stands between a stranger and 70 ms of CPU is keyed on the
/// credential: the cache is, and so is [`Credentials::throttled`]. A caller who
/// never presents the same credential twice therefore misses the cache every
/// time and is never throttled, and each of those misses becomes a
/// `spawn_blocking` task. Tokio's blocking pool is 512 threads by default and
/// nothing else bounds this, so a few hundred concurrent `/dav` requests — none
/// of them authenticated, none of them ever going to be — take every core the
/// box has *and* the pool that **every filesystem operation in this crate runs
/// on**. The share stops answering, the console stops answering, and the
/// requests that did it were all rejected.
///
/// The gate in front of that is a source address, not an identity, and on this
/// box "inside the gate" includes three co-hosted web applications: a bug in any
/// one of them is a request from inside it. So the ceiling is not a hypothetical.
///
/// # Why two, and why a queue rather than a refusal
///
/// A deployment has **one** console password, so the honest working set is one
/// verification at a time; the second slot is there so a second client, or an
/// operator retyping while a mount is connecting, is not waiting behind a
/// stranger.
///
/// Callers past the ceiling **wait** rather than being refused, and that is the
/// load-bearing half of the choice. A refusal here would be a `401`, and this
/// module's whole reason for existing is that macOS and Windows read a second
/// `401` as *the password you stored is wrong* and throw the keychain item away
/// — so a burst of traffic from anywhere on the box would unmount the
/// operator's drive. Waiting costs latency under attack, which is latency that
/// already existed when 512 verifications were fighting for four cores, and it
/// leaves the blocking pool free for the work that is actually serving somebody.
///
/// The queue is also why a burst of *legitimate* traffic now costs one
/// verification rather than one each: Finder opening a mount issues its requests
/// in parallel, every one of them missed the cache before the first had
/// finished, and [`Credentials::verification_slot`]'s call site asks the cache
/// again once it holds a slot.
pub const MAX_CONCURRENT_VERIFICATIONS: usize = 2;

/// The window failures are counted in.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// The realm a `401` advertises.
///
/// Clients show it in their password prompt, and Finder uses it as the label of
/// the keychain item it stores — so it names the box rather than the protocol.
pub const REALM: &str = "selfhost console";

/// A credential a client presented on this request.
///
/// Holds the plaintext, briefly, because verifying a password needs the
/// password. Everything about the type is arranged so that it goes no further:
/// its `Debug` redacts, it has no `Display`, it is not `Clone`, and the only
/// way to read the secret is [`Presented::password`], which exists for the one
/// caller that hands it to the PBKDF2 verifier.
pub struct Presented {
    /// The login name. Not secret, and worth logging: an operator diagnosing a
    /// mount needs to know which account a client tried.
    user: String,
    /// The password. Never logged, never compared here.
    password: String,
}

impl Presented {
    /// The login name, which may be logged.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The secret, for the verifier and for nothing else.
    ///
    /// Named as a plain accessor rather than hidden behind a callback because
    /// hiding it would be theatre — the caller has the value either way — and
    /// because the honest arrangement is one obvious place a reviewer can grep
    /// for. What matters is that this is the only one.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Presented {
    /// Prints the user and redacts the secret.
    ///
    /// `admin/src/token.rs:82-86` is the precedent, and the reason is the same:
    /// a type whose `Debug` prints a credential will eventually be printed. A
    /// derived `Debug` here would put the console password in the first panic
    /// message or `dbg!` anybody writes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presented").field("user", &self.user).field("password", &"<redacted>").finish()
    }
}

/// Reads an `Authorization: Basic …` header.
///
/// `None` for an absent header, a scheme that is not Basic, base64 that does not
/// decode, bytes that are not UTF-8, and a payload with no colon — all of which
/// are the same answer on the wire (`401` with a challenge), because telling a
/// client *how* its credential was malformed tells a prober how to build a
/// better one.
///
/// The split is on the **first** colon, which RFC 7617 requires: a password may
/// contain colons and a user name may not.
pub fn parse_basic(header: Option<&str>) -> Option<Presented> {
    let value = header?.trim();
    let (scheme, payload) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = decode_base64(payload.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    Some(Presented { user: user.to_string(), password: password.to_string() })
}

/// What a cache lookup found.
///
/// A three-valued answer rather than an `Option<bool>` so a call site cannot
/// read "not cached" as "not verified" — the difference is a PBKDF2 verification
/// that must happen versus a `401` that must be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cached {
    /// This exact credential was verified recently. Let it through.
    Verified,
    /// This exact credential was rejected recently. Refuse it without spending
    /// 70 ms proving the same thing again.
    Rejected,
    /// Nothing is known about it. Verify it, then [`Credentials::remember`].
    Unknown,
}

/// The verified-credential cache, and the per-credential failure counter.
///
/// One per daemon, shared. Everything it stores is a fingerprint under a
/// process-lifetime HMAC key; see this module's documentation for the six
/// properties that make it safe and for why the failure counter here can never
/// reach the console's login gate.
///
/// # Poisoning
///
/// The lock guards a `Vec` of plain values and is never held across a call that
/// can panic, so a poisoned lock means another thread died with the table
/// intact. Recovering is right; propagating would turn one unrelated panic into
/// a `/dav` endpoint that answers nothing for the life of the process.
#[derive(Debug)]
pub struct Credentials {
    /// The keyed-hash key, drawn once at startup and never persisted.
    key: hmac::Key,
    /// The decisions, most recently decided last.
    entries: Mutex<Vec<Entry>>,
    /// Permission to run a cold verification, [`MAX_CONCURRENT_VERIFICATIONS`]
    /// at a time.
    ///
    /// Held here rather than in the route because it is a property of the thing
    /// being protected — the one password every `/dav` request is checked
    /// against — and a ceiling owned by a call site is a ceiling the second call
    /// site does not have.
    slots: Semaphore,
}

/// One remembered credential.
#[derive(Debug)]
struct Entry {
    /// HMAC-SHA256 of the presented credential under the process key.
    fingerprint: [u8; FINGERPRINT_BYTES],
    /// Whether it verified.
    verified: bool,
    /// When that was decided, for the TTL and for eviction order.
    decided_at: Instant,
    /// Consecutive failures inside the current window.
    failures: u32,
    /// When the current failure window started.
    window_started: Instant,
}

/// The width of an HMAC-SHA256 tag.
const FINGERPRINT_BYTES: usize = 32;

impl Credentials {
    /// A cache with a fresh key.
    ///
    /// # Errors
    ///
    /// Fails only if the system random source refuses, which is a box with no
    /// entropy — and a cache keyed on a constant would be a table an attacker
    /// who read the process's memory could build offline. Failing here rather
    /// than falling back is the point: a `/dav` endpoint that will not start is
    /// better than one whose fingerprints are guessable.
    pub fn new() -> Result<Self, KeyUnavailable> {
        let mut secret = [0u8; FINGERPRINT_BYTES];
        SystemRandom::new().fill(&mut secret).map_err(|_| KeyUnavailable)?;
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &secret),
            entries: Mutex::new(Vec::new()),
            slots: Semaphore::new(MAX_CONCURRENT_VERIFICATIONS),
        })
    }

    /// Waits for permission to run one cold PBKDF2 verification.
    ///
    /// The ceiling [`MAX_CONCURRENT_VERIFICATIONS`] describes, and the whole of
    /// its enforcement. The permit is released when the returned value is
    /// dropped, so a caller holds it for exactly as long as it is verifying and
    /// a caller that returns early — by finding the answer in the cache, or by
    /// failing — releases it on the way out without having to remember to.
    ///
    /// The queue is fair, so a request that arrives while a flood is in progress
    /// is served after the requests already waiting rather than being starved
    /// behind an endless stream of new ones.
    ///
    /// `None` is returned only if the semaphore has been closed, which nothing
    /// in this crate does. It is written as an `Option` rather than an `expect`
    /// because the workspace builds with `panic = "abort"`, where an `expect` on
    /// an unreachable branch is the whole box rather than one failed request —
    /// and because the safe reading of "the ceiling is gone" is to verify
    /// anyway, which is what this deployment did before the ceiling existed. It
    /// must never become a refusal: a refusal on this path is a `401`, and a
    /// second `401` is how a mounted drive loses its stored credential.
    pub async fn verification_slot(&self) -> Option<SemaphorePermit<'_>> {
        self.slots.acquire().await.ok()
    }

    /// What is known about this credential.
    ///
    /// Cheap: one HMAC and a scan of at most [`MAX_ENTRIES`] constant-time
    /// comparisons. This is the call that runs on every one of Finder's 500
    /// requests.
    pub fn look_up(&self, presented: &Presented) -> Cached {
        let fingerprint = self.fingerprint(presented);
        let mut entries = self.lock();
        let now = Instant::now();
        entries.retain(|entry| entry.is_live(now));
        match find(&entries, &fingerprint) {
            Some(index) => {
                if entries[index].verified {
                    Cached::Verified
                } else {
                    Cached::Rejected
                }
            }
            None => Cached::Unknown,
        }
    }

    /// Whether this credential has failed too often to be worth verifying.
    ///
    /// The brake on PBKDF2 burn. It refuses **only this credential**, it never
    /// touches a console login, and it clears on its own after
    /// [`FAILURE_WINDOW`] — so an operator who mistyped a password once is not
    /// waiting on anything, and a client looping on a stale keychain entry is
    /// not costing a core.
    pub fn throttled(&self, presented: &Presented) -> bool {
        let fingerprint = self.fingerprint(presented);
        let entries = self.lock();
        let now = Instant::now();
        find(&entries, &fingerprint).is_some_and(|index| {
            let entry = &entries[index];
            entry.failures >= MAX_FAILURES
                && now.saturating_duration_since(entry.window_started) < FAILURE_WINDOW
        })
    }

    /// Records the outcome of a cold verification.
    ///
    /// A success clears the failure count — the credential is right, so
    /// whatever came before it was somebody typing. A failure extends the count
    /// inside the window and starts a new window once the old one has passed.
    pub fn remember(&self, presented: &Presented, verified: bool) {
        let fingerprint = self.fingerprint(presented);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| entry.is_live(now));

        if let Some(index) = find(&entries, &fingerprint) {
            let entry = &mut entries[index];
            entry.verified = verified;
            entry.decided_at = now;
            if verified {
                entry.failures = 0;
                entry.window_started = now;
            } else if now.saturating_duration_since(entry.window_started) >= FAILURE_WINDOW {
                entry.failures = 1;
                entry.window_started = now;
            } else {
                entry.failures = entry.failures.saturating_add(1);
            }
            return;
        }

        // Room is made by dropping the least recently decided entry, which is
        // the one whose absence costs the least: a client that is actively
        // mounting refreshes its entry on every request.
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = oldest_index(&entries) {
                entries.remove(oldest);
            }
        }
        entries.push(Entry {
            fingerprint,
            verified,
            decided_at: now,
            failures: u32::from(!verified),
            window_started: now,
        });
    }

    /// Forgets everything, immediately.
    ///
    /// For a rotation that happens **while this process is running**, so that a
    /// password just changed cannot keep opening shares for up to [`ENTRY_TTL`]
    /// — the minute after a rotation being exactly the minute the old password
    /// was rotated away from.
    ///
    /// No such rotation exists in this deployment yet: the console password is
    /// read from disk once, when the daemon builds its API, so
    /// `selfhost console-password` takes effect at the next restart and the
    /// restart discards this table wholesale. This is therefore called by
    /// nothing but its own test, deliberately and not by oversight — it is the
    /// half of the rule that will be needed the day a rotation route lands, and
    /// writing it then rather than now would mean writing it in the same change
    /// that first makes it necessary. See property 5 in this module's
    /// documentation.
    ///
    /// Failure counts go with it, deliberately: an operator who has just fixed
    /// their password must not be told to wait.
    pub fn invalidate(&self) {
        self.lock().clear();
    }

    /// How many decisions are being held, for a test or a status plate.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The keyed fingerprint of a credential.
    ///
    /// User and password are joined by a NUL, which neither can contain: a
    /// separator that could appear in either half would let `alice` with
    /// password `x:y` and `alice:x` with password `y` share a cache entry.
    fn fingerprint(&self, presented: &Presented) -> [u8; FINGERPRINT_BYTES] {
        let mut message = Vec::with_capacity(presented.user.len() + presented.password.len() + 1);
        message.extend_from_slice(presented.user.as_bytes());
        message.push(0);
        message.extend_from_slice(presented.password.as_bytes());
        let tag = hmac::sign(&self.key, &message);
        let mut fingerprint = [0u8; FINGERPRINT_BYTES];
        // The tag of HMAC-SHA256 is exactly 32 bytes; copying the overlap
        // rather than asserting it keeps a wrong algorithm from becoming a
        // panic, which under `panic = "abort"` is the whole box.
        let bytes = tag.as_ref();
        let width = bytes.len().min(FINGERPRINT_BYTES);
        fingerprint[..width].copy_from_slice(&bytes[..width]);
        fingerprint
    }

    /// The table, with a poisoned lock recovered rather than propagated.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Entry {
    /// Whether this decision is still worth keeping.
    ///
    /// An entry outlives its decision when it is still counting failures: the
    /// throttle would be trivially defeated if a wrong password's record
    /// expired a second after it was made.
    fn is_live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.decided_at) < ENTRY_TTL
            || (self.failures > 0
                && now.saturating_duration_since(self.window_started) < FAILURE_WINDOW)
    }
}

/// The index of the entry matching a fingerprint, compared in constant time.
///
/// The comparison does not short-circuit, so the time a lookup takes does not
/// describe how much of a fingerprint was right. That matters less here than
/// for a token — a fingerprint is not a credential — but the rule this project
/// follows is that secret-derived material is compared one way, everywhere, so
/// nobody has to decide per call site which comparison is the safe one.
fn find(entries: &[Entry], fingerprint: &[u8; FINGERPRINT_BYTES]) -> Option<usize> {
    entries.iter().position(|entry| constant_time_eq(&entry.fingerprint, fingerprint))
}

/// Whether two byte strings are equal, without short-circuiting.
///
/// A mirror of `admin/src/token.rs:97`, which is `pub(crate)` there — and this
/// crate must not depend on the admin API to compare two arrays. `ring`'s own
/// `constant_time` module is deprecated with an explicit warning that it makes
/// no promises about side channels, so it is not the answer either. Six lines,
/// with the length check first because the length of a fingerprint is public.
fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(actual) {
        difference |= a ^ b;
    }
    difference == 0
}

/// The index of the least recently decided entry.
fn oldest_index(entries: &[Entry]) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .min_by_key(|(_, entry)| entry.decided_at)
        .map(|(index, _)| index)
}

/// The caller a successful WebDAV authentication produces.
///
/// One constructor, no arguments, no choice. `crates/identity` documents
/// `Credential::Password` as **unattended** — a keychain replays it on every
/// request for the life of a mount with nobody present — and the policy refuses
/// it the capabilities that drive the machine on exactly that ground. A
/// function here that could produce some other caller would be a way to
/// mount a share and end up holding a keyboard.
pub fn authenticated() -> Caller {
    Caller::password()
}

/// The `WWW-Authenticate` challenge value a `401` carries.
///
/// `charset="UTF-8"` is RFC 7617's one parameter and it is not decoration:
/// without it a client is entitled to send a password in ISO-8859-1, and a
/// password with a non-ASCII character would then hash to something that never
/// matches what the operator set.
pub fn challenge() -> String {
    format!("Basic realm=\"{REALM}\", charset=\"UTF-8\"")
}

/// The system random source refused to seed the cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUnavailable;

impl fmt::Display for KeyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system random source was unavailable, so no credential cache key exists")
    }
}

impl std::error::Error for KeyUnavailable {}

/// Decodes padded or unpadded standard base64.
///
/// Written here rather than imported because `crates/admin`'s copy is private
/// to that crate and this crate must not depend on it — a NAS that pulled in the
/// admin API to read one header would be a dependency edge in the wrong
/// direction. Roughly twenty lines against a crate, which is the same trade
/// `admin/src/passwd.rs` records for mirroring the password format.
///
/// Strict about the alphabet and about a truncated final group: a decoder that
/// accepted anything would let two spellings of one credential produce two
/// cache entries, and a permissive decoder is how a `401` becomes a `500`.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for character in text.chars() {
        if character == '=' {
            break;
        }
        let value = match character {
            'A'..='Z' => character as u32 - 'A' as u32,
            'a'..='z' => character as u32 - 'a' as u32 + 26,
            '0'..='9' => character as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accumulator >> bits) & 0xff).ok()?;
            out.push(byte);
        }
    }
    // Leftover bits must be zero padding; anything else is a truncated group,
    // which means the credential was mangled and must not be guessed at.
    if accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::{Credential, Identity};

    fn credentials() -> Credentials {
        Credentials::new().expect("a random source")
    }

    fn presented(user: &str, password: &str) -> Presented {
        Presented { user: user.to_string(), password: password.to_string() }
    }

    #[test]
    fn a_basic_header_is_read_and_everything_else_is_the_same_refusal() {
        // `alice:secret:with:colons`, base64.
        let header = "Basic YWxpY2U6c2VjcmV0OndpdGg6Y29sb25z";
        let parsed = parse_basic(Some(header)).expect("a legal header");
        assert_eq!(parsed.user(), "alice");
        assert_eq!(parsed.password(), "secret:with:colons", "only the first colon splits");

        // The scheme is case-insensitive, as RFC 9110 requires.
        assert!(parse_basic(Some("basic YWxpY2U6eA==")).is_some());
        assert!(parse_basic(Some("BASIC YWxpY2U6eA==")).is_some());

        for hostile in [
            "",
            "Basic",
            "Bearer YWxpY2U6eA==",
            "Basic !!!!",
            "Basic YWxpY2U",   // no colon in the payload
            "Basic ///",       // truncated group
        ] {
            assert!(parse_basic(Some(hostile)).is_none(), "{hostile}");
        }
        assert!(parse_basic(None).is_none());
    }

    /// The one property that must never regress: no formatting of this type
    /// puts the secret anywhere.
    #[test]
    fn a_presented_credential_never_prints_its_secret() {
        let rendered = format!("{:?}", presented("alice", "hunter2"));
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("hunter2"));
    }

    /// The 500-file Finder copy, in miniature: one cold verification, and every
    /// request after it answered from the table.
    #[test]
    fn a_verified_credential_is_remembered_and_a_wrong_one_is_too() {
        let cache = credentials();
        let right = presented("owner", "correct horse");
        let wrong = presented("owner", "battery staple");

        assert_eq!(cache.look_up(&right), Cached::Unknown);
        cache.remember(&right, true);
        assert_eq!(cache.look_up(&right), Cached::Verified);

        // A different password is a different credential, not a hit.
        assert_eq!(cache.look_up(&wrong), Cached::Unknown);
        cache.remember(&wrong, false);
        assert_eq!(cache.look_up(&wrong), Cached::Rejected);
        assert_eq!(cache.look_up(&right), Cached::Verified);

        // And a different user with the same password is a different credential
        // too, which the NUL separator is what guarantees.
        assert_eq!(cache.look_up(&presented("intruder", "correct horse")), Cached::Unknown);
    }

    #[test]
    fn a_rotated_password_stops_working_at_once_rather_than_in_a_minute() {
        let cache = credentials();
        let old = presented("owner", "old");
        cache.remember(&old, true);
        assert_eq!(cache.look_up(&old), Cached::Verified);

        cache.invalidate();
        assert!(cache.is_empty());
        assert_eq!(cache.look_up(&old), Cached::Unknown, "the next request pays for a verify");
    }

    /// An unbounded table keyed on attacker-supplied credentials is a memory
    /// exhaustion primitive that needs no authentication to drive.
    #[test]
    fn the_table_is_bounded_however_many_credentials_are_thrown_at_it() {
        let cache = credentials();
        for attempt in 0..(MAX_ENTRIES * 4) {
            cache.remember(&presented("owner", &format!("guess-{attempt}")), false);
            assert!(cache.len() <= MAX_ENTRIES);
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
    }

    /// The brake, and the two things it must never do: apply to anybody else,
    /// or outlast its window.
    #[test]
    fn repeated_failures_throttle_that_credential_and_nothing_else() {
        let cache = credentials();
        let wrong = presented("owner", "wrong");
        let right = presented("owner", "right");
        cache.remember(&right, true);

        for _ in 0..MAX_FAILURES {
            assert!(!cache.throttled(&wrong));
            cache.remember(&wrong, false);
        }
        assert!(cache.throttled(&wrong));

        // The credential that works is untouched — which is the whole reason
        // this counter exists instead of the console's global gate.
        assert!(!cache.throttled(&right));
        assert_eq!(cache.look_up(&right), Cached::Verified);

        // And a success clears the count, so an operator who mistyped is not
        // left waiting once they type it correctly.
        cache.remember(&wrong, true);
        assert!(!cache.throttled(&wrong));
    }

    /// A failure record outlives the ordinary entry TTL, or the throttle would
    /// be defeated by waiting a minute between guesses — which is no wait at
    /// all for a machine.
    #[test]
    fn a_failure_record_is_kept_for_its_own_window_not_the_entry_ttl() {
        let now = Instant::now();
        let long_ago = now.checked_sub(ENTRY_TTL * 2).expect("a clock with two minutes on it");
        let recent = now.checked_sub(Duration::from_secs(1)).expect("a clock with a second on it");

        let stale_success = Entry {
            fingerprint: [1; FINGERPRINT_BYTES],
            verified: true,
            decided_at: long_ago,
            failures: 0,
            window_started: long_ago,
        };
        assert!(!stale_success.is_live(now), "an old success is simply proved again");

        let counting = Entry {
            fingerprint: [2; FINGERPRINT_BYTES],
            verified: false,
            decided_at: long_ago,
            failures: MAX_FAILURES,
            window_started: recent,
        };
        assert!(counting.is_live(now), "a live failure window keeps its record");
    }

    /// The caller a mount produces is the unattended one, and the policy is
    /// what refuses it a keyboard — this test is here so that a future edit
    /// which "helpfully" upgraded the caller fails loudly.
    #[test]
    fn a_webdav_mount_authenticates_as_the_unattended_password_caller() {
        let caller = authenticated();
        assert_eq!(caller.credential(), Credential::Password);
        assert_eq!(caller.identity(), &Identity::Owner);
        assert!(caller.credential().is_deployment_wide());
    }

    /// The hole the per-credential throttle cannot close: a caller who never
    /// presents the same credential twice misses the cache every time and is
    /// never throttled, so nothing keyed on the credential bounds what he
    /// spends. This asserts that the ceiling which is *not* keyed on his choices
    /// holds regardless.
    #[tokio::test]
    async fn a_caller_who_never_repeats_a_credential_still_cannot_run_more_than_the_ceiling() {
        let cache = credentials();
        let mut held = Vec::new();
        for attempt in 0..MAX_CONCURRENT_VERIFICATIONS {
            // Every one of these is a distinct credential: a cache miss, and
            // never throttled, exactly as an attacker would arrange.
            assert_eq!(cache.look_up(&presented("owner", &format!("miss-{attempt}"))), Cached::Unknown);
            assert!(!cache.throttled(&presented("owner", &format!("miss-{attempt}"))));
            held.push(cache.verification_slot().await.expect("the ceiling is open"));
        }
        assert_eq!(held.len(), MAX_CONCURRENT_VERIFICATIONS);

        // The next one waits. `timeout` is how "waits" is asserted without a
        // test that hangs when the ceiling is removed.
        let refused_for_now = tokio::time::timeout(
            Duration::from_millis(50),
            cache.verification_slot(),
        )
        .await;
        assert!(refused_for_now.is_err(), "a verification past the ceiling ran anyway");

        // And it is a queue, not a lockout: a slot released lets the next one
        // through, so a burst costs latency rather than a `401` — which on this
        // path would take the operator's mounted drive with it.
        held.pop();
        let next = tokio::time::timeout(Duration::from_secs(1), cache.verification_slot()).await;
        assert!(next.expect("the queue drains").is_some());
    }

    #[test]
    fn the_challenge_names_the_box_and_pins_the_encoding() {
        let challenge = challenge();
        assert!(challenge.starts_with("Basic realm="));
        assert!(challenge.contains(REALM));
        assert!(challenge.contains("charset=\"UTF-8\""));
    }

    #[test]
    fn base64_decodes_what_it_should_and_refuses_what_it_should_not() {
        assert_eq!(decode_base64("YWJj").as_deref(), Some(b"abc".as_slice()));
        assert_eq!(decode_base64("YWI=").as_deref(), Some(b"ab".as_slice()));
        assert_eq!(decode_base64("YWI").as_deref(), Some(b"ab".as_slice()), "padding is optional");
        assert_eq!(decode_base64("").as_deref(), Some(b"".as_slice()));
        for bad in ["YW-j", "YW_j", "YW j", "!"] {
            assert!(decode_base64(bad).is_none(), "{bad}");
        }
    }
}
