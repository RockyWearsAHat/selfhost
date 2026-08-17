//! `LOCK` and `UNLOCK`, and the exclusion they actually perform.
//!
//! # Which clients demand this, and which merely like it
//!
//! Both of the two clients this deployment has to satisfy demand it, for the
//! same reason and at the same moment:
//!
//! - **The Windows Mini-Redirector** reads the `DAV` header from `OPTIONS` and
//!   mounts the share **read-only** unless it sees class `2`. Having mounted
//!   read-write, it takes a `LOCK` before every `PUT` and releases it after.
//! - **macOS WebDAVFS** (what Finder uses for `davs://`) does the same: no
//!   class 2, no writable mount. It locks a file for the duration of an edit,
//!   which is what makes "open the document, save it, close it" safe against a
//!   second machine having the same share mounted.
//!
//! Linux `davfs2`, `rclone` and `curl` do not care. So the rule is: **the two
//! clients that would make this NAS feel like a disk are exactly the two that
//! will not write to it without locking.** That is why `LOCK` is not optional
//! and why [`crate::dav::method::IMPLEMENTED`] carries it rather than the `DAV`
//! header carrying a claim.
//!
//! # Why a fake lock would be worse than a `501`
//!
//! The tempting shortcut is a `LOCK` that mints a token, remembers nothing, and
//! answers `200`. Every client would mount, every copy would work, and the
//! implementation would be twenty lines. It is worse than refusing, and the
//! difference is not tidiness:
//!
//! - A client that holds a lock **believes it has exclusive access**, and acts
//!   on that belief. Finder keeps an open document's buffer and writes it back
//!   whole; Word writes a whole file at a time. Two machines editing one
//!   document under two fake locks do not merge — the second write silently
//!   destroys the first, which is the exact class of loss the exclusive create
//!   in [`crate::fs`] exists to prevent from the other direction.
//! - A `501` is a client that *cannot* do the thing and knows it. Silent data
//!   loss is a client that did the thing and reported success.
//!
//! So the locks here are real: [`Locks::guard`] refuses a write to a locked
//! resource whose token was not submitted, and it refuses it with `423`.
//!
//! # What is implemented, and what is refused honestly
//!
//! - **Exclusive write locks.** RFC 4918 §6.2 permits a server to offer only
//!   these, and shared locks are what nobody asks for: neither Finder nor the
//!   Mini-Redirector requests one. A request for one is a plain `403` rather
//!   than a shared lock pretending to be exclusive.
//! - **Depth 0 and depth infinity**, because a client locking a collection
//!   before a recursive copy asks for infinity.
//! - **A timeout, always.** RFC 4918 allows `Infinite`; this server does not
//!   grant it, and caps every lock at [`MAX_LOCK_SECONDS`]. A lock with no
//!   expiry on a box that self-updates unattended is a file nobody can write to
//!   again until somebody notices, and the client that took it may have been a
//!   laptop that closed its lid. Clients refresh, and a capped `Timeout` in the
//!   response is how they are told to.
//! - **No lock persistence across restarts.** A daemon restart releases every
//!   lock. That is honest and it is also what the alternative would cost: a
//!   lock file surviving a crash is a share nobody can write to after one.
//!
//! # The `If` header is parsed as a subset, deliberately
//!
//! RFC 4918 §10.4's grammar carries tagged lists, `Not`, entity tags and
//! parenthesised conditions. [`submitted_tokens`] reads out the **coded-URLs**
//! and nothing else, because that is the only part this server acts on, and a
//! full evaluator would be a second parser fed by strangers in a process where
//! a parser that panics is a whole-box outage. What the subset does with the
//! parts it does not evaluate is stated where it is done, and it is always the
//! conservative direction: a token inside a `Not` clause is **not** counted as
//! submitted, so a client that says "provided nobody holds this lock" is never
//! read as "I hold this lock".

use crate::dav::multistatus::{error_body, escape, or_internal_error, Href, Mount, XML_TYPE};
use crate::path::RelativePath;
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_http::{Response, Status};
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The longest a lock is granted for, however long the client asked.
///
/// One hour. Long enough that an ordinary edit never has to refresh, short
/// enough that a laptop that closed its lid mid-save does not leave a file
/// unwritable for a working day.
pub const MAX_LOCK_SECONDS: u64 = 3600;

/// What a lock is granted for when the client expresses no preference.
pub const DEFAULT_LOCK_SECONDS: u64 = 600;

/// The most locks held at once, across every share.
///
/// A ceiling rather than a limit anybody will meet: a client holds one lock per
/// file it is writing, and the concurrency ceiling in [`crate::quota`] already
/// bounds how many of those there can be. It exists because `LOCK` is a verb an
/// authenticated caller can issue in a loop, and an unbounded table is a memory
/// exhaustion primitive with a `423` for a symptom.
pub const MAX_LOCKS: usize = 256;

/// The status a locked resource answers with.
///
/// Spelled here for the reason [`crate::dav::multistatus::MULTI_STATUS`] is
/// spelled there: `selfhost_http::Status` covers the codes the proxy and the
/// console use, and `423` belongs to WebDAV alone.
pub const LOCKED: Status = Status(423);

/// How far below a resource a lock reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// This resource alone.
    Zero,
    /// This resource and everything beneath it.
    Infinity,
}

impl Reach {
    /// Reads a `Depth` header for a `LOCK`.
    ///
    /// RFC 4918 §9.10.3: only `0` and `infinity` are legal on a `LOCK`, and an
    /// absent header means infinity. `1` is not a lock depth and is refused
    /// rather than rounded to one of the two — a client that asked to lock "one
    /// level" and got a whole subtree locked would be surprised in the
    /// expensive direction.
    pub fn parse(header: Option<&str>) -> Option<Self> {
        match header.map(str::trim) {
            None => Some(Self::Infinity),
            Some("0") => Some(Self::Zero),
            Some(other) if other.eq_ignore_ascii_case("infinity") => Some(Self::Infinity),
            Some(_) => None,
        }
    }

    /// The spelling that goes in a `lockdiscovery` body.
    pub fn token(self) -> &'static str {
        match self {
            Self::Zero => "0",
            Self::Infinity => "infinity",
        }
    }
}

/// What resource a lock is about.
///
/// The share id is part of the key because two shares may hold the same
/// relative path, and a lock on `vault:/report.pdf` must not silence a write to
/// `photos:/report.pdf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// The share's id.
    pub share: String,
    /// The path inside it, already validated.
    pub path: RelativePath,
}

impl Resource {
    /// The resource at a path in a share.
    pub fn new(share: &str, path: RelativePath) -> Self {
        Self { share: share.to_string(), path }
    }

    /// Whether `other` is this resource or lies beneath it.
    ///
    /// Segment-wise rather than by string prefix, which is the difference
    /// between `photos` containing `photos-private` and not: a textual
    /// `starts_with` on `"photos"` matches `"photos-private/secret.txt"` and
    /// would let a lock on one directory silence writes to a sibling.
    pub fn contains(&self, other: &Self) -> bool {
        if self.share != other.share {
            return false;
        }
        let mine = self.path.segments();
        let theirs = other.path.segments();
        theirs.len() >= mine.len() && theirs.iter().zip(mine).all(|(a, b)| a == b)
    }
}

/// A lock token, as it appears in `Lock-Token` and `If` headers.
///
/// A `urn:uuid:` URI holding 128 random bits. It is a **capability**: whoever
/// can produce it may write through the lock, so it is generated from the
/// system random source rather than from a counter or a clock. There is no
/// constructor from a string, so a token in this program is either one this
/// server minted or one a client submitted as text — never the two confused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// A fresh token.
    ///
    /// # Errors
    ///
    /// Only if the system random source refuses, which is answered `500` rather
    /// than falling back to something predictable: a guessable lock token is a
    /// lock a second client can steal, which is the failure locking exists to
    /// prevent.
    pub fn mint() -> Result<Self, RandomUnavailable> {
        let mut bytes = [0u8; 16];
        SystemRandom::new().fill(&mut bytes).map_err(|_| RandomUnavailable)?;
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            // `{:02x}` cannot fail on a `u8` and cannot produce a character
            // that needs escaping in a URI.
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(Self(format!(
            "urn:uuid:{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )))
    }

    /// The token as it appears on the wire, without the angle brackets.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a token a client submitted is this one.
    ///
    /// Compared as text without short-circuiting, because a lock token is a
    /// capability and this project compares secret-derived material one way
    /// everywhere.
    pub fn matches(&self, presented: &str) -> bool {
        let expected = self.0.as_bytes();
        let actual = presented.as_bytes();
        if expected.len() != actual.len() {
            return false;
        }
        let mut difference = 0u8;
        for (a, b) in expected.iter().zip(actual) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The system random source refused to mint a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomUnavailable;

impl fmt::Display for RandomUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system random source was unavailable, so no lock token could be minted")
    }
}

impl std::error::Error for RandomUnavailable {}

/// A lock this server is holding.
///
/// Compared by value so that [`crate::dav::propfind::Resource`] — which carries
/// the locks it will report — stays comparable in a test. The expiry is an
/// [`Instant`] and takes part in that comparison, which is right: two locks
/// that differ only in when they run out are two different locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// The capability that opens it.
    pub token: Token,
    /// What it covers.
    pub resource: Resource,
    /// How far below the resource it reaches.
    pub reach: Reach,
    /// The `<D:owner>` the client sent, as text and already bounded.
    pub owner: Option<String>,
    /// How long it was granted for, in seconds, after the cap.
    pub seconds: u64,
    /// When it stops being honoured.
    expires_at: Instant,
}

impl Lock {
    /// Whether this lock is still in force at `now`.
    pub fn is_live(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// What a `LOCK` request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    /// Whether the client asked for an exclusive lock. A shared request is
    /// refused rather than quietly upgraded.
    pub exclusive: bool,
    /// Whether the client asked for a write lock; nothing else exists in
    /// RFC 4918, and a body naming something else is refused.
    pub write: bool,
    /// The `<D:owner>` element's text, bounded and stripped of markup.
    pub owner: Option<String>,
}

/// Why a `LOCK` body could not be read.
///
/// Typed for the same reason [`crate::dav::propfind::BodyError`] is: three of
/// these are a `400` with quite different causes, and the document-type
/// declaration is worth logging as an attempt rather than as a client bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// Longer than [`MAX_BODY_BYTES`].
    TooLarge,
    /// Not valid UTF-8.
    NotUtf8,
    /// Not a `lockinfo` document.
    Malformed,
    /// A document type declaration, which is refused rather than ignored — see
    /// [`crate::dav::propfind`] for the entity-expansion argument.
    ProhibitedDoctype,
    /// A lock scope or type this server does not offer.
    Unsupported,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::TooLarge => "the request body is too large",
            Self::NotUtf8 => "the request body is not valid UTF-8",
            Self::Malformed => "the request body is not a lockinfo document",
            Self::ProhibitedDoctype => "a document type declaration is not accepted here",
            Self::Unsupported => "this server grants exclusive write locks only",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for BodyError {}

/// The largest `LOCK` body that will be read.
///
/// Sixteen kilobytes. A `lockinfo` document is four elements and an owner
/// string; anything larger is a client with a bug or a caller with a plan.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The longest `<D:owner>` text kept.
///
/// It is echoed back in every `lockdiscovery` body, so an unbounded one is a
/// response amplifier: a caller could store a megabyte and have it returned on
/// every `PROPFIND` of the directory.
pub const MAX_OWNER_CHARS: usize = 256;

/// Reads a `LOCK` body.
///
/// An empty body is `None`, which is RFC 4918's **refresh** request: the client
/// is asking to extend a lock it already holds and names in its `If` header. A
/// caller that treated `None` as "take a new lock" would mint a second lock on
/// a resource the first one already covers, and then refuse the client's own
/// writes with `423`.
pub fn parse_lockinfo(body: &[u8]) -> Result<Option<LockInfo>, BodyError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(BodyError::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| BodyError::NotUtf8)?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    // The same refusal `propfind` makes, and for the same reason: an entity
    // expansion costs the whole process rather than one request.
    if contains_doctype(text) {
        return Err(BodyError::ProhibitedDoctype);
    }

    let mut exclusive = false;
    let mut shared = false;
    let mut write = false;
    let mut lockinfo = false;
    let mut owner = None;

    let mut rest = text;
    while let Some(open) = rest.find('<') {
        let Some(after) = rest.get(open + 1..) else {
            break;
        };
        let Some(close) = after.find('>') else {
            return Err(BodyError::Malformed);
        };
        let Some(tag) = after.get(..close) else {
            return Err(BodyError::Malformed);
        };
        match local_name(tag) {
            Some("lockinfo") => lockinfo = true,
            Some("exclusive") => exclusive = true,
            Some("shared") => shared = true,
            Some("write") => write = true,
            Some("owner") if !tag.starts_with('/') => {
                let body_start = open + 1 + close + 1;
                owner = rest.get(body_start..).map(owner_text);
            }
            _ => {}
        }
        rest = after.get(close + 1..).unwrap_or_default();
    }

    if !lockinfo {
        return Err(BodyError::Malformed);
    }
    if shared || !exclusive || !write {
        return Err(BodyError::Unsupported);
    }
    Ok(Some(LockInfo { exclusive, write, owner }))
}

/// Whether a document carries a `<!DOCTYPE` declaration, in any casing.
fn contains_doctype(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("<!doctype") || lowered.contains("<!entity")
}

/// The local name of an element from its tag text, without the namespace prefix
/// and without attributes.
///
/// `None` for a comment, a processing instruction or a declaration, which are
/// skipped rather than parsed: none of them can carry the four element names
/// this reader is looking for.
fn local_name(tag: &str) -> Option<&str> {
    let tag = tag.strip_prefix('/').unwrap_or(tag);
    if tag.starts_with('!') || tag.starts_with('?') {
        return None;
    }
    let name = tag.split([' ', '\t', '\r', '\n', '/']).next().unwrap_or_default();
    let local = name.rsplit(':').next().unwrap_or(name);
    (!local.is_empty()).then_some(local)
}

/// The text of an `<D:owner>` element, with markup dropped and length bounded.
///
/// Clients put arbitrary XML in here — Finder sends a `<D:href>` naming the
/// machine — and RFC 4918 §14.17 asks a server to preserve it. This does not:
/// it keeps the **text** and drops the elements, and the reason is that the
/// alternative is to store attacker-supplied XML and re-emit it inside a body
/// we tell the client to trust. What is lost is fidelity in a field no
/// behaviour depends on; what is avoided is a second injection surface in every
/// `lockdiscovery` body this server will ever write. The trade is recorded here
/// rather than left to be discovered as a difference from other servers.
fn owner_text(rest: &str) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    while let Some(chunk) = rest.get(cursor..) {
        let Some(open) = chunk.find('<') else {
            // No closing tag at all: a truncated body, whose remaining text is
            // taken and bounded rather than treated as an error. A malformed
            // owner is not worth failing a lock over.
            out.push_str(chunk);
            break;
        };
        out.push_str(chunk.get(..open).unwrap_or_default());
        let tail = chunk.get(open + 1..).unwrap_or_default();
        let Some(close) = tail.find('>') else {
            break;
        };
        let tag = tail.get(..close).unwrap_or_default();
        if tag.starts_with('/') && local_name(tag) == Some("owner") {
            break;
        }
        // Byte positions throughout, never character counts: `find` returns a
        // byte index, and advancing a character iterator by one would desync on
        // the first non-ASCII byte in an attribute.
        cursor = cursor.saturating_add(open + 1 + close + 1);
    }
    out.trim().chars().take(MAX_OWNER_CHARS).collect()
}

/// Reads the `Timeout` header, capped.
///
/// `Second-<n>` is the only form with a number in it; `Infinite` is a request
/// this server does not grant, and a header naming several preferences is read
/// left to right with the first usable one taken, which is what RFC 4918 §10.7
/// asks for. Everything is capped at [`MAX_LOCK_SECONDS`] and zero is raised to
/// one — a zero-second lock is a lock that has already expired, which no client
/// means to ask for.
pub fn timeout(header: Option<&str>) -> u64 {
    let Some(value) = header else {
        return DEFAULT_LOCK_SECONDS;
    };
    for candidate in value.split(',') {
        let candidate = candidate.trim();
        if candidate.eq_ignore_ascii_case("infinite") {
            return MAX_LOCK_SECONDS;
        }
        if let Some(seconds) = candidate
            .get(..7)
            .filter(|prefix| prefix.eq_ignore_ascii_case("second-"))
            .and_then(|_| candidate.get(7..))
            .and_then(|digits| digits.parse::<u64>().ok())
        {
            return seconds.clamp(1, MAX_LOCK_SECONDS);
        }
    }
    DEFAULT_LOCK_SECONDS
}

/// The lock tokens an `If` header submits.
///
/// A deliberate subset of RFC 4918 §10.4 — see this module's documentation.
/// Every `<…>` coded-URL is collected **except** one immediately preceded by
/// `Not`, which is the conservative reading: a condition of the form
/// `(Not <urn:uuid:…>)` asserts that the client does *not* hold that lock, and
/// counting it as submitted would let a client unlock a resource by claiming
/// not to have locked it.
///
/// Entity tags (`[…]`) are ignored rather than evaluated: this server has no
/// state that a conditional write on an entity tag would protect that the lock
/// does not already protect, and a half-evaluated precondition is worse than an
/// unevaluated one.
pub fn submitted_tokens(header: Option<&str>) -> Vec<String> {
    let Some(value) = header else {
        return Vec::new();
    };
    let mut tokens = Vec::new();
    let mut negated = false;
    let mut rest = value;
    while let Some(index) = rest.find(['<', 'N', 'n']) {
        let Some(from) = rest.get(index..) else {
            break;
        };
        if from.starts_with('<') {
            let Some(inner) = from.get(1..) else {
                break;
            };
            let Some(end) = inner.find('>') else {
                break;
            };
            let Some(token) = inner.get(..end) else {
                break;
            };
            if !negated {
                tokens.push(token.to_string());
            }
            negated = false;
            rest = inner.get(end + 1..).unwrap_or_default();
            continue;
        }
        // `Not` applies to the next condition only.
        if from.len() >= 3 && from.get(..3).is_some_and(|word| word.eq_ignore_ascii_case("not")) {
            negated = true;
            rest = from.get(3..).unwrap_or_default();
            continue;
        }
        rest = from.get(1..).unwrap_or_default();
    }
    tokens
}

/// What [`Locks::guard`] decided about a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guard {
    /// Nothing is in the way.
    Clear,
    /// A lock covers this resource and its token was not submitted. The answer
    /// is `423`, and the path is carried so the log line can say which lock —
    /// never the token, which is a capability.
    Locked {
        /// The resource the blocking lock is on, share-relative.
        holder: String,
    },
}

/// Why an `UNLOCK` did not release anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// It did.
    Released,
    /// No lock of that token is held. RFC 4918 §9.11.1 makes this a `409`.
    NotHeld,
    /// The token names a lock on a different resource, which is a `409` too:
    /// releasing it would let one client unlock another's file by naming the
    /// wrong URL.
    WrongResource,
}

/// The live locks, and the only thing that grants or honours one.
///
/// One per daemon, shared. Expired locks are swept on every operation rather
/// than by a timer: a sweep that needs a task is a sweep that stops when the
/// task does, and there is nothing to sweep unless somebody is asking.
///
/// # Poisoning
///
/// The lock guards a `Vec` of plain values and is never held across a call that
/// can panic. A poisoned mutex therefore means another thread died with the
/// table intact, and recovering is right; propagating would make every share
/// unwritable for the life of the process.
#[derive(Debug, Default)]
pub struct Locks {
    held: Mutex<Vec<Lock>>,
}

impl Locks {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes an exclusive lock, or says what is in the way.
    ///
    /// Conflict is symmetric and both directions matter: a new lock is refused
    /// if an existing one covers it (`LOCK /a/b` under a depth-infinity lock on
    /// `/a`) **and** if it would cover an existing one (`LOCK /a` at depth
    /// infinity while somebody holds `/a/b`). A server that checked only the
    /// first would let a client lock a whole tree out from under another
    /// client's open document.
    pub fn take(
        &self,
        resource: Resource,
        reach: Reach,
        owner: Option<String>,
        seconds: u64,
    ) -> Result<Lock, TakeRefused> {
        let now = Instant::now();
        let mut held = self.lock();
        held.retain(|existing| existing.is_live(now));

        for existing in held.iter() {
            let covers = match existing.reach {
                Reach::Infinity => existing.resource.contains(&resource),
                Reach::Zero => existing.resource == resource,
            };
            let covered = reach == Reach::Infinity && resource.contains(&existing.resource);
            if covers || covered {
                return Err(TakeRefused::Conflict {
                    holder: existing.resource.path.to_string(),
                });
            }
        }
        if held.len() >= MAX_LOCKS {
            return Err(TakeRefused::TooMany);
        }

        let seconds = seconds.clamp(1, MAX_LOCK_SECONDS);
        let lock = Lock {
            token: Token::mint().map_err(|_| TakeRefused::NoRandom)?,
            resource,
            reach,
            owner,
            seconds,
            expires_at: now
                .checked_add(Duration::from_secs(seconds))
                .unwrap_or_else(|| now + Duration::from_secs(1)),
        };
        held.push(lock.clone());
        Ok(lock)
    }

    /// Extends a lock the client already holds.
    ///
    /// `None` when no live lock carries that token — which is a `412`, because
    /// the client stated a precondition (*I hold this lock*) that is not true.
    pub fn refresh(&self, token: &str, seconds: u64) -> Option<Lock> {
        let now = Instant::now();
        let mut held = self.lock();
        held.retain(|existing| existing.is_live(now));
        let existing = held.iter_mut().find(|existing| existing.token.matches(token))?;
        let seconds = seconds.clamp(1, MAX_LOCK_SECONDS);
        existing.seconds = seconds;
        existing.expires_at = now
            .checked_add(Duration::from_secs(seconds))
            .unwrap_or_else(|| now + Duration::from_secs(1));
        Some(existing.clone())
    }

    /// Releases a lock, if the token names one on this resource.
    ///
    /// The resource is checked as well as the token, so a client cannot release
    /// a lock by naming the right token at the wrong URL — which matters
    /// because the token is the capability and the URL is what an operator sees
    /// in a log.
    pub fn release(&self, resource: &Resource, token: &str) -> Release {
        let now = Instant::now();
        let mut held = self.lock();
        held.retain(|existing| existing.is_live(now));
        match held.iter().position(|existing| existing.token.matches(token)) {
            None => Release::NotHeld,
            Some(index) if held[index].resource != *resource => Release::WrongResource,
            Some(index) => {
                held.remove(index);
                Release::Released
            }
        }
    }

    /// Whether a write to this resource may proceed.
    ///
    /// This is the call that makes the lock a lock. Every writing verb goes
    /// through it before it touches the filesystem — `PUT`, `DELETE`, `MKCOL`,
    /// `PROPPATCH`, and both ends of a `COPY` or `MOVE`, since a move writes to
    /// its destination as surely as to its source.
    pub fn guard(&self, resource: &Resource, submitted: &[String]) -> Guard {
        let now = Instant::now();
        let mut held = self.lock();
        held.retain(|existing| existing.is_live(now));
        for existing in held.iter() {
            let covers = match existing.reach {
                Reach::Infinity => existing.resource.contains(resource),
                Reach::Zero => existing.resource == *resource,
            };
            if !covers {
                continue;
            }
            let submitted_it = submitted.iter().any(|token| existing.token.matches(token));
            if !submitted_it {
                return Guard::Locked { holder: existing.resource.path.to_string() };
            }
        }
        Guard::Clear
    }

    /// The live locks covering exactly this resource, for `lockdiscovery`.
    pub fn discover(&self, resource: &Resource) -> Vec<Lock> {
        let now = Instant::now();
        let mut held = self.lock();
        held.retain(|existing| existing.is_live(now));
        held.iter().filter(|existing| existing.resource == *resource).cloned().collect()
    }

    /// How many locks are held, for a test or a status plate.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.lock().iter().filter(|existing| existing.is_live(now)).count()
    }

    /// Whether nothing is locked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The table, with a poisoned lock recovered rather than propagated.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Lock>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a `LOCK` was not granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeRefused {
    /// Somebody else holds a lock that covers this resource, or one this
    /// request would cover.
    Conflict {
        /// The path of the lock in the way. Never the token.
        holder: String,
    },
    /// [`MAX_LOCKS`] are already held.
    TooMany,
    /// The system random source refused, so no token could be minted.
    NoRandom,
}

impl TakeRefused {
    /// The status this refusal is answered with.
    ///
    /// A conflict is `423`, which is what a client retries or reports. A full
    /// table is `503`: it clears on its own, exactly like the concurrency
    /// ceiling in [`crate::quota`], and telling a client to retry is honest.
    pub fn status(&self) -> Status {
        match self {
            Self::Conflict { .. } => LOCKED,
            Self::TooMany => Status::SERVICE_UNAVAILABLE,
            Self::NoRandom => Status::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for TakeRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { holder } => write!(f, "{holder} is already locked"),
            Self::TooMany => f.write_str("too many locks are held; try again shortly"),
            Self::NoRandom => f.write_str("no lock token could be minted"),
        }
    }
}

impl std::error::Error for TakeRefused {}

/// The `200` a granted or refreshed `LOCK` answers with.
///
/// Two things make it usable and both are easy to leave out:
///
/// - the **`Lock-Token` header**, which is where every client reads the token
///   from — the body carries it too, but the Mini-Redirector reads the header;
/// - a **`prop` body** carrying `lockdiscovery`, which is what Finder parses to
///   learn the timeout it has to refresh within.
pub fn granted(mount: &Mount, lock: &Lock) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <D:prop xmlns:D=\"DAV:\">\n{}</D:prop>\n",
        lockdiscovery(mount, std::slice::from_ref(lock))
    );
    let built = Response::bytes(Status::OK, XML_TYPE, body.into_bytes()).and_then(|mut response| {
        // The angle brackets are part of the header's grammar (RFC 4918 §10.5),
        // not decoration: a client that receives the bare URN puts the bare URN
        // in its `If` header, which then fails to parse as a coded-URL.
        response.headers.set("Lock-Token", format!("<{}>", lock.token))?;
        response.headers.set("Timeout", format!("Second-{}", lock.seconds))?;
        Ok(response)
    });
    or_internal_error(built)
}

/// The `<D:lockdiscovery>` element for a set of locks.
///
/// Also the value of the `lockdiscovery` live property, which is why it is a
/// string rather than a whole response: a `PROPFIND` embeds it, and a `LOCK`
/// wraps it in a `prop`.
pub fn lockdiscovery(mount: &Mount, locks: &[Lock]) -> String {
    let mut out = String::from("<D:lockdiscovery>\n");
    for lock in locks {
        let href: Href = mount.href(&lock.resource.path, crate::listing::Kind::File);
        out.push_str("<D:activelock>\n");
        out.push_str("<D:locktype><D:write/></D:locktype>\n");
        out.push_str("<D:lockscope><D:exclusive/></D:lockscope>\n");
        out.push_str("<D:depth>");
        out.push_str(lock.reach.token());
        out.push_str("</D:depth>\n");
        if let Some(owner) = &lock.owner {
            // Escaped, always. The owner is text a client chose, and this body
            // is a document we are telling the client to trust.
            out.push_str("<D:owner>");
            out.push_str(&escape(owner));
            out.push_str("</D:owner>\n");
        }
        out.push_str("<D:timeout>Second-");
        out.push_str(&lock.seconds.to_string());
        out.push_str("</D:timeout>\n");
        out.push_str("<D:locktoken><D:href>");
        out.push_str(&escape(lock.token.as_str()));
        out.push_str("</D:href></D:locktoken>\n");
        out.push_str("<D:lockroot><D:href>");
        out.push_str(&escape(href.as_str()));
        out.push_str("</D:href></D:lockroot>\n");
        out.push_str("</D:activelock>\n");
    }
    out.push_str("</D:lockdiscovery>\n");
    out
}

/// The `<D:supportedlock>` element, which says what a client may ask for.
///
/// Exclusive write only, which is what this server grants — so a client that
/// reads it never asks for a shared lock and never has to handle the `403`.
pub fn supportedlock() -> &'static str {
    "<D:supportedlock>\n\
     <D:lockentry><D:lockscope><D:exclusive/></D:lockscope>\
     <D:locktype><D:write/></D:locktype></D:lockentry>\n\
     </D:supportedlock>\n"
}

/// The `423` a write to a locked resource gets.
///
/// Carrying `<D:lock-token-submitted/>`, which is RFC 4918 §16's precondition
/// for exactly this: it tells the client that the resource is locked and that
/// submitting the token in an `If` header is what makes the request work —
/// rather than leaving it to conclude that the file is unwritable.
pub fn locked() -> Response {
    or_internal_error(error_body(LOCKED, "lock-token-submitted"))
}

/// The `403` a shared-lock request gets.
///
/// A plain refusal, not a shared lock granted as an exclusive one. A client
/// that asked for a lock several writers may hold and received one only it may
/// hold would behave correctly; a client that asked for exclusivity and got a
/// shared lock would not, and a server that blurs the two eventually does the
/// second.
pub fn scope_unsupported() -> Response {
    Response::error_page(Status::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::ShareId;

    fn path(segments: &[&str]) -> RelativePath {
        let mut path = RelativePath::default();
        for segment in segments {
            path = path.join(segment).expect("a legal test path");
        }
        path
    }

    fn resource(share: &str, segments: &[&str]) -> Resource {
        Resource::new(share, path(segments))
    }

    fn mount() -> Mount {
        Mount::for_share(&ShareId::parse("vault").expect("a legal id"))
    }

    #[test]
    fn a_token_is_random_unguessable_and_compared_whole() {
        let first = Token::mint().expect("a random source");
        let second = Token::mint().expect("a random source");
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("urn:uuid:"));
        assert_eq!(first.as_str().len(), "urn:uuid:".len() + 36);

        assert!(first.matches(first.as_str()));
        assert!(!first.matches(second.as_str()));
        assert!(!first.matches(""));
        // A prefix of the right token is not the right token, which is what a
        // short-circuiting comparison would eventually reveal one byte at a
        // time.
        assert!(!first.matches(&first.as_str()[..10]));
    }

    /// Containment is segment-wise, so a lock on `photos` does not silence
    /// writes to `photos-private`.
    #[test]
    fn a_lock_covers_a_subtree_and_not_a_similarly_spelled_sibling() {
        let photos = resource("vault", &["photos"]);
        assert!(photos.contains(&resource("vault", &["photos"])));
        assert!(photos.contains(&resource("vault", &["photos", "2026", "a.jpg"])));
        assert!(!photos.contains(&resource("vault", &["photos-private", "secret"])));
        assert!(!photos.contains(&resource("vault", &["other"])));
        // And never across shares, however the paths line up.
        assert!(!photos.contains(&resource("archive", &["photos", "a.jpg"])));
        // The share root contains everything in its own share.
        assert!(resource("vault", &[]).contains(&resource("vault", &["anything", "at", "all"])));
    }

    /// The property that makes the lock a lock: a write without the token is
    /// refused, and the same write with it goes through.
    #[test]
    fn a_locked_resource_refuses_a_write_that_did_not_submit_the_token() {
        let locks = Locks::new();
        let report = resource("vault", &["report.pdf"]);
        let lock = locks
            .take(report.clone(), Reach::Zero, Some("alex".into()), 600)
            .expect("granted");

        assert_eq!(
            locks.guard(&report, &[]),
            Guard::Locked { holder: "report.pdf".to_string() }
        );
        assert_eq!(locks.guard(&report, &["urn:uuid:not-the-one".to_string()]), Guard::Locked {
            holder: "report.pdf".to_string()
        });
        assert_eq!(locks.guard(&report, &[lock.token.as_str().to_string()]), Guard::Clear);

        // A depth-zero lock covers exactly one name.
        assert_eq!(locks.guard(&resource("vault", &["other.pdf"]), &[]), Guard::Clear);

        // And releasing it lets the write through.
        assert_eq!(locks.release(&report, lock.token.as_str()), Release::Released);
        assert_eq!(locks.guard(&report, &[]), Guard::Clear);
        assert!(locks.is_empty());
    }

    #[test]
    fn a_depth_infinity_lock_covers_everything_beneath_it() {
        let locks = Locks::new();
        let photos = resource("vault", &["photos"]);
        let lock = locks.take(photos.clone(), Reach::Infinity, None, 600).expect("granted");

        let child = resource("vault", &["photos", "2026", "a.jpg"]);
        assert_eq!(locks.guard(&child, &[]), Guard::Locked { holder: "photos".to_string() });
        assert_eq!(locks.guard(&child, &[lock.token.as_str().to_string()]), Guard::Clear);
        assert_eq!(locks.guard(&resource("vault", &["notes.txt"]), &[]), Guard::Clear);
    }

    /// Conflict is symmetric: a client must not be able to lock a whole tree
    /// out from under another client's open document.
    #[test]
    fn a_conflicting_lock_is_refused_in_both_directions() {
        let locks = Locks::new();
        let child = resource("vault", &["photos", "a.jpg"]);
        locks.take(child.clone(), Reach::Zero, None, 600).expect("granted");

        // A depth-infinity lock above it would swallow the existing one.
        assert!(matches!(
            locks.take(resource("vault", &["photos"]), Reach::Infinity, None, 600),
            Err(TakeRefused::Conflict { .. })
        ));
        // A depth-zero lock above it does not conflict — it covers a different
        // resource entirely.
        let parent = locks
            .take(resource("vault", &["photos"]), Reach::Zero, None, 600)
            .expect("a sibling scope");

        // And the same resource cannot be locked twice.
        assert!(matches!(
            locks.take(child, Reach::Zero, None, 600),
            Err(TakeRefused::Conflict { .. })
        ));
        assert_eq!(parent.reach, Reach::Zero);
        assert_eq!(TakeRefused::Conflict { holder: "x".into() }.status(), LOCKED);
    }

    #[test]
    fn a_lock_expires_and_a_refresh_extends_it() {
        let locks = Locks::new();
        let report = resource("vault", &["report.pdf"]);
        let lock = locks.take(report.clone(), Reach::Zero, None, 600).expect("granted");
        assert_eq!(lock.seconds, 600);

        // Refreshing needs the token, and a token nobody holds refreshes
        // nothing — which is the 412 a client gets for claiming a lock it does
        // not have.
        assert!(locks.refresh("urn:uuid:invented", 600).is_none());
        let refreshed = locks.refresh(lock.token.as_str(), 30).expect("refreshed");
        assert_eq!(refreshed.seconds, 30);
        assert_eq!(refreshed.token, lock.token);

        // Expiry is real: a lock that has run out no longer excludes anything.
        {
            let mut held = locks.lock();
            let entry = held.first_mut().expect("the lock");
            entry.expires_at = Instant::now();
        }
        assert_eq!(locks.guard(&report, &[]), Guard::Clear);
        assert!(locks.is_empty());
    }

    #[test]
    fn a_token_cannot_release_a_lock_on_a_different_resource() {
        let locks = Locks::new();
        let lock = locks
            .take(resource("vault", &["mine.txt"]), Reach::Zero, None, 600)
            .expect("granted");
        assert_eq!(
            locks.release(&resource("vault", &["yours.txt"]), lock.token.as_str()),
            Release::WrongResource
        );
        assert_eq!(locks.release(&resource("vault", &["mine.txt"]), "nonsense"), Release::NotHeld);
        assert_eq!(locks.len(), 1);
    }

    #[test]
    fn the_table_is_bounded_so_a_loop_of_locks_cannot_exhaust_memory() {
        let locks = Locks::new();
        for index in 0..MAX_LOCKS {
            locks
                .take(resource("vault", &[&format!("f{index}.txt")]), Reach::Zero, None, 600)
                .expect("granted");
        }
        assert!(matches!(
            locks.take(resource("vault", &["one-more.txt"]), Reach::Zero, None, 600),
            Err(TakeRefused::TooMany)
        ));
        assert_eq!(TakeRefused::TooMany.status(), Status::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn a_lockinfo_body_is_read_and_a_shared_request_is_refused_rather_than_upgraded() {
        let exclusive = br#"<?xml version="1.0" encoding="utf-8"?>
            <D:lockinfo xmlns:D="DAV:">
              <D:lockscope><D:exclusive/></D:lockscope>
              <D:locktype><D:write/></D:locktype>
              <D:owner><D:href>http://laptop.local/alex</D:href></D:owner>
            </D:lockinfo>"#;
        let parsed = parse_lockinfo(exclusive).expect("readable").expect("not a refresh");
        assert!(parsed.exclusive);
        assert!(parsed.write);
        assert_eq!(parsed.owner.as_deref(), Some("http://laptop.local/alex"));

        // An empty body is a refresh, not a new lock.
        assert_eq!(parse_lockinfo(b"").expect("readable"), None);
        assert_eq!(parse_lockinfo(b"   \n ").expect("readable"), None);

        let shared = br#"<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope>
            <D:locktype><D:write/></D:locktype></D:lockinfo>"#;
        assert_eq!(parse_lockinfo(shared), Err(BodyError::Unsupported));

        assert_eq!(parse_lockinfo(b"<D:propfind/>"), Err(BodyError::Malformed));
        assert_eq!(parse_lockinfo(&[0xff, 0xfe]), Err(BodyError::NotUtf8));
        assert_eq!(parse_lockinfo(&vec![b' '; MAX_BODY_BYTES + 1]), Err(BodyError::TooLarge));
    }

    /// The hazard `propfind` names, refused here too: an entity expansion costs
    /// the whole process rather than one request.
    #[test]
    fn a_document_type_declaration_is_refused_rather_than_ignored() {
        let bomb = br#"<?xml version="1.0"?>
            <!DOCTYPE lockinfo [<!ENTITY a "aaaaaaaaaa">]>
            <D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>
            <D:locktype><D:write/></D:locktype><D:owner>&a;</D:owner></D:lockinfo>"#;
        assert_eq!(parse_lockinfo(bomb), Err(BodyError::ProhibitedDoctype));
    }

    #[test]
    fn an_owner_is_bounded_so_it_cannot_amplify_every_later_response() {
        let long = "x".repeat(MAX_OWNER_CHARS * 4);
        let body = format!(
            "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>\
             <D:locktype><D:write/></D:locktype><D:owner>{long}</D:owner></D:lockinfo>"
        );
        let parsed = parse_lockinfo(body.as_bytes()).expect("readable").expect("a lock");
        let owner = parsed.owner.expect("an owner");
        assert!(owner.chars().count() <= MAX_OWNER_CHARS);
    }

    /// The owner scanner keeps text and drops markup, and it stops at its own
    /// closing tag rather than swallowing the rest of the document.
    #[test]
    fn an_owner_keeps_its_text_drops_its_markup_and_ends_where_it_ends() {
        for (body, expected) in [
            ("<D:owner>alex</D:owner><D:locktype><D:write/></D:locktype>", "alex"),
            ("<D:owner><D:href>x</D:href></D:owner><D:locktype/>", "x"),
            ("<D:owner></D:owner><D:locktype/>", ""),
            ("<D:owner>  spaced  </D:owner>", "spaced"),
            // Non-ASCII in an attribute must not desync the scan, which is why
            // it walks byte positions rather than characters.
            ("<D:owner><x a=\"é\">naïve</x></D:owner>", "naïve"),
            // A truncated body yields what it has rather than an error.
            ("<D:owner>half", "half"),
        ] {
            assert_eq!(owner_text(body.trim_start_matches("<D:owner>")), expected, "{body}");
        }
    }

    #[test]
    fn the_if_header_yields_the_tokens_a_client_submitted_and_never_a_negated_one() {
        assert_eq!(submitted_tokens(None), Vec::<String>::new());
        assert_eq!(
            submitted_tokens(Some("(<urn:uuid:one>)")),
            vec!["urn:uuid:one".to_string()]
        );
        // Tagged lists, several conditions, and an entity tag that is ignored.
        assert_eq!(
            submitted_tokens(Some(
                "</dav/vault/a.txt> (<urn:uuid:one> [\"etag\"]) (<urn:uuid:two>)"
            )),
            vec!["/dav/vault/a.txt".to_string(), "urn:uuid:one".to_string(), "urn:uuid:two".to_string()]
        );
        // A `Not` clause asserts the client does *not* hold the lock, so
        // counting it would let a client write through a lock by denying it.
        assert_eq!(submitted_tokens(Some("(Not <urn:uuid:one>)")), Vec::<String>::new());
        assert_eq!(
            submitted_tokens(Some("(Not <urn:uuid:one>) (<urn:uuid:two>)")),
            vec!["urn:uuid:two".to_string()]
        );
        // Nothing here may loop or panic on a truncated header.
        for hostile in ["<", "(<unterminated", "Not", "()", "<<<<", ""] {
            let _ = submitted_tokens(Some(hostile));
        }
    }

    #[test]
    fn a_timeout_is_read_capped_and_never_infinite() {
        assert_eq!(timeout(None), DEFAULT_LOCK_SECONDS);
        assert_eq!(timeout(Some("Second-30")), 30);
        assert_eq!(timeout(Some("second-30")), 30);
        assert_eq!(timeout(Some("Infinite")), MAX_LOCK_SECONDS);
        assert_eq!(timeout(Some("Second-99999999")), MAX_LOCK_SECONDS);
        assert_eq!(timeout(Some("Second-0")), 1, "a zero-second lock is already expired");
        assert_eq!(timeout(Some("Infinite, Second-30")), MAX_LOCK_SECONDS);
        assert_eq!(timeout(Some("nonsense")), DEFAULT_LOCK_SECONDS);
        assert_eq!(timeout(Some("Second-")), DEFAULT_LOCK_SECONDS);
        assert_eq!(timeout(Some("Second-abc")), DEFAULT_LOCK_SECONDS);
    }

    #[test]
    fn a_lock_depth_is_zero_or_infinity_and_never_one() {
        assert_eq!(Reach::parse(None), Some(Reach::Infinity));
        assert_eq!(Reach::parse(Some("0")), Some(Reach::Zero));
        assert_eq!(Reach::parse(Some("Infinity")), Some(Reach::Infinity));
        assert_eq!(Reach::parse(Some("1")), None, "a lock has no one-level depth");
        assert_eq!(Reach::parse(Some("2")), None);
    }

    #[test]
    fn a_granted_lock_carries_the_token_in_the_header_and_the_body() {
        let locks = Locks::new();
        let lock = locks
            .take(resource("vault", &["a.txt"]), Reach::Zero, Some("Q&A <alex>".into()), 45)
            .expect("granted");
        let response = granted(&mount(), &lock);
        assert_eq!(response.status, Status::OK);
        assert_eq!(
            response.headers.get_str("lock-token"),
            Some(format!("<{}>", lock.token).as_str())
        );
        assert_eq!(response.headers.get_str("timeout"), Some("Second-45"));

        let body = match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(body.contains("<D:lockdiscovery>"));
        assert!(body.contains("<D:exclusive/>"));
        assert!(body.contains(lock.token.as_str()));
        assert!(body.contains("<D:depth>0</D:depth>"));
        assert!(body.contains("Second-45"));
        assert!(body.contains("/dav/vault/a.txt"));
        // The owner is a client's text and is escaped, never echoed as markup.
        assert!(body.contains("Q&amp;A &lt;alex&gt;"));
        assert!(!body.contains("Q&A <alex>"));
    }

    #[test]
    fn a_refusal_says_which_condition_failed_rather_than_only_that_one_did() {
        let response = locked();
        assert_eq!(response.status, LOCKED);
        let body = match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(body.contains("<D:lock-token-submitted/>"));
        assert_eq!(scope_unsupported().status, Status::FORBIDDEN);
        assert!(supportedlock().contains("<D:exclusive/>"));
        assert!(!supportedlock().contains("<D:shared/>"));
    }

    #[test]
    fn discovery_reports_the_lock_on_a_resource_and_nothing_else() {
        let locks = Locks::new();
        let mine = resource("vault", &["a.txt"]);
        locks.take(mine.clone(), Reach::Zero, None, 600).expect("granted");
        locks.take(resource("vault", &["b.txt"]), Reach::Zero, None, 600).expect("granted");

        assert_eq!(locks.discover(&mine).len(), 1);
        assert_eq!(locks.discover(&resource("vault", &["c.txt"])).len(), 0);
        assert_eq!(lockdiscovery(&mount(), &[]).trim(), "<D:lockdiscovery>\n</D:lockdiscovery>");
    }
}
