//! Where WebDAV meets the control API: the routing half of `/dav`.
//!
//! `selfhost-storage` holds the whole of WebDAV that can be got wrong without a
//! socket — the verb table, the `PROPFIND` reader, the `207` printer, the lock
//! registry, the `Destination` parser, and the Basic-credential cache. This
//! module is the other half: it authenticates, decides, names a share, and calls
//! into that engine. It is deliberately thin, for the same reason
//! [`crate::storage_api`] is: everything worth attacking lives on the other side
//! of the seam and is tested there without a port.
//!
//! # Why a mount authenticates even though the console site is gated
//!
//! The proxy admits the console site only after its source-address gate has
//! passed the client, and that gate is **loopback plus the tunnel's exit** — not
//! authentication. Three co-hosted web applications share that same loopback,
//! and a bug in any of them issues requests from inside the gate. So every
//! `/dav` request carries a credential, and one that does not is refused with a
//! challenge, whatever the verb and whatever the path.
//!
//! # Basic, and only Basic
//!
//! A WebDAV client speaks HTTP authentication or nothing: Finder, the Windows
//! Mini-Redirector, `cadaver` and `rclone` have no notion of a login form or a
//! session cookie. Digest is unavailable to us on purpose — it needs the server
//! to hold a reversible derivation of the password, and the console credential
//! is PBKDF2-SHA256. So Basic, over TLS, and [`selfhost_storage::auth`] states
//! the six properties that make its verified-credential cache safe.
//!
//! The session cookie and the bearer token are deliberately **not** accepted
//! here. A cookie would make every `/dav` path a cross-site request forgery
//! surface reachable from any page the operator's browser loads, on the very
//! origin that holds the console session; the bearer token would put the
//! deployment's root credential into a keychain that replays it for the life of
//! a mount. One door, one credential, one challenge.
//!
//! # The cache is a correctness requirement, not an optimisation
//!
//! [`ConsolePassword::verify`](crate::ConsolePassword::verify) is 600,000 PBKDF2
//! iterations — about 70 ms of deliberate CPU. WebDAV re-authenticates on
//! essentially every request, and Finder's first act on a mount is a `PROPFIND`
//! sweep: five hundred files is five hundred verifications, thirty-five seconds
//! of a core spent proving one password, during which the daemon serves nobody.
//! [`authenticate`] therefore consults
//! [`Credentials`] **before** it verifies,
//! and the one cold verification per minute per credential is handed to
//! [`tokio::task::spawn_blocking`] so even that does not sit on a runtime
//! worker.
//!
//! # A refusal after authentication is never a `401`
//!
//! This is the rule that makes a mount usable, and it is the opposite of the
//! rule the rest of this crate follows. Everywhere else a caller who is known
//! and holds nothing gets the same uninformative `401` as a stranger, so the
//! console cannot be used to enumerate what sits behind it. Here that answer is
//! a trap: macOS and Windows both read a second `401` as *the password you
//! stored is wrong*, throw away the keychain item and prompt the operator again
//! — for ever, on a mount whose credential was right the whole time.
//!
//! It is safe to break the pattern here precisely because of what the credential
//! is. The only credential that opens `/dav` is the console password, which is
//! deployment-wide and answers as [`selfhost_identity::Identity::Owner`] — an
//! identity that holds every share there is. So an authenticated caller learning
//! that `vault` exists and `attic` does not has learned nothing they could not
//! read from `GET /api/storage/shares`. The uniform `401` still holds, and is
//! tested, for every request that has *not* authenticated.
//!
//! # What a mount is not allowed to become
//!
//! [`selfhost_storage::auth::authenticated`] mints
//! [`selfhost_identity::Caller::password`] and nothing else, and this module
//! never builds a caller by any other route. `Credential::Password` is
//! documented in `crates/identity` as **unattended**: an operating system's
//! keychain stores it at mount time and replays it on every request for the life
//! of the mount, with nobody present. The policy refuses an unattended
//! credential the capabilities that drive a machine, and this module reinforces
//! that structurally — the only capabilities it ever asks about are
//! [`Capability::FilesRead`] and [`Capability::FilesWrite`], so there is no
//! spelling of a `/dav` request that reaches a desktop route.
//!
//! # Every `href` goes through the encoded type
//!
//! [`Href`](selfhost_storage::dav::multistatus::Href) has no constructor from a
//! `String`; the only way to make one is
//! [`Mount::href`](selfhost_storage::dav::multistatus::Mount::href), which
//! percent-encodes every segment. Nothing in this file formats a URL, and
//! nothing in it may: a directory can hold a name containing `%`, whose own text
//! placed in a URL asks for a *different* file one level down, and a client
//! shown that link copies, overwrites or deletes the wrong thing. The rule is
//! enforced by the type rather than by this paragraph.
//!
//! # Two planes, drawn where [`crate::storage_api`] draws them
//!
//! The **document plane** is every verb whose request and response fit in
//! memory — `OPTIONS`, `PROPFIND`, `PROPPATCH`, `MKCOL`, `DELETE`, `COPY`,
//! `MOVE`, `LOCK`, `UNLOCK` — and it is answered through
//! [`Api::handle`](crate::Api::handle), which touches no socket, so every way of
//! getting authorisation wrong is a unit test over a `Request`.
//!
//! The **byte plane** is `GET`, `HEAD` and `PUT`, which are gigabytes in one
//! direction or the other and cannot be a `Vec`. [`passage`] is the pure
//! decision over the request head — reached from `Api::handle` as well, so its
//! refusals are tested the same way — and [`serve`] is the only thing here that
//! owns a connection.
//!
//! # Paths are the sensitive thing, so nothing here logs one
//!
//! The same rule [`crate::storage_api`] holds: on a NAS the file names *are* the
//! data. A refusal is logged by share id and reason tag, never by name.

use crate::{ConsolePassword, storage_api::Volumes};
use selfhost_http::{Method, Request, Response, Status};
use selfhost_identity::{Capability, Caller, Identity, Policy, ShareId as CapabilityShareId};
use selfhost_storage::api::{Failure, Volume};
use selfhost_storage::auth::{self, Cached, Credentials, KeyUnavailable, Presented};
use selfhost_storage::dav::lock::{self, Guard, Locks, Reach, Release, TakeRefused};
use selfhost_storage::dav::method::{self, Overwrite, Verb};
use selfhost_storage::dav::multistatus::Mount;
use selfhost_storage::dav::propfind::{self, Depth, Quota};
use selfhost_storage::fs::Existing;
use selfhost_storage::listing::Kind;
use selfhost_storage::path::RelativePath;
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// The URL prefix WebDAV is mounted at, above the share segment.
///
/// Re-exported from the storage crate rather than spelled again: the `href`
/// printer builds every link from that constant, and a second copy here would be
/// a mount point that could drift from the links it serves.
pub use selfhost_storage::dav::multistatus::DAV_ROOT;

/// `/dav/` — the prefix a share path sits under.
///
/// Matched with its trailing slash so `/davos` is not a WebDAV path, in exactly
/// the way [`crate::storage_api::is_bulk`] matches its own prefix.
pub const DAV_PREFIX: &str = "/dav/";

/// Whether a path belongs to the WebDAV mount.
///
/// The bare root counts: a client asks `OPTIONS /dav` before it knows a share
/// exists, and macOS asks it of `/` on the way to a mount, so the root has to be
/// a WebDAV path rather than a 404 that ends the mount attempt.
pub fn is_dav_path(path: &str) -> bool {
    path == DAV_ROOT || path.starts_with(DAV_PREFIX)
}

/// Whether this method moves bytes rather than a document.
///
/// The one place the two planes are told apart, so the socket layer and
/// [`answer`] cannot come to disagree about which verbs need a connection.
pub fn is_byte_verb(method: &Method) -> bool {
    matches!(method, Method::Get | Method::Head | Method::Put)
}

/// Splits a WebDAV path into its share id and the path inside it.
///
/// Pure, and deliberately naive: the remainder is handed to
/// [`Volume::resolve`] exactly as it arrived, percent-escapes and all, because
/// that function is the security resolver and anything cleaned up here would be
/// a rule enforced in two places — which is a rule that eventually disagrees
/// with itself.
///
/// `None` for the mount root, which names no share. An empty remainder is the
/// share root and is returned as `Some`, because `PROPFIND /dav/vault` is how
/// every client starts.
pub fn split_dav(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix(DAV_PREFIX)?;
    let (share, remainder) = match rest.split_once('/') {
        Some(pair) => pair,
        None => (rest, ""),
    };
    (!share.is_empty()).then_some((share, remainder))
}

/// The two pieces of state WebDAV needs to keep between requests.
///
/// One per daemon, shared by every clone of the [`Api`](crate::Api). Both are
/// in-memory and neither is persisted, which is the honest arrangement for both:
/// a credential fingerprint keyed on a process-lifetime secret is useless after
/// a restart, and a lock that survived a restart would be a lock whose holder
/// has certainly gone.
#[derive(Debug)]
pub struct Webdav {
    /// Verified-and-rejected credentials, so a `PROPFIND` sweep costs one
    /// PBKDF2 verification rather than five hundred.
    credentials: Credentials,
    /// The live `LOCK`s. Locking is what makes a Windows mount writable at all —
    /// the Mini-Redirector locks before every write — so this is not optional
    /// state.
    locks: Locks,
}

impl Webdav {
    /// A fresh cache and an empty lock table.
    ///
    /// # Errors
    ///
    /// Only if the system random source refuses to seed the cache key. Failing
    /// is the point: a cache keyed on a constant is a fingerprint table an
    /// attacker could build offline, and a `/dav` endpoint that does not exist
    /// is better than one whose fingerprints are guessable.
    pub fn new() -> Result<Self, KeyUnavailable> {
        Ok(Self { credentials: Credentials::new()?, locks: Locks::new() })
    }

    /// The verified-credential cache.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The live locks.
    pub fn locks(&self) -> &Locks {
        &self.locks
    }
}

/// Everything a WebDAV request is decided against, gathered for one call.
///
/// Borrowed rather than owned, and built per request by
/// [`Api::dav_wiring`](crate::Api), so this module never holds deployment state
/// of its own and cannot form a second opinion about the policy, the shares or
/// the password.
pub struct Wiring<'a> {
    /// The stored hash every Basic credential is verified against. An `Arc`
    /// rather than a reference because the cold verification is moved onto the
    /// blocking pool.
    pub password: Arc<ConsolePassword>,
    /// The credential cache and the lock table, shared with every other
    /// connection.
    pub webdav: Arc<Webdav>,
    /// The shares this daemon serves.
    pub volumes: &'a Volumes,
    /// The authorisation model, as it stands for this request. Consulted even
    /// though the only credential that reaches here is the owner's: a check that
    /// is skipped because it *happens* to be redundant is a check nobody notices
    /// has become load-bearing.
    ///
    /// Held by value rather than by reference because it is no longer a field
    /// somewhere else to point at: half of it is a fact
    /// ([`Api::policy`](crate::Api)) that is read fresh per request, and it is a
    /// `Copy` pair of booleans.
    pub policy: Policy,
    /// The console site's configured hostname, for the `Destination` header's
    /// authority check. `None` when no console site is configured, which makes
    /// [`method::destination`] accept any authority — the safe reading, because
    /// the path is still funnelled through the same resolver either way.
    pub host: Option<&'a str>,
}

/// Why a `/dav` request carried no credential this deployment accepts.
///
/// Four causes, one answer. Naming them is for the daemon's log — an operator
/// diagnosing a mount that will not connect needs to know whether the client
/// sent nothing, sent the wrong password, or is being throttled — and never for
/// the wire, where all four are the identical `401`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unauthenticated {
    /// No `Authorization: Basic`, or one that did not parse. Ordinary: every
    /// WebDAV client's first request is unauthenticated by protocol design.
    Absent,
    /// This exact credential has failed too often to be worth verifying again.
    /// Per-credential and self-clearing; see [`selfhost_storage::auth`] for why
    /// it can never reach the console's login gate.
    Throttled,
    /// The password is wrong.
    Wrong,
    /// This deployment has no console password, no shares, or no credential
    /// cache, so nothing could ever authenticate.
    NothingToOpen,
}

impl fmt::Display for Unauthenticated {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Absent => "no Basic credential was presented",
            Self::Throttled => "that credential has failed too often to be verified again yet",
            Self::Wrong => "the password did not match",
            Self::NothingToOpen => "this deployment serves no WebDAV",
        };
        out.write_str(reason)
    }
}

/// The `401` every unauthenticated `/dav` request gets, byte for byte.
///
/// The challenge is [`selfhost_storage::auth::challenge`], which is one constant
/// realm and `charset="UTF-8"`. Both parts are load-bearing:
///
/// - **The realm never changes.** Finder keys its keychain item on it and
///   Windows keys its credential on it, so a realm that varied — by share, by
///   host, by anything — would look to both clients like a different server on
///   every request and would re-prompt for ever.
/// - **`charset="UTF-8"`** is RFC 7617's one parameter, and without it a client
///   is entitled to send the password in ISO-8859-1; a password with a non-ASCII
///   character would then hash to something that never matches what the operator
///   set.
///
/// The body is empty. A WebDAV client shows its own dialog and never renders
/// one, and a JSON error object here would only be a thing to parse wrongly.
pub fn unauthenticated() -> Response {
    let mut response = Response::empty(Status::UNAUTHORIZED);
    if response.headers.set("WWW-Authenticate", auth::challenge()).is_err() {
        // Unreachable: the challenge is built from compile-time constants and
        // cannot hold a CR, an LF or a NUL. A `401` without the header would be
        // a mount that can never authenticate, so the honest fallback is a
        // `500` that says the box is wrong rather than the client.
        return Response::empty(Status::INTERNAL_SERVER_ERROR);
    }
    response
}

/// Authenticates a WebDAV request against the console password.
///
/// The order is the whole of the design and each step exists for a measured
/// reason:
///
/// 1. **Parse.** An absent header, a scheme that is not Basic, base64 that does
///    not decode and a payload with no colon are one answer, because telling a
///    prober *how* their credential was malformed tells them how to build a
///    better one.
/// 2. **Throttle.** A credential that has failed [`auth::MAX_FAILURES`] times
///    inside the window is refused without being verified. This is a brake on
///    PBKDF2 burn, not a lockout: it names one credential, it clears itself, and
///    it is in a crate the console's login gate does not call.
/// 3. **Cache.** A recent decision stands for [`auth::ENTRY_TTL`], which is what
///    turns Finder's five hundred requests into one verification.
/// 4. **Queue.** The three checks above are all keyed on the credential the
///    caller chose, so a caller who never repeats one passes all three every
///    time and reaches the PBKDF2 every time. [`Credentials::verification_slot`]
///    is the ceiling that is not keyed on anything the caller controls; a caller
///    past it waits rather than being refused, because a refusal here is a `401`
///    and a second `401` is how a mount loses its stored credential.
/// 5. **Verify, off the runtime.** Only a credential nothing is known about
///    reaches the 70 ms of PBKDF2, and it reaches it on the blocking pool, so a
///    cold mount does not stall every other connection the daemon is serving.
///
/// The user name is not checked against anything, and that is deliberate rather
/// than an omission: the console credential is a password with no account beside
/// it, so there is no name to compare against and inventing one would be a
/// second secret an operator has to be told. The name is still part of the cache
/// key — `alice` and `bob` with the same password are two entries — and it is
/// the only half of the credential that may be logged.
///
/// Returns [`auth::authenticated`]'s caller and no other, for the reason this
/// module's documentation gives: a mount must never be able to hold a keyboard.
pub async fn authenticate(
    request: &Request,
    password: Arc<ConsolePassword>,
    cache: &Credentials,
) -> Result<Caller, Unauthenticated> {
    let presented =
        auth::parse_basic(request.headers.get_str("authorization")).ok_or(Unauthenticated::Absent)?;
    if cache.throttled(&presented) {
        return Err(Unauthenticated::Throttled);
    }
    match cache.look_up(&presented) {
        Cached::Verified => return Ok(auth::authenticated()),
        Cached::Rejected => return Err(Unauthenticated::Wrong),
        Cached::Unknown => {}
    }

    // Nothing is known about this credential, so it is about to cost 70 ms of a
    // core — and the two checks above are both keyed on the credential, so a
    // caller who never repeats one is never stopped by either. The ceiling that
    // is not keyed on anything the caller chooses is held here; see
    // [`auth::MAX_CONCURRENT_VERIFICATIONS`] for what it costs and what it buys.
    let _slot = cache.verification_slot().await;
    // Asked again now that a slot is in hand, because the wait may have been
    // spent behind a verification of this very credential: Finder opens a mount
    // with its requests in parallel, and every one of them missed the cache
    // before the first had finished. Without this second look the queue would
    // drain into one PBKDF2 run per waiter, which is the cost this cache exists
    // to remove.
    match cache.look_up(&presented) {
        Cached::Verified => return Ok(auth::authenticated()),
        Cached::Rejected => return Err(Unauthenticated::Wrong),
        Cached::Unknown => {}
    }

    let Some((presented, verified)) = verify_off_runtime(password, presented).await else {
        // The verification did not finish, so nothing is known and nothing is
        // remembered — a decision that was never made must not become a cache
        // entry. Refusing is the only safe reading.
        return Err(Unauthenticated::Wrong);
    };
    cache.remember(&presented, verified);
    if verified { Ok(auth::authenticated()) } else { Err(Unauthenticated::Wrong) }
}

/// Runs the one cold PBKDF2 verification on the blocking pool.
///
/// The credential travels into the task and back out again rather than being
/// cloned, because [`Presented`] is deliberately not `Clone` — a credential that
/// can be duplicated is a credential that ends up in two places, one of which
/// eventually gets logged. That is also why the answer is an `Option` rather
/// than a `(Presented, bool)` with a fabricated credential in the failing arm:
/// there is no honest `Presented` to return when the task did not finish, and
/// inventing one would put a value nobody presented into the cache.
///
/// `None` only if the task failed to join, which under `panic = "abort"` cannot
/// happen in production — the process is already gone — so the branch is written
/// for a test build rather than unwrapped.
async fn verify_off_runtime(
    password: Arc<ConsolePassword>,
    presented: Presented,
) -> Option<(Presented, bool)> {
    tokio::task::spawn_blocking(move || {
        let verified = password.verify(presented.password());
        (presented, verified)
    })
    .await
    .ok()
}

/// Why a WebDAV request was refused after it authenticated.
///
/// Every one of these is a refusal the *route* makes before the storage engine
/// is reached, and **none of them is a `401`** — see this module's documentation
/// for why a second `401` is what makes a mount prompt for ever.
#[derive(Debug)]
pub enum Denied {
    /// The path named no share, or named one this daemon does not serve.
    NoShare,
    /// The capability model refused this caller for this share. Unreachable
    /// today, because the only credential that opens `/dav` is the owner's, and
    /// deliberately still checked: see [`Wiring::policy`].
    NotPermitted,
    /// The resolver refused the path. Carries its reason, which decides the
    /// status.
    Refused(Failure),
    /// A `PUT` that declared no length, declared a chunked body, or declared
    /// more than [`crate::storage_api::BULK_MAX_BODY`].
    Unframed(&'static str),
    /// A lock covers this resource and its token was not submitted. Carries the
    /// locked path for the log — never the token, which is a capability.
    Locked {
        /// The share-relative path of the lock in the way.
        holder: String,
    },
}

impl Denied {
    /// The response this refusal becomes.
    pub fn response(&self) -> Response {
        match self {
            Self::NoShare => method::status_only(Status::NOT_FOUND),
            Self::NotPermitted => method::status_only(Status::FORBIDDEN),
            Self::Refused(failure) => method::status_only(failure.status()),
            // 411 Length Required. Spelled numerically because
            // `selfhost_http::Status`'s table covers the codes the proxy and the
            // console use and this one belongs to a body nobody framed; the
            // honest fix is a larger table in `crates/http`, recorded as owed
            // rather than worked around with a second constant here.
            Self::Unframed(_) => method::status_only(Status(411)),
            Self::Locked { .. } => lock::locked(),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoShare => out.write_str("no share by that id is served"),
            Self::NotPermitted => out.write_str("this credential holds nothing for that share"),
            // The *tag*, never the failure's own sentence: a resolver refusal
            // names the segment it refused, and this string reaches a log.
            Self::Refused(failure) => write!(out, "the path was refused: {}", failure.tag()),
            Self::Unframed(why) => out.write_str(why),
            Self::Locked { .. } => out.write_str("a lock covers that resource"),
        }
    }
}

impl std::error::Error for Denied {}

/// Why a byte-plane request will not be served, in the vocabulary the socket
/// layer needs.
///
/// Separate from [`Denied`] because the socket layer has to answer *before* a
/// verb is known and before a share is named — and because the one refusal that
/// must carry a challenge is the one refusal [`Denied`] deliberately cannot
/// express.
#[derive(Debug)]
pub enum Refused {
    /// No credential this deployment accepts. The only `401` on this path.
    Unauthenticated(Unauthenticated),
    /// Not a verb this build answers on a share, or one that reached the wrong
    /// plane. Answered `405` with `Allow`, so a client learns what to send
    /// instead rather than retrying the same thing.
    NotAVerb,
    /// Authenticated, and refused for a reason that is never a `401`.
    Denied(Denied),
}

impl Refused {
    /// The response this refusal becomes.
    pub fn response(&self) -> Response {
        match self {
            Self::Unauthenticated(_) => unauthenticated(),
            Self::NotAVerb => method::not_allowed(),
            Self::Denied(denied) => denied.response(),
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated(why) => write!(out, "{why}"),
            Self::NotAVerb => out.write_str("not a WebDAV verb this build serves"),
            Self::Denied(denied) => write!(out, "{denied}"),
        }
    }
}

impl std::error::Error for Refused {}

/// Decides a byte-plane request end to end, for the socket layer.
///
/// The counterpart to [`answer`] on the other plane, and the only entry point
/// the connection handler needs: it authenticates, recognises the verb, and
/// hands back everything the transfer will need — without opening a descriptor.
pub async fn admit(wiring: &Wiring<'_>, request: &Request) -> Result<Passage, Refused> {
    let caller =
        authenticate(request, Arc::clone(&wiring.password), wiring.webdav.credentials())
            .await
            .map_err(Refused::Unauthenticated)?;
    if !is_byte_verb(&request.method) {
        return Err(Refused::NotAVerb);
    }
    let verb = Verb::classify(&request.method)
        .filter(|verb| method::implemented(*verb))
        .ok_or(Refused::NotAVerb)?;
    passage(wiring, &caller, request, verb).map_err(Refused::Denied)
}

/// A share, its mount point, and a path inside it that has been through the
/// resolver.
///
/// Produced by [`located`] and by nothing else, so no handler can reach a
/// filesystem with a path that skipped [`Volume::resolve`].
pub struct Located {
    /// The share, held so a blocking task can walk it.
    pub volume: Arc<Volume>,
    /// Where the share is mounted in the URL space, and the only source of an
    /// `href`.
    pub mount: Mount,
    /// The resolved path inside the share.
    pub at: RelativePath,
    /// Who asked, in the vocabulary the share's own grant check speaks.
    pub who: Identity,
}

impl fmt::Debug for Located {
    /// Names the share and never the path.
    ///
    /// On a NAS the file names *are* the data, and a type whose `Debug` prints
    /// one will eventually be printed — into a log, into a panic message, into a
    /// test failure somebody pastes. The share id is a configured name and is
    /// safe; the path is not, so there is no derived `Debug` here.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Located")
            .field("share", &self.volume.share().id().as_str())
            .field("path", &"<elided>")
            .field("who", &self.who)
            .finish()
    }
}

impl fmt::Debug for Passage {
    /// The same elision, for the same reason.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Passage")
            .field("target", &self.target)
            .field("verb", &self.verb)
            .field("declared", &self.declared)
            .finish()
    }
}

impl Located {
    /// The lock-table key for this resource.
    ///
    /// Share-qualified, because two shares may hold the same relative path and a
    /// lock on one must not silence a write to the other.
    fn resource(&self) -> lock::Resource {
        lock::Resource::new(self.volume.share().id().as_str(), self.at.clone())
    }
}

/// A `GET`, `HEAD` or `PUT` that may proceed, and everything the bytes need.
///
/// The byte plane's counterpart to [`Located`], and the value
/// [`admit`] hands to [`serve`].
pub struct Passage {
    /// Where the bytes come from or go.
    pub target: Located,
    /// Which of the three verbs this is.
    pub verb: Verb,
    /// The `PUT` body's declared length — a *claim*, admitted against the quota
    /// and re-checked as the bytes land. Zero for a read.
    pub declared: u64,
}

/// Names the share, checks the capability and resolves the path.
///
/// The one door onto a share from WebDAV. Every refusal it makes is a refusal
/// made before a descriptor is opened, and the order matters: an unparseable
/// share id and an unserved one are the same `404`, because a caller who has
/// already proved they hold the deployment's own password can read the share
/// list anyway and there is nothing left to conceal from them.
pub fn located(
    wiring: &Wiring<'_>,
    caller: &Caller,
    path: &str,
    want: Wants,
) -> Result<Located, Denied> {
    let (id, remainder) = split_dav(path).ok_or(Denied::NoShare)?;
    let share = CapabilityShareId::parse(id).map_err(|_| Denied::NoShare)?;
    let capability = match want {
        Wants::Read => Capability::FilesRead(share),
        Wants::Write => Capability::FilesWrite(share),
    };
    if !wiring.policy.decide(caller, &capability).is_allowed() {
        return Err(Denied::NotPermitted);
    }
    let volume = wiring.volumes.find(id).ok_or(Denied::NoShare)?;
    // The share's own `[[shares.access]]` list and its `read_only` flag, which
    // are a *second* permission layer and not a restatement of the capability
    // above: one is the deployment's model of who a person is, the other is a
    // statement about the data that binds the owner too. The storage engine
    // checks it again on every single operation, so this is not the rule moved —
    // it is the rule asked early, which is what lets a `PUT` onto a read-only
    // share be refused by the route rather than by a descriptor that has already
    // been opened on the byte plane.
    volume.permit(caller.identity(), share_want(want)).map_err(Denied::Refused)?;
    let at = volume.resolve(remainder).map_err(Denied::Refused)?;
    Ok(Located {
        mount: Mount::for_share(volume.share().id()),
        volume: Arc::clone(volume),
        at,
        who: caller.identity().clone(),
    })
}

/// Which half of the share capability ladder a verb sits on.
///
/// A mirror of the `Wants` in [`crate::storage_api`], which is `pub(crate)`
/// there and names the same two rungs. Duplicated rather than widened because the two
/// enums answer for two different protocols and a shared one would invite a
/// third rung that only one of them serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wants {
    /// Reading, listing, and taking a lock.
    Read,
    /// Creating, replacing, moving and deleting.
    Write,
}

/// The same rung, in the vocabulary a share's own access list speaks.
///
/// Two enums rather than one because they answer for two different things —
/// this API's capability ladder and the share's grant table — and
/// [`selfhost_storage::share::Want`] has a rung (`Admin`) that no WebDAV verb
/// exercises. A total match rather than a conversion trait keeps a future third
/// rung from silently becoming one of these two.
fn share_want(want: Wants) -> selfhost_storage::share::Want {
    match want {
        Wants::Read => selfhost_storage::share::Want::Read,
        Wants::Write => selfhost_storage::share::Want::Write,
    }
}

/// What a verb demands **of the resource on the request line**.
///
/// Three of these are worth stating because getting them wrong is not a compile
/// error, it is a share that behaves oddly:
///
/// - **`COPY` reads its source.** A copy out of a read-only share into a
///   writable one is an ordinary, correct request, and asking the source for
///   `Write` would refuse it. The destination is asked for `Write` separately,
///   by [`transfer_answer`], because it is a different share with different
///   rules — a check given only a path would have applied the source's.
/// - **`MOVE` writes its source**, because it removes the thing from it.
/// - **`LOCK` reads.** A lock changes no bytes, and the write it protects is
///   checked against [`Capability::FilesWrite`] when that write arrives.
///
/// `PROPPATCH` is on the write side even though this build stores no
/// properties, because a caller who may not write must not be told a property
/// write "failed" rather than that they may not make one.
fn wants(verb: Verb) -> Wants {
    match verb {
        Verb::Options
        | Verb::PropFind
        | Verb::Get
        | Verb::Head
        | Verb::Lock
        | Verb::Unlock
        | Verb::Copy => Wants::Read,
        Verb::PropPatch | Verb::MkCol | Verb::Put | Verb::Delete | Verb::Move => Wants::Write,
    }
}

/// Decides a `GET`, `HEAD` or `PUT` without opening anything.
///
/// Pure over the request head and the in-memory lock table, exactly as
/// [`Api::bulk_for`](crate::Api::bulk_for) is: no descriptor, no socket. That is
/// what lets every way of getting a byte-plane transfer's authorisation wrong be
/// a unit test over a `Request`, and it is why [`answer`] calls this too rather
/// than leaving the byte verbs untested on the document plane.
pub fn passage(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    verb: Verb,
) -> Result<Passage, Denied> {
    let target = located(wiring, caller, request.path(), wants(verb))?;
    let declared = match verb {
        Verb::Put => {
            // A write, so the lock table is consulted before anything else: the
            // Windows Mini-Redirector locks and then writes, and a `PUT` that
            // ignored the lock would make locking decorative.
            guard(wiring, &target, request)?;
            declared_length(request)?
        }
        _ => 0,
    };
    Ok(Passage { target, verb, declared })
}

/// Refuses a write that a lock covers and whose token was not submitted.
///
/// Called by every writing verb, including both ends of a `COPY` or a `MOVE`,
/// because a move writes to its destination as surely as to its source.
fn guard(wiring: &Wiring<'_>, target: &Located, request: &Request) -> Result<(), Denied> {
    let submitted = lock::submitted_tokens(request.headers.get_str("if"));
    match wiring.webdav.locks().guard(&target.resource(), &submitted) {
        Guard::Clear => Ok(()),
        Guard::Locked { holder } => Err(Denied::Locked { holder }),
    }
}

/// The declared length of a `PUT` body, or why it cannot be accepted.
///
/// Chunked is refused rather than dechunked, for the reason
/// [`crate::storage_api::declared_length`] gives: a dechunker is a parser fed by
/// strangers, and no WebDAV client this deployment serves sends one. The cap is
/// the same one the JSON bulk plane applies, so the two protocols cannot
/// disagree about how large an upload this API will consider.
fn declared_length(request: &Request) -> Result<u64, Denied> {
    match request.body_length() {
        Ok(selfhost_http::BodyLength::Fixed(length))
            if length <= crate::storage_api::BULK_MAX_BODY =>
        {
            Ok(length)
        }
        Ok(selfhost_http::BodyLength::Fixed(_)) => {
            Err(Denied::Unframed("that Content-Length is larger than this API will accept"))
        }
        // An empty `PUT` is a legal way to create a zero-byte file, and Finder
        // does exactly that before it writes a new document.
        Ok(selfhost_http::BodyLength::None) => Ok(0),
        Ok(selfhost_http::BodyLength::Chunked) => {
            Err(Denied::Unframed("send a Content-Length rather than chunked framing"))
        }
        Err(_) => Err(Denied::Unframed("the body framing could not be read")),
    }
}

/// The status a storage failure becomes on WebDAV.
///
/// Three answers differ from the JSON API's, and each difference is a
/// requirement of RFC 4918 rather than a preference:
///
/// - **`MKCOL` onto an occupied name is `405`** (§9.3.1), not `409`. A client
///   that reads `409` looks for a missing parent that is not missing.
/// - **`COPY`/`MOVE` onto an occupied destination is `412`** (§9.8.5, §9.9.4),
///   because `Overwrite: F` is a *precondition* the client stated and the client
///   retries by restating it.
/// - **A name that collides with an existing one** is the same `412` for the
///   same reason: on a case-folding volume it is an occupied destination wearing
///   a different spelling.
///
/// Everything else is the storage crate's own status, so the two protocols agree
/// about what a refusal means wherever they can.
fn dav_status(verb: Verb, failure: &Failure) -> Status {
    match (verb, failure) {
        (Verb::MkCol, Failure::Occupied) => Status::METHOD_NOT_ALLOWED,
        (Verb::Copy | Verb::Move, Failure::Occupied | Failure::Collides { .. }) => {
            method::PRECONDITION_FAILED
        }
        _ => failure.status(),
    }
}

/// A storage failure as a WebDAV response.
///
/// Body-less on purpose. Every WebDAV client switches on the status and none
/// renders a body, so the JSON error object the console reads would be a
/// document nothing parses — and one that would carry the refused path into a
/// place this module has promised not to put it.
fn failed(verb: Verb, failure: &Failure) -> Response {
    method::status_only(dav_status(verb, failure))
}

/// Answers a WebDAV request on the document plane.
///
/// The order of the four gates is the order of the argument: authenticate, then
/// recognise the verb, then answer `OPTIONS` — which a client asks before it
/// knows a share exists — and only then name a share. A verb this build does not
/// answer is a `405` carrying `Allow`, never a `501`: `501` says the server does
/// not understand the method, which is untrue and which some clients treat as
/// fatal for the whole mount rather than for the request.
pub async fn answer(wiring: &Wiring<'_>, request: &Request, body: &[u8]) -> Response {
    let caller = match authenticate(
        request,
        Arc::clone(&wiring.password),
        wiring.webdav.credentials(),
    )
    .await
    {
        Ok(caller) => caller,
        Err(refusal) => {
            // Logged, never sent: an operator debugging a mount that will not
            // connect can read which check failed, and a stranger cannot.
            eprintln!("admin: refused a WebDAV request: {refusal}");
            return unauthenticated();
        }
    };

    let Some(verb) = Verb::classify(&request.method).filter(|verb| method::implemented(*verb))
    else {
        return method::not_allowed();
    };

    match verb {
        // Answered without naming a share, deliberately. Finder issues
        // `OPTIONS /dav` and Windows issues `OPTIONS /` on the way to a mount,
        // before either knows a share exists, and a `404` for that request ends
        // the attempt.
        Verb::Options => method::options(),
        Verb::PropFind => propfind_answer(wiring, &caller, request, body).await,
        Verb::PropPatch => proppatch_answer(wiring, &caller, request, body).await,
        Verb::MkCol => mkcol_answer(wiring, &caller, request, body).await,
        Verb::Delete => delete_answer(wiring, &caller, request).await,
        Verb::Copy | Verb::Move => transfer_answer(wiring, &caller, request, verb).await,
        Verb::Lock => lock_answer(wiring, &caller, request, body).await,
        Verb::Unlock => unlock_answer(wiring, &caller, request).await,
        // The byte plane. The decision is still made here, so that every refusal
        // a `GET` or a `PUT` can meet is exercised through `Api::handle` without
        // a socket; only the bytes themselves need one, and they are `serve`'s.
        Verb::Get | Verb::Head | Verb::Put => match passage(wiring, &caller, request, verb) {
            Err(denied) => denied.response(),
            Ok(_) => byte_plane_misrouted(),
        },
    }
}

/// The answer to a byte verb that reached the document plane.
///
/// Unreachable through the daemon: `handle_connection` routes `GET`, `HEAD` and
/// `PUT` on a `/dav` path to [`serve`] before [`Api::handle`](crate::Api::handle)
/// is called. It is reachable by a test or by a future caller that forgets, and
/// a `500` naming the mistake is better than a truncated file: answering it here
/// would mean reading a whole share's largest file into a `Vec`, which is the
/// one thing the split between the two planes exists to prevent.
fn byte_plane_misrouted() -> Response {
    method::status_only(Status::INTERNAL_SERVER_ERROR)
}

/// Answers `PROPFIND`: the listing every client builds its view from.
///
/// `Depth: infinity` is refused with `<D:propfind-finite-depth/>` rather than
/// served, because a single request would otherwise walk a whole NAS; the
/// condition element is what tells the client that retrying at depth 1 works.
/// An absent `Depth` header means infinity, which RFC 4918 §9.1 requires and
/// which is worth stating because it is the opposite of the safe-looking
/// default — every real client sends the header.
///
/// The quota pair is not decoration: without `quota-available-bytes` Finder
/// reads zero free space and refuses every copy before it starts. It is measured
/// through the same functions the write path enforces with, so the property and
/// the enforcement cannot disagree.
async fn propfind_answer(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    body: &[u8],
) -> Response {
    let depth = match propfind::depth(request.headers.get_str("depth")) {
        Ok(depth) => depth,
        Err(_) => return method::status_only(Status::BAD_REQUEST),
    };
    if depth == Depth::Infinity {
        return propfind::depth_infinity_refused();
    }
    let requested = match propfind::parse(body) {
        Ok(requested) => requested,
        Err(_) => return method::status_only(Status::BAD_REQUEST),
    };
    let target = match located(wiring, caller, request.path(), Wants::Read) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };

    let webdav = Arc::clone(&wiring.webdav);
    let Located { volume, mount, at, who } = target;
    let share = volume.share().id().as_str().to_owned();
    let built = blocking(move || {
        let attributes = volume.stat(&who, &at)?;
        let here = lock::Resource::new(&share, at.clone());
        let mut resources = vec![propfind::Resource::new(
            at.clone(),
            attributes.kind,
            attributes.size,
            attributes.modified,
        )
        .with_locks(webdav.locks().discover(&here))];

        if depth == Depth::One && attributes.kind == Kind::Directory {
            for entry in &volume.listing(&who, &at)?.entries {
                // `from_entry` is the one-way door: an entry with no servable
                // URL is skipped rather than given an `href` that would resolve
                // to something else.
                if let Some(resource) = propfind::Resource::from_entry(&at, entry) {
                    let held =
                        webdav.locks().discover(&lock::Resource::new(&share, resource.path.clone()));
                    resources.push(resource.with_locks(held));
                }
            }
        }

        // `None` rather than a guess when the volume cannot be measured: a
        // fabricated zero would tell Finder the share is full.
        let quota = volume.quota().ok().map(|(available, used)| Quota { available, used });
        Ok(propfind::respond(&mount, &resources, &requested, quota))
    })
    .await;
    built.unwrap_or_else(|failure| failed(Verb::PropFind, &failure))
}

/// Answers `PROPPATCH`: a `207` saying, per property, that nothing was written.
///
/// This build has no dead-property store and does not apply the Win32 times
/// Explorer sends after every `PUT`, so each property is answered `403`. The
/// alternative — answering `200` to a property we did not store — is a server
/// telling a client that a timestamp was preserved when it was not, and this
/// project does not make that trade anywhere else either.
///
/// The resource is stated first, so a `PROPPATCH` of something that is not there
/// is a `404` rather than a `207` full of refusals about a file that does not
/// exist.
async fn proppatch_answer(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    body: &[u8],
) -> Response {
    let target = match located(wiring, caller, request.path(), Wants::Write) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };
    if let Err(denied) = guard(wiring, &target, request) {
        return denied.response();
    }
    let Located { volume, mount, at, who } = target;
    let body = body.to_vec();
    let stated = blocking(move || {
        let attributes = volume.stat(&who, &at)?;
        // The `href` comes from the mount, which encodes every segment. There is
        // no way to spell one here and there must not be.
        Ok(method::proppatch(&mount.href(&at, attributes.kind), &body))
    })
    .await;
    stated.unwrap_or_else(|failure| failed(Verb::PropPatch, &failure))
}

/// Answers `MKCOL`: one directory, never a tree.
///
/// A body is `415`, which RFC 4918 §9.3 requires: this server implements no
/// extended `MKCOL`, and quietly ignoring a body would create a collection that
/// is not the one the client asked for.
///
/// Only the last segment is created. A `MKCOL` that invented intermediate
/// collections would turn a typo into a tree, and §9.3.1 requires `409` when the
/// parent is missing — which is also what the console's folder button does, so
/// the two protocols cannot disagree.
async fn mkcol_answer(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    body: &[u8],
) -> Response {
    if !body.is_empty() {
        return method::status_only(method::UNSUPPORTED_MEDIA_TYPE);
    }
    let target = match located(wiring, caller, request.path(), Wants::Write) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };
    if let Err(denied) = guard(wiring, &target, request) {
        return denied.response();
    }
    let Located { volume, mount, at, who } = target;
    let made = blocking(move || {
        volume.create_directory(&who, &at)?;
        Ok(method::created(&mount.href(&at, Kind::Directory)))
    })
    .await;
    made.unwrap_or_else(|failure| failed(Verb::MkCol, &failure))
}

/// Answers `DELETE`: depth-infinity on a collection, which is what §9.6 means
/// and what a person means by the delete button.
///
/// The share root cannot be deleted: it has no last segment, so the storage
/// engine refuses it before anything is removed. That is a property of the
/// resolver rather than a check here, which is the right place for it — a check
/// here would be a second rule that could drift from the first.
async fn delete_answer(wiring: &Wiring<'_>, caller: &Caller, request: &Request) -> Response {
    let target = match located(wiring, caller, request.path(), Wants::Write) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };
    if let Err(denied) = guard(wiring, &target, request) {
        return denied.response();
    }
    let Located { volume, at, who, .. } = target;
    let removed = blocking(move || {
        volume.delete(&who, &at)?;
        Ok(method::status_only(method::NO_CONTENT))
    })
    .await;
    removed.unwrap_or_else(|failure| failed(Verb::Delete, &failure))
}

/// Answers `COPY` and `MOVE`.
///
/// **The `Destination` header is a second attacker-controlled path and gets the
/// identical treatment as the request line.** It goes through
/// [`method::destination`], which funnels it back into the same
/// [`Volume::resolve`] the request line goes through, and then through the
/// *destination* share's own capability check, its own read-only flag and its
/// own lock. A `MOVE` whose destination escapes its root is a write-anywhere
/// primitive as complete as a traversal, and `Overwrite: T` compounds it.
///
/// The destination's authority is compared against the console site's configured
/// hostname rather than the request's `Host`, because the proxy's relay forwards
/// no `Host` and a host the client chose would make the comparison meaningless.
/// A mismatch is `502`, which is what §9.8.3 asks for and what tells a client to
/// perform the copy itself.
async fn transfer_answer(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    verb: Verb,
) -> Response {
    let Some(replace) = method::overwrite(request.headers.get_str("overwrite")) else {
        // Neither `T` nor `F`. Guessing at a third spelling means guessing
        // whether the client meant to destroy something.
        return method::status_only(Status::BAD_REQUEST);
    };
    let asked = match method::destination(request.headers.get_str("destination"), wiring.host) {
        Ok(asked) => asked,
        Err(bad) => return method::status_only(bad.status()),
    };

    let source = match located(wiring, caller, request.path(), wants(verb)) {
        Ok(source) => source,
        Err(denied) => return denied.response(),
    };
    // The destination is named by its own `/dav/<share>/<path>`, rebuilt so it
    // reaches exactly the function the request line reached.
    let destination_path = format!("{DAV_PREFIX}{}{}", asked.share, asked.path);
    let destination = match located(wiring, caller, &destination_path, Wants::Write) {
        Ok(destination) => destination,
        // A destination naming no share is `409`, not `404`: §9.8.5 makes a
        // destination whose parent does not exist a conflict, and a client reads
        // `404` as a statement about the resource it is copying *from*.
        Err(Denied::NoShare) => return method::status_only(method::CONFLICT),
        Err(denied) => return denied.response(),
    };

    // Both ends, because a move writes to its destination as surely as to its
    // source and a copy writes to its destination alone.
    if verb == Verb::Move {
        if let Err(denied) = guard(wiring, &source, request) {
            return denied.response();
        }
    }
    if let Err(denied) = guard(wiring, &destination, request) {
        return denied.response();
    }

    let replace = replace == Overwrite::Allowed;
    let Located { volume, at: from, who, .. } = source;
    let Located { volume: into, mount, at: to, .. } = destination;
    let moved = blocking(move || {
        // The source's kind decides the destination's `href`: a collection's
        // link ends in a slash, and Finder builds a child's URL by appending to
        // it, so a collection served without one produces children a directory
        // too high.
        let kind = volume.stat(&who, &from)?.kind;
        let landing = if verb == Verb::Move {
            volume.move_to(&who, &from, &into, &to, replace)?
        } else {
            volume.copy_to(&who, &from, &into, &to, replace)?
        };
        Ok(match landing {
            selfhost_storage::api::Landing::Created => method::created(&mount.href(&to, kind)),
            selfhost_storage::api::Landing::Replaced => method::status_only(method::NO_CONTENT),
        })
    })
    .await;
    moved.unwrap_or_else(|failure| failed(verb, &failure))
}

/// Answers `LOCK`: a real exclusive lock, and the reason the mount is writable.
///
/// Both the Windows Mini-Redirector and macOS WebDAVFS lock before every write
/// and mount read-only without `DAV: 1, 2`. So this is not a formality, and the
/// lock it grants is not the twenty-line fake that would have satisfied both
/// clients right up until two of them edited one file — the exclusion is
/// [`Locks::take`]'s and it is symmetric in both directions.
///
/// An empty body is a **refresh**, not a new lock: the client is asking to
/// extend a lock it already holds and names in its `If` header. Treating it as a
/// new lock would mint a second lock over the first and then refuse the client's
/// own writes with `423`.
///
/// A `LOCK` on a name that does not exist is granted and answered `201`, which
/// RFC 4918 §7.3 calls a lock-null resource. That is not permissiveness: it is
/// exactly what Windows does before it creates a file, and refusing it makes
/// every new document on a Windows mount fail.
async fn lock_answer(
    wiring: &Wiring<'_>,
    caller: &Caller,
    request: &Request,
    body: &[u8],
) -> Response {
    let info = match lock::parse_lockinfo(body) {
        Ok(info) => info,
        Err(lock::BodyError::Unsupported) => return lock::scope_unsupported(),
        Err(_) => return method::status_only(Status::BAD_REQUEST),
    };
    let target = match located(wiring, caller, request.path(), Wants::Read) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };
    let seconds = lock::timeout(request.headers.get_str("timeout"));
    let locks = wiring.webdav.locks();

    let Some(info) = info else {
        // A refresh. The token comes from the `If` header, and a token naming no
        // live lock is `412`: the client stated a precondition — *I hold this
        // lock* — that is not true.
        let submitted = lock::submitted_tokens(request.headers.get_str("if"));
        return submitted
            .iter()
            .find_map(|token| locks.refresh(token, seconds))
            .map_or_else(
                || method::status_only(method::PRECONDITION_FAILED),
                |lock| lock::granted(&target.mount, &lock),
            );
    };
    if !info.exclusive || !info.write {
        // Refused rather than quietly upgraded. A client that asked for a lock
        // several writers may hold and received one only it may hold would
        // behave correctly; one that asked for exclusivity and got a shared lock
        // would not, and a server that blurs the two eventually does the second.
        return lock::scope_unsupported();
    }
    let Some(reach) = Reach::parse(request.headers.get_str("depth")) else {
        return method::status_only(Status::BAD_REQUEST);
    };

    // Whether the name exists decides `200` against `201`, and nothing else: the
    // lock is granted either way.
    let existed = {
        let volume = Arc::clone(&target.volume);
        let who = target.who.clone();
        let at = target.at.clone();
        blocking(move || Ok(volume.stat(&who, &at).is_ok())).await.unwrap_or(false)
    };

    match locks.take(target.resource(), reach, info.owner, seconds) {
        Ok(lock) => {
            let mut response = lock::granted(&target.mount, &lock);
            if !existed {
                response.status = method::CREATED;
            }
            response
        }
        Err(TakeRefused::Conflict { holder }) => Denied::Locked { holder }.response(),
        Err(refused) => method::status_only(refused.status()),
    }
}

/// Answers `UNLOCK`.
///
/// The resource is checked as well as the token, so a client cannot release a
/// lock by naming the right token at the wrong URL — which matters because the
/// token is the capability and the URL is what an operator reads in a log. A
/// token naming no lock here is `409`, per §9.11.1.
async fn unlock_answer(wiring: &Wiring<'_>, caller: &Caller, request: &Request) -> Response {
    let Some(token) = coded_url(request.headers.get_str("lock-token")) else {
        return method::status_only(Status::BAD_REQUEST);
    };
    let target = match located(wiring, caller, request.path(), Wants::Read) {
        Ok(target) => target,
        Err(denied) => return denied.response(),
    };
    match wiring.webdav.locks().release(&target.resource(), &token) {
        Release::Released => method::status_only(method::NO_CONTENT),
        Release::NotHeld | Release::WrongResource => method::status_only(method::CONFLICT),
    }
}

/// Reads a `Lock-Token: <urn:uuid:…>` header.
///
/// The angle brackets are part of the grammar (§10.5) rather than decoration,
/// and they are stripped here rather than compared with: a client that sends the
/// bare URN is spelling the header wrongly, and accepting both spellings costs
/// one line and saves a mount.
fn coded_url(header: Option<&str>) -> Option<String> {
    let value = header?.trim();
    let inner = value.strip_prefix('<').and_then(|rest| rest.strip_suffix('>')).unwrap_or(value);
    (!inner.is_empty()).then(|| inner.to_string())
}

/// Runs a blocking filesystem operation off the runtime.
///
/// A local copy of [`crate::storage_api`]'s, and for the same reason it exists
/// there: every call into a [`Volume`] is a synchronous filesystem call, and run
/// on a runtime worker it would stall every other connection the daemon is
/// serving. A join failure is surfaced rather than unwrapped so a test build
/// cannot hide a real fault behind a second one.
async fn blocking<T, F>(work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, Failure> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => Err(Failure::Io(format!("the filesystem task did not finish: {error}"))),
    }
}

// ─── The byte plane ──────────────────────────────────────────────────────────

/// Serves a `GET`, `HEAD` or `PUT` over the connection that asked for it.
///
/// The only function here that owns a socket. It writes its own response head,
/// because a download's head is built by `selfhost_storage::respond` from the
/// **already-open handle's** metadata rather than from a `stat` that could
/// describe a different file by the time the bytes are read.
///
/// `prefix` is whatever the request reader took off the socket past the head. It
/// is the first of the body and it must not be dropped: an upload that ignored
/// it would corrupt every file whose first bytes arrived in the same segment as
/// the headers, which is most of them.
pub async fn serve<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    request: &Request,
    passage: Passage,
) -> std::io::Result<crate::storage_api::Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Passage { target, verb, declared } = passage;
    let Located { volume, mount, at, who } = target;
    let placement = crate::storage_api::Placement { volume, who, at };
    match verb {
        Verb::Put => upload(stream, prefix, placement, &mount, declared).await,
        // `Disposition::Attachment`, pinned exactly as `method::blob` pins it
        // and not a parameter here: `/dav` is served from the console's own
        // origin, and a file a caller uploaded and then persuaded a browser to
        // render inline on that origin is stored cross-site scripting with the
        // console as its target.
        _ => {
            crate::storage_api::download_bytes(
                stream,
                request,
                placement,
                selfhost_storage::respond::Disposition::Attachment,
                &|failure| failed(Verb::Get, failure),
            )
            .await
        }
    }
}

/// Receives a `PUT`, streaming it to a temporary name and publishing it
/// atomically at the end.
///
/// `201` when the name was free and `204` when it was taken, which is what
/// §9.7.1 requires and what a client uses to decide whether to refresh its view.
/// The existence check is a separate `stat` and is therefore a race — with
/// itself only: whichever answer it gives, the bytes land in the same place, and
/// the worst outcome is a `201` for a file that another writer created a
/// millisecond earlier. Paying for a rename that reported what it replaced would
/// mean a different primitive on each platform.
///
/// Nothing here ever holds the body. The work is
/// [`crate::storage_api::upload_bytes`], which owns the socket-to-disk feed and
/// is shared with the JSON bulk plane so the two protocols cannot come to
/// disagree about backpressure, quota or what a truncated body does.
async fn upload<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    placement: crate::storage_api::Placement,
    mount: &Mount,
    declared: u64,
) -> std::io::Result<crate::storage_api::Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let existed = {
        let volume = Arc::clone(&placement.volume);
        let who = placement.who.clone();
        let at = placement.at.clone();
        blocking(move || Ok(volume.stat(&who, &at).is_ok())).await.unwrap_or(false)
    };
    let created = method::created(&mount.href(&placement.at, Kind::File));
    let landed = if existed { method::status_only(method::NO_CONTENT) } else { created };

    crate::storage_api::upload_bytes(
        stream,
        prefix,
        placement,
        // `PUT` replaces, which is what the verb means in HTTP and what every
        // WebDAV client expects; `Overwrite` is a `COPY`/`MOVE` header and has
        // no bearing here.
        Existing::Replace,
        declared,
        crate::storage_api::Answers {
            landed,
            truncated: method::status_only(Status::BAD_REQUEST),
            failed: &|failure| failed(Verb::Put, failure),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mount_prefix_is_matched_at_a_segment_boundary() {
        assert!(is_dav_path("/dav"));
        assert!(is_dav_path("/dav/"));
        assert!(is_dav_path("/dav/vault/tax/2019.pdf"));
        assert!(!is_dav_path("/davos"));
        assert!(!is_dav_path("/dav-share"));
        assert!(!is_dav_path("/api/storage/blob/vault/x"));
    }

    #[test]
    fn a_dav_path_splits_into_a_share_and_an_untouched_remainder() {
        assert_eq!(split_dav("/dav/vault/a/b.txt"), Some(("vault", "a/b.txt")));
        // The share root is a share, and every client asks about it first.
        assert_eq!(split_dav("/dav/vault"), Some(("vault", "")));
        assert_eq!(split_dav("/dav/vault/"), Some(("vault", "")));
        // Handed on exactly as it arrived: cleaning it here would be the
        // security rule enforced in two places.
        assert_eq!(split_dav("/dav/vault/%2e%2e/etc"), Some(("vault", "%2e%2e/etc")));
        assert_eq!(split_dav("/dav"), None);
        assert_eq!(split_dav("/dav/"), None);
        assert_eq!(split_dav("/api/storage/shares"), None);
    }

    #[test]
    fn the_challenge_names_one_unchanging_realm_and_pins_the_encoding() {
        let response = unauthenticated();
        assert_eq!(response.status.code(), 401);
        let challenge = response.headers.get_str("www-authenticate").expect("a challenge");
        assert!(challenge.starts_with("Basic realm="), "{challenge}");
        assert!(challenge.contains("charset=\"UTF-8\""), "{challenge}");
        // Byte-for-byte the same on every refusal: Finder and Windows key their
        // stored credential on the realm, and one that varied would re-prompt
        // for ever.
        assert_eq!(
            unauthenticated().headers.get_str("www-authenticate"),
            Some(challenge),
            "the challenge is a constant"
        );
    }

    #[test]
    fn every_verb_lands_on_the_capability_its_effect_deserves() {
        for verb in [
            Verb::Options,
            Verb::PropFind,
            Verb::Get,
            Verb::Head,
            Verb::Lock,
            Verb::Unlock,
            // A copy *out of* a read-only share is an ordinary request; the
            // destination is asked for `Write` separately, and it is a
            // different share with different rules.
            Verb::Copy,
        ] {
            assert_eq!(wants(verb), Wants::Read, "{verb:?}");
        }
        for verb in [Verb::PropPatch, Verb::MkCol, Verb::Put, Verb::Delete, Verb::Move] {
            assert_eq!(wants(verb), Wants::Write, "{verb:?}");
        }
    }

    #[test]
    fn the_three_statuses_webdav_spells_differently_are_spelled_differently() {
        assert_eq!(dav_status(Verb::MkCol, &Failure::Occupied).code(), 405);
        assert_eq!(dav_status(Verb::Copy, &Failure::Occupied).code(), 412);
        assert_eq!(dav_status(Verb::Move, &Failure::Occupied).code(), 412);
        assert_eq!(
            dav_status(Verb::Move, &Failure::Collides { existing: "Report.pdf".into() }).code(),
            412
        );
        // Everything else keeps the storage crate's own answer, so the two
        // protocols agree wherever they can.
        assert_eq!(dav_status(Verb::Put, &Failure::NoParent).code(), 409);
        assert_eq!(dav_status(Verb::Delete, &Failure::NotFound).code(), 404);
        assert_eq!(dav_status(Verb::Get, &Failure::Occupied).code(), 409);
    }

    #[test]
    fn a_lock_token_header_is_read_with_or_without_its_brackets() {
        assert_eq!(coded_url(Some("<urn:uuid:abc>")).as_deref(), Some("urn:uuid:abc"));
        assert_eq!(coded_url(Some(" urn:uuid:abc ")).as_deref(), Some("urn:uuid:abc"));
        assert_eq!(coded_url(Some("<>")), None);
        assert_eq!(coded_url(Some("")), None);
        assert_eq!(coded_url(None), None);
    }

    #[test]
    fn a_refusal_after_authentication_is_never_a_401() {
        // The rule that makes a mount usable: macOS and Windows read a second
        // `401` as "the stored password is wrong" and prompt for ever.
        for denied in [
            Denied::NoShare,
            Denied::NotPermitted,
            Denied::Refused(Failure::NotFound),
            Denied::Unframed("no length"),
            Denied::Locked { holder: "a/b".into() },
        ] {
            assert_ne!(denied.response().status.code(), 401, "{denied}");
        }
    }

    #[test]
    fn a_refusal_never_carries_the_path_it_refused() {
        // On a NAS the file names are the data, and this string reaches a log.
        let refused = Denied::Refused(Failure::Refused(
            selfhost_storage::path::Refusal::Traversal,
        ));
        assert!(!format!("{refused}").contains('/'), "{refused}");
    }
}
