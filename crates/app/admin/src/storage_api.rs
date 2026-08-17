//! Where the storage subsystem meets the control API.
//!
//! `selfhost-storage` is a whole NAS with no socket in it: [`Volume`] opens a
//! declared share, resolves an attacker-chosen path against it, and refuses or
//! performs one operation. This module is the other half — the part that knows
//! about requests, capabilities and a tokio runtime — and it is deliberately
//! thin, because everything worth attacking lives on the other side of the seam
//! and is tested there without a port.
//!
//! # Two planes, and why they are not one
//!
//! The **control plane** is ordinary JSON: what shares exist, what one directory
//! holds, make a folder, rename, delete. Every one of those is small enough to
//! answer through [`Api::handle`](crate::Api::handle), which takes a request and
//! returns a response and touches no socket. That property is the reason every
//! route in this crate is testable, including every way of getting the
//! authorisation wrong, and it is not negotiable.
//!
//! The **bulk plane** is `GET` and `PUT` on `/api/storage/blob/…`, and it cannot
//! be expressed that way. A download is gigabytes read from a descriptor; an
//! upload is gigabytes arriving on a socket that must reach a temporary file
//! without ever being a `Vec`. So the split is drawn the same place
//! [`crate::stream`] draws it: [`Api::bulk_for`](crate::Api::bulk_for) is a pure
//! function over the request head that says *whether, and to what*, and
//! `download` and `upload` are the only things here that own bytes.
//!
//! # Everything in this file blocks, and none of it blocks the runtime
//!
//! A descriptor walk, a `stat`, a directory read, a rename, a subtree measure —
//! every call into [`Volume`] is a synchronous filesystem call. Run on a runtime
//! worker they would stall every other connection the daemon is serving, so each
//! one is handed to [`tokio::task::spawn_blocking`] and the `Volume` is held in
//! an [`Arc`] precisely so it can be. The upload path goes further and moves the
//! [`selfhost_storage::Receiver`] itself onto a blocking task, fed through a
//! bounded channel, so
//! the socket read and the disk write overlap without either one running on the
//! other's thread.
//!
//! # Two permission layers, and why both are real
//!
//! A caller reaching a share passes **two** independent checks, and neither is a
//! restatement of the other:
//!
//! 1. **The capability**, decided here by
//!    [`Policy::decide`](selfhost_identity::Policy::decide) against
//!    [`Capability::FilesRead`] or [`Capability::FilesWrite`] for that share id.
//!    This is the deployment's own model — the one the console's PEOPLE plate
//!    edits, the one the audit log records, and the one that answers with the
//!    uniform 401.
//! 2. **The share's own access list**, `[[shares.access]]`, decided inside
//!    [`Volume`] on every single operation rather than at the route. This one
//!    also carries `read_only`, which is a statement about the *data* and binds
//!    the owner too.
//!
//! The consequence an operator has to know, and which the console must say: a
//! named person needs an entry in **both**. Today the two are declared in two
//! places — a capability in `console.people`, a grant in the `[[shares.access]]`
//! block — and a person with one and not the other is refused. Projecting the
//! config block into the registry at start-up is the right end state and is
//! written down as a follow-up rather than half-built here; the owner is
//! unaffected either way, because [`selfhost_identity::Policy::decide`] never
//! consults an owner's
//! grants and [`Share::permits`](selfhost_storage::share::Share::permits) treats
//! the owner as holding every mode.
//!
//! # Paths are the sensitive thing, so nothing here logs one
//!
//! On a NAS the file names *are* the data: a log line naming
//! `tax/2019 return.pdf` has disclosed the household's affairs to anyone who can
//! read the log, without ever disclosing a byte of the file. The proxy already
//! elides the remainder of `/api/storage/blob/…` from its access log
//! (`proxy::upgrade::loggable_target`), and this module holds the same rule on
//! this side of loopback: a transfer that is worth a line is logged by share id
//! and byte count, never by name.

use crate::{Demand, problem};
use selfhost_config::{AccessMode, ShareConfig};
use selfhost_http::{Body, Method, Request, Response, Status};
use selfhost_identity::{Capability, Identity, ShareId};
use selfhost_json::Json;
use selfhost_storage::api::{Failure, Sessions, Volume};
use selfhost_storage::fs::{Existing, OpenError};
use selfhost_storage::path::RelativePath;
use selfhost_storage::quota::Ledger;
use selfhost_storage::respond::Disposition;
use selfhost_storage::share::{Grant, Mode, Reserved, Share, ShareError, SmbExport, SmbName};
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How many bytes are moved between the socket and the disk at a time.
///
/// The same 64 KiB the storage crate copies with. Fixed rather than derived from
/// the declared length, which is the whole point: a client may declare a hundred
/// gigabytes and this process allocates sixty-four kilobytes either way.
const CHUNK: usize = 64 * 1024;

/// How many chunks may be in flight between the socket reader and the disk
/// writer.
///
/// Small on purpose. The queue exists so a fast network and a slow disk overlap,
/// not so an upload can buffer; four chunks is a quarter of a megabyte of
/// give, and past that the socket read simply waits, which is backpressure
/// arriving where it belongs — at the sender.
const FEED_DEPTH: usize = 4;

/// The largest `Content-Length` this API will accept on a bulk upload.
///
/// # Why there is a number here at all
///
/// The real ceilings on an upload are the share's quota, the volume's free space
/// and the deployment's in-flight budget, and all three are enforced as the
/// bytes land rather than from a header the client wrote. This is not those. It
/// is a sanity bound on a claim, refused before a temporary file is created, so
/// that a declared exabyte costs one response rather than an open descriptor and
/// a reservation.
///
/// # What actually limits a browser upload today
///
/// **Less than this.** The proxy relays the console site's `/api/*` through
/// `relay_console_api`, which buffers a body with `take_body` and refuses
/// anything over `CONSOLE_API_MAX_BODY` — 64 KiB — at
/// `crates/proxy/src/server.rs:846`. Until that route learns to stream a fixed
/// length straight through for the `/api/storage/blob/` prefix, an upload from a
/// browser is capped at 64 KiB by the relay and never reaches this cap. The
/// direct loopback path — the native console over its SSH tunnel — has no such
/// limit, which is why this number is generous rather than 64 KiB: the admin API
/// must not be the thing that has to change when the relay is fixed.
pub const BULK_MAX_BODY: u64 = 64 * 1024 * 1024 * 1024;

/// The path prefix every bulk transfer sits under.
///
/// One constant, and it is the same string the proxy elides from its access log.
pub const BLOB_PREFIX: &str = "/api/storage/blob/";

/// Every share this daemon serves, opened once.
///
/// Built at startup rather than per request, because the open root descriptor is
/// what every walk begins from: re-opening it on each call would put a by-path
/// open back on the hot path, which is the thing `selfhost_storage::fs` exists
/// to remove. A daemon with no `[[shares]]` block has no `Volumes` at all and
/// answers every storage route with the same uninformative 401 as an
/// unauthenticated caller — see this crate's `Demand::Unsatisfiable`.
#[derive(Debug, Clone)]
pub struct Volumes {
    /// The opened shares, in the order they were declared, each shared with
    /// whatever blocking task is currently walking it.
    volumes: Vec<Arc<Volume>>,
    /// The resumable-upload sessions, one set for the whole daemon.
    uploads: Arc<Sessions>,
}

impl Volumes {
    /// Opens every declared share, or names the first one that cannot be served.
    ///
    /// Fails loudly and at startup on purpose. A share whose root does not
    /// exist, or that is rooted somewhere `reserved` protects, is an operator
    /// mistake with a security consequence, and the moment to say so is before
    /// the daemon is answering requests rather than on the first one that
    /// happens to touch it.
    pub fn open(shares: &[ShareConfig], reserved: &Reserved) -> Result<Self, Unusable> {
        let ledger = Arc::new(Ledger::new());
        let mut volumes = Vec::with_capacity(shares.len());
        for declared in shares {
            let share = share_from_config(declared, reserved)
                .map_err(|error| Unusable::Declared { id: declared.id.clone(), error })?;
            let volume = Volume::open(share, Arc::clone(&ledger))
                .map_err(|error| Unusable::Unopenable { id: declared.id.clone(), error })?;
            volumes.push(Arc::new(volume));
        }
        Ok(Self { volumes, uploads: Arc::new(Sessions::new()) })
    }

    /// The same, from volumes a test opened itself.
    ///
    /// The seam that keeps this module testable: building a `Volumes` from
    /// config needs a real directory tree and a real `Reserved`, and a test that
    /// only wants to assert a route's authorisation should not have to build
    /// either.
    pub fn from_opened(volumes: Vec<Volume>) -> Self {
        Self {
            volumes: volumes.into_iter().map(Arc::new).collect(),
            uploads: Arc::new(Sessions::new()),
        }
    }

    /// The share with this id, if this daemon serves one.
    pub fn find(&self, id: &str) -> Option<&Arc<Volume>> {
        self.volumes.iter().find(|volume| volume.share().id().as_str() == id)
    }

    /// Every opened share, in declaration order.
    pub fn all(&self) -> &[Arc<Volume>] {
        &self.volumes
    }

    /// The resumable-upload sessions this daemon holds.
    pub fn uploads(&self) -> &Arc<Sessions> {
        &self.uploads
    }

    /// How many shares are served.
    pub fn len(&self) -> usize {
        self.volumes.len()
    }

    /// Whether no share is served.
    pub fn is_empty(&self) -> bool {
        self.volumes.is_empty()
    }
}

/// Why a declared share could not be served.
///
/// Carries the share's id in both variants, because an operator reading a
/// startup failure needs to know *which* `[[shares]]` block to go and edit, and
/// a message naming only a path does not say that when two shares differ by one
/// directory.
#[derive(Debug)]
pub enum Unusable {
    /// The declaration itself is refused — a bad id, a relative root, a root
    /// overlapping something this deployment protects.
    Declared {
        /// The `id` key of the offending block.
        id: String,
        /// What the share model refused, and why.
        error: ShareError,
    },
    /// The declaration is sound and the directory is not there, is not a
    /// directory, or cannot be opened.
    Unopenable {
        /// The `id` key of the offending block.
        id: String,
        /// What the filesystem said.
        error: OpenError,
    },
}

impl fmt::Display for Unusable {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared { id, error } => write!(out, "share \"{id}\" is not usable: {error}"),
            Self::Unopenable { id, error } => write!(out, "share \"{id}\" cannot be opened: {error}"),
        }
    }
}

impl std::error::Error for Unusable {}

/// Turns one `[[shares]]` block into the checked share the storage crate serves.
///
/// The conversion lives here rather than in `selfhost-config`, which never
/// depends on a subsystem crate, and rather than in `selfhost-storage`, which
/// never depends on config. Both halves already exist; this is the twenty lines
/// that join them, and it is pure.
///
/// Note what is *not* copied across: nothing. Every field of the declaration is
/// carried, and the two that need checking — the SMB name and each grantee's
/// name — go through the storage crate's own parsers rather than being trusted
/// because config already looked at them. Config checks shape at load so an
/// operator gets a message; this checks it again because a value that reaches a
/// command line or a permission decision is checked by whoever uses it.
pub fn share_from_config(declared: &ShareConfig, reserved: &Reserved) -> Result<Share, ShareError> {
    let mut share = Share::new(
        reserved,
        &declared.id,
        declared.root.clone(),
        declared.read_only,
        declared.browsable,
        declared.quota_bytes,
    )?;
    if let Some(smb) = &declared.smb {
        share = share.with_smb(SmbExport {
            name: SmbName::parse(&smb.name)?,
            encrypt: smb.encrypt,
            read_only: smb.read_only,
        });
    }
    let mut grants = Vec::with_capacity(declared.access.len());
    for access in &declared.access {
        grants.push(Grant::parse(&access.user, mode_of(access.mode))?);
    }
    Ok(share.with_grants(grants))
}

/// The storage crate's mode for a config access mode.
///
/// Two enums with the same three variants, one in each crate, because neither
/// crate may depend on the other. A `match` rather than a cast, so adding a mode
/// to either side is a build error rather than a silent misgrant.
fn mode_of(mode: AccessMode) -> Mode {
    match mode {
        AccessMode::Read => Mode::Read,
        AccessMode::Write => Mode::Write,
        AccessMode::Admin => Mode::Admin,
    }
}

/// What a storage route demands of its caller.
///
/// The bridge between a URL segment and the capability vocabulary, and the one
/// place a share id becomes a [`ShareId`]. An id that is not a legal share id
/// cannot name a share this deployment serves, so it yields
/// [`Demand::Unsatisfiable`] — the uniform 401 — rather than a 404: a refusal
/// that distinguishes "no such share" from "not yours" is a way to enumerate
/// what exists behind the wall.
pub(crate) fn demand(id: &str, want: Wants) -> Demand {
    match ShareId::parse(id) {
        Ok(share) => Demand::Held(match want {
            Wants::Read => Capability::FilesRead(share),
            Wants::Write => Capability::FilesWrite(share),
        }),
        Err(_) => Demand::Unsatisfiable,
    }
}

/// Which half of the share capability ladder a route sits on.
///
/// Deliberately not `selfhost_storage::share::Want`: that enum answers what the
/// *share* is being asked for, including `Admin`, which no route here exercises.
/// This one names only what the *capability check* needs, so a route cannot ask
/// for a power the API does not serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wants {
    /// Listing and downloading.
    Read,
    /// Creating, replacing, moving and deleting.
    Write,
}

/// Answers `GET /api/storage/shares`.
///
/// Reports only the shares this caller may read, which is the same pattern
/// `POST /api/desktop/ticket` follows: the route's own demand is a floor
/// ([`Capability::ConsoleRead`]), and each item is decided separately against
/// its own capability. A caller who holds nothing therefore gets an empty list
/// rather than a refusal — they are authenticated and they may read the console,
/// and the honest answer to "what may I open" is "nothing", not "no".
///
/// Usage is measured through the ledger's cache, so a console refreshing this
/// panel does not walk every share's subtree on every poll.
pub async fn shares(volumes: &Volumes, who: &Identity, may: &(dyn Fn(&Capability) -> bool + Sync)) -> Response {
    let mut visible = Vec::new();
    for volume in volumes.all() {
        // The two crates each own a checked share-id newtype and neither
        // depends on the other, so the identity crate's is re-parsed from the
        // storage crate's text. It cannot fail — both grammars are the same
        // token — and the `else` branch skips rather than unwraps, because
        // under `panic = "abort"` an impossible branch that panics is a whole
        // box outage waiting for the day the two grammars drift.
        let Ok(id) = ShareId::parse(volume.share().id().as_str()) else {
            continue;
        };
        if !may(&Capability::FilesRead(id)) {
            continue;
        }
        visible.push(Arc::clone(volume));
    }
    let who = who.clone();
    let described = blocking(move || {
        Ok(Json::array(visible.iter().map(|volume| describe(volume, &who))))
    })
    .await;
    match described {
        Ok(shares) => ok(Json::object([("shares", shares)])),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// One share as the console draws it.
///
/// Usage is reported as `null` rather than omitted when it cannot be measured —
/// a share on a disk that has just been unplugged is still a declared share, and
/// a panel that hides it would be telling the operator their configuration
/// changed when what changed is the hardware.
fn describe(volume: &Arc<Volume>, who: &Identity) -> Json {
    let share = volume.share();
    let (available, used) = match volume.quota() {
        Ok(pair) => (Json::Number(pair.0 as f64), Json::Number(pair.1 as f64)),
        Err(_) => (Json::Null, Json::Null),
    };
    Json::object([
        ("id", Json::string(share.id().as_str())),
        ("readOnly", Json::Bool(share.read_only())),
        ("browsable", Json::Bool(share.browsable())),
        (
            "quotaBytes",
            share.quota_bytes().map_or(Json::Null, |bytes| Json::Number(bytes as f64)),
        ),
        ("availableBytes", available),
        ("usedBytes", used),
        (
            "smb",
            share.smb().map_or(Json::Null, |smb| {
                Json::object([
                    ("name", Json::string(smb.name.as_str())),
                    ("encrypt", Json::Bool(smb.encrypt)),
                    ("readOnly", Json::Bool(share.smb_read_only())),
                ])
            }),
        ),
        // What *this* caller may do with it, so the console can grey a button
        // rather than offer one that will be refused.
        (
            "writable",
            Json::Bool(
                !share.read_only()
                    && volume
                        .permit(who, selfhost_storage::share::Want::Write)
                        .is_ok(),
            ),
        ),
    ])
}

/// Answers `GET /api/storage/shares/<id>/list?path=…`.
pub async fn list(volume: &Arc<Volume>, who: &Identity, path: &str) -> Response {
    let volume = Arc::clone(volume);
    let who = who.clone();
    let at = match volume.resolve(path) {
        Ok(at) => at,
        Err(failure) => return selfhost_storage::api::failed(&failure),
    };
    match blocking(move || volume.listing(&who, &at)).await {
        Ok(listing) => selfhost_storage::api::listed(&listing),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// Answers `GET /api/storage/shares/<id>/stat?path=…`.
pub async fn stat(volume: &Arc<Volume>, who: &Identity, path: &str) -> Response {
    let volume = Arc::clone(volume);
    let who = who.clone();
    let at = match volume.resolve(path) {
        Ok(at) => at,
        Err(failure) => return selfhost_storage::api::failed(&failure),
    };
    let reported = at.clone();
    match blocking(move || volume.stat(&who, &at)).await {
        Ok(attributes) => selfhost_storage::api::stated(&reported, &attributes),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// Answers `POST /api/storage/shares/<id>/mkdir`.
///
/// One directory, never a tree: a `mkdir` that created intermediate
/// directories would turn a typo into a folder, and it would disagree with
/// WebDAV's `MKCOL`, which RFC 4918 §9.3.1 requires to answer `409` when the
/// parent is missing. The two protocols must not disagree about what the same
/// button does.
pub async fn mkdir(volume: &Arc<Volume>, who: &Identity, body: &[u8]) -> Response {
    let Some(path) = string_field(body, "path") else {
        return problem(Status(400), "body must be JSON with a \"path\" string");
    };
    let volume = Arc::clone(volume);
    let who = who.clone();
    let at = match volume.resolve(&path) {
        Ok(at) => at,
        Err(failure) => return selfhost_storage::api::failed(&failure),
    };
    match blocking(move || volume.create_directory(&who, &at)).await {
        Ok(()) => selfhost_storage::api::done(),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// Answers `DELETE /api/storage/shares/<id>/entry?path=…`.
///
/// Depth-infinity on a directory, which is what the console's delete button
/// means to a person and what `DELETE` means in RFC 4918 §9.6.
pub async fn delete(volume: &Arc<Volume>, who: &Identity, path: &str) -> Response {
    let volume = Arc::clone(volume);
    let who = who.clone();
    let at = match volume.resolve(path) {
        Ok(at) => at,
        Err(failure) => return selfhost_storage::api::failed(&failure),
    };
    match blocking(move || volume.delete(&who, &at)).await {
        Ok(()) => selfhost_storage::api::done(),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// Answers `POST /api/storage/shares/<id>/rename`.
///
/// `{"from": "...", "to": "...", "toShare": "...", "replace": false}`. The
/// destination share defaults to the source, so the ordinary in-place rename is
/// two fields.
///
/// **The destination is a second attacker-controlled path and gets the identical
/// treatment as the first**: its own [`Volume::resolve`], its own share's
/// read-only flag, and — because it may name a different share — its own
/// capability check, made by the caller through `may` before this is reached.
/// A move whose destination escapes its root is a write-anywhere primitive as
/// complete as a traversal, and `replace` compounds it.
pub async fn rename(
    volumes: &Volumes,
    from_volume: &Arc<Volume>,
    who: &Identity,
    body: &[u8],
    may: &(dyn Fn(&Capability) -> bool + Sync),
) -> Response {
    let (Some(from), Some(to)) = (string_field(body, "from"), string_field(body, "to")) else {
        return problem(Status(400), "body must be JSON with \"from\" and \"to\" strings");
    };
    let replace = bool_field(body, "replace").unwrap_or(false);
    let into = match string_field(body, "toShare") {
        None => Arc::clone(from_volume),
        Some(id) => {
            // The destination share is decided exactly as the source was, and
            // refused with the same uniform 401: a caller who may write here and
            // not there must not learn which of the two was the problem, nor
            // whether the other share exists at all.
            let Ok(parsed) = ShareId::parse(&id) else {
                return problem(Status(401), "authorisation required");
            };
            if !may(&Capability::FilesWrite(parsed)) {
                return problem(Status(401), "authorisation required");
            }
            match volumes.find(&id) {
                Some(volume) => Arc::clone(volume),
                None => return problem(Status(404), "no such share"),
            }
        }
    };

    let source = Arc::clone(from_volume);
    let who = who.clone();
    let (from, to) = match (source.resolve(&from), into.resolve(&to)) {
        (Ok(from), Ok(to)) => (from, to),
        (Err(failure), _) | (_, Err(failure)) => return selfhost_storage::api::failed(&failure),
    };
    match blocking(move || source.move_to(&who, &from, &into, &to, replace)).await {
        Ok(landing) => selfhost_storage::api::json(
            landing.status(),
            &Json::object([("moved", Json::Bool(true))]),
        ),
        Err(failure) => selfhost_storage::api::failed(&failure),
    }
}

/// Reads a string field out of a JSON body.
fn string_field(body: &[u8], name: &str) -> Option<String> {
    crate::parse_json_body(body)?.get(name).and_then(Json::as_str).map(str::to_owned)
}

/// Reads a boolean field out of a JSON body.
fn bool_field(body: &[u8], name: &str) -> Option<bool> {
    crate::parse_json_body(body)?.get(name).and_then(Json::as_bool)
}

/// A JSON 200 in the storage crate's own shape, so a route here and a route
/// there cannot disagree about caching headers.
fn ok(body: Json) -> Response {
    selfhost_storage::api::json(Status(200), &body)
}

/// Runs a blocking filesystem operation off the runtime.
///
/// A panic inside the closure would be reported here as a join error — which
/// under `panic = "abort"` cannot happen, because the process is already gone,
/// but the branch is written rather than unwrapped so that a *test* build cannot
/// hide a real fault behind a second one.
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

// ─── The bulk plane ──────────────────────────────────────────────────────────

/// Whether a path names a bulk transfer.
///
/// Checked on the path rather than the whole target, so a query string cannot
/// smuggle a route past it, and matched as a prefix with its trailing slash so
/// `/api/storage/blobs` is not `/api/storage/blob/`.
pub fn is_bulk(path: &str) -> bool {
    path.starts_with(BLOB_PREFIX)
}

/// A bulk transfer that may proceed, and everything it needs.
///
/// Produced by [`Api::bulk_for`](crate::Api::bulk_for), which is pure: it reads
/// a request head, consults the capability model and resolves the path against
/// the share, and touches neither a socket nor a descriptor. Every way of
/// getting the authorisation wrong is therefore a unit test over a `Request`.
#[derive(Debug)]
pub struct Bulk {
    /// The share, held so the blocking task can walk it.
    pub volume: Arc<Volume>,
    /// The resolved path inside it, already through the security resolver.
    pub at: RelativePath,
    /// Who asked, in the vocabulary the share's own grant check speaks.
    pub who: Identity,
    /// Which direction the bytes go, and what that direction needs.
    pub transfer: Transfer,
}

/// Which way a bulk transfer runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    /// Bytes leave the box. Carries what the caller asked to happen to them,
    /// which the storage crate is free to overrule for anything that could carry
    /// script.
    Download(Disposition),
    /// Bytes arrive. Carries the declared length — a *claim*, admitted against
    /// the quota and re-checked as the bytes land — and whether an existing file
    /// may be destroyed.
    Upload {
        /// The client's `Content-Length`.
        declared: u64,
        /// Whether an existing name may be replaced.
        existing: Existing,
    },
}

/// Why a bulk transfer was refused before it began.
///
/// Split from [`Failure`] because these are refusals the *route* makes — no
/// share, no capability, a body this API will not frame — and every one of them
/// has to answer before a descriptor is opened.
///
/// Neither `Clone` nor `Eq`: [`Denied::Refused`] carries a [`Failure`], which is
/// neither, and a refusal is answered once. Tests match on the variant.
#[derive(Debug)]
pub enum Denied {
    /// No credential, or one that does not hold the capability this share
    /// needs. Answered with the same uninformative 401 an anonymous caller gets,
    /// which is also what an unknown share id produces: a refusal that told them
    /// apart would be a way to enumerate the shares.
    Unauthorised,
    /// The method is neither `GET`, `HEAD` nor `PUT`.
    WrongMethod,
    /// The path names no file — an empty remainder after the share id.
    NoPath,
    /// The capability holds and this daemon serves no share by that name.
    ///
    /// Safe to distinguish from [`Denied::Unauthorised`] precisely because it is
    /// reached only *after* the capability check: the callers who can tell an
    /// unknown share from a known one are the ones who could list them anyway.
    NoShare,
    /// The resolver refused the path. Carries its reason for the response.
    Refused(Failure),
    /// A `PUT` that declared no length, declared a chunked body, or declared
    /// more than [`BULK_MAX_BODY`].
    Unframed(&'static str),
}

impl Denied {
    /// The response this refusal becomes.
    ///
    /// [`Denied::Unauthorised`] is byte-for-byte the API's ordinary 401, which
    /// is the point of it.
    pub fn response(&self) -> Response {
        match self {
            Self::Unauthorised => problem(Status(401), "authorisation required"),
            Self::WrongMethod => problem(Status(405), "this path serves GET, HEAD and PUT"),
            Self::NoPath => problem(Status(404), "no such file"),
            Self::NoShare => problem(Status(404), "no such share"),
            Self::Refused(failure) => selfhost_storage::api::failed(failure),
            Self::Unframed(why) => problem(Status(411), why),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorised => write!(out, "no credential holding this share's capability"),
            Self::WrongMethod => write!(out, "not a bulk method"),
            Self::NoPath => write!(out, "no file named after the share"),
            Self::NoShare => write!(out, "no share by that id is served"),
            // The *tag*, never the failure's own sentence: a resolver refusal
            // names the segment it refused, and this string is written to a log.
            // On a NAS the file names are the sensitive thing.
            Self::Refused(failure) => write!(out, "the path was refused: {}", failure.tag()),
            Self::Unframed(why) => write!(out, "{why}"),
        }
    }
}

impl std::error::Error for Denied {}

/// Splits a blob target into its share id and the path inside it.
///
/// Pure, and deliberately naive: the remainder is handed to
/// [`Volume::resolve`] exactly as it arrived, percent-escapes and all, because
/// that function is the security resolver and anything this one cleaned up first
/// would be a rule enforced in two places. `None` when the target is not a blob
/// path or names no file.
pub fn split_blob(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix(BLOB_PREFIX)?;
    let (share, remainder) = match rest.split_once('/') {
        Some(pair) => pair,
        None => (rest, ""),
    };
    (!share.is_empty() && !remainder.is_empty()).then_some((share, remainder))
}

/// The declared length of a `PUT` body, or why it cannot be accepted.
///
/// Chunked is refused rather than dechunked, exactly as this crate's ordinary
/// body reader refuses it for every other route: the only
/// clients of this API are ones we wrote, and a dechunker written for a client
/// that has no reason to use it is a parser fed by strangers for no benefit.
pub fn declared_length(request: &Request) -> Result<u64, Denied> {
    match request.body_length() {
        Ok(selfhost_http::BodyLength::Fixed(length)) if length <= BULK_MAX_BODY => Ok(length),
        Ok(selfhost_http::BodyLength::Fixed(_)) => {
            Err(Denied::Unframed("that Content-Length is larger than this API will accept"))
        }
        Ok(selfhost_http::BodyLength::None) => Ok(0),
        Ok(selfhost_http::BodyLength::Chunked) => {
            Err(Denied::Unframed("send a Content-Length rather than chunked framing"))
        }
        Err(_) => Err(Denied::Unframed("the body framing could not be read")),
    }
}

/// Whether the caller asked for a preview rather than a download.
///
/// `?inline=1`. The storage crate decides what that actually means — anything
/// that could carry script is sent as an attachment whatever the query says —
/// so this is a request, not an instruction.
pub fn requested_disposition(query: &str) -> Disposition {
    match crate::query_value(query, "inline") {
        Some("1") | Some("true") => Disposition::InlineIfSafe,
        _ => Disposition::Attachment,
    }
}

/// Whether a `PUT` may replace what is already there.
///
/// Defaults to replacing, which is what `PUT` means in HTTP and what every
/// WebDAV client and every drag-and-drop upload expects. `?replace=0` asks for
/// the safer behaviour, which answers `409` rather than destroying anything.
pub fn requested_existing(query: &str) -> Existing {
    match crate::query_value(query, "replace") {
        Some("0") | Some("false") => Existing::Refuse,
        _ => Existing::Replace,
    }
}

/// Serves a bulk transfer over the connection that asked for it.
///
/// The only function in this module that owns a socket. It writes its own
/// response head, because a download's head is built by
/// `selfhost_storage::respond` from the *already-open handle's* metadata rather
/// than from a `stat` that could describe a different file by the time the bytes
/// are read.
///
/// `prefix` is whatever the request reader took off the socket past the head. It
/// is the first of the body and it must not be dropped: `crates/proxy` documents
/// this stranding trap, and it applies again here — an upload that ignored it
/// would corrupt every file whose first bytes arrived in the same segment as the
/// headers, which is most of them.
pub async fn serve<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    request: &Request,
    plan: Bulk,
) -> std::io::Result<Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let placement = Placement { volume: plan.volume, who: plan.who, at: plan.at };
    match plan.transfer {
        Transfer::Download(disposition) => {
            download_bytes(stream, request, placement, disposition, &json_failure).await
        }
        Transfer::Upload { declared, existing } => {
            upload_bytes(
                stream,
                prefix,
                placement,
                existing,
                declared,
                Answers {
                    landed: selfhost_storage::api::done(),
                    truncated: problem(Status(400), "the body ended before the declared length"),
                    failed: &json_failure,
                },
            )
            .await
        }
    }
}

/// A storage failure as the JSON file API renders it.
///
/// Named rather than written inline because it is now one of **two** renderings
/// — WebDAV answers the same failures with a bare status, since no WebDAV client
/// parses a body and the JSON one would carry a refused path into a response
/// this crate has promised not to put it in. Two protocols, one engine, and the
/// difference held in one visible place.
fn json_failure(failure: &Failure) -> Response {
    selfhost_storage::api::failed(failure)
}

/// The file a transfer is about: the share, the caller, and the resolved path.
///
/// The three travel together everywhere because they are only meaningful
/// together — a path with no share is not a file, and a share with no caller
/// cannot decide whether the file may be touched. Bundling them also keeps both
/// byte-plane entry points inside a parameter count a reader can hold, which
/// matters more than usual here: these are the two functions in this crate that
/// move a gigabyte, and a transposed argument would be silent.
pub struct Placement {
    /// The share, held so the blocking task can walk it.
    pub volume: Arc<Volume>,
    /// Who asked, in the vocabulary the share's own grant check speaks.
    pub who: Identity,
    /// The path inside the share, already through the security resolver.
    pub at: RelativePath,
}

/// How a transfer's outcome is spoken on the wire.
///
/// The bytes are identical for both protocols and the sentences are not: the
/// browser file manager wants JSON it can render, and WebDAV wants `201`, `204`
/// and a bare status. Carrying the three answers rather than branching on a
/// protocol flag is what keeps [`upload_bytes`] from having to know which caller
/// it has — and keeps a future third caller from adding a third branch to it.
pub struct Answers<'a> {
    /// The whole declared length arrived and the file was published.
    pub landed: Response,
    /// The body ended early. Nothing was published, and the status says the
    /// request was the problem rather than the box.
    pub truncated: Response,
    /// How this protocol renders a failure the storage engine reported.
    pub failed: &'a (dyn Fn(&Failure) -> Response + Sync),
}

/// What a finished transfer did, for the daemon's log.
///
/// Names the share and the byte count and **never the path** — see this module's
/// documentation. A `Debug` that printed the path would put it back in the log
/// the first time somebody logged the whole struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The share id, which is not a secret: it is a configured name, and the
    /// caller had to hold a capability naming it to get here.
    pub share: String,
    /// Which way the bytes went.
    pub direction: &'static str,
    /// How many bytes crossed.
    pub bytes: u64,
    /// The status that was written.
    pub status: u16,
}

impl fmt::Display for Report {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{direction} {bytes} bytes on share {share} ({status})",
            direction = self.direction,
            bytes = self.bytes,
            share = self.share,
            status = self.status
        )
    }
}

/// Sends a file, honouring `Range`, `If-None-Match` and `If-Modified-Since`.
///
/// The head and the byte window both come from `selfhost_storage::respond`,
/// which reuses `http::range::evaluate` and `date::entity_tag` unchanged — the
/// same code the static file server has always used, so a 206, a 304 and a 416
/// mean here exactly what they mean there.
///
/// `failed` is how the calling protocol renders a refusal; see [`Answers`] for
/// why that is a parameter rather than a fixed shape.
pub async fn download_bytes<S>(
    stream: &mut S,
    request: &Request,
    placement: Placement,
    disposition: Disposition,
    failed: &(dyn Fn(&Failure) -> Response + Sync),
) -> std::io::Result<Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Placement { volume, who, at } = placement;
    let share = volume.share().id().as_str().to_owned();
    let head_only = request.method == Method::Head;
    // `Volume::download` opens a descriptor and reads its metadata, both of
    // which block; the request is cloned into the task because the head is built
    // from it.
    let request = request.clone();
    let opened = blocking(move || volume.download(&who, &request, &at, disposition)).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(failure) => {
            let response = failed(&failure);
            let status = response.status.code();
            write_response(stream, &response).await?;
            return Ok(Report { share, direction: "download", bytes: 0, status });
        }
    };

    let status = opened.blob.response.status.code();
    let length = if head_only { 0 } else { opened.blob.length };

    let mut head = Vec::with_capacity(512);
    opened
        .blob
        .response
        .write_head(&mut head, false)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    stream.write_all(&head).await?;

    if length == 0 {
        stream.flush().await?;
        return Ok(Report { share, direction: "download", bytes: 0, status });
    }

    // Seek on the blocking pool, then hand the positioned handle to tokio. The
    // copy is bounded by `take`, so a file that grows under us sends exactly the
    // `Content-Length` that was written rather than desynchronising the
    // connection.
    let offset = opened.blob.offset;
    let file = positioned(opened, offset).await?;
    let mut source = tokio::io::BufReader::with_capacity(CHUNK, file).take(length);
    let sent = tokio::io::copy(&mut source, stream).await?;
    stream.flush().await?;
    Ok(Report { share, direction: "download", bytes: sent, status })
}

/// Receives a file, streaming it to a temporary name in the destination
/// directory and publishing it atomically at the end.
///
/// Nothing here ever holds the body: the socket is read into a fixed
/// fixed 64 KiB buffer, the chunk is handed to a blocking task that owns the
/// [`selfhost_storage::api::Receiver`], and the task writes it. The declared length is admitted against
/// the share's quota before the first byte and re-checked as bytes land, so a
/// client that declares a kilobyte and sends a hundred gigabytes is stopped
/// while it is sending them rather than after.
///
/// A body that ends early abandons the upload rather than committing a truncated
/// file. That is the whole reason the feed carries a marker instead of relying on
/// the channel closing: a closed channel cannot tell "the client finished" from
/// "the client vanished", and one of those must not publish a file.
///
/// `answers` is how the calling protocol speaks the three outcomes; see
/// [`Answers`].
pub async fn upload_bytes<S>(
    stream: &mut S,
    prefix: Vec<u8>,
    placement: Placement,
    existing: Existing,
    declared: u64,
    answers: Answers<'_>,
) -> std::io::Result<Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Placement { volume, who, at } = placement;
    let share = volume.share().id().as_str().to_owned();
    let opening = {
        let volume = Arc::clone(&volume);
        let at = at.clone();
        let who = who.clone();
        blocking(move || volume.receive(&who, &at, existing, declared)).await
    };
    let mut receiver = match opening {
        Ok(receiver) => receiver,
        Err(failure) => {
            return refuse_upload(stream, &share, &(answers.failed)(&failure)).await;
        }
    };

    let (feed, mut chunks) = tokio::sync::mpsc::channel::<Feed>(FEED_DEPTH);
    let writer = tokio::task::spawn_blocking(move || {
        while let Some(item) = chunks.blocking_recv() {
            match item {
                Feed::Chunk(bytes) => receiver.write(&bytes)?,
                Feed::Complete => return receiver.commit().map(|()| true),
                Feed::Abandon => return receiver.abandon().map(|()| false),
            }
        }
        // The feed was dropped without a verdict, which happens only if the
        // reading half panicked or was cancelled. Abandoning is the safe reading
        // of an upload nobody finished.
        receiver.abandon().map(|()| false)
    });

    let mut received: u64 = 0;
    let mut scratch = vec![0u8; CHUNK];
    let mut remaining = declared;
    let mut truncated = false;

    for start in prefix.chunks(CHUNK) {
        let take = (remaining.min(start.len() as u64)) as usize;
        if take == 0 {
            break;
        }
        remaining -= take as u64;
        received += take as u64;
        if feed.send(Feed::Chunk(start[..take].to_vec())).await.is_err() {
            break;
        }
    }

    while remaining > 0 {
        let want = (remaining.min(CHUNK as u64)) as usize;
        match stream.read(&mut scratch[..want]).await {
            Ok(0) => {
                truncated = true;
                break;
            }
            Ok(read) => {
                remaining -= read as u64;
                received += read as u64;
                if feed.send(Feed::Chunk(scratch[..read].to_vec())).await.is_err() {
                    break;
                }
            }
            Err(error) => {
                // Named, not merely counted. A client that hung up mid-upload
                // and a socket that faulted both abandon the write, and the
                // operator reading the refusal needs to know which: the first is
                // somebody closing a laptop, the second is a machine to go and
                // look at.
                eprintln!("admin: upload abandoned after {received} byte(s): {error}");
                truncated = true;
                break;
            }
        }
    }

    let verdict = if truncated || remaining > 0 { Feed::Abandon } else { Feed::Complete };
    let _ = feed.send(verdict).await;
    drop(feed);

    let finished = match writer.await {
        Ok(result) => result,
        Err(error) => Err(Failure::Io(format!("the upload task did not finish: {error}"))),
    };

    let response = match finished {
        Ok(true) => answers.landed,
        // The body did not arrive whole. Nothing was published, and the status
        // says the request was the problem rather than the box.
        Ok(false) => answers.truncated,
        Err(failure) => (answers.failed)(&failure),
    };
    let status = response.status.code();
    write_response(stream, &response).await?;
    Ok(Report { share, direction: "upload", bytes: received, status })
}

/// One item on the socket-to-disk feed.
///
/// The two terminal markers are the point of the type: see [`upload`].
#[derive(Debug)]
enum Feed {
    /// Bytes to write.
    Chunk(Vec<u8>),
    /// The declared length arrived; publish it.
    Complete,
    /// It did not; roll the reservation back and leave nothing behind.
    Abandon,
}

/// Answers an upload that was refused before it began.
///
/// The body is drained rather than ignored only in the sense that it is not
/// read at all: the connection is answered and closed, which is what
/// [`crate::handle_connection`](crate) does with every response, so the
/// unread body dies with the socket rather than being read into memory to be
/// thrown away.
async fn refuse_upload<S>(
    stream: &mut S,
    share: &str,
    response: &Response,
) -> std::io::Result<Report>
where
    S: AsyncWrite + Unpin,
{
    let status = response.status.code();
    write_response(stream, response).await?;
    Ok(Report { share: share.to_owned(), direction: "upload", bytes: 0, status })
}

/// Writes a complete response — head and in-memory body — to a socket.
///
/// A local copy of the crate's own writer, generic over the stream so the bulk
/// paths are testable against `tokio::io::duplex` rather than a listener.
async fn write_response<S>(stream: &mut S, response: &Response) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(256);
    response
        .write_head(&mut out, false)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if let Body::Bytes(bytes) = &response.body {
        out.extend_from_slice(bytes);
    }
    stream.write_all(&out).await?;
    stream.flush().await
}

/// Positions an opened download at the byte a `Range` asked for.
///
/// The seek is a blocking call on a `std::fs::File`, so it happens on the
/// blocking pool and the positioned handle comes back as a tokio one. Written as
/// one function rather than done at the call site so the blocking hop cannot be
/// forgotten, and so the `Download` is consumed here — a handle that had been
/// seeked and a handle that had not would otherwise be the same type.
async fn positioned(
    download: selfhost_storage::api::Download,
    offset: u64,
) -> std::io::Result<tokio::fs::File> {
    let file = tokio::task::spawn_blocking(move || {
        use std::io::Seek;
        let mut file = download.file;
        file.seek(std::io::SeekFrom::Start(offset))?;
        Ok::<_, std::io::Error>(file)
    })
    .await
    .map_err(|error| std::io::Error::other(error.to_string()))??;
    Ok(tokio::fs::File::from_std(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_path_splits_into_a_share_and_an_untouched_remainder() {
        assert_eq!(split_blob("/api/storage/blob/vault/a/b.txt"), Some(("vault", "a/b.txt")));
        // The remainder is handed on exactly as it arrived: cleaning it here
        // would be the security rule enforced in two places.
        assert_eq!(
            split_blob("/api/storage/blob/vault/%2e%2e/etc"),
            Some(("vault", "%2e%2e/etc"))
        );
    }

    #[test]
    fn a_blob_path_naming_no_file_is_not_a_transfer() {
        assert_eq!(split_blob("/api/storage/blob/vault"), None);
        assert_eq!(split_blob("/api/storage/blob/vault/"), None);
        assert_eq!(split_blob("/api/storage/blob/"), None);
        assert_eq!(split_blob("/api/storage/shares"), None);
    }

    #[test]
    fn the_bulk_prefix_is_matched_at_a_segment_boundary() {
        assert!(is_bulk("/api/storage/blob/vault/x"));
        assert!(!is_bulk("/api/storage/blobs/vault/x"));
        assert!(!is_bulk("/api/storage/shares"));
    }

    #[test]
    fn an_id_that_could_never_name_a_share_demands_something_nobody_holds() {
        // Not a 404: a refusal that distinguished "no such share" from "not
        // yours" would enumerate what is behind the wall.
        assert_eq!(demand("Not A Share", Wants::Read), Demand::Unsatisfiable);
        assert_eq!(demand("../etc", Wants::Write), Demand::Unsatisfiable);
        assert!(matches!(demand("vault", Wants::Read), Demand::Held(Capability::FilesRead(_))));
        assert!(matches!(demand("vault", Wants::Write), Demand::Held(Capability::FilesWrite(_))));
    }

    #[test]
    fn a_put_must_declare_a_length_this_api_will_accept() {
        let head = |extra: &str| {
            let raw = format!("PUT /api/storage/blob/v/a HTTP/1.1\r\nHost: x\r\n{extra}\r\n");
            Request::parse(raw.as_bytes()).expect("a well-formed head").request
        };
        assert!(matches!(declared_length(&head("Content-Length: 10\r\n")), Ok(10)));
        assert!(matches!(
            declared_length(&head("Transfer-Encoding: chunked\r\n")),
            Err(Denied::Unframed(_))
        ));
        assert!(matches!(
            declared_length(&head(&format!("Content-Length: {}\r\n", BULK_MAX_BODY + 1))),
            Err(Denied::Unframed(_))
        ));
    }

    #[test]
    fn a_download_is_an_attachment_unless_a_preview_was_asked_for() {
        assert_eq!(requested_disposition(""), Disposition::Attachment);
        assert_eq!(requested_disposition("inline=0"), Disposition::Attachment);
        assert_eq!(requested_disposition("inline=1"), Disposition::InlineIfSafe);
    }

    #[test]
    fn a_put_replaces_unless_the_caller_asked_it_not_to() {
        assert_eq!(requested_existing(""), Existing::Replace);
        assert_eq!(requested_existing("replace=0"), Existing::Refuse);
    }

    #[test]
    fn a_refusal_that_could_enumerate_shares_is_the_ordinary_401() {
        assert_eq!(Denied::Unauthorised.response().status.code(), 401);
    }

    #[test]
    fn a_transfer_report_names_the_share_and_never_the_path() {
        let report =
            Report { share: "vault".into(), direction: "download", bytes: 12, status: 200 };
        let printed = format!("{report}");
        assert!(printed.contains("vault"), "{printed}");
        let debugged = format!("{report:?}");
        assert!(!debugged.contains('/'), "a report must not carry a path: {debugged}");
    }
}
