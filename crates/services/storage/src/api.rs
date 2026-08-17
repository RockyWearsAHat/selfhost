//! What a share lets a caller do, as functions rather than as routes.
//!
//! Everything here takes values and returns values. Nothing touches a socket,
//! reads a header off the wire, or spawns a task — `crates/admin` does all
//! three and calls into this. That split is not tidiness: it is what lets a
//! `5 GB` upload, a `Range` request, a quota breach and a traversal attempt all
//! be tested in a unit test with a real directory and no network at all.
//!
//! # One engine, two protocols
//!
//! The browser file manager speaks JSON over `/api/storage/…` and WebDAV speaks
//! RFC 4918 over `/dav/…`. They are two spellings of one set of rules, and they
//! run on this module rather than on two implementations — because two
//! implementations of "may this overwrite that" eventually disagree, and the
//! disagreement is a file somebody loses. [`crate::dav`] turns these outcomes
//! into WebDAV's statuses and bodies; [`Failure::to_json`] turns them into the
//! console's.
//!
//! # Streaming is the whole design, not an optimisation
//!
//! A `5 GB` upload must complete with the daemon's resident memory flat, and a
//! `2 GB` download must not be buffered anywhere. So:
//!
//! - **Downloads** hand back an open [`File`] plus the byte window to send.
//!   `crates/proxy`'s existing seek-take-copy loop moves the bytes; this module
//!   never reads one.
//!   ([`Download`])
//! - **Uploads** are a [`Receiver`] the caller feeds in chunks of whatever size
//!   it already has in hand from the socket. The receiver holds an open
//!   destination file and a [`crate::quota::Reservation`], and it never
//!   accumulates: `write` goes straight to the filesystem, and what it keeps is
//!   two counters.
//! - **Copies** move bytes through one fixed [`COPY_BUFFER_BYTES`] buffer,
//!   however large the file.
//!
//! There is deliberately no function here that takes a `Vec<u8>` body for a
//! file, because such a function is how a 5 GB upload becomes 5 GB of resident
//! memory the day somebody uses it for convenience.
//!
//! # Resumable uploads, and why they hold a descriptor open
//!
//! A large upload over a tunnel gets interrupted. [`Sessions`] lets a client
//! resume one: a ticket, an offset, and chunks appended across as many requests
//! as it takes.
//!
//! Each session keeps its destination **directory descriptor** open for its
//! whole life, which is the point. A session that re-walked its path on every
//! chunk would be a session whose path could be renamed out from under it
//! between chunks — the attacker plants a link where the directory used to be
//! and the remaining gigabytes land wherever they chose. Holding the descriptor
//! means the second chunk lands in the same directory *object* the first one
//! did, whatever the path says by then.
//!
//! The name is reserved by an exclusive create at the start ([`crate::fs::Upload`]),
//! so two clients cannot resume onto one name and the destination cannot be a
//! planted symlink. The consequence is the one [`crate::fs`] already records: a
//! partially-uploaded file is visible in the share under its own name until it
//! completes or is swept.
//!
//! # Every operation still asks the share
//!
//! The console gate is loopback, and loopback on this box includes three
//! co-hosted web applications. Nothing here treats being reachable as being
//! authorised: every writing operation is refused on the share's read-only flag
//! and on [`crate::share::Share::permits`] before it reaches a descriptor.

use crate::fs::{Attributes, Dir, Existing, OpenError, Upload, WriteError};
use crate::listing::{Entry, Kind, Listing};
use crate::path::{self, RelativePath, Refusal};
use crate::quota::{self, Admission, Ledger, Limits, Reservation, Usage};
use crate::respond::{self, BlobResponse, Disposition};
use crate::share::{GrantOutcome, Grantee, Share, Want};
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_http::{HeaderError, Request, Response, Status};
use selfhost_json::Json;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The scratch buffer a server-side copy moves bytes through.
///
/// Sixty-four kilobytes, the same order as the relay's own bulk path. It is a
/// fixed buffer rather than a read-it-all because a `COPY` of a 5 GB file is an
/// ordinary thing for a WebDAV client to ask for, and the daemon that serves
/// ports 80 and 443 is the same process.
pub const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// How long an idle resumable upload is kept before it is swept.
///
/// Fifteen minutes. Long enough to survive a tunnel dropping and a client
/// backing off, short enough that an abandoned session does not hold a
/// descriptor, a quota reservation and a concurrency slot until the daemon
/// restarts.
pub const SESSION_IDLE: Duration = Duration::from_secs(900);

/// The most resumable uploads in flight at once.
///
/// Each one holds an open file, an open directory and a slot in the quota's
/// concurrency ceiling, so this is bounded for the same reason that ceiling is.
/// It is deliberately larger than [`crate::quota::DEFAULT_MAX_CONCURRENT`] —
/// the quota is what actually refuses the ninth upload; this is only what stops
/// the table itself growing without limit.
pub const MAX_SESSIONS: usize = 64;

/// Why an operation could not be performed.
///
/// Typed all the way through rather than collapsed into a status code, because
/// the same outcome is spelled differently by the two protocols — a destination
/// that is already occupied is `409` to the file API and `412` to a WebDAV
/// `MOVE` with `Overwrite: F` — and because the console renders the prose.
///
/// **Nothing here echoes attacker text.** [`Failure::Refused`] carries the rule
/// that fired and not the name that fired it, exactly as
/// [`crate::path::Refusal`] does and for the same reason: a log line that
/// repeats a caller's bytes is a second injection surface.
#[derive(Debug)]
pub enum Failure {
    /// The name is not one this share will serve.
    ///
    /// Answered `404`, the same as a name that simply is not there, so a prober
    /// cannot tell a refused name from an absent one — the choice
    /// `proxy/src/server.rs:889` already makes for the static server.
    Refused(Refusal),
    /// Nothing of that name is here.
    NotFound,
    /// The caller asked for a file and named a collection, or the reverse.
    WrongKind,
    /// A parent collection on the way to the target does not exist.
    ///
    /// Distinct from [`Failure::NotFound`] because RFC 4918 §9.3.1 answers it
    /// `409`: the request is fine, the tree is not, and telling a client `404`
    /// would send it looking for the file it was trying to create.
    NoParent,
    /// Something is already at the destination.
    Occupied,
    /// The destination name cannot be told apart from one already there.
    Collides {
        /// The existing name, which is safe to show: it came off our own disk
        /// and through [`crate::path::validate_segment`].
        existing: String,
    },
    /// A `COPY` or `MOVE` whose destination is the file it came from.
    ///
    /// RFC 4918 §9.8.1 and §9.9.2 both answer this `403`, and the reason is the
    /// one this crate found out the expensive way: the destination of a
    /// replacing transfer is deleted before the transfer runs, so a destination
    /// that *is* the source is a delete followed by a move of something that is
    /// no longer there. Refusing it is not pedantry about a redundant request —
    /// it is the difference between a no-op and losing the file.
    ///
    /// It is asked of the two objects on disk rather than of the two request
    /// paths, because a folding volume calls `report.pdf` and `Report.pdf` one
    /// file and neither path says so.
    SameResource,
    /// A `COPY` or `MOVE` of a collection into a place inside itself.
    ///
    /// `COPY /tree` to `/tree/copy` is a directory that grows a copy of itself
    /// inside the copy it is making, for as long as the recursion will let it —
    /// which is until the depth limit, having written the source's contents
    /// sixty-four times over. RFC 4918 §9.8.1 answers `403`, and the request is
    /// refused before a byte is written rather than abandoned partway through.
    IntoOwnSubtree,
    /// The share or the caller's grants say no.
    NotPermitted(GrantOutcome),
    /// The quota, the volume, or a concurrency ceiling says no.
    OutOfRoom(Admission),
    /// A tree deeper than [`crate::fs::MAX_TREE_DEPTH`].
    TooDeep,
    /// No resumable upload of that ticket, or it was swept.
    NoSession,
    /// A resumable chunk arrived at the wrong offset.
    ///
    /// Carries what the server has, which is what makes a resume possible: the
    /// client seeks to this offset and continues rather than starting again.
    WrongOffset {
        /// The offset the next chunk must start at.
        expected: u64,
    },
    /// The filesystem, or the box, is unwell.
    Io(String),
}

impl Failure {
    /// The status the JSON file API answers with.
    ///
    /// WebDAV's answers differ in three places and are chosen at the WebDAV
    /// route rather than here — an occupied destination is `412` there, a
    /// missing parent is already `409` in both, and a refused name is `404` in
    /// both.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Refused(_) | Self::NotFound => 404,
            Self::WrongKind => 400,
            Self::NoParent | Self::Occupied | Self::Collides { .. } => 409,
            Self::SameResource | Self::IntoOwnSubtree | Self::NotPermitted(_) => 403,
            Self::OutOfRoom(admission) => admission.status_code(),
            Self::TooDeep => 409,
            Self::NoSession => 404,
            Self::WrongOffset { .. } => 409,
            Self::Io(_) => 500,
        }
    }

    /// The status as this workspace's type.
    pub fn status(&self) -> Status {
        Status(self.status_code())
    }

    /// Whether waiting and retrying would plausibly succeed.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::OutOfRoom(admission) if admission.retryable())
    }

    /// The failure as the console reads it.
    ///
    /// `error` is a stable tag the front end switches on and `message` is the
    /// prose it renders. Two fields rather than one because a console that
    /// matched on prose is a console that breaks when the prose improves.
    pub fn to_json(&self) -> Json {
        let mut fields =
            vec![("error", Json::string(self.tag())), ("message", Json::string(self.to_string()))];
        if let Self::WrongOffset { expected } = self {
            fields.push(("offset", Json::Number(*expected as f64)));
        }
        if let Self::Collides { existing } = self {
            fields.push(("existing", Json::string(existing)));
        }
        Json::object(fields)
    }

    /// The stable tag the console switches on.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Refused(_) | Self::NotFound => "not-found",
            Self::WrongKind => "wrong-kind",
            Self::NoParent => "no-parent",
            Self::Occupied => "occupied",
            Self::Collides { .. } => "collides",
            Self::SameResource => "same-resource",
            Self::IntoOwnSubtree => "into-own-subtree",
            Self::NotPermitted(_) => "not-permitted",
            Self::OutOfRoom(_) => "out-of-room",
            Self::TooDeep => "too-deep",
            Self::NoSession => "no-session",
            Self::WrongOffset { .. } => "wrong-offset",
            Self::Io(_) => "io",
        }
    }
}

impl fmt::Display for Failure {
    /// Prose the console renders as-is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Deliberately the same sentence as an absent name: see the type's
            // documentation.
            Self::Refused(_) | Self::NotFound => f.write_str("no such file in this share"),
            Self::WrongKind => f.write_str("that name is not the kind of thing this asks for"),
            Self::NoParent => f.write_str("the folder this would go in does not exist"),
            Self::Occupied => f.write_str("something is already there"),
            Self::Collides { existing } => {
                write!(f, "this name cannot be told apart from the existing {existing}")
            }
            Self::SameResource => f.write_str("that is where the file already is"),
            Self::IntoOwnSubtree => {
                f.write_str("a folder cannot be copied or moved into itself")
            }
            Self::NotPermitted(GrantOutcome::ReadOnly) => {
                f.write_str("this share is published read-only")
            }
            Self::NotPermitted(_) => f.write_str("you do not have permission to do that here"),
            Self::OutOfRoom(admission) => write!(f, "{admission}"),
            Self::TooDeep => f.write_str("that folder tree is deeper than one request will walk"),
            Self::NoSession => f.write_str("that upload is no longer in progress"),
            Self::WrongOffset { expected } => {
                write!(f, "the next part of this upload must start at byte {expected}")
            }
            Self::Io(message) => write!(f, "the filesystem refused: {message}"),
        }
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }
}

impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<OpenError> for Failure {
    /// Three different refusals become one `404`.
    ///
    /// A missing name, a link, and something that is not a regular file are the
    /// same answer on the wire — `proxy/src/server.rs:889` makes the same
    /// choice — because a prober must not learn from the status code that a
    /// name exists but is a symlink.
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Refused(refusal) => Self::Refused(refusal),
            OpenError::NotFound | OpenError::Symlink | OpenError::Moved => Self::NotFound,
            OpenError::NotADirectory | OpenError::NotAFile => Self::WrongKind,
            OpenError::AlreadyExists => Self::Occupied,
            OpenError::Io(error) => Self::Io(error.to_string()),
        }
    }
}

impl From<WriteError> for Failure {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Refused(refusal) => Self::Refused(refusal),
            WriteError::NameTaken => Self::Occupied,
            WriteError::Collides { existing } => Self::Collides { existing },
            WriteError::Open(error) => Self::from(error),
            WriteError::Io(error) => Self::Io(error.to_string()),
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// One share, opened, with the ceilings it is enforced against.
///
/// Built once when the daemon starts and held for the process's life, because
/// the open root descriptor is what every walk begins from: re-opening it per
/// request would put a by-path open back on the hot path, which is the thing
/// [`crate::fs`] exists to remove.
#[derive(Debug)]
pub struct Volume {
    /// What the operator declared.
    share: Share,
    /// The root, opened and canonicalised once.
    root: Dir,
    /// The live counts, shared with every other share on this box — the
    /// concurrency ceiling and the in-flight budget are properties of the
    /// machine, not of one share.
    ledger: Arc<Ledger>,
    /// The ceilings, carrying this share's own quota.
    limits: Limits,
}

impl Volume {
    /// Opens a share.
    ///
    /// The root is canonicalised and opened here, which is also where a share
    /// pointing at something that is not a directory, or that is not there at
    /// all, is found out — at startup, with a message, rather than on the first
    /// request.
    pub fn open(share: Share, ledger: Arc<Ledger>) -> Result<Self, OpenError> {
        let root = Dir::open_root(share.root())?;
        let limits = Limits::for_quota(share.quota_bytes());
        Ok(Self { share, root, ledger, limits })
    }

    /// The share this serves.
    pub fn share(&self) -> &Share {
        &self.share
    }

    /// The open root, for a caller that needs to walk it itself.
    pub fn root(&self) -> &Dir {
        &self.root
    }

    /// The ceilings, so a caller can report them.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Resolves a request path against this share.
    ///
    /// The one entry point for attacker-controlled text, and it is the same one
    /// for the request line and for a WebDAV `Destination` — see
    /// [`crate::dav::method::destination`] for why that matters.
    pub fn resolve(&self, request_path: &str) -> Result<RelativePath, Failure> {
        Ok(path::resolve(self.share.root(), request_path)?.relative().clone())
    }

    /// Refuses the caller if the share or their grants say so.
    ///
    /// Called at the top of every operation rather than at the route, because a
    /// route is a place a check can be forgotten and this is not.
    pub fn permit(&self, caller: &Grantee, want: Want) -> Result<(), Failure> {
        match self.share.permits(caller, want) {
            GrantOutcome::Allowed => Ok(()),
            refused => Err(Failure::NotPermitted(refused)),
        }
    }

    /// What one directory holds.
    pub fn listing(&self, caller: &Grantee, at: &RelativePath) -> Result<Listing, Failure> {
        self.permit(caller, Want::Read)?;
        let directory = self.root.walk(at)?;
        Ok(Listing::new(at.clone(), directory.entries()?))
    }

    /// What one name is.
    pub fn stat(&self, caller: &Grantee, at: &RelativePath) -> Result<Attributes, Failure> {
        self.permit(caller, Want::Read)?;
        let Some(name) = at.file_name() else {
            // The share root is a collection and has no parent to be named in;
            // its own metadata is the root descriptor's.
            let metadata = self.root.metadata()?;
            return Ok(Attributes { kind: Kind::Directory, size: 0, modified: metadata.modified().ok() });
        };
        Ok(self.root.walk(&at.parent())?.stat(name)?)
    }

    /// Opens a file for sending, with the response head already built.
    ///
    /// The head is built from the **already-open handle's** metadata, not from
    /// a separate `stat`, for the reason [`crate::respond::blob`] gives: a
    /// `Content-Length` read before the open describes a file that may no
    /// longer be the one whose bytes follow.
    pub fn download(
        &self,
        caller: &Grantee,
        request: &Request,
        at: &RelativePath,
        disposition: Disposition,
    ) -> Result<Download, Failure> {
        self.permit(caller, Want::Read)?;
        let name = at.file_name().ok_or(Failure::WrongKind)?;
        let file = self.root.walk(&at.parent())?.open_file(name)?;
        let metadata = file.metadata()?;
        let blob = respond::blob(request, name, metadata.len(), metadata.modified().ok(), disposition);
        Ok(Download { file, blob })
    }

    /// Creates one directory.
    ///
    /// Only the last segment: a `mkdir` that created intermediate directories
    /// would make a typo in a path build a tree, and RFC 4918 §9.3.1 requires
    /// `MKCOL` to answer `409` when the parent is missing rather than inventing
    /// it. The JSON API behaves the same way so the two protocols cannot
    /// disagree about what a folder button does.
    pub fn create_directory(&self, caller: &Grantee, at: &RelativePath) -> Result<(), Failure> {
        self.permit(caller, Want::Write)?;
        let name = at.file_name().ok_or(Failure::Occupied)?;
        let parent = self.parent_of(at)?;
        parent.create_dir(name)?;
        Ok(())
    }

    /// Removes a file, or a directory and everything beneath it.
    ///
    /// Depth-infinity on a collection, which is what `DELETE` means in
    /// RFC 4918 §9.6 and what a console's delete button means to a person. The
    /// share's own size is forgotten rather than adjusted afterwards: a
    /// recursive delete's byte total is a second walk, and a cached number that
    /// is confidently wrong is worse than one that asks to be measured again.
    pub fn delete(&self, caller: &Grantee, at: &RelativePath) -> Result<(), Failure> {
        self.permit(caller, Want::Write)?;
        let name = at.file_name().ok_or(Failure::WrongKind)?;
        self.parent_of(at)?.remove_tree(name)?;
        self.ledger.forget(self.share.id().as_str());
        Ok(())
    }

    /// Moves a name, within this share or into another.
    ///
    /// `into` is a whole [`Volume`] rather than a path because a cross-share
    /// move is two shares' worth of rules: the destination's read-only flag,
    /// the destination's grants, and the destination's quota all belong to the
    /// share being written to, and a function that took only a path would check
    /// the source's.
    ///
    /// `replace` is `Overwrite: T`. When it is set and something is at the
    /// destination, the destination is deleted first — which is exactly what
    /// RFC 4918 §9.9.3 requires, and which is also the only portable way to get
    /// one behaviour out of two platforms whose rename primitives disagree
    /// about replacement.
    ///
    /// **Nothing is deleted until the move is known to be possible.** That
    /// sentence is the whole of [`Volume::survey`], and it is written here
    /// because getting the order wrong does not produce a failed request, it
    /// produces a destroyed file: a `MOVE` from a name that does not exist, or
    /// onto the file it came from, used to delete the destination first and
    /// discover the problem second. Every refusal a transfer can make is made
    /// before the destination is touched.
    ///
    /// A cross-**volume** move falls back to copy-then-delete, because
    /// `rename` cannot cross a filesystem and two shares may well be on two
    /// disks. That is stated rather than hidden: the operation stops being
    /// atomic, and a failure partway leaves the source intact and a partial
    /// destination visible, which is the safe half to leave behind.
    pub fn move_to(
        &self,
        caller: &Grantee,
        from: &RelativePath,
        into: &Self,
        to: &RelativePath,
        replace: bool,
    ) -> Result<Landing, Failure> {
        self.permit(caller, Want::Write)?;
        into.permit(caller, Want::Write)?;
        let source_name = from.file_name().ok_or(Failure::WrongKind)?;
        let target_name = to.file_name().ok_or(Failure::Occupied)?;
        let source_parent = self.root.walk(&from.parent())?;
        let target_parent = into.parent_of(to)?;

        // Every refusal first, and only then the destructive part.
        let existed = match survey(&source_parent, source_name, &target_parent, target_name)? {
            // The destination is another spelling of the source: a person
            // fixing a file's capitalisation. There is nothing at the
            // destination to clear — the thing that is "there" is the file being
            // moved — and `Dir::rename_into` is where the two-step rename that
            // performs it lives.
            Transfer::Respelling => false,
            Transfer::Onto => into.clear_destination(&target_parent, target_name, replace)?,
        };

        match source_parent.rename_into(source_name, &target_parent, target_name) {
            Ok(()) => {}
            // `EXDEV`, or Windows' equivalent: the two ends are on different
            // volumes, so there is nothing to rename and the bytes have to
            // travel.
            Err(WriteError::Io(error)) if is_cross_device(&error) => {
                self.copy_into(&source_parent, source_name, into, &target_parent, target_name, 0)?;
                source_parent.remove_tree(source_name)?;
            }
            Err(other) => return Err(other.into()),
        }
        self.ledger.forget(self.share.id().as_str());
        into.ledger.forget(into.share.id().as_str());
        Ok(if existed { Landing::Replaced } else { Landing::Created })
    }

    /// Copies a name, within this share or into another.
    ///
    /// A collection is copied whole, bounded by [`crate::fs::MAX_TREE_DEPTH`]
    /// like every other descent in this crate. The bytes move through one
    /// [`COPY_BUFFER_BYTES`] buffer however large the file is.
    ///
    /// The two refusals [`Volume::survey`] makes matter more here than anywhere
    /// else. A copy onto its own source is `403`, and a copy of a collection
    /// into its own subtree is `403` — because the alternative is not a slow
    /// request, it is a directory copying itself into itself until the depth
    /// limit stops it, sixty-four copies of every file later.
    pub fn copy_to(
        &self,
        caller: &Grantee,
        from: &RelativePath,
        into: &Self,
        to: &RelativePath,
        replace: bool,
    ) -> Result<Landing, Failure> {
        self.permit(caller, Want::Read)?;
        into.permit(caller, Want::Write)?;
        let source_name = from.file_name().ok_or(Failure::WrongKind)?;
        let target_name = to.file_name().ok_or(Failure::Occupied)?;
        let source_parent = self.root.walk(&from.parent())?;
        let target_parent = into.parent_of(to)?;

        // Every refusal first, and only then the destructive part.
        if survey(&source_parent, source_name, &target_parent, target_name)? == Transfer::Respelling
        {
            // A copy onto a name the volume considers to be the source's own is
            // a copy onto the source. A move can honour that request by
            // renaming; a copy cannot honour it at all.
            return Err(Failure::SameResource);
        }
        let existed = into.clear_destination(&target_parent, target_name, replace)?;
        self.copy_into(&source_parent, source_name, into, &target_parent, target_name, 0)?;
        into.ledger.forget(into.share.id().as_str());
        Ok(if existed { Landing::Replaced } else { Landing::Created })
    }

    /// Begins a streamed upload.
    ///
    /// `declared` is the client's `Content-Length`, which is a **claim**: it is
    /// what the quota is admitted against, and [`Receiver::write`] re-checks
    /// against what actually lands, so a client that declares a kilobyte and
    /// sends a hundred gigabytes is stopped while it is sending them.
    ///
    /// `existing` is the caller's intent, not a hint about the disk. Only
    /// [`Existing::Replace`] may destroy anything, and it is the only path that
    /// reaches a rename.
    pub fn receive(
        &self,
        caller: &Grantee,
        at: &RelativePath,
        existing: Existing,
        declared: u64,
    ) -> Result<Receiver, Failure> {
        self.permit(caller, Want::Write)?;
        let name = at.file_name().ok_or(Failure::WrongKind)?.to_string();
        let parent = self.parent_of(at)?;

        // Room first, and the file second: an upload that was going to be
        // refused should not create anything, not even briefly.
        let usage = self.usage()?;
        let reservation = self
            .ledger
            .admit(self.share.id().as_str(), self.limits, usage.used_bytes, usage.free_bytes, declared)
            .map_err(Failure::OutOfRoom)?;

        let upload = Upload::begin(parent, &name, existing)?;
        Ok(Receiver { upload, reservation, declared, share: self.share.id().as_str().to_string() })
    }

    /// What this share holds and what the volume has free.
    ///
    /// The used figure comes from [`crate::quota::Ledger`]'s cache when it is
    /// fresh and from a subtree walk when it is not — the walk is the expensive
    /// one, and the caching argument is made in that module. The free figure is
    /// always measured, because it is a fact about a disk several processes are
    /// writing to.
    pub fn usage(&self) -> Result<Usage, Failure> {
        let id = self.share.id().as_str();
        let used_bytes = match self.ledger.used(id) {
            Some(known) => known,
            None => {
                let measured = self.root.measure()?;
                self.ledger.observe(id, measured);
                measured
            }
        };
        Ok(Usage {
            used_bytes,
            free_bytes: self.root.free_space()?,
            // The two live counts belong to the ledger and are read there, at
            // the moment of admission, under its own lock: reading them here
            // would produce a number that is already stale by the time it is
            // compared against anything.
            uploads_running: 0,
            in_flight_bytes: 0,
        })
    }

    /// Bytes still accepted and bytes held, for RFC 4331 and for the console.
    pub fn quota(&self) -> Result<(u64, u64), Failure> {
        let usage = self.usage()?;
        Ok((quota::available(self.limits, usage), quota::used(usage)))
    }

    /// The directory a path's last segment goes in.
    ///
    /// A missing intermediate collection is [`Failure::NoParent`] rather than
    /// [`Failure::NotFound`], because those are two different answers to a
    /// client: one means *the file you asked for is not here* and the other
    /// means *the folder you are putting it in is not here*.
    fn parent_of(&self, at: &RelativePath) -> Result<Dir, Failure> {
        self.root.walk(&at.parent()).map_err(|error| match error {
            OpenError::NotFound | OpenError::NotADirectory => Failure::NoParent,
            other => Failure::from(other),
        })
    }

    /// Makes room at a destination, or refuses to.
    ///
    /// Returns whether something was there — which is the difference between a
    /// `201` and a `204` on the wire, and the reason this is a function rather
    /// than an `if` in three places.
    ///
    /// **This is the destructive step, and it runs last.** It is called only
    /// after [`survey`] has established that the source is there, that it is not
    /// this very destination, and that this destination is not inside it —
    /// because each of those, discovered afterwards, turns a request that
    /// achieves nothing into a request that deletes a file.
    fn clear_destination(
        &self,
        parent: &Dir,
        name: &str,
        replace: bool,
    ) -> Result<bool, Failure> {
        if !parent.occupied(name)? {
            return Ok(false);
        }
        if !replace {
            return Err(Failure::Occupied);
        }
        // RFC 4918 §9.9.3: the destination is deleted, depth-infinity, before
        // the move. Doing it explicitly rather than leaning on a platform's
        // replacing rename is what makes both platforms behave alike.
        parent.remove_tree(name)?;
        Ok(true)
    }

    /// Copies one name into another directory, descending if it is a
    /// collection.
    ///
    /// Bounded by [`crate::fs::MAX_TREE_DEPTH`] for the reason every descent
    /// here is: a share can hold a tree thousands of levels deep, and a
    /// recursion that followed it would overflow the stack — which under
    /// `panic = "abort"` is the whole box rather than one failed request.
    fn copy_into(
        &self,
        source_parent: &Dir,
        source_name: &str,
        into: &Self,
        target_parent: &Dir,
        target_name: &str,
        depth: usize,
    ) -> Result<(), Failure> {
        if depth >= crate::fs::MAX_TREE_DEPTH {
            return Err(Failure::TooDeep);
        }
        match source_parent.open_dir(source_name) {
            Ok(source) => {
                let target = target_parent.create_dir(target_name)?;
                for entry in source.entries()? {
                    if !entry.reachable() {
                        // A name this share cannot spell cannot be created in
                        // the destination either, and inventing a spelling for
                        // it would put a *different* file there. The same test
                        // now also excludes what this share will not *open* — a
                        // link, a device, a FIFO — which is the honest answer
                        // for those too: this crate never creates a link, and
                        // copying what one points at would follow it out of the
                        // share. Skipped, and visible in the destination's
                        // listing by its absence.
                        continue;
                    }
                    self.copy_into(&source, &entry.name, into, &target, &entry.name, depth + 1)?;
                }
                Ok(())
            }
            Err(OpenError::NotADirectory) => {
                self.copy_file(source_parent, source_name, into, target_parent, target_name)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Copies one file's bytes through a fixed buffer.
    ///
    /// The destination goes through [`Upload`], so a copy is subject to exactly
    /// the same exclusive create, the same case-collision refusal and the same
    /// quota as an upload — a `COPY` that bypassed the quota would be a way to
    /// fill a share from inside it.
    fn copy_file(
        &self,
        source_parent: &Dir,
        source_name: &str,
        into: &Self,
        target_parent: &Dir,
        target_name: &str,
    ) -> Result<(), Failure> {
        let mut source = source_parent.open_file(source_name)?;
        let declared = source.metadata()?.len();

        let usage = into.usage()?;
        let mut reservation = into
            .ledger
            .admit(into.share.id().as_str(), into.limits, usage.used_bytes, usage.free_bytes, declared)
            .map_err(Failure::OutOfRoom)?;

        let mut upload = Upload::begin(target_parent, target_name, Existing::Refuse)?;
        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        loop {
            let read = std::io::Read::read(&mut source, &mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk = buffer.get(..read).unwrap_or_default();
            let admission = reservation.record(read as u64);
            if !admission.allowed() {
                // The reservation goes back on the way out of scope, crediting
                // nothing, because nothing was published — and the same is true
                // of the `?` on the line below, which is why neither needs an
                // unwind of its own.
                let _ = upload.abandon();
                return Err(Failure::OutOfRoom(admission));
            }
            upload.file().write_all(chunk)?;
        }
        upload.commit()?;
        // Only now: the destination is published, so the bytes belong in the
        // share's size. A whole-directory copy is many of these in a row, and
        // each one has to move the cached figure the next is admitted against.
        reservation.finish();
        Ok(())
    }
}

/// What a `COPY` or `MOVE` turned out to be, once both ends were examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    /// The destination is a name of its own. Clear it if the caller asked to,
    /// then move or copy onto it.
    Onto,
    /// The destination is another spelling of the source itself, on a volume
    /// that folds the two together — `report.pdf` to `Report.pdf`. There is
    /// nothing at the destination to make room for, and making room would
    /// delete the source.
    Respelling,
}

/// Examines both ends of a `COPY` or `MOVE` before either is disturbed.
///
/// This function is where an ordering bug used to live, so it is worth saying
/// what the order buys. A replacing transfer deletes its destination first
/// (RFC 4918 §9.9.3), and that delete used to happen before anything had
/// checked that the source existed, that it was not the destination, and that
/// the destination was not inside it. Each of those three is a way for the
/// delete to be the *only* thing the request accomplishes:
///
/// 1. **The source must be there.** A `MOVE` from a mistyped name deleted the
///    file at the destination and then reported that the source was missing.
///    The open is the proof, and it is a descriptor walk, so a link at the
///    source is [`Failure::NotFound`] — a share never moves what it will not
///    serve.
/// 2. **The destination must not be the source.** Two request paths cannot
///    decide this; [`Dir::is_same_child`] asks the volume. For a `MOVE` a
///    differently-spelled answer is a legitimate rename, which is why this
///    returns [`Transfer::Respelling`] rather than refusing outright — a `COPY`
///    turns it into [`Failure::SameResource`] itself.
/// 3. **The destination must not be inside the source.** Compared on the
///    directories' own paths, which are canonical below a canonicalised root
///    because every component under it is opened with links refused, so a path
///    prefix here is a real containment rather than a textual coincidence.
fn survey(
    source_parent: &Dir,
    source_name: &str,
    target_parent: &Dir,
    target_name: &str,
) -> Result<Transfer, Failure> {
    if source_parent.is_same_directory(target_parent) && source_name == target_name {
        return Err(Failure::SameResource);
    }

    match source_parent.open_dir(source_name) {
        Ok(source) => {
            if target_parent.path().starts_with(source.path()) {
                return Err(Failure::IntoOwnSubtree);
            }
        }
        // A file has no subtree for a destination to be inside, and it is here
        // rather than in a separate `stat` so that the source's existence is
        // proven by one open.
        Err(OpenError::NotADirectory) => {}
        Err(other) => return Err(other.into()),
    }

    if source_parent.is_same_child(source_name, target_parent, target_name)? {
        return Ok(Transfer::Respelling);
    }
    Ok(Transfer::Onto)
}

/// The code a platform reports when a rename would cross a filesystem.
///
/// `EXDEV` is 18 on both Darwin and Linux; Windows says `ERROR_NOT_SAME_DEVICE`,
/// which is 17. `std` has no portable `ErrorKind` for either, so the number is
/// compared — and a wrong number here is not a security failure: a missed match
/// is a `500` an operator sees rather than a silent wrong answer, and a false
/// match costs a copy-then-delete that produces the same result more slowly.
#[cfg(unix)]
const CROSS_DEVICE: i32 = 18;

/// See the unix arm above.
#[cfg(windows)]
const CROSS_DEVICE: i32 = 17;

/// Whether an I/O error is "these two names are on different filesystems".
///
/// The one condition a `MOVE` recovers from rather than reports, because two
/// shares may well live on two disks and a person moving a file between them
/// means the same thing either way.
fn is_cross_device(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(CROSS_DEVICE)
}

/// What a `COPY` or `MOVE` did, which decides `201` against `204`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landing {
    /// Nothing was there; the destination is new.
    Created,
    /// Something was there and was replaced.
    Replaced,
}

impl Landing {
    /// The status this landing is answered with.
    pub fn status(self) -> Status {
        match self {
            Self::Created => crate::dav::method::CREATED,
            Self::Replaced => crate::dav::method::NO_CONTENT,
        }
    }
}

/// An open file and the window of it to send.
///
/// The bytes are the caller's to move — `crates/proxy`'s seek-take-copy loop
/// does it — because a function here that returned them would be a function
/// that buffered a 2 GB file.
#[derive(Debug)]
pub struct Download {
    /// The open handle, reached through the descriptor walk.
    pub file: File,
    /// The head, and the offset and length to send.
    pub blob: BlobResponse,
}

/// An upload in progress.
///
/// Holds the destination file, the directory descriptor it was created relative
/// to, and the quota room it is spending. It accumulates nothing: [`write`] goes
/// straight to the filesystem, so a 5 GB upload costs whatever buffer the caller
/// already had in hand from the socket.
///
/// [`write`]: Receiver::write
#[derive(Debug)]
pub struct Receiver {
    /// The destination, created exclusively and held open.
    upload: Upload<Dir>,
    /// The room this upload is spending, given back when it is dropped.
    reservation: Reservation,
    /// What the client said it would send.
    declared: u64,
    /// Which share's size the bytes belong to.
    share: String,
}

impl Receiver {
    /// Writes one chunk, re-checking the quota against what has landed.
    ///
    /// The re-check is the belt that does not depend on `Content-Length` being
    /// true. A refusal leaves the partial file in place and the reservation
    /// held; the caller answers `507` and calls [`Receiver::abandon`], which is
    /// what removes it.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), Failure> {
        let admission = self.reservation.record(chunk.len() as u64);
        if !admission.allowed() {
            return Err(Failure::OutOfRoom(admission));
        }
        self.upload.file().write_all(chunk)?;
        Ok(())
    }

    /// How far along this upload is.
    pub fn progress(&self) -> Progress {
        Progress { received: self.reservation.written(), declared: self.declared }
    }

    /// The bytes received so far, which is also a resumable upload's offset.
    pub fn received(&self) -> u64 {
        self.reservation.written()
    }

    /// Which share this is writing into.
    pub fn share(&self) -> &str {
        &self.share
    }

    /// Publishes the file and gives the quota room back.
    ///
    /// The order is the point. A failed publish means the bytes are **not**
    /// where the caller believes they are — a `sync_all` on a dying disk, a
    /// rename onto a name that was taken in the meantime — so
    /// [`crate::quota::Reservation::finish`] is reached only after the publish
    /// has succeeded, and the share's cached size does not grow by bytes that
    /// did not land. Getting this backwards is invisible until a share reports
    /// itself full of files it does not have.
    ///
    /// The failing arm needs no unwinding of its own: a reservation that is
    /// dropped rather than finished credits nothing, which is what makes every
    /// *other* way this upload can end — a swept session, a failed write, a
    /// cancelled task — correct without a call somebody has to remember.
    pub fn commit(self) -> Result<(), Failure> {
        let Self { upload, reservation, .. } = self;
        upload.commit()?;
        reservation.finish();
        Ok(())
    }

    /// Removes what was written and gives the room back without counting it.
    ///
    /// The deliberate counterpart to [`Receiver::commit`], and the difference is
    /// only that it *reports*: dropping a receiver removes the partial file and
    /// credits nothing too, but a `Drop` has nowhere to say that the filesystem
    /// would not co-operate.
    pub fn abandon(self) -> Result<(), Failure> {
        self.upload.abandon()?;
        Ok(())
    }
}

/// How far along an upload is, for the console's progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Bytes that have landed.
    pub received: u64,
    /// Bytes the client said it would send.
    pub declared: u64,
}

impl Progress {
    /// The progress as the console reads it.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("received", Json::Number(self.received as f64)),
            ("declared", Json::Number(self.declared as f64)),
        ])
    }
}

/// A ticket naming one resumable upload.
///
/// Opaque and unguessable, because it is a capability: whoever holds it may
/// append to somebody else's upload. It is minted from the system random source
/// rather than from a counter for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket(String);

impl Ticket {
    /// A fresh ticket.
    ///
    /// # Errors
    ///
    /// Only if the system random source refuses, which is answered `500`: a
    /// guessable ticket is an upload a second caller can hijack.
    pub fn mint() -> Result<Self, Failure> {
        let mut bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| Failure::Io("the system random source was unavailable".to_string()))?;
        let mut text = String::with_capacity(32);
        for byte in bytes {
            text.push_str(&format!("{byte:02x}"));
        }
        Ok(Self(text))
    }

    /// The ticket as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a presented ticket is this one, compared without
    /// short-circuiting.
    fn matches(&self, presented: &str) -> bool {
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

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The resumable uploads in flight.
///
/// One per daemon, shared. Each entry holds an open destination file and the
/// directory descriptor it was created relative to — see this module's
/// documentation for why the descriptor is held rather than the path re-walked.
///
/// # Poisoning
///
/// The lock is never held across a call that can panic, so a poisoned mutex
/// means another thread died with the table intact and recovering is right.
#[derive(Debug, Default)]
pub struct Sessions {
    entries: Mutex<Vec<Session>>,
}

/// One resumable upload.
#[derive(Debug)]
struct Session {
    /// The capability that names it.
    ticket: Ticket,
    /// The upload itself.
    receiver: Receiver,
    /// When it was last touched, for the idle sweep.
    touched_at: Instant,
}

impl Sessions {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts a resumable upload and returns its ticket.
    ///
    /// The destination name is reserved here, by the same exclusive create an
    /// ordinary upload uses, so two clients cannot resume onto one name and the
    /// destination cannot be a planted symlink.
    pub fn begin(&self, receiver: Receiver) -> Result<Ticket, Failure> {
        let ticket = Ticket::mint()?;
        let mut entries = self.lock();
        Self::sweep(&mut entries);
        if entries.len() >= MAX_SESSIONS {
            return Err(Failure::OutOfRoom(Admission::TooManyUploads {
                limit: u32::try_from(MAX_SESSIONS).unwrap_or(u32::MAX),
            }));
        }
        entries.push(Session { ticket: ticket.clone(), receiver, touched_at: Instant::now() });
        Ok(ticket)
    }

    /// Appends one chunk at `offset`.
    ///
    /// The offset is checked rather than trusted, and a mismatch is
    /// [`Failure::WrongOffset`] **carrying what the server has** — which is
    /// what makes a resume possible: a client that lost its connection asks,
    /// learns the offset, seeks and continues rather than starting again.
    ///
    /// A refused chunk (a quota breach) leaves the session in place, so the
    /// caller can report the failure and then abandon it deliberately.
    ///
    /// **This holds the table's lock across the write**, so two resumable
    /// uploads do not proceed in parallel. That is a known ceiling on
    /// throughput and it is stated rather than hidden: the alternative is a
    /// per-session lock, which is the right shape once more than one person
    /// uploads to this box at a time. It is bounded by the chunk size the
    /// caller sends, not by the file size, so a client that streams in
    /// megabytes holds it for a megabyte's worth of write.
    pub fn append(&self, ticket: &str, offset: u64, chunk: &[u8]) -> Result<Progress, Failure> {
        let mut entries = self.lock();
        Self::sweep(&mut entries);
        let index = Self::find(&entries, ticket).ok_or(Failure::NoSession)?;
        let session = entries.get_mut(index).ok_or(Failure::NoSession)?;
        let expected = session.receiver.received();
        if offset != expected {
            return Err(Failure::WrongOffset { expected });
        }
        session.receiver.write(chunk)?;
        session.touched_at = Instant::now();
        Ok(session.receiver.progress())
    }

    /// How far along a session is.
    pub fn progress(&self, ticket: &str) -> Result<Progress, Failure> {
        let mut entries = self.lock();
        Self::sweep(&mut entries);
        let index = Self::find(&entries, ticket).ok_or(Failure::NoSession)?;
        entries.get(index).map(|session| session.receiver.progress()).ok_or(Failure::NoSession)
    }

    /// Publishes a finished upload.
    pub fn finish(&self, ticket: &str) -> Result<(), Failure> {
        let session = self.take(ticket)?;
        session.receiver.commit()
    }

    /// Removes an abandoned upload and the partial file it created.
    pub fn abandon(&self, ticket: &str) -> Result<(), Failure> {
        let session = self.take(ticket)?;
        session.receiver.abandon()
    }

    /// How many sessions are live.
    pub fn len(&self) -> usize {
        let mut entries = self.lock();
        Self::sweep(&mut entries);
        entries.len()
    }

    /// Whether nothing is in flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops a session out of the table.
    fn take(&self, ticket: &str) -> Result<Session, Failure> {
        let mut entries = self.lock();
        Self::sweep(&mut entries);
        let index = Self::find(&entries, ticket).ok_or(Failure::NoSession)?;
        Ok(entries.remove(index))
    }

    /// Removes sessions nobody has touched for [`SESSION_IDLE`].
    ///
    /// Dropping a [`Session`] drops its [`Receiver`], whose `Upload` removes the
    /// partial file and whose `Reservation` gives the quota room back — so the
    /// sweep is one `retain` and the cleanup is the type system's.
    fn sweep(entries: &mut Vec<Session>) {
        let now = Instant::now();
        entries.retain(|session| now.saturating_duration_since(session.touched_at) < SESSION_IDLE);
    }

    /// The index of a session, compared without short-circuiting.
    fn find(entries: &[Session], ticket: &str) -> Option<usize> {
        entries.iter().position(|session| session.ticket.matches(ticket))
    }

    /// The table, with a poisoned lock recovered rather than propagated.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Session>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A JSON response, with the framing this workspace's HTTP layer expects.
///
/// The one place a body becomes a response in this module, so the content type
/// and the no-store policy are stated once. `no-store` because a directory
/// listing is a person's filenames and a shared cache has no business holding
/// them.
pub fn json(status: Status, body: &Json) -> Response {
    build_json(status, body).unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR))
}

/// The body of [`json`], with header failures surfaced rather than ignored.
fn build_json(status: Status, body: &Json) -> Result<Response, HeaderError> {
    let mut response =
        Response::bytes(status, "application/json; charset=utf-8", body.to_text().into_bytes())?;
    response.headers.set("Cache-Control", "no-store")?;
    response.headers.set("X-Content-Type-Options", "nosniff")?;
    Ok(response)
}

/// A failure as the console's JSON, with the status it belongs to.
///
/// A `Retry-After` is attached to the two refusals that clear on their own, so
/// a client backs off rather than hammering — and is deliberately absent from a
/// quota breach, which will not clear until somebody deletes something.
pub fn failed(failure: &Failure) -> Response {
    let mut response = json(failure.status(), &failure.to_json());
    if failure.retryable() && response.headers.set("Retry-After", "5").is_err() {
        response.headers.remove("Retry-After");
    }
    response
}

/// A listing as the console's JSON.
pub fn listed(listing: &Listing) -> Response {
    json(Status::OK, &listing.to_json())
}

/// One name's attributes as the console's JSON.
pub fn stated(at: &RelativePath, attributes: &Attributes) -> Response {
    let name = at.file_name().unwrap_or_default();
    let entry = Entry::new(
        std::ffi::OsStr::new(name),
        attributes.kind,
        attributes.size,
        attributes.modified,
    );
    json(Status::OK, &entry.to_json(&at.parent()))
}

/// An empty success, for a `mkdir`, a `rename` or a `delete`.
pub fn done() -> Response {
    json(Status::OK, &Json::object([("ok", Json::Bool(true))]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, ShareId};
    use selfhost_http::{Body, Headers, Method};
    use std::path::{Path, PathBuf};

    /// A scratch directory of our own, shaped on `fs::tests`'.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-storage-api-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        std::fs::canonicalize(&path).expect("a canonical scratch directory")
    }

    fn reserved() -> Reserved {
        Reserved::new(std::env::temp_dir().join("selfhost-data-unused"), None)
            .expect("an absolute fixture")
    }

    fn open_volume(id: &str, root: &Path, quota: Option<u64>) -> Volume {
        let share = Share::new(&reserved(), id, root, false, true, quota)
            .expect("a legal share");
        Volume::open(share, Arc::new(Ledger::new())).expect("the root opens")
    }

    fn owner() -> Grantee {
        Grantee::Owner
    }

    fn request(method: &str, target: &str) -> Request {
        Request {
            method: Method::parse(method),
            target: target.to_string(),
            minor_version: 1,
            headers: Headers::new(),
        }
    }

    fn upload(volume: &Volume, path: &str, bytes: &[u8]) {
        let at = volume.resolve(path).expect("a legal path");
        let mut receiver = volume
            .receive(&owner(), &at, Existing::Refuse, bytes.len() as u64)
            .expect("admitted");
        receiver.write(bytes).expect("written");
        receiver.commit().expect("committed");
    }

    #[test]
    fn a_share_lists_stats_and_downloads_what_is_in_it() {
        let root = scratch("read");
        std::fs::create_dir(root.join("photos")).expect("a directory");
        std::fs::write(root.join("notes.txt"), b"hello").expect("a file");
        let volume = open_volume("vault", &root, None);

        let listing = volume.listing(&owner(), &RelativePath::default()).expect("listed");
        assert_eq!(listing.entries.len(), 2);
        // Directories first, which is what a person expects.
        assert_eq!(listing.entries[0].name, "photos");

        let at = volume.resolve("/notes.txt").expect("a legal path");
        assert_eq!(volume.stat(&owner(), &at).expect("stat").size, 5);

        let download = volume
            .download(&owner(), &request("GET", "/notes.txt"), &at, Disposition::Attachment)
            .expect("opened");
        assert_eq!(download.blob.length, 5);
        assert!(matches!(download.blob.response.body, Body::Streamed(5)));

        // A range is the same head-building path the static server uses.
        let mut ranged = request("GET", "/notes.txt");
        ranged.headers.set("Range", "bytes=1-3").expect("a legal header");
        let partial = volume
            .download(&owner(), &ranged, &at, Disposition::Attachment)
            .expect("opened");
        assert_eq!(partial.blob.offset, 1);
        assert_eq!(partial.blob.length, 3);
        assert_eq!(partial.blob.response.status, Status::PARTIAL_CONTENT);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The whole point of the streaming design, asserted rather than described:
    /// a body far larger than any buffer lands without one.
    #[test]
    fn a_large_upload_lands_in_chunks_without_ever_being_held_whole() {
        let root = scratch("stream");
        let volume = open_volume("vault", &root, None);
        let at = volume.resolve("/big.bin").expect("a legal path");

        // Eight megabytes, fed in 64 KiB chunks — the same shape a 5 GB upload
        // has, with the same peak memory: one chunk.
        let chunk = vec![7u8; 64 * 1024];
        let chunks = 128;
        let total = (chunk.len() * chunks) as u64;
        let mut receiver =
            volume.receive(&owner(), &at, Existing::Refuse, total).expect("admitted");
        for _ in 0..chunks {
            receiver.write(&chunk).expect("written");
        }
        assert_eq!(receiver.progress(), Progress { received: total, declared: total });
        receiver.commit().expect("committed");

        assert_eq!(std::fs::metadata(root.join("big.bin")).expect("landed").len(), total);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A quota breach is a `507` carrying prose the console renders, and the
    /// partial file goes.
    #[test]
    fn a_quota_breach_is_507_with_something_a_person_can_read() {
        let root = scratch("quota");
        let volume = open_volume("vault", &root, Some(64));
        let at = volume.resolve("/too-big.bin").expect("a legal path");

        // Refused before a byte is written, so nothing is created at all.
        let refused = volume.receive(&owner(), &at, Existing::Refuse, 4096).expect_err("refused");
        assert_eq!(refused.status_code(), 507);
        assert!(refused.to_string().contains("limited to 64 bytes"));
        assert!(!root.join("too-big.bin").exists(), "a refused upload creates nothing");

        let response = failed(&refused);
        assert_eq!(response.status, Status(507));
        assert!(response.headers.get_str("retry-after").is_none(), "a full share does not clear");

        // And a client that lies about its length is stopped as the bytes land,
        // one byte past the declaration the room was admitted against.
        let mut sneaky = volume.receive(&owner(), &at, Existing::Refuse, 16).expect("admitted");
        sneaky.write(&[0u8; 16]).expect("within the declaration");
        let caught = sneaky.write(&[0u8; 4096]).expect_err("refused mid-body");
        assert_eq!(caught.status_code(), 400, "a body longer than its framing is the client's bug");
        assert_eq!(sneaky.received(), 16, "the refused chunk is not counted as landed");
        sneaky.abandon().expect("removed");
        assert!(!root.join("too-big.bin").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_read_only_share_refuses_every_write_and_still_serves_reads() {
        let root = scratch("readonly");
        std::fs::write(root.join("notes.txt"), b"hello").expect("a file");
        let share = Share::new(&reserved(), "vault", root.clone(), true, true, None)
            .expect("a legal share");
        let volume = Volume::open(share, Arc::new(Ledger::new())).expect("the root opens");

        let at = volume.resolve("/new.txt").expect("a legal path");
        let refused = volume.receive(&owner(), &at, Existing::Refuse, 5).expect_err("refused");
        assert_eq!(refused.status_code(), 403);
        assert!(refused.to_string().contains("read-only"));
        assert!(volume.create_directory(&owner(), &at).is_err());
        assert!(volume.delete(&owner(), &at).is_err());

        // Reading is untouched, which is what makes the flag a statement about
        // the data rather than about the caller.
        assert!(volume.listing(&owner(), &RelativePath::default()).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_folder_is_made_only_where_its_parent_already_exists_and_is_deleted_whole() {
        let root = scratch("mkdir");
        let volume = open_volume("vault", &root, None);

        let photos = volume.resolve("/photos").expect("a legal path");
        volume.create_directory(&owner(), &photos).expect("created");
        assert!(root.join("photos").is_dir());

        // A second one is refused rather than silently accepted.
        assert!(matches!(
            volume.create_directory(&owner(), &photos),
            Err(Failure::Occupied | Failure::Collides { .. })
        ));

        // And a missing intermediate is `no-parent`, not `not-found`: the
        // difference is what the client is told to fix.
        let deep = volume.resolve("/absent/inner").expect("a legal path");
        let refused = volume.create_directory(&owner(), &deep).expect_err("refused");
        assert_eq!(refused.tag(), "no-parent");
        assert_eq!(refused.status_code(), 409);

        upload(&volume, "/photos/a.txt", b"a");
        volume.delete(&owner(), &photos).expect("removed whole");
        assert!(!root.join("photos").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_move_replaces_only_when_replacing_was_the_request() {
        let root = scratch("move");
        let volume = open_volume("vault", &root, None);
        upload(&volume, "/a.txt", b"first");
        upload(&volume, "/b.txt", b"second");

        let a = volume.resolve("/a.txt").expect("a legal path");
        let b = volume.resolve("/b.txt").expect("a legal path");
        let c = volume.resolve("/c.txt").expect("a legal path");

        // Onto a free name.
        assert_eq!(volume.move_to(&owner(), &a, &volume, &c, false).expect("moved"), Landing::Created);
        assert_eq!(std::fs::read_to_string(root.join("c.txt")).expect("read"), "first");
        assert!(!root.join("a.txt").exists());

        // Onto an occupied one, without permission to replace: refused, and the
        // file that was there is untouched.
        let refused = volume.move_to(&owner(), &c, &volume, &b, false).expect_err("refused");
        assert_eq!(refused.tag(), "occupied");
        assert_eq!(std::fs::read_to_string(root.join("b.txt")).expect("read"), "second");

        // And with permission.
        assert_eq!(
            volume.move_to(&owner(), &c, &volume, &b, true).expect("moved"),
            Landing::Replaced
        );
        assert_eq!(std::fs::read_to_string(root.join("b.txt")).expect("read"), "first");
        assert_eq!(Landing::Created.status(), crate::dav::method::CREATED);
        assert_eq!(Landing::Replaced.status(), crate::dav::method::NO_CONTENT);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_copy_duplicates_a_whole_tree_and_leaves_the_original() {
        let root = scratch("copy");
        let volume = open_volume("vault", &root, None);
        let tree = volume.resolve("/tree").expect("a legal path");
        volume.create_directory(&owner(), &tree).expect("created");
        upload(&volume, "/tree/a.txt", b"alpha");
        let inner = volume.resolve("/tree/inner").expect("a legal path");
        volume.create_directory(&owner(), &inner).expect("created");
        upload(&volume, "/tree/inner/b.txt", b"beta");

        let copy = volume.resolve("/copy").expect("a legal path");
        assert_eq!(
            volume.copy_to(&owner(), &tree, &volume, &copy, false).expect("copied"),
            Landing::Created
        );
        assert_eq!(std::fs::read_to_string(root.join("copy/a.txt")).expect("read"), "alpha");
        assert_eq!(std::fs::read_to_string(root.join("copy/inner/b.txt")).expect("read"), "beta");
        assert_eq!(std::fs::read_to_string(root.join("tree/a.txt")).expect("read"), "alpha");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A transfer that cannot succeed must not have destroyed anything on its
    /// way to finding out.
    ///
    /// The destination of a replacing transfer is deleted first, so every
    /// refusal has to be made before that delete. Each case here was a way of
    /// losing a file: a source that never existed, a destination that was the
    /// source, and a collection copied into its own subtree.
    #[test]
    fn a_transfer_that_is_refused_leaves_both_ends_exactly_as_they_were() {
        let root = scratch("transfer-refusals");
        let volume = open_volume("vault", &root, None);
        upload(&volume, "/keep.pdf", b"the only copy");
        let keep = volume.resolve("/keep.pdf").expect("a legal path");
        let absent = volume.resolve("/typo.pdf").expect("a legal path");

        // Onto itself: `403`, and the file is still there. Both spellings of
        // `Overwrite`, because it was the replacing one that destroyed it.
        for replace in [false, true] {
            let refused =
                volume.move_to(&owner(), &keep, &volume, &keep, replace).expect_err("refused");
            assert_eq!(refused.tag(), "same-resource", "replace={replace}");
            assert_eq!(refused.status_code(), 403);
            assert_eq!(std::fs::read_to_string(root.join("keep.pdf")).expect("read"), "the only copy");
        }

        // From a source that is not there: the destination is untouched, by
        // either verb.
        for replace in [false, true] {
            assert!(volume.move_to(&owner(), &absent, &volume, &keep, replace).is_err());
            assert!(volume.copy_to(&owner(), &absent, &volume, &keep, replace).is_err());
            assert_eq!(std::fs::read_to_string(root.join("keep.pdf")).expect("read"), "the only copy");
        }

        // Into its own subtree: refused before anything is created, so the
        // recursion that used to build sixty-four copies of the tree never
        // starts.
        let tree = volume.resolve("/tree").expect("a legal path");
        volume.create_directory(&owner(), &tree).expect("created");
        upload(&volume, "/tree/a.txt", b"alpha");
        for into in ["/tree/copy", "/tree"] {
            let inside = volume.resolve(into).expect("a legal path");
            let refused = volume.copy_to(&owner(), &tree, &volume, &inside, false).expect_err("refused");
            assert_eq!(refused.status_code(), 403, "{into}");
            assert!(volume.move_to(&owner(), &tree, &volume, &inside, true).is_err(), "{into}");
        }
        assert!(!root.join("tree/copy").exists(), "nothing was created");
        assert_eq!(std::fs::read_to_string(root.join("tree/a.txt")).expect("read"), "alpha");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Fixing a file's capitalisation is a rename, on a volume that folds case
    /// and on one that does not — and on neither is it a way to lose the file.
    #[test]
    fn a_case_only_rename_moves_the_file_rather_than_destroying_it() {
        let root = scratch("transfer-case");
        let volume = open_volume("vault", &root, None);
        upload(&volume, "/report.pdf", b"the only copy");
        let lower = volume.resolve("/report.pdf").expect("a legal path");
        let upper = volume.resolve("/Report.pdf").expect("a legal path");

        volume.move_to(&owner(), &lower, &volume, &upper, true).expect("the case is fixed");

        let survivors: Vec<String> = std::fs::read_dir(&root)
            .expect("read")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(survivors, ["Report.pdf"]);
        assert_eq!(std::fs::read_to_string(root.join("Report.pdf")).expect("read"), "the only copy");

        // A *copy* onto a spelling of its own name is refused rather than
        // honoured: on a folding volume the two names are one file and there is
        // nothing to copy onto (`403`), and on a case-sensitive one the pair is
        // the collision no Mac client could hold (`409`). The refusal differs
        // with the volume; that the source survives it does not.
        let copied = volume.copy_to(&owner(), &upper, &volume, &lower, true);
        assert!(copied.is_err(), "a copy onto its own name is not a copy: {copied:?}");
        assert_eq!(std::fs::read_to_string(root.join("Report.pdf")).expect("read"), "the only copy");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A move between two shares is two shares' worth of rules — and the
    /// destination's are the ones that decide whether the write happens.
    #[test]
    fn a_cross_share_move_is_refused_by_the_destination_shares_own_flag() {
        let source_root = scratch("cross-source");
        let target_root = scratch("cross-target");
        let source = open_volume("vault", &source_root, None);
        let target_share =
            Share::new(&reserved(), "archive", &target_root, true, true, None)
                .expect("a legal share");
        let target = Volume::open(target_share, Arc::new(Ledger::new())).expect("the root opens");

        upload(&source, "/a.txt", b"alpha");
        let from = source.resolve("/a.txt").expect("a legal path");
        let to = target.resolve("/a.txt").expect("a legal path");

        let refused = source.move_to(&owner(), &from, &target, &to, false).expect_err("refused");
        assert_eq!(refused.tag(), "not-permitted");
        assert!(source_root.join("a.txt").exists(), "the source is untouched");

        let _ = std::fs::remove_dir_all(&source_root);
        let _ = std::fs::remove_dir_all(&target_root);
    }

    /// The resolver is reached through this layer too, so a traversal in a
    /// request path is refused before anything is opened.
    #[test]
    fn a_traversing_path_never_reaches_a_descriptor() {
        let root = scratch("traversal");
        let outside = scratch("traversal-outside");
        std::fs::write(outside.join("secret"), b"secret").expect("a file");
        let volume = open_volume("vault", &root, None);

        for hostile in [
            "/../traversal-outside/secret",
            "/%2e%2e/traversal-outside/secret",
            "/..%20/secret",
            "/a/../../secret",
            "/CON.txt",
            "/notes.txt:evil",
        ] {
            assert!(volume.resolve(hostile).is_err(), "{hostile}");
        }
        assert_eq!(std::fs::read_to_string(outside.join("secret")).expect("read"), "secret");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_resumable_upload_survives_being_interrupted_and_refuses_a_wrong_offset() {
        let root = scratch("resume");
        let volume = open_volume("vault", &root, None);
        let sessions = Sessions::new();
        let at = volume.resolve("/resumed.bin").expect("a legal path");

        let receiver = volume.receive(&owner(), &at, Existing::Refuse, 9).expect("admitted");
        let ticket = sessions.begin(receiver).expect("a ticket");
        assert_eq!(sessions.len(), 1);

        let progress = sessions.append(ticket.as_str(), 0, b"abc").expect("appended");
        assert_eq!(progress, Progress { received: 3, declared: 9 });

        // A client that lost its connection asks where it got to and continues.
        assert_eq!(sessions.progress(ticket.as_str()).expect("known").received, 3);
        let wrong = sessions.append(ticket.as_str(), 0, b"abc").expect_err("refused");
        assert!(matches!(wrong, Failure::WrongOffset { expected: 3 }));
        assert!(wrong.to_json().to_text().contains("\"offset\""));

        sessions.append(ticket.as_str(), 3, b"def").expect("appended");
        sessions.append(ticket.as_str(), 6, b"ghi").expect("appended");
        sessions.finish(ticket.as_str()).expect("published");

        assert_eq!(std::fs::read_to_string(root.join("resumed.bin")).expect("read"), "abcdefghi");
        assert!(sessions.is_empty());
        assert!(matches!(sessions.progress(ticket.as_str()), Err(Failure::NoSession)));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_abandoned_session_takes_its_partial_file_and_its_quota_room_with_it() {
        let root = scratch("resume-abandon");
        let volume = open_volume("vault", &root, None);
        let sessions = Sessions::new();
        let at = volume.resolve("/half.bin").expect("a legal path");

        let receiver = volume.receive(&owner(), &at, Existing::Refuse, 100).expect("admitted");
        let ticket = sessions.begin(receiver).expect("a ticket");
        sessions.append(ticket.as_str(), 0, b"partial").expect("appended");
        assert!(root.join("half.bin").exists(), "the name is reserved while it uploads");

        sessions.abandon(ticket.as_str()).expect("removed");
        assert!(!root.join("half.bin").exists());
        assert!(sessions.is_empty());

        // And the share's cached size does not count the bytes that went.
        assert_eq!(volume.usage().expect("measured").used_bytes, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A ticket is a capability: holding one lets a caller append to somebody
    /// else's upload, so it must be unguessable and it must not be a counter.
    #[test]
    fn a_ticket_is_random_and_unrelated_to_the_last_one() {
        let first = Ticket::mint().expect("a random source");
        let second = Ticket::mint().expect("a random source");
        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 32);
        assert!(first.matches(first.as_str()));
        assert!(!first.matches(second.as_str()));
        assert!(!first.matches(""));
    }

    #[test]
    fn the_quota_properties_a_client_reads_come_from_the_same_place_the_writes_are_gated_on() {
        let root = scratch("usage");
        let volume = open_volume("vault", &root, Some(1000));
        upload(&volume, "/a.txt", &vec![0u8; 400]);

        let (available, used) = volume.quota().expect("measured");
        assert_eq!(used, 400);
        assert_eq!(available, 600, "the quota is the binding limit here, not the disk");

        // A share with no quota reports what the volume has, minus the reserve
        // — never zero, which is what makes Finder willing to copy at all.
        let open_root = scratch("usage-open");
        let unlimited = open_volume("photos", &open_root, None);
        let (open_available, _) = unlimited.quota().expect("measured");
        assert!(open_available > 0, "a share with room must never report zero free");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&open_root);
    }

    #[test]
    fn every_failure_carries_a_status_a_tag_and_prose() {
        let cases = [
            (Failure::Refused(Refusal::Traversal), 404, "not-found"),
            (Failure::NotFound, 404, "not-found"),
            (Failure::WrongKind, 400, "wrong-kind"),
            (Failure::NoParent, 409, "no-parent"),
            (Failure::Occupied, 409, "occupied"),
            (Failure::Collides { existing: "report.pdf".into() }, 409, "collides"),
            (Failure::SameResource, 403, "same-resource"),
            (Failure::IntoOwnSubtree, 403, "into-own-subtree"),
            (Failure::NotPermitted(GrantOutcome::ReadOnly), 403, "not-permitted"),
            (Failure::TooDeep, 409, "too-deep"),
            (Failure::NoSession, 404, "no-session"),
            (Failure::WrongOffset { expected: 7 }, 409, "wrong-offset"),
            (Failure::Io("disk on fire".into()), 500, "io"),
        ];
        for (failure, status, tag) in cases {
            assert_eq!(failure.status_code(), status, "{tag}");
            assert_eq!(failure.tag(), tag);
            assert!(!failure.to_string().is_empty(), "{tag}");
            let rendered = failure.to_json().to_text();
            assert!(rendered.contains(tag), "{tag}");
        }

        // A refused name and an absent one read identically, so a prober learns
        // nothing from the difference.
        assert_eq!(Failure::Refused(Refusal::Traversal).to_string(), Failure::NotFound.to_string());

        // The two refusals that clear on their own say so.
        let busy = Failure::OutOfRoom(Admission::TooManyUploads { limit: 8 });
        assert_eq!(busy.status_code(), 503);
        assert!(busy.retryable());
        assert_eq!(failed(&busy).headers.get_str("retry-after"), Some("5"));
    }

    #[test]
    fn the_json_helpers_carry_the_headers_a_listing_needs() {
        let response = done();
        assert_eq!(response.status, Status::OK);
        assert_eq!(response.headers.get_str("cache-control"), Some("no-store"));
        assert_eq!(response.headers.get_str("x-content-type-options"), Some("nosniff"));

        let listing = Listing::new(
            RelativePath::default(),
            vec![Entry::new(std::ffi::OsStr::new("a.txt"), Kind::File, 3, None)],
        );
        assert!(!listed(&listing).body.is_empty());

        let at = RelativePath::default().join("a.txt").expect("a legal name");
        let stated = stated(&at, &Attributes { kind: Kind::File, size: 3, modified: None });
        assert_eq!(stated.status, Status::OK);
    }

    #[test]
    fn a_share_id_is_what_the_ledger_keys_on() {
        let root = scratch("ids");
        let volume = open_volume("vault", &root, None);
        assert_eq!(volume.share().id(), &ShareId::parse("vault").expect("a legal id"));
        assert_eq!(volume.limits().quota_bytes, None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
