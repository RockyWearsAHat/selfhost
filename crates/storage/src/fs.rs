//! The impure floor: opening, reading and writing bytes in a share.
//!
//! Two things live here, and they are the two halves of one promise. [`Dir`] is
//! the **descriptor walk**: the only way this crate reaches a name on disk, and
//! the reason a symlink cannot lead out of a share. [`Upload`] is the
//! **creation primitive**: the reason a write cannot silently destroy a file
//! that was already there.
//!
//! The streaming copy loop and the quota bookkeeping that wraps it still belong
//! to Phase 5; what is here is everything those need to be built *on*.
//!
//! # Why the resolver is not the confinement
//!
//! [`crate::path`] proves that a request *names* something inside the share.
//! Only this layer can prove that the *bytes* it reaches are inside the share,
//! and the difference is a symlink. On a published static site that gap is
//! theoretical, because nobody can create the link. On a share the attacker can
//! — over WebDAV, over SMB, or as any local user of a box that also hosts three
//! other web applications — so a textual check followed by `File::open` is not a
//! confinement at all. `File::open("/srv/vault/photos/x")` walks `photos`
//! wherever `photos` points, and it does so *after* the resolver has finished
//! agreeing that the name looked fine.
//!
//! `Path::canonicalize` cannot patch that. It returns `ENOENT` for every path
//! being created, which is the whole write path; and canonicalising the deepest
//! *existing* ancestor and joining the rest leaves everything below that
//! ancestor unchecked at open time, which widens the race rather than closing
//! it. `proxy/src/files.rs::confine` (`:172`) is right for a read-only root and
//! wrong here, which is why this crate does not call it.
//!
//! **The open is the confinement.** [`Dir`] holds an open directory descriptor
//! and every step down is taken *relative to that descriptor*, one already
//! validated component at a time, with the platform's refuse-a-link flag set:
//!
//! - unix — `openat(dirfd, name, O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC)`. A
//!   symlink at that name fails with `ELOOP` instead of redirecting.
//! - Windows — `NtCreateFile` with the parent handle as `RootDirectory` and
//!   `FILE_OPEN_REPARSE_POINT`, then the opened object's own attributes are
//!   checked for `FILE_ATTRIBUTE_REPARSE_POINT`. Windows opens the reparse
//!   point rather than failing, so the refusal is ours to make and it is made
//!   on the handle, not on a name that could have changed since.
//!
//! No full path is ever handed to the operating system below the root. That is
//! what makes the guarantee structural: there is no window between "we checked"
//! and "we opened", because the check *is* the open, and it is repeated for
//! every single component.
//!
//! Two consequences worth stating plainly. **We never create a link** — no
//! symlink, no hardlink, at any API; the SMB backend sets `follow symlinks = no`
//! and `wide links = no` for the same reason from the other direction. And a
//! symlink already sitting in a share is not followed, not served, and reported
//! by [`crate::listing`] as an entry that exists and cannot be reached.
//!
//! # Where the guarantee still has an edge, said out loud
//!
//! - **The share root itself is opened by path**, once, and
//!   [`Dir::open_root`] canonicalises it first. That is deliberate: an operator
//!   who points a share at `/Volumes/media` through a symlink meant it. Every
//!   component *below* the root is walked; none of them may be a link.
//! - **[`Dir::names`] reads the directory by path**, because enumerating a
//!   directory from a descriptor needs `fdopendir`/`readdir` on unix — whose
//!   `struct dirent` layout and even whose symbol name vary by operating system
//!   and architecture — and `NtQueryDirectoryFile` on Windows. Getting that
//!   wrong reads garbage filenames on a platform this machine cannot test, which
//!   is a worse failure than the one it would close. So the read is guarded
//!   instead: the path is opened and its identity compared against the walked
//!   descriptor, and a mismatch is [`OpenError::Moved`]. What remains is a
//!   window in which an attacker could make us enumerate *a different
//!   directory's names*. Nothing is opened, read or written through that result
//!   — [`Dir::collision`] uses it only to name a file in a `409` message — so
//!   the window leaks names at worst and can never move a byte.
//! - **A staged replace publishes with `std::fs::rename` on textual paths.**
//!   `rename` never follows the final component, and the directory above it was
//!   proven link-free by the walk, but a component swapped *afterwards* could
//!   still redirect the publish. Closing it needs `renameat` on unix and
//!   `SetFileInformationByHandle(FileRenameInfo)` with a `RootDirectory` on
//!   Windows. It is owed with the write verbs in Phase 5, which is where
//!   [`Existing::Replace`] first becomes reachable at all; it is written down
//!   here rather than left to be discovered.
//!
//! # Why the create happens at the destination name
//!
//! This file used to describe one scheme for every write: a temporary file named
//! with [`crate::path::TEMP_PREFIX`] in the destination directory, then
//! `rename` into place. That is the right shape for replacing a file whose
//! *contents* must never be seen half-written — it is what
//! `admin/src/store.rs:77-88` does for the service catalogue — and it is the
//! wrong shape for creating one, because `rename(2)` replaces its destination
//! **silently and unconditionally**. The `O_EXCL` in that scheme guards the
//! temporary name, which nobody is racing for, and guards nothing at the name
//! that matters.
//!
//! The consequence was not theoretical. A share on this machine's APFS volume
//! holds `café.txt` spelled NFC; an upload names it NFD (`cafe` + U+0301);
//! [`crate::path::collides`] is a case fold and reports no collision, so the
//! upload proceeds; `create_new` on the temporary name succeeds; the rename
//! succeeds — and because APFS decomposes both spellings to one key, the
//! original file is gone. Every call returned `Ok`.
//!
//! Two fixes were available. The first is to teach `collides` about Unicode
//! normalisation, which needs the decomposition tables — a dependency this
//! project does not take, and a hand-rolled Latin-1 subset of them would be
//! right for `café.txt`, wrong for `한.txt`, and *trusted* for both, which is
//! worse than the honest gap. It would also still be a guess about somebody
//! else's volume: case- and normalisation-folding are per-filesystem and, on
//! APFS, per-volume properties that no pure function can know.
//!
//! So the second: **ask the volume.** [`Upload::begin`] creates the destination
//! name itself, exclusively — `O_CREAT | O_EXCL` on unix, `FILE_CREATE` on
//! Windows — which fails with `EEXIST` exactly when that volume considers the
//! name taken, under whatever folding it applies, including one this code has
//! never heard of. The exclusive create *is* the collision oracle, and
//! [`crate::path::collides`] is demoted to what it always was: the half of the
//! answer that can be explained in a `409` message, which is precisely the job
//! [`Dir::collision`] does.
//!
//! Only a caller that explicitly asked to replace an existing file
//! ([`Existing::Replace`]) reaches a `rename`, and it reaches one only after the
//! exclusive create has already reported that something is there. So the
//! destructive operation happens exactly when destruction was the request.
//!
//! ## The residue, stated exactly
//!
//! A fresh file is written **in place**, so a concurrent reader can observe it
//! partially written, and an upload cut off mid-body leaves a short file at the
//! destination rather than nothing. [`Upload`]'s `Drop` removes it, but a
//! process killed between the create and the last byte cannot run that, so after
//! a crash a share can hold a truncated file whose name is the one the uploader
//! chose. That is visible in every listing and deletable by the operator, and it
//! is the price of never silently destroying a file that was already there. The
//! alternative — atomic contents, occasional silent data loss — is the trade
//! this project will not make. WebDAV clients that need atomic publication have
//! `MOVE`, which is a rename the caller asked for by name.
//!
//! A replace is atomic in its contents, as before.

use crate::path::{self, RelativePath, Refusal, TEMP_PREFIX};
use std::fmt;
use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
#[path = "fs/unix.rs"]
mod sys;

#[cfg(windows)]
#[path = "fs/windows.rs"]
mod sys;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "crates/storage has no descriptor walk for this platform, and a share served without one \
     is a share a symlink can lead out of. Add a `fs/<platform>.rs` implementing `sys` before \
     enabling this target rather than falling back to opening paths."
);

/// Why a name could not be opened.
///
/// Typed rather than a bare [`io::Error`] because three of these are decisions
/// this module made — [`OpenError::Symlink`], [`OpenError::NotAFile`],
/// [`OpenError::Moved`] — and flattening them into "I/O error" would hide the
/// one class of failure an operator most needs to see: a share containing
/// something that is trying to lead out of it.
///
/// A route turns [`OpenError::NotFound`], [`OpenError::Symlink`] and
/// [`OpenError::NotAFile`] into the *same* `404`, exactly as
/// `proxy/src/server.rs:889` does for the static server: a prober must not learn
/// from the status code whether a name exists but is a link.
#[derive(Debug)]
pub enum OpenError {
    /// The name is not one this share will serve, and here is which rule fired.
    Refused(Refusal),
    /// A component is a symlink (unix) or a reparse point (Windows). The walk
    /// refuses rather than following, which is the whole point of the walk.
    Symlink,
    /// Nothing of that name is there.
    NotFound,
    /// A component that had to be a directory is not one.
    NotADirectory,
    /// The final name is not a regular file — a directory, a device, a socket or
    /// a FIFO. Serving any of those would block the daemon or read a device.
    NotAFile,
    /// The name is already taken, as [`Upload::begin`]'s exclusive create found
    /// out from the volume itself.
    AlreadyExists,
    /// The path no longer names the directory this descriptor is open on, so a
    /// by-path read of it would be a read of something else. See the module
    /// documentation's note on [`Dir::names`].
    Moved,
    /// The filesystem refused, and this is what it said.
    Io(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "name refused: {refusal}"),
            Self::Symlink => f.write_str("a component is a link, which a share never follows"),
            Self::NotFound => f.write_str("no such name in this share"),
            Self::NotADirectory => f.write_str("a component is not a directory"),
            Self::NotAFile => f.write_str("that name is not a regular file"),
            Self::AlreadyExists => f.write_str("a file of that name already exists"),
            Self::Moved => f.write_str("the directory moved while it was being read"),
            Self::Io(error) => write!(f, "filesystem error: {error}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Refusal> for OpenError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

/// An open directory inside a share, and the proof that no link was followed to
/// reach it.
///
/// Every value of this type was produced either by [`Dir::open_root`] — the one
/// place a directory is named by path — or by a walk from such a value, one
/// [`crate::path::validate_segment`]-checked component at a time. There is no
/// constructor that takes a path and skips the walk, deliberately: a type whose
/// only guarantee can be opted out of is documentation with a `struct` around
/// it.
///
/// The descriptor is what everything else is done relative to, so a `Dir` must
/// be kept alive for as long as work is being done in it — which is why
/// [`Upload`] borrows one rather than copying a path out of it.
#[derive(Debug)]
pub struct Dir {
    /// The open directory. On unix a descriptor, on Windows a handle; both are
    /// owned by [`File`] so that closing is the compiler's job rather than a
    /// habit maintained on every error path.
    handle: File,
    /// Where this directory was when it was opened, for messages, logs and the
    /// guarded read in [`Dir::names`]. **Never** used to open anything.
    path: PathBuf,
}

impl Dir {
    /// Opens a share root, canonicalising it first.
    ///
    /// This is the only function in the crate that opens a directory by name,
    /// and the canonicalise is deliberate rather than an oversight: an operator
    /// who declares a share at a path that happens to be a symlink meant that
    /// path, and resolving it once at startup is how the root becomes a fixed
    /// point that the rest of the walk can be measured against. Everything
    /// *below* the root is walked with links refused.
    ///
    /// Canonicalising also gives [`crate::share::Share`]'s textual root check
    /// the thing it admits it cannot see — that check refuses a root that is,
    /// contains, or sits inside a protected directory, but it reads text, and a
    /// symlink is not text. A caller that wants both guarantees compares this
    /// canonical path against the same [`crate::share::Reserved`] set at
    /// startup.
    pub fn open_root(root: &Path) -> Result<Self, OpenError> {
        let canonical = std::fs::canonicalize(root).map_err(classify_io)?;
        let handle = sys::open_root(&canonical)?;
        if !handle.metadata().map_err(classify_io)?.is_dir() {
            return Err(OpenError::NotADirectory);
        }
        Ok(Self { handle, path: canonical })
    }

    /// The path this directory was opened at — for a log line or a message.
    ///
    /// Opening anything joined onto this is the defect the whole module exists
    /// to prevent; [`Dir::open_dir`] and [`Dir::open_file`] are the ways down.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory's own metadata, read from the descriptor.
    ///
    /// From the descriptor and not from the path, so the answer describes the
    /// directory that was walked to rather than whatever the path names now.
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.handle.metadata()
    }

    /// Descends one already-validated component, refusing a link.
    ///
    /// The name is re-validated here rather than trusted. A name reaches this
    /// function from a request line, from a WebDAV `Destination` header, or
    /// from a directory read — and a name that came *off* the disk is no safer
    /// than one that arrived on the wire, because it may have been written over
    /// SMB by somebody else entirely.
    pub fn open_dir(&self, name: &str) -> Result<Self, OpenError> {
        path::validate_segment(name)?;
        let handle = sys::open_child_dir(&self.handle, name)?;
        if !handle.metadata().map_err(classify_io)?.is_dir() {
            return Err(OpenError::NotADirectory);
        }
        Ok(Self { handle, path: self.path.join(name) })
    }

    /// Walks a whole validated relative path, component by component.
    ///
    /// The root of a share walks to itself, which is why this returns a new
    /// `Dir` rather than an `Option`: "the share root" is a perfectly ordinary
    /// answer and a caller should not have to special-case it.
    pub fn walk(&self, relative: &RelativePath) -> Result<Self, OpenError> {
        let mut here = self.reopen()?;
        for segment in relative.segments() {
            here = here.open_dir(segment)?;
        }
        Ok(here)
    }

    /// Opens one child as a regular file, refusing a link and refusing anything
    /// that is not an ordinary file.
    ///
    /// The second refusal is not fussiness. A FIFO opened for reading blocks
    /// until somebody writes to it, and a daemon that blocks on a filename an
    /// attacker chose has been stopped by a `mkfifo`; a device node reads the
    /// device. The unix walk therefore opens non-blocking and this check throws
    /// away anything that is not a regular file, so neither can happen.
    pub fn open_file(&self, name: &str) -> Result<File, OpenError> {
        path::validate_segment(name)?;
        let handle = sys::open_child_file(&self.handle, name)?;
        if !handle.metadata().map_err(classify_io)?.is_file() {
            return Err(OpenError::NotAFile);
        }
        Ok(handle)
    }

    /// Opens the file a resolved request names, walking every directory above
    /// it.
    ///
    /// The share root is not a file, so a root path is [`OpenError::NotAFile`]
    /// rather than a panic or an empty read — a `GET` of a collection is a
    /// listing, and that decision belongs to the route.
    pub fn open_at(&self, relative: &RelativePath) -> Result<File, OpenError> {
        let Some(name) = relative.file_name() else {
            return Err(OpenError::NotAFile);
        };
        self.walk(&relative.parent())?.open_file(name)
    }

    /// The names in this directory, read under the guard the module
    /// documentation describes.
    ///
    /// The identity of the path is compared against this descriptor before the
    /// read, so a directory that has been swapped since the walk is
    /// [`OpenError::Moved`] rather than a silent read of somewhere else. What
    /// this does **not** promise is that no swap happens between that comparison
    /// and the read itself; nothing is opened through the result, so the residual
    /// window discloses names and can never move a byte.
    ///
    /// Names arrive as [`std::ffi::OsString`] because that is what the volume
    /// holds: a name that is not valid UTF-8 exists, must be shown, and must not
    /// be silently repaired into a different name. [`crate::listing::Entry::new`]
    /// is what turns one into something a listing can show.
    ///
    /// **Names only.** A listing also needs each entry's kind, size and
    /// modification time, and this does not supply them — the honest way to get
    /// them is [`Dir::open_dir`] or [`Dir::open_file`] per name followed by
    /// `File::metadata`, which is confined but costs an open per entry. That
    /// trade belongs to whoever writes the listing route, and it is left here as
    /// a decision rather than made quietly: a by-path `symlink_metadata` per
    /// entry would be cheaper and would reintroduce exactly the redirection this
    /// module removes.
    pub fn names(&self) -> Result<Vec<std::ffi::OsString>, OpenError> {
        let by_path = sys::open_root(&self.path)?;
        if !sys::same_object(&self.handle, &by_path) {
            return Err(OpenError::Moved);
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path).map_err(classify_io)? {
            names.push(entry.map_err(classify_io)?.file_name());
        }
        Ok(names)
    }

    /// The existing name that would fold onto `proposed`, if this directory
    /// holds one.
    ///
    /// This is the case/normalisation collision scan, and its exact standing is
    /// worth being precise about, because a reader who mistakes it for the
    /// safety mechanism will later "simplify" the exclusive create away:
    ///
    /// - It is **not** what stops an upload destroying a file. That is
    ///   [`Upload::begin`]'s exclusive create, which asks the volume rather than
    ///   guessing on its behalf.
    /// - It is what lets a `409` say *`report.pdf` is already here* instead of
    ///   *already exists*, on a volume that folded the two names together.
    /// - It is also a policy gate on a volume that does **not** fold: `ext4`
    ///   will happily hold `Report.pdf` beside `report.pdf`, and a share that
    ///   accepted both would be a share that cannot be copied to a Mac or a
    ///   Windows box without one of them destroying the other. So
    ///   [`Existing::Refuse`] refuses the pair here too, and says which name it
    ///   collided with.
    ///
    /// [`crate::path::collides`] supplies the fold, and its documentation is
    /// exact about what a `false` from it does and does not mean.
    ///
    /// This reads the whole directory, so an upload into a directory of forty
    /// thousand files costs forty thousand comparisons before it starts. That is
    /// the price of the third bullet and it is worth stating: a share used as a
    /// bulk dump rather than as a person's files will feel it, and the way out
    /// when it matters is an index kept beside the directory, not a quieter
    /// rule.
    pub fn collision(&self, proposed: &str) -> Result<Option<String>, OpenError> {
        for name in self.names()? {
            let Some(text) = name.to_str() else {
                continue;
            };
            if path::collides(text, proposed) {
                return Ok(Some(text.to_string()));
            }
        }
        Ok(None)
    }

    /// Flushes this directory's own metadata, so a name that was published
    /// survives a power cut.
    ///
    /// On unix a rename is durable only once the *directory* is synced; bytes
    /// surviving under no name is not a useful guarantee. Windows has no
    /// directory sync reachable this way and journals the metadata operation
    /// itself, so the platform already makes the promise this would buy — which
    /// is why the implementation is one of the few `cfg`-gated pieces in the
    /// crate. It is gated because it is a *durability* detail; the security
    /// rules here are unconditional on purpose, and
    /// [`crate::path::validate_segment`] says at length why.
    pub fn sync(&self) -> Result<(), OpenError> {
        #[cfg(unix)]
        self.handle.sync_all().map_err(classify_io)?;
        Ok(())
    }

    /// A second descriptor onto the same directory, so a walk can start from a
    /// borrowed `Dir` without consuming it.
    ///
    /// Duplicating the descriptor keeps the guarantee: the copy points at the
    /// same directory *object* the walk reached, not at a path that might name
    /// something else by now.
    fn reopen(&self) -> Result<Self, OpenError> {
        let handle = self.handle.try_clone().map_err(classify_io)?;
        Ok(Self { handle, path: self.path.clone() })
    }
}

/// Maps a standard-library error onto this module's vocabulary.
///
/// Only the two kinds `std` names portably are translated; everything else stays
/// an [`OpenError::Io`] carrying the original, because an operator diagnosing a
/// full disk needs `ENOSPC` and a `Permission denied` that arrives as "open
/// failed" costs an hour.
fn classify_io(error: io::Error) -> OpenError {
    match error.kind() {
        io::ErrorKind::NotFound => OpenError::NotFound,
        io::ErrorKind::AlreadyExists => OpenError::AlreadyExists,
        _ => OpenError::Io(error),
    }
}

/// What an already-taken destination name means to this caller.
///
/// The distinction is the caller's *intent*, not a hint about what is on disk:
/// a `PUT` to a name a WebDAV client believes is free is [`Existing::Refuse`],
/// and a `PUT` the client issued knowing it overwrites is
/// [`Existing::Replace`]. Only the second is allowed to destroy anything, and
/// it is the only path in this module that reaches a `rename`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse the write. The answer on the wire is `409`, and
    /// [`Dir::collision`] supplies the name to put in the message when it can.
    Refuse,
    /// Replace the file that is there, atomically.
    Replace,
}

/// Why a write could not be started or finished.
///
/// Typed rather than a bare [`io::Error`] because exactly two of these are
/// normal outcomes the route turns into a status code — [`WriteError::NameTaken`]
/// and [`WriteError::Collides`] are both `409` — while the rest are the box
/// being unwell.
#[derive(Debug)]
pub enum WriteError {
    /// The name is not one this share will serve. Carries the resolver's reason.
    Refused(Refusal),
    /// The volume says the destination name is already taken.
    ///
    /// Note the phrasing: *the volume says*. On a case- or normalisation-folding
    /// filesystem this fires for a name that is not byte-identical to any
    /// existing one, which is the whole point — see this module's documentation.
    NameTaken,
    /// The name folds onto one already in the directory, and here is that one.
    ///
    /// Distinct from [`WriteError::NameTaken`] because it can say *which* file
    /// the upload would have collided with, which is the difference between a
    /// message a person can act on and one they cannot.
    Collides {
        /// The name already in the directory.
        existing: String,
    },
    /// The directory could not be reached, or the file could not be opened.
    Open(OpenError),
    /// The filesystem refused, and this is what it said.
    Io(io::Error),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "name refused: {refusal}"),
            Self::NameTaken => f.write_str("a file of that name already exists"),
            Self::Collides { existing } => {
                write!(f, "this name cannot be told apart from the existing {existing}")
            }
            Self::Open(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "filesystem error: {error}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Refused(refusal) => Some(refusal),
            Self::Open(error) => Some(error),
            Self::NameTaken | Self::Collides { .. } => None,
        }
    }
}

impl From<io::Error> for WriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Refusal> for WriteError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<OpenError> for WriteError {
    /// Keeps the two refusals that already have a name of their own, so a route
    /// matching on [`WriteError`] does not have to reach through a wrapper to
    /// find the `409` it is looking for.
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Refused(refusal) => Self::Refused(refusal),
            OpenError::AlreadyExists => Self::NameTaken,
            other => Self::Open(other),
        }
    }
}

/// A file being written into a share, and the promise that it destroys nothing
/// the caller did not ask it to.
///
/// The upload borrows the [`Dir`] it writes into, which is how the descriptor
/// walk reaches this far: the file is created *relative to that descriptor*, so
/// no part of the path can be redirected between the walk and the create. The
/// borrow is not a lifetime formality — it is the guarantee.
///
/// # Lifecycle
///
/// [`begin`](Upload::begin), write into [`file`](Upload::file), then either
/// [`commit`](Upload::commit) — which flushes, publishes and (on unix) fsyncs
/// the containing directory — or [`abandon`](Upload::abandon), which removes
/// what was created and *reports* whether it managed to. Dropping without either
/// also removes it, best effort and silently, which is the crash-safety net and
/// not the intended path: a `Drop` cannot return an error, so a caller that
/// wants to know calls `abandon`.
#[derive(Debug)]
pub struct Upload<'a> {
    /// The directory this write is confined to, held open for the whole write.
    directory: &'a Dir,
    /// `None` once the handle has been surrendered by `commit`, which is also
    /// how `Drop` knows the upload was finished rather than dropped.
    handle: Option<File>,
    /// The name the bytes must end up under.
    name: String,
    /// The temporary name currently holding the bytes, when the caller asked to
    /// replace something. `None` means the handle is already the destination.
    staged: Option<String>,
}

impl<'a> Upload<'a> {
    /// Creates `name` in `directory` without destroying anything.
    ///
    /// The name is re-validated here rather than trusted, exactly as
    /// [`Dir::open_dir`] does and for the same reason: a name can reach this
    /// function from a request line, a WebDAV `Destination` header, or a
    /// directory read, and only one of those three has been past the resolver.
    ///
    /// Then, for [`Existing::Refuse`] only, the directory is scanned for a name
    /// that folds onto this one ([`Dir::collision`]) — which catches the pair
    /// that a case-sensitive volume would otherwise accept and every Mac and
    /// Windows client would later ruin.
    ///
    /// Then the destination name is created exclusively, which is the collision
    /// oracle described in this module's documentation:
    ///
    /// - it succeeds → nothing was there by *this volume's* reckoning, and the
    ///   bytes are written straight into the file that was just created;
    /// - it fails "already exists" and the caller said [`Existing::Refuse`] →
    ///   [`WriteError::NameTaken`], with nothing on disk touched;
    /// - it fails "already exists" and the caller said [`Existing::Replace`] →
    ///   the bytes go to a [`TEMP_PREFIX`] file in the same directory, and
    ///   [`commit`](Upload::commit) renames it over the destination.
    ///
    /// An exclusive create also refuses a destination that is a symlink,
    /// dangling or not, because an exclusive create never follows the final
    /// component. That is part of the guarantee rather than an accident of the
    /// API: an attacker who plants `notes.txt -> /etc/crontab` inside a share
    /// gets a refusal rather than a write through it.
    ///
    /// This call blocks. Every caller in the daemon runs it on
    /// `spawn_blocking`, the same discipline the mail and admin stores follow
    /// for their own `std::fs` work.
    pub fn begin(
        directory: &'a Dir,
        name: &str,
        existing: Existing,
    ) -> Result<Self, WriteError> {
        path::validate_segment(name)?;

        if existing == Existing::Refuse {
            if let Some(collision) = directory.collision(name)? {
                return Err(WriteError::Collides { existing: collision });
            }
        }

        match sys::create_child(&directory.handle, name) {
            Ok(handle) => Ok(Self {
                directory,
                handle: Some(handle),
                name: name.to_string(),
                staged: None,
            }),
            Err(OpenError::AlreadyExists) => match existing {
                Existing::Refuse => Err(WriteError::NameTaken),
                Existing::Replace => {
                    let staged = temporary_name();
                    let handle = sys::create_child(&directory.handle, &staged)?;
                    Ok(Self {
                        directory,
                        handle: Some(handle),
                        name: name.to_string(),
                        staged: Some(staged),
                    })
                }
            },
            Err(other) => Err(other.into()),
        }
    }

    /// The handle the body is streamed into.
    ///
    /// Returned rather than wrapped in a `write` method so that the copy loop
    /// can be `io::copy` or a fixed scratch buffer without this type having an
    /// opinion, and so that a caller can `set_len` a known content length.
    /// Writing here is not durable and, for a replace, not visible under the
    /// destination name until [`commit`](Upload::commit).
    ///
    /// # Panics
    ///
    /// Never in practice: [`commit`](Upload::commit) consumes the upload, so a
    /// handle taken by it cannot be asked for again. The `expect` states that
    /// invariant where a future edit would break it.
    pub fn file(&mut self) -> &mut File {
        self.handle.as_mut().expect("an Upload holds its handle until it is committed")
    }

    /// The name the bytes will appear under, for logs and messages.
    pub fn destination(&self) -> PathBuf {
        self.directory.path().join(&self.name)
    }

    /// Flushes, publishes, and reports anything that went wrong.
    ///
    /// `sync_all` first, then — only when the write was staged — the rename,
    /// then an fsync of the containing directory on unix so that the name
    /// survives a power cut rather than only the bytes. The order is the
    /// durability argument every atomic write in this repository makes; the
    /// difference here is that in the common case there is no rename at all,
    /// because the file was created at its final name.
    ///
    /// A failure leaves the partial file where it is and returns why. It is not
    /// cleaned up, deliberately: a failing `sync_all` is usually a full or dying
    /// disk, and issuing more writes to prettify the directory is how the last
    /// good data goes too. The route answers `507`/`500` and the operator sees
    /// the file in the listing.
    pub fn commit(mut self) -> Result<(), WriteError> {
        // Taken before the rename because Windows refuses to rename a file with
        // an open handle, and dropping the `File` is how it is closed.
        let handle = self.handle.take().expect("commit consumes the upload exactly once");
        handle.sync_all()?;
        drop(handle);

        if let Some(staged) = self.staged.take() {
            // The one publish that is still done by path; the module
            // documentation states the residual window and what closes it.
            let directory = self.directory.path();
            std::fs::rename(directory.join(&staged), directory.join(&self.name))?;
        }
        self.directory.sync()?;
        Ok(())
    }

    /// Removes what was created and says whether it worked.
    ///
    /// The honest counterpart to `Drop`: a caller that abandons an upload
    /// because the client hung up wants the leftover gone, and wants to log it
    /// if the filesystem would not co-operate.
    pub fn abandon(mut self) -> Result<(), WriteError> {
        match self.remove() {
            // Something else already removed it, which is the state we wanted.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other.map_err(WriteError::Io),
        }
    }

    /// Removes whichever name currently holds the bytes.
    ///
    /// Shared by [`abandon`](Upload::abandon) and `Drop` so that the two cannot
    /// drift into removing different files; the handle is surrendered to the
    /// platform because Windows deletes through it rather than by name.
    fn remove(&mut self) -> io::Result<()> {
        let name = self.staged.clone().unwrap_or_else(|| self.name.clone());
        let handle = self.handle.take();
        sys::remove_child(&self.directory.handle, &name, handle)
    }
}

impl Drop for Upload<'_> {
    /// Best-effort cleanup for the path nobody wrote: a panic, a `?` in the
    /// middle of a copy loop, a task cancelled at an `await`.
    ///
    /// Silent by necessity — a `Drop` has nowhere to report — which is precisely
    /// why [`Upload::abandon`] exists and why the failure this cannot report is
    /// stated in the module documentation as visible residue rather than hidden.
    fn drop(&mut self) {
        if self.handle.is_none() {
            return;
        }
        let _ = self.remove();
    }
}

/// A name for a staged write, inside the namespace [`TEMP_PREFIX`] reserves.
///
/// Uniqueness is belt and braces: the process id separates two daemons sharing a
/// volume, the counter separates concurrent uploads in one process, and the
/// clock separates restarts that reuse a process id. None of it has to be
/// unguessable, because the file is created exclusively — a name that collides
/// is an error, never a silent reuse — and it cannot be planted by a caller,
/// because [`crate::path::validate_segment`] refuses the prefix.
fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.subsec_nanos())
        .unwrap_or_default();
    format!("{TEMP_PREFIX}{:x}-{nanos:x}-{sequence:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A scratch directory of our own, shaped on `admin/src/store.rs`'s.
    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("selfhost-storage-fs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        // Canonicalised because `Dir::open_root` canonicalises, and on macOS
        // `/tmp` is itself a symlink to `/private/tmp` — a test that compared
        // the two raw would be testing the platform's spelling.
        std::fs::canonicalize(&path).expect("a canonical scratch directory")
    }

    fn open(path: &Path) -> Dir {
        Dir::open_root(path).expect("the scratch root opens")
    }

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).expect("fixture written");
    }

    fn read_file(path: &Path) -> String {
        let mut text = String::new();
        File::open(path).expect("fixture readable").read_to_string(&mut text).expect("utf-8");
        text
    }

    fn relative(segments: &[&str]) -> RelativePath {
        let mut path = RelativePath::default();
        for segment in segments {
            path = path.join(segment).expect("a legal test path");
        }
        path
    }

    /// The ordinary case, so the refusals below read as rules rather than as an
    /// outage: a nested path walks, and the file at the end of it reads.
    #[test]
    fn a_walk_descends_through_real_directories_and_opens_the_file_at_the_end() {
        let root = scratch("walk-ordinary");
        std::fs::create_dir_all(root.join("photos").join("2026")).expect("directories");
        write_file(&root.join("photos").join("2026").join("notes.txt"), "inside");

        let dir = open(&root);
        let walked = dir.walk(&relative(&["photos", "2026"])).expect("walked");
        assert_eq!(walked.path(), root.join("photos").join("2026"));
        assert!(walked.metadata().expect("metadata").is_dir());

        let mut file =
            dir.open_at(&relative(&["photos", "2026", "notes.txt"])).expect("a real file");
        let mut text = String::new();
        file.read_to_string(&mut text).expect("utf-8");
        assert_eq!(text, "inside");

        // And a walk through a name that is a file, not a directory, stops.
        assert!(matches!(
            dir.walk(&relative(&["photos", "2026", "notes.txt"])),
            Err(OpenError::NotADirectory)
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The whole point of the module: a symlink is refused, not followed.
    ///
    /// This test is also what keeps the platform flag constants honest. Both
    /// `O_NOFOLLOW` and `O_DIRECTORY` are spelled as numbers per operating
    /// system and architecture, and a wrong `O_NOFOLLOW` would silently restore
    /// the vulnerability rather than fail to compile — so the guarantee is
    /// asserted against a real link on the running platform rather than trusted
    /// to a table.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_refused_rather_than_followed() {
        let root = scratch("walk-root");
        let outside = scratch("walk-outside");
        write_file(&outside.join("secret"), "secret");
        std::os::unix::fs::symlink(&outside, root.join("escape")).expect("linked");
        std::fs::create_dir(root.join("real")).expect("a real directory");
        write_file(&root.join("real").join("notes.txt"), "inside");

        let dir = open(&root);
        assert!(matches!(dir.open_dir("escape"), Err(OpenError::Symlink)));
        assert!(matches!(dir.walk(&relative(&["escape"])), Err(OpenError::Symlink)));
        assert!(matches!(
            dir.open_at(&relative(&["escape", "secret"])),
            Err(OpenError::Symlink)
        ));

        // And the ordinary case still works, so the refusal is a rule and not
        // an outage.
        let mut inside = dir.open_at(&relative(&["real", "notes.txt"])).expect("a real file");
        let mut text = String::new();
        inside.read_to_string(&mut text).expect("utf-8");
        assert_eq!(text, "inside");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A symlink to a *file* is refused too, and so is one that dangles.
    ///
    /// The file case matters on its own: a link named `notes.txt` pointing at
    /// `/etc/passwd` is the whole attack, and it is the last component — the one
    /// a walk that only checked directories would hand straight to `open`.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_is_refused_and_so_is_a_dangling_one() {
        let root = scratch("walk-file");
        let outside = scratch("walk-file-outside");
        let secret = outside.join("secret");
        write_file(&secret, "secret");
        std::os::unix::fs::symlink(&secret, root.join("notes.txt")).expect("linked");
        std::os::unix::fs::symlink(outside.join("absent"), root.join("dangling.txt"))
            .expect("linked");

        let dir = open(&root);
        assert!(matches!(dir.open_file("notes.txt"), Err(OpenError::Symlink)));
        assert!(matches!(dir.open_file("dangling.txt"), Err(OpenError::Symlink)));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Nothing but a regular file is ever handed back, so a FIFO cannot stop the
    /// daemon and a device cannot be read through a share.
    #[cfg(unix)]
    #[test]
    fn a_directory_is_not_a_file_and_a_file_is_not_a_directory() {
        let root = scratch("kinds");
        std::fs::create_dir(root.join("photos")).expect("a directory");
        write_file(&root.join("notes.txt"), "text");

        let dir = open(&root);
        assert!(matches!(dir.open_file("photos"), Err(OpenError::NotAFile)));
        assert!(matches!(dir.open_dir("notes.txt"), Err(OpenError::NotADirectory)));
        assert!(matches!(dir.open_dir("absent"), Err(OpenError::NotFound)));
        assert!(matches!(dir.open_file("absent"), Err(OpenError::NotFound)));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The walk re-validates every component, so a name that came off the disk
    /// is checked exactly as hard as one that arrived on the wire.
    #[test]
    fn the_walk_refuses_a_name_the_resolver_refuses() {
        let root = scratch("walk-refuse");
        let dir = open(&root);
        for name in ["..", "a/b", "CON.txt", "trailing.", ".selfhost-tmp-x"] {
            assert!(
                matches!(dir.open_dir(name), Err(OpenError::Refused(_))),
                "{name} should be refused before it reaches the platform"
            );
            assert!(matches!(dir.open_file(name), Err(OpenError::Refused(_))), "{name}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The share root walks to itself, because "the root" is an ordinary answer.
    #[test]
    fn the_root_walks_to_itself_and_is_not_a_file() {
        let root = scratch("walk-root-self");
        let dir = open(&root);
        assert_eq!(dir.walk(&RelativePath::default()).expect("the root").path(), dir.path());
        assert!(matches!(dir.open_at(&RelativePath::default()), Err(OpenError::NotAFile)));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The reviewer's scenario, run against a real directory: an upload spelled
    /// NFD may not destroy the NFC file it folds onto.
    ///
    /// This is the exact sequence that used to lose data on APFS — write
    /// `café.txt` NFC, upload `cafe`+U+0301, watch every call return `Ok` and
    /// the original vanish. The assertion is deliberately written to hold on
    /// **both** kinds of volume, because that is the honest statement of the
    /// guarantee:
    ///
    /// - on a folding volume (APFS, NTFS) the exclusive create fails and the
    ///   upload is refused as [`WriteError::NameTaken`];
    /// - on a case- and form-sensitive volume (ext4) the two names are two
    ///   files, and the upload proceeds — the pure fold cannot see this pair, so
    ///   the collision scan does not catch it either.
    ///
    /// In neither case is the original's content anything but the original's.
    /// A test that asserted only the refusal would pass on this machine and
    /// silently mean nothing in CI, which is how this class of bug survives.
    #[test]
    fn an_nfd_upload_cannot_destroy_the_nfc_file_it_folds_onto() {
        let root = scratch("nfd");
        let nfc = "caf\u{e9}.txt";
        let nfd = "cafe\u{301}.txt";
        write_file(&root.join(nfc), "original");
        let dir = open(&root);

        // The pure fold cannot see this collision, which is the premise.
        assert!(!path::collides(nfc, nfd));

        match Upload::begin(&dir, nfd, Existing::Refuse) {
            Err(WriteError::NameTaken) => {
                // A folding volume answered the question the fold could not.
            }
            Ok(mut upload) => {
                upload.file().write_all(b"attacker").expect("written");
                upload.commit().expect("committed");
                assert_eq!(read_file(&root.join(nfd)), "attacker");
            }
            Err(other) => panic!("unexpected refusal: {other}"),
        }

        assert_eq!(
            read_file(&root.join(nfc)),
            "original",
            "the file that was already there must survive under either folding"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A name that folds onto an existing one is refused by name, on every
    /// volume — including the case-sensitive ones that would have allowed it.
    #[test]
    fn a_name_that_folds_onto_an_existing_one_is_refused_and_says_which() {
        let root = scratch("collide");
        write_file(&root.join("report.pdf"), "original");
        let dir = open(&root);

        assert_eq!(dir.collision("Report.pdf").expect("scanned").as_deref(), Some("report.pdf"));
        // A byte-identical name is an overwrite, not a collision: the caller's
        // intent decides that one, not the scan.
        assert_eq!(dir.collision("report.pdf").expect("scanned"), None);
        assert_eq!(dir.collision("notes.txt").expect("scanned"), None);

        match Upload::begin(&dir, "Report.pdf", Existing::Refuse) {
            Err(WriteError::Collides { existing }) => assert_eq!(existing, "report.pdf"),
            other => panic!("expected a named collision, got {other:?}"),
        }
        assert_eq!(read_file(&root.join("report.pdf")), "original");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_free_name_is_created_at_its_own_name_and_published_by_commit() {
        let root = scratch("create");
        let dir = open(&root);
        let mut upload = Upload::begin(&dir, "notes.txt", Existing::Refuse).expect("begun");
        assert_eq!(upload.destination(), root.join("notes.txt"));
        upload.file().write_all(b"hello").expect("written");

        // No temporary file is involved when nothing is being replaced.
        let staged = dir
            .names()
            .expect("readable")
            .into_iter()
            .filter(|name| name.to_string_lossy().starts_with(TEMP_PREFIX))
            .count();
        assert_eq!(staged, 0, "a fresh create must not stage");

        upload.commit().expect("committed");
        assert_eq!(read_file(&root.join("notes.txt")), "hello");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_occupied_name_is_refused_unless_replacing_was_the_request() {
        let root = scratch("occupied");
        write_file(&root.join("notes.txt"), "original");
        let dir = open(&root);

        let refused = Upload::begin(&dir, "notes.txt", Existing::Refuse);
        assert!(matches!(refused, Err(WriteError::NameTaken)));
        assert_eq!(read_file(&root.join("notes.txt")), "original");

        let mut replacing =
            Upload::begin(&dir, "notes.txt", Existing::Replace).expect("replace begun");
        replacing.file().write_all(b"replacement").expect("written");
        // Until commit, the original is still the file at that name — the
        // replace path stages, so its contents are never half-written.
        assert_eq!(read_file(&root.join("notes.txt")), "original");
        replacing.commit().expect("committed");
        assert_eq!(read_file(&root.join("notes.txt")), "replacement");

        // And the staging file is gone, not left behind as litter.
        let leftovers = dir
            .names()
            .expect("readable")
            .into_iter()
            .filter(|name| name.to_string_lossy().starts_with(TEMP_PREFIX))
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_abandoned_or_dropped_upload_leaves_nothing_behind() {
        let root = scratch("abandon");
        let dir = open(&root);

        let mut abandoned = Upload::begin(&dir, "half.txt", Existing::Refuse).expect("begun");
        abandoned.file().write_all(b"partial").expect("written");
        abandoned.abandon().expect("removed");
        assert!(!root.join("half.txt").exists());

        {
            let mut dropped = Upload::begin(&dir, "dropped.txt", Existing::Refuse).expect("begun");
            dropped.file().write_all(b"partial").expect("written");
        }
        assert!(!root.join("dropped.txt").exists());

        // Abandoning a replace removes the staged file and leaves the original.
        write_file(&root.join("kept.txt"), "original");
        let staged = Upload::begin(&dir, "kept.txt", Existing::Replace).expect("begun");
        staged.abandon().expect("removed");
        assert_eq!(read_file(&root.join("kept.txt")), "original");
        assert_eq!(dir.names().expect("readable").len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_name_the_resolver_refuses_never_reaches_the_disk() {
        let root = scratch("refused");
        let dir = open(&root);
        for (name, expected) in [
            ("CON.txt", Refusal::ReservedDeviceName),
            ("..", Refusal::Traversal),
            ("a/b", Refusal::NotOneComponent),
            ("trailing.", Refusal::TrailingDotOrSpace),
            (".selfhost-tmp-stolen", Refusal::ReservedPrefix),
            ("stream:evil", Refusal::ForbiddenCharacter(':')),
        ] {
            match Upload::begin(&dir, name, Existing::Replace) {
                Err(WriteError::Refused(refusal)) => assert_eq!(refusal, expected, "{name}"),
                other => panic!("{name} should be refused, got {other:?}"),
            }
        }
        assert_eq!(dir.names().expect("readable").len(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A planted symlink is refused rather than written through.
    ///
    /// The descriptor walk covers every component; this covers the last one,
    /// which is the create's own responsibility. It is worth its own test
    /// because the guarantee would be silently lost the day somebody replaced
    /// the exclusive create with a truncating one.
    #[cfg(unix)]
    #[test]
    fn an_exclusive_create_refuses_to_write_through_a_planted_symlink() {
        let root = scratch("symlink");
        let outside = scratch("symlink-target");
        let secret = outside.join("secret");
        write_file(&secret, "secret");
        std::os::unix::fs::symlink(&secret, root.join("notes.txt")).expect("linked");
        let dir = open(&root);

        assert!(matches!(
            Upload::begin(&dir, "notes.txt", Existing::Refuse),
            Err(WriteError::NameTaken)
        ));
        assert_eq!(read_file(&secret), "secret");

        // A caller that explicitly replaces gets the *link* replaced, because
        // `rename` acts on the name and not on what it points at.
        let mut replacing = Upload::begin(&dir, "notes.txt", Existing::Replace).expect("begun");
        replacing.file().write_all(b"local").expect("written");
        replacing.commit().expect("committed");
        assert_eq!(read_file(&secret), "secret", "the link's target is untouched");
        assert_eq!(read_file(&root.join("notes.txt")), "local");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A directory read whose path has been swapped underneath is refused
    /// rather than answered with somebody else's names.
    #[cfg(unix)]
    #[test]
    fn a_directory_read_whose_path_was_swapped_is_refused() {
        let root = scratch("moved");
        std::fs::create_dir(root.join("photos")).expect("a directory");
        write_file(&root.join("photos").join("a.txt"), "a");
        let elsewhere = scratch("moved-elsewhere");
        write_file(&elsewhere.join("b.txt"), "b");

        let dir = open(&root);
        let photos = dir.open_dir("photos").expect("walked");
        assert_eq!(photos.names().expect("readable").len(), 1);

        // The attacker replaces the directory with a link to their own.
        std::fs::remove_dir_all(root.join("photos")).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, root.join("photos")).expect("linked");
        assert!(matches!(photos.names(), Err(OpenError::Symlink | OpenError::Moved)));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn every_failure_says_what_it_was_without_flattening_the_cause() {
        use std::error::Error;

        let refused = WriteError::Refused(Refusal::Traversal);
        assert!(refused.to_string().contains("parent directory"));
        assert!(refused.source().is_some());

        assert!(WriteError::NameTaken.to_string().contains("already exists"));
        assert!(WriteError::NameTaken.source().is_none());

        let collides = WriteError::Collides { existing: "report.pdf".to_string() };
        assert!(collides.to_string().contains("report.pdf"));

        let io = WriteError::from(io::Error::new(io::ErrorKind::StorageFull, "no space left"));
        assert!(io.to_string().contains("no space left"));
        assert!(io.source().is_some());

        // An open failure keeps its own name when it has one, so a route does
        // not have to unwrap a wrapper to find its 409.
        assert!(matches!(WriteError::from(OpenError::AlreadyExists), WriteError::NameTaken));
        assert!(matches!(
            WriteError::from(OpenError::Refused(Refusal::Nul)),
            WriteError::Refused(Refusal::Nul)
        ));
        assert!(matches!(
            WriteError::from(OpenError::Symlink),
            WriteError::Open(OpenError::Symlink)
        ));
        assert!(OpenError::Symlink.to_string().contains("link"));
        assert!(OpenError::Moved.to_string().contains("moved"));
    }

    #[test]
    fn a_staged_name_is_unique_per_call_and_inside_our_reserved_namespace() {
        let first = temporary_name();
        let second = temporary_name();
        assert_ne!(first, second);
        for name in [&first, &second] {
            assert!(name.starts_with(TEMP_PREFIX));
            assert_eq!(path::validate_segment(name), Err(Refusal::ReservedPrefix));
        }
    }
}
