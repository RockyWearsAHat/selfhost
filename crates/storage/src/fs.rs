//! The impure floor: opening, reading and writing bytes in a share.
//!
//! Two things live here, and they are the two halves of one promise. [`Dir`] is
//! the **descriptor walk**: the only way this crate reaches a name on disk, and
//! the reason a symlink cannot lead out of a share. [`Upload`] is the
//! **creation primitive**: the reason a write cannot silently destroy a file
//! that was already there.
//!
//! Around those two, this module holds the rest of the write path's floor:
//! creating and removing directories ([`Dir::create_dir`], [`Dir::remove_dir`],
//! [`Dir::remove_tree`]), moving a name between two open directories
//! ([`Dir::rename_into`]), describing what is there ([`Dir::stat`],
//! [`Dir::entries`]), and the two numbers the quota is enforced against
//! ([`Dir::free_space`], [`Dir::measure`]). The streaming copy loop and the
//! bookkeeping that wraps it live in [`crate::api`], which drives these.
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
//! - **Publishing and moving are relative too, and no longer by path.** A
//!   staged replace once published with `std::fs::rename` on textual paths,
//!   which left a component swapped *after* the walk able to redirect it.
//!   [`Dir::rename_into`] and [`Upload::commit`] now go through `renameat` on
//!   unix and `SetFileInformationByHandle(FileRenameInfo)` with a
//!   `RootDirectory` handle on Windows, so both ends of every rename are
//!   descriptors and neither can be renamed out from under the operation.
//!   [`Dir::path`] is left with exactly one job: appearing in messages.
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

use crate::listing::{Entry, Kind};
use crate::path::{self, RelativePath, Refusal, TEMP_PREFIX};
use std::borrow::Borrow;
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

/// How far below a directory a recursive operation will descend.
///
/// Sixty-four. Deeper than any tree a person makes and far shallower than the
/// two thousand levels [`crate::path::MAX_PATH_BYTES`] would allow if every
/// name were one byte — and a share can genuinely hold such a tree, written
/// over SMB or restored from a backup. The limit is on the *recursion*, so its
/// job is to keep the stack bounded: under `panic = "abort"` a stack overflow
/// is not a failed request, it is the daemon that serves 80 and 443
/// disappearing while a share was being tidied.
///
/// Because it bounds the recursion and not the operation, it does not have to
/// mean a refusal. [`Dir::remove_tree`] keeps the bound and removes a tree of
/// any depth by resuming from a descriptor, and it is written that way because
/// deletion is the way out of every other refusal here — a share this API can
/// build a tree in and not remove one from is a share the operator has to fix
/// over SSH.
pub const MAX_TREE_DEPTH: usize = 64;

/// What one name in a directory turned out to be.
///
/// Returned as a value rather than as a [`Metadata`] because two of the three
/// fields are this crate's own answers rather than the platform's: a directory
/// reports zero bytes (its *contents* are a recursive walk, not a number a
/// listing may cost), and a modification time the filesystem declined to give
/// is `None` rather than an epoch that would sort as 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes {
    /// File or directory. Nothing else is ever reported: a link is a refusal.
    pub kind: Kind,
    /// Size in bytes, zero for a directory.
    pub size: u64,
    /// Last modification, when the filesystem reported one.
    pub modified: Option<SystemTime>,
}

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

    /// Whether this descriptor and another are open on the same directory.
    ///
    /// Asked of the two open objects — `(st_dev, st_ino)` on unix, the file
    /// index on Windows — and never of their paths, because the question is
    /// whether two walks arrived at one directory and a path is exactly the
    /// thing that can have been swapped since. An identity that cannot be
    /// proven answers `false`: "not proven the same" must never read as a
    /// match.
    ///
    /// [`crate::api::Volume`]'s `COPY` and `MOVE` are what need it. A move whose
    /// destination is its own source is data loss dressed as a rename, and it
    /// cannot be recognised from the two request paths alone: two shares can be
    /// two names for one directory, and a case-folding volume calls
    /// `report.pdf` and `Report.pdf` one file.
    pub fn is_same_directory(&self, other: &Self) -> bool {
        sys::same_object(&self.handle, &other.handle)
    }

    /// Whether two names, in two open directories, are one object on disk.
    ///
    /// The question a `MOVE` or a `COPY` must ask before it clears its
    /// destination, and the only form of it that is actually answerable. The two
    /// request paths cannot answer it: a case-folding volume calls `report.pdf`
    /// and `Report.pdf` one file, APFS calls an NFC and an NFD spelling one file,
    /// two shares can be two names for one directory, and a hard link made
    /// before this crate ever saw the volume is one file under two names in one
    /// directory. Every one of those is a destination whose deletion destroys the
    /// source.
    ///
    /// So the objects are opened and their identity compared. A name that is not
    /// there, or that this share will not open — a link, a device — answers
    /// `false`: it is not the source, and clearing it destroys nothing the
    /// caller still needs.
    pub fn is_same_child(
        &self,
        name: &str,
        other: &Self,
        other_name: &str,
    ) -> Result<bool, OpenError> {
        let (Some(here), Some(there)) =
            (self.open_child_object(name)?, other.open_child_object(other_name)?)
        else {
            return Ok(false);
        };
        Ok(sys::same_object(&here, &there))
    }

    /// One child opened as whatever it is, for an identity comparison only.
    ///
    /// `None` for a name that is absent or that the walk refuses, because the
    /// only caller is asking *is this the same thing as that*, and both answers
    /// to that question are "no". Nothing is read or written through the handle;
    /// the directory arm is tried first because Windows opens the two kinds with
    /// different dispositions.
    fn open_child_object(&self, name: &str) -> Result<Option<File>, OpenError> {
        path::validate_segment(name)?;
        match sys::open_child_dir(&self.handle, name) {
            Ok(handle) => return Ok(Some(handle)),
            Err(OpenError::NotADirectory) => {}
            Err(OpenError::NotFound | OpenError::Symlink | OpenError::NotAFile) => {
                return Ok(None)
            }
            Err(other) => return Err(other),
        }
        match sys::open_child_file(&self.handle, name) {
            Ok(handle) => Ok(Some(handle)),
            Err(
                OpenError::NotFound
                | OpenError::Symlink
                | OpenError::NotADirectory
                | OpenError::NotAFile,
            ) => Ok(None),
            Err(other) => Err(other),
        }
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
    ///   Windows box without one of them destroying the other. So the pair is
    ///   refused here, whatever the caller's intent — [`Upload::begin`] says why
    ///   `Replace` is not an exemption — and the refusal says which name it
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
        Ok(self.collisions(proposed)?.into_iter().next())
    }

    /// Every existing name that folds onto `proposed`, not just the first.
    ///
    /// [`Dir::collision`] answers the question a `409` message asks — *which
    /// file did I collide with* — and one name is enough for that. This answers
    /// the question a rename asks, which is different and cannot be served by a
    /// first match: a case-only rename's destination legitimately folds onto the
    /// file being renamed, and *only* onto it. Deciding that from whichever name
    /// `readdir` happened to yield first would let `report.pdf` be renamed to
    /// `Report.pdf` in a directory that also holds `REPORT.PDF`, which is the
    /// pair no Mac or Windows client can hold at once.
    ///
    /// A byte-identical name is never in this list: [`crate::path::collides`] is
    /// about two *spellings* of one name, and whether an exactly-spelled name may
    /// be overwritten is the caller's intent to declare, not a collision.
    fn collisions(&self, proposed: &str) -> Result<Vec<String>, OpenError> {
        let mut folding = Vec::new();
        for name in self.names()? {
            let Some(text) = name.to_str() else {
                continue;
            };
            if path::collides(text, proposed) {
                folding.push(text.to_string());
            }
        }
        Ok(folding)
    }

    /// What one child is, how large it is, and when it last changed.
    ///
    /// Two opens in the worst case, because the platform seam has one call for
    /// a directory and one for a file and no third that takes either. That is
    /// deliberate: a combined open would be a third set of flags to get right
    /// on Windows, on a path where the only benefit is halving the cost of a
    /// listing — and a listing already costs one open per entry, which
    /// [`Dir::names`] states is the price of not reaching a name by path.
    ///
    /// A link is [`OpenError::Symlink`] here as everywhere else, so a caller
    /// building a listing learns that the entry exists and cannot be served
    /// rather than being handed the target's metadata.
    pub fn stat(&self, name: &str) -> Result<Attributes, OpenError> {
        match self.open_dir(name) {
            Ok(directory) => {
                let metadata = directory.metadata().map_err(classify_io)?;
                Ok(Attributes { kind: Kind::Directory, size: 0, modified: metadata.modified().ok() })
            }
            Err(OpenError::NotADirectory) => {
                let metadata = self.open_file(name)?.metadata().map_err(classify_io)?;
                Ok(Attributes {
                    kind: Kind::File,
                    size: metadata.len(),
                    modified: metadata.modified().ok(),
                })
            }
            Err(other) => Err(other),
        }
    }

    /// Whether a child of this name exists at all, whatever it is.
    ///
    /// The question `Overwrite: F` asks, and the reason it is a question rather
    /// than a flag on the rename: a portable "rename unless the destination
    /// exists" needs a different symbol on each unix, and WebDAV wants a `412`
    /// with an explanation rather than a failed syscall. A link counts as
    /// occupied — [`OpenError::Symlink`] is an existence proof — because a
    /// destination we refuse to write through is still a destination that is
    /// taken.
    pub fn occupied(&self, name: &str) -> Result<bool, OpenError> {
        match self.stat(name) {
            Ok(_) | Err(OpenError::Symlink) | Err(OpenError::NotAFile) => Ok(true),
            Err(OpenError::NotFound) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Everything in this directory, with each entry's kind, size and
    /// modification time.
    ///
    /// One open per entry, through the descriptor walk, which is the cost
    /// [`Dir::names`] describes and refuses to avoid with a by-path
    /// `symlink_metadata`. A name that cannot be reached — not UTF-8, refused
    /// by the resolver, a link, or something that vanished between the read and
    /// the open — becomes an entry marked unreachable rather than an error for
    /// the whole listing: one strange file in a share must not make the share
    /// unlistable.
    pub fn entries(&self) -> Result<Vec<Entry>, OpenError> {
        let mut entries = Vec::new();
        for name in self.names()? {
            entries.push(self.entry_for(&name));
        }
        Ok(entries)
    }

    /// One directory entry, with the unreachable cases folded in.
    ///
    /// Reachability has two halves and this is where they meet.
    /// [`Entry::new`] judges the **name**: a name that is not UTF-8, or that the
    /// resolver refuses, can never appear in a URL. This function judges the
    /// **thing**: a name the resolver likes is still unreachable if the walk
    /// will not open what is under it — a symlink, a device node, a FIFO, or
    /// something that vanished between the read and the open.
    ///
    /// Deciding only the first half was a real defect, and a quiet one: a
    /// symlink out of the share listed as an ordinary zero-byte file with
    /// `reachable == true`, so the console offered a link and `PROPFIND` minted
    /// an `href` — for a name that answers every `GET` with a `404`, because
    /// [`Dir::open_file`] refuses the link the listing had just advertised.
    fn entry_for(&self, name: &std::ffi::OsStr) -> Entry {
        match name.to_str().map(|text| self.stat(text)) {
            Some(Ok(attributes)) => {
                Entry::new(name, attributes.kind, attributes.size, attributes.modified)
            }
            // Shown, at zero bytes, and marked: a file that exists and cannot be
            // reached is exactly what an operator needs to see, and hiding it
            // would make the console and Finder show different directories.
            Some(Err(_)) | None => Entry::unopenable(name),
        }
    }

    /// Creates one child directory, refusing to destroy anything.
    ///
    /// The same exclusive-create discipline [`Upload::begin`] uses, for the
    /// same reason and with the same collision oracle: the platform's create
    /// fails when *that volume* considers the name taken, under whatever
    /// folding it applies. `MKCOL` on an existing name is therefore a refusal
    /// the volume made, not a guess this code made.
    ///
    /// Returns the new directory already walked to, so a caller that is about
    /// to write into it does not reach it by path.
    pub fn create_dir(&self, name: &str) -> Result<Self, WriteError> {
        path::validate_segment(name)?;
        if let Some(existing) = self.collision(name)? {
            return Err(WriteError::Collides { existing });
        }
        sys::create_child_dir(&self.handle, name)?;
        self.sync()?;
        Ok(self.open_dir(name)?)
    }

    /// Removes one child file.
    ///
    /// Refuses a directory: `unlinkat` without `AT_REMOVEDIR` says so itself on
    /// unix, and the Windows half opens with `FILE_NON_DIRECTORY_FILE`, so
    /// neither platform can be talked into removing a tree through this call.
    pub fn remove_file(&self, name: &str) -> Result<(), WriteError> {
        path::validate_segment(name)?;
        sys::remove_child(&self.handle, name, None)?;
        self.sync()?;
        Ok(())
    }

    /// Removes one child directory, which must be empty.
    ///
    /// Emptiness is the kernel's rule rather than a scan this code performs,
    /// which is what makes it race-free: a file that arrived a microsecond ago
    /// makes the removal fail rather than disappearing with the directory.
    pub fn remove_dir(&self, name: &str) -> Result<(), WriteError> {
        path::validate_segment(name)?;
        sys::remove_child_dir(&self.handle, name)?;
        self.sync()?;
        Ok(())
    }

    /// Removes one child and, if it is a directory, everything beneath it.
    ///
    /// `DELETE` on a WebDAV collection is defined as depth-infinity, so this is
    /// not an optional convenience. Three properties are worth stating because
    /// each of them is a way this operation could have gone wrong:
    ///
    /// - **It descends through descriptors**, never through paths, so a link
    ///   planted mid-tree during the walk cannot redirect the deletion out of
    ///   the share. A link *found* in the tree is unlinked as itself, never
    ///   followed, which is [`Dir::remove_file`]'s guarantee applied at depth.
    /// - **It removes a tree of any depth, with the recursion still bounded by
    ///   [`MAX_TREE_DEPTH`].** Those two are not in tension, and the way they
    ///   are reconciled is the whole of the loop below.
    /// - **It stops at the first failure and says so.** A partial deletion is
    ///   visible in the next listing; a partial deletion reported as success is
    ///   how a caller comes to believe a file is gone when it is not.
    ///
    /// # Why deletion, alone among the descents here, has no depth ceiling
    ///
    /// Every other recursive walk in this crate answers [`MAX_TREE_DEPTH`] with
    /// a refusal, and that is right for them: a `COPY` or a `measure` that gives
    /// up leaves the share exactly as it found it. Deletion cannot do that,
    /// because **deletion is the way out**. A depth ceiling on it means this API
    /// can produce a tree it cannot then remove — and it does not take an
    /// attacker or a restored backup to reach one, since a client that issues
    /// `MKCOL` a hundred times has built it through the front door. A share with
    /// an undeletable directory in it is not a bounded failure; it is a share
    /// the operator has to go to SSH to fix.
    ///
    /// So the *recursion* keeps its bound and the *operation* loses its ceiling.
    /// A pass descends at most [`MAX_TREE_DEPTH`] levels; when it runs out of
    /// budget it hands back an open descriptor on the deepest directory it
    /// reached, and the loop starts a fresh pass from there. The stack is
    /// bounded by the recursion limit exactly as before, the open descriptors by
    /// one per pass — a few dozen for a tree thousands of levels deep — and
    /// progress is guaranteed because every pass either finishes its subtree or
    /// anchors strictly deeper than the last.
    pub fn remove_tree(&self, name: &str) -> Result<(), WriteError> {
        // Each anchor is a directory a pass reached its recursion limit in, and
        // the child of it still to be removed. The innermost is worked first;
        // when it comes back done, the pass below it is retried — its tree is
        // now that much shorter.
        let mut anchors = vec![(self.reopen()?, name.to_string())];
        while let Some((at, target)) = anchors.pop() {
            match at.remove_tree_within(&target, 0)? {
                Removal::Done => {}
                Removal::Deeper { at: below, name: next } => {
                    anchors.push((at, target));
                    anchors.push((below, next));
                }
            }
        }
        Ok(())
    }

    /// One pass of [`Dir::remove_tree`], bounded by the recursion limit.
    fn remove_tree_within(&self, name: &str, depth: usize) -> Result<Removal, WriteError> {
        path::validate_segment(name)?;
        if depth >= MAX_TREE_DEPTH {
            // The budget is spent, not the tree. A descriptor on this directory
            // goes back to the loop, which resumes from here with a fresh one —
            // a descriptor rather than a path, so the resumed pass cannot be
            // pointed at a different directory than the one this walk reached.
            return Ok(Removal::Deeper { at: self.reopen()?, name: name.to_string() });
        }
        match self.open_dir(name) {
            Ok(child) => {
                for entry in child.names()? {
                    // A name that this crate cannot spell cannot be removed
                    // through the descriptor walk either, and reaching for it
                    // by path is the one thing the walk exists to prevent. The
                    // parent's own removal will then fail as not-empty, which
                    // is the honest report: the operator is told the directory
                    // still holds something rather than told it is gone.
                    let Some(text) = entry.to_str() else {
                        continue;
                    };
                    match child.remove_tree_within(text, depth.saturating_add(1))? {
                        Removal::Done => {}
                        // This directory cannot go until that subtree has, and
                        // its remaining siblings will be found by the retry.
                        deeper @ Removal::Deeper { .. } => return Ok(deeper),
                    }
                }
                self.remove_dir(name)?;
                Ok(Removal::Done)
            }
            // Not a directory, so it is a file or a link, and both are unlinked
            // by name without being opened.
            Err(OpenError::NotADirectory | OpenError::Symlink) => {
                self.remove_file(name)?;
                Ok(Removal::Done)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Moves one child of this directory to a name in another.
    ///
    /// Both ends are open directories, so this is the operation
    /// [`Upload::commit`]'s by-path publish is documented as still owing: no
    /// component of either side can be redirected between the walk that proved
    /// it link-free and the rename itself.
    ///
    /// **The destination must be free.** The platform call replaces silently on
    /// unix and is asked not to on Windows, so relying on either would give the
    /// two platforms different semantics for the same request; instead the
    /// occupancy is a decision made here, and a caller that means to overwrite
    /// removes the destination first — which is exactly what RFC 4918 §9.9.3
    /// requires of `MOVE` with `Overwrite: T`, and exactly what
    /// [`WriteError::NameTaken`] tells a caller that did not ask for it.
    ///
    /// The case-collision scan runs against the destination directory for the
    /// same reason [`Upload::begin`] runs it: a `MOVE` of `Report.pdf` into a
    /// directory holding `report.pdf` is a share that cannot survive being
    /// copied to a Mac, whatever this volume thinks.
    ///
    /// # The one name that folds onto the destination and is not a collision
    ///
    /// Renaming `report.pdf` to `Report.pdf` in one directory is a person fixing
    /// a file's capitalisation, and it is the single rename whose destination
    /// folds onto its own source. Every rule above fires on it — the fold scan
    /// finds `report.pdf`, and on APFS or NTFS the occupancy check finds the
    /// destination taken by the very file being moved — so the operation was
    /// refused on a case-sensitive volume and, when the caller had said
    /// `Overwrite: T`, the destination was deleted first and the file ceased to
    /// exist.
    ///
    /// So the source is excluded from both questions — but only from the
    /// questions, never from the *decision*. The occupancy check still runs on
    /// that branch, because "the destination folds onto the source" is a fact
    /// about two spellings and not about two files: on a case-sensitive volume
    /// `Report.pdf` can be a second, unrelated file, and the two-step rename
    /// below ends in a replacing rename that would destroy it. What the branch
    /// buys is that the destination is allowed to be occupied *by the source
    /// itself*, which [`Dir::is_same_child`] is what proves.
    ///
    /// The rename is then done in two steps through a name inside
    /// [`TEMP_PREFIX`]'s reserved namespace: on
    /// a folding volume a single rename would be asked to replace the file it is
    /// moving, which is the platform's business to define and not something to
    /// find out per filesystem. If the second step fails the first is undone, so
    /// the file is back under the name it started with rather than under a name
    /// no listing will show.
    pub fn rename_into(
        &self,
        name: &str,
        destination: &Self,
        destination_name: &str,
    ) -> Result<(), WriteError> {
        path::validate_segment(name)?;
        path::validate_segment(destination_name)?;
        // The fold is asked first, exactly as [`Upload::begin`] asks it first,
        // so that a name which merely *folds* onto an existing one is refused
        // with that one's spelling rather than with a bare "already exists" —
        // on a folding volume both rules fire, and only one of them can explain
        // itself to a person.
        let one_directory = self.is_same_directory(destination);
        let mut folding = destination.collisions(destination_name)?;
        let folds_onto_source =
            one_directory && folding.iter().any(|existing| existing == name);
        folding.retain(|existing| !(one_directory && existing == name));
        if let Some(existing) = folding.into_iter().next() {
            return Err(WriteError::Collides { existing });
        }
        if folds_onto_source {
            // The fold says the destination is another spelling of the source,
            // and on a folding volume it is — there is only one file the two
            // names can mean. On a case-sensitive volume it may be a *second*
            // file: this API refuses to create `report.pdf` beside `Report.pdf`,
            // and a backup, an SMB client or another operating system delivers
            // the pair anyway. The two-step rename below ends in a *replacing*
            // rename, so a branch that skipped the occupancy question would
            // silently overwrite that second file and report success.
            //
            // Asked of the objects rather than of the names, for the reason
            // [`Dir::is_same_child`] gives: names are exactly what cannot answer
            // it. A destination that is the source is the case-only rename this
            // branch exists for; a destination that is anything else is taken.
            if destination.occupied(destination_name)?
                && !self.is_same_child(name, destination, destination_name)?
            {
                return Err(WriteError::NameTaken);
            }
            return self.rename_case_only(name, destination_name);
        }
        if destination.occupied(destination_name)? {
            return Err(WriteError::NameTaken);
        }
        sys::rename_child(
            &self.handle,
            name,
            &destination.handle,
            destination_name,
            Existing::Refuse,
        )?;
        self.sync()?;
        destination.sync()?;
        Ok(())
    }

    /// Renames a child onto a spelling of its own name, in two steps.
    ///
    /// The case-only rename [`Dir::rename_into`] documents. Private, because it
    /// is correct exactly under the condition that call site has just proven —
    /// that the only name folding onto the destination is the source itself —
    /// and a public entry point would be one a caller could reach without it.
    fn rename_case_only(&self, name: &str, destination_name: &str) -> Result<(), WriteError> {
        if name == destination_name {
            // Not a rename at all. Refusing here rather than performing a
            // two-step move of a file onto itself keeps the destructive path
            // reachable only when something actually changes.
            return Err(WriteError::NameTaken);
        }
        let staged = temporary_name();
        sys::rename_child(&self.handle, name, &self.handle, &staged, Existing::Refuse)?;
        match sys::rename_child(
            &self.handle,
            &staged,
            &self.handle,
            destination_name,
            Existing::Replace,
        ) {
            Ok(()) => {
                self.sync()?;
                Ok(())
            }
            Err(error) => {
                // Put it back. A file under a `TEMP_PREFIX` name is one no
                // listing will offer and no request can name, so leaving it
                // there would be losing it in all the ways that matter.
                let _ = sys::rename_child(
                    &self.handle,
                    &staged,
                    &self.handle,
                    name,
                    Existing::Replace,
                );
                let _ = self.sync();
                Err(error.into())
            }
        }
    }

    /// Bytes an ordinary writer may still put on the volume this directory
    /// lives on.
    ///
    /// The free-space floor's input, and the one number in the write path that
    /// is a fact about the machine rather than about the share: a full boot
    /// volume does not make a smaller NAS, it stops the box answering on 443.
    /// The reserve a filesystem keeps for the superuser is excluded, because
    /// the daemon is not the superuser and a floor that counted space it cannot
    /// spend would pass right up to the `ENOSPC` it exists to prevent.
    pub fn free_space(&self) -> Result<u64, OpenError> {
        sys::free_space(&self.handle, &self.path).map_err(classify_io)
    }

    /// The total size of every file at or beneath this directory.
    ///
    /// The quota's input. It is a **whole-subtree walk**, one open per entry,
    /// and that cost is why it is a named function rather than something the
    /// write path calls per request: a share holding forty thousand files
    /// cannot afford to be measured on every `PUT`, so the caller measures once
    /// and keeps the answer, adjusting it as bytes land — which is what
    /// [`crate::quota::Ledger`] exists to do.
    ///
    /// Bounded by [`MAX_TREE_DEPTH`] like every other descent here, saturating
    /// on the addition so that a volume reporting nonsense produces a large
    /// number rather than an aborting overflow, and skipping — rather than
    /// failing on — anything it cannot open: a quota that refused to be
    /// measured because one file was unreadable would refuse every upload.
    pub fn measure(&self) -> Result<u64, OpenError> {
        self.measure_within(0)
    }

    /// [`Dir::measure`] with the depth it has already descended.
    fn measure_within(&self, depth: usize) -> Result<u64, OpenError> {
        if depth >= MAX_TREE_DEPTH {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for name in self.names()? {
            let Some(text) = name.to_str() else {
                continue;
            };
            match self.open_dir(text) {
                Ok(child) => {
                    total = total.saturating_add(child.measure_within(depth.saturating_add(1))?);
                }
                Err(OpenError::NotADirectory) => {
                    if let Ok(file) = self.open_file(text) {
                        if let Ok(metadata) = file.metadata() {
                            total = total.saturating_add(metadata.len());
                        }
                    }
                }
                // A link, a device, a name the resolver refuses, or something
                // that vanished mid-walk: not counted, and not fatal.
                Err(_) => continue,
            }
        }
        Ok(total)
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

/// How far one pass of [`Dir::remove_tree`] got.
///
/// Private, and a type rather than a `bool`, because the second case carries the
/// one thing that makes an unbounded removal possible with a bounded recursion:
/// an **open descriptor** on the directory the pass stopped in. Handing back a
/// path instead would mean the resumed pass re-opened a name that could have
/// become something else in the meantime, which is the redirection the whole
/// module exists to prevent.
#[derive(Debug)]
enum Removal {
    /// The named child, and everything beneath it, is gone.
    Done,
    /// The pass spent its recursion budget with a subtree still standing.
    Deeper {
        /// The deepest directory the pass reached, still open.
        at: Dir,
        /// The child of it that has still to go.
        name: String,
    },
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
/// The upload **holds** the [`Dir`] it writes into, which is how the descriptor
/// walk reaches this far: the file is created *relative to that descriptor*, so
/// no part of the path can be redirected between the walk and the create. That
/// is not a lifetime formality — it is the guarantee.
///
/// # Why it is generic over how it holds that directory
///
/// `D` is `&Dir` for the ordinary case, where a request opens a directory,
/// streams a body into it and returns. It is `Dir` — owned — for a **resumable**
/// upload, which outlives the request that started it: the directory descriptor
/// is kept open for the whole session precisely so that the second chunk lands
/// in the same directory object the first one did, even if the path has since
/// been renamed out from under it. A resumable upload that re-walked its path
/// on every chunk would be a resumable upload an attacker could redirect
/// halfway through.
///
/// One implementation covers both because [`Borrow`] is the whole difference; a
/// second, owned copy of this type would be a second place for the
/// exclusive-create discipline to be got subtly wrong.
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
pub struct Upload<D: Borrow<Dir>> {
    /// The directory this write is confined to, held open for the whole write.
    directory: D,
    /// `None` once the handle has been surrendered by `commit`, which is also
    /// how `Drop` knows the upload was finished rather than dropped.
    handle: Option<File>,
    /// The name the bytes must end up under.
    name: String,
    /// The temporary name currently holding the bytes, when the caller asked to
    /// replace something. `None` means the handle is already the destination.
    staged: Option<String>,
}

impl<D: Borrow<Dir>> Upload<D> {
    /// Creates `name` in `directory` without destroying anything.
    ///
    /// The name is re-validated here rather than trusted, exactly as
    /// [`Dir::open_dir`] does and for the same reason: a name can reach this
    /// function from a request line, a WebDAV `Destination` header, or a
    /// directory read, and only one of those three has been past the resolver.
    ///
    /// Then the directory is scanned for a name that folds onto this one
    /// ([`Dir::collision`]) — which catches the pair that a case-sensitive
    /// volume would otherwise accept and every Mac and Windows client would
    /// later ruin.
    ///
    /// **The scan runs whatever the caller's intent is**, and the reason is the
    /// worst bug this file has had. It used to run for [`Existing::Refuse`]
    /// only, which is to say it ran for every path except the one every ordinary
    /// upload takes: a `PUT` is [`Existing::Replace`]. So `report.pdf` uploaded
    /// into a directory holding `Report.pdf` skipped the scan, the exclusive
    /// create failed because APFS folds the two, the replace path staged and
    /// renamed — and a *different file*, with a different name, was silently
    /// overwritten with the uploader's bytes. `Replace` is permission to replace
    /// the file at **this** name; a file whose name merely folds onto it is not
    /// that file, and the caller never asked for it.
    ///
    /// A byte-identical name is not a collision — [`crate::path::collides`] says
    /// so — so this refuses nothing an overwrite is entitled to do.
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
    pub fn begin(directory: D, name: &str, existing: Existing) -> Result<Self, WriteError> {
        path::validate_segment(name)?;

        if let Some(collision) = directory.borrow().collision(name)? {
            return Err(WriteError::Collides { existing: collision });
        }

        // The create is finished before the `match`, so that its borrow of
        // `directory` has ended by the time an arm moves the directory into the
        // value being returned.
        let created = sys::create_child(&directory.borrow().handle, name);
        match created {
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
                    let handle = sys::create_child(&directory.borrow().handle, &staged)?;
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

    /// The directory this upload is confined to, however it is held.
    pub fn directory(&self) -> &Dir {
        self.directory.borrow()
    }

    /// The name the bytes will appear under, without the directory.
    pub fn name(&self) -> &str {
        &self.name
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
        self.directory.borrow().path().join(&self.name)
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

        let directory = self.directory.borrow();
        if let Some(staged) = self.staged.take() {
            // Relative to the descriptor at both ends, which is what closes the
            // window this crate's documentation used to record as owed: the
            // publish cannot be redirected by a component swapped after the
            // walk, because no component is named.
            sys::rename_child(
                &directory.handle,
                &staged,
                &directory.handle,
                &self.name,
                Existing::Replace,
            )?;
        }
        directory.sync()?;
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
        sys::remove_child(&self.directory.borrow().handle, &name, handle)
    }
}

impl<D: Borrow<Dir>> Drop for Upload<D> {
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

    /// A listing describes what is there, and marks what cannot be reached.
    #[test]
    fn a_listing_names_every_entry_and_greys_the_ones_that_cannot_be_served() {
        let root = scratch("entries");
        std::fs::create_dir(root.join("photos")).expect("a directory");
        write_file(&root.join("notes.txt"), "hello");
        let dir = open(&root);

        let entries = dir.entries().expect("listed");
        assert_eq!(entries.len(), 2);
        let photos = entries.iter().find(|entry| entry.name == "photos").expect("the directory");
        assert_eq!(photos.kind, Kind::Directory);
        assert_eq!(photos.size, 0, "a directory's contents are a walk, not a number");
        assert!(photos.reachable());
        let notes = entries.iter().find(|entry| entry.name == "notes.txt").expect("the file");
        assert_eq!(notes.kind, Kind::File);
        assert_eq!(notes.size, 5);
        assert!(notes.modified.is_some());

        assert_eq!(dir.stat("notes.txt").expect("stat").size, 5);
        assert!(dir.occupied("notes.txt").expect("asked"));
        assert!(!dir.occupied("absent").expect("asked"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A name that another operating system wrote is shown and refused, not
    /// hidden and not fatal to the whole listing.
    #[cfg(unix)]
    #[test]
    fn a_listing_survives_a_name_this_share_will_never_serve() {
        let root = scratch("entries-hostile");
        write_file(&root.join("good.txt"), "fine");
        // A trailing space is a legal unix name and one the resolver refuses,
        // because Windows would normalise it to a different name.
        write_file(&root.join("trailing "), "written elsewhere");
        std::os::unix::fs::symlink("/etc/passwd", root.join("link.txt")).expect("linked");
        let dir = open(&root);

        let entries = dir.entries().expect("listed");
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().find(|entry| entry.name == "good.txt").expect("good").reachable());
        assert!(!entries.iter().find(|entry| entry.name == "trailing ").expect("odd").reachable());
        // A link is listed — hiding it would make the console and Finder show
        // different directories — at zero bytes and **unreachable**: every `GET`
        // of it is a `404`, because the walk refuses the link the listing would
        // otherwise have advertised a URL for.
        let link = entries.iter().find(|entry| entry.name == "link.txt").expect("the link");
        assert_eq!(link.size, 0);
        assert!(!link.reachable(), "a symlink is never a name this share serves");
        assert!(!link.to_json(&RelativePath::default()).to_text().contains(r#""path""#));
        assert!(matches!(dir.stat("link.txt"), Err(OpenError::Symlink)));
        assert!(dir.occupied("link.txt").expect("a link occupies its name"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_is_created_exclusively_and_removed_only_when_empty() {
        let root = scratch("mkcol");
        let dir = open(&root);

        let photos = dir.create_dir("photos").expect("created");
        assert_eq!(photos.path(), root.join("photos"));
        assert!(matches!(dir.create_dir("photos"), Err(WriteError::NameTaken)));
        // And a name that folds onto it is refused by name on every volume.
        match dir.create_dir("Photos") {
            Err(WriteError::Collides { existing }) => assert_eq!(existing, "photos"),
            other => panic!("expected a named collision, got {other:?}"),
        }

        write_file(&root.join("photos").join("a.txt"), "a");
        assert!(dir.remove_dir("photos").is_err(), "a directory with a file in it stays");
        photos.remove_file("a.txt").expect("removed");
        dir.remove_dir("photos").expect("removed");
        assert!(!root.join("photos").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_is_removed_whole_and_a_file_is_removed_alone() {
        let root = scratch("rmtree");
        std::fs::create_dir_all(root.join("a").join("b").join("c")).expect("directories");
        write_file(&root.join("a").join("one.txt"), "1");
        write_file(&root.join("a").join("b").join("two.txt"), "2");
        write_file(&root.join("a").join("b").join("c").join("three.txt"), "3");
        write_file(&root.join("loose.txt"), "loose");
        let dir = open(&root);

        dir.remove_tree("a").expect("removed");
        assert!(!root.join("a").exists());
        assert!(root.join("loose.txt").exists(), "only what was named goes");

        dir.remove_tree("loose.txt").expect("removed");
        assert_eq!(dir.names().expect("readable").len(), 0);

        // A directory is never removed by the file call, whatever the caller
        // believed it was holding.
        std::fs::create_dir(root.join("kept")).expect("a directory");
        assert!(dir.remove_file("kept").is_err());
        assert!(root.join("kept").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tree deeper than the recursion limit is still removable, because
    /// deletion is the way out of every other refusal in this crate.
    ///
    /// Several levels deeper than one pass can reach, so the resume path is what
    /// is being exercised and not an off-by-one at the boundary. Nothing else
    /// here loses its ceiling: `measure` still stops, and a `COPY` still
    /// refuses.
    #[test]
    fn a_tree_deeper_than_the_recursion_limit_is_still_removed_whole() {
        let root = scratch("rmtree-deep");
        let levels = MAX_TREE_DEPTH * 2 + 5;
        let mut deep = root.join("d");
        for _ in 0..levels {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).expect("a deep tree");
        write_file(&deep.join("bottom.txt"), "at the bottom");
        // A second branch below the first pass's reach, so the retry has to find
        // a sibling as well as a descendant.
        std::fs::create_dir_all(deep.join("sibling")).expect("a second branch");
        let dir = open(&root);

        dir.remove_tree("d").expect("removed however deep it was");
        assert!(!root.join("d").exists());
        assert_eq!(dir.names().expect("readable").len(), 0);

        // Measurement stops at the recursion limit instead of failing, because a
        // quota that refused to be measured would refuse every upload.
        let mut shallow = root.join("d");
        for _ in 0..(MAX_TREE_DEPTH + 2) {
            shallow = shallow.join("d");
        }
        std::fs::create_dir_all(&shallow).expect("a deep tree");
        assert_eq!(dir.measure().expect("measured"), 0);
        dir.remove_tree("d").expect("removed");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A link found inside a tree is unlinked as itself, never followed.
    #[cfg(unix)]
    #[test]
    fn removing_a_tree_unlinks_a_planted_link_rather_than_its_target() {
        let root = scratch("rmtree-link");
        let outside = scratch("rmtree-link-target");
        write_file(&outside.join("secret"), "secret");
        std::fs::create_dir(root.join("tree")).expect("a directory");
        std::os::unix::fs::symlink(&outside, root.join("tree").join("escape")).expect("linked");
        std::os::unix::fs::symlink(outside.join("secret"), root.join("tree").join("file"))
            .expect("linked");

        open(&root).remove_tree("tree").expect("removed");
        assert!(!root.join("tree").exists());
        assert_eq!(read_file(&outside.join("secret")), "secret", "the target is untouched");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_rename_moves_between_two_open_directories_and_never_clobbers() {
        let root = scratch("rename");
        std::fs::create_dir(root.join("from")).expect("a directory");
        std::fs::create_dir(root.join("to")).expect("a directory");
        write_file(&root.join("from").join("notes.txt"), "moved");
        write_file(&root.join("to").join("taken.txt"), "original");
        let dir = open(&root);
        let from = dir.open_dir("from").expect("walked");
        let to = dir.open_dir("to").expect("walked");

        from.rename_into("notes.txt", &to, "notes.txt").expect("moved");
        assert_eq!(read_file(&root.join("to").join("notes.txt")), "moved");
        assert!(!root.join("from").join("notes.txt").exists());

        // An occupied destination is refused rather than replaced, which is what
        // lets `Overwrite: F` be a 412 instead of a lost file.
        write_file(&root.join("from").join("second.txt"), "second");
        assert!(matches!(
            from.rename_into("second.txt", &to, "taken.txt"),
            Err(WriteError::NameTaken)
        ));
        assert_eq!(read_file(&root.join("to").join("taken.txt")), "original");

        // And one that only folds onto an occupied name is refused by name.
        match from.rename_into("second.txt", &to, "Taken.txt") {
            Err(WriteError::Collides { existing }) => assert_eq!(existing, "taken.txt"),
            other => panic!("expected a named collision, got {other:?}"),
        }

        // A rename within one directory is a plain rename.
        from.rename_into("second.txt", &from, "renamed.txt").expect("renamed");
        assert_eq!(read_file(&root.join("from").join("renamed.txt")), "second");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A person fixing a file's capitalisation is the one rename whose
    /// destination folds onto its own source, and it must not cost them the
    /// file.
    ///
    /// Written to hold on both kinds of volume, like the NFD test above: on
    /// APFS or NTFS the destination name is *taken by the file being renamed*,
    /// and on ext4 it is free but folds onto it. Both used to be refusals, and
    /// on a folding volume a caller that had said `Overwrite: T` reached a
    /// destination-first delete and lost the file outright.
    #[test]
    fn a_case_only_rename_is_a_rename_and_not_a_way_to_lose_the_file() {
        let root = scratch("rename-case");
        write_file(&root.join("report.pdf"), "the only copy");
        let dir = open(&root);

        dir.rename_into("report.pdf", &dir, "Report.pdf").expect("the case is fixed");

        let names: Vec<String> = dir
            .names()
            .expect("readable")
            .into_iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["Report.pdf"], "one file, under the spelling that was asked for");
        assert_eq!(read_file(&root.join("Report.pdf")), "the only copy");

        // Nothing is staged: a failed second step puts the file back under the
        // name it started with, and a successful one leaves no litter.
        assert!(!names.iter().any(|name| name.starts_with(TEMP_PREFIX)));

        // A rename onto the name it already has changes nothing and is refused,
        // so the two-step path is reachable only when something moves.
        assert!(matches!(dir.rename_into("Report.pdf", &dir, "Report.pdf"), Err(WriteError::NameTaken)));
        assert_eq!(read_file(&root.join("Report.pdf")), "the only copy");

        // And the exemption is exactly one name wide: a *third* spelling in the
        // directory is still the collision no Mac can hold. The pair can only be
        // built on a case-sensitive volume — on a folding one the second write
        // lands in the first file — so the case is asserted where it exists
        // rather than assumed to.
        write_file(&root.join("other.txt"), "other");
        write_file(&root.join("OTHER.TXT"), "another");
        if dir.names().expect("readable").len() == 3 {
            match dir.rename_into("other.txt", &dir, "Other.txt") {
                Err(WriteError::Collides { existing }) => assert_eq!(existing, "OTHER.TXT"),
                other => panic!("expected the third spelling to collide, got {other:?}"),
            }
            assert_eq!(read_file(&root.join("OTHER.TXT")), "another");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The fold scan runs on the path every ordinary upload takes.
    ///
    /// `PUT` is [`Existing::Replace`], and the scan used to be skipped for it —
    /// so an upload of `report.pdf` beside `Report.pdf` overwrote a *different*
    /// file on a folding volume and created an uncopyable pair on a
    /// case-sensitive one. Replacing is permission to replace the file at this
    /// name, not the file at a name that folds onto it.
    #[test]
    fn replacing_a_name_never_replaces_a_different_spelling_of_it() {
        let root = scratch("replace-fold");
        write_file(&root.join("Report.pdf"), "original");
        let dir = open(&root);

        match Upload::begin(&dir, "report.pdf", Existing::Replace) {
            Err(WriteError::Collides { existing }) => assert_eq!(existing, "Report.pdf"),
            other => panic!("expected a named collision, got {other:?}"),
        }
        assert_eq!(read_file(&root.join("Report.pdf")), "original");
        assert_eq!(dir.names().expect("readable").len(), 1, "nothing was created");

        // The name it actually names is still replaceable, which is the whole
        // point of the intent: this refuses nothing an overwrite may do.
        let mut replacing =
            Upload::begin(&dir, "Report.pdf", Existing::Replace).expect("the same name replaces");
        replacing.file().write_all(b"replacement").expect("written");
        replacing.commit().expect("committed");
        assert_eq!(read_file(&root.join("Report.pdf")), "replacement");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The two numbers the write path is gated on, measured against a real
    /// volume rather than mocked: a wrong `statfs` head would read as an absurd
    /// free-space figure here rather than as a floor that silently never fires.
    #[test]
    fn the_volume_reports_a_plausible_free_space_and_the_tree_reports_its_size() {
        let root = scratch("measure");
        std::fs::create_dir(root.join("nested")).expect("a directory");
        write_file(&root.join("a.txt"), "0123456789");
        write_file(&root.join("nested").join("b.txt"), "01234");
        let dir = open(&root);

        assert_eq!(dir.measure().expect("measured"), 15);

        let free = dir.free_space().expect("a volume that answers");
        assert!(free > 1024 * 1024, "a writable scratch volume has at least a megabyte free");
        assert!(
            free < 1 << 60,
            "an exabyte of free space means the statfs fields are being read at the wrong offsets"
        );

        let _ = std::fs::remove_dir_all(&root);
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
