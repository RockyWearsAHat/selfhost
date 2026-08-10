//! The unix half of the descriptor walk: `openat`, and nothing else.
//!
//! One syscall pair — `openat` and `unlinkat` — declared rather than depended
//! on, for the reason the rest of this project gives for the same choice
//! (`supervisor/src/child.rs:222` declares `kill` the same way): libc is the
//! operating system, and a single symbol is a smaller surface than a crate with
//! its own release cadence.
//!
//! # Why the flag values are written out, and what keeps them honest
//!
//! `O_NOFOLLOW` and friends are numbers chosen by each kernel, and on Linux
//! `O_NOFOLLOW` differs **by architecture** as well as by operating system.
//! That is a genuinely dangerous kind of constant: a wrong `O_NOFOLLOW`
//! silently restores the vulnerability the walk exists to close, because the
//! open simply succeeds by following the link.
//!
//! Two things guard it. Architectures whose values are not written here are a
//! **compile error** rather than a guess — a build that will not start is a
//! better outcome than a share that can be escaped. And
//! `fs::tests::a_symlinked_directory_is_refused_rather_than_followed` plants a
//! real link and asserts the refusal, so a wrong number fails the test suite on
//! whatever platform it is built for rather than waiting to be discovered.
//!
//! # `O_DIRECTORY` is deliberately not used, and that is a finding
//!
//! The obvious spelling for descending is `O_NOFOLLOW | O_DIRECTORY`. That test
//! above is what caught the problem with it: on Darwin, the two flags together
//! report a symlink as `ENOTDIR` rather than `ELOOP`, so the one refusal an
//! operator most wants to see in a log — *something in this share is trying to
//! lead out of it* — arrives indistinguishable from *that name is a file*.
//! Linux reports `ELOOP`, so the symptom would have been a platform-dependent
//! log message nobody would think to check.
//!
//! Both opens therefore use the **same** flags, and whether the object is a
//! directory or a regular file is decided afterwards from the open handle by
//! [`super::Dir`]. `fstat` on a descriptor is a stronger check than a flag
//! anyway — it describes the object that was actually opened rather than a
//! condition on opening it — and it takes one arch-varying constant out of the
//! security path entirely.

use super::{Existing, OpenError};
use std::ffi::{c_char, c_int, c_uint, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The open flags this module uses, as each kernel spells them.
///
/// Cited rather than derived: Darwin's are in `sys/fcntl.h` and are the same for
/// every Apple architecture; Linux's live in `asm-generic/fcntl.h`, which
/// `arch/arm64` and `arch/arm` override for exactly the one flag marked below.
#[cfg(target_vendor = "apple")]
mod flags {
    /// Open for reading only.
    pub const O_RDONLY: i32 = 0x0000;
    /// Open for writing only.
    pub const O_WRONLY: i32 = 0x0001;
    /// Create the file if it is absent.
    pub const O_CREAT: i32 = 0x0200;
    /// Fail if the file is already there — the collision oracle.
    pub const O_EXCL: i32 = 0x0800;
    /// Fail rather than follow a symlink at the final component.
    pub const O_NOFOLLOW: i32 = 0x0100;
    /// Close the descriptor across an `exec`, so a spawned service never
    /// inherits a handle into a share.
    pub const O_CLOEXEC: i32 = 0x0100_0000;
    /// Do not block waiting for a writer, which is how a FIFO would stop the
    /// daemon.
    pub const O_NONBLOCK: i32 = 0x0004;
    /// A symlink was found where the flags said not to follow one.
    pub const ELOOP: i32 = 62;
    /// A component that had to be a directory is not one.
    pub const ENOTDIR: i32 = 20;
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
mod flags {
    /// Open for reading only.
    pub const O_RDONLY: i32 = 0o0;
    /// Open for writing only.
    pub const O_WRONLY: i32 = 0o1;
    /// Create the file if it is absent.
    pub const O_CREAT: i32 = 0o100;
    /// Fail if the file is already there — the collision oracle.
    pub const O_EXCL: i32 = 0o200;
    /// Fail rather than follow a symlink at the final component.
    pub const O_NOFOLLOW: i32 = 0o400_000;
    /// Close the descriptor across an `exec`.
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    /// Do not block waiting for a writer.
    pub const O_NONBLOCK: i32 = 0o4_000;
    /// A symlink was found where the flags said not to follow one.
    pub const ELOOP: i32 = 40;
    /// A component that had to be a directory is not one.
    pub const ENOTDIR: i32 = 20;
}

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
mod flags {
    /// Open for reading only.
    pub const O_RDONLY: i32 = 0o0;
    /// Open for writing only.
    pub const O_WRONLY: i32 = 0o1;
    /// Create the file if it is absent.
    pub const O_CREAT: i32 = 0o100;
    /// Fail if the file is already there — the collision oracle.
    pub const O_EXCL: i32 = 0o200;
    /// Fail rather than follow a symlink. **Architecture-specific on Linux.**
    pub const O_NOFOLLOW: i32 = 0o100_000;
    /// Close the descriptor across an `exec`.
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    /// Do not block waiting for a writer.
    pub const O_NONBLOCK: i32 = 0o4_000;
    /// A symlink was found where the flags said not to follow one.
    pub const ELOOP: i32 = 40;
    /// A component that had to be a directory is not one.
    pub const ENOTDIR: i32 = 20;
}

#[cfg(not(any(
    target_vendor = "apple",
    all(
        target_os = "linux",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm"
        )
    )
)))]
compile_error!(
    "the open flags for this unix are not written down here, and guessing O_NOFOLLOW wrong is \
     a silently escapable share rather than a build failure. Add this platform's values to \
     `flags` from its own fcntl.h before building a NAS for it."
);

/// The mode a created file asks for, before the process umask narrows it.
///
/// `0o666` is what `std::fs::File::create` passes, and passing the same thing
/// means a file written through the console is exactly as private as a file the
/// operator wrote by hand — the umask decides, in one place, rather than this
/// crate inventing a second policy that would surprise whoever set it.
const CREATE_MODE: c_uint = 0o666;

/// The mode a created directory asks for, before the process umask narrows it.
///
/// `0o777` for the reason [`CREATE_MODE`] is `0o666`: it is what
/// `std::fs::create_dir` passes, so a directory made through the console is
/// exactly as private as one the operator made by hand, and the umask remains
/// the single place that decides.
const CREATE_DIR_MODE: ModeT = 0o777;

/// `mode_t`, which is **not** the same width on every unix.
///
/// Darwin spells it `unsigned short`; Linux spells it `unsigned int`. It is
/// written out per platform rather than approximated with `c_uint` because
/// `mkdirat` takes it as an ordinary (non-variadic) parameter, where no default
/// argument promotion applies and the declared width is the ABI.
#[cfg(target_vendor = "apple")]
type ModeT = u16;

/// See the Apple arm above.
#[cfg(not(target_vendor = "apple"))]
type ModeT = u32;

/// The flag that turns `unlinkat` into `rmdir` rather than `unlink`.
///
/// `AT_REMOVEDIR` is `0x80` on Darwin and `0x200` on Linux — an
/// operating-system constant, not an architecture one, so a two-arm `cfg` is
/// the whole of it. Getting it wrong is not a security failure but a functional
/// one: `unlinkat` without it refuses a directory outright (`EPERM`/`EISDIR`),
/// which is a visible error rather than a silent removal of the wrong thing.
#[cfg(target_vendor = "apple")]
const AT_REMOVEDIR: c_int = 0x80;

/// See the Apple arm above.
#[cfg(not(target_vendor = "apple"))]
const AT_REMOVEDIR: c_int = 0x200;

// The syscalls. `openat` is genuinely variadic in C — the mode argument is
// read only when `O_CREAT` is set — and it is declared variadic here so the
// calls that pass a mode and the calls that do not are both built with the ABI
// the platform actually uses for it, which differs from the fixed-argument ABI
// on aarch64 Apple targets.
//
// `mkdirat` and `renameat` are the write path's two remaining relative
// operations, and they are declared for exactly the reason `openat` is: the
// whole-path spellings (`mkdir`, `rename`) resolve every component themselves,
// so a link planted anywhere above the name would redirect the operation after
// the walk had finished proving there was none.
#[allow(unsafe_code)]
unsafe extern "C" {
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn unlinkat(directory: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn mkdirat(directory: c_int, path: *const c_char, mode: ModeT) -> c_int;
    fn renameat(
        from_directory: c_int,
        from: *const c_char,
        to_directory: c_int,
        to: *const c_char,
    ) -> c_int;
    fn fstatfs(descriptor: c_int, out: *mut StatFs) -> c_int;
}

/// Opens a directory by path. Used for the share root and for the identity
/// check that guards [`super::Dir::names`], and nowhere else.
///
/// Deliberately without `O_NOFOLLOW`: the root may legitimately be a symlink an
/// operator chose, and the identity check that the other caller performs is what
/// makes following one safe there.
pub(super) fn open_root(path: &Path) -> Result<File, OpenError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_CLOEXEC)
        .open(path)
        .map_err(classify)
}

/// Opens one child relative to an open directory, refusing a symlink.
///
/// Whether the result is the directory the caller wanted is decided by
/// [`super::Dir`] from the handle, not by `O_DIRECTORY` — this module's
/// documentation explains what that flag cost on Darwin.
pub(super) fn open_child_dir(parent: &File, name: &str) -> Result<File, OpenError> {
    open_child(parent, name, flags::O_RDONLY | flags::O_NOFOLLOW | flags::O_NONBLOCK)
}

/// Opens one child file relative to an open directory, refusing a symlink.
///
/// `O_NONBLOCK` is set so that a FIFO planted in a share returns instead of
/// blocking the daemon until somebody writes to it; the caller then throws away
/// anything that is not a regular file. On a regular file the flag has no
/// effect, which is why it can be unconditional.
pub(super) fn open_child_file(parent: &File, name: &str) -> Result<File, OpenError> {
    open_child(parent, name, flags::O_RDONLY | flags::O_NOFOLLOW | flags::O_NONBLOCK)
}

/// Creates one child file relative to an open directory, failing if the name is
/// taken.
///
/// `O_EXCL` is the collision oracle the module documentation describes, and it
/// also never follows the final component — so a planted symlink is a refusal
/// rather than a write through it.
pub(super) fn create_child(parent: &File, name: &str) -> Result<File, OpenError> {
    let name = c_name(name)?;
    let flags =
        flags::O_WRONLY | flags::O_CREAT | flags::O_EXCL | flags::O_NOFOLLOW | flags::O_CLOEXEC;
    // Safety: `parent` owns a live descriptor for the duration of the call,
    // `name` is a NUL-terminated C string that outlives it, and the returned
    // descriptor is handed straight to `File`, which owns and closes it.
    #[allow(unsafe_code)]
    let raw = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags, CREATE_MODE) };
    finish(raw)
}

/// Removes one child of an open directory.
///
/// The handle is taken by value and dropped first so that the descriptor is
/// closed before the name goes; unix does not require it, and Windows — whose
/// implementation deletes *through* the handle — does, so the signature is the
/// one both platforms can honour.
pub(super) fn remove_child(parent: &File, name: &str, handle: Option<File>) -> io::Result<()> {
    drop(handle);
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // Safety: as `create_child`; `unlinkat` borrows both arguments for the call
    // and returns ownership of nothing.
    #[allow(unsafe_code)]
    let status = unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether two open handles are the same directory on the same volume.
///
/// `(st_dev, st_ino)` is the definition of filesystem identity on unix, and it
/// is read from the descriptors rather than from either path — which is the
/// whole point, since the question being asked is whether a path still names
/// what a descriptor holds. A metadata call that fails answers "not proven the
/// same", because an unprovable identity must never read as a match.
pub(super) fn same_object(a: &File, b: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (a.metadata(), b.metadata()) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Creates one child directory relative to an open directory.
///
/// `mkdirat` fails with `EEXIST` when the name is taken — including when it is
/// taken by a symlink, dangling or not — which makes it the same collision
/// oracle [`create_child`] is, asked of the volume rather than guessed at.
pub(super) fn create_child_dir(parent: &File, name: &str) -> Result<(), OpenError> {
    let name = c_name(name)?;
    // Safety: `parent` owns a live descriptor for the duration of the call and
    // `name` is a NUL-terminated C string that outlives it. Nothing is returned
    // but a status.
    #[allow(unsafe_code)]
    let status = unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), CREATE_DIR_MODE) };
    if status < 0 {
        return Err(classify(io::Error::last_os_error()));
    }
    Ok(())
}

/// Removes one child directory of an open directory, which must be empty.
///
/// The emptiness is the kernel's rule, not ours (`ENOTEMPTY`), and relying on
/// it is deliberate: a recursive delete that raced a concurrent upload would
/// otherwise remove a directory whose last file arrived a microsecond ago. The
/// recursive form in [`super::Dir::remove_tree`] descends first and then calls
/// this, so the kernel gets the final say every time.
pub(super) fn remove_child_dir(parent: &File, name: &str) -> io::Result<()> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // Safety: as `remove_child`; both arguments are borrowed for the call.
    #[allow(unsafe_code)]
    let status = unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), AT_REMOVEDIR) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Renames one child of an open directory to a name in another open directory.
///
/// Both ends are descriptors, so neither the source nor the destination path
/// can be redirected between the walk that proved them link-free and the
/// operation itself. This is what closes the window
/// [`super::Upload::commit`]'s by-path publish still has, and it is why every
/// caller of a rename in this crate that has two `Dir`s in hand uses this one.
///
/// **`renameat` replaces its destination silently**, exactly as `rename(2)`
/// does, and `existing` is therefore *not* enforced here — a portable "fail if
/// the destination exists" needs `renameatx_np` on Darwin and `renameat2` on
/// Linux, two different symbols with two different flag words. The occupancy
/// decision is made one layer up in [`super::Dir::rename_into`], where WebDAV's
/// `Overwrite` header lives and where the answer has to be a `412` rather than
/// a failed syscall. The argument is still taken, because the Windows half has
/// a flag for it and a signature that differed by platform would put the
/// difference somewhere a caller has to remember it.
pub(super) fn rename_child(
    parent: &File,
    name: &str,
    destination: &File,
    destination_name: &str,
    _existing: Existing,
) -> Result<(), OpenError> {
    let from = c_name(name)?;
    let to = c_name(destination_name)?;
    // Safety: both descriptors are owned by live `File`s and both C strings
    // outlive the call; `renameat` returns ownership of nothing.
    #[allow(unsafe_code)]
    let status =
        unsafe { renameat(parent.as_raw_fd(), from.as_ptr(), destination.as_raw_fd(), to.as_ptr()) };
    if status < 0 {
        return Err(classify(io::Error::last_os_error()));
    }
    Ok(())
}

/// Bytes an unprivileged writer may still put on the volume this directory
/// lives on.
///
/// Read from the **descriptor**, so the answer describes the volume the walk
/// reached rather than whatever the path names now. The Windows half cannot do
/// this — `GetDiskFreeSpaceExW` takes a path — and that asymmetry is recorded
/// in [`super::free_space`].
///
/// `f_bavail` rather than `f_bfree`: the difference is the reserve a filesystem
/// keeps for the superuser, and the daemon is not the superuser. Counting a
/// reserve we cannot spend would let the free-space floor pass while the write
/// fails with `ENOSPC`, which is the one outcome the floor exists to prevent.
/// The `path` argument is unused here and present so that both platforms
/// declare the same function: the Windows half has no handle-taking form of
/// this question, and a signature that differed by platform would push a `cfg`
/// into [`super::Dir`], where the security rules are deliberately
/// unconditional.
pub(super) fn free_space(directory: &File, _path: &Path) -> io::Result<u64> {
    let mut out = StatFs::default();
    // Safety: `directory` owns a live descriptor for the duration of the call,
    // and `out` is a local at least as large as the structure the kernel writes
    // — see `StatFs`'s own documentation for why the tail is oversized.
    #[allow(unsafe_code)]
    let status = unsafe { fstatfs(directory.as_raw_fd(), &raw mut out) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(available_bytes(&out))
}

/// The head of `struct statfs`, plus a tail large enough that the kernel cannot
/// write past it.
///
/// Only three fields are read, and only the *offsets* of those three have to be
/// right. Everything after them is a byte array rather than a transcription of
/// the rest of the structure, which is the point: `f_mntonname` alone is 1024
/// bytes on Darwin and the tail differs between kernels and kernel versions, so
/// transcribing it would be a large surface with no benefit and a real chance
/// of being wrong. An oversized opaque tail is right as long as it is *at
/// least* as long as the real one, and 4 KiB is comfortably more than the
/// ~2.2 KiB Darwin writes and the 120 bytes Linux writes.
///
/// The structure is written out twice rather than once with conditional fields,
/// because the two kernels genuinely disagree about it: Darwin opens with a
/// 32-bit `f_bsize` and puts `f_iosize` before the counts, which are 64-bit on
/// every architecture; Linux opens with `f_type` and makes every field a
/// machine word. Two honest declarations are shorter than one parameterised by
/// three type aliases, and each can be read against its own header.
///
/// `fs::tests::the_volume_reports_a_plausible_free_space_and_the_tree_reports_its_size`
/// is what keeps the offsets honest: fields read at the wrong offset produce an
/// absurd figure on a real volume, which that test asserts against.
#[cfg(target_vendor = "apple")]
#[repr(C)]
struct StatFs {
    /// `f_bsize`: the fundamental block size, in bytes.
    block_size: u32,
    /// `f_iosize`, never read; present so the counts are at their offsets.
    _io_size: i32,
    /// `f_blocks`, never read.
    _blocks: u64,
    /// `f_bfree` — free blocks *including* the superuser's reserve, never read.
    _blocks_free: u64,
    /// `f_bavail`: free blocks an ordinary writer may actually use.
    blocks_available: u64,
    /// Everything after, deliberately opaque and deliberately oversized.
    _tail: [u8; 4096],
}

/// See the Apple declaration above.
#[cfg(not(target_vendor = "apple"))]
#[repr(C)]
struct StatFs {
    /// `f_type`, never read.
    _kind: isize,
    /// `f_bsize`: the fundamental block size, in bytes. A signed word, so a
    /// negative value is a kernel that has gone wrong rather than a huge block.
    block_size: isize,
    /// `f_blocks`, never read.
    _blocks: usize,
    /// `f_bfree`, never read.
    _blocks_free: usize,
    /// `f_bavail`: free blocks an ordinary writer may actually use.
    blocks_available: usize,
    /// Everything after, deliberately opaque and deliberately oversized.
    _tail: [u8; 4096],
}

impl Default for StatFs {
    /// Zeroed, because the kernel overwrites everything it uses and a partial
    /// write must not leave a stale number that reads as free space.
    fn default() -> Self {
        Self {
            block_size: 0,
            #[cfg(target_vendor = "apple")]
            _io_size: 0,
            #[cfg(not(target_vendor = "apple"))]
            _kind: 0,
            _blocks: 0,
            _blocks_free: 0,
            blocks_available: 0,
            _tail: [0; 4096],
        }
    }
}

/// The bytes an ordinary writer may still use, from a filled-in structure.
///
/// Split out so that the one `unsafe` call has one body while the arithmetic —
/// which is where the platforms differ, in the width and signedness of two
/// fields — stays a small function per platform that can be read against its
/// own header.
#[cfg(target_vendor = "apple")]
fn available_bytes(out: &StatFs) -> u64 {
    out.blocks_available.saturating_mul(u64::from(out.block_size))
}

/// See the Apple arm above. A negative block size or a count that will not fit
/// a `u64` are both a kernel that has gone wrong, and both answer *no space
/// measured* rather than an enormous amount of it — the safe direction, since
/// this number's only use is to refuse writes.
#[cfg(not(target_vendor = "apple"))]
fn available_bytes(out: &StatFs) -> u64 {
    let block = u64::try_from(out.block_size).unwrap_or(0);
    let blocks = u64::try_from(out.blocks_available).unwrap_or(0);
    blocks.saturating_mul(block)
}

/// The shared body of the two read opens.
fn open_child(parent: &File, name: &str, flags: c_int) -> Result<File, OpenError> {
    let name = c_name(name)?;
    // Safety: as `create_child`.
    #[allow(unsafe_code)]
    let raw = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags | flags::O_CLOEXEC) };
    finish(raw)
}

/// Turns a raw result into an owned [`File`] or a typed refusal.
fn finish(raw: c_int) -> Result<File, OpenError> {
    if raw < 0 {
        return Err(classify(io::Error::last_os_error()));
    }
    // Safety: `raw` is a descriptor this call just created and has not been
    // given to anything else, so `File` is its sole owner.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(raw) })
}

/// A validated segment as a C string.
///
/// An interior NUL cannot reach here — [`crate::path::validate_segment`] refuses
/// control bytes — but the failure is mapped rather than unwrapped, because
/// under `panic = "abort"` an unwrap that is merely *believed* unreachable is a
/// whole-box outage waiting for the belief to be wrong.
fn c_name(name: &str) -> Result<CString, OpenError> {
    CString::new(name).map_err(|_| OpenError::Refused(crate::path::Refusal::Nul))
}

/// Maps an errno onto this module's vocabulary.
///
/// `ELOOP` is the one that matters: it is what a kernel says when `O_NOFOLLOW`
/// met a symlink, and turning it into a plain I/O error would hide the single
/// event an operator most wants to see in a log. `std` has no stable
/// `ErrorKind` for either of these two, which is why the numbers appear.
fn classify(error: io::Error) -> OpenError {
    match error.raw_os_error() {
        Some(flags::ELOOP) => OpenError::Symlink,
        Some(flags::ENOTDIR) => OpenError::NotADirectory,
        _ => match error.kind() {
            io::ErrorKind::NotFound => OpenError::NotFound,
            io::ErrorKind::AlreadyExists => OpenError::AlreadyExists,
            _ => OpenError::Io(error),
        },
    }
}
