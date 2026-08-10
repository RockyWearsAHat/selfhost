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

use super::OpenError;
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

// The two syscalls. `openat` is genuinely variadic in C — the mode argument is
// read only when `O_CREAT` is set — and it is declared variadic here so the
// calls that pass a mode and the calls that do not are both built with the ABI
// the platform actually uses for it, which differs from the fixed-argument ABI
// on aarch64 Apple targets.
#[allow(unsafe_code)]
unsafe extern "C" {
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn unlinkat(directory: c_int, path: *const c_char, flags: c_int) -> c_int;
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
