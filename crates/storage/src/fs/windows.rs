//! The Windows half of the descriptor walk: `NtCreateFile` relative to an open
//! directory handle.
//!
//! # Why the native call and not `CreateFileW`
//!
//! Win32 has no `openat`. `CreateFileW` takes a whole path, and
//! `FILE_FLAG_OPEN_REPARSE_POINT` protects only its **final** component — so
//! opening `root\a\b\c` with that flag still walks a junction planted at `a`.
//! Checking each prefix in turn with `CreateFileW` and then opening the next one
//! is a check followed by a separate resolution, which is the exact race this
//! module exists to remove.
//!
//! `NtCreateFile` takes an `OBJECT_ATTRIBUTES` whose `RootDirectory` is an open
//! handle and whose `ObjectName` is a name *relative to it*. That is `openat`,
//! spelled in the native API, and it is the only way to make the walk
//! structural on this platform. It is one declared symbol from `ntdll`, in the
//! style `admin/src/token.rs:466` already uses for `kernel32` and `advapi32`.
//!
//! # Windows opens the reparse point instead of refusing it
//!
//! With `FILE_OPEN_REPARSE_POINT` the open **succeeds** and yields a handle to
//! the link itself rather than to its target. That is what makes the refusal
//! possible, and it also means the refusal is ours to make: every open here is
//! followed by a check of the opened object's own `FILE_ATTRIBUTE_REPARSE_POINT`
//! bit. The check is on the handle, not on a name, so nothing can change
//! underneath it — a junction, a directory symlink, a file symlink and a mount
//! point are all reparse points and all refused alike.

use super::OpenError;
use std::ffi::{c_void, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

/// Lets `CreateFileW` — and so `OpenOptions::open` — open a directory at all.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// The bit that says an object is a junction, a symlink or a mount point.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// Ordinary attributes for a file this crate creates.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Names are matched the way the rest of the platform matches them.
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// Open an existing object; fail if it is absent.
const FILE_OPEN: u32 = 1;
/// Create a new object; fail if the name is taken. The collision oracle.
const FILE_CREATE: u32 = 2;

/// The object must be a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// The object must not be a directory.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// Synchronous I/O, which is what a `File` handle is expected to be.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
/// Open the reparse point itself rather than walking through it.
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Read, write and delete sharing, so an operator is never locked out of their
/// own file by the daemon holding it open.
const FILE_SHARE_ALL: u32 = 0x0000_0007;

/// List the names in a directory.
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
/// Traverse into a directory.
const FILE_TRAVERSE: u32 = 0x0000_0020;
/// Read the attributes that the reparse-point check needs.
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Required by `FILE_SYNCHRONOUS_IO_NONALERT`.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// Everything a read of a file needs, `SYNCHRONIZE` included.
const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// Everything a write of a file needs, `SYNCHRONIZE` included.
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// Needed to delete through the handle, which is how an abandoned upload is
/// removed.
const DELETE: u32 = 0x0001_0000;

/// The name is taken — what `FILE_CREATE` says instead of `EEXIST`.
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
/// No object of that name.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
/// No path leading to that name.
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
/// A component that had to be a directory is not one.
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
/// The object is a directory where a file was required.
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
/// The filesystem met a reparse tag it would not act on.
const STATUS_IO_REPARSE_TAG_NOT_HANDLED: i32 = 0xC000_0279_u32 as i32;

/// `FileDispositionInfo`, the class that marks a handle's file for deletion.
const FILE_DISPOSITION_INFO: u32 = 4;

/// A counted, **not** NUL-terminated string, which is how the native API names
/// objects.
///
/// `length` and `maximum_length` are byte counts rather than character counts —
/// the single most common way to get this structure wrong.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// The name to open and, crucially, the directory to open it relative to.
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

/// The completion record every native I/O call writes. Its contents are not
/// read here; the status returned by the call is the answer.
#[repr(C)]
struct IoStatusBlock {
    pointer: *mut c_void,
    information: usize,
}

/// `FILE_DISPOSITION_INFO`: one byte saying "delete this when the last handle
/// closes".
#[repr(C)]
struct FileDispositionInfo {
    delete_file: u8,
}

/// A 64-bit time split into two words, as every Win32 structure carries it.
///
/// Never read here; it is present because the fields after it in
/// [`ByHandleFileInformation`] are only at the right offsets if it is.
#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}

/// `BY_HANDLE_FILE_INFORMATION`, of which two fields are wanted: the volume
/// serial number and the two halves of the file index, which together are this
/// platform's `(st_dev, st_ino)`.
///
/// `std` exposes both through `MetadataExt`, but only behind the unstable
/// `windows_by_handle` feature — and a stable toolchain is not negotiable for a
/// box that rebuilds itself unattended, so the call is made directly.
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[allow(unsafe_code)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[allow(unsafe_code)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        file: *mut c_void,
        information_class: u32,
        information: *const c_void,
        size: u32,
    ) -> i32;
    fn GetFileInformationByHandle(
        file: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
}

/// Whether two open handles are the same directory on the same volume.
///
/// The volume serial number and the 64-bit file index are Windows' answer to
/// `(st_dev, st_ino)`, and they are read from the handles rather than from
/// either path — which is the whole point, since the question being asked is
/// whether a path still names what a handle holds. A call that fails answers
/// "not proven the same", because an unprovable identity must never read as a
/// match.
pub(super) fn same_object(a: &File, b: &File) -> bool {
    let (Some(a), Some(b)) = (identity(a), identity(b)) else {
        return false;
    };
    a == b
}

/// One handle's `(volume, index)` pair, or `None` if the volume would not say.
fn identity(handle: &File) -> Option<(u32, u32, u32)> {
    let mut information = ByHandleFileInformation::default();
    // Safety: the handle is live for the duration of the call and the structure
    // is a local the callee only writes into, sized by its own layout.
    #[allow(unsafe_code)]
    let ok = unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut information) };
    if ok == 0 {
        return None;
    }
    Some((
        information.volume_serial_number,
        information.file_index_high,
        information.file_index_low,
    ))
}

/// Opens a directory by path. Used for the share root and for the identity
/// check that guards [`super::Dir::names`], and nowhere else.
///
/// Deliberately without `FILE_FLAG_OPEN_REPARSE_POINT`: the root may
/// legitimately be a junction an operator chose, and the identity check that the
/// other caller performs is what makes walking through one safe there.
pub(super) fn open_root(path: &Path) -> Result<File, OpenError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(classify_io)
}

/// Opens one child directory relative to an open directory, refusing a reparse
/// point.
pub(super) fn open_child_dir(parent: &File, name: &str) -> Result<File, OpenError> {
    let handle = native_open(
        parent,
        name,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )?;
    refuse_reparse_point(handle)
}

/// Opens one child file relative to an open directory, refusing a reparse point.
pub(super) fn open_child_file(parent: &File, name: &str) -> Result<File, OpenError> {
    let handle = native_open(
        parent,
        name,
        FILE_GENERIC_READ,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )?;
    refuse_reparse_point(handle)
}

/// Creates one child file relative to an open directory, failing if the name is
/// taken.
///
/// `FILE_CREATE` is the collision oracle the module documentation describes: it
/// fails with `STATUS_OBJECT_NAME_COLLISION` exactly when NTFS — under its own
/// case folding, which this code does not attempt to reproduce — considers the
/// name to be in use. `DELETE` is requested so that an abandoned upload can be
/// removed through the handle it already holds.
pub(super) fn create_child(parent: &File, name: &str) -> Result<File, OpenError> {
    native_open(
        parent,
        name,
        FILE_GENERIC_WRITE | DELETE,
        FILE_ATTRIBUTE_NORMAL,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

/// Removes one child of an open directory.
///
/// Windows deletes **through a handle** rather than by name, which is what makes
/// this operation as confined as the rest of the walk: the handle came from the
/// relative open, so nothing about the path can have changed in between. The
/// file goes when the last handle to it closes, which is why the handle is
/// dropped immediately afterwards.
///
/// When the caller has no handle — a path this crate does not currently take,
/// kept because the signature is shared with unix — one is opened relative to
/// the directory, with the same refusal of reparse points as every other open.
pub(super) fn remove_child(parent: &File, name: &str, handle: Option<File>) -> io::Result<()> {
    let handle = match handle {
        Some(handle) => handle,
        None => native_open(
            parent,
            name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
        .map_err(io::Error::other)?,
    };

    let disposition = FileDispositionInfo { delete_file: 1 };
    // Safety: the handle is live for the duration of the call and was opened
    // with `DELETE`; the pointer is to a local whose size is passed alongside
    // it, which is the contract this function documents.
    #[allow(unsafe_code)]
    let ok = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle(),
            FILE_DISPOSITION_INFO,
            (&raw const disposition).cast(),
            size_of::<FileDispositionInfo>() as u32,
        )
    };
    drop(handle);
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The one relative open, which every other function here is a set of flags
/// for.
fn native_open(
    parent: &File,
    name: &str,
    desired_access: u32,
    file_attributes: u32,
    disposition: u32,
    options: u32,
) -> Result<File, OpenError> {
    // Not NUL-terminated, and byte-counted: `UnicodeString` says so, and this is
    // where getting it wrong would silently open the wrong name.
    let mut wide: Vec<u16> = OsStr::new(name).encode_wide().collect();
    let Ok(bytes) = u16::try_from(wide.len().saturating_mul(2)) else {
        // Unreachable through `validate_segment`, which caps a segment at 255
        // bytes; mapped rather than unwrapped because an `unwrap` believed
        // unreachable is a whole-box outage under `panic = "abort"`.
        return Err(OpenError::Refused(crate::path::Refusal::SegmentTooLong));
    };
    let object_name = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: wide.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &object_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };

    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut status_block = IoStatusBlock { pointer: std::ptr::null_mut(), information: 0 };
    // Safety: every pointer passed is to a local that outlives the call, the
    // parent handle is owned by a live `File`, and the handle written back is
    // handed straight to `File`, which owns and closes it.
    #[allow(unsafe_code)]
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            file_attributes,
            FILE_SHARE_ALL,
            disposition,
            options,
            std::ptr::null_mut(),
            0,
        )
    };
    // Keeping the name and the attributes alive until after the call is not
    // decoration: `object_name.buffer` points into `wide`.
    drop(wide);

    if status != 0 {
        return Err(classify_status(status));
    }
    // Safety: `handle` was written by a successful `NtCreateFile` and has been
    // given to nothing else, so `File` is its sole owner.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Turns an opened reparse point back into a refusal.
///
/// The check is on the handle rather than on the name, so there is no window in
/// which the object could be swapped between deciding and using.
fn refuse_reparse_point(handle: File) -> Result<File, OpenError> {
    let attributes = handle.metadata().map_err(classify_io)?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OpenError::Symlink);
    }
    Ok(handle)
}

/// Maps an `NTSTATUS` onto this module's vocabulary, keeping the operating
/// system's own message for everything it does not name.
#[allow(unsafe_code)]
fn classify_status(status: i32) -> OpenError {
    match status {
        STATUS_OBJECT_NAME_COLLISION => OpenError::AlreadyExists,
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => OpenError::NotFound,
        STATUS_NOT_A_DIRECTORY => OpenError::NotADirectory,
        STATUS_FILE_IS_A_DIRECTORY => OpenError::NotAFile,
        STATUS_IO_REPARSE_TAG_NOT_HANDLED => OpenError::Symlink,
        // Safety: a pure translation of one integer into another, with no
        // pointers and no ownership involved.
        other => {
            let code = unsafe { RtlNtStatusToDosError(other) };
            OpenError::Io(io::Error::from_raw_os_error(code as i32))
        }
    }
}

/// Maps a standard-library error onto this module's vocabulary.
fn classify_io(error: io::Error) -> OpenError {
    match error.kind() {
        io::ErrorKind::NotFound => OpenError::NotFound,
        io::ErrorKind::AlreadyExists => OpenError::AlreadyExists,
        _ => OpenError::Io(error),
    }
}
