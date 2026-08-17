//! The shared secret that authorises control of the deployment.
//!
//! Whoever holds this token can start and stop everything on the machine, so it
//! is generated from the operating system's entropy — never from a clock, a
//! process id, or a hash of them, all of which are guessable by someone who knows
//! roughly when the daemon started.
//!
//! It lives in a file only the service account can read. That is the same trust
//! model as an SSH private key: the file permissions *are* the security boundary,
//! and anyone who can already read arbitrary files as that account can control
//! the services anyway.
//!
//! # Why the permissions are written twice, once per platform
//!
//! Because "the file permissions are the boundary" is a claim, and a claim has
//! to be true on the machine the deployment actually runs on. On unix the file
//! is created `0600` from the outset. On Windows — where production runs, as a
//! Scheduled Task under `SYSTEM` — there are no mode bits, and a file created
//! with `std::fs::write` simply inherits whatever the parent directory hands
//! down. Inside a user profile tree that inheritance routinely includes the
//! interactive user and, on a machine with more than one account, other accounts
//! besides. This file's contents are the deployment's root credential: a valid
//! bearer token skips every browser-side defence at once — no CSRF header, no
//! `Origin`, no `SameSite`, no session expiry, no login rate limiter, no passkey.
//! So [`write_private`] on Windows builds an **explicit, protected DACL**
//! granting only `SYSTEM` and `Administrators`, hands it to `CreateFileW` at
//! creation time, and renames the result into place — never `std::fs::write`,
//! and never a permission applied after the bytes already exist, because the
//! gap between those two steps is exactly when a shared machine gets to read it.
//!
//! # The unsafe exemption
//!
//! The crate sets `unsafe_code = "deny"` rather than `forbid` for one reason:
//! Windows has no safe standard-library route to either of the two things this
//! module needs from the operating system. There are exactly two exemptions,
//! each granted with an explicit `#[allow(unsafe_code)]` at the call site rather
//! than crate-wide: [`random_bytes`] (entropy, via `RtlGenRandom`) and
//! [`write_private`]'s Windows arm (the DACL, via `advapi32`/`kernel32`). Both
//! are confined to this file; no other module in the crate contains `unsafe`.

use std::io;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a token. 256 bits, rendered as 64 hex characters.
const TOKEN_BYTES: usize = 32;

/// The name of the token file inside the data directory.
pub const TOKEN_FILENAME: &str = "admin.token";

/// A bearer token authorising control of the deployment.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Loads the token from the data directory, generating one if absent.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        let path = Self::path_in(data_dir);
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                return Ok(Self(trimmed.to_owned()));
            }
        }

        std::fs::create_dir_all(data_dir)?;
        let token = Self(hex(&random_bytes(TOKEN_BYTES)?));
        write_private(&path, &token.0)?;
        Ok(token)
    }

    /// Where the token file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(TOKEN_FILENAME)
    }

    /// The token as it appears in an `Authorization: Bearer` header.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a presented credential matches.
    ///
    /// Compared in constant time. A short-circuiting comparison leaks how many
    /// leading characters were right, which turns guessing the token from
    /// infeasible into a few thousand requests against a local port.
    pub fn matches(&self, presented: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), presented.as_bytes())
    }
}

/// Whether two byte strings are equal, in constant time for equal lengths.
///
/// Shared by every credential comparison in this crate — the bearer token and
/// the session ids — so the no-short-circuit property lives in one place. A
/// length mismatch returns early, which is fine: the length of our secrets is
/// public (64 hex characters).
pub(crate) fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(actual) {
        difference |= a ^ b;
    }
    difference == 0
}

// Deliberately not `Display` or a revealing `Debug`: a token that formats itself
// ends up in a log line eventually, and a secret in a log is a secret no longer.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(<redacted>)")
    }
}

/// Writes a secret so only its owner can read it.
///
/// Shared with [`crate::passwd`], which stores the console password hash under
/// the same trust model as the token: the file permissions are the boundary.
#[cfg(unix)]
pub(crate) fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Created 0600 from the outset rather than written and then chmod-ed: between
    // those two steps the secret is world-readable, and that window is exactly
    // when a shared machine gets to read it.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

/// Writes a secret under an explicit DACL that names only `SYSTEM` and
/// `Administrators` (Windows).
///
/// Windows has no mode bits. A file created by `std::fs::write` takes the
/// inheritable ACEs of whatever directory it lands in, which inside a user
/// profile tree means at least the interactive user — and on a machine with a
/// second account, potentially that account too. For the deployment's root
/// credential that is not a boundary at all, so the descriptor is stated rather
/// than inherited:
///
/// `D:P(A;;FA;;;SY)(A;;FA;;;BA)` — a **protected** (`P`) DACL, so no ACE flows
/// down from the parent, granting full access to `SY` (LocalSystem, which is
/// what the production Scheduled Task runs as) and `BA`
/// (`BUILTIN\Administrators`, which is how an operator reaches it from an
/// elevated shell) and to nobody else.
///
/// # Why the write goes through a temporary file
///
/// `CreateFileW` applies a `SECURITY_ATTRIBUTES` descriptor **only when it
/// creates the file**; open an existing path with `CREATE_ALWAYS` and the
/// descriptor is ignored outright, leaving whatever ACL was there before. A
/// rotation onto an already-loose file would therefore silently keep the loose
/// ACL. So the bytes go to a fresh `CREATE_NEW` file — which cannot exist, so
/// the DACL is always applied — and are then renamed over the destination.
/// NTFS keeps the source file's own security descriptor across a rename within
/// a directory, and the replacement is atomic for readers, which is the same
/// property [`crate::store`] wants from its own temp-then-rename.
///
/// # What this does not claim
///
/// The creating process's account becomes the file's owner, and an owner can
/// always rewrite the DACL. That is inherent to Windows and is not a hole this
/// function can close: it means "only SYSTEM and Administrators may read it,
/// plus whoever created it" — and everything that writes this file already runs
/// as one of those. A non-elevated administrator is a real caveat: their token
/// carries `BUILTIN\Administrators` as deny-only, so a token written from an
/// elevated shell is not readable from a non-elevated one. Ownership is the
/// escape hatch there, and `selfhost doctor` reports what the ACL actually says
/// rather than what this comment hopes it says.
#[cfg(windows)]
pub(crate) fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    let temporary = temporary_sibling(path)?;
    let result = windows_acl::write_new_private(&temporary, contents.as_bytes())
        .and_then(|()| windows_acl::rename_over(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// A never-yet-existing sibling path to create the secret at first.
///
/// The name carries entropy from the same generator as the token itself, so two
/// concurrent writers cannot collide and an attacker cannot pre-create the path
/// to make `CREATE_NEW` fail forever.
#[cfg(windows)]
fn temporary_sibling(path: &Path) -> io::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::other("a secret needs a file name, not a directory path"))?
        .to_owned();
    name.push(format!(".new-{}", hex(&random_bytes(8)?)));
    Ok(path.with_file_name(name))
}

/// Neither unix nor Windows: refuse rather than write an unprotected secret.
///
/// There is no third platform in this deployment, and inventing a silent
/// `std::fs::write` fallback would mean a target where the token is written with
/// whatever permissions happen to apply while this module's doc comment claims
/// the file permissions are the boundary. Failing loudly is the honest answer:
/// whoever ports this deployment writes the arm for their platform first.
#[cfg(not(any(unix, windows)))]
pub(crate) fn write_private(_path: &Path, _contents: &str) -> io::Result<()> {
    Err(io::Error::other(
        "refusing to write a secret on a platform whose file permissions this build \
         cannot set; add a write_private arm for it before storing credentials here",
    ))
}

/// Who can read a secret on disk, as an observation rather than a verdict.
///
/// Returned by [`privacy_of`] and rendered by `selfhost doctor`. The third
/// variant exists because "could not tell" and "fine" are different states, and
/// a diagnostic that collapses them tells the operator their root credential is
/// protected on a platform where nothing was ever inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privacy {
    /// Nobody but the owner (unix) or `SYSTEM`/`Administrators` (Windows) can
    /// read it. The string says what was actually observed, e.g. `mode 0600`.
    Private(String),
    /// Somebody else can read it, named as concretely as the platform allows.
    Exposed(String),
    /// The question could not be answered here; the string says why.
    Unanswerable(String),
}

impl Privacy {
    /// The observation, for a report line that shows what was measured.
    pub fn detail(&self) -> &str {
        match self {
            Self::Private(detail) | Self::Exposed(detail) | Self::Unanswerable(detail) => detail,
        }
    }
}

/// Reports who can read the file or directory at `path`.
///
/// An `Err` means the path itself could not be examined — most usefully
/// `NotFound`, which a caller should render as "not created yet" rather than as
/// either a pass or a failure.
///
/// On unix this is the mode bits: anything in the group or other triads is
/// exposure. On Windows it is the object's real DACL, read back through
/// `GetNamedSecurityInfoW` and judged by [`judge_dacl_sddl`]. On any other
/// platform it is [`Privacy::Unanswerable`], because guessing would be the same
/// lie [`write_private`] refuses to tell there.
pub fn privacy_of(path: &Path) -> io::Result<Privacy> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        let shared = mode & 0o077;
        Ok(if shared == 0 {
            Privacy::Private(format!("mode {:04o} — owner only", mode & 0o7777))
        } else {
            Privacy::Exposed(format!(
                "mode {:04o} — {} can reach it",
                mode & 0o7777,
                if mode & 0o007 != 0 { "any account on this machine" } else { "the file's group" }
            ))
        })
    }
    #[cfg(windows)]
    {
        let sddl = windows_acl::dacl_sddl(path)?;
        Ok(judge_dacl_sddl(&sddl))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = std::fs::metadata(path)?;
        Ok(Privacy::Unanswerable(
            "this platform's file permissions are not modelled by selfhost".into(),
        ))
    }
}

/// Judges a Windows DACL, written in SDDL, against "only SYSTEM and
/// Administrators".
///
/// Pure, so the rule that decides whether the production box's root credential
/// is protected is testable on a laptop that has never seen an ACL. The input is
/// the string `ConvertSecurityDescriptorToStringSecurityDescriptorW` produces
/// for `DACL_SECURITY_INFORMATION`, e.g. `D:P(A;;FA;;;SY)(A;;FA;;;BA)`:
///
/// - the field starts at `D:`, followed by control flags and then one
///   parenthesised ACE per entry, each six semicolon-separated fields whose
///   first is the type and whose last is the trustee;
/// - `NO_ACCESS_CONTROL` in the flags means a **NULL** DACL, which grants
///   everyone everything — the worst case, not the empty one;
/// - deny ACEs only ever subtract, so they are not exposure and are ignored;
/// - an allow ACE naming anything other than `SY`/`BA` (or their literal SIDs
///   `S-1-5-18` / `S-1-5-32-544`) is exposure, and the trustee is named;
/// - a DACL without the `P` flag is reported as private if its trustees are
///   right, but says so, because an unprotected DACL inherits whatever the
///   parent directory is changed to later.
pub fn judge_dacl_sddl(sddl: &str) -> Privacy {
    let Some(dacl) = dacl_field(sddl) else {
        return Privacy::Unanswerable(format!(
            "no DACL in the security descriptor \"{}\"",
            sddl.trim()
        ));
    };

    let (flags, aces) = match dacl.find('(') {
        Some(start) => (&dacl[..start], &dacl[start..]),
        None => (dacl, ""),
    };

    if flags.to_ascii_uppercase().contains("NO_ACCESS_CONTROL") {
        return Privacy::Exposed(
            "a NULL DACL — every account on the machine has full access".into(),
        );
    }

    let mut granted: Vec<&str> = Vec::new();
    let mut strangers: Vec<&str> = Vec::new();
    for ace in parse_aces(aces) {
        let Some(trustee) = ace.trustee else {
            return Privacy::Unanswerable(format!("unreadable ACE in \"{}\"", dacl.trim()));
        };
        if !ace.allows {
            continue;
        }
        if is_privileged_trustee(trustee) {
            if !granted.contains(&trustee) {
                granted.push(trustee);
            }
        } else if !strangers.contains(&trustee) {
            strangers.push(trustee);
        }
    }

    if !strangers.is_empty() {
        return Privacy::Exposed(format!("readable by {}", strangers.join(", ")));
    }

    let who = if granted.is_empty() {
        "no account at all is granted access; only the file's owner can reach it".to_owned()
    } else {
        format!("{} only", granted.join(", "))
    };
    let inheritance = if flags.to_ascii_uppercase().contains('P') {
        "inheritance blocked"
    } else {
        "but the DACL is not protected from inheritance, so a change to the parent \
         directory can widen it"
    };
    Privacy::Private(format!("{who}, {inheritance}"))
}

/// The `D:` field of an SDDL security descriptor, without its `D:` marker.
///
/// The reader requests `DACL_SECURITY_INFORMATION` alone, so in practice the
/// string begins with `D:` and the rest is the DACL. A descriptor that also
/// carries owner or group fields is still handled, and a `S:` (audit) field is
/// trimmed off the end, because an SACL is not an access rule.
fn dacl_field(sddl: &str) -> Option<&str> {
    let text = sddl.trim();
    let start = if let Some(rest) = text.strip_prefix("D:") {
        rest
    } else {
        let at = text.find("D:")?;
        &text[at + 2..]
    };
    Some(match start.find("S:") {
        // An "S:" inside an ACE list belongs to no field — the SACL can only
        // follow the last ACE, so only a match outside parentheses ends it.
        Some(at) if start[..at].matches('(').count() == start[..at].matches(')').count() => {
            &start[..at]
        }
        _ => start,
    })
}

/// One access-control entry, reduced to the two things this judgement needs.
struct Ace<'a> {
    /// Whether it grants access. Deny and audit entries do not.
    allows: bool,
    /// The trustee field, or `None` when the entry was not six fields long.
    trustee: Option<&'a str>,
}

/// Splits the parenthesised ACE list of a DACL.
///
/// Deliberately tolerant of trailing text and forgiving of whitespace, and
/// deliberately *not* tolerant of a short entry: a malformed ACE yields
/// `trustee: None` so the caller reports "unreadable" rather than quietly
/// judging a descriptor it did not understand.
fn parse_aces(text: &str) -> Vec<Ace<'_>> {
    let mut aces = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else { break };
        let body = &after[..close];
        rest = &after[close + 1..];

        let fields: Vec<&str> = body.split(';').map(str::trim).collect();
        if fields.len() < 6 {
            aces.push(Ace { allows: true, trustee: None });
            continue;
        }
        // Allow types are A, OA (object) and XA (conditional); every other
        // first letter is a denial or an audit, neither of which grants access.
        let allows = fields[0].to_ascii_uppercase().ends_with('A');
        aces.push(Ace { allows, trustee: Some(fields[5]) });
    }
    aces
}

/// Whether a trustee is one of the two accounts a secret may name.
///
/// Both the SDDL abbreviation and the literal SID are accepted, because
/// Windows emits the abbreviation for well-known accounts but a descriptor
/// written by hand or copied from another machine may carry either.
fn is_privileged_trustee(trustee: &str) -> bool {
    matches!(
        trustee.to_ascii_uppercase().as_str(),
        "SY" | "BA" | "S-1-5-18" | "S-1-5-32-544"
    )
}

/// The Windows system calls this module needs, and nothing else.
///
/// Every `unsafe` in the crate outside [`random_bytes`] is in here, each call
/// carrying its own `#[allow(unsafe_code)]` so the crate-level `deny` keeps
/// meaning something everywhere else.
#[cfg(windows)]
mod windows_acl {
    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    /// The descriptor every secret this crate writes is created under:
    /// protected, full access for LocalSystem and BUILTIN\Administrators, and
    /// no other entry.
    const SECRET_DACL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

    // Win32 constants, spelled out rather than imported — this workspace links
    // no Windows crate, by policy.
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x4;
    const ERROR_SUCCESS: u32 = 0;

    /// `INVALID_HANDLE_VALUE`, which is `-1` rather than null.
    fn invalid_handle() -> *mut c_void {
        -1isize as *mut c_void
    }

    #[allow(unsafe_code)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn WriteFile(
            file: *mut c_void,
            buffer: *const u8,
            to_write: u32,
            written: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn FlushFileBuffers(file: *mut c_void) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    #[allow(unsafe_code)]
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_descriptor: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *mut c_void,
            revision: u32,
            information: u32,
            string_descriptor: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
        fn GetNamedSecurityInfoW(
            object_name: *const u16,
            object_type: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
    }

    /// `SECURITY_ATTRIBUTES`, the only Win32 struct this module passes.
    ///
    /// `n_length` must be the size of this struct; Windows rejects the call
    /// outright if it disagrees, which is the one field worth stating twice.
    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    /// A self-relative security descriptor, freed on drop.
    ///
    /// Owning it in a type rather than remembering to call `LocalFree` on every
    /// path is the difference between a leak-free function and a function that
    /// leaks on its error branches only.
    struct LocalDescriptor(*mut c_void);

    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                #[allow(unsafe_code)]
                unsafe {
                    LocalFree(self.0)
                };
            }
        }
    }

    /// A `LocalAlloc`-owned wide string, freed on drop.
    struct LocalString(*mut u16);

    impl Drop for LocalString {
        fn drop(&mut self) {
            if !self.0.is_null() {
                #[allow(unsafe_code)]
                unsafe {
                    LocalFree(self.0.cast())
                };
            }
        }
    }

    /// A path as a NUL-terminated UTF-16 string.
    ///
    /// A path containing an interior NUL is refused rather than silently
    /// truncated — a truncated path is a different file, and writing a secret to
    /// a different file is the failure this whole module exists to prevent.
    fn wide(path: &OsStr) -> io::Result<Vec<u16>> {
        let mut units: Vec<u16> = path.encode_wide().collect();
        if units.contains(&0) {
            return Err(io::Error::other("path contains an interior NUL"));
        }
        units.push(0);
        Ok(units)
    }

    /// The same, for a string literal known at compile time.
    fn wide_str(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Creates `path` — which must not already exist — under [`SECRET_DACL`]
    /// and writes `contents` to it.
    ///
    /// `CREATE_NEW` is what makes the descriptor load-bearing: Windows applies
    /// a `SECURITY_ATTRIBUTES` descriptor only when the call actually creates
    /// the file, so opening an existing path would take the existing ACL and
    /// this function would quietly become the no-op it replaced.
    pub(super) fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
        let descriptor = parse_descriptor(SECRET_DACL)?;
        let attributes = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: descriptor.0,
            inherit_handle: 0,
        };
        let name = wide(path.as_os_str())?;

        #[allow(unsafe_code)]
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0, // no sharing: nothing reads a half-written credential
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == invalid_handle() {
            return Err(io::Error::last_os_error());
        }

        let result = write_all(handle, contents);
        #[allow(unsafe_code)]
        unsafe {
            CloseHandle(handle)
        };
        result
    }

    /// Writes every byte, tolerating the short writes `WriteFile` may report.
    fn write_all(handle: *mut c_void, contents: &[u8]) -> io::Result<()> {
        let mut remaining = contents;
        while !remaining.is_empty() {
            let chunk = u32::try_from(remaining.len()).unwrap_or(u32::MAX);
            let mut written: u32 = 0;
            #[allow(unsafe_code)]
            let ok = unsafe {
                WriteFile(handle, remaining.as_ptr(), chunk, &mut written, std::ptr::null_mut())
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::Error::other("the file system accepted no bytes"));
            }
            remaining = &remaining[written as usize..];
        }
        #[allow(unsafe_code)]
        let flushed = unsafe { FlushFileBuffers(handle) };
        if flushed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Renames `from` over `to`, replacing it, keeping the source's own DACL.
    pub(super) fn rename_over(from: &Path, to: &Path) -> io::Result<()> {
        let source = wide(from.as_os_str())?;
        let destination = wide(to.as_os_str())?;
        #[allow(unsafe_code)]
        let ok = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Reads back the DACL of `path` as SDDL, for [`super::judge_dacl_sddl`].
    pub(super) fn dacl_sddl(path: &Path) -> io::Result<String> {
        let name = wide(path.as_os_str())?;
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut c_void = std::ptr::null_mut();

        #[allow(unsafe_code)]
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let owned = LocalDescriptor(descriptor);

        let mut text: *mut u16 = std::ptr::null_mut();
        let mut length: u32 = 0;
        #[allow(unsafe_code)]
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                owned.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let owned_text = LocalString(text);
        // Whether the reported length counts the terminating NUL is not worth
        // depending on: take it as an upper bound and trim what a NUL would
        // leave behind, so the judgement never sees a stray control character.
        #[allow(unsafe_code)]
        let units = unsafe { std::slice::from_raw_parts(owned_text.0, length as usize) };
        Ok(String::from_utf16_lossy(units).trim_end_matches('\0').to_owned())
    }

    /// Turns an SDDL string into a security descriptor Windows will accept.
    fn parse_descriptor(sddl: &str) -> io::Result<LocalDescriptor> {
        let text = wide_str(sddl);
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        #[allow(unsafe_code)]
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalDescriptor(descriptor))
    }
}

/// Renders bytes as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Fills a buffer with entropy from the operating system.
///
/// Shared with [`crate::session`], whose session ids need the same
/// unguessability as the token itself.
#[cfg(unix)]
pub(crate) fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buffer = vec![0u8; count];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Windows equivalent, via the system's own generator.
///
/// `RtlGenRandom` is the long-standing entry point for this and needs no
/// initialisation, which keeps the declaration to a single symbol.
#[cfg(windows)]
pub(crate) fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    #[allow(unsafe_code)]
    #[link(name = "advapi32")]
    unsafe extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buffer: *mut u8, length: u32) -> u8;
    }

    let mut buffer = vec![0u8; count];
    #[allow(unsafe_code)]
    let ok = unsafe { RtlGenRandom(buffer.as_mut_ptr(), buffer.len() as u32) };
    if ok == 0 {
        return Err(io::Error::other("the system random number generator refused"));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to one test.
    ///
    /// Named per test rather than per process: tests run concurrently, and a
    /// shared directory means one test deletes the file another is asserting on.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-token-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_generated_token_is_long_and_unpredictable() {
        let bytes = random_bytes(TOKEN_BYTES).expect("system entropy");
        assert_eq!(bytes.len(), TOKEN_BYTES);
        // Two draws matching would mean the source is not random at all.
        let again = random_bytes(TOKEN_BYTES).expect("system entropy");
        assert_ne!(bytes, again);
        assert!(bytes.iter().any(|&b| b != 0), "entropy should not be all zeroes");
    }

    #[test]
    fn the_token_survives_a_restart_rather_than_being_regenerated() {
        // Regenerating on every start would log the console out each time the
        // daemon restarted, which trains the operator to ignore auth failures.
        let dir = scratch("restart");
        let first = Token::load_or_create(&dir).expect("created");
        let second = Token::load_or_create(&dir).expect("loaded");
        assert_eq!(first.as_str(), second.as_str());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn comparison_rejects_wrong_credentials_including_prefixes() {
        let token = Token("abcdef".to_owned());
        assert!(token.matches("abcdef"));
        assert!(!token.matches("abcdeg"));
        assert!(!token.matches("abcde"), "a prefix is not a match");
        assert!(!token.matches("abcdefg"), "nor is an extension");
        assert!(!token.matches(""));
    }

    #[test]
    fn the_token_does_not_print_itself() {
        // A token that formats itself reaches a log file eventually.
        let token = Token("supersecret".to_owned());
        assert!(!format!("{token:?}").contains("supersecret"));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        Token::load_or_create(&dir).expect("created");
        let mode = std::fs::metadata(Token::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_token_reports_itself_private() {
        // The same question `selfhost doctor` asks, asked of a file this crate
        // just wrote: whatever the platform, writing and inspecting must agree.
        let dir = scratch("privacy");
        Token::load_or_create(&dir).expect("created");
        match privacy_of(&Token::path_in(&dir)).expect("the file exists") {
            Privacy::Private(_) => {}
            other => panic!("a freshly written token should be private, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspecting_a_missing_secret_is_an_error_not_a_verdict() {
        // "Not created yet" is neither protected nor exposed, and a caller that
        // cannot tell those apart reports a pass on a file that does not exist.
        let dir = scratch("absent");
        let error = privacy_of(&dir.join("nothing-here")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_secret_is_reported_as_exposed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("loose");
        let path = dir.join("loose.token");
        std::fs::write(&path, "secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match privacy_of(&path).expect("the file exists") {
            Privacy::Exposed(detail) => assert!(detail.contains("0644"), "{detail}"),
            other => panic!("0644 is not private, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_descriptor_this_crate_writes_is_judged_private() {
        // Exactly the string `write_private` hands to CreateFileW, and exactly
        // the string Windows hands back with the auto-inherited flag added.
        for sddl in ["D:P(A;;FA;;;SY)(A;;FA;;;BA)", "D:PAI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"] {
            match judge_dacl_sddl(sddl) {
                Privacy::Private(detail) => {
                    assert!(detail.contains("SY"), "{detail}");
                    assert!(detail.contains("inheritance blocked"), "{detail}");
                }
                other => panic!("{sddl} should be private, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_dacl_naming_anyone_else_is_exposure_and_says_who() {
        // The realistic production failure: the file inherits the profile
        // directory's ACE for the interactive user.
        let inherited = "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1-2-3-1001)";
        match judge_dacl_sddl(inherited) {
            Privacy::Exposed(detail) => {
                assert!(detail.contains("S-1-5-21-1-2-3-1001"), "{detail}");
            }
            other => panic!("an inherited user ACE is exposure, got {other:?}"),
        }

        for sddl in [
            "D:P(A;;FA;;;WD)",             // Everyone
            "D:P(A;;FA;;;BU)",             // BUILTIN\Users
            "D:P(A;;FA;;;SY)(A;;FR;;;AU)", // Authenticated Users, read-only, still exposure
        ] {
            assert!(
                matches!(judge_dacl_sddl(sddl), Privacy::Exposed(_)),
                "{sddl} should be exposure"
            );
        }
    }

    #[test]
    fn a_null_dacl_is_the_worst_case_not_the_empty_one() {
        // "No access control" reads like "nothing granted" and means the
        // opposite: every account has full access.
        match judge_dacl_sddl("D:NO_ACCESS_CONTROL") {
            Privacy::Exposed(detail) => assert!(detail.contains("NULL DACL"), "{detail}"),
            other => panic!("a NULL DACL is exposure, got {other:?}"),
        }
    }

    #[test]
    fn deny_entries_do_not_count_as_exposure() {
        // A deny ACE only ever subtracts access, so a descriptor that denies a
        // stranger and allows only SYSTEM is still owner-only.
        let sddl = "D:P(D;;FA;;;WD)(A;;FA;;;SY)";
        assert!(matches!(judge_dacl_sddl(sddl), Privacy::Private(_)), "{sddl}");
    }

    #[test]
    fn an_unprotected_dacl_is_private_but_says_it_can_drift() {
        match judge_dacl_sddl("D:(A;;FA;;;SY)(A;;FA;;;BA)") {
            Privacy::Private(detail) => assert!(detail.contains("not protected"), "{detail}"),
            other => panic!("expected a qualified pass, got {other:?}"),
        }
    }

    #[test]
    fn an_owner_and_group_prefixed_descriptor_is_still_read() {
        // Only the DACL is requested, but a descriptor carrying every field
        // must not be mistaken for one carrying none.
        let sddl = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:AI(AU;SAFA;FA;;;WD)";
        assert!(matches!(judge_dacl_sddl(sddl), Privacy::Private(_)), "{sddl}");
    }

    #[test]
    fn a_descriptor_that_cannot_be_parsed_is_never_a_pass() {
        // The rule the whole report depends on: not understood is not fine.
        for sddl in ["", "O:BAG:SY", "garbage"] {
            assert!(
                matches!(judge_dacl_sddl(sddl), Privacy::Unanswerable(_)),
                "{sddl:?} should be unanswerable"
            );
        }
        assert!(
            matches!(judge_dacl_sddl("D:P(A;;FA;;SY)"), Privacy::Unanswerable(_)),
            "a five-field ACE is not understood"
        );
    }

    #[test]
    fn an_empty_dacl_grants_nobody() {
        match judge_dacl_sddl("D:P") {
            Privacy::Private(detail) => assert!(detail.contains("owner"), "{detail}"),
            other => panic!("an empty DACL grants nobody, got {other:?}"),
        }
    }
}
