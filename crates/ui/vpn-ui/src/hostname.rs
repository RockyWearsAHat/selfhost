//! This machine's own name, read straight from the OS.
//!
//! A Peer can be any device a Person enrols — a Mac, a Windows box, a Linux
//! server — so this cannot be the Unix-only lookup it used to be (`nix`'s
//! `gethostname`, a crate this workspace does not otherwise depend on and
//! which does not build for Windows at all). The workspace's own rule is to
//! own the FFI at this level rather than take a dependency for it — see
//! `crates/services/screen/src/windows/sys.rs` for the same call spelled out
//! by hand — so each platform gets its own few lines here instead of a crate.

// Two raw OS calls, each filling a caller-owned buffer it cannot overrun by
// construction (its length is passed in and re-checked on return) — the same
// shape `macos_native.rs` allows unsafe for.
#![allow(unsafe_code)]

/// The OS-reported name of this machine, or `None` if it could not be read.
///
/// Callers decide what an absent or empty answer is worth; this function only
/// ever reports what the OS actually said.
pub fn hostname() -> Option<String> {
    imp::hostname()
}

#[cfg(unix)]
mod imp {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};

    // Declared, not linked: `gethostname(3)` lives in libc/libSystem, which
    // every Rust binary on Unix already links, exactly as
    // `crates/foundation/presence`'s `pthread_main_np` needs no `#[link]` of
    // its own.
    unsafe extern "C" {
        fn gethostname(name: *mut c_char, len: usize) -> c_int;
    }

    pub fn hostname() -> Option<String> {
        // POSIX caps a hostname at 255 bytes; this is generous headroom, not a
        // tight fit.
        let mut buf = [0u8; 256];
        let ok = unsafe { gethostname(buf.as_mut_ptr().cast::<c_char>(), buf.len()) } == 0;
        if !ok {
            return None;
        }
        // SAFETY: a successful call NUL-terminates within the buffer it was
        // given.
        let name = unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) };
        let name = name.to_str().ok()?.to_owned();
        (!name.is_empty()).then_some(name)
    }
}

#[cfg(windows)]
mod imp {
    use std::os::raw::c_int;

    // `GetComputerNameW` — the plain NetBIOS-style machine name, no domain
    // suffix — is a `kernel32` export, not something this workspace's
    // dependency policy would let a `windows`/`windows-sys` crate stand in
    // for.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetComputerNameW(buffer: *mut u16, size: *mut u32) -> c_int;
    }

    pub fn hostname() -> Option<String> {
        // `MAX_COMPUTERNAME_LENGTH` is 15 on every Windows version there has
        // ever been; this is headroom over that, plus the NUL the call wants
        // room for.
        let mut buf = [0u16; 64];
        let mut len = buf.len() as u32;
        let ok = unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) } != 0;
        if !ok {
            return None;
        }
        let name = String::from_utf16_lossy(&buf[..len as usize]);
        (!name.is_empty()).then_some(name)
    }
}
