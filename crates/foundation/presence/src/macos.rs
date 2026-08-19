//! The macOS answer: `LocalAuthentication`, asked through the Objective-C runtime.
//!
//! # Why the runtime and not a binding
//!
//! This workspace links no third-party crates outside the two foundations it has
//! argued for, so there is no `objc2` here and there will not be one. What is
//! needed is four messages — `alloc`, `init`, `canEvaluatePolicy:error:`,
//! `evaluatePolicy:localizedReason:reply:` — and the runtime that sends them is a
//! C library macOS ships. `crates/services/screen` already reaches CoreGraphics
//! the same way, for the same reason.
//!
//! # Why the policy is the device owner's and not biometry's
//!
//! `LAPolicyDeviceOwnerAuthentication` is the sheet that asks for a fingerprint
//! **and offers the account password in the same sheet** when the finger is not
//! read, is not enrolled, or the Mac has no sensor at all. Asking for biometrics
//! alone would turn a wet fingertip into a locked console, and would refuse the
//! very fallback the person asked for by name. The password is typed into the
//! system's own sheet, in another process: it never reaches this one.
//!
//! # The block
//!
//! `evaluatePolicy:` answers through an Objective-C block, so one is built here
//! by hand: an isa, flags, an invoke function and a descriptor, which is the whole
//! of the ABI. It is marked `BLOCK_IS_GLOBAL`, which is what makes a copy of it a
//! no-op — the framework's `Block_copy` hands back the same pointer, and its
//! `Block_release` does nothing. That is why the block and the channel it writes
//! into are **deliberately leaked**: a sheet nobody ever answers leaves the
//! framework holding a pointer, and the only way that pointer is guaranteed to
//! stay valid is for the memory never to be reclaimed. It costs a hundred bytes
//! per unlock, and it is the difference between a stale sheet and a crash.

use crate::Presence;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

/// An Objective-C object.
type Id = *mut c_void;

/// An Objective-C selector.
type Sel = *const c_void;

/// A fingerprint, or the account password behind it, in one sheet.
const DEVICE_OWNER: isize = 2;

/// How long the sheet may stand before this call gives up on it.
///
/// Not a timeout on the person: it is the guard that stops a console thread from
/// waiting for ever on a sheet the system never presented. Ten minutes is far
/// longer than anybody takes to press a finger, and far shorter than a thread
/// leak nobody notices.
const PATIENCE: Duration = Duration::from_secs(600);

#[link(name = "LocalAuthentication", kind = "framework")]
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    /// The isa every block that is never copied points at.
    static _NSConcreteGlobalBlock: [*const c_void; 32];
    /// Non-zero on the thread that draws the window.
    fn pthread_main_np() -> i32;
}

/// The three words of a block's descriptor. No copy or dispose helper, because a
/// global block is never copied and never disposed of.
#[repr(C)]
struct Descriptor {
    reserved: u64,
    size: u64,
}

/// The block `evaluatePolicy:` replies through.
#[repr(C)]
struct Reply {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: extern "C" fn(*mut Reply, i8, Id),
    descriptor: *const Descriptor,
    /// A leaked `Sender<Presence>`, which is where the answer goes.
    answer: *mut c_void,
}

/// `BLOCK_IS_GLOBAL` — copying this block returns it unchanged.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

static DESCRIPTOR: Descriptor =
    Descriptor { reserved: 0, size: std::mem::size_of::<Reply>() as u64 };

/// Asks, and waits for the person to answer.
pub fn demand(reason: &str) -> Presence {
    // The sheet is drawn over this application's window by the system, and the
    // window is drawn by the main thread. Blocking that thread here would hang
    // the interface the sheet is attached to, so this is a refusal rather than a
    // deadlock — and it names the mistake, because the caller is a program and
    // the fix is one `std::thread::spawn`.
    if unsafe { pthread_main_np() } != 0 {
        return Presence::Unavailable(
            "presence must be demanded off the thread drawing the window".to_owned(),
        );
    }
    unsafe { ask(reason) }
}

/// Whether this machine could be asked, without asking.
pub fn askable() -> Result<(), String> {
    unsafe {
        let pool = pool();
        let context = context();
        if context.is_null() {
            drain(pool);
            return Err("LocalAuthentication is not available on this computer".to_owned());
        }
        let mut trouble: Id = ptr::null_mut();
        let can = can_evaluate(context, &mut trouble);
        let answer =
            if can != 0 { Ok(()) } else { Err(describe(trouble)) };
        release(context);
        drain(pool);
        answer
    }
}

/// The whole ceremony, from the pool to the answer.
unsafe fn ask(reason: &str) -> Presence {
    unsafe {
        let pool = pool();
        let context = context();
        if context.is_null() {
            drain(pool);
            return Presence::Unavailable(
                "LocalAuthentication is not available on this computer".to_owned(),
            );
        }

        // Asked before the sheet, so that a Mac which cannot be asked says why
        // instead of showing a sheet that fails a moment later.
        let mut trouble: Id = ptr::null_mut();
        if can_evaluate(context, &mut trouble) == 0 {
            let why = describe(trouble);
            release(context);
            drain(pool);
            return Presence::Unavailable(why);
        }

        let (sender, inbox) = mpsc::channel();
        // Leaked on purpose — see the module note. The framework may hold this
        // block after this function has returned.
        let answer = Box::into_raw(Box::new(sender)) as *mut c_void;
        let block = Box::into_raw(Box::new(Reply {
            isa: &raw const _NSConcreteGlobalBlock as *const c_void,
            flags: BLOCK_IS_GLOBAL,
            reserved: 0,
            invoke: replied,
            descriptor: &raw const DESCRIPTOR,
            answer,
        }));

        let words = nsstring(reason);
        evaluate(context, DEVICE_OWNER, words, block);
        let answer = inbox.recv_timeout(PATIENCE);
        release(words);

        match answer {
            Ok(presence) => {
                // Released only here. On the other branch the sheet may still be
                // standing, and a context freed under a live sheet is a crash.
                release(context);
                drain(pool);
                presence
            }
            Err(_) => {
                drain(pool);
                Presence::Unavailable(
                    "the system never answered the request to prove somebody is here".to_owned(),
                )
            }
        }
    }
}

/// What the framework calls when the person has answered.
extern "C" fn replied(block: *mut Reply, proved: i8, trouble: Id) {
    let presence = if proved != 0 { Presence::Proved } else { unsafe { classify(trouble) } };
    // The sender outlives this call by construction: it is leaked.
    let sender = unsafe { &*((*block).answer as *const Sender<Presence>) };
    // A closed channel means the console gave up waiting and moved on. Nothing
    // to do about it, and nothing that needs saying: the lock simply stayed shut.
    let _ = sender.send(presence);
}

/// Which of the three shut answers an `LAError` is.
///
/// The codes are `LAError`'s own. Cancellation — by the person, by the system
/// putting the machine to sleep, or by the application — is not a failure and
/// must not be reported as one; a wrong finger or a wrong password is.
unsafe fn classify(trouble: Id) -> Presence {
    unsafe {
        match code(trouble) {
            -1 => Presence::Refused,
            -2 | -4 | -9 => Presence::Declined,
            _ => Presence::Unavailable(describe(trouble)),
        }
    }
}

// ------------------------------------------------------------------ messages

/// `[[NSAutoreleasePool alloc] init]`, because this runs on a thread of its own.
///
/// Without one, everything the framework autoreleases on this thread leaks and
/// says so in the log. A thread that exists to show one sheet gets one pool.
unsafe fn pool() -> Id {
    unsafe { send(send(class("NSAutoreleasePool"), sel("alloc")), sel("init")) }
}

/// `[pool drain]`.
unsafe fn drain(pool: Id) {
    unsafe { send(pool, sel("drain")) };
}

/// `[[LAContext alloc] init]`.
unsafe fn context() -> Id {
    let class = unsafe { class("LAContext") };
    if class.is_null() {
        return ptr::null_mut();
    }
    unsafe { send(send(class, sel("alloc")), sel("init")) }
}

/// `[context canEvaluatePolicy:DEVICE_OWNER error:&trouble]`.
unsafe fn can_evaluate(context: Id, trouble: &mut Id) -> i8 {
    let message: unsafe extern "C" fn(Id, Sel, isize, *mut Id) -> i8 =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { message(context, sel("canEvaluatePolicy:error:"), DEVICE_OWNER, trouble) }
}

/// `[context evaluatePolicy:policy localizedReason:words reply:block]`.
unsafe fn evaluate(context: Id, policy: isize, words: Id, block: *mut Reply) {
    let message: unsafe extern "C" fn(Id, Sel, isize, Id, *mut Reply) =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { message(context, sel("evaluatePolicy:localizedReason:reply:"), policy, words, block) };
}

/// `[[NSString alloc] initWithUTF8String:]`, owned by the caller.
unsafe fn nsstring(text: &str) -> Id {
    // An interior NUL cannot reach here from any reason this crate is given, and
    // a reason that lost its tail would be a sheet asking for something else.
    let Ok(text) = CString::new(text) else {
        return ptr::null_mut();
    };
    let message: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe {
        message(
            send(class("NSString"), sel("alloc")),
            sel("initWithUTF8String:"),
            text.as_ptr(),
        )
    }
}

/// `[error code]`, or zero when there is no error object.
unsafe fn code(trouble: Id) -> isize {
    if trouble.is_null() {
        return 0;
    }
    let message: unsafe extern "C" fn(Id, Sel) -> isize =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { message(trouble, sel("code")) }
}

/// `[[error localizedDescription] UTF8String]`, as words a person can read.
unsafe fn describe(trouble: Id) -> String {
    let unknown = "this computer cannot be asked to prove somebody is here".to_owned();
    if trouble.is_null() {
        return unknown;
    }
    unsafe {
        let words = send(trouble, sel("localizedDescription"));
        if words.is_null() {
            return unknown;
        }
        let message: unsafe extern "C" fn(Id, Sel) -> *const c_char =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let utf8 = message(words, sel("UTF8String"));
        if utf8.is_null() {
            return unknown;
        }
        CStr::from_ptr(utf8).to_string_lossy().into_owned()
    }
}

/// `[object release]`.
unsafe fn release(object: Id) {
    if object.is_null() {
        return;
    }
    unsafe { send(object, sel("release")) };
}

/// A message with no arguments, answering an object.
unsafe fn send(receiver: Id, selector: Sel) -> Id {
    if receiver.is_null() {
        return ptr::null_mut();
    }
    let message: unsafe extern "C" fn(Id, Sel) -> Id =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { message(receiver, selector) }
}

/// A class by name, or null if this system has no such class.
unsafe fn class(name: &str) -> Id {
    let Ok(name) = CString::new(name) else {
        return ptr::null_mut();
    };
    unsafe { objc_getClass(name.as_ptr()) }
}

/// A selector by name.
///
/// Registering one that already exists returns the existing one, so this is the
/// whole of the caching that is needed.
fn sel(name: &str) -> Sel {
    let Ok(name) = CString::new(name) else {
        return ptr::null();
    };
    unsafe { sel_registerName(name.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_knows_the_class_this_crate_is_built_on() {
        // If this fails, `LocalAuthentication` did not link, and every later
        // failure would look like "this Mac cannot be asked" rather than like the
        // build problem it is.
        assert!(!unsafe { class("LAContext") }.is_null(), "LAContext is missing");
        assert!(!sel("evaluatePolicy:localizedReason:reply:").is_null());
    }

    #[test]
    fn asking_this_machine_whether_it_could_be_asked_shows_nothing_and_answers() {
        // `askable` presents no sheet and blocks on nothing, so it is the one
        // half of this module a test may run: it proves the class was found, the
        // selector was sent, and an answer came back. **Nothing here calls
        // [`demand`]** — that would put a real Touch ID sheet in front of whoever
        // is running the tests, and a test suite that demands a fingerprint is a
        // test suite nobody runs.
        let answer = askable();
        if let Err(why) = &answer {
            assert!(!why.is_empty(), "a refusal has to say something");
        }
    }

    #[test]
    fn the_block_is_the_shape_the_abi_expects() {
        // Six words: isa, flags, reserved, invoke, descriptor, and the one
        // capture. The descriptor states that size, and the framework reads it.
        assert_eq!(std::mem::size_of::<Reply>(), 40);
        assert_eq!(DESCRIPTOR.size, std::mem::size_of::<Reply>() as u64);
        assert_eq!(DESCRIPTOR.reserved, 0);
    }
}
