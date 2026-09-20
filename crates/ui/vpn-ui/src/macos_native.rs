//! Tiny, direct AppKit calls that replace this app's old `osascript` shell-outs.
//!
//! Both `Panel::hide_window`/`Panel::show_window` and the quit confirmation used
//! to shell out to `osascript`: the window pair told "System Events" to toggle
//! `visible` on this process (Automation permission — never granted on the
//! installed app, so it silently failed or hung on a permission prompt), and
//! quitting ran `display dialog` through the same binary (no Automation needed,
//! but tangled up with the same "does osascript even work here" failure mode,
//! and `confirm_quit`'s `match ... Ok(status) if status.success()` reads any
//! failure — including a blocked Automation prompt — as "Cancel", which is
//! exactly the reported "Quit does nothing").
//!
//! This module talks to AppKit directly instead: `NSApplication.windows`,
//! `-orderOut:`/`-makeKeyAndOrderFront:` for show/hide, and a real `NSAlert`
//! for the quit confirmation. None of it needs any permission at all — it is
//! the same process calling its own process's own UI framework, not one app
//! asking the system to let it drive another.
//!
//! # Safety
//!
//! Every `unsafe` block here does exactly one of two things: sends an
//! Objective-C message with the signature Apple documents (`objc_msgSend`,
//! transmuted to the right argument/return shape), or calls a C entry point
//! (`objc_getClass`, `sel_registerName`) with a valid, NUL-terminated name.
//! `rui`'s own macOS backend (`shell/platform/macos.rs`) uses the identical
//! idiom for the same reason: there is no safe wrapper for the Objective-C
//! runtime to call into instead.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_void, CStr};

type Object = *mut c_void;
type Sel = *const c_void;

unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Object;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}

fn class(name: &CStr) -> Object {
    unsafe { objc_getClass(name.as_ptr()) }
}

fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

unsafe fn send<R>(receiver: Object, selector: Sel) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector) }
}

unsafe fn send1<R, A>(receiver: Object, selector: Sel, a: A) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel, A) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector, a) }
}

fn ns_string(text: &CStr) -> Object {
    unsafe { send1(class(c"NSString"), sel(c"stringWithUTF8String:"), text.as_ptr()) }
}

/// The Rust string behind an `NSString`, or empty when there is none.
fn from_ns_string(string: Object) -> String {
    if string.is_null() {
        return String::new();
    }
    let utf8: *const c_char = unsafe { send(string, sel(c"UTF8String")) };
    if utf8.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(utf8) }.to_string_lossy().into_owned()
}

/// `NSApplication.sharedApplication`.
fn shared_application() -> Object {
    unsafe { send(class(c"NSApplication"), sel(c"sharedApplication")) }
}

/// Every top-level `NSWindow` this process currently has open.
fn app_windows() -> Vec<Object> {
    let app = shared_application();
    let windows: Object = unsafe { send(app, sel(c"windows")) };
    let count: usize = unsafe { send(windows, sel(c"count")) };
    (0..count)
        .map(|index| unsafe { send1(windows, sel(c"objectAtIndex:"), index) })
        .collect()
}

/// Shows or hides the app's main window (the one titled `title`) by calling
/// AppKit directly — no Automation permission, no shell-out, no dependence on
/// "System Events" ever having been granted control of this process.
///
/// Matched by title rather than by keeping a window handle around: `rui`'s
/// `App` owns the real `NSWindow` and does not hand a reference out, so this
/// finds it the same way the platform's own reopen handler finds every window
/// belonging to the app — via `NSApplication.windows` — and narrows to the one
/// this app actually opened (as opposed to, say, the mini dropdown panel,
/// which carries no title at all).
pub fn set_main_window_visible(title: &str, visible: bool) {
    let Ok(wanted) = std::ffi::CString::new(title) else { return };
    for window in app_windows() {
        if window.is_null() {
            continue;
        }
        let window_title: Object = unsafe { send(window, sel(c"title")) };
        if from_ns_string(window_title) != wanted.to_string_lossy() {
            continue;
        }
        if visible {
            unsafe {
                let _: () =
                    send1(window, sel(c"makeKeyAndOrderFront:"), std::ptr::null_mut::<c_void>());
                let _: () = send1(shared_application(), sel(c"activateIgnoringOtherApps:"), true);
            }
        } else {
            unsafe {
                let _: () = send1(window, sel(c"orderOut:"), std::ptr::null_mut::<c_void>());
            }
        }
        return;
    }
}

/// `NSAlertSecondButtonReturn`: the second button added was clicked.
const ALERT_SECOND_BUTTON: isize = 1001;

/// Runs a native, modal "Quit SelfHost VPN?" alert and reports whether the
/// destructive button ("Quit") was chosen.
///
/// Replaces the old `osascript -e 'display dialog ...'` call. An `NSAlert` run
/// with `-runModal` needs nothing from the system beyond drawing its own
/// window — unlike shelling out to a second process and hoping it can reach
/// this one, which is what made a blocked or failing `osascript` read as a
/// silent "Cancel" and made Quit look broken.
pub fn confirm_quit_native() -> bool {
    let alert: Object = unsafe { send(class(c"NSAlert"), sel(c"alloc")) };
    let alert: Object = unsafe { send(alert, sel(c"init")) };
    if alert.is_null() {
        // No alert could be built at all — refuse the destructive path rather
        // than silently tearing the tunnel down unconfirmed.
        return false;
    }
    unsafe {
        let _: () = send1(
            alert,
            sel(c"setMessageText:"),
            ns_string(c"Quit SelfHost VPN?"),
        );
        let _: () = send1(
            alert,
            sel(c"setInformativeText:"),
            ns_string(c"Quitting will disconnect the tunnel and end your VPN session."),
        );
        // Buttons are added in visual, right-to-left order: the first one
        // added becomes the rightmost, default (Return-key) button. "Cancel"
        // is added first — matching the old dialog's own default/cancel
        // button — so a stray Return or Escape never confirms the quit;
        // "Quit" is the second button, reported as `NSAlertSecondButtonReturn`.
        let _: Object = send1(alert, sel(c"addButtonWithTitle:"), ns_string(c"Cancel"));
        let _: Object = send1(alert, sel(c"addButtonWithTitle:"), ns_string(c"Quit"));
        let response: isize = send(alert, sel(c"runModal"));
        response == ALERT_SECOND_BUTTON
    }
}

/// Runs a native, modal "Remove this device?" alert and reports whether the
/// destructive button ("Remove") was chosen.
///
/// Same shape as [`confirm_quit_native`] and for the same reason: removing
/// the device this install itself is signs it out immediately, so a stray
/// Return or Escape must never be read as "yes".
pub fn confirm_remove_device_native() -> bool {
    let alert: Object = unsafe { send(class(c"NSAlert"), sel(c"alloc")) };
    let alert: Object = unsafe { send(alert, sel(c"init")) };
    if alert.is_null() {
        // No alert could be built at all — refuse the destructive path rather
        // than silently signing this device out unconfirmed.
        return false;
    }
    unsafe {
        let _: () = send1(alert, sel(c"setMessageText:"), ns_string(c"Remove this device?"));
        let _: () = send1(
            alert,
            sel(c"setInformativeText:"),
            ns_string(c"This will sign you out and disconnect the tunnel on this device."),
        );
        // Same right-to-left button order as `confirm_quit_native`: "Cancel"
        // added first (rightmost, the Return-key default), "Remove" second,
        // reported as `NSAlertSecondButtonReturn`.
        let _: Object = send1(alert, sel(c"addButtonWithTitle:"), ns_string(c"Cancel"));
        let _: Object = send1(alert, sel(c"addButtonWithTitle:"), ns_string(c"Remove"));
        let response: isize = send(alert, sel(c"runModal"));
        response == ALERT_SECOND_BUTTON
    }
}

