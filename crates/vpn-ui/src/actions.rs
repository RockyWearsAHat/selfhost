//! The slow controls, run off the window thread.
//!
//! Rotating a key takes seconds and opening the console prompts for a password;
//! both would freeze the window if run in a handler. Each spawns a thread, marks
//! the shared [`Activity`] busy while it works, and leaves a result the next
//! frame reads.

use crate::app::{Activity, CONSOLE_URL};
use crate::keys;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// The host the console is reached at, mapped to loopback for the tunnel.
const CONSOLE_HOST: &str = "admin.rockywearsahat.com";

/// Rotates the identity key, then refreshes the shown fingerprints.
pub fn rotate(activity: Arc<Mutex<Activity>>) {
    if !set_busy(&activity, "Rotating keys…") {
        return;
    }
    std::thread::spawn(move || {
        let outcome = keys::rotate();
        let (client, server) = keys::identities();
        let last = keys::last_rotation();
        finish(&activity, outcome.map(|()| "Key rotated and verified.".to_string()), move |a| {
            a.client = client;
            a.server = server;
            a.last_rotation = last;
        });
    });
}

/// Ensures the console host resolves to the tunnel, then opens it in the browser.
pub fn open_console(activity: Arc<Mutex<Activity>>) {
    if !set_busy(&activity, "Opening console…") {
        return;
    }
    std::thread::spawn(move || {
        let outcome = ensure_hosts().and_then(|()| open_url());
        finish(&activity, outcome.map(|()| "Opened the admin console.".to_string()), |_| {});
    });
}

/// Adds `127.0.0.1 admin.rockywearsahat.com` to `/etc/hosts` if it is not there.
///
/// The write needs privilege; it is done through `osascript`, which prompts once
/// (Touch ID or a password). An entry already present is left alone.
fn ensure_hosts() -> Result<(), String> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let present = hosts.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line.starts_with("127.0.0.1")
            && line.split_whitespace().skip(1).any(|host| host == CONSOLE_HOST)
    });
    if present {
        return Ok(());
    }
    let script = format!(
        "do shell script \"printf '%s\\\\n' '127.0.0.1 {CONSOLE_HOST}' >> /etc/hosts\" \
         with administrator privileges"
    );
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|error| format!("could not update hosts: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.lines().last().unwrap_or("could not update hosts").to_string())
    }
}

/// Opens the console URL in the default browser.
fn open_url() -> Result<(), String> {
    let status = Command::new("open")
        .arg(CONSOLE_URL)
        .status()
        .map_err(|error| format!("could not open the browser: {error}"))?;
    if status.success() { Ok(()) } else { Err("the browser did not open".into()) }
}

/// Marks the activity busy, unless it already is (one slow action at a time).
///
/// Returns whether the caller may proceed.
fn set_busy(activity: &Arc<Mutex<Activity>>, what: &str) -> bool {
    let mut guard = lock(activity);
    if guard.busy.is_some() {
        return false;
    }
    guard.busy = Some(what.to_string());
    guard.notice = None;
    true
}

/// Clears busy, records the result, and applies any state the action gathered.
fn finish(
    activity: &Arc<Mutex<Activity>>,
    result: Result<String, String>,
    apply: impl FnOnce(&mut Activity),
) {
    let mut guard = lock(activity);
    guard.busy = None;
    apply(&mut guard);
    guard.notice = Some(match result {
        Ok(message) => (true, message),
        Err(message) => (false, message),
    });
}

/// Reads-through a poisoned lock rather than panicking a worker thread.
fn lock(activity: &Arc<Mutex<Activity>>) -> std::sync::MutexGuard<'_, Activity> {
    match activity.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
