//! The slow controls, run off the window thread.
//!
//! Rotating a key takes seconds and opening the console prompts for a password;
//! both would freeze the window if run in a handler. Each spawns a thread, marks
//! the shared [`Activity`] busy while it works, and leaves a result the next
//! frame reads.

use crate::app::{Activity, CONSOLE_HOST, CONSOLE_URL};
use crate::dns::RESPONDER_PORT;
use crate::keys;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// The launchd label of the console gate, the loopback 443 → 8443 bridge.
const GATE_LABEL: &str = "com.selfhost.console-gate";

/// Where the gate binary is installed: root-owned, off every user-writable path,
/// so the LaunchDaemon never executes from the repo or the app bundle.
const GATE_BIN: &str = "/Library/PrivilegedHelperTools/com.selfhost.console-gate";

/// The LaunchDaemon plist that keeps the gate running from boot.
const GATE_PLIST: &str = "/Library/LaunchDaemons/com.selfhost.console-gate.plist";

/// Where the gate's stderr lands — a bind failure names its errno here.
const GATE_LOG: &str = "/var/log/selfhost-console-gate.log";

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

/// Ensures the console route is installed, then opens the console in the browser.
pub fn open_console(activity: Arc<Mutex<Activity>>) {
    if !set_busy(&activity, "Opening console…") {
        return;
    }
    std::thread::spawn(move || {
        let outcome = ensure_console_route().and_then(|()| open_url());
        finish(&activity, outcome.map(|()| "Opened the admin console.".to_string()), |_| {});
    });
}

/// Ensures everything the portless console URL needs, in one privileged prompt.
///
/// Three pieces make `https://admin.rockywearsahat.com/` land on the tunnel: the
/// scoped resolver file (pointing the host at the app's split-DNS responder),
/// a clean `/etc/hosts` (the legacy hosts-line mechanism removed), and the
/// console gate — a root LaunchDaemon holding `127.0.0.1:443` and splicing it
/// to the tunnel's local end. When all three are already exact, nothing runs
/// and nothing prompts; otherwise one `osascript` administrator prompt installs
/// them together and verifies the gate actually listens before reporting done.
fn ensure_console_route() -> Result<(), String> {
    let gate = bundled_gate()?;
    if console_route_current(&gate) {
        return Ok(());
    }
    install_console_route(&gate)
}

/// Whether the installed route matches this build exactly.
///
/// Exactness is byte equality — resolver file, plist, and gate binary — plus a
/// hosts file free of the legacy console line, so an upgrade or a hand-edit
/// re-triggers the one-time install. Files only: the daemon itself is
/// launchd-kept (`KeepAlive`), and the installer is the step that proves the
/// listener; a user who booted the gate out on purpose is not fought here.
fn console_route_current(gate: &Path) -> bool {
    let resolver_ok = std::fs::read_to_string(resolver_path())
        .map(|current| current == resolver_body())
        .unwrap_or(false);
    let plist_ok =
        std::fs::read_to_string(GATE_PLIST).map(|current| current == gate_plist()).unwrap_or(false);
    let gate_ok = match (std::fs::read(gate), std::fs::read(GATE_BIN)) {
        (Ok(bundled), Ok(installed)) => bundled == installed,
        _ => false,
    };
    resolver_ok && plist_ok && gate_ok && !hosts_has_legacy_line()
}

/// Runs the one-time privileged install for the whole console route.
///
/// The work is staged as a shell script in the temp directory and run through
/// `osascript` "with administrator privileges" — one prompt (Touch ID or a
/// password), one script: resolver file, hosts cleanup, gate binary + plist,
/// `launchctl bootstrap`, then a verification loop that requires the gate to be
/// the process listening on `127.0.0.1:443` (the proxy's wildcard `*:443` must
/// not be the one answering). On failure the script's last stderr line — which
/// names the gate's log for a bind failure — is surfaced verbatim in the notice.
fn install_console_route(gate: &Path) -> Result<(), String> {
    let staged = std::env::temp_dir().join("selfhost-console-route-install.sh");
    std::fs::write(&staged, install_script(gate))
        .map_err(|error| format!("could not stage the install script: {error}"))?;
    let shell = format!("/bin/sh {}", sh_quote(&staged));
    let output = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "do shell script \"{}\" with administrator privileges",
            shell.replace('\\', "\\\\").replace('"', "\\\"")
        ))
        .output();
    let _ = std::fs::remove_file(&staged);
    let output = output.map_err(|error| format!("could not run the install: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.lines().last().unwrap_or("the console-route install failed").to_string())
    }
}

/// The scoped resolver file for the console host.
fn resolver_path() -> String {
    format!("/etc/resolver/{CONSOLE_HOST}")
}

/// What the resolver file must say: the app's responder, on its loopback port.
fn resolver_body() -> String {
    format!("nameserver 127.0.0.1\nport {RESPONDER_PORT}\n")
}

/// The gate's LaunchDaemon definition.
///
/// `KeepAlive` + `RunAtLoad` keep the route alive from boot; `ThrottleInterval`
/// spaces restarts if the bind fails repeatedly. Deliberately **no**
/// `EnvironmentVariables` dict — a plist must never carry a secret
/// (docs/SECURITY.md, SEC-04), and the gate needs no environment at all.
fn gate_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{GATE_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{GATE_BIN}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardErrorPath</key><string>{GATE_LOG}</string>
</dict>
</plist>
"#
    )
}

/// The privileged install script, generated for this build's gate binary.
///
/// `set -e`: any failing step aborts the install and surfaces as the prompt's
/// error. The verification loop is the admission test for the one assumption
/// the design leans on — that a root-owned specific `127.0.0.1:443` bind
/// coexists with the proxy's wildcard `*:443` and wins loopback delivery. It
/// polls `lsof` for up to ~3s until the *gate* is the loopback listener; if the
/// bind loses, the install fails loudly and touches nothing else — never the
/// running proxy. The cache flush comes last so the resolver switch and the
/// gate go live together.
fn install_script(gate: &Path) -> String {
    let resolver_path = resolver_path();
    let resolver_printf = resolver_body().replace('\n', "\\n");
    let host_pattern = CONSOLE_HOST.replace('.', "\\.");
    let plist = gate_plist();
    let gate = sh_quote(gate);
    format!(
        r#"#!/bin/sh
# One-time privileged console-route install, staged and run by SelfHost VPN.
set -e
mkdir -p /etc/resolver /Library/PrivilegedHelperTools
printf '{resolver_printf}' > '{resolver_path}'
chown root:wheel '{resolver_path}'
chmod 644 '{resolver_path}'
[ ! -f /etc/hosts ] || /usr/bin/sed -i '' -E -e '/^127\.0\.0\.1[[:space:]]+{host_pattern}[[:space:]]*(#.*)?$/d' -e '/^127\.0\.0\.1[[:space:]]/s/[[:space:]]+{host_pattern}([[:space:]]|$)/\1/g' /etc/hosts
cp {gate} '{GATE_BIN}'
chown root:wheel '{GATE_BIN}'
chmod 755 '{GATE_BIN}'
cat > '{GATE_PLIST}' <<'PLIST'
{plist}PLIST
chown root:wheel '{GATE_PLIST}'
chmod 644 '{GATE_PLIST}'
launchctl bootout system/{GATE_LABEL} 2>/dev/null || true
launchctl bootstrap system '{GATE_PLIST}'
tries=0
until /usr/sbin/lsof +c 0 -nP -iTCP@127.0.0.1:443 -sTCP:LISTEN 2>/dev/null | grep -q com.selfhost.con; do
  tries=$((tries+1))
  if [ "$tries" -ge 30 ]; then
    echo 'console gate failed to bind 127.0.0.1:443 - see {GATE_LOG}' >&2
    exit 1
  fi
  sleep 0.1
done
dscacheutil -flushcache
killall -HUP mDNSResponder
"#
    )
}

/// Whether `/etc/hosts` still carries the legacy console mapping.
fn hosts_has_legacy_line() -> bool {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    hosts.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line.starts_with("127.0.0.1")
            && line.split_whitespace().skip(1).any(|host| host == CONSOLE_HOST)
    })
}

/// The gate binary shipped beside the app's own, ready to be installed.
///
/// `build-app.sh` copies `selfhost-console-gate` into the bundle's `MacOS/`
/// directory (a `cargo run` finds it in `target/release` the same way); a build
/// without it cannot install the route and says how to get one.
fn bundled_gate() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("could not locate the app binary: {error}"))?;
    let dir = exe.parent().ok_or("the app binary has no parent directory")?;
    let gate = dir.join("selfhost-console-gate");
    if gate.is_file() {
        Ok(gate)
    } else {
        Err("the console gate is missing from this build — rebuild with crates/vpn-ui/build-app.sh"
            .into())
    }
}

/// The path as a single-quoted shell word, safe against spaces and quotes.
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_wraps_and_escapes() {
        assert_eq!(sh_quote(Path::new("/plain/path")), "'/plain/path'");
        assert_eq!(sh_quote(Path::new("/with space/it's")), r"'/with space/it'\''s'");
    }

    #[test]
    fn plist_carries_no_environment_and_the_right_program() {
        let plist = gate_plist();
        assert!(plist.contains(GATE_LABEL));
        assert!(plist.contains(GATE_BIN));
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        // A LaunchDaemon plist must never carry secrets or env (SEC-04).
        assert!(!plist.contains("EnvironmentVariables"));
    }

    #[test]
    fn install_script_covers_every_step_and_parses() {
        let script = install_script(Path::new("/tmp/gate"));
        for step in [
            "printf 'nameserver 127.0.0.1\\nport 53535\\n' > '/etc/resolver/admin.rockywearsahat.com'",
            "/etc/hosts",
            "cp '/tmp/gate' '/Library/PrivilegedHelperTools/com.selfhost.console-gate'",
            "launchctl bootstrap system",
            "lsof +c 0 -nP -iTCP@127.0.0.1:443",
            "dscacheutil -flushcache",
        ] {
            assert!(script.contains(step), "missing step: {step}");
        }
        // The generated shell must be syntactically valid: `sh -n` parses
        // without running anything.
        let staged = std::env::temp_dir().join("console-route-script-test.sh");
        std::fs::write(&staged, &script).expect("script stages");
        let parsed = Command::new("/bin/sh")
            .arg("-n")
            .arg(&staged)
            .status()
            .expect("sh runs")
            .success();
        let _ = std::fs::remove_file(&staged);
        assert!(parsed, "install script does not parse");
    }
}
