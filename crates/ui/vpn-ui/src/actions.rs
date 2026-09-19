//! The slow controls, run off the window thread.
//!
//! Rotating a key takes seconds and opening the console prompts for a password;
//! both would freeze the window if run in a handler. Each spawns a thread, marks
//! the shared [`Activity`] busy while it works, and leaves a result the next
//! frame reads.

use crate::app::{Activity, AI_URL, CONSOLE_URL, GATED_HOSTS, SARA_URL};
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

/// The launchd label of the Secure-VPN Mac auto-updater.
///
/// This is a per-user **LaunchAgent**, not a LaunchDaemon like the console
/// gate: it runs `~/.securevpn` under this user's own account (it needs no
/// privilege at all — the one step that would, restarting a root-bound
/// tunnel, uses non-interactive `sudo -n` and simply skips itself if that
/// is not configured; see `scripts/securevpn/mac-auto-update.sh`), so it
/// belongs in the user's own launchd domain rather than the system one.
const UPDATER_LABEL: &str = "com.selfhost.securevpn-updater";

/// Where the updater binary is installed: user-owned, so no privileged
/// install step is ever needed for it (unlike the console gate).
fn updater_bin() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library/Application Support/SelfHostVPN/securevpn-updater"))
}

/// The LaunchAgent plist that fires the updater once at login/boot.
fn updater_plist_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library/LaunchAgents").join(format!("{UPDATER_LABEL}.plist")))
}

/// Where the updater's stderr lands.
fn updater_log() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library/Logs/selfhost-securevpn-updater.log"))
}

/// The current user's home directory.
fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "no HOME in the environment".into())
}

/// Where the gate's stderr lands — a bind failure names its errno here.
const GATE_LOG: &str = "/var/log/selfhost-console-gate.log";

/// Rotates the identity key, then refreshes the shown fingerprints.
pub fn rotate(activity: Arc<Mutex<Activity>>) {
    if !set_busy(&activity, "Rotating keys…") {
        return;
    }
    std::thread::spawn(move || {
        let outcome = keys::rotate();
        let account = keys::account();
        let (client, server) = keys::identities(account.as_deref());
        let last = keys::last_rotation();
        finish(&activity, outcome.map(|()| "Key rotated and verified.".to_string()), move |a| {
            a.client = client;
            a.server = server;
            a.last_rotation = last;
        });
    });
}

/// Signs this install in through the public sign-in site's OAuth-with-PKCE
/// flow (see [`crate::oauth`]): opens the browser to `auth.rockywearsahat.com`
/// and waits for it to hand a redeemed identity back over a loopback callback.
///
/// No admin command to copy and no name typed by hand — the account that
/// approves the browser prompt, and whether it holds `vpn.access:<location>`
/// for this relay, is the whole decision; this call just carries the result.
///
/// Unlike [`open_console`]/[`open_sara`]/[`open_ai_studio`], this does *not*
/// call `ensure_console_route()` first: the sign-in site is a public, ungated
/// host reachable over the open internet, precisely so a first-time sign-in
/// never depends on the privileged gate that only signing in can justify
/// installing.
pub fn sign_in(activity: Arc<Mutex<Activity>>) {
    if !set_busy(&activity, "Waiting for the browser sign-in…") {
        return;
    }
    std::thread::spawn(move || match crate::oauth::sign_in() {
        Ok(result) => {
            let client = keys::identities(Some(&result.peer)).0;
            finish(&activity, Ok(format!("Signed in as {}.", result.account)), move |a| {
                a.client = client;
                a.account = Some(result.account);
                a.pending_identity = Some(result.peer);
            });
        }
        Err(error) => finish(&activity, Err(format!("Sign-in failed: {error}")), |_| {}),
    });
}

/// Ensures the console route is installed, then opens the console in the browser.
pub fn open_console(activity: Arc<Mutex<Activity>>) {
    open_gated(activity, CONSOLE_URL, "Opened the admin console.")
}

/// Ensures the console route is installed, then opens the SARA gateway.
///
/// Shares the same route as the console: the tunnel and the loopback 443 gate
/// are host-agnostic, so the only thing that differs per gated host is which
/// name the split-DNS responder answers for.
pub fn open_sara(activity: Arc<Mutex<Activity>>) {
    open_gated(activity, SARA_URL, "Opened SARA.")
}

/// Ensures the console route is installed, then opens the AI Studio.
///
/// Shares the same route as the console and SARA: the tunnel and the loopback
/// 443 gate are host-agnostic, so the only thing that differs per gated host
/// is which name the split-DNS responder answers for.
pub fn open_ai_studio(activity: Arc<Mutex<Activity>>) {
    open_gated(activity, AI_URL, "Opened AI Studio.")
}

/// Ensures the Secure-VPN Mac auto-updater's LaunchAgent is installed and
/// current, so it fires once at every login/boot from here on.
///
/// Called once at app startup (`main.rs`), not from a button: unlike the
/// console route this needs no privileged prompt (it is a per-user
/// LaunchAgent, not a LaunchDaemon), so there is nothing to gate behind user
/// action — installing it silently on every launch is what makes the
/// "no user prompt, fully automatic" requirement actually automatic, rather
/// than automatic-once-someone-remembers-to-click-something. A failure here
/// is logged to stderr and does not stop the window from opening: a Mac that
/// cannot get the updater installed is still a Mac that can run the VPN by
/// hand exactly as it always could.
pub fn ensure_updater_agent() {
    if let Err(error) = install_updater_agent_if_needed() {
        eprintln!("selfhost-vpn-ui: could not install the Secure-VPN auto-updater: {error}");
    }
}

/// Installs the updater binary, the script it runs, and the LaunchAgent
/// plist, unless all three already match this build exactly — then
/// `launchctl bootstrap`s it into the user's own launchd domain.
///
/// No `sudo`, no `osascript` prompt: every path here is under this user's
/// own `$HOME`, which this process can already write.
fn install_updater_agent_if_needed() -> Result<(), String> {
    let bundled_updater = bundled_binary("securevpn-updater")?;
    let bundled_script = bundled_update_script()?;
    let bin = updater_bin()?;
    let plist_path = updater_plist_path()?;
    let script_dest = home_dir()?.join(".securevpn/mac-auto-update.sh");
    let plist_body = updater_plist(&bin, &updater_log()?);

    let current = std::fs::read(&bundled_updater).ok() == std::fs::read(&bin).ok()
        && std::fs::read_to_string(&plist_path).map(|c| c == plist_body).unwrap_or(false)
        && std::fs::read_to_string(&bundled_script).ok()
            == std::fs::read_to_string(&script_dest).ok();
    if current {
        return Ok(());
    }

    if let Some(dir) = bin.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    std::fs::copy(&bundled_updater, &bin)
        .map_err(|e| format!("copy updater binary to {}: {e}", bin.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", bin.display()))?;
    }

    if let Some(dir) = script_dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    std::fs::copy(&bundled_script, &script_dest)
        .map_err(|e| format!("copy update script to {}: {e}", script_dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", script_dest.display()))?;
    }

    if let Some(dir) = plist_path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    std::fs::write(&plist_path, &plist_body)
        .map_err(|e| format!("write {}: {e}", plist_path.display()))?;

    let uid = current_uid()?;
    let target = format!("gui/{uid}/{UPDATER_LABEL}");
    // Reload cleanly rather than assume nothing is loaded — an earlier build's
    // plist could already be bootstrapped under the same label.
    let _ = Command::new("launchctl").args(["bootout", &format!("gui/{uid}")]).arg(&plist_path).output();
    let output = Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}")])
        .arg(&plist_path)
        .output()
        .map_err(|e| format!("launchctl bootstrap: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "launchctl bootstrap {target} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// The updater's LaunchAgent definition.
///
/// `RunAtLoad` alone — deliberately **no** `KeepAlive` and **no**
/// `StartInterval`: login/boot is the one sanctioned trigger for the Mac-side
/// update check (see docs/VPN.md), not a standing timer. The process is
/// meant to run once and exit; `KeepAlive` would relaunch it in a loop the
/// moment it does. No `EnvironmentVariables` (SEC-04) and no secrets.
fn updater_plist(bin: &Path, log: &Path) -> String {
    let bin = bin.display();
    let log = log.display();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{UPDATER_LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{bin}</string></array>
    <key>RunAtLoad</key><true/>
    <key>StandardErrorPath</key><string>{log}</string>
    <key>StandardOutPath</key><string>{log}</string>
</dict>
</plist>
"#
    )
}

/// The current user's numeric uid, for the `gui/<uid>` launchd domain target —
/// read with `id -u` rather than an FFI call, matching
/// `crates/app/cli/src/service_install.rs`'s own launchd-domain code.
fn current_uid() -> Result<String, String> {
    let output =
        Command::new("id").arg("-u").output().map_err(|e| format!("could not run id -u: {e}"))?;
    if !output.status.success() {
        return Err("id -u failed".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// A binary named `name` shipped beside this app's own executable, the same
/// way [`bundled_gate`] finds the console gate.
fn bundled_binary(name: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("could not locate the app binary: {error}"))?;
    let dir = exe.parent().ok_or("the app binary has no parent directory")?;
    let candidate = dir.join(name);
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!("{name} is missing from this build — rebuild with crates/ui/vpn-ui/build-app.sh"))
    }
}

/// The update script shipped beside the app, the same way `rotate-keys.sh`
/// already rides in the bundle's `Resources/` (see `build-app.sh`).
fn bundled_update_script() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("could not locate the app binary: {error}"))?;
    let dir = exe.parent().ok_or("the app binary has no parent directory")?;
    // MacOS/ and Resources/ are siblings inside Contents/.
    let candidate = dir.join("../Resources/mac-auto-update.sh");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err("mac-auto-update.sh is missing from this build — rebuild with \
             crates/ui/vpn-ui/build-app.sh"
            .into())
    }
}

/// Ensures the route is installed, then opens `url` in the browser.
fn open_gated(activity: Arc<Mutex<Activity>>, url: &'static str, done: &'static str) {
    if !set_busy(&activity, "Opening…") {
        return;
    }
    std::thread::spawn(move || {
        let outcome = ensure_console_route().and_then(|()| open_url(url));
        finish(&activity, outcome.map(|()| done.to_string()), |_| {});
    });
}

/// Ensures everything the portless gated URLs need, in one privileged prompt.
///
/// Three pieces make each host in [`GATED_HOSTS`] land on the tunnel: its
/// scoped resolver file (pointing the host at the app's split-DNS responder),
/// a clean `/etc/hosts` (the legacy hosts-line mechanism removed), and the
/// console gate — a root LaunchDaemon holding `127.0.0.1:443` and splicing it
/// to the tunnel's local end. When everything is already exact, nothing runs
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
/// Exactness is byte equality — every gated host's resolver file, the plist,
/// and the gate binary — plus a hosts file free of any gated host's legacy
/// line, so an upgrade, a hand-edit, or adding a new gated host re-triggers
/// the one-time install. Files only: the daemon itself is launchd-kept
/// (`KeepAlive`), and the installer is the step that proves the listener; a
/// user who booted the gate out on purpose is not fought here.
fn console_route_current(gate: &Path) -> bool {
    let resolvers_ok = GATED_HOSTS.iter().all(|host| {
        std::fs::read_to_string(resolver_path(host))
            .map(|current| current == resolver_body())
            .unwrap_or(false)
    });
    let plist_ok =
        std::fs::read_to_string(GATE_PLIST).map(|current| current == gate_plist()).unwrap_or(false);
    let gate_ok = match (std::fs::read(gate), std::fs::read(GATE_BIN)) {
        (Ok(bundled), Ok(installed)) => bundled == installed,
        _ => false,
    };
    resolvers_ok && plist_ok && gate_ok && !GATED_HOSTS.iter().any(|host| hosts_has_legacy_line(host))
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

/// The scoped resolver file for a gated host.
fn resolver_path(host: &str) -> String {
    format!("/etc/resolver/{host}")
}

/// What every resolver file must say: the app's responder, on its loopback port.
///
/// Identical for every gated host — the responder itself is what tells hosts
/// apart (see [`crate::dns`]) — so one body serves all of them.
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
    let resolver_printf = resolver_body().replace('\n', "\\n");
    let resolver_steps: String = GATED_HOSTS
        .iter()
        .map(|host| {
            let resolver_path = resolver_path(host);
            let host_pattern = host.replace('.', "\\.");
            format!(
                "printf '{resolver_printf}' > '{resolver_path}'\n\
                 chown root:wheel '{resolver_path}'\n\
                 chmod 644 '{resolver_path}'\n\
                 [ ! -f /etc/hosts ] || /usr/bin/sed -i '' -E -e '/^127\\.0\\.0\\.1[[:space:]]+{host_pattern}[[:space:]]*(#.*)?$/d' -e '/^127\\.0\\.0\\.1[[:space:]]/s/[[:space:]]+{host_pattern}([[:space:]]|$)/\\1/g' /etc/hosts\n"
            )
        })
        .collect();
    let plist = gate_plist();
    let gate = sh_quote(gate);
    format!(
        r#"#!/bin/sh
# One-time privileged console-route install, staged and run by SelfHost VPN.
set -e
mkdir -p /etc/resolver /Library/PrivilegedHelperTools
{resolver_steps}cp {gate} '{GATE_BIN}'
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

/// Whether `/etc/hosts` still carries the legacy mapping for `host`.
fn hosts_has_legacy_line(host: &str) -> bool {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    hosts.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line.starts_with("127.0.0.1")
            && line.split_whitespace().skip(1).any(|candidate| candidate == host)
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

/// Opens `url` in the default browser.
pub(crate) fn open_url(url: &str) -> Result<(), String> {
    let status = Command::new("open")
        .arg(url)
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
            "printf 'nameserver 127.0.0.1\\nport 53535\\n' > '/etc/resolver/sara.rockywearsahat.com'",
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
