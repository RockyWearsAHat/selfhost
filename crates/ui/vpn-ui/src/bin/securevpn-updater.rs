//! The Secure-VPN Mac auto-updater: a one-shot check-and-update run once at
//! login/boot by the `com.selfhost.securevpn-updater` LaunchAgent, installed
//! by the SelfHost VPN app (`crates/ui/vpn-ui/src/actions.rs`).
//!
//! All of the actual work — the read-only newer-commit check, the KAT-test
//! gate, the build, the trial install, and only then the real
//! fast-forward-pull-and-install — lives in
//! `scripts/securevpn/mac-auto-update.sh` (copied to
//! `~/.securevpn/mac-auto-update.sh` by `build-app.sh`, the same way
//! `rotate-keys.sh` already is). This binary exists only because a
//! LaunchAgent's `ProgramArguments` needs a stable installed path to point
//! at, the same reason `console-gate.rs` is a tiny compiled binary rather
//! than the reverse-proxy logic living inline in a plist — see that file for
//! the precedent this mirrors.
//!
//! Deliberately **single-shot**: this process runs the script once and
//! exits. The LaunchAgent that launches it is `RunAtLoad` with no
//! `KeepAlive`/`StartInterval`, so login/boot is the only trigger — there is
//! no standing timer here and none should be added (see docs/VPN.md).
//!
//! Silent by design: nothing here prompts. A failure is left in
//! `~/.securevpn/auto-update.log` for the next person who opens the app or
//! looks at the Mac to find, not surfaced as a dialog.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::process::Command;

fn main() -> std::process::ExitCode {
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("securevpn-updater: no HOME in the environment — cannot find ~/.securevpn");
        return std::process::ExitCode::FAILURE;
    };
    let script = std::path::Path::new(&home).join(".securevpn").join("mac-auto-update.sh");
    if !script.is_file() {
        // Nothing installed yet on this Mac (join-mac.sh / build-app.sh never
        // ran here). That is a normal, unremarkable state for a LaunchAgent
        // that fires at every login — say so once in its own log rather than
        // failing loudly at every boot.
        eprintln!("securevpn-updater: {} not found — nothing to update", script.display());
        return std::process::ExitCode::SUCCESS;
    }

    match Command::new("/bin/bash").arg(&script).status() {
        Ok(status) if status.success() => std::process::ExitCode::SUCCESS,
        Ok(status) => {
            eprintln!("securevpn-updater: {} exited {status}", script.display());
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("securevpn-updater: could not run {}: {error}", script.display());
            std::process::ExitCode::FAILURE
        }
    }
}
