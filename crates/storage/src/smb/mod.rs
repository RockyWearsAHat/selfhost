//! Asking the operating system to export a share over SMB.
//!
//! **Not built yet** — Phase 10. We do not implement SMB and never will: the
//! protocol is a decade of work and every platform already ships a server that
//! the platform's own clients trust. What this module does is drive that server,
//! as a structural clone of [`selfhost_firewall`](../../selfhost_firewall/index.html):
//! a **pure** desired-vs-live diff, then one thin backend per platform shelling
//! out through a copy of `firewall/src/run.rs` (20 s deadline, `kill_on_drop`,
//! `looks_denied` mapped to a typed error naming the privilege needed), with an
//! honest `unsupported` variant rather than a silent no-op.
//!
//! - **macOS** — `sharing -l -f json` to read; `sharing -a <path> -S <name>
//!   -n <name> -s 001 -g 000 -R <0|1> -E <0|1>` to create; `sharing -r <name>`
//!   to remove; `launchctl enable system/com.apple.smbd` + `bootstrap` to start
//!   the service.
//! - **Windows** — `Get-SmbShare | ConvertTo-Json`, `New-SmbShare`,
//!   `Remove-SmbShare -Force`, **plus `icacls` for the NTFS ACL**: share
//!   permissions and NTFS permissions are both enforced, so a share created
//!   without the second is visible and unusable.
//! - **Linux** — an `smb.conf` stanza plus `smbcontrol all reload-config`.
//!
//! # The name reaching those command lines is already checked
//!
//! Every command above interpolates the operator's chosen share name, and two
//! of the three do it as an *argument*: a name beginning with `-` is an option
//! to `sharing` and to `New-SmbShare`, and a name holding a newline is a second
//! line of `smb.conf`. That is why the name arrives as a
//! [`crate::share::SmbName`] rather than a `String` — checked at the type, in
//! the crate that claims to have checked, before any of these backends existed
//! to argue about whose job it was. A backend re-deriving its own rules here
//! would be a fourth opinion; it passes [`crate::share::SmbName::as_str`] on.
//!
//! # Two rules that are not negotiable
//!
//! **Teardown touches only shares selfhost created.** The plan records which
//! export points it made. This very Mac already exports a pre-existing,
//! guest-accessible *"Alex Waldmann's Public Folder"*, and a reconcile that
//! deleted everything it did not recognise would delete somebody's sharing
//! configuration to enforce a config file that never mentioned it.
//!
//! **Guest and `Everyone` access are refused, and that is not configurable.**
//! `-g 000` on macOS and the restricted `icacls` grant on Windows are fixed. An
//! SMB share is reachable from the whole LAN, and the gate that protects the
//! console — `allowed_cidrs` on the console site — does not apply to it.
//!
//! # The honest limitation, said in the UI
//!
//! SMB authenticates against **operating-system accounts** (NTLM, Kerberos,
//! `smbpasswd`). The console password cannot open an SMB session on any of the
//! three platforms, and no amount of work here would change that. The browser
//! file manager, WebDAV and the CLI all use the console credential; SMB uses the
//! OS account, and the console plate says so rather than letting an operator
//! discover it as a bug report.
