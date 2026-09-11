# Incident: SSH/VPN flakiness traced to Windows Update auto-reboot, not sshd or Secure-VPN

2026-09-10. User-reported flakiness ("Handshake failed" in SelfHostVPN.app, SSH tunnels timing out and recovering) diagnosed live and fixed. A new `[maintenance]` scheduled-reboot subsystem was added as the durable fix.

## Symptom

The user reported SSH, VPN, and the admin console connection from their Mac to ALEX-DESKTOP were "flaky" — the SelfHostVPN app periodically showed `FAILED` / "Handshake failed", and SSH tunnels through the `vpn-ssh` relay would time out for a few minutes, then recover on their own.

## False leads ruled out

- **Not the Secure-VPN tunnel's crypto handshake.** Every connection in the `vpn-ssh` relay log completed `CLIENT_HELLO` → `SERVER_HELLO` → `CLIENT_AUTH` → "Handshake complete, tunnel established" successfully. The tunnel layer was never the problem.
- **Not sshd crashing.** Windows Event Log showed repeated `Service Control Manager` event 7034 ("The OpenSSH SSH Server service terminated unexpectedly") going back months, which looked at first like an unstable service — especially suspicious right after the 2026-09-09 upgrade to Win32-OpenSSH 10.0.0.0p2-Preview for post-quantum KEX (see `docs/incidents/2026-09-09-vpn-daemon-cutover-and-sshd-pq-upgrade.md`). No Application-log fault/crash-dump entry for sshd.exe exists anywhere, which was the tell that this wasn't a real crash.

## Root cause

Every "sshd terminated unexpectedly" event lines up exactly with a `User32` event 1074 (restart-initiated) and `EventLog` events 6006/6005 (log stopped/started) at the same timestamp — the **entire machine was rebooting**, not just sshd. Confirmed twice on 2026-09-10 alone:

- 08:49:58 AM — `wbem\wmiprvse.exe` initiated a restart.
- 05:34:01 PM — `svchost.exe` initiated a restart "on behalf of NT AUTHORITY\SYSTEM" for **"Operating System: Service pack (Planned)"** — a Windows-Update-triggered reboot, confirmed by a burst of `Microsoft-Windows-WindowsUpdateClient` install events at the same time (Defender intelligence update, an ESU licensing package, Store app updates).

ALEX-DESKTOP was auto-installing and auto-rebooting for Windows Update on its own schedule, with no maintenance window — taking down every selfhost service (sshd, both VPN relays, the proxy, everything) for a minute or two, unpredictably, at any hour. The post-quantum sshd upgrade had nothing to do with it; it never actually faulted.

## Fix

**Immediate, on the box (2026-09-10, done live over the SSH tunnel while it was up):**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`: `NoAutoRebootWithLoggedOnUsers=1`, `AUOptions=3` (auto-download, notify-for-install, never auto-restart).
- A Windows Scheduled Task `SelfHostMaintenanceReboot` (`\SelfHost\` folder), daily, running as SYSTEM at highest privilege, action `shutdown /r /t 60`. Initially set to 05:30, **corrected to 04:30 America/Denver** per the operator's decision (see below). The box's own timezone is already Mountain, so the trigger's local wall-clock time tracks DST automatically.

**Durable, in-tree (commit `386476e`, pushed to `main`):** a new `[maintenance]` config section (`crates/foundation/config/src/maintenance.rs`) and `selfhost-maintenance` crate so the daemon itself owns this duty instead of relying on an OS-level scheduled task:
- `reboot_hour` / `reboot_minute` / `tz` (IANA) — daily local-time trigger.
- `drain_timeout_secs` — how long to mark maintenance mode and let in-flight connections finish before rebooting.
- `peers: Vec<MaintenancePeer>` — shaped like the VPN roster (name/person/admin_socket). Empty today (ALEX-DESKTOP is the only node — decided explicitly, see below). When a second node exists, the design's extension point is that this scheduler checks that peer's health before rebooting; **no live failover/traffic-migration protocol exists yet** — that's future work, deliberately not invented here.
- Exposed read-only at `GET /api/maintenance/status` (`Capability::ConsoleRead`): `in_maintenance`, `last_reboot`, `next_reboot`.
- Wired into daemon startup (`crates/app/cli/src/main.rs`) only when `[maintenance]` is present in config — absent config means no scheduler, no behavior change.

**Live config** (`C:\Users\Alex\Self-Host\selfhost.config.toml` on the box) now carries:
```toml
[maintenance]
reboot_hour = 4
reboot_minute = 30
tz = "America/Denver"
drain_timeout_secs = 30
peers = []
```
This won't take effect until the daemon restarts on new code — `[maintenance]` is not part of the hot-reload path (same as `[dns]`/`[mail]`/bind addresses). The OS-level Scheduled Task is the floor that keeps the 4:30am reboot happening in the meantime; once the daemon has restarted onto a build containing the maintenance scheduler, the in-daemon scheduler and the OS task will both fire at the same time (redundant, harmless) until the OS task is deliberately retired.

## Decision — single-node today, 100%-uptime design deferred

The operator was explicit: ALEX-DESKTOP is the only node today, but the maintenance config should already be "shaped interconnected" so a second node slots in later without a redesign. Accepted trade-off for now: **one full-machine restart per day is an acceptable brief outage** (services "briefly fluctuate," roughly guaranteed not to be the moment anyone is depending on them) — because with one machine and a real OS reboot, there is no way to avoid *some* outage window. Zero-downtime rolling restarts across multiple nodes is out of scope until a second node actually exists; the `peers` field and the "check peer health before rebooting" extension point are the seam left for that, not an implementation of it.

## Outstanding

- The box's live `selfhost.config.toml` has a **pre-existing, unrelated** validation failure: `acme = "letsencrypt"` (line 7) is not a valid value for the current binary's `acme` enum (`staging`/`production`/`self-signed`). This predates tonight's changes and blocks `selfhost check` from validating anything past that line, including the new `[maintenance]` section. Not yet fixed — flagged for a separate pass.
- The daemon on ALEX-DESKTOP has not yet restarted onto the commits containing the maintenance scheduler (`386476e`, `fc651e0`) — it self-updates from pushes to `main`, so this should happen automatically on its next poll, but has not been verified live as of this writing.
- Retire the OS-level `SelfHostMaintenanceReboot` Scheduled Task once the in-daemon scheduler is confirmed running and rebooting correctly on its own, to avoid two independent reboot triggers.
