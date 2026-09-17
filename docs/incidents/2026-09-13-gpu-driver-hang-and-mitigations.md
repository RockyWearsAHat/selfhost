# Incident: ALEX-DESKTOP hung ~9 hours (dead screen, box powered) — GPU driver, not selfhost/SARA/Windows Update

2026-09-13. Diagnosed with a 5-agent haiku-model investigation fleet (Kernel-Power/bugcheck events, Windows Update, the selfhost daemon and self-update state, SARA and the VPN relays, and resource/hardware health) run in parallel over the Secure-VPN SSH tunnel, plus a synthesis pass. Full findings: see the workflow's journal, or the summary below.

## Symptom

Screen dead/unresponsive, no video output, but the box's internal lights stayed on as if it was powered and running. The operator physically hard-restarted it after noticing the SelfHostVPN Mac app couldn't connect (DNS for `rockywearsahat.com` was failing because the box, its own authoritative DNS server, was down).

## Root cause

An NVIDIA `nvlddmkm` (GeForce GTX 1080) display-driver failure. Timeline:

- **04:30:30** — the daily `SelfHostMaintenanceReboot` scheduled task ran and completed successfully. Not implicated — it finished cleanly, well before anything went wrong.
- **01:32:59 and 03:43:50 UTC** (early morning) — two bugcheck `0x00000116` (VIDEO_TDR_FAILURE) crashes, both of which self-recovered (Windows auto-rebooted on its own, as `AutoReboot=TRUE`/`DebugInfoType=7` are correctly configured). A 1.4 GB `MEMORY.DMP` exists from the 03:43 event.
- **05:01:53** — last normal log activity anywhere on the box (a Video.UI diagnostic entry).
- **05:11:49** — Event ID 6008: *"The previous system shutdown at 5:11:49 AM was unexpected."* This is the actual onset of the fatal hang — unlike the two earlier same-morning TDR crashes, this one did **not** produce a bugcheck/dump and did **not** auto-recover. The GPU/display stack wedged hard enough to take the rest of the kernel down with it (or at least stop it from logging anything), rather than cleanly bugchecking and rebooting.
- **05:11:49 → 14:30** (~9 hours) — complete silence in System and Application logs. No heartbeat, no crash dump, nothing.
- **14:30:02** — operator's hard restart. Event 41 (Kernel-Power, Critical) and Event 6008 both fire at 14:30:04/14:30:16, confirming the unclean shutdown.

This driver/bugcheck pair (`nvlddmkm`, 0x116) has recurred **16+ times over roughly 16 months** (2024-05 through 2026-07, plus the two same-day recoveries), all previously self-recovering. This is the first time it wedged instead of recovering.

## Ruled out (with evidence)

- **Windows Update.** Anti-reboot policy (`NoAutoRebootWithLoggedOnUsers=1`, `AUOptions=3`, from the 2026-09-10 incident fix) confirmed intact. The daily maintenance reboot ran and succeeded at 04:30, 40+ minutes before the hang began. The only pending item was an unrelated, weeks-stale `gamingservicesproxy_13.dll` rename with no evidence connecting it to this hang.
- **The selfhost daemon.** No crash/panic entries in the Application log; the box hadn't even self-updated in 4 days (running commit `e15d026`, 4 days behind `main`) before the incident. Current post-restart processes show normal, modest CPU/memory.
- **SARA / the VPN relays.** SARA's `EBUSY`/`ETIMEDOUT` errors (git worktree lock contention on `D:\SARA\Desktop\Forge\.sara\worktrees\wk-worklist-12-95a1de46`, `cmd.exe` timeouts) all timestamp to **after** the 14:30 restart — SARA reacting to interrupted state, not causing the hang. The VPN relay processes showed no errors at all.
- **Resource exhaustion.** Memory (54% free post-restart), disk (ample on all drives), CPU, and WHEA hardware-error logs all came back clean.

## Mitigations applied this session (2026-09-13)

The GPU is genuinely needed on this box (used for local gaming, per the operator — not a case where the display path can just be moved to onboard graphics), so the driver stays in the crash path. Two things were done:

1. **TDR tuning** — `HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`: `TdrDelay=8`, `TdrDdiDelay=8` (up from the unset default of 2s). Gives a slow/stalled GPU operation more time to actually finish before Windows escalates to a driver-timeout recovery attempt — the mechanism that failed to complete cleanly at 05:11:49. Takes full effect on next reboot.
2. **An external heartbeat monitor**, since nothing on the box itself can watch for a hang that takes the whole kernel down with it: `~/.securevpn/box-heartbeat.sh` on the Mac, installed as the launchd agent `com.selfhost.box-heartbeat` (`~/Library/LaunchAgents/com.selfhost.box-heartbeat.plist`, `StartInterval=120`, `RunAtLoad`). Pings `192.168.1.8` every 2 minutes; after 3 consecutive misses (~6 minutes) fires a macOS notification ("ALEX-DESKTOP has stopped answering pings..."), and another when it comes back. This runs independently of any Claude Code session. It does **not** auto-fix anything — there is no smart plug on this box's power (checked via the home-automation registry: only TVs/speakers/lights are controllable), so recovery from a true hang is still a manual power-cycle. What it fixes is detection latency: this incident sat undetected for ~9 hours; the heartbeat cuts that to single-digit minutes.

## Second hang, same day (15:50, ~14 min this time)

A second silent full hang occurred at **15:50:17** (confirmed via Event 6008 on the next boot: *"The previous system shutdown at 3:50:17 PM was unexpected"*), noticed and hard-restarted by the operator within ~14 minutes (boot time 16:04:37) — much faster detection than the first, but the hang itself again produced **no bugcheck, no dump**, matching the 05:11:49 signature exactly. This happened *before* the TDR registry fix above had a chance to take effect (it was set ~14:57, and `TdrDelay`/`TdrDdiDelay` only load when the display driver reinitializes — normally at boot), so it isn't evidence the fix failed; the fix has only actually been active since the 16:04 reboot.

While re-checking, `nvidia-smi` surfaced a concrete, previously-unchecked suspect: **Wallpaper Engine** (`wallpaper32.exe`/`wallpaperui.exe`, from `C:\SteamLibrary\steamapps\common\wallpaper_engine\`), auto-starting at every login via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WallpaperEngine`, was running continuously and burning 40%+22% CPU across two processes rendering onto the same GPU (`nvlddmkm`) that keeps crashing. This is a widely-reported real-world trigger for exactly this TDR-failure signature — a background process with nothing to do with the box's actual purpose, touching the display driver nonstop for the box's entire uptime.

**Applied, with operator confirmation:** killed all running Wallpaper Engine processes and removed the `WallpaperEngine` value from `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`, so it no longer auto-starts. The operator wants an eventual replacement (mentioned "Wallpaper Studio" as a maybe-safer alternative) but hasn't chosen one yet — nothing else was installed in its place this session.

## Third-party corroboration and the driver-update attempt

A separate Claude session working on this box for an unrelated GPU workload (ai-studio / sdxl-dmd2) independently reported the same failure mode from its own side: repeated bugcheck `0x116` (VIDEO_TDR_FAILURE) crashes today under sustained GPU compute, hitting a VRAM ceiling around 7.6GB, with `TdrDelay` confirmed unset (2s default) — the same root mechanism, from the compute side rather than the display side. It confirmed a safe state to reboot from (service drained, nothing mid-write, auto-starts on boot) before the box was restarted with the operator's go-ahead.

**NVIDIA driver update attempted, and partially blocked — needs an interactive session, not SSH.** Using NVIDIA's own (non-JS) driver-lookup API (`nvidia.com/Download/API/lookupValueSearch.aspx`, then `gfwsl.geforce.com/.../AjaxDriverService.php`), confirmed the current real latest driver for this GPU: **582.66** (released 2026-06-16), a large jump from the installed **560.94** (2024-08-13). Downloaded the verified installer (`https://us.download.nvidia.com/Windows/582.66/582.66-desktop-win10-win11-64bit-international-dch-whql.exe`, 912,109,016 bytes, matches NVIDIA's own reported size) directly to the box over SSH and ran it silently twice (`-s -noreboot -clean`, then `-s -noreboot`), both returning exit code 0 with no visible error.

**Neither attempt actually staged the new driver.** Checked directly with `pnputil /enum-drivers`, both immediately after each install and again after a full reboot: the core `nv_dispi.inf` display driver entry stayed at `08/14/2024 32.0.15.6094` (=560.94) throughout. The installer reports success without error, but never touches the driver store. Root cause: NVIDIA's installer needs access to an interactive desktop/window-station session to actually perform a kernel driver swap; an SSH session is non-interactive (similar to a service/scheduled-task session), so `-s` (silent, i.e. no UI) is not the same as "works headlessly" — it silently no-ops the actual driver-store update instead of failing loudly. This is a real, load-bearing limitation of SSH-based administration for this one specific kind of change, not a flag that was missed.

**Confirmed intact through the reboot (boot time 2026-09-13 21:22:05):** `TdrDelay`/`TdrDdiDelay` both still `8` in `HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`, and Wallpaper Engine confirmed not running post-reboot (its autostart removal held).

**Resolved without needing RDP or physical access.** There was already an active interactive console session on the box (session 1, `ALEX-DESKTOP\Alex`, confirmed via `Get-Process -IncludeUserName explorer` → `SessionId 1`). Used Task Scheduler to inject the install into that real interactive session from SSH:

```
schtasks /create /tn NvidiaInstallInteractive /tr "C:\Users\Alex\Downloads\nvidia-582.66-driver.exe -s -noreboot" /sc once /st 23:59 /ru Alex /it /rl highest /f
schtasks /run /tn NvidiaInstallInteractive
```

First attempt (`/it` without `/rl highest`) failed instantly with `Last Result: -2147024156` = `0x800702E4` = **"The requested operation requires elevation"** — the interactive session trick alone gets you a real desktop session, but not an admin token; the installer needs both. Adding `/rl highest` (Task Scheduler's own privilege-elevation, which for an admin account runs elevated silently, no UAC prompt) fixed it. The task then ran for several minutes (a ~900MB install), finished with `Last Result: 0`, and `nvidia-smi` immediately confirmed **Driver Version: 582.66, CUDA 13.0** — live, with no reboot required this time. The old `08/14/2024 32.0.15.6094` package remains in the driver store as an inactive leftover entry (normal; harmless).

**Takeaway for future SSH-based admin on this box:** a plain SSH session can't perform actions requiring an interactive desktop (driver installs being the concrete example here) — `schtasks ... /it /rl highest /ru <account>` against an already-logged-on session is the workaround, not RDP.

## Honest limits — this is risk reduction, not a guarantee

A full kernel-level hang caused by a third-party driver bug cannot be made provably impossible from the OS/application side. `TdrDelay` tuning reduces one known trigger path (a timeout that previously fired too eagerly); it does not patch the underlying `nvlddmkm` bug, which is NVIDIA's to fix in a driver release. Two further mitigations were identified but **not** applied, and are worth doing when convenient:

- **Update the NVIDIA driver.** Currently `32.0.15.6094`, dated 2024-08-13 — over a year old as of this incident. A newer driver may have already fixed this specific TDR-recovery bug. Not done automatically this session: it's a large interactive install (GPU driver reinstall blinks the display, and the box is actively used for gaming) that the operator should run themselves at a convenient time, not something to push silently onto a box someone might be using.
- **A smart plug on the box's power**, wired into the same home-automation system already controlling the TVs/lights, would let a failed heartbeat trigger an actual remote power-cycle instead of only a notification — the difference between "you find out in 6 minutes" and "it fixes itself in 6 minutes." Not something this session can buy or install.
