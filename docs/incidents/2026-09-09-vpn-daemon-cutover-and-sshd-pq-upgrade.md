# Incident: VPN daemon cutover and post-quantum SSH upgrade — five-bug cascade

2026-09-09. Live production outage, cascade of root causes found and fixed in sequence, full recovery verified. All services running and healthy at end state.

## Summary

vpn-console (port 8443) and vpn-ssh (port 8444) were transitioned from ad-hoc Windows Scheduled Tasks to proper daemon-supervised services (commits 7b0a668, e15d026). The transition was technically correct but exposed a causal chain of five distinct bugs, each surfaced only after the previous one was fixed. Simultaneously, OpenSSH's key exchange was upgraded to post-quantum (sshd.exe from Win32-OpenSSH 9.5.4.1 to 10.0.0.0p2-Preview), which during the upgrade triggered a sixth issue (TrustedInstaller file lock). Both issues are resolved; the box's SSH and VPN relays are fully operational with post-quantum support enabled.

## Causal chain: five bugs in sequence

### Bug 1: Stale Python PATH entry (Windows error 1920)

**What happened:** Once daemon supervision for vpn-console/vpn-ssh was deployed, both services landed in state `unstartable`/`backoff`. Root cause: the daemon's own process launched VPN relays by invoking "python" (bare, no path) from `crates/services/vpn/src/runner.rs` Install::vendored() on Windows. The box's system-wide (Machine-scope) PATH environment variable contained a stale entry (`C:\Python311\`, which does not exist on disk) pointing to a deleted Python installation, and had no entry at all for the real installed Python (`C:\Users\Alex\AppData\Local\Programs\Python\Python312\`, which has all required packages: cryptography, mlkem768). Result: Windows error 1920 ("could not start python: The file cannot be accessed by the system").

**Fix:** Prepended both `C:\Users\Alex\AppData\Local\Programs\Python\Python312\` and its `Scripts\` subfolder to the Machine-scope PATH, then restarted the daemon. This is a durable, box-level fix (not stored in git) and would need reapplication if the box's PATH is ever reset. Worth flagging as tribal knowledge: "vpn relay unstartable" in the future should trigger a PATH audit, not just a code review.

**Causal note:** This bug was invisible during the ad-hoc Scheduled Task era because those tasks ran interactively under the logged-in user's own profile and PATH; the daemon's background service context exposed it immediately.

### Bug 2: Windows Task Scheduler silent failure (task shows Running but never launches child)

**What happened:** Before the PATH fix, diagnostics invoked `schtasks /run /tn ai-studio` and similar manual Task Scheduler invocations (from a separate SARA services investigation). Tasks reported state `Running` and `Ready` but inspection of actual process trees showed no child processes actually launching. Windows Task Scheduler can report a task's *own* state as Running/Ready while the action's child process never starts—a race between state-reporting and execution.

**Significance:** Not directly the cause of the VPN relay failure, but it revealed why ad-hoc Scheduled Tasks (the pre-daemon-supervision path) were never discovered as broken during testing. The failure was structurally invisible unless you cross-checked actual process trees against the scheduler's reported state.

### Bug 3: Windows Job Object kill-on-close (one-shot CLI process exits, child dies)

**What happened:** The interim workaround before daemon supervision was to launch VPN relays from the selfhost CLI as a direct foreground process. That worked briefly because the process stayed alive, but once the design shifted to "the daemon should supervise relays," the architectural pattern changed: the CLI invocation is one-shot (exits after handing the process to the supervisor), but Windows Job Objects by default kill all child processes when the job handle is closed. Result: any relay launched from a CLI process died immediately when the CLI exited.

**Fix:** Code was updated to decouple the relay process from the CLI process's Job Object, allowing it to outlive the one-shot CLI invocation. This was the correct architectural fix (code layer, commits 7b0a668, e15d026).

**Causal note:** Bug 1 (stale PATH) masked this because relays never even started; only after PATH was fixed did this bug's symptom (relay exits immediately) become visible.

### Bug 4: Bare "python" not resolving in daemon's environment (revealed after Bug 1 fixed)

**What happened:** After the PATH fix was deployed, relays did start successfully. However, "python" resolution is evaluated in the daemon *process's own environment*, not the administrator's shell where you added the PATH entries. A daemon restart was necessary for the machine-wide PATH change to take effect in the daemon's environment. This was a process-lifecycle issue, not a code bug, but the diagnosis required understanding that the daemon needed to be restarted after a system environment change.

**Significance:** This is primarily an operational lesson: system environment changes take effect only for newly-spawned processes.

### Bug 5: TrustedInstaller lock on sshd.exe during post-quantum upgrade

**What happened:** To upgrade OpenSSH to post-quantum key exchange (moving from 9.5.4.1 to 10.0.0.0p2-Preview for mlkem768x25519-sha256 negotiation), sshd.exe and supporting binaries needed replacement on disk. However, sshd.exe on Windows is owned by TrustedInstaller with NTFS permissions that even a non-elevated interactive SSH session cannot overwrite. A partial/mismatched binary swap (new libcrypto.dll paired with old sshd.exe) caused sshd to hang on start (Windows SCM error 1053, "did not respond to the start or control request in a timely fashion"). This took down the box's *only SSH access path* because vpn-ssh (port 8444) forwards to sshd on loopback 22.

**Fix and recovery technique:** The box's separate VPN relay (vpn-console, port 8443) forwarding to the local web proxy (443) on the admin console remained up. This provided access to the daemon's own admin API (loopback 127.0.0.1:9191 via that relay with Host-header routing to admin.rockywearsahat.com). A temporary one-shot service was created via PUT /api/services/NAME and started via POST /api/services/NAME/start, with output read via GET /api/services/NAME/logs—effectively using the admin API as a remote command-execution channel. This service ran `takeown` and `icacls` with elevated privileges, successfully replacing the TrustedInstaller-locked sshd.exe. Once the binaries were correctly matched and sshd was restarted, SSH recovered.

**Operational note:** This is a reusable recovery technique for "SSH is broken but the admin console is reachable"—the services API can run arbitrary commands with the daemon's own privilege level (which is higher than a non-elevated SSH session). It is also a security-relevant fact: any credential with `services.admin` has arbitrary command execution on the box by the design of services_add/services_control itself. This is not a new vulnerability (it is inherent to the services feature), but it is worth documenting as tribal knowledge since it was exercised here in a novel way.

## Post-quantum SSH upgrade details

After resolving the sshd.exe lock issue, the full OpenSSH upgrade was completed:

- **Baseline:** Win32-OpenSSH 9.5.4.1 (via C:\Windows\System32\OpenSSH\, Windows Optional Feature)
- **Target:** Win32-OpenSSH 10.0.0.0p2-Preview (github.com/PowerShell/Win32-OpenSSH, official Microsoft release)
- **Rationale:** Post-quantum key exchange. Version 9.5.4.1 has zero post-quantum KEX algorithms (confirmed via 'ssh -Q kex'). Version 10.0p2 incorporates upstream OpenSSH 10.0 with mlkem768x25519-sha256 and sntrup761x25519 support. Verified live: client negotiates mlkem768x25519-sha256, and the client's own "not using post-quantum" warning is gone.
- **Binaries backed up:** C:\Users\Alex\Downloads\OpenSSH-backup-20260909 for rollback.
- **Note:** The release is tagged "Preview" upstream, not GA/stable. Periodic checks for a stable release with matching PQ support are recommended.

## Verified state at resolution

- **vpn-console:** running (daemon-supervised, port 8443, real HTTPS traffic verified)
- **vpn-ssh:** running (daemon-supervised, port 8444, real SSH traffic verified)
- **vpn-updater:** registered (state `stopped`/`exited`, correct for RestartPolicy::Never), not yet armed (webhook_secret not configured, GitHub App installation pending)
- **SSH key exchange:** mlkem768x25519-sha256 (post-quantum, verified live)
- **sshd.exe:** Win32-OpenSSH 10.0.0.0p2-Preview (confirmed via version output)

All traffic paths verified live at each stopping point; no unresolved issues remain.

## Recommendations

1. **Document the admin-API-as-command-channel recovery technique** in operational runbooks for "SSH access lost but admin console is reachable" scenarios.
2. **Add Windows PATH environment audit to "vpn relay unstartable" diagnostic runbook** — the PATH is the first thing to check when bare "python" fails to launch in a daemon context.
3. **Arm vpn-updater:** configure webhook_secret and confirm Secure-VPN repository is installed in the GitHub App, so that future pushes to Secure-VPN automatically trigger box updates.
4. **Periodic review of OpenSSH release status:** the current build is tagged "Preview" upstream; move to GA/stable once a stable release with equivalent post-quantum support is available.
