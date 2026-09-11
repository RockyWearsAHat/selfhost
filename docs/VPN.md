# VPN.md — Secure-VPN access to the admin console

The web admin console (`admin.rockywearsahat.com`) is **VPN-only**;
`rockywearsahat.com` itself stays a normal public site. The proxy's per-site
`allowed_cidrs` gate admits only the loopback address that the VPN tunnel emerges
from on the box, so the console does not exist for anyone who is not on the
tunnel: a direct request to the admin host returns the same `404` as an unhosted
name, on HTTPS and cleartext alike.

The tunnel is **Secure-VPN** (`github.com/RockyWearsAHat/Secure-VPN`), the
project's own from-scratch VPN — not WireGuard. It is a mutually-authenticated,
encrypted TCP forward: the client listens on a local port and every connection
is tunnelled, under its own session, to the server, which forwards it to a local
target. Here the target is the selfhost proxy itself.

## Why an external VPN at all (the trust-anchor exception)

The project's rule is no third-party runtime dependencies on the data path. A VPN
is the one place we deliberately lean on audited primitives rather than invent
our own transport crypto — the same exception we make for Let's Encrypt as a
trust anchor. Secure-VPN is the user's own code, but it builds on the audited
`cryptography` library (X25519, Ed25519, ChaCha20-Poly1305, HKDF) rather than
hand-rolled ciphers. Do **not** reimplement its crypto.

## Topology

```
  Mac                              public internet                 ALEX-DESKTOP (box)
  +-------------------+                                           +------------------------+
  | browser            |                                         | selfhost proxy :443     |
  |  https://admin.…   |  name -> 127.0.0.1 via scoped resolver  |  (console site, gated   |
  |      | :443        |  (vpn-ui split-DNS on 127.0.0.1:53535)  |   to 127.0.0.1/32)      |
  |      v             |                                         |        ^                |
  | loopback 443 gate  |                                         |        | loopback :443  |
  |  127.0.0.1:443     |   TCP 8443, ChaCha20-Poly1305,          | Secure-VPN server :8443 |
  |      v             |   mutual-auth; silent to anyone         |  (forwards to :443)     |
  | Secure-VPN client  | --------------------------------------->|                         |
  |  127.0.0.1:8443    |   without the client key                |                         |
  +-------------------+                                           +------------------------+
```

- The **only** public port this adds is TCP **8443**. It answers nothing without
  the client's pre-shared Ed25519 key — a scanner sees a socket that never
  completes a handshake. It is part of the box's sanctioned inbound set,
  enumerated in `docs/SECURITY.md` §1 and justified there as VPN-01; that
  document is the authority on what may be forwarded, and it lists nothing else
  for this tunnel.
- The tunnel exits on the box as a **loopback** connection to `:443`. The proxy
  therefore sees `peer.ip() == 127.0.0.1`, which the console site's
  `allowed_cidrs = ["127.0.0.1/32","::1/128"]` admits. Every other source is
  refused with a uniform `404`. Config validation now refuses to *load* a
  console site whose gate is wider than that shape — loopback, RFC 1918, CGNAT
  (`100.64.0.0/10`) or IPv6 unique-local (`fc00::/7`) only, and no IPv4 prefix
  broader than `/24` — so the one line between the internet and the control
  plane cannot be disarmed by an edit that looks harmless
  (`crates/foundation/config/src/validate.rs`; `selfhost doctor` reports the same judgement
  against a running deployment).
- On the Mac, three loopback-only pieces make the **portless** URL work (all
  described under *Using it* below): a **scoped resolver file** sends lookups for
  the one admin name to vpn-ui's embedded **split-DNS responder**
  (`127.0.0.1:53535`), which answers `A = 127.0.0.1`; a **loopback 443 gate**
  then carries the browser's connection from `127.0.0.1:443` to the tunnel's
  local end at `127.0.0.1:8443`. Nothing listens beyond loopback and no other
  name's resolution is touched.
- TLS is **end to end through the tunnel**: the browser speaks TLS to the proxy,
  which serves the real Let's Encrypt certificate for `admin.rockywearsahat.com`;
  the 443 gate and the tunnel are pure passthrough — they never open the bytes.
  The URL carries no port, so the certificate validates against
  `admin.rockywearsahat.com` with no warnings. (This needs a public `A` record
  for `admin.rockywearsahat.com` → the box so ACME can issue the certificate;
  until it exists the console still works over the tunnel but with a self-signed
  cert warning.)

## Defence in depth

1. **Network**: no request from the internet or from the LAN can reach the
   console — the source-IP gate admits only the loopback address the tunnel
   exits on, and answers everything else with the same `404` an unhosted name
   gets.

   > **What that gate does not do.** It is a perimeter against the internet and
   > against the LAN. **It is not a perimeter against the box.** Because the
   > tunnel exits on loopback, `allowed_cidrs = ["127.0.0.1/32","::1/128"]`
   > admits *anything already executing on the machine*: every local account at
   > any privilege level, and every co-hosted upstream application (`blog`,
   > `mayr`, `lvlup`) whose code can be made to fetch a URL. An SSRF or an RCE in
   > any co-hosted app is, by construction, a request the gate admits. So
   > "behind `allowed_cidrs`" never means "authenticated": layers 2–3 below are
   > what actually decide who is admitted, and any future subsystem that can
   > *drive* this machine rather than serve data needs its own credential —
   > a fresh one, not a live session — on top of them. `docs/SECURITY.md` VPN-02
   > carries the same statement; it is written in both places deliberately.
2. **VPN auth**: reaching the tunnel at all requires the client's Ed25519 private
   key; both sides pin the other's public key (no MITM, no unknown clients).
3. **Console password**: a PBKDF2-SHA256 (600k) password login mints an
   HttpOnly/Secure/SameSite=Strict session cookie. Even if the client key leaked,
   the console still demands the password. Cross-site forgery is blocked by a
   required `X-Selfhost-Console` header (the login POST needs it too).
4. **Webhooks and ACME stay public** on the same host — the gate is placed after
   those, so GitHub deploys and certificate renewals keep working.

## What runs where

| Where | What | How |
|-------|------|-----|
| Box | Secure-VPN server | Scheduled task `selfhost-vpn` (SYSTEM, at startup, auto-restart), `scripts/securevpn/install-vpn-service.ps1`. Listens `0.0.0.0:8443`, forwards to `127.0.0.1:443`. |
| Box | keys | `C:\ProgramData\selfhost\securevpn\keys` — `server.key` (private, never leaves), `client.pub` (pins the client). ACL: SYSTEM + Administrators only. |
| Box | firewall + router | Inbound allow `SecureVPN 8443` (not `selfhost-` prefixed, so the reconciler leaves it alone); router forward WAN 8443 -> 192.168.1.8 via `forward-vpn-port.ps1`. |
| Mac | Secure-VPN client | `~/.securevpn/` (`app/`, `venv/`, `keys/`). Driven by the SelfHostVPN app (`crates/ui/vpn-ui`). |
| Upstream | the implementation | `https://github.com/RockyWearsAHat/Secure-VPN.git` — the operator's own project, all of it including `server.py`. This is the source of truth for both ends. |
| Repo | a stamped snapshot | `scripts/securevpn/app/` — `crypto_core.py`, `protocol.py`, `client.py`, `key_manager.py`, `config.py`, vendored 2026-08-17 with SHA-256 digests so an installed copy can be checked against a reviewed one rather than assumed equal. Its `protocol.py` is already a commit behind upstream. |
| Mac | keys | `~/.securevpn/keys` — `client.key` (private), `server.pub` (pins the server). No server private key here. |
| Mac | portless-URL plumbing | Scoped resolver files for gated hosts (admin, sara, ai) + vpn-ui's split-DNS responder (`127.0.0.1:53535`) + launchd-managed loopback 443 gate. See *Using it*. |

**Correction, 2026-09-09 — there is no auto-update for any of this, and there is supposed to be.** An earlier revision of this document (and of `docs/SECURITY.md`) described the three hand-vendored copies above as a *deliberate* security decision — the reasoning given was that an unattended update to a component gating SSH/console access could silently lock the operator out with no recovery path, unlike an ordinary service that just fails and restarts. **That reasoning was invented after the fact to explain an absence, not a decision anyone actually made.** The intended design is that Secure-VPN is managed by selfhost like everything else it deploys — the same self-update discipline `[self_update]` already gives the daemon's own binary — and today it simply isn't wired up that way. The gap became a live incident on 2026-09-09: a protocol change (hybrid X25519+ML-KEM-768, `PROTOCOL_VERSION` 1→2) was implemented directly in this Mac's live `~/.securevpn/app` checkout, which made this Mac's client a protocol version ahead of the box's `server.py` with nothing keeping them in step — both the console tunnel (8443) and a newly-added SSH forwarder (8444) went down simultaneously. Recovery was `git checkout` back to the pre-change commit in the live client directory, by hand. This is tracked as a real gap to close (build-then-verify-then-swap for the vendored copies, box-first ordering, a compiled-extension build story for the Rust/PyO3 ML-KEM module across platforms — see `docs/labs/vpn-lab.dx` for the design work), not as a feature working as intended.

### Relays now start with the daemon, not with `vpn up` (2026-09-09)

**Bug, found live today.** `selfhost vpn up <name>` built its own throwaway `Supervisor` inside the one-shot CLI process, installed the relay's `ServiceSpec` into it, and started the child — then the CLI printed the resulting state and exited within about a second. On Windows the supervisor puts every child it starts into a Job Object for reliable-kill semantics; closing a Job Object kills every process still in it. So the moment the CLI process exited, its Job Object closed, and the relay it had just started died with it — typically 2-3 seconds after `vpn up` printed `state: Starting`/`Running`. Verified live: `vpn up console` returned in ~1.1s, and a `vpn status console` moments later reported `Down` with no such process running. Meanwhile every other supervised service (mail, git-watched apps, `vpn-updater`) stayed up fine, because those are installed into and started by the *daemon's own* long-lived `Supervisor` — the one built once in `serve_everything` and kept alive for the life of the `selfhost daemon`/`selfhost run` process — never a disposable one a CLI subcommand builds for itself.

**Fix.** `serve_everything` (`crates/app/cli/src/main.rs`) now calls `selfhost_vpn::Relays::start_enabled()` (`crates/services/vpn/src/lib.rs`) right after `supervisor.load(&catalog)`, using its own long-lived `supervisor`. That method walks every `[[vpn]]` relay in config, skips any with `enabled = false`, and does what `vpn up` does — but into the daemon's own supervisor, whose Job Object (if any) lives exactly as long as the daemon. One relay's failure (missing keys, no usable peers, the tunnel implementation not installed yet) is logged and does not stop the daemon or any other relay from starting. `vpn-updater` is registered (installed, not started — it is `RestartPolicy::Never`) in the same block whenever at least one relay is declared, unless an operator has already added their own `vpn-updater` entry to `data/services.toml` (that entry is the only place a `webhook_secret` can live, and this fix never overwrites it).

**Convention followed, not invented.** This is a config-reload-requires-restart subsystem, exactly like `[desktop]`, `[dns]`, and `[[shares]]`: editing `enabled`, a relay's peers, or its keys takes effect at the daemon's *next restart*. There is no live reconcile-now path for `[[vpn]]`, and none was added.

**`vpn up`/`vpn down` remain, and are documented as manual, foreground-lifetime tools.** They still build their own one-shot `Supervisor` — that has not changed — but their `--help` text and their printed output now say plainly that a relay `vpn up` starts lives only as long as that command's own process (on Windows, killed by Job Object closure within seconds of the command returning), and that since this fix an `enabled = true` relay is already started by the daemon at boot. Reach for `vpn up`/`down` to diagnose a relay the daemon is not running, or one deliberately left disabled — not to keep a relay up in the background.

**Python PATH resolution issue, discovered and fixed today.** During the cutover to daemon-supervised relays, `vpn-console` and `vpn-ssh` initially landed in state `unstartable`/`backoff`. The daemon's service process launched relays by running a bare `python` command (no full path) — `crates/services/vpn/src/runner.rs`'s `Install::vendored()` on Windows. The box's system-wide (Machine-scope) PATH environment variable contained a stale entry (`C:\Python311\`, which does not exist on disk) and no entry for the *actual* installed Python (`C:\Users\Alex\AppData\Local\Programs\Python\Python312\`, which has the required packages: `cryptography`, `mlkem768`). When the daemon tried to spawn a relay, `python` failed to resolve with Windows error 1920 ("could not start python: The file cannot be accessed by the system"). **Fix applied:** prepended `C:\Users\Alex\AppData\Local\Programs\Python\Python312\` and its `Scripts` subfolder to the box's system-wide PATH, then restarted the daemon. Machine-scope PATH changes take effect only for newly-started processes. This is a durable, box-level fix not stored in git — it persists across reboots and would need reapplication only if the box's PATH is ever reset. Worth flagging for future diagnostics of "vpn relay unstartable": check the daemon's actual visible PATH, not just whether `python.exe` exists somewhere on disk.

**vpn-updater is registered but unarmed.** The auto-update meta-service for Secure-VPN is installed on the box (confirmed via `GET /api/services`, state `stopped`/`exited` — correct for a `RestartPolicy::Never` one-shot). However, it is not yet operational: no `webhook_secret` has been configured (the only place this lives is in `data/services.toml`'s `vpn-updater` entry), and the GitHub App has not yet been confirmed to have the Secure-VPN repository installed. Until an operator supplies both, pushes to the Secure-VPN repo do not trigger automatic updates. The design is code-complete and deployed but operationally dormant — a clearly-scoped next step, not a bug.

**Secure-VPN crypto and sshd key exchange are separate protocol layers; sshd upgraded to post-quantum KEX today.** Secure-VPN itself provides encryption and authentication for the tunnel (hybrid X25519+ML-KEM-768 handshake). The SSH protocol inside the tunnel (sshd on the box's loopback 22, reachable only via the `vpn-ssh` relay's forward on port 8444) uses its own separate key exchange algorithms, independent of and layered on top of Secure-VPN — the VPN just forwards SSH's bytes opaquely. The box's sshd was Microsoft Win32-OpenSSH 9.5.4.1 (built-in Windows Optional Feature), which had zero post-quantum KEX algorithms available (`ssh -Q kex` on that build showed no `sntrup761x25519` or `mlkem768x25519`, versus the Mac client's OpenSSH 10.3 which has both). **Upgraded sshd.exe and supporting binaries to Microsoft Win32-OpenSSH 10.0.0.0p2-Preview** (official vendor build from github.com/PowerShell/Win32-OpenSSH, incorporating upstream OpenSSH 10.0p2 — not custom/hand-rolled crypto). Verified live via `ssh -v` from the Mac: the connection now negotiates `kex algorithm mlkem768x25519-sha256`, and the client's "not using a post-quantum key exchange algorithm" warning is gone. The original 9.5.4.1 binaries are backed up at `C:\Users\Alex\Downloads\OpenSSH-backup-20260909` on the box for rollback if needed. Note: the release used is tagged "Preview" upstream, not GA/stable — worth a periodic check for a stable release with the same PQ support to migrate to later.

## Using it

Open the SelfHostVPN app (`crates/ui/vpn-ui`), **Connect**, then **Open Admin
Console** — it opens `https://admin.rockywearsahat.com` (no port). Log in with
the console password. The console is reachable only while the tunnel runs.

Three Mac-side, loopback-only pieces make the portless URL work:

- **Scoped resolver** — a one-time privileged setup (one admin prompt) installs
  scoped resolver files for each gated host (`/etc/resolver/admin.rockywearsahat.com`,
  `/etc/resolver/sara.rockywearsahat.com`, `/etc/resolver/ai.rockywearsahat.com`)
  each containing `nameserver 127.0.0.1` and `port 53535`, so macOS sends lookups
  for those three names to the responder below. The same setup deletes legacy
  /etc/hosts lines for all gated hosts and installs the launchd-managed 443 gate.
- **Split-DNS responder** — vpn-ui answers on `127.0.0.1:53535` for three gated
  hosts: `A admin.rockywearsahat.com = 127.0.0.1`, `A sara.rockywearsahat.com = 127.0.0.1`,
  `A ai.rockywearsahat.com = 127.0.0.1`; an empty `NOERROR` for `AAAA` queries; and
  `REFUSED` for any other name. It never forwards, caches, or answers for
  anything else.
- **Loopback 443 gate** — `com.selfhost.console-gate`, a root LaunchDaemon
  (binary `/Library/PrivilegedHelperTools/com.selfhost.console-gate`, source
  `crates/ui/vpn-ui/src/bin/console-gate.rs`, stderr
  `/var/log/selfhost-console-gate.log`) holding the *specific* `127.0.0.1:443`
  beside the proxy's wildcard `*:443` and passing the TLS bytes straight through
  to the tunnel's local end at `127.0.0.1:8443` — TLS stays end-to-end, the far
  certificate stays valid. The installer verifies with `lsof` that the gate is
  the loopback `:443` listener and fails loudly rather than touch the proxy.

Caveats: scoped resolvers are honoured by mDNSResponder/getaddrinfo (browsers,
curl) but **not** by `dig`/`nslookup` — verify with
`dscacheutil -q host -a name admin.rockywearsahat.com`. With the app closed, the
name falls through to public DNS and the proxy answers its uniform 404 — same
as before this plumbing existed.

**Uninstall mirror** (`KeepAlive` means bootout alone does not remove it):

```sh
sudo launchctl bootout system/com.selfhost.console-gate
sudo rm /Library/LaunchDaemons/com.selfhost.console-gate.plist
sudo rm /Library/PrivilegedHelperTools/com.selfhost.console-gate
sudo rm /etc/resolver/admin.rockywearsahat.com
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```

**iPhone**: the same mutual-auth model applies. A `client` identity was generated
for the phone; import its key into a Secure-VPN iOS client (or run the client on
a laptop tethered to the phone). Off the home LAN, the endpoint
`rockywearsahat.com:8443` resolves to the public IP; on the LAN, split-horizon
DNS resolves it to `192.168.1.8`. Either way it reaches the same server.

## Key rotation / revoking a device

Keys are pinned by public value. To revoke a device, regenerate the server's
`client.pub` set without that device's key and restart `selfhost-vpn`; the
revoked key can no longer complete a handshake. To rotate the server key,
regenerate `server.key`/`server.pub` on the box, restart the service, and
distribute the new `server.pub` to each client.

## Fixes applied to Secure-VPN — all four are upstream now

**Corrected 2026-08-17.** This section used to say the deployed copy carried four
fixes over upstream and that two of them lived in a `server.py` "not in the
repository", so they could only be taken on trust. Both halves were wrong.
Secure-VPN is the operator's own repository —
`https://github.com/RockyWearsAHat/Secure-VPN.git` — and a clone of it shows all
four fixes present: `client.py` there is byte-identical to
`scripts/securevpn/app/client.py`, and its `server.py` carries the leftover
buffer, the 256-connection cap, the 30-second handshake deadline and `--key-dir`.
They can be read, and they have been. The four are still listed because they
explain *why* the code is shaped this way:
1. **Per-connection sessions.** Upstream multiplexes every local connection over
   one shared tunnel to one target socket — fine for a single SSH session, but a
   browser's parallel connections would interleave and corrupt. Each local
   connection now opens its own VPN session (matching the server's existing
   per-connection-target model).
2. **Handshake leftover-buffer fix.** The server's handshake read could pull the
   client's first request (coalesced with `CLIENT_AUTH` in one TCP segment) into
   a buffer that was then discarded, stranding that request. The leftover is now
   carried into the tunnel loop.
3. **Pre-auth DoS hardening.** A connection cap (256) and an overall 30s handshake
   deadline stop an unauthenticated slow-drip from exhausting the server.
4. **`--key-dir` flag** so the server/client can run as a service with keys
   outside `~/.securevpn`.

## Validation checklist (all verified live)

- Handshake: client preflight prints "server authenticated".
- Console over VPN: `https://admin.rockywearsahat.com/` (portless, via the
  Mac-side resolver + 443 gate) -> `200`, `ssl_verify_result 0`.
- No VPN: direct `https://admin.rockywearsahat.com/` and `http://...` -> `404`;
  `rockywearsahat.com` itself stays publicly `200`.
- Login: wrong password -> `401`; correct -> `200` + session cookie; authed
  `/api/services` -> `200`.
- Other sites (`blog`, `mayr`, `lvlup`) and webhooks unaffected.
- Concurrency: 60/60 requests at 10-way parallel through the tunnel.

## Verified 2026-09-09 — Mac client repin + app rebuild, end-to-end state

**Note on how this section was written**: dx_append and dx_edit both reported success
against this document while silently failing to persist any change (the raw
`docs/VPN.md` file's mtime never advanced; only the small `docs/VPN.md.dx` pointer
file changed) — filed as dx bugs report-81241c0c and report-3feccada. This section was
added with a direct file edit instead, the only way left to get it written at all.

**Correction to the plan this pass was asked to verify**: the plan/done blocks named
(`plan-stated-intent-not-yet-done-mac-client-repin-to-v2-app-rebuild-2026-09-09-2`,
`paragraph-59`, `numbered-list-60`) do **not exist anywhere in this document** — no
earlier turn in this task actually appended them, despite the documentation-first
mandate above requiring it. Nothing in `~/.securevpn/app` was ever committed to the
plan's stated target (`289324b`) either. This section states what is actually true as
of this verification, replacing the missing ones.

**Secure-VPN client checkout (`~/.securevpn/app`, separate non-dx repo)** — re-checked live:

- `git status --short` still shows: `M crypto_core.py`, `M protocol.py`, `?? mlkem768/`.
- `git log -1` HEAD is still `437108e` ("Many peers, enrolled without restarting the
  tunnel") — the pre-hybrid-handshake / protocol-v1 commit. It was **never reset or
  committed to `289324b`** (protocol v2, fixed KAT bug) as the plan called for. The
  working tree is exactly the same dirty, mixed state recorded before this task started.
- Despite that, `python3 client.py rockywearsahat.com --port 8443 --local-port 12443`
  run fresh right now still succeeds: `✓ Handshake complete, server authenticated,
  secure tunnel ready`, and the local SSH proxy comes up on `127.0.0.1:12443`. This
  works *only* because the uncommitted `protocol.py`/`crypto_core.py` modifications
  already are the v2 (289324b-content) files — the handshake is riding on uncommitted
  working-tree state, not a clean commit. A `git stash`, `git checkout .`, or any
  accidental revert of this tree would silently drop back to v1 and break the handshake
  against the box (which is permanently v2 now) with no warning until the next connect
  attempt.
- `mlkem768` still imports cleanly from
  `/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages/mlkem768/__init__.py`.
- Rebuilding the Mac apps did **not** touch this checkout — confirmed, `git status` is
  unchanged from before that work.

**Mac apps** — both executables now carry today's date, confirmed live:

- `/Applications/SelfHostVPN.app/Contents/MacOS/selfhost-vpn-ui` — Sep 9 23:36.
- `/Applications/Selfhost Console.app/Contents/MacOS/selfhost-console` — Sep 9 23:36.
- Both are rebuilt against today's `crates/ui/vpn-ui` / `crates/ui/console` changes.
  Not independently checkable headlessly (GUI apps, no stdout/stderr on launch).

**Closed, 2026-09-09 (later the same day):** the "one accidental commit away from
breaking" risk above is resolved. `~/.securevpn/app` was cleanly checked out to
`289324b` (`git checkout 289324b -- .` then `git checkout 289324b`) — `git status`
reports nothing dirty, no leftover uncommitted files, and `mlkem768/` is now the real
checked-out crate directory that commit carries, not a stray debug artifact. Re-verified
after the clean checkout: `mlkem768`'s own KAT suite (`cargo test --release` in
`mlkem768/`) passes (3/3), and a live handshake against `rockywearsahat.com:8443`
succeeds — "Handshake complete, server authenticated, secure tunnel ready" — confirming
the client is durably on v2, matching the box's two permanently-v2 relays, with no
dependency on an uncommitted working tree surviving.

**ONE remaining manual step for the human**: open `/Applications/SelfHostVPN.app` and
`/Applications/Selfhost Console.app` and confirm on screen that Connect / the console
UI actually work — that cannot be verified headlessly. Everything below the GUI layer
(client repo state, protocol version, both app binaries rebuilt from current source) is
now verified.
