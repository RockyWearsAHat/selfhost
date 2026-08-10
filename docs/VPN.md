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
  completes a handshake.
- The tunnel exits on the box as a **loopback** connection to `:443`. The proxy
  therefore sees `peer.ip() == 127.0.0.1`, which the console site's
  `allowed_cidrs = ["127.0.0.1/32","::1/128"]` admits. Every other source is
  refused with a uniform `404`.
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

1. **Network**: only the box's tunnel exit can reach the console (source-IP gate).
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
| Mac | Secure-VPN client | `~/.securevpn/` (`app/`, `venv/`, `keys/`). Driven by the SelfHostVPN app (`crates/vpn-ui`). |
| Mac | keys | `~/.securevpn/keys` — `client.key` (private), `server.pub` (pins the server). No server private key here. |
| Mac | portless-URL plumbing | Scoped resolver `/etc/resolver/admin.rockywearsahat.com` + vpn-ui's split-DNS responder (`127.0.0.1:53535`) + launchd-managed loopback 443 gate. See *Using it*. |

## Using it

Open the SelfHostVPN app (`crates/vpn-ui`), **Connect**, then **Open Admin
Console** — it opens `https://admin.rockywearsahat.com` (no port). Log in with
the console password. The console is reachable only while the tunnel runs.

Three Mac-side, loopback-only pieces make the portless URL work:

- **Scoped resolver** — a one-time privileged setup (one admin prompt) installs
  `/etc/resolver/admin.rockywearsahat.com` containing `nameserver 127.0.0.1` and
  `port 53535`, so macOS sends lookups for that one name — and no other — to the
  responder below. The same setup deletes the legacy
  `127.0.0.1 admin.rockywearsahat.com` line from `/etc/hosts` (the old
  mechanism) and installs the launchd-managed 443 gate.
- **Split-DNS responder** — vpn-ui answers on `127.0.0.1:53535`:
  `A admin.rockywearsahat.com = 127.0.0.1`, an empty `NOERROR` for `AAAA`, and
  `REFUSED` for any other name. It never forwards, caches, or answers for
  anything else.
- **Loopback 443 gate** — `com.selfhost.console-gate`, a root LaunchDaemon
  (binary `/Library/PrivilegedHelperTools/com.selfhost.console-gate`, source
  `crates/vpn-ui/src/bin/console-gate.rs`, stderr
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

## Fixes applied to Secure-VPN (vendored copy on the box)

The deployed copy carries four fixes over upstream; offer them back:
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
