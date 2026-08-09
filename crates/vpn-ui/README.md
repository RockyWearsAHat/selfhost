# selfhost-vpn-ui — the desktop VPN panel

A small native window, built in this project's own `rui` toolkit (the same one
behind the console), that brings up the Secure-VPN tunnel and opens the admin
console. It reads as one machine with the console: the same instrument palette,
the same hairline rules and status lamps.

Render its looks any time with `cargo run -p selfhost-vpn-ui -- --render <dir>`
(see the end of this file).

## What it does

- **Connect / Disconnect** the tunnel. The hero at the top *is* the status: two
  nodes and the link between them — dormant and dashed when off, a charge
  travelling along it while it reaches the server, solid and breathing when up,
  broken when it fails.
- **Open Admin Console** — adds `127.0.0.1 admin.rockywearsahat.com` to
  `/etc/hosts` (one password prompt) and opens `https://admin.rockywearsahat.com:8443`.
  Enabled only while the tunnel is up.
- **Keys** — shows the client and server identity fingerprints and when the key
  last rotated. **Rotate now** runs the safe rotation; **AUTO** rotates the
  identity key weekly on its own. (Session keys already rotate every connection.)

It never blocks: the tunnel client runs as a child process and the slow actions
(rotation, the console's password prompt) run off the window thread, reported
back through a shared state the window reads each frame — the console's pattern.

## Build and run

```sh
crates/vpn-ui/build-app.sh          # -> target/SelfHostVPN.app  (+ installs the rotate script)
open target/SelfHostVPN.app         # or drag it into /Applications
```

Or run it straight from cargo during development:

```sh
cargo run -p selfhost-vpn-ui
```

## Prerequisites

The panel drives the Secure-VPN client installed under `~/.securevpn/`:

- `~/.securevpn/venv/bin/python` and `~/.securevpn/app/client.py` — the client.
- `~/.securevpn/keys/client.key` + `server.pub` — this machine's identity and
  the pinned server key.
- `~/.securevpn/rotate-keys.sh` — the rotation script (`build-app.sh` copies it).
- **macOS Local Network permission.** On the LAN the endpoint resolves to the
  box's private address (split-horizon DNS), so the app needs Local Network
  access. Reinstalling the bundle resets that grant, and until it is restored
  every connect fails with `[Errno 65] No route to host`: click Allow on the
  prompt, then **relaunch the app** — the grant only takes effect on a fresh
  launch.

See `docs/VPN.md` for how those are set up and the tunnel's security model.

## Reviewing the looks

The `rui` renderer is pure, so the window can be drawn with no display:

```sh
cargo run -p selfhost-vpn-ui -- --render /tmp/shots
# writes vpn-offline.png, vpn-dialling.png, vpn-connected.png, vpn-failed.png
```
