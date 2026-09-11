# Fix: SelfHostVPN.app's tunnel had no reconnect supervisor — it just gave up

2026-09-11. Traced the ongoing "the VPN keeps glitching, SSH keeps flaking out" complaint to a real, fixed client-side bug — separate from the 2026-09-10 Windows Update reboot incident and from a same-night misdiagnosis (below).

## What was actually wrong

`crates/ui/vpn-ui/src/tunnel.rs`'s `Tunnel::connect()` was a **one-shot spawn**: it launched the Secure-VPN Python client once, read its output onto a `Link` the window draws, and if that child process ever exited on its own — a dropped connection, a laptop sleep/wake, a transient network blip, anything — the tunnel simply reported `Phase::Failed` and sat there. Nothing brought it back. The user had to notice the app said `FAILED` and press Connect again by hand every time.

This is the direct cause of "the VPN keeps glitching, it should be steadfast": it was never actually reconnecting on its own. Compare `crates/ui/console/src/tunnel.rs`, which already had exactly the right pattern (`keep_open`, exponential backoff via `retry_delay`, a `running` flag distinguishing an intentional stop from a drop) — `vpn-ui`'s tunnel manager had simply never been given the same treatment.

## A same-night misdiagnosis, corrected

Earlier the same session, a constant "SSH->VPN error: [WinError 64]" spam in the `vpn-ssh` relay's log (roughly every 13 seconds, for hours) was initially suspected as a server-side defect. It was traced instead to a leftover diagnostic `client.py` process left running from an earlier part of the session on this Mac — killing it stopped the spam immediately, confirmed by watching the log go quiet. That specific spam was self-inflicted noise from manual diagnostics, not a product defect. It is recorded here only so a future reader does not go looking for a phantom every-13-seconds bug in the relay itself — there wasn't one.

The real, user-facing bug was the missing reconnect supervisor above, which is a separate thing from that log noise and was still there regardless of it.

## The fix

The operator was explicit about the shape wanted: **not** an always-on background daemon — a connectable/disconnectable client like an ordinary VPN toggle — but one that, once connected, actually stays connected without needing a human to notice a drop.

`crates/ui/vpn-ui/src/tunnel.rs`:
- `Tunnel` no longer owns a `Child` and `reader` directly. It owns a `wanted: Arc<AtomicBool>` (what the user last asked for) and a `supervisor: JoinHandle` running a new `keep_open` loop, mirroring `crates/ui/console/src/tunnel.rs`'s function of the same name and the same `retry_delay`/`MAX_RETRY` (30s ceiling, doubling from 1s) backoff.
- `connect()` sets `wanted` and starts the supervisor once (idempotent — a double-press does not spawn a second client).
- `disconnect()` clears `wanted` *first*, which is exactly what tells the supervisor loop an exit is intentional rather than a drop to recover from, then joins the thread and kills the child.
- A connection that reached `Phase::Up` before dropping resets the failure counter to 0 before retrying — a laptop waking from sleep should retry immediately, not inherit a long backoff from whatever state came before it slept.
- `spawn_client`/`real_python` factored out so `keep_open` takes the interpreter path as a parameter — this is what makes the new behavior actually testable: `crates/ui/vpn-ui/src/tunnel.rs`'s tests now include `a_client_that_drops_on_its_own_is_relaunched_without_being_asked` and `disconnecting_stops_the_client_instead_of_relaunching_it`, both driving `keep_open` against a stub script exactly the way `crates/ui/console/src/tunnel.rs`'s existing `closing_the_console_takes_the_tunnel_with_it` test drives its own `keep_open`. Both new tests pass.

`scripts/securevpn/mac-auto-update.sh`:
- The old step 4 force-killed any running `client.py` (`sudo -n pkill -f "client.py.*--identity"`) and relaunched it by hand immediately after an update landed on disk — a deliberate, visible disconnect for the sake of adopting new code a few minutes sooner. With the reconnect supervisor above now in the picture, this would additionally **race** it: a `pkill` here fires at the same moment the app's own supervisor notices the drop and relaunches its child, both potentially trying to bind the same local port at once.
- Replaced with: touch nothing that is currently connected. The verified new code is already on disk once this line is reached (the KAT-gated staged build in steps 2-3 is unchanged); a running Python process only reads `client.py` at process start, so it keeps running its already-loaded old code, uninterrupted, until it reconnects for any ordinary reason — and a fresh interpreter at that point reads whatever is on disk then, i.e. the update. No connection is ever killed by this script to make that happen sooner. This is the "zero downtime" the operator asked for: an update never disrupts a live session; it is simply what a process gets automatically the next time it (re)connects on its own.

## Verified

- `cargo test -p selfhost-vpn-ui`: 25 passed, including the two new reconnect tests, which actually drive a stub client process being killed and relaunched (not just asserting on state transitions).
- `cargo test --lib --workspace --exclude selfhost-presence`: every crate's library tests pass (`selfhost-presence` excluded only for its pre-existing, unrelated macOS Objective-C linker issue on this dev machine — not something this change touched).
- `cargo build --release -p selfhost-vpn-ui` and `cargo check --workspace`: clean.
- `scripts/securevpn/mac-auto-update.sh`: `bash -n` syntax-checked; the deployed copy at `~/.securevpn/mac-auto-update.sh` on this Mac was synced to match the repo source (they were previously byte-identical, so this is the same script the LaunchAgent already runs).

## Outstanding

- The rebuilt `SelfHostVPN.app` has not yet been reinstalled/relaunched on this Mac to pick up the new tunnel.rs behavior — the currently-running app in `/Applications` still has the old one-shot logic in memory. `crates/ui/vpn-ui/build-app.sh` (already fixed 2026-09-09/10 for its `../..` → `../../..` path bug) rebuilds and reinstalls the bundle.
- The broader "copy to a stable install location separate from the live/build path" idea the operator raised is only partially addressed here: Python's own import model already makes an in-place `git pull` safe for an already-running interpreter (it never re-reads `client.py` after start), so the actual risk was the forced restart, not the file layout — which is why this fix targets the restart, not a new versioned-install-directory scheme. If a future need arises to hot-swap the interpreter itself (not just the script it runs), a staged-directory-plus-symlink scheme would be the next step, but nothing found today required it.
