#!/bin/bash
# rotate-keys.sh — rotate the Secure-VPN client identity key, safely.
#
# Two layers of key freshness protect this tunnel:
#   * Session keys already rotate on EVERY connection — each session derives new
#     ephemeral X25519 keys (perfect forward secrecy). Nothing to do there.
#   * This script rotates the long-term Ed25519 *identity* key that the two ends
#     pin. Run it on a schedule (the Mac app does, weekly) or by hand.
#
# The dance is now entirely in-band, over the ordinary VPN port — no SSH, no
# admin credential, nothing an operator holds that an ordinary enrolled peer
# (this identity, "dad", or anyone enrolled later) does not also hold:
#   1. Generate a fresh client keypair on the Mac.
#   2. Authenticate to the server with the CURRENT key (an ordinary handshake)
#      and hand it the new public key over that same already-authenticated,
#      already-encrypted session (client.py --rotate-new-key). The server can
#      only ever replace the identity that handshake just proved possession
#      of — see protocol.py's `PacketType.ROTATE_REQUEST` docstring for the
#      full argument for why this is safe to expose to every peer, not just
#      whoever holds admin/SSH access.
#   3. Switch the Mac to the new key and prove a full handshake succeeds.
#   4. On success, drop the backup.
#
# Rollback only ever covers step 1-2: if generating the new identity fails,
# or the server refuses the rotate request, nothing on either end has
# changed and the backup is simply restored (a no-op, since nothing moved
# yet). Once step 2 succeeds the server already has the NEW key — from that
# point on, restoring the Mac's OLD key file would be the bug, not the fix:
# it would strand this Mac authenticating with a key the server no longer
# accepts, which is a real lock-out where none existed before. So step 3
# disarms the rollback before switching, and a step 4 verification failure
# is reported as exactly what it is — the server already made the switch,
# investigate connectivity — never "helpfully" undone.
#
# What this replaced: earlier versions of this script used direct SSH to the
# box (`Stop/Start-ScheduledTask`), which SSH-02 (docs/SECURITY.md) firewalls
# even from the LAN; then a version that opened its own SSH-02 admin tunnel
# (port 8444 -> loopback 22) to push the new key as a file over SSH exec,
# which worked but meant only whoever held admin SSH access to the box could
# ever rotate a key — wrong for a VPN other people (e.g. "dad") are also
# meant to use themselves. Neither restarts anything either way: the box's
# `Roster.current()` (server.py) watches each pinned name's own `.pub` file
# mtime, so a rotated key is authoritative from its very next handshake.
#
# Usage:  rotate-keys.sh [--server <host>] [--port <p>] [--identity <name>]
set -euo pipefail

SERVER="${SECUREVPN_SERVER:-rockywearsahat.com}"
PORT="${SECUREVPN_PORT:-8443}"
IDENTITY="${SECUREVPN_IDENTITY:-client}"
VPN_HOME="${SECUREVPN_HOME:-$HOME/.securevpn}"
KEYDIR="$VPN_HOME/keys"
PY="$VPN_HOME/venv/bin/python"
APP="$VPN_HOME/app"
STAMP="$(date +%Y%m%d-%H%M%S)"

while [ $# -gt 0 ]; do
  case "$1" in
    --server)   SERVER="$2"; shift 2;;
    --port)     PORT="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

log() { echo "[rotate] $*"; }
for f in "$PY" "$APP/key_manager.py" "$KEYDIR/$IDENTITY.key"; do
  [ -e "$f" ] || { echo "missing $f"; exit 1; }
done

BACKUP="$KEYDIR/.rotate-backup-$STAMP"
mkdir -p "$BACKUP"
cp "$KEYDIR/$IDENTITY.key" "$KEYDIR/$IDENTITY.pub" "$BACKUP/"
log "backed up current $IDENTITY key -> $BACKUP"

restore() {
  log "ROLLBACK: restoring the previous key here (nothing on the box needs undoing — see header)"
  cp "$BACKUP/$IDENTITY.key" "$KEYDIR/$IDENTITY.key"
  cp "$BACKUP/$IDENTITY.pub" "$KEYDIR/$IDENTITY.pub"
  log "previous key restored; the tunnel is unchanged"
}
trap 'restore' ERR

# --- 1. Generate a fresh identity into a temp dir -----------------------------
NEWDIR="$(mktemp -d)"
# `generate_identity` itself prints its own "✓ Identity ... saved" lines
# (key_manager.py's `save_identity`), so the base64 key this needs is only
# ever the LAST line of output -- never the whole captured stdout.
NEW_PUB_B64="$(SECUREVPN_KEY_DIR="$NEWDIR" "$PY" - "$NEWDIR" "$IDENTITY" <<'PYEOF' | tail -n 1
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".securevpn" / "app"))
from key_manager import KeyManager
km = KeyManager(Path(sys.argv[1]))
km.generate_identity(sys.argv[2])
print(km.export_public_key(sys.argv[2]))
PYEOF
)"
log "generated a new $IDENTITY identity"

# --- 2. Authenticate with the CURRENT key, hand over the new one, in-band ----
log "authenticating with the current key and requesting rotation…"
SECUREVPN_KEY_DIR="$KEYDIR" "$PY" -u "$APP/client.py" "$SERVER" --port "$PORT" \
  --identity "$IDENTITY" --peer server --rotate-new-key "$NEW_PUB_B64"
log "the server accepted the new key"

# --- 3. Switch the Mac to the new key ----------------------------------------
# The rollback is disarmed *before* touching anything further: the server
# already committed to the new key in step 2, so from here on "restoring"
# the Mac's old key would create the very mismatch this trap exists to
# prevent, not undo one. See the header for the full argument.
trap - ERR
cp "$NEWDIR/$IDENTITY.key" "$KEYDIR/$IDENTITY.key"
cp "$NEWDIR/$IDENTITY.pub" "$KEYDIR/$IDENTITY.pub"
chmod 600 "$KEYDIR/$IDENTITY.key"
rm -rf "$NEWDIR"

# --- 4. Prove a handshake with the new key -----------------------------------
log "verifying a handshake with the new key…"
VERIFY_LOG="$(mktemp)"
SECUREVPN_KEY_DIR="$KEYDIR" "$PY" -u "$APP/client.py" "$SERVER" --port "$PORT" \
  --local-host 127.0.0.1 --local-port 18443 --identity "$IDENTITY" --peer server >"$VERIFY_LOG" 2>&1 &
VPID=$!
ok=""
for _ in $(seq 1 20); do
  if grep -q "server authenticated" "$VERIFY_LOG"; then ok=1; break; fi
  if grep -qiE "Handshake (error|failed)|Connection (failed|refused)" "$VERIFY_LOG"; then break; fi
  sleep 0.5
done
kill "$VPID" 2>/dev/null || true
rm -f "$VERIFY_LOG"
if [ -z "$ok" ]; then
  echo "verification handshake with the new key FAILED, but the server already" >&2
  echo "switched to it in step 2 and so has this Mac (step 3) -- both ends agree," >&2
  echo "so the old key was deliberately NOT restored (that would create a" >&2
  echo "mismatch, not fix one). This looks like a connectivity problem, not a" >&2
  echo "key problem: check the network/server, or run rotate-keys.sh again to" >&2
  echo "issue a fresh key once connectivity is confirmed." >&2
  exit 1
fi

# --- 5. Success ---------------------------------------------------------------
rm -rf "$BACKUP"
# Record the rotation time where the Mac app reads it.
defaults write com.selfhost.vpn lastKeyRotation -string "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>/dev/null || true
log "rotation complete — new $IDENTITY key is live and verified"
