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
#   3. Switch the Mac to the new key (atomically: a relay reading it mid-swap
#      sees the old file or the new one, never half of either).
#   4. Prove the server ADMITS the new key (client.py --check: a full session
#      judged by the server's answer, not our own half of the handshake).
#   5. On success, drop the backup and record the time.
#
# No lock-out window: the box keeps the key that asked for the rotation valid
# beside the new one until the new key completes an admitted handshake
# (server.py `Roster.rotate`/`Roster.confirm`), and the Mac's running relays
# re-read the identity file on every session. So a relay still holding the
# old key keeps working through steps 2-4, and step 4's own check is the
# handshake that retires the old key on the box.
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
# `Roster.current()` (server.py) watches every roster name's `.pub` and
# `.retiring.pub` files, so a rotation is seen from the very next handshake.
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
NEW_PUB_B64="$(SECUREVPN_KEY_DIR="$NEWDIR" "$PY" - "$NEWDIR" "$IDENTITY" "$APP" <<'PYEOF' | tail -n 1
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
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
for part in key pub; do
  cp "$NEWDIR/$IDENTITY.$part" "$KEYDIR/.$IDENTITY.$part.new"
done
chmod 600 "$KEYDIR/.$IDENTITY.key.new"
mv -f "$KEYDIR/.$IDENTITY.pub.new" "$KEYDIR/$IDENTITY.pub"
mv -f "$KEYDIR/.$IDENTITY.key.new" "$KEYDIR/$IDENTITY.key"
rm -rf "$NEWDIR"

# --- 4. Prove the server admits the new key ---------------------------------
log "verifying the server admits the new key…"
if ! SECUREVPN_KEY_DIR="$KEYDIR" "$PY" -u "$APP/client.py" "$SERVER" --port "$PORT" \
     --identity "$IDENTITY" --peer server --check; then
  echo "the server did not admit the new key. It still holds the old one beside" >&2
  echo "it, so nothing is locked out; the old key is in $BACKUP. Run" >&2
  echo "rotate-keys.sh again once the box answers." >&2
  exit 1
fi

# --- 5. Success ---------------------------------------------------------------
rm -rf "$BACKUP"
# Record the rotation time where the Mac app reads it.
defaults write com.selfhost.vpn lastKeyRotation -string "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>/dev/null || true
log "rotation complete — new $IDENTITY key is live and verified"
