#!/bin/bash
# rotate-keys.sh — rotate the Secure-VPN client identity key, safely.
#
# Two layers of key freshness protect this tunnel:
#   * Session keys already rotate on EVERY connection — each session derives new
#     ephemeral X25519 keys (perfect forward secrecy). Nothing to do there.
#   * This script rotates the long-term Ed25519 *identity* key that the two ends
#     pin. Run it on a schedule (the Mac app does, weekly) or by hand.
#
# The dance, made lock-out-proof by using SSH (independent of the VPN) as the
# recovery channel:
#   1. Generate a fresh client keypair on the Mac.
#   2. Back up the current client key here and the pinned client.pub on the box.
#   3. Push the new client.pub to the box and restart the VPN server so it pins
#      the new key.
#   4. Switch the Mac to the new key and prove a full handshake succeeds.
#   5. On success, drop the backups. On ANY failure, restore both ends over SSH
#      and restart — the old key keeps working, so a failed rotation is a no-op.
#
# Usage:  rotate-keys.sh [--box-ssh <alias>] [--server <host>] [--port <p>]
set -euo pipefail

BOX_SSH="${SECUREVPN_BOX_SSH:-alexdesktop}"
SERVER="${SECUREVPN_SERVER:-rockywearsahat.com}"
PORT="${SECUREVPN_PORT:-8443}"
VPN_HOME="${SECUREVPN_HOME:-$HOME/.securevpn}"
KEYDIR="$VPN_HOME/keys"
PY="$VPN_HOME/venv/bin/python"
APP="$VPN_HOME/app"
BOX_KEYDIR='C:/ProgramData/selfhost/securevpn/keys'
STAMP="$(date +%Y%m%d-%H%M%S)"

while [ $# -gt 0 ]; do
  case "$1" in
    --box-ssh) BOX_SSH="$2"; shift 2;;
    --server)  SERVER="$2"; shift 2;;
    --port)    PORT="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

log() { echo "[rotate] $*"; }
for f in "$PY" "$APP/key_manager.py" "$KEYDIR/client.key"; do
  [ -e "$f" ] || { echo "missing $f"; exit 1; }
done

BACKUP="$KEYDIR/.rotate-backup-$STAMP"
mkdir -p "$BACKUP"
cp "$KEYDIR/client.key" "$KEYDIR/client.pub" "$BACKUP/"
log "backed up current client key -> $BACKUP"

# Pull the box's current pinned client.pub so we can restore it on failure.
scp -q "$BOX_SSH:$BOX_KEYDIR/client.pub" "$BACKUP/box-client.pub" || true

restore() {
  log "ROLLBACK: restoring the previous key on both ends"
  cp "$BACKUP/client.key" "$KEYDIR/client.key"
  cp "$BACKUP/client.pub" "$KEYDIR/client.pub"
  if [ -f "$BACKUP/box-client.pub" ]; then
    scp -q "$BACKUP/box-client.pub" "$BOX_SSH:$BOX_KEYDIR/client.pub" || true
    ssh "$BOX_SSH" "Stop-ScheduledTask -TaskName selfhost-vpn; Start-Sleep 2; Start-ScheduledTask -TaskName selfhost-vpn" >/dev/null 2>&1 || true
  fi
  log "previous key restored; the tunnel is unchanged"
}
trap 'restore' ERR

# --- 1. Generate a fresh client identity into a temp dir ---------------------
NEWDIR="$(mktemp -d)"
SECUREVPN_KEY_DIR="$NEWDIR" "$PY" - "$NEWDIR" <<'PYEOF'
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".securevpn" / "app"))
from key_manager import KeyManager
km = KeyManager(Path(sys.argv[1]))
km.generate_identity("client")
print(km.export_public_key("client"))
PYEOF
log "generated a new client identity"

# --- 2. Push new public key to the box, restart the server -------------------
scp -q "$NEWDIR/client.pub" "$BOX_SSH:$BOX_KEYDIR/client.pub"
ssh "$BOX_SSH" "Stop-ScheduledTask -TaskName selfhost-vpn; Start-Sleep 2; Start-ScheduledTask -TaskName selfhost-vpn" >/dev/null 2>&1
sleep 4
log "box now pins the new client key"

# --- 3. Switch the Mac to the new key ----------------------------------------
cp "$NEWDIR/client.key" "$KEYDIR/client.key"
cp "$NEWDIR/client.pub" "$KEYDIR/client.pub"
chmod 600 "$KEYDIR/client.key"

# --- 4. Prove a handshake with the new key -----------------------------------
log "verifying a handshake with the new key…"
VERIFY_LOG="$(mktemp)"
SECUREVPN_KEY_DIR="$KEYDIR" "$PY" -u "$APP/client.py" "$SERVER" --port "$PORT" \
  --local-host 127.0.0.1 --local-port 18443 --identity client --peer server >"$VERIFY_LOG" 2>&1 &
VPID=$!
ok=""
for _ in $(seq 1 20); do
  if grep -q "server authenticated" "$VERIFY_LOG"; then ok=1; break; fi
  if grep -qiE "Handshake (error|failed)|Connection (failed|refused)" "$VERIFY_LOG"; then break; fi
  sleep 0.5
done
kill "$VPID" 2>/dev/null || true
rm -f "$VERIFY_LOG"
[ -n "$ok" ] || { echo "handshake with new key FAILED"; false; }

# --- 5. Success ---------------------------------------------------------------
trap - ERR
rm -rf "$NEWDIR"
rm -rf "$BACKUP"
# Record the rotation time where the Mac app reads it.
defaults write com.selfhost.vpn lastKeyRotation -string "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>/dev/null || true
log "rotation complete — new client key is live and verified"
