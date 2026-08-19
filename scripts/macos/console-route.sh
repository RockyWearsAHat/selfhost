#!/bin/bash
# console-route.sh — controls for every link of this Mac's route to the console.
#
# The portless console URL (https://admin.rockywearsahat.com/) reaches the box
# through five links on this machine, in order:
#
#   1. /etc/resolver/admin.rockywearsahat.com  — scoped resolver → 127.0.0.1:53535
#   2. a split-DNS responder on 53535          — answers the one name with 127.0.0.1
#      (the SelfHost VPN app runs one for its lifetime; `up` runs a headless twin
#      when the app is closed, same one-name stub, REFUSED for every other name)
#   3. com.selfhost.console-gate               — root LaunchDaemon, 127.0.0.1:443 → 8443
#   4. the Secure-VPN client                   — local 8443 → the box's VPN server
#   5. the console site itself, and the MCP door behind it (~/.selfhost/agent-token)
#
# Any one of those down makes every MCP tool call from this Mac fail — and which
# one is down decides whether the failure is a 10s DNS timeout (responder), an
# instant refusal (tunnel), or a 401 (token). This script exists so nobody has to
# rediscover that chain by hand again.
#
#   status   probe every link, name the broken one and its fix; exit 0 iff the
#            MCP door answers end-to-end
#   up       put every automatable link in the right state, headless: install
#            the client if missing, start the responder if nothing answers on
#            53535, start the tunnel if 8443 is closed, then prove end-to-end
#   down     stop what `up` started (never the app's own responder or tunnel)
#   enrol    first-time or lost-key identity enrolment: generate a client key,
#            pin it on the box over SSH (the recovery channel), verify a real
#            handshake, roll back on any failure
#
# Nothing here needs sudo: the gate is launchd-kept from its one-time install,
# the responder port (53535) and the tunnel port (8443) are unprivileged.
set -euo pipefail

CONSOLE_HOST="admin.rockywearsahat.com"
RESPONDER_PORT=53535
GATE_PORT=443
TUNNEL_PORT=8443
SERVER_HOST="${SECUREVPN_SERVER:-rockywearsahat.com}"
SERVER_PORT="${SECUREVPN_PORT:-8443}"
BOX_SSH="${SECUREVPN_BOX_SSH:-alexdesktop}"
BOX_KEYDIR='C:/ProgramData/selfhost/securevpn/keys'
REPO="${SECUREVPN_REPO:-https://github.com/RockyWearsAHat/Secure-VPN.git}"

BASE="$HOME/.securevpn"
APP="$BASE/app"
KEYS="$BASE/keys"
VENV="$BASE/venv"
RUN="$BASE/run"
TOKEN="$HOME/.selfhost/agent-token"
RESOLVER_FILE="/etc/resolver/$CONSOLE_HOST"
RESOLVER_BODY="nameserver 127.0.0.1
port $RESPONDER_PORT"

ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m✗\033[0m %s\n' "$*"; }
off()  { printf '· %s\n' "$*"; }
fix()  { printf '    \033[2mfix:\033[0m %s\n' "$*"; }
say()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# TCP connect probe, 2s. Succeeds iff something accepts on host:port.
can_connect() { nc -z -G 2 "$1" "$2" >/dev/null 2>&1; }

# Ask the responder directly, bypassing the system resolver.
responder_answer() {
  dig +short +time=1 +tries=1 -p "$RESPONDER_PORT" "$CONSOLE_HOST" @127.0.0.1 2>/dev/null || true
}

# The console over the route the system actually uses (name resolution included).
console_http_code() {
  # curl's write-out prints 000 itself on a failed transfer; never add a second.
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://$CONSOLE_HOST/" 2>/dev/null || true
}

# The MCP door: the same GET /api/sites the sites_list tool performs.
door_http_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "Authorization: Bearer $(cat "$TOKEN")" \
    "https://$CONSOLE_HOST/api/sites" 2>/dev/null || true
}

# ── the headless split-DNS responder ─────────────────────────────────────────
# The same one-name stub the app runs (crates/ui/vpn-ui/src/dns.rs): A for the
# console host is 127.0.0.1, any other type for it is an empty NOERROR, every
# other name is REFUSED. Loopback-only, per docs/SECURITY.md. The app's own
# responder takes priority: `up` starts this only when 53535 is silent, and the
# app reports (rather than fails) if it later finds the port held.
RESPONDER_TAG="console-route-responder"

responder_py() {
  cat <<'PYEOF'
import socket, struct, sys

HOST = sys.argv[1].lower()
PORT = int(sys.argv[2])

def qname(data, at):
    parts = []
    while True:
        n = data[at]
        if n == 0:
            return ".".join(parts), at + 1
        at += 1
        parts.append(data[at:at + n].decode("ascii", "replace"))
        at += n

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", PORT))
while True:
    try:
        data, peer = sock.recvfrom(512)
        name, end = qname(data, 12)
        qtype, qclass = struct.unpack(">HH", data[end:end + 4])
        question = data[12:end + 4]
        if name.lower() != HOST:
            # REFUSED: this is a one-name stub, not a resolver.
            head = struct.pack(">HHHHHH", struct.unpack(">H", data[:2])[0],
                               0x8005, 1, 0, 0, 0)
            sock.sendto(head + question, peer)
            continue
        if qtype == 1:  # A → 127.0.0.1, authoritative
            head = struct.pack(">HHHHHH", struct.unpack(">H", data[:2])[0],
                               0x8400, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
            sock.sendto(head + question + answer, peer)
        else:  # empty authoritative NOERROR: no such record, fall back to v4
            head = struct.pack(">HHHHHH", struct.unpack(">H", data[:2])[0],
                               0x8400, 1, 0, 0, 0)
            sock.sendto(head + question, peer)
    except Exception:
        continue
PYEOF
}

# ── status ───────────────────────────────────────────────────────────────────
status() {
  local broken=0

  # 1. the resolver file
  if [ "$(cat "$RESOLVER_FILE" 2>/dev/null)" = "$RESOLVER_BODY" ]; then
    ok "resolver — $RESOLVER_FILE → 127.0.0.1:$RESPONDER_PORT"
  else
    bad "resolver — $RESOLVER_FILE missing or not exact"
    fix "open the SelfHost VPN app and press Open Console (its one-time privileged install)"
    broken=1
  fi

  # 2. the responder behind it
  local answer; answer="$(responder_answer)"
  if [ "$answer" = "127.0.0.1" ]; then
    local who="app"
    pgrep -f "$RESPONDER_TAG" >/dev/null 2>&1 && who="headless ($RESPONDER_TAG)"
    ok "responder — $CONSOLE_HOST → 127.0.0.1 on :$RESPONDER_PORT ($who)"
  else
    bad "responder — nothing answers on 127.0.0.1:$RESPONDER_PORT; the console name is a 10s DNS timeout on this Mac"
    fix "$0 up   (or open the SelfHost VPN app, whose responder runs for its lifetime)"
    broken=1
  fi

  # 3. the gate
  if can_connect 127.0.0.1 "$GATE_PORT"; then
    ok "gate — 127.0.0.1:$GATE_PORT accepts (com.selfhost.console-gate, launchd-kept)"
  else
    bad "gate — nothing accepts on 127.0.0.1:$GATE_PORT"
    fix "sudo launchctl bootstrap system /Library/LaunchDaemons/com.selfhost.console-gate.plist; bind errors land in /var/log/selfhost-console-gate.log"
    broken=1
  fi

  # 4. the client install and identity
  if [ -f "$APP/client.py" ] && [ -x "$VENV/bin/python" ]; then
    ok "client — $APP + venv installed"
  else
    bad "client — ~/.securevpn has no runnable Secure-VPN client"
    fix "$0 up   (clones $REPO and builds the venv)"
    broken=1
  fi
  if [ -f "$KEYS/client.key" ] && [ -f "$KEYS/server.pub" ]; then
    ok "identity — $KEYS/client.key + server.pub present"
  else
    bad "identity — no client key on this Mac; the box cannot recognise it"
    fix "$0 enrol   (generates a key, pins it on the box over SSH, verifies a handshake)"
    broken=1
  fi

  # 5. the tunnel
  if can_connect 127.0.0.1 "$TUNNEL_PORT"; then
    ok "tunnel — 127.0.0.1:$TUNNEL_PORT accepts (client → $SERVER_HOST:$SERVER_PORT)"
  else
    bad "tunnel — nothing listens on 127.0.0.1:$TUNNEL_PORT; the gate has nowhere to splice"
    fix "$0 up   (or press Connect in the SelfHost VPN app)"
    broken=1
  fi

  # 6. end to end: the console, then the MCP door behind it
  local code; code="$(console_http_code)"
  if [ "$code" != "000" ]; then
    ok "console — https://$CONSOLE_HOST/ answers ($code) through the route above"
  else
    bad "console — https://$CONSOLE_HOST/ does not answer through the local route"
    broken=1
  fi

  if [ ! -f "$TOKEN" ]; then
    bad "door — no agent token at $TOKEN"
    fix "on the box: selfhost agent add <name> --grant site.admin, then place the token here (mode 600)"
    broken=1
  elif [ "$code" = "000" ]; then
    off "door — unprobed while the console is unreachable"
  else
    local door; door="$(door_http_code)"
    if [ "$door" = "200" ]; then
      ok "door — GET /api/sites with the agent token → 200; MCP tools work from this Mac"
    else
      bad "door — GET /api/sites with the agent token → $door (401 means the token is not an agent credential the box accepts)"
      broken=1
    fi
  fi

  # Context, not a link: whether the box is even on this network.
  if can_connect 192.168.1.8 443; then
    off "(LAN: the box answers 192.168.1.8:443 directly — you are at home)"
  else
    off "(LAN: 192.168.1.8 unreachable — off-network, the tunnel is the only path)"
  fi

  return $broken
}

# ── up ───────────────────────────────────────────────────────────────────────
up() {
  mkdir -p "$RUN"

  # The client, from nothing — same layout join-mac.sh and the app share.
  if [ ! -f "$APP/client.py" ]; then
    say "installing the Secure-VPN client"
    mkdir -p "$BASE"
    git clone --quiet --depth 1 "$REPO" "$APP" || die "could not clone $REPO"
  fi
  if [ ! -x "$VENV/bin/python" ]; then
    say "building its Python environment"
    python3 -m venv "$VENV" || die "could not create $VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
    "$VENV/bin/pip" install --quiet cryptography || die "could not install cryptography"
  fi

  # The responder needs no identity, so it comes up first: with it, a broken
  # tunnel fails in milliseconds at the gate instead of a 10s DNS timeout.
  # Only if nothing already answers — the app's own responder has priority.
  if [ "$(responder_answer)" != "127.0.0.1" ]; then
    say "starting the headless split-DNS responder on 127.0.0.1:$RESPONDER_PORT"
    responder_py > "$RUN/$RESPONDER_TAG.py"
    nohup python3 "$RUN/$RESPONDER_TAG.py" "$CONSOLE_HOST" "$RESPONDER_PORT" \
      > "$RUN/responder.log" 2>&1 &
    echo $! > "$RUN/responder.pid"
    sleep 1
    [ "$(responder_answer)" = "127.0.0.1" ] || die "the responder did not come up — $RUN/responder.log"
  fi

  [ -f "$KEYS/client.key" ] && [ -f "$KEYS/server.pub" ] \
    || die "no identity on this Mac — run: $0 enrol (the responder stays up meanwhile)"

  # The tunnel, only if 8443 is closed.
  if ! can_connect 127.0.0.1 "$TUNNEL_PORT"; then
    say "starting the tunnel: 127.0.0.1:$TUNNEL_PORT → $SERVER_HOST:$SERVER_PORT"
    nohup "$VENV/bin/python" -u "$APP/client.py" "$SERVER_HOST" \
      --port "$SERVER_PORT" --local-host 127.0.0.1 --local-port "$TUNNEL_PORT" \
      --identity client --peer server --key-dir "$KEYS" \
      > "$RUN/tunnel.log" 2>&1 &
    echo $! > "$RUN/tunnel.pid"
    local up=""
    for _ in $(seq 1 20); do
      grep -qE "tunnel active|proxy listening" "$RUN/tunnel.log" 2>/dev/null && { up=1; break; }
      grep -qiE "Handshake (error|failed)|Connection (failed|refused)|key mismatch" "$RUN/tunnel.log" 2>/dev/null && break
      sleep 0.5
    done
    if [ -z "$up" ]; then
      tail -5 "$RUN/tunnel.log" >&2 || true
      die "the tunnel did not come up — $RUN/tunnel.log ('key mismatch' means: $0 enrol)"
    fi
  fi

  # The scoped resolver caches for TTL=60s; a flush makes the switch immediate.
  dscacheutil -flushcache 2>/dev/null || true

  say "verifying end to end"
  status
}

# ── down ─────────────────────────────────────────────────────────────────────
# Stops only what `up` started; the app's own responder and tunnel are its.
down() {
  local stopped=0
  for piece in tunnel responder; do
    if [ -f "$RUN/$piece.pid" ]; then
      kill "$(cat "$RUN/$piece.pid")" 2>/dev/null && { ok "stopped the $piece"; stopped=1; } || true
      rm -f "$RUN/$piece.pid"
    fi
  done
  pkill -f "$RESPONDER_TAG" 2>/dev/null && stopped=1 || true
  [ "$stopped" = 1 ] || off "nothing of ours was running"
  off "note: with no responder, $CONSOLE_HOST is a 10s DNS timeout on this Mac (the resolver file scopes it to :$RESPONDER_PORT)"
}

# ── enrol ────────────────────────────────────────────────────────────────────
# First-time (or lost-key) version of rotate-keys.sh: there is no working key to
# fall back to, so the rollback restores the BOX's previous pin, proving over
# SSH — the channel independent of the VPN — that a failed enrolment changes
# nothing that used to work.
enrol() {
  [ -x "$VENV/bin/python" ] && [ -f "$APP/key_manager.py" ] \
    || die "install the client first: $0 up (it stops at enrol if keys are missing)"

  local stamp backup
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup="$KEYS/.enrol-backup-$stamp"
  mkdir -p "$KEYS" "$backup"
  chmod 700 "$KEYS"

  say "1/4  backing up the box's current pinned key (if any)"
  scp -q "$BOX_SSH:$BOX_KEYDIR/client.pub" "$backup/box-client.pub" 2>/dev/null \
    && ok "saved $backup/box-client.pub" \
    || off "the box pins no client key yet"

  say "2/4  generating a fresh client identity"
  SECUREVPN_KEY_DIR="$KEYS" "$VENV/bin/python" - "$KEYS" <<PYEOF
import sys
from pathlib import Path
sys.path.insert(0, "$APP")
from key_manager import KeyManager
km = KeyManager(Path(sys.argv[1]))
km.generate_identity("client")
print(km.export_public_key("client"))
PYEOF
  chmod 600 "$KEYS/client.key"

  say "3/4  pinning it on the box and fetching the server's key"
  scp -q "$KEYS/client.pub" "$BOX_SSH:$BOX_KEYDIR/client.pub" || die "could not push client.pub over SSH"
  scp -q "$BOX_SSH:$BOX_KEYDIR/server.pub" "$KEYS/server.pub" || die "could not fetch server.pub"
  ssh "$BOX_SSH" "Stop-ScheduledTask -TaskName selfhost-vpn; Start-Sleep 2; Start-ScheduledTask -TaskName selfhost-vpn" \
    >/dev/null 2>&1 || die "could not restart the selfhost-vpn task on the box"
  sleep 4

  say "4/4  proving a handshake with the new key"
  local verify; verify="$(mktemp)"
  SECUREVPN_KEY_DIR="$KEYS" "$VENV/bin/python" -u "$APP/client.py" "$SERVER_HOST" \
    --port "$SERVER_PORT" --local-host 127.0.0.1 --local-port 18443 \
    --identity client --peer server --key-dir "$KEYS" > "$verify" 2>&1 &
  local vpid=$!
  local proved=""
  for _ in $(seq 1 20); do
    grep -q "server authenticated" "$verify" && { proved=1; break; }
    grep -qiE "Handshake (error|failed)|Connection (failed|refused)" "$verify" && break
    sleep 0.5
  done
  kill "$vpid" 2>/dev/null || true

  if [ -z "$proved" ]; then
    tail -5 "$verify" >&2 || true
    rm -f "$verify"
    if [ -f "$backup/box-client.pub" ]; then
      say "ROLLBACK: restoring the box's previous pinned key"
      scp -q "$backup/box-client.pub" "$BOX_SSH:$BOX_KEYDIR/client.pub" || true
      ssh "$BOX_SSH" "Stop-ScheduledTask -TaskName selfhost-vpn; Start-Sleep 2; Start-ScheduledTask -TaskName selfhost-vpn" >/dev/null 2>&1 || true
    fi
    die "the handshake failed; the box is exactly as it was"
  fi
  rm -f "$verify"
  rm -rf "$backup"
  ok "enrolled — this Mac's key is pinned on the box and a real handshake succeeded"
}

case "${1:-status}" in
  status) status ;;
  up)     up ;;
  down)   down ;;
  enrol)  enrol ;;
  *) die "usage: $0 <status|up|down|enrol>" ;;
esac
