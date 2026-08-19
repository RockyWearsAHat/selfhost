#!/bin/zsh
# harden-perimeter.zsh — idempotent macOS perimeter hardening for the Self-Host box.
# Run as: sudo zsh harden-perimeter.zsh
# Covers: Application Firewall (ALF), SSH key-only drop-in (guarded against lockout),
# rebind guidance for dev listeners, secret-rotation reminders.
# Deliberately does NOT touch the intended public selfhost surface on TCP 80/443.
set -euo pipefail

SFW=/usr/libexec/ApplicationFirewall/socketfilterfw
SCRIPT_DIR="${0:A:h}"

banner() {
  echo
  echo "=============================================================="
  echo "== $1"
  echo "=============================================================="
}

# ---------------------------------------------------------------- preflight
banner "PREFLIGHT"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: must run with sudo (need root for socketfilterfw and /etc/ssh)." >&2
  exit 1
fi
# Resolve the invoking (non-root) user so the authorized_keys guard checks the
# right home directory, not /var/root.
TARGET_USER="${SUDO_USER:-alexwaldmann}"
TARGET_HOME=$(dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory | awk '{print $2}')
echo "Hardening for user: ${TARGET_USER} (home: ${TARGET_HOME})"

# ---------------------------------------------------------------- firewall
banner "1/5 APPLICATION FIREWALL (ALF)"
# Reverse: sudo $SFW --setglobalstate off
"$SFW" --setglobalstate on
# Reverse: sudo $SFW --setstealthmode off
"$SFW" --setstealthmode on
# Reverse: sudo $SFW --setallowsigned on
"$SFW" --setallowsigned off
# Reverse: sudo $SFW --setblockall off   (run this if the public selfhost proxy on 80/443 stops answering)
"$SFW" --setblockall on
echo
echo "NOTE: ALF block-all is app-level, not port-level. If external probes to the"
echo "selfhost proxy on 80/443 start timing out after this, reverse with:"
echo "  sudo $SFW --setblockall off"
echo "and rely on the pf default-deny anchor (NP-1) for per-port filtering instead."
"$SFW" --getglobalstate
"$SFW" --getstealthmode
"$SFW" --getblockall

# ---------------------------------------------------------------- ssh
banner "2/5 SSH HARDENING (guarded)"
AUTH_KEYS="${TARGET_HOME}/.ssh/authorized_keys"
DROPIN=/etc/ssh/sshd_config.d/010-hardening.conf

if [[ ! -s "$AUTH_KEYS" ]]; then
  echo "!! WARNING: ${AUTH_KEYS} is missing or EMPTY."
  echo "!! Disabling password auth now would LOCK YOU OUT of SSH."
  echo "!! Add your public key first (ssh-copy-id ${TARGET_USER}@192.168.1.31), then re-run."
  echo "!! SKIPPING SSH hardening — all other sections still apply."
else
  echo "Guard passed: ${AUTH_KEYS} is non-empty ($(wc -c < "$AUTH_KEYS" | tr -d ' ') bytes)."
  mkdir -p /etc/ssh/sshd_config.d
  # Reverse: sudo rm /etc/ssh/sshd_config.d/010-hardening.conf   (macOS defaults return; if locked out, remove it from the local console — FileVault console login is unaffected)
  cat > "$DROPIN" <<'EOF'
# Self-Host perimeter hardening — sorts before 100-macos.conf; sshd keeps first value set.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  chmod 644 "$DROPIN"
  if ! /usr/sbin/sshd -t; then
    echo "ERROR: sshd -t rejected the config. Removing drop-in, sshd untouched." >&2
    rm -f "$DROPIN"
    exit 1
  fi
  # Reverse: not needed — kickstart only re-reads config; removing the drop-in and kickstarting again reverts.
  launchctl kickstart -k system/com.openssh.sshd 2>/dev/null || true
  echo "Drop-in installed and sshd reloaded (new connections use it immediately)."
  echo ">> Before closing this session: open a NEW terminal and confirm key-based"
  echo ">> 'ssh ${TARGET_USER}@192.168.1.31 true' still works. Also re-test the iOS"
  echo ">> selfhost app's SSH loopback — if it used password auth, it will now fail."
  /usr/sbin/sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin)' || true
fi

# ---------------------------------------------------------------- rebind guidance
banner "3/5 REBIND GUIDANCE (manual — lives in project config, NOT auto-applied)"
cat <<'EOF'
These listeners currently bind the wildcard address. Rebind them to loopback in
their own configs — this script will not edit project files:

1) Demo static server (*:8000, python http.server):
     Change its launch command to bind loopback explicitly:
       python3 -m http.server 8000 --bind 127.0.0.1
     If launched from a LaunchAgent/script, add "--bind 127.0.0.1" to its
     ProgramArguments / command line.

2) Node dev app:
     Bind the dev server to loopback in the project config (package.json script,
     vite/next/express config, or env):
       HOST=127.0.0.1        # env-based servers
       --host 127.0.0.1      # vite / webpack-dev-server flag
       app.listen(PORT, '127.0.0.1')   # raw express/http
     Verify afterwards:  netstat -an | grep LISTEN | grep -E '8000|3000'
     — every dev listener should show 127.0.0.1.*, never *.* .
EOF

# ---------------------------------------------------------------- secrets
banner "4/5 SECRETS TO ROTATE — DO THIS TODAY"
cat <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! 1) GitHub OAuth token  gho_TZ2W...FNoCL  — ASSUME COMPROMISED.
!!    Sat in plaintext in com.engine.server.plist behind *:24444.
!!    Revoke SERVER-SIDE first (local deletion does NOT invalidate it):
!!      open https://github.com/settings/applications
!!      -> Authorized OAuth Apps -> GitHub CLI -> Revoke
!!      gh auth logout --hostname github.com
!!      gh auth login  --hostname github.com --git-protocol https --web
!!    Note: revoking invalidates gh CLI on ALL your devices; re-login each.
!!    Check https://github.com/settings/security-log for use since exposure.
!!
!! 2) ANTHROPIC_API_KEY — a slot for it existed in the same leaked plist.
!!    Rotate at https://console.anthropic.com/settings/keys : create a new
!!    key, update consumers, delete the old key. Store the replacement in
!!    the Keychain (SEC-04 wrapper), never in a LaunchAgent plist.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF

# ---------------------------------------------------------------- public surface
banner "5/5 PUBLIC SURFACE — UNTOUCHED"
echo "TCP 80/443 (selfhost reverse proxy, com.selfhost.proxy) intentionally left"
echo "alone. Router discipline stays: forward ONLY 80/443 -> 192.168.1.31, DHCP"
echo "reservation set, no DMZ, no UPnP/NAT-PMP, never forward 22."

# ---------------------------------------------------------------- verify
banner "DONE — VERIFY"
VERIFY="${SCRIPT_DIR}/verify-hardening.zsh"
if [[ -x "$VERIFY" || -f "$VERIFY" ]]; then
  echo "Running companion verify script: ${VERIFY}"
  zsh "$VERIFY"
else
  echo "No companion verify script at ${VERIFY} — skipping."
  echo "Manual spot-checks:"
  echo "  $SFW --getglobalstate && $SFW --getstealthmode && $SFW --getblockall"
  echo "  sudo /usr/sbin/sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin)'"
fi