#!/bin/bash
# macos-admin-url.sh — make https://admin.rockywearsahat.com work in a browser
# on this Mac, with the traffic still riding the Secure-VPN tunnel.
#
# The admin console answers only connections that emerge on the box itself, so
# the browser must reach the local Secure-VPN client (127.0.0.1:8443) rather
# than the box directly. Typing a port into the URL is nobody's idea of a
# website, so this script makes the plain name land there:
#
#   1. /etc/hosts maps admin.rockywearsahat.com -> 127.0.0.1, overriding the
#      LAN's split-horizon answer on this machine only.
#   2. A pf rule redirects loopback port 443 -> 8443, where the VPN client
#      listens. Installed as its own anchor referenced from /etc/pf.conf, and
#      enabled at boot by a small LaunchDaemon, so it survives restarts.
#
# The VPN client itself is still managed by SelfHostVPN.app — the URL works
# whenever the tunnel is up, and fails closed (connection refused) when it
# is not.
#
# Usage:  sudo scripts/macos-admin-url.sh          # install (idempotent)
#         sudo scripts/macos-admin-url.sh remove   # undo everything
set -euo pipefail

HOST="admin.rockywearsahat.com"
HOSTS_LINE="127.0.0.1	${HOST}"
ANCHOR="selfhost-admin"
ANCHOR_FILE="/etc/pf.anchors/${ANCHOR}"
ANCHOR_RULE="rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443"
PF_CONF="/etc/pf.conf"
DAEMON="/Library/LaunchDaemons/com.selfhost.pf.plist"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

remove() {
    sed -i '' "/${HOST}/d" /etc/hosts
    sed -i '' "/${ANCHOR}/d" "$PF_CONF"
    rm -f "$ANCHOR_FILE"
    launchctl bootout system "$DAEMON" 2>/dev/null || true
    rm -f "$DAEMON"
    pfctl -q -f "$PF_CONF" 2>/dev/null || true
    echo "removed: hosts entry, pf anchor, boot daemon"
}

install() {
    # 1. The hosts override, once.
    grep -q "$HOST" /etc/hosts || printf '%s\n' "$HOSTS_LINE" >> /etc/hosts

    # 2. The pf anchor: our one redirect rule, in its own file.
    printf '%s\n' "$ANCHOR_RULE" > "$ANCHOR_FILE"

    # Reference it from pf.conf — the rdr-anchor must sit with the other
    # translation rules (pf grammar orders translation before filtering), so
    # it is inserted right after Apple's own rdr-anchor line; the load line
    # is order-free and goes at the end.
    if ! grep -q "rdr-anchor \"${ANCHOR}\"" "$PF_CONF"; then
        sed -i '' "/^rdr-anchor \"com.apple\/\*\"/a\\
rdr-anchor \"${ANCHOR}\"
" "$PF_CONF"
    fi
    grep -q "load anchor \"${ANCHOR}\"" "$PF_CONF" || \
        printf 'load anchor "%s" from "%s"\n' "$ANCHOR" "$ANCHOR_FILE" >> "$PF_CONF"

    # 3. Apply now, and enable pf at every boot (macOS loads pf.conf at boot
    # but leaves pf disabled; the daemon just flips it on).
    pfctl -q -f "$PF_CONF"
    pfctl -q -E 2>/dev/null || true
    cat > "$DAEMON" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.selfhost.pf</string>
    <key>ProgramArguments</key>
    <array><string>/sbin/pfctl</string><string>-E</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST
    launchctl bootstrap system "$DAEMON" 2>/dev/null || true

    echo "installed. https://${HOST} now rides the VPN tunnel whenever it is up."
}

case "${1:-install}" in
    install) install ;;
    remove)  remove ;;
    *) echo "usage: sudo $0 [install|remove]" >&2; exit 1 ;;
esac
