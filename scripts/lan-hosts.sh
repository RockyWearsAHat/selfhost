#!/usr/bin/env bash
#
# lan-hosts.sh — make THIS computer resolve the selfhost box's hosted domains to
# its LAN address, so you can browse them from inside the network (NAT hairpin
# makes the public IP time out from home). macOS + Linux.
#
#   ./lan-hosts.sh apply     # add/refresh the entries (asks for sudo)
#   ./lan-hosts.sh remove    # take them back out
#   ./lan-hosts.sh list      # show what would be applied, change nothing
#
# The domain list is pulled LIVE from the box via `selfhost routes` so it stays
# correct as you add sites. Override anything with env vars:
#   SELFHOST_BOX_IP   the box's LAN IP        (default 192.168.1.8)
#   SELFHOST_SSH      ssh host/alias for box  (default alexdesktop)
#   SELFHOST_ROUTES_CMD  remote routes command
#   SELFHOST_DOMAINS  space-separated list; skips SSH entirely (for machines
#                     that can't reach the box over SSH)
set -euo pipefail

BOX_IP="${SELFHOST_BOX_IP:-192.168.1.8}"
SSH_HOST="${SELFHOST_SSH:-alexdesktop}"
ROUTES_CMD="${SELFHOST_ROUTES_CMD:-Set-Location 'C:\\Users\\Alex\\Self-Host'; .\\target\\release\\selfhost.exe routes}"
BEGIN="# >>> selfhost lan-hosts (auto-managed — do not edit inside) >>>"
END="# <<< selfhost lan-hosts <<<"
HOSTS="${HOSTS_FILE:-/etc/hosts}"
mode="${1:-apply}"

# Collect the hosted domain names — real names only (must contain a dot, must not
# be a bare IP), so the box's own IP/localhost entries are skipped.
collect_domains() {
  if [ -n "${SELFHOST_DOMAINS:-}" ]; then
    printf '%s\n' $SELFHOST_DOMAINS
    return
  fi
  ssh -o ConnectTimeout=6 -o BatchMode=yes "$SSH_HOST" "$ROUTES_CMD" 2>/dev/null \
    | awk '{print $1}' \
    | grep -E '\.' \
    | grep -Ev '^[0-9.]+$' \
    | sort -u
}

# Print the hosts file with any previous managed block stripped out.
strip_block() {
  awk -v b="$BEGIN" -v e="$END" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    !skip {print}
  ' "$HOSTS"
}

flush_dns() {
  case "$(uname -s)" in
    Darwin) sudo dscacheutil -flushcache 2>/dev/null || true; sudo killall -HUP mDNSResponder 2>/dev/null || true ;;
    Linux)  sudo resolvectl flush-caches 2>/dev/null || sudo systemd-resolve --flush-caches 2>/dev/null || true ;;
  esac
}

domains="$(collect_domains || true)"

if [ "$mode" = "list" ]; then
  echo "box: $BOX_IP"
  if [ -z "$domains" ]; then echo "(no domains found — is the box reachable? try SELFHOST_DOMAINS=...)"; exit 1; fi
  while IFS= read -r d; do echo "$BOX_IP $d"; done <<< "$domains"
  exit 0
fi

if [ "$mode" = "remove" ]; then
  tmp="$(mktemp)"; strip_block > "$tmp"
  sudo cp "$tmp" "$HOSTS"; rm -f "$tmp"; flush_dns
  echo "removed selfhost entries from $HOSTS"
  exit 0
fi

# apply
if [ -z "$domains" ]; then
  echo "no domains found — the box wasn't reachable over SSH." >&2
  echo "pass them explicitly, e.g.: SELFHOST_DOMAINS=\"rockywearsahat.com www.rockywearsahat.com\" $0 apply" >&2
  exit 1
fi

tmp="$(mktemp)"
strip_block > "$tmp"
{
  echo "$BEGIN"
  while IFS= read -r d; do echo "$BOX_IP $d"; done <<< "$domains"
  echo "$END"
} >> "$tmp"
sudo cp "$tmp" "$HOSTS"; rm -f "$tmp"; flush_dns
echo "applied to $HOSTS:"
while IFS= read -r d; do echo "  $BOX_IP $d"; done <<< "$domains"
