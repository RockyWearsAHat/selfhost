#!/bin/bash
# Every 5 minutes, snapshot the box's DNS capture and speak only when a remote
# peer asks our authority a *client-discovery* question — the SRV names, the
# autoconfig hostnames, or anything from Apple's own address space. Those are
# the questions only a mail client or a provider's backend asks; ordinary
# crawler and NS-refresh traffic is silent.
#
# Address space alone is not the test: a backend may resolve through a public
# resolver, in which case the source is Google's or Cloudflare's, not 17/8.
# The question asked is the signal; the source only says who asked it.
#
# Also speaks when the rig itself breaks, because silence must mean "armed and
# nothing seen", never "the watcher died".
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DISCOVERY='_imaps\._tcp|_submissions?\._tcp|autodiscover|autoconfig|Q .*(mail|imap|smtp)\.rockywearsahat'

while true; do
  out=$("$HERE/verdict.sh" rockywearsahat 2>&1)

  if ! grep -q "re-armed" <<<"$out"; then
    echo "WATCHER BROKEN at $(date -u +%H:%M:%SZ): capture did not re-arm"
    tail -3 <<<"$out"
  fi

  # Drop the household's own machines: they are the trigger, not the discovery.
  hits=$(grep -E "^[0-9:]+Z Q " <<<"$out" | grep -v " 192\.168\." \
         | grep -E "$DISCOVERY")
  [ -n "$hits" ] && { echo "DISCOVERY QUESTION at $(date -u +%H:%M:%SZ):"; echo "$hits"; }

  apple=$(grep -E "^[0-9:]+Z Q 17\.[0-9]" <<<"$out")
  [ -n "$apple" ] && { echo "APPLE ADDRESS SPACE (17/8) at $(date -u +%H:%M:%SZ):"; echo "$apple"; }

  sleep 300
done
