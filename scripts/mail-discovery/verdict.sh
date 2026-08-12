#!/bin/bash
# Snapshot the box's armed DNS capture, decode it, and say who asked about the
# mail domain since the last snapshot. Re-arms the capture before copying, so
# the blind window is the conversion itself (~1s), not the analysis.
#
# Usage: verdict.sh [name-filter]   (default filter: rockywearsahat)
set -u
BOX=Alex@192.168.1.8
KEY=~/.ssh/alexdesktop_ed25519
HERE="$(cd "$(dirname "$0")" && pwd)"
# Captures are evidence, not source: they land outside the checkout.
WORK="${TMPDIR:-/tmp}/mail-discovery"; mkdir -p "$WORK"
FILTER="${1:-rockywearsahat}"
SSH="ssh -o ConnectTimeout=15 -i $KEY $BOX"

echo "== snapshot at $(date -u +%H:%M:%SZ) =="
$SSH "pktmon stop | Out-Null; \
      pktmon etl2pcap C:\\Users\\Alex\\dnswatch.etl -o C:\\Users\\Alex\\dnswatch.pcapng | Select-String 'Packets total'; \
      pktmon start -c --comp nics --pkt-size 512 -f C:\\Users\\Alex\\dnswatch.etl -s 64 -m circular | Out-Null; \
      'recapture re-armed'" 2>&1 | grep -v '^$'

scp -q -o ConnectTimeout=15 -i "$KEY" "$BOX":C:/Users/Alex/dnswatch.pcapng "$WORK/dnswatch.pcapng" || exit 1

echo "== DNS questions about '$FILTER' reaching the box's authority =="
python3 "$HERE/dnsread.py" "$WORK/dnswatch.pcapng" "$FILTER"

echo "== source classification =="
python3 "$HERE/dnsread.py" "$WORK/dnswatch.pcapng" "$FILTER" \
  | awk '$2=="Q" {split($3,a,":"); print a[1]}' | sort -u \
  | while read -r ip; do
      case "$ip" in
        17.*)          tag="APPLE (17.0.0.0/8) — live discovery by Apple" ;;
        192.168.*)     tag="LAN" ;;
        *)             tag="other resolver / client" ;;
      esac
      printf "  %-18s %s\n" "$ip" "$tag"
    done

# Crawlers hammer the example sites all day; only mail-protocol lines and
# requests actually aimed at the mail domain say anything about discovery.
echo "== mail-protocol and mail-domain touches on the box, last 25 non-LAN lines =="
$SSH "Get-Content C:\\Users\\Alex\\Self-Host\\proxy.log -Tail 600" 2>/dev/null \
  | grep -E "\[(imap|submission|smtp)\]|\[access\].*(rockywearsahat|autodiscover|autoconfig)" \
  | grep -v "192\.168\." | tail -25
