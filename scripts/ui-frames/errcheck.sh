#!/bin/bash
# errcheck.sh — load every state of the app and record whether its script threw.
#
# Run from an ordinary shell (Chrome cannot start inside the dx sandbox; see all.sh). Writes
# one line per state to target/ui-frames/errcheck.txt, which the dx block in reports-ui-lab.dx
# reads as its verdict. A screenshot proves the markup; only this proves the behaviour.
set -u
ROOT=/Users/alexwaldmann/Desktop/Self-Host
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="${SELFHOST_FRAME_DIR:-$ROOT/target/ui-frames}"
OUT="$DIR/errcheck.txt"

STATES="checking anon anon-plain dash-file dash-unverified mine-list mine-expanded withdraw-confirm
        mine-empty account account-oauth-only download verify unavailable ratelimited-driven"

mkdir -p "$DIR"
: > "$OUT"

for state in $STATES; do
  query=""
  [ "$state" = "verify" ] && query="?token=demo"
  work="$DIR/errcheck/$state"
  rm -rf "$work"; mkdir -p "$work"
  cp "$ROOT/crates/reports/assets/app.css" "$ROOT/crates/reports/assets/app.js" \
     "$ROOT/crates/reports/assets/favicon.svg" "$work/"
  python3 "$HERE/inject.py" "$ROOT/crates/reports/assets/index.html" "$work/index.html" \
    "$HERE/states/$state.js" "$HERE/stub-lib.js" "$HERE/errcheck.js" >/dev/null

  "$CHROME" --headless --disable-gpu --no-first-run --no-default-browser-check \
    --disable-crash-reporter --user-data-dir="$work/prof" --virtual-time-budget=2500 \
    --dump-dom "file://$work/index.html$query" </dev/null >"$work/dom.html" 2>/dev/null &
  pid=$!
  # Chrome lingers for minutes after it has printed; take the answer and end it.
  for _ in $(seq 1 150); do
    grep -q 'foot-route' "$work/dom.html" 2>/dev/null && break
    sleep 0.1
  done
  sleep 0.2
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null

  verdict=$(grep -o 'id="foot-route">[^<]*' "$work/dom.html" | head -1 |
            sed 's/id="foot-route">//')
  [ -z "$verdict" ] && verdict="NO ANSWER — the page never finished loading"
  printf '%-22s %s\n' "$state" "$verdict" | tee -a "$OUT"
  rm -rf "$work"
done

rm -rf "$DIR/errcheck"
# One line per state, and every one of them has to be the clean verdict.
! grep -q 'ERRORS\|NO ANSWER' "$OUT"
