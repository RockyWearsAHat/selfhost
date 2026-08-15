#!/bin/bash
# shot.sh <out.png> <W,H> <url>
# Offline, deterministic Chrome-headless screenshot of a local file:// page.
#
# Chrome 151 on macOS writes the PNG promptly but then lingers ~2 min before
# exiting (idle, no CPU). So we do NOT wait for exit: we wait for Chrome's own
# completion line on stderr -- "<N> bytes written to file <path>" -- then kill it.
set -u
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
OUT="$1"; SIZE="$2"; URL="$3"; shift 3
DSF="${DSF:-2}"          # rasterise at 2x (retina), like the native frame harness
CAP="${CAP:-30}"         # seconds to wait for the completion line

# The scratch directory is given by the caller (frames.sh points it inside the frame
# directory) so that this script writes nothing outside the one folder it was granted.
PROF="${SHOT_TMP:-$(mktemp -d)}"
rm -rf "$PROF"
mkdir -p "$PROF"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

"$CHROME" \
  --headless \
  --disable-gpu \
  --no-first-run \
  --no-default-browser-check \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --disable-crash-reporter \
  --disable-extensions \
  --no-pings \
  --metrics-recording-only \
  --use-mock-keychain \
  --user-data-dir="$PROF/prof" \
  --hide-scrollbars \
  --force-device-scale-factor="$DSF" \
  --virtual-time-budget=2000 \
  --window-size="$SIZE" \
  --screenshot="$OUT" \
  "$@" \
  "$URL" </dev/null >"$PROF/out.log" 2>"$PROF/err.log" &
PID=$!

# Poll for Chrome's completion line (10 Hz).
ok=0
for _ in $(seq 1 $((CAP * 10))); do
  if grep -q "bytes written to file" "$PROF/err.log" 2>/dev/null; then ok=1; break; fi
  kill -0 "$PID" 2>/dev/null || { grep -q "bytes written to file" "$PROF/err.log" 2>/dev/null && ok=1; break; }
  sleep 0.1
done

kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

if [ "$ok" != 1 ]; then
  echo "FAILED: no completion line within ${CAP}s" >&2
  sed -n '1,20p' "$PROF/err.log" >&2
  rm -rf "$PROF"; exit 1
fi
rm -rf "$PROF"

# Validate the PNG really terminates (IEND), so a kill never yields a torn file.
python3 - "$OUT" <<'PY' || exit 1
import sys
d = open(sys.argv[1], 'rb').read()
assert d.startswith(b'\x89PNG\r\n\x1a\n'), "not a PNG"
assert d.rstrip().endswith(b'IEND\xaeB`\x82'), "PNG truncated (no IEND)"
print(f"ok {sys.argv[1]} {len(d)} bytes")
PY
