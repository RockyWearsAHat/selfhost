#!/bin/bash
# frames.sh <name> <state.js> <W,H> [url-query]
#
# Photograph one state of the reports account app, offline and reproducibly, at both
# densities — 2x into <dir>/<name>.png and a true 1x rasterisation into <dir>/web/<name>.png,
# the same two-real-renders rule the native console harness follows (console-lab.dx).
#
#   THEME=dark|light     which colour scheme to photograph (default: light)
#   NARROW=390           photograph a phone-width viewport (see the note below)
#   SELFHOST_FRAME_DIR   where the frames land (default: target/ui-frames)
#
# Everything this script writes lands under the frame directory — the injected copy of the
# page, the copies of its assets, and Chrome's throwaway profile. Nothing is written beside
# the real page and nothing is written to the system temp directory, so the whole harness
# runs inside a dx block that has been granted `writes=target` and nothing else.
set -u
ROOT=/Users/alexwaldmann/Desktop/Self-Host
ASSETS="$ROOT/crates/reports/assets"
DIR="${SELFHOST_FRAME_DIR:-$ROOT/target/ui-frames}"
HERE="$(cd "$(dirname "$0")" && pwd)"

NAME="$1"; STATE="$2"; SIZE="$3"; QUERY="${4:-}"
case "$STATE" in
  /*) ;;
  *) STATE="$HERE/states/$STATE" ;;
esac

WORK="$DIR/work/$NAME"
rm -rf "$WORK"
mkdir -p "$WORK" "$DIR/web"

# The page is copied into the work directory together with the assets it names relatively,
# so app.css, app.js and favicon.svg resolve by exactly the paths they resolve by in
# production without the harness ever writing into the crate.
cp "$ASSETS/app.css" "$ASSETS/app.js" "$ASSETS/favicon.svg" "$WORK/"
# The state file goes first: the stub library reads window.__STATE as it loads.
python3 "$HERE/inject.py" "$ASSETS/index.html" "$WORK/index.html" "$STATE" \
  "$HERE/stub-lib.js" >/dev/null || exit 1

URL="file://$WORK/index.html$QUERY"

# Headless Chrome refuses a window narrower than 500 CSS pixels, so a phone-width frame
# cannot be taken by shrinking the window: the layout viewport stays 500 and the screenshot
# merely clips it, which reads as a page that overflows when it does not. A phone frame is
# therefore an iframe of the exact width, photographed inside a wider window.
if [ -n "${NARROW:-}" ]; then
  HEIGHT="${SIZE#*,}"
  PAPER="#0e0f12"; EDGE="#2e323a"
  [ "${THEME:-}" = "light" ] && { PAPER="#fbfaf7"; EDGE="#dedacf"; }
  cat > "$WORK/narrow.html" <<HTML
<!doctype html><meta charset="utf-8">
<style>
  html, body { margin: 0; height: 100%; background: $PAPER; }
  body { display: grid; place-items: center; }
  iframe { width: ${NARROW}px; height: $((HEIGHT - 40))px; border: 1px solid $EDGE;
           border-radius: 14px; background: $PAPER; }
</style>
<iframe src="index.html$QUERY" title="the app at ${NARROW}px"></iframe>
HTML
  URL="file://$WORK/narrow.html"
fi

SHOT_TMP="$WORK/chrome" DSF=2 "$HERE/shot.sh" "$DIR/$NAME.png"     "$SIZE" "$URL" || exit 1
SHOT_TMP="$WORK/chrome" DSF=1 "$HERE/shot.sh" "$DIR/web/$NAME.png" "$SIZE" "$URL" || exit 1
rm -rf "$WORK"
