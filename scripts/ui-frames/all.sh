#!/bin/bash
# all.sh — render every frame of the reports account app.
#
# Run this from an ordinary shell, NOT from inside a dx block: Chrome cannot start under the
# dx sandbox. It reaches for the real ~/Library/Application Support/Google/Chrome and, worse,
# builds its ProcessSingleton socket inside the per-user Darwin temp directory that
# NSTemporaryDirectory() hands out — neither is reachable, and Chrome aborts before it draws
# anything ("Failed to create socket directory"). The dx block in reports-ui-lab.dx therefore
# verifies freshness rather than rendering: it fails if any frame here is older than the
# three files it depicts.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
made=0
failed=0

run() {
  local theme="$1" name="$2" state="$3" narrow="$4" size="$5" query="${6:-}"
  if THEME="$theme" NARROW="$narrow" "$HERE/frames.sh" "$name" "$state" "$size" "$query" \
      >/dev/null 2>&1; then
    made=$((made + 1)); printf '  %-20s %s\n' "$name" "$theme"
  else
    failed=$((failed + 1)); printf '  %-20s FAILED\n' "$name"
  fi
}

run dark  checking           checking.js           ""  1000,520
run dark  anon               anon.js               ""  1000,1200
run dark  anon-plain         anon-plain.js         ""  1000,900
run dark  dash-file          dash-file.js          ""  1180,1220
run dark  dash-unverified    dash-unverified.js    ""  1180,800
run dark  mine-list          mine-list.js          ""  1180,760
run dark  mine-empty         mine-empty.js         ""  1000,620
run dark  account            account.js            ""  1180,1300
run dark  account-oauth-only account-oauth-only.js ""  1180,1000
run dark  download           download.js           ""  1000,760
run dark  verify             verify.js             ""  1000,520 "?token=demo"
run dark  unavailable        unavailable.js        ""  1000,460
run dark  mine-expanded      mine-expanded.js      ""  1180,1100
run dark  withdraw-confirm   withdraw-confirm.js   ""  1180,1100
run dark  ratelimited        ratelimited-driven.js ""  1000,900
run light anon-light         anon.js               ""  1000,1200
run light mine-light         mine-list.js          ""  1180,760
run dark  mobile-anon        anon.js               390 560,1100
run dark  mobile-dash        mine-list.js          390 560,940

echo "$made rendered, $failed failed"
exit $((failed > 0))
