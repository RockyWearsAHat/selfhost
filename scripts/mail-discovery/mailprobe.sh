#!/bin/bash
# Drive Mail's "Other Mail Account" sheet on this Mac while every sensor is
# watching, so that for once the failure happens in front of witnesses.
#
# It records what THIS machine does — which sockets Mail and accountsd open,
# and what Mail's own IMAP/account log says — because the box's sensors can
# only see what arrives, and the whole question is whether anything is sent.
# It finishes by asking the box what reached it in the same seconds.
#
# Nothing is saved: the sheet is cancelled after its contents are read, so no
# account is created and Mail's existing accounts are untouched. The password
# is a placeholder; discovery happens before any credential is checked, and a
# real secret has no business in an experiment.
#
# The UI is dumped at every step rather than assumed. Menu titles and sheet
# layouts move between macOS releases, and a probe that dies on a renamed
# button teaches nothing; a probe that prints the tree it found can be fixed
# in one pass. Identifiers avoid System Events' own property names — `container`
# and `line` are properties, and a variable by either name will not compile.
#
# Usage: mailprobe.sh <address>            e.g. mailprobe.sh alex@rockywearsahat.com
#
# With --manual, the script drives nothing: it arms the same sensors, gives you
# ninety seconds to walk the sheet by hand, and then correlates. UI scripting is
# a convenience here, never the experiment — the measurement is what leaves this
# Mac and what reaches the box, and a human finger produces that just as well.
set -u
MANUAL=0
if [ "${1:-}" = "--manual" ]; then MANUAL=1; shift; fi
ADDR="${1:?usage: mailprobe.sh [--manual] <address>}"
NAME="Discovery Probe"
PASS="not-a-real-password"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/mail-discovery"; mkdir -p "$WORK"

# Everything this run prints is also kept, so the transcript can be read back
# instead of copied out of a terminal.
exec > >(tee "$WORK/lastrun.log") 2>&1

echo "== trigger at $(date -u +%H:%M:%SZ) for $ADDR =="

# Sensor 1: every socket Mail or accountsd opens, sampled fast enough to catch
# a connection opened and dropped inside a second. It writes raw and is sorted
# at collection time: piping into `sort` would make $! the sorter's pid, and
# killing the sorter leaves the sampler running.
( for _ in $(seq 1 160); do
    /usr/sbin/lsof -nP -i -a -c Mail -c accountsd 2>/dev/null \
      | awk 'NR>1 {print $1, $9}'
    sleep 0.25
  done ) > "$WORK/sockets.raw" 2>/dev/null &
SOCKETS=$!

# Sensor 2: what the account machinery says about itself, protocol lines and all.
log stream --style compact --info \
    --predicate 'process == "Mail" OR process == "accountsd"' \
    > "$WORK/logstream.txt" 2>/dev/null &
LOGGER=$!

if [ "$MANUAL" = "1" ]; then
  echo
  echo "  DO IT BY HAND NOW — 90 seconds, sensors are recording:"
  echo "    Mail ▸ Add Account… ▸ Other Mail Account… ▸ Continue"
  echo "    Name: anything   Email: $ADDR   Password: anything"
  echo "    ▸ Sign In, wait for the error, then Cancel."
  echo
  for s in $(seq 90 -10 10); do printf "  %ss left\r" "$s"; sleep 10; done
  echo "  time up — collecting                    "
else
osascript <<APPLESCRIPT 2>&1
-- The sheet does not reliably hang off window 1 — Mail has several windows and
-- the chooser attaches to whichever was front. Find the window that owns a
-- sheet, and fall back to the front window only if none does.
on findPane()
    tell application "System Events" to tell process "Mail"
        repeat with w in windows
            try
                return sheet 1 of w
            end try
        end repeat
        try
            return window 1
        end try
    end tell
    return missing value
end findPane

-- A control's label can live in title, name, value or description depending on
-- how the control was built; a radio button in this sheet is not reliably
-- titled. Match across all four, and press rather than click: AXPress is what
-- the control actually implements.
on pressLabeled(uiRoot, wanted)
    tell application "System Events"
        repeat with e in (entire contents of uiRoot)
            try
                set label to ""
                try
                    set label to label & (title of e) & " "
                end try
                try
                    set label to label & (name of e) & " "
                end try
                try
                    set label to label & ((value of e) as text) & " "
                end try
                try
                    set label to label & (description of e)
                end try
                if label contains wanted then
                    try
                        perform action "AXPress" of e
                    on error
                        click e
                    end try
                    return true
                end if
            end try
        end repeat
    end tell
    return false
end pressLabeled

-- `entire contents`, `role`, `title` and friends are System Events terminology:
-- outside a tell block for it they do not even compile, so the handler carries
-- its own.
on dumpTree(uiRoot)
    set report to ""
    tell application "System Events"
        try
            repeat with e in (entire contents of uiRoot)
                try
                    set entry to (role of e)
                    try
                        set entry to entry & " title=" & (title of e)
                    end try
                    try
                        set entry to entry & " desc=" & (description of e)
                    end try
                    try
                        set entry to entry & " value=" & ((value of e) as text)
                    end try
                    set report to report & entry & linefeed
                end try
            end repeat
        end try
    end tell
    return report
end dumpTree

tell application "Mail" to activate
delay 2

tell application "System Events" to tell process "Mail"
    -- "Add Account…" has lived under both the Mail and File menus; find it.
    set opened to false
    repeat with mb in menu bar items of menu bar 1
        try
            repeat with mi in menu items of menu 1 of mb
                if (name of mi) starts with "Add Account" then
                    click mi
                    set opened to true
                    exit repeat
                end if
            end repeat
        end try
        if opened then exit repeat
    end repeat
    if not opened then return "NO ADD-ACCOUNT MENU ITEM FOUND"
    delay 3

    set pane to my findPane()
    if pane is missing value then return "NO SHEET OR WINDOW APPEARED"

    set out to "---- CHOOSER ----" & linefeed & my dumpTree(pane)

    set picked to my pressLabeled(pane, "Other Mail Account")
    set out to out & "picked Other Mail Account: " & picked & linefeed
    delay 1
    set went to my pressLabeled(pane, "Continue")
    set out to out & "pressed Continue: " & went & linefeed
    delay 3

    -- Re-acquire: the sheet is replaced, not edited.
    set pane to my findPane()
    set out to out & "---- CREDENTIAL SHEET ----" & linefeed & my dumpTree(pane)

    -- The fields sit inside groups, so a direct-child lookup finds none of
    -- them. Walk the whole tree in visual order and sort by role: the open
    -- fields are name then address, the secure one is the password.
    -- (`plain` and `secret` are AppleScript constants; naming a variable
    -- either one fails to compile with "Access not allowed".)
    set openFields to {}
    set secureFields to {}
    repeat with e in (entire contents of pane)
        try
            if (role of e) is "AXTextField" then
                if (subrole of e) is "AXSecureTextField" then
                    set end of secureFields to e
                else
                    set end of openFields to e
                end if
            end if
        end try
    end repeat
    try
        if (count of openFields) is greater than or equal to 2 then
            set value of item 1 of openFields to "$NAME"
            set value of item 2 of openFields to "$ADDR"
        end if
        if (count of secureFields) is greater than or equal to 1 then
            set value of item 1 of secureFields to "$PASS"
        end if
    end try
    delay 1

    -- Submit, and give discovery a generous eight seconds to happen.
    set sent to my pressLabeled(pane, "Sign In")
    if not sent then set sent to my pressLabeled(pane, "Continue")
    set out to out & "pressed submit: " & sent & linefeed
    delay 8

    set pane to my findPane()
    set out to out & "---- AFTER SUBMIT ----" & linefeed & my dumpTree(pane)
    return out
end tell
APPLESCRIPT

echo "== cancelling: nothing is saved =="
osascript -e 'tell application "System Events" to tell process "Mail" to keystroke (ASCII character 27)' 2>/dev/null
sleep 1
osascript -e 'tell application "System Events" to tell process "Mail" to click (first button of sheet 1 of window 1 whose title is "Cancel")' 2>/dev/null
fi

# Stop the sensors. A bare `wait` here would block until the sampler's full
# forty seconds elapsed — the run looks finished and the shell never returns.
sleep 2
pkill -P "$SOCKETS" 2>/dev/null
kill "$SOCKETS" "$LOGGER" 2>/dev/null
sort -u "$WORK/sockets.raw" > "$WORK/sockets.txt" 2>/dev/null

echo
echo "== sockets Mail/accountsd held (existing accounts filtered out) =="
grep -v "127.0.0.1\|\[::1\]\|gmail\|google\|icloud\|apple.com" "$WORK/sockets.txt" 2>/dev/null | tail -25

echo
echo "== what Mail said about anything that is not the existing accounts =="
grep -viE "gmail|\[Google\]|icloud" "$WORK/logstream.txt" 2>/dev/null \
  | grep -iE "rockywearsahat|setup|discover|autoconfig|configuration\.ls|Wrote:|Read:|error|fail" \
  | tail -40

echo
"$HERE/verdict.sh" rockywearsahat
