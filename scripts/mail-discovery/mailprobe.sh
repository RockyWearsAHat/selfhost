#!/bin/bash
# Drive Mail's "Other Mail Account" sheet on this Mac while every sensor is
# watching, so that for once the failure happens in front of witnesses.
#
# It records what THIS machine does — which hosts it resolves and which sockets
# it opens — because the box's sensors can only see what arrives, and the whole
# question is whether anything is sent. Nothing is saved: the sheet is
# cancelled after the error is read, so no account is created and Mail's
# existing accounts are untouched. The password is a placeholder; discovery
# happens before any credential is checked, and a real secret has no business
# in an experiment.
#
# Usage: mailprobe.sh <address>            e.g. mailprobe.sh alex@rockywearsahat.com
set -u
ADDR="${1:?usage: mailprobe.sh <address>}"
NAME="Discovery Probe"
PASS="not-a-real-password"
WORK="${TMPDIR:-/tmp}/mail-discovery"; mkdir -p "$WORK"

echo "== trigger at $(date -u +%H:%M:%SZ) for $ADDR =="

# Sensor 1: every socket Mail or accountsd opens, sampled fast enough to catch
# a connection that is opened and dropped inside a second.
( for _ in $(seq 1 120); do
    /usr/sbin/lsof -nP -i -a -c Mail -c accountsd 2>/dev/null \
      | awk 'NR>1 {print $1, $9, $10}'
    sleep 0.25
  done ) | sort -u > "$WORK/sockets.txt" &
SOCKETS=$!

# Sensor 2: what the account machinery says about itself.
log stream --style compact --info \
    --predicate 'process == "Mail" OR process == "accountsd" OR process == "mDNSResponder"' \
    > "$WORK/logstream.txt" 2>/dev/null &
LOGGER=$!

osascript <<APPLESCRIPT
tell application "Mail" to activate
delay 2
tell application "System Events" to tell process "Mail"
    click menu item "Add Account…" of menu 1 of menu bar item "File" of menu bar 1
    delay 2
    -- The provider chooser: pick the manual path, then Continue.
    try
        click radio button "Other Mail Account…" of radio group 1 of sheet 1 of window 1
    end try
    try
        click button "Continue" of sheet 1 of window 1
    end try
    delay 2
    -- Name, address, password, then Sign In.
    set fields to text fields of sheet 1 of window 1
    if (count of fields) ≥ 2 then
        set value of item 1 of fields to "$NAME"
        set value of item 2 of fields to "$ADDR"
    end if
    try
        set value of text field 1 of sheet 1 of window 1 to "$PASS"
    end try
    delay 1
    try
        click button "Sign In" of sheet 1 of window 1
    end try
    delay 8
    -- Read whatever the sheet now says: that text is the finding.
    set report to ""
    try
        repeat with e in (entire contents of sheet 1 of window 1)
            try
                set report to report & (description of e) & " | " & (value of e) & linefeed
            end try
        end repeat
    end try
    return report
end tell
APPLESCRIPT

echo "== sheet cancelled, nothing saved =="
osascript -e 'tell application "System Events" to tell process "Mail" to click button "Cancel" of sheet 1 of window 1' 2>/dev/null

sleep 2; kill $SOCKETS $LOGGER 2>/dev/null

echo "== sockets Mail/accountsd opened =="
grep -v "127.0.0.1\|\[::1\]" "$WORK/sockets.txt" 2>/dev/null | tail -30
echo "== names looked up, and what the account machinery said =="
grep -iE "rockywearsahat|configuration\.ls|imap|smtp|autodiscover" "$WORK/logstream.txt" 2>/dev/null | tail -30
echo "== now run verdict.sh to see what reached the box =="
