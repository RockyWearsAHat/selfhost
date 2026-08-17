#!/bin/zsh
# security-watchdog.zsh — scheduled security self-check for the Self-Host box.
#
# Contract: run every 15 min by launchd agent com.selfhost.watchdog as the login
# user (no sudo). Detects and alerts on:
#   1. NEW wildcard (*.port) TCP listeners vs an approved baseline (default-deny)
#   2. sshd auth failures in the unified log above a threshold
#   3. any change to launchd plists (~/Library/LaunchAgents, /Library/LaunchAgents,
#      /Library/LaunchDaemons) vs a hash baseline
#   4. daily: public-IP drift, Spamhaus ZEN DNSBL listing (prior XBL+CSS history),
#      and hairpin reachability of ports that must never answer publicly
#
# State + log: ~/.selfhost-watchdog/   Alerts: ALERT line in watchdog.log + macOS
# notification. Run with --approve to accept the CURRENT listeners/plists as the
# new baseline after an intended change.

set -u
STATE="$HOME/.selfhost-watchdog"
LOG="$STATE/watchdog.log"
LOOKBACK_MIN=16                                  # keep >= launchd StartInterval
SSH_FAIL_THRESHOLD=5
CLOSED_PORTS=(22 3306 8000 24444 25565 25575)    # must never answer on public IP
mkdir -p "$STATE"

ts()    { date '+%Y-%m-%d %H:%M:%S'; }
note()  { print -r -- "$(ts) INFO  $1" >> "$LOG"; }
alert() {
  print -r -- "$(ts) ALERT $1" >> "$LOG"
  /usr/bin/osascript -e "display notification \"${1//\"/}\" with title \"Self-Host watchdog\"" >/dev/null 2>&1
}

snapshot_listeners() {
  netstat -an | awk '$NF=="LISTEN" && $4 ~ /^\*\./ {print $4}' | sort -u
}
snapshot_plists() {
  shasum -a 256 \
    "$HOME"/Library/LaunchAgents/*.plist(N) \
    /Library/LaunchAgents/*.plist(N) \
    /Library/LaunchDaemons/*.plist(N) 2>/dev/null | sort -k2
}

if [[ "${1:-}" == "--approve" ]]; then
  snapshot_listeners > "$STATE/listeners.baseline"
  snapshot_plists   > "$STATE/plists.baseline"
  note "baselines re-approved by operator"
  print "watchdog baselines re-approved (listeners + plists)."
  exit 0
fi

# --- 1. wildcard listeners: diff against approved baseline (default-deny) ------
snapshot_listeners > "$STATE/listeners.now"
if [[ ! -f "$STATE/listeners.baseline" ]]; then
  cp "$STATE/listeners.now" "$STATE/listeners.baseline"
  note "listener baseline created: $(tr '\n' ' ' < "$STATE/listeners.baseline")"
else
  new=$(comm -13 "$STATE/listeners.baseline" "$STATE/listeners.now")
  gone=$(comm -23 "$STATE/listeners.baseline" "$STATE/listeners.now")
  for addr in ${(f)new}; do
    port=${addr##*.}
    owner=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1"/"$2}')
    alert "NEW wildcard listener $addr${owner:+ owner=$owner} — internet-exposed once router forwards; run --approve only if intended"
  done
  [[ -n "$gone" ]] && note "listener(s) gone: $(print -r -- "$gone" | tr '\n' ' ')"
fi

# --- 2. sshd auth failures (unified log; requires admin-group user) ------------
# /usr/bin/log absolute path is load-bearing: zsh's builtin `log` shadows it.
fails=$(/usr/bin/log show --last "${LOOKBACK_MIN}m" --style compact \
  --predicate 'process CONTAINS[c] "sshd" AND (eventMessage CONTAINS "Failed" OR eventMessage CONTAINS "Invalid user" OR eventMessage CONTAINS "Connection closed by authenticating" OR eventMessage CONTAINS "maximum authentication attempts")' \
  2>/dev/null | grep -c sshd)
(( fails > SSH_FAIL_THRESHOLD )) && alert "sshd: $fails auth-failure lines in last ${LOOKBACK_MIN}m — possible brute force"
(( fails > 0 && fails <= SSH_FAIL_THRESHOLD )) && note "sshd auth-failure lines: $fails"

# --- 3. launchd plist integrity ------------------------------------------------
snapshot_plists > "$STATE/plists.now"
if [[ ! -f "$STATE/plists.baseline" ]]; then
  cp "$STATE/plists.now" "$STATE/plists.baseline"
  note "launchd plist baseline created ($(wc -l < "$STATE/plists.now" | tr -d ' ') plists)"
elif ! diff -q "$STATE/plists.baseline" "$STATE/plists.now" >/dev/null; then
  changed=$(diff "$STATE/plists.baseline" "$STATE/plists.now" | awk '/^[<>]/ {print $NF}' | sort -u | tr '\n' ' ')
  alert "launchd plists changed: $changed — persistence vector; inspect, then --approve if intended"
fi

# --- 4. daily: public IP drift, Spamhaus ZEN, hairpin port check ---------------
today=$(date +%F)
last=""; [[ -f "$STATE/daily.stamp" ]] && last=$(<"$STATE/daily.stamp")
if [[ "$last" != "$today" ]]; then
  ip=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null)
  if [[ "$ip" == [0-9]*.[0-9]*.[0-9]*.[0-9]* ]]; then
    prev=""; [[ -f "$STATE/public.ip" ]] && prev=$(<"$STATE/public.ip")
    [[ -n "$prev" && "$prev" != "$ip" ]] && alert "public IP changed $prev -> $ip — re-verify DNS, forwards, and RBL status"
    print -r -- "$ip" > "$STATE/public.ip"

    # Spamhaus ZEN (this box's former IP 172.83.7.210 was XBL+CSS listed).
    # 127.255.255.x return codes mean the query was refused (open/public
    # resolver or rate limit) — use the ISP/own resolver or Spamhaus DQS.
    rev=$(print -r -- "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
    res=$(dig +short "$rev.zen.spamhaus.org" A 2>/dev/null | tr '\n' ' ')
    case "$res" in
      (*127.255.255.*) note "Spamhaus query refused ($res) — resolver is public/open; switch resolver or use DQS" ;;
      (*127.0.0.*)     alert "Spamhaus ZEN LISTING for $ip: $res — delist and hunt outbound abuse NOW" ;;
      (*)              note "Spamhaus ZEN clean for $ip" ;;
    esac

    # Hairpin reachability: CLOSED_PORTS must not answer on the public IP.
    # Caveat: NAT loopback may differ from a true external vantage — treat a
    # clean result as best-effort, an open result as certain trouble.
    open_ports=""
    for p in $CLOSED_PORTS; do
      nc -z -G 3 "$ip" "$p" >/dev/null 2>&1 && open_ports+="$p "
    done
    [[ -n "$open_ports" ]] && alert "closed-set ports ANSWERING on public IP (hairpin test): $open_ports"
    note "daily checks done for $ip"
  else
    note "daily: could not determine public IP (offline?)"
  fi
  print -r -- "$today" > "$STATE/daily.stamp"
fi

exit 0
