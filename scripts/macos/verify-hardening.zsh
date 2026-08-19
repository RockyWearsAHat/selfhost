#!/bin/zsh
# verify-security.sh — proves this macOS box is locked down.
#
# Contract: runs a fixed battery of security checks and prints one colored
# PASS/FAIL line per check, then a summary. Exits 0 only if every check passed.
#
# Checks:
#   1. Application firewall enabled + stealth mode enabled.
#   2. No unexpected wildcard (*) TCP listeners — only `selfhost` on 80/443 allowed.
#   3. mysqld / mongod / redis / postgres bound to loopback only.
#   4. sshd effective PasswordAuthentication = no (sshd -T, config fallback).
#   5. External reachability of 22 and 3306 on the public IP via the
#      check-host.net TCP API — PASS when filtered/closed from the internet.
#
# Expected values sourced from the machine inventory (2026-08): public IP
# 172.83.6.109; intended public surface is the Self-Host reverse proxy on 80/443.

set -u

readonly PUBLIC_IP="172.83.6.109"
readonly ALLOWED_WILDCARD_CMD="selfhost"
readonly -a ALLOWED_WILDCARD_PORTS=(80 443)
readonly SFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

GREEN=$'\e[32m'; RED=$'\e[31m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
typeset -i PASS_COUNT=0 FAIL_COUNT=0

# pass/fail — print one result line and tally it for the summary/exit code.
pass() { print -r -- "${GREEN}PASS${RESET} $1"; (( PASS_COUNT += 1 )); }
fail() { print -r -- "${RED}FAIL${RESET} $1";  (( FAIL_COUNT += 1 )); }

section() { print -r -- "${BOLD}== $1 ==${RESET}"; }

# ---------------------------------------------------------------------------
# 1. Application firewall: global state on, stealth mode on.
# ---------------------------------------------------------------------------
section "Application firewall"
fw_state=$("$SFW" --getglobalstate 2>/dev/null)
if [[ $fw_state == *"enabled"* ]]; then
  pass "application firewall enabled"
else
  fail "application firewall NOT enabled (${fw_state:-socketfilterfw unavailable})"
fi

fw_stealth=$("$SFW" --getstealthmode 2>/dev/null)
if [[ $fw_stealth == *"enabled"* ]]; then
  pass "stealth mode enabled"
else
  fail "stealth mode NOT enabled (${fw_stealth:-socketfilterfw unavailable})"
fi

# ---------------------------------------------------------------------------
# 2. Wildcard listeners: only selfhost on 80/443 may bind *.
#    lsof NAME column shows wildcard binds as "*:<port>".
# ---------------------------------------------------------------------------
section "Wildcard (*) TCP listeners"
typeset -i wildcard_bad=0 wildcard_seen=0
while IFS= read -r line; do
  wildcard_seen=1
  cmd=${line%% *}
  rest=${line#* }
  pid=${rest%% *}
  name=${rest##* }
  port=${name##*:}
  if [[ $cmd == ${ALLOWED_WILDCARD_CMD}* ]] && (( ${ALLOWED_WILDCARD_PORTS[(Ie)$port]} )); then
    pass "expected public surface: $cmd (pid $pid) on $name"
  else
    fail "unexpected wildcard listener: $cmd (pid $pid) on $name — bind to 127.0.0.1 or stop it"
    wildcard_bad=1
  fi
done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '$9 ~ /^\*:/ {print $1, $2, $9}' | sort -u)
if (( wildcard_seen == 0 )); then
  pass "no wildcard listeners at all"
elif (( wildcard_bad == 0 )); then
  pass "no unexpected wildcard listeners"
fi

# ---------------------------------------------------------------------------
# 3. Databases loopback-only: any LISTEN not on 127.0.0.1/::1 is a FAIL.
# ---------------------------------------------------------------------------
section "Database bind addresses"

# check_loopback <process-prefix> <label> — FAIL if the process listens on any
# non-loopback address; PASS if loopback-only or not running.
check_loopback() {
  local proc=$1 label=$2
  local binds bad="" n
  binds=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null \
          | awk -v p="$proc" 'index($1, p) == 1 {print $9}' | sort -u)
  if [[ -z $binds ]]; then
    pass "$label: no listener (not running)"
    return
  fi
  for n in ${(f)binds}; do
    [[ $n == "127.0.0.1:"* || $n == "[::1]:"* ]] || bad+="$n "
  done
  if [[ -z $bad ]]; then
    pass "$label: loopback only (${${(f)binds}// /,})"
  else
    fail "$label: bound non-loopback: ${bad% }"
  fi
}

check_loopback "mysqld"   "MySQL"
check_loopback "mongod"   "mongod"
check_loopback "redis"    "redis"
check_loopback "postgres" "postgres"

# ---------------------------------------------------------------------------
# 4. sshd: effective PasswordAuthentication must be "no".
#    Prefer sshd -T (effective config); fall back to parsing sshd_config,
#    where a commented directive means the macOS default of "yes".
# ---------------------------------------------------------------------------
section "sshd configuration"
sshd_eff=$(/usr/sbin/sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
if [[ -z $sshd_eff ]]; then
  sshd_eff=$(sudo -n /usr/sbin/sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
fi
if [[ -n $sshd_eff ]]; then
  if [[ $sshd_eff == "no" ]]; then
    pass "sshd PasswordAuthentication no (sshd -T)"
  else
    fail "sshd PasswordAuthentication $sshd_eff (sshd -T) — set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
  fi
else
  if grep -Eqs '^[[:space:]]*PasswordAuthentication[[:space:]]+no' \
       /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*(N); then
    pass "sshd PasswordAuthentication no (sshd_config; sshd -T unavailable)"
  else
    fail "sshd PasswordAuthentication effectively YES (directive absent/commented => macOS default) — set 'PasswordAuthentication no'"
  fi
fi

# ---------------------------------------------------------------------------
# 5. External reachability via check-host.net TCP API.
#    PASS when every reporting node sees the port filtered (timeout) or
#    closed (refused); FAIL if any node completes a TCP connect.
# ---------------------------------------------------------------------------
section "External reachability (check-host.net -> ${PUBLIC_IP})"

# check_external <port> — one PASS/FAIL line for internet reachability of the port.
check_external() {
  local port=$1
  local req rid result verdict=""
  local -i tries=0

  if ! command -v python3 >/dev/null 2>&1; then
    fail "port $port: python3 unavailable, cannot parse check-host.net response"
    return
  fi

  req=$(curl -fsS -m 20 -H "Accept: application/json" \
        "https://check-host.net/check-tcp?host=${PUBLIC_IP}:${port}&max_nodes=3" 2>/dev/null)
  rid=$(print -r -- "$req" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("request_id",""))
except Exception: print("")' 2>/dev/null)
  if [[ -z $rid ]]; then
    fail "port $port: check-host.net request failed (no request_id)"
    return
  fi

  while (( tries++ < 8 )); do
    sleep 5
    result=$(curl -fsS -m 20 -H "Accept: application/json" \
             "https://check-host.net/check-result/${rid}" 2>/dev/null)
    verdict=$(print -r -- "$result" | python3 -c '
import sys, json
# Node result shapes: null = pending; [{"error": ..., "time": ...}] = filtered/
# closed (timeout or refused); [{"time": ..., "address": ...}] = TCP connect OK.
try:
    data = json.load(sys.stdin)
except Exception:
    print("PENDING"); raise SystemExit
states = []
for res in data.values():
    if res is None:
        states.append("pending"); continue
    entry = res[0] if isinstance(res, list) and res else {}
    if isinstance(entry, dict) and "error" not in entry and "time" in entry:
        states.append("open")
    else:
        states.append("blocked")
if "open" in states:      print("OPEN")
elif "pending" in states: print("PENDING")
elif states:              print("BLOCKED")
else:                     print("PENDING")
' 2>/dev/null)
    [[ $verdict == "OPEN" || $verdict == "BLOCKED" ]] && break
  done

  case $verdict in
    OPEN)    fail "port $port REACHABLE from internet at ${PUBLIC_IP}:${port} — close the forward NOW" ;;
    BLOCKED) pass "port $port filtered/closed from internet" ;;
    *)       fail "port $port: check-host.net result inconclusive after polling" ;;
  esac
}

check_external 22
check_external 3306

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print
print -r -- "${BOLD}Summary:${RESET} ${GREEN}${PASS_COUNT} PASS${RESET}, ${RED}${FAIL_COUNT} FAIL${RESET}"
(( FAIL_COUNT > 0 )) && exit 1
exit 0