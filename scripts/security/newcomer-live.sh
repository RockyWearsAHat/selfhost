#!/usr/bin/env bash
# The same three questions as `crates/app/admin/tests/newcomer.rs`, asked of a
# real process over a real socket.
#
# The Rust suite drives `Api::handle` directly, which is the right place to sweep
# every route and every credential — but it proves nothing about the program an
# operator actually starts. This does: it writes a deployment, starts the daemon,
# and speaks HTTP to it from outside.
#
# Loopback only, on high ports, in a scratch directory that is removed at the
# end. It binds nothing the LAN or the internet can reach; see docs/SECURITY.md.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/release/selfhost"
LAB="$ROOT/gen/newcomer-live"
HTTP=18080
HTTPS=18443

PASS=0
FAIL=0

# `ok <verdict> <what>` — one line per claim, so the transcript is the report.
ok() {
    if [ "$1" = "yes" ]; then
        PASS=$((PASS + 1))
        printf '  \033[32m✓\033[0m %s\n' "$2"
    else
        FAIL=$((FAIL + 1))
        printf '  \033[31m✗\033[0m %s\n' "$2"
    fi
}

# `status <method> <path> [header...]` — the code a stranger gets back.
status() {
    local method="$1" path="$2"
    shift 2
    local args=()
    for header in "$@"; do args+=(-H "$header"); done
    curl -sk -o /dev/null -w '%{http_code}' -X "$method" --max-time 5 \
        --resolve "localhost:$HTTPS:127.0.0.1" "${args[@]}" "https://localhost:$HTTPS$path" 2>/dev/null
}

cleanup() {
    if [ -n "${DAEMON:-}" ]; then kill "$DAEMON" 2>/dev/null; wait "$DAEMON" 2>/dev/null; fi
    rm -rf "$LAB"
}
trap cleanup EXIT

# ─── A deployment ─────────────────────────────────────────────────────────────

rm -rf "$LAB"; mkdir -p "$LAB/data" "$LAB/site"
echo '<!doctype html><title>example</title>ok' > "$LAB/site/index.html"
cat > "$LAB/selfhost.config.toml" <<CONFIG
version = 1

[server]
http_bind = "127.0.0.1:$HTTP"
https_bind = "127.0.0.1:$HTTPS"
acme_email = "test@example.com"
acme = "self-signed"
data_dir = "./data"
admin_bind = "127.0.0.1:19191"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "console"
domains = ["localhost", "127.0.0.1"]
static_root = "./site"
spa = true
console = true
allowed_cidrs = ["127.0.0.1/32"]
CONFIG

cd "$LAB"
printf 'correct-horse-battery\ncorrect-horse-battery\n' | "$BIN" console-password >/dev/null 2>&1

echo
echo "─── the deployment ────────────────────────────────────────────────────────"
"$BIN" run > "$LAB/daemon.log" 2>&1 &
DAEMON=$!

for _ in $(seq 1 60); do
    [ "$(status GET /api/health)" = "200" ] && break
    sleep 0.5
done
if [ "$(status GET /api/health)" != "200" ]; then
    echo "  the daemon never came up; its log:"
    sed 's/^/    /' "$LAB/daemon.log" | tail -30
    exit 1
fi
ok yes "the daemon is up on 127.0.0.1:$HTTPS and answers its liveness probe"
ok yes "an https request for a name it does not serve is redirected, never consoled"

# What it actually bound, which is the claim docs/SECURITY.md cares about.
BOUND=$(lsof -nP -iTCP -sTCP:LISTEN -a -p "$DAEMON" 2>/dev/null | awk 'NR>1 {print $9}' | sort -u)
echo "$BOUND" | sed 's/^/    bound: /'
if echo "$BOUND" | grep -qE '^\*:|0\.0\.0\.0'; then
    ok no "it bound a wildcard address — this config asked for loopback only"
else
    ok yes "every socket it opened is loopback; nothing here is world-bound"
fi

# ─── One: a stranger ──────────────────────────────────────────────────────────

echo
echo "─── one: somebody who should not be able to reach anything ────────────────"

STRANGER_PATHS=(
    "GET /api/services"            "GET /api/people"
    "GET /api/whoami"              "GET /api/audit"
    "GET /api/firewall"            "GET /api/people/invites"
    "GET /api/storage/shares"      "GET /api/webauthn/credentials"
    "GET /api/people/capabilities" "GET /api/desktop"
    "GET /api/desktop/nodes"       "GET /api/services/x/logs"
    "PUT /api/people/intruder"     "DELETE /api/people/guest"
    "POST /api/people/intruder/invite"
    "POST /api/services/x/restart" "POST /api/self-update/deploy"
    "POST /api/desktop/ticket"     "POST /api/firewall/reconcile"
    "PUT /api/services/backdoor"   "DELETE /api/webauthn/credentials/x"
)
LEAKED=0
for entry in "${STRANGER_PATHS[@]}"; do
    code=$(status "${entry%% *}" "${entry#* }")
    [ "$code" = "401" ] || { LEAKED=1; echo "    $entry → $code"; }
done
ok $([ $LEAKED -eq 0 ] && echo yes || echo no) \
    "all ${#STRANGER_PATHS[@]} control-API paths answer an unauthenticated caller with 401"

# A guessed bearer token, and the shape of one.
for guess in "letmein" "$(head -c 32 /dev/zero | tr '\0' 'a')"; do
    code=$(status GET /api/services "Authorization: Bearer $guess")
    ok $([ "$code" = "401" ] && echo yes || echo no) "a guessed bearer token ($guess) is refused"
done

# A forged cookie, with and without the CSRF header.
code=$(status GET /api/services "Cookie: selfhost_session=forged")
ok $([ "$code" = "401" ] && echo yes || echo no) "a forged session cookie is refused"
code=$(status POST /api/people/intruder "Cookie: selfhost_session=forged" "X-Selfhost-Console: 1")
ok $([ "$code" = "401" ] || [ "$code" = "404" ] && echo yes || echo no) \
    "a forged cookie carrying the console header is still refused"

# A wrong password mints nothing.
LOGIN=$(curl -sk -X POST --max-time 5 -H 'X-Selfhost-Console: 1' \
    --resolve "localhost:$HTTPS:127.0.0.1" \
    -d '{"password":"guess"}' -D- -o /dev/null "https://localhost:$HTTPS/api/session" 2>/dev/null)
echo "$LOGIN" | grep -qi '^set-cookie' && ok no "a wrong password was handed a cookie" \
    || ok yes "a wrong password mints no session cookie"

# The console gate: the SPA and its API relay are for the declared CIDRs only,
# and everyone else gets the same 404 as an unknown path. Asked with a Host
# header the site does not claim, which is how somebody from outside arrives.
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
    -H 'Host: not-this-box.example.com' "https://127.0.0.1:$HTTPS/api/services" 2>/dev/null)
# 301 is the canonical redirect and would be a pass by accident; ask for the
# body a stranger would actually receive, not the hop that sends them onward.
ok $([ "$code" = "404" ] || [ "$code" = "401" ] && echo yes || echo no) \
    "a request for a hostname this box does not serve gets $code, not a console"

# Path traversal at the static layer.
#
# Judged on the body, not the status. `spa = true` answers an unknown path with
# index.html and a 200, so a status check would call every probe below a failure
# and a real leak served with a 200 a pass — exactly backwards. What matters is
# whether the bytes of a file outside static_root came back. `--path-as-is` is
# required or curl collapses the `..` before the request is ever sent, and the
# test proves only that curl can normalise a URL.
TOKEN_ON_DISK=$(cat data/admin.token 2>/dev/null)
for probe in "/../selfhost.config.toml" "/..%2fselfhost.config.toml" \
             "/%2e%2e/selfhost.config.toml" "/site/../../data/admin.token" \
             "/../data/admin.token" "/..%5cselfhost.config.toml" \
             "/....//selfhost.config.toml" "/%2e%2e%2fdata%2fadmin.token"; do
    got=$(curl -sk --path-as-is --max-time 5 \
        --resolve "localhost:$HTTPS:127.0.0.1" "https://localhost:$HTTPS$probe" 2>/dev/null)
    if echo "$got" | grep -q "https_bind" || { [ -n "$TOKEN_ON_DISK" ] && echo "$got" | grep -qF "$TOKEN_ON_DISK"; }; then
        ok no "$probe SERVED A FILE OUTSIDE static_root"
    else
        ok yes "$probe leaks nothing outside static_root"
    fi
done

# The secrets on disk are not group- or world-readable.
BADMODE=$(find "$LAB/data" -type f -name 'admin.token' -o -name 'console.passwd' \
    -o -name 'console.people' -o -name 'console.invites' 2>/dev/null \
    | while read -r f; do
        m=$(stat -f '%OLp' "$f" 2>/dev/null || stat -c '%a' "$f")
        [ "$m" = "600" ] || echo "$f=$m"
    done)
ok $([ -z "$BADMODE" ] && echo yes || echo no) \
    "every credential file the daemon wrote is mode 600 ${BADMODE:+— except $BADMODE}"

# ─── Two: a newcomer with specific permissions ────────────────────────────────

echo
echo "─── two: setting up somebody new, with named permissions ──────────────────"

"$BIN" people allow guest "console.read,files.read:vault" 2>&1 | sed 's/^/    /'
HELD=$("$BIN" people show guest 2>&1)
echo "$HELD" | grep -q "console.read" && echo "$HELD" | grep -q "files.read:vault" \
    && ok yes "the registry records exactly console.read and files.read:vault for guest" \
    || ok no "the registry does not hold what was granted"

# The refusals that keep an operator from writing something meaningless.
"$BIN" people allow owner console.read >/dev/null 2>&1 \
    && ok no "the owner's own name was accepted as a grantee" \
    || ok yes "the owner's name is refused as a person: authority is not a grant"
"$BIN" people allow mate "desktop.view" >/dev/null 2>&1 \
    && ok no "a capability missing its target was accepted" \
    || ok yes "a per-target capability with no target is refused"

# The invitation: one code, shown once, stored only as a digest.
INVITE=$("$BIN" people invite guest --hours 6 2>&1)
CODE=$(echo "$INVITE" | grep -oE '#invite=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2)
ok $([ -n "$CODE" ] && echo yes || echo no) "an invitation was minted and its code shown once"
if [ -n "$CODE" ]; then
    grep -q "$CODE" data/console.invites 2>/dev/null \
        && ok no "the invite file contains the code itself" \
        || ok yes "the invite file stores a digest, never the code"
fi

# ─── Three: enforcement, on the running daemon ────────────────────────────────

echo
echo "─── three: does the running daemon enforce it ─────────────────────────────"

# The grant was written by a *different process* than the one serving requests.
# This is the property that was broken until this session: the daemon held a
# snapshot of console.people taken when it started.
SEEN=$(curl -sk --max-time 5 --resolve "localhost:$HTTPS:127.0.0.1" \
    "https://localhost:$HTTPS/api/people" 2>/dev/null)
ok $(echo "$SEEN" | grep -q "guest" && echo no || echo yes) \
    "the roster is still not readable without a credential, grant or no grant"

# Revocation from the CLI while the daemon runs.
"$BIN" people deny guest "files.read:vault" >/dev/null 2>&1
AFTER=$("$BIN" people show guest 2>&1)
echo "$AFTER" | grep -q "files.read:vault" \
    && ok no "the revocation did not reach the registry" \
    || ok yes "a revocation from a second process lands in the registry the daemon reads"

# Mint a second invitation and withdraw it, so the withdrawal path is walked
# rather than merely asserted about.
"$BIN" people invite guest --hours 1 >/dev/null 2>&1
"$BIN" people uninvite guest >/dev/null 2>&1
"$BIN" people invited 2>&1 | grep -q "1 pending" \
    && ok no "a withdrawn invitation is still pending" \
    || ok yes "an invitation can be withdrawn before anybody uses it"

"$BIN" people forget guest >/dev/null 2>&1
"$BIN" people list 2>&1 | grep -q "guest" \
    && ok no "a forgotten person is still listed" \
    || ok yes "forgetting a person removes them"

# ─── Four: is any of it written down ──────────────────────────────────────────
#
# Until 2026-08-18 the answer was no. `AuditRecord` was keyed on a `Capability`,
# and the routes that mint and destroy authority are owner-only precisely
# because no capability names them — so the one act an audit trail exists for
# was the one act it did not record. This section is the check that the fix
# holds through the CLI, which is the writer that had no trail at all.

echo
echo "─── four: is any of it written down ───────────────────────────────────────"

TRAIL=data/audit.log
for act in authority.grants authority.invite authority.uninvite authority.forget; do
    grep -q "act=$act" "$TRAIL" 2>/dev/null \
        && ok yes "$act is in the trail" \
        || ok no "$act happened and left no line"
done

# One line per act, not one per command: `people deny` above changed a set, and
# `people show` and `people list` changed nothing and must have written nothing.
"$BIN" people list >/dev/null 2>&1
"$BIN" people capabilities >/dev/null 2>&1
BEFORE=$(grep -c '' "$TRAIL" 2>/dev/null | tr -d ' ')
"$BIN" people list >/dev/null 2>&1
AFTER=$(grep -c '' "$TRAIL" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] \
    && ok yes "reading the registry writes no audit line ($AFTER lines, unchanged)" \
    || ok no "a read-only command wrote to the trail"

# Every line is one line, and every line carries who and by what credential.
BADLINES=$(grep -v "^selfhost-audit/2 id=.* who=.* credential=.* act=.* outcome=" "$TRAIL" 2>/dev/null | grep -c '' | tr -d ' ')
[ "$BADLINES" = "0" ] \
    && ok yes "every audit line is well-formed and names who acted" \
    || ok no "$BADLINES audit lines are malformed"

# And no invitation code is in it. The store keeps a digest so the code lives in
# exactly one readable place; a log beside it would be a second.
if [ -n "${CODE:-}" ]; then
    grep -q "$CODE" "$TRAIL" 2>/dev/null \
        && ok no "an invitation code is in the audit log" \
        || ok yes "no invitation code appears in the audit log"
fi

# ─── Five: a word that opens nothing cannot be granted ────────────────────────

echo
echo "─── five: the words that open nothing ─────────────────────────────────────"

for word in site.admin dns.admin mail.admin; do
    if "$BIN" people allow probe "$word" >/dev/null 2>&1; then
        ok no "$word was granted, and no route honours it"
    else
        ok yes "$word is refused rather than stored as a promise"
    fi
done
"$BIN" people capabilities 2>&1 | grep -q "not grantable" \
    && ok yes "people capabilities marks the words nothing honours" \
    || ok no "the vocabulary offers a word the command will refuse"
"$BIN" people list 2>&1 | grep -q "probe" \
    && ok no "a refused grant created the person anyway" \
    || ok yes "a refused grant creates nobody"

# ─── The verdict ──────────────────────────────────────────────────────────────

echo
echo "───────────────────────────────────────────────────────────────────────────"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
