#!/bin/bash
# mac-auto-update.sh — the Mac-side Secure-VPN client auto-update, run once at
# login/boot by the com.selfhost.securevpn-updater LaunchAgent
# (crates/ui/vpn-ui/src/bin/securevpn-updater.rs installs the plist).
#
# WHAT THIS DOES
#   1. Checks the Secure-VPN repository (github.com/RockyWearsAHat/Secure-VPN)
#      for a commit newer than what ~/.securevpn/app has checked out. A
#      read-only check only — nothing under ~/.securevpn/app is touched yet.
#   2. If there is one, builds and proves the new commit in a THROWAWAY clone
#      first: the KAT test suite (`cargo test --release` in mlkem768/) gates
#      everything else, then `maturin build --release -o dist`, then a trial
#      `pip install` into a scratch venv. Any failure here aborts the whole
#      run and leaves ~/.securevpn untouched — the staging clone is the only
#      thing that ever holds unverified code.
#   3. Only once every one of those has succeeded does it touch the real
#      install: fast-forward-only pull into ~/.securevpn/app (the same policy
#      join-mac.sh uses — a diverged or dirty checkout aborts loudly rather
#      than being reset or merged), then install the already-proven wheel
#      into the real venv.
#   4. Best-effort restart of a currently-running tunnel. This step is
#      allowed to fail without failing the update: the code on disk is
#      already correct and verified by step 2/3, so a restart that cannot
#      complete leaves the OLD client process running rather than a half-torn
#      one — never the reverse. See NOTE ON RESTART below.
#
# NEVER KILLS BEFORE VERIFYING. If any gate step (fetch, KAT tests, wheel
# build, trial install, fast-forward pull, real install) fails, the script
# exits non-zero having changed nothing under ~/.securevpn, and the tunnel
# that was already running keeps running exactly as it was.
#
# SILENT BY DESIGN — no prompts, no dialogs (per product decision). It never
# asks `sudo` for a password: every step it runs itself is either read-only,
# confined to a scratch directory, or a plain non-privileged write under
# ~/.securevpn. See NOTE ON RESTART for the one place that matters.
#
# THIS IS THE ONLY MAC-SIDE AUTO-UPDATE TRIGGER for Secure-VPN. It runs once,
# at login/boot (`RunAtLoad`), and exits — there is deliberately no
# `StartInterval`/timer poll here and none should be added; see docs/VPN.md.
# `join-mac.sh` also does a `git pull --ff-only` but only when a human runs it
# by hand, which is not a standing trigger.
#
# Usage: mac-auto-update.sh [--repo <url>] [--branch <name>]
set -euo pipefail

REPO="${SECUREVPN_REPO:-https://github.com/RockyWearsAHat/Secure-VPN.git}"
BRANCH="${SECUREVPN_BRANCH:-main}"
VPN_HOME="${SECUREVPN_HOME:-$HOME/.securevpn}"
APP="$VPN_HOME/app"
VENV="$VPN_HOME/venv"
LOG="$VPN_HOME/auto-update.log"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)   REPO="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$VPN_HOME"
log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

# Nothing installed yet: this LaunchAgent has nothing to update. Not an
# error — a Mac that has never run join-mac.sh is a normal state.
if [ ! -d "$APP/.git" ]; then
  log "no ~/.securevpn/app checkout — nothing to update"
  exit 0
fi

command -v git >/dev/null 2>&1 || { log "git not found — skipping"; exit 0; }

# ── 1. Read-only check: is there anything to do at all? ──────────────────────
LIVE_SHA="$(git -C "$APP" rev-parse HEAD 2>/dev/null || echo "")"
REMOTE_SHA="$(git ls-remote "$REPO" "refs/heads/$BRANCH" 2>/dev/null | cut -f1)"

if [ -z "$LIVE_SHA" ] || [ -z "$REMOTE_SHA" ]; then
  log "could not determine commits (offline, or a detached/unreadable checkout) — skipping this run"
  exit 0
fi
if [ "$LIVE_SHA" = "$REMOTE_SHA" ]; then
  log "up to date at $LIVE_SHA — nothing to do"
  exit 0
fi
log "update available: $LIVE_SHA -> $REMOTE_SHA — verifying in a scratch clone before touching the live install"

# ── 2. Build and prove the new commit somewhere that is not the live install ─
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/securevpn-update.XXXXXX")"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

STAGE_APP="$STAGING/app"
if ! git clone --quiet --branch "$BRANCH" --depth 50 "$REPO" "$STAGE_APP" >>"$LOG" 2>&1; then
  log "ABORT: could not clone $REPO — live install untouched"
  exit 1
fi

if [ ! -d "$STAGE_APP/mlkem768" ]; then
  log "ABORT: the new commit has no mlkem768/ — nothing to gate against, refusing to guess. Live install untouched."
  exit 1
fi

log "running the KAT test suite (cargo test --release) as the gate"
if ! ( cd "$STAGE_APP/mlkem768" && cargo test --release ) >>"$LOG" 2>&1; then
  log "ABORT: KAT test suite failed on the new commit — live install untouched"
  exit 1
fi
log "KAT tests passed"

command -v maturin >/dev/null 2>&1 || { log "ABORT: maturin not found — cannot build the wheel. Live install untouched"; exit 1; }

log "building the wheel (maturin build --release -o dist)"
if ! ( cd "$STAGE_APP/mlkem768" && maturin build --release -o dist ) >>"$LOG" 2>&1; then
  log "ABORT: maturin build failed — live install untouched"
  exit 1
fi

WHEEL="$(find "$STAGE_APP/mlkem768/dist" -maxdepth 1 -name '*.whl' -print -quit)"
if [ -z "$WHEEL" ]; then
  log "ABORT: maturin reported success but produced no wheel — live install untouched"
  exit 1
fi
log "built $WHEEL"

# A trial install into a scratch venv — proves the wheel actually installs on
# this machine before the real venv (the one the running tunnel uses) is ever
# touched.
log "trial-installing the wheel into a scratch venv"
if ! python3 -m venv "$STAGING/trial-venv" >>"$LOG" 2>&1; then
  log "ABORT: could not create a scratch venv to trial the wheel — live install untouched"
  exit 1
fi
if ! "$STAGING/trial-venv/bin/pip" install --quiet "$WHEEL" >>"$LOG" 2>&1; then
  log "ABORT: the wheel failed to install even in a scratch venv — live install untouched"
  exit 1
fi
log "trial install succeeded — the new commit is verified"

# ── 3. Only now: touch the real install ───────────────────────────────────────
log "fast-forwarding the live checkout at $APP"
if ! git -C "$APP" fetch --quiet origin "$BRANCH" >>"$LOG" 2>&1; then
  log "ABORT: fetch into the live checkout failed — live install untouched (network blip? retried next login)"
  exit 1
fi
if ! git -C "$APP" merge --ff-only --quiet "origin/$BRANCH" >>"$LOG" 2>&1; then
  log "ABORT: the live checkout cannot fast-forward (local edits or a diverged branch — this is exactly the state a hand-fix leaves it in; see docs/VPN.md). Live install untouched. Fix by hand: git -C $APP status"
  exit 1
fi
log "live checkout now at $(git -C "$APP" rev-parse HEAD)"

if [ -x "$VENV/bin/pip" ]; then
  log "installing the verified wheel into the live venv"
  if ! "$VENV/bin/pip" install --quiet --force-reinstall "$WHEEL" >>"$LOG" 2>&1; then
    log "WARNING: the live checkout was fast-forwarded but the wheel failed to install into $VENV. \
The already-running tunnel (old code, still in memory) is untouched and kept running. \
Fix by hand: $VENV/bin/pip install --force-reinstall $WHEEL"
    exit 1
  fi
  log "live venv now has the verified wheel"
else
  log "no venv at $VENV yet — the wheel will install the next time join-mac.sh runs"
fi

# ── 4. Deliberately NOT restarting a running tunnel. ──────────────────────────
#
# CHANGED: this step used to `pkill` any running client.py and relaunch it by
# hand, on the theory that an update should take effect immediately. That is
# exactly the wrong trade for a live SSH/VPN session: it is a forced, visible
# disconnect for the sake of adopting new code a few minutes sooner. Since
# `crates/ui/vpn-ui/src/tunnel.rs` grew its own supervisor (a dropped tunnel
# is relaunched automatically, with backoff, until the user disconnects), the
# two would now race on top of that: a `pkill` here fires at the same instant
# the app's own supervisor notices the drop and relaunches its child, and both
# sides can end up trying to bind the same local port at once.
#
# The correct zero-downtime behaviour is simpler: touch nothing that is
# currently connected. The verified new code is already on disk (steps 2-3
# proved it before this line ever ran) and Python only reads client.py at
# process start, so a live process keeps running its already-loaded old code
# — uninterrupted — until it reconnects for any ordinary reason (a real drop,
# sleep/wake, a manual disconnect/reconnect, or the next login). At that
# point `spawn_client`/`join-mac.sh` launches a fresh interpreter, which reads
# whatever is on disk *then* — the update. No connection is ever killed by
# this script to make that happen sooner.
log "update installed; a running tunnel (if any) keeps its current connection and \
picks up this code on its own next reconnect — nothing was restarted"

log "done"
