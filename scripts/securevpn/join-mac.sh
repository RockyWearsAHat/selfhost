#!/bin/bash
# join-mac.sh — bring up the Secure-VPN tunnel on a Mac, from nothing.
#
# WHY THIS EXISTS
#
# The admin console is loopback-gated: it does not exist for the internet, and
# the only way in is the tunnel. That made an ordering problem the invitation
# could not solve on its own — you cannot fetch the VPN from the console when
# the console is what the VPN is for. Every earlier attempt to let somebody in
# ended with the owner running commands over SSH on their behalf, which is not a
# thing that scales past one favour.
#
# So this script is the first half of the invitation, and it assumes nothing:
# no Homebrew, no Python knowledge, no repository checked out. It installs into
# ~/.securevpn using the same layout the desktop app (selfhost-vpn-ui) expects,
# so installing that later finds these keys and this checkout rather than a
# second copy.
#
# WHAT IT DOES NOT DO
#
# It does not give you access to anything. It puts you on the tunnel, which
# gets you to the console's LOGIN PAGE and nothing else — every route behind it
# still demands a credential you do not have yet. That second half is the
# invite link, which registers a passkey under the name you were invited as.
# Being on the VPN is not being authorised, and this deployment never treats it
# as though it were.
#
# USAGE
#   ./join-mac.sh                 install, then start the tunnel
#   ./join-mac.sh --install-only  install and stop, do not start the tunnel
#   ./join-mac.sh --stop          take the tunnel down and undo the hosts entry
#
# The key material is written by whoever sent you this file; see KEYS below.
#
# WHAT IT WILL NOT DO TO A MACHINE THAT ALREADY WORKS
#
# It never deletes ~/.securevpn/app. If a client is already installed there, this
# script adopts that directory as a checkout of the Secure-VPN repository without
# overwriting a single file, and prints anything that differs from upstream. An
# earlier version deleted the directory and cloned over the top, which threw away
# a working install — and any local fix in it — on a machine whose owner was
# running this to get their tunnel back.

set -euo pipefail

# ── what this deployment is ───────────────────────────────────────────────────
SERVER_HOST="${SECUREVPN_SERVER:-172.83.6.109}"
SERVER_PORT="${SECUREVPN_PORT:-8443}"
CONSOLE_HOST="${SECUREVPN_CONSOLE:-admin.rockywearsahat.com}"
REPO="${SECUREVPN_REPO:-https://github.com/RockyWearsAHat/Secure-VPN.git}"

HOME_DIR="${HOME}"
BASE="${HOME_DIR}/.securevpn"
APP="${BASE}/app"
KEYS="${BASE}/keys"
VENV="${BASE}/venv"
HOSTS_MARK="# selfhost secure-vpn (${CONSOLE_HOST})"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── KEYS ──────────────────────────────────────────────────────────────────────
# Your identity, and the server's public key. These are filled in by the person
# who invited you. IDENTITY_NAME must match the name they enrolled in the
# roster, because that is the entry the server looks you up under.
IDENTITY_NAME="${SECUREVPN_IDENTITY:-__IDENTITY_NAME__}"
IDENTITY_KEY_B64="${SECUREVPN_IDENTITY_KEY:-__IDENTITY_KEY__}"
SERVER_PUB_B64="${SECUREVPN_SERVER_PUB:-__SERVER_PUB__}"

stop_tunnel() {
  say "Stopping the tunnel"
  # The client runs as root because it binds 127.0.0.1:443, and macOS reserves
  # ports below 1024. Nothing else about it wants privilege.
  sudo pkill -f "client.py ${SERVER_HOST}" 2>/dev/null && note "tunnel stopped" || note "no tunnel was running"
  if grep -qF "${HOSTS_MARK}" /etc/hosts 2>/dev/null; then
    sudo sed -i '' "/${CONSOLE_HOST//./\\.}.*selfhost secure-vpn/d" /etc/hosts
    sudo sed -i '' "\|^${HOSTS_MARK}$|d" /etc/hosts 2>/dev/null || true
    note "removed the /etc/hosts entry"
  fi
  exit 0
}

[[ "${1:-}" == "--stop" ]] && stop_tunnel

# ── 1. Python ─────────────────────────────────────────────────────────────────
say "1/5  Checking Python"
PY="$(command -v python3 || true)"
[[ -n "${PY}" ]] || die "python3 not found. Install Xcode command line tools first:
    xcode-select --install"
note "$(${PY} --version)"

# ── 2. The client itself ──────────────────────────────────────────────────────
#
# THIS STEP NEVER DELETES ANYTHING. It used to: when ~/.securevpn/app existed
# without a .git directory — which is exactly the state a hand-copied install is
# in — it ran `rm -rf` and cloned over the top, destroying a working client and
# any local fix in it, on a machine whose owner ran this script to *repair* their
# tunnel. The source is a known repository (${REPO}), so there is no need to
# guess: an existing directory is adopted as a checkout in place, with every file
# left exactly as it is, and whatever differs from upstream is printed rather than
# overwritten.
say "2/5  Fetching the VPN client"
mkdir -p "${BASE}"
command -v git >/dev/null || die "git not found. Install Xcode command line tools:
    xcode-select --install"

if [[ -d "${APP}/.git" ]]; then
  # Fast-forward only, and non-fatal. A merge or a rebase here would rewrite
  # somebody's tunnel from a script they ran to start it; a failure to update is
  # not a reason to refuse to connect with the client already on disk.
  if git -C "${APP}" pull --ff-only --quiet 2>/dev/null; then
    note "updated ${APP} from ${REPO}"
  else
    note "could not fast-forward ${APP} — LEAVING IT EXACTLY AS IT IS"
    note "  (local edits, or a diverged branch: git -C ${APP} status)"
  fi
elif [[ -e "${APP}" && ! -d "${APP}" ]]; then
  # A file where the app directory belongs. Refusing is the only safe answer: it
  # is not something this script put there, so it is not something this script
  # gets to remove.
  die "${APP} exists and is not a directory. Move it aside yourself, then re-run;
    this script does not delete anything it did not create."
elif [[ -d "${APP}" ]]; then
  # Adopt: clone into a temporary directory, move only its .git into place, and
  # touch none of the files that are already there. Afterwards the directory is a
  # real checkout of ${REPO} whose working tree is still the user's own copy, so
  # `git status` names the drift instead of the drift being silently discarded.
  say "     ${APP} already exists and is not a git checkout"
  note "adopting it in place — nothing here is deleted or overwritten"
  TMP_CLONE="$(mktemp -d "${BASE}/.clone.XXXXXX")"
  trap 'rm -rf "${TMP_CLONE}"' EXIT
  git clone --quiet --depth 1 "${REPO}" "${TMP_CLONE}/app" || die "could not clone ${REPO}"
  mv "${TMP_CLONE}/app/.git" "${APP}/.git"
  rm -rf "${TMP_CLONE}"
  trap - EXIT
  if [[ -n "$(git -C "${APP}" status --porcelain)" ]]; then
    note "your copy differs from ${REPO}:"
    git -C "${APP}" status --short | sed 's/^/      /'
    note "those files are UNCHANGED, and they are what the tunnel will run."
    note "to take upstream's version of everything:  git -C ${APP} checkout -- ."
  else
    note "your copy matches upstream exactly; ${APP} is now tracked"
  fi
else
  git clone --quiet --depth 1 "${REPO}" "${APP}" || die "could not clone ${REPO}"
  note "cloned ${REPO} into ${APP}"
fi

# ── 3. Its one dependency ─────────────────────────────────────────────────────
say "3/5  Preparing the Python environment"
if [[ ! -x "${VENV}/bin/python" ]]; then
  "${PY}" -m venv "${VENV}" || die "could not create a virtualenv at ${VENV}"
fi
# `cryptography` is the audited library this VPN leans on deliberately rather
# than hand-rolling ciphers; it is the only dependency.
"${VENV}/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
"${VENV}/bin/pip" install --quiet cryptography || die "could not install cryptography"
note "$( "${VENV}/bin/python" -c 'import cryptography; print("cryptography " + cryptography.__version__)' )"

# ── 4. Your keys ──────────────────────────────────────────────────────────────
say "4/5  Installing your identity"
[[ "${IDENTITY_NAME}" != "__IDENTITY_NAME__" ]] || die "this script has no identity in it.
  It should have been filled in by whoever invited you — ask them to re-send it."

mkdir -p "${KEYS}"
chmod 700 "${KEYS}"

# The private key never leaves this machine after this point, and the file is
# written 0600 before anything is written into it.
KEY_FILE="${KEYS}/${IDENTITY_NAME}.key"
umask 077
cat > "${KEY_FILE}" <<KEYEOF
{
  "type": "plain",
  "algorithm": "ed25519",
  "data": "${IDENTITY_KEY_B64}"
}
KEYEOF
chmod 600 "${KEY_FILE}"
printf 'securevpn-ed25519 %s server\n' "${SERVER_PUB_B64}" > "${KEYS}/server.pub"
chmod 644 "${KEYS}/server.pub"
note "identity '${IDENTITY_NAME}' installed in ${KEYS}"

if [[ "${1:-}" == "--install-only" ]]; then
  say "Installed. Start the tunnel later with:  $0"
  exit 0
fi

# ── 5. Up ─────────────────────────────────────────────────────────────────────
say "5/5  Starting the tunnel"

# The console's certificate is issued for its real hostname, so the browser has
# to arrive at that name on port 443 for TLS — and for WebAuthn, whose relying
# party is that same name — to be satisfied. Pointing the name at loopback is
# the whole trick; the tunnel is what is listening there.
if ! grep -qF "${HOSTS_MARK}" /etc/hosts 2>/dev/null; then
  note "adding ${CONSOLE_HOST} → 127.0.0.1 to /etc/hosts (needs your password)"
  printf '%s\n127.0.0.1\t%s\n' "${HOSTS_MARK}" "${CONSOLE_HOST}" | sudo tee -a /etc/hosts >/dev/null
fi

sudo pkill -f "client.py ${SERVER_HOST}" 2>/dev/null || true
LOG="${BASE}/tunnel.log"
note "binding 127.0.0.1:443 (needs your password)"
sudo "${VENV}/bin/python" -u "${APP}/client.py" "${SERVER_HOST}" \
  --port "${SERVER_PORT}" --local-port 443 \
  --identity "${IDENTITY_NAME}" --peer server --key-dir "${KEYS}" \
  > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
  sleep 1
  grep -q "VPN tunnel active" "${LOG}" 2>/dev/null && break
done

if grep -q "VPN tunnel active" "${LOG}" 2>/dev/null; then
  printf '\n\033[32m✓ The tunnel is up.\033[0m\n\n'
  note "Now open the invitation link you were sent. It looks like:"
  note "    https://${CONSOLE_HOST}/#invite=<your code>"
  printf '\n'
  note "That asks this Mac for your fingerprint and registers you. Until you do"
  note "it, the tunnel gets you to a login page and nothing more."
  printf '\n'
  note "Take it down again with:  $0 --stop"
else
  printf '\n\033[31m✗ The tunnel did not come up.\033[0m\n\n'
  note "The log is at ${LOG}:"
  sed 's/^/    /' "${LOG}" | tail -20
  printf '\n'
  note "'Client identity key mismatch' means you have not been enrolled yet —"
  note "send this line to whoever invited you and ask them to enrol it:"
  note "    $(cat "${KEYS}/${IDENTITY_NAME}.pub" 2>/dev/null || echo "(no public key on disk)")"
  exit 1
fi
