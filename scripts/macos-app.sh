#!/bin/bash
#
# Builds, installs, and removes "Selfhost Console.app" on macOS.
#
#   scripts/macos-app.sh install     build, bundle, install, pin, and relaunch
#   scripts/macos-app.sh uninstall   unpin, remove the bundle and the CLI link
#   scripts/macos-app.sh bundle      build the .app into target/ and stop there
#
# Install is the only way a code change reaches the window on screen. A running
# console is the *old* binary and stays the old binary however long it is left
# open, because the bundle it was launched from is a copy — editing the source,
# or even `cargo build`, changes nothing it is running. So install quits the
# running console, replaces the bundle, and starts it again: after it returns,
# what is on screen is what is in the working tree.
#
# Why a bundle at all: macOS gives a Dock icon, a name in the menu bar, and a
# double-clickable thing in /Applications to bundles, and to nothing else. A
# bare binary in target/ has none of those however it is launched.
#
# The icon is not stored in this repository. It is drawn, at every size, by the
# same toolkit that draws the console's own interface — see
# crates/ui/examples/icon.rs. A checked-in .icns would be a binary nobody can
# review that drifts from the interface it is supposed to match.
#
# Everything here uses tools macOS ships with: iconutil, codesign, defaults,
# PlistBuddy. Nothing is downloaded.

set -euo pipefail

APP_NAME="Selfhost Console"
BUNDLE_ID="dev.selfhost.console"
INSTALL_DIR="/Applications"
APP="${INSTALL_DIR}/${APP_NAME}.app"
CLI_LINK="/usr/local/bin/selfhost"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${REPO}/target/macos-app"
STAGED="${BUILD}/${APP_NAME}.app"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die() { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "this script is for macOS; on Linux and Windows the console is run from target/release"

# ---------------------------------------------------------------- running app

# Whether a console launched from the installed bundle is running right now.
# Matched on the bundle path, so a console run straight out of target/release
# during development is left alone — that one is not what install replaces.
console_running() {
  pgrep -f "${APP_NAME}.app/Contents/MacOS/selfhost-console" >/dev/null 2>&1
}

# Ask, then insist. `quit` gives the console the chance to close its window and
# drop its connection to the daemon; the kill is for a console that is wedged,
# which must not be able to block an install — the whole point of installing is
# that the code on screen is stale.
quit_console() {
  console_running || return 0
  note "quitting the running console"
  osascript -e "tell application \"${APP_NAME}\" to quit" >/dev/null 2>&1 || true

  local waited=0
  while console_running && (( waited < 30 )); do
    sleep 0.1
    waited=$(( waited + 1 ))
  done

  if console_running; then
    note "it did not quit; force-closing it"
    pkill -f "${APP_NAME}.app/Contents/MacOS/selfhost-console" 2>/dev/null || true
    sleep 0.5
    pkill -9 -f "${APP_NAME}.app/Contents/MacOS/selfhost-console" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------- build

build_bundle() {
  say "Building"
  ( cd "$REPO" && cargo build --release --workspace )

  say "Drawing the icon"
  local iconset="${BUILD}/selfhost.iconset"
  rm -rf "$iconset"
  ( cd "$REPO" && cargo run --release --quiet -p rui --example icon -- --out "$iconset" >/dev/null )
  iconutil --convert icns "$iconset" --output "${BUILD}/selfhost.icns"
  note "$(ls "$iconset" | wc -l | tr -d ' ') sizes rendered, each at its own resolution"

  say "Assembling ${APP_NAME}.app"
  rm -rf "$STAGED"
  mkdir -p "${STAGED}/Contents/MacOS" "${STAGED}/Contents/Resources"
  cp "${REPO}/target/release/selfhost-console" "${STAGED}/Contents/MacOS/selfhost-console"
  cp "${BUILD}/selfhost.icns" "${STAGED}/Contents/Resources/selfhost.icns"
  printf 'APPL????' > "${STAGED}/Contents/PkgInfo"

  # LSUIElement is deliberately absent: this *is* a normal windowed application
  # and should appear in the Dock and the app switcher like one.
  cat > "${STAGED}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key><string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleExecutable</key><string>selfhost-console</string>
  <key>CFBundleIconFile</key><string>selfhost</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>0.1.0</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

  # Ad-hoc signature. Not a distribution signature and does not pretend to be —
  # it gives the bundle a stable identity so macOS stops re-asking for any
  # permission it is granted, which an unsigned binary is asked for every build.
  codesign --force --sign - --timestamp=none "$STAGED" >/dev/null 2>&1 \
    || note "could not ad-hoc sign (harmless; permissions may be re-asked after each build)"

  note "$STAGED"
}

# ---------------------------------------------------------------- Dock

# The Dock's pinned applications are an array of dictionaries in its
# preferences. `defaults` can append one but cannot remove one, so removal
# exports the domain, edits it with PlistBuddy, and imports it back. Editing the
# plist file directly would race the preferences daemon's own cache.
# A tile for this application is present, in whichever of the two forms it is
# currently written in.
#
# There are two, and confusing them pins a second copy of the same application
# on every install. What we write is the plain path; the Dock rewrites the tile
# when it next processes it, into a percent-encoded URL with the bundle
# identifier alongside — "/Applications/Selfhost Console.app" becomes
# "file:///Applications/Selfhost%20Console.app/". Matching only the path we
# wrote misses every tile the Dock has touched; matching only the bundle
# identifier misses every tile it has not touched *yet*, which includes the one
# written seconds ago. So: undo the encoding and match the path, which appears
# in both forms, and accept the identifier as well.
dock_contains_app() {
  local tiles
  tiles="$(defaults read com.apple.dock persistent-apps 2>/dev/null | sed 's/%20/ /g')"
  grep -qF "${APP_NAME}.app" <<< "$tiles" \
    || grep -qF "\"bundle-identifier\" = \"${BUNDLE_ID}\"" <<< "$tiles"
}

dock_pin() {
  if dock_contains_app; then
    note "already in the Dock"
    return
  fi
  defaults write com.apple.dock persistent-apps -array-add "<dict>
      <key>tile-data</key><dict>
        <key>file-data</key><dict>
          <key>_CFURLString</key><string>${APP}</string>
          <key>_CFURLStringType</key><integer>0</integer>
        </dict>
      </dict>
    </dict>"
  killall Dock
  note "pinned to the Dock"
}

dock_unpin() {
  if ! dock_contains_app; then
    note "not in the Dock"
    return
  fi
  local plist="${TMPDIR:-/tmp}/selfhost-dock.plist"
  defaults export com.apple.dock "$plist"

  # Counted by walking until there is no next one, rather than by matching the
  # shape of PlistBuddy's output — which is indentation its authors are free to
  # change.
  local total=0
  while /usr/libexec/PlistBuddy -c "Print :persistent-apps:${total}" "$plist" >/dev/null 2>&1; do
    total=$(( total + 1 ))
  done

  # Backwards, so removing one does not renumber the ones not yet examined.
  # Every match goes, not just the first: a duplicate is exactly what the old
  # path-matching check used to leave behind, and an uninstall that removed one
  # of two would look like it had not worked.
  local index identifier url removed=0
  for (( index = total - 1; index >= 0; index-- )); do
    identifier="$(/usr/libexec/PlistBuddy -c "Print :persistent-apps:${index}:tile-data:bundle-identifier" "$plist" 2>/dev/null || true)"
    url="$(/usr/libexec/PlistBuddy -c "Print :persistent-apps:${index}:tile-data:file-data:_CFURLString" "$plist" 2>/dev/null | sed 's/%20/ /g' || true)"
    if [[ "$identifier" == "$BUNDLE_ID" || "$url" == *"${APP_NAME}.app"* ]]; then
      /usr/libexec/PlistBuddy -c "Delete :persistent-apps:${index}" "$plist"
      removed=$(( removed + 1 ))
    fi
  done

  defaults import com.apple.dock "$plist"
  rm -f "$plist"
  killall Dock
  note "removed ${removed} tile(s) from the Dock"
}

# ---------------------------------------------------------------- install

install_app() {
  build_bundle

  # Asked before the bundle is touched, because after it is replaced there is no
  # way to tell whether the console on screen was the one we just overwrote.
  local was_running=no
  console_running && was_running=yes

  say "Installing to ${INSTALL_DIR}"
  quit_console
  if [[ -e "$APP" ]]; then
    rm -rf "$APP" 2>/dev/null || die "cannot replace ${APP} — remove it by hand, or run this with sudo"
  fi
  cp -R "$STAGED" "$APP" 2>/dev/null || die "cannot write to ${INSTALL_DIR} — run this with sudo, or use ~/Applications"
  note "$APP"

  # So the Finder and the Dock notice a bundle that was copied rather than
  # downloaded; without it the icon can stay generic until the next log-in.
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f "$APP" >/dev/null 2>&1 || true

  say "Linking the command line"
  if ln -sf "${REPO}/target/release/selfhost" "$CLI_LINK" 2>/dev/null; then
    note "${CLI_LINK} -> target/release/selfhost"
  else
    note "could not write ${CLI_LINK}; add this to your PATH instead:"
    note "  export PATH=\"${REPO}/target/release:\$PATH\""
  fi

  dock_pin

  # Reopened only if it was open, so an install run from a terminal does not
  # throw a window in front of whatever is being worked on. `open` goes through
  # LaunchServices, which is what the Dock tile does — the same instance, so the
  # tile stays live rather than growing a second, unpinned copy beside it.
  if [[ "$was_running" == yes ]]; then
    say "Reopening ${APP_NAME}"
    open -a "$APP" 2>/dev/null && note "running the build that was just installed" \
      || note "could not reopen it — start it from the Dock"
  fi

  say "Installed"
  cat <<DONE
  Start the daemon in the directory holding selfhost.config.toml:

      selfhost daemon

  Then open ${APP_NAME} from the Dock. The daemon records where it is running,
  so the console finds it without being told. Opening the console first is fine
  too — it will say no daemon is running, and connect as soon as one is.

  To remove everything: scripts/macos-app.sh uninstall
DONE
}

# ---------------------------------------------------------------- uninstall

uninstall_app() {
  say "Removing ${APP_NAME}"
  dock_unpin

  if [[ -e "$APP" ]]; then
    # A running console holds no lock on its own bundle, but removing the
    # bundle under it leaves a window nobody can quit from the Dock.
    quit_console
    rm -rf "$APP" 2>/dev/null || die "cannot remove ${APP} — run this with sudo"
    note "removed $APP"
  else
    note "no bundle at $APP"
  fi

  if [[ -L "$CLI_LINK" ]]; then
    rm -f "$CLI_LINK" 2>/dev/null && note "removed $CLI_LINK" \
      || note "could not remove $CLI_LINK — run this with sudo"
  fi

  rm -rf "$BUILD"

  say "Removed"
  cat <<DONE
  The application is gone. Your project, its config, and its data are not —
  removing an application must not delete what it was managing.

  To remove those as well, in the directory holding selfhost.config.toml:

      selfhost teardown              # services, checkouts, catalogue, token
      selfhost teardown --everything # the above and the whole data directory
DONE
}

# ---------------------------------------------------------------- entry

case "${1:-}" in
  install)   install_app ;;
  uninstall) uninstall_app ;;
  bundle)    build_bundle ;;
  *)
    cat >&2 <<USAGE
Usage: scripts/macos-app.sh <install|uninstall|bundle>

  install     build, bundle, install to ${INSTALL_DIR}, pin to the Dock, and
              reopen the console if it was running
  uninstall   unpin, remove the bundle and the ${CLI_LINK} link
  bundle      build the .app into target/macos-app and stop there
USAGE
    exit 2
    ;;
esac
