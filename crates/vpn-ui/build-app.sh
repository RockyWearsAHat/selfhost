#!/bin/bash
# build-app.sh — build the VPN panel and wrap it in a double-clickable .app.
#
# Produces target/SelfHostVPN.app. Also copies the key-rotation script to
# ~/.securevpn/ where the app calls it. Run from anywhere.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
app="$root/target/SelfHostVPN.app"
bin="selfhost-vpn-ui"

echo "building $bin (release)…"
cargo build --release -p selfhost-vpn-ui --manifest-path "$root/Cargo.toml"

echo "assembling $app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$root/target/release/$bin" "$app/Contents/MacOS/$bin"
# The console gate rides in the bundle so the app's one-time privileged setup
# can install it as the com.selfhost.console-gate LaunchDaemon (docs/VPN.md).
cp "$root/target/release/selfhost-console-gate" "$app/Contents/MacOS/selfhost-console-gate"

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SelfHost VPN</string>
  <key>CFBundleDisplayName</key><string>SelfHost VPN</string>
  <key>CFBundleIdentifier</key><string>com.selfhost.vpn</string>
  <key>CFBundleExecutable</key><string>selfhost-vpn-ui</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# The app runs ~/.securevpn/rotate-keys.sh for the "Rotate now" button and the
# weekly auto-rotation; keep a current copy there.
if [ -f "$root/scripts/securevpn/rotate-keys.sh" ]; then
  mkdir -p "$HOME/.securevpn"
  cp "$root/scripts/securevpn/rotate-keys.sh" "$HOME/.securevpn/rotate-keys.sh"
  chmod +x "$HOME/.securevpn/rotate-keys.sh"
  echo "installed rotate-keys.sh to ~/.securevpn/"
fi

echo
echo "done: $app"
echo "open it with:  open \"$app\""
echo "or drag it into /Applications."
