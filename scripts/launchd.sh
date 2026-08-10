#!/bin/sh
# Automatic startup for a selfhost deployment on macOS, via launchd.
#
# Installs two LaunchAgents for the current user:
#
#   com.selfhost.daemon — `selfhost daemon` (services + control API)
#   com.selfhost.proxy  — `selfhost run`    (the websites)
#
# Both start at login and are restarted by launchd if they die. The daemon
# already handles SIGTERM by stopping its services cleanly, which is exactly
# how launchd stops a job.
#
#   scripts/launchd.sh install [daemon-dir] [proxy-dir]
#   scripts/launchd.sh uninstall
#   scripts/launchd.sh status
#
# daemon-dir / proxy-dir are the deployment directories holding each program's
# selfhost.config.toml. Defaults: the repository root for the proxy, .demo for
# the daemon (the demo deployment that already carries services).
#
# A LaunchAgent runs when this user logs in. For a machine that must serve with
# nobody logged in, promote the same plists to /Library/LaunchDaemons (sudo),
# or enable automatic login — the roadmap's "service install" item is the real
# fix and is not built yet.

set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
binary="$repo/target/release/selfhost"
agents="$HOME/Library/LaunchAgents"

daemon_dir="${2:-$repo/.demo}"
proxy_dir="${3:-$repo}"

# Writes one job plist: $1 label, $2 subcommand, $3 working directory.
write_plist() {
    label="$1" command="$2" directory="$3"
    mkdir -p "$directory/data"
    cat > "$agents/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$binary</string>
        <string>$command</string>
    </array>
    <key>WorkingDirectory</key><string>$directory</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$directory/data/launchd-$command.log</string>
    <key>StandardErrorPath</key><string>$directory/data/launchd-$command.log</string>
</dict>
</plist>
PLIST
}

# Loads $1, replacing a copy launchd already holds so install is repeatable.
reload() {
    launchctl bootout "gui/$(id -u)/$1" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$agents/$1.plist"
}

case "${1:-}" in
install)
    [ -x "$binary" ] || { echo "build first: cargo build --release -p selfhost-cli" >&2; exit 1; }
    [ -f "$daemon_dir/selfhost.config.toml" ] || { echo "no selfhost.config.toml in $daemon_dir" >&2; exit 1; }
    [ -f "$proxy_dir/selfhost.config.toml" ] || { echo "no selfhost.config.toml in $proxy_dir" >&2; exit 1; }

    mkdir -p "$agents"
    write_plist com.selfhost.daemon daemon "$daemon_dir"
    write_plist com.selfhost.proxy run "$proxy_dir"
    reload com.selfhost.daemon
    reload com.selfhost.proxy
    echo "installed — both start at login and restart if they die:"
    echo "  com.selfhost.daemon  in $daemon_dir"
    echo "  com.selfhost.proxy   in $proxy_dir"
    ;;
uninstall)
    for label in com.selfhost.daemon com.selfhost.proxy; do
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
        rm -f "$agents/$label.plist"
    done
    echo "uninstalled — nothing selfhost starts at login any more"
    ;;
status)
    launchctl list | grep selfhost || echo "no selfhost jobs loaded"
    ;;
*)
    echo "usage: scripts/launchd.sh install [daemon-dir] [proxy-dir] | uninstall | status" >&2
    exit 1
    ;;
esac
