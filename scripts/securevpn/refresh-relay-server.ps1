# Brings the installed Secure-VPN server up to the version the daemon drives.
#
# The daemon passes `--account-manager`, `--account-manager-token-file` and
# `--location`; an installed server.py that predates them exits on argparse and
# every relay stays down. This fetches the current server, keeps the old files
# beside it, proves the relay stays up by hand, and only then restarts the daemon.
#
#   powershell -ExecutionPolicy Bypass -File scripts\securevpn\refresh-relay-server.ps1
param(
  [string]$LiveDir = 'C:\ProgramData\selfhost\securevpn',
  [string]$Source  = 'https://github.com/RockyWearsAHat/Secure-VPN.git'
)
$ErrorActionPreference = 'Stop'

$checkout = Join-Path $env:TEMP 'securevpn-refresh'
if (Test-Path $checkout) { Remove-Item $checkout -Recurse -Force }
git clone --quiet --depth 1 $Source $checkout
"fetched    $(git -C $checkout log --oneline -1)"

$backup = Join-Path $LiveDir ("backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory $backup | Out-Null
Get-ChildItem $LiveDir -Filter *.py | Copy-Item -Destination $backup
"backed up  $backup"

# Only the server's own modules. The image-auth package under scripts\ is left
# out on purpose: without it protocol.py falls back to the handshake every
# already-joined client speaks.
Get-ChildItem $checkout -Filter *.py | Where-Object { $_.Name -notlike 'test_*' } |
  Copy-Item -Destination $LiveDir -Force

python -m pip install --quiet aiohttp
"aiohttp    $(python -c 'import aiohttp; print(aiohttp.__version__)')"

$try = Join-Path $PSScriptRoot 'try-relay.ps1'
$result = & powershell -NoProfile -ExecutionPolicy Bypass -File $try ssh
$result
if (-not ($result -match 'STILL RUNNING')) {
  Get-ChildItem $backup -Filter *.py | Copy-Item -Destination $LiveDir -Force
  "RELAY DID NOT STAY UP - old files restored, daemon untouched"
  exit 1
}

Stop-ScheduledTask selfhost-daemon
Start-Sleep 5
Start-ScheduledTask selfhost-daemon
Start-Sleep 25
foreach ($port in 8443, 8444) {
  "port $port  $((Test-NetConnection 127.0.0.1 -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded)"
}
