# install-vpn-service.ps1 - run the Secure-VPN server as a boot service on the box.
#
# The Secure-VPN server (github.com/RockyWearsAHat/Secure-VPN, vendored under
# C:\ProgramData\selfhost\securevpn) accepts mutually-authenticated, encrypted
# connections on TCP 8443 and forwards each to the selfhost proxy on
# 127.0.0.1:443. It is the ONLY public door to the admin console: the console
# site (rockywearsahat.com) is gated to loopback in the proxy, so the box's own
# tunnel exit is the sole source address that may reach it.
#
# Security model (see docs/VPN.md):
#   - 8443 answers nothing without the client's pre-shared Ed25519 key - silent
#     to scanners.
#   - Keys live in C:\ProgramData\selfhost\securevpn\keys, locked to
#     Administrators+SYSTEM (no inheritance). The private key is never printed.
#   - Runs as a Scheduled Task (SYSTEM, at startup, auto-restart) exactly like the
#     other selfhost tasks; NOT named 'selfhost-*' so the firewall reconciler
#     leaves its rule alone.
#
# Usage (run over SSH as administrator):
#   .\install-vpn-service.ps1 [-Python <path>] [-VpnDir <path>]
#
# Idempotent: re-running re-registers the task and refreshes the firewall rule.

param(
  [string]$Python = "",
  [string]$VpnDir = "C:\ProgramData\selfhost\securevpn",
  [int]$ListenPort = 8443,
  [string]$TargetHost = "127.0.0.1",
  [int]$TargetPort = 443
)

$ErrorActionPreference = 'Stop'
$taskName = 'selfhost-vpn'
$keyDir   = Join-Path $VpnDir 'keys'
$server   = Join-Path $VpnDir 'server.py'

# --- 1. Locate Python ---------------------------------------------------------
if (-not $Python) {
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd) { $Python = $cmd.Source }
  foreach ($cand in @(
      "C:\Program Files\Python312\python.exe",
      "C:\Program Files\Python311\python.exe",
      "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")) {
    if (-not $Python -and (Test-Path $cand)) { $Python = $cand }
  }
}
if (-not $Python -or -not (Test-Path $Python)) { throw "Python not found; pass -Python <path>" }
Write-Output "Python: $Python"

if (-not (Test-Path $server)) { throw "Secure-VPN not vendored at $server - copy the repo there first" }

# --- 2. Verify keys exist (generated separately, never by this script) --------
foreach ($f in @('server.key', 'client.pub')) {
  if (-not (Test-Path (Join-Path $keyDir $f))) {
    throw "Missing $f in $keyDir - run generate-keys first (server identity + client public key)"
  }
}

# --- 3. Firewall: inbound allow TCP 8443 (NOT 'selfhost-' prefixed) -----------
# The selfhost firewall reconciler adopts and deletes any rule whose name starts
# 'selfhost-'. Keep this rule outside that namespace so it is never withdrawn.
$fwName = 'SecureVPN 8443'
if (-not (Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $fwName -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $ListenPort | Out-Null
  Write-Output "Firewall rule added: $fwName (TCP $ListenPort)"
} else {
  Write-Output "Firewall rule present: $fwName"
}

# --- 4. Register the scheduled task ------------------------------------------
# Launched through cmd so stdout/stderr land in a real log file (a detached
# SYSTEM task has no console, and the server prints Unicode status marks).
# `-X utf8` forces UTF-8 stdio so those marks cannot raise UnicodeEncodeError
# on a cp1252 console and abort a connection handler; `-u` keeps the log live.
$logFile = Join-Path $VpnDir 'vpn.log'
$pyArgs  = "-X utf8 -u `"$server`" --host 0.0.0.0 --port $ListenPort --ssh-host $TargetHost --ssh-port $TargetPort --key-dir `"$keyDir`" --identity server --peer client"
$cmdLine = "/c `"`"$Python`" $pyArgs >> `"$logFile`" 2>&1`""
$action  = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdLine -WorkingDirectory $VpnDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

$state = (Get-ScheduledTask -TaskName $taskName).State
Write-Output "Scheduled task '$taskName' = $state"
$listening = Get-NetTCPConnection -State Listen -LocalPort $ListenPort -ErrorAction SilentlyContinue
if ($listening) { Write-Output "Listening on ${ListenPort}: OK" } else { Write-Output "WARNING: nothing listening on $ListenPort yet - check the task's last run" }
