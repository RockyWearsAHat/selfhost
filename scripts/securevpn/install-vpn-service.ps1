# install-vpn-service.ps1 - run a Secure-VPN forwarder as a boot service on the box.
#
# The Secure-VPN server (github.com/RockyWearsAHat/Secure-VPN, vendored under
# C:\ProgramData\selfhost\securevpn) accepts mutually-authenticated, encrypted
# connections on one listen port and forwards each session to one fixed
# (host, port) target. `server.py`'s own flags are named --ssh-host/--ssh-port
# because SSH forwarding was the program's original demo shape (see its
# SSH_SETUP.md) — this script repoints those same flags at whatever target the
# deployment needs. One instance is the ONLY public door to the admin console
# (default: TargetPort 443, the selfhost proxy) — the console site
# (rockywearsahat.com) is gated to loopback in the proxy, so that instance's
# tunnel exit is the sole source address that may reach it. A second instance,
# same identity and roster, same pinned client key, pointed at 127.0.0.1:22
# instead, is SSH-02's sanctioned remote-SSH path (see docs/SECURITY.md) — one
# more forwarded target behind the same audited tunnel, not a second VPN
# product.
#
# Multiple instances distinguish themselves by -Name: each gets its own
# Scheduled Task (selfhost-vpn-<Name>) and firewall rule (SecureVPN <port>),
# all sharing the same vendored server.py, key directory and roster file — a
# peer enrolled once is enrolled for every forwarded target, and revoking them
# (deleting their roster entry) revokes every target at once.
#
# Security model (see docs/VPN.md):
#   - Each listen port answers nothing without the client's pre-shared Ed25519
#     key - silent to scanners.
#   - Keys live in C:\ProgramData\selfhost\securevpn\keys, locked to
#     Administrators+SYSTEM (no inheritance). The private key is never printed.
#   - Runs as a Scheduled Task (SYSTEM, at startup, auto-restart) exactly like the
#     other selfhost tasks; the firewall reconciler only ever touches firewall
#     rules, never Scheduled Tasks, so each instance's task name (selfhost-vpn
#     or selfhost-vpn-<Name>) is unaffected either way. Its firewall rule name
#     ('SecureVPN <port>') is what must never start with 'selfhost-' — that
#     prefix is what the reconciler adopts and deletes on sight.
#
# Usage (run over SSH as administrator):
#   .\install-vpn-service.ps1 [-Name <suffix>] [-Python <path>] [-VpnDir <path>] `
#       [-ListenPort <port>] [-TargetHost <host>] [-TargetPort <port>]
#
#   Console (default, unchanged):
#     .\install-vpn-service.ps1
#   SSH, same box, same roster, different door:
#     .\install-vpn-service.ps1 -Name ssh -ListenPort 8444 -TargetHost 127.0.0.1 -TargetPort 22
#
# Idempotent: re-running re-registers the task and refreshes the firewall rule.

param(
  [string]$Name = "",
  [string]$Python = "",
  [string]$VpnDir = "C:\ProgramData\selfhost\securevpn",
  [int]$ListenPort = 8443,
  [string]$TargetHost = "127.0.0.1",
  [int]$TargetPort = 443
)

$ErrorActionPreference = 'Stop'
$taskName = if ($Name) { "selfhost-vpn-$Name" } else { 'selfhost-vpn' }
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

# --- 3. Firewall: inbound allow TCP $ListenPort (NOT 'selfhost-' prefixed) ----
# The selfhost firewall reconciler adopts and deletes any rule whose name starts
# 'selfhost-'. Keep this rule outside that namespace so it is never withdrawn.
$fwName = "SecureVPN $ListenPort"
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
$logFile = Join-Path $VpnDir $(if ($Name) { "vpn-$Name.log" } else { 'vpn.log' })
$pyArgs  = "-X utf8 -u `"$server`" --host 0.0.0.0 --port $ListenPort --ssh-host $TargetHost --ssh-port $TargetPort --key-dir `"$keyDir`" --identity server --peer client"
$cmdLine = "/c `"`"$Python`" $pyArgs >> `"$logFile`" 2>&1`""
$action  = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdLine -WorkingDirectory $VpnDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# ExecutionTimeLimit of zero means *no limit*, and it is not a preference: leave
# it out and Task Scheduler applies its own default of 72 hours and kills the
# server three days after it starts, with the task still sitting in `Ready`. That
# is what happened to `selfhost-lan-dns` on 2026-08-16, and this task is the same
# shape of risk — a VPN killed every three days takes the admin console's only
# reachable route with it.
#
# `selfhost service check` audits this task's settings against the one
# authoritative statement of them (crates/app/cli/src/service_install.rs), and
# the running daemon re-checks every six hours and repairs drift, whichever path
# created the task. It never touches what the task *runs*: the action below
# starts a Python program from another repository and is nobody else's business.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -MultipleInstances IgnoreNew `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

$state = (Get-ScheduledTask -TaskName $taskName).State
Write-Output "Scheduled task '$taskName' = $state"
$listening = Get-NetTCPConnection -State Listen -LocalPort $ListenPort -ErrorAction SilentlyContinue
if ($listening) { Write-Output "Listening on ${ListenPort}: OK" } else { Write-Output "WARNING: nothing listening on $ListenPort yet - check the task's last run" }
