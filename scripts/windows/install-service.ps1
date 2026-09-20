# install-service.ps1 — register selfhost as a Windows startup service.
#
# What it does (review before running):
#   - Delegates entirely to `selfhost service install --system`, the one
#     authoritative registrar (crates/app/cli/src/service_install.rs). That
#     command registers the Scheduled Task named "selfhost-daemon" — never
#     "selfhost", a name `service install`/`service check --repair` actively
#     removes as superseded (SUPERSEDED_TASK_NAMES) — running through the
#     keep-alive wrapper it generates, AT SYSTEM STARTUP, as the SYSTEM
#     account, with auto-restart.
#   - This is what makes the site stay up 24/7 without anyone logged in.
#   - It is a "persistence" mechanism — that is the whole point of a server —
#     which is why `service install` prints the full plan and asks for
#     confirmation before writing anything (bypassed here with -y since this
#     script is itself the deliberate step).
#
# This script used to hand-roll its own Register-ScheduledTask call, under
# the name "selfhost" — the very name `service install` supersedes and
# removes. That meant this script would register one task, `service check
# --repair` (below) would immediately delete it and create "selfhost-daemon"
# in its place, and the final Start-ScheduledTask -TaskName 'selfhost' would
# then fail because that task no longer existed. Fixed by deleting the
# duplicated logic and delegating to the one registrar instead of
# maintaining a second, competing implementation of it.
#
# Reverse any time with:  scripts\uninstall-service.ps1
#   (or:  selfhost service uninstall --system)

$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\Alex\Self-Host'
$exe = Join-Path $dir 'target\release\selfhost.exe'
$taskName = 'selfhost-daemon'

if (-not (Test-Path $exe)) { throw "binary not found: $exe (build it first)" }

Push-Location $dir
try {
  & $exe service install --system --yes
  if ($LASTEXITCODE -ne 0) {
    throw "selfhost service install failed (see above)"
  }
} finally {
  Pop-Location
}

Start-Sleep -Seconds 7

Write-Output '=== listening on 80/443 (expect 0.0.0.0 both) ==='
Get-NetTCPConnection -State Listen -LocalPort 80,443 -EA SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -Auto | Out-String

Write-Output '=== task result (0 = ok) ==='
Get-ScheduledTask -TaskName $taskName | Get-ScheduledTaskInfo |
  Select-Object LastRunTime,LastTaskResult | Format-Table -Auto | Out-String
