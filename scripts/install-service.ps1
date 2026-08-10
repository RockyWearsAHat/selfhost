# install-service.ps1 — register selfhost as a Windows startup service.
#
# What it does (review before running):
#   - Creates a Scheduled Task named "selfhost" that runs
#       C:\Users\Alex\Self-Host\target\release\selfhost.exe run
#     from the repo dir, AT SYSTEM STARTUP, as the SYSTEM account, with
#     auto-restart (3 tries, 1 min apart) and no run-time limit.
#   - This is what makes the site stay up 24/7 without anyone logged in.
#   - It is a "persistence" mechanism — that is the whole point of a server —
#     which is why it must be installed deliberately by you.
#
# Reverse it any time with:  scripts\uninstall-service.ps1
#   (or:  Unregister-ScheduledTask -TaskName selfhost -Confirm:$false;
#          Stop-ScheduledTask -TaskName selfhost)

$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\Alex\Self-Host'
$exe = Join-Path $dir 'target\release\selfhost.exe'

if (-not (Test-Path $exe)) { throw "binary not found: $exe (build it first)" }

$action    = New-ScheduledTaskAction -Execute $exe -Argument 'run' -WorkingDirectory $dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName 'selfhost' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'selfhost'
Start-Sleep -Seconds 7

Write-Output '=== listening on 80/443 (expect 0.0.0.0 both) ==='
Get-NetTCPConnection -State Listen -LocalPort 80,443 -EA SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -Auto | Out-String

Write-Output '=== task result (0 = ok) ==='
Get-ScheduledTask -TaskName selfhost | Get-ScheduledTaskInfo |
  Select-Object LastRunTime,LastTaskResult | Format-Table -Auto | Out-String
