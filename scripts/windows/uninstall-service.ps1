# uninstall-service.ps1 — stop and remove the selfhost startup service.
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName selfhost
Unregister-ScheduledTask -TaskName selfhost -Confirm:$false
Get-Process selfhost -EA SilentlyContinue | Stop-Process -Force
Write-Output 'selfhost service removed and process stopped.'
