# uninstall-service.ps1 — stop and remove the selfhost startup service.
#
# Delegates to `selfhost service uninstall --system`, the one authoritative
# de-registrar (crates/app/cli/src/service_install.rs), which unregisters the
# "selfhost-daemon" Scheduled Task — never "selfhost", a name superseded and
# already removed by any `service install`/`service check --repair` this box
# has run since. The old version of this script targeted "selfhost" directly
# and had stopped removing anything real the day that rename shipped.
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\Users\Alex\Self-Host'
$exe = Join-Path $dir 'target\release\selfhost.exe'

if (Test-Path $exe) {
  & $exe service uninstall --system --yes
} else {
  Write-Output "binary not found at $exe; falling back to removing the scheduled task by name only"
}

# Best-effort cleanup of the legacy "selfhost" task name, in case this box
# was ever registered by the old hand-rolled installer and never repaired.
Stop-ScheduledTask -TaskName selfhost
Unregister-ScheduledTask -TaskName selfhost -Confirm:$false

Get-Process selfhost -EA SilentlyContinue | Stop-Process -Force
Write-Output 'selfhost service removed and process stopped.'
