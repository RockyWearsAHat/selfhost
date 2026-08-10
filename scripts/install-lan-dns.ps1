# install-lan-dns.ps1 — register the split-horizon LAN DNS resolver as a startup
# service. It answers the hosted domains with the box's LAN IP (192.168.1.8) and
# forwards everything else upstream, so every device on the network reaches your
# sites without per-device hosts edits.
#
# This is a persistence mechanism (a startup service running as SYSTEM), which is
# why you install it deliberately. Reverse with: uninstall-lan-dns.ps1
$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\Alex\Self-Host'
$exe = Join-Path $dir 'target\release\selfhost.exe'
if (-not (Test-Path $exe)) { throw "binary not found: $exe" }

$action    = New-ScheduledTaskAction -Execute $exe -Argument 'lan-dns --lan-ip 192.168.1.8' -WorkingDirectory $dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName 'selfhost-lan-dns' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'selfhost-lan-dns'
Start-Sleep -Seconds 5

Write-Output '=== self-test (hosted name should be 192.168.1.8) ==='
(Resolve-DnsName rockywearsahat.com -Server 127.0.0.1 -Type A -DnsOnly -EA SilentlyContinue).IPAddress
Write-Output '=== external (should be a real internet IP) ==='
(Resolve-DnsName example.com -Server 127.0.0.1 -Type A -DnsOnly -EA SilentlyContinue | Where-Object IPAddress).IPAddress | Select-Object -First 1
Write-Output ''
Write-Output 'Installed. Now set the router DHCP DNS server to 192.168.1.8 and reboot devices.'
