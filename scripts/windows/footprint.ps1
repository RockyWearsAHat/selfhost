# footprint.ps1 — read-only snapshot of what Self-Host costs this machine, and how
# house DNS is doing. ASSIGNMENT.md §2.1: every efficiency claim is compared
# against a recorded run of this script, never against prose.
#
# Run on the box (or over the VPN SSH tunnel: ssh pc 'powershell -File ...').
# Changes nothing.
param([int]$SampleSeconds = 10, [int]$LogTail = 400000)
$ErrorActionPreference = 'Continue'
$data = 'C:\Users\Alex\Self-Host\data'

"== when"
"local $(Get-Date -Format o)  boot $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o'))"
"cores $([Environment]::ProcessorCount)"

"== deployed"
Push-Location 'C:\Users\Alex\Self-Host'; "commit $(git rev-parse --short HEAD)"; Pop-Location
Get-ScheduledTask selfhost* | ForEach-Object { "task $($_.TaskName) $($_.State)" }

"== processes (cpu rate over ${SampleSeconds}s)"
$procs = Get-Process selfhost* -ErrorAction SilentlyContinue
$before = @{}; $procs | ForEach-Object { $before[$_.Id] = $_.CPU }
Start-Sleep -Seconds $SampleSeconds
foreach ($p in $procs) {
    $p.Refresh()
    $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").CommandLine
    $role = ($cmd -replace '^"[^"]*"\s*', '') -replace '\s+--.*$', ''
    $rate = [math]::Round(($p.CPU - $before[$p.Id]) / $SampleSeconds, 3)
    $hot = $p.Threads | Sort-Object { $_.TotalProcessorTime } -Descending | Select-Object -First 1
    "pid $($p.Id) role [$role] cores_busy $rate cpu_total_s $([int]$p.CPU) ws_mb $([int]($p.WorkingSet64/1MB)) private_mb $([int]($p.PrivateMemorySize64/1MB)) threads $($p.Threads.Count) handles $($p.HandleCount) hottest_tid $($hot.Id) hottest_s $([int]$hot.TotalProcessorTime.TotalSeconds) started $($p.StartTime.ToString('o'))"
}

"== sockets"
Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | ForEach-Object { "udp53 $($_.LocalAddress) pid $($_.OwningProcess)" }
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | ForEach-Object { "box_resolver $($_.InterfaceAlias) $($_.ServerAddresses -join ',')" }

"== logs"
Get-ChildItem $data -Filter *.log | Sort-Object Length -Descending | Select-Object -First 4 | ForEach-Object { "log $($_.Name) mb $([math]::Round($_.Length/1MB,1))" }

"== house dns (last $LogTail log lines)"
$lines = Get-Content (Join-Path $data 'selfhost-daemon.log') -Tail $LogTail | Where-Object { $_ -like '*`[dns`]*' }
$first = ($lines | Select-Object -First 1).Substring(0, 15); $last = ($lines | Select-Object -Last 1).Substring(0, 15)
$lan = $lines | Where-Object { $_ -match '\] 192\.168\.' }
$fail = $lan | Where-Object { $_ -match ' SERVFAIL ' }
$slow = $lan | Where-Object { $_ -match ' (\d+)ms$' -and [int]$Matches[1] -ge 1000 }
$ms = $lan | ForEach-Object { if ($_ -match ' (\d+)ms$') { [int]$Matches[1] } } | Sort-Object
$p = { param($q) if ($ms.Count) { $ms[[math]::Min($ms.Count - 1, [int]($ms.Count * $q))] } else { 0 } }
"window $first .. $last"
"lan_queries $($lan.Count) servfail $($fail.Count) slow_ge_1s $($slow.Count) p50_ms $(& $p 0.5) p99_ms $(& $p 0.99) p999_ms $(& $p 0.999)"
"servfail_by_day:"; $fail | ForEach-Object { $_.Substring(0, 5) } | Group-Object | ForEach-Object { "  $($_.Name) $($_.Count)" }
"server_stopped_events:"; Get-Content (Join-Path $data 'daemon-startup.log') -ErrorAction SilentlyContinue | Select-String 'DNS server stopped' | ForEach-Object { "  $($_.Line)" }
