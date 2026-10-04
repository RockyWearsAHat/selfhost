$ErrorActionPreference = 'Continue'
$side = 'D:\selfhost-m7\run'
$exe = 'D:\selfhost-m7\target\release\selfhost.exe'
$types = @{ 'A' = 1; 'NS' = 2; 'MX' = 15; 'TXT' = 16; 'AAAA' = 28 }
function Query([string]$server, [int]$port, [string]$type, [string]$name, [int]$id, [int]$wait = 2500) {
  $q = New-Object System.Collections.Generic.List[byte]
  $q.AddRange([byte[]]@((($id -shr 8) -band 255), ($id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
  foreach ($label in $name.TrimEnd('.').Split('.')) { $q.Add([byte]$label.Length); $q.AddRange([Text.Encoding]::ASCII.GetBytes($label)) }
  $t = $types[$type]; $q.AddRange([byte[]]@(0, (($t -shr 8) -band 255), ($t -band 255), 0, 1))
  $udp = New-Object Net.Sockets.UdpClient; $udp.Client.ReceiveTimeout = $wait
  $watch = [Diagnostics.Stopwatch]::StartNew()
  try {
    [void]$udp.Send($q.ToArray(), $q.Count, $server, $port)
    $from = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
    $r = $udp.Receive([ref]$from)
  } catch { return "{0,5}ms NO ANSWER" -f $watch.ElapsedMilliseconds } finally { $udp.Close() }
  $ms = $watch.ElapsedMilliseconds
  $rcode = @('NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED')[$r[3] -band 15]
  $an = $r[6] * 256 + $r[7]
  $i = 12
  while ($r[$i] -ne 0) { $i += $r[$i] + 1 }; $i += 5
  $data = @()
  for ($k = 0; $k -lt $an; $k++) {
    if (($r[$i] -band 192) -eq 192) { $i += 2 } else { while ($r[$i] -ne 0) { $i += $r[$i] + 1 }; $i += 1 }
    $rt = $r[$i] * 256 + $r[$i+1]; $len = $r[$i+8] * 256 + $r[$i+9]; $i += 10
    if ($rt -eq 1) { $data += ($r[$i..($i+3)] -join '.') }
    elseif ($rt -eq 28) { $data += ([Net.IPAddress]::new([byte[]]$r[$i..($i+15)])).ToString() }
    else { $data += "type$rt/$len" }
    $i += $len
  }
  "{0,5}ms {1} an={2} {3}" -f $ms, $rcode, $an, (($data | Sort-Object) -join ',')
}

# The live situation in miniature: a plain (no SO_REUSEADDR) UDP socket and
# TCP listener hold the port first, like the daemon's :53; lan-dns then binds
# with SO_REUSEADDR. Does it bind, and who receives the queries?
$old = 'C:\Users\Alex\Self-Host\target\release\selfhost.exe'
"new exe sha $((Get-FileHash -Algorithm SHA256 $exe).Hash.Substring(0,16).ToLower())"
function Stream($port, [double]$seconds, [scriptblock]$at1s) {
  $clock = [Diagnostics.Stopwatch]::StartNew(); $fired = $false; $log = @(); $id = 1000
  while ($clock.Elapsed.TotalSeconds -lt $seconds) {
    if (-not $fired -and $clock.ElapsedMilliseconds -ge 1000) { & $at1s; $fired = $true; $log += [pscustomobject]@{ t = $clock.ElapsedMilliseconds; kind = 'event'; ms = 0 } }
    $r = Query '127.0.0.1' $port 'A' 'rockywearsahat.com' ($id++ % 65000) 150
    $log += [pscustomobject]@{ t = $clock.ElapsedMilliseconds; kind = $(if ($r -match 'NO ANSWER') { 'miss' } else { 'ok' }); ms = [int](($r -split 'ms')[0].Trim()) }
    Start-Sleep -Milliseconds 20
  }
  $log
}
function Summary($log) {
  $q = @($log | Where-Object { $_.kind -ne 'event' })
  $miss = @($q | Where-Object { $_.kind -eq 'miss' })
  $event = (@($log | Where-Object { $_.kind -eq 'event' }) | Select-Object -First 1).t
  $after = @($q | Where-Object { $_.t -gt $event -and $_.kind -eq 'ok' }) | Select-Object -First 1
  $okms = @($q | Where-Object { $_.kind -eq 'ok' } | ForEach-Object { $_.ms } | Sort-Object)
  "queries $($q.Count), answered $($q.Count - $miss.Count), unanswered $($miss.Count) at ms [$((($miss | ForEach-Object { $_.t }) -join ','))]; event at $event ms; first answer after it at $($after.t) ms; answer latency p50 $($okms[[int]($okms.Count/2)]) ms max $($okms[-1]) ms"
}
Remove-Item "$side\data\dns-handoff" -ErrorAction SilentlyContinue

"=== A: cutover from the old binary (plain bind) to a waiting lan-dns, port 15355"
$o = Start-Process -FilePath $old -ArgumentList 'serve-dns','--bind','127.0.0.1:15355' -WorkingDirectory $side -RedirectStandardOutput "$side\a-old.out" -RedirectStandardError "$side\a-old.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
$n = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind','127.0.0.1:15355' -WorkingDirectory $side -RedirectStandardOutput "$side\a-new.out" -RedirectStandardError "$side\a-new.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
"old alive $(-not $o.HasExited), new alive (waiting) $(-not $n.HasExited)"
$log = Stream 15355 4 { Stop-Process -Id $o.Id -Force }
Summary $log
"new stdout:"; Get-Content "$side\a-new.out" -Tail 3
"new stderr:"; Get-Content "$side\a-new.err" -Tail 2
Stop-Process -Id $n.Id -Force -ErrorAction SilentlyContinue
Remove-Item "$side\data\dns-handoff" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

"=== B: true handoff between two new instances, port 15356"
$a = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind','127.0.0.1:15356' -WorkingDirectory $side -RedirectStandardOutput "$side\b-a.out" -RedirectStandardError "$side\b-a.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
1..4 | ForEach-Object { [void](Query '127.0.0.1' 15356 'A' 'rockywearsahat.com' (50 + $_) 500) }
Start-Sleep -Seconds 2
"A pid $($a.Id) handoff file: $(Get-Content "$side\data\dns-handoff" -ErrorAction SilentlyContinue)"
$script:b = $null
$log = Stream 15356 14 { $script:b = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind','127.0.0.1:15356' -WorkingDirectory $side -RedirectStandardOutput "$side\b-b.out" -RedirectStandardError "$side\b-b.err" -PassThru -WindowStyle Hidden }
Summary $log
"B pid $($b.Id) alive $(-not $b.HasExited); A alive $(-not $a.HasExited); handoff file: $(Get-Content "$side\data\dns-handoff" -ErrorAction SilentlyContinue)"
"A stdout:"; Get-Content "$side\b-a.out" -Tail 2; "A stderr:"; Get-Content "$side\b-a.err" -Tail 2
"B stdout:"; Get-Content "$side\b-b.out" -Tail 2; "B stderr:"; Get-Content "$side\b-b.err" -Tail 2
foreach ($proc in @($a, $b)) { if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } }
Start-Sleep -Seconds 1
"== stragglers"; Get-CimInstance Win32_Process -Filter "Name='selfhost.exe'" | ForEach-Object { "$($_.ProcessId) $($_.CommandLine.Substring(0, [math]::Min(90, $_.CommandLine.Length)))" }
"== :53 owners"; Get-NetUDPEndpoint -LocalPort 53 | ForEach-Object { "$($_.LocalAddress) pid $($_.OwningProcess)" }
