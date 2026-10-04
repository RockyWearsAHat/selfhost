$ErrorActionPreference = 'Continue'
$side = 'D:\selfhost-m7\run'
$exe = 'D:\selfhost-m7\target\release\selfhost.exe'
$port = 15357
"new exe sha $((Get-FileHash -Algorithm SHA256 $exe).Hash.Substring(0,16).ToLower())"
function Packet([int]$id) {
  $q = New-Object System.Collections.Generic.List[byte]
  $q.AddRange([byte[]]@((($id -shr 8) -band 255), ($id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
  foreach ($label in 'rockywearsahat.com'.Split('.')) { $q.Add([byte]$label.Length); $q.AddRange([Text.Encoding]::ASCII.GetBytes($label)) }
  $q.AddRange([byte[]]@(0, 0, 1, 0, 1)); $q.ToArray()
}
# Fire-and-collect: one query every ~2 ms without waiting, replies matched by id.
function Burst([double]$seconds, [scriptblock]$at1s) {
  $udp = New-Object Net.Sockets.UdpClient; $udp.Connect('127.0.0.1', $port)
  $sent = @{}; $got = @{}; $id = 1; $clock = [Diagnostics.Stopwatch]::StartNew(); $fired = $false; $script:eventAt = 0
  $from = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
  while ($clock.Elapsed.TotalSeconds -lt $seconds) {
    if (-not $fired -and $clock.ElapsedMilliseconds -ge 1000) { & $at1s; $fired = $true; $script:eventAt = $clock.ElapsedMilliseconds }
    $p = Packet $id; [void]$udp.Send($p, $p.Length); $sent[$id] = $clock.Elapsed.TotalMilliseconds; $id++
    while ($udp.Available -gt 0) { try { $r = $udp.Receive([ref]$from); $got[$r[0] * 256 + $r[1]] = $true } catch {} }
    $until = $clock.Elapsed.TotalMilliseconds + 2; while ($clock.Elapsed.TotalMilliseconds -lt $until) {}
  }
  $end = $clock.ElapsedMilliseconds + 1500
  while ($clock.ElapsedMilliseconds -lt $end) { while ($udp.Available -gt 0) { try { $r = $udp.Receive([ref]$from); $got[$r[0] * 256 + $r[1]] = $true } catch {} }; Start-Sleep -Milliseconds 5 }
  $udp.Close()
  $lost = @($sent.Keys | Where-Object { -not $got.ContainsKey($_) } | Sort-Object)
  "sent $($sent.Count), answered $($got.Count), lost $($lost.Count); event at $($script:eventAt) ms"
  if ($lost.Count) { "lost send times ms: $((($lost | ForEach-Object { [int]$sent[$_] }) -join ','))"; "lost window ms: $([int]($sent[$lost[-1]] - $sent[$lost[0]]))" }
}
Remove-Item "$side\data\dns-handoff" -ErrorAction SilentlyContinue
$a = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind',"127.0.0.1:$port" -WorkingDirectory $side -RedirectStandardOutput "$side\c-a.out" -RedirectStandardError "$side\c-a.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
"A pid $($a.Id) handoff: $(Get-Content "$side\data\dns-handoff" -ErrorAction SilentlyContinue)"
$script:b = $null
Burst 9 { $script:b = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind',"127.0.0.1:$port" -WorkingDirectory $side -RedirectStandardOutput "$side\c-b.out" -RedirectStandardError "$side\c-b.err" -PassThru -WindowStyle Hidden }
"B alive $(-not $b.HasExited); A alive $(-not $a.HasExited); handoff: $(Get-Content "$side\data\dns-handoff" -ErrorAction SilentlyContinue)"
"A stderr:"; Get-Content "$side\c-a.err" -Tail 2
foreach ($proc in @($a, $b)) { if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } }
Start-Sleep -Seconds 1
"stragglers: $((Get-CimInstance Win32_Process -Filter "Name='selfhost.exe'" | Where-Object { $_.CommandLine -match 'lan-dns' } | ForEach-Object { $_.ProcessId }) -join ',')"
