$ErrorActionPreference = 'Continue'
$side = 'D:\selfhost-m7\run'
$exe = 'D:\selfhost-m7\target\release\selfhost.exe'
$types = @{ 'A' = 1; 'NS' = 2; 'MX' = 15; 'TXT' = 16; 'AAAA' = 28 }
function Query([string]$server, [int]$port, [string]$type, [string]$name, [int]$id) {
  $q = New-Object System.Collections.Generic.List[byte]
  $q.AddRange([byte[]]@((($id -shr 8) -band 255), ($id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
  foreach ($label in $name.TrimEnd('.').Split('.')) { $q.Add([byte]$label.Length); $q.AddRange([Text.Encoding]::ASCII.GetBytes($label)) }
  $t = $types[$type]; $q.AddRange([byte[]]@(0, (($t -shr 8) -band 255), ($t -band 255), 0, 1))
  $udp = New-Object Net.Sockets.UdpClient; $udp.Client.ReceiveTimeout = 2500
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
$port = 15354
$old = 'C:\Users\Alex\Self-Host\target\release\selfhost.exe'
"old exe sha $((Get-FileHash -Algorithm SHA256 $old).Hash.Substring(0,16).ToLower())"
"== control before anything: NO ANSWER expected"
"  " + (Query '127.0.0.1' $port 'A' 'example.com' 1)
$o = Start-Process -FilePath $old -ArgumentList 'serve-dns','--bind',"127.0.0.1:$port" -WorkingDirectory $side -RedirectStandardOutput "$side\old.out" -RedirectStandardError "$side\old.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
"old serve-dns pid $($o.Id) exited: $($o.HasExited)"
"== old alone: 5 queries"
1..5 | ForEach-Object { "  " + (Query '127.0.0.1' $port 'A' 'example.com' (10 + $_)) }
$n = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind',"127.0.0.1:$port" -WorkingDirectory $side -RedirectStandardOutput "$side\new.out" -RedirectStandardError "$side\new.err" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 8
"new lan-dns pid $($n.Id) exited: $($n.HasExited)"
"== both bound: 20 queries"
$r = 1..20 | ForEach-Object { Query '127.0.0.1' $port 'A' 'example.com' (100 + $_) }
"answered $(($r | Where-Object { $_ -notmatch 'NO ANSWER' }).Count)/20"
"== old exits (Stop-Process, like the old daemon going away): 20 queries"
Stop-Process -Id $o.Id -Force; Start-Sleep -Milliseconds 300
$r = 1..20 | ForEach-Object { Query '127.0.0.1' $port 'A' 'example.com' (200 + $_) }
"answered $(($r | Where-Object { $_ -notmatch 'NO ANSWER' }).Count)/20"
if (-not $n.HasExited) { Stop-Process -Id $n.Id -Force }
Start-Sleep -Seconds 1
"old query lines logged: $((Select-String -Path "$side\old.out","$side\old.err" -Pattern 'example.com' -SimpleMatch).Count)"
"new stdout:"; Get-Content "$side\new.out" -Tail 3
"new stderr:"; Get-Content "$side\new.err" -Tail 4
"old stderr tail:"; Get-Content "$side\old.err" -Tail 3
"== stragglers"; Get-CimInstance Win32_Process -Filter "Name='selfhost.exe'" | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }
"== :53 owners"; Get-NetUDPEndpoint -LocalPort 53 | ForEach-Object { "$($_.LocalAddress) pid $($_.OwningProcess)" }
