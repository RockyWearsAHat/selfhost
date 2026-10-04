$ErrorActionPreference = 'Continue'
$side = 'D:\selfhost-m7\run'
$exe = 'D:\selfhost-m7\target\release\selfhost.exe'
New-Item -ItemType Directory -Force "$side\data" | Out-Null
Copy-Item 'C:\Users\Alex\Self-Host\selfhost.config.toml' "$side\selfhost.config.toml" -Force
"exe sha $((Get-FileHash -Algorithm SHA256 $exe).Hash.Substring(0,16).ToLower())"
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
"== control: 127.0.0.1:15353 before the side starts (must be NO ANSWER)"
"  " + (Query '127.0.0.1' 15353 'A' 'example.com' 1)
"== control: live 192.168.1.8:53 (must answer)"
"  " + (Query '192.168.1.8' 53 'A' 'example.com' 2)
try { $p = Start-Process -FilePath $exe -ArgumentList 'lan-dns','--lan-ip','192.168.1.8','--bind','127.0.0.1:15353' -WorkingDirectory $side -RedirectStandardOutput "$side\lan-dns.out" -RedirectStandardError "$side\lan-dns.err" -PassThru -WindowStyle Hidden -ErrorAction Stop }
catch { "START FAILED: $($_.Exception.Message)"; return }
Start-Sleep -Seconds 8
"side pid $($p.Id) exited: $($p.HasExited)"
$cases = @(
  @('A','rockywearsahat.com'), @('A','git.rockywearsahat.com'), @('A','admin.rockywearsahat.com'),
  @('MX','rockywearsahat.com'), @('NS','rockywearsahat.com'), @('TXT','rockywearsahat.com'),
  @('A','nosuchname-zz9.rockywearsahat.com'),
  @('A','example.com'), @('A','www.google.com'), @('AAAA','www.cloudflare.com'),
  @('A','nxdomain-zz9-selfhost.com'), @('A','leveluplongboarding.surf')
)
$id = 100
foreach ($c in $cases) {
  "== $($c[0]) $($c[1])"
  "  live " + (Query '192.168.1.8' 53 $c[0] $c[1] ($id++))
  "  side " + (Query '127.0.0.1' 15353 $c[0] $c[1] ($id++))
}
"== side burst: 30 distinct-ish names, then repeats (cache)"
$cold = foreach ($n in 'github.com','microsoft.com','apple.com','amazon.com','netflix.com','wikipedia.org','reddit.com','youtube.com','twitch.tv','spotify.com') { (Query '127.0.0.1' 15353 'A' $n ($id++)) }
$warm = foreach ($n in 'github.com','microsoft.com','apple.com','amazon.com','netflix.com','wikipedia.org','reddit.com','youtube.com','twitch.tv','spotify.com') { (Query '127.0.0.1' 15353 'A' $n ($id++)) }
"  cold: " + (($cold | ForEach-Object { ($_ -split 'ms')[0].Trim() + '/' + ($_ -split ' ')[1+(($_ -split ' ') | Where-Object {$_ -eq ''}).Count] }) -join ' ')
"  cold raw: " + (($cold | ForEach-Object { $_.Substring(0, [math]::Min(22, $_.Length)) }) -join ' | ')
"  warm raw: " + (($warm | ForEach-Object { $_.Substring(0, [math]::Min(22, $_.Length)) }) -join ' | ')
$proc = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($proc) { "side footprint: working set $([math]::Round($proc.WorkingSet64/1MB,1)) MB, private $([math]::Round($proc.PrivateMemorySize64/1MB,1)) MB, cpu $([math]::Round($proc.TotalProcessorTime.TotalSeconds,2)) s, threads $($proc.Threads.Count), handles $($proc.HandleCount)" }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
"side stopped: $($null -eq (Get-Process -Id $p.Id -ErrorAction SilentlyContinue))"
"== control after stop: 127.0.0.1:15353 (must be NO ANSWER)"
"  " + (Query '127.0.0.1' 15353 'A' 'example.com' 9)
"== :53 owners after"; Get-NetUDPEndpoint -LocalPort 53 | ForEach-Object { "$($_.LocalAddress):53 pid $($_.OwningProcess)" }
"== side stderr"; Get-Content "$side\lan-dns.err" -Tail 15
"== side stdout tail"; Get-Content "$side\lan-dns.out" -Tail 4
