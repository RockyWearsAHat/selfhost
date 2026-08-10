# lan-hosts.ps1 — make THIS Windows PC resolve the selfhost box's hosted domains
# to its LAN address, to browse them from inside the network (NAT hairpin makes
# the public IP time out from home). Run in an ADMIN PowerShell.
#
#   .\lan-hosts.ps1 apply
#   .\lan-hosts.ps1 remove
#   .\lan-hosts.ps1 list
#
# Domains are pulled live from the box via `selfhost routes`. Override via env:
#   SELFHOST_BOX_IP (default 192.168.1.8), SELFHOST_SSH (default alexdesktop),
#   SELFHOST_ROUTES_CMD, or SELFHOST_DOMAINS (space-separated; skips SSH).
param([string]$Mode = 'apply')

$boxIp   = if ($env:SELFHOST_BOX_IP) { $env:SELFHOST_BOX_IP } else { '192.168.1.8' }
$sshHost = if ($env:SELFHOST_SSH)    { $env:SELFHOST_SSH }    else { 'alexdesktop' }
$routes  = if ($env:SELFHOST_ROUTES_CMD) { $env:SELFHOST_ROUTES_CMD } else { "Set-Location 'C:\Users\Alex\Self-Host'; .\target\release\selfhost.exe routes" }
$begin   = '# >>> selfhost lan-hosts (auto-managed - do not edit inside) >>>'
$end     = '# <<< selfhost lan-hosts <<<'
$hosts   = "$env:SystemRoot\System32\drivers\etc\hosts"

function Get-Domains {
  if ($env:SELFHOST_DOMAINS) { return $env:SELFHOST_DOMAINS.Split(' ') | Where-Object { $_ } }
  $out = ssh -o ConnectTimeout=6 -o BatchMode=yes $sshHost $routes 2>$null
  $out | ForEach-Object { ($_ -split '\s+' | Where-Object { $_ })[0] } |
    Where-Object { $_ -match '\.' -and $_ -notmatch '^[0-9.]+$' } |
    Sort-Object -Unique
}

# hosts content minus any previous managed block
function Strip-Block {
  $lines = Get-Content -LiteralPath $hosts
  $skip = $false; $keep = @()
  foreach ($l in $lines) {
    if ($l -eq $begin) { $skip = $true; continue }
    if ($l -eq $end)   { $skip = $false; continue }
    if (-not $skip) { $keep += $l }
  }
  ,$keep
}

$domains = @(Get-Domains)

switch ($Mode) {
  'list' {
    Write-Output "box: $boxIp"
    if (-not $domains) { Write-Output '(no domains found - is the box reachable?)'; exit 1 }
    $domains | ForEach-Object { Write-Output "$boxIp $_" }
    exit 0
  }
  'remove' {
    Set-Content -LiteralPath $hosts -Value (Strip-Block) -Encoding ascii
    ipconfig /flushdns | Out-Null
    Write-Output "removed selfhost entries from $hosts"
    exit 0
  }
  default {
    if (-not $domains) { Write-Error "no domains found over SSH; set SELFHOST_DOMAINS=... and retry"; exit 1 }
    $new = @(Strip-Block) + $begin + ($domains | ForEach-Object { "$boxIp $_" }) + $end
    Set-Content -LiteralPath $hosts -Value $new -Encoding ascii
    ipconfig /flushdns | Out-Null
    Write-Output "applied to ${hosts}:"
    $domains | ForEach-Object { Write-Output "  $boxIp $_" }
  }
}
