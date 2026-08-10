# close-forward.ps1 — remove the 80/443 router forwards this box created.
$ErrorActionPreference = 'SilentlyContinue'
$nat = New-Object -ComObject HNetCfg.NATUPnP
$col = $nat.StaticPortMappingCollection
if ($null -eq $col) { Write-Output 'UPnP unavailable — nothing to remove via UPnP.'; return }
foreach ($p in 80, 443) {
    try { $col.Remove($p, 'TCP'); Write-Output "removed WAN:$p" } catch { Write-Output "no mapping for $p" }
}
Write-Output '=== remaining router port-forwards ==='
foreach ($m in $col) { '{0}/{1} -> {2}:{3}  [{4}]' -f $m.ExternalPort,$m.Protocol,$m.InternalClient,$m.InternalPort,$m.Description }
