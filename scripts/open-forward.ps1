# open-forward.ps1 — from THIS box, ask the router (UPnP-IGD) to forward 80/443 to us.
#
# This is exactly what the selfhost firewall "edge backend" will do, run by hand
# for now. It must run ON the box (192.168.1.8): this router only allows a device
# to forward ports to ITSELF, which is why the same request from the Mac failed.
#
# Requires the Netgear's UPnP to be ENABLED. Opens ONLY 80 and 443 to this host.
# Reverse with: close-forward.ps1
$ErrorActionPreference = 'Stop'
$self = '192.168.1.8'

$nat = New-Object -ComObject HNetCfg.NATUPnP
$col = $nat.StaticPortMappingCollection
if ($null -eq $col) {
    Write-Output 'UPnP UNAVAILABLE — the router IGD is not reachable (UPnP disabled on the Netgear).'
    Write-Output 'Enable UPnP on the router, or add a static 80/443 -> 192.168.1.8 forward in its UI.'
    return
}

foreach ($p in 443, 80) {
    try {
        $col.Add($p, 'TCP', $p, $self, $true, 'selfhost-managed') | Out-Null
        Write-Output "forwarded WAN:$p -> ${self}:$p"
    } catch {
        Write-Output ("FAILED $p : " + $_.Exception.Message)
    }
}

Write-Output '=== all router port-forwards now (watch for any you did NOT create) ==='
foreach ($m in $col) {
    '{0}/{1} -> {2}:{3}  [{4}]' -f $m.ExternalPort, $m.Protocol, $m.InternalClient, $m.InternalPort, $m.Description
}
