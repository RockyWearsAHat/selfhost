# forward-soap.ps1 — the selfhost "edge backend" logic, prototyped in PowerShell.
# Speaks UPnP-IGD SOAP directly to the router's known control URL, from THIS box.
# No Windows COM, no SSDP multicast, plain outbound TCP -> works through default-deny.
# Opens 80, 443, 25, and 587 to 192.168.1.8, and prints the router's exact answer.
$ctrl = 'http://192.168.1.1:56688/ctl/IPConn'
$svc  = 'urn:schemas-upnp-org:service:WANIPConnection:1'
$self = '192.168.1.8'

function Add-Map($ext, $intp) {
  $body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:AddPortMapping xmlns:u="$svc">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>$ext</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>$intp</NewInternalPort>
<NewInternalClient>$self</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>selfhost-managed</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping></s:Body></s:Envelope>
"@
  try {
    $r = Invoke-WebRequest -Uri $ctrl -Method Post -TimeoutSec 10 `
         -ContentType 'text/xml; charset="utf-8"' `
         -Headers @{ SOAPAction = "`"$svc#AddPortMapping`"" } -Body $body
    Write-Output ("WAN:{0} -> {1}:{2}  OK (HTTP {3})" -f $ext, $self, $intp, $r.StatusCode)
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $txt = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
      $code = ([regex]::Match($txt, 'errorCode>(\d+)<')).Groups[1].Value
      $desc = ([regex]::Match($txt, 'errorDescription>([^<]*)<')).Groups[1].Value
      Write-Output ("WAN:{0} FAILED - UPnP error {1} ({2})" -f $ext, $code, $desc)
    } else {
      Write-Output ("WAN:{0} ERROR - {1}" -f $ext, $_.Exception.Message)
    }
  }
}

Add-Map 443 443
Add-Map 80 80
Add-Map 25 25
Add-Map 587 587
