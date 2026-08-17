# forward-vpn-port.ps1 - open (or close) the router forward for the Secure-VPN.
# Speaks UPnP-IGD SOAP directly to the router from THIS box (the router only
# forwards to the requesting device), same mechanism as scripts/windows/forward-soap.ps1.
# Maps WAN TCP 8443 -> 192.168.1.8:8443 so the VPN is reachable from the internet.
#
# Usage:  .\forward-vpn-port.ps1            (add the mapping)
#         .\forward-vpn-port.ps1 -Remove    (delete the mapping)
param([switch]$Remove, [int]$Port = 8443)

$ctrl = 'http://192.168.1.1:56688/ctl/IPConn'
$svc  = 'urn:schemas-upnp-org:service:WANIPConnection:1'
$self = '192.168.1.8'

function Invoke-Soap($action, $inner) {
  $body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:$action xmlns:u="$svc">$inner</u:$action></s:Body></s:Envelope>
"@
  try {
    $r = Invoke-WebRequest -Uri $ctrl -Method Post -TimeoutSec 10 `
         -ContentType 'text/xml; charset="utf-8"' `
         -Headers @{ SOAPAction = "`"$svc#$action`"" } -Body $body
    Write-Output ("{0} {1}/TCP  OK (HTTP {2})" -f $action, $Port, $r.StatusCode)
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $txt = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
      $code = ([regex]::Match($txt, 'errorCode>(\d+)<')).Groups[1].Value
      $desc = ([regex]::Match($txt, 'errorDescription>([^<]*)<')).Groups[1].Value
      Write-Output ("{0} {1}/TCP FAILED - UPnP error {2} ({3})" -f $action, $Port, $code, $desc)
    } else {
      Write-Output ("{0} {1}/TCP ERROR - {2}" -f $action, $Port, $_.Exception.Message)
    }
  }
}

if ($Remove) {
  Invoke-Soap 'DeletePortMapping' "<NewRemoteHost></NewRemoteHost><NewExternalPort>$Port</NewExternalPort><NewProtocol>TCP</NewProtocol>"
} else {
  Invoke-Soap 'AddPortMapping' "<NewRemoteHost></NewRemoteHost><NewExternalPort>$Port</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>$Port</NewInternalPort><NewInternalClient>$self</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>selfhost-managed vpn</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>"
}
