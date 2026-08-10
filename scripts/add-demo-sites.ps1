# add-demo-sites.ps1 — add two more sites (a subdomain and a whole different
# domain) to prove multi-domain virtual hosting, then validate + restart.
$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\Alex\Self-Host'
$cfg = "$dir\selfhost.config.toml"

function Add-Site($name, $domainsToml, $html) {
  New-Item -ItemType Directory -Force "$dir\sites\$name" | Out-Null
  Set-Content "$dir\sites\$name\index.html" $html -Encoding UTF8
  if (-not (Select-String -Path $cfg -Pattern ('name = "' + $name + '"') -Quiet)) {
    $block = "`n[[sites]]`nname = `"$name`"`ndomains = [$domainsToml]`nstatic_root = `"./sites/$name`"`nspa = false`n"
    Add-Content -Path $cfg -Value $block -Encoding UTF8
  }
}

Add-Site 'blog' '"blog.rockywearsahat.com"' '<!doctype html><meta charset="utf-8"><title>Blog</title><h1>Blog</h1><p>Subdomain of rockywearsahat.com.</p>'
Add-Site 'lvlup' '"leveluplongboarding.surf", "www.leveluplongboarding.surf"' '<!doctype html><meta charset="utf-8"><title>Level Up Longboarding</title><h1>Level Up Longboarding</h1><p>A completely different DOMAIN on the same box.</p>'

$out = & "$dir\target\release\selfhost.exe" check 2>&1
Write-Output ($out | Out-String)
if ($LASTEXITCODE -eq 0) {
  Stop-ScheduledTask selfhost | Out-Null; Start-Sleep 2; Start-ScheduledTask selfhost | Out-Null; Start-Sleep 6
  Write-Output "restarted"
  & "$dir\target\release\selfhost.exe" routes
} else {
  Write-Output "CONFIG INVALID - not restarted"
}
