# Runs one relay by hand for a few seconds and prints what it says.
#
# The daemon keeps a relay's output only in memory, so when a relay will not
# stay up this is the way to read why: the exact command `vpn preflight`
# reports, started here, its output captured, then stopped again.
#
#   powershell -ExecutionPolicy Bypass -File scripts\securevpn\try-relay.ps1 ssh
param([string]$Relay = "ssh", [int]$Seconds = 8)

$repo = Split-Path (Split-Path $PSScriptRoot)
$exe = Join-Path $repo "target\release\selfhost.exe"
Set-Location $repo

$line = & $exe vpn preflight $Relay | Where-Object { $_ -match '^command\s+' } | Select-Object -First 1
if (-not $line) { "no command reported for relay '$Relay'"; exit 1 }
$command = ($line -replace '^command\s+', '').Trim()
$program, $arguments = $command -split ' ', 2
"program   $program -> $((Get-Command $program -ErrorAction SilentlyContinue).Source)"
"server.py $(Test-Path 'C:\ProgramData\selfhost\securevpn\server.py')"

$out = Join-Path $env:TEMP "try-relay-out.log"
$err = Join-Path $env:TEMP "try-relay-err.log"
$process = Start-Process $program -ArgumentList $arguments -PassThru -NoNewWindow `
    -WorkingDirectory 'C:\ProgramData\selfhost\securevpn' `
    -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep $Seconds
if ($process.HasExited) { "EXITED with code $($process.ExitCode)" } else { "STILL RUNNING after ${Seconds}s (good)"; Stop-Process $process }
"--- stdout"; Get-Content $out -Tail 30
"--- stderr"; Get-Content $err -Tail 30
