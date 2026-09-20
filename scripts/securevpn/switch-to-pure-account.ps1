# Switches this box to the pure-account build, which refuses any config that
# still carries [[vpn.peers]] blocks.
#
# The relay on 8444 is the only SSH path to this box, and on Windows it dies with
# the daemon - so the SSH session running this script dies at the swap too. The
# script therefore builds, strips and proves everything first, touching nothing
# live, and then hands the swap to a one-shot SYSTEM scheduled task that no
# session owns. That task swaps exe + config, checks the ports, and puts BOTH
# back if 8444 or 9191 stays closed. Reconnect and read the log it names.
#
#   powershell -ExecutionPolicy Bypass -File scripts\securevpn\switch-to-pure-account.ps1
param(
  [string]$Ref = 'origin/windows-test',
  # Internal: set by this script when it re-launches itself as the swap task.
  [switch]$Swap,
  [string]$Repo = '',
  [string]$Stamp = '',
  [string]$OldCommit = '',
  [string]$NewCommit = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $Repo) { $Repo = Split-Path (Split-Path $PSScriptRoot) }
if (-not $Stamp) { $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss' }
Set-Location $Repo

$daemonTask  = 'selfhost-daemon'
$swapTask    = 'selfhost-switch-to-pure-account'
$config      = Join-Path $Repo 'selfhost.config.toml'
$configNext  = Join-Path $Repo 'selfhost.config.toml.next'
$backup      = Join-Path $Repo "selfhost.config.toml.bak-$Stamp"
$liveExe     = Join-Path $Repo 'target\release\selfhost.exe'
$prevExe     = Join-Path $Repo 'target\release\selfhost.exe.prev'
$newExe      = Join-Path $Repo 'target-next\release\selfhost.exe'
$dataDir     = Join-Path $Repo 'data'
$peersFile   = Join-Path $dataDir 'vpn.peers'
$peersBackup = Join-Path $dataDir "vpn.peers.bak-$Stamp"
$log         = Join-Path $dataDir "switch-to-pure-account-$Stamp.log"
$utf8        = New-Object System.Text.UTF8Encoding($false)

# PowerShell 5.1 turns a native command's stderr into terminating errors when
# it is redirected under 'Stop', and cargo and git both talk on stderr. Run them
# under 'Continue' (function scope only) and judge them by exit code alone.
function Invoke-Native {
  param([string]$Exe, [string[]]$Arguments)
  $ErrorActionPreference = 'Continue'
  $lines = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
  $script:nativeExit = $LASTEXITCODE
  $lines
}

function Restore-Commit {
  param([string]$Commit)
  $out = Invoke-Native git @('-c', 'safe.directory=*', 'checkout', '--detach', $Commit)
  if ($script:nativeExit -ne 0) { "could not restore commit $Commit"; $out }
}

function Test-Ports {
  $result = @{}
  foreach ($port in 8444, 8443, 9191) {
    $probe = Test-NetConnection 127.0.0.1 -Port $port -WarningAction SilentlyContinue
    $result[$port] = [bool]$probe.TcpTestSucceeded
  }
  $result
}

# ---------------------------------------------------------------------------
# Swap phase: runs as the one-shot SYSTEM task, detached from any session.
# ---------------------------------------------------------------------------
if ($Swap) {
  function Log {
    param([string]$Text)
    $line = "$(Get-Date -Format 'HH:mm:ss')  $Text"
    [IO.File]::AppendAllText($log, $line + "`r`n", $utf8)
  }

  function Get-Daemon {
    Get-CimInstance Win32_Process -Filter "Name='selfhost.exe'" |
      Where-Object { -not $_.ExecutablePath -or $_.ExecutablePath -eq $liveExe }
  }

  # Stopped means the process is gone, not that the task was asked to stop:
  # a live process keeps its exe locked and the copy over it fails.
  function Stop-Daemon {
    try { Stop-ScheduledTask $daemonTask } catch { Log "stop task: $($_.Exception.Message)" }
    Start-Sleep 5
    for ($i = 0; $i -lt 30 -and (Get-Daemon); $i++) { Start-Sleep 2 }
    foreach ($p in @(Get-Daemon)) {
      Log "daemon pid $($p.ProcessId) still alive - killing it"
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if (Get-Daemon) { Start-Sleep 3 }
  }

  function Start-Daemon {
    try { Start-ScheduledTask $daemonTask }
    catch {
      Log "start task: $($_.Exception.Message) - trying schtasks"
      Invoke-Native schtasks @('/run', '/tn', $daemonTask) | Out-Null
    }
  }

  # Lands the file whole or not at all: copy beside the target, then replace.
  # Something (the watchdog) may restart the daemon under us, so a locked
  # target means stop it again and retry.
  function Copy-Exe {
    param([string]$From, [string]$To)
    $staged = "$To.staged"
    Copy-Item $From -Destination $staged -Force
    for ($try = 1; $try -le 5; $try++) {
      try { Move-Item $staged -Destination $To -Force; return }
      catch {
        Log "exe locked (try $try): $($_.Exception.Message)"
        Stop-Daemon
      }
    }
    throw "could not replace $To"
  }

  function Wait-Ports {
    Start-Sleep 30
    $ports = Test-Ports
    for ($i = 0; $i -lt 6 -and -not ($ports[8444] -and $ports[9191]); $i++) {
      Start-Sleep 10
      $ports = Test-Ports
    }
    $ports
  }

  function Log-Ports {
    param($Ports)
    foreach ($port in 8444, 8443, 9191) { Log "port $port  $($Ports[$port])" }
  }

  $ok = $false
  $ports = $null
  try {
    Log "swap begins: $OldCommit -> $NewCommit"
    Stop-Daemon
    Copy-Exe $newExe $liveExe
    Copy-Item $configNext -Destination $config -Force
    Start-Daemon
    $ports = Wait-Ports
    $ok = $ports[8444] -and $ports[9191]
  }
  catch { Log "swap error: $($_.Exception.Message)" }

  if ($ok) {
    Remove-Item $configNext -Force -ErrorAction SilentlyContinue
    Log-Ports $ports
    Log "SWITCHED to $($NewCommit.Substring(0, 7))"
    exit 0
  }

  # Roll back. Every step stands alone so that nothing here can stop the last
  # one - starting the daemon - from running. The exe and the config are kept a
  # pair: old exe with the old config, or, if the old exe cannot be put back,
  # the new exe with the stripped config it was proven against.
  if ($ports) { Log-Ports $ports }
  Log 'rolling back'
  try { Stop-Daemon } catch { Log "stop: $($_.Exception.Message)" }
  $exeBack = $false
  try { Copy-Exe $prevExe $liveExe; $exeBack = $true }
  catch { Log "exe restore: $($_.Exception.Message)" }
  try {
    if ($exeBack) { Copy-Item $backup -Destination $config -Force }
    else {
      Copy-Item $configNext -Destination $config -Force
      Log 'OLD EXE NOT RESTORED - new exe left with the stripped config'
    }
  }
  catch { Log "config restore: $($_.Exception.Message)" }
  try {
    # Put vpn.peers back only if it is still exactly the old text + our line.
    if ($exeBack -and (Test-Path $peersBackup)) {
      $was = [IO.File]::ReadAllText($peersBackup)
      $now = [IO.File]::ReadAllText($peersFile)
      if ($now.StartsWith($was) -and $now.Substring($was.Length).Trim() -eq 'dad Dad') {
        Copy-Item $peersBackup -Destination $peersFile -Force
      }
    }
  }
  catch { Log "vpn.peers restore: $($_.Exception.Message)" }
  try { if ($exeBack) { Restore-Commit $OldCommit | ForEach-Object { Log $_ } } }
  catch { Log "commit restore: $($_.Exception.Message)" }
  try { Start-Daemon } catch { Log "start: $($_.Exception.Message)" }
  try { Log-Ports (Wait-Ports) } catch { Log "ports: $($_.Exception.Message)" }
  Log 'ROLLED BACK'
  exit 1
}

# ---------------------------------------------------------------------------
# Front phase: nothing below touches the live exe, the live config or the task
# until the very last step.
# ---------------------------------------------------------------------------
foreach ($needed in $config, $liveExe) {
  if (-not (Test-Path $needed)) { "missing $needed"; exit 1 }
}

# Step 1: fetch, record the current commit, check out the new one.
$out = Invoke-Native git @('fetch', 'origin')
if ($nativeExit -ne 0) { $out; 'git fetch failed - nothing changed'; exit 1 }
$OldCommit = "$(Invoke-Native git @('rev-parse', 'HEAD'))".Trim()
if ($nativeExit -ne 0 -or $OldCommit -notmatch '^[0-9a-f]{40}$') {
  'could not read the current commit - nothing changed'; exit 1
}
$out = Invoke-Native git @('checkout', '--detach', $Ref)
if ($nativeExit -ne 0) { $out; "could not check out $Ref - nothing changed"; exit 1 }
$NewCommit = "$(Invoke-Native git @('rev-parse', 'HEAD'))".Trim()
"checkout   $($OldCommit.Substring(0, 7)) -> $($NewCommit.Substring(0, 7))"

function Abort {
  param([string]$Why)
  $Why
  Remove-Item $configNext -Force -ErrorAction SilentlyContinue
  if (Test-Path $peersBackup) {
    Copy-Item $peersBackup -Destination $peersFile -Force -ErrorAction SilentlyContinue
  }
  Restore-Commit $OldCommit
  'ABORTED - live exe, live config and daemon untouched'
  exit 1
}

try {
  # Step 2: build into a separate target dir so the live exe is untouched.
  "building   $Ref (several minutes, silent unless it fails)"
  $build = @('build', '--release', '-p', 'selfhost-cli', '--target-dir', 'target-next')
  $out = Invoke-Native cargo $build
  if ($nativeExit -ne 0) { $out | Select-Object -Last 40; Abort 'build failed' }
  if (-not (Test-Path $newExe)) { Abort "build left no $newExe" }

  # Step 3: back up the config, write a copy without any [[vpn.peers]] block.
  # A block is its header plus every line up to the next blank line or the next
  # line opening with "[" - which is kept. Read and written as UTF-8, no BOM.
  Copy-Item $config -Destination $backup
  "backed up  $backup"
  $kept = New-Object System.Collections.Generic.List[string]
  $inPeers = $false
  $blocks = 0
  foreach ($line in [IO.File]::ReadAllLines($config)) {
    if ($line -match '^\s*\[\[\s*vpn\s*\.\s*peers\s*\]\]') {
      $inPeers = $true
      $blocks++
      continue
    }
    if ($inPeers) {
      if ($line -match '^\s*$' -or $line -match '^\s*\[') { $inPeers = $false }
      else { continue }
    }
    $kept.Add($line)
  }
  [IO.File]::WriteAllLines($configNext, $kept, $utf8)
  "stripped   $blocks [[vpn.peers]] block(s)"

  # Step 5 (before 4, so a refused config leaves data\ untouched too): prove the
  # new exe accepts the stripped config. `check` takes no config flag - it walks
  # up from the current directory - so it gets a directory holding only the copy.
  $checkDir = Join-Path $env:TEMP "selfhost-check-$Stamp"
  New-Item -ItemType Directory $checkDir -Force | Out-Null
  Copy-Item $configNext -Destination (Join-Path $checkDir 'selfhost.config.toml')
  Push-Location $checkDir
  try { $out = Invoke-Native $newExe @('check') }
  finally {
    Pop-Location
    Remove-Item $checkDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if ($nativeExit -ne 0) { $out; Abort 'the new build refuses the stripped config' }
  'check      new exe accepts the stripped config'

  # Step 4: make sure the roster names dad. Append only, never rewrite: a
  # missing final newline is supplied first so the line cannot fuse to another.
  if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory $dataDir | Out-Null }
  $peersText = ''
  if (Test-Path $peersFile) { $peersText = [IO.File]::ReadAllText($peersFile) }
  if ($peersText -notmatch '(?m)^\s*dad\s') {
    if (Test-Path $peersFile) { Copy-Item $peersFile -Destination $peersBackup }
    $lead = ''
    if ($peersText.Length -gt 0 -and -not $peersText.EndsWith("`n")) { $lead = "`n" }
    [IO.File]::AppendAllText($peersFile, $lead + "dad Dad`n", $utf8)
    'vpn.peers  added "dad Dad"'
  }

  # Keep the running exe beside itself; reading a running exe is allowed.
  Copy-Item $liveExe -Destination $prevExe -Force
  if ((Get-Item $prevExe).Length -ne (Get-Item $liveExe).Length) {
    Abort 'selfhost.exe.prev is not a full copy of the live exe'
  }

  # Step 6-8: hand the swap to a task no session owns. It runs a copy of this
  # script, because the checkout above may have changed the one in the repo.
  $runCopy = Join-Path $Repo "target-next\switch-to-pure-account-$Stamp.ps1"
  Copy-Item $PSCommandPath -Destination $runCopy -Force
  $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$runCopy`" -Swap" +
    " -Repo `"$Repo`" -Stamp $Stamp -OldCommit $OldCommit -NewCommit $NewCommit"
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount `
    -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
  Register-ScheduledTask -TaskName $swapTask -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
}
catch { Abort "error before the swap: $($_.Exception.Message)" }

"swap log   $log"
'swapping   this session may drop now; reconnect and read the swap log'
try { Start-ScheduledTask $swapTask }
catch { Abort "could not start the swap task: $($_.Exception.Message)" }

# Follow the log for as long as this session lives. The task does not need us.
$shown = 0
$verdict = ''
for ($i = 0; $i -lt 120 -and -not $verdict; $i++) {
  Start-Sleep 5
  $lines = @()
  try { if (Test-Path $log) { $lines = @([IO.File]::ReadAllLines($log)) } } catch { }
  for (; $shown -lt $lines.Count; $shown++) {
    $lines[$shown]
    if ($lines[$shown] -match 'SWITCHED to|ROLLED BACK') { $verdict = $lines[$shown] }
  }
}
if ($verdict) {
  Unregister-ScheduledTask -TaskName $swapTask -Confirm:$false -ErrorAction SilentlyContinue
}
if ($verdict -match 'SWITCHED to') { exit 0 }
if (-not $verdict) { "no verdict after 10 minutes - read $log" }
exit 1
