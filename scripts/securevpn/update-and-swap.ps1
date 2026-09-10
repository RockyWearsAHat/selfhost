# update-and-swap.ps1 - atomically swap a VERIFIED Secure-VPN build onto the
# live install, then restart vpn-console and vpn-ssh.
#
# This is the "program" the `vpn-updater` meta-service itself runs
# (crates/services/vpn/src/updater.rs). The supervisor only ever reaches this
# script through `supervisor.start("vpn-updater")`, which `selfhost-git`'s
# deploy.rs calls ONLY after `update-and-verify.ps1` (this service's
# `[service.git].post_pull`) has already exited 0 for the commit sitting in
# the staging checkout. By the time this script runs:
#   - the KAT test suite has already passed on that commit,
#   - the wheel has already been built,
#   - the wheel has already been installed into a STAGING venv and imported
#     successfully.
# Nothing before this point has touched vpn-console, vpn-ssh, or the live
# install directory. This script is the only place that does either.
#
# Usage (invoked by the supervisor; no arguments expected in normal
# operation - everything is read from box-standard, recorded locations):
#   powershell -NoProfile -ExecutionPolicy Bypass -File update-and-swap.ps1
#     [-StagingDir <path>] [-LiveDir <path>] [-Selfhost <path to selfhost.exe>]

param(
  [string]$StagingDir = 'C:\ProgramData\selfhost\data\vpn-updater\staging',
  [string]$LiveDir    = 'C:\ProgramData\selfhost\securevpn',
  [string]$Selfhost   = 'C:\Users\Alex\Self-Host\target\release\selfhost.exe'
)

$ErrorActionPreference = 'Stop'

$verifiedMarker = Join-Path $StagingDir '.verified-wheel'
if (-not (Test-Path $verifiedMarker)) {
  throw "no $verifiedMarker - update-and-verify.ps1 has not recorded a verified build for " +
        "this staging checkout. Refusing to swap: there is nothing here proven to be safe."
}
$verifiedWheel = (Get-Content $verifiedMarker -Raw).Trim()
if (-not (Test-Path $verifiedWheel)) {
  throw "the recorded verified wheel ($verifiedWheel) no longer exists on disk"
}
Write-Output "[update-and-swap] swapping in the build verified at $verifiedWheel"

# --- 1. Move the current live install aside, never delete it ----------------
# A rename, not a copy-then-delete: the live directory either fully exists
# under its old name or fully exists under $LiveDir at every point in time,
# so a crash mid-step never leaves "neither" on disk. Mirrors the daemon's own
# self-update rename-aside for its binary (crates/app/cli/src/self_update.rs)
# for the identical reason: Windows will not let a directory be replaced while
# something has it open, so the old one is renamed aside rather than deleted.
$backupDir = "$LiveDir.previous"
if (Test-Path $backupDir) {
  Write-Output "[update-and-swap] removing a stale previous backup at $backupDir"
  Remove-Item -Recurse -Force $backupDir
}

$hadLiveInstall = Test-Path $LiveDir
if ($hadLiveInstall) {
  Write-Output "[update-and-swap] renaming the live install aside: $LiveDir -> $backupDir"
  Rename-Item -Path $LiveDir -NewName (Split-Path $backupDir -Leaf)
}

try {
  # --- 2. Copy the verified staging checkout into the live location ---------
  # A copy, not a rename of the staging directory itself: the staging checkout
  # stays where GitWatch expects it for the next push, and a hard reset on the
  # next fetch cannot then accidentally reset "the live install" because they
  # are two different directories on disk.
  Write-Output "[update-and-swap] copying the verified staging checkout into $LiveDir"
  Copy-Item -Path $StagingDir -Destination $LiveDir -Recurse -Force

  # The verify venv and marker file are staging-only bookkeeping, not part of
  # the server's runtime - keep the live directory to exactly what
  # install-vpn-service.ps1 already expects there (server.py, keys/, etc).
  Remove-Item -Force (Join-Path $LiveDir '.verified-wheel') -ErrorAction SilentlyContinue

  # Keys are never part of the git checkout (see runner.rs and
  # scripts/securevpn/rotate-keys.sh) and this copy does not touch them - the
  # live keys/ directory the old install had is not something this script
  # creates, moves, or deletes. If the previous install had one and the fresh
  # copy does not (it never will - keys are box-local and gitignored), restore
  # it from the backup so a swap can never turn into a key loss.
  $backupKeys = Join-Path $backupDir 'keys'
  $liveKeys = Join-Path $LiveDir 'keys'
  if ((Test-Path $backupKeys) -and -not (Test-Path $liveKeys)) {
    Write-Output '[update-and-swap] carrying the existing keys/ directory forward'
    Copy-Item -Path $backupKeys -Destination $liveKeys -Recurse
  }
}
catch {
  Write-Output "[update-and-swap] swap failed ($_); rolling the live install back"
  if (Test-Path $LiveDir) { Remove-Item -Recurse -Force $LiveDir }
  if ($hadLiveInstall) { Rename-Item -Path $backupDir -NewName (Split-Path $LiveDir -Leaf) }
  throw
}

# --- 3. Restart the real relays - the only place either is ever touched -----
# Through this box's own `selfhost vpn` verbs, never a raw process kill: `up`
# re-plans the invocation (runner::plan) against whatever server.py is now on
# disk, so a version that gained/lost a flag is reflected immediately rather
# than restarting the OLD command line against the NEW server.py.
foreach ($relay in @('console', 'ssh')) {
  Write-Output "[update-and-swap] restarting relay '$relay'"
  & $Selfhost vpn down $relay
  & $Selfhost vpn up $relay
  if ($LASTEXITCODE -ne 0) {
    Write-Output "[update-and-swap] WARNING: 'selfhost vpn up $relay' exited $LASTEXITCODE - check " +
                 "'selfhost vpn status $relay' by hand; the swap itself already succeeded."
  }
}

Write-Output '[update-and-swap] done'
exit 0
