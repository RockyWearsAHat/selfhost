# update-and-verify.ps1 - the build+KAT-test gate for a STAGED Secure-VPN checkout.
#
# This is `[service.git].post_pull` for the `vpn-updater` meta-service
# (crates/services/vpn/src/updater.rs). The daemon runs it with its working
# directory already set to the STAGING checkout - a clone of
# https://github.com/RockyWearsAHat/Secure-VPN.git that is NOT the live
# install at C:\ProgramData\selfhost\securevpn. Nothing this script does may
# touch that live directory, and nothing here may touch the vpn-console or
# vpn-ssh services - see crates/services/vpn/src/updater.rs's module doc for
# the full chain and why the ordering matters (deploy.rs stops the service
# that owns the GitWatch - vpn-updater, never the relay - BEFORE this runs).
#
# What this proves, before anything is allowed to swap in:
#   1. The mlkem768 KAT test suite passes on this exact commit.
#   2. The Python wheel builds.
#   3. The wheel installs cleanly into a STAGING venv (never the live one) and
#      the module actually imports.
#
# A non-zero exit here aborts the deployment (selfhost-git::deploy leaves
# vpn-updater stopped and never calls its start). The staging tree is left in
# place for a human to inspect. vpn-console/vpn-ssh are never touched by a
# failure here, because they are a different service entirely.
#
# Usage (invoked by the daemon; cwd is already the staging checkout root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File update-and-verify.ps1
#     [-StagingVenv <path>]

param(
  [string]$StagingVenv = (Join-Path $PSScriptRoot '..\..\vpn-updater-verify-venv' | Resolve-Path -ErrorAction SilentlyContinue)
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Get-Location).Path
Write-Output "[update-and-verify] staging checkout: $RepoRoot"

if (-not $StagingVenv) {
  # Deliberately NOT under the staging checkout itself (a `git reset --hard`
  # on the next fetch would delete a venv living inside it) and deliberately
  # NOT anywhere near the live install.
  $StagingVenv = Join-Path $env:ProgramData 'selfhost\vpn-updater\verify-venv'
}
Write-Output "[update-and-verify] staging (never live) venv: $StagingVenv"

# --- 1. The KAT test suite, exactly as an operator would run it by hand -----
$mlkemDir = Join-Path $RepoRoot 'mlkem768'
if (-not (Test-Path $mlkemDir)) {
  throw "no mlkem768/ directory in the staged checkout at $RepoRoot - is this really Secure-VPN?"
}
Write-Output '[update-and-verify] running cargo test --release in mlkem768/ (the KAT suite) ...'
Push-Location $mlkemDir
try {
  & cargo test --release
  if ($LASTEXITCODE -ne 0) { throw "cargo test --release failed (exit $LASTEXITCODE) - KAT suite did not pass, refusing to build a wheel from this commit" }
} finally {
  Pop-Location
}

# --- 2. Build the wheel -------------------------------------------------------
Write-Output '[update-and-verify] building the wheel with maturin ...'
Push-Location $mlkemDir
try {
  & maturin build --release -o dist
  if ($LASTEXITCODE -ne 0) { throw "maturin build failed (exit $LASTEXITCODE)" }
  $wheel = Get-ChildItem -Path (Join-Path $mlkemDir 'dist') -Filter '*.whl' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $wheel) { throw "maturin reported success but no .whl was found in $mlkemDir\dist" }
  Write-Output "[update-and-verify] built $($wheel.FullName)"
} finally {
  Pop-Location
}

# --- 3. Install into a STAGING venv and prove the module imports -------------
# Never `pip install` into anything the live relay's interpreter reads. This
# venv exists only to prove the wheel is installable and importable; the swap
# script (update-and-swap.ps1) is the only thing that ever touches the live
# install, and only after this whole script has already exited 0.
if (-not (Test-Path $StagingVenv)) {
  Write-Output "[update-and-verify] creating staging venv at $StagingVenv"
  New-Item -ItemType Directory -Force -Path (Split-Path $StagingVenv -Parent) | Out-Null
  & python -m venv $StagingVenv
  if ($LASTEXITCODE -ne 0) { throw "python -m venv failed (exit $LASTEXITCODE)" }
}
$venvPython = Join-Path $StagingVenv 'Scripts\python.exe'

Write-Output '[update-and-verify] installing the freshly built wheel into the staging venv ...'
& $venvPython -m pip install --force-reinstall $wheel.FullName
if ($LASTEXITCODE -ne 0) { throw "pip install --force-reinstall failed (exit $LASTEXITCODE)" }

Write-Output '[update-and-verify] importing the built module to confirm it actually loads ...'
& $venvPython -c "import mlkem768; print('mlkem768 import OK:', mlkem768.__file__)"
if ($LASTEXITCODE -ne 0) { throw "the built wheel installed but failed to import (exit $LASTEXITCODE)" }

# Record exactly which wheel passed, so update-and-swap.ps1 (running later,
# under vpn-updater's own `start`, in a separate process) knows what to swap
# in without re-deriving "the newest .whl" and possibly picking up a stray
# file left by a half-finished previous attempt.
$verifiedMarker = Join-Path $RepoRoot '.verified-wheel'
Set-Content -Path $verifiedMarker -Value $wheel.FullName -NoNewline
Write-Output "[update-and-verify] PASS - verified wheel recorded at $verifiedMarker"
exit 0
