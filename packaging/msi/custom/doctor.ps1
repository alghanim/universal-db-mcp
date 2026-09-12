#
# UniversalDB MCP - MSI deferred custom action: doctor smoke check.
#
# Contract (wired by scripts/package/build_msi.sh; see packaging/msi/udbmcp.wxs):
#   Deferred custom action, Impersonate="no", Return="check", e.g.:
#     powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
#       "[INSTALLFOLDER]scripts\doctor.ps1"
#       -VenvDir "[INSTALLFOLDER]venv"
#       -ConfigPath "[ProgramDataUdbmcpDir]config.yaml"
#       -BundleManifest "[INSTALLFOLDER]bundle\manifest.json"
#   Exit code 0 = continue; any nonzero exit fails the action and WiX rolls
#   back the entire install. There is deliberately no "warn and continue"
#   path: an install whose doctor is unhealthy must not complete.
#
# TRUST MODEL - DO NOT BREAK:
#   * This action EXECUTES PAYLOAD BITS (the venv interpreter and the
#     universal_db_mcp wheel). It must be scheduled strictly AFTER the
#     trusted-channel verify_bundle.py custom action has re-verified the
#     installed bundle with the admin-distributed release public key, and
#     AFTER the venv has been built from that verified wheelhouse. Reordering
#     this action before verification would execute unverified payload and
#     violate the project's first trust invariant.
#   * The release public key is NEVER shipped inside the package; nothing in
#     this script reads, writes or embeds key material.
#   * No network access: doctor runs with the flags it is given and never
#     performs connectivity probes (no --connectivity).
#
# Parameters may also be supplied via environment variables for manual runs
# from the delivered gate script (scripts/test_package_msi.ps1):
#   UDBMCP_VENV_DIR, UDBMCP_CONFIG, UDBMCP_BUNDLE_MANIFEST
#
[CmdletBinding()]
param(
    [string]$VenvDir,
    [string]$ConfigPath,
    [string]$BundleManifest
)

$ErrorActionPreference = 'Stop'

function Fail {
    param([string]$Message)
    Write-Output ("DOCTOR-ACTION FAILED: " + $Message)
    exit 1
}

function Invoke-Payload {
    # Runs the venv interpreter and returns ONLY its exit code. The child's
    # stdout/stderr are echoed via Write-Host so they land in the MSI log
    # without polluting this function's output stream (Write-Output here
    # would be captured together with the exit code by the caller). stderr is
    # redirected explicitly because Windows PowerShell 5.1 turns native-
    # command stderr output into error records that
    # $ErrorActionPreference='Stop' would escalate.
    param([string]$Python, [string[]]$PythonArgs)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Python @PythonArgs 2>&1 | ForEach-Object { Write-Host ("    " + $_) }
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

try {
    # --- resolve the venv interpreter ---------------------------------------
    if (-not $VenvDir) { $VenvDir = $env:UDBMCP_VENV_DIR }
    if (-not $VenvDir) { Fail "no venv directory: pass -VenvDir or set UDBMCP_VENV_DIR" }
    $python = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Fail ("venv interpreter not found at '" + $python + "'; the venv-build custom action must run before this one")
    }

    # --- resolve the config to validate --------------------------------------
    # The MSI installs the staged config template to the machine-wide config
    # path (NeverOverwrite), so on both fresh installs and upgrades the file
    # at -ConfigPath is the template content the admin will run with.
    if (-not $ConfigPath) { $ConfigPath = $env:UDBMCP_CONFIG }
    if (-not $ConfigPath) { Fail "no config to validate: pass -ConfigPath or set UDBMCP_CONFIG" }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Fail ("config not found at '" + $ConfigPath + "'")
    }

    # --- let doctor report the true installed profile ------------------------
    # Same hook the .deb postinst and macOS pkg postinstall provide: doctor
    # derives the bundle profile from the manifest instead of guessing from
    # the running platform. Optional and guarded: a bundle without a manifest
    # still runs doctor (which falls back to an honest platform description).
    if (-not $BundleManifest) { $BundleManifest = $env:UDBMCP_BUNDLE_MANIFEST }
    if ($BundleManifest -and (Test-Path -LiteralPath $BundleManifest -PathType Leaf)) {
        $env:UDBMCP_BUNDLE_MANIFEST = $BundleManifest
    }

    # --- run doctor (no --connectivity: install-time check is offline) -------
    Write-Output ("==> running doctor against config: " + $ConfigPath)
    $doctorArgs = @('-m', 'universal_db_mcp', 'doctor', '--config', $ConfigPath)
    $code = Invoke-Payload -Python $python -PythonArgs $doctorArgs

    if ($null -eq $code) {
        Fail "doctor did not run (interpreter returned no exit code)"
    }
    if ($code -ne 0) {
        Fail ("doctor reported an unhealthy installation (exit code " + $code + "); rolling back the install")
    }

    Write-Output "==> doctor passed"
    exit 0
}
catch {
    Fail ("unexpected error: " + $_.Exception.Message)
}
