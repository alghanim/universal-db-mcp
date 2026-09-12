# MSI deferred custom action: verify the installed bundle BEFORE any payload runs.
#
# ---------------------------------------------------------------------------
# TRUST MODEL -- READ BEFORE "FIXING" THIS SCRIPT
#
# Windows mirrors the deb (packaging/deb/{preinst,postinst}) and the macOS pkg
# (packaging/pkg/{preinstall,postinstall}): an MSI is just a container, so a
# tampered MSI ships a tampered payload -- and a verifier shipped inside the
# payload would be a tampered verifier that prints PASSED. Therefore:
#
#   1. NOTHING in the installed bundle is executed before the ADMIN-INSTALLED
#      trusted verify_bundle.py --pubkey run has passed. This action runs the
#      verifier from the trust directory the MSI pins via CustomActionData
#      (C:\Program Files\udbmcp-trust -- the admin-write-only Program Files
#      tree, so a non-admin process cannot pre-create it) -- a path OUTSIDE
#      the bundle, populated by the admin from the same trusted channel that
#      delivered the MSI. The bundle is only ever READ (manifest, SHA256SUMS,
#      wheel hashes) by that verifier, never run.
#   2. The release public key is NEVER shipped inside the MSI (or any release
#      artifact). The admin distributes it out-of-band and points
#      UDBMCP_RELEASE_PUBKEY (machine scope) at it; without it this action
#      fails closed.
#   3. Fail closed on EVERY failure: missing prerequisites, wrong wiring, a
#      verifier exit code != 0, or missing proof-of-verification in its output
#      all exit nonzero. Scheduled with Return="check", that makes
#      msiexec roll the install back (never partially trusted).
#
# Defense in depth: if the trust directory, the verifier, the profiles
# registry, the public key, or the Python interpreter resolve INSIDE the
# bundle directory, refuse to proceed -- those are exactly the positions a
# tampered bundle can abuse (its own verifier/key would "verify" itself).
# ---------------------------------------------------------------------------
#
# SCHEDULING CONTRACT (for packaging/msi/udbmcp.wxs -- not authored here):
#   Deferred, impersonate=no (runs as LocalSystem), Return="check", and
#   scheduled AFTER the InstallFiles action (the bundle is on disk) and
#   BEFORE the venv/doctor/service custom actions (nothing may run payload
#   first). A rollback twin must be scheduled so a failed install is undone.
#   Pass parameters via CustomActionData as semicolon-separated KEY=VALUE:
#
#     BUNDLE_DIR=C:\Program Files\UniversalDB MCP\bundle   (required)
#     TRUST_DIR=C:\Program Files\udbmcp-trust  (ALWAYS passed by the wxs as
#         [ProgramFiles64Folder]udbmcp-trust -- the admin-write-only Program
#         Files tree, the analogue of the deb/pkg root-owned
#         /usr/local/lib/udbmcp-trust; never left to the fallback below)
#     PUBKEY=C:\ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem (optional override)
#     PYTHON=C:\Program Files\Python312\python.exe         (optional override)
#
#   Values may contain spaces but not ';'. TRUST_DIR is always passed by the
#   wxs, so the machine-scope UDBMCP_TRUST_DIR below is a fallback for
#   STANDALONE/manual runs of this script only (e.g. the delivered gate's
#   tamper negative) -- it is NEVER read during an MSI install. The other
#   keys may be omitted and fall back to the machine-scope environment
#   variables below (set by the admin with setx /M BEFORE running msiexec --
#   a deferred action runs as LocalSystem and sees machine env only):
#
#     UDBMCP_TRUST_DIR        (standalone-only fallback; default C:\ProgramData\udbmcp-trust)
#     UDBMCP_RELEASE_PUBKEY   (required, directly or via PUBKEY in CustomActionData)
#     UDBMCP_PYTHON           (optional interpreter override)
#
# TRUST BOOTSTRAP (admin, elevated prompt, from the trusted channel that
# delivered this MSI -- see docs/offline-deployment.md, 'Trust bootstrap'):
#
#     setx /M UDBMCP_RELEASE_PUBKEY "C:\ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem"
#     New-Item -ItemType Directory -Force "$env:ProgramData\universal-db-mcp\keys"
#     Copy-Item <trusted-path>\udbmcp-release.pub.pem `
#         "$env:ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem"
#     New-Item -ItemType Directory -Force 'C:\Program Files\udbmcp-trust\lib'
#     Copy-Item <trusted-channel>\verify_bundle.py 'C:\Program Files\udbmcp-trust\'
#     Copy-Item <trusted-channel>\profiles.py      'C:\Program Files\udbmcp-trust\'
#
# The verifier checks Ed25519 signatures via openssl.exe (e.g. from Git for
# Windows on PATH) or, failing that, the `cryptography` package importable by
# the interpreter above; with neither it FAILS (fail closed) with its
# canonical diagnostic.
# ---------------------------------------------------------------------------

param(
    # Semicolon-separated KEY=VALUE pairs (the MSI CustomActionData string).
    [string]$CustomActionData = ''
)

# Fail closed on ANY cmdlet error: an unhandled terminating error falls into
# the catch block below, which exits nonzero (MSI rollback). There is no code
# path that exits 0 without the verifier having passed.
$ErrorActionPreference = 'Stop'

$script:LogPath = Join-Path $env:ProgramData 'universal-db-mcp\install-verify.log'

# Write a line to the persistent install log and to stdout (stdout reaches a
# manual powershell.exe run and the delivered test gate; deferred custom
# action output does not land in the msiexec /l*v log, hence the file).
function Write-Log {
    param([string]$Message)
    Write-Output $Message
    try {
        $dir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Add-Content -LiteralPath $script:LogPath -Value $Message -Encoding UTF8
    } catch {
        # A broken log file must never mask a verification result; keep going
        # -- every decision below is made on the verifier itself, not the log.
        Write-Output "WARNING: cannot write $script:LogPath : $($_.Exception.Message)"
    }
}

# Print the canonical FAIL diagnostic and exit nonzero -> msiexec rolls back.
function Fail {
    param([string]$Message)
    Write-Log "FAIL: $Message"
    Write-Log "universal-db-mcp: installation ABORTED (fail closed); msiexec will roll back."
    exit 1
}

# Full paths (no short-name/relative trickery) for prefix containment checks.
function Real-Path {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

# True when $Candidate lives inside $Directory (case-insensitive, prefix on
# full paths with a separator boundary, so C:\ProgramData\udbmcp-trust2 is
# NOT "inside" C:\ProgramData\udbmcp-trust).
function Test-InsideDir {
    param([string]$Candidate, [string]$Directory)
    $c = (Real-Path $Candidate) + '\'
    $d = (Real-Path $Directory) + '\'
    return $c.ToLower().StartsWith($d.ToLower())
}

try {
    Write-Log "==> universal-db-mcp MSI: verifying the installed bundle before any payload execution"

    # --- parse CustomActionData (semicolon-separated KEY=VALUE) -------------
    $data = @{}
    foreach ($pair in ($CustomActionData -split ';')) {
        $t = $pair.Trim()
        if ($t -eq '') { continue }
        $idx = $t.IndexOf('=')
        if ($idx -lt 1) {
            Fail "malformed CustomActionData pair '$t' (expected KEY=VALUE); this is a packaging bug in udbmcp.wxs, not an admin problem."
        }
        $data[$t.Substring(0, $idx)] = $t.Substring($idx + 1).Trim()
    }

    # --- resolve the installed bundle directory (required) -------------------
    if (-not $data.ContainsKey('BUNDLE_DIR') -or $data['BUNDLE_DIR'] -eq '') {
        Fail "BUNDLE_DIR missing from CustomActionData; the wxs must pass the installed bundle path (packaging bug), so verification cannot proceed."
    }
    $BundleDir = $data['BUNDLE_DIR']
    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        Fail "installed bundle directory not found at $BundleDir (wrong BUNDLE_DIR wiring in udbmcp.wxs?)."
    }

    # This script ships inside the MSI; if it is somehow running from inside
    # the bundle, the bundle supply chain already won -- refuse.
    if ($PSCommandPath -and (Test-InsideDir $PSCommandPath $BundleDir)) {
        Fail "this verifier is running from inside the bundle ($PSCommandPath); the verifier MUST come from the trust directory outside the bundle, never from the payload it would verify."
    }

    # --- resolve the trust directory ----------------------------------------
    $TrustDir = $data['TRUST_DIR']
    if (-not $TrustDir) { $TrustDir = $env:UDBMCP_TRUST_DIR }
    if (-not $TrustDir) { $TrustDir = 'C:\ProgramData\udbmcp-trust' }
    $Verifier = Join-Path $TrustDir 'verify_bundle.py'

    # A tampered bundle ships a verifier that prints PASSED: never accept a
    # trust directory (verifier, profiles registry) located inside the bundle.
    if (Test-InsideDir $TrustDir $BundleDir) {
        Fail "trust directory ($TrustDir) is inside the installed bundle ($BundleDir); a verifier from the payload proves nothing. Install the trusted tools outside the bundle at the path the MSI pins via CustomActionData: C:\Program Files\udbmcp-trust."
    }

    # --- prerequisite 1: the trusted verifier + its profiles registry -------
    # Admin-installed with a plain copy (no exec semantics on Windows); it is
    # run via python.exe, never directly.
    if (-not (Test-Path -LiteralPath $Verifier -PathType Leaf)) {
        Write-Log "trusted verifier not found at $Verifier."
        Write-Log "The MSI refuses to install without it: nothing in this package may run payload that has not passed verification by an admin-installed trusted verifier obtained outside the package/bundle supply chain."
        Write-Log "Bootstrap it from the same trusted channel that delivered this MSI (the MSI reads TRUST_DIR from CustomActionData, so provision exactly the path below):"
        Write-Log "    New-Item -ItemType Directory -Force '$TrustDir\lib'"
        Write-Log "    Copy-Item <trusted-channel>\verify_bundle.py '$TrustDir\'"
        Write-Log "    Copy-Item <trusted-channel>\profiles.py      '$TrustDir\'"
        Fail "trusted verifier not found at $Verifier; installation ABORTED (fail closed)."
    }
    # verify_bundle.py imports the target-profile registry from its own
    # directory or its lib/; missing registry = it fails closed, but a clear
    # prerequisite diagnostic here beats a Python traceback.
    $profilesPy = @(
        (Join-Path $TrustDir 'profiles.py'),
        (Join-Path $TrustDir 'lib\profiles.py')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $profilesPy) {
        Write-Log "profiles registry not found next to the verifier (checked '$TrustDir\profiles.py' and '$TrustDir\lib\profiles.py')."
        Write-Log "verify_bundle.py needs profiles.py (the target-profile registry) to check the bundle profile against this machine; it fails closed without it."
        Write-Log "    Copy-Item <trusted-channel>\profiles.py '$TrustDir\'"
        Fail "profiles.py not found in the trust directory ($TrustDir); installation ABORTED (fail closed)."
    }

    # --- prerequisite 2: the release public key (NEVER shipped in the MSI) ---
    $PubKey = $data['PUBKEY']
    if (-not $PubKey) { $PubKey = $env:UDBMCP_RELEASE_PUBKEY }
    if (-not $PubKey) {
        Write-Log "FAIL: no release public key: set UDBMCP_RELEASE_PUBKEY machine-wide (or pass PUBKEY in CustomActionData) to the release public key PEM path;"
        Write-Log "      the key is NEVER shipped inside the MSI: the release administrator distributes it out-of-band, and an unsigned/unverified bundle must never be installed."
        Write-Log "    setx /M UDBMCP_RELEASE_PUBKEY `"C:\ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem`""
        Write-Log "    (then copy the key to that path from your trusted channel)"
        Fail "release public key not configured (UDBMCP_RELEASE_PUBKEY); installation ABORTED (fail closed)."
    }
    if (-not (Test-Path -LiteralPath $PubKey -PathType Leaf)) {
        Write-Log "release public key not found at $PubKey."
        Write-Log "The key is distributed out-of-band by the release administrator; install it before running msiexec:"
        Write-Log "    New-Item -ItemType Directory -Force (Split-Path '$PubKey')"
        Write-Log "    Copy-Item <trusted-path>\udbmcp-release.pub.pem '$PubKey'"
        Fail "release public key not found at $PubKey; installation ABORTED (fail closed)."
    }
    # Defense in depth: a pubkey inside the bundle is attacker-controlled
    # (a tampered bundle would ship its own key and "verify" against it).
    if (Test-InsideDir $PubKey $BundleDir) {
        Fail "release public key ($PubKey) is inside the installed bundle ($BundleDir); a key shipped with the payload authenticates nothing. Install the key outside the bundle (set UDBMCP_RELEASE_PUBKEY machine-wide)."
    }

    # --- prerequisite 3: the PER-MACHINE python interpreter -------------------
    # The bundle's own python (venv/python.exe) may not run anything yet --
    # including the verifier. The wxs LaunchCondition guarantees a per-machine
    # python.org CPython 3.12 (HKLM\SOFTWARE\Python\PythonCore\3.12, PEP 514);
    # resolution is pinned to EXACTLY that registry value and never via py.exe
    # or PATH: py.exe prefers a per-user (HKCU) installation over the
    # per-machine one, and a local non-admin can register one. Python startup
    # auto-executes user site-packages (.pth files), so an unpinned resolver
    # would let a non-admin run arbitrary code HERE, as LocalSystem, BEFORE the
    # bundle is verified -- the verify-before-execute gate itself would be
    # attacker-controlled. The LaunchCondition only proves a per-machine 3.12
    # EXISTS; this block pins execution to that same hive, and an HKCU-only
    # machine fails closed with the bootstrap diagnostic below.
    $pyExe = $null
    $pyArgs = @()
    $candidate = $data['PYTHON']
    if (-not $candidate) { $candidate = $env:UDBMCP_PYTHON }
    if ($candidate) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Fail "configured python interpreter not found at $candidate (PYTHON in CustomActionData or UDBMCP_PYTHON)."
        }
        $pyExe = $candidate
    }
    if (-not $pyExe) {
        $pyHive = 'HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath'
        if (Test-Path -LiteralPath $pyHive) {
            $pyProps = Get-ItemProperty -LiteralPath $pyHive
            # PEP 514: ExecutablePath when present, else the key's default
            # value (the install directory) + python.exe.
            $regCandidate = $pyProps.ExecutablePath
            if (-not $regCandidate) {
                $pyInstallPath = $pyProps.'(default)'
                if ($pyInstallPath) { $regCandidate = Join-Path $pyInstallPath 'python.exe' }
            }
            if ($regCandidate -and (Test-Path -LiteralPath $regCandidate -PathType Leaf)) {
                $pyExe = $regCandidate
            }
        }
    }
    if (-not $pyExe) {
        Write-Log "no PER-MACHINE CPython 3.12 found (HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath)."
        Write-Log "A per-user (HKCU) interpreter is deliberately NOT accepted: py.exe would prefer it and a local non-admin can register one, so executing it here -- as LocalSystem, before the bundle is verified -- would run attacker-controlled code."
        Write-Log "Install python.org CPython 3.12 per-machine (the MSI launch condition requires it), or pass PYTHON in CustomActionData / set UDBMCP_PYTHON machine-wide."
        Fail "no python interpreter available to run the trusted verifier; installation ABORTED (fail closed)."
    }
    # The interpreter must not come from the bundle either (no venv exists
    # yet, but refuse a misconfigured path regardless).
    if (Test-InsideDir $pyExe $BundleDir) {
        Fail "python interpreter ($pyExe) is inside the installed bundle; bundle payload (including its python) may not execute before verification passes."
    }
    # Prove the registry-resolved interpreter is really CPython 3.12 BEFORE the
    # trusted verifier is executed with it: a stale/wrong HKLM registration
    # must fail closed with a clear diagnostic, not crash inside the verifier
    # (the admin-provided PYTHON/UDBMCP_PYTHON override above is a deliberate
    # administrator decision and is not second-guessed here). EAP is relaxed
    # around the native invocation for the same Windows PowerShell 5.1
    # stderr-escalation reason documented at the verifier run below.
    if (-not $candidate) {
        $prevProbeEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $pyExe -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' 1> $null 2> $null
            $pyProbeExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevProbeEap
        }
        if ($pyProbeExit -ne 0) {
            Fail "the per-machine interpreter registered at HKLM\SOFTWARE\Python\PythonCore\3.12 ($pyExe) is not CPython 3.12.x (the wheelhouse is built for cp312); installation ABORTED (fail closed)."
        }
    }

    Write-Log "  bundle:   $BundleDir"
    Write-Log "  verifier: $Verifier"
    Write-Log "  profiles: $profilesPy"
    Write-Log "  pubkey:   $PubKey"
    Write-Log "  python:   $pyExe $($pyArgs -join ' ')"

    # --- run the ONE trusted verifier against the installed bundle ----------
    # Reading the bundle is safe; executing it is not, and nothing here runs
    # any of it. Output goes to files (not the pipeline), and the invocation
    # runs with $ErrorActionPreference temporarily relaxed: Windows
    # PowerShell 5.1 turns native-command stderr into error records that a
    # 'Stop' preference would escalate into a spurious terminating error.
    # The verifier's exit code + output remain the ONLY decision inputs.
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $pyExe @pyArgs $Verifier --bundle $BundleDir --pubkey $PubKey 1> $outFile 2> $errFile
        $verifierExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
        $verifierOut = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
        $verifierErr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $verifierOut) { $verifierOut = '' }
    if ($null -eq $verifierErr) { $verifierErr = '' }

    foreach ($line in ($verifierOut -split "`r?`n")) { if ($line.Trim()) { Write-Log "  verify: $line" } }
    foreach ($line in ($verifierErr -split "`r?`n")) { if ($line.Trim()) { Write-Log "  verify(err): $line" } }

    # --- fail closed on EVERY non-passing outcome ----------------------------
    # The verifier's canonical diagnostics are its "FAIL: ..." lines and
    # "bundle verification FAILED; do not install" -- forwarded verbatim above
    # and into $script:LogPath for the post-mortem. Exit code alone is not
    # trusted: success requires exit 0 AND the verifier's explicit
    # "bundle verification PASSED" AND no FAIL line (a verifier that exits 0
    # without proof is treated as failed).
    if ($verifierExit -ne 0) {
        Fail "trusted verifier exited $verifierExit (see 'verify:' lines and $script:LogPath); the canonical diagnostic is included above. The bundle is untrusted: installation ABORTED."
    }
    if (($verifierOut + $verifierErr) -match '(?m)^FAIL:') {
        Fail "trusted verifier reported FAIL (see above); the bundle is untrusted: installation ABORTED."
    }
    if (($verifierOut + $verifierErr) -notmatch 'bundle verification PASSED') {
        Fail "trusted verifier exited 0 but did not print 'bundle verification PASSED'; without explicit proof of verification the bundle is treated as untrusted: installation ABORTED."
    }

    Write-Log "==> universal-db-mcp: installed bundle verified (integrity + authenticity) via the admin-installed trusted verifier; payload may now be used by the subsequent custom actions."

    # The ONLY exit-0 path: verification passed with proof.
    exit 0
} catch {
    Fail "unexpected error during bundle verification: $($_.Exception.Message)"
}
