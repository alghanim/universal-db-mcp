# Gate: Windows .msi native package (plan Phase 5).
#
# DELIVERED FOR A REAL WINDOWS MACHINE - never executed on the staging host
# (the staging host is macOS; the ledger honestly records the Windows runtime
# checks as run by THIS script on a Windows machine, or not_run).
#
# ---------------------------------------------------------------------------
# WHAT THIS GATE PROVES (one check per line in the evidence JSON):
#   1. prerequisites: running on Windows, elevated (admin), a per-machine
#      python.org CPython 3.12 is present, the MSI exists, the admin
#      trust bootstrap (trusted verify_bundle.py + profiles.py + release
#      public key) is in place, and packaging/msi/custom/verify.ps1 is
#      available for the standalone negative case.
#   2. msi_install: msiexec /i with /l*v logging succeeds (exit 0 or 3010).
#      The MSI's own deferred verify custom action must have passed BEFORE
#      anything executed payload; this gate independently re-proves it (8).
#   3. installed_bundle_verified: the ADMIN-INSTALLED trusted verifier
#      (C:\Program Files\udbmcp-trust\verify_bundle.py --pubkey ...; the
#      fixed path the MSI pins via CustomActionData) re-verifies
#      the installed bundle at "C:\Program Files\UniversalDB MCP\bundle" and
#      prints its "bundle verification PASSED" proof. The bundle's own
#      bundled verifier copy (installers/verify_bundle.py) is NEVER executed.
#   4. service_running: sc.exe query udbmcp shows the service; if it is not
#      RUNNING it is started and polled (mirrors the deferred sc.exe create
#      custom action wired by udbmcp.wxs / build_msi.sh; if the service is
#      absent this check fails closed with the sc.exe exit-1060 diagnostic).
#   5. doctor_smoke: "<venv>\Scripts\python.exe -m universal_db_mcp doctor"
#      with a demo config exits 0 (the first execution of payload code).
#   6. stdio_protocol_probe: the full MCP stdio lifecycle (initialize,
#      tools, query, write-denied-by-policy, sample) driven by
#      scripts/protocol_probe.py against a synthetic SQLite demo fixture
#      created by the bundle's config-templates/create_demo.py.
#   7. tamper_negative: a wheel inside the INSTALLED bundle under Program
#      Files is corrupted, then the verify custom action
#      (packaging/msi/custom/verify.ps1) is run standalone against the
#      tampered bundle - it MUST fail closed (nonzero exit + FAIL output).
#      The wheel is then restored and the same verifier MUST pass again,
#      proving the failure was caused by the tamper and nothing else.
#   8. peruser_interpreter_refused: a per-user CPython 3.12 (HKCU PEP 514)
#      whose interpreter is an attacker-controlled stub that prints
#      'bundle verification PASSED' and exits 0 is registered, and the
#      per-machine HKLM PythonCore\3.12 key is temporarily moved aside: BOTH
#      the standalone verify custom action AND a full msiexec install must
#      FAIL (the verifier refuses to run on anything but the per-machine
#      interpreter; the stub must never execute - proven by a canary file the
#      stub would write). The registry and environment are restored and the
#      trusted verifier must pass again afterwards.
#
# TRUST INVARIANTS (identical to packaging/msi/custom/verify.ps1):
#   * Every payload execution in this gate (doctor, probe, create_demo) is
#     sequenced AFTER the trusted verifier has PASSED against the installed
#     bundle on this machine (checks 2/3 before 5/6).
#   * The release public key is NEVER shipped in any package; it is read
#     from the admin's out-of-band location. If it is missing the gate
#     fails closed at the prerequisites check.
#   * The verifier always comes from OUTSIDE the bundle (the trust
#     directory or the repository checkout), never from the payload.
#   * Fail closed on every verification failure; the evidence JSON is
#     written even when the gate fails.
#
# EVIDENCE: out/package-evidence/msi/results.json (+ logs\). Exit code is
# nonzero if any check fails.
#
# TYPICAL INVOCATION (elevated PowerShell, from the repository checkout that
# also contains dist\universal-db-mcp-<ver>-win-x86_64.msi):
#     powershell.exe -NoProfile -ExecutionPolicy Bypass `
#         -File scripts\test_package_msi.ps1
# Re-run against an existing install without reinstalling:
#     powershell.exe -NoProfile -ExecutionPolicy Bypass `
#         -File scripts\test_package_msi.ps1 -SkipMsiInstall
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    # Path to the MSI built by scripts/package/build_msi.sh. Default: newest
    # *.msi under <RepoDir>\dist.
    [string]$MsiPath = '',

    # Repository checkout (holds scripts\protocol_probe.py and
    # packaging\msi\custom\verify.ps1). Default: the directory above this
    # script (the repo root, when run from a checkout).
    [string]$RepoDir = '',

    # Trust directory holding the ADMIN-INSTALLED trusted verifier
    # (verify_bundle.py + profiles.py). Must live OUTSIDE the bundle. Default:
    # the fixed path the MSI passes via CustomActionData
    # (TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust). A custom -TrustDir is
    # STAGED (copied) to that fixed path before msiexec runs: the deferred
    # verify custom action no longer reads a machine-scope UDBMCP_TRUST_DIR
    # override, so it always looks in the Program Files location.
    [string]$TrustDir = 'C:\Program Files\udbmcp-trust',

    # Release public key PEM (distributed out-of-band by the release
    # administrator; NEVER shipped in the MSI or the bundle). Default:
    # machine-scope UDBMCP_RELEASE_PUBKEY, else the documented default path.
    [string]$PubKey = '',

    # Explicit CPython 3.12 interpreter. Default: the per-machine PEP 514
    # registry value (HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath); a
    # per-user (HKCU) interpreter or the py launcher is deliberately not used
    # (a non-admin can register either; see Find-Cpython312 below).
    [string]$PythonExe = '',

    # The verify custom action for the standalone negative case. Default:
    # <RepoDir>\packaging\msi\custom\verify.ps1.
    [string]$VerifyScript = '',

    # Install root (must mirror udbmcp.wxs: ProgramFiles64Folder\UniversalDB MCP).
    [string]$InstallRoot = '',

    # Windows service name created by the deferred custom action.
    [string]$ServiceName = 'udbmcp',

    # Evidence directory (results.json + logs\). Default: <RepoDir>\out\package-evidence\msi.
    [string]$EvidenceDir = '',

    # Skip msiexec (re-run the runtime checks against an existing install).
    [switch]$SkipMsiInstall
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------- paths
if (-not $RepoDir) {
    if ($PSScriptRoot) {
        $RepoDir = Split-Path -Parent $PSScriptRoot   # scripts\.. -> repo root
    } else {
        $RepoDir = (Get-Location).Path   # interactive fallback
    }
}
if (-not $InstallRoot) { $InstallRoot = Join-Path $env:ProgramFiles 'UniversalDB MCP' }
if (-not $EvidenceDir) { $EvidenceDir = Join-Path $RepoDir 'out\package-evidence\msi' }
$LogDir      = Join-Path $EvidenceDir 'logs'
$BundleDir   = Join-Path $InstallRoot 'bundle'
$VenvDir     = Join-Path $InstallRoot 'venv'
$VenvPython  = Join-Path $VenvDir 'Scripts\python.exe'
$WorkDir     = Join-Path $EvidenceDir ('work-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
# The MSI's deferred verify custom action resolves its trust dir from
# CustomActionData (TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust) and does
# NOT read a machine-scope UDBMCP_TRUST_DIR override: msiexec will look for
# the trusted verifier HERE no matter where -TrustDir points.
$MsiTrustDir = Join-Path $env:ProgramFiles 'udbmcp-trust'

# --------------------------------------------------------------- check ledger
# Mirrors the bash gates (scripts/package/test_package_pkg.sh): every result
# is recorded; any non-pass aborts the gate via Stop-Gate (fail closed) and
# the evidence JSON is still written (Stop-Gate saves it before exiting).
$script:Checks = New-Object System.Collections.Generic.List[object]
$script:Failed = 0

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $Detail = ($Detail -replace "`r?`n", ' ')
    $script:Checks.Add(@{ name = $Name; status = $Status; detail = $Detail }) | Out-Null
    Write-Host ("==> [{0}] {1}: {2}" -f $Status, $Name, $Detail)
    if ($Status -ne 'passed') { $script:Failed = 1 }
}

function Stop-Gate {
    param([string]$Name, [string]$Detail)
    Add-Check -Name $Name -Status 'failed' -Detail $Detail
    # `exit` unwinds the script WITHOUT running the catch block, so the
    # evidence must be written HERE - before exiting - or no results.json
    # would ever be produced for a real gate failure (the bash gates get the
    # same guarantee from their `trap finalize EXIT`).
    Save-Evidence -Status 'failed' -InstallExitCode $script:InstallExitCode -MsiUsed $script:MsiUsed -MsiLog $script:MsiLog
    Write-Host "==> msi gate FAILED (fail closed); evidence: $EvidenceDir\results.json"
    exit 1
}

function Save-Evidence {
    # Always writes results.json (also reached via `exit` from Stop-Gate).
    param([string]$Status, [int]$InstallExitCode, [string]$MsiUsed, [string]$MsiLog)
    $doc = [ordered]@{
        gate              = 'msi'
        generated_at      = (Get-Date).ToUniversalTime().ToString('o')
        status            = $Status
        host              = [ordered]@{
            system      = 'Windows'
            machine     = $env:PROCESSOR_ARCHITECTURE
            powershell  = $PSVersionTable.PSVersion.ToString()
            python312   = $script:HostPython
        }
        msi               = $MsiUsed
        msi_log           = $MsiLog
        install_exit_code = $InstallExitCode
        trust_dir         = $TrustDir
        pubkey            = $script:PubKeyUsed
        install_root      = $InstallRoot
        checks            = $script:Checks
    }
    $json = $doc | ConvertTo-Json -Depth 5
    $outPath = Join-Path $EvidenceDir 'results.json'
    # Stop-Gate (and the catch block) may run before the try body created the
    # evidence directories; never let the evidence write itself fail.
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    [System.IO.File]::WriteAllText($outPath, $json + [Environment]::NewLine)
    Write-Host ("==> evidence written to {0} (status: {1})" -f $outPath, $Status)
}

$script:HostPython = ''
$script:PubKeyUsed = ''
# Install state mirrored here so Stop-Gate can record it in the evidence at
# ANY failure point (including the prerequisite checks, before the MSI has
# been touched: exit code -1, no MSI used, no log).
$script:InstallExitCode = -1
$script:MsiUsed = ''
$script:MsiLog = ''

try {
    New-Item -ItemType Directory -Force -Path $EvidenceDir, $LogDir, $WorkDir | Out-Null

    # ------------------------------------------------------------ helpers ----
    function Find-Cpython312 {
        # Same resolution order as packaging/msi/custom/verify.ps1 and venv.ps1:
        # explicit override, then the PER-MACHINE PEP 514 registry value ONLY
        # (HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath). The HKCU hive and
        # the py launcher are deliberately NOT consulted: both resolve to a
        # per-user installation a local non-admin can register (py.exe prefers
        # per-user installs), and this gate executes the trusted verifier under
        # the interpreter returned here. Returns $null if not found.
        if ($PythonExe) {
            if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { return $null }
            return $PythonExe
        }
        $hive = 'HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath'
        if (-not (Test-Path -LiteralPath $hive)) { return $null }
        $props = Get-ItemProperty -LiteralPath $hive
        $candidate = $props.ExecutablePath
        if (-not $candidate) {
            $installPath = $props.'(default)'
            if ($installPath) { $candidate = Join-Path $installPath 'python.exe' }
        }
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
        return $null
    }

    function Test-Elevated {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-InsideDir {
        param([string]$Candidate, [string]$Directory)
        $c = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\').ToLower()
        $d = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\').ToLower()
        return ($c + '\').StartsWith($d + '\')
    }

    # Run a native command (via scriptblock) with $ErrorActionPreference
    # temporarily relaxed: Windows PowerShell 5.1 turns native-command stderr
    # (merged via 2>&1 or redirected to a file) into error records that a
    # 'Stop' preference would escalate into a spurious terminating error -
    # e.g. sc.exe writing its 1060 diagnostic to stderr. The same
    # neutralization is deliberately applied by
    # packaging/msi/custom/verify.ps1 for the identical construct; the
    # command's exit code and output remain the ONLY decision inputs.
    function Invoke-Native {
        param([scriptblock]$Block)
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { return & $Block } finally { $ErrorActionPreference = $prevEap }
    }

    # Run the trusted verifier (OUTSIDE the bundle, never the bundle's own
    # copy) and return @{ ExitCode; Output }. Proof-of-pass requires exit 0
    # AND the literal 'bundle verification PASSED' AND no FAIL line, exactly
    # like packaging/msi/custom/verify.ps1.
    function Invoke-TrustedVerifier {
        param([string]$TargetBundle)
        $verifier = Join-Path $TrustDir 'verify_bundle.py'
        # Splatting needs a plain local variable (no scope modifier).
        $py = $script:Py
        $pyArgs = $script:PyArgs
        $outFile = [System.IO.Path]::GetTempFileName()
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            Invoke-Native { & $py @pyArgs $verifier --bundle $TargetBundle --pubkey $script:PubKeyUsed 1> $outFile 2> $errFile } | Out-Null
            $code = $LASTEXITCODE
        } finally {
            $out = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
            $err = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
            Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
        }
        if ($null -eq $out) { $out = '' }
        if ($null -eq $err) { $err = '' }
        return @{ ExitCode = $code; Output = ($out + $err) }
    }

    function Assert-VerifierPassed {
        param([string]$TargetBundle, [hashtable]$Result, [string]$CheckName)
        if ($Result.ExitCode -ne 0) {
            Stop-Gate $CheckName ("trusted verifier exited {0}: {1}" -f $Result.ExitCode, ($Result.Output -split "`r?`n" | Select-Object -Last 3) -join ' ')
        }
        if ($Result.Output -match '(?m)^FAIL:') {
            Stop-Gate $CheckName "trusted verifier printed FAIL: $($Result.Output)"
        }
        if ($Result.Output -notmatch 'bundle verification PASSED') {
            Stop-Gate $CheckName "trusted verifier exited 0 without printing 'bundle verification PASSED'; treated as failed (fail closed)"
        }
    }

    # ------------------------------------------------------- 1. prerequisites
    Write-Host "==> msi gate starting (repo: $RepoDir)"

    if (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') -and $env:OS -ne 'Windows_NT') {
        Stop-Gate 'host_is_windows' "this gate must run on Windows (got PSVersionTable platform $($PSVersionTable.Platform))"
    }
    Add-Check 'host_is_windows' 'passed' "Windows host ($env:PROCESSOR_ARCHITECTURE, PowerShell $($PSVersionTable.PSVersion))"

    if (-not (Test-Elevated)) {
        Stop-Gate 'admin_elevation' 'this gate must run elevated (msiexec perMachine install + sc.exe + Program Files writes need admin); re-launch PowerShell as Administrator'
    }
    Add-Check 'admin_elevation' 'passed' 'running elevated (Administrator)'

    if (-not $MsiPath) {
        $candidate = Get-ChildItem -LiteralPath (Join-Path $RepoDir 'dist') -Filter '*.msi' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { $MsiPath = $candidate.FullName }
    }
    if (-not ($SkipMsiInstall -or ($MsiPath -and (Test-Path -LiteralPath $MsiPath -PathType Leaf)))) {
        Stop-Gate 'msi_present' "no MSI found (looked for -MsiPath and the newest dist\*.msi under $RepoDir\dist); build one with scripts/package/build_msi.sh first"
    }
    if ($SkipMsiInstall) {
        Add-Check 'msi_present' 'passed' 'skipped (-SkipMsiInstall): runtime checks against the existing install'
    } else {
        Add-Check 'msi_present' 'passed' "MSI: $MsiPath"
    }

    $script:Py = Find-Cpython312
    $script:PyArgs = @()
    if (-not $script:Py) {
        Stop-Gate 'cpython312_present' 'per-machine CPython 3.12 not found (HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath); install 64-bit python.org CPython 3.12 for all users (the MSI launch condition requires it; a per-user HKCU interpreter or the py launcher is deliberately not accepted)'
    }
    # Interpreter containment, BEFORE this gate executes anything under it
    # (the version probe below and, later, the trusted verifier): a
    # bundle-resident interpreter (misregistered in PEP 514 or passed via
    # -PythonExe) is untrusted payload - running it would execute bundle
    # content before verification passes. Same rule as
    # packaging/msi/custom/verify.ps1, which refuses before its first
    # interpreter invocation.
    if (Test-InsideDir $script:Py $BundleDir) {
        Stop-Gate 'cpython312_present' "host interpreter ($($script:Py)) is inside the installed bundle ($BundleDir); bundle payload (including its python) may not execute before verification passes (fail closed)"
    }
    $v = & $script:Py -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'
    if ($LASTEXITCODE -ne 0 -or -not ($v -match '^3\.12\.')) {
        Stop-Gate 'cpython312_present' "interpreter at $($script:Py) reports '$v'; CPython 3.12.x is required (the wheelhouse is built for cp312)"
    }
    $script:HostPython = $v.Trim()
    Add-Check 'cpython312_present' 'passed' "CPython $v at $($script:Py)"

    # Trust bootstrap: admin-installed trusted verifier + profiles registry +
    # out-of-band release public key. Fails closed when any piece is missing.
    $TrustVerifier = Join-Path $TrustDir 'verify_bundle.py'
    if (-not (Test-Path -LiteralPath $TrustVerifier -PathType Leaf)) {
        Stop-Gate 'trust_bootstrap' "trusted verifier not found at $TrustVerifier; bootstrap it from the trusted channel that delivered the MSI: Copy-Item <trusted-channel>\verify_bundle.py '$TrustDir\' (+ profiles.py)"
    }
    $ProfilesPy = @((Join-Path $TrustDir 'profiles.py'), (Join-Path $TrustDir 'lib\profiles.py')) |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $ProfilesPy) {
        Stop-Gate 'trust_bootstrap' "profiles.py not found in the trust directory ($TrustDir or $TrustDir\lib); the trusted verifier needs it to check the bundle profile"
    }
    if (-not $PubKey) { $PubKey = [Environment]::GetEnvironmentVariable('UDBMCP_RELEASE_PUBKEY', 'Machine') }
    if (-not $PubKey) { $PubKey = 'C:\ProgramData\universal-db-mcp\keys\udbmcp-release.pub.pem' }
    if (-not (Test-Path -LiteralPath $PubKey -PathType Leaf)) {
        Stop-Gate 'trust_bootstrap' "release public key not found at $PubKey; the key is NEVER shipped in the MSI - the release administrator distributes it out-of-band (setx /M UDBMCP_RELEASE_PUBKEY <path>)"
    }
    $script:PubKeyUsed = $PubKey
    if (Test-InsideDir $TrustDir $BundleDir) {
        Stop-Gate 'trust_bootstrap' "trust directory ($TrustDir) is inside the installed bundle ($BundleDir); a verifier from the payload proves nothing (fail closed)"
    }
    if (Test-InsideDir $PubKey $BundleDir) {
        Stop-Gate 'trust_bootstrap' "release public key ($PubKey) is inside the installed bundle; a key shipped with the payload authenticates nothing (fail closed)"
    }
    Add-Check 'trust_bootstrap' 'passed' "trusted verifier: $TrustVerifier; profiles: $ProfilesPy; pubkey: $PubKeyUsed"

    # Make the key visible to the deferred custom actions, which run as
    # LocalSystem and see MACHINE env only (the pubkey is NOT passed in
    # CustomActionData, so this env var is still how the MSI finds it).
    $machineKey = [Environment]::GetEnvironmentVariable('UDBMCP_RELEASE_PUBKEY', 'Machine')
    if ($machineKey -ne $PubKeyUsed) {
        [Environment]::SetEnvironmentVariable('UDBMCP_RELEASE_PUBKEY', $PubKeyUsed, 'Machine')
        Add-Check 'pubkey_machine_env' 'passed' "set machine-scope UDBMCP_RELEASE_PUBKEY=$PubKeyUsed (deferred custom actions run as LocalSystem and read machine env)"
    }
    # The trust dir, by contrast, is NOT read from the environment any more:
    # VerifyBundleCA gets TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust via
    # CustomActionData (an env override cannot win, and ProgramData would be
    # non-admin squattable). When the admin bootstrapped the trust material
    # somewhere else, STAGE (copy) it to the fixed path msiexec will resolve
    # -- an admin-elevated write into the admin-write-only Program Files tree.
    if ($TrustDir -ne $MsiTrustDir) {
        New-Item -ItemType Directory -Force -Path $MsiTrustDir | Out-Null
        foreach ($item in @('verify_bundle.py', 'profiles.py', 'lib')) {
            $src = Join-Path $TrustDir $item
            if (Test-Path -LiteralPath $src) {
                Copy-Item -LiteralPath $src -Destination $MsiTrustDir -Recurse -Force
            }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $MsiTrustDir 'verify_bundle.py') -PathType Leaf)) {
            Stop-Gate 'trust_dir_staged' "could not stage the trusted verifier from $TrustDir to $MsiTrustDir; VerifyBundleCA resolves TRUST_DIR=[ProgramFiles64Folder]udbmcp-trust via CustomActionData and fails closed without it"
        }
        Add-Check 'trust_dir_staged' 'passed' "staged the trusted verifier + profiles registry from $TrustDir to the MSI's fixed trust dir $MsiTrustDir (VerifyBundleCA reads TRUST_DIR from CustomActionData; a machine-scope UDBMCP_TRUST_DIR env override is no longer read)"
    }

    if (-not $VerifyScript) { $VerifyScript = Join-Path $RepoDir 'packaging\msi\custom\verify.ps1' }
    if (-not (Test-Path -LiteralPath $VerifyScript -PathType Leaf)) {
        Stop-Gate 'verify_script_present' "verify custom action not found at $VerifyScript (needed for the standalone tamper negative case)"
    }
    Add-Check 'verify_script_present' 'passed' "verify custom action: $VerifyScript"

    # ---------------------------------------------------------- 2. msi install
    # Kept in $script: scope so Stop-Gate records the real install state in
    # the evidence JSON no matter where the gate fails afterwards.
    $script:InstallExitCode = -1
    $script:MsiLog = Join-Path $LogDir 'msi-install.log'
    $script:MsiUsed = $MsiPath
    if ($SkipMsiInstall) {
        Add-Check 'msi_install' 'passed' 'skipped (-SkipMsiInstall); the install-time verify custom action is re-proven by installed_bundle_verified below'
        $script:MsiLog = ''
    } else {
        Write-Host "==> installing $MsiPath (msiexec /i /qn /norestart /l*v)"
        if (Test-Path -LiteralPath $script:MsiLog) { Remove-Item -LiteralPath $script:MsiLog -Force }
        $argStr = "/i `"$MsiPath`" /qn /norestart /l*v `"$($script:MsiLog)`""
        $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $argStr -Wait -PassThru
        $script:InstallExitCode = $proc.ExitCode
        if ($script:InstallExitCode -eq 0) {
            Add-Check 'msi_install' 'passed' "msiexec /i exited 0 (log: $($script:MsiLog))"
        } elseif ($script:InstallExitCode -eq 3010) {
            Add-Check 'msi_install' 'passed' "msiexec /i exited 3010 (success, reboot required; log: $($script:MsiLog))"
        } else {
            $tail = ''
            if (Test-Path -LiteralPath $script:MsiLog) {
                $tail = ((Get-Content -LiteralPath $script:MsiLog -Tail 40) -join ' ')
            }
            Stop-Gate 'msi_install' "msiexec /i exited $($script:InstallExitCode) (0 and 3010 are the only success codes); log tail: $tail"
        }
    }

    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        Stop-Gate 'installed_bundle_present' "installed bundle not found at $BundleDir (udbmcp.wxs installs it under ProgramFiles64Folder\UniversalDB MCP\bundle)"
    }
    Add-Check 'installed_bundle_present' 'passed' "installed bundle: $BundleDir"

    # --------------------------------------- 3. trusted verify of the INSTALL
    # Independent confirmation that the installed tree is the signed bundle:
    # the admin-installed trusted verifier (outside the payload) must PASS
    # before this gate executes any payload code (doctor / probe / demo).
    $verifierResult = Invoke-TrustedVerifier -TargetBundle $BundleDir
    Assert-VerifierPassed -Result $verifierResult -CheckName 'installed_bundle_verified'
    Add-Check 'installed_bundle_verified' 'passed' "trusted verifier ($TrustDir\verify_bundle.py --pubkey) PASSED against the installed bundle; payload execution may proceed"

    # --------------------------------------------------------- 4. the service
    $scExe = Join-Path $env:SystemRoot 'System32\sc.exe'
    # Stringify the native output: 2>&1 under $ErrorActionPreference='Stop'
    # yields ErrorRecords, and every consumer below wants plain strings.
    $qOut = (Invoke-Native { & $scExe query $ServiceName 2>&1 }) | ForEach-Object { "$_" }
    if ($LASTEXITCODE -eq 1060) {
        Stop-Gate 'service_running' "service '$ServiceName' does not exist (sc.exe query exit 1060); the deferred sc.exe create custom action did not run or failed - inspect the msiexec log"
    }
    $stateLine = ($qOut | Where-Object { $_ -match '^\s*STATE' } | Select-Object -First 1)
    if ($stateLine -match 'RUNNING') {
        Add-Check 'service_running' 'passed' "service '$ServiceName' is RUNNING"
    } else {
        Write-Host "==> service not RUNNING ($stateLine); attempting sc.exe start"
        (Invoke-Native { & $scExe start $ServiceName 2>&1 }) | ForEach-Object { "$_" } | Out-Null
        $running = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Seconds 2
            $qOut = Invoke-Native { & $scExe query $ServiceName 2>&1 }
            $stateLine = ($qOut | Where-Object { $_ -match '^\s*STATE' } | Select-Object -First 1)
            if ($stateLine -match 'RUNNING') { $running = $true; break }
        }
        if ($running) {
            Add-Check 'service_running' 'passed' "service '$ServiceName' RUNNING after sc.exe start"
        } else {
            Stop-Gate 'service_running' "service '$ServiceName' exists but is not RUNNING (last state: $stateLine); check the Windows event log and the msiexec log"
        }
    }

    # --------------------------------------------- 5. doctor smoke (payload)
    # First execution of payload code; reached only after installed_bundle_verified.
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Stop-Gate 'doctor_smoke' "venv python not found at $VenvPython; the venv custom action should have built it from the verified wheelhouse"
    }
    $DemoDb = Join-Path $WorkDir 'demo.db'
    $CreateDemo = Join-Path $BundleDir 'config-templates\create_demo.py'
    if (-not (Test-Path -LiteralPath $CreateDemo -PathType Leaf)) {
        Stop-Gate 'doctor_smoke' "demo fixture generator not found at $CreateDemo (bundle layout changed?)"
    }
    Invoke-Native { & $VenvPython $CreateDemo --path $DemoDb 1> (Join-Path $LogDir 'create-demo.log') 2>&1 } | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $DemoDb -PathType Leaf)) {
        Stop-Gate 'doctor_smoke' "create_demo.py exited $LASTEXITCODE; see $(Join-Path $LogDir 'create-demo.log')"
    }
    $DoctorConfig = Join-Path $WorkDir 'doctor-config.yaml'
    $doctorCfg = @"
application:
  airgapped: true
  transport: stdio
  metadata_cache_path: $(Join-Path $WorkDir 'meta.sqlite')
  audit_path: $(Join-Path $WorkDir 'audit.jsonl')
  telemetry_enabled: false
security:
  read_only: true
  default_deny_objects: true
connections:
  demo_sqlite:
    type: sqlite
    database: $DemoDb
    read_only: true
"@
    [System.IO.File]::WriteAllText($DoctorConfig, $doctorCfg)
    Invoke-Native { & $VenvPython -m universal_db_mcp doctor --config $DoctorConfig 1> (Join-Path $LogDir 'doctor.json') 2> (Join-Path $LogDir 'doctor.err') } | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $err = (Get-Content -LiteralPath (Join-Path $LogDir 'doctor.err') -Raw -ErrorAction SilentlyContinue)
        Stop-Gate 'doctor_smoke' "doctor exited $LASTEXITCODE: $err"
    }
    Add-Check 'doctor_smoke' 'passed' "doctor (venv python -m universal_db_mcp doctor) exited 0 against the demo config (log: $(Join-Path $LogDir 'doctor.json'))"

    # ------------------------------------------- 6. stdio protocol probe
    # The probe drives the real server (`python -m universal_db_mcp serve`)
    # with the pinned SDK client over the full lifecycle. It needs an
    # interpreter with the mcp SDK: the installed venv itself.
    $ProbeScript = Join-Path $RepoDir 'scripts\protocol_probe.py'
    $probeSource = 'repository copy (scripts\protocol_probe.py)'
    if (-not (Test-Path -LiteralPath $ProbeScript -PathType Leaf)) {
        # Fallback: the bundle ships the same probe; it may be executed here
        # because installed_bundle_verified has already PASSED.
        $ProbeScript = Join-Path $BundleDir 'tests\protocol_probe.py'
        $probeSource = 'bundle copy (bundle\tests\protocol_probe.py; executed after the trusted verifier PASSED)'
    }
    if (-not (Test-Path -LiteralPath $ProbeScript -PathType Leaf)) {
        Stop-Gate 'stdio_protocol_probe' "protocol probe not found (checked $RepoDir\scripts\protocol_probe.py and $BundleDir\tests\protocol_probe.py)"
    }
    $ProbeOut = Join-Path $EvidenceDir 'protocol-probe.json'
    Invoke-Native { & $VenvPython $ProbeScript $VenvPython $DemoDb 1> $ProbeOut 2> (Join-Path $LogDir 'probe.err') } | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $err = (Get-Content -LiteralPath (Join-Path $LogDir 'probe.err') -Raw -ErrorAction SilentlyContinue)
        Stop-Gate 'stdio_protocol_probe' "protocol probe exited $LASTEXITCODE: $err"
    }
    $probeJson = $null
    try { $probeJson = Get-Content -LiteralPath $ProbeOut -Raw | ConvertFrom-Json } catch { $probeJson = $null }
    if ($probeJson -and $probeJson.status -eq 'passed') {
        Add-Check 'stdio_protocol_probe' 'passed' "full stdio MCP lifecycle passed ($probeSource; evidence: $ProbeOut)"
    } else {
        Stop-Gate 'stdio_protocol_probe' "probe output at $ProbeOut does not report status=passed (source: $probeSource)"
    }

    # --------------------------------------- 7. tamper negative (fail closed)
    # Corrupt one wheel inside the INSTALLED bundle under Program Files, run
    # the verify custom action standalone (CustomActionData contract from
    # packaging/msi/custom/verify.ps1) and require a nonzero exit with the
    # canonical FAIL diagnostic; then restore the wheel and require the same
    # verifier to PASS again. The tamper only affects a read-only-verified
    # wheel: no payload runs between tamper and restore.
    $wheel = Get-ChildItem -LiteralPath (Join-Path $BundleDir 'wheelhouse') -Filter '*.whl' -File |
        Sort-Object Name | Select-Object -First 1
    if (-not $wheel) {
        Stop-Gate 'tamper_detected' "no wheel found in $(Join-Path $BundleDir 'wheelhouse'); cannot build the negative case"
    }
    $Backup = Join-Path $WorkDir ($wheel.Name + '.gate-backup')
    Copy-Item -LiteralPath $wheel.FullName -Destination $Backup -Force

    # Exception-safe tamper window: from the moment the wheel is corrupted in
    # place until it is restored, ANY abnormal unwind (a terminating error
    # reaching the outer catch, or Stop-Gate's `exit`) must restore the
    # backup - otherwise the gate leaves a permanently corrupted bundle under
    # Program Files. The finally below runs on every unwind (PowerShell runs
    # finally blocks even for `exit`), so the explicit restores inside the try
    # are belt-and-braces for the two decision paths whose evidence is saved
    # before the unwind reaches the finally.
    $WheelTampered = $false
    try {
        # Append 16 bytes of junk: SHA256SUMS no longer matches.
        $orig = [System.IO.File]::ReadAllBytes($wheel.FullName)
        $tampered = New-Object byte[] ($orig.Length + 16)
        [Array]::Copy($orig, $tampered, $orig.Length)
        for ($i = $orig.Length; $i -lt $tampered.Length; $i++) { $tampered[$i] = 0xAB }
        [System.IO.File]::WriteAllBytes($wheel.FullName, $tampered)
        $WheelTampered = $true

        $cad = 'BUNDLE_DIR={0};TRUST_DIR={1};PUBKEY={2};PYTHON={3}' -f $BundleDir, $TrustDir, $PubKeyUsed, $script:Py
        $tamperLog = Join-Path $LogDir 'verify-tampered.log'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CustomActionData $cad 1> $tamperLog 2>&1 } | Out-Null
        $tamperExit = $LASTEXITCODE
        $tamperOut = (Get-Content -LiteralPath $tamperLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $tamperOut) { $tamperOut = '' }

        if ($tamperExit -eq 0) {
            # Restore before failing so the machine is left as found.
            Copy-Item -LiteralPath $Backup -Destination $wheel.FullName -Force
            Stop-Gate 'tamper_detected' "verify custom action exited 0 against a TAMPERED wheel ($($wheel.Name)); it must fail closed - this is a hard trust failure"
        }
        if ($tamperOut -notmatch 'FAIL:') {
            Copy-Item -LiteralPath $Backup -Destination $wheel.FullName -Force
            Stop-Gate 'tamper_detected' "verify custom action exited $tamperExit but printed no 'FAIL:' diagnostic against the tampered wheel; the canonical diagnostic is required"
        }
        Add-Check 'tamper_detected' 'passed' "corrupted $($wheel.Name) inside the installed bundle; standalone verify custom action exited $tamperExit with FAIL (log: $tamperLog)"

        # Restore and require the verifier to pass again (same script, clean tree).
        Copy-Item -LiteralPath $Backup -Destination $wheel.FullName -Force
        $WheelTampered = $false
    } finally {
        if ($WheelTampered) {
            # Abnormal unwind with the wheel still corrupted: leave the
            # machine as found (best effort) even though the gate is failing.
            Copy-Item -LiteralPath $Backup -Destination $wheel.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    $restoreResult = Invoke-TrustedVerifier -TargetBundle $BundleDir
    if ($restoreResult.ExitCode -eq 0 -and $restoreResult.Output -match 'bundle verification PASSED' -and $restoreResult.Output -notmatch '(?m)^FAIL:') {
        Add-Check 'restore_reverified' 'passed' "wheel restored; trusted verifier PASSED again (tamper was the sole cause of the failure)"
    } else {
        Stop-Gate 'restore_reverified' "after restoring the wheel the trusted verifier did not pass (exit $($restoreResult.ExitCode)); the bundle may be left tampered - reinstall the MSI"
    }

    # ---------------------------------- 8. per-user interpreter refusal (fail closed)
    # A local non-admin can register a per-user CPython 3.12 (HKCU PEP 514)
    # whose interpreter is arbitrary code (Python startup auto-executes user
    # site-packages .pth files). py.exe prefers per-user installs over
    # per-machine ones, so an unpinned resolver would run attacker-controlled
    # code as LocalSystem DURING INSTALL -- before the bundle is verified,
    # i.e. the verify-before-execute gate itself would be attacker-controlled.
    # The verify custom action must be pinned to the exact HKLM hive the
    # LaunchCondition checks: with ONLY a per-user 3.12 available it must
    # REFUSE (fail closed), never execute the stub.
    #
    # Exercise: register an HKCU PythonCore\3.12 pointing at a stub that prints
    # 'bundle verification PASSED' and exits 0 (exactly what a defeated gate
    # needs), temporarily move the per-machine HKLM
    # SOFTWARE\Python\PythonCore\3.12 key aside (so the refusal -- not a
    # legitimate per-machine hit -- is observable), and require BOTH:
    #   (a) the standalone verify custom action (no PYTHON override) exits
    #       nonzero with its FAIL diagnostic, and
    #   (b) a full msiexec install FAILS rather than completing (the product is
    #       Installed after check 2, so the LaunchCondition passes and the
    #       deferred VerifyBundleCA itself must refuse).
    # The stub writes a canary file when executed; its absence after both
    # negatives proves the attacker interpreter never ran. Everything is
    # restored in finally (registry + environment) and the trusted verifier
    # must pass again afterwards, proving the machine was left as found.
    $StubDir = Join-Path $WorkDir 'peruser-python'
    New-Item -ItemType Directory -Force -Path $StubDir | Out-Null
    $StubPython = Join-Path $StubDir 'stub-python.cmd'
    $StubCanary = Join-Path $WorkDir 'peruser-python-ran.canary'
    # Batch "interpreter": if it is ever executed it forges the verifier's
    # proof AND drops the canary; the refusal must leave the canary nonexistent.
    [System.IO.File]::WriteAllText($StubPython, "@echo off`r`n@echo attacked>`"$StubCanary`"`r`necho bundle verification PASSED`r`nexit /b 0`r`n")
    $StubHive = 'HKCU:\SOFTWARE\Python\PythonCore\3.12\InstallPath'
    $StubHiveExisted = Test-Path -LiteralPath $StubHive
    $StubHiveCreated = $false
    $StubOrigExec = $null
    $StubOrigDefault = $null
    if ($StubHiveExisted) {
        $stubProps = Get-ItemProperty -LiteralPath $StubHive
        if ($null -ne $stubProps.ExecutablePath) { $StubOrigExec = $stubProps.ExecutablePath }
        if ($null -ne $stubProps.'(default)') { $StubOrigDefault = $stubProps.'(default)' }
    }
    $HklmPythonKey = 'HKLM:\SOFTWARE\Python\PythonCore\3.12'
    $HklmPythonBackupName = '3.12.gate-backup'
    $HklmPythonExisted = Test-Path -LiteralPath $HklmPythonKey
    $HklmPythonMoved = $false
    $SavedProcessUdbmcpPython = $env:UDBMCP_PYTHON
    try {
        # Register the attacker-controlled per-user interpreter (exactly what a
        # local non-admin can do without any elevation).
        if (-not $StubHiveExisted) {
            New-Item -ItemType Directory -Force -Path $StubHive | Out-Null
            $StubHiveCreated = $true
        }
        New-ItemProperty -LiteralPath $StubHive -Name 'ExecutablePath' -Value $StubPython -PropertyType String -Force | Out-Null
        Set-Item -LiteralPath $StubHive -Value $StubDir
        # Move the per-machine key aside so interpreter resolution CANNOT
        # legitimately succeed (the key is restored in finally).
        if ($HklmPythonExisted) {
            Rename-Item -LiteralPath $HklmPythonKey -NewName $HklmPythonBackupName
            $HklmPythonMoved = $true
        }
        # The custom actions see this process's environment; make sure an
        # interpreter override cannot mask the refusal (restored in finally).
        Remove-Item -Path 'env:UDBMCP_PYTHON' -ErrorAction SilentlyContinue

        # (a) standalone verify custom action: no PYTHON override anywhere ->
        #     it must refuse instead of falling back to the HKCU stub.
        $peruserCad = 'BUNDLE_DIR={0};TRUST_DIR={1};PUBKEY={2}' -f $BundleDir, $TrustDir, $PubKeyUsed
        $peruserLog = Join-Path $LogDir 'verify-peruser-refusal.log'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CustomActionData $peruserCad 1> $peruserLog 2>&1 } | Out-Null
        $peruserExit = $LASTEXITCODE
        $peruserOut = (Get-Content -LiteralPath $peruserLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $peruserOut) { $peruserOut = '' }
        if ($peruserExit -eq 0) {
            Stop-Gate 'peruser_interpreter_refused' "verify custom action exited 0 with ONLY a per-user (HKCU) interpreter registered; it must fail closed - a non-admin-registered interpreter must never run the trusted verifier"
        }
        if ($peruserOut -notmatch 'FAIL:') {
            Stop-Gate 'peruser_interpreter_refused' "verify custom action exited $peruserExit but printed no 'FAIL:' diagnostic with only a per-user interpreter registered; the canonical diagnostic is required (log: $peruserLog)"
        }
        if ($peruserOut -notmatch 'no python interpreter available to run the trusted verifier') {
            Stop-Gate 'peruser_interpreter_refused' "verify custom action failed with an unexpected diagnostic (expected the interpreter refusal, got: $($peruserOut.Trim().Substring(0, [Math]::Min(300, $peruserOut.Length)))); it must refuse THE INTERPRETER, not fail for an unrelated reason"
        }
        if (Test-Path -LiteralPath $StubCanary) {
            Stop-Gate 'peruser_interpreter_refused' "the per-user stub interpreter was EXECUTED during the refused verify run (canary written); a non-admin-registered interpreter must never execute"
        }
        Add-Check 'peruser_standalone_refused' 'passed' "standalone verify custom action exited $peruserExit with FAIL and never executed the HKCU stub interpreter (log: $peruserLog)"

        # (b) full msiexec install: the product is Installed (check 2), so the
        #     LaunchCondition passes and the deferred VerifyBundleCA itself
        #     must refuse -> msiexec must NOT complete.
        if ($SkipMsiInstall) {
            Add-Check 'peruser_install_refused' 'passed' 'skipped (-SkipMsiInstall); the standalone refusal above proves a per-user interpreter is never accepted'
        } else {
            $peruserMsiLog = Join-Path $LogDir 'msi-install-peruser-refusal.log'
            $peruserArgStr = "/i `"$MsiPath`" /qn /norestart /l*v `"$peruserMsiLog`""
            $peruserProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $peruserArgStr -Wait -PassThru
            if ($peruserProc.ExitCode -eq 0 -or $peruserProc.ExitCode -eq 3010) {
                Stop-Gate 'peruser_interpreter_refused' "msiexec install SUCCEEDED ($($peruserProc.ExitCode)) with ONLY a per-user (HKCU) interpreter registered; the verify-before-execute gate must have refused it"
            }
            if (Test-Path -LiteralPath $StubCanary) {
                Stop-Gate 'peruser_interpreter_refused' "the per-user stub interpreter was EXECUTED during the refused msiexec install (canary written); a non-admin-registered interpreter must never run as SYSTEM"
            }
            Add-Check 'peruser_install_refused' 'passed' "msiexec exited $($peruserProc.ExitCode) (nonzero) with only a per-user interpreter registered; the deferred verify action refused it (log: $peruserMsiLog)"
        }
    } finally {
        # Restore the machine EXACTLY as found, on every unwind (Stop-Gate's
        # `exit` included): registry keys/values, environment, canary.
        if ($HklmPythonMoved) {
            Rename-Item -LiteralPath (Join-Path (Split-Path $HklmPythonKey) $HklmPythonBackupName) -NewName '3.12' -ErrorAction SilentlyContinue
        }
        if ($StubHiveCreated) {
            Remove-Item -LiteralPath $StubHive -Recurse -Force -ErrorAction SilentlyContinue
        } elseif ($StubHiveExisted) {
            if ($null -ne $StubOrigExec) {
                New-ItemProperty -LiteralPath $StubHive -Name 'ExecutablePath' -Value $StubOrigExec -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $StubHive -Name 'ExecutablePath' -ErrorAction SilentlyContinue
            }
            if ($null -ne $StubOrigDefault) {
                Set-Item -LiteralPath $StubHive -Value $StubOrigDefault -ErrorAction SilentlyContinue
            }
        }
        if ($null -ne $SavedProcessUdbmcpPython) {
            $env:UDBMCP_PYTHON = $SavedProcessUdbmcpPython
        }
        Remove-Item -LiteralPath $StubCanary -Force -ErrorAction SilentlyContinue
    }
    # Restore sanity proof: the per-machine interpreter and the bundle are back
    # to as-found state and the trusted verifier still passes.
    $peruserRestoreResult = Invoke-TrustedVerifier -TargetBundle $BundleDir
    if ($peruserRestoreResult.ExitCode -eq 0 -and $peruserRestoreResult.Output -match 'bundle verification PASSED' -and $peruserRestoreResult.Output -notmatch '(?m)^FAIL:') {
        Add-Check 'peruser_cleanup_reverified' 'passed' "per-machine HKLM key and HKCU stub restored; trusted verifier PASSED again (the negative case left the machine as found)"
    } else {
        Stop-Gate 'peruser_cleanup_reverified' "after restoring the per-machine interpreter the trusted verifier did not pass (exit $($peruserRestoreResult.ExitCode)); inspect $HklmPythonKey (backup name: $HklmPythonBackupName) and reinstall the MSI"
    }

    # ------------------------------------------------------------------ done
    if ($script:Failed -eq 0) {
        Save-Evidence -Status 'passed' -InstallExitCode $script:InstallExitCode -MsiUsed $script:MsiUsed -MsiLog $script:MsiLog
        Write-Host "==> msi gate PASSED (evidence: $(Join-Path $EvidenceDir 'results.json'))"
        exit 0
    }
    Save-Evidence -Status 'failed' -InstallExitCode $script:InstallExitCode -MsiUsed $script:MsiUsed -MsiLog $script:MsiLog
    Write-Host "==> msi gate FAILED (evidence: $(Join-Path $EvidenceDir 'results.json'))"
    exit 1
} catch {
    # Any terminating error: record it and fail closed; evidence still written.
    $msg = $_.Exception.Message
    Add-Check 'unexpected_error' 'failed' $msg
    Save-Evidence -Status 'failed' -InstallExitCode $script:InstallExitCode -MsiUsed $script:MsiUsed -MsiLog $script:MsiLog
    Write-Host "==> msi gate FAILED (unexpected error; evidence: $(Join-Path $EvidenceDir 'results.json'))"
    exit 1
} finally {
    # Best-effort cleanup of the scratch dir on SUCCESS only: on failure it
    # still holds the pristine wheel backup (tamper case) and the demo
    # fixture needed for the post-mortem. Never masks the gate result.
    try {
        if ($script:Failed -eq 0 -and (Test-Path -LiteralPath $WorkDir)) {
            Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}
