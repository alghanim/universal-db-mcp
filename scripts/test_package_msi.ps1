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
#   3b. programdata_acl: C:\ProgramData\UniversalDB MCP and the HTTP bearer
#      token in it (the listener's only credential) are owned by SYSTEM or
#      Administrators and do not inherit C:\ProgramData's DACL, and neither
#      they nor any other entry below the folder grants access to anyone but
#      SYSTEM, Administrators and the installed service's account.
#   3c. token_squat_doctor + token_squat_refused: an http-token planted as a
#      non-admin would (owned by BUILTIN\Users, known value) is never
#      adopted. The installed doctor action (scripts\doctor.ps1, with the
#      real payload doctor) must remove it before the payload runs and exit
#      0; planted again, re-running the installed registration action
#      (scripts\service.ps1, under the account the install registered) must
#      exit 0 having regenerated it under a protected DACL. service.ps1
#      replaces every token it cannot trust and never refuses one, so any
#      failure fails this check.
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
#   7b. rollback_refused: the install recorded its release at
#      "C:\Program Files\UniversalDB MCP\manifest.json", and its commit
#      action left no rollback copy (manifest.json.previous) or marker
#      (manifest.json.kept) beside it (installed_manifest_recorded). With
#      that record temporarily claiming a newer release, the standalone
#      verify custom action MUST refuse the
#      installed bundle as an older release, and MUST pass the same bundle
#      with ALLOW_DOWNGRADE=1 (what msiexec UDBMCP_ALLOW_DOWNGRADE=1 passes);
#      the record is then restored.
#   8. peruser_interpreter_refused: a per-user CPython 3.12 (HKCU PEP 514)
#      whose interpreter is an attacker-controlled stub that prints
#      'bundle verification PASSED' and exits 0 is registered, and the
#      per-machine HKLM PythonCore\3.12 key is temporarily moved aside: BOTH
#      the standalone verify custom action AND a full msiexec install must
#      FAIL (the verifier refuses to run on anything but the per-machine
#      interpreter; the stub must never execute - proven by a canary file the
#      stub would write). The registry and environment are restored and the
#      trusted verifier must pass again afterwards.
#   9. folder_squat_refused: with the admin's C:\ProgramData\UniversalDB MCP
#      moved aside, a repair (REINSTALL=ALL, so CreateFolders runs as on a
#      first install) over a folder owned by BUILTIN\Users, and then over a
#      config.yaml owned by BUILTIN\Users, must FAIL at DoctorSmokeCA; the
#      folder is restored and the same repair must pass again.
#  10. launch_conditions: repairs passing UDBMCP_SERVICE_ACCOUNT with a double
#      quote or a trailing backslash, or UDBMCP_ALLOW_DOWNGRADE=yes, must fail
#      at LaunchConditions before any custom action runs; the same repair
#      passing UDBMCP_SERVICE_ACCOUNT from this elevated administrator must
#      pass (MSIUSEREALADMINDETECTION=1 still sets AdminUser for a real
#      administrator). A standard user's repair is not exercised.
#  11. repair_keeps_account: a repair naming NetworkService switches the
#      service to it; a repair WITHOUT UDBMCP_SERVICE_ACCOUNT (msiexec keeps
#      no property between runs) must keep NetworkService, and logs\ and the
#      token must still grant it access (the wxs reads the account the
#      service is registered under); a repair naming LocalSystem restores
#      the install. Runs only when the install registered LocalSystem.
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
    # machine-scope UDBMCP_RELEASE_PUBKEY, else the documented default path
    # C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem (admin-write-
    # only; a non-admin can pre-create folders under C:\ProgramData).
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
# Machine-wide config folder (udbmcp.wxs: CommonAppDataFolder\UniversalDB MCP)
# and the HTTP bearer token RegisterServiceCA provisions in it.
$ProgramDataDir = Join-Path $env:ProgramData 'UniversalDB MCP'
$TokenFile   = Join-Path $ProgramDataDir 'http-token'
$IcaclsExe   = Join-Path $env:SystemRoot 'System32\icacls.exe'

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

    # Why $Path is no place for a secret, or $null: the owner must be SYSTEM
    # or Administrators, the DACL must not inherit from C:\ProgramData, and
    # no ACE may allow a SID outside $AllowedSids (an allowlist, as in
    # service.ps1: a denylist of broad principals misses every other
    # account). -DaclOnly checks the ACEs alone, for the other entries below
    # the folder. Well-known SIDs, never localized account names.
    function Get-SecretAclProblem {
        param([string]$Path, [string[]]$AllowedSids, [switch]$DaclOnly)
        $acl = Get-Acl -LiteralPath $Path
        if (-not $DaclOnly) {
            $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($owner -ne 'S-1-5-18' -and $owner -ne 'S-1-5-32-544') {
                return "owner is $owner, not SYSTEM (S-1-5-18) or Administrators (S-1-5-32-544)"
            }
            if (-not $acl.AreAccessRulesProtected) {
                return 'the DACL still inherits from its parent (inheritance not disabled)'
            }
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $AllowedSids -notcontains $rule.IdentityReference.Value) {
                return "the DACL allows $($rule.IdentityReference.Value) $($rule.FileSystemRights)"
            }
        }
        return $null
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
    if (-not $PubKey) { $PubKey = Join-Path $MsiTrustDir 'keys\udbmcp-release.pub.pem' }
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

    # ----------------------------- 3b. ProgramData folder + bearer token ACLs
    # The config folder and the HTTP bearer token (the listener's only
    # credential) must be readable by SYSTEM, Administrators and the service
    # account only: C:\ProgramData's inheritable DACL gives BUILTIN\Users read
    # access and lets any local user create entries there. Every other entry
    # below the folder (config.yaml, the secrets it names, smoke\) is checked
    # too: the folder's DACL must have reached the entries already in it.
    # Checked BEFORE the service check so the result is recorded even where
    # the service cannot start.
    foreach ($secretPath in @($ProgramDataDir, $TokenFile)) {
        if (-not (Test-Path -LiteralPath $secretPath)) {
            Stop-Gate 'programdata_acl' "$secretPath not found; RegisterServiceCA provisions the bearer token during the install - inspect the msiexec log"
        }
    }
    # service.ps1 grants a dedicated service account read access; LocalSystem
    # is SYSTEM already.
    $SecretSids = @('S-1-5-18', 'S-1-5-32-544')
    $installedService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($installedService -and $installedService.StartName -and
        $installedService.StartName -notmatch '^(\.\\)?LocalSystem$|^NT AUTHORITY\\SYSTEM$') {
        $serviceAccount = $installedService.StartName
        if ($serviceAccount.StartsWith('.\')) { $serviceAccount = $env:COMPUTERNAME + $serviceAccount.Substring(1) }
        try {
            $SecretSids += (New-Object System.Security.Principal.NTAccount($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Stop-Gate 'programdata_acl' "cannot resolve the SID of the service account '$($installedService.StartName)': $($_.Exception.Message)"
        }
    }
    $aclProblem = Get-SecretAclProblem -Path $ProgramDataDir -AllowedSids $SecretSids
    if ($aclProblem) { Stop-Gate 'programdata_acl' "${ProgramDataDir}: $aclProblem" }
    $aclProblem = Get-SecretAclProblem -Path $TokenFile -AllowedSids $SecretSids
    if ($aclProblem) { Stop-Gate 'programdata_acl' "${TokenFile}: $aclProblem" }
    foreach ($entry in @(Get-ChildItem -LiteralPath $ProgramDataDir -Force -Recurse)) {
        $aclProblem = Get-SecretAclProblem -Path $entry.FullName -AllowedSids $SecretSids -DaclOnly
        if ($aclProblem) { Stop-Gate 'programdata_acl' "$($entry.FullName): $aclProblem" }
    }
    Add-Check 'programdata_acl' 'passed' "$ProgramDataDir and $TokenFile are owned by SYSTEM or Administrators and do not inherit; no entry below the folder grants access to anyone but $($SecretSids -join ', ')"

    # ----------------------- 3c. squatted bearer token (never adopted)
    # Any local user can create files under C:\ProgramData and choose their
    # content. Simulate one: plant http-token owned by BUILTIN\Users, with a
    # DACL granting it Full Control and a value the "attacker" knows.
    # First the installed doctor action (INSTALLFOLDER\scripts\doctor.ps1,
    # exactly what DoctorSmokeCA runs, with the real payload doctor, which
    # refuses such a token as fatal) must remove it before any payload runs
    # and exit 0 (token_squat_doctor): a refusal there rolled the install
    # back with the token's owner as the only lead, and an owner change
    # launders a planted value. Then the token is planted again and the
    # installed registration action (INSTALLFOLDER\scripts\service.ps1,
    # exactly what RegisterServiceCA runs) must regenerate it (new value,
    # protected DACL) and exit 0: it replaces every token it
    # cannot trust and never refuses one, so a nonzero exit fails the gate,
    # and so does adopting the planted value. The service is re-registered
    # stopped (check 4 starts it) under the account the install registered
    # (a dedicated account with a password needs UDBMCP_SERVICE_PASSWORD in
    # this gate's environment), and the previous token value is replaced,
    # not restored.
    # Runs payload (doctor, and the venv interpreter generates the token):
    # only after installed_bundle_verified passed.
    $ServiceScript = Join-Path $InstallRoot 'scripts\service.ps1'
    $DoctorScript = Join-Path $InstallRoot 'scripts\doctor.ps1'
    foreach ($installedScript in @($DoctorScript, $ServiceScript)) {
        if (-not (Test-Path -LiteralPath $installedScript -PathType Leaf)) {
            Stop-Gate 'token_squat_refused' "installed custom action script not found at $installedScript"
        }
    }
    $SquatValue = 'squatted-' + [System.Guid]::NewGuid().ToString('N')
    # Plants the token as a local user would (see above).
    $plantToken = {
        if (Test-Path -LiteralPath $TokenFile) { Remove-Item -LiteralPath $TokenFile -Force }
        [System.IO.File]::WriteAllText($TokenFile, $SquatValue)
        Invoke-Native { & $IcaclsExe $TokenFile /setowner *S-1-5-32-545 2>&1 } | Out-Null
        $setOwnerExit = $LASTEXITCODE
        Invoke-Native { & $IcaclsExe $TokenFile /inheritance:e /grant '*S-1-5-32-545:F' 2>&1 } | Out-Null
        $grantExit = $LASTEXITCODE
        $plantedOwner = (Get-Acl -LiteralPath $TokenFile).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($setOwnerExit -ne 0 -or $grantExit -ne 0 -or $plantedOwner -ne 'S-1-5-32-545') {
            Stop-Gate 'token_squat_refused' "could not plant the squatted token (icacls exit codes $setOwnerExit/$grantExit, owner $plantedOwner)"
        }
    }
    $ConfigYaml = Join-Path $ProgramDataDir 'config.yaml'
    $squatAccount = 'LocalSystem'
    if ($installedService -and $installedService.StartName) { $squatAccount = $installedService.StartName }
    try {
        & $plantToken
        $doctorLog = Join-Path $LogDir 'doctor-squatted-token.log'
        $bundleManifestPath = Join-Path $BundleDir 'manifest.json'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $DoctorScript -VenvDir $VenvDir -ConfigPath $ConfigYaml -BundleManifest $bundleManifestPath -ServiceAccount $squatAccount 1> $doctorLog 2>&1 } | Out-Null
        $doctorExit = $LASTEXITCODE
        $doctorOut = (Get-Content -LiteralPath $doctorLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $doctorOut) { $doctorOut = '' }
        if ($doctorExit -ne 0) {
            Stop-Gate 'token_squat_doctor' "doctor.ps1 exited $doctorExit over a planted token; it must remove a token RegisterServiceCA would replace before the payload doctor (which refuses it as fatal) runs (log: $doctorLog)"
        }
        if (Test-Path -LiteralPath $TokenFile) {
            Stop-Gate 'token_squat_doctor' "doctor.ps1 exited 0 but left the planted token at $TokenFile (log: $doctorLog)"
        }
        if ($doctorOut -notmatch [regex]::Escape("'$TokenFile' is owned by S-1-5-32-545") -or $doctorOut -notmatch 'removing it before doctor runs') {
            Stop-Gate 'token_squat_doctor' "doctor.ps1 removed the planted token without naming it and why (expected '$TokenFile' is owned by S-1-5-32-545 ... removing it before doctor runs; log: $doctorLog)"
        }
        Add-Check 'token_squat_doctor' 'passed' "doctor.ps1 (account $squatAccount) removed the planted token (owned by BUILTIN\Users) before the payload doctor ran, and the payload doctor passed (log: $doctorLog)"

        & $plantToken
        $squatLog = Join-Path $LogDir 'service-squatted-token.log'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ServiceScript -VenvDir $VenvDir -ConfigPath $ConfigYaml -ServiceName $ServiceName -ServiceAccount $squatAccount 1> $squatLog 2>&1 } | Out-Null
        $squatExit = $LASTEXITCODE
        $squatOut = (Get-Content -LiteralPath $squatLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $squatOut) { $squatOut = '' }
        $afterSquat = (Get-Content -LiteralPath $TokenFile -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $afterSquat) { $afterSquat = '' }

        if ($squatExit -ne 0) {
            Stop-Gate 'token_squat_refused' "service.ps1 exited $squatExit over a planted token it must replace (it regenerates any token it cannot trust and never refuses one); the service is not registered until the MSI is repaired (log: $squatLog)"
        }
        if ($afterSquat.Trim() -eq $SquatValue) {
            Stop-Gate 'token_squat_refused' "service.ps1 exited 0 and KEPT the planted token (owned by BUILTIN\Users, value known to its planter); a squatted credential must never be adopted (log: $squatLog)"
        }
        if (-not $afterSquat.Trim()) {
            Stop-Gate 'token_squat_refused' "service.ps1 exited 0 but left an empty token at $TokenFile (log: $squatLog)"
        }
        $aclProblem = Get-SecretAclProblem -Path $TokenFile -AllowedSids $SecretSids
        if ($aclProblem) {
            Stop-Gate 'token_squat_refused' "the regenerated token is not protected: $aclProblem (log: $squatLog)"
        }
        if ($squatOut -notmatch [regex]::Escape("'$TokenFile' is owned by S-1-5-32-545") -or $squatOut -notmatch 'regenerating it') {
            Stop-Gate 'token_squat_refused' "service.ps1 replaced the planted token without naming it and why (expected '$TokenFile' is owned by S-1-5-32-545 ... regenerating it; log: $squatLog)"
        }
        Add-Check 'token_squat_refused' 'passed' "service.ps1 (account $squatAccount) replaced the planted token (owned by BUILTIN\Users) with a new value under a protected DACL (log: $squatLog)"
    } finally {
        # Never leave the planted token (a known value) behind, Stop-Gate's
        # exit included; the next registration run provisions a new one.
        $leftover = (Get-Content -LiteralPath $TokenFile -Raw -ErrorAction SilentlyContinue)
        if ($leftover -and $leftover.Trim() -eq $SquatValue) {
            Remove-Item -LiteralPath $TokenFile -Force -ErrorAction SilentlyContinue
        }
    }

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
        Stop-Gate 'doctor_smoke' "doctor exited ${LASTEXITCODE}: $err"
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
        Stop-Gate 'stdio_protocol_probe' "protocol probe exited ${LASTEXITCODE}: $err"
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

    # ----------------------------- 7b. anti-rollback (older release refused)
    # RegisterServiceCA records the installed release at C:\Program Files\
    # UniversalDB MCP\manifest.json (whatever INSTALLFOLDER is), and the
    # verify action hands that record (INSTALLED_MANIFEST in its
    # CustomActionData) to the trusted verifier, which refuses an OLDER
    # release unless the msiexec run sets UDBMCP_ALLOW_DOWNGRADE=1
    # (ALLOW_DOWNGRADE=1, the last key). No older MSI is needed to prove it:
    # the record is replaced, for the two runs below only, by the installed
    # manifest with a higher release_seq, and restored byte for byte on every
    # unwind.
    $InstalledManifest = Join-Path $env:ProgramFiles 'UniversalDB MCP\manifest.json'
    if (-not (Test-Path -LiteralPath $InstalledManifest -PathType Leaf)) {
        Stop-Gate 'installed_manifest_recorded' "$InstalledManifest not found; RegisterServiceCA records the installed release there as its last step - inspect the msiexec log"
    }
    $RecordBytes = [System.IO.File]::ReadAllBytes($InstalledManifest)
    $bundleManifestBytes = [System.IO.File]::ReadAllBytes((Join-Path $BundleDir 'manifest.json'))
    if ([Convert]::ToBase64String($RecordBytes) -ne [Convert]::ToBase64String($bundleManifestBytes)) {
        Stop-Gate 'installed_manifest_recorded' "$InstalledManifest differs from the installed bundle's manifest.json; the record must be the release that is installed"
    }
    # The commit action (CommitReleaseRecordCA) removed the record's rollback
    # copy and marker: a copy left behind is one a later failed install's
    # rollback could otherwise have restored.
    foreach ($leftover in @(($InstalledManifest + '.previous'), ($InstalledManifest + '.kept'))) {
        if (Test-Path -LiteralPath $leftover) {
            Stop-Gate 'installed_manifest_recorded' "$leftover is still there after the install; the commit action (CommitReleaseRecordCA) removes it - inspect the msiexec log"
        }
    }
    Add-Check 'installed_manifest_recorded' 'passed' "the installed release is recorded at $InstalledManifest, with no rollback copy left beside it"

    $newer = [System.Text.Encoding]::UTF8.GetString($bundleManifestBytes) | ConvertFrom-Json
    $newerSeq = 1
    if ($newer.release_seq -is [int] -or $newer.release_seq -is [long]) { $newerSeq = [long]$newer.release_seq + 1 }
    $newer | Add-Member -NotePropertyName 'release_seq' -NotePropertyValue $newerSeq -Force
    $rollbackCad = 'BUNDLE_DIR={0};TRUST_DIR={1};PUBKEY={2};PYTHON={3};INSTALLED_MANIFEST={4}' -f $BundleDir, $TrustDir, $PubKeyUsed, $script:Py, $InstalledManifest
    try {
        [System.IO.File]::WriteAllText($InstalledManifest, ($newer | ConvertTo-Json -Depth 32))

        $rollbackLog = Join-Path $LogDir 'verify-older-release.log'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CustomActionData $rollbackCad 1> $rollbackLog 2>&1 } | Out-Null
        $rollbackExit = $LASTEXITCODE
        $rollbackOut = (Get-Content -LiteralPath $rollbackLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $rollbackOut) { $rollbackOut = '' }
        if ($rollbackExit -eq 0 -or $rollbackOut -notmatch 'FAIL: rollback refused') {
            Stop-Gate 'rollback_refused' "with the installed release recorded as release_seq $newerSeq, the verify custom action exited $rollbackExit without 'FAIL: rollback refused'; an older release must be refused (log: $rollbackLog)"
        }

        $downgradeLog = Join-Path $LogDir 'verify-allowed-downgrade.log'
        $downgradeCad = $rollbackCad + ';ALLOW_DOWNGRADE=1'
        Invoke-Native { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CustomActionData $downgradeCad 1> $downgradeLog 2>&1 } | Out-Null
        $downgradeExit = $LASTEXITCODE
        $downgradeOut = (Get-Content -LiteralPath $downgradeLog -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $downgradeOut) { $downgradeOut = '' }
        if ($downgradeExit -ne 0 -or $downgradeOut -notmatch 'DOWNGRADE allowed') {
            Stop-Gate 'rollback_refused' "the verify custom action with ALLOW_DOWNGRADE=1 exited $downgradeExit without the verifier's 'DOWNGRADE allowed' warning; the explicit override must work (log: $downgradeLog)"
        }
        Add-Check 'rollback_refused' 'passed' "an older release than the recorded one was refused (log: $rollbackLog) and accepted with ALLOW_DOWNGRADE=1 (log: $downgradeLog)"
    } finally {
        # The real record, byte for byte, on every unwind (Stop-Gate's exit included).
        [System.IO.File]::WriteAllBytes($InstalledManifest, $RecordBytes)
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

    # ------------------- 9. squatted config folder / config (never adopted)
    # Any local user can create C:\ProgramData\UniversalDB MCP before the
    # first install, own it, and leave a config.yaml in it that names files
    # LocalSystem then reads and writes (token file, audit log, databases);
    # NeverOverwrite keeps such a config. The MSI's folder DACL names no
    # owner, so CreateFolders leaves a squatted folder owned by its creator,
    # and DoctorSmokeCA refuses a folder or config.yaml that SYSTEM or
    # Administrators do not own. Exercised the way a first install meets it:
    # REINSTALL=ALL reinstalls every component, so CreateFolders applies the
    # folder permission again. The admin's folder is moved aside (never
    # uninstalled: uninstall deletes config.yaml) and a planted one owned by
    # BUILTIN\Users takes its place:
    #   folder - the folder itself (msiexec installs config.yaml into it);
    #   config - config.yaml only (the shipped template, so its owner is the
    #            only thing wrong with it).
    # Each install must FAIL at DoctorSmokeCA, the first action that reads
    # the folder. The planted folder is then removed, the admin's folder
    # restored, and the same repair must pass, proving the squat was the
    # only cause.
    if ($SkipMsiInstall) {
        Add-Check 'folder_squat_refused' 'passed' 'skipped (-SkipMsiInstall); needs msiexec runs against the MSI'
    } else {
        # A running service can hold the venv and files in the folder open.
        (Invoke-Native { & $scExe stop $ServiceName 2>&1 }) | Out-Null
        for ($i = 0; $i -lt 30; $i++) {
            $stateLine = ((Invoke-Native { & $scExe query $ServiceName 2>&1 }) | ForEach-Object { "$_" } |
                Where-Object { $_ -match '^\s*STATE' } | Select-Object -First 1)
            if (-not $stateLine -or $stateLine -match 'STOPPED') { break }
            Start-Sleep -Seconds 2
        }
        $SquatBackup = $ProgramDataDir + '.gate-backup'
        $SquatBackupName = Split-Path -Leaf $SquatBackup
        $ProgramDataName = Split-Path -Leaf $ProgramDataDir
        if (Test-Path -LiteralPath $SquatBackup) {
            Stop-Gate 'folder_squat_refused' "$SquatBackup already exists (an interrupted gate run?); restore it to $ProgramDataDir or remove it, then rerun the gate"
        }
        $SquatTemplate = Join-Path $BundleDir 'config-templates\config.template.yaml'
        $SquatMoved = $false
        $squatLogs = @()
        try {
            Rename-Item -LiteralPath $ProgramDataDir -NewName $SquatBackupName
            $SquatMoved = $true
            foreach ($squat in @('folder', 'config')) {
                New-Item -ItemType Directory -Path $ProgramDataDir | Out-Null
                $squatTarget = $ProgramDataDir
                if ($squat -eq 'config') {
                    $squatTarget = Join-Path $ProgramDataDir 'config.yaml'
                    Copy-Item -LiteralPath $SquatTemplate -Destination $squatTarget
                    Invoke-Native { & $IcaclsExe $ProgramDataDir /setowner *S-1-5-32-544 2>&1 } | Out-Null
                }
                Invoke-Native { & $IcaclsExe $squatTarget /setowner *S-1-5-32-545 2>&1 } | Out-Null
                $plantedOwner = (Get-Acl -LiteralPath $squatTarget).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                if ($plantedOwner -ne 'S-1-5-32-545') {
                    Stop-Gate 'folder_squat_refused' "could not plant the squatted $squat ($squatTarget is owned by $plantedOwner)"
                }
                $squatMsiLog = Join-Path $LogDir "msi-install-squatted-$squat.log"
                $squatLogs += $squatMsiLog
                $squatArgStr = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus /qn /norestart /l*v `"$squatMsiLog`""
                $squatProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $squatArgStr -Wait -PassThru
                if ($squatProc.ExitCode -eq 0 -or $squatProc.ExitCode -eq 3010) {
                    Stop-Gate 'folder_squat_refused' "msiexec exited $($squatProc.ExitCode) with the $squat owned by BUILTIN\Users ($squatTarget): the install adopted a squatted config (log: $squatMsiLog)"
                }
                $squatMsiText = (Get-Content -LiteralPath $squatMsiLog -Raw -ErrorAction SilentlyContinue)
                # A failing exe custom action is logged as "CustomAction <Id>
                # returned actual error code <n>" and in Error 1722 as
                # "Action <Id>, location: ...".
                if ($squatMsiText -notmatch 'CustomAction DoctorSmokeCA returned actual error code|Action DoctorSmokeCA, location:') {
                    Stop-Gate 'folder_squat_refused' "msiexec exited $($squatProc.ExitCode) with the $squat owned by BUILTIN\Users, but not at DoctorSmokeCA, the first action that reads the folder: the refusal is unproven (log: $squatMsiLog)"
                }
                Remove-Item -LiteralPath $ProgramDataDir -Recurse -Force
            }
        } finally {
            # Never leave a planted folder behind, and put the admin's folder
            # back, on every unwind (Stop-Gate's exit included).
            if ($SquatMoved) {
                if (Test-Path -LiteralPath $ProgramDataDir) {
                    Remove-Item -LiteralPath $ProgramDataDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                if (-not (Test-Path -LiteralPath $ProgramDataDir)) {
                    Rename-Item -LiteralPath $SquatBackup -NewName $ProgramDataName -ErrorAction SilentlyContinue
                }
            }
        }
        Add-Check 'folder_squat_refused' 'passed' "msiexec REINSTALL=ALL failed at DoctorSmokeCA with the config folder, and then config.yaml alone, owned by BUILTIN\Users; neither was adopted (logs: $($squatLogs -join ', '))"

        if (Test-Path -LiteralPath $SquatBackup) {
            Stop-Gate 'folder_squat_cleanup_reinstalled' "could not restore $ProgramDataDir from $SquatBackup; move it back by hand"
        }
        # The same repair on the restored folder must pass. It re-registers
        # the service stopped, as check 3c does.
        $restoreMsiLog = Join-Path $LogDir 'msi-install-squat-restored.log'
        $restoreArgStr = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus /qn /norestart /l*v `"$restoreMsiLog`""
        $restoreProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $restoreArgStr -Wait -PassThru
        if ($restoreProc.ExitCode -ne 0 -and $restoreProc.ExitCode -ne 3010) {
            Stop-Gate 'folder_squat_cleanup_reinstalled' "msiexec REINSTALL=ALL exited $($restoreProc.ExitCode) on the restored $ProgramDataDir, so the squat negative above is inconclusive; repair the install (log: $restoreMsiLog)"
        }
        Add-Check 'folder_squat_cleanup_reinstalled' 'passed' "admin's $ProgramDataDir restored; the same msiexec REINSTALL=ALL exited $($restoreProc.ExitCode) (the squat was the only cause; log: $restoreMsiLog)"
    }

    # ------------------------------ 10. launch conditions (who passes what)
    # UDBMCP_SERVICE_ACCOUNT and UDBMCP_ALLOW_DOWNGRADE reach the SYSTEM
    # custom actions, so udbmcp.wxs takes them from an administrator only
    # (MSIUSEREALADMINDETECTION=1 and AdminUser) and refuses an account that
    # would break out of its quotes on the custom actions' command lines.
    # Each repair below must fail at LaunchConditions: the Launch message in
    # the log and no custom action run. The same repair passing
    # UDBMCP_SERVICE_ACCOUNT from this elevated administrator must pass
    # (AdminUser is set for a real administrator); it runs only when the
    # install registered LocalSystem, so no account changes. A standard
    # user's repair is not exercised (it needs a second, non-admin account).
    if ($SkipMsiInstall) {
        Add-Check 'launch_conditions' 'passed' 'skipped (-SkipMsiInstall); needs msiexec runs against the MSI'
    } else {
        $accountMessage = 'UDBMCP_SERVICE_ACCOUNT may not contain a double quote or end with a backslash.'
        # msiexec's own quoting: "" is a literal quote inside a quoted value
        $LaunchCases = @(
            @{ Name = 'account-quote'; Property = 'UDBMCP_SERVICE_ACCOUNT="x"" -ServiceName ""evil"'; Message = $accountMessage },
            @{ Name = 'account-backslash'; Property = 'UDBMCP_SERVICE_ACCOUNT=CORP\'; Message = $accountMessage },
            @{ Name = 'downgrade-value'; Property = 'UDBMCP_ALLOW_DOWNGRADE=yes'; Message = 'UDBMCP_ALLOW_DOWNGRADE may only be 1' }
        )
        $launchLogs = @()
        foreach ($case in $LaunchCases) {
            $launchLog = Join-Path $LogDir ('msi-launch-' + $case.Name + '.log')
            $launchLogs += $launchLog
            $launchArgStr = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus " + $case.Property + " /qn /norestart /l*v `"$launchLog`""
            $launchProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $launchArgStr -Wait -PassThru
            $launchText = (Get-Content -LiteralPath $launchLog -Raw -ErrorAction SilentlyContinue)
            if ($null -eq $launchText) { $launchText = '' }
            if ($launchProc.ExitCode -eq 0 -or $launchProc.ExitCode -eq 3010) {
                Stop-Gate 'launch_conditions' "msiexec exited $($launchProc.ExitCode) with $($case.Property): the Launch condition did not refuse it (log: $launchLog)"
            }
            if ($launchText -notmatch [regex]::Escape($case.Message)) {
                Stop-Gate 'launch_conditions' "msiexec exited $($launchProc.ExitCode) with $($case.Property), but not with the Launch message '$($case.Message)' (log: $launchLog)"
            }
            if ($launchText -match 'VerifyBundleCA') {
                Stop-Gate 'launch_conditions' "msiexec refused $($case.Property) only after a custom action ran (log: $launchLog)"
            }
        }
        $adminDetail = 'not run: the install registered a dedicated account (a repair would need its password)'
        if (-not $installedService -or $installedService.StartName -match '^(\.\\)?LocalSystem$') {
            $adminLog = Join-Path $LogDir 'msi-launch-admin-account.log'
            $adminArgStr = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus UDBMCP_SERVICE_ACCOUNT=LocalSystem /qn /norestart /l*v `"$adminLog`""
            $adminProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $adminArgStr -Wait -PassThru
            if ($adminProc.ExitCode -ne 0 -and $adminProc.ExitCode -ne 3010) {
                Stop-Gate 'launch_conditions' "msiexec exited $($adminProc.ExitCode) with UDBMCP_SERVICE_ACCOUNT=LocalSystem from this elevated administrator: AdminUser is not set for a real administrator (log: $adminLog)"
            }
            $adminDetail = "an elevated administrator's UDBMCP_SERVICE_ACCOUNT=LocalSystem passed (log: $adminLog)"
        }
        Add-Check 'launch_conditions' 'passed' "a quote or trailing backslash in UDBMCP_SERVICE_ACCOUNT and UDBMCP_ALLOW_DOWNGRADE=yes were refused at LaunchConditions, before any custom action (logs: $($launchLogs -join ', ')); $adminDetail"
    }

    # ------------------ 11. a repair keeps the registered service account
    # msiexec keeps no property between runs: a repair or upgrade that does
    # not pass UDBMCP_SERVICE_ACCOUNT again gets the account the service is
    # registered under (the wxs reads the service key's ObjectName before
    # anything runs), where it used to fall back to LocalSystem and take the
    # running service's token and its Modify on logs\ away. A repair naming
    # NetworkService (no password to carry over) switches the service to
    # it; a repair without the property must keep NetworkService, and logs\
    # and the token must still grant it access. A repair naming LocalSystem
    # then restores the install, and runs in finally if anything before it
    # failed. Runs only when the install registered LocalSystem: a dedicated
    # account would need its password.
    if ($SkipMsiInstall) {
        Add-Check 'repair_keeps_account' 'passed' 'skipped (-SkipMsiInstall); needs msiexec runs against the MSI'
    } elseif ($installedService -and $installedService.StartName -notmatch '^(\.\\)?LocalSystem$') {
        Add-Check 'repair_keeps_account' 'passed' "not run: the install registered $($installedService.StartName) (a repair would need its password)"
    } else {
        $keepSteps = @(
            @{ Name = 'networkservice'; Property = 'UDBMCP_SERVICE_ACCOUNT="NT AUTHORITY\NetworkService"'; Expect = '^NT AUTHORITY\\Network ?Service$' },
            @{ Name = 'unnamed'; Property = ''; Expect = '^NT AUTHORITY\\Network ?Service$' },
            @{ Name = 'localsystem'; Property = 'UDBMCP_SERVICE_ACCOUNT=LocalSystem'; Expect = '^(\.\\)?LocalSystem$' }
        )
        $keepLogs = @()
        $keepRestored = $false
        try {
            foreach ($step in $keepSteps) {
                $keepLog = Join-Path $LogDir ('msi-repair-account-' + $step.Name + '.log')
                $keepLogs += $keepLog
                $keepArgStr = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus " + $step.Property + " /qn /norestart /l*v `"$keepLog`""
                $keepProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $keepArgStr -Wait -PassThru
                if ($keepProc.ExitCode -ne 0 -and $keepProc.ExitCode -ne 3010) {
                    Stop-Gate 'repair_keeps_account' "msiexec REINSTALL=ALL $($step.Property) exited $($keepProc.ExitCode) (log: $keepLog)"
                }
                $keepRestored = ($step.Name -eq 'localsystem')
                $startName = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").StartName
                if ($startName -notmatch $step.Expect) {
                    Stop-Gate 'repair_keeps_account' "after msiexec REINSTALL=ALL $($step.Property) the service runs as '$startName' (log: $keepLog)"
                }
                if ($step.Name -eq 'unnamed') {
                    # NetworkService kept its Modify on logs\ and its read
                    # access to the token.
                    foreach ($kept in @((Join-Path $ProgramDataDir 'logs'), $TokenFile)) {
                        $grants = @((Get-Acl -LiteralPath $kept).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                            Where-Object { $_.IdentityReference.Value -eq 'S-1-5-20' })
                        if ($grants.Count -eq 0) {
                            Stop-Gate 'repair_keeps_account' "a repair without UDBMCP_SERVICE_ACCOUNT kept NetworkService, but $kept no longer grants it access (log: $keepLog)"
                        }
                    }
                }
            }
        } finally {
            # Never leave the service switched to NetworkService, Stop-Gate's
            # exit included.
            if (-not $keepRestored) {
                $keepRestoreLog = Join-Path $LogDir 'msi-repair-account-restore.log'
                $keepRestoreArgs = "/i `"$MsiPath`" REINSTALL=ALL REINSTALLMODE=omus UDBMCP_SERVICE_ACCOUNT=LocalSystem /qn /norestart /l*v `"$keepRestoreLog`""
                Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $keepRestoreArgs -Wait | Out-Null
            }
        }
        Add-Check 'repair_keeps_account' 'passed' "a repair without UDBMCP_SERVICE_ACCOUNT kept NetworkService, its Modify on logs\ and its read access to the token; a repair naming LocalSystem restored the install (logs: $($keepLogs -join ', '))"
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
