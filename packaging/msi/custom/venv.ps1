# MSI deferred custom action: build the service virtual environment from the
# verified signed bundle's wheelhouse.
#
# Trust model (invariants that must never break):
#   1. NO bundle payload is executed by this script. It creates the venv with
#      the machine's CPython 3.12 and populates it with `pip install` from the
#      bundle wheelhouse only. Wheels are unpacked, never run (no setup.py is
#      ever executed: --only-binary=:all:), so the first execution of payload
#      code remains the doctor smoke custom action that is sequenced AFTER
#      this one. This action MUST be scheduled after the trusted
#      verify_bundle.py action has passed against the installed bundle with
#      the admin-provided release pubkey (see udbmcp.wxs); this script never
#      weakens that ordering, it only depends on it.
#   2. The release pubkey is NEVER shipped inside this package and is never
#      referenced here. Verification belongs to the dedicated custom action
#      reading the admin-distributed key; this script does no trust decisions
#      of its own and fails closed on every anomaly it can see (missing
#      wheelhouse, missing runtime.lock, wrong interpreter version, any
#      nonzero exit).
#   3. pip runs --no-index --require-hashes against the bundle wheelhouse
#      only, with the inherited (hostile) pip environment neutralized:
#      PIP_CONFIG_FILE points at the NUL device (the Windows equivalent of
#      the /dev/null used by scripts/install_offline.sh and the pkg
#      postinstall), proxy and index overrides are scrubbed, and --isolated
#      makes pip ignore ANY residual environment variables on top of the
#      explicit command-line flags (belt and suspenders, mirroring
#      install_offline.sh).
#   4. Every failure exits nonzero so the deferred custom action (Return="check")
#      aborts the install and triggers MSI rollback.
#
# Invocation contract (set up by udbmcp.wxs / test_package_msi.ps1):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<...>\venv.ps1"
#   [deferred, impersonate=no (runs as SYSTEM), Return="check"]
#   The same script is the rollback twin (RollbackBuildVenvCA, -Rollback,
#   Execute="rollback") and the commit action (CommitBuildVenvCA, -Commit,
#   Execute="commit", Return="ignore"); see "The previous venv" below.
#   Optional environment overrides (defaults below match the udbmcp.wxs
#   directory tree under ProgramFiles64Folder\UniversalDB MCP):
#     UDBMCP_BUNDLE_DIR  signed bundle directory (contains wheelhouse/,
#                        requirements/runtime.lock)
#     UDBMCP_VENV_DIR    virtual environment to create
#     UDBMCP_PYTHON      explicit CPython 3.12 python.exe (otherwise resolved
#                        from the PER-MACHINE PEP 514 registry value,
#                        HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath --
#                        never the HKCU hive or the py launcher, which a
#                        local non-admin can point at their own interpreter;
#                        see Find-Cpython312 below)
#
# The previous venv: a repair or upgrade finds the venv an earlier install
# built, and the service (and any MCP client a configure-agents registration
# started) may be running from it. It is never deleted in place: Windows
# refuses to delete a file a process has open or mapped, so a recursive
# delete failed part-way and left a gutted venv that no rollback restores
# (it is not an MSI file). Instead the service is stopped, the venv is
# moved aside whole to <venv>.previous-<id> (a move refuses a folder a
# process still runs from; the install then fails with the venv untouched),
# and the new one is built in its place. The marker <venv>.moved names the
# folder moved aside and whether the new venv is complete ("building",
# "built"). Until the install commits, that folder is kept: a failure in
# this action puts it back at once, and the rollback twin (RollbackBuildVenvCA,
# run when this or any later action fails) puts it back too. The commit
# action (CommitBuildVenvCA) removes it and the marker once the install has
# succeeded. A marker an interrupted install left is settled first, before
# anything here can fail: "building" puts its folder back (the venv in
# place is incomplete), "built" drops it (the venv in place is complete).
#
# Logging: this script has no UI; every message is a structured console write
# (stdout for progress, stderr for failures) that msiexec captures verbatim
# into the /l*v MSI log. Format mirrors the shell installers:
#     ==> venv[step N]: <step description>
#         <key=value detail lines>
#     FAIL: <reason>          (stderr, followed by exit 1)

param(
    [string]$BundleDir,
    [string]$VenvDir,
    [string]$PythonExe,
    # The service that runs from the venv: stopped before the venv is moved
    # aside (see "The previous venv" above).
    [string]$ServiceName = 'udbmcp',
    # The rollback twin: put back the venv this install moved aside.
    [switch]$Rollback,
    # The commit action: remove the venv this install moved aside.
    [switch]$Commit
)

$ErrorActionPreference = 'Stop'

$script:StepNumber = 0

function Write-Step {
    param([string]$Message)
    $script:StepNumber++
    [Console]::Out.WriteLine("==> venv[step $script:StepNumber]: $Message")
}

function Write-Detail {
    param([string]$Message)
    [Console]::Out.WriteLine("    $Message")
}

# Exit codes of sc.exe: ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE.
$script:ErrServiceAbsent = 1060
$script:ErrServiceNotActive = 1062
# The venv this run moved aside (full path), until the install is settled.
$script:Aside = $null

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine("FAIL: $Message")
    if ($script:Aside) {
        $aside = $script:Aside
        $script:Aside = $null
        Restore-PreviousVenv -Aside $aside
    }
    [Console]::Error.WriteLine("      The installation has been aborted; nothing was started.")
    exit 1
}

function Get-MarkerPath {
    return ($VenvDir + '.moved')
}

function Read-Marker {
    # The marker's folder (full path) and state, or $null when there is no
    # marker. A marker naming anything but a <venv>.previous-<id> folder
    # beside the venv is refused (fail closed: nothing is moved for it).
    $marker = Get-MarkerPath
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { return $null }
    $lines = @(Get-Content -LiteralPath $marker)
    $leaf = ''
    $state = ''
    if ($lines.Count -ge 1) { $leaf = [string]$lines[0] }
    if ($lines.Count -ge 2) { $state = [string]$lines[1] }
    $prefix = [regex]::Escape((Split-Path -Leaf $VenvDir) + '.previous-')
    if ($leaf -notmatch ('^' + $prefix + '[0-9a-f]{32}$')) {
        throw ("the marker '" + $marker + "' names '" + $leaf + "', not a venv this action moved aside; inspect it")
    }
    return [pscustomobject]@{ Path = (Join-Path (Split-Path -Parent $VenvDir) $leaf); State = $state }
}

function Write-Marker {
    param([string]$Aside, [string]$State)
    Set-Content -LiteralPath (Get-MarkerPath) -Value @((Split-Path -Leaf $Aside), $State) -Encoding ascii
}

function Remove-Marker {
    $marker = Get-MarkerPath
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
}

function Restore-PreviousVenv {
    # Puts the venv moved aside to $Aside back in place of whatever stands at
    # $VenvDir (the new venv, complete or not). The marker is set to
    # "building" first, so a restore that cannot finish leaves the moved
    # venv for the next install to put back, never to drop. Reports, never
    # throws: it runs on the way out of a failure.
    param([string]$Aside)
    try {
        if (-not (Test-Path -LiteralPath $Aside -PathType Container)) {
            [Console]::Error.WriteLine("      the previous venv '" + $Aside + "' is gone; nothing to put back")
            Remove-Marker
            return
        }
        Write-Marker -Aside $Aside -State 'building'
        if (Test-Path -LiteralPath $VenvDir) {
            Remove-Item -LiteralPath $VenvDir -Recurse -Force
        }
        Move-Item -LiteralPath $Aside -Destination $VenvDir
        Remove-Marker
        [Console]::Error.WriteLine("      the previous venv is back at '" + $VenvDir + "'")
    }
    catch {
        [Console]::Error.WriteLine("      could not put the previous venv '" + $Aside + "' back at '" + $VenvDir + "': " +
                                   $_.Exception.Message + "; the next install puts it back (marker " + (Get-MarkerPath) + ")")
    }
}

function Invoke-Tool {
    # Runs a tool with a fully controlled raw command line and returns the
    # exit code plus captured output (sc.exe output is small, so synchronous
    # ReadToEnd is safe).
    param([string]$Tool, [string]$Arguments)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Tool
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        return [pscustomobject]@{ ExitCode = $proc.ExitCode; StdOut = $stdout; StdErr = $stderr }
    }
    catch {
        Fail ("could not start '" + $Tool + "': " + $_.Exception.Message)
    }
}

function Stop-VenvService {
    # Stops the service $Name when it is registered and not stopped: it runs
    # from the venv about to be moved aside. Fails closed on anything it
    # cannot resolve, before the venv is touched.
    param([string]$Name)
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $r = Invoke-Tool -Tool $sc -Arguments ('query ' + $Name)
    if ($r.ExitCode -eq $script:ErrServiceAbsent) { return }
    if ($r.ExitCode -ne 0) {
        Fail ("sc.exe query " + $Name + " failed with exit code " + $r.ExitCode + "; the venv is unchanged")
    }
    if ($r.StdOut -match 'STOPPED') { return }
    Write-Detail ("stopping service '" + $Name + "' (it runs from this venv)")
    $r = Invoke-Tool -Tool $sc -Arguments ('stop ' + $Name)
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne $script:ErrServiceNotActive -and $r.ExitCode -ne $script:ErrServiceAbsent) {
        Fail ("sc.exe stop " + $Name + " failed with exit code " + $r.ExitCode + "; the venv is unchanged")
    }
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-Tool -Tool $sc -Arguments ('query ' + $Name)
        if ($r.ExitCode -eq $script:ErrServiceAbsent -or ($r.ExitCode -eq 0 -and $r.StdOut -match 'STOPPED')) { return }
        Start-Sleep -Seconds 1
    }
    Fail ("service '" + $Name + "' did not reach STOPPED within 60 seconds; the venv is unchanged")
}

function Resolve-InterruptedInstall {
    # Settles a marker an earlier install left (it was interrupted, or ran
    # with rollback disabled, so neither its twin nor its commit ran); see
    # "The previous venv" in the header. Runs before anything here can fail,
    # so the twin never finds that marker.
    $found = Read-Marker
    if (-not $found) { return }
    if ($found.State -eq 'building' -and (Test-Path -LiteralPath $found.Path -PathType Container)) {
        Write-Detail ("an interrupted install left an incomplete venv; putting back '" + $found.Path + "'")
        if (Test-Path -LiteralPath $VenvDir) { Remove-Item -LiteralPath $VenvDir -Recurse -Force }
        Move-Item -LiteralPath $found.Path -Destination $VenvDir
        Remove-Marker
        return
    }
    Remove-Marker
    if (Test-Path -LiteralPath $found.Path) {
        Write-Detail ("removing '" + $found.Path + "', which an earlier install moved aside")
        try {
            Remove-Item -LiteralPath $found.Path -Recurse -Force
        }
        catch {
            Write-Detail ("could not remove it (" + $_.Exception.Message + "); remove it once nothing runs from it")
        }
    }
}

function Get-EnvValue {
    # Strict-mode-safe environment lookup: a missing variable is $null.
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name)
}

function Invoke-Native {
    # Runs a native command and returns ONLY its exit code; the caller still
    # fails closed on every nonzero result, so $LASTEXITCODE remains the sole
    # decision input. The preference is relaxed around the invocation because
    # Windows PowerShell 5.1 turns native-command stderr output into error
    # records that a 'Stop' preference escalates into a terminating
    # NativeCommandError -- under msiexec the host's handles are redirected,
    # so ANY stderr line from the child (a pip warning, a python caveat) would
    # otherwise abort an otherwise-successful step via the catch block below.
    # stderr is merged into the echoed output so it still reaches the msiexec
    # /l*v log. Same guard as this action's siblings (verify.ps1, doctor.ps1)
    # apply around their native invocations.
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @ArgumentList 2>&1 | ForEach-Object { [Console]::Out.WriteLine("    $_") }
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
}

function Find-Cpython312 {
    # Locate the machine's PER-MACHINE CPython 3.12 interpreter. Order:
    # explicit override, then the PEP 514 registry -- HKLM ONLY. Returns $null
    # if nothing suitable is found (the caller fails closed).
    #
    # The HKCU hive and the py launcher are deliberately NOT consulted. Both
    # resolve to a per-user installation that a local NON-ADMIN can register
    # (Python's own preference order is per-user over per-machine), and this
    # script runs deferred with Impersonate=no (LocalSystem): a venv built
    # with attacker-controlled python would make the service interpreter
    # attacker-controlled. The udbmcp.wxs LaunchCondition enforces the same
    # HKLM hive (Installed OR CPYTHON312), so an HKCU-only machine fails
    # closed here with the per-machine bootstrap diagnostic instead of
    # silently building on a per-user interpreter.
    if ($PythonExe) {
        if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
            Fail "UDBMCP_PYTHON override is set but the interpreter does not exist: $PythonExe"
        }
        return $PythonExe
    }

    $hive = 'HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath'
    if (Test-Path -LiteralPath $hive) {
        $props = Get-ItemProperty -LiteralPath $hive
        # PEP 514: ExecutablePath when present, else the key's default value
        # (the install directory) + python.exe.
        $candidate = $props.ExecutablePath
        if (-not $candidate) {
            $installPath = $props.'(default)'
            if ($installPath) { $candidate = Join-Path $installPath 'python.exe' }
        }
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    return $null
}

try {
    # --- step 1: resolve and validate the inputs ------------------------------
    # Defaults mirror the udbmcp.wxs directory tree; the environment overrides
    # exist for the PowerShell gate script and tests, not to relocate trust.
    $installRoot = Join-Path $env:ProgramFiles 'UniversalDB MCP'
    if (-not $BundleDir) { $BundleDir = Get-EnvValue 'UDBMCP_BUNDLE_DIR' }
    if (-not $BundleDir) { $BundleDir = Join-Path $installRoot 'bundle' }
    if (-not $VenvDir)   { $VenvDir   = Get-EnvValue 'UDBMCP_VENV_DIR' }
    if (-not $VenvDir)   { $VenvDir   = Join-Path $installRoot 'venv' }
    if (-not $PythonExe) { $PythonExe = Get-EnvValue 'UDBMCP_PYTHON' }
    $Wheelhouse = Join-Path $BundleDir 'wheelhouse'
    $Lock       = Join-Path $BundleDir 'requirements\runtime.lock'

    # --- the rollback twin and the commit action (see the header) -------------
    # Neither builds anything, and neither fails: the install is being rolled
    # back, or it has committed.
    if ($Rollback) {
        try {
            $found = Read-Marker
            if (-not $found) {
                Write-Detail ('this install moved no venv aside: ' + $VenvDir + ' is left as it is')
            }
            else {
                Restore-PreviousVenv -Aside $found.Path
            }
        }
        catch {
            Write-Detail ('WARNING: ' + $_.Exception.Message)
        }
        exit 0
    }
    if ($Commit) {
        try {
            $found = Read-Marker
            if ($found) {
                Remove-Marker
                if (Test-Path -LiteralPath $found.Path) {
                    Remove-Item -LiteralPath $found.Path -Recurse -Force
                }
                Write-Detail ('the install committed: removed the previous venv ' + $found.Path)
            }
        }
        catch {
            Write-Detail ('WARNING: could not remove the previous venv (' + $_.Exception.Message +
                          '); remove it once nothing runs from it')
        }
        exit 0
    }
    Resolve-InterruptedInstall

    Write-Step 'resolving inputs'
    Write-Detail "bundle_dir=$BundleDir"
    Write-Detail "wheelhouse=$Wheelhouse"
    Write-Detail "runtime_lock=$Lock"
    Write-Detail "venv_dir=$VenvDir"

    # Fail closed on missing prerequisites. The presence checks below are NOT
    # the trust boundary (that is the verify_bundle.py custom action that ran
    # before this script); they catch a broken payload layout loudly here
    # instead of letting pip fail later with a confusing diagnostic.
    if (-not (Test-Path -LiteralPath (Join-Path $BundleDir 'manifest.json') -PathType Leaf)) {
        Fail "bundle payload missing or incomplete: no manifest.json at $BundleDir"
    }
    if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
        Fail "wheelhouse missing from the bundle at $Wheelhouse"
    }
    if (-not (Get-ChildItem -LiteralPath $Wheelhouse -Filter '*.whl' -File | Select-Object -First 1)) {
        Fail "wheelhouse at $Wheelhouse contains no wheels; the bundle is incomplete"
    }
    if (-not (Test-Path -LiteralPath $Lock -PathType Leaf)) {
        Fail "runtime.lock missing from the bundle at $Lock; refusing to resolve pins outside the signed lockfile"
    }

    # --- step 2: locate the machine's CPython 3.12 ----------------------------
    # The interpreter is an admin-provisioned machine prerequisite (same trust
    # position as python3 on the .deb); the udbmcp.wxs LaunchCondition already
    # gated on a per-machine python.org CPython 3.12. We re-assert the exact
    # minor version here because the wheelhouse is built for cp312.
    Write-Step 'locating CPython 3.12'
    $py = Find-Cpython312
    if (-not $py) {
        Fail 'CPython 3.12 not found; install python.org CPython 3.12 (64-bit, per-machine) and re-run the installer'
    }
    Write-Detail "python=$py"
    # Native invocation: EAP is relaxed inside Invoke-Native, so a stray
    # interpreter stderr line cannot escalate; the exit code alone decides.
    # -I, as for every LocalSystem python run of the MSI (here and in the
    # venv's pip below): no PYTHON* variables, no user site and no working
    # directory on sys.path.
    $verExit = Invoke-Native -FilePath $py -ArgumentList @(
        '-I', '-c', 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)')
    if ($verExit -ne 0) {
        Fail "CPython 3.12.x is required (the wheelhouse is built for cp312); found: $py"
    }

    # --- step 3: neutralize the inherited pip environment ---------------------
    # A curated pip.conf, an index override or proxy variables inherited from
    # the session must not be able to redirect these installs to a network
    # source. PIP_CONFIG_FILE=NUL is the Windows equivalent of the /dev/null
    # used by scripts/install_offline.sh and the pkg postinstall; --isolated
    # in step 5 additionally makes pip ignore any environment variable at all.
    Write-Step 'neutralizing inherited pip environment'
    foreach ($hostile in 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_PRE',
                         'http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY',
                         'ALL_PROXY', 'all_proxy') {
        if ($null -ne (Get-EnvValue $hostile)) {
            Remove-Item -Path "env:$hostile" -ErrorAction SilentlyContinue
            Write-Detail "removed=$hostile"
        }
    }
    $env:PIP_CONFIG_FILE = 'NUL'
    $env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
    $env:PIP_NO_INDEX = '1'
    $env:PIP_FIND_LINKS = $Wheelhouse
    Write-Detail 'PIP_CONFIG_FILE=NUL'
    Write-Detail 'PIP_NO_INDEX=1'
    Write-Detail "PIP_FIND_LINKS=$Wheelhouse"

    # --- step 4: (re)create the venv ------------------------------------------
    # A venv from a previous install (upgrade/re-install, where MSI does not
    # remove custom-action-created files) is replaced, so the result always
    # reflects exactly the freshly verified wheelhouse, never a stale mix. It
    # is moved aside whole, never deleted in place, and kept until the
    # install commits (see "The previous venv" in the header).
    Write-Step "creating virtual environment at $VenvDir"
    if (Test-Path -LiteralPath $VenvDir) {
        if (-not (Test-Path -LiteralPath $VenvDir -PathType Container)) {
            Fail "'$VenvDir' is not a directory; inspect it, then remove it and rerun the install"
        }
        Stop-VenvService -Name $ServiceName
        $aside = $VenvDir + '.previous-' + [guid]::NewGuid().ToString('N')
        Write-Detail "moving the previous venv aside to $aside (kept until the install commits)"
        try {
            Move-Item -LiteralPath $VenvDir -Destination $aside
        }
        catch {
            Fail ("could not move the previous venv '" + $VenvDir + "' aside (" + $_.Exception.Message + '): a process' +
                  ' still runs from it (an MCP client a configure-agents registration started, such as Claude' +
                  ' Desktop, or a shell). Close it and rerun the install; the venv is unchanged, and the service' +
                  " '" + $ServiceName + "', if registered, is stopped")
        }
        $script:Aside = $aside
        Write-Marker -Aside $aside -State 'building'
    }
    # Native invocation: EAP is relaxed inside Invoke-Native and the exit code
    # alone decides (fail closed on nonzero, exactly as before).
    $venvExit = Invoke-Native -FilePath $py -ArgumentList @('-I', '-m', 'venv', $VenvDir)
    if ($venvExit -ne 0) {
        Fail "could not create the virtual environment at $VenvDir (python -m venv exited $venvExit)"
    }
    $VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Fail "venv created but $VenvPython is missing; the environment is unusable"
    }

    # --- step 5: install the application from the bundle wheelhouse -----------
    # --no-index + --find-links make the verified wheelhouse the only source;
    # --require-hashes + -r runtime.lock make the shipped lockfile the only
    # acceptable resolution; --only-binary=:all: forbids any sdist (and thus
    # any setup.py execution) so payload code is still not being run here.
    # --isolated ignores user configuration and ALL environment variables, so
    # the flags below (not the ambient machine state) carry the policy.
    Write-Step 'installing application from bundle wheelhouse (no index, hashed)'
    # Native invocation with the preference relaxed inline (same reason as
    # Invoke-Native): pip writes warnings and retry notices to stderr, and
    # under msiexec the host's handles are redirected, so a 'Stop' preference
    # would escalate any stderr line into a terminating NativeCommandError
    # and abort an otherwise-successful install via the catch block. The
    # pip flags are unchanged: --no-index --require-hashes --find-links over
    # the wheelhouse only, --only-binary=:all:, pinned by the signed lock.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $VenvPython -I -m pip --isolated --disable-pip-version-check install `
        '--no-index' `
        '--no-cache-dir' `
        "--find-links=$Wheelhouse" `
        '--only-binary=:all:' `
        '--require-hashes' `
        '-r' $Lock
    $pipExit = $LASTEXITCODE
    $ErrorActionPreference = $previousEap
    if ($pipExit -ne 0) {
        Fail "wheelhouse install failed (pip exited $pipExit); install from the verified bundle did not complete"
    }

    # Complete: an interrupted install's marker now drops the venv moved
    # aside instead of putting it back. Until the install commits, the
    # rollback twin still puts it back.
    if ($script:Aside) {
        Write-Marker -Aside $script:Aside -State 'built'
        $script:Aside = $null
    }

    Write-Step 'venv ready'
    Write-Detail "venv_python=$VenvPython"
    Write-Detail 'next: doctor smoke custom action (the first execution of payload code)'
    exit 0
}
catch {
    # $ErrorActionPreference = 'Stop' turns any cmdlet failure into a
    # terminating error; route it through the same structured FAIL channel.
    # Native-command stderr can no longer land here: every native invocation
    # above (Invoke-Native for the interpreter check and venv create, the pip
    # install) relaxes
    # the preference for its own scope and decides solely on $LASTEXITCODE,
    # while the exit-code checks keep failing closed on every nonzero result.
    Fail ("unexpected error: " + $_.Exception.Message)
}
