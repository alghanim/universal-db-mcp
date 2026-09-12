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
#   Optional environment overrides (defaults below match the udbmcp.wxs
#   directory tree under ProgramFiles64Folder\UniversalDB MCP):
#     UDBMCP_BUNDLE_DIR  signed bundle directory (contains wheelhouse/,
#                        requirements/runtime.lock)
#     UDBMCP_VENV_DIR    virtual environment to create
#     UDBMCP_PYTHON      explicit CPython 3.12 python.exe (otherwise found via
#                        the PEP 514 registry or the py launcher)
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
    [string]$PythonExe
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

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine("FAIL: $Message")
    [Console]::Error.WriteLine("      The installation has been aborted; nothing was started.")
    exit 1
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
    # Locate a CPython 3.12 interpreter. Order: explicit override, PEP 514
    # registry (python.org install; HKLM per-machine preferred, HKCU
    # fallback), py launcher. Returns $null if nothing suitable is found.
    if ($PythonExe) {
        if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
            Fail "UDBMCP_PYTHON override is set but the interpreter does not exist: $PythonExe"
        }
        return $PythonExe
    }

    foreach ($hive in 'HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath',
                      'HKCU:\SOFTWARE\Python\PythonCore\3.12\InstallPath') {
        if (-not (Test-Path -LiteralPath $hive)) { continue }
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

    $launcher = Get-Command -Name 'py.exe' -ErrorAction SilentlyContinue
    if ($launcher) {
        # py.exe prints its "no Python 3.12 found" diagnostic on stderr -- the
        # exact case this fallback handles -- and Windows PowerShell 5.1 turns
        # that stderr into error records that a 'Stop' preference escalates
        # into a terminating NativeCommandError before the exit-code check
        # below (same hazard Invoke-Native guards against). Relax the
        # preference for this one invocation and decide solely on
        # $LASTEXITCODE: a missing 3.12 is the graceful not-found return, not
        # a crash.
        $previousEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $found = & $launcher.Source -3.12 -c 'import sys; print(sys.executable)' 2>$null
        $launcherExit = $LASTEXITCODE
        $ErrorActionPreference = $previousEap
        if ($launcherExit -eq 0 -and $found -and (Test-Path -LiteralPath $found.Trim() -PathType Leaf)) {
            return $found.Trim()
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
    $verExit = Invoke-Native -FilePath $py -ArgumentList @(
        '-c', 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)')
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
    # remove custom-action-created files) is removed so the result always
    # reflects exactly the freshly verified wheelhouse, never a stale mix.
    Write-Step "creating virtual environment at $VenvDir"
    if (Test-Path -LiteralPath $VenvDir -PathType Container) {
        Write-Detail 'removing stale venv from a previous install'
        Remove-Item -LiteralPath $VenvDir -Recurse -Force
    }
    # Native invocation: EAP is relaxed inside Invoke-Native and the exit code
    # alone decides (fail closed on nonzero, exactly as before).
    $venvExit = Invoke-Native -FilePath $py -ArgumentList @('-m', 'venv', $VenvDir)
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
    & $VenvPython -m pip --isolated --disable-pip-version-check install `
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

    Write-Step 'venv ready'
    Write-Detail "venv_python=$VenvPython"
    Write-Detail 'next: doctor smoke custom action (the first execution of payload code)'
    exit 0
}
catch {
    # $ErrorActionPreference = 'Stop' turns any cmdlet failure into a
    # terminating error; route it through the same structured FAIL channel.
    # Native-command stderr can no longer land here: every native invocation
    # above (Invoke-Native, the py-launcher probe, the pip install) relaxes
    # the preference for its own scope and decides solely on $LASTEXITCODE,
    # while the exit-code checks keep failing closed on every nonzero result.
    Fail ("unexpected error: " + $_.Exception.Message)
}
