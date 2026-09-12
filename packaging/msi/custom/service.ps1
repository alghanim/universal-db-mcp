#
# UniversalDB MCP - MSI deferred custom action: service registration.
#
# Contract (wired by scripts/package/build_msi.sh; see packaging/msi/udbmcp.wxs):
#   Deferred custom action, Impersonate="no", Return="check", e.g.:
#     powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
#       "[INSTALLFOLDER]scripts\service.ps1"
#       -VenvDir "[INSTALLFOLDER]venv"
#       -ConfigPath "[ProgramDataUdbmcpDir]config.yaml"
#       -ServiceAccount "[UDBMCP_SERVICE_ACCOUNT]"
#   Exit code 0 = continue; any nonzero exit fails the action and WiX rolls
#   back the entire install (any service created here is best-effort removed
#   first, because sc.exe is not transactional).
#
# TRUST MODEL - DO NOT BREAK:
#   * This action registers the payload interpreter as a Windows service. It
#     must be scheduled strictly AFTER the trusted-channel verify_bundle.py
#     custom action has passed and AFTER the venv-build and doctor custom
#     actions have succeeded. A package that registers unverified payload as
#     an auto-start service would violate the project's first trust
#     invariant.
#   * The release public key is NEVER shipped inside the package; nothing in
#     this script reads, writes or embeds key material.
#   * No pip, no downloads: this script only configures the service control
#     manager. Wheel installation is exclusively the venv-build action
#     (--no-index --require-hashes with PIP_CONFIG_FILE neutralized).
#
# Service shape (mirrors packaging/systemd/universal-db-mcp.service):
#   sc.exe create udbmcp binPath= "<venv>\Scripts\python.exe" -m universal_db_mcp serve start= auto
#   sc.exe failure udbmcp reset= 86400 actions= restart/60000
# When a dedicated account is configured, its password is written through the
# Service Control Manager API (Win32_Service.Change), NEVER as a command-line
# token: the OS records command lines in durable audit logs (Event 4688 with
# include-command-line / Sysmon EID 1). LocalSystem needs no password.
# The service reads its configuration from the UDBMCP_CONFIG environment
# value written under HKLM\SYSTEM\CurrentControlSet\Services\<name>\
# Environment (services.exe injects it into the process), so the binPath
# stays exactly the interpreter plus "serve".
#
# Idempotency: on upgrade the previous service is stopped and deleted before
# the new one is created (delete-then-create). On a fresh install the query
# reports the service absent and creation proceeds directly.
#
# Parameters may also be supplied via environment variables for manual runs
# from the delivered gate script (scripts/test_package_msi.ps1):
#   UDBMCP_VENV_DIR, UDBMCP_CONFIG, UDBMCP_SERVICE_NAME,
#   UDBMCP_SERVICE_ACCOUNT (default LocalSystem), UDBMCP_SERVICE_PASSWORD
#
[CmdletBinding()]
param(
    [string]$VenvDir,
    [string]$ConfigPath,
    # Defaults for the direct msiexec wiring (udbmcp.wxs passes an explicit
    # -ServiceAccount); manual runs may override them via the environment
    # variables documented in the header by passing empty strings.
    [string]$ServiceName = 'udbmcp',
    [string]$ServiceAccount = 'LocalSystem',
    [string]$ServicePassword = ''
)

$ErrorActionPreference = 'Stop'

$script:ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
$script:RegExe = Join-Path $env:SystemRoot 'System32\reg.exe'

# sc.exe / reg.exe exit codes: ERROR_SERVICE_DOES_NOT_EXIST,
# ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_MARKED_FOR_DELETE.
$script:ErrServiceAbsent = 1060
$script:ErrServiceNotActive = 1062
$script:ErrServiceMarkedForDelete = 1072

$script:Created = $false

function Fail {
    # Hard exit for failures BEFORE the service is created: nothing to clean
    # up, and "exit" deliberately bypasses catch blocks.
    param([string]$Message)
    Write-Output ("SERVICE-ACTION FAILED: " + $Message)
    exit 1
}

function Abort {
    # Failure AFTER the service was created: throws so the outer catch can
    # remove the half-configured service before exiting nonzero.
    param([string]$Message)
    throw $Message
}

function ConvertTo-ScArgument {
    # Escapes a value for embedding between the double quotes the caller
    # appends, with full CommandLineToArgvW semantics:
    #   * A run of n backslashes immediately followed by a double quote is an
    #     escape sequence: it must be emitted as 2n+1 backslashes followed by
    #     \" so the quote stays a literal character. Escaping only the quote
    #     (" -> \") is wrong: the backslashes in front of it then escape the
    #     escape and the quote toggles/consumes the argument state.
    #   * A trailing run of n backslashes sits immediately before the closing
    #     quote the caller appends, so it must be emitted as 2n backslashes.
    #     With an odd count the last backslash escapes the closing quote: the
    #     argument never terminates and silently swallows the tokens that
    #     follow (a service password ending in '\' is stored wrongly by the
    #     SCM with exit 0; a trailing-'\' account absorbs 'start= auto').
    param([string]$Value)
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    return ($escaped -replace '(\\+)$', '$1$1')
}

function Invoke-Tool {
    # Runs a tool with a fully controlled raw command line (avoids Windows
    # PowerShell 5.1's native argument-quoting quirks) and returns the exit
    # code plus captured output. Tool output is small (sc.exe / reg.exe
    # status lines), so synchronous ReadToEnd is safe.
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

function Write-ToolOutput {
    # Echoes tool output into the MSI log. Never logs the command line:
    # a service password may be part of it.
    param($Result)
    if ($Result.StdOut) {
        $Result.StdOut.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Output ("    " + $_) }
    }
    if ($Result.StdErr) {
        $Result.StdErr.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Output ("    [stderr] " + $_) }
    }
}

function Set-ServiceLogonCredential {
    # Writes the service account + password through the Service Control
    # Manager API (Win32_Service.Change -> ChangeServiceConfig, out of
    # process via the WMI/CIM RPC channel). The credential therefore never
    # appears on any process command line: the OS records command lines into
    # durable audit logs (Event 4688 with include-command-line, Sysmon
    # EID 1) that no Write-Output discipline in this script can suppress.
    # Fails closed: a missing service or a nonzero provider return value
    # throws into the caller's catch block, which removes the
    # half-configured service before the action exits nonzero.
    param([string]$Name, [string]$Account, [string]$Password)
    $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Name + "'")
    if (-not $svc) {
        throw ("service '" + $Name + "' not found via Win32_Service after creation")
    }
    $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{
        StartName     = $Account
        StartPassword = $Password
    }
    if ($result.ReturnValue -ne 0) {
        throw ("Win32_Service.Change (ChangeServiceConfig) failed for service '" + $Name + "' with return value " + $result.ReturnValue)
    }
}

function Test-ServiceExists {
    param([string]$Name)
    $r = Invoke-Tool -Tool $script:ScExe -Arguments ("query " + $Name)
    if ($r.ExitCode -eq 0) { return $true }
    if ($r.ExitCode -eq $script:ErrServiceAbsent) { return $false }
    Write-ToolOutput $r
    Fail ("sc.exe query " + $Name + " failed with exit code " + $r.ExitCode)
}

function Wait-ServiceStopped {
    # Bounded wait until the service reports STATE STOPPED (or is gone).
    param([string]$Name, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        $r = Invoke-Tool -Tool $script:ScExe -Arguments ("query " + $Name)
        if ($r.ExitCode -eq $script:ErrServiceAbsent) { return }
        if ($r.ExitCode -ne 0) {
            Write-ToolOutput $r
            Fail ("sc.exe query " + $Name + " failed while waiting for stop (exit code " + $r.ExitCode + ")")
        }
        if ($r.StdOut -match 'STOPPED') { return }
    }
    Fail ("service '" + $Name + "' did not reach STOPPED within " + $TimeoutSeconds + " seconds")
}

function Remove-ExistingService {
    # Upgrade path: stop + delete the previous service so create starts from
    # a clean slate. Tolerates absence (fresh install); fails closed on
    # anything it cannot resolve.
    param([string]$Name)

    if (-not (Test-ServiceExists -Name $Name)) {
        Write-Output ("==> service '" + $Name + "' not present (fresh install)")
        return
    }

    Write-Output ("==> existing service '" + $Name + "' found (upgrade): deleting before create")
    $r = Invoke-Tool -Tool $script:ScExe -Arguments ("stop " + $Name)
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0 -and
        $r.ExitCode -ne $script:ErrServiceNotActive -and
        $r.ExitCode -ne $script:ErrServiceAbsent) {
        Fail ("sc.exe stop " + $Name + " failed with exit code " + $r.ExitCode)
    }
    Wait-ServiceStopped -Name $Name

    $r = Invoke-Tool -Tool $script:ScExe -Arguments ("delete " + $Name)
    Write-ToolOutput $r
    if ($r.ExitCode -eq $script:ErrServiceMarkedForDelete) {
        Fail ("service '" + $Name + "' is already marked for deletion; reboot the host and rerun the install")
    }
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne $script:ErrServiceAbsent) {
        Fail ("sc.exe delete " + $Name + " failed with exit code " + $r.ExitCode)
    }

    # A deleted service disappears only once all handles are closed; poll
    # until the SCM no longer lists it (bounded, then fail closed).
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-ServiceExists -Name $Name)) {
            Write-Output ("==> previous service '" + $Name + "' removed")
            return
        }
        Start-Sleep -Seconds 1
    }
    Fail ("service '" + $Name + "' still present 60 seconds after sc.exe delete")
}

function Remove-ServiceBestEffort {
    # Cleanup before a failing exit: the WiX transaction rolls back, but
    # sc.exe state is not transactional, so a half-configured service is
    # removed here.
    param([string]$Name)
    $r = Invoke-Tool -Tool $script:ScExe -Arguments ("delete " + $Name)
    Write-ToolOutput $r
    if ($r.ExitCode -eq 0) {
        Write-Output ("==> cleanup: service '" + $Name + "' deleted")
    }
    else {
        Write-Output ("==> cleanup: sc.exe delete " + $Name + " returned exit code " + $r.ExitCode)
    }
}

try {
    # --- resolve inputs ------------------------------------------------------
    if (-not $VenvDir) { $VenvDir = $env:UDBMCP_VENV_DIR }
    if (-not $ConfigPath) { $ConfigPath = $env:UDBMCP_CONFIG }
    if (-not $ServiceName) { $ServiceName = $env:UDBMCP_SERVICE_NAME }
    if (-not $ServiceAccount) { $ServiceAccount = $env:UDBMCP_SERVICE_ACCOUNT }
    if (-not $ServicePassword -and $env:UDBMCP_SERVICE_PASSWORD) { $ServicePassword = $env:UDBMCP_SERVICE_PASSWORD }
    if (-not $ServiceName) { $ServiceName = 'udbmcp' }
    if (-not $ServiceAccount) { $ServiceAccount = 'LocalSystem' }

    if (-not $VenvDir) { Fail "no venv directory: pass -VenvDir or set UDBMCP_VENV_DIR" }
    if (-not $ConfigPath) { Fail "no config path: pass -ConfigPath or set UDBMCP_CONFIG (a service without a config cannot start)" }
    # The name is embedded unquoted in sc.exe command lines and inside a WMI
    # filter string, so both quote styles and whitespace are rejected here.
    if ($ServiceName -match '[\s"'']') {
        Fail "service name must not contain whitespace or quotes"
    }
    if ($ServiceAccount -match '["\r\n]') {
        Fail "service account name must not contain quotes or line breaks"
    }

    $python = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Fail ("venv interpreter not found at '" + $python + "'; the verify, venv-build and doctor custom actions must run before this one")
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Fail ("config not found at '" + $ConfigPath + "'")
    }

    Remove-ExistingService -Name $ServiceName

    # --- create ---------------------------------------------------------------
    # Raw command line (CommandLineToArgvW semantics): the binPath value is
    # itself quoted and contains the quoted interpreter path, so its embedded
    # quotes are backslash-escaped.
    $binPath = '"' + $python + '" -m universal_db_mcp serve'
    $createArgs = 'create ' + $ServiceName +
        ' binPath= "' + (ConvertTo-ScArgument $binPath) + '"' +
        ' start= auto' +
        ' obj= "' + (ConvertTo-ScArgument $ServiceAccount) + '"'
    # The password is deliberately NOT part of this command line: command
    # lines are captured into durable OS audit logs (Event 4688 with
    # include-command-line, Sysmon EID 1). It is written through the Service
    # Control Manager API below, after the create succeeded.

    Write-Output ("==> creating service '" + $ServiceName + "' (start= auto, account " + $ServiceAccount + ")")
    $r = Invoke-Tool -Tool $script:ScExe -Arguments $createArgs
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0) {
        Fail ("sc.exe create " + $ServiceName + " failed with exit code " + $r.ExitCode)
    }
    $script:Created = $true

    # --- credential (SCM API, never a command line) ---------------------------
    if ($ServicePassword) {
        Write-Output ("==> setting the service account credential via the SCM API (never via a command line)")
        Set-ServiceLogonCredential -Name $ServiceName -Account $ServiceAccount -Password $ServicePassword
    }

    # --- description ----------------------------------------------------------
    $r = Invoke-Tool -Tool $script:ScExe -Arguments (
        'description ' + $ServiceName + ' "' +
        (ConvertTo-ScArgument 'UniversalDB MCP server (air-gapped): stdio/HTTP MCP gateway over local databases.') + '"')
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0) {
        Abort ("sc.exe description " + $ServiceName + " failed with exit code " + $r.ExitCode)
    }

    # --- failure recovery (mirrors systemd Restart=on-failure) ----------------
    # First failure: restart after 60000 ms; the failure counter resets after
    # 86400 seconds without failures.
    $r = Invoke-Tool -Tool $script:ScExe -Arguments (
        'failure ' + $ServiceName + ' reset= 86400 actions= restart/60000')
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0) {
        Abort ("sc.exe failure " + $ServiceName + " failed with exit code " + $r.ExitCode)
    }

    # --- service environment ----------------------------------------------------
    # serve requires a config (UDBMCP_CONFIG or --config). The binPath stays
    # exactly the interpreter plus "serve"; the validated machine-wide config
    # path is injected via the service Environment registry value, which
    # services.exe merges into the service process environment.
    $envKey = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $ServiceName + '\Environment'
    $r = Invoke-Tool -Tool $script:RegExe -Arguments (
        'add "' + $envKey + '" /v UDBMCP_CONFIG /t REG_MULTI_SZ /d "' + (ConvertTo-ScArgument $ConfigPath) + '" /f')
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0) {
        Abort ("could not write UDBMCP_CONFIG under " + $envKey + " (reg.exe exit code " + $r.ExitCode + ")")
    }

    Write-Output ("==> service '" + $ServiceName + "' registered (the installer does not auto-start it; the admin or the delivered gate script starts it)")
    exit 0
}
catch {
    if ($script:Created) { Remove-ServiceBestEffort -Name $ServiceName }
    Fail ("service registration failed: " + $_.Exception.Message)
}
