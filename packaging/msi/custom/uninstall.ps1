#
# UniversalDB MCP - MSI deferred custom action: service removal (uninstall).
#
# Contract (wired by scripts/package/build_msi.sh; see packaging/msi/udbmcp.wxs):
#   Deferred custom action, Impersonate="no", Return="check", e.g.:
#     powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
#       "[INSTALLFOLDER]scripts\uninstall.ps1"
#       -ServiceName "udbmcp"
#   Exit code 0 = continue; any nonzero exit fails the action and WiX rolls
#   back the uninstall.
#
# TRUST MODEL - DO NOT BREAK:
#   * This action only stops/deletes the service registered by service.ps1
#     and removes the service Environment value. It executes no payload and
#     must never be reordered to run before the payload verify action on
#     upgrade paths.
#   * The release public key is NEVER shipped inside the package; nothing in
#     this script reads, writes or embeds key material.
#
# Tolerance contract:
#   * Absent service (1060) and not-running service (1062) are success
#     conditions here: uninstall must work on a host where the service was
#     never created or already removed.
#   * "Marked for deletion" (1072) after delete is tolerated with a note:
#     the SCM removes the service once all handles close (typically at
#     reboot); failing the uninstall for that would strand the files.
#   * Any other sc.exe/reg.exe failure exits nonzero (fail closed).
#   * The machine-wide config at ProgramData\UniversalDB MCP\config.yaml is
#     deliberately NOT touched (retention semantics, mirrors the .deb
#     conffile behavior on remove).
#
# Parameters may also be supplied via environment variables for manual runs:
#   UDBMCP_SERVICE_NAME
#
[CmdletBinding()]
param(
    [string]$ServiceName = 'udbmcp'
)

$ErrorActionPreference = 'Stop'

$script:ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
$script:RegExe = Join-Path $env:SystemRoot 'System32\reg.exe'

# sc.exe / reg.exe exit codes: ERROR_SERVICE_DOES_NOT_EXIST,
# ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_MARKED_FOR_DELETE.
$script:ErrServiceAbsent = 1060
$script:ErrServiceNotActive = 1062
$script:ErrServiceMarkedForDelete = 1072

function Fail {
    param([string]$Message)
    Write-Output ("UNINSTALL-ACTION FAILED: " + $Message)
    exit 1
}

function Invoke-Tool {
    # Runs a tool with a fully controlled raw command line and returns the
    # exit code plus captured output (sc.exe / reg.exe output is small, so
    # synchronous ReadToEnd is safe).
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
    param($Result)
    if ($Result.StdOut) {
        $Result.StdOut.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Output ("    " + $_) }
    }
    if ($Result.StdErr) {
        $Result.StdErr.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Output ("    [stderr] " + $_) }
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

try {
    if (-not $ServiceName) { $ServiceName = $env:UDBMCP_SERVICE_NAME }
    if (-not $ServiceName) { $ServiceName = 'udbmcp' }

    if (-not (Test-ServiceExists -Name $ServiceName)) {
        Write-Output ("==> service '" + $ServiceName + "' not present: nothing to stop or delete")
    }
    else {
        # --- stop (tolerant when not running) --------------------------------
        Write-Output ("==> stopping service '" + $ServiceName + "'")
        $r = Invoke-Tool -Tool $script:ScExe -Arguments ("stop " + $ServiceName)
        Write-ToolOutput $r
        if ($r.ExitCode -eq 0) {
            # Bounded wait until stopped; a stop that does not complete is a
            # real failure (fail closed) rather than a silent dangling service.
            $deadline = (Get-Date).AddSeconds(60)
            $stopped = $false
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 1
                $qr = Invoke-Tool -Tool $script:ScExe -Arguments ("query " + $ServiceName)
                if ($qr.ExitCode -eq $script:ErrServiceAbsent) { $stopped = $true; break }
                if ($qr.ExitCode -ne 0) {
                    Write-ToolOutput $qr
                    Fail ("sc.exe query " + $ServiceName + " failed while waiting for stop (exit code " + $qr.ExitCode + ")")
                }
                if ($qr.StdOut -match 'STOPPED') { $stopped = $true; break }
            }
            if (-not $stopped) {
                Fail ("service '" + $ServiceName + "' did not reach STOPPED within 60 seconds")
            }
        }
        elseif ($r.ExitCode -eq $script:ErrServiceNotActive -or $r.ExitCode -eq $script:ErrServiceAbsent) {
            Write-Output ("==> service '" + $ServiceName + "' was not running (exit code " + $r.ExitCode + "): tolerated")
        }
        else {
            Fail ("sc.exe stop " + $ServiceName + " failed with exit code " + $r.ExitCode)
        }

        # --- delete (tolerant when absent or already marked) ------------------
        Write-Output ("==> deleting service '" + $ServiceName + "'")
        $r = Invoke-Tool -Tool $script:ScExe -Arguments ("delete " + $ServiceName)
        Write-ToolOutput $r
        if ($r.ExitCode -eq 0) {
            Write-Output ("==> service '" + $ServiceName + "' deleted")
        }
        elseif ($r.ExitCode -eq $script:ErrServiceMarkedForDelete) {
            Write-Output ("==> service '" + $ServiceName + "' is marked for deletion; the SCM removes it once handles close (typically at reboot)")
        }
        elseif ($r.ExitCode -eq $script:ErrServiceAbsent) {
            Write-Output ("==> service '" + $ServiceName + "' already absent (exit code 1060): tolerated")
        }
        else {
            Fail ("sc.exe delete " + $ServiceName + " failed with exit code " + $r.ExitCode)
        }
    }

    # --- remove the service Environment value written by service.ps1 --------
    # reg.exe returns 1 when the value or key does not exist; that is the
    # expected state on hosts where the service never got that far.
    $envKey = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $ServiceName + '\Environment'
    $r = Invoke-Tool -Tool $script:RegExe -Arguments ('query "' + $envKey + '" /v UDBMCP_CONFIG')
    if ($r.ExitCode -eq 0) {
        $r = Invoke-Tool -Tool $script:RegExe -Arguments ('delete "' + $envKey + '" /v UDBMCP_CONFIG /f')
        Write-ToolOutput $r
        if ($r.ExitCode -ne 0) {
            Fail ("could not delete UDBMCP_CONFIG under " + $envKey + " (reg.exe exit code " + $r.ExitCode + ")")
        }
        Write-Output ("==> removed UDBMCP_CONFIG from " + $envKey)
    }
    else {
        Write-Output ("==> no UDBMCP_CONFIG value under " + $envKey + " (nothing to clean)")
    }

    Write-Output ("==> uninstall custom action complete (machine-wide config under ProgramData is retained by design)")
    exit 0
}
catch {
    Fail ("unexpected error: " + $_.Exception.Message)
}
