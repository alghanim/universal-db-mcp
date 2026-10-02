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
#   The same script is the rollback twin of RegisterServiceCA
#   (RollbackRemoveServiceCA, Execute="rollback"), which also passes
#       -InstalledManifest "[ProgramFiles64Folder]UniversalDB MCP\manifest.json"
#   so that a failed install puts back the installed-release record
#   RegisterServiceCA replaced (see "Rollback" below), and
#       -Repair "[Installed]"
#   (non-empty when the product was installed before this run: a repair),
#   and the commit action
#   CommitReleaseRecordCA (Execute="commit", Return="ignore"), which passes
#   that and -Commit, and only removes the record's rollback copy once the
#   install succeeded. The uninstall itself never passes -InstalledManifest:
#   the record outlives the product, so a downgrade after an uninstall is
#   still refused.
#
# TRUST MODEL - DO NOT BREAK:
#   * This action only stops/deletes the service registered by service.ps1
#     and removes the service Environment value (and, as the rollback twin,
#     restores the installed-release record; as the commit action it only
#     removes that record's rollback copy). It executes no payload and
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
#     retained at uninstall: the config component is Permanent (and
#     NeverOverwrite), so neither an uninstall nor the uninstall of the old
#     product a major upgrade runs first removes it, as the .deb's postrm
#     keeps the config on remove. This script never touches it.
#
# Rollback: RegisterServiceCA copies the installed-release record it replaces
# to <record>.previous (an empty copy: there was none) just before it writes
# the new one, and until then keeps the marker <record>.kept beside it. The
# rollback twin copies the copy back (or removes the record when the copy is
# empty) and removes both; with the marker there, or no copy, this install
# never replaced the record and it is left as it is. A copy an earlier
# install left is never restored: RegisterServiceCA puts the marker down
# before it removes such a copy, and a copy this script cannot remove (a
# local user may hold it open: anyone can read under Program Files) keeps
# the marker. A failure there is reported and the service is still removed.
# The service: a first install or an upgrade that fails has no service to
# keep (an upgrade removed the old product, and its service, first), so the
# twin stops and deletes the one this install registered. A repair (-Repair
# non-empty) keeps it: the product, and a registered service, were there
# before the repair began, and the rollback restores the files the service
# runs. Deleting it there took a working service away whenever the repair
# failed, even before RegisterServiceCA had touched the service.
# Commit (-Commit): the install succeeded, so the copy and the marker go and
# nothing else is done.
#
# Parameters may also be supplied via environment variables for manual runs:
#   UDBMCP_SERVICE_NAME
#
[CmdletBinding()]
param(
    [string]$ServiceName = 'udbmcp',
    # The rollback twin and the commit action only: the installed-release
    # record to restore, or whose rollback copy to remove.
    [string]$InstalledManifest = '',
    # The commit action: remove the record's rollback copy, and nothing else.
    [switch]$Commit,
    # The rollback twin only: Windows Installer's Installed property, set
    # when this run maintains an installed product (a repair). The twin then
    # keeps the service (see "Rollback" above).
    [string]$Repair = ''
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

function Remove-RecordCopy {
    # Removes the rollback copy of the installed-release record ($Copy) and
    # the marker beside it ($Kept). A copy that cannot be removed keeps the
    # marker, put down here if RegisterServiceCA had already removed it, so
    # no later rollback restores that copy.
    param([string]$Copy, [string]$Kept)
    try {
        if (Test-Path -LiteralPath $Copy) { Remove-Item -LiteralPath $Copy -Force }
    }
    catch {
        if (-not (Test-Path -LiteralPath $Kept)) { [System.IO.File]::WriteAllBytes($Kept, [byte[]]@()) }
        throw
    }
    if (Test-Path -LiteralPath $Kept) { Remove-Item -LiteralPath $Kept -Force }
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

    # The name is embedded unquoted in sc.exe command lines and inside a
    # quoted reg.exe key path, so both quote styles and whitespace are
    # rejected here (same guard as service.ps1; fail closed).
    if ($ServiceName -match '[\s"'']') {
        Fail "service name must not contain whitespace or quotes"
    }

    # --- commit: the install succeeded (see the header) -------------------------
    if ($Commit) {
        if ($InstalledManifest) {
            $recordCopy = $InstalledManifest + '.previous'
            try {
                Remove-RecordCopy -Copy $recordCopy -Kept ($InstalledManifest + '.kept')
                Write-Output ("==> the installed release record " + $InstalledManifest + " stands: its rollback copy is removed")
            }
            catch {
                Write-Output ("==> WARNING: could not remove " + $recordCopy + ": " + $_.Exception.Message +
                              "; the marker beside it keeps any later rollback from restoring it")
            }
        }
        exit 0
    }

    # --- rollback: the installed-release record (see the header) --------------
    if ($InstalledManifest) {
        $recordCopy = $InstalledManifest + '.previous'
        $recordKept = $InstalledManifest + '.kept'
        try {
            if (Test-Path -LiteralPath $recordKept) {
                Write-Output ("==> this install did not replace the installed release record " + $InstalledManifest + ": it is unchanged")
            }
            elseif (-not (Test-Path -LiteralPath $recordCopy -PathType Leaf)) {
                Write-Output ("==> no copy of the installed release record at " + $recordCopy + ": the record is unchanged")
            }
            elseif ((Get-Item -LiteralPath $recordCopy).Length -gt 0) {
                [System.IO.File]::Copy($recordCopy, $InstalledManifest, $true)
                Write-Output ("==> restored the installed release record " + $InstalledManifest + " from " + $recordCopy)
            }
            else {
                if (Test-Path -LiteralPath $InstalledManifest -PathType Leaf) {
                    Remove-Item -LiteralPath $InstalledManifest -Force
                }
                Write-Output ("==> removed the installed release record " + $InstalledManifest + " (none was recorded before this install)")
            }
            Remove-RecordCopy -Copy $recordCopy -Kept $recordKept
        }
        catch {
            Write-Output ("==> WARNING: " + $_.Exception.Message + "; inspect the installed release record " +
                          $InstalledManifest + " and " + $recordCopy)
        }
    }

    if ($InstalledManifest -and $Repair) {
        Write-Output ("==> a failed repair: the service '" + $ServiceName + "' registered before it is kept")
        exit 0
    }

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

    Write-Output ("==> uninstall custom action complete (the machine-wide config.yaml under ProgramData is retained)")
    exit 0
}
catch {
    Fail ("unexpected error: " + $_.Exception.Message)
}
