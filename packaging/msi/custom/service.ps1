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
#       -BundleDir "[INSTALLFOLDER]bundle"
#       -InstalledManifest "[ProgramFiles64Folder]UniversalDB MCP\manifest.json"
#       -RegisteredAccount "[UdbmcpRegisteredAccount]"
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
#   sc.exe create udbmcp binPath= "<venv>\Scripts\python.exe" -I -m universal_db_mcp serve --transport http start= auto
#   sc.exe failure udbmcp reset= 86400 actions= restart/60000
# --transport http is MANDATORY here: a daemon under the SCM has no stdin
# client, so the config's stdio default would read EOF and exit 0 immediately
# (and failure recovery only fires on nonzero exit). The HTTP listener's only
# authentication is a bearer token; this action provisions it at
# <config dir>\http-token, owned by Administrators, with its own protected
# DACL (an existing token is kept only when SYSTEM or Administrators own it
# and its protected DACL allows nobody else but the service account; the
# value is never printed) and injects its PATH via
# UDBMCP_HTTP_BEARER_TOKEN_FILE alongside UDBMCP_CONFIG.
# When a dedicated account is configured, its password is written through the
# Service Control Manager API (Win32_Service.Change), NEVER as a command-line
# token: the OS records command lines in durable audit logs (Event 4688 with
# include-command-line / Sysmon EID 1). LocalSystem needs no password.
# The service reads its configuration from the UDBMCP_CONFIG environment
# value written under HKLM\SYSTEM\CurrentControlSet\Services\<name>\
# Environment (services.exe injects it into the process), so the binPath
# stays exactly the interpreter plus "serve". The interpreter runs with -I
# (as every LocalSystem python run of the MSI does): no PYTHON* variables,
# user site or working directory on sys.path.
# A dedicated account reads the config folder only; it writes its audit log
# (the Windows default audit_path) and other state in <config dir>\logs,
# which DoctorSmokeCA creates and this action gives the folder's protected
# DACL plus Modify for that account (creating it if it is missing).
# Once everything else succeeded, the bundle's manifest.json is recorded as
# the installed release at -InstalledManifest (C:\Program Files\UniversalDB
# MCP\manifest.json, whatever INSTALLFOLDER is): verify.ps1 refuses a bundle
# that is an older release than that record (anti-rollback). The record it
# replaces is kept at <record>.previous for the rollback twin
# (RollbackRemoveServiceCA), which puts it back when the install fails, and
# until it is replaced <record>.kept tells that twin to leave it alone; the
# commit action (CommitReleaseRecordCA) removes both once the install
# succeeded.
#
# Idempotency: on upgrade the previous service is stopped and deleted before
# the new one is created (delete-then-create). On a fresh install the query
# reports the service absent and creation proceeds directly.
#
# The service account: -ServiceAccount (UDBMCP_SERVICE_ACCOUNT, which
# msiexec does not keep between runs), else the account the service is
# registered under when the install starts (-RegisteredAccount), else
# LocalSystem. A repair or upgrade that does not name the account again
# keeps it; one it was not given is refused before anything changes when
# the service signs in with a password, or when logs\ shows the service
# ran as another account (see Get-ImplicitAccountProblem).
#
# Parameters may also be supplied via environment variables for manual runs
# from the delivered gate script (scripts/test_package_msi.ps1):
#   UDBMCP_VENV_DIR, UDBMCP_CONFIG, UDBMCP_SERVICE_NAME,
#   UDBMCP_SERVICE_ACCOUNT (see above), UDBMCP_SERVICE_PASSWORD
#
[CmdletBinding()]
param(
    [string]$VenvDir,
    [string]$ConfigPath,
    # Defaults for the direct msiexec wiring (udbmcp.wxs passes an explicit,
    # possibly empty, -ServiceAccount); manual runs may override them via the
    # environment variables documented in the header by passing empty
    # strings. An empty -ServiceAccount resolves as the header says.
    [string]$ServiceName = 'udbmcp',
    [string]$ServiceAccount = '',
    [string]$ServicePassword = '',
    # The installed bundle, whose manifest is recorded as the installed
    # release at the end; empty (a manual run) records nothing.
    [string]$BundleDir = '',
    # Where that record goes; empty: beside the bundle directory.
    [string]$InstalledManifest = '',
    # The account the service is registered under when the install starts:
    # the wxs reads the service key's ObjectName before anything runs, so a
    # major upgrade passes it although the old product's uninstall has
    # deleted the service by the time this action runs. Empty: none.
    [string]$RegisteredAccount = ''
)

$ErrorActionPreference = 'Stop'

$script:ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
$script:RegExe = Join-Path $env:SystemRoot 'System32\reg.exe'
$script:IcaclsExe = Join-Path $env:SystemRoot 'System32\icacls.exe'

# Well-known SIDs, never localized account names (they change with the OS
# language): LocalSystem and BUILTIN\Administrators.
$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
# Direct members of the local Administrators group; looked up on first use.
$script:AdminMemberSids = $null
# FileSystemRights bits that let a principal change an entry: write or
# append its data (in a folder: create files or subfolders), write its
# attributes or extended attributes, delete it or entries in it, change its
# DACL or owner, and the generic all and write bits an inheritable ACE may
# carry.
$script:WriteRights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor
    0x10000000 -bor 0x40000000
# Modify, Synchronize: the most an earlier service account may hold on logs\
# (what the registration action grants a service account there).
$script:ModifyRights = 0x1301BF
# The config folder's DACL, as the MSI's PermissionEx sets it: nothing
# inherited (C:\ProgramData's inheritable ACEs let BUILTIN\Users read and
# create entries), SYSTEM and Administrators Full Control, owned by
# Administrators.
$script:ProtectedDirSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

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

function Get-EntryAttributes {
    # Attributes of the directory entry at $Path itself, or $null when there
    # is none. Unlike Test-Path, GetAttributes never follows a junction or
    # symbolic link, so a dangling one is still seen.
    param([string]$Path)
    try {
        return [System.IO.File]::GetAttributes($Path)
    }
    catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
        return $null
    }
}

function Test-TrustedOwner {
    # True when $Sid may own an entry this LocalSystem action reads or writes
    # through: SYSTEM, Administrators, or a direct member of the local
    # Administrators group (an elevated administrator's new files are owned
    # by their own account where the "Default owner for objects created by
    # members of the Administrators group" policy is "Object creator"). When
    # the members cannot be listed (no LocalAccounts module, an orphaned SID
    # in the group), only SYSTEM and Administrators are trusted.
    param([string]$Sid)
    if ($Sid -eq $script:SidSystem -or $Sid -eq $script:SidAdmins) { return $true }
    if ($null -eq $script:AdminMemberSids) {
        try {
            $script:AdminMemberSids = @(Get-LocalGroupMember -SID $script:SidAdmins | ForEach-Object { $_.SID.Value })
        }
        catch {
            $script:AdminMemberSids = @()
        }
    }
    return ($script:AdminMemberSids -contains $Sid)
}

function Get-WriteProblem {
    # Why this LocalSystem action must not write through $Path, or $null when
    # it may (including when nothing exists there yet). Any local user can
    # create a folder under C:\ProgramData and owns what it creates, so an
    # existing entry must be owned by SYSTEM, Administrators or an
    # administrator, must not be a junction or symbolic link that redirects
    # the write, and must carry no ACE of its own that lets anybody else
    # write it or create entries in it: a new owner keeps such an ACE, and
    # the folder's DACL replaces neither it nor a protected child's DACL.
    # Inherited ACEs follow the folder, whose DACL the installer sets.
    # $OwnerSid (the service account, for what it wrote in logs\) may own it
    # and $WriterSid (that account, on logs\ and below) may hold such an ACE,
    # but a reparse point is refused whoever owns it. With -AccountWriters
    # (logs\ itself) an ACE that grants any account a service runs as at most
    # Modify is accepted too: an earlier service account's grant, which the
    # action resets before anything relies on logs\.
    param([string]$Path, [string]$OwnerSid = '', [string]$WriterSid = $OwnerSid, [switch]$AccountWriters)
    $attributes = Get-EntryAttributes -Path $Path
    if ($null -eq $attributes) { return $null }
    if ($attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return 'is a reparse point (junction or symbolic link)'
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not ($OwnerSid -and $owner -eq $OwnerSid) -and -not (Test-TrustedOwner -Sid $owner)) {
        $trusted = 'SYSTEM, Administrators or an administrator'
        if ($OwnerSid) { $trusted = 'SYSTEM, Administrators, an administrator or the service account ' + $OwnerSid }
        return ('is owned by ' + $owner + ', not ' + $trusted)
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            ($WriterSid -and $sid -eq $WriterSid) -or (Test-TrustedOwner -Sid $sid)) { continue }
        $granted = [int64]([System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights)
        if ($AccountWriters -and (Test-AccountSid -Sid $sid) -and -not ($granted -band -bnot $script:ModifyRights)) { continue }
        if ($granted -band $script:WriteRights) {
            return ('grants ' + $sid + ' ' + $rule.FileSystemRights)
        }
    }
    return $null
}

function Get-TreeProblem {
    # The first entry below $Directory, at any depth, that Get-WriteProblem
    # refuses, as @{ Path; Problem; InLogs }, or $null. Entries directly in
    # $Directory named in $SkipNames are checked by the caller. Its logs\
    # folder may grant $LogsSid, the service account, write access, and any
    # account a service runs as at most Modify (an earlier service account's
    # grant, which the action resets); the entries at any depth below it may
    # also be owned by the service account, which writes them (logs\ itself
    # may not). InLogs tells the caller the entry is logs\ or in it, where
    # the audit log is kept. A refused entry is never descended into, so no
    # junction is followed.
    param([string]$Directory, [string[]]$SkipNames = @(), [string]$LogsSid = '', [string]$OwnerSid = '',
          [switch]$Nested, [switch]$InLogs)
    foreach ($entry in @(Get-ChildItem -LiteralPath $Directory -Force)) {
        if ($SkipNames -contains $entry.Name) { continue }
        $logs = $InLogs -or (-not $Nested -and $entry.Name -eq 'logs')
        $below = $OwnerSid
        if ($logs -and -not $InLogs) { $below = $LogsSid }
        $problem = Get-WriteProblem -Path $entry.FullName -OwnerSid $OwnerSid -WriterSid $below -AccountWriters:($logs -and -not $InLogs)
        if ($problem) { return @{ Path = $entry.FullName; Problem = $problem; InLogs = $logs } }
        if ($entry.PSIsContainer) {
            $found = Get-TreeProblem -Directory $entry.FullName -OwnerSid $below -Nested -InLogs:$logs
            if ($found) { return $found }
        }
    }
    return $null
}

function Get-TreeRemedy {
    # What the administrator does about the entry Get-TreeProblem refused
    # ($Found), which -Appeared while the action protected the folder when
    # the second walk finds it. logs\ keeps the audit log, which an earlier
    # service account may have written: it is moved aside and archived, not
    # deleted.
    param($Found, [switch]$Appeared)
    if ($Found.InLogs) {
        return ('logs\ keeps the audit log, and an earlier service account may have written this entry; inspect it,' +
                ' then move it out of this folder (archive it rather than deleting it) and rerun the install')
    }
    if ($Appeared) {
        return 'It appeared while this action protected the folder; inspect it, then remove it and rerun the install'
    }
    return ('Earlier releases let any local user add entries to this folder, and a new owner or DACL would keep' +
            ' whatever its creator put in it; inspect it, then remove it and rerun the install')
}

function Test-AccountSid {
    # True when $Sid is an account a service runs as: a local or domain
    # account, a gMSA included (S-1-5-21-..., but not a domain's well-known
    # groups, RIDs 498 and 510-599), LocalSystem, LocalService,
    # NetworkService or a virtual service account (NT SERVICE\...,
    # S-1-5-80- and five numbers). Never a group or a well-known principal
    # (BUILTIN\Users, Authenticated Users, Everyone, a domain's Domain Users,
    # NT SERVICE\ALL SERVICES, S-1-5-80-0): what it is granted, all its
    # members get.
    param([string]$Sid)
    if ($Sid -notmatch '^S-1-5-(1[89]|20|80(-\d+){5}|21(-\d+){4})$') { return $false }
    return ($Sid -notmatch '^S-1-5-21(-\d+){3}-(498|5[1-9]\d)$')
}

function Get-AclProblem {
    # Why the owner or DACL of $Path is not safe for the bearer token, or
    # $null. The owner must be SYSTEM or Administrators: the service accepts
    # no other owner for a secret file when it starts. The DACL must not
    # inherit from the folder (C:\ProgramData's inheritable ACEs give
    # BUILTIN\Users read access), and it may allow no SID outside
    # $AllowedSids. Any other account, a broad principal or a previously
    # configured service account alike, may already have read the value.
    param([string]$Path, [string[]]$AllowedSids)
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $script:SidSystem -and $owner -ne $script:SidAdmins) {
        return ('is owned by ' + $owner + ', not SYSTEM or Administrators')
    }
    if (-not $acl.AreAccessRulesProtected) {
        return 'inherits its DACL from the folder'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $AllowedSids -notcontains $rule.IdentityReference.Value) {
            return ('grants ' + $rule.IdentityReference.Value + ' ' + $rule.FileSystemRights)
        }
    }
    return $null
}

function Get-TokenProblem {
    # Why the existing bearer token $Path cannot be kept, or $null: it must
    # be a non-empty plain file owned by SYSTEM or Administrators whose DACL
    # is protected and allows nobody but $AllowedSids (SYSTEM,
    # Administrators and the service account). Anything else may have been
    # read or chosen by another account (a local user, or a previously
    # configured service account). One rule for both actions: doctor.ps1
    # removes such a token before the payload doctor (which refuses it) runs,
    # and service.ps1 replaces it; neither ever changes its owner, which
    # would keep a value its creator knows. A token whose DACL does not even
    # let this action read it is one of those (the folder's DACL still lets
    # it delete the file).
    param([string]$Path, [string[]]$AllowedSids)
    try {
        $problem = Get-WriteProblem -Path $Path
        if (-not $problem) { $problem = Get-AclProblem -Path $Path -AllowedSids $AllowedSids }
    }
    catch {
        return ('cannot be inspected (' + $_.Exception.Message + ')')
    }
    if (-not $problem) {
        $existing = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
        if (-not ($existing -and $existing.Trim())) { $problem = 'is empty' }
    }
    return $problem
}

function Set-ProtectedAcl {
    # Makes Administrators the owner of $Path (a file an elevated
    # administrator creates may be owned by their own account), removes the
    # inherited ACEs and (re)grants $Grants (icacls grant strings naming
    # SIDs), then proves the result instead of assuming it. Called before the
    # service is created, so Fail needs no cleanup.
    param([string]$Path, [string]$Grants, [string[]]$AllowedSids)
    $target = '"' + (ConvertTo-ScArgument $Path) + '"'
    $steps = @(
        ($target + ' /setowner *' + $script:SidAdmins),
        ($target + ' /inheritance:r /grant:r ' + $Grants)
    )
    foreach ($arguments in $steps) {
        $r = Invoke-Tool -Tool $script:IcaclsExe -Arguments $arguments
        Write-ToolOutput $r
        if ($r.ExitCode -ne 0) {
            Fail ("icacls could not protect '" + $Path + "' (exit code " + $r.ExitCode + ")")
        }
    }
    $problem = Get-AclProblem -Path $Path -AllowedSids $AllowedSids
    if ($problem) {
        Fail ("'" + $Path + "' still " + $problem + " after icacls")
    }
}

function Get-ServiceAccountSid {
    # SID of the service logon account, or $null for LocalSystem (already
    # granted Full Control as S-1-5-18). The built-in service accounts map to
    # fixed SIDs, and a virtual account NT SERVICE\<name> to the service SID
    # Windows derives from the name ('sc.exe showsid'): S-1-5-80- and the
    # SHA-1 of the upper-cased UTF-16LE name as five little-endian 32-bit
    # numbers. That one is derived, not translated: the local security
    # authority knows it only while the service exists, and it does not
    # yet on a fresh install, or once a major upgrade removed the old
    # product. Any other account is translated by the local security
    # authority, and one it cannot resolve fails the action (fail closed).
    # So does a SID no service runs as (Test-AccountSid): this SID is granted
    # access to the config folder, the token and logs\ before sc.exe create
    # could refuse it, and a group or well-known principal would pass that
    # access on to all its members.
    param([string]$Account)
    switch -Regex ($Account) {
        '^(\.\\)?LocalSystem$' { return $null }
        '^NT AUTHORITY\\SYSTEM$' { return $null }
        '^NT AUTHORITY\\Local ?Service$' { return 'S-1-5-19' }
        '^NT AUTHORITY\\Network ?Service$' { return 'S-1-5-20' }
    }
    if ($Account -match '^NT SERVICE\\(.+)$') {
        $hash = [System.Security.Cryptography.SHA1]::Create().ComputeHash(
            [System.Text.Encoding]::Unicode.GetBytes($Matches[1].ToUpperInvariant()))
        $sid = 'S-1-5-80'
        for ($i = 0; $i -lt 20; $i += 4) { $sid += '-' + [System.BitConverter]::ToUInt32($hash, $i) }
    }
    else {
        $name = $Account
        if ($name.StartsWith('.\')) { $name = $env:COMPUTERNAME + $name.Substring(1) }
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($name)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Fail ("cannot resolve the SID of service account '" + $Account + "': " + $_.Exception.Message)
        }
    }
    if (-not (Test-AccountSid -Sid $sid)) {
        Fail ("service account '" + $Account + "' resolves to " + $sid + ', which is no account a service runs as' +
              ' (a group or a well-known principal); name a user, managed service or NT SERVICE account')
    }
    return $sid
}

function Test-PasswordAccount {
    # True when the service account $Account signs in with a password, which
    # the Service Control Manager keeps and never gives back: any account but
    # LocalSystem, LocalService, NetworkService, a virtual account
    # (NT SERVICE\...) or a group managed service account (DOMAIN\name$).
    param([string]$Account)
    return ($Account -notmatch '^((\.\\)?LocalSystem|NT AUTHORITY\\(SYSTEM|Local ?Service|Network ?Service)|NT SERVICE\\.+|.+\$)$')
}

function Get-EarlierAccountSid {
    # An account other than $ServiceSid that the service ran as, as the
    # write access the registration action granted it on $LogsDir (logs\)
    # shows, or $null. Only a logs\ an install made counts: a directory, not
    # a junction or symbolic link, owned by SYSTEM, Administrators or an
    # administrator (the walk refuses any other).
    param([string]$LogsDir, [string]$ServiceSid)
    $attributes = Get-EntryAttributes -Path $LogsDir
    if ($null -eq $attributes -or ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        -not ($attributes -band [System.IO.FileAttributes]::Directory)) { return $null }
    $acl = Get-Acl -LiteralPath $LogsDir
    if (-not (Test-TrustedOwner -Sid $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value)) { return $null }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $sid -eq $ServiceSid -or (Test-TrustedOwner -Sid $sid) -or -not (Test-AccountSid -Sid $sid)) { continue }
        if ([int64]([System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights) -band $script:WriteRights) {
            return $sid
        }
    }
    return $null
}

function Get-ImplicitAccountProblem {
    # Why this install may not use $Account ($ServiceSid), a service account
    # it was not given, or $null. msiexec keeps no property between runs, so
    # a repair or upgrade without UDBMCP_SERVICE_ACCOUNT gets the account the
    # service is registered under, or LocalSystem when there is none. Such
    # an account is refused when it signs in with a password and none was
    # given ($Password): the service is registered again, and its password
    # cannot be read back. It is refused too when logs\ in $ConfigDir grants
    # another account write access: the service ran as that account, and
    # would lose its token and logs\ although nobody named another one.
    param([string]$Account, [string]$ServiceSid, [string]$ConfigDir, [switch]$Password)
    $remedy = ('pass UDBMCP_SERVICE_ACCOUNT to msiexec (from an elevated prompt), naming the account to keep' +
               ' or another one, and rerun the install')
    if ((Test-PasswordAccount -Account $Account) -and -not $Password) {
        return ("the service is registered under '" + $Account + "', which signs in with a password this install" +
                ' cannot carry over (it registers the service again); ' + $remedy +
                ', then set that password again (services.msc or sc.exe config)')
    }
    $logsDir = Join-Path $ConfigDir 'logs'
    $earlier = Get-EarlierAccountSid -LogsDir $logsDir -ServiceSid $ServiceSid
    if ($earlier) {
        return ("'" + $logsDir + "' grants " + $earlier + ' write access: the service ran as that account, and' +
                " this install, given no account, would take its token and logs\ away and use '" + $Account +
                "'; " + $remedy)
    }
    return $null
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
    # --- the rollback copy of the installed-release record --------------------
    # The record (see the end of this action) is replaced only once the one
    # it replaces is kept beside it, at <record>.previous (empty when there
    # was none): RollbackRemoveServiceCA (uninstall.ps1, run when the install
    # fails at or after this action) restores the record from that copy, so
    # a rolled-back upgrade does not leave the newer release recorded. Until
    # this action replaces the record, the marker <record>.kept tells that
    # twin the record is this install's to leave alone: a copy an earlier
    # install left, which a local user holding it open (anyone may read
    # under Program Files) keeps this action from removing, is then never
    # restored over a newer record. The marker comes first, before anything
    # here can fail, then that copy goes.
    if ($BundleDir -and -not $InstalledManifest) {
        $InstalledManifest = Join-Path (Split-Path -Parent $BundleDir) 'manifest.json'
    }
    $recordCopy = $InstalledManifest + '.previous'
    $recordKept = $InstalledManifest + '.kept'
    if ($BundleDir) {
        $recordDir = Split-Path -Parent $InstalledManifest
        if ((Test-Path -LiteralPath $recordDir -PathType Container) -and $null -eq (Get-EntryAttributes -Path $recordKept)) {
            [System.IO.File]::WriteAllBytes($recordKept, [byte[]]@())
        }
        if ($null -ne (Get-EntryAttributes -Path $recordCopy)) {
            Remove-Item -LiteralPath $recordCopy -Force
        }
    }

    # --- resolve inputs ------------------------------------------------------
    if (-not $VenvDir) { $VenvDir = $env:UDBMCP_VENV_DIR }
    if (-not $ConfigPath) { $ConfigPath = $env:UDBMCP_CONFIG }
    if (-not $ServiceName) { $ServiceName = $env:UDBMCP_SERVICE_NAME }
    if (-not $ServiceAccount) { $ServiceAccount = $env:UDBMCP_SERVICE_ACCOUNT }
    # Not given: the account the service is registered under, else
    # LocalSystem (see the header; judged once the config folder is known).
    $accountGiven = [bool]$ServiceAccount
    if (-not $accountGiven) { $ServiceAccount = $RegisteredAccount }
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

    # --- the config folder and config: refuse squatted ones --------------------
    # The LocalSystem service reads this config (it names the token file, the
    # listener address, the audit log and the databases), and the bearer
    # token is written next to it. Any local user can create a folder under
    # C:\ProgramData before the first install and owns what it creates; the
    # MSI's folder DACL names no owner, so such a folder stays theirs, and
    # NeverOverwrite keeps a config.yaml found in it. Both are refused before
    # anything on this machine is changed, and so is every entry below the
    # folder that a non-administrator owns or that is a junction or symbolic
    # link (a LocalSystem write through it lands wherever its creator pointed
    # it): on an upgrade the folder carried C:\ProgramData's inheritable ACEs
    # for the previous version's lifetime, so any local user could create
    # entries in it and in its subfolders (an audit directory the service
    # writes into, whose owner can later turn it into a junction; an audit
    # log or metadata cache its owner can read or rewrite). An entry whose own
    # ACEs let anybody else write it is refused too (a new owner keeps
    # them). The one other owner accepted is the service account, for what
    # it wrote in logs\, and it alone may be granted write access there (on
    # logs\ itself, an earlier service account's Modify too: it is reset
    # below, before the folder is walked again).
    $configDir = Split-Path -Parent $ConfigPath
    foreach ($path in @($configDir, $ConfigPath)) {
        $problem = Get-WriteProblem -Path $path
        if ($problem) {
            Fail ("refusing '" + $path + "': it " + $problem +
                  '. A non-admin can pre-create entries under C:\ProgramData, and a new owner or DACL would keep' +
                  ' whatever its creator put in it; inspect it, then remove it and rerun the install')
        }
    }
    $tokenFile = Join-Path $configDir 'http-token'
    $tokenAttributes = Get-EntryAttributes -Path $tokenFile
    if ($null -ne $tokenAttributes -and
        ($tokenAttributes -band ([System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Directory))) {
        Fail ("'" + $tokenFile + "' is a directory, junction or symbolic link, not a token file; inspect and remove it, then rerun the install")
    }
    $serviceSid = Get-ServiceAccountSid -Account $ServiceAccount
    if (-not $accountGiven) {
        $problem = Get-ImplicitAccountProblem -Account $ServiceAccount -ServiceSid $serviceSid -ConfigDir $configDir `
            -Password:([bool]$ServicePassword)
        if ($problem) { Fail $problem }
        if ($RegisteredAccount) {
            Write-Output ("==> no service account given: keeping '" + $ServiceAccount +
                          "', the account the service is registered under")
        }
    }
    # The token is checked on its own below: an unsafe one is replaced.
    $found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token') -LogsSid $serviceSid
    if ($found) {
        Fail ("refusing '" + $configDir + "': '" + $found.Path + "' in it " + $found.Problem + '. ' + (Get-TreeRemedy $found))
    }

    # The folder's own DACL is re-applied, not assumed: it drops the access a
    # previously configured service account was granted, and Set-Acl
    # propagates the new inheritable ACEs to the entries already in the
    # folder, which on an upgrade still carry the ones they inherited from
    # C:\ProgramData. A dedicated account then gets read access to its config
    # and to the token.
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($script:ProtectedDirSddl)
    Set-Acl -LiteralPath $configDir -AclObject $security

    # --- logs\: the one place the service account writes ---------------------
    # A dedicated account only reads the folder (the config, the secrets it
    # names, the token), but it writes its audit log (the Windows default
    # audit_path) and other state: logs\ gets the folder's protected DACL
    # and that account Modify on it. DoctorSmokeCA creates it (so that
    # doctor finds it); it is checked, created if missing and protected
    # only now, when no local user can create entries in the folder any more;
    # re-applying the DACL drops an earlier account's grant, which is
    # accepted until then.
    $logsDir = Join-Path $configDir 'logs'
    $problem = Get-WriteProblem -Path $logsDir -WriterSid $serviceSid -AccountWriters
    if ($problem) {
        Fail ("refusing '" + $logsDir + "': it " + $problem + '; inspect it, then move it out of this folder (it may' +
              ' hold the audit log: archive it rather than deleting it) and rerun the install')
    }
    $logsAttributes = Get-EntryAttributes -Path $logsDir
    if ($null -eq $logsAttributes) {
        # No -Force: if something appeared there since the check above, this
        # throws and the install is aborted.
        New-Item -ItemType Directory -Path $logsDir | Out-Null
    }
    elseif (-not ($logsAttributes -band [System.IO.FileAttributes]::Directory)) {
        Fail ("'" + $logsDir + "' is not a directory; inspect it, then move it out of this folder and rerun the install")
    }
    Set-Acl -LiteralPath $logsDir -AclObject $security
    $tokenGrants = '*' + $script:SidSystem + ':F *' + $script:SidAdmins + ':F'
    $tokenSids = @($script:SidSystem, $script:SidAdmins)
    if ($serviceSid) {
        $r = Invoke-Tool -Tool $script:IcaclsExe -Arguments (
            '"' + (ConvertTo-ScArgument $configDir) + '" /grant:r *' + $serviceSid + ':(OI)(CI)RX')
        Write-ToolOutput $r
        if ($r.ExitCode -ne 0) {
            Fail ("icacls could not grant the service account read access to '" + $configDir + "' (exit code " + $r.ExitCode + ")")
        }
        $r = Invoke-Tool -Tool $script:IcaclsExe -Arguments (
            '"' + (ConvertTo-ScArgument $logsDir) + '" /grant:r *' + $serviceSid + ':(OI)(CI)M')
        Write-ToolOutput $r
        if ($r.ExitCode -ne 0) {
            Fail ("icacls could not grant the service account write access to '" + $logsDir + "' (exit code " + $r.ExitCode + ")")
        }
        $tokenGrants += ' *' + $serviceSid + ':R'
        $tokenSids += $serviceSid
    }

    # The folder is walked again now that its DACL is in place: an entry a
    # local user created between the walk above and Set-Acl (in a subfolder
    # that still carried C:\ProgramData's inheritable ACEs) is still theirs.
    $found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token') -LogsSid $serviceSid
    if ($found) {
        Fail ("refusing '" + $configDir + "': '" + $found.Path + "' in it " + $found.Problem + '. ' + (Get-TreeRemedy $found -Appeared))
    }

    Remove-ExistingService -Name $ServiceName

    # --- bearer token (HTTP listener's only authentication) --------------------
    # The service runs --transport http; serve refuses to start without a
    # bearer token file. An existing token is kept only when it is a
    # non-empty plain file owned by SYSTEM or Administrators whose DACL is
    # protected and allows nobody but SYSTEM, Administrators and the service
    # account (Get-TokenProblem, the rule DoctorSmokeCA applies before it).
    # Anything else may have been read or chosen by another account (a local
    # user, or a previously configured service account), so it is replaced,
    # and the replacement is logged (never the value). A new token
    # file is created empty, handed to Administrators, locked down, and only
    # then written. The value comes from the verified venv interpreter and is
    # never printed or logged.
    $needToken = $true
    if ($null -ne $tokenAttributes) {
        $problem = Get-TokenProblem -Path $tokenFile -AllowedSids $tokenSids
        if ($problem) {
            Write-Output ("==> '" + $tokenFile + "' " + $problem + "; regenerating it")
            Remove-Item -LiteralPath $tokenFile -Force
        }
        else {
            $needToken = $false
            # Re-applied so that a changed service account can read it.
            Set-ProtectedAcl -Path $tokenFile -Grants $tokenGrants -AllowedSids $tokenSids
        }
    }
    if ($needToken) {
        Write-Output ("==> provisioning HTTP bearer token at '" + $tokenFile + "'")
        $gen = Invoke-Tool -Tool $python -Arguments '-I -c "import secrets; print(secrets.token_hex(32))"'
        # Its stdout IS the token: only stderr is echoed.
        Write-ToolOutput ([pscustomobject]@{ StdOut = ''; StdErr = $gen.StdErr })
        if ($gen.ExitCode -ne 0 -or -not $gen.StdOut) {
            Fail ("could not generate the HTTP bearer token (venv python secrets); exit code " + $gen.ExitCode)
        }
        # CreateNew never opens an entry that appeared since the checks
        # above, and the empty file is locked down before the value lands.
        [System.IO.File]::Open($tokenFile, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None).Dispose()
        Set-ProtectedAcl -Path $tokenFile -Grants $tokenGrants -AllowedSids $tokenSids
        Set-Content -LiteralPath $tokenFile -Value $gen.StdOut.Trim() -NoNewline -Encoding ascii
        if (-not (Test-Path -LiteralPath $tokenFile -PathType Leaf)) {
            Fail ("bearer token file was not created at '" + $tokenFile + "'")
        }
    }

    # --- create ---------------------------------------------------------------
    # Raw command line (CommandLineToArgvW semantics): the binPath value is
    # itself quoted and contains the quoted interpreter path, so its embedded
    # quotes are backslash-escaped.
    # A daemon under the SCM has no client on stdin, so the config's stdio
    # default would read EOF and exit 0 immediately (and the registered
    # failure recovery only fires on nonzero exit): the service must force
    # HTTP transport, exactly like the launchd plist and systemd unit. -I:
    # the service reads no PYTHON* variables, user site or working directory.
    $binPath = '"' + $python + '" -I -m universal_db_mcp serve --transport http'
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
    # services.exe reads ONE REG_MULTI_SZ value named Environment directly
    # under the service key, holding NAME=VALUE entries. Writing each variable
    # as its own value under an Environment SUBKEY (what this did) is ignored
    # by Windows while reg.exe still exits 0, so the action reported success
    # and the service started with no UDBMCP_CONFIG: a CONFIG_ERROR on a
    # stderr nobody reads, surfacing as "the service terminated unexpectedly".
    # reg.exe separates REG_MULTI_SZ entries with \0.
    $svcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $ServiceName
    $envValue = 'UDBMCP_CONFIG=' + (ConvertTo-ScArgument $ConfigPath) +
        '\0UDBMCP_HTTP_BEARER_TOKEN_FILE=' + (ConvertTo-ScArgument $tokenFile)
    $r = Invoke-Tool -Tool $script:RegExe -Arguments (
        'add "' + $svcKey + '" /v Environment /t REG_MULTI_SZ /d "' + $envValue + '" /f')
    Write-ToolOutput $r
    if ($r.ExitCode -ne 0) {
        Abort ("could not write the service Environment value under " + $svcKey +
               " (reg.exe exit code " + $r.ExitCode + ")")
    }

    # --- record the installed release --------------------------------------------
    # verify.ps1 gives the trusted verifier this record and refuses a bundle
    # that is an older release (anti-rollback). The wxs names a fixed place
    # under Program Files that no INSTALLFOLDER moves, outside everything the
    # MSI installs or removes, so the next major upgrade (which removes this
    # product's files first) still finds it; its folder is made when an
    # install elsewhere left it absent. Written last, once every step above
    # has succeeded, and after the record it replaces is copied to
    # <record>.previous for RollbackRemoveServiceCA, which restores it from
    # that copy once the marker is gone (see the top).
    if ($BundleDir) {
        $bundleManifest = Join-Path $BundleDir 'manifest.json'
        $recordDir = Split-Path -Parent $InstalledManifest
        if (-not (Test-Path -LiteralPath $recordDir -PathType Container)) {
            New-Item -ItemType Directory -Path $recordDir | Out-Null
        }
        $problem = Get-WriteProblem -Path $InstalledManifest
        if ($problem) {
            Abort ("refusing to record the installed release: '" + $InstalledManifest + "' " + $problem)
        }
        if (Test-Path -LiteralPath $InstalledManifest -PathType Leaf) {
            [System.IO.File]::Copy($InstalledManifest, $recordCopy, $true)
        }
        else {
            [System.IO.File]::WriteAllBytes($recordCopy, [byte[]]@())
        }
        if ($null -ne (Get-EntryAttributes -Path $recordKept)) {
            Remove-Item -LiteralPath $recordKept -Force
        }
        [System.IO.File]::Copy($bundleManifest, $InstalledManifest, $true)
        Write-Output ("==> recorded the installed release: " + $InstalledManifest)
    }

    Write-Output ("==> service '" + $ServiceName + "' registered (the installer does not auto-start it; the admin or the delivered gate script starts it)")
    exit 0
}
catch {
    if ($script:Created) { Remove-ServiceBestEffort -Name $ServiceName }
    Fail ("service registration failed: " + $_.Exception.Message)
}
