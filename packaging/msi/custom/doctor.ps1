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
#       -ServiceAccount "[UDBMCP_SERVICE_ACCOUNT]"
#       -RegisteredAccount "[UDBMCPREGISTEREDACCOUNT]"
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
# (e.g. from an elevated PowerShell session when debugging an install):
#   UDBMCP_VENV_DIR, UDBMCP_CONFIG, UDBMCP_BUNDLE_MANIFEST,
#   UDBMCP_SERVICE_ACCOUNT (resolved as in service.ps1: see -ServiceAccount)
#
# CHANGES BEFORE THE PAYLOAD RUNS: a bearer token RegisterServiceCA would
# replace is removed (the payload doctor refuses it as fatal), logs\ is made
# when missing, and a logs\ granting an earlier service account write access
# gets the folder's protected DACL back; RegisterServiceCA then provisions
# the token and grants the service account Modify on logs\. This action has
# no rollback twin, so an account change it was not asked for (no account
# given, and the service signs in with a password or logs\ shows it ran as
# another account) is refused before any of that.
#
# PLACEHOLDER TEMPLATES: the config installed to -ConfigPath is the staged
# template (config-templates/config.template.yaml), which intentionally
# carries PLACEHOLDER_DIR / PLACEHOLDER_DB tokens for the admin to resolve.
# A verbatim doctor run against those tokens would fail closed (missing
# parent directories, missing sqlite data file) on every fresh install and
# roll the install back, so when the installed config still contains
# placeholders this action derives a smoke config that resolves them to real
# paths under the config directory, materializes those paths, and validates
# the derived config. Any unrecognized PLACEHOLDER_ token fails the install
# (fail closed) rather than being validated half-substituted.
#
[CmdletBinding()]
param(
    [string]$VenvDir,
    [string]$ConfigPath,
    [string]$BundleManifest,
    # The account RegisterServiceCA registers the service under, resolved as
    # service.ps1 resolves it: this, else UDBMCP_SERVICE_ACCOUNT, else
    # -RegisteredAccount, else LocalSystem. Entries below the config folder's
    # logs\ may be owned by it, since it writes them, and the bearer token
    # may grant it read access. A given account's predecessor loses its
    # token and logs\ grant (see below); one not given is checked first.
    [string]$ServiceAccount = '',
    # The account the service is registered under when the install starts
    # (the wxs reads the service key's ObjectName before anything runs, so a
    # major upgrade passes it too); empty: none.
    [string]$RegisteredAccount = ''
)

$ErrorActionPreference = 'Stop'

# Well-known SIDs, never localized account names: LocalSystem and
# BUILTIN\Administrators.
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
# Protected DACL for a directory this action creates under C:\ProgramData:
# nothing inherited (C:\ProgramData's inheritable ACEs let BUILTIN\Users read
# and create entries), SYSTEM and Administrators Full Control, and owned by
# Administrators whoever ran this (an elevated administrator's new folder may
# otherwise be owned by their own account).
$script:ProtectedDirSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

function Fail {
    param([string]$Message)
    Write-Output ("DOCTOR-ACTION FAILED: " + $Message)
    exit 1
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
    # shows, or $null; with $GrantedSid, that account if logs\ grants it
    # write access, or $null. Only a logs\ an install made counts: a
    # directory, not a junction or symbolic link, owned by SYSTEM,
    # Administrators or an administrator (the walk refuses any other).
    param([string]$LogsDir, [string]$ServiceSid, [string]$GrantedSid = '')
    $attributes = Get-EntryAttributes -Path $LogsDir
    if ($null -eq $attributes -or ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        -not ($attributes -band [System.IO.FileAttributes]::Directory)) { return $null }
    $acl = Get-Acl -LiteralPath $LogsDir
    if (-not (Test-TrustedOwner -Sid $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value)) { return $null }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $sid -eq $ServiceSid -or ($GrantedSid -and $sid -ne $GrantedSid) -or (Test-TrustedOwner -Sid $sid) -or
            -not (Test-AccountSid -Sid $sid)) { continue }
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
    # cannot be read back. An account other than LocalSystem is refused
    # unless logs\ in $ConfigDir grants it write access, as the registration
    # action did when it registered the service under it: the MSI reads the
    # account into a public property, which msiexec lets anybody set when
    # the service key is absent, so only that grant tells the account the
    # service ran as from one named on a command line. It is refused too
    # when logs\ grants another account write access: the service ran as
    # that account, and would lose its token and logs\ although nobody named
    # another one.
    param([string]$Account, [string]$ServiceSid, [string]$ConfigDir, [switch]$Password)
    $remedy = ('pass UDBMCP_SERVICE_ACCOUNT to msiexec (from an elevated prompt), naming the account to keep' +
               ' or another one, and rerun the install')
    if ((Test-PasswordAccount -Account $Account) -and -not $Password) {
        return ("the service is registered under '" + $Account + "', which signs in with a password this install" +
                ' cannot carry over (it registers the service again); ' + $remedy +
                ', then set that password again (services.msc or sc.exe config)')
    }
    $logsDir = Join-Path $ConfigDir 'logs'
    if ($ServiceSid -and -not (Get-EarlierAccountSid -LogsDir $logsDir -GrantedSid $ServiceSid)) {
        return ("this install was told the service is registered under '" + $Account + "', but '" + $logsDir +
                "' does not grant that account write access, as the install that registered it does; " + $remedy)
    }
    $earlier = Get-EarlierAccountSid -LogsDir $logsDir -ServiceSid $ServiceSid
    if ($earlier) {
        return ("'" + $logsDir + "' grants " + $earlier + ' write access: the service ran as that account, and' +
                " this install, given no account, would take its token and logs\ away and use '" + $Account +
                "'; " + $remedy)
    }
    return $null
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
    # path (NeverOverwrite), so on fresh installs the file at -ConfigPath is
    # the template content the admin will run with. On upgrades it may be the
    # admin's own edited configuration. Both are validated: verbatim when
    # they contain no placeholder tokens, via a derived smoke config when
    # they still do (see the header notes).
    if (-not $ConfigPath) { $ConfigPath = $env:UDBMCP_CONFIG }
    if (-not $ConfigPath) { Fail "no config to validate: pass -ConfigPath or set UDBMCP_CONFIG" }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Fail ("config not found at '" + $ConfigPath + "'")
    }

    # --- refuse a squatted config folder or config ----------------------------
    # doctor runs below as LocalSystem with this config, which names files it
    # opens and may create (audit log, metadata cache, sqlite databases). Any
    # local user can create a folder under C:\ProgramData before the first
    # install and owns what it creates; the MSI's folder DACL names no owner,
    # so such a folder stays theirs, and NeverOverwrite keeps a config.yaml
    # found in it. Both are refused before the config is read, and so is
    # every entry below the folder that a non-administrator owns or that is a
    # junction or symbolic link: on an upgrade the folder carried
    # C:\ProgramData's inheritable ACEs for the previous version's lifetime,
    # so any local user could create entries in it and in its subfolders (an
    # audit directory doctor opens files in, whose owner can later turn it
    # into a junction; a metadata cache its owner can rewrite). An entry
    # whose own ACEs let anybody else write it is refused too (a new owner
    # keeps them). The one other owner accepted is the service account, for
    # what it wrote in logs\ (its audit log, the Windows default
    # audit_path), and it alone may be granted write access there (on logs\
    # itself, an earlier service account's Modify too: it is reset below).
    $configDir = Split-Path -Parent $ConfigPath
    foreach ($path in @($configDir, $ConfigPath)) {
        $problem = Get-WriteProblem $path
        if ($problem) {
            Fail ("refusing '" + $path + "': it " + $problem +
                  '. A non-admin can pre-create entries under C:\ProgramData, and a new owner or DACL would keep' +
                  ' whatever its creator put in it; inspect it, then remove it and rerun the install')
        }
    }
    # The service account, resolved as service.ps1 resolves it: given
    # (-ServiceAccount, else UDBMCP_SERVICE_ACCOUNT), else the one the
    # service is registered under, else LocalSystem. One this install was
    # not given is judged before anything changes: this action has no
    # rollback twin, and the changes below would take a running service's
    # token and logs\ away.
    if (-not $ServiceAccount) { $ServiceAccount = $env:UDBMCP_SERVICE_ACCOUNT }
    $accountGiven = [bool]$ServiceAccount
    if (-not $accountGiven) { $ServiceAccount = $RegisteredAccount }
    if (-not $ServiceAccount) { $ServiceAccount = 'LocalSystem' }
    $serviceSid = Get-ServiceAccountSid -Account $ServiceAccount
    if (-not $accountGiven) {
        $problem = Get-ImplicitAccountProblem -Account $ServiceAccount -ServiceSid $serviceSid -ConfigDir $configDir `
            -Password:([bool]$env:UDBMCP_SERVICE_PASSWORD)
        if ($problem) { Fail $problem }
        if ($RegisteredAccount) {
            Write-Output ("==> no service account given: keeping '" + $ServiceAccount +
                          "', the account the service is registered under")
        }
    }
    # The bearer token is judged on its own below. Whoever owns a token, its
    # value may be known to whoever made it, so an owner change would only
    # launder a planted value: only an entry that is not a plain file is
    # refused, as service.ps1 refuses it.
    $tokenFile = Join-Path $configDir 'http-token'
    $tokenAttributes = Get-EntryAttributes -Path $tokenFile
    if ($null -ne $tokenAttributes -and
        ($tokenAttributes -band ([System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Directory))) {
        Fail ("'" + $tokenFile + "' is a directory, junction or symbolic link, not a token file; inspect and remove it" +
              ' (the install provisions a new token), then rerun the install')
    }
    $found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token') -LogsSid $serviceSid
    if ($found) {
        Fail ("refusing '" + $configDir + "': '" + $found.Path + "' in it " + $found.Problem + '. ' + (Get-TreeRemedy $found))
    }
    $logsDir = Join-Path $configDir 'logs'
    $logsAttributes = Get-EntryAttributes -Path $logsDir
    if ($null -ne $logsAttributes -and -not ($logsAttributes -band [System.IO.FileAttributes]::Directory)) {
        Fail ("'" + $logsDir + "' is not a directory; inspect it, then move it out of this folder and rerun the install")
    }

    # --- the bearer token: only one RegisterServiceCA would keep ---------------
    # The payload doctor below validates the service's token whenever it
    # exists, and refuses one that another account owns or can read as
    # fatal: the install rolled back before RegisterServiceCA could replace
    # it, and the owner it named was the only lead left (an owner change
    # launders a planted value). The token is judged here by service.ps1's
    # own rule, and one RegisterServiceCA would replace is removed, never
    # re-owned: RegisterServiceCA provisions a new one. Only after every
    # refusal above, and before any payload runs.
    $tokenSids = @($script:SidSystem, $script:SidAdmins)
    if ($serviceSid) { $tokenSids += $serviceSid }
    if ($null -ne $tokenAttributes) {
        $problem = Get-TokenProblem -Path $tokenFile -AllowedSids $tokenSids
        if ($problem) {
            Write-Output ("==> '" + $tokenFile + "' " + $problem +
                          '; removing it before doctor runs (RegisterServiceCA provisions a new one)')
            Remove-Item -LiteralPath $tokenFile -Force
        }
    }

    # --- logs\: made here when it is missing ----------------------------------
    # The service's state folder (the Windows default audit_path): doctor
    # treats a missing parent of an audit_path or metadata_cache_path under
    # it as fatal. It is made here, once the checks above refused a logs\
    # that is a junction, a symbolic link or a file, not by the MSI:
    # CreateFolders would apply its DACL before any check, through such a
    # junction. A logs\ that still grants an earlier service account write
    # access (the account changed) gets the folder's protected DACL back
    # before any payload runs; RegisterServiceCA grants the service account
    # Modify again. Either way the folder is walked again once the DACL is
    # in place.
    $protectLogs = $false
    if ($null -eq $logsAttributes) {
        # No -Force: if something appeared there since the walk above, this
        # throws and the install is aborted.
        New-Item -ItemType Directory -Path $logsDir | Out-Null
        $protectLogs = $true
    }
    elseif (Get-WriteProblem -Path $logsDir -WriterSid $serviceSid) {
        Write-Output ("==> '" + $logsDir + "' grants a service account this install does not run as write access;" +
                      ' resetting its DACL (RegisterServiceCA grants the service account Modify again)')
        $protectLogs = $true
    }
    if ($protectLogs) {
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetSecurityDescriptorSddlForm($script:ProtectedDirSddl)
        Set-Acl -LiteralPath $logsDir -AclObject $security
        $found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token') -LogsSid $serviceSid
        if ($found) {
            Fail ("refusing '" + $configDir + "': '" + $found.Path + "' in it " + $found.Problem + '. ' + (Get-TreeRemedy $found -Appeared))
        }
    }

    # --- resolve placeholders into a smoke-passing config ---------------------
    # The template ships with PLACEHOLDER_DIR / PLACEHOLDER_DB tokens; doctor
    # treats their unresolved forms as fatal (missing audit/metadata-cache
    # parent directories, missing sqlite data file). Resolve them against a
    # dedicated smoke directory next to the installed config, which this
    # action (running as LocalSystem) guarantees exists, and materialize the
    # sqlite data file with the already-verified venv interpreter.
    # That directory is under C:\ProgramData, where a non-admin can
    # pre-create folders (and own them) or plant junctions: a squatted smoke
    # directory is refused (fail closed), a missing one is created, and it
    # gets the protected DACL before the entries in it are checked and
    # written. Every entry is checked, not only the two files named here: an
    # older doctor.ps1 made the directory with the DACL inherited from
    # C:\ProgramData, which let any local user create entries in it, and the
    # smoke config points the metadata cache and the audit log there.
    $doctorConfigPath = $ConfigPath
    $configContent = [System.IO.File]::ReadAllText($ConfigPath)
    if ($configContent -match 'PLACEHOLDER_') {
        $smokeDir = Join-Path $configDir 'smoke'
        $demoDb = Join-Path $smokeDir 'finlink-demo.db'
        $smokeConfigPath = Join-Path $smokeDir 'config.smoke.yaml'
        $problem = Get-WriteProblem $smokeDir
        if ($problem) {
            Fail ("refusing to write the smoke config: '" + $smokeDir + "' " + $problem +
                  ". A non-admin can pre-create entries under C:\ProgramData; inspect and remove it, then rerun the install")
        }
        if (-not (Test-Path -LiteralPath $smokeDir -PathType Container)) {
            # No -Force: if something appeared there since the check above,
            # this throws and the install is aborted.
            New-Item -ItemType Directory -Path $smokeDir | Out-Null
        }
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetSecurityDescriptorSddlForm($script:ProtectedDirSddl)
        Set-Acl -LiteralPath $smokeDir -AclObject $security
        foreach ($entry in @(Get-ChildItem -LiteralPath $smokeDir -Force)) {
            $problem = Get-WriteProblem $entry.FullName
            if ($problem) {
                Fail ("refusing to write the smoke config: '" + $entry.FullName + "' " + $problem +
                      "; inspect and remove it, then rerun the install")
            }
        }
        if (-not (Test-Path -LiteralPath $demoDb -PathType Leaf)) {
            Write-Output ("==> creating smoke demo database: " + $demoDb)
            # Parenthesized: the comma operator binds tighter than +, and an
            # unparenthesized concatenation would split the -c program.
            $createArgs = @(
                '-I',
                '-c',
                ("import sqlite3; con = sqlite3.connect(r'" + $demoDb + "'); con.execute('CREATE TABLE IF NOT EXISTS smoke_probe (id INTEGER PRIMARY KEY)'); con.commit(); con.close()")
            )
            $dbCode = Invoke-Payload -Python $python -PythonArgs $createArgs
            if ($dbCode -ne 0) {
                Fail ("could not create the smoke demo database at '" + $demoDb + "' (exit code " + $dbCode + ")")
            }
        }
        $smokeConfig = $configContent.Replace('PLACEHOLDER_DIR', $smokeDir).Replace('PLACEHOLDER_DB', $demoDb)
        if ($smokeConfig -match 'PLACEHOLDER_') {
            Fail "config contains an unrecognized PLACEHOLDER_ token; refusing to validate a half-substituted config"
        }
        [System.IO.File]::WriteAllText($smokeConfigPath, $smokeConfig)
        $doctorConfigPath = $smokeConfigPath
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
    # -I, as for every LocalSystem python run here: no PYTHON* variables, no
    # user site and no working directory on sys.path.
    Write-Output ("==> running doctor against config: " + $doctorConfigPath)
    $doctorArgs = @('-I', '-m', 'universal_db_mcp', 'doctor', '--config', $doctorConfigPath)
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
