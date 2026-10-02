#
# UniversalDB MCP - MSI deferred custom action: the two folders the install
# writes into, checked before it writes anything.
#
# Contract (wired by scripts/package/build_msi.sh; see packaging/msi/udbmcp.wxs):
#   Deferred custom action CheckFoldersCA, Impersonate="no", Return="check",
#   sequenced Before="CreateFolders" on install and repair (NOT REMOVE).
#   This script is NOT installed: it runs before InstallFiles has put
#   anything in INSTALLFOLDER, and a script there is one the folder's ACL
#   decides who may edit. build_msi.sh embeds it (UTF-8, base64) as the
#   private property UdbmcpFolderCheck, and the action runs it as
#     powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
#       -Command "& ([scriptblock]::Create(<UTF-8 of base64 [UdbmcpFolderCheck]>))
#                 -InstallFolder '[INSTALLFOLDER]' -ConfigFolder '[ProgramDataUdbmcpDir]'"
#   (a Launch condition refuses an INSTALLFOLDER holding a single quote).
#   Exit code 0 = continue; any nonzero exit fails the action and rolls the
#   install back before CreateFolders, InstallFiles or any other action ran.
#
# Why, for each folder:
#   * C:\ProgramData\UniversalDB MCP: CreateFolders applies the folder's
#     protected DACL (PermissionEx) as LocalSystem, and InstallFiles writes
#     config.yaml into it. A local user can create that path before the
#     first install, as a junction to any folder: the DACL would land on the
#     junction's target. It must be a real directory, owned by SYSTEM,
#     Administrators or an administrator, that no one else may delete or
#     re-permission (a user who could would swap it for a junction after
#     this check). One that does not exist yet is created here with that
#     DACL, so there is never a moment it does not have it.
#   * INSTALLFOLDER: everything installed there runs as LocalSystem (the
#     custom action scripts, the venv the service runs, a .pth file in it).
#     The default, C:\Program Files\UniversalDB MCP, inherits a DACL that
#     lets only administrators write; a custom INSTALLFOLDER (D:\Apps\...)
#     usually inherits Authenticated Users Modify. So nobody but SYSTEM,
#     Administrators, TrustedInstaller or an administrator may hold any
#     write right on it, inherit-only grants included (they reach what the
#     install creates in it). One that does not exist yet is created with a
#     protected DACL: SYSTEM and Administrators Full Control, BUILTIN\Users
#     read and execute (a dedicated service account reads the venv).
#   * Every folder above either one: a non-administrator who may delete or
#     re-permission it, or delete entries in it, can move the folder below
#     away and put a junction in its place. Each must be a real directory
#     owned by SYSTEM, Administrators, TrustedInstaller or an administrator.
#
[CmdletBinding()]
param(
    [string]$InstallFolder = '',
    [string]$ConfigFolder = ''
)

$ErrorActionPreference = 'Stop'

$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:SidCreatorOwner = 'S-1-3-0'
# Direct members of the local Administrators group; looked up on first use.
$script:AdminMemberSids = $null
# FileSystemRights bits that let a principal change an entry (as in
# doctor.ps1): write or append its data (in a folder: create files or
# subfolders), write its attributes or extended attributes, delete it or
# entries in it, change its DACL or owner, and the generic all and write
# bits an inheritable ACE may carry.
$script:WriteRights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor
    0x10000000 -bor 0x40000000
# The bits that let a principal move a folder or what is in it: delete it,
# delete entries in it, change its DACL or owner, generic all.
$script:MoveRights = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000
$script:ConfigSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$script:InstallSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'

function Fail {
    param([string]$Message)
    Write-Output ("FOLDER-CHECK FAILED: " + $Message)
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

function Get-FolderProblem {
    # Why the install must not write through the folder $Path, or $null.
    # $Rights are the rights nobody else may hold on it; -Ancestor: a folder
    # above the one the install writes into, whose inherit-only ACEs reach
    # only the folders below (checked on their own), and which cannot be
    # deleted when it is a drive's root.
    param([string]$Path, [int64]$Rights, [switch]$Ancestor)
    $attributes = Get-EntryAttributes -Path $Path
    if ($null -eq $attributes) { return 'does not exist' }
    if ($attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return 'is a junction or symbolic link (a reparse point)'
    }
    if (-not ($attributes -band [System.IO.FileAttributes]::Directory)) { return 'is not a directory' }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $script:SidTrustedInstaller -and -not (Test-TrustedOwner -Sid $owner)) {
        return ('is owned by ' + $owner + ', not SYSTEM, Administrators, TrustedInstaller or an administrator')
    }
    if ($Ancestor -and -not [System.IO.Path]::GetDirectoryName($Path)) { $Rights = $Rights -band -bnot 0x10000 }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $sid -eq $script:SidTrustedInstaller -or $sid -eq $script:SidCreatorOwner -or (Test-TrustedOwner -Sid $sid)) {
            continue
        }
        if ($Ancestor -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) {
            continue
        }
        if ([int64]([System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights) -band $Rights) {
            return ('grants ' + $sid + ' ' + $rule.FileSystemRights)
        }
    }
    return $null
}

function New-ProtectedDirectory {
    # Creates the folder $Path with the DACL $Sddl. Windows PowerShell 5.1
    # (what the custom action runs) creates it with that DACL in one call,
    # so no one can change or replace it before the DACL is there. A
    # folder that appeared meanwhile is left as it is, and the caller's
    # check that follows refuses it unless it is safe.
    param([string]$Path, [string]$Sddl)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($Sddl)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [void][System.IO.Directory]::CreateDirectory($Path, $security)
    }
    else {
        # PowerShell 7 (manual runs): .NET has no such overload there.
        New-Item -ItemType Directory -Path $Path | Out-Null
        Set-Acl -LiteralPath $Path -AclObject $security
    }
}

function Assert-Folder {
    # Refuses $Path (the folder the install writes into, named $Label in
    # messages) unless every folder above it and the folder itself are
    # safe (see the header); creates it with $Sddl when it does not exist.
    param([string]$Path, [string]$Label, [string]$Sddl, [int64]$Rights, [string]$Remedy)
    if (-not $Path) { Fail ("no " + $Label + " given") }
    $Path = $Path.TrimEnd('\', '/')
    if (-not [System.IO.Path]::IsPathRooted($Path)) { Fail ($Label + " '" + $Path + "' is not an absolute path") }
    $ancestors = @()
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    while ($parent) {
        $ancestors = @($parent) + $ancestors
        $parent = [System.IO.Path]::GetDirectoryName($parent)
    }
    foreach ($ancestor in $ancestors) {
        if ($null -eq (Get-EntryAttributes -Path $ancestor)) { break }
        $problem = Get-FolderProblem -Path $ancestor -Rights $script:MoveRights -Ancestor
        if ($problem) {
            Fail ("refusing " + $Label + " '" + $Path + "': the folder above it '" + $ancestor + "' " + $problem +
                  '. Whoever may change that folder can move this one away and put a junction in its place, and' +
                  ' the install would write through it as LocalSystem; ' + $Remedy)
        }
    }
    if ($null -eq (Get-EntryAttributes -Path $Path)) {
        Write-Output ("==> creating " + $Label + " '" + $Path + "' with its protected DACL")
        New-ProtectedDirectory -Path $Path -Sddl $Sddl
    }
    $problem = Get-FolderProblem -Path $Path -Rights $Rights
    if ($problem) { Fail ("refusing " + $Label + " '" + $Path + "': it " + $problem + '. ' + $Remedy) }
    Write-Output ("==> " + $Label + " '" + $Path + "' is safe to install into")
}

try {
    Assert-Folder -Path $InstallFolder -Label 'INSTALLFOLDER' -Sddl $script:InstallSddl -Rights $script:WriteRights `
        -Remedy ('everything installed there runs as LocalSystem. Install into a folder only administrators can' +
                 ' change (the default is under C:\Program Files), or remove the other principals'' access and inspect' +
                 ' what the folder holds, then rerun the install')
    Assert-Folder -Path $ConfigFolder -Label 'the config folder' -Sddl $script:ConfigSddl -Rights $script:MoveRights `
        -Remedy ('a non-admin can pre-create entries under C:\ProgramData. Inspect it, then remove it (or the' +
                 ' junction) and rerun the install')
    exit 0
}
catch {
    Fail ("folder check failed: " + $_.Exception.Message)
}
