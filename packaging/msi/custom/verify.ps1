# MSI deferred custom action: verify the installed bundle BEFORE any payload runs.
#
# ---------------------------------------------------------------------------
# TRUST MODEL -- READ BEFORE "FIXING" THIS SCRIPT
#
# Windows mirrors the deb (packaging/deb/{preinst,postinst}) and the macOS pkg
# (packaging/pkg/{preinstall,postinstall}): an MSI is just a container, so a
# tampered MSI ships a tampered payload -- and a verifier shipped inside the
# payload would be a tampered verifier that prints PASSED. Therefore:
#
#   1. NOTHING in the installed bundle is executed before the ADMIN-INSTALLED
#      trusted verify_bundle.py --pubkey run has passed. This action runs the
#      verifier from the trust directory the MSI pins via CustomActionData
#      (C:\Program Files\udbmcp-trust -- the admin-write-only Program Files
#      tree, so a non-admin process cannot pre-create it) -- a path OUTSIDE
#      the bundle, populated by the admin from the same trusted channel that
#      delivered the MSI. The bundle is only ever READ (manifest, SHA256SUMS,
#      wheel hashes) by that verifier, never run.
#   2. The release public key is NEVER shipped inside the MSI (or any release
#      artifact). The admin distributes it out-of-band and points
#      UDBMCP_RELEASE_PUBKEY (machine scope) at it; without it this action
#      fails closed.
#   3. Fail closed on EVERY failure: missing prerequisites, wrong wiring, a
#      verifier exit code != 0, or missing proof-of-verification in its output
#      all exit nonzero. Scheduled with Return="check", that makes
#      msiexec roll the install back (never partially trusted).
#
# Defense in depth: if the trust directory, the verifier, the profiles
# registry, the public key, or the Python interpreter resolve INSIDE the
# bundle directory, refuse to proceed -- those are exactly the positions a
# tampered bundle can abuse (its own verifier/key would "verify" itself).
# The interpreter runs as LocalSystem before anything is verified, so it runs
# isolated (-I: no PYTHON* variables, user site or working directory on
# sys.path) and only from a folder nobody but SYSTEM, Administrators and
# TrustedInstaller can write, under one they alone can write (Python runs
# .pth and sitecustomize files and its standard library from there, and
# takes a pyvenv.cfg in either as a virtual environment).
#
# Anti-rollback: every older signed release still verifies, so the verifier
# also gets the installed release's manifest (--installed-manifest) and
# refuses a bundle that is an older release. RegisterServiceCA records that
# manifest at C:\Program Files\UniversalDB MCP\manifest.json (whatever
# INSTALLFOLDER is) once an install has succeeded, and the rollback of an
# install that fails later puts the previous record back; none there means
# a first install. An intended downgrade is asked for per msiexec run with
# UDBMCP_ALLOW_DOWNGRADE=1.
# ---------------------------------------------------------------------------
#
# SCHEDULING CONTRACT (for packaging/msi/udbmcp.wxs -- not authored here):
#   Deferred, impersonate=no (runs as LocalSystem), Return="check", and
#   scheduled AFTER the InstallFiles action (the bundle is on disk) and
#   BEFORE the venv/doctor/service custom actions (nothing may run payload
#   first). A rollback twin must be scheduled so a failed install is undone.
#   Pass parameters via CustomActionData as semicolon-separated KEY=VALUE:
#
#     BUNDLE_DIR=C:\Program Files\UniversalDB MCP\bundle   (required)
#     TRUST_DIR=C:\Program Files\udbmcp-trust  (ALWAYS passed by the wxs as
#         [ProgramFiles64Folder]udbmcp-trust -- the admin-write-only Program
#         Files tree, the analogue of the deb/pkg root-owned
#         /usr/local/lib/udbmcp-trust; never left to the fallback below)
#     PUBKEY=C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem (optional override)
#     PYTHON=C:\Program Files\Python312\python.exe         (optional override)
#     INSTALLED_MANIFEST=C:\Program Files\UniversalDB MCP\manifest.json  (passed
#         by the wxs; a standalone run without it reads the record beside
#         BUNDLE_DIR)
#     ALLOW_DOWNGRADE=[UDBMCP_ALLOW_DOWNGRADE]  (passed by the wxs, LAST; '1'
#         accepts an OLDER release than the installed one for this run only,
#         via the verifier's --allow-downgrade; empty or absent refuses it)
#
#   Values may contain spaces but not ';', a key may appear once, and none may
#   follow ALLOW_DOWNGRADE (the one public msiexec property in the data: a
#   key after it came from a ';' in its value). TRUST_DIR is always passed by the
#   wxs, so the machine-scope UDBMCP_TRUST_DIR below is a fallback for
#   STANDALONE/manual runs of this script only (e.g. the delivered gate's
#   tamper negative) -- it is NEVER read during an MSI install. The other
#   keys may be omitted and fall back to the machine-scope environment
#   variables below (set by the admin with setx /M BEFORE running msiexec --
#   a deferred action runs as LocalSystem and sees machine env only):
#
#     UDBMCP_TRUST_DIR        (standalone-only fallback; default C:\Program Files\udbmcp-trust)
#     UDBMCP_RELEASE_PUBKEY   (required, directly or via PUBKEY in CustomActionData)
#     UDBMCP_PYTHON           (optional interpreter override)
#
# TRUST BOOTSTRAP (admin, elevated prompt, from the trusted channel that
# delivered this MSI -- see docs/offline-deployment.md, 'Trust bootstrap'):
#
#     New-Item -ItemType Directory -Force 'C:\Program Files\udbmcp-trust\lib'
#     Copy-Item <trusted-channel>\verify_bundle.py 'C:\Program Files\udbmcp-trust\'
#     Copy-Item <trusted-channel>\profiles.py      'C:\Program Files\udbmcp-trust\'
#     New-Item -ItemType Directory -Force 'C:\Program Files\udbmcp-trust\keys'
#     Copy-Item <trusted-path>\udbmcp-release.pub.pem 'C:\Program Files\udbmcp-trust\keys\'
#     setx /M UDBMCP_RELEASE_PUBKEY "C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem"
#
# The key lives in the admin-write-only Program Files tree for the same reason
# as the verifier: a non-admin can pre-create any folder under C:\ProgramData.
# UPGRADING SITES: earlier releases documented the key under
# C:\ProgramData\universal-db-mcp\keys. A key anywhere outside Program Files
# is still used, with a WARNING under C:\ProgramData, but only while it and
# every folder above it are owned by SYSTEM, Administrators, TrustedInstaller
# or an administrator, none is a junction or symbolic link, the key grants
# nobody else write access and no folder above it lets anybody else delete
# or rename what is in it or change its permissions; otherwise this action
# fails closed and names the entry. Move the key (the lines above): a new
# owner or DACL on that entry would keep whatever its creator changed.
#
# The verifier checks the Ed25519 signature with its own RFC 8032 code
# (standard library only; it runs no external tool). Only a key in another
# encoding than a plain Ed25519 SubjectPublicKeyInfo PEM falls back to the
# `cryptography` package of the interpreter above; without it such a key
# FAILS (fail closed) with the verifier's canonical diagnostic. A verifier
# copy older than --installed-manifest is refused by name (OUTDATED) before
# it runs.
# ---------------------------------------------------------------------------

param(
    # Semicolon-separated KEY=VALUE pairs (the MSI CustomActionData string).
    [string]$CustomActionData = ''
)

# Fail closed on ANY cmdlet error: an unhandled terminating error falls into
# the catch block below, which exits nonzero (MSI rollback). There is no code
# path that exits 0 without the verifier having passed.
$ErrorActionPreference = 'Stop'

$script:LogPath = Join-Path $env:ProgramData 'universal-db-mcp\install-verify.log'
# Set by Initialize-LogDirectory once the log directory is proven safe; until
# then Write-Log writes to stdout only.
$script:LogReady = $false

# Well-known SIDs, never localized account names: LocalSystem,
# BUILTIN\Administrators and NT SERVICE\TrustedInstaller (the owner of the
# volume root and the Program Files tree).
$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Direct members of the local Administrators group; looked up on first use.
$script:AdminMemberSids = $null
# FileSystemRights bits that let a principal change an entry: write or
# append its data (in a folder: create files or subfolders), write its
# attributes or extended attributes, delete it or entries in it, change its
# DACL or owner, and the generic all and write bits an inheritable ACE may
# carry.
$script:WriteRights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor
    0x10000000 -bor 0x40000000
# The rights that matter on a folder a path only goes through (to the release
# key, or the log): deleting or renaming an entry in it (DeleteChild) or the
# folder itself (Delete), changing its DACL or owner, and the generic all
# bit. With one, its holder puts an entry of their own in place of the one
# the path names. Creating entries changes nothing already there, so the
# create rights every user has in C:\ProgramData do not count.
$script:ReplaceRights = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000
# Protected DACL for a directory this action creates under C:\ProgramData:
# nothing inherited (C:\ProgramData's inheritable ACEs let BUILTIN\Users read
# and create entries), SYSTEM and Administrators Full Control, and owned by
# Administrators whoever ran this (an elevated administrator's new folder may
# otherwise be owned by their own account).
$script:ProtectedDirSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

# Write a line to the persistent install log and to stdout (stdout reaches a
# manual powershell.exe run and the delivered test gate; deferred custom
# action output does not land in the msiexec /l*v log, hence the file).
function Write-Log {
    param([string]$Message)
    Write-Output $Message
    if (-not $script:LogReady) { return }
    try {
        Add-Content -LiteralPath $script:LogPath -Value $Message -Encoding UTF8
    } catch {
        # A broken log file must never mask a verification result; keep going
        # -- every decision below is made on the verifier itself, not the log.
        Write-Output "WARNING: cannot write $script:LogPath : $($_.Exception.Message)"
    }
}

# Print the canonical FAIL diagnostic and exit nonzero -> msiexec rolls back.
function Fail {
    param([string]$Message)
    Write-Log "FAIL: $Message"
    Write-Log "universal-db-mcp: installation ABORTED (fail closed); msiexec will roll back."
    exit 1
}

# True when $Sid may own an entry this LocalSystem action writes through or
# reads the release key from: SYSTEM, Administrators, TrustedInstaller, or a
# direct member of the local Administrators group (an elevated
# administrator's new files are owned by their own account where the
# "Default owner for objects created by members of the Administrators group"
# policy is "Object creator"). When the members cannot be listed (no
# LocalAccounts module, an orphaned SID in the group), only the fixed SIDs are
# trusted. In-process cmdlet: no external process runs before the verifier.
function Test-TrustedOwner {
    param([string]$Sid)
    if (@($script:SidSystem, $script:SidAdmins, $script:SidTrustedInstaller) -contains $Sid) { return $true }
    if ($null -eq $script:AdminMemberSids) {
        try {
            $script:AdminMemberSids = @(Get-LocalGroupMember -SID $script:SidAdmins | ForEach-Object { $_.SID.Value })
        } catch {
            $script:AdminMemberSids = @()
        }
    }
    return ($script:AdminMemberSids -contains $Sid)
}

# Why this LocalSystem action must not write through $Path (or read the
# release key through it), or $null when it may (including when nothing
# exists there yet). Any local user can create a folder under C:\ProgramData
# and owns what it creates, so an existing entry must be owned by SYSTEM,
# Administrators or an administrator and must not be a junction or symbolic
# link that redirects the write. GetAttributes reports the entry itself,
# never the target of a reparse point, so a dangling one is seen too.
function Get-WriteProblem {
    param([string]$Path)
    try {
        $attributes = [System.IO.File]::GetAttributes($Path)
    } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
        return $null
    }
    if ($attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return 'is a reparse point (junction or symbolic link)'
    }
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not (Test-TrustedOwner $owner)) {
        return "is owned by $owner, not SYSTEM, Administrators or an administrator"
    }
    return $null
}

# Why the existing entry $Path grants someone other than SYSTEM,
# Administrators, TrustedInstaller or an administrator one of the
# FileSystemRights in $Rights, or $null. Inherited ACEs count as much as the
# entry's own (a new owner keeps both); an inherit-only ACE (CREATOR OWNER on
# Program Files) grants nothing on the entry itself. In-process cmdlets only.
function Get-GrantProblem {
    param([string]$Path, [int64]$Rights)
    $rules = (Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $granted = [int64]([System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights)
        if (($granted -band $Rights) -and -not (Test-TrustedOwner $rule.IdentityReference.Value)) {
            return "grants $($rule.IdentityReference.Value) $($rule.FileSystemRights)"
        }
    }
    return $null
}

# The first entry below $Directory, at any depth, that Get-WriteProblem
# refuses or that grants anyone else a write-class right (Get-GrantProblem),
# as "'<path>' <problem>", or $null. A refused entry is never descended into,
# so no junction is followed. In-process cmdlets only.
function Get-TreeGrantProblem {
    param([string]$Directory)
    foreach ($entry in @(Get-ChildItem -LiteralPath $Directory -Force)) {
        $problem = Get-WriteProblem $entry.FullName
        if (-not $problem) { $problem = Get-GrantProblem $entry.FullName $script:WriteRights }
        if ($problem) { return "'$($entry.FullName)' $problem" }
        if ($entry.PSIsContainer) {
            $problem = Get-TreeGrantProblem $entry.FullName
            if ($problem) { return $problem }
        }
    }
    return $null
}

# Why the interpreter $Exe is not safe to run as LocalSystem before the
# bundle is verified, or $null. Whoever can change what Python loads at
# startup runs code in the verifier's process. Even under -I, CPython takes
# a pyvenv.cfg beside the interpreter or in the folder above it as a virtual
# environment and runs the .pth files of the prefix it names (a python.org
# install has none), so one there is refused, and the folder above is judged
# like the interpreter's own: nobody else may add one to either. Judged too:
# every file in the interpreter's folder (python.exe, the DLLs beside it,
# python312.zip, a ._pth file), and Lib (the standard library, and
# site-packages with its .pth files: -I does not skip site-packages) and
# DLLs at any depth. Each entry must pass Get-WriteProblem and grant no
# write-class right to anyone else (Get-GrantProblem).
function Get-InterpreterProblem {
    param([string]$Exe)
    $dir = Split-Path -Parent $Exe
    $parent = Split-Path -Parent $dir
    foreach ($folder in @($dir, $parent)) {
        if (-not $folder) { continue }
        $cfg = Join-Path $folder 'pyvenv.cfg'
        if (Test-Path -LiteralPath $cfg) {
            return "'$cfg' exists: Python reads it at startup, even under -I, and runs the .pth files of the prefix it names"
        }
    }
    $paths = @($parent, $dir, $Exe) | Where-Object { $_ }
    $paths += @(Get-ChildItem -LiteralPath $dir -File -Force | ForEach-Object { $_.FullName })
    $paths += @((Join-Path $dir 'Lib'), (Join-Path $dir 'DLLs'))
    foreach ($path in $paths) {
        $problem = Get-WriteProblem $path
        if (-not $problem -and (Test-Path -LiteralPath $path)) { $problem = Get-GrantProblem $path $script:WriteRights }
        if ($problem) { return "'$path' $problem" }
    }
    foreach ($name in @('Lib', 'DLLs')) {
        if (Test-Path -LiteralPath (Join-Path $dir $name) -PathType Container) {
            $problem = Get-TreeGrantProblem (Join-Path $dir $name)
            if ($problem) { return $problem }
        }
    }
    return $null
}

# The log lives under C:\ProgramData, where a non-admin can pre-create the
# directory (or a junction in its place) before an elevated msiexec run.
# Refuses a squatted directory (fail closed), creates a missing one, and
# gives it the protected DACL; only then is the log file checked, because
# until that DACL is in place a local user can still create it (and own it)
# in an existing directory. An existing directory is judged by its DACL too,
# before Set-Acl replaces it: that also recomputes what everything below it
# inherits, which would hide the access a user had to a release key kept
# there (earlier releases documented C:\ProgramData\universal-db-mcp\keys).
# Cmdlets and .NET only: no external process runs before the trusted verifier.
function Initialize-LogDirectory {
    $dir = Split-Path -Parent $script:LogPath
    $problem = Get-WriteProblem $dir
    if (-not $problem -and (Test-Path -LiteralPath $dir)) { $problem = Get-GrantProblem $dir $script:ReplaceRights }
    if ($problem) {
        Fail "refusing to write the install log: '$dir' $problem. A non-admin can pre-create entries under C:\ProgramData, and a new owner or DACL would keep whatever they changed in it: inspect it, then remove it with everything in it (a release key kept there is copied again from your trusted channel, to C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem) and rerun the install."
    }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        # No -Force: if something appeared there since the check above, this
        # throws and the catch-all aborts the install.
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($script:ProtectedDirSddl)
    Set-Acl -LiteralPath $dir -AclObject $security
    $problem = Get-WriteProblem $script:LogPath
    if ($problem) {
        Fail "refusing to write the install log: '$script:LogPath' $problem. A non-admin can pre-create entries under C:\ProgramData; inspect and remove it, then rerun the install."
    }
    $script:LogReady = $true
}

# Full paths (no short-name/relative trickery) for prefix containment checks.
function Real-Path {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

# True when $Candidate lives inside $Directory (case-insensitive, prefix on
# full paths with a separator boundary, so C:\Program Files\udbmcp-trust2 is
# NOT "inside" C:\Program Files\udbmcp-trust).
function Test-InsideDir {
    param([string]$Candidate, [string]$Directory)
    $c = (Real-Path $Candidate) + '\'
    $d = (Real-Path $Directory) + '\'
    return $c.ToLower().StartsWith($d.ToLower())
}

try {
    Initialize-LogDirectory
    Write-Log "==> universal-db-mcp MSI: verifying the installed bundle before any payload execution"

    # --- parse CustomActionData (semicolon-separated KEY=VALUE) -------------
    $data = @{}
    foreach ($pair in ($CustomActionData -split ';')) {
        $t = $pair.Trim()
        if ($t -eq '') { continue }
        $idx = $t.IndexOf('=')
        if ($idx -lt 1) {
            Fail "malformed CustomActionData pair '$t' (expected KEY=VALUE); this is a packaging bug in udbmcp.wxs, not an admin problem."
        }
        # ALLOW_DOWNGRADE carries a public msiexec property and the wxs passes
        # it last: a key after it came from a ';' in that value (a PUBKEY,
        # PYTHON or TRUST_DIR of the caller's choosing), and so may a key
        # named twice.
        $key = $t.Substring(0, $idx)
        if ($data.ContainsKey('ALLOW_DOWNGRADE')) {
            Fail "CustomActionData names $key after ALLOW_DOWNGRADE; a msiexec property value may not contain ';'."
        }
        if ($data.ContainsKey($key)) {
            Fail "CustomActionData names $key twice; a msiexec property value may not contain ';'."
        }
        $data[$key] = $t.Substring($idx + 1).Trim()
    }

    # --- resolve the installed bundle directory (required) -------------------
    if (-not $data.ContainsKey('BUNDLE_DIR') -or $data['BUNDLE_DIR'] -eq '') {
        Fail "BUNDLE_DIR missing from CustomActionData; the wxs must pass the installed bundle path (packaging bug), so verification cannot proceed."
    }
    $BundleDir = $data['BUNDLE_DIR']
    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        Fail "installed bundle directory not found at $BundleDir (wrong BUNDLE_DIR wiring in udbmcp.wxs?)."
    }

    # This script ships inside the MSI; if it is somehow running from inside
    # the bundle, the bundle supply chain already won -- refuse.
    if ($PSCommandPath -and (Test-InsideDir $PSCommandPath $BundleDir)) {
        Fail "this verifier is running from inside the bundle ($PSCommandPath); the verifier MUST come from the trust directory outside the bundle, never from the payload it would verify."
    }

    # --- resolve the trust directory ----------------------------------------
    $TrustDir = $data['TRUST_DIR']
    if (-not $TrustDir) { $TrustDir = $env:UDBMCP_TRUST_DIR }
    if (-not $TrustDir) { $TrustDir = Join-Path $env:ProgramFiles 'udbmcp-trust' }
    $Verifier = Join-Path $TrustDir 'verify_bundle.py'

    # A tampered bundle ships a verifier that prints PASSED: never accept a
    # trust directory (verifier, profiles registry) located inside the bundle.
    if (Test-InsideDir $TrustDir $BundleDir) {
        Fail "trust directory ($TrustDir) is inside the installed bundle ($BundleDir); a verifier from the payload proves nothing. Install the trusted tools outside the bundle at the path the MSI pins via CustomActionData: C:\Program Files\udbmcp-trust."
    }

    # --- prerequisite 1: the trusted verifier + its profiles registry -------
    # Admin-installed with a plain copy (no exec semantics on Windows); it is
    # run via python.exe, never directly.
    if (-not (Test-Path -LiteralPath $Verifier -PathType Leaf)) {
        Write-Log "trusted verifier not found at $Verifier."
        Write-Log "The MSI refuses to install without it: nothing in this package may run payload that has not passed verification by an admin-installed trusted verifier obtained outside the package/bundle supply chain."
        Write-Log "Bootstrap it from the same trusted channel that delivered this MSI (the MSI reads TRUST_DIR from CustomActionData, so provision exactly the path below):"
        Write-Log "    New-Item -ItemType Directory -Force '$TrustDir\lib'"
        Write-Log "    Copy-Item <trusted-channel>\verify_bundle.py '$TrustDir\'"
        Write-Log "    Copy-Item <trusted-channel>\profiles.py      '$TrustDir\'"
        Fail "trusted verifier not found at $Verifier; installation ABORTED (fail closed)."
    }
    # verify_bundle.py imports the target-profile registry from its own
    # directory or its lib/; missing registry = it fails closed, but a clear
    # prerequisite diagnostic here beats a Python traceback.
    $profilesPy = @(
        (Join-Path $TrustDir 'profiles.py'),
        (Join-Path $TrustDir 'lib\profiles.py')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $profilesPy) {
        Write-Log "profiles registry not found next to the verifier (checked '$TrustDir\profiles.py' and '$TrustDir\lib\profiles.py')."
        Write-Log "verify_bundle.py needs profiles.py (the target-profile registry) to check the bundle profile against this machine; it fails closed without it."
        Write-Log "    Copy-Item <trusted-channel>\profiles.py '$TrustDir\'"
        Fail "profiles.py not found in the trust directory ($TrustDir); installation ABORTED (fail closed)."
    }
    # The verification below passes --installed-manifest (anti-rollback). A
    # verifier that parses options ('--pubkey') but has no
    # '--installed-manifest' predates that check and would stop on the
    # unknown option with a bare usage error: name the fix instead. It is
    # read here, never run.
    $verifierText = [System.IO.File]::ReadAllText($Verifier)
    if ($verifierText.Contains('"--pubkey"') -and -not $verifierText.Contains('"--installed-manifest"')) {
        Fail "the trusted verifier at $Verifier is an OUTDATED copy (no --installed-manifest option): it cannot refuse a downgrade to an older release. Install verify_bundle.py and profiles.py from this release's trusted channel into $TrustDir, then re-run the installer."
    }

    # --- prerequisite 2: the release public key (NEVER shipped in the MSI) ---
    $PubKey = $data['PUBKEY']
    if (-not $PubKey) { $PubKey = $env:UDBMCP_RELEASE_PUBKEY }
    if (-not $PubKey) {
        Write-Log "FAIL: no release public key: set UDBMCP_RELEASE_PUBKEY machine-wide (or pass PUBKEY in CustomActionData) to the release public key PEM path;"
        Write-Log "      the key is NEVER shipped inside the MSI: the release administrator distributes it out-of-band, and an unsigned/unverified bundle must never be installed."
        Write-Log "    setx /M UDBMCP_RELEASE_PUBKEY `"C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem`""
        Write-Log "    (then copy the key to that path from your trusted channel)"
        Fail "release public key not configured (UDBMCP_RELEASE_PUBKEY); installation ABORTED (fail closed)."
    }
    if (-not (Test-Path -LiteralPath $PubKey -PathType Leaf)) {
        Write-Log "release public key not found at $PubKey."
        Write-Log "The key is distributed out-of-band by the release administrator; install it before running msiexec:"
        Write-Log "    New-Item -ItemType Directory -Force (Split-Path '$PubKey')"
        Write-Log "    Copy-Item <trusted-path>\udbmcp-release.pub.pem '$PubKey'"
        Fail "release public key not found at $PubKey; installation ABORTED (fail closed)."
    }
    # Defense in depth: a pubkey inside the bundle is attacker-controlled
    # (a tampered bundle would ship its own key and "verify" against it).
    if (Test-InsideDir $PubKey $BundleDir) {
        Fail "release public key ($PubKey) is inside the installed bundle ($BundleDir); a key shipped with the payload authenticates nothing. Install the key outside the bundle (set UDBMCP_RELEASE_PUBKEY machine-wide)."
    }
    # Outside the admin-write-only Program Files tree a key may sit in a
    # folder a local user created (and so owns) and swapped it in: earlier
    # releases documented C:\ProgramData\universal-db-mcp\keys. Such a key is
    # used only when it and every folder above it, up to the volume root, are
    # owned by SYSTEM, Administrators, TrustedInstaller or an administrator,
    # none is a junction or symbolic link, the key grants nobody else a
    # write-class right, and no folder above it lets anybody else replace
    # what is in it ($script:ReplaceRights). Each folder on disk is checked,
    # not the path's spelling: the legacy "All Users" profile link, an 8.3
    # name or a \\?\ prefix all lead into C:\ProgramData.
    if (-not ($env:ProgramFiles -and (Test-InsideDir $PubKey $env:ProgramFiles))) {
        $keyPath = Real-Path $PubKey
        $rights = $script:WriteRights
        while ($keyPath) {
            $problem = Get-WriteProblem $keyPath
            if (-not $problem) { $problem = Get-GrantProblem $keyPath $rights }
            if ($problem) {
                Fail "release public key: '$keyPath' $problem. A non-admin can pre-create folders outside Program Files (under C:\ProgramData, for one), and a new owner or DACL would keep whatever they changed: copy the key from your trusted channel to C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem and point UDBMCP_RELEASE_PUBKEY at it (setx /M)."
            }
            $rights = $script:ReplaceRights
            $parent = Split-Path -Parent $keyPath
            if ($parent -eq $keyPath) { break }
            $keyPath = $parent
        }
    }
    if (Test-InsideDir $PubKey $env:ProgramData) {
        Write-Log "WARNING: the release public key is under $env:ProgramData ($PubKey), where a non-admin can pre-create folders; move it to C:\Program Files\udbmcp-trust\keys\udbmcp-release.pub.pem and point UDBMCP_RELEASE_PUBKEY at it (setx /M)."
    }

    # --- prerequisite 3: the PER-MACHINE python interpreter -------------------
    # The bundle's own python (venv/python.exe) may not run anything yet --
    # including the verifier. The wxs LaunchCondition guarantees a per-machine
    # python.org CPython 3.12 (HKLM\SOFTWARE\Python\PythonCore\3.12, PEP 514);
    # resolution is pinned to EXACTLY that registry value and never via py.exe
    # or PATH: py.exe prefers a per-user (HKCU) installation over the
    # per-machine one, and a local non-admin can register one. Python startup
    # auto-executes user site-packages (.pth files), so an unpinned resolver
    # would let a non-admin run arbitrary code HERE, as LocalSystem, BEFORE the
    # bundle is verified -- the verify-before-execute gate itself would be
    # attacker-controlled. The LaunchCondition only proves a per-machine 3.12
    # EXISTS; this block pins execution to that same hive, and an HKCU-only
    # machine fails closed with the bootstrap diagnostic below.
    $pyExe = $null
    # -I: this interpreter runs as LocalSystem before anything is verified.
    $pyArgs = @('-I')
    $candidate = $data['PYTHON']
    if (-not $candidate) { $candidate = $env:UDBMCP_PYTHON }
    if ($candidate) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Fail "configured python interpreter not found at $candidate (PYTHON in CustomActionData or UDBMCP_PYTHON)."
        }
        $pyExe = $candidate
    }
    if (-not $pyExe) {
        $pyHive = 'HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath'
        if (Test-Path -LiteralPath $pyHive) {
            $pyProps = Get-ItemProperty -LiteralPath $pyHive
            # PEP 514: ExecutablePath when present, else the key's default
            # value (the install directory) + python.exe.
            $regCandidate = $pyProps.ExecutablePath
            if (-not $regCandidate) {
                $pyInstallPath = $pyProps.'(default)'
                if ($pyInstallPath) { $regCandidate = Join-Path $pyInstallPath 'python.exe' }
            }
            if ($regCandidate -and (Test-Path -LiteralPath $regCandidate -PathType Leaf)) {
                $pyExe = $regCandidate
            }
        }
    }
    if (-not $pyExe) {
        Write-Log "no PER-MACHINE CPython 3.12 found (HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath)."
        Write-Log "A per-user (HKCU) interpreter is deliberately NOT accepted: py.exe would prefer it and a local non-admin can register one, so executing it here -- as LocalSystem, before the bundle is verified -- would run attacker-controlled code."
        Write-Log "Install python.org CPython 3.12 per-machine (the MSI launch condition requires it), or pass PYTHON in CustomActionData / set UDBMCP_PYTHON machine-wide."
        Fail "no python interpreter available to run the trusted verifier; installation ABORTED (fail closed)."
    }
    # The interpreter must not come from the bundle either (no venv exists
    # yet, but refuse a misconfigured path regardless).
    if (Test-InsideDir $pyExe $BundleDir) {
        Fail "python interpreter ($pyExe) is inside the installed bundle; bundle payload (including its python) may not execute before verification passes."
    }
    # Registry-resolved or an administrator's override alike: whoever can
    # write what the interpreter loads runs code as LocalSystem here.
    $problem = Get-InterpreterProblem $pyExe
    if ($problem) {
        Fail "python interpreter: $problem. This action runs that interpreter as LocalSystem before the bundle is verified, and Python loads code from its own tree (the DLLs beside it, .pth and sitecustomize files, the standard library) and takes a pyvenv.cfg beside it or one folder up as a virtual environment: install python.org CPython 3.12 for all users under C:\Program Files (a virtual environment's interpreter is refused). Removing that access now would keep whatever was already written there. An owner counts as an administrator here only as SYSTEM, Administrators, TrustedInstaller or a direct member of the local Administrators group that Get-LocalGroupMember lists: if the owner named above is an administrator through a domain group (for example after an elevated pip install into this interpreter), add that account to the local Administrators group itself and rerun the install."
    }
    # Prove the registry-resolved interpreter is really CPython 3.12 BEFORE the
    # trusted verifier is executed with it: a stale/wrong HKLM registration
    # must fail closed with a clear diagnostic, not crash inside the verifier
    # (the admin-provided PYTHON/UDBMCP_PYTHON override above is a deliberate
    # administrator decision and is not second-guessed here). EAP is relaxed
    # around the native invocation for the same Windows PowerShell 5.1
    # stderr-escalation reason documented at the verifier run below.
    if (-not $candidate) {
        $prevProbeEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $pyExe -I -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' 1> $null 2> $null
            $pyProbeExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevProbeEap
        }
        if ($pyProbeExit -ne 0) {
            Fail "the per-machine interpreter registered at HKLM\SOFTWARE\Python\PythonCore\3.12 ($pyExe) is not CPython 3.12.x (the wheelhouse is built for cp312); installation ABORTED (fail closed)."
        }
    }

    # --- anti-rollback: the release installed now ----------------------------
    # RegisterServiceCA records it where the wxs says (INSTALLED_MANIFEST, a
    # fixed path under Program Files that no INSTALLFOLDER moves) once an
    # install has succeeded (none there: a first install); a standalone run
    # without it reads the record beside the bundle directory. That place is
    # not an MSI file, so a major upgrade, which removes the previous product
    # before this action runs, keeps it. Whoever can rewrite the record can
    # lower it. The override is per msiexec run (UDBMCP_ALLOW_DOWNGRADE=1,
    # passed as ALLOW_DOWNGRADE in CustomActionData), never a machine-wide
    # variable, which would stay on for every later install.
    $InstalledManifest = $data['INSTALLED_MANIFEST']
    if (-not $InstalledManifest) { $InstalledManifest = Join-Path (Split-Path -Parent (Real-Path $BundleDir)) 'manifest.json' }
    $problem = Get-WriteProblem $InstalledManifest
    if (-not $problem -and (Test-Path -LiteralPath $InstalledManifest)) {
        $problem = Get-GrantProblem $InstalledManifest $script:WriteRights
    }
    if ($problem) {
        Fail "the installed release record '$InstalledManifest' $problem; the MSI writes it after a successful install. Inspect and remove it, then rerun the install."
    }
    $rollbackArgs = @('--installed-manifest', $InstalledManifest)
    if ($data['ALLOW_DOWNGRADE'] -eq '1') {
        $rollbackArgs += '--allow-downgrade'
        Write-Log "WARNING: ALLOW_DOWNGRADE=1 (msiexec UDBMCP_ALLOW_DOWNGRADE=1): an OLDER release than the installed one is accepted for this install only."
    } elseif ($data['ALLOW_DOWNGRADE']) {
        Fail "ALLOW_DOWNGRADE='$($data['ALLOW_DOWNGRADE'])' is not understood; pass UDBMCP_ALLOW_DOWNGRADE=1 to msiexec to accept an older release, or leave it unset."
    }

    Write-Log "  bundle:   $BundleDir"
    Write-Log "  verifier: $Verifier"
    Write-Log "  profiles: $profilesPy"
    Write-Log "  pubkey:   $PubKey"
    Write-Log "  python:   $pyExe $($pyArgs -join ' ')"
    Write-Log "  installed: $InstalledManifest"

    # --- run the ONE trusted verifier against the installed bundle ----------
    # Reading the bundle is safe; executing it is not, and nothing here runs
    # any of it. Output goes to files (not the pipeline), and the invocation
    # runs with $ErrorActionPreference temporarily relaxed: Windows
    # PowerShell 5.1 turns native-command stderr into error records that a
    # 'Stop' preference would escalate into a spurious terminating error.
    # The verifier's exit code + output remain the ONLY decision inputs.
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $pyExe @pyArgs $Verifier --bundle $BundleDir --pubkey $PubKey @rollbackArgs 1> $outFile 2> $errFile
        $verifierExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
        $verifierOut = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
        $verifierErr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $verifierOut) { $verifierOut = '' }
    if ($null -eq $verifierErr) { $verifierErr = '' }

    foreach ($line in ($verifierOut -split "`r?`n")) { if ($line.Trim()) { Write-Log "  verify: $line" } }
    foreach ($line in ($verifierErr -split "`r?`n")) { if ($line.Trim()) { Write-Log "  verify(err): $line" } }

    # --- fail closed on EVERY non-passing outcome ----------------------------
    # The verifier's canonical diagnostics are its "FAIL: ..." lines and
    # "bundle verification FAILED; do not install" -- forwarded verbatim above
    # and into $script:LogPath for the post-mortem. Exit code alone is not
    # trusted: success requires exit 0 AND the verifier's explicit
    # "bundle verification PASSED" AND no FAIL line (a verifier that exits 0
    # without proof is treated as failed). An older release gets its own
    # diagnostic, with the remedy for an intended downgrade.
    if ($verifierExit -ne 0 -and ($verifierOut + $verifierErr) -match '(?m)^FAIL: rollback refused') {
        Fail "this MSI carries an OLDER release than the one installed (see 'verify:' lines and $script:LogPath); installation ABORTED. To downgrade on purpose, run msiexec with UDBMCP_ALLOW_DOWNGRADE=1 for that one install (a standalone run: ALLOW_DOWNGRADE=1 in -CustomActionData)."
    }
    if ($verifierExit -ne 0) {
        Fail "trusted verifier exited $verifierExit (see 'verify:' lines and $script:LogPath); the canonical diagnostic is included above. The bundle is untrusted: installation ABORTED."
    }
    if (($verifierOut + $verifierErr) -match '(?m)^FAIL:') {
        Fail "trusted verifier reported FAIL (see above); the bundle is untrusted: installation ABORTED."
    }
    if (($verifierOut + $verifierErr) -notmatch 'bundle verification PASSED') {
        Fail "trusted verifier exited 0 but did not print 'bundle verification PASSED'; without explicit proof of verification the bundle is treated as untrusted: installation ABORTED."
    }

    Write-Log "==> universal-db-mcp: installed bundle verified (integrity + authenticity) via the admin-installed trusted verifier; payload may now be used by the subsequent custom actions."

    # The ONLY exit-0 path: verification passed with proof.
    exit 0
} catch {
    Fail "unexpected error during bundle verification: $($_.Exception.Message)"
}
