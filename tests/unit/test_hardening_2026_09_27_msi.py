"""Hardening 2026-09-27, MSI group: the ProgramData writes of the elevated
Windows custom actions.

F15: RegisterServiceCA (service.ps1, LocalSystem) wrote the HTTP bearer token,
the listener's only credential, into C:\\ProgramData\\UniversalDB MCP with the
DACL inherited from C:\\ProgramData, which gives BUILTIN\\Users read access and
lets any local user create entries there (and own them). Any local user could
read the token, or plant one before the service registration adopted it. A
user could also pre-create the whole folder with a config.yaml of their
choosing: the folder SDDL's owner (O:BA) handed such a folder to
Administrators before any custom action ran, and NeverOverwrite kept the
planted config for the LocalSystem doctor run and service.

F94: VerifyBundleCA (verify.ps1) and DoctorSmokeCA (doctor.ps1) created and
wrote C:\\ProgramData\\universal-db-mcp\\install-verify.log and
C:\\ProgramData\\UniversalDB MCP\\smoke with no reparse-point or owner check,
and the documented release public key location sat in the same squattable
tree.

Running the scripts under pwsh (Linux, Windows-only pieces stubbed) also
showed that the code paths carrying these fixes could not run at all: the
delivered gate did not parse ("$LASTEXITCODE: $err"), and the doctor
placeholder branch threw on Split-Path -LiteralPath -Parent and split its
sqlite -c program into several arguments. Those are pinned here too.

There is no Windows host in the test environment. The first half of this file
is static checks over the authored XML and the PowerShell code lines
(comments stripped), in the style of tests/unit/test_msi_custom_actions.py;
the second half runs the real scripts under pwsh with the Windows APIs
stubbed, wherever pwsh exists (see "executed under pwsh" below).
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess  # noqa: S404 - runs the custom actions under test only
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - first-party repo file, no DTD/entities
from collections.abc import Mapping
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
WXS = PROJECT / "packaging" / "msi" / "udbmcp.wxs"
CUSTOM = PROJECT / "packaging" / "msi" / "custom"
SERVICE_PS1 = CUSTOM / "service.ps1"
VERIFY_PS1 = CUSTOM / "verify.ps1"
DOCTOR_PS1 = CUSTOM / "doctor.ps1"
UNINSTALL_PS1 = CUSTOM / "uninstall.ps1"
VENV_PS1 = CUSTOM / "venv.ps1"
GATE_PS1 = PROJECT / "scripts" / "test_package_msi.ps1"
BUILD_MSI = PROJECT / "scripts" / "package" / "build_msi.sh"
VERIFY_BUNDLE_PY = PROJECT / "scripts" / "verify_bundle.py"

_XML_COMMENT = re.compile(r"<!--.*?-->", re.S)

# Well-known SIDs: LocalSystem, BUILTIN\Administrators, and the broad
# principals that must never be granted access to the token or its folder.
SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
BROAD_SIDS = ("S-1-5-32-545", "S-1-5-11", "S-1-1-0")  # BU, AU, WD
BROAD_SDDL_ALIASES = ("BU", "AU", "WD", "IU")


def _code(path: Path) -> str:
    """PowerShell code lines only: backtick continuations joined, comment-only
    lines dropped, so trust-model prose can neither satisfy nor defeat a check."""
    text = re.sub(r"`\r?\n", " ", path.read_text(encoding="utf-8"))
    return "\n".join(ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))


def _without_strings(code: str) -> str:
    """*code* with its string literals emptied (a diagnostic may name icacls)."""
    return re.sub(r'"(?:`.|[^"`])*"|\'(?:\'\'|[^\'])*\'', '""', code)


def _function(code: str, name: str) -> str:
    """Body of ``function <name>`` up to the next function definition."""
    start = code.index(f"function {name}")
    nxt = code.find("\nfunction ", start + 1)
    indented = code.find("\n    function ", start + 1)
    ends = [i for i in (nxt, indented) if i != -1]
    return code[start : min(ends)] if ends else code[start:]


def _main_body(code: str) -> str:
    """The script body after its last function definition."""
    last = code.rindex("\nfunction ")
    return code[code.index("\ntry {", last) :]


def _wxs_root() -> ET.Element:
    return ET.fromstring(_XML_COMMENT.sub("", WXS.read_text(encoding="utf-8")))  # noqa: S314


def _local(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


# --------------------------------------------------------------------- F15 --


def test_f15_wxs_gives_the_programdata_folder_a_protected_sddl() -> None:
    root = _wxs_root()
    folder = next(el for el in root.iter() if _local(el) == "Directory" and el.get("Id") == "ProgramDataUdbmcpDir")
    perms = [el for el in folder.iter() if _local(el) == "PermissionEx"]
    assert perms, "ProgramDataUdbmcpDir needs a PermissionEx (MsiLockPermissionsEx) with a protected SDDL"
    sddl = perms[0].get("Sddl") or ""
    dacl = sddl.split("D:", 1)[1] if "D:" in sddl else ""
    assert dacl.startswith("P"), f"the DACL must be protected (D:P...), got {sddl!r}"
    assert "(A;OICI;FA;;;SY)" in dacl and "(A;OICI;FA;;;BA)" in dacl, sddl
    for alias in BROAD_SDDL_ALIASES:
        assert f";;;{alias})" not in dacl, f"the folder DACL must grant nothing to {alias}: {sddl!r}"
    for sid in BROAD_SIDS:
        assert sid not in dacl, f"the folder DACL must grant nothing to {sid}: {sddl!r}"

    # The permission sits on a CreateFolder of its OWN component: the config
    # component is NeverOverwrite, so on an upgrade that keeps config.yaml it
    # is not reinstalled and would never re-apply the DACL.
    create_folder = next(el for el in folder.iter() if _local(el) == "CreateFolder" and perms[0] in list(el))
    component = next(el for el in folder.iter() if _local(el) == "Component" and create_folder in list(el))
    assert component.get("NeverOverwrite") != "yes"
    guid = component.get("Guid") or ""
    assert re.fullmatch(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", guid), (
        "a component whose key path is a directory cannot use an auto-generated GUID"
    )
    refs = {el.get("Id") for el in root.iter() if _local(el) == "ComponentRef"}
    assert component.get("Id") in refs, "the folder ACL component must be part of the Main feature"
    package = next(el for el in root.iter() if _local(el) == "Package")
    assert int(package.get("InstallerVersion") or 0) >= 500, "MsiLockPermissionsEx needs Windows Installer 5.0"


def test_f15_service_protects_the_token_file_before_the_value_is_written() -> None:
    code = _code(SERVICE_PS1)
    protect = _function(code, "Set-ProtectedAcl")
    assert "/inheritance:r" in protect and "/grant:r" in protect, protect
    assert "Get-AclProblem" in protect, "the applied DACL must be verified, not assumed"

    body = _main_body(code)
    provision = body[body.index("if ($needToken) {") :]
    create = provision.index("[System.IO.FileMode]::CreateNew")
    lock = provision.index("Set-ProtectedAcl -Path $tokenFile")
    write = provision.index("Set-Content -LiteralPath $tokenFile")
    assert create < lock < write, "create the file empty, lock it down, THEN write the value"
    assert body.count("Set-Content -LiteralPath $tokenFile") == 1
    assert "'*' + $script:SidSystem + ':F *' + $script:SidAdmins + ':F'" in body
    assert f"$script:SidSystem = '{SID_SYSTEM}'" in code and f"$script:SidAdmins = '{SID_ADMINS}'" in code
    for sink in ("Add-Content -LiteralPath $tokenFile", "WriteAllText($tokenFile"):
        assert sink not in body


def test_f15_service_adopts_an_existing_token_only_when_owner_and_acl_are_safe() -> None:
    code = _code(SERVICE_PS1)
    write_problem = _function(code, "Get-WriteProblem")
    assert "ReparsePoint" in write_problem and "GetOwner" in write_problem
    assert "-and -not (Test-TrustedOwner -Sid $owner)) {" in write_problem
    acl_problem = _function(code, "Get-AclProblem")
    assert "AreAccessRulesProtected" in acl_problem
    # The token's owner is held to SYSTEM or Administrators, not to any
    # administrator: the LocalSystem service's own startup check refuses a
    # secret file anyone else owns.
    assert "if ($owner -ne $script:SidSystem -and $owner -ne $script:SidAdmins) {" in acl_problem

    token_problem = _function(code, "Get-TokenProblem")
    assert "Get-WriteProblem -Path $Path" in token_problem and "Get-AclProblem -Path $Path" in token_problem

    body = _main_body(code)
    adopt = body.index("$needToken = $false")
    decision = body[body.index("if ($null -ne $tokenAttributes) {\n        $problem = ") : adopt]
    assert "Get-TokenProblem -Path $tokenFile" in decision
    assert "Remove-Item -LiteralPath $tokenFile" in decision, "an untrusted token is replaced, not kept"
    # The old keep-if-non-empty shortcut is gone.
    assert "if ($existing -and $existing.Trim()) { $needToken = $false }" not in code


def test_f15_service_regenerates_a_token_any_other_account_can_read() -> None:
    # A kept token only had its grants re-applied with icacls /grant:r, which
    # replaces the ACEs of the SIDs it names and nothing else: the read ACE
    # of a previously configured service account survived a change of
    # account (to LocalSystem, or to another account), and that account
    # knows the value. The DACL is now checked against an ALLOWLIST (SYSTEM,
    # Administrators, the current service account), so such a token is
    # regenerated, the same as one granting BUILTIN\Users.
    code = _code(SERVICE_PS1)
    acl_problem = _function(code, "Get-AclProblem")
    assert "[string[]]$AllowedSids" in acl_problem
    assert "$AllowedSids -notcontains $rule.IdentityReference.Value" in acl_problem
    assert "BroadSids" not in code, "a denylist of broad principals misses every other account"

    body = _main_body(code)
    assert "$tokenSids = @($script:SidSystem, $script:SidAdmins)" in body
    grant = body.index("$tokenSids += $serviceSid")
    assert body.index("$serviceSid = Get-ServiceAccountSid -Account $ServiceAccount") < grant
    assert "Get-TokenProblem -Path $tokenFile -AllowedSids $tokenSids" in body
    assert "Get-AclProblem -Path $Path -AllowedSids $AllowedSids" in _function(code, "Get-TokenProblem")
    assert body.count("Set-ProtectedAcl -Path $tokenFile -Grants $tokenGrants -AllowedSids $tokenSids") == 2
    assert "Get-AclProblem -Path $Path -AllowedSids $AllowedSids" in _function(code, "Set-ProtectedAcl")


def test_f15_service_refuses_a_squatted_config_before_changing_anything() -> None:
    # With the MSI no longer handing a pre-created folder to Administrators,
    # a squatted folder reaches this action still owned by its creator. The
    # config.yaml in it (NeverOverwrite keeps one found there) is what the
    # LocalSystem service reads: it names the token file, the listener
    # address, the audit log and the databases. A config owned by a
    # non-admin, or one that is a junction or symbolic link, is refused, and
    # so is any junction or symbolic link directly in the folder (a LocalSystem
    # write through it lands wherever its creator pointed it).
    body = _main_body(_code(SERVICE_PS1))
    loop = body.index("foreach ($path in @($configDir, $ConfigPath)) {")
    assert re.match(
        r"foreach \(\$path in @\(\$configDir, \$ConfigPath\)\) \{\s*\n\s*\$problem = Get-WriteProblem -Path \$path\s*\n"
        r"\s*if \(\$problem\) \{\s*\n\s*Fail ",
        body[loop:],
    ), body[loop : loop + 300]
    scan = body.index("$found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token')")
    assert re.match(r"\$found = Get-TreeProblem [^\n]*\n\s*if \(\$found\) \{\s*\n\s*Fail ", body[scan:])
    first_change = min(
        body.index("Stop-ExistingService -Name $ServiceName"),
        body.index("$r = Invoke-Tool -Tool $script:IcaclsExe"),
        body.index("Set-Acl -LiteralPath $configDir"),
    )
    assert loop < scan < first_change
    assert "Get-WriteProblem -Path $configDir\n" not in body, "the folder is checked in the loop, with the config"


def test_f15_service_checks_the_token_entry_before_removing_the_old_service() -> None:
    # The fail-closed check on an http-token that is a directory, junction or
    # symbolic link ran after the old service was stopped and deleted (now:
    # stopped, to be updated in place), so the action failed without it.
    body = _main_body(_code(SERVICE_PS1))
    entry = body.index("$tokenAttributes = Get-EntryAttributes -Path $tokenFile")
    refuse = body.index("is a directory, junction or symbolic link, not a token file")
    remove = body.index("Stop-ExistingService -Name $ServiceName")
    assert entry < refuse < remove
    assert body.index("$tokenFile = Join-Path $configDir 'http-token'") < entry


def test_f15_doctor_refuses_a_squatted_config_before_reading_it() -> None:
    # DoctorSmokeCA runs before RegisterServiceCA and executes payload as
    # LocalSystem with the config it is given (audit log, metadata cache and
    # sqlite paths in it are opened, some created). The folder and config
    # checks ran only in the PLACEHOLDER_ branch, so an edited planted config
    # skipped every check, and the config file itself was never checked.
    body = _main_body(_code(DOCTOR_PS1))
    loop = body.index("foreach ($path in @($configDir, $ConfigPath)) {")
    assert re.match(
        r"foreach \(\$path in @\(\$configDir, \$ConfigPath\)\) \{\s*\n\s*\$problem = Get-WriteProblem \$path\s*\n"
        r"\s*if \(\$problem\) \{\s*\n\s*Fail ",
        body[loop:],
    ), body[loop : loop + 300]
    scan = body.index("$found = Get-TreeProblem -Directory $configDir")
    assert re.match(r"\$found = Get-TreeProblem [^\n]*\n\s*if \(\$found\) \{\s*\n\s*Fail ", body[scan:])
    read = body.index("ReadAllText($ConfigPath)")
    branch = body.index("if ($configContent -match 'PLACEHOLDER_') {")
    assert loop < scan < read < branch < body.index("Invoke-Payload")


def test_f15_wxs_folder_sddl_names_no_owner_or_group() -> None:
    # MsiLockPermissionsEx applies an owner and group named in the SDDL
    # during CreateFolders, before any custom action runs. "O:BAG:SY" handed
    # a folder a non-admin had pre-created to Administrators, so the custom
    # actions' folder-owner refusal could never fire in the MSI flow; and the
    # new DACL does not propagate to entries already in the folder, so the
    # squatter's config.yaml (kept by NeverOverwrite) stayed theirs.
    root = _wxs_root()
    folder = next(el for el in root.iter() if _local(el) == "Directory" and el.get("Id") == "ProgramDataUdbmcpDir")
    sddl = next(el for el in folder.iter() if _local(el) == "PermissionEx").get("Sddl") or ""
    assert sddl.startswith("D:"), sddl
    assert "O:" not in sddl and "G:" not in sddl, sddl


def test_f15_service_grants_a_dedicated_account_by_sid() -> None:
    code = _code(SERVICE_PS1)
    sid = _function(code, "Get-ServiceAccountSid")
    assert "'S-1-5-19'" in sid and "'S-1-5-20'" in sid
    assert "[System.Security.Principal.SecurityIdentifier]" in sid
    body = _main_body(code)
    assert "':(OI)(CI)RX'" in body and "':R'" in body
    # icacls grants name SIDs (*S-...), never localized account names.
    for grant in re.findall(r"/grant:r ([^'\"]*)", code):
        assert "Administrators" not in grant and "SYSTEM" not in grant and "Users" not in grant, grant


def test_f15_acceptance_comment_is_gone_and_the_token_is_never_echoed() -> None:
    text = SERVICE_PS1.read_text(encoding="utf-8")
    assert "same reality as the audit file" not in text
    assert "ACLs inherit from the ProgramData" not in text
    # The generator's stdout IS the token value.
    assert "Write-ToolOutput $gen" not in _code(SERVICE_PS1)


def test_f15_gate_asserts_the_post_install_acl() -> None:
    code = _code(GATE_PS1)
    helper = _function(code, "Get-SecretAclProblem")
    helper = helper[: helper.index("\n    }\n")]  # the last function nested in the gate's try block
    assert "GetOwner" in helper and "AreAccessRulesProtected" in helper
    assert f"'{SID_SYSTEM}'" in helper and f"'{SID_ADMINS}'" in helper
    # an allowlist, as in service.ps1: a denylist of broad principals passed
    # an ACE for any other account (a user, a stale service account)
    assert "$AllowedSids -notcontains $rule.IdentityReference.Value" in helper
    for sid in BROAD_SIDS:
        assert f"'{sid}'" not in helper
    assert f"$SecretSids = @('{SID_SYSTEM}', '{SID_ADMINS}')" in code
    assert "$installedService.StartName" in code and "$SecretSids += " in code
    assert "Get-SecretAclProblem -Path $ProgramDataDir -AllowedSids $SecretSids" in code
    assert code.count("Get-SecretAclProblem -Path $TokenFile -AllowedSids $SecretSids") == 2
    # every entry below the folder: its DACL must have reached them
    walk = code.index("foreach ($entry in @(Get-ChildItem -LiteralPath $ProgramDataDir -Force -Recurse)) {")
    assert "Get-SecretAclProblem -Path $entry.FullName -AllowedSids $SecretSids -DaclOnly" in code[walk : walk + 300]
    assert "'programdata_acl'" in code
    # evaluated before the service check, which cannot pass yet on Windows
    assert code.index("'programdata_acl'") < code.index("'service_running'")


def test_f15_gate_has_a_squatted_token_negative() -> None:
    code = _code(GATE_PS1)
    assert "'token_squat_refused'" in code
    squat = code[code.index("$SquatValue = ") :]
    # a token planted by a non-admin: owned by BUILTIN\Users, holding a known value
    assert "/setowner *S-1-5-32-545" in squat
    assert "WriteAllText($TokenFile, $SquatValue)" in squat
    # the shipped registration action runs again
    assert "Join-Path $InstallRoot 'scripts\\service.ps1'" in code
    assert "-File $ServiceScript" in squat
    # adopting the planted value after a successful run fails the gate
    assert re.search(r"-eq \$SquatValue\)\s*\{\s*\n\s*Stop-Gate 'token_squat_refused'", squat)


def test_f15_gate_has_a_squatted_folder_negative() -> None:
    # The whole-folder squat, as the MSI meets it: the folder (and then only
    # config.yaml) owned by BUILTIN\Users when the ACL component is
    # installed. REINSTALL=ALL reinstalls every component, so CreateFolders
    # applies MsiLockPermissionsEx exactly as a first install does, and the
    # admin's own folder is moved aside instead of uninstalling (uninstall
    # deletes config.yaml).
    code = _code(GATE_PS1)
    assert "'folder_squat_refused'" in code and "'folder_squat_cleanup_reinstalled'" in code
    squat = code[code.index("$SquatBackup = ") :]
    assert "Rename-Item -LiteralPath $ProgramDataDir -NewName" in squat
    assert "REINSTALL=ALL REINSTALLMODE=omus" in squat
    assert "/setowner *S-1-5-32-545" in squat
    assert "'folder'" in squat and "'config'" in squat, "both the folder and a planted config.yaml are exercised"
    # the planted config is the shipped template: only its owner is wrong
    assert "Join-Path $BundleDir 'config-templates\\config.template.yaml'" in squat
    # a successful install over a squatted folder or config fails the gate
    assert re.search(r"-eq 0 -or \$\w+\.ExitCode -eq 3010\) \{\s*\n\s*Stop-Check 'folder_squat_refused'", squat), (
        "an install that adopts a squatted folder or config must fail the gate"
    )
    # the planted folder is removed and the admin's folder restored on every unwind
    fin = squat[squat.index("} finally {") :]
    assert "Remove-Item -LiteralPath $ProgramDataDir -Recurse -Force" in fin
    assert "Rename-Item -LiteralPath $SquatBackup -NewName" in fin
    # evaluated after the per-user negative restored the machine
    assert code.index("'peruser_cleanup_reverified'") < code.index("'folder_squat_refused'")


# --------------------------------------------------------------------- F94 --


def test_f94_gate_default_pubkey_is_under_program_files() -> None:
    code = _code(GATE_PS1)
    defaults = re.findall(r"if \(-not \$PubKey\) \{ \$PubKey = ([^}]*)\}", code)
    fallback = [d for d in defaults if "GetEnvironmentVariable" not in d]
    assert fallback, defaults
    assert "ProgramData" not in fallback[0]
    assert "Join-Path $MsiTrustDir 'keys\\udbmcp-release.pub.pem'" in fallback[0]
    assert "$MsiTrustDir = Join-Path $env:ProgramFiles 'udbmcp-trust'" in code


def test_f94_verify_documents_the_pubkey_under_program_files() -> None:
    text = VERIFY_PS1.read_text(encoding="utf-8")
    # The earlier location is named only in comments (the upgrade note, the
    # check's rationale); every instruction points at Program Files.
    old = [ln.strip() for ln in text.splitlines() if "universal-db-mcp\\keys" in ln]
    assert old and all(ln.startswith("#") for ln in old), old
    assert "C:\\Program Files\\udbmcp-trust\\keys\\udbmcp-release.pub.pem" in text
    for ln in text.splitlines():
        if re.search(r"setx /M UDBMCP_RELEASE_PUBKEY|New-Item .*keys|Copy-Item .*pub\.pem", ln):
            assert "ProgramData" not in ln, ln


def test_f94_verify_refuses_a_squattable_pubkey_under_programdata() -> None:
    # Sites that followed the earlier docs have UDBMCP_RELEASE_PUBKEY set
    # machine-wide to C:\ProgramData\universal-db-mcp\keys\..., a tree any
    # local user may have pre-created (and so own). A key outside Program
    # Files is accepted only when it and every folder above it, up to the
    # volume root, pass the owner and reparse-point check. The walk used to
    # start only for a path spelled under %ProgramData%: the legacy "All
    # Users" profile link, an 8.3 name or another world-creatable root
    # skipped it.
    body = _main_body(_code(VERIFY_PS1))
    guard = body.index("if (-not ($env:ProgramFiles -and (Test-InsideDir $PubKey $env:ProgramFiles))) {")
    walk = body[guard : body.index("\n    }\n", guard)]
    assert "$keyPath = Real-Path $PubKey" in walk and "while ($keyPath) {" in walk
    assert "$parent = Split-Path -Parent $keyPath" in walk and "if ($parent -eq $keyPath) { break }" in walk
    assert "$keyPath.Length -gt" not in walk, "no stop at C:\\ProgramData"
    assert re.search(
        r"\$problem = Get-WriteProblem \$keyPath\s*\n\s*if \(-not \$problem\) \{ \$problem = Get-GrantProblem [^\n]*\n"
        r"\s*if \(\$problem\) \{\s*\n\s*Fail ",
        walk,
    ), walk
    assert "setowner" not in walk and "C:\\Program Files\\udbmcp-trust\\keys" in walk
    warning = body.index("if (Test-InsideDir $PubKey $env:ProgramData) {")
    assert guard < warning and "WARNING" in body[warning : body.index("\n    }\n", warning)]
    assert body.index("if (-not (Test-Path -LiteralPath $PubKey -PathType Leaf)) {") < guard
    assert warning < body.index("--pubkey $PubKey")
    # TrustedInstaller owns the volume root and the Program Files tree.
    trusted = _function(_code(VERIFY_PS1), "Test-TrustedOwner")
    assert "$script:SidTrustedInstaller" in trusted
    assert "$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'" in (
        _code(VERIFY_PS1)
    )


def test_f94_verify_standalone_trust_dir_fallback_is_under_program_files() -> None:
    # The wxs always passes TRUST_DIR, but a manual elevated run of verify.ps1
    # without it executed the verifier from C:\ProgramData\udbmcp-trust, a
    # folder any local user can pre-create. The executed Python twin of
    # verify.ps1 mirrors the fallback.
    code = _code(VERIFY_PS1)
    assert "if (-not $TrustDir) { $TrustDir = Join-Path $env:ProgramFiles 'udbmcp-trust' }" in code
    assert "ProgramData\\udbmcp-trust" not in VERIFY_PS1.read_text(encoding="utf-8")
    twin = (PROJECT / "tests" / "unit" / "test_msi_ca_executed_failclosed.py").read_text(encoding="utf-8")
    assert '"ProgramData", "udbmcp-trust"' not in twin
    assert 'os.environ.get("ProgramFiles"' in twin


def test_f94_verify_checks_the_log_directory_before_creating_or_writing_it() -> None:
    code = _code(VERIFY_PS1)
    problem = _function(code, "Get-WriteProblem")
    assert "ReparsePoint" in problem and "GetOwner" in problem
    assert "if (-not (Test-TrustedOwner $owner)) {" in problem

    init = _function(code, "Initialize-LogDirectory")
    refuse = r"\s*\n\s*if \(\$problem\) \{\s*\n\s*Fail "
    check_dir = init.index("$problem = Get-WriteProblem $dir")
    # (an existing directory's DACL is judged in between: test_r1_*)
    judged = r"\s*\n\s*if \(-not \$problem -and \(Test-Path -LiteralPath \$dir\)\) \{ \$problem = Get-GrantProblem "
    judged += r"[^\n]*"
    assert re.match(r"\$problem = Get-WriteProblem \$dir" + judged + refuse, init[check_dir:])
    create = init.index("New-Item -ItemType Directory -Path $dir")
    protect = init.index("Set-Acl -LiteralPath $dir")
    # The log FILE is checked only once the DACL is on the directory: checked
    # earlier, a local user could still plant it (and own it) in between, and
    # LocalSystem would then append every log line to the user's file.
    check_log = init.index("$problem = Get-WriteProblem $script:LogPath")
    assert re.match(r"\$problem = Get-WriteProblem \$script:LogPath" + refuse, init[check_log:])
    ready = init.index("$script:LogReady = $true")
    assert check_dir < create < protect < check_log < ready
    assert "-Force" not in init[create : init.index("\n", create)], "no -Force: a racing creator must abort"

    write_log = _function(code, "Write-Log")
    assert "if (-not $script:LogReady) { return }" in write_log
    assert write_log.index("$script:LogReady") < write_log.index("Add-Content")
    assert "New-Item" not in write_log, "Write-Log no longer creates the directory itself"
    assert "$script:LogReady = $false" in code

    body = _main_body(code)
    assert body.split("\n")[2].strip() == "Initialize-LogDirectory", "the log is secured before anything else"


def test_f94_verify_runs_no_external_process_for_the_log_directory() -> None:
    # test_msi_packaging pins the trusted verifier as the first external
    # process (after the interpreter's version probe): the log directory is
    # secured with cmdlets and .NET only.
    code = _without_strings(_code(VERIFY_PS1))
    for name in ("Initialize-LogDirectory", "Get-WriteProblem", "Test-TrustedOwner"):
        body = _function(code, name)
        assert not re.search(r"(?<!\w)&\s", body), body
        assert "icacls" not in body and "Invoke-Tool" not in body and "Start-Process" not in body, body


def test_f94_doctor_checks_the_smoke_directory_before_creating_or_writing_it() -> None:
    code = _code(DOCTOR_PS1)
    problem = _function(code, "Get-WriteProblem")
    assert "ReparsePoint" in problem and "GetOwner" in problem
    assert "-and -not (Test-TrustedOwner -Sid $owner)) {" in problem

    body = _main_body(code)
    configs = body.index("foreach ($path in @($configDir, $ConfigPath)) {")
    smoke = body.index("$problem = Get-WriteProblem $smokeDir")
    assert re.match(r"\$problem = Get-WriteProblem \$smokeDir\s*\n\s*if \(\$problem\) \{\s*\n\s*Fail ", body[smoke:])
    create = body.index("New-Item -ItemType Directory -Path $smokeDir")
    protect = body.index("Set-Acl -LiteralPath $smokeDir")
    entries = body.index("foreach ($entry in @(Get-ChildItem -LiteralPath $smokeDir -Force)) {")
    db = body.index("Invoke-Payload -Python $python -PythonArgs $createArgs")
    cfg = body.index("WriteAllText($smokeConfigPath")
    assert configs < smoke < create < protect < entries < db < cfg
    assert "-Force" not in body[create : body.index("\n", create)]


def test_f94_doctor_checks_every_entry_in_the_smoke_directory() -> None:
    # Only finlink-demo.db and config.smoke.yaml were checked. On an upgrade
    # smoke\ was made by the previous doctor.ps1 with the DACL inherited from
    # C:\ProgramData, which let any local user create entries in it; the
    # smoke config points the metadata cache and the audit log there, and
    # sqlite writes journals next to the database, so a planted
    # metadata-cache.sqlite or audit.jsonl (a symbolic link, or a file its
    # planter owns) was opened read-write by the LocalSystem doctor run.
    # Every entry is checked, after the protected DACL is in place.
    body = _main_body(_code(DOCTOR_PS1))
    entries = body.index("foreach ($entry in @(Get-ChildItem -LiteralPath $smokeDir -Force)) {")
    assert re.match(
        r"foreach \(\$entry in @\(Get-ChildItem -LiteralPath \$smokeDir -Force\)\) \{\s*\n"
        r"\s*\$problem = Get-WriteProblem \$entry\.FullName\s*\n\s*if \(\$problem\) \{\s*\n\s*Fail ",
        body[entries:],
    ), body[entries : entries + 300]
    assert "foreach ($path in @($demoDb, $smokeConfigPath))" not in body, "named files only: planted ones were missed"


def test_f94_custom_actions_apply_the_same_owned_protected_directory_sddl() -> None:
    # The directories the actions secure name Administrators as owner: left to
    # the creator's default owner, a manual run by an administrator whose new
    # objects are their own left smoke\ or the log directory owned by that
    # account. (The MSI folder's PermissionEx deliberately names no owner, so
    # a squatted folder still shows who made it; see the wxs test above.)
    for path in (VERIFY_PS1, DOCTOR_PS1, SERVICE_PS1):
        code = _code(path)
        assert f"$script:ProtectedDirSddl = '{PROTECTED_DIR_SDDL}'" in code, path.name
        assert "SetSecurityDescriptorSddlForm($script:ProtectedDirSddl)" in code, path.name
        assert f"$script:SidSystem = '{SID_SYSTEM}'" in code and f"$script:SidAdmins = '{SID_ADMINS}'" in code


def test_f15_trusted_owners_are_admins_and_a_failed_lookup_trusts_only_the_fixed_sids() -> None:
    # An owner check that accepted SYSTEM and Administrators only refused
    # every file an administrator's own account owns (the "Object creator"
    # default owner): a manual run left objects the next install refused.
    # Direct members of the local Administrators group are trusted; when they
    # cannot be listed, nobody beyond the fixed SIDs is.
    for path in (SERVICE_PS1, DOCTOR_PS1, VERIFY_PS1):
        trusted = _function(_code(path), "Test-TrustedOwner")
        lookup = trusted.index("$script:AdminMemberSids = @(Get-LocalGroupMember -SID $script:SidAdmins")
        assert trusted.rindex("try {", 0, lookup) < lookup < trusted.index("$script:AdminMemberSids = @()"), path.name
        assert "return ($script:AdminMemberSids -contains $Sid)" in trusted, path.name
        assert "$script:AdminMemberSids = $null" in _code(path), path.name


def test_f15_service_hands_the_token_to_administrators_before_locking_it() -> None:
    protect = _function(_code(SERVICE_PS1), "Set-ProtectedAcl")
    assert protect.index("' /setowner *' + $script:SidAdmins") < protect.index("' /inheritance:r /grant:r '")
    assert protect.index("' /inheritance:r /grant:r '") < protect.index("Get-AclProblem -Path $Path")


def test_f15_service_and_doctor_walk_the_whole_config_folder() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        walk = _function(_code(path), "Get-TreeProblem")
        check = walk.index("$problem = Get-WriteProblem")
        descend = walk.index("$found = Get-TreeProblem -Directory $entry.FullName")
        assert check < walk.index("if ($entry.PSIsContainer) {") < descend, path.name
        assert "Get-ChildItem -LiteralPath $Directory -Force" in walk and "-Recurse" not in walk, path.name
    body = _main_body(_code(SERVICE_PS1))
    reset = body.index("Set-Acl -LiteralPath $configDir -AclObject $security")
    assert body.index("$serviceSid = Get-ServiceAccountSid") < reset < body.index("':(OI)(CI)RX'")


def test_f15_gate_and_custom_actions_have_no_colon_after_a_bare_variable_in_strings() -> None:
    # "$LASTEXITCODE: $err" is a PowerShell PARSE error ("Variable reference
    # is not valid. ':' was not followed by a valid variable name
    # character"), and a script that does not parse never runs: the gate
    # carrying the F15 ACL assertion and squat negative could not execute at
    # all. ${name}: or $($name): are the valid spellings.
    bare_colon = re.compile(r"\$(?!\{)\w+:(?=[\s\"'])")
    for path in (GATE_PS1, SERVICE_PS1, VERIFY_PS1, DOCTOR_PS1):
        for line in _code(path).splitlines():
            assert not bare_colon.search(line), f"{path.name}: {line.strip()}"


def test_f94_doctor_placeholder_branch_resolves_its_directory() -> None:
    # Split-Path's -Parent switch exists only in the -Path parameter set, so
    # "Split-Path -LiteralPath $ConfigPath -Parent" throws "Parameter set
    # cannot be resolved" (PowerShell 5.1 and 7): the placeholder branch that
    # holds the smoke-directory guard never ran, and the fresh-install doctor
    # action failed on the template config.
    for path in (DOCTOR_PS1, SERVICE_PS1, VERIFY_PS1, GATE_PS1):
        for line in _code(path).splitlines():
            if "Split-Path" in line and "-LiteralPath" in line:
                assert "-Parent" not in line and "-Leaf" not in line, f"{path.name}: {line.strip()}"
    assert "$configDir = Split-Path -Parent $ConfigPath" in _code(DOCTOR_PS1)


def test_f94_doctor_passes_the_smoke_database_program_as_one_argument() -> None:
    # PowerShell's comma operator binds tighter than +, so
    #   @('-c', "...connect(r'" + $demoDb + "')...")
    # is FOUR array elements and python gets a truncated -c program
    # (SyntaxError): the smoke database behind the F94 guard was never
    # created. A concatenation used as an array element must be
    # parenthesized.
    comma_then_concat = re.compile(r",[ \t]*\n[ \t]*(\"[^\"\n]*\"|'[^'\n]*')[ \t]*\+")
    for path in (DOCTOR_PS1, SERVICE_PS1, VERIFY_PS1, GATE_PS1):
        match = comma_then_concat.search(_code(path))
        assert not match, f"{path.name}: {match.group(0) if match else ''}"
    body = _main_body(_code(DOCTOR_PS1))
    create_args = body[body.index("$createArgs = @(") : body.index("$dbCode = ")]
    assert re.search(r"'-c',\s*\n\s*\(\"import sqlite3; con = sqlite3\.connect\(r'\" \+ \$demoDb \+ ", create_args)


# ------------------------------------------- executed under pwsh (stubbed) --
#
# The checks above pin the code's shape; these run the REAL service.ps1,
# doctor.ps1 and verify.ps1 under pwsh on a POSIX host, with the Windows-only
# pieces stubbed: Get-Acl, Set-Acl, New-Object DirectorySecurity, Remove-Item
# (it forgets a deleted entry's stub ACL) and, when a test names the
# administrators, Get-LocalGroupMember; icacls.exe, sc.exe, reg.exe and the
# venv python.exe are shell stubs. Each ACL decision is taken on a stub ACL
# store (acl.json: path -> owner, protected flag, ACEs) that icacls and Set-Acl
# update, so disabling or inverting an owner, reparse-point or DACL check in a
# script fails a test here. CI's ubuntu runner ships pwsh; hosts without it
# skip (the static checks above still run).

PWSH = shutil.which("pwsh")
executed = pytest.mark.skipif(
    PWSH is None or sys.platform == "win32",
    reason="runs the custom actions under pwsh with POSIX shell stubs for the Windows tools; needs pwsh on a "
    "non-Windows host (the CI ubuntu runner ships it)",
)

USER_SID = "S-1-5-21-1111-2222-3333-1001"  # an ordinary local user
ADMIN_USER_SID = "S-1-5-21-1111-2222-3333-500"  # an administrator's own account
GENERATED = "GENERATEDTOKEN0123456789abcdef"  # what the python.exe stub prints for secrets.token_hex
PROTECTED_DIR_SDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


def _entry(owner: str, *extra: list[object], protected: bool = True) -> dict[str, object]:
    rules: list[list[object]] = [
        [SID_SYSTEM, "Allow", "FullControl", False],
        [SID_ADMINS, "Allow", "FullControl", False],
    ]
    return {"owner": owner, "protected": protected, "rules": rules + list(extra)}


SAFE = _entry(SID_ADMINS)
# What service.ps1 leaves on the token: owned by Administrators, nothing inherited.
TOKEN_ACL = {
    "owner": SID_ADMINS,
    "protected": True,
    "rules": [[SID_SYSTEM, "Allow", "F", False], [SID_ADMINS, "Allow", "F", False]],
}
USER_OWNED = {"owner": USER_SID, "protected": False, "rules": [[USER_SID, "Allow", "FullControl", False]]}

_ACL_HELPER = r'''
"""Stub Windows ACL store: path -> {"owner": SID, "protected": bool,
"rules": [[SID, "Allow", rights, inherited]]}. An entry nobody described
has the default owner and inherits the DACL of ProgramData (Users may read)."""
import json
import os
import re
import sys

ALIASES = {"SY": "S-1-5-18", "BA": "S-1-5-32-544"}
INHERITED = [["S-1-5-18", "Allow", "FullControl", True], ["S-1-5-32-544", "Allow", "FullControl", True],
             ["S-1-5-32-545", "Allow", "ReadAndExecute", True]]
RACER = "S-1-5-21-1111-2222-3333-1001"  # the local user of the H_RACE plant


def log(line):
    with open(os.environ["H_CALLS"], "a", encoding="utf-8") as f:
        f.write(line + "\n")


def main(cmd, path, *args):
    with open(os.environ["H_ACL"], encoding="utf-8") as f:
        state = json.load(f)
    entry = state.get(path) or {"owner": os.environ.get("H_DEFAULT_OWNER") or "S-1-5-18", "protected": False,
                                "rules": [list(r) for r in INHERITED]}
    if cmd == "get":
        print(json.dumps(entry))
        return 0
    if cmd == "forget":
        state.pop(path, None)
    elif cmd == "setacl":
        log("Set-Acl " + path + " " + args[0])
        m = re.fullmatch(r"(?:O:(\w\w))?D:PAI((?:\(A;OICI;FA;;;\w\w\))+)", args[0])
        if not m:
            raise SystemExit("Set-Acl stub: unsupported SDDL " + args[0])
        if m.group(1):
            entry["owner"] = ALIASES[m.group(1)]
        entry["protected"] = True
        entry["rules"] = [[ALIASES[a], "Allow", "FullControl", False] for a in re.findall(r";;;(\w\w)\)", m.group(2))]
        state[path] = entry
        # As on Windows, the inherited ACEs of every described entry below
        # are recomputed from the new DACL, unless it (or a folder between)
        # has a protected DACL; explicit ACEs stay.
        for other in list(state):
            if not other.startswith(path + "/"):
                continue
            chain, parent = [other], os.path.dirname(other)
            while parent != path:
                chain.append(parent)
                parent = os.path.dirname(parent)
            if not any(state.get(p, {}).get("protected") for p in chain):
                state[other]["rules"] = [r for r in state[other]["rules"] if not r[3]] + [
                    [sid, kind, rights, True] for sid, kind, rights, _ in entry["rules"]
                ]
        # H_RACE="<directory>|<entry>": a local user creates <entry> while the
        # script puts the DACL on <directory> (between its walk and the DACL).
        target, _, planted = os.environ.get("H_RACE", "").partition("|")
        if planted and path == target:
            with open(planted, "w", encoding="utf-8") as f:
                f.write("planted-by-user")
            state[planted] = {"owner": RACER, "protected": False, "rules": [[RACER, "Allow", "FullControl", False]]}
            log("RACE planted " + planted)
    elif cmd == "icacls":
        size = os.path.getsize(path) if os.path.isfile(path) else -1
        log("icacls " + " | ".join((path,) + args) + " [size=%d]" % size)
        if os.environ.get("H_ICACLS_FAIL"):
            return 5
        i = 0
        while i < len(args):
            if args[i] == "/setowner":
                entry["owner"] = args[i + 1].lstrip("*")
                i += 2
            elif args[i] == "/inheritance:r":
                entry["protected"] = True
                entry["rules"] = [r for r in entry["rules"] if not r[3]]
                i += 1
            elif args[i] in ("/grant:r", "/grant"):
                replace = args[i] == "/grant:r"
                i += 1
                while i < len(args) and not args[i].startswith("/"):
                    sid, rights = args[i].lstrip("*").split(":", 1)
                    entry["rules"] = [r for r in entry["rules"] if not (replace and r[0] == sid and not r[3])]
                    entry["rules"].append([sid, "Allow", rights, False])
                    i += 1
            else:
                raise SystemExit("icacls stub: unsupported argument " + args[i])
        state[path] = entry
    with open(os.environ["H_ACL"], "w", encoding="utf-8") as f:
        json.dump(state, f)
    return 0


sys.exit(main(*sys.argv[1:]))
'''

_STUBS_PS1 = r"""
function global:Invoke-AclStub { & $env:H_PY $env:H_HELPER @args }

function global:Get-Acl {
    param([string]$LiteralPath)
    Add-Content -LiteralPath $env:H_CALLS -Value ('Get-Acl ' + $LiteralPath)
    $entry = (Invoke-AclStub get $LiteralPath) | ConvertFrom-Json -AsHashtable
    # a DACL that grants the caller no READ_CONTROL
    if ($entry.unreadable) {
        throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.')
    }
    $acl = [pscustomobject]@{
        AreAccessRulesProtected = [bool]$entry.protected; Owner = $entry.owner; Rules = $entry.rules
    }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value {
        param($type) [pscustomobject]@{ Value = $this.Owner }
    }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
        param($explicit, $inherited, $type)
        foreach ($rule in $this.Rules) {
            # an optional fifth element names the ACE's propagation flags; a
            # grant the stub icacls stored ('(OI)(CI)RX') is reported as .NET
            # reports it (ReadAndExecute, Synchronize; (IO): inherit-only)
            $propagation = 'None'
            if ($rule.Count -gt 4) { $propagation = $rule[4] }
            if ($rule[2] -match '\(IO\)') { $propagation = 'InheritOnly' }
            $rights = $rule[2] -replace '\([A-Z]+\)', ''
            $short = @{
                F = 'FullControl'; M = 'Modify, Synchronize'
                RX = 'ReadAndExecute, Synchronize'; R = 'Read, Synchronize'
            }
            if ($short.ContainsKey($rights)) { $rights = $short[$rights] }
            [pscustomobject]@{
                IdentityReference = [pscustomobject]@{ Value = $rule[0] }
                AccessControlType = [System.Security.AccessControl.AccessControlType]$rule[1]
                FileSystemRights  = [System.Security.AccessControl.FileSystemRights]$rights
                IsInherited       = [bool]$rule[3]
                PropagationFlags  = [System.Security.AccessControl.PropagationFlags]$propagation
            }
        }
    }
    return $acl
}

function global:Set-Acl {
    param([string]$LiteralPath, $AclObject)
    Invoke-AclStub setacl $LiteralPath $AclObject.Sddl
}

function global:New-Object {
    if ($args.Count -ge 1 -and $args[0] -eq 'System.Security.AccessControl.DirectorySecurity') {
        $security = [pscustomobject]@{ Sddl = '' }
        $security | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptorSddlForm -Value {
            param($sddl) $this.Sddl = $sddl
        }
        return $security
    }
    # H_ACCOUNTS="<name>=<SID>;...": the local security authority that
    # NTAccount.Translate asks (there is none on a POSIX host)
    if ($env:H_ACCOUNTS -and $args.Count -ge 2 -and $args[0] -eq 'System.Security.Principal.NTAccount') {
        $account = [pscustomobject]@{ Name = [string]$args[1] }
        $account | Add-Member -MemberType ScriptMethod -Name Translate -Value {
            param($type)
            foreach ($pair in ($env:H_ACCOUNTS -split ';')) {
                $name, $sid = $pair -split '=', 2
                if ($name -eq $this.Name) { return [pscustomobject]@{ Value = $sid } }
            }
            throw ('stub LSA: no account ' + $this.Name)
        }
        return $account
    }
    Microsoft.PowerShell.Utility\New-Object @args
}

function global:Remove-Item {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string[]]$LiteralPath, [switch]$Force, [switch]$Recurse)
    # H_LOCKED=<path>: a local user holds that file open without
    # FILE_SHARE_DELETE (any user may read what is under Program Files)
    foreach ($path in $LiteralPath) {
        if ($env:H_LOCKED -and $path -eq $env:H_LOCKED) {
            throw [System.IO.IOException]::new(
                "The process cannot access the file '" + $path + "' because it is being used by another process.")
        }
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force:$Force -Recurse:$Recurse
    foreach ($path in $LiteralPath) { Invoke-AclStub forget $path }
}

if ($env:H_ADMIN_MEMBERS) {
    function global:Get-LocalGroupMember {
        param([string]$SID)
        Add-Content -LiteralPath $env:H_CALLS -Value ('Get-LocalGroupMember ' + $SID)
        foreach ($member in ($env:H_ADMIN_MEMBERS -split ',')) {
            [pscustomobject]@{ SID = [pscustomobject]@{ Value = $member } }
        }
    }
}
"""

_RUN_PS1 = r"""
param([string]$Script, [string]$ArgsJson)
. (Join-Path $PSScriptRoot 'stubs.ps1')
$params = $ArgsJson | ConvertFrom-Json -AsHashtable
& $Script @params
exit $LASTEXITCODE
"""

_ICACLS_STUB = '#!/bin/sh\nexec "$H_PY" "$H_HELPER" icacls "$@"\n'
# H_SC_SERVICE=1: the service exists (and reads as stopped); else sc.exe
# query answers 1060, as on a host without it.
_SC_STUB = (
    '#!/bin/sh\necho "sc $*" >> "$H_CALLS"\n'
    'if [ "$1" = query ]; then [ -n "$H_SC_SERVICE" ] || exit 36; echo "        STATE              : 1  STOPPED"; fi\n'
    "exit 0\n"
)
_REG_STUB = '#!/bin/sh\necho "reg $*" >> "$H_CALLS"\n[ -n "$H_REG_FAIL" ] && exit 1\nexit 0\n'
_PYTHON_STUB = f"""#!/bin/sh
echo "python $*" >> "$H_CALLS"
# Every LocalSystem run of the venv interpreter is isolated (-I): PYTHON*
# variables, the user site and the working directory stay off sys.path.
[ "$1" = -I ] || {{ echo "python stub: run without -I: $*" >&2; exit 97; }}
shift
case "$2" in *secrets.token_hex*) echo "{GENERATED}"; exit 0 ;; esac
[ "$1" = -m ] && exec "$H_PY" -I "$H_PAYLOAD_DOCTOR"
exec "$H_PY" -I "$@"
"""
_PAYLOAD_DOCTOR = r'''
r"""Stub payload doctor ("python -I -m universal_db_mcp doctor", which
DoctorSmokeCA runs as LocalSystem): the one check of the real one that reads
the folder's ACLs. diagnostics/doctor.py validates the service's bearer token
at %ProgramData%\UniversalDB MCP\http-token whenever it exists, and
config.win32_secret_file_problems makes an owner other than SYSTEM,
Administrators or the running account (SYSTEM here), or access for a broad
principal, fatal. Read from the stub ACL store."""
import json
import os
import subprocess
import sys

TRUSTED = ("S-1-5-18", "S-1-5-32-544")
BROAD = ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4")
token = os.path.join(os.environ["ProgramData"], "UniversalDB MCP", "http-token")
if os.path.isfile(token):
    helper = [os.environ["H_PY"], os.environ["H_HELPER"], "get", token]
    entry = json.loads(subprocess.run(helper, capture_output=True, text=True, check=True).stdout)
    problems = []
    if entry["owner"] not in TRUSTED:
        problems.append("owned by %s, not by SYSTEM, Administrators or the account running this process"
                        % entry["owner"])
    for rule in entry["rules"]:
        if rule[1] == "Allow" and rule[0] in BROAD and not (len(rule) > 4 and rule[4] == "InheritOnly"):
            problems.append("readable by %s" % rule[0])
    if problems:
        print("FATAL http-bearer-token: bearer token file '%s' is exposed to other local users: %s"
              % (token, "; ".join(problems)))
        sys.exit(1)
print("doctor: healthy")
'''
_TEMPLATE_CONFIG = (
    "application:\n  audit_path: PLACEHOLDER_DIR/audit.jsonl\nconnections:\n  d:\n    database: PLACEHOLDER_DB\n"
)
_EDITED_CONFIG = "application:\n  metadata_cache_path: metadata-cache.sqlite\nconnections: {}\n"


def _executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class _Host:
    """A stubbed Windows host: C:\\ProgramData\\UniversalDB MCP with the
    template config, a venv, System32 tools, and the stub ACL store."""

    def __init__(self, root: Path) -> None:
        self.root = root
        stubs = root / "stubs"
        stubs.mkdir()
        self.helper = stubs / "acl.py"
        self.helper.write_text(_ACL_HELPER, encoding="utf-8")
        self.payload_doctor = stubs / "doctor.py"
        self.payload_doctor.write_text(_PAYLOAD_DOCTOR, encoding="utf-8")
        (stubs / "stubs.ps1").write_text(_STUBS_PS1, encoding="utf-8")
        self.runner = stubs / "run.ps1"
        self.runner.write_text(_RUN_PS1, encoding="utf-8")
        for name, body in (("icacls.exe", _ICACLS_STUB), ("sc.exe", _SC_STUB), ("reg.exe", _REG_STUB)):
            _executable(root / "win" / "System32" / name, body)
        self.venv = root / "venv"
        _executable(self.venv / "Scripts" / "python.exe", _PYTHON_STUB)
        self.program_data = root / "ProgramData"
        self.cfgdir = self.program_data / "UniversalDB MCP"
        self.cfgdir.mkdir(parents=True)
        self.config = self.cfgdir / "config.yaml"
        self.config.write_text(_TEMPLATE_CONFIG, encoding="utf-8")
        self.token = self.cfgdir / "http-token"
        self.smoke = self.cfgdir / "smoke"
        self.acl_file = root / "acl.json"
        self.acl_file.write_text("{}", encoding="utf-8")
        self.calls_file = root / "calls.log"
        # POSIX exit statuses are 8 bits: sc.exe's ERROR_SERVICE_DOES_NOT_EXIST
        # (1060) arrives as 36, so service.ps1 runs from a copy with only that
        # constant mapped.
        self.service_ps1, self.uninstall_ps1 = root / "service.ps1", root / "uninstall.ps1"
        for script, copy in ((SERVICE_PS1, self.service_ps1), (UNINSTALL_PS1, self.uninstall_ps1)):
            source = script.read_text(encoding="utf-8")
            assert "$script:ErrServiceAbsent = 1060" in source
            copy.write_text(source.replace("$script:ErrServiceAbsent = 1060", "$script:ErrServiceAbsent = 36"))

    def acl(self, path: Path) -> dict[str, object]:
        entry: dict[str, object] = json.loads(self.acl_file.read_text(encoding="utf-8"))[str(path)]
        return entry

    def run(
        self, script: Path, params: Mapping[str, object], acl: dict[Path, dict[str, object]] | None = None, **env: str
    ) -> tuple[int, str, str]:
        """Runs *script* once; *acl* replaces the stub ACL store (None keeps
        it from the previous run). Returns (exit code, output, stub calls)."""
        if acl is not None:
            self.acl_file.write_text(json.dumps({str(p): e for p, e in acl.items()}), encoding="utf-8")
        self.calls_file.write_text("", encoding="utf-8")
        proc = subprocess.run(  # noqa: S603 - fixed argv, repo scripts under test
            [
                str(PWSH),
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.runner),
                "-Script",
                str(script),
                "-ArgsJson",
                json.dumps(params),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            env=self.env(**env),
        )
        return proc.returncode, proc.stdout + proc.stderr, self.calls_file.read_text(encoding="utf-8")

    def env(self, **extra: str) -> dict[str, str]:
        """The stubbed host's environment: Windows folders and the stub hooks
        (and no service account or password from the host running the tests)."""
        env = dict(
            os.environ,
            SystemRoot=str(self.root / "win"),
            ProgramData=str(self.program_data),
            ProgramFiles=str(self.root / "ProgramFiles"),
            COMPUTERNAME="HOST",
            UDBMCP_SERVICE_ACCOUNT="",
            UDBMCP_SERVICE_PASSWORD="",
            H_ACL=str(self.acl_file),
            H_CALLS=str(self.calls_file),
            H_PY=sys.executable,
            H_HELPER=str(self.helper),
            H_PAYLOAD_DOCTOR=str(self.payload_doctor),
        )
        env.update(extra)
        return env

    def service(
        self,
        acl: dict[Path, dict[str, object]] | None = None,
        account: str = "LocalSystem",
        bundle: Path | None = None,
        record: Path | None = None,
        registered: str | None = None,
        **env: str,
    ) -> tuple[int, str, str]:
        """service.ps1 as RegisterServiceCA runs it; *account* "" is an
        install without UDBMCP_SERVICE_ACCOUNT, *registered* the account the
        MSI found the service registered under."""
        params = {"VenvDir": str(self.venv), "ConfigPath": str(self.config), "ServiceAccount": account}
        if bundle is not None:
            params["BundleDir"] = str(bundle)
        if record is not None:
            params["InstalledManifest"] = str(record)
        if registered is not None:
            params["RegisteredAccount"] = registered
        return self.run(self.service_ps1, params, acl, **env)

    def doctor(
        self,
        acl: dict[Path, dict[str, object]] | None = None,
        account: str | None = None,
        registered: str | None = None,
        **env: str,
    ) -> tuple[int, str, str]:
        params = {"VenvDir": str(self.venv), "ConfigPath": str(self.config)}
        if account is not None:
            params["ServiceAccount"] = account
        if registered is not None:
            params["RegisteredAccount"] = registered
        return self.run(DOCTOR_PS1, params, acl, **env)

    def verify(self, data: str, acl: dict[Path, dict[str, object]] | None = None, **env: str) -> tuple[int, str, str]:
        return self.run(VERIFY_PS1, {"CustomActionData": data}, acl, **env)

    def uninstall(self, record: Path | None = None, commit: bool = False, **env: str) -> tuple[int, str, str]:
        """uninstall.ps1 as RemoveServiceCA runs it, or with *record* as its
        rollback twin RollbackRemoveServiceCA does (*commit*: as
        CommitReleaseRecordCA does)."""
        params: dict[str, str | bool] = {"ServiceName": "udbmcp"}
        if record is not None:
            params["InstalledManifest"] = str(record)
        if commit:
            params["Commit"] = True
        return self.run(self.uninstall_ps1, params, None, **env)


@pytest.fixture()
def host(tmp_path: Path) -> _Host:
    return _Host(tmp_path)


def _line(calls: str, prefix: str) -> int:
    """Index of the first stub call starting with *prefix*."""
    lines = calls.splitlines()
    return next(i for i, ln in enumerate(lines) if ln.startswith(prefix))


# --------------------------------------------------- executed: service.ps1 --


@executed
def test_exec_service_owns_and_locks_the_empty_token_before_writing_it(host: _Host) -> None:
    code, out, calls = host.service({host.cfgdir: SAFE})
    assert code == 0, out
    assert host.token.read_text(encoding="utf-8") == GENERATED
    assert GENERATED not in out, "the token value is never printed"
    token_calls = [ln for ln in calls.splitlines() if ln.startswith(f"icacls {host.token} ")]
    assert token_calls[:2] == [
        f"icacls {host.token} | /setowner | *{SID_ADMINS} [size=0]",
        f"icacls {host.token} | /inheritance:r | /grant:r | *{SID_SYSTEM}:F | *{SID_ADMINS}:F [size=0]",
    ], calls
    assert _line(calls, f"icacls {host.token} ") < _line(calls, "sc create")
    assert host.acl(host.token) == TOKEN_ACL


@executed
@pytest.mark.parametrize(
    ("token_acl", "reason"),
    [
        (USER_OWNED, f"is owned by {USER_SID}"),
        (_entry(SID_SYSTEM, protected=False), "inherits its DACL from the folder"),
        (_entry(SID_ADMINS, [USER_SID, "Allow", "Read", False]), f"grants {USER_SID} Read"),
        # the read ACE of a previously configured service account
        (_entry(SID_ADMINS, ["S-1-5-20", "Allow", "R", False]), "grants S-1-5-20 R"),
        # an administrator may own it, but the LocalSystem service's own
        # startup check accepts only SYSTEM or Administrators
        (_entry(ADMIN_USER_SID), f"is owned by {ADMIN_USER_SID}, not SYSTEM or Administrators"),
    ],
    ids=["user-owned", "inherited-dacl", "user-ace", "stale-service-account-ace", "admin-account-owner"],
)
def test_exec_service_regenerates_a_token_it_cannot_trust(
    host: _Host, token_acl: dict[str, object], reason: str
) -> None:
    host.token.write_text("planted-known-value", encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE, host.token: token_acl}, H_ADMIN_MEMBERS=ADMIN_USER_SID)
    assert code == 0, out
    assert f"'{host.token}' {reason}" in out and "regenerating it" in out, out
    assert host.token.read_text(encoding="utf-8") == GENERATED
    assert "planted-known-value" not in out
    assert host.acl(host.token) == TOKEN_ACL


@executed
def test_exec_service_keeps_a_safe_token(host: _Host) -> None:
    host.token.write_text("admins-own-token", encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE, host.token: SAFE})
    assert code == 0, out
    assert host.token.read_text(encoding="utf-8") == "admins-own-token"
    assert "regenerating" not in out and "token_hex" not in calls


@executed
def test_exec_service_keeps_the_token_an_elevated_admin_run_created(host: _Host) -> None:
    # Where an administrator's new files are owned by their own account
    # ("Object creator" default owner), a token created without an explicit
    # owner failed the action's own owner check on the next run (and the
    # service's startup check): every run rotated it.
    admin = {"H_DEFAULT_OWNER": ADMIN_USER_SID}
    code, out, calls = host.service({host.cfgdir: SAFE, host.config: SAFE}, **admin)
    assert code == 0, out
    assert host.acl(host.token)["owner"] == SID_ADMINS
    code, out, calls = host.service(None, **admin)
    assert code == 0, out
    assert "regenerating" not in out and "token_hex" not in calls, out


@executed
@pytest.mark.parametrize("target", ["folder", "config"])
def test_exec_service_refuses_a_squatted_folder_or_config_before_changing_anything(host: _Host, target: str) -> None:
    path = host.cfgdir if target == "folder" else host.config
    code, out, calls = host.service({host.cfgdir: SAFE, path: USER_OWNED})
    assert code == 1, out
    assert f"refusing '{path}': it is owned by {USER_SID}" in out, out
    assert "remove it" in out and "setowner" not in out, "an owner change keeps what its creator put in it"
    assert not any(ln.startswith(("sc ", "icacls ", "Set-Acl ")) for ln in calls.splitlines()), calls
    assert not host.token.exists()


@executed
@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_exec_service_fails_closed_on_a_token_that_is_a_link_or_directory(host: _Host, kind: str) -> None:
    victim = host.root / "victim"
    if kind == "symlink":
        host.token.symlink_to(victim)
    else:
        host.token.mkdir()
    code, out, calls = host.service({host.cfgdir: SAFE})
    assert code == 1, out
    assert "is a directory, junction or symbolic link, not a token file" in out
    assert not victim.exists()
    assert "sc " not in calls


@executed
@pytest.mark.parametrize(
    "plant",
    ["user-dir", "user-file", "user-file-in-admin-dir", "symlink-in-admin-dir"],
)
def test_exec_service_refuses_non_admin_entries_anywhere_in_the_config_folder(host: _Host, plant: str) -> None:
    # On an upgrade the folder carried C:\ProgramData's inheritable ACEs for
    # the previous version's lifetime, so any local user could create entries
    # in it (and in its subfolders) and owns them: a directory the service
    # later writes through (its owner can turn it into a junction), an audit
    # log or a metadata cache it can read or rewrite. Owners are checked all
    # the way down, not only junctions directly in the folder.
    audit = host.cfgdir / "audit"
    audit.mkdir()
    acl: dict[Path, dict[str, object]] = {host.cfgdir: SAFE, host.config: SAFE, audit: SAFE}
    if plant == "user-dir":
        planted = audit
    elif plant == "user-file":
        planted = host.cfgdir / "metadata-cache.sqlite"
        planted.write_text("user-controlled", encoding="utf-8")
    elif plant == "user-file-in-admin-dir":
        planted = audit / "audit.jsonl"
        planted.write_text("", encoding="utf-8")
    else:
        planted = audit / "audit.jsonl"
        planted.symlink_to(host.root / "victim")
    if plant != "symlink-in-admin-dir":
        acl[planted] = USER_OWNED
    code, out, calls = host.service(acl)
    assert code == 1, out
    assert f"'{planted}'" in out and "refusing" in out, out
    assert "remove it" in out and "setowner" not in out
    assert not any(ln.startswith(("sc ", "icacls ", "Set-Acl ")) for ln in calls.splitlines()), calls
    assert not host.token.exists()


@executed
def test_exec_service_accepts_entries_an_administrator_owns(host: _Host) -> None:
    # An elevated administrator's own files may be owned by their account
    # rather than Administrators; a direct member of the local Administrators
    # group is trusted, anyone else is not.
    audit = host.cfgdir / "audit"
    audit.mkdir()
    acl = {host.cfgdir: SAFE, host.config: _entry(ADMIN_USER_SID), audit: _entry(ADMIN_USER_SID)}
    code, out, calls = host.service(acl, H_ADMIN_MEMBERS=f"{ADMIN_USER_SID},S-1-5-21-1111-2222-3333-1002")
    assert code == 0, out
    assert calls.count("Get-LocalGroupMember S-1-5-32-544") == 1, "looked up once"
    code, out, calls = host.service(acl, H_ADMIN_MEMBERS="S-1-5-21-1111-2222-3333-1002")
    assert code == 1 and f"is owned by {ADMIN_USER_SID}" in out, out


@executed
def test_exec_service_resets_the_folder_dacl_before_granting_the_service_account(host: _Host) -> None:
    # icacls /grant:r replaces only the named SID's ACE: the read access of a
    # previously configured service account (and, on an upgrade, ACEs the
    # folder's entries inherited from C:\ProgramData) survived a re-run.
    stale = _entry(SID_ADMINS, ["S-1-5-19", "Allow", "(OI)(CI)RX", False])
    code, out, calls = host.service({host.cfgdir: stale}, account="NT AUTHORITY\\NetworkService")
    assert code == 0, out
    reset = _line(calls, f"Set-Acl {host.cfgdir} {PROTECTED_DIR_SDDL}")
    grant = _line(calls, f"icacls {host.cfgdir} | /grant:r | *S-1-5-20:(OI)(CI)RX")
    assert reset < grant < _line(calls, "sc create"), calls
    assert host.acl(host.cfgdir)["rules"] == SAFE["rules"] + [["S-1-5-20", "Allow", "(OI)(CI)RX", False]]
    assert host.acl(host.token)["rules"] == TOKEN_ACL["rules"] + [["S-1-5-20", "Allow", "R", False]]


@executed
def test_exec_service_icacls_failure_fails_closed_before_the_value_is_written(host: _Host) -> None:
    code, out, calls = host.service({host.cfgdir: SAFE}, H_ICACLS_FAIL="1")
    assert code == 1 and "icacls could not" in out, out
    assert not host.token.exists() or host.token.read_text(encoding="utf-8") == ""
    assert "sc create" not in calls


# ---------------------------------------------------- executed: doctor.ps1 --


@executed
def test_exec_doctor_protects_the_smoke_directory_before_writing_it(host: _Host) -> None:
    code, out, calls = host.doctor({host.cfgdir: SAFE})
    assert code == 0, out
    protect = _line(calls, f"Set-Acl {host.smoke} {PROTECTED_DIR_SDDL}")
    assert protect < _line(calls, "python -I -c import sqlite3") < _line(calls, "python -I -m universal_db_mcp doctor")
    assert (host.smoke / "finlink-demo.db").is_file() and (host.smoke / "config.smoke.yaml").is_file()
    assert host.acl(host.smoke)["owner"] == SID_ADMINS, "the directory it made is owned by Administrators"


@executed
@pytest.mark.parametrize("target", ["folder", "config", "smoke"])
def test_exec_doctor_refuses_a_squatted_folder_config_or_smoke_directory(host: _Host, target: str) -> None:
    host.smoke.mkdir()
    path = {"folder": host.cfgdir, "config": host.config, "smoke": host.smoke}[target]
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.smoke: SAFE, path: USER_OWNED})
    assert code == 1, out
    assert f"'{path}'" in out and f"is owned by {USER_SID}" in out, out
    assert "python" not in calls and "Set-Acl" not in calls, calls
    assert os.listdir(host.smoke) == []


@executed
def test_exec_doctor_refuses_a_symlinked_smoke_config(host: _Host) -> None:
    host.smoke.mkdir()
    victim = host.root / "victim.txt"
    (host.smoke / "config.smoke.yaml").symlink_to(victim)
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.smoke: SAFE})
    assert code == 1 and "junction or symbolic link" in out, out
    assert not victim.exists()


@executed
@pytest.mark.parametrize("plant", ["audit-dir", "metadata-cache", "file-in-admin-dir"])
def test_exec_doctor_refuses_non_admin_entries_in_an_edited_config_folder(host: _Host, plant: str) -> None:
    # An upgrade keeps the admin's edited config (no placeholders, so no smoke
    # directory): doctor runs as LocalSystem against the folder the previous
    # version left open to every local user.
    host.config.write_text(_EDITED_CONFIG, encoding="utf-8")
    audit = host.cfgdir / "audit"
    audit.mkdir()
    acl: dict[Path, dict[str, object]] = {host.cfgdir: SAFE, host.config: SAFE, audit: SAFE}
    planted = {
        "audit-dir": audit,
        "metadata-cache": host.cfgdir / "metadata-cache.sqlite",
        "file-in-admin-dir": audit / "audit.jsonl",
    }[plant]
    if not planted.exists():
        planted.write_text("user-controlled", encoding="utf-8")
    acl[planted] = USER_OWNED
    code, out, calls = host.doctor(acl)
    assert code == 1, out
    assert f"'{planted}' in it is owned by {USER_SID}" in out and "setowner" not in out, out
    assert "python" not in calls, calls


@executed
def test_exec_doctor_accepts_entries_an_administrator_owns(host: _Host) -> None:
    host.config.write_text(_EDITED_CONFIG, encoding="utf-8")
    (host.cfgdir / "metadata-cache.sqlite").write_text("", encoding="utf-8")
    acl = {host.cfgdir: SAFE, host.config: SAFE, host.cfgdir / "metadata-cache.sqlite": _entry(ADMIN_USER_SID)}
    code, out, calls = host.doctor(acl, H_ADMIN_MEMBERS=ADMIN_USER_SID)
    assert code == 0, out
    assert "python -I -m universal_db_mcp doctor" in calls


# ---------------------------------------------------- executed: verify.ps1 --


def _interpreter(host: _Host) -> Path:
    """A python.exe in a folder of its own, so its ACL can be described: a
    plain file (as in a python.org install; verify.ps1 refuses a link) that
    runs this interpreter."""
    exe = host.root / "Python312" / "python.exe"
    if not exe.exists():
        _executable(exe, f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    return exe


def _trusted_install(host: _Host, python: str | None = None) -> str:
    """A bundle, a trusted verifier outside it that passes, and the
    CustomActionData naming them (the key is added by the caller)."""
    bundle = host.root / "bundle"
    (bundle / "wheelhouse").mkdir(parents=True)
    trust = host.root / "trust"
    trust.mkdir()
    (trust / "profiles.py").write_text("# registry\n", encoding="utf-8")
    (trust / "verify_bundle.py").write_text(
        "import sys\nprint('isolated=%d' % sys.flags.isolated)\nprint('bundle verification PASSED')\n",
        encoding="utf-8",
    )
    return f"BUNDLE_DIR={bundle};TRUST_DIR={trust};PYTHON={python or _interpreter(host)}"


@executed
@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "upgrade"])
def test_exec_verify_protects_the_log_directory_before_writing_it(host: _Host, existing: bool) -> None:
    log_dir = host.program_data / "universal-db-mcp"
    log = log_dir / "install-verify.log"
    acl: dict[Path, dict[str, object]] = {}
    if existing:
        # made by an earlier release's LocalSystem run, DACL inherited
        log_dir.mkdir()
        log.write_text("earlier run\n", encoding="utf-8")
        acl = {log_dir: _entry(SID_SYSTEM, protected=False), log: _entry(SID_SYSTEM, protected=False)}
    # a manual run by an administrator whose new files are their own
    code, out, calls = host.verify("BUNDLE_DIR=/nonexistent-bundle", acl, H_DEFAULT_OWNER=ADMIN_USER_SID)
    assert code == 1 and "installed bundle directory not found" in out, out
    protect = _line(calls, f"Set-Acl {log_dir} {PROTECTED_DIR_SDDL}")
    if existing:
        # the log file is checked once no local user can create it any more
        assert _line(calls, f"Get-Acl {log_dir}") < protect < _line(calls, f"Get-Acl {log}")
    assert "installed bundle directory not found" in log.read_text(encoding="utf-8")
    assert "icacls" not in calls, "no external process before the trusted verifier"
    assert host.acl(log_dir)["owner"] == SID_ADMINS, "owned by Administrators whoever ran it"


@executed
@pytest.mark.parametrize("plant", ["user-dir", "junction", "user-log"])
def test_exec_verify_refuses_a_squatted_log(host: _Host, plant: str) -> None:
    log_dir = host.program_data / "universal-db-mcp"
    log = log_dir / "install-verify.log"
    acl: dict[Path, dict[str, object]] = {}
    if plant == "junction":
        (host.root / "elsewhere").mkdir()
        log_dir.symlink_to(host.root / "elsewhere")
    else:
        log_dir.mkdir()
        acl[log_dir] = USER_OWNED if plant == "user-dir" else SAFE
    if plant == "user-log":
        log.write_text("planted\n", encoding="utf-8")
        acl[log] = USER_OWNED
    code, out, calls = host.verify("BUNDLE_DIR=/nonexistent-bundle", acl)
    assert code == 1 and "refusing to write the install log" in out, out
    assert "installed bundle directory" not in out, "nothing else runs"
    if plant == "junction":
        assert os.listdir(host.root / "elsewhere") == []
    elif plant == "user-log":
        assert log.read_text(encoding="utf-8") == "planted\n"
    else:
        assert not log.exists() and "Set-Acl" not in calls


@executed
def test_exec_verify_accepts_a_log_directory_an_administrator_made(host: _Host) -> None:
    log_dir = host.program_data / "universal-db-mcp"
    log_dir.mkdir()
    code, out, calls = host.verify(
        "BUNDLE_DIR=/nonexistent-bundle", {log_dir: _entry(ADMIN_USER_SID)}, H_ADMIN_MEMBERS=ADMIN_USER_SID
    )
    assert code == 1 and "installed bundle directory not found" in out, out
    assert (log_dir / "install-verify.log").is_file()


@executed
def test_exec_verify_passes_with_a_key_in_folders_admins_own(host: _Host) -> None:
    data = _trusted_install(host)
    key = host.root / "keys" / "udbmcp-release.pub.pem"
    key.parent.mkdir()
    key.write_text("-----BEGIN PUBLIC KEY-----\n", encoding="utf-8")
    code, out, calls = host.verify(f"{data};PUBKEY={key}")
    assert code == 0, out
    assert f"Get-Acl {key.parent}" in calls, "the folders above a key outside Program Files are checked"


@executed
@pytest.mark.parametrize("plant", ["user-folder", "user-key", "linked-folder"])
def test_exec_verify_refuses_a_key_a_non_admin_could_have_swapped(host: _Host, plant: str) -> None:
    # Earlier releases documented the key under C:\ProgramData, and any path
    # outside Program Files may pass through a folder a local user made (or a
    # junction such as the legacy "All Users" profile link): each folder is
    # checked, whatever the path's spelling.
    data = _trusted_install(host)
    keys = host.root / "keys"
    acl: dict[Path, dict[str, object]] = {}
    if plant == "linked-folder":
        (host.root / "real-keys").mkdir()
        keys.symlink_to(host.root / "real-keys")
    else:
        keys.mkdir()
    key = keys / "udbmcp-release.pub.pem"
    key.write_text("-----BEGIN PUBLIC KEY-----\n", encoding="utf-8")
    if plant == "user-folder":
        acl[keys] = USER_OWNED
    elif plant == "user-key":
        acl[key] = USER_OWNED
    code, out, calls = host.verify(f"{data};PUBKEY={key}", acl)
    assert code == 1 and "release public key:" in out, out
    assert "bundle verification PASSED" not in out, "the verifier never ran"
    assert "setowner" not in out and "C:\\Program Files\\udbmcp-trust\\keys" in out, out


# ============================================ integration wave (I60-I67) ==
#
# Residuals of review round 3. Static pins first; the executed scenarios
# after them reuse the stubbed host above.

SID_NETWORK_SERVICE = "S-1-5-20"
NETWORK_SERVICE = "NT AUTHORITY\\NetworkService"


def _custom_action_commands() -> dict[str, str]:
    return {el.get("Id") or "": el.get("ExeCommand") or "" for el in _wxs_root().iter() if _local(el) == "CustomAction"}


def _squat_check(code: str) -> str:
    """Gate check 3c, from the planted value to the service check."""
    return code[code.index("$SquatValue = ") : code.index("$scExe = Join-Path $env:SystemRoot 'System32\\sc.exe'")]


def test_i60_doctor_leaves_the_token_to_the_registration_action() -> None:
    # doctor.ps1 walked the whole folder, http-token included, and refused a
    # token a local user owned with an owner-change remedy. An administrator
    # who followed it handed the planted token (whose value its planter
    # knows) to Administrators, and service.ps1 then kept it as trusted. The
    # token is skipped as in service.ps1, which replaces any token it cannot
    # trust; only one that is not a plain file is refused, and that remedy
    # never offers an owner change.
    code = _code(DOCTOR_PS1)
    walk = _function(code, "Get-TreeProblem")
    assert "if ($SkipNames -contains $entry.Name) { continue }" in walk
    body = _main_body(code)
    token = body.index("$tokenFile = Join-Path $configDir 'http-token'")
    scan = body.index("$found = Get-TreeProblem -Directory $configDir -SkipNames @('http-token')")
    refusal = body[token:scan]
    assert "ReparsePoint" in refusal and "Directory" in refusal, refusal
    assert "the install provisions a new token" in refusal and "setowner" not in refusal, refusal
    assert scan < body.index("ReadAllText($ConfigPath)")


def test_i61_service_gives_the_service_account_a_writable_logs_folder() -> None:
    # A dedicated service account got read access only to C:\ProgramData\
    # UniversalDB MCP, the Windows state location: it could not create its
    # audit log (with audit_fail_closed, no audited call is served). logs\
    # is created and protected like the folder, and the account gets Modify
    # on it, after the folder's own DACL is in place (no local user can then
    # race an entry into the folder).
    body = _main_body(_code(SERVICE_PS1))
    assert "$logsDir = Join-Path $configDir 'logs'" in body
    reset = body.index("Set-Acl -LiteralPath $configDir -AclObject $security")
    check = body.index("$problem = Get-WriteProblem -Path $logsDir")
    create = body.index("New-Item -ItemType Directory -Path $logsDir")
    protect = body.index("Set-Acl -LiteralPath $logsDir -AclObject $security")
    grant = body.index("':(OI)(CI)M'")
    assert reset < check < create < protect < grant < body.index("Stop-ExistingService -Name $ServiceName")
    assert "-Force" not in body[create : body.index("\n", create)]
    # the SID is known before the walks, which accept its files in logs\
    assert body.index("$serviceSid = Get-ServiceAccountSid") < body.index("$found = Get-TreeProblem")


def test_i61_both_walks_accept_the_service_account_only_inside_logs() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        code = _code(path)
        walk = _function(code, "Get-TreeProblem")
        # only a top-level logs\ hands its SID down, and logs\ itself is
        # still held to the installer's owners
        assert "if ($logs -and -not $InLogs) { $below = $LogsSid }" in walk, path.name
        assert "Get-TreeProblem -Directory $entry.FullName -OwnerSid $below" in walk, path.name
        assert "Get-WriteProblem -Path $entry.FullName -OwnerSid $OwnerSid" in walk, path.name
        problem = _function(code, "Get-WriteProblem")
        assert problem.index("ReparsePoint") < problem.index("$OwnerSid -and $owner -eq $OwnerSid"), path.name
        body = _main_body(code)
        assert "-LogsSid $serviceSid" in body, path.name
    sid = _function(_code(DOCTOR_PS1), "Get-ServiceAccountSid")
    assert sid == _function(_code(SERVICE_PS1), "Get-ServiceAccountSid"), "one resolution rule in both actions"


def test_i61_wxs_tells_doctor_the_service_account() -> None:
    cmds = _custom_action_commands()
    for action in ("DoctorSmokeCA", "RegisterServiceCA"):
        assert '-ServiceAccount "[UDBMCP_SERVICE_ACCOUNT]"' in cmds[action], action


def test_i62_wxs_carries_the_downgrade_override_and_the_release_to_record() -> None:
    props = {el.get("Id"): el for el in _wxs_root().iter() if _local(el) == "Property"}
    assert props["UDBMCP_ALLOW_DOWNGRADE"].get("Secure") == "yes"
    cmds = _custom_action_commands()
    assert "ALLOW_DOWNGRADE=[UDBMCP_ALLOW_DOWNGRADE]" in cmds["VerifyBundleCA"]
    assert '-BundleDir "[INSTALLFOLDER]bundle"' in cmds["RegisterServiceCA"]


def test_i62_verify_passes_the_installed_manifest_to_the_trusted_verifier() -> None:
    code = _code(VERIFY_PS1)
    body = _main_body(code)
    record = body.index("$InstalledManifest = Join-Path (Split-Path -Parent (Real-Path $BundleDir)) 'manifest.json'")
    assert re.search(r"\$problem = Get-WriteProblem \$InstalledManifest\s*\n\s*if \(-not \$problem ", body)
    assert re.search(r"\n\s*\}\s*\n\s*if \(\$problem\) \{\s*\n\s*Fail \"the installed release record", body)
    assert "$rollbackArgs = @('--installed-manifest', $InstalledManifest)" in body
    override = body.index("if ($data['ALLOW_DOWNGRADE'] -eq '1') {")
    assert "$rollbackArgs += '--allow-downgrade'" in body[override : override + 200]
    assert "$env:UDBMCP_ALLOW_DOWNGRADE" not in code, "a machine-wide override would stay on for every later install"
    # a ';' in the property value cannot add a key (see test_r1_* for the one after ALLOW_DOWNGRADE)
    assert re.search(r"if \(\$data\.ContainsKey\(\$key\)\) \{\s*\n\s*Fail ", body)
    run = body.index("& $pyExe @pyArgs $Verifier --bundle $BundleDir --pubkey $PubKey @rollbackArgs 1>")
    assert record < override < run
    # an older release gets its own diagnostic and remedy
    refused = body.index("'(?m)^FAIL: rollback refused'")
    assert run < refused < body.index("if ($verifierExit -ne 0) {")
    assert "UDBMCP_ALLOW_DOWNGRADE=1" in body[refused : refused + 600]


def test_i62_verify_refuses_an_outdated_trusted_verifier() -> None:
    body = _main_body(_code(VERIFY_PS1))
    outdated = body.index(
        """if ($verifierText.Contains('"--pubkey"') -and -not $verifierText.Contains('"--installed-manifest"')) {"""
    )
    assert "OUTDATED" in body[outdated : outdated + 400]
    assert body.index("$verifierText = [System.IO.File]::ReadAllText($Verifier)") < outdated
    assert outdated < body.index("& $pyExe @pyArgs $Verifier")


def test_i62_verify_header_no_longer_claims_openssl() -> None:
    # The verifier checks Ed25519 itself; it never runs openssl.exe.
    assert "openssl" not in VERIFY_PS1.read_text(encoding="utf-8").lower()


def test_i62_service_records_the_installed_release_after_everything_else() -> None:
    body = _main_body(_code(SERVICE_PS1))
    record = body.index("$bundleManifest = Join-Path $BundleDir 'manifest.json'")
    assert body.index("/v Environment /t REG_MULTI_SZ") < record
    assert record < body.index("registered (the installer does not auto-start it")
    publish = body[record : body.index("registered (the installer does not auto-start it")]
    refuse = r"\$problem = Get-WriteProblem -Path \$InstalledManifest\s*\n\s*if \(\$problem\) \{\s*\n\s*Abort "
    assert re.search(refuse, publish), publish
    assert "[System.IO.File]::Copy($bundleManifest, $InstalledManifest, $true)" in publish


def test_i62_gate_proves_the_rollback_refusal_on_windows() -> None:
    code = _code(GATE_PS1)
    assert "'installed_manifest_recorded'" in code and "'rollback_refused'" in code
    # where the MSI records it (not under -InstallRoot), handed over as the wxs does
    rollback = code[code.index("$InstalledManifest = Join-Path $env:ProgramFiles 'UniversalDB MCP\\manifest.json'") :]
    assert "INSTALLED_MANIFEST={4}' -f $BundleDir, $TrustDir, $PubKeyUsed, $script:Py, $InstalledManifest" in rollback
    assert "ALLOW_DOWNGRADE=1" in rollback and "rollback refused" in rollback
    restore = rollback[rollback.index("} finally {") :]
    assert "[System.IO.File]::WriteAllBytes($InstalledManifest, $RecordBytes)" in restore[:400]
    assert code.index("'restore_reverified'") < code.index("'rollback_refused'")


def test_i63_service_walks_the_folder_again_once_its_dacl_is_in_place() -> None:
    # The walk ran before Set-Acl only: an entry a local user created in the
    # window (audit\audit.jsonl in a subfolder that still had C:\ProgramData's
    # inherited create right) survived, user-owned, into the service's run.
    body = _main_body(_code(SERVICE_PS1))
    walks = [m.start() for m in re.finditer(r"\$found = Get-TreeProblem -Directory \$configDir", body)]
    assert len(walks) == 2, walks
    grant = body.index("':(OI)(CI)M'")
    assert walks[0] < body.index("Set-Acl -LiteralPath $configDir") < grant < walks[1]
    assert walks[1] < body.index("Stop-ExistingService -Name $ServiceName")
    assert re.match(r"\$found = Get-TreeProblem [^\n]*\n\s*if \(\$found\) \{\s*\n\s*Fail ", body[walks[1] :])
    assert "-SkipNames @('http-token')" in body[walks[1] : walks[1] + 120]


def test_i64_gate_token_squat_requires_a_regenerated_token_under_the_installed_account() -> None:
    # Check 3c passed on ANY 'SERVICE-ACTION FAILED', although service.ps1
    # never refuses a planted token (it replaces it), and re-registered the
    # service under LocalSystem even after an install under a dedicated
    # account.
    code = _code(GATE_PS1)
    squat = _squat_check(code)
    assert "-ServiceAccount 'LocalSystem'" not in squat
    assert "$squatAccount = 'LocalSystem'" in code
    fallback = "if ($installedService -and $installedService.StartName) { $squatAccount = $installedService.StartName }"
    assert fallback in code
    assert "-ServiceAccount $squatAccount" in squat
    assert "SERVICE-ACTION FAILED" not in squat
    assert re.search(r"if \(\$squatExit -ne 0\) \{\s*\n\s*Stop-Gate 'token_squat_refused'", squat), squat
    assert squat.count("Add-Check 'token_squat_refused' 'passed'") == 1


def test_i66_build_script_points_admins_at_program_files_for_trust_material() -> None:
    text = BUILD_MSI.read_text(encoding="utf-8")
    assert "ProgramData\\udbmcp-trust" not in text
    assert "universal-db-mcp\\keys" not in text
    assert "C:\\Program Files\\udbmcp-trust\\keys\\udbmcp-release.pub.pem" in text


def test_i67_localsystem_python_runs_are_isolated() -> None:
    # -I: no PYTHON* variables, no user site, no script or working directory
    # on sys.path for the interpreter the actions run as LocalSystem.
    verify = _code(VERIFY_PS1)
    assert "$pyArgs = @('-I')" in verify
    assert "& $pyExe -I -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)'" in verify
    doctor = _main_body(_code(DOCTOR_PS1))
    assert "$doctorArgs = @('-I', '-m', 'universal_db_mcp', 'doctor', '--config', $doctorConfigPath)" in doctor
    assert re.search(r"\$createArgs = @\(\s*\n\s*'-I',\s*\n\s*'-c',", doctor)
    service = _main_body(_code(SERVICE_PS1))
    assert "$binPath = '\"' + $python + '\" -I -m universal_db_mcp serve --transport http'" in service
    assert "-Arguments '-I -c \"import secrets; print(secrets.token_hex(32))\"'" in service


def test_i67_verify_checks_who_can_write_the_interpreter_directory() -> None:
    code = _code(VERIFY_PS1)
    check = _function(code, "Get-InterpreterProblem")
    assert "Get-WriteProblem $path" in check and "Get-GrantProblem $path $script:WriteRights" in check
    grant = _function(code, "Get-GrantProblem")
    assert "GetAccessRules($true, $true" in grant and "InheritOnly" in grant
    trusted = _function(code, "Test-TrustedOwner")
    for sid in ("$script:SidSystem", "$script:SidAdmins", "$script:SidTrustedInstaller"):
        assert sid in trusted
    assert not re.search(r"(?<!\w)&\s", _without_strings(check)), "cmdlets only before the trusted verifier"
    body = _main_body(code)
    use = body.index("$problem = Get-InterpreterProblem $pyExe")
    assert body.index("Test-InsideDir $pyExe $BundleDir") < use < body.index("& $pyExe -I -c")


# ------------------------------------------ executed: integration wave ----

PLANTED_TOKEN = {
    "owner": USER_SID,
    "protected": True,
    "rules": [[SID_SYSTEM, "Allow", "FullControl", False], [SID_ADMINS, "Allow", "FullControl", False]],
}


def _written_by(sid: str) -> dict[str, object]:
    """An entry the service account created in logs\\ (it inherits there)."""
    return {"owner": sid, "protected": False, "rules": [[sid, "Allow", "Modify", True]]}


@executed
def test_exec_i60_doctor_never_offers_to_launder_a_planted_token(host: _Host) -> None:
    # The reviewer's chain: a user plants http-token (a value they know)
    # with a DACL that looks protected. doctor.ps1 refused it and told the
    # administrator to hand it to Administrators; after that, service.ps1
    # kept it. Skipping the token in doctor.ps1 was not enough: the payload
    # doctor it runs (stubbed as the real one judges the service token)
    # refused the planted token as fatal, so the install rolled back before
    # service.ps1 could replace it, and the owner stayed the only lead.
    # doctor.ps1 now removes the token service.ps1 would replace before any
    # payload runs, and the registration action provisions a new one.
    host.token.write_text("attacker-known-value", encoding="utf-8")
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.config: SAFE, host.token: PLANTED_TOKEN})
    assert code == 0, out
    owner = f"is owned by {USER_SID}, not SYSTEM, Administrators or an administrator"
    assert f"'{host.token}' {owner}; removing it before doctor runs" in out, out
    assert "setowner" not in out and "FATAL" not in out, out
    assert not host.token.exists() and "python -I -m universal_db_mcp doctor" in calls
    code, out, calls = host.service(None)
    assert code == 0, out
    assert "provisioning HTTP bearer token" in out, out
    assert host.token.read_text(encoding="utf-8") == GENERATED


@executed
@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_exec_i60_doctor_refuses_a_token_that_is_no_file_without_an_owner_remedy(host: _Host, kind: str) -> None:
    victim = host.root / "victim"
    if kind == "symlink":
        host.token.symlink_to(victim)
    else:
        host.token.mkdir()
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.config: SAFE})
    assert code == 1, out
    assert "the install provisions a new token" in out and "setowner" not in out, out
    assert "python" not in calls and not victim.exists()


@executed
@pytest.mark.parametrize("account", ["LocalSystem", NETWORK_SERVICE])
def test_exec_i61_service_provisions_a_logs_folder_the_service_can_write(host: _Host, account: str) -> None:
    code, out, calls = host.service({host.cfgdir: SAFE}, account=account)
    assert code == 0, out
    logs = host.cfgdir / "logs"
    assert logs.is_dir()
    dedicated = account != "LocalSystem"
    grant = [[SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False]] if dedicated else []
    assert host.acl(logs) == {"owner": SID_ADMINS, "protected": True, "rules": SAFE["rules"] + grant}
    # the folder itself (config, secrets, token) stays read-only for it
    read = [[SID_NETWORK_SERVICE, "Allow", "(OI)(CI)RX", False]] if dedicated else []
    assert host.acl(host.cfgdir)["rules"] == SAFE["rules"] + read
    assert _line(calls, f"Set-Acl {host.cfgdir} ") < _line(calls, f"Set-Acl {logs} {PROTECTED_DIR_SDDL}")
    assert _line(calls, f"Set-Acl {logs} ") < _line(calls, "sc create")
    if dedicated:
        assert _line(calls, f"icacls {logs} | /grant:r | *{SID_NETWORK_SERVICE}:(OI)(CI)M") < _line(calls, "sc create")


@executed
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_i61_a_rerun_accepts_what_the_service_account_wrote_in_logs(host: _Host, script: str) -> None:
    # The service (NetworkService) owns the audit log and its lock it made in
    # logs\; a repair or upgrade must not refuse them.
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl: dict[Path, dict[str, object]] = {host.cfgdir: SAFE, host.config: SAFE, logs: SAFE}
    for name in ("audit.jsonl", "audit.jsonl.lock"):
        (logs / name).write_text("", encoding="utf-8")
        acl[logs / name] = _written_by(SID_NETWORK_SERVICE)
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account=NETWORK_SERVICE)
    assert code == 0, out


@executed
@pytest.mark.parametrize(
    "case", ["outside-logs", "other-folder", "other-account", "logs-folder-itself", "link-in-logs"]
)
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_i61_only_the_service_accounts_files_inside_logs_are_accepted(
    host: _Host, script: str, case: str
) -> None:
    logs = host.cfgdir / "logs"
    logs.mkdir()
    audit = host.cfgdir / "audit"
    audit.mkdir()
    acl: dict[Path, dict[str, object]] = {host.cfgdir: SAFE, host.config: SAFE, logs: SAFE, audit: SAFE}
    account = NETWORK_SERVICE
    if case == "logs-folder-itself":
        planted = logs
        acl[logs] = _written_by(SID_NETWORK_SERVICE)
    elif case == "link-in-logs":
        planted = logs / "audit.jsonl"
        planted.symlink_to(host.root / "victim")
    else:
        folder = {"outside-logs": host.cfgdir, "other-folder": audit}.get(case, logs)
        planted = folder / "audit.jsonl"
        planted.write_text("", encoding="utf-8")
        acl[planted] = _written_by(SID_NETWORK_SERVICE)
        if case == "other-account":
            account = "LocalSystem"
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account=account)
    assert code == 1, out
    assert f"'{planted}'" in out and "refusing" in out, out
    assert not any(ln.startswith(("sc ", "icacls ", "Set-Acl ", "python ")) for ln in calls.splitlines()), calls


@executed
def test_exec_i61_service_refuses_a_logs_entry_that_is_not_a_folder(host: _Host) -> None:
    logs = host.cfgdir / "logs"
    logs.write_text("", encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE, logs: SAFE}, account=NETWORK_SERVICE)
    assert code == 1 and f"'{logs}' is not a directory" in out, out
    assert not any(ln.startswith("sc ") for ln in calls.splitlines()), calls


_RELEASE_VERIFIER = f'''
"""Stub trusted verifier: the real release-order check of scripts/verify_bundle.py, no signatures."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("verify_bundle", {str(VERIFY_BUNDLE_PY)!r})
vb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vb)
ap = argparse.ArgumentParser()
ap.add_argument("--bundle")
ap.add_argument("--pubkey")
ap.add_argument("--installed-manifest")
ap.add_argument("--allow-downgrade", action="store_true")
args = ap.parse_args()
print("isolated=%d" % sys.flags.isolated)
manifest = json.loads((Path(args.bundle) / "manifest.json").read_text())
if args.installed_manifest:
    vb.check_release_order(manifest, Path(args.installed_manifest), args.allow_downgrade)
if vb.failed:
    print("bundle verification FAILED; do not install")
    sys.exit(1)
print("bundle verification PASSED")
'''

# A verifier from before anti-rollback: it parses options but has no
# --installed-manifest, so it would stop on the unknown option.
_OUTDATED_VERIFIER = """import argparse
import pathlib
ap = argparse.ArgumentParser()
ap.add_argument("--bundle")
ap.add_argument("--pubkey")
ap.parse_args()
pathlib.Path({canary!r}).write_text("ran")
print("bundle verification PASSED")
"""


def _release_install(
    host: _Host,
    bundle_seq: int,
    installed_seq: int | None,
    verifier: str = _RELEASE_VERIFIER,
    python: str | None = None,
) -> str:
    """CustomActionData for a bundle of *bundle_seq* over an install whose
    recorded release is *installed_seq* (None: nothing installed)."""
    data = _trusted_install(host, python)
    (host.root / "bundle" / "manifest.json").write_text(json.dumps({"release_seq": bundle_seq}), encoding="utf-8")
    (host.root / "trust" / "verify_bundle.py").write_text(verifier, encoding="utf-8")
    if installed_seq is not None:
        (host.root / "manifest.json").write_text(json.dumps({"release_seq": installed_seq}), encoding="utf-8")
    key = host.root / "keys" / "udbmcp-release.pub.pem"
    key.parent.mkdir()
    key.write_text("-----BEGIN PUBLIC KEY-----\n", encoding="utf-8")
    return f"{data};PUBKEY={key}"


@executed
def test_exec_i62_verify_refuses_an_older_release_than_the_installed_one(host: _Host) -> None:
    code, out, calls = host.verify(_release_install(host, bundle_seq=5, installed_seq=6))
    assert code == 1, out
    assert "FAIL: rollback refused" in out and "UDBMCP_ALLOW_DOWNGRADE=1" in out, out
    assert "bundle verification PASSED" not in out


@executed
def test_exec_i62_the_downgrade_override_applies_to_one_run_only(host: _Host) -> None:
    data = _release_install(host, bundle_seq=5, installed_seq=6)
    code, out, calls = host.verify(data + ";ALLOW_DOWNGRADE=1")
    assert code == 0, out
    assert "DOWNGRADE allowed by --allow-downgrade" in out, out
    code, out, calls = host.verify(data)
    assert code == 1 and "FAIL: rollback refused" in out, out


@executed
@pytest.mark.parametrize(
    ("installed_seq", "expected"),
    [(None, "nothing installed yet"), (5, "(not a downgrade)"), (4, "(not a downgrade)")],
    ids=["first-install", "reinstall", "upgrade"],
)
def test_exec_i62_verify_accepts_a_first_install_a_reinstall_and_an_upgrade(
    host: _Host, installed_seq: int | None, expected: str
) -> None:
    code, out, calls = host.verify(_release_install(host, bundle_seq=5, installed_seq=installed_seq))
    assert code == 0, out
    assert expected in out and f"{host.root / 'manifest.json'}" in out, out
    assert "isolated=1" in out, "the trusted verifier runs under -I"


@executed
def test_exec_i62_verify_refuses_an_outdated_trusted_verifier(host: _Host) -> None:
    canary = host.root / "outdated-verifier-ran"
    code, out, calls = host.verify(_release_install(host, 5, 6, verifier=_OUTDATED_VERIFIER.format(canary=str(canary))))
    assert code == 1 and "is an OUTDATED copy (no --installed-manifest option)" in out, out
    assert not canary.exists(), "the outdated verifier never runs"


@executed
def test_exec_i62_a_property_value_cannot_add_a_customactiondata_key(host: _Host) -> None:
    # UDBMCP_ALLOW_DOWNGRADE is a public msiexec property carried into
    # CustomActionData: a value such as "1;TRUST_DIR=<folder>" must not
    # replace the pinned trust directory.
    data = _release_install(host, bundle_seq=5, installed_seq=None)
    elsewhere = host.root / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "profiles.py").write_text("# registry\n", encoding="utf-8")
    (elsewhere / "verify_bundle.py").write_text("print('bundle verification PASSED')\n", encoding="utf-8")
    code, out, calls = host.verify(f"{data};TRUST_DIR={elsewhere}")
    assert code == 1 and "CustomActionData names TRUST_DIR twice" in out, out
    code, out, calls = host.verify(f"{data};ALLOW_DOWNGRADE=1;TRUST_DIR={elsewhere}")
    assert code == 1 and "CustomActionData names TRUST_DIR after ALLOW_DOWNGRADE" in out, out
    code, out, calls = host.verify(data + ";ALLOW_DOWNGRADE=yes")
    assert code == 1 and "ALLOW_DOWNGRADE='yes' is not understood" in out, out


@executed
@pytest.mark.parametrize("plant", ["user-owned", "symlink"])
def test_exec_i62_verify_refuses_a_squatted_installed_manifest(host: _Host, plant: str) -> None:
    data = _release_install(host, bundle_seq=5, installed_seq=None)
    record = host.root / "manifest.json"
    acl: dict[Path, dict[str, object]] = {}
    if plant == "symlink":
        record.symlink_to(host.root / "elsewhere.json")
    else:
        record.write_text('{"release_seq": 1}', encoding="utf-8")
        acl[record] = USER_OWNED
    code, out, calls = host.verify(data, acl)
    assert code == 1 and f"'{record}'" in out, out
    assert "isolated=" not in out, "the verifier never runs"


@executed
def test_exec_i62_service_records_the_installed_release_once_registered(host: _Host) -> None:
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"release_seq": 7}', encoding="utf-8")
    record = bundle.parent / "manifest.json"
    # an earlier release's record is replaced by this one
    record.write_text('{"release_seq": 6}', encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle)
    assert code == 0, out
    assert record.read_text(encoding="utf-8") == '{"release_seq": 7}'


@executed
def test_exec_i62_service_records_nothing_when_the_registration_fails(host: _Host) -> None:
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"release_seq": 7}', encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, H_REG_FAIL="1")
    assert code == 1, out
    assert not (bundle.parent / "manifest.json").exists()
    assert "sc delete" in calls, "the half-registered service is removed"


@executed
def test_exec_i62_service_refuses_to_record_through_a_link(host: _Host) -> None:
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"release_seq": 7}', encoding="utf-8")
    victim = host.root / "victim.json"
    (bundle.parent / "manifest.json").symlink_to(victim)
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle)
    assert code == 1 and "reparse point" in out, out
    assert not victim.exists()
    assert "sc delete" in calls


@executed
def test_exec_i63_service_rechecks_the_folder_after_its_dacl_lands(host: _Host) -> None:
    # A local user creates audit\audit.jsonl between the walk and the DACL
    # (the subfolder still carries C:\ProgramData's inherited create right).
    audit = host.cfgdir / "audit"
    audit.mkdir()
    planted = audit / "audit.jsonl"
    acl = {host.cfgdir: SAFE, host.config: SAFE, audit: _entry(SID_SYSTEM, protected=False)}
    code, out, calls = host.service(acl, H_RACE=f"{host.cfgdir}|{planted}")
    assert "RACE planted" in calls, calls
    assert code == 1, out
    assert f"'{planted}' in it is owned by {USER_SID}" in out, out
    assert not any(ln.startswith("sc ") for ln in calls.splitlines()), "refused before the old service is touched"
    assert not host.token.exists()


@executed
def test_exec_i65_doctor_rechecks_smoke_after_its_dacl_lands(host: _Host) -> None:
    # The same race on smoke\: an entry planted while the protected DACL is
    # applied is refused before any payload runs.
    planted = host.smoke / "audit.jsonl"
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.config: SAFE}, H_RACE=f"{host.smoke}|{planted}")
    assert "RACE planted" in calls, calls
    assert code == 1, out
    assert f"'{planted}' is owned by {USER_SID}" in out, out
    assert "python" not in calls, calls


@executed
@pytest.mark.parametrize(
    ("folder_acl", "reason"),
    [
        (_entry(SID_ADMINS, [USER_SID, "Allow", "Modify", False]), f"grants {USER_SID} Modify"),
        # C:\PythonXY inherits Modify for Authenticated Users from C:\
        (_entry(SID_ADMINS, ["S-1-5-11", "Allow", "Modify, Synchronize", True]), "grants S-1-5-11"),
        (_entry(SID_ADMINS, ["S-1-5-32-545", "Allow", "CreateFiles", False]), "grants S-1-5-32-545"),
        (USER_OWNED, f"is owned by {USER_SID}"),
    ],
    ids=["user-modify", "inherited-authenticated-users", "users-create-files", "user-owned"],
)
def test_exec_i67_verify_refuses_an_interpreter_others_can_write(
    host: _Host, folder_acl: dict[str, object], reason: str
) -> None:
    exe = _interpreter(host)
    data = _release_install(host, 5, None)
    code, out, calls = host.verify(data, {exe.parent: folder_acl})
    assert code == 1, out
    assert f"'{exe.parent}' {reason}" in out, out
    assert "isolated=" not in out, "the interpreter never runs"


@executed
def test_exec_i67_verify_accepts_an_interpreter_only_admins_can_write(host: _Host) -> None:
    # The ACL a per-machine python.org install inherits from Program Files:
    # CREATOR OWNER's ACE is inherit-only (it grants nothing on the folder).
    exe = _interpreter(host)
    trusted_installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    folder_acl = {
        "owner": trusted_installer,
        "protected": False,
        "rules": [
            [trusted_installer, "Allow", "FullControl", True],
            [SID_SYSTEM, "Allow", "FullControl", True],
            [SID_ADMINS, "Allow", "FullControl", True],
            ["S-1-5-32-545", "Allow", "ReadAndExecute, Synchronize", True],
            ["S-1-3-0", "Allow", "FullControl", True, "InheritOnly"],
            ["S-1-15-2-1", "Allow", "ReadAndExecute, Synchronize", True],
        ],
    }
    data = _release_install(host, 5, None)
    code, out, calls = host.verify(data, {exe.parent: folder_acl})
    assert code == 0, out
    assert "isolated=1" in out


# ============================================ fix-up round 1 (R1) ==
#
# Residuals of the review of the integration wave. Their root cause: the
# walks judged an entry's owner only, and the refusals offered an owner
# change as the remedy. A new owner keeps every ACE on the entry and
# whatever its creator already changed below it, so the release key chain,
# the log folder and the config folder walks judge the DACL too, and no
# refusal offers an owner (or ACL) change any more.

SID_USERS = "S-1-5-32-545"
SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


def _service_sid(name: str) -> str:
    """The SID Windows derives for the virtual account NT SERVICE\\<name>
    ('sc.exe showsid <name>'): S-1-5-80- and the SHA-1 of the upper-cased
    UTF-16LE name as five little-endian 32-bit numbers."""
    digest = hashlib.sha1(name.upper().encode("utf-16-le")).digest()  # noqa: S324 - Windows' derivation
    return "S-1-5-80-" + "-".join(str(n) for n in struct.unpack("<5I", digest))

CREATOR_OWNER_IO = ["S-1-3-0", "Allow", "FullControl", True, "InheritOnly"]
# What C:\ProgramData's DACL lets every user do in a folder made in it.
USERS_CREATE = [SID_USERS, "Allow", "CreateFiles, CreateDirectories, WriteExtendedAttributes, WriteAttributes", True]
PROGRAM_DATA = {
    "owner": SID_SYSTEM,
    "protected": True,
    "rules": [
        [SID_SYSTEM, "Allow", "FullControl", False],
        [SID_ADMINS, "Allow", "FullControl", False],
        ["S-1-3-0", "Allow", "FullControl", False, "InheritOnly"],
        [SID_USERS, "Allow", "ReadAndExecute, Synchronize", False],
        [*USERS_CREATE[:3], False],
    ],
}
# A per-machine python.org install: inherited from Program Files.
PYTHON_ORG_FOLDER = {
    "owner": SID_TRUSTED_INSTALLER,
    "protected": False,
    "rules": [
        [SID_TRUSTED_INSTALLER, "Allow", "FullControl", True],
        [SID_SYSTEM, "Allow", "FullControl", True],
        [SID_ADMINS, "Allow", "FullControl", True],
        [SID_USERS, "Allow", "ReadAndExecute, Synchronize", True],
        CREATOR_OWNER_IO,
    ],
}
RECORD = "[ProgramFiles64Folder]UniversalDB MCP\\manifest.json"


def _programdata_child(owner: str, *, folder: bool = True) -> dict[str, object]:
    """The DACL an entry made under C:\\ProgramData inherits: SYSTEM,
    Administrators and its creator (CREATOR OWNER) Full Control, Users read
    and, in a folder, create entries."""
    rules: list[list[object]] = [
        [SID_SYSTEM, "Allow", "FullControl", True],
        [SID_ADMINS, "Allow", "FullControl", True],
        [owner, "Allow", "FullControl", True],
        [SID_USERS, "Allow", "ReadAndExecute, Synchronize", True],
    ]
    if folder:
        rules += [USERS_CREATE, CREATOR_OWNER_IO]
    return {"owner": owner, "protected": False, "rules": rules}


def _key(path: Path, text: str = "-----BEGIN PUBLIC KEY-----\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _changed_nothing(calls: str) -> bool:
    return not any(ln.startswith(("sc ", "icacls ", "Set-Acl ", "python ")) for ln in calls.splitlines())


# ---------------------------------------------- R1 static pins ----


def test_r1_no_refusal_offers_an_owner_change() -> None:
    # "icacls <entry> /setowner *S-1-5-32-544" made every owner on a path an
    # administrator's without undoing anything its creator could do or had
    # done: the refused key, log folder or config entry then passed.
    for path in (VERIFY_PS1, DOCTOR_PS1):
        assert "setowner" not in path.read_text(encoding="utf-8"), path.name
    service = _code(SERVICE_PS1)
    assert service.count("setowner") == 1, "only Set-ProtectedAcl's own icacls step"
    assert "' /setowner *' + $script:SidAdmins" in _function(service, "Set-ProtectedAcl")


def test_r1_verify_judges_the_dacl_along_the_key_and_of_the_log_folder() -> None:
    code = _code(VERIFY_PS1)
    grant = _function(code, "Get-GrantProblem")
    assert "GetAccessRules($true, $true" in grant and "InheritOnly" in grant
    assert "Test-TrustedOwner $rule.IdentityReference.Value" in grant
    assert not re.search(r"(?<!\w)&\s", _without_strings(grant)), "cmdlets only before the trusted verifier"
    # on a folder: delete or rename what is in it or itself, change its DACL
    # or owner (create rights, which every user has in C:\ProgramData, do not count)
    assert "$script:ReplaceRights = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000" in code
    init = _function(code, "Initialize-LogDirectory")
    judged = init.index("Get-GrantProblem $dir $script:ReplaceRights")
    assert init.index("$problem = Get-WriteProblem $dir") < judged < init.index("Set-Acl -LiteralPath $dir")
    body = _main_body(code)
    guard = body.index("if (-not ($env:ProgramFiles -and (Test-InsideDir $PubKey $env:ProgramFiles))) {")
    walk = body[guard : body.index("\n    }\n", guard)]
    key_rights = walk.index("$rights = $script:WriteRights")
    judge = walk.index("$problem = Get-GrantProblem $keyPath $rights")
    assert key_rights < judge < walk.index("$rights = $script:ReplaceRights")


def test_r1_verify_judges_what_the_interpreter_loads_at_startup() -> None:
    check = _function(_code(VERIFY_PS1), "Get-InterpreterProblem")
    # every file beside the interpreter, and Lib (site-packages and its .pth
    # files included) and DLLs at any depth
    for part in ("'Lib'", "'DLLs'", "Get-ChildItem -LiteralPath $dir -File -Force", "Get-TreeGrantProblem"):
        assert part in check, part
    assert "Get-WriteProblem $path" in check and "Get-GrantProblem $path $script:WriteRights" in check
    assert "$problem = Get-InterpreterProblem $pyExe" in _main_body(_code(VERIFY_PS1))


def test_r1_walks_judge_an_entrys_own_aces_too() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        code = _code(path)
        assert "$script:WriteRights = " in code, path.name
        problem = _function(code, "Get-WriteProblem")
        assert "[string]$WriterSid = $OwnerSid" in problem, path.name
        assert "$rule.IsInherited" in problem and "$script:WriteRights" in problem, path.name
        walk = _function(code, "Get-TreeProblem")
        assert "Get-WriteProblem -Path $entry.FullName -OwnerSid $OwnerSid -WriterSid $below" in walk, path.name
        assert walk.index("$below = $LogsSid") < walk.index("-WriterSid $below"), path.name
    body = _main_body(_code(SERVICE_PS1))
    assert "$problem = Get-WriteProblem -Path $logsDir -WriterSid $serviceSid" in body


def test_r1_service_account_must_be_one_a_service_runs_as() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        sid = _function(_code(path), "Test-AccountSid")
        # a service SID has five sub-authorities; S-1-5-80-0 is the group of all services
        assert "'^S-1-5-(1[89]|20|80(-\\d+){5}|21(-\\d+){4})$'" in sid, path.name
        assert "'^S-1-5-21(-\\d+){3}-(498|5[1-9]\\d)$'" in sid, path.name
    assert _function(_code(DOCTOR_PS1), "Get-ServiceAccountSid") == _function(
        _code(SERVICE_PS1), "Get-ServiceAccountSid"
    )


def test_r1_wxs_passes_the_downgrade_property_last_and_checks_its_value() -> None:
    cmd = _custom_action_commands()["VerifyBundleCA"]
    start = cmd.index('-CustomActionData "') + len('-CustomActionData "')
    cad = cmd[start : cmd.rindex('"')]
    assert cad.endswith(";ALLOW_DOWNGRADE=[UDBMCP_ALLOW_DOWNGRADE]"), cad
    assert re.findall(r"\[(\w+)\]", cad) == ["INSTALLFOLDER", "ProgramFiles64Folder", "ProgramFiles64Folder",
                                             "UDBMCP_ALLOW_DOWNGRADE"], "the one public property comes last"
    launches = [el.get("Condition") for el in _wxs_root().iter() if _local(el) == "Launch"]
    assert 'NOT UDBMCP_ALLOW_DOWNGRADE OR UDBMCP_ALLOW_DOWNGRADE="1"' in launches, launches


def test_r1_wxs_pins_the_release_record_to_program_files() -> None:
    # The record sat at [INSTALLFOLDER]manifest.json. INSTALLFOLDER is a
    # public property the wxs does not remember, so an install to another
    # folder found no record and accepted any older release.
    cmds = _custom_action_commands()
    assert f"INSTALLED_MANIFEST={RECORD};ALLOW_DOWNGRADE=" in cmds["VerifyBundleCA"]
    assert f'-InstalledManifest "{RECORD}"' in cmds["RegisterServiceCA"]
    assert "[INSTALLFOLDER]manifest.json" not in WXS.read_text(encoding="utf-8")
    body = _main_body(_code(VERIFY_PS1))
    assert "$InstalledManifest = $data['INSTALLED_MANIFEST']" in body
    assert body.index("$InstalledManifest = $data['INSTALLED_MANIFEST']") < body.index("Split-Path -Parent (Real-Path")


# ------------------------------- R1 executed: the release key chain ----


@executed
@pytest.mark.parametrize("where", ["log-folder", "elsewhere"])
def test_exec_r1_verify_still_uses_a_key_an_administrator_put_under_programdata(host: _Host, where: str) -> None:
    # An upgrading site that followed the earlier docs: an earlier verify.ps1
    # (LocalSystem) made C:\ProgramData\universal-db-mcp, and an
    # administrator made keys\ in it and copied the key there. The create
    # rights every user has in such folders change nothing on the path to
    # the key, so it is still used.
    data = _release_install(host, 5, None).rsplit(";PUBKEY=", 1)[0]
    top = host.program_data if where == "log-folder" else host.root / "PD"
    legacy = top / "universal-db-mcp"
    key = _key(legacy / "keys" / "udbmcp-release.pub.pem")
    acl = {
        top: PROGRAM_DATA,
        legacy: _programdata_child(SID_SYSTEM),
        key.parent: _programdata_child(ADMIN_USER_SID),
        key: _programdata_child(ADMIN_USER_SID, folder=False),
    }
    code, out, calls = host.verify(f"{data};PUBKEY={key}", acl, H_ADMIN_MEMBERS=ADMIN_USER_SID)
    assert code == 0, out
    assert "isolated=1" in out


@executed
@pytest.mark.parametrize("owner", [USER_SID, SID_ADMINS], ids=["as-made", "owner-changed"])
def test_exec_r1_verify_refuses_a_key_folder_a_user_made_whoever_owns_it_now(host: _Host, owner: str) -> None:
    # A user made the folder above keys\ first, so it grants them Full
    # Control (CREATOR OWNER): they can put a keys\ and key of their own in
    # place of the administrator's. The owner change the refusal used to
    # offer keeps that ACE.
    data = _release_install(host, 5, None).rsplit(";PUBKEY=", 1)[0]
    legacy = host.root / "PD" / "universal-db-mcp"
    key = _key(legacy / "keys" / "udbmcp-release.pub.pem")
    acl = {
        legacy: dict(_programdata_child(USER_SID), owner=owner),
        key.parent: _programdata_child(SID_ADMINS),
        key: _programdata_child(SID_ADMINS, folder=False),
    }
    code, out, calls = host.verify(f"{data};PUBKEY={key}", acl)
    assert code == 1, out
    reason = f"is owned by {USER_SID}" if owner == USER_SID else f"grants {USER_SID} FullControl"
    assert f"release public key: '{legacy}' {reason}" in out, out
    assert "setowner" not in out and "C:\\Program Files\\udbmcp-trust\\keys\\udbmcp-release.pub.pem" in out
    assert "isolated=" not in out, "the verifier never runs"


@executed
@pytest.mark.parametrize(
    ("target", "rights"),
    [
        ("key", "Write"),
        ("key", "AppendData"),
        ("key", "Modify, Synchronize"),
        ("key", "ChangePermissions"),
        ("keys", "DeleteSubdirectoriesAndFiles"),
        ("keys", "Delete"),
        ("keys", "TakeOwnership"),
        ("above", "FullControl"),
    ],
)
def test_exec_r1_verify_refuses_an_admin_owned_key_path_a_user_can_change(
    host: _Host, target: str, rights: str
) -> None:
    data = _release_install(host, 5, None)
    key = host.root / "keys" / "udbmcp-release.pub.pem"
    path = {"key": key, "keys": key.parent, "above": host.root}[target]
    code, out, calls = host.verify(data, {path: _entry(SID_ADMINS, [USER_SID, "Allow", rights, False])})
    assert code == 1, out
    assert f"release public key: '{path}' grants {USER_SID}" in out, out
    assert "setowner" not in out and "isolated=" not in out


_KEY_ECHO_VERIFIER = """import argparse
ap = argparse.ArgumentParser()
for option in ("--bundle", "--pubkey", "--installed-manifest"):
    ap.add_argument(option)
args = ap.parse_args()
print("KEY CONTENT: " + open(args.pubkey).read().strip())
print("bundle verification PASSED")
"""


@executed
def test_exec_r1_verify_judges_the_log_folder_before_its_dacl_hides_a_swapped_key(host: _Host) -> None:
    # The earlier docs put the key in C:\ProgramData\universal-db-mcp\keys,
    # the folder verify.ps1 logs to. A user made that folder first and gave
    # it an inheritable ACE for themselves, so the key an administrator
    # copied in inherited their write access and they rewrote it. After an
    # owner change the folder passed, and the Set-Acl that protects it
    # recomputes what keys\ and the key inherit: the swapped key looked clean.
    data = _release_install(host, 5, None, verifier=_KEY_ECHO_VERIFIER).rsplit(";PUBKEY=", 1)[0]
    legacy = host.program_data / "universal-db-mcp"
    key = _key(legacy / "keys" / "udbmcp-release.pub.pem", "ATTACKER PUBLIC KEY\n")
    inherited_from_user = {"owner": SID_ADMINS, "protected": False,
                           "rules": [*SAFE["rules"], [USER_SID, "Allow", "FullControl", True]]}
    acl = {
        legacy: _entry(USER_SID, [USER_SID, "Allow", "FullControl", False], protected=False),
        key.parent: inherited_from_user,
        key: dict(inherited_from_user),
    }
    code, out, calls = host.verify(data, acl, UDBMCP_RELEASE_PUBKEY=str(key))
    assert code == 1 and f"refusing to write the install log: '{legacy}' is owned by {USER_SID}" in out, out
    acl[legacy] = dict(acl[legacy], owner=SID_ADMINS)  # an owner change, against the advice
    code, out, calls = host.verify(data, acl, UDBMCP_RELEASE_PUBKEY=str(key))
    assert code == 1, out
    assert f"refusing to write the install log: '{legacy}' grants {USER_SID} FullControl" in out, out
    assert "setowner" not in out and "remove it" in out
    assert "Set-Acl" not in calls and "KEY CONTENT" not in out


@executed
def test_exec_r1_verify_refuses_a_release_record_a_user_can_rewrite(host: _Host) -> None:
    data = _release_install(host, bundle_seq=5, installed_seq=6)
    record = host.root / "manifest.json"
    code, out, calls = host.verify(data, {record: _entry(SID_ADMINS, [USER_SID, "Allow", "Write", False])})
    assert code == 1 and f"the installed release record '{record}' grants {USER_SID}" in out, out
    assert "isolated=" not in out


# ------------------------------ R1 executed: the interpreter tree ----


def _interpreter_tree(host: _Host) -> dict[str, Path]:
    """The parts of a python.org install that Python loads code from at startup."""
    exe = _interpreter(host)
    site = exe.parent / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (exe.parent / "DLLs").mkdir()
    dll = exe.parent / "python312.dll"
    dll.write_bytes(b"MZ")
    pth = site / "distutils-precedence.pth"
    pth.write_text("import os\n", encoding="utf-8")
    return {
        "folder": exe.parent,
        "Lib": site.parent,
        "site-packages": site,
        "DLLs": exe.parent / "DLLs",
        "python.exe": exe,
        "dll": dll,
        "pth": pth,
    }


@executed
@pytest.mark.parametrize("weak", ["Lib", "site-packages", "DLLs", "python.exe", "dll", "pth"])
def test_exec_r1_verify_refuses_an_interpreter_whose_startup_files_others_can_write(host: _Host, weak: str) -> None:
    # Only the interpreter's folder was judged: a Users-writable
    # site-packages (-I does not skip its .pth files), Lib, DLLs, python.exe
    # or a DLL beside it ran code in the LocalSystem verifier all the same.
    tree = _interpreter_tree(host)
    target = tree[weak]
    users_modify = _entry(SID_ADMINS, [SID_USERS, "Allow", "Modify, Synchronize", True], protected=False)
    acl = {tree["folder"]: PYTHON_ORG_FOLDER, target: users_modify}
    code, out, calls = host.verify(_release_install(host, 5, None), acl)
    assert code == 1, out
    assert f"python interpreter: '{target}' grants {SID_USERS}" in out, out
    assert "isolated=" not in out, "the interpreter never runs"


@executed
def test_exec_r1_verify_refuses_a_linked_interpreter(host: _Host) -> None:
    exe = _interpreter(host)
    real = host.root / "elsewhere" / "python.exe"
    real.parent.mkdir()
    exe.rename(real)
    exe.symlink_to(real)
    code, out, calls = host.verify(_release_install(host, 5, None), {exe.parent: PYTHON_ORG_FOLDER})
    assert code == 1 and f"python interpreter: '{exe}' is a reparse point" in out, out


@executed
def test_exec_r1_verify_accepts_an_interpreter_tree_only_admins_can_write(host: _Host) -> None:
    tree = _interpreter_tree(host)
    code, out, calls = host.verify(_release_install(host, 5, None), {tree["folder"]: PYTHON_ORG_FOLDER})
    assert code == 0, out
    assert "isolated=1" in out
    for part in tree.values():
        assert f"Get-Acl {part}\n" in calls, f"{part} is judged"


# --------------------- R1 executed: CustomActionData and the record ----


@executed
@pytest.mark.parametrize("injected", ["PUBKEY", "PYTHON", "TRUST_DIR", "ALLOW_DOWNGRADE"])
def test_exec_r1_verify_refuses_any_key_after_the_downgrade_property(host: _Host, injected: str) -> None:
    # ALLOW_DOWNGRADE=[UDBMCP_ALLOW_DOWNGRADE] is the one public msiexec
    # property in the CustomActionData, and the wxs passes it last. A value
    # such as "1;PUBKEY=<file>" added a key the wxs never passes, which
    # overrode the administrator's machine-wide UDBMCP_RELEASE_PUBKEY (or
    # UDBMCP_PYTHON): it was no duplicate, so the duplicate check missed it.
    _release_install(host, 5, None)
    admin = {
        "UDBMCP_RELEASE_PUBKEY": str(host.root / "keys" / "udbmcp-release.pub.pem"),
        "UDBMCP_PYTHON": str(_interpreter(host)),
    }
    wxs_shaped = (
        f"BUNDLE_DIR={host.root / 'bundle'};TRUST_DIR={host.root / 'trust'};"
        f"INSTALLED_MANIFEST={host.root / 'manifest.json'};ALLOW_DOWNGRADE=1"
    )
    code, out, calls = host.verify(wxs_shaped, None, **admin)
    assert code == 0, out
    other = host.root / "other"
    value = {
        "PUBKEY": str(_key(other / "attacker.pem")),
        "PYTHON": str(_interpreter(host)),
        "TRUST_DIR": str(other),
        "ALLOW_DOWNGRADE": "",
    }[injected]
    code, out, calls = host.verify(f"{wxs_shaped};{injected}={value}", None, **admin)
    assert code == 1 and f"CustomActionData names {injected} after ALLOW_DOWNGRADE" in out, out
    assert "isolated=" not in out


@executed
def test_exec_r1_verify_reads_the_record_the_wxs_names(host: _Host) -> None:
    data = _release_install(host, bundle_seq=5, installed_seq=None)
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"release_seq": 6}), encoding="utf-8")
    code, out, calls = host.verify(f"{data};INSTALLED_MANIFEST={record}")
    assert code == 1 and "FAIL: rollback refused" in out and f"installed manifest {record}" in out, out


@executed
def test_exec_r1_service_records_the_release_where_the_wxs_says(host: _Host) -> None:
    # A custom INSTALLFOLDER no longer moves the record: its folder under
    # Program Files is made when it does not exist.
    bundle = host.root / "D" / "custom" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"release_seq": 7}', encoding="utf-8")
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, record=record)
    assert code == 0, out
    assert record.read_text(encoding="utf-8") == '{"release_seq": 7}'
    assert not (bundle.parent / "manifest.json").exists()


# ----------------------------- R1 executed: the config folder walks ----


@executed
@pytest.mark.parametrize(
    "case",
    [
        "protected-user-folder",
        "user-ace-on-admin-file",
        "user-inherit-only-ace",
        "users-create-made-explicit",
        "service-account-ace-outside-logs",
        "group-ace-on-logs",
        "previous-account-full-control-on-logs",
    ],
)
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_r1_walks_refuse_an_entry_whose_own_dacl_lets_another_account_write(
    host: _Host, script: str, case: str
) -> None:
    # The reviewer's chain: audit\ a user made with a protected DACL granting
    # themselves Full Control, refused with the owner-change remedy; after
    # it, both walks passed and the user kept Full Control (the folder's
    # Set-Acl does not reach a protected child, nor remove explicit ACEs).
    audit = host.cfgdir / "audit"
    audit.mkdir()
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl: dict[Path, dict[str, object]] = {host.cfgdir: SAFE, host.config: SAFE, audit: SAFE, logs: SAFE}
    account, writer, planted = NETWORK_SERVICE, USER_SID, audit
    if case == "protected-user-folder":
        acl[audit] = {"owner": SID_ADMINS, "protected": True, "rules": [[USER_SID, "Allow", "FullControl", False]]}
    elif case == "user-ace-on-admin-file":
        planted = host.cfgdir / "metadata-cache.sqlite"
        planted.write_text("", encoding="utf-8")
        acl[planted] = _entry(SID_ADMINS, [USER_SID, "Allow", "Write", False])
    elif case == "user-inherit-only-ace":
        # whatever the service creates in audit\ later is the user's too
        acl[audit] = _entry(SID_ADMINS, [USER_SID, "Allow", "FullControl", False, "InheritOnly"])
    elif case == "users-create-made-explicit":
        # inheritance disabled with the inherited ACEs copied
        writer = SID_USERS
        acl[audit] = _entry(SID_ADMINS, [*USERS_CREATE[:3], False])
    elif case == "service-account-ace-outside-logs":
        writer = SID_NETWORK_SERVICE
        acl[audit] = _entry(SID_ADMINS, [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False])
    elif case == "group-ace-on-logs":
        # an earlier service account's Modify on logs\ is accepted (see
        # test_exec_w2_i61_*); a group's never is
        writer, planted = SID_USERS, logs
        acl[logs] = _entry(SID_ADMINS, [SID_USERS, "Allow", "(OI)(CI)M", False])
    else:
        # more than the Modify the actions grant: it may have changed the DACL
        account, writer, planted = "LocalSystem", SID_NETWORK_SERVICE, logs
        acl[logs] = _entry(SID_ADMINS, [SID_NETWORK_SERVICE, "Allow", "FullControl", False])
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account=account)
    assert code == 1, out
    assert f"'{planted}' in it grants {writer}" in out, out
    # logs\ holds the audit log: moved aside and archived, never deleted
    remedy = "move it out of" if planted == logs else "remove it"
    assert "setowner" not in out and remedy in out, out
    assert _changed_nothing(calls), calls


@executed
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_r1_walks_accept_inherited_aces_and_the_service_accounts_own_grant(host: _Host, script: str) -> None:
    # What an upgrade finds: a subfolder that inherited C:\ProgramData's
    # ACEs (Users may create entries; the folder's DACL replaces them), and
    # logs\ as the previous run left it, with the service account's Modify
    # and the files it wrote.
    audit = host.cfgdir / "audit"
    audit.mkdir()
    logs = host.cfgdir / "logs"
    logs.mkdir()
    (logs / "audit.jsonl").write_text("", encoding="utf-8")
    acl = {
        host.cfgdir: SAFE,
        host.config: SAFE,
        audit: _programdata_child(SID_SYSTEM),
        logs: _entry(SID_ADMINS, [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False]),
        logs / "audit.jsonl": _written_by(SID_NETWORK_SERVICE),
    }
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account=NETWORK_SERVICE)
    assert code == 0, out


@executed
@pytest.mark.parametrize("existing", [True, False], ids=["made-earlier", "absent"])
@pytest.mark.parametrize("account", ["LocalSystem", NETWORK_SERVICE])
def test_exec_r1_doctor_accepts_the_logs_folder_the_msi_makes(host: _Host, account: str, existing: bool) -> None:
    # The recommended migration: the state paths point at logs\, which
    # doctor.ps1 makes when it is absent (SYSTEM and Administrators, nothing
    # inherited) before it runs doctor against that config; doctor treats a
    # missing parent of either path as fatal.
    host.config.write_text(
        "application:\n  audit_path: logs/audit.jsonl\n  metadata_cache_path: logs/metadata-cache.sqlite\n"
        "connections: {}\n",
        encoding="utf-8",
    )
    logs = host.cfgdir / "logs"
    acl = {host.cfgdir: SAFE, host.config: SAFE}
    if existing:
        logs.mkdir()
        acl[logs] = _entry(SID_SYSTEM)
    code, out, calls = host.doctor(acl, account=account)
    assert code == 0, out
    assert logs.is_dir()
    owner = SID_SYSTEM if existing else SID_ADMINS
    assert host.acl(logs) == {"owner": owner, "protected": True, "rules": SAFE["rules"]}
    assert "python -I -m universal_db_mcp doctor" in calls


# ----------------------------------- R1 executed: the service account ----

ACCOUNTS = ";".join(
    [
        "BUILTIN\\Users=S-1-5-32-545",
        "NT AUTHORITY\\Authenticated Users=S-1-5-11",
        "Everyone=S-1-1-0",
        "NT AUTHORITY\\INTERACTIVE=S-1-5-4",
        "CORP\\Domain Users=S-1-5-21-10-20-30-513",
        "ALL SERVICES=S-1-5-80-0",  # NT SERVICE\ALL SERVICES, a group every service is in
        "HOST\\svc-udbmcp=S-1-5-21-1111-2222-3333-1005",
        "NT SERVICE\\udbmcp=" + _service_sid("udbmcp"),
        "CORP\\udbmcp-gmsa$=S-1-5-21-10-20-30-4101",
    ]
)


@executed
@pytest.mark.parametrize(
    "account",
    [
        "BUILTIN\\Users",
        "NT AUTHORITY\\Authenticated Users",
        "Everyone",
        "NT AUTHORITY\\INTERACTIVE",
        "CORP\\Domain Users",
        "ALL SERVICES",
    ],
)
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_r1_a_group_is_never_the_service_account(host: _Host, script: str, account: str) -> None:
    # The account's SID is granted read access to the config folder and the
    # token, and Modify on logs\, before sc.exe create could refuse a group:
    # every member of BUILTIN\Users would have read the token.
    run = host.service if script == "service" else host.doctor
    code, out, calls = run({host.cfgdir: SAFE, host.config: SAFE}, account=account, H_ACCOUNTS=ACCOUNTS)
    assert code == 1, out
    assert f"service account '{account}' resolves to " in out, out
    assert _changed_nothing(calls), calls
    assert not host.token.exists()


@executed
@pytest.mark.parametrize(
    ("account", "sid"),
    [
        ("HOST\\svc-udbmcp", "S-1-5-21-1111-2222-3333-1005"),
        ("NT SERVICE\\udbmcp", _service_sid("udbmcp")),
        ("CORP\\udbmcp-gmsa$", "S-1-5-21-10-20-30-4101"),
    ],
)
def test_exec_r1_accounts_a_service_runs_as_are_accepted(host: _Host, account: str, sid: str) -> None:
    code, out, calls = host.service({host.cfgdir: SAFE}, account=account, H_ACCOUNTS=ACCOUNTS)
    assert code == 0, out
    assert f"icacls {host.cfgdir / 'logs'} | /grant:r | *{sid}:(OI)(CI)M" in calls, calls


# ================================== integration wave, second review (W2) ==
#
# Residuals of the review of the integration wave's fix-up round.
#   I60: the payload doctor that DoctorSmokeCA runs refuses an untrusted
#        service token as fatal, so the install rolled back before
#        RegisterServiceCA could replace it, and changing the owner the
#        doctor named still laundered a planted value. doctor.ps1 now applies
#        service.ps1's token rule and removes such a token before any
#        payload runs.
#   I67: CPython reads pyvenv.cfg from the folder above the interpreter even
#        under -I and then runs that folder's .pth files; that folder, and
#        what is below Lib and DLLs, were not judged.
#   I61: a standard user's repair passed the service account and downgrade
#        properties to the SYSTEM actions; logs\ was made by CreateFolders
#        before any junction check; an account change was refused with a
#        remedy that deleted the audit log.
#   I62: the release record had no rollback twin.

PROGRAM_FILES = {
    # C:\Program Files, the folder above a per-machine python.org install
    "owner": SID_TRUSTED_INSTALLER,
    "protected": True,
    "rules": [
        [SID_TRUSTED_INSTALLER, "Allow", "FullControl", False],
        [SID_SYSTEM, "Allow", "Modify, Synchronize", False],
        [SID_SYSTEM, "Allow", "FullControl", False, "InheritOnly"],
        [SID_ADMINS, "Allow", "Modify, Synchronize", False],
        [SID_ADMINS, "Allow", "FullControl", False, "InheritOnly"],
        [SID_USERS, "Allow", "ReadAndExecute, Synchronize", False],
        ["S-1-3-0", "Allow", "FullControl", False, "InheritOnly"],
        ["S-1-15-2-1", "Allow", "ReadAndExecute, Synchronize", False],
    ],
}
SID_LOCAL_SERVICE = "S-1-5-19"
LOCAL_SERVICE = "NT AUTHORITY\\LocalService"
DEDICATED_SID = "S-1-5-21-1111-2222-3333-1005"


def _token_acl(*extra: list[object]) -> dict[str, object]:
    """TOKEN_ACL (what service.ps1 leaves on the token) with *extra* ACEs."""
    rules: list[list[object]] = [[SID_SYSTEM, "Allow", "F", False], [SID_ADMINS, "Allow", "F", False], *extra]
    return {**TOKEN_ACL, "rules": rules}


# ----------------------------------------- W2 I60: the service token ----


def test_w2_i60_doctor_and_service_share_one_token_rule() -> None:
    doctor, service = _code(DOCTOR_PS1), _code(SERVICE_PS1)
    shared = ("Test-TrustedOwner", "Get-WriteProblem", "Get-TreeProblem", "Get-TreeRemedy", "Test-AccountSid")
    for name in (*shared, "Get-AclProblem", "Get-TokenProblem"):
        assert _function(doctor, name) == _function(service, name), name
    rule = _function(service, "Get-TokenProblem")
    owner = rule.index("Get-WriteProblem -Path $Path")
    assert owner < rule.index("Get-AclProblem -Path $Path -AllowedSids $AllowedSids") < rule.index("'is empty'")
    assert "$problem = Get-TokenProblem -Path $tokenFile -AllowedSids $tokenSids" in _main_body(service)
    body = _main_body(doctor)
    # after every refusal, before the first payload run; never an owner change
    walk = body.index("$found = Get-TreeProblem -Directory $configDir")
    judge = body.index("$problem = Get-TokenProblem -Path $tokenFile -AllowedSids $tokenSids")
    remove = body.index("Remove-Item -LiteralPath $tokenFile -Force")
    assert walk < judge < remove < body.index("Invoke-Payload")
    assert "$tokenSids += $serviceSid" in body[:judge]


@pytest.mark.skipif(sys.platform == "win32", reason="the venv interpreter is a POSIX shell stub")
@pytest.mark.parametrize(
    ("token_acl", "healthy"),
    [(PLANTED_TOKEN, False), (_programdata_child(SID_SYSTEM, folder=False), False), (TOKEN_ACL, True)],
    ids=["user-owned", "users-can-read", "protected"],
)
def test_w2_i60_the_stub_payload_doctor_judges_the_service_token_as_the_real_one(
    tmp_path: Path, token_acl: dict[str, object], healthy: bool
) -> None:
    # The executed doctor.ps1 tests below would pass against a payload that
    # ignores the token (the reviewer's point about the earlier stub): the
    # stub refuses what diagnostics/doctor.py refuses when run as SYSTEM.
    host = _Host(tmp_path)
    host.token.write_text("value", encoding="utf-8")
    host.acl_file.write_text(json.dumps({str(host.token): token_acl}), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 - the harness's own stub
        [str(host.venv / "Scripts" / "python.exe"), "-I", "-m", "universal_db_mcp", "doctor"],
        capture_output=True, text=True, timeout=60, env=host.env(), check=False,
    )
    assert (proc.returncode == 0) is healthy, proc.stdout + proc.stderr
    if not healthy:
        assert f"FATAL http-bearer-token: bearer token file '{host.token}'" in proc.stdout


@executed
@pytest.mark.parametrize(
    ("token_acl", "content", "reason"),
    [
        (_entry(SID_ADMINS, protected=False), "known-value", "inherits its DACL from the folder"),
        (
            _token_acl([SID_NETWORK_SERVICE, "Allow", "R", False]),
            "known-value",
            f"grants {SID_NETWORK_SERVICE} Read, Synchronize",
        ),
        (_programdata_child(SID_SYSTEM, folder=False), "known-value", "inherits its DACL from the folder"),
        (TOKEN_ACL, "", "is empty"),
        # a user's DACL that grants SYSTEM nothing, not even READ_CONTROL
        (
            {**PLANTED_TOKEN, "unreadable": True},
            "known-value",
            "cannot be inspected (Attempted to perform an unauthorized operation.)",
        ),
    ],
    ids=["inherited", "previous-account", "users-can-read", "empty", "unreadable"],
)
def test_exec_w2_i60_doctor_removes_every_token_the_registration_action_would_replace(
    host: _Host, token_acl: dict[str, object], content: str, reason: str
) -> None:
    host.token.write_text(content, encoding="utf-8")
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.config: SAFE, host.token: token_acl})
    assert code == 0, out
    assert f"'{host.token}' {reason}; removing it before doctor runs" in out, out
    assert not host.token.exists()
    assert "python -I -m universal_db_mcp doctor" in calls
    code, out, calls = host.service(None)
    assert code == 0 and "provisioning HTTP bearer token" in out, out
    assert host.token.read_text(encoding="utf-8") == GENERATED


@executed
@pytest.mark.parametrize("account", ["LocalSystem", NETWORK_SERVICE])
def test_exec_w2_i60_doctor_keeps_the_token_the_registration_action_keeps(host: _Host, account: str) -> None:
    host.token.write_text("admins-own-token", encoding="utf-8")
    token_acl = _token_acl([SID_NETWORK_SERVICE, "Allow", "R", False]) if account != "LocalSystem" else TOKEN_ACL
    acl = {host.cfgdir: SAFE, host.config: SAFE, host.token: token_acl}
    code, out, calls = host.doctor(acl, account=account)
    assert code == 0, out
    assert "removing it" not in out and host.token.read_text(encoding="utf-8") == "admins-own-token"
    code, out, calls = host.service(None, account=account)
    assert code == 0, out
    assert host.token.read_text(encoding="utf-8") == "admins-own-token"


@executed
def test_exec_w2_i60_doctor_removes_nothing_when_it_refuses_the_folder(host: _Host) -> None:
    host.token.write_text("known-value", encoding="utf-8")
    audit = host.cfgdir / "audit"
    audit.mkdir()
    acl = {host.cfgdir: SAFE, host.config: SAFE, host.token: PLANTED_TOKEN, audit: USER_OWNED}
    code, out, calls = host.doctor(acl)
    assert code == 1 and f"'{audit}' in it is owned by {USER_SID}" in out, out
    assert host.token.read_text(encoding="utf-8") == "known-value"
    assert _changed_nothing(calls), calls


def test_w2_i60_gate_proves_doctor_removes_a_planted_token_with_the_real_payload() -> None:
    # Only a Windows run executes the real payload doctor: check 3c first
    # runs the installed doctor.ps1 (as DoctorSmokeCA does) over the planted
    # token, then plants it again for service.ps1.
    code = _code(GATE_PS1)
    squat = _squat_check(code)
    doctor = squat.index("-File $DoctorScript -VenvDir $VenvDir -ConfigPath $ConfigYaml")
    assert "-ServiceAccount $squatAccount" in squat[doctor : doctor + 300]
    assert re.search(r"if \(\$doctorExit -ne 0\) \{\s*\n\s*Stop-Gate 'token_squat_doctor'", squat), squat
    assert "if (Test-Path -LiteralPath $TokenFile) {" in squat[doctor:]
    assert "removing it before doctor runs" in squat
    assert squat.count("Add-Check 'token_squat_doctor' 'passed'") == 1
    assert doctor < squat.index("-File $ServiceScript")
    assert squat.count("& $plantToken") == 2


# --------------------------------------- W2 I67: the interpreter tree ----


def _tools_interpreter(host: _Host) -> Path:
    """A python.org-shaped install one folder down (Tools\\Python312), so the
    folder above it is not the host root the key and the bundle sit in."""
    exe = host.root / "Tools" / "Python312" / "python.exe"
    _executable(exe, f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    encodings = exe.parent / "Lib" / "encodings"
    encodings.mkdir(parents=True)
    (encodings / "__init__.py").write_text("", encoding="utf-8")
    (exe.parent / "Lib" / "site-packages").mkdir()
    (exe.parent / "DLLs").mkdir()
    (exe.parent / "DLLs" / "_socket.pyd").write_bytes(b"MZ")
    (exe.parent / "python312.zip").write_bytes(b"PK")
    return exe


def test_w2_i67_verify_judges_the_folder_above_the_interpreter_and_all_it_loads() -> None:
    code = _code(VERIFY_PS1)
    check = _function(code, "Get-InterpreterProblem")
    # pyvenv.cfg beside the interpreter or one folder up (CPython's venv landmark)
    assert "foreach ($folder in @($dir, $parent))" in check
    assert "Join-Path $folder 'pyvenv.cfg'" in check
    assert "$paths = @($parent, $dir, $Exe)" in check
    assert "Get-ChildItem -LiteralPath $dir -File -Force" in check
    assert "Get-TreeGrantProblem (Join-Path $dir $name)" in check and "@('Lib', 'DLLs')" in check
    walk = _function(code, "Get-TreeGrantProblem")
    assert walk.index("Get-WriteProblem $entry.FullName") < walk.index("Get-GrantProblem $entry.FullName")
    assert walk.index("return") < walk.index("Get-TreeGrantProblem $entry.FullName"), "no descent into a refused entry"
    for body in (check, walk):
        assert not re.search(r"(?<!\w)&\s", _without_strings(body)), "cmdlets only before the trusted verifier"


@executed
def test_exec_w2_i67_verify_accepts_a_python_org_install_under_program_files(host: _Host) -> None:
    exe = _tools_interpreter(host)
    acl = {exe.parent.parent: PROGRAM_FILES, exe.parent: PYTHON_ORG_FOLDER}
    code, out, calls = host.verify(_release_install(host, 5, None, python=str(exe)), acl)
    assert code == 0, out
    assert "isolated=1" in out
    lib = exe.parent / "Lib"
    for part in (exe.parent.parent, lib / "encodings", lib / "encodings" / "__init__.py",
                 exe.parent / "DLLs" / "_socket.pyd", exe.parent / "python312.zip"):
        assert f"Get-Acl {part}\n" in calls, f"{part} is judged"


@executed
@pytest.mark.parametrize(
    "case",
    [
        "pyvenv-above",
        "pyvenv-beside",
        "above-authenticated-users-modify",
        "above-users-create-files",
        "above-user-owned",
        "lib-subfolder",
        "lib-file",
        "dlls-file",
        "zip-beside",
        "link-in-lib",
    ],
)
def test_exec_w2_i67_verify_refuses_an_interpreter_something_else_can_change(host: _Host, case: str) -> None:
    # The reviewer's chain: D:\Tools\Python312 locked down, D:\Tools
    # writable by users. CPython 3.12 under -I reads D:\Tools\pyvenv.cfg,
    # takes D:\Tools as its prefix and runs the .pth files of its
    # Lib\site-packages, as LocalSystem, before the bundle is verified.
    exe = _tools_interpreter(host)
    tools, lib = exe.parent.parent, exe.parent / "Lib"
    acl: dict[Path, dict[str, object]] = {tools: PROGRAM_FILES, exe.parent: PYTHON_ORG_FOLDER}
    users_modify = [SID_USERS, "Allow", "Modify, Synchronize", False]
    if case in ("pyvenv-above", "pyvenv-beside"):
        target = (tools if case == "pyvenv-above" else exe.parent) / "pyvenv.cfg"
        target.write_text("home = C:\\Program Files\\Python312\n", encoding="utf-8")
        acl[target] = _entry(SID_ADMINS)
        expected = f"'{target}' exists"
    elif case == "above-authenticated-users-modify":
        target = tools
        acl[tools] = _entry(SID_ADMINS, ["S-1-5-11", "Allow", "Modify, Synchronize", True], protected=False)
        expected = f"'{target}' grants S-1-5-11"
    elif case == "above-users-create-files":
        target = tools
        acl[tools] = _entry(SID_ADMINS, [SID_USERS, "Allow", "CreateFiles", False])
        expected = f"'{target}' grants {SID_USERS}"
    elif case == "above-user-owned":
        target = tools
        acl[tools] = USER_OWNED
        expected = f"'{target}' is owned by {USER_SID}"
    elif case == "link-in-lib":
        target = lib / "zz_elsewhere"
        (host.root / "elsewhere").mkdir()
        target.symlink_to(host.root / "elsewhere")
        expected = f"'{target}' is a reparse point"
    else:
        target = {
            "lib-subfolder": lib / "encodings",
            "lib-file": lib / "encodings" / "__init__.py",
            "dlls-file": exe.parent / "DLLs" / "_socket.pyd",
            "zip-beside": exe.parent / "python312.zip",
        }[case]
        acl[target] = _entry(SID_ADMINS, users_modify)
        expected = f"'{target}' grants {SID_USERS}"
    code, out, calls = host.verify(_release_install(host, 5, None, python=str(exe)), acl)
    assert code == 1, out
    assert f"python interpreter: {expected}" in out, out
    assert "isolated=" not in out, "the interpreter never runs"
    if case == "link-in-lib":
        assert f"Get-Acl {host.root / 'elsewhere'}" not in calls, "a link is never followed"


# ------------------------------------ W2 I61: who may pass properties ----

_MSI_TOKEN = re.compile(r'\s*(?:(?P<literal>"[^"]*")|(?P<op><>|><|<<|>>|=)|(?P<paren>[()])|(?P<word>\w+))')


def _msi_condition(condition: str, props: dict[str, str]) -> bool:
    """Evaluates the subset of the Windows Installer conditional statement
    syntax the wxs uses: NOT, AND and OR (in that precedence) and
    parentheses over property names and "literals" compared with =, <>, ><
    (contains), << (starts with) and >> (ends with). A property that is not
    set is the empty string, and a lone value is true when it is not empty."""
    tokens: list[tuple[str, str]] = []
    pos, text = 0, condition.rstrip()
    while pos < len(text):
        m = _MSI_TOKEN.match(text, pos)
        assert m and m.lastgroup, f"unsupported condition syntax at {text[pos:]!r}"
        tokens.append((m.lastgroup, m.group(m.lastgroup)))
        pos = m.end()

    def keyword(i: int, word: str) -> bool:
        return i < len(tokens) and tokens[i][0] == "word" and tokens[i][1].upper() == word

    def value(i: int) -> str:
        kind, tok = tokens[i]
        assert kind in ("literal", "word"), tokens[i]
        return tok[1:-1] if kind == "literal" else props.get(tok, "")

    def term(i: int) -> tuple[bool, int]:
        if tokens[i] == ("paren", "("):
            result, i = expr(i + 1)
            assert tokens[i] == ("paren", ")"), tokens[i:]
            return result, i + 1
        left = value(i)
        if i + 1 < len(tokens) and tokens[i + 1][0] == "op":
            right = value(i + 2)
            compare = {"=": left == right, "<>": left != right, "><": right in left,
                       "<<": left.startswith(right), ">>": left.endswith(right)}
            return compare[tokens[i + 1][1]], i + 3
        return left != "", i + 1

    def factor(i: int) -> tuple[bool, int]:
        if keyword(i, "NOT"):
            result, i = factor(i + 1)
            return not result, i
        return term(i)

    def conjunction(i: int) -> tuple[bool, int]:
        result, i = factor(i)
        while keyword(i, "AND"):
            right, i = factor(i + 1)
            result = result and right
        return result, i

    def expr(i: int) -> tuple[bool, int]:
        result, i = conjunction(i)
        while keyword(i, "OR"):
            right, i = conjunction(i + 1)
            result = result or right
        return result, i

    result, end = expr(0)
    assert end == len(tokens), tokens[end:]
    return result


def test_w2_i61_the_condition_evaluator_follows_the_msi_grammar() -> None:
    assert _msi_condition('NOT A OR B', {"A": "1"}) is False
    assert _msi_condition('NOT (A OR B)', {"B": "1"}) is False
    assert _msi_condition('A OR B AND C', {"A": "1"}) is True
    assert _msi_condition('A >< Q', {"A": 'x"y', "Q": '"'}) is True
    assert _msi_condition('A >> "\\"', {"A": "CORP\\"}) is True
    assert _msi_condition('NOT A OR A="1"', {}) is True


def _launch_allows(**props: str) -> bool:
    """Whether every Launch condition passes: the Property table's values,
    CPython 3.12 present, and *props* as msiexec and the installer set them
    (AdminUser is set by the installer, never on the command line)."""
    root = _wxs_root()
    table = {el.get("Id") or "": el.get("Value") or "" for el in root.iter() if _local(el) == "Property"}
    env = {**table, "CPYTHON312": "C:\\Program Files\\Python312\\", **props}
    return all(_msi_condition(el.get("Condition") or "", env) for el in root.iter() if _local(el) == "Launch")


@pytest.mark.parametrize(
    ("props", "allowed"),
    [
        ({}, True),
        ({"Installed": "1"}, True),
        # a standard user's repair of the per-machine product: the SYSTEM
        # actions would grant the account read access to the config folder
        # and Modify on logs\, or accept an older release
        ({"Installed": "1", "UDBMCP_SERVICE_ACCOUNT": ".\\mallory"}, False),
        ({"Installed": "1", "UDBMCP_ALLOW_DOWNGRADE": "1"}, False),
        ({"AdminUser": "1", "UDBMCP_SERVICE_ACCOUNT": NETWORK_SERVICE}, True),
        ({"AdminUser": "1", "UDBMCP_SERVICE_ACCOUNT": "CORP\\udbmcp-gmsa$"}, True),
        ({"AdminUser": "1", "UDBMCP_ALLOW_DOWNGRADE": "1"}, True),
        # a quote ends the -ServiceAccount argument of the powershell.exe
        # command line and adds parameters (-ServiceName, -ServicePassword);
        # a trailing backslash escapes the closing quote
        ({"AdminUser": "1", "UDBMCP_SERVICE_ACCOUNT": 'x" -ServiceName "evil'}, False),
        ({"AdminUser": "1", "UDBMCP_SERVICE_ACCOUNT": "CORP\\"}, False),
        ({"AdminUser": "1", "UDBMCP_ALLOW_DOWNGRADE": "yes"}, False),
        ({"AdminUser": "1", "UDBMCP_ALLOW_DOWNGRADE": "1;PUBKEY=C:\\x.pem"}, False),
    ],
    ids=[
        "no-properties", "repair", "user-repair-account", "user-repair-downgrade", "admin-account",
        "admin-gmsa", "admin-downgrade", "account-quote", "account-trailing-backslash", "downgrade-yes",
        "downgrade-semicolon",
    ],
)
def test_w2_i61_launch_conditions_take_the_properties_from_an_administrator_only(
    props: dict[str, str], allowed: bool
) -> None:
    assert _launch_allows(**props) is allowed


def test_w2_i61_wxs_detects_a_real_administrator_and_holds_the_quote_privately() -> None:
    root = _wxs_root()
    props = {el.get("Id"): el for el in root.iter() if _local(el) == "Property"}
    # without it, Windows Installer sets AdminUser for every user
    assert props["MSIUSEREALADMINDETECTION"].get("Value") == "1"
    quotes = [el for el in props.values() if el.get("Value") == '"']
    assert len(quotes) == 1
    name = quotes[0].get("Id") or ""
    assert name != name.upper(), "a private property: msiexec cannot override it"
    launches = [el for el in root.iter() if _local(el) == "Launch"]
    assert all(el.get("Message") for el in launches)
    conditions = [el.get("Condition") or "" for el in launches]
    assert any(f"UDBMCP_SERVICE_ACCOUNT >< {name}" in c for c in conditions), conditions
    assert any(c.startswith("AdminUser OR ") for c in conditions), conditions


def test_w2_i61_gate_proves_the_launch_conditions_on_windows() -> None:
    code = _code(GATE_PS1)
    launch = code[code.index("$LaunchCases = @(") :]
    # msiexec's own quoting: "" is a literal quote in a quoted value
    assert "'UDBMCP_SERVICE_ACCOUNT=\"x\"\" -ServiceName \"\"evil\"'" in launch
    assert "'UDBMCP_SERVICE_ACCOUNT=CORP\\'" in launch and "'UDBMCP_ALLOW_DOWNGRADE=yes'" in launch
    assert "Stop-Check 'launch_conditions'" in launch and "Add-Check 'launch_conditions' 'passed'" in launch
    assert "VerifyBundleCA" in launch, "refused before any custom action runs"


# ------------------------------------------------ W2 I61: logs\ ----


def test_w2_i61_wxs_leaves_logs_to_the_custom_actions() -> None:
    # CreateFolders applied logs\'s PermissionEx before any action could
    # refuse a logs\ junction a local user planted in an upgraded folder, so
    # the MSI engine (SYSTEM) would have reset the DACL of its target.
    # doctor.ps1 and service.ps1 check for a reparse point first.
    root = _wxs_root()
    folder = next(el for el in root.iter() if _local(el) == "Directory" and el.get("Id") == "ProgramDataUdbmcpDir")
    assert not [el for el in folder.iter() if _local(el) == "Directory" and el is not folder], "no folder below it"
    assert "ProgramDataUdbmcpLogsDir" not in WXS.read_text(encoding="utf-8")
    body = _main_body(_code(DOCTOR_PS1))
    walk = body.index("$found = Get-TreeProblem -Directory $configDir")
    create = body.index("New-Item -ItemType Directory -Path $logsDir")
    assert "-Force" not in body[create : body.index("\n", create)]
    protect = body.index("Set-Acl -LiteralPath $logsDir -AclObject $security")
    rewalk = body.index("$found = Get-TreeProblem -Directory $configDir", protect)
    assert walk < create < protect < rewalk < body.index("Invoke-Payload")


@executed
@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_exec_w2_i61_doctor_refuses_a_logs_entry_before_making_logs(host: _Host, kind: str) -> None:
    logs = host.cfgdir / "logs"
    victim = host.root / "victim"
    victim.mkdir()
    if kind == "symlink":
        logs.symlink_to(victim)
        expected = f"'{logs}' in it is a reparse point"
    else:
        logs.write_text("", encoding="utf-8")
        expected = f"'{logs}' is not a directory"
    code, out, calls = host.doctor({host.cfgdir: SAFE, host.config: SAFE, logs: SAFE})
    assert code == 1 and expected in out, out
    assert _changed_nothing(calls), calls
    assert os.listdir(victim) == [] and str(victim) not in json.loads(host.acl_file.read_text(encoding="utf-8"))


@executed
@pytest.mark.parametrize("previous", [SID_NETWORK_SERVICE, DEDICATED_SID], ids=["NetworkService", "dedicated"])
@pytest.mark.parametrize("account", ["LocalSystem", LOCAL_SERVICE])
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_w2_i61_an_account_change_resets_the_previous_accounts_grant_on_logs(
    host: _Host, script: str, account: str, previous: str
) -> None:
    # The reviewer's variants: installed as one account, repaired as
    # another. logs\ still grants the previous account the Modify the
    # registration gave it; both walks refused it, with a remedy that
    # deleted the audit log. It is accepted on logs\ itself, and logs\'s
    # DACL is reset before anything relies on it (doctor.ps1 before the
    # payload runs, service.ps1 before it walks again).
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl = {host.cfgdir: SAFE, host.config: SAFE, logs: _entry(SID_ADMINS, [previous, "Allow", "(OI)(CI)M", False])}
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account=account)
    assert code == 0, out
    rules = host.acl(logs)["rules"]
    assert isinstance(rules, list) and all(r[0] != previous for r in rules), rules
    reset = _line(calls, f"Set-Acl {logs} {PROTECTED_DIR_SDDL}")
    if script == "doctor":
        assert "a service account this install does not run as" in out, out
        assert reset < _line(calls, "python -I -m universal_db_mcp doctor")
    else:
        assert reset < _line(calls, "sc create")


@executed
@pytest.mark.parametrize("script", ["service", "doctor"])
def test_exec_w2_i61_an_account_change_says_to_archive_the_previous_accounts_audit_log(
    host: _Host, script: str
) -> None:
    logs = host.cfgdir / "logs"
    logs.mkdir()
    audit_log = logs / "audit.jsonl"
    audit_log.write_text('{"event": "earlier"}\n', encoding="utf-8")
    acl = {
        host.cfgdir: SAFE,
        host.config: SAFE,
        logs: _entry(SID_ADMINS, [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False]),
        audit_log: _written_by(SID_NETWORK_SERVICE),
    }
    run = host.service if script == "service" else host.doctor
    code, out, calls = run(acl, account="LocalSystem")
    assert code == 1, out
    assert f"'{audit_log}' in it is owned by {SID_NETWORK_SERVICE}" in out, out
    assert "move it out of" in out and "archive" in out and "remove it" not in out, out
    assert _changed_nothing(calls), calls
    assert audit_log.read_text(encoding="utf-8") == '{"event": "earlier"}\n'


def test_w2_i61_walks_accept_at_most_modify_for_an_earlier_account_on_logs_only() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        code = _code(path)
        assert "$script:ModifyRights = 0x1301BF" in code, path.name
        problem = _function(code, "Get-WriteProblem")
        accept = problem.index("if ($AccountWriters -and (Test-AccountSid -Sid $sid) -and")
        assert "-not ($granted -band -bnot $script:ModifyRights)" in problem[accept : accept + 200], path.name
        walk = _function(code, "Get-TreeProblem")
        assert "$logs = $InLogs -or (-not $Nested -and $entry.Name -eq 'logs')" in walk, path.name
        assert "-AccountWriters:($logs -and -not $InLogs)" in walk, path.name
        assert "Get-TreeProblem -Directory $entry.FullName -OwnerSid $below -Nested -InLogs:$logs" in walk, path.name
        sid = _function(code, "Get-ServiceAccountSid")
        assert "if (-not (Test-AccountSid -Sid $sid)) {" in sid, path.name


# ----------------------------------- W2 I62: the record's rollback ----


def _bundle(host: _Host, seq: int) -> Path:
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "manifest.json").write_text(json.dumps({"release_seq": seq}), encoding="utf-8")
    return bundle


@executed
@pytest.mark.parametrize("earlier", [6, None], ids=["upgrade", "first-install"])
def test_exec_w2_i62_a_rolled_back_install_restores_the_release_record(host: _Host, earlier: int | None) -> None:
    # RegisterServiceCA replaced the record and nothing undid it when the
    # transaction failed afterwards: the restored release then read as a
    # downgrade. RollbackRemoveServiceCA restores the copy it kept.
    bundle = _bundle(host, 7)
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    backup = record.with_name("manifest.json.previous")
    if earlier is not None:
        record.parent.mkdir(parents=True)
        record.write_text(json.dumps({"release_seq": earlier}), encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, record=record)
    assert code == 0, out
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 7}
    assert backup.read_text(encoding="utf-8") == ("" if earlier is None else json.dumps({"release_seq": earlier}))
    code, out, calls = host.uninstall(record)
    assert code == 0, out
    if earlier is None:
        assert not record.exists() and "removed the installed release record" in out, out
    else:
        assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": earlier}
        assert "restored the installed release record" in out, out
    assert not backup.exists() and not record.with_name("manifest.json.kept").exists()


@executed
def test_exec_w2_i62_a_stale_copy_is_never_restored(host: _Host) -> None:
    # An earlier install left its copy (release 5); this one fails before it
    # records anything (release 6 stays installed): the rollback leaves 6.
    bundle = _bundle(host, 7)
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"release_seq": 6}), encoding="utf-8")
    backup = record.with_name("manifest.json.previous")
    backup.write_text(json.dumps({"release_seq": 5}), encoding="utf-8")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, record=record, H_REG_FAIL="1")
    assert code == 1, out
    assert not backup.exists()
    code, out, calls = host.uninstall(record)
    assert code == 0, out
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 6}


@executed
def test_exec_w2_i62_uninstall_leaves_the_record(host: _Host) -> None:
    # RemoveServiceCA (no -InstalledManifest): the record outlives the
    # product, so a downgrade after an uninstall is still refused.
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"release_seq": 7}), encoding="utf-8")
    record.with_name("manifest.json.previous").write_text(json.dumps({"release_seq": 6}), encoding="utf-8")
    code, out, calls = host.uninstall()
    assert code == 0, out
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 7}


def test_w2_i62_only_the_rollback_twin_restores_the_record() -> None:
    cmds = _custom_action_commands()
    assert cmds["RollbackRemoveServiceCA"].endswith(
        f'-ServiceName "udbmcp" -InstalledManifest "{RECORD}" -Repair "[Installed]"'
    )
    assert "-InstalledManifest" not in cmds["RemoveServiceCA"]
    body = _main_body(_code(SERVICE_PS1))
    # the stale copy goes first, before anything in the action can fail
    first = body.split("\n")[2].strip()
    assert first == "if ($BundleDir -and -not $InstalledManifest) {", first
    stale = body.index("Remove-Item -LiteralPath $recordCopy -Force")
    assert stale < body.index("Fail ")
    keep = body.index("[System.IO.File]::Copy($InstalledManifest, $recordCopy, $true)")
    assert keep < body.index("[System.IO.File]::Copy($bundleManifest, $InstalledManifest, $true)")


# ------------------ W2 FU2: the service account across repairs ----
#
# The integration review's residuals:
#   medium: msiexec keeps no property between runs, so a repair or upgrade
#           without UDBMCP_SERVICE_ACCOUNT fell back to LocalSystem. With the
#           I60/I61 rules that deleted a NetworkService service's token and
#           reset its Modify on logs\ before anything else could fail (no
#           rollback twin), or refused its audit log with an "archive it"
#           remedy that then re-registered the service as LocalSystem.
#   low:    doctor.ps1's walk after the logs\ DACL was pinned statically only;
#           venv.ps1 ran python as LocalSystem without -I.

REGISTERED = "UDBMCPREGISTEREDACCOUNT"
SERVICE_KEY = "SYSTEM\\CurrentControlSet\\Services\\udbmcp"
GMSA = "CORP\\udbmcp-gmsa$"
GMSA_SID = "S-1-5-21-1111-2222-3333-1106"
VIRTUAL = "NT SERVICE\\udbmcp"
VIRTUAL_SID = _service_sid("udbmcp")


def _plant(host: _Host, path: Path, entry: dict[str, object], text: str = "") -> None:
    """*path* with *entry* in the stub ACL store, the rest of it kept."""
    path.write_text(text, encoding="utf-8")
    state = json.loads(host.acl_file.read_text(encoding="utf-8"))
    state[str(path)] = entry
    host.acl_file.write_text(json.dumps(state), encoding="utf-8")


def _installed_as_network_service(host: _Host) -> str:
    """A NetworkService install (RegisterServiceCA given the account); its token."""
    code, out, calls = host.service({host.cfgdir: SAFE}, account=NETWORK_SERVICE)
    assert code == 0, out
    assert [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False] in host.acl(host.cfgdir / "logs")["rules"]
    return host.token.read_text(encoding="utf-8")


def test_fu2_wxs_reads_the_registered_account_before_anything_runs() -> None:
    # AppSearch runs before InstallValidate and so before a major upgrade's
    # RemoveExistingProducts (afterInstallValidate) deletes the old service:
    # the service key's ObjectName is still there for an upgrade too.
    root = _wxs_root()
    props = {el.get("Id"): el for el in root.iter() if _local(el) == "Property"}
    prop = props[REGISTERED]
    # A search property must be public (WiX refuses a lower-case one with
    # WIX0012, so no MSI could be built) and Secure (with a user interface
    # AppSearch runs in the client only). Being public, the actions keep it
    # only when logs\ corroborates it (test_cr_fix_msi.py).
    assert REGISTERED == REGISTERED.upper(), "a search property must be public"
    assert prop.get("Secure") == "yes" and prop.get("Value") is None
    searches = [el for el in prop.iter() if _local(el) == "RegistrySearch"]
    assert len(searches) == 1
    search = searches[0]
    assert (search.get("Root"), search.get("Key"), search.get("Name"), search.get("Type")) == (
        "HKLM", SERVICE_KEY, "ObjectName", "raw"
    )
    cmds = _custom_action_commands()
    for action in ("DoctorSmokeCA", "RegisterServiceCA"):
        # last, after every other argument
        assert cmds[action].endswith(f' -RegisteredAccount "[{REGISTERED}]"'), action
    assert REGISTERED not in " ".join(el.get("Condition") or "" for el in root.iter() if _local(el) == "Launch")
    # the property comment no longer says an unelevated client passes the account
    assert "from an unelevated client" not in WXS.read_text(encoding="utf-8")


def test_fu2_a_standard_users_repair_keeps_the_registered_account() -> None:
    # The Launch conditions take UDBMCP_SERVICE_ACCOUNT from an administrator
    # only; the account AppSearch found must not turn a standard user's
    # repair (or self-repair) away.
    assert _launch_allows(Installed="1", **{REGISTERED: NETWORK_SERVICE}) is True
    assert _launch_allows(Installed="1", UDBMCP_SERVICE_ACCOUNT=NETWORK_SERVICE) is False


def test_fu2_doctor_and_service_resolve_the_account_alike() -> None:
    doctor, service = _code(DOCTOR_PS1), _code(SERVICE_PS1)
    for name in ("Test-PasswordAccount", "Get-EarlierAccountSid", "Get-ImplicitAccountProblem"):
        assert _function(doctor, name) == _function(service, name), name
    for path, code in ((DOCTOR_PS1, doctor), (SERVICE_PS1, service)):
        assert "[string]$ServiceAccount = ''," in code, path.name
        assert "[string]$RegisteredAccount = ''" in code, path.name
        body = _main_body(code)
        env = body.index("if (-not $ServiceAccount) { $ServiceAccount = $env:UDBMCP_SERVICE_ACCOUNT }")
        given = body.index("$accountGiven = [bool]$ServiceAccount")
        kept = body.index("if (-not $accountGiven) { $ServiceAccount = $RegisteredAccount }")
        default = body.index("if (-not $ServiceAccount) { $ServiceAccount = 'LocalSystem' }")
        sid = body.index("$serviceSid = Get-ServiceAccountSid -Account $ServiceAccount")
        check = body.index("$problem = Get-ImplicitAccountProblem -Account $ServiceAccount")
        assert env < given < kept < default < sid < check < body.index("$found = Get-TreeProblem"), path.name
        # refused before anything on the machine changes
        for change in ("Set-Acl", "Remove-Item -LiteralPath $tokenFile", "Invoke-Payload", "Stop-ExistingService"):
            if change in body:
                assert check < body.index(change), (path.name, change)
    problem = _function(service, "Get-ImplicitAccountProblem")
    assert problem.index("Test-PasswordAccount -Account $Account") < problem.index("Get-EarlierAccountSid")
    assert "-Password:([bool]$env:UDBMCP_SERVICE_PASSWORD)" in _main_body(doctor)
    assert "-Password:([bool]$ServicePassword)" in _main_body(service)


@pytest.mark.parametrize(
    ("account", "password"),
    [
        ("LocalSystem", False), (".\\LocalSystem", False), ("NT AUTHORITY\\SYSTEM", False),
        (NETWORK_SERVICE, False), ("NT AUTHORITY\\Network Service", False), (LOCAL_SERVICE, False),
        (VIRTUAL, False), (GMSA, False), (".\\svc", True), ("HOST\\svc", True), ("CORP\\svc", True),
    ],
)
@executed
def test_exec_fu2_only_accounts_that_sign_in_with_a_password_need_one(
    tmp_path: Path, account: str, password: bool
) -> None:
    code = _code(SERVICE_PS1)
    script = tmp_path / "probe.ps1"
    probe = "\nif (Test-PasswordAccount -Account $args[0]) { 'yes' } else { 'no' }\n"
    script.write_text(_function(code, "Test-PasswordAccount") + probe, encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 - the function under test
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(script), account],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.stdout.strip() == ("yes" if password else "no"), proc.stdout + proc.stderr


@executed
@pytest.mark.parametrize("account", [NETWORK_SERVICE, LOCAL_SERVICE])
def test_exec_fu2_a_repair_without_the_property_keeps_the_registered_account(host: _Host, account: str) -> None:
    # The reviewer's repro: installed as the account, audited, then repaired
    # without UDBMCP_SERVICE_ACCOUNT. The MSI passes the account the service
    # is registered under; both actions keep it, its token and its logs\.
    sid = {NETWORK_SERVICE: SID_NETWORK_SERVICE, LOCAL_SERVICE: SID_LOCAL_SERVICE}[account]
    code, out, calls = host.service({host.cfgdir: SAFE}, account=account)
    assert code == 0, out
    token = host.token.read_text(encoding="utf-8")
    logs = host.cfgdir / "logs"
    audit_log = logs / "audit.jsonl"
    _plant(host, audit_log, _written_by(sid), '{"event": "served"}\n')
    code, out, calls = host.doctor(None, registered=account)
    assert code == 0, out
    assert f"==> no service account given: keeping '{account}', the account the service is registered under" in out
    assert "removing it" not in out and "resetting its DACL" not in out, out
    assert host.token.read_text(encoding="utf-8") == token
    assert [sid, "Allow", "(OI)(CI)M", False] in host.acl(logs)["rules"]
    code, out, calls = host.service(None, account="", registered=account)
    assert code == 0, out
    assert f"==> creating service 'udbmcp' (start= auto, account {account})" in out, out
    assert "regenerating it" not in out and host.token.read_text(encoding="utf-8") == token
    assert [sid, "Allow", "R", False] in host.acl(host.token)["rules"]
    assert [sid, "Allow", "(OI)(CI)M", False] in host.acl(logs)["rules"]
    assert audit_log.read_text(encoding="utf-8") == '{"event": "served"}\n'


@executed
@pytest.mark.parametrize(("account", "sid"), [(GMSA, GMSA_SID), (VIRTUAL, VIRTUAL_SID)], ids=["gmsa", "virtual"])
def test_exec_fu2_a_registered_account_without_a_password_is_kept(host: _Host, account: str, sid: str) -> None:
    lsa = {"H_ACCOUNTS": f"{account}={sid}"}
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl = {host.cfgdir: SAFE, host.config: SAFE, logs: _entry(SID_ADMINS, [sid, "Allow", "(OI)(CI)M", False])}
    code, out, calls = host.doctor(acl, registered=account, **lsa)
    assert code == 0, out
    assert f"keeping '{account}'" in out, out
    code, out, calls = host.service(None, account="", registered=account, **lsa)
    assert code == 0, out
    assert f"account {account})" in out and [sid, "Allow", "(OI)(CI)M", False] in host.acl(logs)["rules"]


@executed
@pytest.mark.parametrize("audited", [False, True], ids=["not-audited", "audited"])
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_fu2_an_account_change_nobody_asked_for_is_refused_before_anything_changes(
    host: _Host, script: str, audited: bool
) -> None:
    # The same install, then one that found no registered service (an
    # uninstall and a new install, or the service deleted by hand) and was
    # not given UDBMCP_SERVICE_ACCOUNT: logs\ still grants NetworkService
    # Modify. Falling back to LocalSystem took the service's token and logs\
    # away, or asked to archive its audit log.
    token = _installed_as_network_service(host)
    logs = host.cfgdir / "logs"
    if audited:
        _plant(host, logs / "audit.jsonl", _written_by(SID_NETWORK_SERVICE), '{"event": "served"}\n')
    before = host.acl_file.read_text(encoding="utf-8")
    run = host.doctor if script == "doctor" else functools.partial(host.service, account="")
    code, out, calls = run(None)
    assert code == 1, out
    assert f"'{logs}' grants {SID_NETWORK_SERVICE} write access: the service ran as that account" in out, out
    assert "UDBMCP_SERVICE_ACCOUNT" in out and "archive" not in out, out
    assert _changed_nothing(calls), calls
    assert host.token.read_text(encoding="utf-8") == token
    assert host.acl_file.read_text(encoding="utf-8") == before


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_fu2_an_account_named_again_still_changes_it(host: _Host, script: str) -> None:
    # An administrator who passes UDBMCP_SERVICE_ACCOUNT (or sets it
    # machine-wide) changes the account as before: the earlier grant goes.
    _installed_as_network_service(host)
    logs = host.cfgdir / "logs"
    run = host.doctor if script == "doctor" else host.service
    code, out, calls = run(None, account="", registered=NETWORK_SERVICE, UDBMCP_SERVICE_ACCOUNT="LocalSystem")
    assert code == 0, out
    assert "keeping" not in out
    assert all(rule[0] != SID_NETWORK_SERVICE for rule in host.acl(logs)["rules"])


@executed
def test_exec_fu2_a_failed_repair_leaves_the_registered_accounts_token_and_logs(host: _Host) -> None:
    # The reviewer's second variant: the repair fails after DoctorSmokeCA
    # began (here doctor itself, on an unknown placeholder); DoctorSmokeCA
    # has no rollback twin, so it must not have taken anything away.
    token = _installed_as_network_service(host)
    host.config.write_text(host.config.read_text(encoding="utf-8") + "  x: PLACEHOLDER_OTHER\n", encoding="utf-8")
    code, out, calls = host.doctor(None, registered=NETWORK_SERVICE)
    assert code == 1 and "unrecognized PLACEHOLDER_ token" in out, out
    assert host.token.read_text(encoding="utf-8") == token
    assert [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False] in host.acl(host.cfgdir / "logs")["rules"]


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_fu2_a_password_account_is_not_kept_without_its_password(host: _Host, script: str) -> None:
    # service.ps1 registers the service again, and the SCM never gives a
    # password back: keeping the account without it breaks the service's
    # sign-in; refused before anything changes.
    lsa = {"H_ACCOUNTS": "HOST\\svc=" + DEDICATED_SID}
    run = host.doctor if script == "doctor" else functools.partial(host.service, account="")
    code, out, calls = run({host.cfgdir: SAFE, host.config: SAFE}, registered=".\\svc", **lsa)
    assert code == 1, out
    assert "is registered under '.\\svc', which signs in with a password this install cannot carry over" in out, out
    assert "UDBMCP_SERVICE_ACCOUNT" in out, out
    assert _changed_nothing(calls), calls


@executed
def test_exec_fu2_doctor_keeps_a_password_account_whose_password_is_given(host: _Host) -> None:
    lsa = {"H_ACCOUNTS": "HOST\\svc=" + DEDICATED_SID, "UDBMCP_SERVICE_PASSWORD": "pw-4f1e"}
    logs = host.cfgdir / "logs"
    logs.mkdir()
    # the grant the install that registered the service under it made
    acl = {host.cfgdir: SAFE, host.config: SAFE, logs: _entry(SID_ADMINS, [DEDICATED_SID, "Allow", "(OI)(CI)M", False])}
    code, out, calls = host.doctor(acl, registered=".\\svc", **lsa)
    assert code == 0, out
    assert "keeping '.\\svc'" in out and "pw-4f1e" not in out + calls, out


@executed
@pytest.mark.parametrize("logs_state", ["missing", "earlier-account"])
def test_exec_fu2_doctor_rechecks_the_folder_after_the_logs_dacl_lands(host: _Host, logs_state: str) -> None:
    # The race the second walk closes (mutation M15 left only a static test
    # failing): a local user creates an entry in logs\ while doctor.ps1
    # creates it or resets its DACL.
    logs = host.cfgdir / "logs"
    acl = {host.cfgdir: SAFE, host.config: SAFE}
    if logs_state == "earlier-account":
        logs.mkdir()
        acl[logs] = _entry(SID_ADMINS, [SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False])
    planted = logs / "x"
    code, out, calls = host.doctor(acl, account="LocalSystem", H_RACE=f"{logs}|{planted}")
    assert "RACE planted" in calls, calls
    assert code == 1, out
    assert f"'{planted}' in it is owned by {USER_SID}" in out, out
    assert not any(ln.startswith("python ") for ln in calls.splitlines()), calls


def test_fu2_venv_runs_the_machine_interpreter_isolated() -> None:
    # BuildVenvCA runs as LocalSystem too: the cp312 probe, python -m venv
    # and the venv's pip, like every other LocalSystem python run.
    code = _code(VENV_PS1)
    runs = re.findall(r"Invoke-Native -FilePath \$py -ArgumentList @\(\s*([^)]*)\)", code)
    assert len(runs) == 2, runs
    assert all(run.lstrip().startswith("'-I', ") for run in runs), runs
    pips = re.findall(r"& \$VenvPython [^\n]*", code)
    assert pips and all(pip.startswith("& $VenvPython -I -m pip --isolated ") for pip in pips), pips
    assert not re.search(r"&\s*\$py\b", code), "the machine interpreter only runs through Invoke-Native"


def test_fu2_gate_proves_a_repair_keeps_the_registered_account() -> None:
    code = _code(GATE_PS1)
    start = code.index("$keepSteps = @(")
    check = code[start : code.index("if ($script:Failed -eq 0) {", start)]
    assert "Add-Check 'repair_keeps_account' 'passed' \"a repair" in check
    # after check 10, and never over a dedicated account (its password)
    assert code.index("Add-Check 'launch_conditions' 'passed' \"") < start
    guard = code[code.rindex("if ($SkipMsiInstall) {", 0, start) : start]
    assert "elseif ($installedService -and $installedService.StartName -notmatch '^(\\.\\\\)?LocalSystem$')" in guard
    steps = re.findall(r"@\{ Name = '(\w+)'; Property = '([^']*)'", check)
    assert steps == [
        ("networkservice", 'UDBMCP_SERVICE_ACCOUNT="NT AUTHORITY\\NetworkService"'),
        ("unnamed", ""),
        ("localsystem", "UDBMCP_SERVICE_ACCOUNT=LocalSystem"),
    ], steps
    assert "REINSTALL=ALL REINSTALLMODE=omus " in check
    assert "(Get-CimInstance Win32_Service -Filter \"Name='$ServiceName'\").StartName" in check
    # after the unnamed repair: NetworkService still has logs\ and the token
    unnamed = check[check.index("if ($step.Name -eq 'unnamed') {") :]
    assert "(Join-Path $ProgramDataDir 'logs'), $TokenFile" in unnamed and "'S-1-5-20'" in unnamed
    # the install's own account comes back whatever happened
    assert "finally {" in check and "UDBMCP_SERVICE_ACCOUNT=LocalSystem" in check[check.index("finally {") :]
    header = GATE_PS1.read_text(encoding="utf-8")
    assert "#  11. repair_keeps_account:" in header


# ================================================ final round (W3) ==
#
# The integration review's last residuals:
#   I62 (medium): RegisterServiceCA left the rollback copy of the release
#        record (manifest.json.previous) after a successful install. A later
#        install could not delete it while a local user held it open (anyone
#        may read under Program Files), failed, and its rollback twin put the
#        stale copy back over the newer record, or deleted the record when
#        the copy was the empty "nothing recorded" one.
#   I61 (low): NT SERVICE\<name> was translated by the local security
#        authority, which knows it only while that service exists.
#   I67 (low): an interpreter file owned by an administrator through a
#        domain group is refused without saying what to do.
# And two owner decisions of 2026-09-28: release gates verify with
# --no-installed-manifest, and the maintainers are "universal-db-mcp
# maintainers".


def _record(host: _Host) -> Path:
    return host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"


def _lock_holder(host: _Host) -> None:
    """The stub Remove-Item honours H_LOCKED (see _STUBS_PS1)."""
    assert "H_LOCKED" in (host.root / "stubs" / "stubs.ps1").read_text(encoding="utf-8")


@executed
@pytest.mark.parametrize(
    ("installed", "uninstalled", "failing"),
    [([1, 2], False, 3), ([2], True, 3), ([1, 2], False, 2)],
    ids=["upgrade", "install-after-an-uninstall", "repair"],
)
def test_exec_w3_i62_a_rollback_never_restores_a_copy_this_install_did_not_make(
    host: _Host, installed: list[int], uninstalled: bool, failing: int
) -> None:
    # The reviewer's i62_v3 (upgrade) and i62_v4 (install after an
    # uninstall, the copy empty), and a repair of the recorded release: the
    # earlier installs left their copy (the commit action that now removes
    # it is not run here), a local user holds it open, and this install's
    # RegisterServiceCA cannot delete it and fails.
    _lock_holder(host)
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True)
    record = _record(host)
    copy, kept = record.with_name("manifest.json.previous"), record.with_name("manifest.json.kept")
    for i, seq in enumerate(installed):
        (bundle / "manifest.json").write_text(json.dumps({"release_seq": seq}), encoding="utf-8")
        code, out, calls = host.service({host.cfgdir: SAFE} if i == 0 else None, bundle=bundle, record=record)
        assert code == 0, out
    assert copy.exists() and not kept.exists()
    if uninstalled:
        code, out, calls = host.uninstall()
        assert code == 0, out
    before = record.read_bytes()
    (bundle / "manifest.json").write_text(json.dumps({"release_seq": failing}), encoding="utf-8")
    code, out, calls = host.service(None, bundle=bundle, record=record, H_LOCKED=str(copy))
    assert code == 1 and "being used by another process" in out, out
    assert not any(ln.startswith("sc ") for ln in calls.splitlines()), "it fails before touching the service"
    # RollbackRemoveServiceCA, the copy still held open
    code, out, calls = host.uninstall(record, H_LOCKED=str(copy))
    assert code == 0, out
    assert record.exists() and record.read_bytes() == before, out
    assert "this install did not replace the installed release record" in out, out
    # the copy stays, and so does the marker that keeps every later rollback off it
    assert copy.exists() and kept.exists()
    # once the user lets go, the next rollback clears both and still leaves the record
    code, out, calls = host.uninstall(record)
    assert code == 0, out
    assert record.read_bytes() == before
    assert not copy.exists() and not kept.exists()


@executed
def test_exec_w3_i62_the_commit_action_removes_the_rollback_copy(host: _Host) -> None:
    bundle = _bundle(host, 6)
    record = _record(host)
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"release_seq": 5}), encoding="utf-8")
    copy, kept = record.with_name("manifest.json.previous"), record.with_name("manifest.json.kept")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, record=record)
    assert code == 0, out
    assert copy.exists() and not kept.exists()
    code, out, calls = host.uninstall(record, commit=True)
    assert code == 0, out
    assert not copy.exists() and not kept.exists()
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 6}
    assert calls == "", "the commit touches neither the service nor its registry key"


@executed
def test_exec_w3_i62_a_copy_the_commit_cannot_remove_is_never_restored(host: _Host) -> None:
    # A user holds the copy open when the install commits: the commit leaves
    # the marker beside it and still succeeds. A later install that fails
    # before its RegisterServiceCA runs a line (powershell.exe never starts)
    # then rolls back without touching the record.
    _lock_holder(host)
    bundle = _bundle(host, 6)
    record = _record(host)
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"release_seq": 5}), encoding="utf-8")
    copy, kept = record.with_name("manifest.json.previous"), record.with_name("manifest.json.kept")
    code, out, calls = host.service({host.cfgdir: SAFE}, bundle=bundle, record=record)
    assert code == 0, out
    code, out, calls = host.uninstall(record, commit=True, H_LOCKED=str(copy))
    assert code == 0, out
    assert "WARNING" in out and str(copy) in out, out
    assert copy.exists() and kept.exists()
    code, out, calls = host.uninstall(record)
    assert code == 0, out
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 6}, out
    assert not copy.exists() and not kept.exists()


def test_w3_i62_wxs_commits_the_record_by_removing_its_rollback_copy() -> None:
    root = _wxs_root()
    cas = {el.get("Id"): el for el in root.iter() if _local(el) == "CustomAction"}
    ca = cas["CommitReleaseRecordCA"]
    assert ca.get("Execute") == "commit" and ca.get("Impersonate") == "no"
    assert ca.get("Property") == "POWERSHELLEXE"
    # the install has committed when it runs: a failure cannot roll it back,
    # so uninstall.ps1 warns and exits 0 and msiexec ignores the exit code
    assert ca.get("Return") == "ignore"
    assert (ca.get("ExeCommand") or "").endswith(
        f'-File "[INSTALLFOLDER]scripts\\uninstall.ps1" -InstalledManifest "{RECORD}" -Commit'
    )
    rows = {el.get("Action"): el for el in root.iter() if _local(el) == "Custom"}
    assert rows["CommitReleaseRecordCA"].get("After") == "RegisterServiceCA"
    assert rows["CommitReleaseRecordCA"].get("Condition") == "NOT REMOVE"


def test_w3_i62_the_marker_stands_until_this_install_replaces_the_record() -> None:
    body = _main_body(_code(SERVICE_PS1))
    mark = body.index("[System.IO.File]::WriteAllBytes($recordKept, [byte[]]@())")
    stale = body.index("Remove-Item -LiteralPath $recordCopy -Force")
    assert mark < stale < body.index("Fail "), "the marker first, before anything in the action can fail"
    keep = body.index("[System.IO.File]::Copy($InstalledManifest, $recordCopy, $true)")
    unmark = body.index("Remove-Item -LiteralPath $recordKept -Force")
    assert keep < unmark < body.index("[System.IO.File]::Copy($bundleManifest, $InstalledManifest, $true)")
    code = _code(UNINSTALL_PS1)
    helper = _function(code, "Remove-RecordCopy")
    # a copy that stays keeps its marker
    assert helper.index("Remove-Item -LiteralPath $Copy -Force") < helper.index("[System.IO.File]::WriteAllBytes($Kept")
    body = _main_body(code)
    commit = body[body.index("if ($Commit) {") : body.index("Test-ServiceExists")]
    assert "exit 0" in commit, "the commit never reaches the service"


def test_w3_i62_gate_requires_no_rollback_copy_after_the_install() -> None:
    code = _code(GATE_PS1)
    check = code[code.index("$InstalledManifest = Join-Path $env:ProgramFiles") : code.index(
        "Add-Check 'installed_manifest_recorded' 'passed'"
    )]
    assert "foreach ($leftover in @(($InstalledManifest + '.previous'), ($InstalledManifest + '.kept'))) {" in check
    assert "Stop-Gate 'installed_manifest_recorded'" in check[check.index("foreach ($leftover") :]


def test_w3_i61_the_service_sid_reference_matches_windows() -> None:
    assert _service_sid("TrustedInstaller") == SID_TRUSTED_INSTALLER
    assert _service_sid("MSSQLSERVER") == "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"


@executed
@pytest.mark.parametrize("script", ["service", "doctor"])
@pytest.mark.parametrize("spelling", ["NT SERVICE\\udbmcp", "nt service\\UDBMCP"])
def test_exec_w3_i61_a_virtual_account_resolves_before_its_service_exists(
    host: _Host, script: str, spelling: str
) -> None:
    # A fresh install, or a major upgrade whose old product's uninstall
    # deleted the service: the stub LSA (no H_ACCOUNTS) knows no account,
    # as Windows' does not know NT SERVICE\udbmcp without the service.
    sid = _service_sid("udbmcp")
    run = host.service if script == "service" else host.doctor
    code, out, calls = run({host.cfgdir: SAFE, host.config: SAFE}, account=spelling)
    assert code == 0, out
    assert "cannot resolve" not in out, out
    if script == "service":
        assert f"icacls {host.cfgdir / 'logs'} | /grant:r | *{sid}:(OI)(CI)M" in calls, calls
        rules = host.acl(host.token)["rules"]
        assert isinstance(rules, list) and [sid, "Allow", "R", False] in rules


@executed
def test_exec_w3_i67_the_refusal_says_which_administrators_may_own_the_interpreter(host: _Host) -> None:
    # A domain administrator (in the local Administrators group only through
    # Domain Admins) upgraded pip in the base interpreter: those files are
    # owned by their own account. Still refused; the refusal says why and
    # what an administrator can do about it.
    exe = _tools_interpreter(host)
    pip = exe.parent / "Lib" / "site-packages" / "pip.py"
    pip.write_text("", encoding="utf-8")
    domain_admin = "S-1-5-21-9-9-9-1105"
    acl = {exe.parent.parent: PROGRAM_FILES, exe.parent: PYTHON_ORG_FOLDER, pip: _entry(domain_admin)}
    code, out, calls = host.verify(
        _release_install(host, 5, None, python=str(exe)), acl, H_ADMIN_MEMBERS=ADMIN_USER_SID
    )
    assert code == 1, out
    assert f"python interpreter: '{pip}' is owned by {domain_admin}" in out, out
    assert "a direct member of the local Administrators group" in out, out
    assert "through a domain group" in out, out
    assert "setowner" not in out


def test_w3_build_script_verifies_without_the_build_machines_installed_release() -> None:
    # verify_bundle.py compares a bundle with this machine's installed
    # release by default; the build machine's must never decide a build.
    calls = [
        line
        for line in re.sub(r"\\\n\s*", " ", BUILD_MSI.read_text(encoding="utf-8")).splitlines()
        if "verify_bundle.py" in line and "--bundle" in line and not line.lstrip().startswith("#")
    ]
    assert len(calls) == 1, calls
    assert "--no-installed-manifest" in calls[0], calls[0]


def test_w3_wxs_names_the_maintainers_without_an_address() -> None:
    package = next(el for el in _wxs_root().iter() if _local(el) == "Package")
    assert package.get("Manufacturer") == "universal-db-mcp maintainers"
    assert not re.search(r"[\w.+-]+@[\w-]+\.\w", WXS.read_text(encoding="utf-8")), "no e-mail address"


def test_w3_i61_virtual_accounts_are_derived_not_translated() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        sid = _function(_code(path), "Get-ServiceAccountSid")
        derive = sid.index("if ($Account -match '^NT SERVICE\\\\(.+)$') {")
        assert "[System.Security.Cryptography.SHA1]::Create()" in sid, path.name
        assert ".ToUpperInvariant()" in sid and "[System.BitConverter]::ToUInt32(" in sid, path.name
        assert derive < sid.index("New-Object System.Security.Principal.NTAccount"), path.name
