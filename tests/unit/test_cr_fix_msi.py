"""Code review fixes, MSI group (W1-W4, N1, N2, N4).

W3: UdbmcpRegisteredAccount, a mixed-case property fed by a RegistrySearch:
    WiX refuses a search property that is not public (WIX0012), so no MSI
    could be built at all. It is UDBMCPREGISTEREDACCOUNT now, Secure (with a
    user interface AppSearch runs in the client only), and because msiexec
    can set a public property, the actions keep an account they were not
    given only when logs\\ grants it write access.
W1: RemoveServiceCA (Before RemoveFiles) ran before SetPowerShellExe (After
    InstallFiles) on every uninstall, an upgrade's RemoveExistingProducts
    included: no interpreter, error 1721, rollback. SetPowerShellExe runs
    before InstallInitialize now.
W2: MajorUpgrade afterInstallValidate removes the old product first, and
    config.yaml was NeverOverwrite but not Permanent: the admin's config was
    deleted and the template installed. It is Permanent now.
W4: CreateFolders applied the config folder's PermissionEx through a junction
    a local user planted. CheckFoldersCA (folders.ps1), before CreateFolders,
    refuses a reparse point, a folder no administrator owns, and any folder a
    non-administrator could move, and creates a missing one protected.
N1: a custom INSTALLFOLDER inherits Authenticated Users Modify, and what is
    installed there runs as LocalSystem: the same action refuses an
    INSTALLFOLDER anybody else may write.
N2: the rollback twin deleted the service on a failed repair, even one that
    failed before RegisterServiceCA touched it; the test stub hid it (sc.exe
    query always answered "no such service").
N4: the MSI gate stopped at service_running (error 1053, the known blocker),
    so none of the security checks after it ever ran.

The static checks run everywhere; the executed ones need pwsh (the CI ubuntu
runner ships it), like tests/unit/test_hardening_2026_09_27_msi.py, whose
stubbed Windows host they reuse for doctor.ps1, service.ps1 and uninstall.ps1.
"""

from __future__ import annotations

import base64
import functools
import importlib.util
import json
import re
import shutil
import subprocess  # noqa: S404 - runs the custom actions under test only
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - first-party repo file, no DTD/entities
from pathlib import Path
from types import ModuleType

import pytest

PROJECT = Path(__file__).resolve().parents[2]
WXS = PROJECT / "packaging" / "msi" / "udbmcp.wxs"
CUSTOM = PROJECT / "packaging" / "msi" / "custom"
FOLDERS_PS1 = CUSTOM / "folders.ps1"
UNINSTALL_PS1 = CUSTOM / "uninstall.ps1"
GATE_PS1 = PROJECT / "scripts" / "test_package_msi.ps1"
BUILD_MSI = PROJECT / "scripts" / "package" / "build_msi.sh"

_XML_COMMENT = re.compile(r"<!--.*?-->", re.S)

SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"
SID_AUTH_USERS = "S-1-5-11"
SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
SID_CREATOR_OWNER = "S-1-3-0"
SID_APP_PACKAGES = "S-1-15-2-1"
USER_SID = "S-1-5-21-1111-2222-3333-1001"
FULL, MODIFY, READ_EXECUTE = 0x1F01FF, 0x1301BF, 0x1200A9
GENERIC_ALL, GENERIC_READ_EXECUTE = 0x10000000, -0x60000000  # 0xA0000000 as a signed 32-bit value

# WiX v4's sequence numbers for the standard actions this package uses (as
# the compiled InstallExecuteSequence table shows them).
STANDARD_ACTIONS = {
    "FindRelatedProducts": 25,
    "AppSearch": 50,
    "LaunchConditions": 100,
    "CostInitialize": 800,
    "FileCost": 900,
    "CostFinalize": 1000,
    "InstallValidate": 1400,
    "RemoveExistingProducts": 1401,
    "InstallInitialize": 1500,
    "ProcessComponents": 1600,
    "UnpublishFeatures": 1800,
    "RemoveFiles": 3500,
    "RemoveFolders": 3600,
    "CreateFolders": 3700,
    "InstallFiles": 4000,
    "RegisterUser": 6000,
    "RegisterProduct": 6100,
    "PublishFeatures": 6300,
    "PublishProduct": 6400,
    "InstallFinalize": 6600,
}
# What a condition reads in each mode: a first install (or the new product of
# an upgrade), a repair, and an uninstall (msiexec /x, or the old product a
# major upgrade removes).
MODES = {"install": {}, "repair": {"Installed": "1"}, "uninstall": {"Installed": "1", "REMOVE": "ALL"}}


def _wxs_root() -> ET.Element:
    return ET.fromstring(_XML_COMMENT.sub("", WXS.read_text(encoding="utf-8")))  # noqa: S314


def _local(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _elements(name: str) -> list[ET.Element]:
    return [el for el in _wxs_root().iter() if _local(el) == name]


def _custom_actions() -> dict[str, ET.Element]:
    return {el.get("Id") or "": el for el in _elements("CustomAction")}


def _runs(condition: str | None, mode: str) -> bool:
    """Whether an InstallExecuteSequence condition this package uses holds in
    *mode*; any other condition fails the test, to be added here."""
    props = MODES[mode]
    if condition is None:
        return True
    if condition == "NOT REMOVE":
        return not props.get("REMOVE")
    if condition == 'REMOVE="ALL"':
        return props.get("REMOVE") == "ALL"
    raise AssertionError(f"unknown condition {condition!r}: teach _runs() what it means")


def _sequence() -> dict[str, tuple[float, str | None]]:
    """InstallExecuteSequence as (position, condition) per action, with the
    Before/After chains resolved the way WiX numbers them (one step away
    from the action they name)."""
    entries = {el.get("Action") or "": el for el in _elements("InstallExecuteSequence")[0] if _local(el) == "Custom"}

    @functools.cache
    def position(action: str) -> float:
        if action in STANDARD_ACTIONS:
            return float(STANDARD_ACTIONS[action])
        el = entries[action]
        if el.get("Before"):
            return position(el.get("Before") or "") - 0.01
        if el.get("After"):
            return position(el.get("After") or "") + 0.01
        raise AssertionError(f"{action} is scheduled neither Before nor After an action")

    return {action: (position(action), el.get("Condition")) for action, el in entries.items()}


# ----------------------------------------------------------------- W3 -----


SEARCH_ELEMENTS = {"RegistrySearch", "DirectorySearch", "FileSearch", "ComponentSearch", "IniFileSearch"}


def test_w3_every_search_property_is_public_and_secure() -> None:
    # WIX0012: "cannot contain lowercase characters. Since this is a search
    # property, it must also be a public property". Secure: with a user
    # interface AppSearch runs in the client's UI sequence only, and only a
    # Secure property reaches the deferred actions on the server side.
    searched = [
        el
        for el in _elements("Property")
        if any(_local(child) in SEARCH_ELEMENTS for child in el.iter() if child is not el)
    ]
    assert {el.get("Id") for el in searched} == {"CPYTHON312", "UDBMCPREGISTEREDACCOUNT"}
    for prop in searched:
        name = prop.get("Id") or ""
        assert name == name.upper(), f"{name}: a search property must be public (WIX0012)"
        assert prop.get("Secure") == "yes", name


def test_w3_the_actions_read_the_public_property() -> None:
    cas = _custom_actions()
    for action in ("DoctorSmokeCA", "RegisterServiceCA"):
        assert (cas[action].get("ExeCommand") or "").endswith(' -RegisteredAccount "[UDBMCPREGISTEREDACCOUNT]"'), action
    assert "UdbmcpRegisteredAccount" not in WXS.read_text(encoding="utf-8")
    for script in ("doctor.ps1", "service.ps1"):
        text = (CUSTOM / script).read_text(encoding="utf-8")
        assert "[UdbmcpRegisteredAccount]" not in text and "[UDBMCPREGISTEREDACCOUNT]" in text, script


# ----------------------------------------------------------------- W1 -----


@pytest.mark.parametrize("mode", sorted(MODES))
def test_w1_powershell_is_set_before_every_action_that_runs_it(mode: str) -> None:
    # The reviewer's scenario is the uninstall: RemoveServiceCA at
    # RemoveFiles (3499) and SetPowerShellExe after InstallFiles (4001), so
    # the deferred action was written into the script with no executable.
    sequence = _sequence()
    users = [
        ca.get("Id") or ""
        for ca in _elements("CustomAction")
        if ca.get("Property") == "POWERSHELLEXE" and ca.get("ExeCommand")
    ]
    running = [action for action in users if action in sequence and _runs(sequence[action][1], mode)]
    assert running, f"no POWERSHELLEXE action runs on {mode}?"
    if mode == "uninstall":
        assert running == ["RemoveServiceCA"]
    setter, setter_condition = sequence["SetPowerShellExe"]
    assert setter_condition is None, "the assignment is unconditional (a caller's POWERSHELLEXE never survives it)"
    for action in running:
        assert setter < sequence[action][0], f"{mode}: {action} runs before SetPowerShellExe sets POWERSHELLEXE"
    # before InstallInitialize: before any deferred action can be scheduled
    assert setter < STANDARD_ACTIONS["InstallInitialize"]
    # the only immediate action that runs powershell's path: a type-51 assignment
    assert _custom_actions()["SetPowerShellExe"].get("Execute") is None


# ----------------------------------------------------------------- W2 -----


def test_w2_the_config_survives_a_major_upgrade() -> None:
    # afterInstallValidate: the old product is uninstalled completely before
    # the new one installs, so only Permanent keeps the admin's config.yaml
    # (NeverOverwrite then keeps the new product's template off it).
    (upgrade,) = _elements("MajorUpgrade")
    assert upgrade.get("Schedule") == "afterInstallValidate"
    component = next(el for el in _elements("Component") if el.get("Id") == "ConfigYamlComponent")
    assert component.get("Permanent") == "yes", "config.yaml would be removed with the old product"
    assert component.get("NeverOverwrite") == "yes", "a reinstall must keep the admin's config.yaml"
    files = [el for el in component.iter() if _local(el) == "File"]
    assert [f.get("Name") for f in files] == ["config.yaml"] and files[0].get("KeyPath") == "yes"
    # a stable GUID: a Permanent component is registered for good under it
    assert "ConfigTemplateGuid" in (component.get("Guid") or "")


# ----------------------------------------------------------- W4 + N1 -----


def _folder_check() -> ET.Element:
    return _custom_actions()["CheckFoldersCA"]


def _format(command: str, props: dict[str, str]) -> str:
    """*command* as Windows Installer formats it: [\\x] is the character x,
    [Name] the property's value; a property not in *props* fails."""

    def repl(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("\\"):
            return token[1]
        return props[token]

    return re.sub(r"\[(\\.|[A-Za-z_][\w.]*)\]", repl, command)


def test_w4_n1_the_folders_are_checked_before_createfolders_writes_through_them() -> None:
    sequence = _sequence()
    position, condition = sequence["CheckFoldersCA"]
    for mode in ("install", "repair"):
        assert _runs(condition, mode)
    assert not _runs(condition, "uninstall")
    assert position < STANDARD_ACTIONS["CreateFolders"] < STANDARD_ACTIONS["InstallFiles"]
    assert position > STANDARD_ACTIONS["RemoveFolders"]
    # no other action may come between the check and CreateFolders
    between = [a for a, (p, _) in sequence.items() if position < p < STANDARD_ACTIONS["CreateFolders"]]
    assert between == [], between
    check = _folder_check()
    assert (check.get("Execute"), check.get("Impersonate"), check.get("Return"), check.get("Property")) == (
        "deferred",
        "no",
        "check",
        "POWERSHELLEXE",
    )
    # the folder's DACL still comes from CreateFolders, after the check
    folder = next(el for el in _elements("Directory") if el.get("Id") == "ProgramDataUdbmcpDir")
    assert [el for el in folder.iter() if _local(el) == "PermissionEx"]


def test_w4_n1_the_check_runs_the_embedded_script_never_an_installed_file() -> None:
    command = _folder_check().get("ExeCommand") or ""
    assert "-File" not in command and "[INSTALLFOLDER]scripts" not in command
    references = set(re.findall(r"\[([A-Za-z_][\w.]*)\]", command))
    assert references == {"UdbmcpFolderCheck", "INSTALLFOLDER", "ProgramDataUdbmcpDir"}, references
    formatted = _format(
        command, {"UdbmcpFolderCheck": "QUJD", "INSTALLFOLDER": "D:\\Apps\\U\\", "ProgramDataUdbmcpDir": "C:\\P\\U\\"}
    )
    assert formatted == (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create('
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QUJD')))) "
        "-InstallFolder 'D:\\Apps\\U\\' -ConfigFolder 'C:\\P\\U\\'\""
    ), formatted
    # a private property: msiexec cannot replace the script
    assert "UdbmcpFolderCheck" != "UdbmcpFolderCheck".upper()
    # INSTALLFOLDER sits between single quotes: one in it is refused first
    conditions = [el.get("Condition") for el in _elements("Launch")]
    assert 'NOT (INSTALLFOLDER >< "\'")' in conditions
    assert '<?include "folders.wxi" ?>' in WXS.read_text(encoding="utf-8")


def test_w4_n1_build_msi_embeds_the_staged_folders_script(tmp_path: Path) -> None:
    code = BUILD_MSI.read_text(encoding="utf-8")
    assert re.search(r"for ps1 in [^;]*\bfolders\.ps1\b[^;]*; do", code), "folders.ps1 is staged (and key-scanned)"
    assert 'xmllint --noout "$STAGE/folders.wxi"' in code
    generator = re.search(
        r'python3 - "\$CUSTOM_STAGE/folders\.ps1" "\$STAGE/folders\.wxi" <<\'PYEOF\' \\\n[^\n]*\n(.*?)\nPYEOF\n',
        code,
        re.S,
    )
    assert generator, "build_msi.sh generates folders.wxi from the staged folders.ps1"
    assert code.index('find_pubkey_material "$CUSTOM_STAGE"') < generator.start()
    script = tmp_path / "gen.py"
    script.write_text(generator.group(1), encoding="utf-8")
    wxi = tmp_path / "folders.wxi"
    subprocess.run([sys.executable, str(script), str(FOLDERS_PS1), str(wxi)], check=True)  # noqa: S603
    (prop,) = [el for el in ET.parse(wxi).getroot() if _local(el) == "Property"]  # noqa: S314
    assert prop.get("Id") == "UdbmcpFolderCheck"
    assert base64.b64decode(prop.get("Value") or "") == FOLDERS_PS1.read_bytes()


def test_w4_n1_the_script_fits_a_command_line() -> None:
    # CreateProcess takes 32767 characters; the base64 text is most of it.
    assert len(base64.b64encode(FOLDERS_PS1.read_bytes())) + len(_folder_check().get("ExeCommand") or "") + 1024 < 32767
    FOLDERS_PS1.read_bytes().decode("ascii")


# ----------------------------------------------------------------- N2 -----


def test_n2_the_rollback_twin_knows_a_repair() -> None:
    command = _custom_actions()["RollbackRemoveServiceCA"].get("ExeCommand") or ""
    assert command.endswith(' -Repair "[Installed]"'), command
    # Installed is private: msiexec cannot set it
    assert "Installed" != "Installed".upper()


# ----------------------------------------------------------------- N4 -----


def test_n4_the_gate_records_service_running_and_goes_on() -> None:
    code = GATE_PS1.read_text(encoding="utf-8")
    assert "Stop-Gate 'service_running'" not in code
    assert code.count("Add-Check 'service_running' 'failed'") == 2
    service = code.index("# --------------------------------------------------------- 4. the service")
    for later in (
        "'doctor_smoke'",
        "'installed_manifest_recorded'",
        "'rollback_refused'",
        "'folder_squat_refused'",
        "'launch_conditions'",
        "'repair_keeps_account'",
    ):
        assert code.index(later) > service, later
    # a recorded failure still fails the gate
    done = code[code.index("# ------------------------------------------------------------------ done") :]
    assert "if ($script:Failed -eq 0) {" in done and "exit 1" in done
    assert "if ($Status -ne 'passed') { $script:Failed = 1 }" in code


# ------------------------------------------------- executed under pwsh ----


def _harness() -> ModuleType:
    """tests/unit/test_hardening_2026_09_27_msi.py: its stubbed Windows host."""
    path = Path(__file__).with_name("test_hardening_2026_09_27_msi.py")
    spec = importlib.util.spec_from_file_location("_msi_hardening_harness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _harness()
PWSH = shutil.which("pwsh")
executed = H.executed


@pytest.fixture()
def host(tmp_path: Path):  # noqa: ANN201 - the harness's _Host
    return H._Host(tmp_path)


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_w3_an_account_logs_does_not_vouch_for_is_refused(host, script: str) -> None:  # noqa: ANN001
    # UDBMCPREGISTEREDACCOUNT is public: msiexec sets it, and AppSearch keeps
    # that value when the service key is absent. An install that registered
    # the service under NetworkService granted it Modify on logs\; without
    # that grant the account came from somewhere else, and is refused before
    # anything changes.
    run = host.doctor if script == "doctor" else functools.partial(host.service, account="")
    code, out, calls = run({host.cfgdir: H.SAFE, host.config: H.SAFE}, registered=H.NETWORK_SERVICE)
    assert code == 1, out
    assert f"this install was told the service is registered under '{H.NETWORK_SERVICE}'" in out, out
    assert "does not grant that account write access" in out and "UDBMCP_SERVICE_ACCOUNT" in out, out
    assert H._changed_nothing(calls), calls
    assert not (host.cfgdir / "logs").exists()


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_w3_the_account_logs_vouches_for_is_kept(host, script: str) -> None:  # noqa: ANN001
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl = {
        host.cfgdir: H.SAFE,
        host.config: H.SAFE,
        logs: H._entry(SID_ADMINS, [H.SID_NETWORK_SERVICE, "Allow", "(OI)(CI)M", False]),
    }
    run = host.doctor if script == "doctor" else functools.partial(host.service, account="")
    code, out, calls = run(acl, registered=H.NETWORK_SERVICE)
    assert code == 0, out
    assert f"keeping '{H.NETWORK_SERVICE}'" in out, out


def _rollback(host, repair: str, **env: str) -> tuple[int, str, str]:  # noqa: ANN001
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"release_seq": 7}), encoding="utf-8")
    record.with_name("manifest.json.previous").write_text(json.dumps({"release_seq": 6}), encoding="utf-8")
    params = {"ServiceName": "udbmcp", "InstalledManifest": str(record), "Repair": repair}
    code, out, calls = host.run(host.uninstall_ps1, params, None, **env)
    assert json.loads(record.read_text(encoding="utf-8")) == {"release_seq": 6}, "the record is restored either way"
    return code, out, calls


@executed
def test_exec_n2_a_failed_repair_keeps_the_service(host) -> None:  # noqa: ANN001
    # The service exists (it did before the repair began); the repair failed,
    # e.g. in RegisterServiceCA before it touched the service.
    code, out, calls = _rollback(host, "1", H_SC_SERVICE="1")
    assert code == 0, out
    assert "a failed repair: the service 'udbmcp' registered before it is kept" in out, out
    assert not [ln for ln in calls.splitlines() if ln.startswith(("sc stop", "sc delete", "reg delete"))], calls


@executed
def test_exec_n2_a_failed_install_still_removes_its_service(host) -> None:  # noqa: ANN001
    code, out, calls = _rollback(host, "", H_SC_SERVICE="1")
    assert code == 0, out
    lines = calls.splitlines()
    assert "sc stop udbmcp" in lines and "sc delete udbmcp" in lines, calls


# folders.ps1 runs as CheckFoldersCA runs it: the formatted -Command string,
# its script block decoded from the base64 property, after stubs for the
# Windows ACL cmdlets (an ACL store keyed by path; a path nobody described has
# the DACL a folder under C:\Program Files inherits). Junctions are symbolic
# links, which .NET reports as reparse points on POSIX too.

_FOLDER_STUBS = r"""
function global:Read-AclStore { Get-Content -LiteralPath $env:H_ACL -Raw | ConvertFrom-Json -AsHashtable }
function global:Get-Acl {
    param([string]$LiteralPath)
    Add-Content -LiteralPath $env:H_CALLS -Value ('Get-Acl ' + $LiteralPath)
    $entry = (Read-AclStore)[$LiteralPath]
    if ($null -eq $entry) {
        $entry = @{ owner = 'S-1-5-32-544'; rules = @(@('S-1-5-18', 'Allow', 2032127, $true, 'None'),
            @('S-1-5-32-544', 'Allow', 2032127, $true, 'None'), @('S-1-5-32-545', 'Allow', 1179817, $true, 'None')) }
    }
    $acl = [pscustomobject]@{ Owner = $entry.owner; Rules = $entry.rules }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value {
        param($type) [pscustomobject]@{ Value = $this.Owner }
    }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
        param($explicit, $inherited, $type)
        foreach ($rule in $this.Rules) {
            [pscustomobject]@{
                IdentityReference = [pscustomobject]@{ Value = $rule[0] }
                AccessControlType = [System.Security.AccessControl.AccessControlType]$rule[1]
                # as .NET reports them, generic bits included (a cast would refuse those)
                FileSystemRights  = [Enum]::ToObject([System.Security.AccessControl.FileSystemRights], [int]$rule[2])
                IsInherited       = [bool]$rule[3]
                PropagationFlags  = [System.Security.AccessControl.PropagationFlags]$rule[4]
            }
        }
    }
    return $acl
}
function global:Set-Acl {
    param([string]$LiteralPath, $AclObject)
    Add-Content -LiteralPath $env:H_CALLS -Value ('Set-Acl ' + $LiteralPath + ' ' + $AclObject.Sddl)
}
function global:New-Object {
    if ($args.Count -ge 1 -and $args[0] -eq 'System.Security.AccessControl.DirectorySecurity') {
        $security = [pscustomobject]@{ Sddl = '' }
        $security | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptorSddlForm -Value {
            param($sddl) $this.Sddl = $sddl
        }
        return $security
    }
    Microsoft.PowerShell.Utility\New-Object @args
}
"""

INSTALL_SDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
CONFIG_SDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


class _Folders:
    """C:\\Program Files and C:\\ProgramData under a temporary directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.install = root / "ProgramFiles" / "UniversalDB MCP"
        self.config = root / "ProgramData" / "UniversalDB MCP"
        self.install.parent.mkdir(parents=True)
        self.config.parent.mkdir(parents=True)
        self.acl: dict[str, dict[str, object]] = {}
        self.stubs = root / "stubs.ps1"
        self.stubs.write_text(_FOLDER_STUBS, encoding="utf-8")

    def run(self) -> tuple[int, str, str]:
        calls, store = self.root / "calls.log", self.root / "acl.json"
        calls.write_text("", encoding="utf-8")
        store.write_text(json.dumps(self.acl), encoding="utf-8")
        command = _format(
            _folder_check().get("ExeCommand") or "",
            {
                "UdbmcpFolderCheck": base64.b64encode(FOLDERS_PS1.read_bytes()).decode("ascii"),
                # directory properties end with a separator
                "INSTALLFOLDER": str(self.install) + "/",
                "ProgramDataUdbmcpDir": str(self.config) + "/",
            },
        )
        script = re.fullmatch(r'-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "(.*)"', command)
        assert script, command
        proc = subprocess.run(  # noqa: S603 - fixed argv, the repo script under test
            [str(PWSH), "-NoProfile", "-NonInteractive", "-Command", f". '{self.stubs}'; " + script.group(1)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(self.root),
                "H_ACL": str(store),
                "H_CALLS": str(calls),
            },
        )
        return proc.returncode, proc.stdout + proc.stderr, calls.read_text(encoding="utf-8")


def _acl(owner: str, *rules: tuple[str, int, bool, str]) -> dict[str, object]:
    """owner, then (SID, rights, inherited, propagation flags) Allow rules."""
    return {
        "owner": owner,
        "rules": [[sid, "Allow", rights, inherited, flags] for sid, rights, inherited, flags in rules],
    }


PROGRAM_FILES_CHILD = _acl(
    SID_ADMINS,
    (SID_TRUSTED_INSTALLER, FULL, True, "None"),
    (SID_SYSTEM, FULL, True, "None"),
    (SID_ADMINS, FULL, True, "None"),
    (SID_USERS, READ_EXECUTE, True, "None"),
    (SID_USERS, GENERIC_READ_EXECUTE, True, "InheritOnly"),
    (SID_CREATOR_OWNER, GENERIC_ALL, True, "InheritOnly"),
    (SID_APP_PACKAGES, READ_EXECUTE, True, "None"),
)


@pytest.fixture()
def folders(tmp_path: Path) -> _Folders:
    return _Folders(tmp_path)


@executed
def test_exec_w4_a_planted_junction_is_refused_before_any_dacl(folders: _Folders) -> None:
    # A local user's mklink /J "C:\ProgramData\UniversalDB MCP" "C:\Program
    # Files": CreateFolders would have written the folder's protected DACL
    # onto the target.
    victim = folders.root / "victim"
    victim.mkdir()
    folders.config.symlink_to(victim, target_is_directory=True)
    code, out, calls = folders.run()
    assert code == 1, out
    assert f"refusing the config folder '{folders.config}': it is a junction or symbolic link" in out, out
    touched = [ln for ln in calls.splitlines() if str(folders.config) in ln or str(victim) in ln]
    assert not [ln for ln in touched if ln.startswith("Set-Acl ")] and f"Get-Acl {victim}" not in calls, calls
    assert list(victim.iterdir()) == []


@executed
def test_exec_w4_n1_missing_folders_are_created_protected(folders: _Folders) -> None:
    code, out, calls = folders.run()
    assert code == 0, out
    assert folders.install.is_dir() and folders.config.is_dir()
    sets = [ln for ln in calls.splitlines() if ln.startswith("Set-Acl ")]
    assert sets == [f"Set-Acl {folders.install} {INSTALL_SDDL}", f"Set-Acl {folders.config} {CONFIG_SDDL}"], calls
    assert (
        f"'{folders.install}' is safe to install into" in out and f"'{folders.config}' is safe to install into" in out
    )


@executed
def test_exec_n1_the_default_program_files_acl_passes(folders: _Folders) -> None:
    folders.install.mkdir()
    folders.config.mkdir()
    folders.acl[str(folders.install)] = PROGRAM_FILES_CHILD
    code, out, calls = folders.run()
    assert code == 0, out
    assert "Set-Acl" not in calls, "existing folders keep their DACL"


@executed
@pytest.mark.parametrize(
    "rule",
    [
        (SID_AUTH_USERS, MODIFY, True, "None"),  # D:\Apps\...: inherited from the volume root
        (SID_USERS, 0x116, True, "InheritOnly"),  # what the install creates in it
        (USER_SID, FULL, False, "None"),
    ],
    ids=["authenticated-users-modify", "inherit-only-write", "a-user"],
)
def test_exec_n1_an_install_folder_others_may_write_is_refused(
    folders: _Folders, rule: tuple[str, int, bool, str]
) -> None:
    # The reviewer's scenario: a custom INSTALLFOLDER that inherits
    # Authenticated Users Modify; a .pth file in venv\ or an edited
    # scripts\uninstall.ps1 then runs as LocalSystem.
    folders.install.mkdir()
    entry = PROGRAM_FILES_CHILD | {"rules": [*PROGRAM_FILES_CHILD["rules"], [rule[0], "Allow", *rule[1:]]]}  # type: ignore[misc]
    folders.acl[str(folders.install)] = entry
    code, out, calls = folders.run()
    assert code == 1, out
    assert f"refusing INSTALLFOLDER '{folders.install}': it grants {rule[0]} " in out, out
    assert "everything installed there runs as LocalSystem" in out
    assert not folders.config.exists() and "Set-Acl" not in calls


@executed
def test_exec_n1_an_install_folder_a_user_owns_is_refused(folders: _Folders) -> None:
    folders.install.mkdir()
    folders.acl[str(folders.install)] = PROGRAM_FILES_CHILD | {"owner": USER_SID}
    code, out, calls = folders.run()
    assert code == 1, out
    assert f"it is owned by {USER_SID}, not SYSTEM, Administrators, TrustedInstaller or an administrator" in out, out


@executed
def test_exec_n1_a_folder_above_that_a_user_may_move_is_refused(folders: _Folders) -> None:
    # D:\Apps inherits Authenticated Users Modify (Delete): any user renames
    # it and puts a junction in its place.
    folders.acl[str(folders.install.parent)] = _acl(
        SID_ADMINS, (SID_SYSTEM, FULL, True, "None"), (SID_AUTH_USERS, MODIFY, True, "None")
    )
    code, out, calls = folders.run()
    assert code == 1, out
    assert f"the folder above it '{folders.install.parent}' grants {SID_AUTH_USERS} " in out, out
    assert not folders.install.exists(), "nothing is created under a folder a user can move"


@executed
def test_exec_n1_a_drive_root_users_may_modify_passes(folders: _Folders) -> None:
    # A volume root's Authenticated Users Modify cannot move the root (it has
    # no parent); Modify holds no Delete-child right.
    folders.acl["/"] = _acl(SID_SYSTEM, (SID_SYSTEM, FULL, False, "None"), (SID_AUTH_USERS, MODIFY, False, "None"))
    code, out, calls = folders.run()
    assert code == 0, out


@executed
def test_exec_w4_a_config_folder_a_user_owns_is_refused(folders: _Folders) -> None:
    folders.config.mkdir()
    folders.acl[str(folders.config)] = _acl(USER_SID, (USER_SID, FULL, False, "None"))
    code, out, calls = folders.run()
    assert code == 1, out
    assert f"refusing the config folder '{folders.config}': it is owned by {USER_SID}" in out, out
    assert not [ln for ln in calls.splitlines() if ln.startswith(f"Set-Acl {folders.config}")], calls


@executed
def test_exec_w4_an_upgraded_config_folder_passes(folders: _Folders) -> None:
    # An earlier release's folder still carries C:\ProgramData's inheritable
    # ACEs (Users may create entries, never delete or re-permission the
    # folder): doctor.ps1 and service.ps1 deal with what is in it.
    folders.config.mkdir()
    folders.acl[str(folders.config)] = _acl(
        SID_ADMINS,
        (SID_SYSTEM, FULL, True, "None"),
        (SID_ADMINS, FULL, True, "None"),
        (SID_USERS, READ_EXECUTE, True, "None"),
        (SID_USERS, 0x116, True, "None"),
        (SID_CREATOR_OWNER, GENERIC_ALL, True, "InheritOnly"),
    )
    code, out, calls = folders.run()
    assert code == 0, out
