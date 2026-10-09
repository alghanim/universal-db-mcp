"""Second code review of the MSI fixes (V4-g, V4-i, V4-j).

V4-i: gate check 9 (folder_squat_refused) required the planted-folder repair
      to fail at DoctorSmokeCA, but CheckFoldersCA (before CreateFolders)
      refuses a folder BUILTIN\\Users owns first. The check stopped the gate on
      every real run, so checks 10 and 11 never ran. The 'folder' case now
      expects CheckFoldersCA and the 'config' case DoctorSmokeCA, and checks
      9-11 record a failure and go on (Stop-Check), so each one runs.
V4-g: the lookup that keeps an account the install was not given
      (Get-EarlierAccountSid -GrantedSid) skipped every member of
      Administrators, so a gMSA in that group, which the registration action
      had granted Modify on logs\\ like any other account, was refused on
      every repair. The granted account is now matched as it is.
V4-j: a repair deleted the registered service and created it again; a
      failure after `sc.exe create` removed the new one, and the rollback
      twin (which keeps the service on a repair) had nothing left to keep. A
      registered service is now stopped and updated in place (sc.exe config),
      never deleted, which also closes the window between the delete and the
      create.

The executed tests run the real scripts under pwsh with the stubbed Windows
host of tests/unit/test_hardening_2026_09_27_msi.py; the gate's checks 9-11
run verbatim against a simulated msiexec.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess  # noqa: S404 - runs the scripts under test only
from pathlib import Path
from types import ModuleType

import pytest

PROJECT = Path(__file__).resolve().parents[2]
CUSTOM = PROJECT / "packaging" / "msi" / "custom"
SERVICE_PS1 = CUSTOM / "service.ps1"
DOCTOR_PS1 = CUSTOM / "doctor.ps1"
GATE_PS1 = PROJECT / "scripts" / "test_package_msi.ps1"

SID_ADMINS = "S-1-5-32-544"
GMSA = "CONTOSO\\udbmcp$"
GMSA_SID = "S-1-5-21-1111-2222-3333-1105"
OTHER_GMSA = "CONTOSO\\other$"
OTHER_GMSA_SID = "S-1-5-21-1111-2222-3333-1106"
# gate checks 9-11
ALL_CHECKS = ["folder_squat_refused", "folder_squat_cleanup_reinstalled", "launch_conditions", "repair_keeps_account"]


def _harness() -> ModuleType:
    """tests/unit/test_hardening_2026_09_27_msi.py: its stubbed Windows host."""
    path = Path(__file__).with_name("test_hardening_2026_09_27_msi.py")
    spec = importlib.util.spec_from_file_location("_msi_hardening_harness_cr2", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _harness()
PWSH = shutil.which("pwsh")
executed = H.executed


def _code(path: Path) -> str:
    return H._code(path)


def _main_body(code: str) -> str:
    return H._main_body(code)


# ------------------------------------------------------------------ V4-g --


def test_v4g_the_granted_account_is_matched_as_it_is() -> None:
    for path in (SERVICE_PS1, DOCTOR_PS1):
        lookup = H._function(_code(path), "Get-EarlierAccountSid")
        granted = lookup[lookup.index("if ($GrantedSid) {") :]
        # with $GrantedSid: that SID, whoever it is; without: any account but
        # the service's. A member of Administrators counts in both through
        # the registration's Modify only (cr3 A8-5: both paths alike).
        assert re.match(
            r"if \(\$GrantedSid\) \{\s*\n\s*if \(\$sid -ne \$GrantedSid\) \{ continue \}\s*\n\s*\}\s*\n"
            r"\s*elseif \(\$sid -eq \$ServiceSid\) \{ continue \}\s*\n"
            r"[^\n]*\n\s*if \(\(Test-TrustedOwner -Sid \$sid\) -and "
            r"\$granted -ne \$script:ModifyRights\) \{ continue \}",
            granted,
        ), granted[:400]
        common = lookup[lookup.index("foreach ($rule in") : lookup.index("if ($GrantedSid) {")]
        assert "Test-TrustedOwner" not in common, path.name
        assert "-not (Test-AccountSid -Sid $sid)" in common, "a group or well-known principal never counts"


def _gmsa_logs(host, *sids: str) -> dict[Path, dict[str, object]]:  # noqa: ANN001
    logs = host.cfgdir / "logs"
    logs.mkdir()
    rules = [[sid, "Allow", "(OI)(CI)M", False] for sid in sids]
    return {host.cfgdir: H.SAFE, host.config: H.SAFE, logs: H._entry(SID_ADMINS, *rules)}


def _run(host, script: str, acl, registered: str, **env: str):  # noqa: ANN001, ANN202
    if script == "doctor":
        return host.doctor(acl, registered=registered, **env)
    return host.service(acl, account="", registered=registered, **env)


GMSA_ENV = {
    "H_ADMIN_MEMBERS": f"{GMSA_SID},{OTHER_GMSA_SID}",
    "H_ACCOUNTS": f"{GMSA}={GMSA_SID};{OTHER_GMSA}={OTHER_GMSA_SID}",
}


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_v4g_a_gmsa_in_administrators_that_logs_grants_is_kept(host, script: str) -> None:  # noqa: ANN001
    # The reviewer's scenario: installed with UDBMCP_SERVICE_ACCOUNT naming a
    # gMSA that is a direct member of Administrators (service.ps1 granted it
    # (OI)(CI)M on logs\), then repaired without the property.
    code, out, calls = _run(host, script, _gmsa_logs(host, GMSA_SID), GMSA, **GMSA_ENV)
    assert code == 0, out
    assert f"keeping '{GMSA}'" in out, out
    if script == "service":
        logs = host.cfgdir / "logs"
        assert f"icacls {logs} | /grant:r | *{GMSA_SID}:(OI)(CI)M" in calls, calls


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_v4g_a_gmsa_in_administrators_logs_does_not_grant_is_refused(host, script: str) -> None:  # noqa: ANN001
    # The previous review's W3 rule still holds for an administrator's
    # account: UDBMCPREGISTEREDACCOUNT is public, and only the grant the
    # registration action made vouches for it. Another member's grant is not
    # this account's.
    for sids in ((), (OTHER_GMSA_SID,)):
        if (host.cfgdir / "logs").exists():
            (host.cfgdir / "logs").rmdir()
        code, out, calls = _run(host, script, _gmsa_logs(host, *sids), GMSA, **GMSA_ENV)
        assert code == 1, (sids, out)
        assert f"this install was told the service is registered under '{GMSA}'" in out, out
        assert H._changed_nothing(calls), calls


@executed
def test_exec_v4g_an_administrators_own_grant_still_is_no_earlier_service_account(host) -> None:  # noqa: ANN001
    # An ACE an administrator gave themselves on logs\ (Full Control, not the
    # registration's Modify) does not stop a repair that keeps LocalSystem.
    # (cr3 A8-5: a member's Modify does, as any account's; test_cr3_msi.py.)
    logs = host.cfgdir / "logs"
    logs.mkdir()
    acl = {
        host.cfgdir: H.SAFE,
        host.config: H.SAFE,
        logs: H._entry(SID_ADMINS, [H.ADMIN_USER_SID, "Allow", "F", False]),
    }
    code, out, calls = host.service(acl, account="", H_ADMIN_MEMBERS=H.ADMIN_USER_SID)
    assert code == 0, out


# ------------------------------------------------------------------ V4-j --


def test_v4j_a_registered_service_is_updated_in_place_never_deleted() -> None:
    code = _code(SERVICE_PS1)
    body = _main_body(code)
    assert "Remove-ExistingService" not in code
    assert "\n    Stop-ExistingService -Name $ServiceName\n" in body
    # a flag, not a return value: the function's Write-Output would join it
    stop = H._function(code, "Stop-ExistingService")
    assert "return $" not in stop and "$script:Existing = $true" in stop
    assert '"delete "' not in stop and "'delete '" not in stop
    # sc.exe delete runs only in the best-effort cleanup, and only for a
    # service this action created
    assert len(re.findall(r"[\"']delete [\"']", code)) == 1
    assert "if ($script:Created) { Remove-ServiceBestEffort -Name $ServiceName }" in body
    created = [m.start() for m in re.finditer(r"\$script:Created = \$true", body)]
    assert len(created) == 1
    # a registered service is probed by its first change, created only when
    # it is gone; the switch (sc.exe config) comes last (cr3 A8-1, A8-4)
    probe = body.index("if ($script:Existing) {")
    create = body.index("('create ' + $ServiceName + $serviceArgs + $accountArgs)")
    config = body.index("('config ' + $ServiceName + $configArgs)")
    assert probe < body.index("if (-not $script:Existing) {") < create < created[0] < config
    # the password never goes on a command line
    args = body[body.index("$serviceArgs = ' binPath= ") : probe]
    assert "Password" not in args


@pytest.fixture()
def host(tmp_path: Path):  # noqa: ANN201 - the harness's _Host
    return H._Host(tmp_path)


# sc.exe that logs each argument as [arg] (an empty one shows as []):
# H_SC_SERVICE=1 the service exists; H_SC_FAIL=<verb> that verb exits 5;
# H_SC_MARKED=1 sc.exe config answers ERROR_SERVICE_MARKED_FOR_DELETE.
_SC_STUB = r"""#!/bin/sh
line="sc"
for a in "$@"; do line="$line [$a]"; done
echo "$line" >> "$H_CALLS"
[ -n "$H_SC_FAIL" ] && [ "$1" = "$H_SC_FAIL" ] && exit 5
[ "$1" = config ] && [ -n "$H_SC_MARKED" ] && exit 48
if [ "$1" = query ]; then [ -n "$H_SC_SERVICE" ] || exit 36; echo "        STATE              : 1  STOPPED"; fi
exit 0
"""


def _sc_host(host):  # noqa: ANN001, ANN202
    H._executable(host.root / "win" / "System32" / "sc.exe", _SC_STUB)
    # POSIX exit statuses are 8 bits: 1072 arrives as 48
    text = host.service_ps1.read_text(encoding="utf-8")
    assert "$script:ErrServiceMarkedForDelete = 1072" in text
    marked = "$script:ErrServiceMarkedForDelete = "
    host.service_ps1.write_text(text.replace(marked + "1072", marked + "48"))
    return host


def _sc(calls: str, verb: str) -> list[str]:
    return [ln for ln in calls.splitlines() if ln.startswith(f"sc [{verb}]")]


def _repair(host, account: str = "LocalSystem", **env: str) -> tuple[int, str, str]:  # noqa: ANN001
    return _sc_host(host).service({host.cfgdir: H.SAFE, host.config: H.SAFE}, account=account, H_SC_SERVICE="1", **env)


@executed
def test_exec_v4j_a_repair_updates_the_service_in_place(host) -> None:  # noqa: ANN001
    code, out, calls = _repair(host)
    assert code == 0, out
    assert _sc(calls, "stop") and not _sc(calls, "delete") and not _sc(calls, "create"), calls
    (config,) = _sc(calls, "config")
    python = host.venv / "Scripts" / "python.exe"
    assert config == (
        f'sc [config] [udbmcp] [binPath=] ["{python}" -I -m universal_db_mcp serve --transport http]'
        " [start=] [auto] [type=] [own] [error=] [normal] [depend=] [/] [DisplayName=] [udbmcp]"
        " [obj=] [LocalSystem] [password=] []"
    ), config
    assert "updating service 'udbmcp' in place" in out
    lines = calls.splitlines()
    # description first (the probe), the switch last (cr3 A8-1, A8-4)
    assert lines.index(_sc(calls, "stop")[0]) < lines.index(_sc(calls, "description")[0]) < lines.index(config)


@executed
@pytest.mark.parametrize(
    ("account", "password"),
    [(H.NETWORK_SERVICE, True), ("NT AUTHORITY\\LocalService", True), (GMSA, False), ("NT SERVICE\\udbmcp", False)],
)
def test_exec_v4j_in_place_passes_an_empty_password_only_for_the_builtin_accounts(
    host,  # noqa: ANN001
    account: str,
    password: bool,
) -> None:
    # ChangeServiceConfig: an empty password for LocalSystem, LocalService and
    # NetworkService; none (NULL: keep) for a managed service or virtual
    # account, which must not be given one.
    code, out, calls = _repair(host, account=account, H_ACCOUNTS=f"{GMSA}={GMSA_SID}")
    assert code == 0, out
    (config,) = _sc(calls, "config")
    assert config.endswith(f"[obj=] [{account}] [password=] []" if password else f"[obj=] [{account}]"), config


@executed
@pytest.mark.parametrize("fail", ["description", "failure", "reg"])
def test_exec_v4j_a_repair_failing_after_the_update_keeps_the_service(host, fail: str) -> None:  # noqa: ANN001
    # The reviewer's scenario: any failure after the service was registered
    # again (sc.exe description / failure, the Environment value, the
    # release record) deleted the service, and the rollback twin, run with
    # -Repair, kept nothing. Now neither run deletes it. (Since cr3 these
    # steps run before the switch, so the service also keeps its account.)
    env = {"H_REG_FAIL": "1"} if fail == "reg" else {"H_SC_FAIL": fail}
    code, out, calls = _repair(host, **env)
    assert code == 1, out
    assert "SERVICE-ACTION FAILED: service registration failed" in out, out
    assert "was registered before this action, which updates it in place and does not remove it" in out, out
    assert "it keeps its binPath and account" in out, out
    assert not _sc(calls, "config") and not _sc(calls, "delete") and not _sc(calls, "create"), calls
    record = host.root / "ProgramFiles" / "UniversalDB MCP" / "manifest.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    params = {"ServiceName": "udbmcp", "InstalledManifest": str(record), "Repair": "1"}
    code, out, calls = host.run(host.uninstall_ps1, params, None, H_SC_SERVICE="1")
    assert code == 0, out
    assert "a failed repair: the service 'udbmcp' registered before it is kept" in out, out
    assert not [ln for ln in calls.splitlines() if ln.startswith(("sc [delete]", "sc delete", "sc [stop]"))], calls


@executed
@pytest.mark.parametrize("marked", [False, True])
def test_exec_v4j_a_failed_update_leaves_the_service_registered(host, marked: bool) -> None:  # noqa: ANN001
    # The earlier residual window (between the delete and sc.exe create) is
    # gone: nothing before sc.exe config, and not sc.exe config itself,
    # removes the service.
    env = {"H_SC_MARKED": "1"} if marked else {"H_SC_FAIL": "config"}
    code, out, calls = _repair(host, **env)
    assert code == 1, out
    if marked:
        assert "service 'udbmcp' is marked for deletion: Windows removes it once it has stopped" in out, out
    else:
        assert "sc.exe config udbmcp failed with exit code 5; the service keeps its binPath and account" in out, out
    assert not _sc(calls, "delete") and not _sc(calls, "create"), calls


@executed
def test_exec_v4j_a_first_install_still_removes_the_service_it_created(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service({host.cfgdir: H.SAFE, host.config: H.SAFE}, H_REG_FAIL="1")
    assert code == 1, out
    assert _sc(calls, "create") and not _sc(calls, "config") and not _sc(calls, "stop"), calls
    lines = calls.splitlines()
    assert lines.index(_sc(calls, "create")[0]) < lines.index(_sc(calls, "delete")[0]), calls
    assert "==> cleanup: service 'udbmcp' deleted" in out


# ------------------------------------------------------------------ V4-i --


def _region(text: str) -> str:
    """The gate's checks 9-11, verbatim."""
    start = text.index("    # ------------------- 9. squatted config folder / config (never adopted)")
    return text[start : text.index("    # ------------------------------------------------------------------ done")]


def _region_code() -> str:
    """Checks 9-11, code lines only (no comment can satisfy a check)."""
    region = re.sub(r"`\r?\n", " ", _region(GATE_PS1.read_text(encoding="ascii")))
    return "\n".join(ln for ln in region.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))


def test_v4i_each_squat_case_expects_the_action_that_refuses_it() -> None:
    region = _region_code()
    assert "@{ Name = 'folder'; Action = 'CheckFoldersCA' }" in region
    assert "@{ Name = 'config'; Action = 'DoctorSmokeCA' }" in region
    refused_at = "'CustomAction ' + $case.Action + ' returned actual error code|Action ' + $case.Action + ', location:'"
    assert refused_at in region
    assert "DoctorSmokeCA returned actual error code" not in region
    # a Launch refusal must come before the first custom action, CheckFoldersCA
    assert "$launchText -match 'CheckFoldersCA|VerifyBundleCA'" in region


def test_v4i_checks_9_to_11_record_a_failure_and_go_on() -> None:
    code = _code(GATE_PS1)
    region = _region_code()
    # only the admin's folder sitting aside stops the gate: a backup an
    # interrupted run left (cr3 D-5), or one that cannot be put back
    stops = re.findall(r"Stop-Gate '(\w+)'", region)
    assert stops == ["folder_squat_refused", "folder_squat_cleanup_reinstalled"], stops
    assert "could not restore $ProgramDataDir from $SquatBackup" in region
    for name in ALL_CHECKS:
        assert f"Add-CheckFailure '{name}' $_" in region, name
    stop_check = H._function(code, "Stop-Check")
    assert "throw $failure" in stop_check and "exit" not in stop_check
    assert "Add-Check $failed 'failed'" in H._function(code, "Add-CheckFailure")


# The gate's checks 9-11 run verbatim under pwsh against a simulated
# msiexec: Start-Process answers as the MSI does (CheckFoldersCA refuses a
# config folder BUILTIN\Users owns, DoctorSmokeCA a config.yaml it owns,
# LaunchConditions the three bad properties, a repair sets the service
# account it names), icacls /setowner and Get-Acl keep owners in a table.
# H_ADOPT=folder|config: the simulated MSI adopts that squat;
# H_LAUNCH_ACCEPT=<case>: it accepts that Launch case.

_GATE_STUBS = r"""
$ErrorActionPreference = 'Stop'
$script:Checks = New-Object System.Collections.Generic.List[object]
$script:Failed = 0
$script:InstallExitCode = 0; $script:MsiUsed = ''; $script:MsiLog = ''
$global:Owners = @{}
$global:Account = 'LocalSystem'
function Save-Evidence { param($Status, $InstallExitCode, $MsiUsed, $MsiLog) Write-Host "evidence: $Status" }
function Invoke-Native { param([scriptblock]$Block) & $Block }
function Invoke-ScStub { 'STATE              : 1  STOPPED' }
function Invoke-IcaclsStub {
    if ($args[1] -eq '/setowner') { $global:Owners[[string]$args[0]] = ([string]$args[2]).TrimStart('*') }
}
function Get-Owner {
    param([string]$Path)
    if ($global:Owners.ContainsKey($Path)) { return $global:Owners[$Path] }
    'S-1-5-32-544'
}
function Get-Acl {
    param([string]$LiteralPath)
    $acl = [pscustomobject]@{ Path = $LiteralPath }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value {
        param($t) [pscustomobject]@{ Value = (Get-Owner $this.Path) }
    }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
        param($e, $i, $t)
        if ($global:Account -match 'NetworkService') {
            [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = 'S-1-5-20' } }
        }
    }
    $acl
}
function Remove-Item {
    param([string]$LiteralPath, [switch]$Recurse, [switch]$Force, $ErrorAction)
    foreach ($key in @($global:Owners.Keys)) {
        if ($key -eq $LiteralPath -or $key.StartsWith($LiteralPath + '/')) { $global:Owners.Remove($key) }
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse:$Recurse -Force:$Force
}
function Get-CimInstance {
    param([Parameter(Position = 0)]$ClassName, $Filter)
    [pscustomobject]@{ StartName = $global:Account }
}
function Start-Process {
    param($FilePath, [string]$ArgumentList, [switch]$Wait, [switch]$PassThru)
    $log = [regex]::Match($ArgumentList, '/l\*v "([^"]+)"').Groups[1].Value
    $exit = 0; $text = "=== Verbose logging started`n"
    $config = Join-Path $ProgramDataDir 'config.yaml'
    $launch = @{
        'UDBMCP_SERVICE_ACCOUNT="x"' = 'account-quote'
        'UDBMCP_SERVICE_ACCOUNT=CORP\ ' = 'account-backslash'
        'UDBMCP_ALLOW_DOWNGRADE=yes' = 'downgrade-value'
    }
    $refused = $null
    foreach ($key in $launch.Keys) {
        $given = ($ArgumentList + ' ').Contains($key)
        if ($given -and $env:H_LAUNCH_ACCEPT -ne $launch[$key]) { $refused = $launch[$key] }
    }
    if ($refused -eq 'downgrade-value') {
        $exit = 1603; $text += "UDBMCP_ALLOW_DOWNGRADE may only be 1`n"
    } elseif ($refused) {
        $exit = 1603; $text += "UDBMCP_SERVICE_ACCOUNT may not contain a double quote or end with a backslash.`n"
    } elseif ((Get-Owner $ProgramDataDir) -eq 'S-1-5-32-545' -and $env:H_ADOPT -ne 'folder') {
        $exit = 1603
        $text += "Action start: CheckFoldersCA.`nCustomAction CheckFoldersCA returned actual error code 1`n"
    } elseif ((Test-Path -LiteralPath $config) -and (Get-Owner $config) -eq 'S-1-5-32-545' -and
              $env:H_ADOPT -ne 'config') {
        $exit = 1603
        $text += "Action start: CheckFoldersCA.`nCustomAction DoctorSmokeCA returned actual error code 1`n"
    } else {
        $text += "Action start: CheckFoldersCA.`nAction start: VerifyBundleCA.`n"
        $m = [regex]::Match($ArgumentList, 'UDBMCP_SERVICE_ACCOUNT=("[^"]*"|\S+)')
        if ($m.Success) { $global:Account = $m.Groups[1].Value.Trim('"') }
    }
    Add-Content -LiteralPath $env:H_MSI_RUNS -Value $ArgumentList
    Microsoft.PowerShell.Management\Set-Content -LiteralPath $log -Value $text
    if ($PassThru) { [pscustomobject]@{ ExitCode = $exit } }
}
"""


def _gate_functions(code: str) -> str:
    names = ("Add-Check", "Stop-Gate", "Stop-Check", "Add-CheckFailure")
    found = [re.search(rf"(?ms)^function {n} \{{\n.*?^\}}\n", code) for n in names]
    return "\n".join(m.group(0) for m in found if m)


class _Gate:
    def __init__(self, root: Path, code: str | None = None) -> None:
        self.root = root
        self.code = code if code is not None else GATE_PS1.read_text(encoding="ascii")
        self.program_data = root / "ProgramData" / "UniversalDB MCP"
        self.program_data.mkdir(parents=True)
        (self.program_data / "config.yaml").write_text("admin: config\n", encoding="utf-8")
        self.bundle = root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "config-templates").mkdir()
        (self.bundle / "config-templates" / "config.template.yaml").write_text("template\n", encoding="utf-8")
        self.logs = root / "logs"
        self.logs.mkdir()
        self.runs = root / "msi-runs.txt"

    def run(self, **env: str) -> tuple[int, str, list[dict[str, str]], list[str]]:
        prelude = (
            f"$ProgramDataDir = '{self.program_data}'\n$TokenFile = Join-Path $ProgramDataDir 'http-token'\n"
            f"$BundleDir = '{self.bundle}'\n$LogDir = '{self.logs}'\n$MsiPath = '{self.root}/x.msi'\n"
            "$ServiceName = 'udbmcp'\n$SkipMsiInstall = $false\n$installedService = $null\n"
            "$scExe = 'Invoke-ScStub'\n$IcaclsExe = 'Invoke-IcaclsStub'\n"
        )
        script = self.root / "gate.ps1"
        results = self.root / "checks.json"
        script.write_text(
            _GATE_STUBS
            + _gate_functions(self.code)
            + prelude
            + "try {\n"
            + _region(self.code)
            + "} finally {\n"
            + "    $json = ConvertTo-Json -InputObject ([object[]]$script:Checks.ToArray()) -Depth 4\n"
            + f"    Set-Content -LiteralPath '{results}' -Value $json\n"
            + "}\nexit $script:Failed\n",
            encoding="utf-8",
        )
        self.runs.write_text("", encoding="utf-8")
        proc = subprocess.run(  # noqa: S603 - fixed argv, the gate code under test
            [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(script)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(self.root),
                "SystemRoot": str(self.root / "Windows"),
                "H_MSI_RUNS": str(self.runs),
                **env,
            },
        )
        checks = json.loads(results.read_text(encoding="utf-8")) if results.exists() else []
        return proc.returncode, proc.stdout + proc.stderr, checks, self.runs.read_text(encoding="utf-8").splitlines()

    def admin_folder_is_back(self) -> bool:
        backup = self.program_data.with_name(self.program_data.name + ".gate-backup")
        config = self.program_data / "config.yaml"
        return not backup.exists() and config.read_text(encoding="utf-8") == "admin: config\n"


def _status(checks: list[dict[str, str]]) -> dict[str, str]:
    return {c["name"]: c["status"] for c in checks}


@executed
def test_exec_v4i_checks_9_to_11_pass_against_an_msi_that_refuses_at_checkfoldersca(tmp_path: Path) -> None:
    # The reviewer's scenario: the real MSI refuses the planted folder at
    # CheckFoldersCA. Check 9 stopped the gate there on every run.
    gate = _Gate(tmp_path)
    code, out, checks, runs = gate.run()
    assert code == 0, out
    assert _status(checks) == dict.fromkeys(ALL_CHECKS, "passed"), checks
    assert gate.admin_folder_is_back()
    assert len(runs) == 1 + 1 + 1 + 3 + 1 + 3, runs  # 2 squats, restore, 3 launch, admin, 3 account repairs
    assert "REINSTALL=ALL REINSTALLMODE=omus UDBMCP_SERVICE_ACCOUNT=LocalSystem" in runs[-1]


@executed
@pytest.mark.parametrize("adopt", ["folder", "config"])
def test_exec_v4i_a_failed_squat_case_is_recorded_and_the_gate_goes_on(tmp_path: Path, adopt: str) -> None:
    gate = _Gate(tmp_path)
    code, out, checks, runs = gate.run(H_ADOPT=adopt)
    assert code == 1, out
    status = _status(checks)
    assert status == {**dict.fromkeys(ALL_CHECKS, "passed"), "folder_squat_refused": "failed"}, checks
    (detail,) = [c["detail"] for c in checks if c["name"] == "folder_squat_refused"]
    assert detail.startswith(f"{adopt}: msiexec exited 0 with the {adopt} owned by BUILTIN\\Users"), detail
    other = "config" if adopt == "folder" else "folder"
    assert f"{other}:" not in detail, "the other case still ran, and passed"
    assert sum("REINSTALL=ALL REINSTALLMODE=omus /qn" in r for r in runs) == 3, runs  # both squats and the restore
    assert gate.admin_folder_is_back()


@executed
def test_exec_v4i_a_failed_launch_case_is_recorded_and_check_11_runs(tmp_path: Path) -> None:
    gate = _Gate(tmp_path)
    code, out, checks, runs = gate.run(H_LAUNCH_ACCEPT="account-backslash")
    assert code == 1, out
    assert _status(checks) == {**dict.fromkeys(ALL_CHECKS, "passed"), "launch_conditions": "failed"}, checks
    (detail,) = [c["detail"] for c in checks if c["name"] == "launch_conditions"]
    assert detail.startswith("account-backslash: msiexec exited 0 with UDBMCP_SERVICE_ACCOUNT=CORP\\"), detail
    assert len(runs) == 10, runs


@executed
def test_exec_v4i_a_leftover_backup_stops_the_gate(tmp_path: Path) -> None:
    # cr3 D-5: a leftover backup holds the admin's folder, so checks 10 and
    # 11 must not run repairs while it sits aside: the gate stops first.
    gate = _Gate(tmp_path)
    backup = gate.program_data.with_name(gate.program_data.name + ".gate-backup")
    backup.mkdir()
    code, out, checks, runs = gate.run()
    assert code == 1, out
    assert _status(checks) == {"folder_squat_refused": "failed"}, checks
    assert (gate.program_data / "config.yaml").read_text(encoding="utf-8") == "admin: config\n"
    assert runs == [], "no repair ran"
