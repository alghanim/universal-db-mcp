"""Third code review of the MSI (review of 9c457ec..0ad054b, MSI notes).

A8-2  venv.ps1 deleted the venv of a running service or MCP client in place
      before anything stopped it: Windows refuses to delete a file a process
      has open or mapped, so the delete failed part-way and no rollback put
      the venv back (it is not an MSI file). The service is now stopped, the
      venv moved aside whole (a move refuses a folder a process runs from,
      and the install fails with the venv untouched), and kept until the
      install commits; RollbackBuildVenvCA puts it back.
A8-1  An account-changing repair took the old account's token and access
      away (doctor.ps1, then service.ps1) before sc.exe config switched the
      service, so a failure in between left an unstartable service. The
      registered account now keeps its access until the switch; the new one
      is granted first, and a failure takes that back.
A8-3  Switching from a password account to a gMSA or virtual account left the
      old password stored with the service: it is cleared through
      LocalService.
B-6   The in-place update kept a service DACL, dependencies and SID type set
      since: the install now sets them (and type, error control and display
      name) on every run.
A8-4  A service marked for deletion that Windows removed once it stopped made
      sc.exe config fail with 1060 and the false "unchanged": it is created.
A8-5  An Administrators-member gMSA's logs\\ grant counted only with
      -GrantedSid: both lookups now read the registration's Modify alike.
D-5   A leftover .gate-backup let checks 10-11 run repairs while the admin's
      folder sat aside: the gate now stops first.

The executed tests run the real scripts under pwsh with the stubbed Windows
host of tests/unit/test_hardening_2026_09_27_msi.py.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

PROJECT = Path(__file__).resolve().parents[2]
CUSTOM = PROJECT / "packaging" / "msi" / "custom"
SERVICE_PS1 = CUSTOM / "service.ps1"
DOCTOR_PS1 = CUSTOM / "doctor.ps1"
VENV_PS1 = CUSTOM / "venv.ps1"
GATE_PS1 = PROJECT / "scripts" / "test_package_msi.ps1"


def _load(name: str, alias: str) -> ModuleType:
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(alias, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = _load("test_hardening_2026_09_27_msi.py", "_msi_hardening_harness_cr3")
CR2 = _load("test_cr2_msi.py", "_msi_cr2_cr3")
executed = H.executed

SID_SYSTEM, SID_ADMINS = H.SID_SYSTEM, H.SID_ADMINS
NS, NETWORK_SERVICE = H.SID_NETWORK_SERVICE, H.NETWORK_SERVICE
VIRTUAL = "NT SERVICE\\udbmcp"
VIRTUAL_SID = H._service_sid("udbmcp")
GMSA, GMSA_SID = "CONTOSO\\udbmcp$", "S-1-5-21-1111-2222-3333-1105"
DOMAIN_USER, DOMAIN_USER_SID = "CORP\\svc", "S-1-5-21-1111-2222-3333-1200"
ACCOUNTS = {"H_ACCOUNTS": f"{GMSA}={GMSA_SID};{DOMAIN_USER}={DOMAIN_USER_SID}"}
ORIGINAL = "ORIGINALTOKEN-the-clients-know-it"
SERVICE_SDDL = (
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
)


@pytest.fixture()
def host(tmp_path: Path):  # noqa: ANN201 - the harness's _Host
    return H._Host(tmp_path)


# A stateful sc.exe: every call is logged as "sc [arg] [arg] ...". The
# service exists while $H_SC_DIR/state holds its STATE line; stop leaves it
# STOPPED (or, with H_SC_GONE_AFTER_STOP, removes it: a service marked for
# deletion). H_SC_EXIT_<verb>=<n> makes every call of that verb exit n,
# H_SC_EXIT_<verb>_<k>=<n> only its k-th call. POSIX exit statuses are 8
# bits: 1060 is 36 and 1072 is 48 (the scripts under test run from copies
# with those constants mapped).
_SC = r"""#!/bin/sh
line="sc"
for a in "$@"; do line="$line [$a]"; done
echo "$line" >> "$H_CALLS"
verb="$1"
count="$H_SC_DIR/count_$verb"
n=$(( $(cat "$count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$count"
eval "code=\${H_SC_EXIT_${verb}_$n:-\${H_SC_EXIT_${verb}:-}}"
[ -n "$code" ] && exit "$code"
state="$H_SC_DIR/state"
case "$verb" in
  query) [ -f "$state" ] || exit 36; echo "        STATE              : $(cat "$state")" ;;
  stop) [ -f "$state" ] || exit 36
        if [ -n "$H_SC_GONE_AFTER_STOP" ]; then rm -f "$state"; else echo "1  STOPPED" > "$state"; fi ;;
  create) echo "1  STOPPED" > "$state" ;;
esac
exit 0
"""


def _sc_host(host, state: str | None = "4  RUNNING"):  # noqa: ANN001, ANN202
    H._executable(host.root / "win" / "System32" / "sc.exe", _SC)
    scdir = host.root / "scstate"
    scdir.mkdir(exist_ok=True)
    if state is not None:
        (scdir / "state").write_text(state + "\n", encoding="utf-8")
    text = host.service_ps1.read_text(encoding="utf-8")
    marked = "$script:ErrServiceMarkedForDelete = "
    assert marked + "1072" in text
    host.service_ps1.write_text(text.replace(marked + "1072", marked + "48"), encoding="utf-8")
    host.sc_env = {"H_SC_DIR": str(scdir)}
    return host


def _sc(calls: str, verb: str) -> list[str]:
    return [ln for ln in calls.splitlines() if ln.startswith(f"sc [{verb}]")]


def _index(calls: str, line: str) -> int:
    return calls.splitlines().index(line)


def _first(calls: str, prefix: str) -> int:
    return next(i for i, ln in enumerate(calls.splitlines()) if ln.startswith(prefix))


def _rules(host, path: Path) -> list[list[object]]:  # noqa: ANN001
    return [r for r in host.acl(path)["rules"] if not r[3]]


# ------------------------------------------------------------------ A8-1 --
#
# The service runs as NetworkService: the folder grants it RX, logs\ M, the
# token R. A repair names NT SERVICE\udbmcp.


def _networkservice(host) -> dict[Path, dict[str, object]]:  # noqa: ANN001
    logs = host.cfgdir / "logs"
    logs.mkdir()
    host.token.write_text(ORIGINAL, encoding="ascii")
    return {
        host.cfgdir: H._entry(SID_ADMINS, [NS, "Allow", "(OI)(CI)RX", False]),
        host.config: H.SAFE,
        logs: H._entry(SID_ADMINS, [NS, "Allow", "(OI)(CI)M", False]),
        host.token: {**H.TOKEN_ACL, "rules": [*H.TOKEN_ACL["rules"], [NS, "Allow", "R", False]]},
    }


def _switch(host, acl, **env: str) -> tuple[int, str, str]:  # noqa: ANN001
    """The repair: service.ps1 told NT SERVICE\\udbmcp, the service registered under NetworkService."""
    host = _sc_host(host)
    return host.service(acl, account=VIRTUAL, registered=NETWORK_SERVICE, **host.sc_env, **env)


@executed
def test_exec_a8_1_doctor_leaves_the_registered_accounts_token_and_logs(host) -> None:  # noqa: ANN001
    # DoctorSmokeCA ran first and deleted the token that granted
    # NetworkService and reset logs\: whatever failed after it, the service
    # still registered under NetworkService could not start.
    acl = _networkservice(host)
    code, out, calls = host.doctor(acl, account=VIRTUAL, registered=NETWORK_SERVICE)
    assert code == 0, out
    assert "removing it before doctor runs" not in out and "resetting its DACL" not in out, out
    assert host.token.read_text(encoding="ascii") == ORIGINAL
    assert [NS, "Allow", "R", False] in _rules(host, host.token)
    assert [NS, "Allow", "(OI)(CI)M", False] in _rules(host, host.cfgdir / "logs")
    assert f"Set-Acl {host.cfgdir / 'logs'}" not in calls


@executed
def test_exec_a8_1_doctor_still_resets_a_third_accounts_grant_but_keeps_the_registered_one(host) -> None:  # noqa: ANN001
    acl = _networkservice(host)
    logs = host.cfgdir / "logs"
    acl[logs] = H._entry(SID_ADMINS, [NS, "Allow", "(OI)(CI)M", False], ["S-1-5-19", "Allow", "(OI)(CI)M", False])
    code, out, calls = host.doctor(acl, account=VIRTUAL, registered=NETWORK_SERVICE)
    assert code == 0, out
    assert f"Set-Acl {logs} {H.PROTECTED_DIR_SDDL}(A;OICI;0x1301bf;;;{NS})" in calls, calls
    assert _rules(host, logs) == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)M", False]]


@executed
def test_exec_a8_1_doctor_never_adds_a_grant_for_an_unvouched_registered_account(host) -> None:  # noqa: ANN001
    # UDBMCPREGISTEREDACCOUNT is public: msiexec lets anybody set it when the
    # service key is absent. Only access the account already holds is kept.
    code, out, calls = host.doctor(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, account=VIRTUAL, registered=NETWORK_SERVICE
    )
    assert code == 0, out
    logs = host.cfgdir / "logs"
    assert f"Set-Acl {logs} {H.PROTECTED_DIR_SDDL}\n" in calls + "\n", calls
    assert NS not in str(host.acl(logs)["rules"])


@executed
def test_exec_a8_1_a_failed_switch_leaves_a_service_that_starts(host) -> None:  # noqa: ANN001
    # The reviewer's path (b): sc.exe config fails (e.g. 1057 for a mistyped
    # account). NetworkService keeps its token (same value) and its access;
    # what NT SERVICE\udbmcp was granted is taken back.
    acl = _networkservice(host)
    code, out, calls = _switch(host, acl, H_SC_EXIT_config="5")
    assert code == 1, out
    assert "sc.exe config udbmcp failed with exit code 5; the service keeps its binPath and account" in out, out
    assert "the service still runs as 'NT AUTHORITY\\NetworkService', which keeps its access" in out, out
    # it was granted first, and the earlier account never lost anything
    assert f"Set-Acl {host.cfgdir} {H.PROTECTED_DIR_SDDL}(A;OICI;0x1200a9;;;{NS})" in calls, calls
    assert f"Set-Acl {host.cfgdir / 'logs'} {H.PROTECTED_DIR_SDDL}(A;OICI;0x1301bf;;;{NS})" in calls, calls
    assert host.token.read_text(encoding="ascii") == ORIGINAL
    assert not (host.cfgdir / "http-token.previous").exists()
    assert _rules(host, host.token) == [*H.TOKEN_ACL["rules"], [NS, "Allow", "R", False]]
    assert _rules(host, host.cfgdir) == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)RX", False]]
    assert _rules(host, host.cfgdir / "logs") == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)M", False]]
    assert VIRTUAL_SID not in str(host.acl(host.cfgdir)) + str(host.acl(host.cfgdir / "logs")) + str(
        host.acl(host.token)
    )
    assert not _sc(calls, "delete") and not _sc(calls, "create"), calls


@executed
@pytest.mark.parametrize("fail", ["description", "failure", "reg", "sdset", "token"])
def test_exec_a8_1_any_failure_before_the_switch_gives_the_access_back(host, fail: str) -> None:  # noqa: ANN001
    acl = _networkservice(host)
    env = {"H_REG_FAIL": "1"} if fail == "reg" else {f"H_SC_EXIT_{fail}": "5"}
    if fail == "token":
        # the token generator fails (the new one is provisioned before the switch)
        H._executable(host.venv / "Scripts" / "python.exe", '#!/bin/sh\necho "python $*" >> "$H_CALLS"\nexit 3\n')
        env = {}
    code, out, calls = _switch(host, acl, **env)
    assert code == 1, out
    assert not _sc(calls, "config"), "the switch never ran"
    assert host.token.read_text(encoding="ascii") == ORIGINAL
    assert _rules(host, host.token) == [*H.TOKEN_ACL["rules"], [NS, "Allow", "R", False]]
    assert _rules(host, host.cfgdir) == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)RX", False]]
    assert _rules(host, host.cfgdir / "logs") == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)M", False]]


@executed
def test_exec_a8_1_the_switch_then_takes_the_earlier_accounts_access_away(host) -> None:  # noqa: ANN001
    acl = _networkservice(host)
    code, out, calls = _switch(host, acl)
    assert code == 0, out
    (config,) = _sc(calls, "config")
    revoke = _first(calls, f"icacls {host.cfgdir} | /remove:g | *{NS}")
    assert _index(calls, config) < revoke < _first(calls, f"icacls {host.cfgdir / 'logs'} | /remove:g | *{NS}")
    # the new account was granted before the switch
    assert _first(calls, f"icacls {host.cfgdir} | /grant:r | *{VIRTUAL_SID}:(OI)(CI)RX") < _index(calls, config)
    assert _rules(host, host.cfgdir) == [*H.SAFE["rules"], [VIRTUAL_SID, "Allow", "(OI)(CI)RX", False]]
    assert _rules(host, host.cfgdir / "logs") == [*H.SAFE["rules"], [VIRTUAL_SID, "Allow", "(OI)(CI)M", False]]
    # NetworkService knew the token: the service now has a new one it alone reads
    assert host.token.read_text(encoding="ascii") == H.GENERATED
    assert _rules(host, host.token) == [
        [SID_SYSTEM, "Allow", "F", False],
        [SID_ADMINS, "Allow", "F", False],
        [VIRTUAL_SID, "Allow", "R", False],
    ]
    assert not (host.cfgdir / "http-token.previous").exists()
    assert "no longer has access" in out


@executed
def test_exec_a8_1_a_failure_after_the_switch_says_the_service_runs_as_the_new_account(host) -> None:  # noqa: ANN001
    acl = _networkservice(host)
    bundle = host.root / "install" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"release_seq": 7}', encoding="utf-8")
    (bundle.parent / "manifest.json").symlink_to(host.root / "victim.json")
    code, out, calls = _sc_host(host).service(
        acl, account=VIRTUAL, registered=NETWORK_SERVICE, bundle=bundle, **host.sc_env
    )
    assert code == 1 and "reparse point" in out, out
    assert f"it runs as '{VIRTUAL}'" in out, out
    assert _rules(host, host.cfgdir) == [*H.SAFE["rules"], [VIRTUAL_SID, "Allow", "(OI)(CI)RX", False]]
    assert not _sc(calls, "delete"), calls


@executed
def test_exec_a8_1_a_same_account_repair_is_unchanged(host) -> None:  # noqa: ANN001
    acl = _networkservice(host)
    code, out, calls = _sc_host(host).service(acl, account=NETWORK_SERVICE, registered=NETWORK_SERVICE, **host.sc_env)
    assert code == 0, out
    assert "/remove:g" not in calls and "account changes" not in out
    assert host.token.read_text(encoding="ascii") == ORIGINAL, "a token only its account reads is kept"
    assert _rules(host, host.cfgdir) == [*H.SAFE["rules"], [NS, "Allow", "(OI)(CI)RX", False]]


def test_a8_1_both_actions_keep_the_registered_account_until_the_switch() -> None:
    service, doctor = H._code(SERVICE_PS1), H._code(DOCTOR_PS1)
    for name in ("Get-KeptAccessSddl", "Get-WriteProblem", "Get-ServiceAccountSid", "Get-EarlierAccountSid"):
        assert H._function(doctor, name) == H._function(service, name), name
    body = H._main_body(service)
    # no explicit grant is dropped before the switch: the protected DACL
    # keeps the registered account's ACE in the same Set-Acl
    for target, mask in (("$configDir", "ReadAccessMask"), ("$logsDir", "ModifyAccessMask")):
        set_acl = body.index(f"Set-Acl -LiteralPath {target} -AclObject $security")
        assert f"(Get-KeptAccessSddl -Sid $registeredSid -Mask $script:{mask}))" in body[set_acl - 200 : set_acl]
    switch = body.index("$r = Invoke-Tool -Tool $script:ScExe -Arguments ('config ' + $ServiceName + $configArgs)")
    assert body.index("/remove:g *' + $previousSid") > switch
    assert "/remove:g" not in H._main_body(doctor)


# ------------------------------------------------------------------ A8-3 --


def _password_account(host) -> dict[Path, dict[str, object]]:  # noqa: ANN001
    logs = host.cfgdir / "logs"
    logs.mkdir()
    return {
        host.cfgdir: H._entry(SID_ADMINS, [DOMAIN_USER_SID, "Allow", "(OI)(CI)RX", False]),
        host.config: H.SAFE,
        logs: H._entry(SID_ADMINS, [DOMAIN_USER_SID, "Allow", "(OI)(CI)M", False]),
    }


@executed
def test_exec_a8_3_switching_to_a_gmsa_clears_the_stored_password(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        _password_account(host), account=GMSA, registered=DOMAIN_USER, **host.sc_env, **ACCOUNTS
    )
    assert code == 0, out
    configs = _sc(calls, "config")
    assert len(configs) == 3, configs
    assert configs[0].endswith(f"[obj=] [{GMSA}]"), configs[0]
    assert configs[1] == "sc [config] [udbmcp] [obj=] [NT AUTHORITY\\LocalService] [password=] []", configs[1]
    assert configs[2] == f"sc [config] [udbmcp] [obj=] [{GMSA}]", configs[2]
    assert f"clearing the password stored for '{DOMAIN_USER}'" in out


@executed
@pytest.mark.parametrize(
    ("registered", "account"),
    [(NETWORK_SERVICE, GMSA), (DOMAIN_USER, NETWORK_SERVICE), (GMSA, VIRTUAL)],
)
def test_exec_a8_3_no_detour_when_no_password_is_left_behind(host, registered: str, account: str) -> None:  # noqa: ANN001
    acl = _password_account(host) if registered == DOMAIN_USER else {host.cfgdir: H.SAFE, host.config: H.SAFE}
    code, out, calls = _sc_host(host).service(acl, account=account, registered=registered, **host.sc_env, **ACCOUNTS)
    assert code == 0, out
    (config,) = _sc(calls, "config")
    assert "clearing the password" not in out


@executed
def test_exec_a8_3_a_failed_clear_is_reported_and_the_service_keeps_the_gmsa(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        _password_account(host), account=GMSA, registered=DOMAIN_USER, H_SC_EXIT_config_2="5", **host.sc_env, **ACCOUNTS
    )
    assert code == 0, out
    assert f"the password stored for '{DOMAIN_USER}' could not be cleared; the service runs as '{GMSA}'" in out, out
    assert len(_sc(calls, "config")) == 2


@executed
def test_exec_a8_3_a_failure_back_to_the_gmsa_says_where_the_service_is(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        _password_account(host), account=GMSA, registered=DOMAIN_USER, H_SC_EXIT_config_3="5", **host.sc_env, **ACCOUNTS
    )
    assert code == 1, out
    assert "the service is registered under NT AUTHORITY\\LocalService; rerun the install naming" in out, out
    assert not _sc(calls, "delete")


# ------------------------------------------------------------------- B-6 --


@executed
def test_exec_b6_an_update_resets_what_a_new_service_gets(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host, "1  STOPPED").service({host.cfgdir: H.SAFE, host.config: H.SAFE}, **host.sc_env)
    assert code == 0, out
    (config,) = _sc(calls, "config")
    python = host.venv / "Scripts" / "python.exe"
    assert config == (
        f'sc [config] [udbmcp] [binPath=] ["{python}" -I -m universal_db_mcp serve --transport http] [start=] [auto]'
        " [type=] [own] [error=] [normal] [depend=] [/] [DisplayName=] [udbmcp] [obj=] [LocalSystem] [password=] []"
    ), config
    (sdset,) = _sc(calls, "sdset")
    assert sdset == f"sc [sdset] [udbmcp] [{SERVICE_SDDL}]"
    assert _sc(calls, "sidtype") == ["sc [sidtype] [udbmcp] [unrestricted]"]
    # all of it before the switch, so a failure there leaves the account
    assert _index(calls, sdset) < _index(calls, config)


@executed
def test_exec_b6_a_new_service_gets_the_same_dacl_and_sid_type(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host, None).service({host.cfgdir: H.SAFE, host.config: H.SAFE}, **host.sc_env)
    assert code == 0, out
    assert _sc(calls, "create") and not _sc(calls, "config")
    assert _sc(calls, "sdset") == [f"sc [sdset] [udbmcp] [{SERVICE_SDDL}]"]
    assert _sc(calls, "sidtype") == ["sc [sidtype] [udbmcp] [unrestricted]"]


@executed
@pytest.mark.parametrize("verb", ["sdset", "sidtype"])
def test_exec_b6_a_failed_reset_fails_closed(host, verb: str) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host, None).service(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, **host.sc_env, **{f"H_SC_EXIT_{verb}": "5"}
    )
    assert code == 1 and f"sc.exe {verb} udbmcp failed with exit code 5" in out, out
    assert _sc(calls, "delete"), "a service this action created is removed"


# ------------------------------------------------------------------ A8-4 --


@executed
def test_exec_a8_4_a_service_windows_removes_once_stopped_is_created(host) -> None:  # noqa: ANN001
    # sc.exe delete ran while it was running: it is marked for deletion, and
    # gone as soon as it stops and its last handle closes.
    code, out, calls = _sc_host(host).service(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, H_SC_GONE_AFTER_STOP="1", **host.sc_env
    )
    assert code == 0, out
    assert "was marked for deletion and is gone now that it stopped: it is created" in out, out
    assert _sc(calls, "stop") and _sc(calls, "create") and not _sc(calls, "config"), calls
    assert "the service is unchanged" not in out


@executed
def test_exec_a8_4_a_service_gone_at_the_first_change_is_created(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, H_SC_EXIT_description_1="36", **host.sc_env
    )
    assert code == 0, out
    assert "is gone (it was marked for deletion): it is created" in out, out
    assert _sc(calls, "create") and not _sc(calls, "config")


@executed
def test_exec_a8_4_a_service_still_marked_names_the_remedy_and_changes_nothing(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, H_SC_EXIT_description="48", **host.sc_env
    )
    assert code == 1, out
    assert "is marked for deletion: Windows removes it once it has stopped and every handle to it is closed" in out
    assert "(the service was not changed)" in out
    for verb in ("failure", "sdset", "sidtype", "config", "create", "delete"):
        assert not _sc(calls, verb), (verb, calls)


@executed
def test_exec_a8_4_a_service_gone_during_the_update_is_reported_truthfully(host) -> None:  # noqa: ANN001
    code, out, calls = _sc_host(host).service(
        {host.cfgdir: H.SAFE, host.config: H.SAFE}, H_SC_EXIT_config="36", **host.sc_env
    )
    assert code == 1, out
    assert "disappeared while it was updated (it was marked for deletion); rerun the install, which creates it" in out
    assert "unchanged" not in out


# ------------------------------------------------------------------ A8-5 --


def _admin_member_logs(host, rights: str) -> dict[Path, dict[str, object]]:  # noqa: ANN001
    logs = host.cfgdir / "logs"
    logs.mkdir()
    return {host.cfgdir: H.SAFE, host.config: H.SAFE, logs: H._entry(SID_ADMINS, [GMSA_SID, "Allow", rights, False])}


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_a8_5_an_admin_member_gmsas_grant_stops_a_silent_fallback(host, script: str) -> None:  # noqa: ANN001
    # The service key is gone (an uninstall kept ProgramData), no account is
    # given: the gMSA in Administrators that logs\ grants Modify is the
    # earlier service account, as any other account is.
    acl = _admin_member_logs(host, "(OI)(CI)M")
    env = {"H_ADMIN_MEMBERS": GMSA_SID}
    if script == "doctor":
        code, out, calls = host.doctor(acl, **env)
    else:
        code, out, calls = host.service(acl, account="", **env)
    assert code == 1, out
    assert f"grants {GMSA_SID} write access: the service ran as that account" in out, out
    assert H._changed_nothing(calls), calls


@executed
def test_exec_a8_5_an_administrators_own_grant_is_still_no_service_account(host) -> None:  # noqa: ANN001
    # Full Control (what an administrator gives themselves) is not the
    # registration action's Modify.
    code, out, calls = host.service(_admin_member_logs(host, "F"), account="", H_ADMIN_MEMBERS=GMSA_SID)
    assert code == 0, out


@executed
@pytest.mark.parametrize("script", ["doctor", "service"])
def test_exec_a8_5_the_granted_lookup_reads_the_grant_alike(host, script: str) -> None:  # noqa: ANN001
    env = {"H_ADMIN_MEMBERS": GMSA_SID, **ACCOUNTS}
    acl = _admin_member_logs(host, "(OI)(CI)M")
    code, out, _ = CR2._run(host, script, acl, GMSA, **env)
    assert code == 0, out
    (host.cfgdir / "logs").rmdir()
    code, out, _ = CR2._run(host, script, _admin_member_logs(host, "F"), GMSA, **env)
    assert code == 1 and f"this install was told the service is registered under '{GMSA}'" in out, out


# ------------------------------------------------------------------- D-5 --


@executed
def test_exec_d5_a_leftover_backup_stops_the_gate_before_anything_changes(tmp_path: Path) -> None:
    gate = CR2._Gate(tmp_path)
    backup = gate.program_data.with_name(gate.program_data.name + ".gate-backup")
    backup.mkdir()
    (backup / "config.yaml").write_text("the admin's real config\n", encoding="utf-8")
    code, out, checks, runs = gate.run()
    assert code == 1, out
    assert [(c["name"], c["status"]) for c in checks] == [("folder_squat_refused", "failed")], checks
    assert "Restore it first" in checks[0]["detail"], checks
    assert runs == [], "no repair ran (checks 10 and 11 included)"
    assert (backup / "config.yaml").read_text(encoding="utf-8") == "the admin's real config\n"
    assert (gate.program_data / "config.yaml").read_text(encoding="utf-8") == "admin: config\n"


def test_d5_only_the_leftover_backup_and_an_unrestorable_folder_stop_the_gate() -> None:
    region = CR2._region_code()
    assert re.findall(r"Stop-Gate '(\w+)'", region) == ["folder_squat_refused", "folder_squat_cleanup_reinstalled"]
    leftover = region.index("if (Test-Path -LiteralPath $SquatBackup) {")
    assert region[leftover:].index("Stop-Gate 'folder_squat_refused'") < 200
    assert (
        leftover < region.index("& $scExe stop $ServiceName") < region.index("Rename-Item -LiteralPath $ProgramDataDir")
    )


# ------------------------------------------------------------------ A8-2 --


_MACHINE_PYTHON = r"""#!/bin/sh
echo "python $*" >> "$H_CALLS"
[ "$1" = -I ] || exit 97
shift
[ "$1" = -c ] && exit 0
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/Scripts" && cp "$H_VENV_PYTHON" "$3/Scripts/python.exe" && echo new > "$3/which.txt"
  exit 0
fi
exit 98
"""
_VENV_PYTHON = """#!/bin/sh
echo "venv-python $*" >> "$H_CALLS"
exit ${H_PIP_EXIT:-0}
"""


class _Venv:
    """venv.ps1 on the stubbed host: a bundle, a machine python, the old venv
    (which.txt says 'old'), and the stateful sc.exe."""

    def __init__(self, host) -> None:  # noqa: ANN001
        self.host = _sc_host(host)
        root = host.root
        self.install = root / "ProgramFiles" / "UniversalDB MCP"
        self.bundle = self.install / "bundle"
        (self.bundle / "wheelhouse").mkdir(parents=True)
        (self.bundle / "wheelhouse" / "a-1-py3-none-any.whl").write_text("w", encoding="utf-8")
        (self.bundle / "requirements").mkdir()
        (self.bundle / "requirements" / "runtime.lock").write_text("a==1\n", encoding="utf-8")
        (self.bundle / "manifest.json").write_text("{}", encoding="utf-8")
        self.venv = self.install / "venv"
        (self.venv / "Scripts").mkdir(parents=True)
        (self.venv / "which.txt").write_text("old\n", encoding="utf-8")
        self.python = root / "py" / "python.exe"
        H._executable(self.python, _MACHINE_PYTHON)
        self.venv_python = root / "py" / "venv-python"
        H._executable(self.venv_python, _VENV_PYTHON)
        self.script = root / "venv.ps1"
        text = VENV_PS1.read_text(encoding="utf-8")
        self.script.write_text(text.replace("$script:ErrServiceAbsent = 1060", "$script:ErrServiceAbsent = 36"))
        self.marker = self.install / "venv.moved"

    def run(self, *switches: str, **env: str) -> tuple[int, str, str]:
        params: dict[str, object] = {"VenvDir": str(self.venv)}
        if not switches:
            params.update(BundleDir=str(self.bundle), PythonExe=str(self.python))
        for switch in switches:
            params[switch] = True
        return self.host.run(self.script, params, None, H_VENV_PYTHON=str(self.venv_python), **self.host.sc_env, **env)

    def asides(self) -> list[Path]:
        return sorted(self.install.glob("venv.previous-*"))

    def which(self, path: Path | None = None) -> str:
        return ((path or self.venv) / "which.txt").read_text(encoding="utf-8").strip()


@pytest.fixture()
def venv(host) -> _Venv:  # noqa: ANN001
    return _Venv(host)


@executed
def test_exec_a8_2_a_repair_stops_the_service_and_moves_the_venv_aside(venv: _Venv) -> None:
    code, out, calls = venv.run()
    assert code == 0, out
    stop = _index(calls, "sc [stop] [udbmcp]")
    (move,) = [ln for ln in calls.splitlines() if ln.startswith("Move-Item ")]
    assert stop < _index(calls, move) < _first(calls, "python -I -m venv"), calls
    (aside,) = venv.asides()
    assert move == f"Move-Item {venv.venv} -> {aside}"
    assert re.fullmatch(r"venv\.previous-[0-9a-f]{32}", aside.name)
    assert venv.which(aside) == "old" and venv.which() == "new"
    assert venv.marker.read_text(encoding="ascii").split() == [aside.name, "built"]
    assert "removing stale venv" not in out


@executed
def test_exec_a8_2_a_venv_a_process_runs_from_is_left_untouched(venv: _Venv) -> None:
    code, out, calls = venv.run(H_BUSY=str(venv.venv))
    assert code == 1, out
    assert "could not move the previous venv" in out and "a process still runs from it" in out, out
    assert "the venv is unchanged" in out
    assert venv.which() == "old" and not venv.asides() and not venv.marker.exists()
    assert "python -I -m venv" not in calls


@executed
def test_exec_a8_2_a_stopped_or_absent_service_is_not_stopped_again(venv: _Venv) -> None:
    (venv.host.root / "scstate" / "state").unlink()
    code, out, calls = venv.run()
    assert code == 0, out
    assert "sc [stop]" not in calls


@executed
def test_exec_a8_2_a_service_that_will_not_stop_leaves_the_venv(venv: _Venv) -> None:
    code, out, calls = venv.run(H_SC_EXIT_stop="5")
    assert code == 1 and "sc.exe stop udbmcp failed with exit code 5; the venv is unchanged" in out, out
    assert venv.which() == "old" and not venv.asides()


@executed
def test_exec_a8_2_a_failed_build_puts_the_previous_venv_back(venv: _Venv) -> None:
    code, out, calls = venv.run(H_PIP_EXIT="1")
    assert code == 1, out
    assert "wheelhouse install failed" in out and "the previous venv is back" in out, out
    assert venv.which() == "old" and not venv.asides() and not venv.marker.exists()


@executed
def test_exec_a8_2_the_rollback_twin_puts_the_previous_venv_back(venv: _Venv) -> None:
    # A later action (DoctorSmokeCA, RegisterServiceCA) failed.
    assert venv.run()[0] == 0
    code, out, calls = venv.run("Rollback")
    assert code == 0, out
    assert venv.which() == "old" and not venv.asides() and not venv.marker.exists()
    # and a second rollback (nothing moved aside) changes nothing
    code, out, calls = venv.run("Rollback")
    assert code == 0 and "this install moved no venv aside" in out, out
    assert venv.which() == "old"


@executed
def test_exec_a8_2_the_commit_action_removes_the_previous_venv(venv: _Venv) -> None:
    assert venv.run()[0] == 0
    code, out, calls = venv.run("Commit")
    assert code == 0, out
    assert venv.which() == "new" and not venv.asides() and not venv.marker.exists()


@executed
def test_exec_a8_2_a_first_install_moves_nothing(venv: _Venv) -> None:
    import shutil

    shutil.rmtree(venv.venv)
    code, out, calls = venv.run()
    assert code == 0, out
    assert "Move-Item" not in calls and "sc [" not in calls and not venv.marker.exists()
    assert venv.run("Rollback")[0] == 0 and venv.which() == "new", "the twin leaves a venv it did not move alone"


@executed
@pytest.mark.parametrize("state", ["building", "built"])
def test_exec_a8_2_an_interrupted_install_is_settled_first(venv: _Venv, state: str) -> None:
    # A hard-killed install (or one with rollback disabled) left its marker.
    left = venv.install / ("venv.previous-" + "a" * 32)
    left.mkdir()
    (left / "which.txt").write_text("older\n", encoding="utf-8")
    (venv.venv / "which.txt").write_text("partial\n", encoding="utf-8")
    venv.marker.write_text(f"{left.name}\n{state}\n", encoding="ascii")
    code, out, calls = venv.run()
    assert code == 0, out
    (aside,) = venv.asides()
    # building: the venv in place was incomplete, so the one moved aside came
    # back and is now the previous venv; built: the one moved aside was stale
    assert venv.which(aside) == ("older" if state == "building" else "partial")
    assert venv.which() == "new"


@executed
def test_exec_a8_2_a_marker_naming_another_folder_is_refused(venv: _Venv) -> None:
    victim = venv.host.root / "elsewhere"
    victim.mkdir()
    venv.marker.write_text("../../elsewhere\nbuilding\n", encoding="ascii")
    code, out, calls = venv.run()
    assert code == 1 and "not a venv this action moved aside" in out, out
    assert victim.exists() and venv.which() == "old"
    code, out, calls = venv.run("Rollback")
    assert code == 0 and victim.exists() and venv.which() == "old", out


def test_a8_2_the_venv_is_never_deleted_in_place_before_the_service_stops() -> None:
    code = H._code(VENV_PS1)
    body = H._main_body(code)
    step4 = body[body.index('Write-Step "creating virtual environment at $VenvDir"') : body.index("$venvExit = ")]
    assert "Remove-Item" not in step4, "the old venv is moved aside, not deleted"
    assert step4.index("Stop-VenvService -Name $ServiceName") < step4.index("Move-Item -LiteralPath $VenvDir")
    root = H._wxs_root()
    cas = {el.get("Id"): el for el in root.iter() if H._local(el) == "CustomAction"}
    rows = {el.get("Action"): el for el in root.iter() if H._local(el) == "Custom"}
    assert (cas["RollbackBuildVenvCA"].get("Execute"), cas["RollbackBuildVenvCA"].get("Return")) == (
        "rollback",
        "check",
    )
    assert cas["RollbackBuildVenvCA"].get("ExeCommand", "").endswith('venv" -Rollback')
    assert cas["CommitBuildVenvCA"].get("ExeCommand", "").endswith('venv" -Commit')
    assert (cas["CommitBuildVenvCA"].get("Execute"), cas["CommitBuildVenvCA"].get("Return")) == ("commit", "ignore")
    assert rows["RollbackBuildVenvCA"].get("Before") == "BuildVenvCA"
    assert rows["CommitBuildVenvCA"].get("After") == "BuildVenvCA"
    for action in ("RollbackBuildVenvCA", "CommitBuildVenvCA"):
        assert cas[action].get("Impersonate") == "no" and rows[action].get("Condition") == "NOT REMOVE"
