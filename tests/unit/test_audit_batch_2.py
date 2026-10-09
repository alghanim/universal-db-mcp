"""Audit batch 2 (2026-09-16): one regression test per confirmed finding.

 1. server: an explicit empty list (``connections=[]``, ``object_kinds=[]``)
    silently meant "everything" (``x or default``); it is now a VALIDATION_ERROR
    and ``None`` keeps meaning "default".
 2. server: ``db_validate_query(operation=...)`` accepted any string and treated
    everything but "explain" as a SELECT; it is a ``Literal`` so the JSON schema
    advertises an enum and the SDK rejects other values.
 3. server: ``getpass.getuser()`` RAISES for an unmapped UID (containers); the
    CLI reported that as CONFIG_ERROR blaming the config.
 4. server: every tool result was transmitted twice, the text half
    pretty-printed (indent=2, ~1.7x the compact size) - the block the model reads.
 5. agents/doctor: the "system" config/token paths were POSIX-only, so on
    Windows every CLI path fell through to the per-user config and doctor
    validated a token file nothing runs.
 6. wizard: ``os.O_NOFOLLOW`` does not exist on Windows (raw AttributeError).
 7. configure-agents: ``*_env`` credentials must live in the HARNESS process
    environment, which GUI harnesses do not inherit from a shell; warn.
 8. upgrade_offline.sh: per-command ``$(date)`` backup names; doctor runs
    without ``$sudo_ok`` while the config is 0640.
 9. deb postrm: ``dpkg -P`` left the postinst-installed unit behind.
10. systemd unit: ``ProtectSystem=strict`` + ``ReadWritePaths=`` of directories
    that may not exist -> 226/NAMESPACE on the manual unit install.
11. launchd: the daemon's logs under /var/log/universal-db-mcp were never rotated. The newsyslog
    rule added for it ran as root over the service account's directory, and launchd opens them as
    root too (re-attack round 3, test_hardening_2026_09_29_root_jobs): they are in a directory only
    root can write now, and the daemon caps them itself.
"""

from __future__ import annotations

import asyncio
import json
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

from universal_db_mcp.__main__ import main
from universal_db_mcp.agents import core as agents_core
from universal_db_mcp.config import load_resolved
from universal_db_mcp.diagnostics import doctor as doctor_module
from universal_db_mcp.server import AppContext, _process_identity, build_server

ROOT = Path(__file__).resolve().parents[2]
UPGRADER = ROOT / "scripts" / "upgrade_offline.sh"
POSTRM = ROOT / "packaging" / "deb" / "postrm"
UNIT = ROOT / "packaging" / "systemd" / "universal-db-mcp.service"
PLIST = ROOT / "packaging" / "launchd" / "com.udbmcp.server.plist"
NEWSYSLOG = ROOT / "packaging" / "launchd" / "udbmcp.newsyslog.conf"
PKG_POSTINSTALL = ROOT / "packaging" / "pkg" / "postinstall"
BUILD_PKG = ROOT / "scripts" / "package" / "build_pkg.sh"
WXS = ROOT / "packaging" / "msi" / "udbmcp.wxs"
SERVICE_PS1 = ROOT / "packaging" / "msi" / "custom" / "service.ps1"

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_lines(text: str) -> str:
    """Executable lines only (full-line comments stripped)."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, syntax check only
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


# ----------------------------------------------------------------- server


@pytest.fixture
def app_and_server(tmp_path: Path) -> tuple[Any, Any]:
    db = tmp_path / "demo.db"
    db.touch()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  demo:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    cfg, resolved = load_resolved(cfg_path)
    app = AppContext(cfg, resolved)
    return app, build_server(app)


def _call(server: Any, name: str, args: dict[str, Any]) -> Any:
    return asyncio.run(server.call_tool(name, args))


def _call_error(server: Any, name: str, args: dict[str, Any]) -> str:
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError) as info:
        _call(server, name, args)
    return str(info.value)


# 1 -------------------------------------------------------------------------


def test_empty_connections_list_is_a_validation_error_not_everything(app_and_server: tuple[Any, Any]) -> None:
    _app, server = app_and_server
    msg = _call_error(server, "db_search_metadata", {"query": "demo", "connections": []})
    assert "VALIDATION_ERROR" in msg and "connections must be omitted or non-empty" in msg
    # None (omitted) still means the default: every authorized connection
    result = _call(server, "db_search_metadata", {"query": "demo"})
    assert "matches" in result.structured_content["data"]


def test_empty_object_kinds_list_is_a_validation_error_not_everything(app_and_server: tuple[Any, Any]) -> None:
    _app, server = app_and_server
    msg = _call_error(server, "db_list_tables", {"connection_id": "demo", "object_kinds": []})
    assert "VALIDATION_ERROR" in msg and "object_kinds must be omitted or non-empty" in msg
    # omitted -> default kinds; an explicit non-empty list still works
    assert "tables" in _call(server, "db_list_tables", {"connection_id": "demo"}).structured_content["data"]
    explicit = _call(server, "db_list_tables", {"connection_id": "demo", "object_kinds": ["view"]})
    assert explicit.structured_content["data"]["tables"] == []


# 2 -------------------------------------------------------------------------


def test_validate_query_operation_is_an_advertised_enum(app_and_server: tuple[Any, Any]) -> None:
    _app, server = app_and_server
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    operation = tools["db_validate_query"].input_schema["properties"]["operation"]
    assert operation["enum"] == ["query", "explain"], operation
    assert operation["default"] == "query"
    # the SDK rejects anything else before the handler runs
    msg = _call_error(server, "db_validate_query", {"connection_id": "demo", "sql": "SELECT 1", "operation": "delete"})
    assert "operation" in msg
    assert _call(server, "db_validate_query", {"connection_id": "demo", "sql": "SELECT 1"}).structured_content["data"][
        "valid"
    ]


# 3 -------------------------------------------------------------------------


# The identity no longer comes from getpass.getuser(), which reads USER/LOGNAME
# first (2026-09-27 F72): these tests used to make getuser() raise, and now
# take the passwd entry of the effective UID away instead.


def _unmapped(uid: int) -> Any:
    raise KeyError(f"getpwuid(): uid not found: {uid}")


@_POSIX
def test_identity_falls_back_to_uid_without_a_passwd_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", _unmapped)
    assert _process_identity() == f"uid:{os.geteuid()}"


def test_identity_is_unknown_without_an_os_account(monkeypatch: pytest.MonkeyPatch) -> None:
    import universal_db_mcp.server as server_module

    def no_token() -> str:
        raise OSError("no process token")

    monkeypatch.delattr(os, "geteuid", raising=False)  # the Windows shape
    monkeypatch.setattr(server_module, "_windows_account", no_token)
    assert _process_identity() == "unknown"


@_POSIX
def test_app_context_builds_with_an_unmapped_uid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI reported a UID without a passwd entry as CONFIG_ERROR: the
    AppContext must construct and audit under the numeric identity instead."""
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", _unmapped)
    db = tmp_path / "demo.db"
    db.touch()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        f"application:\n  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  demo:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    cfg, resolved = load_resolved(cfg_path)
    app = AppContext(cfg, resolved)
    assert app.identity == f"uid:{os.geteuid()}"


# 4 -------------------------------------------------------------------------


def test_tool_results_carry_one_compact_text_block(app_and_server: tuple[Any, Any]) -> None:
    from mcp.types import CallToolResult, TextContent

    _app, server = app_and_server
    result = _call(server, "db_list_connections", {})
    assert isinstance(result, CallToolResult) and not result.is_error
    assert len(result.content) == 1, "exactly one content block (no pretty-printed duplicate)"
    block = result.content[0]
    assert isinstance(block, TextContent)
    assert "\n  " not in block.text, "the text block must be compact, not indent=2"
    assert ": " not in block.text.split('"connections"')[0], "compact separators"
    assert isinstance(result.structured_content, dict)
    assert json.loads(block.text) == result.structured_content
    assert result.structured_content["data"]["connections"][0]["connection_id"] == "demo"


def test_wrapped_tools_keep_schema_annotations_and_argument_validation(app_and_server: tuple[Any, Any]) -> None:
    """functools.wraps must leave the SDK reading the ORIGINAL signature."""
    _app, server = app_and_server
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    lt = tools["db_list_tables"]
    assert set(lt.input_schema["properties"]) == {"connection_id", "schema", "search", "object_kinds", "cursor"}
    assert lt.input_schema["required"] == ["connection_id"]
    assert lt.output_schema is not None, "structured_output=True must still publish an output schema"
    assert lt.annotations is not None and lt.annotations.read_only_hint is True
    # unknown arguments and missing required ones are still rejected by the SDK
    assert "connection_id" in _call_error(server, "db_list_tables", {})
    # a deliberate failure inside the handler still surfaces as ToolError
    assert "not available" in _call_error(server, "db_list_tables", {"connection_id": "nope"})


# 5 -------------------------------------------------------------------------


def test_system_paths_follow_the_msi_layout_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", r"D:\ProgramData")
    # PureWindowsPath: on a POSIX test host a backslash is not a separator
    cfg = PureWindowsPath(str(agents_core.system_config_path()))
    token = PureWindowsPath(str(doctor_module.service_token_path()))
    assert cfg.parts == ("D:\\", "ProgramData", "UniversalDB MCP", "config.yaml"), cfg
    assert token.parts == ("D:\\", "ProgramData", "UniversalDB MCP", "http-token"), token
    # the directory and file names come from the MSI authoring, not from here
    wxs = _read(WXS)
    assert '<Directory Id="ProgramDataUdbmcpDir" Name="UniversalDB MCP">' in wxs
    assert 'Name="config.yaml"' in wxs
    assert "Join-Path $configDir 'http-token'" in _read(SERVICE_PS1)


def test_system_paths_default_to_programdata_root_when_env_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("ProgramData", raising=False)
    cfg = PureWindowsPath(str(agents_core.system_config_path()))
    assert cfg.parts == ("C:\\", "ProgramData", "UniversalDB MCP", "config.yaml"), cfg


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_system_paths_stay_posix_elsewhere(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    assert agents_core.system_config_path() == Path("/etc/universal-db-mcp/config.yaml")
    assert doctor_module.service_token_path() == Path("/etc/universal-db-mcp/http-token")


def test_module_constants_are_the_platform_aware_values() -> None:
    assert agents_core.SYSTEM_CONFIG_PATH == agents_core.system_config_path()
    assert doctor_module.SERVICE_TOKEN_PATH == doctor_module.service_token_path()


# 6 -------------------------------------------------------------------------


def test_write_secret_works_without_o_nofollow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from universal_db_mcp.wizard import _write_secret

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)  # the Windows shape
    target = tmp_path / "demo.password"
    _write_secret(target, "hunter2")
    assert target.read_text(encoding="utf-8") == "hunter2\n"
    if sys.platform != "win32":
        assert (target.stat().st_mode & 0o777) == 0o600


@_POSIX
def test_write_secret_still_refuses_a_planted_symlink(tmp_path: Path) -> None:
    from universal_db_mcp.wizard import _write_secret

    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    link = tmp_path / "demo.password"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        _write_secret(link, "hunter2")
    assert victim.read_text(encoding="utf-8") == "untouched\n"


# 7 -------------------------------------------------------------------------


def _fake_home_with_claude_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # a Linux host's own would win over HOME
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("UDBMCP_CONFIG", raising=False)
    monkeypatch.setattr(agents_core, "SYSTEM_CONFIG_PATH", tmp_path / "no-such-etc" / "config.yaml")
    return home


def _write_per_user_config(home: Path, connections: str) -> Path:
    cfg_dir = home / ".universal-db-mcp"
    cfg_dir.mkdir()
    cfg = cfg_dir / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  metadata_cache_path: {cfg_dir / 'metadata.sqlite'}\n"
        f"  audit_path: {cfg_dir / 'audit.jsonl'}\n"
        f"connections:\n{connections}",
        encoding="utf-8",
    )
    return cfg


_ENV_CONNECTION = (
    "  reporting:\n    type: postgres\n    host: db.internal\n    database: reports\n"
    "    username_env: REPORTING_USER\n    password_env: REPORTING_PASSWORD\n"
)


def test_configure_agents_warns_about_env_sourced_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _fake_home_with_claude_code(tmp_path, monkeypatch)
    cfg = _write_per_user_config(home, _ENV_CONNECTION)
    monkeypatch.setenv("REPORTING_PASSWORD", "SENTINEL-NEVER-PRINTED")
    monkeypatch.setenv("REPORTING_USER", "SENTINEL-USER-NEVER-PRINTED")

    rc = main(["configure-agents", "--agent", "claude-code", "--yes"])
    out, err = capsys.readouterr()

    assert rc == 0, out + err
    assert "universal-db" in json.loads((home / ".claude.json").read_text(encoding="utf-8"))["mcpServers"]
    assert "WARNING" in err
    assert "'reporting'" in err and str(cfg) in err
    assert "REPORTING_USER" in err and "REPORTING_PASSWORD" in err
    assert "username_file/password_file" in err
    assert "GUI harness" in err
    assert "SENTINEL" not in out + err, "the variables' VALUES are never read or printed"


def test_configure_agents_json_apply_warns_on_stderr_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _fake_home_with_claude_code(tmp_path, monkeypatch)
    _write_per_user_config(home, _ENV_CONNECTION)

    rc = main(["configure-agents", "--json", "--agent", "claude-code", "--yes"])
    out, err = capsys.readouterr()

    assert rc == 0
    data = json.loads(out)  # stdout stays pure JSON for the GUI
    assert data["applied"][0]["status"] == "configured"
    assert "WARNING" in err and "REPORTING_PASSWORD" in err


def test_configure_agents_stays_quiet_for_file_backed_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _fake_home_with_claude_code(tmp_path, monkeypatch)
    db = tmp_path / "demo.db"
    db.touch()
    _write_per_user_config(home, f"  demo:\n    type: sqlite\n    database: {db}\n")

    rc = main(["configure-agents", "--agent", "claude-code", "--yes"])
    out, err = capsys.readouterr()

    assert rc == 0, out + err
    assert "WARNING" not in err


# 8 -------------------------------------------------------------------------


def test_upgrade_backup_directory_uses_one_timestamp() -> None:
    text = _read(UPGRADER)
    code = _code_lines(text)
    assert 'BACKUP_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"' in code
    assert 'BACKUP_DIR="$BACKUP/pre-upgrade-$BACKUP_STAMP"' in code
    assert 'mkdir -p "$BACKUP_DIR"' in code
    assert "pre-upgrade-$(date" not in code, "per-command $(date) can name a directory mkdir never created"
    assert code.count("$BACKUP_DIR/") == 2, "both cp targets must use the single computed directory"
    _bash_n(UPGRADER)


def test_upgrade_doctor_runs_go_through_sudo_ok() -> None:
    code = _code_lines(_read(UPGRADER))
    doctor_lines = [ln for ln in code.splitlines() if "-m universal_db_mcp doctor" in ln]
    assert len(doctor_lines) == 2, doctor_lines
    for line in doctor_lines:
        assert "$sudo_ok" in line, f"doctor must run privileged like every step around it: {line.strip()!r}"
    # pre-switch: the env assignment must survive the sudo prefix (`env`)
    assert (
        '$sudo_ok env UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml "$NEWVENV/bin/python" -m universal_db_mcp doctor'
        in code
    )
    # post-switch
    assert 'if ! $sudo_ok "$TARGET/venv/bin/python" -m universal_db_mcp doctor' in code


# 9 -------------------------------------------------------------------------


def test_postrm_purge_removes_the_postinst_installed_unit() -> None:
    code = _code_lines(_read(POSTRM))
    assert 'UNIT_FILE="/etc/systemd/system/universal-db-mcp.service"' in code
    assert 'UNIT_DROPIN_DIR="/etc/systemd/system/universal-db-mcp.service.d"' in code
    assert 'SHIPPED_UNIT_RECORD="/var/lib/universal-db-mcp/.shipped-unit.sha256"' in code
    purge = code.split("purge)", 1)[1].split("remove)", 1)[0]
    assert 'rm -f "$UNIT_FILE"' in purge
    assert 'rm -rf "$UNIT_DROPIN_DIR"' in purge
    assert 'rm -f "$SHIPPED_UNIT_RECORD"' in purge
    assert "systemctl daemon-reload" in purge
    # guarded for containers (no systemd as PID 1), like prerm
    assert "command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]" in code
    # the audit/state directory itself is never removed
    assert 'rm -rf "/var/lib' not in code and "rm -rf /var/lib" not in code
    _bash_n(POSTRM)


def _sandbox_postrm(tmp_path: Path) -> Path:
    text = _read(POSTRM)
    for real, sandbox in (
        ("/opt/universal-db-mcp", tmp_path / "opt" / "universal-db-mcp"),
        ("/usr/share/universal-db-mcp", tmp_path / "usr" / "share" / "universal-db-mcp"),
        ("/etc/universal-db-mcp", tmp_path / "etc" / "universal-db-mcp"),
        ("/etc/systemd/system", tmp_path / "etc" / "systemd" / "system"),
        ("/var/lib/universal-db-mcp", tmp_path / "var" / "lib" / "universal-db-mcp"),
    ):
        text = text.replace(real, str(sandbox))
    script = tmp_path / "postrm.sh"
    script.write_text(text, encoding="utf-8")
    return script


def _plant_unit_artifacts(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    systemd = tmp_path / "etc" / "systemd" / "system"
    dropin_dir = systemd / "universal-db-mcp.service.d"
    dropin_dir.mkdir(parents=True)
    unit = systemd / "universal-db-mcp.service"
    unit.write_text("[Service]\nExecStart=/opt/universal-db-mcp/venv/bin/python\n", encoding="utf-8")
    (dropin_dir / "deferred-install-guard.conf").write_text("[Service]\nExecStartPre=/bin/true\n", encoding="utf-8")
    state = tmp_path / "var" / "lib" / "universal-db-mcp"
    state.mkdir(parents=True)
    record = state / ".shipped-unit.sha256"
    record.write_text("deadbeef\n", encoding="utf-8")
    audit = state / "audit.jsonl"
    audit.write_text('{"event":"tool_call"}\n', encoding="utf-8")
    return unit, dropin_dir, record, audit


@_POSIX
def test_postrm_purge_functionally_removes_unit_dropin_and_record(tmp_path: Path) -> None:
    unit, dropin_dir, record, audit = _plant_unit_artifacts(tmp_path)
    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(_sandbox_postrm(tmp_path)), "purge"], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert not unit.exists() and not dropin_dir.exists() and not record.exists()
    assert audit.read_text(encoding="utf-8") == '{"event":"tool_call"}\n', "the audit trail outlives the package"
    assert audit.parent.is_dir()


@_POSIX
def test_postrm_remove_retains_unit_dropin_and_record(tmp_path: Path) -> None:
    unit, dropin_dir, record, _audit = _plant_unit_artifacts(tmp_path)
    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(_sandbox_postrm(tmp_path)), "remove"], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert unit.exists() and dropin_dir.exists() and record.exists()


# 10 ------------------------------------------------------------------------


def _service_section(text: str) -> dict[str, list[str]]:
    section = None
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]" and "=" in line:
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


def test_systemd_unit_lets_systemd_create_its_writable_directories() -> None:
    service = _service_section(_read(UNIT))
    assert service["ProtectSystem"] == ["strict"]
    assert service["StateDirectory"] == ["universal-db-mcp"]
    assert service["LogsDirectory"] == ["universal-db-mcp"]
    assert service["ReadWritePaths"] == ["/var/lib/universal-db-mcp /var/log/universal-db-mcp"]
    # the directives name the same directories ReadWritePaths= opens
    assert f"/var/lib/{service['StateDirectory'][0]}" in service["ReadWritePaths"][0]
    assert f"/var/log/{service['LogsDirectory'][0]}" in service["ReadWritePaths"][0]


# 11 ------------------------------------------------------------------------

_XML_COMMENT = re.compile(rb"<!--.*?-->", re.S)


def test_the_launchd_logs_are_where_only_root_can_write_and_no_root_job_rotates_them() -> None:
    assert not NEWSYSLOG.exists(), "newsyslog runs as root and follows the links _udbmcp puts in its directory"
    plist = plistlib.loads(_XML_COMMENT.sub(b"", PLIST.read_bytes()))
    for key in ("StandardOutPath", "StandardErrorPath"):
        path = plist[key]
        assert isinstance(path, str)
        # launchd opens them as root, following a link: never in the directory _udbmcp owns
        # (test_hardening_2026_09_29_root_jobs)
        assert path.startswith("/Library/Logs/universal-db-mcp/") and path.endswith(".log"), path


def test_pkg_postinstall_removes_the_newsyslog_rule_an_earlier_release_installed() -> None:
    text = _read(PKG_POSTINSTALL)
    code = _code_lines(text)
    assert 'NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"' in code
    assert "NEWSYSLOG_SRC" not in code
    # the step runs before the daemon starts and fails closed
    step = text.split('NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"', 1)[1].split("\n# --- step ", 1)[0]
    block = _code_lines(step)
    assert 'for stale in "$NEWSYSLOG_DST" "$PREFIX/share/udbmcp.newsyslog.conf"; do' in block
    assert 'rm -f -- "$stale" || fail ' in block
    assert "install -" not in block and "WARNING" not in block
    _bash_n(PKG_POSTINSTALL)


def test_build_pkg_stages_no_newsyslog_rule() -> None:
    assert "newsyslog" not in _code_lines(_read(BUILD_PKG))
    _bash_n(BUILD_PKG)
