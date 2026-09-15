"""Oracle: thick mode, legacy connect forms, and actionable verifier errors.

Live driver (2026-09-15, air-gapped site): a DBA account carrying ONLY the
legacy 10G password verifier is refused by python-oracledb Thin mode with
"DPY-3015: password verifier type 0x939 is not supported". Thin mode supports
11G and later verifiers only, so the client-side remedy is Thick mode with an
administrator-supplied Oracle Instant Client; the server-side remedy is a
password reset that regenerates an 11G/12C verifier. The build used to refuse
Thick mode outright, leaving such a site with no client-side path at all.

Thick mode is PROCESS-GLOBAL in python-oracledb: init_oracle_client() switches
every connection in the interpreter. A config that mixes thick and thin oracle
connections is therefore refused instead of silently making them all thick.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig, load_config
from universal_db_mcp.connectors import oracle as oracle_module
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.errors import ConfigError
from universal_db_mcp.security.policy import EffectivePolicy


class _FakeOracleDb:
    """Records how the connector drives python-oracledb."""

    def __init__(self, connect_error: Exception | None = None) -> None:
        self.init_calls: list[dict[str, Any]] = []
        self.connect_kwargs: list[dict[str, Any]] = []
        self._connect_error = connect_error

    def init_oracle_client(self, **kwargs: Any) -> None:
        self.init_calls.append(kwargs)

    def connect(self, **kwargs: Any) -> str:
        self.connect_kwargs.append(kwargs)
        if self._connect_error is not None:
            raise self._connect_error
        return "handle"


def _secret(tmp_path: Path, name: str, value: str) -> str:
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)
    return str(p)


def _connector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, options: dict[str, Any] | None = None,
    fake: _FakeOracleDb | None = None, database: str = "FREEPDB1",
) -> tuple[Any, _FakeOracleDb]:
    fake = fake or _FakeOracleDb()
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "oracledb", types.ModuleType("oracledb"))
    monkeypatch.setattr(oracle_module, "_THICK_STATE", oracle_module.ThickState(), raising=False)
    cfg = ConnectionConfig.model_validate(
        {
            "type": "oracle", "host": "db.example.internal", "port": 1521, "database": database,
            "username_file": _secret(tmp_path, "u", "app_ro"),
            "password_file": _secret(tmp_path, "p", "s3cret"),
            "options": options or {},
        }
    )
    resolved = ResolvedConnection("ora", cfg)
    conn = oracle_module.OracleConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    return conn, fake


def test_thick_mode_initializes_client_once_with_lib_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, fake = _connector(
        tmp_path, monkeypatch, options={"thick_mode": True, "lib_dir": "/opt/oracle/instantclient_23_5"}
    )
    conn._connect()
    conn._connect()

    assert fake.init_calls == [{"lib_dir": "/opt/oracle/instantclient_23_5"}], (
        "init_oracle_client is process-global: exactly one call, carrying the admin lib_dir"
    )
    assert len(fake.connect_kwargs) == 2


def test_thick_mode_without_lib_dir_uses_default_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, fake = _connector(tmp_path, monkeypatch, options={"thick_mode": True})
    conn._connect()
    assert fake.init_calls == [{}], "no lib_dir: let the driver use its documented search path"


def test_missing_instant_client_fails_closed_with_admin_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeOracleDb()

    def boom(**_kwargs: Any) -> None:
        raise RuntimeError("DPI-1047: Cannot locate a 64-bit Oracle Client library")

    fake.init_oracle_client = boom  # type: ignore[method-assign]
    conn, _ = _connector(tmp_path, monkeypatch, options={"thick_mode": True}, fake=fake)

    with pytest.raises(ConnectorError) as exc:
        conn._connect()
    text = str(exc.value)
    assert "Instant Client" in text and "lib_dir" in text
    assert "DPI-1047" in text, "keep the driver's own diagnostic for the administrator"


def test_thin_mode_verifier_error_names_both_remedies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    err = Exception(
        "DPY-3015: password verifier type 0x939 is not supported by python-oracledb in thin mode"
    )
    conn, _ = _connector(tmp_path, monkeypatch, fake=_FakeOracleDb(connect_error=err))

    with pytest.raises(ConnectorError) as exc:
        conn._connect()
    text = str(exc.value)
    assert "DPY-3015" in text
    assert "thick_mode" in text, "client-side remedy must be named"
    assert "ALTER USER" in text or "password reset" in text, "server-side remedy must be named"


def test_legacy_sid_connect_descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake = _connector(tmp_path, monkeypatch, options={"sid": "ORCL"}, database="ignored")
    conn._connect()
    dsn = fake.connect_kwargs[0]["dsn"]
    assert "(SID=ORCL)" in dsn and "SERVICE_NAME" not in dsn, (
        "pre-12c databases are reached by SID, which the easy-connect service form cannot express"
    )


def test_service_name_form_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake = _connector(tmp_path, monkeypatch)
    conn._connect()
    assert fake.connect_kwargs[0]["dsn"] == "db.example.internal:1521/FREEPDB1"


def test_tns_alias_uses_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake = _connector(
        tmp_path, monkeypatch, options={"tns_alias": "PRODDB", "tns_admin": "/etc/universal-db-mcp/tns"}
    )
    conn._connect()
    kw = fake.connect_kwargs[0]
    assert kw["dsn"] == "PRODDB"
    assert kw["config_dir"] == "/etc/universal-db-mcp/tns"


def test_sid_and_tns_alias_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="mutually exclusive"):
        ConnectionConfig.model_validate(
            {"type": "oracle", "host": "h", "database": "d",
             "options": {"sid": "ORCL", "tns_alias": "PRODDB"}}
        )


def test_tns_alias_requires_tns_admin(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="tns_admin"):
        ConnectionConfig.model_validate(
            {"type": "oracle", "host": "h", "database": "d", "options": {"tns_alias": "PRODDB"}}
        )


def test_mixed_thick_and_thin_oracle_connections_are_refused(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        "connections:\n"
        "  a:\n    type: oracle\n    host: h\n    database: d\n    options:\n      thick_mode: true\n"
        "  b:\n    type: oracle\n    host: h2\n    database: d2\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="process-global"):
        load_config(cfg)


def test_all_thick_oracle_connections_are_accepted(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        "connections:\n"
        "  a:\n    type: oracle\n    host: h\n    database: d\n    options:\n      thick_mode: true\n"
        "  b:\n    type: oracle\n    host: h2\n    database: d2\n    options:\n      thick_mode: true\n"
        "  c:\n    type: sqlite\n    database: /tmp/x.db\n",
        encoding="utf-8",
    )
    loaded = load_config(cfg)
    assert loaded.connections["a"].options["thick_mode"] is True
