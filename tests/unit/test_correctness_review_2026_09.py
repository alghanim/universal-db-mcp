"""Regression tests for the correctness review of 2026-09-16 (H1-H4, M1-M6, L1-L10).

Every test names the finding it pins so a later reader can trace why the
behaviour exists.
"""
from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import clickhouse as ch_module
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.connectors.clickhouse import _split_key_expressions
from universal_db_mcp.connectors.db2 import _db2_type
from universal_db_mcp.connectors.mssql import _mssql_type
from universal_db_mcp.connectors.oracle import _oracle_type
from universal_db_mcp.connectors.postgres import _pg_type
from universal_db_mcp.security.policy import EffectivePolicy


def _resolved(engine: str, tmp_path: Path, **extra: Any) -> ResolvedConnection:
    body: dict[str, Any] = {"type": engine, "database": extra.pop("database", "d")}
    if engine != "sqlite":
        body["host"] = "h"
        u = tmp_path / f"{engine}.u"
        u.write_text("u\n")
        u.chmod(0o600)
        body["username_file"] = str(u)
    body.update(extra)
    return ResolvedConnection("c", ConnectionConfig.model_validate(body))


# --- H1: ClickHouse accounts whose profile is already read-only ---------------

class _Setting:
    def __init__(self, value: str, readonly: int = 0) -> None:
        self.value = value
        self.readonly = readonly


class _FakeCHClient:
    def __init__(self, server_readonly: str) -> None:
        self.server_settings = {"readonly": _Setting(server_readonly)}
        self.set_calls: list[tuple[str, Any]] = []
        self.server_readonly = server_readonly

    def set_client_setting(self, name: str, value: Any) -> None:
        if self.server_readonly == "1":
            raise RuntimeError("Cannot modify setting in readonly mode")
        if self.server_readonly == "2" and name == "readonly":
            raise RuntimeError("Cannot modify 'readonly' setting in readonly mode")
        self.set_calls.append((name, value))

    def close(self) -> None:  # pragma: no cover - not reached
        pass


def _ch_connector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, server_readonly: str) -> tuple[Any, _FakeCHClient]:
    from universal_db_mcp.connectors import registry

    made: list[_FakeCHClient] = []

    def get_client(**kw: Any) -> _FakeCHClient:
        assert "settings" not in kw, "H1: settings must not be sent blind in the request"
        c = _FakeCHClient(server_readonly)
        made.append(c)
        return c

    monkeypatch.setattr(ch_module, "open_module", lambda *_a, **_k: types.SimpleNamespace(get_client=get_client))
    r = _resolved("clickhouse", tmp_path)
    conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    client = conn._connect()
    return conn, made[-1] if made else client


def test_h1_fresh_account_gets_our_readonly_and_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conn, client = _ch_connector(monkeypatch, tmp_path, "0")
    names = [n for n, _v in client.set_calls]
    assert names == ["readonly", "max_execution_time"]
    assert "read_only" in conn.session_status["applied"]


def test_h1_readonly_2_profile_is_kept_and_reported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """readonly=2 forbids changing readonly but allows other settings."""
    conn, client = _ch_connector(monkeypatch, tmp_path, "2")
    assert [n for n, _v in client.set_calls] == ["max_execution_time"]
    assert any("readonly=2" in a for a in conn.session_status["applied"])
    report = conn.session_report({"readonly": "2"})
    assert report["read_only_verified"] is True


def test_h1_readonly_1_profile_sends_nothing_and_still_reports_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conn, client = _ch_connector(monkeypatch, tmp_path, "1")
    assert client.set_calls == []
    assert any("readonly=1" in a for a in conn.session_status["applied"])
    assert any(s.startswith("max_execution_time") for s in conn.session_status["skipped"])


def test_h1_a_refused_readonly_on_a_writable_account_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Refusing(_FakeCHClient):
        def set_client_setting(self, name: str, value: Any) -> None:
            raise RuntimeError("boom")

    from universal_db_mcp.connectors import registry

    monkeypatch.setattr(
        ch_module, "open_module",
        lambda *_a, **_k: types.SimpleNamespace(get_client=lambda **kw: _Refusing("0")),
    )
    r = _resolved("clickhouse", tmp_path)
    conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    with pytest.raises(ConnectorError, match="read-only"):
        conn._connect()


# --- L6: sorting keys with function calls ------------------------------------

def test_l6_sorting_key_split_is_parenthesis_aware() -> None:
    assert _split_key_expressions("toYYYYMM(ts), tuple(a, b), id") == ["toYYYYMM(ts)", "tuple(a, b)", "id"]
    assert _split_key_expressions("id") == ["id"]
    assert _split_key_expressions("") == []


# --- M6: declared lengths and precision reach the profiler --------------------

@pytest.mark.parametrize(
    ("fn", "args", "expected"),
    [
        (_pg_type, ("character varying", 200, None, None), "character varying(200)"),
        (_pg_type, ("numeric", None, 12, 2), "numeric(12,2)"),
        (_pg_type, ("integer", None, 32, 0), "integer"),
        (_pg_type, ("text", None, None, None), "text"),
        (_mssql_type, ("nvarchar", -1, None, None), "nvarchar(max)"),
        (_mssql_type, ("nvarchar", 200, None, None), "nvarchar(200)"),
        (_mssql_type, ("decimal", None, 12, 2), "decimal(12,2)"),
        (_mssql_type, ("int", None, 10, 0), "int"),
        (_oracle_type, ("VARCHAR2", 200, None, None), "VARCHAR2(200)"),
        (_oracle_type, ("NUMBER", None, 12, 2), "NUMBER(12,2)"),
        (_oracle_type, ("NUMBER", None, 10, 0), "NUMBER(10)"),
        (_oracle_type, ("NUMBER", None, None, None), "NUMBER"),
        (_oracle_type, ("TIMESTAMP(6)", None, None, None), "TIMESTAMP(6)"),
        (_db2_type, ("VARCHAR", 200, 0), "VARCHAR(200)"),
        (_db2_type, ("DECIMAL", 12, 2), "DECIMAL(12,2)"),
        (_db2_type, ("INTEGER", 4, 0), "INTEGER"),
    ],
)
def test_m6_declared_size_is_folded_into_the_type(fn: Any, args: tuple[Any, ...], expected: str) -> None:
    assert fn(*args) == expected


def test_m6_composed_types_still_map_to_portable_kinds() -> None:
    from universal_db_mcp.discovery.types import portable_type

    assert portable_type("postgres", "character varying(200)").kind == "string"
    assert portable_type("mssql", "nvarchar(max)").kind == "string"
    assert portable_type("oracle", "NUMBER(12,2)").kind == "numeric"
    assert portable_type("mysql", "enum('a','b')").kind == "string"  # MySQL enums accept LENGTH/LOWER
    assert portable_type("mysql", "bigint(20) unsigned") == portable_type("mysql", "bigint")  # modifiers dropped


# --- L5: SQLite primary key columns come back in key order ----------------------

def test_l5_sqlite_composite_primary_key_keeps_key_order(tmp_path: Path) -> None:
    import sqlite3

    from universal_db_mcp.connectors import registry

    db = tmp_path / "k.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE t (a INTEGER, b INTEGER, c INTEGER, PRIMARY KEY (c, a))")
    r = _resolved("sqlite", tmp_path, database=str(db))
    conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    primary = [i for i in conn.list_indexes(None, "t") if i.primary]
    assert primary and primary[0].columns == ["c", "a"]


# --- L3: PostgreSQL lock_timeout never rounds to 0 (which disables it) --------

def test_l3_postgres_lock_timeout_floor_is_one_millisecond(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from universal_db_mcp.connectors import postgres, registry

    executed: list[str] = []

    class _Conn:
        autocommit = True

        def execute(self, sql: str, *_a: Any) -> Any:
            executed.append(sql)
            return types.SimpleNamespace(fetchone=lambda: ("on", "1ms", "1ms", "x", "read committed"), fetchall=list)

        def close(self) -> None:
            pass

    monkeypatch.setattr(postgres, "open_module", lambda *_a, **_k: types.SimpleNamespace(connect=lambda **kw: _Conn()))
    r = _resolved("postgres", tmp_path, session={"lock_timeout_seconds": 0.0001})
    conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    conn._connect()
    assert any("SET lock_timeout = '1ms'" in s for s in executed), executed
