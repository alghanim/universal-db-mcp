"""EXPLAIN on Oracle, SQL Server and Db2 (plan capture without execution).

Driver fakes pin the statement sequence each engine needs: Oracle writes
into PLAN_TABLE under a private statement id and reads it back; SQL Server
sends SET SHOWPLAN_ALL ON as its own batch, the statement returns the plan
rowset, SHOWPLAN is switched off again; Db2 writes into the provisioned
explain tables, reads the operators of that QUERYNO and deletes the rows.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import registry
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.security.policy import EffectivePolicy


def _connector(engine: str, tmp_path: Path) -> Any:
    u = tmp_path / f"{engine}.u"
    u.write_text("u\n")
    u.chmod(0o600)
    body = {"type": engine, "database": "d", "host": "h", "username_file": str(u)}
    r = ResolvedConnection("c", ConnectionConfig.model_validate(body))
    return registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))


# --------------------------------------------------------------------- Oracle
class _OraCursor:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.description: list[tuple[str, ...]] = []
        self._rows: list[tuple[Any, ...]] = []

    def __enter__(self) -> _OraCursor:
        return self

    def __exit__(self, *_a: Any) -> None:
        pass

    def execute(self, sql: str, params: Any = None) -> None:
        self.log.append(sql)
        if sql.startswith("SELECT id, parent_id"):
            self.description = [("ID",), ("PARENT_ID",), ("DEPTH",), ("OPERATION",), ("OPTIONS",), ("OBJECT_OWNER",),
                                ("OBJECT_NAME",), ("CARDINALITY",), ("BYTES",), ("COST",), ("ACCESS_PREDICATES",),
                                ("FILTER_PREDICATES",)]
            self._rows = [(0, None, 0, "SELECT STATEMENT", None, None, None, 8, 200, 3, None, None),
                          (1, 0, 1, "TABLE ACCESS", "FULL", "TRAVEL", "TRAVELLERS", 8, 200, 3, None, None)]
        elif "DBMS_XPLAN" in sql:
            self._rows = [("Plan hash value: 1",), ("| 0 | SELECT STATEMENT |",)]
        else:
            self._rows = []

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _OraConn:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.closed = False

    def cursor(self) -> _OraCursor:
        return _OraCursor(self.log)

    def close(self) -> None:
        self.closed = True


def test_oracle_explain_plan_is_written_read_and_cleaned_on_a_private_session(tmp_path: Path, monkeypatch: Any) -> None:
    conn = _connector("oracle", tmp_path)
    log: list[str] = []
    fake = _OraConn(log)
    monkeypatch.setattr(conn, "_connect", lambda: fake)
    plan = conn.explain('SELECT * FROM "TRAVEL"."TRAVELLERS"', False)
    assert log[0].startswith("EXPLAIN PLAN SET STATEMENT_ID = 'udbmcp_")
    assert log[0].endswith('FOR SELECT * FROM "TRAVEL"."TRAVELLERS"')
    assert log[1].startswith("SELECT id, parent_id") and "DBMS_XPLAN.DISPLAY" in log[2]
    assert log[3].startswith("DELETE FROM plan_table WHERE statement_id = :1")
    assert fake.closed
    assert plan["rows"][1]["operation"] == "TABLE ACCESS" and plan["rows"][1]["object_name"] == "TRAVELLERS"
    assert plan["raw"].startswith("Plan hash value") and "not executed" in plan["method"]
    with pytest.raises(NotImplementedError):
        conn.explain("SELECT 1 FROM DUAL", True)


# ----------------------------------------------------------------- SQL Server
class _MsCursor:
    def __init__(self, log: list[str], deny: bool) -> None:
        self.log = log
        self.deny = deny
        self.description: list[tuple[str, ...]] = []
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str) -> None:
        self.log.append(sql)
        if sql.startswith("SET SHOWPLAN"):
            return
        if self.deny:
            raise RuntimeError("[42000] SHOWPLAN permission denied in database 'HospitalDB'. (262)")
        self.description = [("StmtText",), ("StmtId",), ("NodeId",), ("Parent",), ("PhysicalOp",), ("LogicalOp",),
                            ("EstimateRows",), ("EstimateIO",), ("EstimateCPU",), ("TotalSubtreeCost",), ("Warnings",)]
        self._rows = [("SELECT * FROM dbo.patients", 1, 1, 0, None, None, 10.0, None, None, 0.01, None),
                      ("  |--Clustered Index Scan", 1, 2, 1, "Clustered Index Scan", "Clustered Index Scan",
                       10.0, 0.003, 0.0001, 0.0032, None)]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _MsConn:
    def __init__(self, log: list[str], deny: bool = False) -> None:
        self.log = log
        self.deny = deny
        self.closed = False

    def cursor(self) -> _MsCursor:
        return _MsCursor(self.log, self.deny)

    def close(self) -> None:
        self.closed = True


def test_mssql_showplan_is_its_own_batch_and_switched_off(tmp_path: Path, monkeypatch: Any) -> None:
    conn = _connector("mssql", tmp_path)
    log: list[str] = []
    fake = _MsConn(log)
    monkeypatch.setattr(conn, "_connect", lambda: fake)
    plan = conn.explain("SELECT * FROM dbo.patients", False)
    assert log == ["SET SHOWPLAN_ALL ON", "SELECT * FROM dbo.patients", "SET SHOWPLAN_ALL OFF"]
    assert fake.closed
    assert plan["rows"][1]["PhysicalOp"] == "Clustered Index Scan" and plan["rows"][1]["TotalSubtreeCost"] == "0.0032"
    assert "Clustered Index Scan" in plan["raw"] and "not executed" in plan["method"]


def test_mssql_missing_showplan_permission_is_named(tmp_path: Path, monkeypatch: Any) -> None:
    conn = _connector("mssql", tmp_path)
    log: list[str] = []
    monkeypatch.setattr(conn, "_connect", lambda: _MsConn(log, deny=True))
    with pytest.raises(ConnectorError, match="GRANT SHOWPLAN"):
        conn.explain("SELECT 1", False)
    assert log[-1] == "SET SHOWPLAN_ALL OFF", "SHOWPLAN must be switched off even after a refusal"


# ------------------------------------------------------------------------ Db2
class _Db2Stmt:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = list(rows)


class _FakeIbmDb:
    """ibm_db surface the connector uses; answers depend on the SQL text."""

    def __init__(self, provisioned: bool) -> None:
        self.provisioned = provisioned
        self.log: list[str] = []
        self.closed = False

    def _answer(self, sql: str) -> list[tuple[Any, ...]]:
        if "TABNAME = 'EXPLAIN_STATEMENT'" in sql:
            return [("SYSTOOLS",)] if self.provisioned else []
        if sql.startswith("VALUES (SESSION_USER)"):
            return [("DB2INST1",)]
        if "FROM \"SYSTOOLS\".EXPLAIN_STATEMENT" in sql:
            return [("DB2INST1", "2026-09-18-10.00.00", "SQLC2O29", "NULLID", "", "P", 1, 1, 12.5)]
        if "FROM \"SYSTOOLS\".EXPLAIN_OPERATOR" in sql:
            return [(1, "RETURN  ", 12.5, 6.0, 1000.0, None, None, None),
                    (2, "TBSCAN  ", 12.4, 6.0, 900.0, "MOI     ", "CITIZENS", 6.0)]
        return []

    def exec_immediate(self, conn: Any, sql: str) -> _Db2Stmt:
        self.log.append(sql)
        return _Db2Stmt(self._answer(sql))

    def prepare(self, conn: Any, sql: str) -> _Db2Stmt:
        self.log.append(sql)
        return _Db2Stmt(self._answer(sql))

    def execute(self, stmt: _Db2Stmt, params: Any = None) -> bool:
        return True

    def fetch_tuple(self, stmt: _Db2Stmt) -> Any:
        return stmt.rows.pop(0) if stmt.rows else False

    def close(self, conn: Any) -> None:
        self.closed = True


def test_db2_explain_uses_the_provisioned_tables_and_cleans_up(tmp_path: Path, monkeypatch: Any) -> None:
    conn = _connector("db2", tmp_path)
    fake = _FakeIbmDb(provisioned=True)
    monkeypatch.setattr(conn, "_module", fake, raising=False)
    monkeypatch.setattr(conn, "_connect", lambda: object())
    plan = conn.explain('SELECT * FROM "MOI"."CITIZENS"', False)
    kinds = [s.split(" ")[0] for s in fake.log]
    assert "EXPLAIN" in kinds and any(s.startswith("EXPLAIN PLAN SET QUERYNO = ") for s in fake.log)
    assert any(s.startswith('DELETE FROM "SYSTOOLS".EXPLAIN_INSTANCE') for s in fake.log)
    assert fake.closed
    assert plan["total_cost"] == 12.5
    assert plan["rows"][1]["operator"] == "TBSCAN" and plan["rows"][1]["object_name"] == "CITIZENS"
    assert "SYSTOOLS" in plan["method"] and "not executed" in plan["method"]


def test_db2_explain_without_tables_says_what_the_dba_must_run(tmp_path: Path, monkeypatch: Any) -> None:
    conn = _connector("db2", tmp_path)
    fake = _FakeIbmDb(provisioned=False)
    monkeypatch.setattr(conn, "_module", fake, raising=False)
    monkeypatch.setattr(conn, "_connect", lambda: object())
    with pytest.raises(NotImplementedError, match="SYSINSTALLOBJECTS"):
        conn.explain("SELECT 1 FROM SYSIBM.SYSDUMMY1", False)
    assert not any(s.startswith("EXPLAIN PLAN") for s in fake.log), "nothing is written without explain tables"


# ------------------------------------------------------------ EXPLAIN ANALYZE
_ANALYZE_REFUSAL = "db_explain never executes the statement; EXPLAIN ANALYZE is not supported"


@pytest.mark.parametrize("engine", ["postgres", "mysql", "clickhouse", "oracle", "mssql", "db2", "sqlite"])
def test_explain_analyze_is_refused_for_what_db_explain_is_not_for_policy(
    engine: str, tmp_path: Path, monkeypatch: Any
) -> None:
    """Wave-3 review (I03): the refusal read 'EXPLAIN ANALYZE is
    policy-disabled', also where security.allow_explain_analyze is on. No
    policy enables it: db_explain captures plans without executing. The
    exception type stays NotImplementedError (CAPABILITY_UNSUPPORTED), and
    nothing is dialed."""
    if engine == "sqlite":
        body = {"type": "sqlite", "database": str(tmp_path / "x.db")}
        r = ResolvedConnection("c", ConnectionConfig.model_validate(body))
        conn = registry.build_connector(r, EffectivePolicy.build(SecurityConfig(), r))
    else:
        conn = _connector(engine, tmp_path)
    monkeypatch.setattr(conn, "_connect", lambda: pytest.fail("EXPLAIN ANALYZE dialed the server"), raising=False)
    monkeypatch.setattr(conn, "_open", lambda: pytest.fail("EXPLAIN ANALYZE opened the database"), raising=False)
    with pytest.raises(NotImplementedError) as info:
        conn.explain("SELECT 1", True)
    assert str(info.value) == _ANALYZE_REFUSAL
    for limitation in conn.capabilities().limitations:
        assert "policy-disabled" not in limitation.detail, limitation
