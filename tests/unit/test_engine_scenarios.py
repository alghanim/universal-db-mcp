"""Engine scenarios that real deployments present but our fixtures never did.

Audit 2026-09-15:

* A `tns_alias` connection returned BEFORE the TLS branch, so `tls.enabled`
  produced no TCPS descriptor and no wallet: the policy gate and doctor
  reported TLS compliance while the credentials could travel in plaintext.
  The alias descriptor decides the protocol, so it is now read and must say
  TCPS.
* Thick mode reaches Oracle 11.2 (Thin is 12.1+), but `FETCH FIRST n ROWS
  ONLY` is 12c syntax: sampling would fail with ORA-00933 on exactly the old
  servers Thick mode was added for.
* The Oracle and Db2 health checks query administrative views that a
  least-privilege account (the one our own docs tell operators to create)
  cannot read, so `db_test_connection` reported an unhealthy connection that
  in fact works for every other tool.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import db2 as db2_module
from universal_db_mcp.connectors import oracle as oracle_module
from universal_db_mcp.connectors.base import ConnectorError
from universal_db_mcp.security.policy import EffectivePolicy

TCPS_ENTRY = """PRODDB =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCPS)(HOST = db.internal)(PORT = 2484))
    (CONNECT_DATA = (SERVICE_NAME = ORCLPDB1))
  )
"""
TCP_ENTRY = TCPS_ENTRY.replace("TCPS", "TCP")


class _FakeOracle:
    def __init__(self) -> None:
        self.connect_kwargs: list[dict[str, Any]] = []

    def init_oracle_client(self, **kwargs: Any) -> None:
        pass

    def connect(self, **kwargs: Any) -> Any:
        self.connect_kwargs.append(kwargs)
        return "handle"


def _secret(tmp_path: Path, name: str, value: str) -> str:
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)
    return str(p)


def _oracle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, options: dict[str, Any],
            tls: dict[str, Any] | None = None, fake: Any = None) -> tuple[Any, Any]:
    fake = fake or _FakeOracle()
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "oracledb", types.ModuleType("oracledb"))
    monkeypatch.setattr(oracle_module, "_THICK_STATE", oracle_module.ThickState(), raising=False)
    body: dict[str, Any] = {
        "type": "oracle", "host": "db.internal", "port": 1521, "database": "ORCLPDB1",
        "username_file": _secret(tmp_path, "ou", "app_ro"),
        "password_file": _secret(tmp_path, "op", "s3cret"),
        "options": options,
    }
    if tls:
        body["tls"] = tls
    cfg = ConnectionConfig.model_validate(body)
    resolved = ResolvedConnection("ora", cfg)
    return oracle_module.OracleConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)), fake


def _tns_dir(tmp_path: Path, entry: str) -> str:
    d = tmp_path / "tns"
    d.mkdir(exist_ok=True)
    (d / "tnsnames.ora").write_text(entry, encoding="utf-8")
    return str(d)


def test_tns_alias_with_tls_refuses_a_plaintext_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    conn, fake = _oracle(
        tmp_path, monkeypatch,
        options={"tns_alias": "PRODDB", "tns_admin": _tns_dir(tmp_path, TCP_ENTRY),
                 "wallet_location": str(wallet)},
        tls={"enabled": True, "verify_server": True, "ca_file": str(tmp_path / "ca.pem")},
    )
    with pytest.raises(ConnectorError, match="TCPS|plaintext"):
        conn._connect()
    assert fake.connect_kwargs == [], "a plaintext alias must never be dialed under tls.enabled"


def test_tns_alias_with_tls_accepts_tcps_and_passes_the_wallet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    conn, fake = _oracle(
        tmp_path, monkeypatch,
        options={"tns_alias": "PRODDB", "tns_admin": _tns_dir(tmp_path, TCPS_ENTRY),
                 "wallet_location": str(wallet)},
        tls={"enabled": True, "verify_server": True, "ca_file": str(tmp_path / "ca.pem")},
    )
    conn._connect()
    kw = fake.connect_kwargs[0]
    assert kw["dsn"] == "PRODDB"
    assert kw["wallet_location"] == str(wallet), "TLS material must reach the alias path too"


def test_tns_alias_without_tls_is_unaffected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake = _oracle(
        tmp_path, monkeypatch,
        options={"tns_alias": "PRODDB", "tns_admin": _tns_dir(tmp_path, TCP_ENTRY)},
    )
    conn._connect()
    assert fake.connect_kwargs[0]["dsn"] == "PRODDB"


def test_oracle_sample_query_runs_on_11g(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, _ = _oracle(tmp_path, monkeypatch, options={})
    sql = conn.build_sample_query("APP", "CUSTOMERS", ["ID", "NAME"], 20)
    assert "FETCH FIRST" not in sql, "12c-only syntax breaks the 11.2 servers Thick mode reaches"
    assert "ROWNUM" in sql.upper()
    assert "20" in sql


class _FakeOracleCursor:
    def __init__(self, fail_on: str) -> None:
        self._fail_on = fail_on
        self.executed: list[str] = []
        self._row: tuple[Any, ...] | None = None

    def __enter__(self) -> _FakeOracleCursor:
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def execute(self, sql: str) -> None:
        self.executed.append(sql)
        if self._fail_on in sql:
            raise RuntimeError("ORA-00942: table or view does not exist")
        self._row = (1,)

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


def test_oracle_health_check_survives_a_least_privilege_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cursor = _FakeOracleCursor(fail_on="v$version")

    class _Conn:
        def cursor(self) -> _FakeOracleCursor:
            return cursor

        def close(self) -> None:
            return None

    class _Fake(_FakeOracle):
        def connect(self, **kwargs: Any) -> Any:
            self.connect_kwargs.append(kwargs)
            return _Conn()

    conn, _ = _oracle(tmp_path, monkeypatch, options={}, fake=_Fake())
    health = conn.health_check()

    assert health.healthy is True, "an account without v$version still has a working connection"
    assert health.server_version is None
    assert any("DUAL" in s.upper() for s in cursor.executed), cursor.executed


def test_db2_health_check_survives_a_least_privilege_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FakeDb2:
        def __init__(self) -> None:
            self.executed: list[str] = []

        def connect(self, dsn: str, user: str, password: str, *a: Any, **k: Any) -> str:
            return "handle"

        def exec_immediate(self, conn: str, sql: str) -> str:
            self.executed.append(sql)
            if "SYSIBMADM" in sql:
                raise RuntimeError("SQL0551N  The statement failed because the authorization ID")
            return "stmt"

        def fetch_tuple(self, stmt: str) -> tuple[Any, ...]:
            return (1,)

        def close(self, conn: str) -> bool:
            return True

    fake = _FakeDb2()
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    cfg = ConnectionConfig.model_validate(
        {"type": "db2", "host": "h", "database": "SAMPLE",
         "username_file": _secret(tmp_path, "du", "db2inst1"),
         "password_file": _secret(tmp_path, "dp", "s3cret")}
    )
    resolved = ResolvedConnection("d", cfg)
    conn = db2_module.Db2Connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))

    health = conn.health_check()

    assert health.healthy is True
    assert health.server_version is None
    assert any("SYSDUMMY1" in s.upper() for s in fake.executed), fake.executed


def test_oracle_capabilities_do_not_claim_thin_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, _ = _oracle(tmp_path, monkeypatch, options={})
    caps = conn.capabilities()
    assert "Thin mode only" not in caps.driver
    text = " ".join(lim.detail for lim in caps.limitations)
    assert "Thick mode is not implemented" not in text
