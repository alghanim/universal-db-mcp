"""SQL connector regressions from the 2026-09-27 security/production review.

Each section names the finding it pins. Drivers are fakes that record what the
connector hands them; where the question is how the REAL driver reads that
input (python-oracledb's tnsnames resolution and its Thick-mode connect-string
handling), the real driver code answers it.
"""

from __future__ import annotations

import array
import base64
import datetime
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
import types
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors import db2 as db2_module
from universal_db_mcp.connectors import driver_helpers
from universal_db_mcp.connectors import mssql as mssql_module
from universal_db_mcp.connectors import mysql as mysql_module
from universal_db_mcp.connectors import oracle as oracle_module
from universal_db_mcp.connectors import postgres as pg_module
from universal_db_mcp.connectors.base import ConnectorError, QuerySpec
from universal_db_mcp.connectors.sqlite import SQLiteConnector
from universal_db_mcp.models.capabilities import Cap, CapabilityState
from universal_db_mcp.security.policy import EffectivePolicy

REPO = Path(__file__).resolve().parents[2]


def _secret(tmp_path: Path, name: str, value: str) -> str:
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    p.chmod(0o600)
    return str(p)


def _real_oracledb() -> Any:
    return pytest.importorskip("oracledb")


# --------------------------------------------------------------------- Oracle


class _FakeOracleDb:
    """Records connect() kwargs; tnsnames resolution is the REAL driver's."""

    def __init__(self, version: str = "19.3.0.0.0", rows: list[tuple[Any, ...]] | None = None) -> None:
        self.connect_kwargs: list[dict[str, Any]] = []
        self.init_calls: list[dict[str, Any]] = []
        self.version = version
        self.rows = rows or []
        self.executed: list[tuple[str, list[Any]]] = []

    @property
    def ConnectParams(self) -> Any:  # noqa: N802 - the driver's attribute name
        return _real_oracledb().ConnectParams

    def init_oracle_client(self, **kwargs: Any) -> None:
        self.init_calls.append(kwargs)

    def connect(self, **kwargs: Any) -> Any:
        self.connect_kwargs.append(kwargs)
        return _FakeOracleConn(self)


class _FakeOracleConn:
    def __init__(self, db: _FakeOracleDb) -> None:
        self._db = db
        self.version = db.version

    def cursor(self) -> _FakeOracleCursor:
        return _FakeOracleCursor(self._db)

    def close(self) -> None:
        return None


class _FakeOracleCursor:
    """Answers catalog queries with the configured rows, applying an
    ``owner NOT IN (...)`` list the way the server would (numbered binds are
    positional in python-oracledb)."""

    def __init__(self, db: _FakeOracleDb) -> None:
        self._db = db
        self._rows: list[tuple[Any, ...]] = []

    def __enter__(self) -> _FakeOracleCursor:
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def execute(self, sql: str, params: Any = None) -> None:
        bound = list(params or [])
        self._db.executed.append((sql, bound))
        excluded: set[Any] = set()
        for head, tail in _not_in_lists(sql, "owner NOT IN ("):
            start = len(re.findall(r":\d+", head))
            excluded |= set(bound[start:start + len(re.findall(r":\d+", tail))])
        self._rows = [r for r in self._db.rows if r[0] not in excluded]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None


def _not_in_lists(sql: str, marker: str) -> list[tuple[str, str]]:
    """(text before, bind list) for every ``marker ...)`` in ``sql``."""
    out = []
    pos = sql.find(marker)
    while pos >= 0:
        start = pos + len(marker)
        out.append((sql[:start], sql[start:sql.index(")", start)]))
        pos = sql.find(marker, start)
    return out


def _oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, options: dict[str, Any], tls: bool = True,
    fake: _FakeOracleDb | None = None, security: SecurityConfig | None = None,
) -> tuple[oracle_module.OracleConnector, _FakeOracleDb]:
    fake = fake or _FakeOracleDb()
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setattr(oracle_module, "_THICK_STATE", oracle_module.ThickState(), raising=False)
    body: dict[str, Any] = {
        "type": "oracle", "host": "db.internal", "port": 2484, "database": "ORCLPDB1",
        "username_file": _secret(tmp_path, "ou", "app_ro"),
        "password_file": _secret(tmp_path, "op", "s3cret"),
        "options": options,
    }
    if tls:
        body["tls"] = {"enabled": True, "verify_server": True, "ca_file": str(tmp_path / "ca.pem")}
    cfg = ConnectionConfig.model_validate(body)
    resolved = ResolvedConnection("ora", cfg)
    policy = EffectivePolicy.build(security or SecurityConfig(), resolved)
    return oracle_module.OracleConnector(resolved, policy), fake


TCPS = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db.internal)(PORT=2484))(CONNECT_DATA=(SERVICE_NAME=S)))"
TCP = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.internal)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=S)))"


def _tns(tmp_path: Path, main: str, extra: str | None = None) -> str:
    d = tmp_path / "tns"
    d.mkdir(exist_ok=True)
    if extra is not None:
        (d / "extra.ora").write_text(extra, encoding="utf-8")
        main = main.replace("@EXTRA@", str(d / "extra.ora"))
    (d / "tnsnames.ora").write_text(main, encoding="utf-8")
    return str(d)


def _wallet(tmp_path: Path, name: str = "wallet") -> str:
    w = tmp_path / name
    w.mkdir(exist_ok=True)
    return str(w)


def _alias_options(tmp_path: Path, tns_admin: str, alias: str, **more: Any) -> dict[str, Any]:
    return {"tns_alias": alias, "tns_admin": tns_admin, "wallet_location": _wallet(tmp_path), **more}


# F31: the TLS gate must check what python-oracledb will dial, not a private
# line scanner's reading of tnsnames.ora.


@pytest.mark.parametrize("thick", [False, True])
def test_f31_ifile_that_redefines_the_alias_as_tcp_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thick: bool
) -> None:
    tns = _tns(tmp_path, f"PROD = {TCPS}\nIFILE = @EXTRA@\n", f"PROD = {TCP}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD", thick_mode=thick))
    with pytest.raises(ConnectorError, match="TCPS|plaintext"):
        conn._connect()
    assert fake.connect_kwargs == [], "a descriptor the driver resolves to TCP must never be dialed"


def test_f31_column_zero_tcp_continuation_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tns = _tns(
        tmp_path,
        "PROD =\n  (DESCRIPTION=(ADDRESS_LIST=\n    (ADDRESS=(PROTOCOL=TCPS)(HOST=h)(PORT=2484))\n"
        "(ADDRESS=(PROTOCOL=TCP)(HOST=h)(PORT=1521)))\n  (CONNECT_DATA=(SERVICE_NAME=S)))\n",
    )
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD"))
    with pytest.raises(ConnectorError, match="TCPS|plaintext"):
        conn._connect()
    assert fake.connect_kwargs == []


def test_f31_unresolvable_alias_is_refused_with_the_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tns = _tns(tmp_path, f"OTHER = {TCPS}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD"))
    with pytest.raises(ConnectorError, match="could not be found") as exc:
        conn._connect()
    assert "LDAP" in str(exc.value), "an alias only a directory server knows cannot be checked; say so"
    assert "DPY-4000" in str(exc.value)
    assert fake.connect_kwargs == []


@pytest.mark.parametrize(
    ("security", "code"),
    [("(SSL_VERSION=1.2)", "DPY-4032"), ("(SSL_CIPHER_SUITES=(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384))", "DPY-4017")],
)
def test_f31_alias_python_oracledb_cannot_parse_is_refused_as_a_parse_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, security: str, code: str
) -> None:
    """Review round 2: Oracle Client spellings python-oracledb's reader
    rejects were refused with the 'could not be resolved ... LDAP' text, which
    sent the operator looking for a directory server."""
    entry = TCPS[:-1] + f"(SECURITY={security}))"
    tns = _tns(tmp_path, f"PROD = {entry}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD"))
    with pytest.raises(ConnectorError, match="could not parse") as exc:
        conn._connect()
    assert code in str(exc.value) and "TLSv1.2" in str(exc.value) and "LDAP" not in str(exc.value)
    assert fake.connect_kwargs == []


def _assert_dials_tcps(kw: dict[str, Any], alias: str) -> str:
    dsn = str(kw["dsn"])
    assert dsn != alias, "the bare alias would let the driver re-resolve it; dial the checked descriptor"
    low = dsn.lower().replace(" ", "")
    assert "protocol=tcps" in low
    assert "protocol=tcp)" not in low
    return dsn


@pytest.mark.parametrize("thick", [False, True])
def test_f31_second_name_of_a_multi_name_entry_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thick: bool
) -> None:
    tns = _tns(tmp_path, f"PRODA, PRODB = {TCPS}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PRODB", thick_mode=thick))
    conn._connect()
    _assert_dials_tcps(fake.connect_kwargs[0], "PRODB")


@pytest.mark.parametrize("thick", [False, True])
def test_f31_alias_defined_only_in_an_ifile_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thick: bool
) -> None:
    tns = _tns(tmp_path, "IFILE = @EXTRA@\n", f"PROD = {TCPS}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD", thick_mode=thick))
    conn._connect()
    _assert_dials_tcps(fake.connect_kwargs[0], "PROD")


def test_f31_alias_without_tls_still_dials_the_alias(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tns = _tns(tmp_path, f"PROD = {TCP}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options={"tns_alias": "PROD", "tns_admin": tns}, tls=False)
    conn._connect()
    assert fake.connect_kwargs[0]["dsn"] == "PROD"
    assert fake.connect_kwargs[0]["config_dir"] == tns


# F32: in Thick mode python-oracledb hands the descriptor to the Oracle Client
# unchanged, so the wallet and host-name matching must be IN the descriptor.


def _thick_client_dsn(kw: dict[str, Any]) -> str:
    """The string python-oracledb's Thick mode hands the Oracle Client
    (Connection.__init__ -> ConnectParamsImpl.process_args -> ThickConnImpl)."""
    base_impl = pytest.importorskip("oracledb.base_impl")
    rest = dict(kw)
    dsn = rest.pop("dsn")
    return str(base_impl.ConnectParamsImpl().process_args(dsn, rest, False))


def test_f32_thick_host_port_tls_puts_dn_match_and_wallet_in_the_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet = _wallet(tmp_path, "wallet dir")
    conn, fake = _oracle(tmp_path, monkeypatch, options={"thick_mode": True, "wallet_location": wallet})
    conn._connect()
    kw = fake.connect_kwargs[0]
    assert "(SSL_SERVER_DN_MATCH=ON)" in kw["dsn"]
    assert f'(MY_WALLET_DIRECTORY="{wallet}")' in kw["dsn"], "the driver does not quote the path; we must"
    client = _thick_client_dsn(kw)
    assert "SSL_SERVER_DN_MATCH=ON" in client and wallet in client, (
        "the Oracle Client must receive both directives, not a bare TCPS descriptor"
    )


def test_f32_thin_host_port_tls_resolves_to_the_same_wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oracledb = _real_oracledb()
    wallet = _wallet(tmp_path, "wallet (prod)")
    conn, fake = _oracle(
        tmp_path, monkeypatch,
        options={"wallet_location": wallet, "wallet_password_file": _secret(tmp_path, "wpw", "wpw"), "sid": "ORCL"},
    )
    conn._connect()
    kw = fake.connect_kwargs[0]
    params = oracledb.ConnectParams()
    params.parse_connect_string(kw["dsn"])
    assert params.protocol == "tcps"
    assert params.ssl_server_dn_match is True
    assert params.wallet_location == wallet
    assert params.sid == "ORCL"
    assert kw["wallet_password"] == "wpw"


@pytest.mark.parametrize("thick", [False, True])
def test_f32_alias_descriptor_carries_dn_match_and_the_configured_wallet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thick: bool
) -> None:
    tns = _tns(tmp_path, f"PROD = {TCPS}\n")
    opts = _alias_options(tmp_path, tns, "PROD", thick_mode=thick)
    conn, fake = _oracle(tmp_path, monkeypatch, options=opts)
    conn._connect()
    kw = fake.connect_kwargs[0]
    _assert_dials_tcps(kw, "PROD")
    assert "(SSL_SERVER_DN_MATCH=ON)" in kw["dsn"]
    assert f'(MY_WALLET_DIRECTORY="{opts["wallet_location"]}")' in kw["dsn"]
    if thick:
        client = _thick_client_dsn(kw)
        assert "SSL_SERVER_DN_MATCH=ON" in client and opts["wallet_location"] in client


@pytest.mark.parametrize("bad", ['/etc/w")(ADDRESS=(PROTOCOL=TCP)', "/etc/w)(x", "/etc/w\nx", '/etc/"w"'])
def test_f32_wallet_location_that_could_rewrite_the_descriptor_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    conn, fake = _oracle(tmp_path, monkeypatch, options={"thick_mode": True, "wallet_location": bad})
    with pytest.raises(ConnectorError, match="wallet_location"):
        conn._connect()
    assert fake.connect_kwargs == []


def test_f32_alias_that_switches_dn_matching_off_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    entry = TCPS[:-1] + "(SECURITY=(SSL_SERVER_DN_MATCH=OFF)))"
    tns = _tns(tmp_path, f"PROD = {entry}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD", thick_mode=True))
    with pytest.raises(ConnectorError, match="SSL_SERVER_DN_MATCH"):
        conn._connect()
    assert fake.connect_kwargs == []


def test_f32_alias_certificate_dn_survives_quoted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oracledb = _real_oracledb()
    entry = TCPS[:-1] + '(SECURITY=(SSL_SERVER_CERT_DN="CN=db.internal, O=Example")))'
    tns = _tns(tmp_path, f"PROD = {entry}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD", thick_mode=True))
    conn._connect()
    dsn = fake.connect_kwargs[0]["dsn"]
    assert '(SSL_SERVER_CERT_DN="CN=db.internal, O=Example")' in dsn
    params = oracledb.ConnectParams()
    params.parse_connect_string(dsn)
    assert params.ssl_server_cert_dn == "CN=db.internal, O=Example"


# F76: a password-protected wallet must be usable on the alias path too.


def test_f76_alias_tls_passes_the_wallet_password_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tns = _tns(tmp_path, f"PROD = {TCPS}\n")
    conn, fake = _oracle(
        tmp_path, monkeypatch,
        options=_alias_options(tmp_path, tns, "PROD", wallet_password_file=_secret(tmp_path, "wpw", "wpw")),
    )
    conn._connect()
    assert fake.connect_kwargs[0]["wallet_password"] == "wpw"


def test_f76_alias_tls_omits_the_wallet_password_when_not_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tns = _tns(tmp_path, f"PROD = {TCPS}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD"))
    conn._connect()
    assert "wallet_password" not in fake.connect_kwargs[0]


# F26 (Oracle): dictionary owners are not permitted data.

_ORACLE_ROWS = [
    ("SYS", "OBJ$", "TABLE"),
    ("SYSTEM", "HELP", "TABLE"),
    ("CTXSYS", "DR$THS", "TABLE"),
    ("SYSADM_APP", "ORDERS", "TABLE"),
    ("TRAVEL", "BOOKINGS", "TABLE"),
]


def test_f26_oracle_12c_filters_oracle_maintained_owners(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeOracleDb(version="19.3.0.0.0", rows=_ORACLE_ROWS)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake)
    conn.list_tables(None, {"table", "view"}, None)
    sql, _params = fake.executed[-1]
    assert sql.count("oracle_maintained = 'N'") == 2, "both the table and the view arm"
    assert "LIKE 'SYS%'" not in sql


def test_f26_oracle_11g_binds_the_static_owner_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeOracleDb(version="11.2.0.4.0", rows=_ORACLE_ROWS)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake)
    out = conn.list_tables(None, {"table"}, None)
    sql, params = fake.executed[-1]
    assert "oracle_maintained" not in sql, "ALL_USERS.ORACLE_MAINTAINED does not exist before 12c"
    assert {"SYS", "SYSTEM", "CTXSYS"} <= set(params)
    assert "'SYS'" not in sql, "owners are bound, never spliced"
    assert {(t.schema, t.name) for t in out} == {("SYSADM_APP", "ORDERS"), ("TRAVEL", "BOOKINGS")}


def test_f26_oracle_explicit_dictionary_schema_lists_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeOracleDb(version="10.2.0.5.0", rows=[r for r in _ORACLE_ROWS if r[0] == "SYS"])
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake)
    assert conn.list_tables("SYS", {"table", "view"}, "OBJ") == []
    sql, params = fake.executed[-1]
    # every bind is numbered in order, so the positional values line up
    assert re.findall(r":(\d+)", sql) == [str(i) for i in range(1, len(params) + 1)]


# ------------------------------------------------------------------------ Db2


class _FakeIbmDb:
    """Records the DSN and answers SYSCAT.TABLES, applying a
    ``TABSCHEMA NOT IN (...)`` list the way the server would."""

    def __init__(self, rows: list[tuple[Any, ...]] | None = None) -> None:
        self.dsns: list[str] = []
        self.rows = rows or []
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self._sql = ""
        self._pending: list[tuple[Any, ...]] = []

    def connect(self, dsn: str, user: str, password: str, *_a: Any, **_k: Any) -> str:
        self.dsns.append(dsn)
        return "handle"

    def exec_immediate(self, conn: str, sql: str) -> str:
        return "stmt"

    def prepare(self, conn: str, sql: str) -> str:
        self._sql = sql
        return "stmt"

    def execute(self, stmt: str, params: tuple[Any, ...]) -> bool:
        self.executed.append((self._sql, params))
        excluded: set[Any] = set()
        for head, tail in _not_in_lists(self._sql, "TABSCHEMA NOT IN ("):
            start = head.count("?")
            excluded |= set(params[start:start + tail.count("?")])
        self._pending = [r for r in self.rows if r[0] not in excluded]
        return True

    def fetch_tuple(self, stmt: str) -> Any:
        return self._pending.pop(0) if self._pending else False

    def close(self, conn: str) -> bool:
        return True


def _db2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, tls: dict[str, Any] | None = None,
    fake: _FakeIbmDb | None = None, security: SecurityConfig | None = None,
) -> tuple[db2_module.Db2Connector, _FakeIbmDb]:
    fake = fake or _FakeIbmDb()
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    body: dict[str, Any] = {
        "type": "db2", "host": "db2.internal.example", "port": 50001, "database": "SAMPLE",
        "username_file": _secret(tmp_path, "du", "db2ro"),
        "password_file": _secret(tmp_path, "dp", "s3cret"),
    }
    if tls is not None:
        body["tls"] = tls
        # these tests read the DSN, never dialed; the TLS probe has its own tests
        monkeypatch.setattr(db2_module.Db2Connector, "_require_tls_answer", lambda _self: None)
    resolved = ResolvedConnection("d", ConnectionConfig.model_validate(body))
    return db2_module.Db2Connector(resolved, EffectivePolicy.build(security or SecurityConfig(), resolved)), fake


def _dsn_keys(dsn: str) -> list[tuple[str, str]]:
    return [(k.upper(), v) for k, _, v in (part.partition("=") for part in dsn.split(";") if part)]


# F33: host-name validation must be on, whatever the clidriver's default is.


def test_f33_db2_tls_turns_on_host_name_validation_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = tmp_path / "ca.pem"
    conn, fake = _db2(tmp_path, monkeypatch, tls={"enabled": True, "verify_server": True, "ca_file": str(ca)})
    conn._connect()
    keys = _dsn_keys(fake.dsns[0])
    assert ("SECURITY", "SSL") in keys
    assert ("SSLSERVERCERTIFICATE", str(ca)) in keys
    assert [v for k, v in keys if k == "SSLCLIENTHOSTNAMEVALIDATION"] == ["Basic"]


def test_f33_db2_without_tls_sends_no_ssl_keywords(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake = _db2(tmp_path, monkeypatch)
    conn._connect()
    keys = {k for k, _ in _dsn_keys(fake.dsns[0])}
    assert not keys & {"SECURITY", "SSLSERVERCERTIFICATE", "SSLCLIENTHOSTNAMEVALIDATION"}


def test_f33_db2_semicolon_in_ca_file_is_still_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    poisoned = str(tmp_path / "ca.pem;SSLClientHostnameValidation=OFF")
    conn, fake = _db2(tmp_path, monkeypatch, tls={"enabled": True, "verify_server": True, "ca_file": poisoned})
    with pytest.raises(ConnectorError, match="';'"):
        conn._connect()
    assert fake.dsns == []


def test_f33_db2_tls_script_issues_certificates_with_a_san() -> None:
    text = (REPO / "scripts" / "db2-enable-tls.sh").read_text(encoding="utf-8")
    creates = [line for line in text.splitlines() if re.search(r"-cert -(create|selfsign) -db ", line)]
    assert len(creates) >= 4, "host-mode and container-mode create/selfsign invocations"
    for line in creates:
        assert "-san_" in line, f"certificate without a subjectAltName: {line.strip()}"
        assert "CN=udbmcp-test" not in line, "the CN must name the host the client dials"


@pytest.mark.parametrize(
    ("host", "san"),
    [("db2.internal.example", "-san_dnsname db2.internal.example"), ("10.20.30.40", "-san_ipaddr 10.20.30.40")],
)
def test_f33_db2_tls_script_host_mode_names_the_host_in_the_certificate(host: str, san: str) -> None:
    proc = subprocess.run(  # noqa: S603 - repository script, fixed arguments, prints only
        ["/bin/bash", str(REPO / "scripts" / "db2-enable-tls.sh"), "--host", host, "--ssl-port", "50001"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    creates = [line for line in proc.stdout.splitlines() if re.search(r"-cert -(create|selfsign) -db ", line)]
    assert creates
    for line in creates:
        assert san in line and f"-dn CN={host}" in line


# F26 (Db2): SYSCAT and friends are not permitted data.

_DB2_ROWS = [
    ("SYSCAT", "TABLES", "V", -1),
    ("SYSIBM", "SYSTABLES", "T", 500),
    ("SYSIBMINTERNAL", "OPTSTATS", "T", 1),
    ("SYSIBMTS", "TSDEFAULTS", "T", 1),
    ("NULLID", "PKG", "T", 1),
    ("SQLJ", "JAR", "T", 1),
    ("SYSADM_APP", "ORDERS", "T", 10),
    ("APP", "CUSTOMERS", "T", 5),
]


def test_f26_db2_list_tables_binds_the_system_schema_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, fake = _db2(tmp_path, monkeypatch, fake=_FakeIbmDb(rows=_DB2_ROWS))
    out = conn.list_tables(None, {"table", "view"}, None)
    sql, params = fake.executed[-1]
    assert "TABSCHEMA NOT IN (" in sql
    assert "LIKE 'SYS%'" not in sql, "a bare prefix match would hide user schemas such as SYSADM_APP"
    assert {"SYSCAT", "SYSIBM", "SYSIBMINTERNAL", "SYSIBMTS", "NULLID", "SQLJ"} <= set(params)
    assert {(t.schema, t.name) for t in out} == {("SYSADM_APP", "ORDERS"), ("APP", "CUSTOMERS")}


def test_f26_db2_explicit_syscat_lists_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [r for r in _DB2_ROWS if r[0] == "SYSCAT"]
    conn, _ = _db2(tmp_path, monkeypatch, fake=_FakeIbmDb(rows=rows))
    assert conn.list_tables("SYSCAT", {"table", "view"}, None) == []


# ----------------------------------------------------------------- SQL Server


class _FakePyodbcError(Exception):
    pass


class _MssqlScript:
    """What the fake server answers, and a log of what the connector did."""

    def __init__(
        self, rows: list[tuple[Any, ...]] | None = None, *, more_results: bool = False,
        later_error: bool = False, execute_error: bool = False, one: tuple[Any, ...] | None = None,
        described: list[tuple[str | None, int]] | None = None,
    ) -> None:
        self.rows = rows if rows is not None else [(1,)]
        # what sp_describe_first_result_set reports: (name, system_type_id)
        self.described = described if described is not None else [("v", 56)]
        self.more_results = more_results
        self.later_error = later_error
        self.execute_error = execute_error
        self.one = one
        self.log: list[Any] = []
        self.fetch_sizes: list[int] = []
        self.connect_kwargs: dict[str, Any] = {}
        self.conn: _FakeMssqlConn | None = None


class _FakeMssqlCursor:
    def __init__(self, script: _MssqlScript) -> None:
        self._s = script
        self.description: list[tuple[Any, ...]] | None = None
        self._pending: list[tuple[Any, ...]] = []

    def execute(self, sql: str, *params: Any) -> None:
        self._s.log.append(("execute", sql, list(params[0]) if params else None))
        if params and isinstance(params[0], dict):
            raise TypeError("Params must be in a list, tuple, or Row")  # pyodbc's own refusal
        if sql.startswith("SET "):
            return
        if sql.startswith("EXEC sys.sp_describe_first_result_set"):
            fields = ("is_hidden", "column_ordinal", "name", "system_type_id")
            self.description = [(f, None, None, None, None, None, True) for f in fields]
            self._pending = [(False, i, n, t) for i, (n, t) in enumerate(self._s.described, start=1)]
            return
        if self._s.execute_error:
            raise _FakePyodbcError("[42000] syntax error (102)")
        self.description = [("v", int, None, None, None, None, True)]
        self._pending = list(self._s.rows)

    def fetchmany(self, n: int) -> list[tuple[Any, ...]]:
        self._s.fetch_sizes.append(n)
        batch, self._pending = self._pending[:n], self._pending[n:]
        return batch

    def fetchone(self) -> Any:
        return self._s.one

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending, []
        return rows

    def nextset(self) -> bool:
        self._s.log.append("nextset")
        if self._s.later_error:
            raise _FakePyodbcError(
                "[42000] The DELETE permission was denied on the object 't', database 'd', schema 'dbo'. (229)"
            )
        return self._s.more_results

    def close(self) -> None:
        return None


class _FakeMssqlConn:
    def __init__(self, script: _MssqlScript) -> None:
        self._s = script
        self.autocommit = True  # what a driver-level default could have been

    def cursor(self) -> _FakeMssqlCursor:
        return _FakeMssqlCursor(self._s)

    def rollback(self) -> None:
        self._s.log.append("rollback")

    def commit(self) -> None:
        self._s.log.append("commit")

    def close(self) -> None:
        self._s.log.append("close")


def _mssql(monkeypatch: pytest.MonkeyPatch, script: _MssqlScript) -> mssql_module.MssqlConnector:
    def connect(connstr: str, **kwargs: Any) -> _FakeMssqlConn:
        script.connect_kwargs = kwargs
        script.conn = _FakeMssqlConn(script)
        return script.conn

    fake = types.SimpleNamespace(
        connect=connect, drivers=lambda: ["ODBC Driver 18 for SQL Server"], Error=_FakePyodbcError
    )
    monkeypatch.setattr(mssql_module, "open_module", lambda *_a, **_k: fake)
    cfg = ConnectionConfig.model_validate({"type": "mssql", "host": "h", "database": "d"})
    resolved = ResolvedConnection("m", cfg)
    return mssql_module.MssqlConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def _tail(script: _MssqlScript) -> list[Any]:
    return [e for e in script.log if isinstance(e, str)]


# F35: roll back explicitly, and notice a batch that carried more statements.


def test_f35_connect_never_enables_autocommit(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript()
    conn = _mssql(monkeypatch, script)
    conn._connect()
    assert script.connect_kwargs.get("autocommit") is not True
    assert script.conn is not None and script.conn.autocommit is False, "set explicitly, not left to a default"


def test_f35_single_result_returns_rows_and_rolls_back_before_close(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(rows=[(1,), (2,)])
    out = _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT v FROM t"))
    assert out.rows == [[1], [2]]
    assert _tail(script) == ["nextset", "rollback", "close"]
    assert "commit" not in script.log


def test_f35_a_second_result_set_is_refused_and_rolled_back(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(more_results=True)
    with pytest.raises(ConnectorError, match="more than one statement") as exc:
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT 1 DELETE FROM dbo.t"))
    assert getattr(exc.value, "category", None) == "POLICY_VIOLATION"
    assert _tail(script) == ["nextset", "rollback", "close"]


def test_f35_an_error_from_a_later_statement_is_refused_and_rolled_back(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(later_error=True)
    with pytest.raises(ConnectorError, match="more than one statement") as exc:
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT 1 DELETE FROM dbo.t"))
    assert getattr(exc.value, "category", None) == "POLICY_VIOLATION"
    assert "(229)" in str(exc.value), "keep the server's own reason for the operator"
    assert _tail(script) == ["nextset", "rollback", "close"]


def test_f35_rollback_precedes_close_when_the_statement_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(execute_error=True)
    with pytest.raises(ConnectorError):
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT v FROM t"))
    assert _tail(script) == ["rollback", "close"]


def test_f35_truncated_result_is_not_drained_to_look_for_more(monkeypatch: pytest.MonkeyPatch) -> None:
    """Draining the rest of a truncated result set would make the server run
    whatever follows it; the rollback is the backstop there."""
    script = _MssqlScript(rows=[(i,) for i in range(10)], more_results=True)
    out = _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT v FROM t", max_rows=3))
    assert out.truncated and len(out.rows) == 3
    assert _tail(script) == ["rollback", "close"]


def test_f35_pyodbc_pooling_is_off_before_the_first_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 1: with pyodbc's default pooling every per-query
    connection was the same server session: one 'SET NOCOUNT ON' disabled the
    detection above for every later call, and a query's TEXTSIZE cut catalog
    reads to 8193 characters."""
    seen: list[Any] = []

    def connect(*_a: Any, **_k: Any) -> _FakeMssqlConn:
        seen.append(fake.pooling)
        return _FakeMssqlConn(_MssqlScript())

    fake: Any = types.SimpleNamespace(
        pooling=True, drivers=lambda: ["ODBC Driver 18 for SQL Server"], Error=_FakePyodbcError, connect=connect,
    )
    monkeypatch.setattr(mssql_module, "open_module", lambda *_a, **_k: fake)
    resolved = _resolved({"type": "mssql", "host": "h", "database": "d"})
    mssql_module.MssqlConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))._connect()
    assert seen == [False]


def test_f35_every_connection_first_resets_what_the_connector_relies_on(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript()
    _mssql(monkeypatch, script)._connect()
    executed = [e[1] for e in script.log if isinstance(e, tuple)]
    assert executed[0] == "SET NOCOUNT OFF; SET TEXTSIZE -1"


# F08 (SQL Server xml): TEXTSIZE does not apply to xml, so xml columns are
# cast to nvarchar(max) where the statement names them.

_XML_OUT = "CAST({} AS nvarchar(max))"


def _mssql_executed(script: _MssqlScript) -> list[tuple[str, Any]]:
    return [(e[1], e[2]) for e in script.log if isinstance(e, tuple) and not e[1].startswith("SET ")]


@pytest.mark.parametrize(
    ("sql", "described", "cast"),
    [
        (
            "SELECT CAST(REPLICATE(CAST('<a>x</a>' AS nvarchar(max)), 50000000) AS xml) AS big, 1 AS n",
            [("big", 241), ("n", 56)],
            "SELECT CAST(CAST(REPLICATE(CAST('<a>x</a>' AS nvarchar(max)), 50000000) AS xml) AS nvarchar(max)) "
            "AS [big], 1 AS n",
        ),
        (
            "SELECT (SELECT REPLICATE(CAST('x' AS nvarchar(max)), 100000000) AS a FOR XML PATH(''), TYPE) AS big;",
            [("big", 241)],
            "SELECT CAST((SELECT REPLICATE(CAST('x' AS nvarchar(max)), 100000000) AS a FOR XML PATH(''), TYPE) "
            "AS nvarchar(max)) AS [big]",
        ),
        (
            "SELECT TOP 5 * FROM dbo.Docs ORDER BY id",
            [("id", 56), ("body]", 241)],
            "SELECT TOP 5 [id], CAST([body]]] AS nvarchar(max)) AS [body]]] FROM dbo.Docs ORDER BY id",
        ),
        (
            "SELECT d.id, body = d.doc.query('/a') FROM dbo.Docs d",
            [("id", 56), ("body", 241)],
            "SELECT d.id, CAST(d.doc.query('/a') AS nvarchar(max)) AS [body] FROM dbo.Docs d",
        ),
    ],
)
def test_f08_mssql_xml_columns_are_cast_so_textsize_cuts_them(
    monkeypatch: pytest.MonkeyPatch, sql: str, described: list[tuple[str | None, int]], cast: str
) -> None:
    """Review round 1: FOR XML ... TYPE and CAST(... AS xml) were read whole
    (maxrss 41 -> 1197 MB live for a 164 KB response)."""
    script = _MssqlScript(rows=[("x" * 20,)], described=described)
    out = _mssql(monkeypatch, script).execute_query(QuerySpec(sql=sql, max_cell_bytes=10))
    executed = _mssql_executed(script)
    assert executed[0] == ("EXEC sys.sp_describe_first_result_set @tsql = ?, @params = ?", [sql, None])
    assert executed[1] == (cast, None)
    assert out.truncated


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT CAST(x AS xml) AS doc FROM t UNION ALL SELECT CAST(y AS xml) FROM u",
        "SELECT * FROM dbo.Docs d JOIN dbo.More m ON m.id = d.id",
        "SELECT 'x' AS a FOR XML PATH(''), TYPE",
    ],
)
def test_f08_mssql_xml_that_cannot_be_cast_is_refused_before_it_runs(monkeypatch: pytest.MonkeyPatch, sql: str) -> None:
    script = _MssqlScript(described=[("doc", 241)] if "UNION" in sql else (
        [("id", 56), ("doc", 241), ("id", 56)] if "JOIN" in sql else [(None, 241)]))
    with pytest.raises(ConnectorError, match="xml") as exc:
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql=sql))
    assert exc.value.category == "QUERY_ERROR"
    assert "nvarchar(max)" in str(exc.value), "the message says how to ask for the value instead"
    assert [e[0] for e in _mssql_executed(script)] == ["EXEC sys.sp_describe_first_result_set @tsql = ?, @params = ?"]
    assert _tail(script) == ["rollback", "close"]


def test_f08_mssql_describe_declares_the_bound_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    sql = "SELECT doc FROM t WHERE id = ? AND name LIKE ? AND note = '?'"
    params = [1, "a%"]
    script = _MssqlScript(rows=[("<a/>",)], described=[("doc", 241)])
    _mssql(monkeypatch, script).execute_query(QuerySpec(sql=sql, parameters=params))
    assert _mssql_executed(script) == [
        (
            "EXEC sys.sp_describe_first_result_set @tsql = ?, @params = ?",
            [
                "SELECT doc FROM t WHERE id = @udbmcp_p1 AND name LIKE @udbmcp_p2 AND note = '?'",
                "@udbmcp_p1 bigint, @udbmcp_p2 nvarchar(max)",
            ],
        ),
        ("SELECT CAST(doc AS nvarchar(max)) AS [doc] FROM t WHERE id = ? AND name LIKE ? AND note = '?'", params),
    ]


def test_f08_mssql_markers_that_do_not_match_the_values_are_refused_undescribed(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _MssqlScript(rows=[("<a/>",)], described=[("doc", 241)])
    with pytest.raises(ConnectorError, match="markers") as exc:
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT doc FROM t WHERE id = ?", parameters=[1, 2]))
    assert exc.value.category == "QUERY_ERROR"
    assert _mssql_executed(script) == [], "neither described nor run"
    script = _MssqlScript(rows=[("<a/>",)], described=[("doc", 241)])
    with pytest.raises(ConnectorError):
        _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT doc FROM t WHERE id = ?", parameters={"a": 1}))
    assert [e[0] for e in _mssql_executed(script)] == ["SELECT doc FROM t WHERE id = ?"], (
        "a dict is left to pyodbc, which refuses it before anything runs"
    )


def test_f08_mssql_statements_without_xml_run_as_written(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(rows=[("x",)], described=[("v", 231), ("w", 99)])
    _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT v, w FROM t"))
    assert [e[0] for e in _mssql_executed(script)][-1] == "SELECT v, w FROM t"


# F75: the row estimate belongs to one schema's table.


def test_f75_mssql_statistics_bind_the_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(one=(1_000_000,))
    stats = _mssql(monkeypatch, script).get_statistics("dbo", "Orders")
    sql, params = [(e[1], e[2]) for e in script.log if isinstance(e, tuple) and "sys.partitions" in e[1]][0]
    assert "sys.schemas" in sql
    assert params == ["dbo", "Orders"]
    assert stats["row_estimate"] == 1_000_000


def test_f75_mssql_statistics_of_a_bare_name_use_the_default_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no allowlist the server asks for a bare name with schema None;
    'WHERE s.name = NULL' matched nothing. SQL Server resolves a bare name in
    the login's default schema and then in dbo (review round 4: a login whose
    default schema is 'app' got no estimate for dbo.Orders), so the estimate
    does too, preferring the default schema."""
    script = _MssqlScript(one=(42,))
    stats = _mssql(monkeypatch, script).get_statistics(None, "Orders")
    sql, params = [(e[1], e[2]) for e in script.log if isinstance(e, tuple) and "sys.partitions" in e[1]][0]
    assert f"s.name = {mssql_module._BARE_NAME_SCHEMA} AND t.name = ?" in sql
    assert "s.name IN (SCHEMA_NAME(), N'dbo')" in mssql_module._BARE_NAME_SCHEMA
    assert mssql_module._BARE_NAME_SCHEMA.endswith("ORDER BY CASE WHEN s.name = SCHEMA_NAME() THEN 0 ELSE 1 END)")
    assert params == ["Orders", "Orders"]
    assert stats["row_estimate"] == 42


class _BareNameCursor(_FakeMssqlCursor):
    """dbo.Patients as SQL Server reports it: a bound NULL matches nothing
    ('table_schema = NULL' is unknown, not true)."""

    def execute(self, sql: str, *params: Any) -> None:
        super().execute(sql, *params)
        bound = list(params[0]) if params else []
        self._one = self._s.one
        if None in bound:
            self._pending, self._one = [], None
        elif sql == f"SELECT {mssql_module._BARE_NAME_SCHEMA}":
            self._one = ("dbo",)
        elif "INFORMATION_SCHEMA.COLUMNS" in sql:
            self._pending = [
                ("PatientId", "int", "NO", None, 1, None, 10, 0, "dbo"),
                ("Name", "nvarchar", "YES", None, 2, 100, None, None, "dbo"),
            ]
        elif "sys.indexes" in sql:
            self._pending = [("Patients", "PK_Patients", 1, 1, "CLUSTERED", "PatientId", 1, "dbo")]
        elif "sys.foreign_keys" in sql:
            self._pending = [("FK_Patients_Wards", "dbo", "Patients", "dbo", "Wards", "WardId", "WardId")]

    def fetchone(self) -> Any:
        return self._one


def test_f75_mssql_columns_indexes_and_keys_of_a_bare_name_use_the_default_schema(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 5: the statistics resolved a bare name, but list_columns
    bound 'table_schema = NULL' (and list_indexes 's.name = NULL'), so
    db_get_table {object_name: 'Patients'} failed with "table 'None.Patients'
    not found or not visible" before the estimate mattered (live, HospitalDB).
    Every catalog read of a bare name now resolves it the way SQL Server does."""
    monkeypatch.setattr(_FakeMssqlConn, "cursor", lambda self: _BareNameCursor(self._s))
    script = _MssqlScript(one=(5,))
    conn = _mssql(monkeypatch, script)

    def statements(marker: str) -> list[tuple[str, list[Any]]]:
        return [(e[1], e[2]) for e in script.log if isinstance(e, tuple) and marker in e[1]]

    cols = conn.list_columns(None, "Patients")
    assert [(c.schema, c.name) for c in cols] == [("dbo", "PatientId"), ("dbo", "Name")]
    idx = conn.list_indexes(None, "Patients")
    assert [(i.schema, i.table, i.name) for i in idx] == [("dbo", "Patients", "PK_Patients")]
    for marker in ("INFORMATION_SCHEMA.COLUMNS", "sys.indexes"):
        sql, params = statements(marker)[-1]
        assert mssql_module._BARE_NAME_SCHEMA in sql, marker
        assert params == ["Patients", "Patients"], (marker, params)
    script.log.clear()
    detail = conn.get_table(None, "Patients")
    assert detail["schema"] == "dbo", "resolved once, then passed down"
    assert [c["name"] for c in detail["columns"]] == ["PatientId", "Name"]
    assert [fk["name"] for fk in detail["foreign_keys"]] == ["FK_Patients_Wards"]
    assert detail["statistics"]["row_estimate"] == 5
    assert len(statements("sys.objects")) == 1
    for marker in ("INFORMATION_SCHEMA.COLUMNS", "sys.foreign_keys", "sys.partitions"):
        assert statements(marker)[-1][1] == ["dbo", "Patients"], marker
    script.log.clear()
    assert [c.schema for c in conn.list_columns("app", "Patients")] == ["app", "app"]
    sql, params = [(e[1], e[2]) for e in script.log if isinstance(e, tuple)][-1]
    assert mssql_module._BARE_NAME_SCHEMA not in sql and params == ["app", "Patients"]


class _MssqlCatalogCursor:
    """information_schema.tables of one database, and the catalog views
    sys.all_objects adds for the schemas the statement binds after the kinds."""

    user = [("dbo", "Orders", "BASE TABLE"), ("app", "v_orders", "VIEW")]
    catalog = [("sys", "objects", "VIEW"), ("sys", "tables", "VIEW"), ("INFORMATION_SCHEMA", "TABLES", "VIEW")]

    def __init__(self, log: list[tuple[str, list[Any]]]) -> None:
        self.log = log
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, params: list[Any]) -> None:
        self.log.append((sql, list(params)))
        kinds = params[: sql.split("TABLE_TYPE IN (", 1)[1].split(")", 1)[0].count("?")]
        self.rows = [r for r in self.user if r[2] in kinds]
        if "sys.all_objects" in sql:
            n = sql.split("s.name IN (", 1)[1].split(")", 1)[0].count("?")
            opened = params[len(kinds) : len(kinds) + n]
            self.rows += [r for r in self.catalog if r[0] in opened]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows


@pytest.mark.parametrize(
    ("opened", "listed"),
    [
        (None, {"dbo", "app", "INFORMATION_SCHEMA"}),  # the default: [information_schema]
        (["information_schema", "sys"], {"dbo", "app", "INFORMATION_SCHEMA", "sys"}),
        ([], {"dbo", "app"}),
    ],
)
def test_f26_mssql_lists_the_catalog_views_the_administrator_allowed(
    monkeypatch: pytest.MonkeyPatch, opened: list[str] | None, listed: set[str]
) -> None:
    """Review round 4: list_tables read information_schema.tables, which never
    lists the INFORMATION_SCHEMA or sys views, and the resolver permits only
    listed objects: live, with allowed_system_schemas [information_schema,
    sys], 'SELECT * FROM sys.objects' could not be resolved."""
    conn = _mssql(monkeypatch, _MssqlScript())
    security = SecurityConfig() if opened is None else SecurityConfig(allowed_system_schemas=opened)
    conn.policy = EffectivePolicy.build(security, conn.connection)
    log: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(
        conn, "_connect", lambda: types.SimpleNamespace(cursor=lambda: _MssqlCatalogCursor(log), close=lambda: None)
    )
    assert {t.schema for t in conn.list_tables(None, {"table", "view"}, None)} == listed
    assert {t.schema for t in conn.list_tables(None, {"table"}, None)} == {"dbo"}, "catalog views are views"
    conn.list_tables("sys", {"view"}, "obj")
    sql, params = log[-1]
    if "sys.all_objects" in sql:  # the schema and search filters apply to the catalog views too
        assert sql.endswith("AND s.name = ? AND o.name LIKE ?") and params[-2:] == ["sys", "%obj%"]
    else:
        assert opened == []


# =================================================================== part 2
# F08, F17, F30, F34, F36, F37: what a query may cost the process, how its
# failures are classified, and how long a connect or a statement may take.


class _Col(tuple):  # type: ignore[type-arg]
    """A DB-API description entry (name, type_code, display_size,
    internal_size, precision, scale, null_ok) that also answers psycopg's
    attribute names."""

    name: str
    type_code: Any
    display_size: Any

    def __new__(cls, name: str, type_code: Any, size: int | None = None, display: int | None = None) -> _Col:
        self = super().__new__(cls, (name, type_code, display, size, size, None, True))
        self.name = name
        self.type_code = type_code
        self.display_size = display
        return self


class _Rows:
    """What a fake server answers and what the connector asked it for.
    ``answers`` overrides the rows/description per statement text."""

    def __init__(self, rows: list[tuple[Any, ...]], description: list[_Col]) -> None:
        self.rows = rows
        self.description = description
        self.answers: dict[str, tuple[list[tuple[Any, ...]], list[_Col]]] = {}
        self.fail: Callable[[str], BaseException | None] = lambda _sql: None
        self.statements: list[tuple[str, Any]] = []
        self.fetch_sizes: list[int] = []
        self.log: list[str] = []
        self.blocked: threading.Event | None = None  # fetchmany waits on it when set
        self.fetching = threading.Event()


class _RowCursor:
    def __init__(self, state: _Rows) -> None:
        self._s = state
        self.description: list[_Col] | None = None
        self._pending: list[tuple[Any, ...]] = []
        self.connection: Any = "bound"
        self.arraysize = 100
        self.prefetchrows = 2

    def __enter__(self) -> _RowCursor:
        return self

    def __exit__(self, *_a: object) -> None:
        self.close()

    def execute(self, sql: str, params: Any = None) -> None:
        self._s.statements.append((sql, params))
        if sql.startswith(("SET ", "KILL ")):
            return
        if (exc := self._s.fail(sql)) is not None:
            raise exc
        rows, desc = self._s.answers.get(sql, (self._s.rows, self._s.description))
        self.description = list(desc)
        self._pending = list(rows)

    def fetchmany(self, n: int) -> list[tuple[Any, ...]]:
        self._s.fetch_sizes.append(n)
        self._s.fetching.set()
        if self._s.blocked is not None:
            self._s.blocked.wait(5)
        batch, self._pending = self._pending[:n], self._pending[n:]
        return batch

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._pending.pop(0) if self._pending else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending, []
        return rows

    def nextset(self) -> bool:
        return False

    def close(self) -> None:
        self._s.log.append("cursor.close")


class _RowConn:
    def __init__(self, state: _Rows, adapters: Any = None) -> None:
        self._s = state
        self.adapters = adapters
        self.autocommit = False

    def cursor(self, name: str | None = None) -> _RowCursor:
        return _RowCursor(self._s)

    def thread_id(self) -> int:
        return 4242

    def cancel(self) -> None:
        self._s.log.append("cancel")

    def rollback(self) -> None:
        self._s.log.append("rollback")

    def close(self) -> None:
        self._s.log.append("close")


def _resolved(body: dict[str, Any], name: str = "c") -> ResolvedConnection:
    return ResolvedConnection(name, ConnectionConfig.model_validate(body))


def _pg(monkeypatch: pytest.MonkeyPatch, state: _Rows) -> pg_module.PostgresConnector:
    psycopg = pytest.importorskip("psycopg")
    resolved = _resolved({"type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True}})
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    monkeypatch.setattr(conn, "_connect", lambda: _RowConn(state, psycopg.adapters))
    return conn


def _my(monkeypatch: pytest.MonkeyPatch, state: _Rows) -> mysql_module.MySQLConnector:
    resolved = _resolved({"type": "mysql", "host": "h", "database": "d", "options": {"os_authentication": True}})
    conn = mysql_module.MySQLConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    monkeypatch.setattr(conn, "_connect", lambda: _RowConn(state))
    return conn


def _db2_dbi(monkeypatch: pytest.MonkeyPatch, state: _Rows) -> types.ModuleType:
    """ibm_db_dbi stand-in: Connection(handle).cursor() reads ``state``."""
    dbi = types.ModuleType("ibm_db_dbi")

    class DataError(Exception):
        pass

    dbi.DataError = DataError  # type: ignore[attr-defined]
    dbi.Connection = lambda _raw: _RowConn(state)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", dbi)
    return dbi


class _OracleExecDb(_FakeOracleDb):
    """python-oracledb stand-in whose connections run queries from ``state``."""

    def __init__(self, state: _Rows) -> None:
        super().__init__()
        self.state = state

    def connect(self, **kwargs: Any) -> Any:
        self.connect_kwargs.append(kwargs)
        return _RowConn(self.state)


def _ora_exec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: _Rows) -> oracle_module.OracleConnector:
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=_OracleExecDb(state))
    return conn


_TEN = [(i,) for i in range(10)]


# F08 (1): no connector asks the driver for more rows than decide truncation.


def test_f08_fetch_size_follows_the_remaining_row_budget() -> None:
    assert driver_helpers.next_fetch_size(1, 0) == 2
    assert driver_helpers.next_fetch_size(1000, 0) == 200
    assert driver_helpers.next_fetch_size(500, 400) == 101
    assert driver_helpers.next_fetch_size(5, 5) == 1


def test_f08_postgres_fetches_within_the_row_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows(_TEN, [_Col("n", 23)])
    out = _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT n FROM t", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert state.fetch_sizes and max(state.fetch_sizes) <= 2, state.fetch_sizes

    state = _Rows([(i,) for i in range(1000)], [_Col("n", 23)])
    _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT n FROM t", max_rows=500))
    assert state.fetch_sizes == [200, 200, 101]


def test_f08_mysql_fetches_within_the_row_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows(_TEN, [_Col("n", 3, 11)])
    out = _my(monkeypatch, state)._execute(QuerySpec(sql="SELECT n FROM t", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert state.fetch_sizes and max(state.fetch_sizes) <= 2, state.fetch_sizes


def test_f08_db2_fetches_within_the_row_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows(_TEN, [_Col("N", int)])
    conn, _ = _db2(tmp_path, monkeypatch)
    _db2_dbi(monkeypatch, state)
    out = conn._execute(QuerySpec(sql="SELECT N FROM T", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert state.fetch_sizes and max(state.fetch_sizes) <= 2, state.fetch_sizes


@pytest.mark.parametrize("type_name", ["TEXT", "BINARY", "XML"])
def test_f08_db2_lob_results_are_fetched_one_row_at_a_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, type_name: str
) -> None:
    """Review round 1: at the default max_rows ibm_db read 200 rows of
    CLOB/BLOB values whole per fetch (36 x 10 MB: RSS delta 757 MB live)."""
    conn, _ = _db2(tmp_path, monkeypatch)
    dbi = _db2_dbi(monkeypatch, _Rows([], []))
    for name in ("TEXT", "BINARY", "XML"):
        setattr(dbi, name, frozenset({name}))  # ibm_db_dbi's DBAPITypeObject singletons
    state = _Rows([(i, "x") for i in range(10)], [_Col("N", int), _Col("DOC", getattr(dbi, type_name))])
    dbi.Connection = lambda _raw: _RowConn(state)  # type: ignore[attr-defined]
    out = conn._execute(QuerySpec(sql="SELECT n, doc FROM t", max_rows=5))
    assert len(out.rows) == 5 and out.truncated
    assert set(state.fetch_sizes) == {1}, state.fetch_sizes
    state = _Rows([(i, "x") for i in range(10)], [_Col("N", int), _Col("NAME", frozenset({"VARCHAR"}))])
    dbi.Connection = lambda _raw: _RowConn(state)  # type: ignore[attr-defined]
    conn._execute(QuerySpec(sql="SELECT n, name FROM t", max_rows=5))
    assert state.fetch_sizes[0] == 6


def test_f08_db2_rows_are_not_formatted_whole_by_the_driver_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 1: ibm_db_dbi's per-row type fix-up formats the whole row
    into a debug message even with logging off; a 10 MB CLOB then cost 17 MB
    of RSS per row that was never given back (live: 110 MB flat without it).
    The fix-up is off; its DECIMAL conversion is done by the connector."""
    conn, _ = _db2(tmp_path, monkeypatch)
    dbi = _db2_dbi(monkeypatch, _Rows([], []))
    dbi.DECIMAL = frozenset({"DECIMAL"})  # type: ignore[attr-defined]
    state = _Rows([("12,50", "7", None)], [_Col("PRICE", dbi.DECIMAL), _Col("N", int), _Col("P", dbi.DECIMAL)])
    fixed: list[bool] = []

    class _Conn(_RowConn):
        def set_fix_return_type(self, on: bool) -> None:
            fixed.append(on)

    dbi.Connection = lambda _raw: _Conn(state)  # type: ignore[attr-defined]
    out = conn._execute(QuerySpec(sql="SELECT price, n, p FROM t"))
    assert fixed == [False]
    assert out.rows == [["12.50", "7", None]], "a DECIMAL keeps its exact text, with a '.' separator"


def test_f08_mssql_fetches_within_the_row_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(rows=list(_TEN))
    out = _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT v FROM t", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert script.fetch_sizes and max(script.fetch_sizes) <= 2, script.fetch_sizes


def test_f08_oracle_fetches_and_prefetches_within_the_row_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _Rows(_TEN, [_Col("N", int)])
    seen: list[tuple[int, int]] = []
    real_execute = _RowCursor.execute

    def execute(cur: _RowCursor, sql: str, params: Any = None) -> None:
        seen.append((cur.arraysize, cur.prefetchrows))  # both must be set BEFORE execute
        real_execute(cur, sql, params)

    monkeypatch.setattr(_RowCursor, "execute", execute)
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(QuerySpec(sql="SELECT n FROM t", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert state.fetch_sizes and max(state.fetch_sizes) <= 2, state.fetch_sizes
    # python-oracledb fetches prefetchrows rows with the execute (before the
    # columns are known: two, so one row and the end of the result take one
    # round trip) and arraysize rows per round trip after it
    assert seen[-1] == (2, 2)


def _ora_fetch_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: _Rows, spec: QuerySpec, *, thin: bool = True
) -> tuple[Any, list[int]]:
    """Run a query; the rows each fetch asked for, with arraysize matching."""
    sizes: list[int] = []
    real_fetchmany = _RowCursor.fetchmany

    def fetchmany(cur: _RowCursor, n: int) -> list[tuple[Any, ...]]:
        assert cur.arraysize == n, "one round trip per fetch"
        sizes.append(n)
        return real_fetchmany(cur, n)

    monkeypatch.setattr(_RowCursor, "fetchmany", fetchmany)
    monkeypatch.setattr(_RowConn, "thin", thin, raising=False)
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(spec)
    return out, sizes


@pytest.mark.parametrize("type_name", ["DB_TYPE_JSON", "DB_TYPE_LONG", "DB_TYPE_LONG_RAW", "DB_TYPE_OBJECT"])
def test_f08_oracle_values_decoded_whole_start_one_row_at_a_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, type_name: str
) -> None:
    """Review round 1: native JSON (JSON_ARRAYAGG ... RETURNING JSON) is
    decoded whole for every row of a fetch before the cell cap applies:
    maxrss 79 -> 1912 MB live for a 164 KB response. After the execute the
    columns are known, and such a result starts at one row per fetch (live,
    20 rows of 30 MB: 1280 -> 247 MB)."""
    state = _Rows([(i, "{}") for i in range(10)], [_Col("N", int), _Col("DOC", _FakeDbType(type_name))])
    out, sizes = _ora_fetch_sizes(tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, doc FROM t", max_rows=5))
    assert len(out.rows) == 5 and out.truncated
    assert sizes[:2] == [1, 2], sizes
    state = _Rows(_TEN, [_Col("N", int), _Col("C", _FakeDbType("DB_TYPE_CLOB"))])
    _out, sizes = _ora_fetch_sizes(tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, c FROM t", max_rows=5))
    assert sizes[0] == 6, "a LOB locator is read up to the cell limit: batches stay"


def test_f08_oracle_small_values_decoded_whole_do_not_cost_a_round_trip_per_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: one row per fetch made 1000 small JSON rows take
    0.465 s instead of 0.059 s on loopback (a round trip each: 20-50 s over a
    WAN). The batch doubles while those values stay within the cell limit,
    up to 4 rows (review round 3: see the test below)."""
    state = _Rows([(i, {"n": i}) for i in range(1000)], [_Col("N", int), _Col("DOC", _FakeDbType("DB_TYPE_JSON"))])
    out, sizes = _ora_fetch_sizes(tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, doc FROM t", max_rows=1000))
    assert len(out.rows) == 1000 and not out.truncated
    assert sizes[:5] == [1, 2, 4, 4, 4], sizes
    assert max(sizes) == oracle_module._WHOLE_BATCH_MAX == 4
    assert len(sizes) <= 255, f"{len(sizes)} round trips for 1000 rows"


def test_f08_oracle_a_value_decoded_whole_past_the_cell_limit_returns_to_one_row_per_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [(i, "x" * (20_000 if i == 10 else 10)) for i in range(200)]
    state = _Rows(rows, [_Col("N", int), _Col("TEXT", _FakeDbType("DB_TYPE_LONG"))])
    out, sizes = _ora_fetch_sizes(tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, text FROM v", max_rows=200))
    assert len(out.rows) == 200 and out.truncated
    assert sizes[:4] == [1, 2, 4, 4], "rows 0-10: the last 4-row fetch carries the 20 KB value (row 10)"
    assert set(sizes[4:]) == {1}, "the rest of the result comes one row at a time"


@pytest.mark.parametrize(("thin", "first"), [(True, 6), (False, 1)])
def test_f08_oracle_xmltype_is_decoded_whole_only_in_thick_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thin: bool, first: int
) -> None:
    """Review round 2: Thin mode reads an XMLType through a LOB (live: 20
    rows of a 6 MB XMLType at arraysize 20, maxrss 40 MB), so it needs no
    one-row fetch; Thick mode is not measured and keeps it."""
    state = _Rows([(i, "<a/>") for i in range(10)], [_Col("N", int), _Col("X", _FakeDbType("DB_TYPE_XMLTYPE"))])
    _out, sizes = _ora_fetch_sizes(
        tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, x FROM t", max_rows=5), thin=thin
    )
    assert sizes[0] == first, sizes


def test_f08_sqlite_fetches_within_the_row_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "t.db"
    with sqlite3.connect(db) as setup:
        setup.execute("CREATE TABLE t (n INTEGER)")
        setup.executemany("INSERT INTO t VALUES (?)", _TEN)
    resolved = _resolved({"type": "sqlite", "database": str(db)})
    conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    sizes: list[int] = []
    real_open = SQLiteConnector._open

    class _Cur:
        def __init__(self, cur: sqlite3.Cursor) -> None:
            self._cur = cur
            self.description = cur.description

        def fetchmany(self, n: int) -> list[Any]:
            sizes.append(n)
            return self._cur.fetchmany(n)

        def fetchone(self) -> Any:
            sizes.append(1)
            return self._cur.fetchone()

    class _Conn:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real

        def execute(self, sql: str, params: Any = ()) -> _Cur:
            return _Cur(self._real.execute(sql, params))

        def create_function(self, *args: Any, **kwargs: Any) -> None:
            self._real.create_function(*args, **kwargs)

        def interrupt(self) -> None:
            self._real.interrupt()

        def close(self) -> None:
            self._real.close()

    monkeypatch.setattr(SQLiteConnector, "_open", lambda self: _Conn(real_open(self)))
    out = conn.execute_query(QuerySpec(sql="SELECT n FROM t ORDER BY n", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    assert sizes and max(sizes) <= 2, sizes
    assert sum(sizes) <= 2, "rows past the one that proves truncation are never fetched"


# F08 (2): one adaptation per cell, and a huge text value is cut without
# being encoded or copied whole.


def test_f08_each_cell_is_adapted_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    real = driver_helpers._adapt_one

    def spy(v: Any, max_cell_bytes: int) -> tuple[Any, str, bool]:
        calls.append(v)
        return real(v, max_cell_bytes)

    monkeypatch.setattr(driver_helpers, "_adapt_one", spy)
    state = _Rows([("x" * 50, 1), ("y" * 50, 2), ("z", 3)], [_Col("note", 25), _Col("id", 23)])
    script = _MssqlScript(rows=[("x" * 50, 1), ("y" * 50, 2), ("z", 3)])
    out = _mssql(monkeypatch, script).execute_query(QuerySpec(sql="SELECT note, id FROM t", max_cell_bytes=10))
    assert out.truncated and any("exceeded" in w for w in out.warnings)
    assert len(calls) == 6, f"{len(calls)} adaptations for 6 cells: truncated rows were adapted twice"
    calls.clear()
    out = _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT note, id FROM t", max_cell_bytes=10))
    assert out.truncated
    assert len(calls) == 6


def test_f08_ten_million_characters_are_cut_without_copying_them() -> None:
    for big in ("x" * 10_000_000, "é" * 5_000_000):
        tracemalloc.start()
        try:
            vals, _labels, cut = driver_helpers.cell_truncated_json([big], 8192)
            _now, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert cut is True
        assert len(vals[0].encode("utf-8")) <= 8192
        assert peak < 1_000_000, f"peak {peak} bytes: the whole value was encoded or copied"


@pytest.mark.parametrize(
    ("value", "cut"),
    [("x" * 8192, False), ("x" * 8193, True), ("é" * 4096, False), ("é" * 4097, True), ("\U0001f600" * 2049, True)],
)
def test_f08_cell_limit_is_exact_in_bytes(value: str, cut: bool) -> None:
    vals, _labels, truncated = driver_helpers.cell_truncated_json([value], 8192)
    assert truncated is cut
    assert len(vals[0].encode("utf-8")) <= 8192
    if not cut:
        assert vals[0] == value
    else:
        assert value.startswith(vals[0])


def test_f08_a_bytearray_is_cut_without_copying_it() -> None:
    blob = bytearray(20_000_000)
    tracemalloc.start()
    try:
        vals, _labels, cut = driver_helpers.cell_truncated_json([blob, memoryview(bytes(10))], 8192)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert cut is True and vals[0]["$truncated"] is True
    assert len(base64.b64decode(vals[0]["$binary_b64"])) == 8192
    assert base64.b64decode(vals[1]["$binary_b64"]) == bytes(10)
    assert peak < 1_000_000, f"peak {peak} bytes"


def test_f08_a_decoded_json_value_is_serialized_only_up_to_the_cell_limit() -> None:
    """Review round 1: a driver-decoded JSON value (Oracle native JSON,
    ClickHouse arrays) was serialized whole with json.dumps before the cut."""
    doc = {"items": ["x" * 3000 + str(i) for i in range(10_000)], "n": 1}
    tracemalloc.start()
    try:
        vals, labels, cut = driver_helpers.adapt_row([doc, [1, "é", None]], 8192)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert cut == [0] and labels == ["json", "array"]
    assert len(vals[0].encode()) == 8192 and vals[0].startswith('{"items": ["xxx')
    assert vals[1] == '[1, "\\u00e9", null]', "the form a caller saw before: json.dumps"
    assert peak < 1_000_000, f"peak {peak} bytes"


def test_f08_a_cut_json_value_is_not_kept_alive_after_the_cut() -> None:
    """An encoder stopped part-way must not keep the document it was
    encoding referenced (json's circular-reference markers sit in a closure
    cycle): live, each 30 MB Oracle JSON row stayed in memory until the
    cyclic collector ran."""
    import gc

    gc.disable()
    tracemalloc.start()
    try:
        doc = ["x" * 3000 + str(i) for i in range(5_000)]
        driver_helpers.adapt_row([doc], 8192)
        del doc
        now, _peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        gc.enable()
    assert now < 1_000_000, f"{now} bytes still referenced"


# F08 (3): values are bounded where the engine produces them.


def test_f08_mssql_bounds_max_values_on_the_server_for_queries_only(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(rows=[(1,)])
    conn = _mssql(monkeypatch, script)
    conn.execute_query(QuerySpec(sql="SELECT v FROM t", max_cell_bytes=8192))
    sets = [e[1] for e in script.log if isinstance(e, tuple) and e[0] == "execute" and "TEXTSIZE" in e[1]]
    # nvarchar(max) travels as UTF-16: twice the byte budget still carries
    # max_cell_bytes + 1 characters, so a cut is always detected client-side
    assert sets == ["SET NOCOUNT OFF; SET TEXTSIZE -1", f"SET TEXTSIZE {2 * (8192 + 1)}"]
    query_at = next(i for i, e in enumerate(script.log) if isinstance(e, tuple) and e[1] == "SELECT v FROM t")
    set_at = next(i for i, e in enumerate(script.log) if isinstance(e, tuple) and e[1].startswith("SET TEXTSIZE 1"))
    assert set_at < query_at
    script.log.clear()
    conn._connect()  # metadata connections read whole definitions (sys.sql_modules)
    assert [e[1] for e in script.log if isinstance(e, tuple) and "TEXTSIZE" in e[1]] == [
        "SET NOCOUNT OFF; SET TEXTSIZE -1"
    ], "a metadata connection never inherits a query's TEXTSIZE"


_PG_ORIGINAL = "SELECT ssn, id, doc, tags, payload, \"odd \"\"name\"\"\", code, born FROM t ORDER BY id;"


def _pg_wrapper_state() -> _Rows:
    desc = [
        _Col("ssn", 25), _Col("id", 23), _Col("doc", 17), _Col("tags", 1007), _Col("payload", 3802),
        _Col('odd "name"', 1043), _Col("code", 1043, display=10), _Col("born", 1082),
    ]
    state = _Rows([], desc)
    state.rows = [("123-45-6789", 1, b"\x01", "[1,2]", {"a": 1}, "o", "c", datetime.date(2024, 1, 1))]
    return state


def test_f08_postgres_caps_unbounded_columns_server_side_and_keeps_names(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _pg_wrapper_state()
    out = _pg(monkeypatch, state)._execute(QuerySpec(sql=_PG_ORIGINAL, max_cell_bytes=100))
    declared = [sql for sql, _ in state.statements]
    assert declared[0] == _PG_ORIGINAL, "the statement as written is declared (planned, not run) to describe it"
    wrapped = declared[-1]
    assert wrapped.startswith("SELECT left(udbmcp_q.c1::text, 101) AS \"ssn\", udbmcp_q.c2 AS \"id\", ")
    assert "substring(udbmcp_q.c3 FROM 1 FOR 101) AS \"doc\"" in wrapped
    assert "left(to_json(udbmcp_q.c4)::text, 101) AS \"tags\"" in wrapped, "arrays keep a JSON form"
    assert (
        "CASE WHEN COALESCE(octet_length(udbmcp_q.c5::text), 0) <= 100 THEN udbmcp_q.c5 "
        "ELSE to_jsonb(left(udbmcp_q.c5::text, 101)) END AS \"payload\""
    ) in wrapped, "jsonb stays jsonb unless it is too long"
    assert "left(udbmcp_q.c6::text, 101) AS \"odd \"\"name\"\"\"" in wrapped
    assert "udbmcp_q.c7 AS \"code\"" in wrapped, "varchar(10) cannot exceed the cell limit"
    assert "udbmcp_q.c8 AS \"born\"" in wrapped
    assert wrapped.endswith(
        "FROM (SELECT * FROM (\n"
        "SELECT ssn, id, doc, tags, payload, \"odd \"\"name\"\"\", code, born FROM t ORDER BY id\n"
        ") AS udbmcp_s OFFSET 0) AS udbmcp_q(c1, c2, c3, c4, c5, c6, c7, c8)"
    ), "the jsonb cut reads its column three times: the statement is fenced so it is computed once"
    # names and type labels are the statement's own, so name-based masking still applies
    assert out.columns == [
        ("ssn", "text"), ("id", "integer"), ("doc", "blob"), ("tags", "unknown"), ("payload", "text"),
        ('odd "name"', "text"), ("code", "text"), ("born", "date"),
    ]
    from universal_db_mcp.server import _apply_masking

    resolved = _resolved({"type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True}})
    cols, rows = _apply_masking(
        EffectivePolicy.build(SecurityConfig(), resolved), out.columns, out.rows, {"warnings": []}
    )
    assert rows[0][0] == "<masked>" and cols[0][0] == "ssn"
    assert rows[0][1] == 1


def test_f08_postgres_bounded_columns_are_not_rewritten(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([(1, datetime.date(2024, 1, 1))], [_Col("id", 23), _Col("born", 1082)])
    _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT id, born FROM t"))
    assert [sql for sql, _ in state.statements] == ["SELECT id, born FROM t"], "one DECLARE, run as written"


def test_f08_postgres_wrapper_doubles_percent_only_when_parameters_are_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([("x",)], [_Col("100%", 25)])
    _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT n AS \"100%\" FROM t WHERE id = %s", parameters=[1]))
    assert 'AS "100%%"' in state.statements[-1][0] and state.statements[-1][1] == (1,)
    state = _Rows([("x",)], [_Col("100%", 25)])
    _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT n AS \"100%\" FROM t"))
    assert 'AS "100%"' in state.statements[-1][0] and '"100%%"' not in state.statements[-1][0]


_PG_CAPPED_T = 'SELECT left(udbmcp_q.c1::text, 11) AS "t" FROM (\nSELECT t FROM x\n) AS udbmcp_q(c1)'


@pytest.mark.parametrize("tail", [";", ";;", "; ;", ";\n;", "; -- trailing comment", ";\n/* c */ ;", " -- c"])
def test_f08_postgres_text_after_the_statement_does_not_escape_the_cap(
    monkeypatch: pytest.MonkeyPatch, tail: str
) -> None:
    """Review round 1: the guard and PostgreSQL accept 'SELECT ...;;'; the
    rewrite kept all but the last ';', failed to parse, and the statement
    then ran uncapped (maxrss 78 -> 2774 MB live)."""
    state = _Rows([("x" * 50,)], [_Col("t", 25)])
    sql = "SELECT t FROM x" + tail
    out = _pg(monkeypatch, state)._execute(QuerySpec(sql=sql, max_cell_bytes=10))
    assert [s for s, _ in state.statements] == [sql, _PG_CAPPED_T]
    assert out.rows == [["x" * 10]] and out.truncated


@pytest.mark.parametrize(
    ("error", "category"),
    [("SyntaxError", "QUERY_ERROR"), ("QueryCanceled", "TIMEOUT"), ("InsufficientPrivilege", "QUERY_ERROR")],
)
def test_f08_postgres_never_runs_the_statement_uncapped_when_the_capped_one_fails(
    monkeypatch: pytest.MonkeyPatch, error: str, category: str
) -> None:
    """Fail closed: neither a rewrite the server refuses nor a cancel while
    it is declared is a reason to run the statement with values uncut."""
    psycopg = pytest.importorskip("psycopg")
    state = _Rows([("x",)], [_Col("t", 25)])
    err = getattr(psycopg.errors, error)("refused")
    state.fail = lambda s: err if s.startswith("SELECT left(") else None
    with pytest.raises(ConnectorError) as exc:
        _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT t FROM x;;", max_cell_bytes=10))
    assert [s for s, _ in state.statements] == ["SELECT t FROM x;;", _PG_CAPPED_T], "no third, uncapped DECLARE"
    assert not state.fetch_sizes
    assert exc.value.category == category
    assert "close" in state.log


_MY_DESC = [
    _Col("ssn", 252, 262140), _Col("id", 3, 11), _Col("doc", 251, 4294967295), _Col("note", 253, 80),
    _Col("j", 245, 4294967295), _Col("g", 255, 4294967295), _Col("w`eird%", 253, 40000),
]


class _MyErr(Exception):
    """PyMySQL's error shape: (errno, message)."""


def _my_described(monkeypatch: pytest.MonkeyPatch, state: _Rows) -> mysql_module.MySQLConnector:
    conn = _my(monkeypatch, state)
    monkeypatch.setattr(conn, "_module", types.SimpleNamespace(MySQLError=_MyErr), raising=False)
    return conn


def test_f08_mysql_caps_unbounded_columns_server_side_and_keeps_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 1: a derived table with a LIMIT is materialized by MySQL
    before the first row (8.28 s instead of 0.09 s live, and an on-disk
    temporary table of full-width rows). The select list itself is rewritten
    instead, so the plan and the streaming stay the statement's own."""
    sql = "SELECT ssn, id, doc, note, j, g, x AS `w``eird%` FROM t ORDER BY id"
    state = _Rows([("123-45-6789", 1, b"d", "n", "{}", b"g", "w")], _MY_DESC)
    out = _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql, max_rows=1, max_cell_bytes=100))
    executed = [s for s, _ in state.statements]
    assert executed[0] == f"{sql}\nLIMIT 0", "described under a top-level LIMIT 0: MySQL plans it, runs nothing"
    assert executed[-1] == (
        "SELECT LEFT(ssn, 101) AS `ssn`, id, LEFT(doc, 101) AS `doc`, note, LEFT(j, 101) AS `j`, "
        "LEFT(g, 101) AS `g`, LEFT(x, 101) AS `w``eird%` FROM t ORDER BY id"
    )
    assert len(executed) == 2 and not any("udbmcp_q" in e for e in executed), "no derived table, no pushed LIMIT"
    assert out.columns == [
        ("ssn", "blob"), ("id", "integer"), ("doc", "blob"), ("note", "text"), ("j", "text"), ("g", "unknown"),
        ("w`eird%", "text"),
    ]
    from universal_db_mcp.server import _apply_masking

    resolved = _resolved({"type": "mysql", "host": "h", "database": "d", "options": {"os_authentication": True}})
    _cols, rows = _apply_masking(
        EffectivePolicy.build(SecurityConfig(), resolved), out.columns, out.rows, {"warnings": []}
    )
    assert rows[0][0] == "<masked>" and rows[0][1] == 1


@pytest.mark.parametrize(
    ("limit", "probe_limit"),
    [(" LIMIT 5", " LIMIT 0"), (" LIMIT 5 OFFSET 10", " LIMIT 0"), (" LIMIT 10, 5", " LIMIT 0"), ("", "\nLIMIT 0")],
)
def test_f08_mysql_describes_under_its_own_limit_replaced_and_escapes_percent_with_parameters(
    monkeypatch: pytest.MonkeyPatch, limit: str, probe_limit: str
) -> None:
    """Review round 1: 'LIMIT 1' statements and primary-key lookups ran twice
    under the derived-table probe (SLEEP(2): 2.00 s -> 4.04 s live). A
    top-level LIMIT 0 is not executed (measured on MySQL 9.7: 0.00 s for
    both shapes)."""
    head = "SELECT j AS `100%` FROM t WHERE id = %s ORDER BY id"
    state = _Rows([("{}",)], [_Col("100%", 245, 4294967295)])
    _my_described(monkeypatch, state)._execute(QuerySpec(sql=head + limit, parameters=[1], max_cell_bytes=100))
    assert state.statements == [
        (head + probe_limit, [1]),
        ("SELECT LEFT(j, 101) AS `100%%` FROM t WHERE id = %s ORDER BY id" + limit, [1]),
    ]


def test_f08_mysql_select_modifiers_stay_where_they_are(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 1: HIGH_PRIORITY and SQL_BUFFER_RESULT were refused
    inside the derived table (errno 1234) and the query failed."""
    sql = "SELECT HIGH_PRIORITY SQL_BUFFER_RESULT CAST(c.notes AS CHAR(10000)) AS n FROM testdb.cuppings c"
    state = _Rows([("x" * 200,)], [_Col("n", 253, 40000)])
    out = _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql, max_cell_bytes=100))
    assert [s for s, _ in state.statements] == [
        sql + "\nLIMIT 0",
        "SELECT HIGH_PRIORITY SQL_BUFFER_RESULT LEFT(CAST(c.notes AS CHAR(10000)), 101) AS `n` FROM testdb.cuppings c",
    ]
    assert out.truncated and len(out.rows[0][0]) == 100


def test_f08_mysql_text_after_the_statement_does_not_escape_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([("x",)], [_Col("notes", 252, 262140)])
    _my_described(monkeypatch, state)._execute(QuerySpec(sql="SELECT notes FROM t;; -- c", max_cell_bytes=100))
    assert [s for s, _ in state.statements] == [
        "SELECT notes FROM t\nLIMIT 0", "SELECT LEFT(notes, 101) AS `notes` FROM t",
    ]


def test_f08_mysql_a_star_over_one_table_is_spelled_out(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([(1, "x")], [_Col("id", 3, 11), _Col("notes", 252, 262140)])
    _my_described(monkeypatch, state)._execute(QuerySpec(sql="SELECT * FROM t WHERE id > 1", max_cell_bytes=100))
    assert state.statements[-1][0] == "SELECT `id`, LEFT(`notes`, 101) AS `notes` FROM t WHERE id > 1"
    state = _Rows([(1, "x")], [_Col("id", 3, 11), _Col("notes", 252, 262140)])
    _my_described(monkeypatch, state)._execute(QuerySpec(sql="SELECT t.* FROM t JOIN u ON u.id = t.id"))
    assert state.statements[-1][0] == "SELECT t.`id`, LEFT(t.`notes`, 8193) AS `notes` FROM t JOIN u ON u.id = t.id"


def test_f08_mysql_a_star_over_a_join_becomes_a_derived_table_with_a_column_list(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its columns cannot be named unambiguously in the select list without
    the schema. Review round 2: it ran uncut, one row at a time (a row costs
    about 6.5 x its size, up to max_allowed_packet). Duplicate names are
    referenced by position."""
    sql = "SELECT * FROM t JOIN u ON u.id = t.id"
    state = _Rows([(1, "x", 1)], [_Col("id", 3, 11), _Col("notes", 252, 262140), _Col("id", 3, 11)])
    out = _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql))
    assert [s for s, _ in state.statements] == [
        sql + "\nLIMIT 0",
        "SELECT udbmcp_q.c1 AS `id`, LEFT(udbmcp_q.c2, 8193) AS `notes`, udbmcp_q.c3 AS `id` FROM (\n"
        + sql + "\n) AS udbmcp_q(c1, c2, c3)",
    ]
    assert out.columns == [("id", "integer"), ("notes", "blob"), ("id", "integer")]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT notes FROM t ORDER BY notes",  # ordered by the output column's name
        "SELECT x AS notes FROM t ORDER BY LENGTH(notes)",
        "SELECT x AS notes, id FROM t ORDER BY 1",  # ... or its position
        "SELECT x AS notes FROM t GROUP BY notes",
        "SELECT x AS notes FROM t GROUP BY x HAVING notes > ''",
        "SELECT DISTINCT notes FROM t",
    ],
)
def test_f08_mysql_a_value_the_statement_compares_is_cut_only_after_it(
    monkeypatch: pytest.MonkeyPatch, sql: str
) -> None:
    """ORDER BY, GROUP BY and HAVING resolve an output name to the output
    column: a value cut in the select list would be ordered, grouped or
    compared by its first max_cell_bytes characters. Review round 2: such a
    column was read uncut (402 MB maxrss for one 60 MB row live). The
    statement now runs whole inside a derived table, and only what it returns
    is cut."""
    state = _Rows([("x", 1)], [_Col("notes", 252, 262140), _Col("id", 3, 11)][: 2 if ", id" in sql else 1])
    state.rows = [r[: len(state.description)] for r in state.rows]
    _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql))
    outer = "LEFT(udbmcp_q.`notes`, 8193) AS `notes`" + (", udbmcp_q.`id` AS `id`" if ", id" in sql else "")
    assert [s for s, _ in state.statements][-1] == f"SELECT {outer} FROM (\n{sql}\n) AS udbmcp_q"


def test_f08_mysql_a_refused_select_list_rewrite_falls_back_to_the_derived_table(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    sql = "SELECT notes FROM t"
    state = _Rows([("x",), ("y",)], [_Col("notes", 252, 262140)])
    refused = _MyErr(1064, "You have an error in your SQL syntax")
    state.fail = lambda s: refused if s == "SELECT LEFT(notes, 8193) AS `notes` FROM t" else None
    out = _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql, max_rows=1))
    assert out.rows == [["x"]]
    assert [s for s, _ in state.statements] == [
        sql + "\nLIMIT 0",
        "SELECT LEFT(notes, 8193) AS `notes` FROM t",
        f"SELECT LEFT(udbmcp_q.`notes`, 8193) AS `notes` FROM (\n{sql}\n) AS udbmcp_q",
    ]


@pytest.mark.parametrize("errno", [1064, 1054, 1060])
def test_f08_mysql_never_runs_the_statement_uncut_when_every_rewrite_is_refused(
    monkeypatch: pytest.MonkeyPatch, errno: int
) -> None:
    """Review round 2: a refused rewrite ran the statement as written, one
    uncut row at a time. It fails closed now, naming the columns."""
    sql = "SELECT notes FROM t"
    state = _Rows([("x",)], [_Col("notes", 252, 262140)])
    state.fail = lambda s: _MyErr(errno, "refused") if s != sql + "\nLIMIT 0" else None
    with pytest.raises(ConnectorError, match="could not be cut") as exc:
        _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql))
    assert exc.value.category == "QUERY_ERROR" and "'notes'" in str(exc.value) and "LEFT(" in str(exc.value)
    assert sql not in [s for s, _ in state.statements], "the statement as written never ran"


def _my_prepared(
    monkeypatch: pytest.MonkeyPatch, state: _Rows, *, server_version: str = "9.7.2"
) -> tuple[mysql_module.MySQLConnector, list[tuple[str, Any]]]:
    """A connector whose prepared-statement describe answers ``state``'s
    columns and records what it was asked (the protocol itself is tested
    against real packets below)."""
    conn = _my_described(monkeypatch, state)
    asked: list[tuple[str, Any]] = []

    def described(_conn: Any, sql: str, args: Any) -> list[Any]:
        asked.append((sql, args))
        return list(state.description)

    monkeypatch.setattr(conn, "_prepared_description", described)
    monkeypatch.setattr(_RowConn, "server_version", server_version, raising=False)
    return conn, asked


def test_f08_mysql_statements_that_are_no_select_are_not_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([("t",)], [_Col("Tables_in_d", 253, 256)])
    conn, asked = _my_prepared(monkeypatch, state)
    conn._execute(QuerySpec(sql="SHOW TABLES", max_cell_bytes=100))
    assert [s for s, _ in state.statements] == ["SHOW TABLES"]
    assert asked == [], "catalog statements are neither described nor wrapped"


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        ("SELECT COUNT(*) AS n, MAX(notes) AS notes FROM t", None),  # one row: MySQL computes it under LIMIT 0
        ("SELECT notes FROM t WHERE id = (SELECT MAX(id) FROM t)", None),  # a subquery evaluated while planning
        ("SELECT REPEAT('x', 1000000) AS notes", None),  # table-less
        ("WITH w AS (SELECT notes FROM t) SELECT notes FROM w", None),  # a CTE MySQL materializes
        ("SELECT notes FROM (SELECT notes FROM t) s", None),
        ("SELECT notes FROM t UNION ALL SELECT notes FROM u", None),
        ("SELECT notes FROM t WHERE id IN (SELECT id FROM u)", None),
        ("SELECT notes FROM t LIMIT %s", [1]),  # a bound LIMIT cannot become LIMIT 0 with the same parameters
    ],
)
def test_f08_mysql_statements_limit_0_cannot_describe_are_described_by_prepare_and_cut(
    monkeypatch: pytest.MonkeyPatch, sql: str, params: list[Any] | None
) -> None:
    """Measured on MySQL 9.7: under LIMIT 0 these shapes took as long as the
    statement itself, so they were run as written, one uncut row at a time.
    Review round 2: adding 'WHERE a.id IN (SELECT ...)' to a statement opted
    out of the cap (402-414 MB maxrss per call with 60 MB values live). The
    prepared-statement protocol describes them without running anything
    (SLEEP(2): 0.00 s live), and they run as a derived table."""
    columns = [_Col("n", 8, 21), _Col("notes", 252, 262140)] if "COUNT" in sql else [_Col("notes", 252, 262140)]
    state = _Rows([(1, "x")[-len(columns):]], columns)
    conn, asked = _my_prepared(monkeypatch, state)
    conn._execute(QuerySpec(sql=sql, parameters=params))
    executed = [s for s, _ in state.statements]
    assert not any("LIMIT 0" in e for e in executed), "not described under LIMIT 0"
    assert asked == [(sql, params)]
    if "LIMIT %s" in sql:
        assert executed == ["SELECT LEFT(notes, 8193) AS `notes` FROM t LIMIT %s"]
    else:
        n = "udbmcp_q.`n` AS `n`, " if "COUNT" in sql else ""
        assert executed == [f"SELECT {n}LEFT(udbmcp_q.`notes`, 8193) AS `notes` FROM (\n{sql}\n) AS udbmcp_q"]


def test_f08_mysql_a_statement_sqlglot_cannot_read_is_still_described_and_cut(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a statement known to be a catalog statement (SHOW, DESCRIBE)
    runs as written; one that cannot be told apart is treated as a query,
    and MySQL refusing it as a derived table fails it closed."""
    sql = "SELECT notes FROM t WHERE ("
    state = _Rows([("x",)], [_Col("notes", 252, 262140)])
    conn, asked = _my_prepared(monkeypatch, state)
    state.fail = lambda s: _MyErr(1064, "You have an error in your SQL syntax") if "udbmcp_q" in s else None
    with pytest.raises(ConnectorError, match="could not be cut"):
        conn._execute(QuerySpec(sql=sql))
    assert asked == [(sql, None)] and sql not in [s for s, _ in state.statements]


def test_f08_mysql_a_derived_table_quotes_names_and_percent_signs(monkeypatch: pytest.MonkeyPatch) -> None:
    sql = "SELECT j AS `100%%`, x AS `w``x` FROM t WHERE id IN (SELECT id FROM u WHERE v = %s)"
    state = _Rows([("{}", "y")], [_Col("100%", 245, 4294967295), _Col("w`x", 253, 80)])
    conn, _asked = _my_prepared(monkeypatch, state)
    out = conn._execute(QuerySpec(sql=sql, parameters=[1], max_cell_bytes=100))
    assert state.statements[-1] == (
        "SELECT LEFT(udbmcp_q.`100%%`, 101) AS `100%%`, udbmcp_q.`w``x` AS `w``x` FROM (\n"
        + sql + "\n) AS udbmcp_q",
        [1],
    )
    assert [c for c, _t in out.columns] == ["100%", "w`x"]


def test_f08_mysql_a_name_mysql_cannot_quote_is_referenced_by_position(monkeypatch: pytest.MonkeyPatch) -> None:
    long_name = "CONCAT(" + "a" * 80 + ")"
    sql = f"SELECT {long_name} FROM t WHERE id IN (SELECT id FROM u)"
    state = _Rows([("x",)], [_Col(long_name, 251, 4294967295)])
    conn, _asked = _my_prepared(monkeypatch, state)
    conn._execute(QuerySpec(sql=sql))
    assert state.statements[-1][0] == (
        f"SELECT LEFT(udbmcp_q.c1, 8193) AS `{long_name}` FROM (\n{sql}\n) AS udbmcp_q(c1)"
    )


@pytest.mark.parametrize(
    ("sql", "refused"),
    [
        ("SELECT notes FROM t WHERE id IN (SELECT id FROM u) ORDER BY id", True),
        ("SELECT notes FROM t UNION ALL SELECT notes FROM u ORDER BY 1", True),
        ("SELECT notes FROM t WHERE id IN (SELECT id FROM u)", False),
        ("SELECT notes FROM t ORDER BY id", False),  # its select list is cut: no derived table
    ],
)
def test_f08_mariadb_never_loses_the_order_of_a_derived_table(
    monkeypatch: pytest.MonkeyPatch, sql: str, refused: bool
) -> None:
    """MariaDB drops the ORDER BY of a derived table without a LIMIT: rows
    would come back in another order (and a row limit would keep other
    rows). Such a statement is refused there, not reordered."""
    state = _Rows([("x",)], [_Col("notes", 252, 262140)])
    conn, _asked = _my_prepared(monkeypatch, state, server_version="5.5.5-10.11.6-MariaDB-1")
    if refused:
        with pytest.raises(ConnectorError, match="MariaDB") as exc:
            conn._execute(QuerySpec(sql=sql))
        assert exc.value.category == "QUERY_ERROR"
        assert all("udbmcp_q" not in s and s != sql for s, _ in state.statements)
    else:
        conn._execute(QuerySpec(sql=sql))
        assert "LEFT(" in state.statements[-1][0]


class _PacketConn:
    """What _prepared_description reads through PyMySQL's (private)
    packet layer: the server's COM_STMT_PREPARE answer, as real packets."""

    def __init__(self, replies: list[bytes]) -> None:
        self.replies = replies
        self.commands: list[tuple[int, Any]] = []

    def cursor(self) -> Any:
        pymysql = pytest.importorskip("pymysql")
        cur = pymysql.cursors.Cursor.__new__(pymysql.cursors.Cursor)
        # What mogrify reads: literal() up to PyMySQL 1.2.0, escape() from 1.2.3.
        escape = pymysql.converters.escape_item
        cur.connection = types.SimpleNamespace(
            literal=lambda v: escape(v, "utf8"), escape=lambda v, mapping=None: escape(v, "utf8", mapping)
        )
        return cur

    def _execute_command(self, command: int, sql: Any) -> None:
        self.commands.append((command, sql))

    def _read_packet(self, packet_type: Any = None) -> Any:
        pymysql = pytest.importorskip("pymysql")
        packet = (packet_type or pymysql.protocol.MysqlPacket)(self.replies.pop(0), "utf8")
        if packet.is_error_packet():
            packet.raise_for_error()
        return packet


def _lenenc(text: str) -> bytes:
    data = text.encode()
    return bytes([len(data)]) + data


def _column_packet(name: str, type_code: int, length: int) -> bytes:
    return (
        _lenenc("def") + _lenenc("d") + _lenenc("t") + _lenenc("t") + _lenenc(name) + _lenenc(name)
        + b"\x0c" + struct.pack("<HIBHB", 45, length, type_code, 0, 0) + b"\x00\x00"
    )


_EOF = b"\xfe\x00\x00\x02\x00"


def test_f08_mysql_prepared_describe_reads_the_columns_and_closes_the_statement(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    pymysql = pytest.importorskip("pymysql")
    conn = _my(monkeypatch, _Rows([], []))
    monkeypatch.setattr(conn, "_module", pymysql, raising=False)
    monkeypatch.setattr(pymysql.connections, "Connection", _PacketConn)
    prepare_ok = b"\x00" + struct.pack("<IHHBH", 7, 2, 1, 0, 0)
    packets = _PacketConn([
        prepare_ok, _column_packet("?", 253, 0), _EOF,  # one parameter definition, then EOF
        _column_packet("notes", 252, 262140), _column_packet("id", 3, 11), _EOF,
    ])
    described = conn._prepared_description(packets, "SELECT notes, id FROM t WHERE id = %s", [5])
    assert [(d[0], d[1], d[3]) for d in described or []] == [("notes", 252, 262140), ("id", 3, 11)]
    command = pymysql.constants.COMMAND
    assert packets.commands == [
        (command.COM_STMT_PREPARE, "SELECT notes, id FROM t WHERE id = 5"),  # the values inlined as sent
        (command.COM_STMT_CLOSE, struct.pack("<I", 7)),
    ]
    assert packets.replies == []


def test_f08_mysql_prepared_describe_of_a_statement_the_protocol_refuses_is_none(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    pymysql = pytest.importorskip("pymysql")
    conn = _my(monkeypatch, _Rows([], []))
    monkeypatch.setattr(conn, "_module", pymysql, raising=False)
    monkeypatch.setattr(pymysql.connections, "Connection", _PacketConn)
    unsupported = b"\xff" + struct.pack("<H", 1295) + b"#HY000This command is not supported"
    assert conn._prepared_description(_PacketConn([unsupported]), "SHOW ENGINES", None) is None
    denied = b"\xff" + struct.pack("<H", 1142) + b"#42000SELECT command denied"
    with pytest.raises(pymysql.MySQLError):
        conn._prepared_description(_PacketConn([denied]), "SELECT notes FROM secret", None)


def test_f08_mysql_prepared_describe_uses_pymysql_internals_that_exist() -> None:
    """COM_STMT_PREPARE goes through PyMySQL's private packet layer: an
    upgrade that renamed it must fail here, not turn the describe off."""
    pymysql = pytest.importorskip("pymysql")
    for name in ("_execute_command", "_read_packet"):
        assert callable(getattr(pymysql.connections.Connection, name, None)), name
    assert callable(getattr(pymysql.protocol.FieldDescriptorPacket, "description", None))
    assert pymysql.constants.COMMAND.COM_STMT_PREPARE == 0x16 and pymysql.constants.COMMAND.COM_STMT_CLOSE == 0x19


def test_f08_mysql_grouped_and_windowed_rows_are_still_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    for sql, capped in (
        ("SELECT taster, MAX(notes) AS notes FROM t GROUP BY taster",
         "SELECT taster, LEFT(MAX(notes), 8193) AS `notes` FROM t GROUP BY taster"),
        ("SELECT notes, COUNT(*) OVER () FROM t",
         "SELECT LEFT(notes, 8193) AS `notes`, COUNT(*) OVER () FROM t"),
    ):
        desc = [_Col("taster", 253, 240), _Col("notes", 252, 262140)] if "taster" in sql else [
            _Col("notes", 252, 262140), _Col("COUNT(*) OVER ()", 8, 21)]
        state = _Rows([("x", 1)], desc)
        _my_described(monkeypatch, state)._execute(QuerySpec(sql=sql))
        assert [s for s, _ in state.statements] == [sql + "\nLIMIT 0", capped]


def test_f08_mysql_a_describe_that_fails_for_its_own_reasons_is_not_run_again(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    class _MyErr(Exception):
        pass

    state = _Rows([("x",)], [_Col("notes", 252, 262140)])
    state.fail = lambda s: _MyErr(1317, "Query execution was interrupted")
    conn = _my(monkeypatch, state)
    monkeypatch.setattr(conn, "_module", types.SimpleNamespace(MySQLError=_MyErr), raising=False)
    with pytest.raises(ConnectorError, match="interrupted"):
        conn._execute(QuerySpec(sql="SELECT notes FROM t"))
    assert len(state.statements) == 1, "a KILLed or failing statement must not be started a second time"


def test_f08_mysql_truncation_leaves_no_unread_result_to_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    results: list[Any] = []
    real_execute = _RowCursor.execute

    def execute(cur: _RowCursor, sql: str, params: Any = None) -> None:
        cur._result = types.SimpleNamespace(unbuffered_active=True)  # type: ignore[attr-defined]
        results.append(cur._result)  # type: ignore[attr-defined]
        real_execute(cur, sql, params)

    monkeypatch.setattr(_RowCursor, "execute", execute)
    state = _Rows(_TEN, [_Col("n", 3, 11)])
    out = _my(monkeypatch, state)._execute(QuerySpec(sql="SELECT n FROM t", max_rows=1))
    assert out.truncated
    assert results[-1].unbuffered_active is False, "PyMySQL's __del__ would read the closed socket"


# F08 (4): a MySQL query can be stopped on the server.


class _FakeMySQLModule:
    """PyMySQL stand-in: the first connect is the query connection, later
    ones are the short-lived KILL connections."""

    class MySQLError(Exception):
        pass

    cursors = types.SimpleNamespace(SSCursor=object)

    def __init__(self, state: _Rows) -> None:
        self.state = state
        self.kwargs: list[dict[str, Any]] = []
        self.conns: list[_RowConn] = []

    def connect(self, **kwargs: Any) -> _RowConn:
        self.kwargs.append(kwargs)
        conn = _RowConn(self.state)
        self.conns.append(conn)
        return conn


def _my_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: _Rows, **body: Any) -> tuple[
    mysql_module.MySQLConnector, _FakeMySQLModule
]:
    fake = _FakeMySQLModule(state)
    monkeypatch.setattr(mysql_module, "open_module", lambda *_a, **_k: fake)
    resolved = _resolved({
        "type": "mysql", "host": "h", "database": "d",
        "username_file": _secret(tmp_path, "mu", "ro"), "password_file": _secret(tmp_path, "mp", "pw"), **body,
    })
    return mysql_module.MySQLConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)), fake


def test_f08_mysql_cancel_kills_the_running_query(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows(_TEN, [_Col("n", 3, 11)])
    state.blocked = threading.Event()
    conn, fake = _my_module(tmp_path, monkeypatch, state)
    assert conn.cancel_current() is False, "nothing is running"
    errors: list[BaseException] = []

    def run() -> None:
        try:
            conn.execute_query(QuerySpec(sql="SELECT n FROM t"))
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assert below
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert state.fetching.wait(5)
        assert conn.cancel_current() is True
    finally:
        state.blocked.set()
        worker.join(5)
    kills = [(s, p) for s, p in state.statements if s.startswith("KILL")]
    assert kills == [("KILL QUERY 4242", None)]
    assert len(fake.conns) == 2 and "close" in state.log, "the KILL travels on its own short-lived connection"
    assert fake.kwargs[1]["user"] == "ro" and fake.kwargs[1]["password"] == "pw"
    assert not errors, errors
    assert conn.cancel_current() is False, "a finished query leaves nothing to kill"
    assert conn.capabilities().get(Cap.SERVER_SIDE_CANCEL) == CapabilityState.UNVERIFIED


def test_f86_postgres_cancel_uses_the_bounded_non_blocking_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    """psycopg's cancel() is libpq PQcancel, which blocks holding the GIL:
    against a host that stopped answering, the event loop and every other
    thread froze with it. cancel_safe() waits without the GIL, for a bounded
    time under the executor's cancel-hook budget."""
    from universal_db_mcp.services.executor import _CANCEL_HOOK_BUDGET

    class _Target:
        def __init__(self, error: BaseException | None = None) -> None:
            self.timeouts: list[float] = []
            self.error = error

        def cancel(self) -> None:
            raise AssertionError("cancel() holds the GIL for as long as the host takes")

        def cancel_safe(self, *, timeout: float = 30.0) -> None:
            self.timeouts.append(timeout)
            if self.error is not None:
                raise self.error

    conn = _pg(monkeypatch, _Rows([], []))
    target = _Target()
    conn._cancel_target = target
    assert conn.cancel_current() is True
    assert len(target.timeouts) == 1 and 0 < target.timeouts[0] < _CANCEL_HOOK_BUDGET
    conn._cancel_target = _Target(TimeoutError("cancellation timed out"))
    assert conn.cancel_current() is False, "a cancel that did not complete is not reported as one"


def test_f86_postgres_never_falls_back_to_the_blocking_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 4: cancel_safe() silently calls the GIL-holding cancel()
    when the bundled libpq predates 17, and the pg extra allows such
    psycopg-binary builds. Then the cancel is not sent (the server's
    statement_timeout still ends the query, and the executor discards the
    connection), and the capability matrix says so."""
    psycopg = pytest.importorskip("psycopg")

    calls: list[str] = []

    class _Target:
        def cancel(self) -> None:
            calls.append("cancel")

        def cancel_safe(self, *, timeout: float = 30.0) -> None:
            calls.append("cancel_safe")  # which is cancel() on this libpq

    conn = _pg(monkeypatch, _Rows([], []))
    assert not any("libpq" in lim.detail for lim in conn.capabilities().limitations)
    monkeypatch.setattr(psycopg.capabilities, "has_cancel_safe", lambda check=False: False)
    conn._cancel_target = _Target()
    assert conn.cancel_current() is False
    assert calls == []
    notes = [lim.detail for lim in conn.capabilities().limitations if lim.scope == "cancel"]
    assert any("libpq" in n and "17" in n for n in notes), notes


def test_f86_postgres_truncated_results_send_no_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 5: every result truncated by max_rows or
    max_response_bytes still called the GIL-holding cancel() (PQcancel), on
    any libpq. With the cancel request held by a proxy, every thread, the
    event loop included, froze for the whole hold. The statement runs in a
    named cursor, so the server does no work between FETCHes; closing the
    cursor and the rollback end it."""
    state = _Rows(_TEN, [_Col("n", 23)])

    class _Recording(_RowConn):
        def cancel_safe(self, *, timeout: float = 30.0) -> None:
            self._s.log.append("cancel_safe")

    conn = _pg(monkeypatch, state)
    monkeypatch.setattr(conn, "_connect", lambda: _Recording(state))
    out = conn._execute(QuerySpec(sql="SELECT n FROM t", max_rows=1))
    assert out.truncated and out.rows == [[0]]
    out = conn._execute(QuerySpec(sql="SELECT n FROM t", max_response_bytes=4))
    assert out.truncated and len(out.rows) <= 1
    assert "cancel" not in state.log and "cancel_safe" not in state.log, state.log
    assert state.log.count("cursor.close") == 2 and state.log.count("rollback") == 2, state.log


# F17: every driver failure is a ConnectorError, classified by phase.


def test_f17_timeout_error_passes_through_unchanged() -> None:
    for phase in ("connect", "execute"):
        with pytest.raises(TimeoutError), driver_helpers.translated_driver_errors(phase=phase):
            raise TimeoutError("timed out")


def test_f17_execute_phase_errors_are_query_errors_and_connect_phase_errors_are_not() -> None:
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise ValueError("invalid input syntax for type integer")
    assert exc.value.category == "QUERY_ERROR"
    assert "ValueError" in str(exc.value)
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors():
        raise OSError("connection refused")
    assert not hasattr(exc.value, "category"), "a connect failure keeps the CONNECTION_ERROR default"


class _DriverError(Exception):
    """PyMySQL's (errno, message) and pyodbc's (sqlstate, message) shape."""


class _OracleCode:
    """python-oracledb's _Error: the first argument of its exceptions."""

    def __init__(self, full_code: str, message: str) -> None:
        self.full_code = full_code
        self.message = message

    def __str__(self) -> str:
        return self.message


class InterfaceError(Exception):
    pass


class OperationalError(Exception):
    sqlstate: str | None = None


@pytest.mark.parametrize(
    "lost",
    [
        InterfaceError("connection already closed"),
        OperationalError("consuming input failed: server closed the connection unexpectedly"),
        OperationalError(2013, "Lost connection to MySQL server during query"),
        OperationalError("08S01", "[08S01] Communication link failure"),
        RuntimeError("[IBM][CLI Driver] SQL30081N A communication error has been detected. SQLSTATE=08001"),
        Exception("[IBM][CLI Driver] SQL30081N  A communication error.  SQLSTATE=08001 SQLCODE=-30081"),
        RuntimeError(_OracleCode("DPY-4011", "DPY-4011: the database or network closed the connection")),
    ],
)
def test_f17_a_connection_lost_mid_query_stays_a_connection_error(lost: Exception) -> None:
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise lost
    assert not hasattr(exc.value, "category")


@pytest.mark.parametrize(
    "timed_out",
    [
        RuntimeError("[IBM][CLI Driver] SQL0952N Processing was cancelled due to an interrupt. SQLSTATE=57014"),
        OperationalError("HYT00", "[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Query timeout expired (0)"),
        OperationalError(3024, "Query execution was interrupted, maximum statement execution time exceeded"),
    ],
)
def test_f17_statement_timeouts_are_reported_as_timeouts(timed_out: Exception) -> None:
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise timed_out
    assert exc.value.category == "TIMEOUT"
    assert "time limit" in str(exc.value)


def _psycopg_error(name: str, message: str) -> Exception:
    err: Exception = getattr(pytest.importorskip("psycopg").errors, name)(message)
    return err


@pytest.mark.parametrize(
    "echoed",
    [
        lambda: _psycopg_error("InvalidTextRepresentation", 'invalid input syntax for type integer: "SQL0952N"'),
        lambda: _psycopg_error("InvalidTextRepresentation", 'invalid input syntax for type integer: "SQLSTATE=08001"'),
        lambda: _psycopg_error("UndefinedColumn", 'column "DPY-4024" does not exist'),
        lambda: _DriverError(1366, "Incorrect integer value: 'SQL0952N SQLSTATE=08001' for column 'n'"),  # PyMySQL
        lambda: _DriverError("22018", "[22018] Conversion failed when converting 'SQL0952N' to int (245)"),  # pyodbc
        lambda: RuntimeError(_OracleCode("ORA-00904", 'ORA-00904: "DPY-4011": invalid identifier')),
    ],
)
def test_f17_a_literal_the_engine_quotes_back_does_not_decide_the_category(echoed: Callable[[], Exception]) -> None:
    """Review round 1: SELECT CAST('SQL0952N' AS int) was reported as a
    TIMEOUT and CAST('SQLSTATE=08001' AS int) as a CONNECTION_ERROR. A
    driver that keeps its error code apart from the message is classified
    by that code only."""
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise echoed()
    assert exc.value.category == "QUERY_ERROR"


@pytest.mark.parametrize(
    "echoed",
    [
        # review round 2, repro 2: a column named after the timeout code
        lambda: Exception(
            'Statement Execute Failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0206N  "NOSUCH_SQL0952N" is not '
            "valid in the context where it is used.  SQLSTATE=42703 SQLCODE=-206"
        ),
        # repro 3: a literal the engine quotes back, cut before its end
        lambda: Exception(
            "Statement Execute Failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0102N  The string constant beginning "
            "with \"'SQLSTATE=08001 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" is too long.  "
            "SQLSTATE=54002 SQLCODE=-102"
        ),
        # a driver that is not ibm_db, whose message ends with the caller's text
        lambda: RuntimeError("Code: 47. DB::Exception: Unknown identifier: SQLSTATE=57014"),
        lambda: RuntimeError("Missing columns: 'SQL0952N' while processing query: 'SELECT SQL0952N' SQLSTATE=08001"),
    ],
)
def test_f17_ibm_db_codes_are_read_from_the_end_of_its_own_message_only(echoed: Callable[[], Exception]) -> None:
    """Review round 2: the message-text fallback applied to every driver
    without a structured code and searched the whole message, so
    'SELECT nosuch_SQL0952N ...' came back as a TIMEOUT and a long literal
    starting 'SQLSTATE=08001' as a CONNECTION_ERROR."""
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise echoed()
    assert exc.value.category == "QUERY_ERROR"


def test_f17_ibm_db_trailing_sqlstate_still_classifies() -> None:
    wrapped = (
        "ibm_db_dbi::ProgrammingError: Statement Execute Failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0952N  "
        "Processing was cancelled due to an interrupt.  SQLSTATE=57014 SQLCODE=-952"
    )
    assert driver_helpers.ibm_db_sqlstate(RuntimeError(wrapped)) == "57014"
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise RuntimeError(wrapped)
    assert exc.value.category == "TIMEOUT"
    assert driver_helpers.ibm_db_sqlstate(RuntimeError("SQLSTATE=57014")) is None, "no ibm_db prefix"


def test_f17_sqlite_errors_are_classified_by_their_result_code(tmp_path: Path) -> None:
    """Review round 2, repro 1: SQLite errors carry no code the old check
    knew, so 'SELECT SQL0952N FROM main.refs' was reported as a TIMEOUT."""
    db = tmp_path / "t.db"
    with sqlite3.connect(db) as setup:
        setup.execute("CREATE TABLE refs (n INTEGER)")
    resolved = _resolved({"type": "sqlite", "database": str(db)})
    conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    for sql in ("SELECT SQL0952N FROM main.refs", "SELECT [x SQLSTATE=08001] FROM main.refs"):
        with pytest.raises(ConnectorError, match="no such column") as exc:
            conn.execute_query(QuerySpec(sql=sql))
        assert exc.value.category == "QUERY_ERROR", sql
    interrupted = sqlite3.connect(":memory:", check_same_thread=False)
    threading.Timer(0.2, interrupted.interrupt).start()
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        interrupted.execute("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT count(*) FROM t")
    assert exc.value.category == "TIMEOUT", "the interrupt that follows a timeout"


def test_f17_structured_codes_still_classify() -> None:
    for timed_out in (RuntimeError(_OracleCode("DPY-4024", "DPY-4024: call timeout of 5000 ms exceeded")),):
        with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
            raise timed_out
        assert exc.value.category == "TIMEOUT"
    for lost in (
        RuntimeError(_OracleCode("DPY-4011", "DPY-4011: the database or network closed the connection")),
        _psycopg_error("AdminShutdown", "terminating connection due to administrator command"),
    ):
        with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
            raise lost
        assert not hasattr(exc.value, "category")


def test_f17_psycopg_query_canceled_is_a_timeout() -> None:
    psycopg = pytest.importorskip("psycopg")
    err = psycopg.errors.QueryCanceled("canceling statement due to statement timeout")
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise err
    assert exc.value.category == "TIMEOUT"


def test_f17_a_login_timeout_is_not_a_statement_timeout() -> None:
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors():
        raise OperationalError("HYT00", "[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Login timeout expired (0)")
    assert not hasattr(exc.value, "category")


def test_f17_systemerror_is_translated_from_the_driver_error_it_carries() -> None:
    """ibm_db_dbi's fetchmany raised a SystemError whose context is the
    driver's own error (live: SQL0801N, and SQL0952N at QUERYTIMEOUT)."""
    wrapper = SystemError("<built-in function fetchmany> returned a result with an exception set")
    wrapper.__context__ = RuntimeError("[IBM][CLI Driver] SQL0801N Division by zero was attempted. SQLSTATE=22012")
    with pytest.raises(ConnectorError) as exc, driver_helpers.translated_driver_errors(phase="execute"):
        raise wrapper
    assert "SQL0801N" in str(exc.value) and "SystemError" not in str(exc.value)
    assert exc.value.category == "QUERY_ERROR"


def test_f17_postgres_metadata_failures_are_connector_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    psycopg = pytest.importorskip("psycopg")
    resolved = _resolved({"type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True}})
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise psycopg.OperationalError("connection failed: password authentication failed")

    monkeypatch.setattr(conn, "_connect", refuse)
    calls: list[Callable[[], Any]] = [
        lambda: conn.list_tables(None, {"table"}, None),
        lambda: conn.list_schemas(None, None),
        lambda: conn.list_columns("public", "t"),
        lambda: conn.list_routines(None),
        lambda: conn.get_statistics("public", "t"),
        lambda: conn.explain("SELECT 1", False),
    ]
    for call in calls:
        with pytest.raises(ConnectorError, match="password authentication failed"):
            call()
        assert conn._meta_conn is None
    with pytest.raises(NotImplementedError):
        conn.explain("SELECT 1", True)


def test_f17_postgres_catalog_query_failure_discards_the_shared_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    psycopg = pytest.importorskip("psycopg")
    state = _Rows([], [])

    class _MetaConn(_RowConn):
        def execute(self, sql: str, params: Any = None) -> Any:
            raise psycopg.errors.InsufficientPrivilege("permission denied for table pg_class")

    resolved = _resolved({"type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True}})
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    monkeypatch.setattr(conn, "_connect", lambda: _MetaConn(state))
    with pytest.raises(ConnectorError, match="permission denied"):
        conn.list_tables(None, {"table"}, None)
    assert conn._meta_conn is None and "close" in state.log


def test_f17_postgres_down_with_tls_configured_is_a_connector_error(tmp_path: Path) -> None:
    """Replaces a vacuous check that failed on the TLS gate before psycopg
    was ever reached: here the TLS config is valid and the server is down."""
    pytest.importorskip("psycopg")
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens there now
    resolved = _resolved({
        "type": "postgres", "host": "127.0.0.1", "port": port, "database": "d", "connect_timeout_seconds": 2,
        "username_file": _secret(tmp_path, "pu", "ro"), "password_file": _secret(tmp_path, "pp", "pw"),
        "tls": {"enabled": True, "verify_server": True, "ca_file": str(ca)},
    })
    policy = EffectivePolicy.build(SecurityConfig(require_remote_tls=True), resolved)
    conn = pg_module.PostgresConnector(resolved, policy)
    with pytest.raises(ConnectorError, match="OperationalError"):
        conn.list_tables(None, {"table"}, None)


def test_f17_db2_statement_errors_are_query_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([], [_Col("N", int)])
    conn, _ = _db2(tmp_path, monkeypatch)
    dbi = _db2_dbi(monkeypatch, state)
    state.fail = lambda _s: dbi.DataError(
        "ibm_db_dbi::DataError: Statement Execute Failed: [IBM][CLI Driver] CLI0109E  String data right "
        "truncation. SQLSTATE=22001 SQLCODE=-99999"
    )
    with pytest.raises(ConnectorError, match="CLI0109E") as exc:
        conn.execute_query(QuerySpec(sql="SELECT N FROM T WHERE PHONE = ?", parameters=["5551234567"]))
    assert exc.value.category == "QUERY_ERROR"


def test_f17_db2_fetch_timeout_is_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows(_TEN, [_Col("N", int)])
    conn, _ = _db2(tmp_path, monkeypatch)
    _db2_dbi(monkeypatch, state)

    def fetchmany(_cur: _RowCursor, _n: int) -> list[Any]:
        try:
            raise RuntimeError(
                "[IBM][CLI Driver][DB2/LINUXX8664] SQL0952N  Processing was cancelled due to an interrupt.  "
                "SQLSTATE=57014"
            )
        except RuntimeError:
            raise SystemError("<built-in function fetchmany> returned a result with an exception set")  # noqa: B904

    monkeypatch.setattr(_RowCursor, "fetchmany", fetchmany)
    with pytest.raises(ConnectorError, match="SQL0952N") as exc:
        conn.execute_query(QuerySpec(sql="SELECT N FROM T"))
    assert exc.value.category == "TIMEOUT"


def test_f17_db2_connect_failure_during_a_query_stays_a_connection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Down(_FakeIbmDb):
        def connect(self, dsn: str, user: str, password: str, *_a: Any, **_k: Any) -> str:
            raise RuntimeError("[IBM][CLI Driver] SQL30081N  A communication error has been detected.")

    conn, _ = _db2(tmp_path, monkeypatch, fake=_Down())
    with pytest.raises(ConnectorError, match="SQL30081N") as exc:
        conn.execute_query(QuerySpec(sql="SELECT 1 FROM SYSIBM.SYSDUMMY1"))
    assert not hasattr(exc.value, "category")


def test_f17_sqlite_value_errors_are_query_errors(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    with sqlite3.connect(db) as setup:
        setup.execute("CREATE TABLE t (n INTEGER)")
    resolved = _resolved({"type": "sqlite", "database": str(db)})
    conn = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    with pytest.raises(ConnectorError, match="OverflowError") as exc:
        conn.execute_query(QuerySpec(sql="SELECT n FROM t WHERE n = ?", parameters=[10**20]))
    assert exc.value.category == "QUERY_ERROR"
    with pytest.raises(ConnectorError, match="no such table") as exc:
        conn.execute_query(QuerySpec(sql="SELECT n FROM missing"))
    assert exc.value.category == "QUERY_ERROR"


def test_f17_postgres_query_errors_are_query_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    psycopg = pytest.importorskip("psycopg")
    state = _Rows([], [_Col("n", 23)])
    state.fail = lambda _s: psycopg.errors.DivisionByZero("division by zero")
    with pytest.raises(ConnectorError, match="division by zero") as exc:
        _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT 1/0"))
    assert exc.value.category == "QUERY_ERROR"


# F30: an 'infinity', BC or year-10000+ date is data, not a failed query.


def _pg_days(d: datetime.date) -> int:
    return d.toordinal() - datetime.date(2000, 1, 1).toordinal()


def test_f30_postgres_datetime_loaders_return_out_of_range_values_as_text() -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.adapt import AdaptersMap
    from psycopg.pq import Format

    conn = types.SimpleNamespace(adapters=AdaptersMap(psycopg.adapters))
    pg_module._register_tolerant_datetime_loaders(conn)

    def load(type_name: str, data: bytes, fmt: Any = Format.TEXT) -> Any:
        oid = psycopg.adapters.types[type_name].oid
        return conn.adapters.get_loader(oid, fmt)(oid, None).load(data)

    for text in (b"infinity", b"-infinity", b"0044-03-15 BC", b"20000-01-01"):
        assert load("date", text) == text.decode()
    assert load("date", b"2024-01-01") == datetime.date(2024, 1, 1)
    assert load("timestamp", b"infinity") == "infinity"
    assert load("timestamp", b"20000-01-01 10:00:00") == "20000-01-01 10:00:00"
    assert load("timestamptz", b"-infinity") == "-infinity"
    assert load("timestamptz", b"0044-03-15 10:00:00+00 BC") == "0044-03-15 10:00:00+00 BC"
    assert load("timestamp", b"2024-01-01 10:00:00") == datetime.datetime(2024, 1, 1, 10)

    binary = Format.BINARY
    assert load("date", struct.pack("!i", 2**31 - 1), binary) == "infinity"
    assert load("date", struct.pack("!i", -(2**31)), binary) == "-infinity"
    assert load("timestamp", struct.pack("!q", 2**63 - 1), binary) == "infinity"
    assert load("timestamptz", struct.pack("!q", -(2**63)), binary) == "-infinity"
    ten_k = _pg_days(datetime.date(9999, 12, 31)) + 1
    assert load("date", struct.pack("!i", ten_k), binary) == "10000-01-01"
    assert load("date", struct.pack("!i", _pg_days(datetime.date(1, 1, 1)) - 1), binary) == "0001-12-31 BC"
    assert load("date", struct.pack("!i", _pg_days(datetime.date(1, 1, 1)) - 366), binary) == "0001-01-01 BC"
    micro = (ten_k * 86400 + 3723) * 1_000_000 + 5
    assert load("timestamp", struct.pack("!q", micro), binary) == "10000-01-01 01:02:03.000005"
    assert load("timestamptz", struct.pack("!q", micro), binary) == "10000-01-01 01:02:03.000005+00"
    assert load("date", struct.pack("!i", _pg_days(datetime.date(2024, 1, 1))), binary) == datetime.date(2024, 1, 1)


def test_f30_postgres_time_and_interval_values_python_cannot_hold_are_text() -> None:
    """Review round 1: time '24:00:00' (end of day) still failed the whole
    query; interval 'infinity' came back as '0:00:00' and '178000000 years'
    as '545490560 days, 0:00:00' (psycopg's C loader wraps around)."""
    psycopg = pytest.importorskip("psycopg")
    from psycopg.adapt import AdaptersMap
    from psycopg.pq import Format

    conn = types.SimpleNamespace(adapters=AdaptersMap(psycopg.adapters))
    pg_module._register_tolerant_datetime_loaders(conn)
    session = types.SimpleNamespace(pgconn=types.SimpleNamespace(parameter_status=lambda _name: b"postgres"))
    context = types.SimpleNamespace(connection=session)

    def load(type_name: str, data: bytes, fmt: Any = Format.TEXT) -> Any:
        oid = psycopg.adapters.types[type_name].oid
        return conn.adapters.get_loader(oid, fmt)(oid, context).load(data)

    assert load("time", b"24:00:00") == "24:00:00"
    assert load("timetz", b"24:00:00+00") == "24:00:00+00"
    assert load("time", b"10:30:00") == datetime.time(10, 30)
    for text in (b"infinity", b"-infinity", b"178000000 years", b"-178000000 years", b"2000000000 days"):
        assert load("interval", text) == text.decode()
    assert load("interval", b"1 year 2 mons 3 days 04:05:06.5") == datetime.timedelta(
        days=365 + 60 + 3, hours=4, minutes=5, seconds=6.5
    )

    binary = Format.BINARY
    end_of_day = 86_400 * 1_000_000
    assert load("time", struct.pack("!q", end_of_day), binary) == "24:00:00"
    assert load("timetz", struct.pack("!qi", end_of_day, 0), binary) == "24:00:00+00"
    assert load("timetz", struct.pack("!qi", end_of_day, -19_800), binary) == "24:00:00+05:30"
    assert load("time", struct.pack("!q", 3_600_000_001), binary) == datetime.time(1, 0, 0, 1)
    assert load("interval", struct.pack("!qii", 2**63 - 1, 2**31 - 1, 2**31 - 1), binary) == "infinity"
    assert load("interval", struct.pack("!qii", -(2**63), -(2**31), -(2**31)), binary) == "-infinity"
    assert load("interval", struct.pack("!qii", 0, 0, 178_000_000 * 12), binary) == "178000000 years"
    assert load("interval", struct.pack("!qii", 3_600_000_000, 3, 14), binary) == datetime.timedelta(
        days=365 + 60 + 3, hours=1
    )


def test_f30_postgres_connect_registers_the_loaders_and_rounds_the_connect_timeout_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.adapt import AdaptersMap
    from psycopg.pq import Format

    made: list[Any] = []

    class _Conn:
        def __init__(self) -> None:
            self.adapters = AdaptersMap(psycopg.adapters)
            self.autocommit = False

        def execute(self, *_a: Any, **_k: Any) -> None:
            return None

    def connect(**kw: Any) -> _Conn:
        made.append(kw)
        return _Conn()

    monkeypatch.setattr(pg_module, "open_module", lambda *_a, **_k: types.SimpleNamespace(connect=connect))
    resolved = _resolved({
        "type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True},
        "connect_timeout_seconds": 0.5,
    })
    conn = pg_module.PostgresConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    handle = conn._connect()
    assert made[0]["connect_timeout"] == 1, "int(0.5) == 0 made libpq wait its 130 s default"
    loader = handle.adapters.get_loader(1082, Format.TEXT)
    assert loader(1082, None).load(b"infinity") == "infinity"


# F34: Oracle LOBs are read up to the cell limit, never whole.


class _FakeDbType:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeLob:
    """python-oracledb LOB stand-in: read(offset, amount) and size(); str()
    of a real LOB reads it whole (bytes for a BLOB, which str() rejects)."""

    def __init__(self, kind: str, data: Any, *, readable: bool = True) -> None:
        self.type = _FakeDbType(f"DB_TYPE_{kind}")
        self._data = data
        self._readable = readable
        self.reads: list[int | None] = []
        self.str_calls = 0

    def size(self) -> int:
        return len(self._data)

    def read(self, offset: int = 1, amount: int | None = None) -> Any:
        self.reads.append(amount)
        if not self._readable:
            raise RuntimeError("ORA-22285: non-existent directory or file for FILEOPEN operation")
        end = None if amount is None else offset - 1 + amount
        return self._data[offset - 1:end]

    def __str__(self) -> str:
        self.str_calls += 1
        return self._data  # type: ignore[no-any-return]


def test_f34_oracle_lobs_are_read_only_up_to_the_cell_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clob = _FakeLob("CLOB", "x" * 100_000)
    nclob = _FakeLob("NCLOB", "é" * 6000)
    blob = _FakeLob("BLOB", b"\x01" * 100_000)
    small = _FakeLob("CLOB", "short")
    tiny = _FakeLob("BLOB", b"\x02\x03")
    state = _Rows(
        [(clob, nclob, blob, small, tiny)],
        [_Col("DOC", str), _Col("NDOC", str), _Col("IMG", bytes), _Col("NOTE", str), _Col("ICON", bytes)],
    )
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(QuerySpec(sql="SELECT * FROM t", max_cell_bytes=8192))
    doc, ndoc, img, note, icon = out.rows[0]
    assert len(doc.encode()) <= 8192 and len(ndoc.encode()) <= 8192
    assert img["$truncated"] is True and len(base64.b64decode(img["$binary_b64"])) == 8192
    assert note == "short"
    assert icon == {"$binary_b64": base64.b64encode(b"\x02\x03").decode()}
    assert out.truncated
    warning = next(w for w in out.warnings if "exceeded" in w)
    assert "'DOC'" in warning and "'NDOC'" in warning and "'IMG'" in warning and "'NOTE'" not in warning
    for lob in (clob, nclob, blob, small, tiny):
        assert lob.str_calls == 0, "str(lob) reads the whole LOB"
        assert all(a is not None and a <= 8193 for a in lob.reads), lob.reads


def test_f34_oracle_unreadable_bfile_is_null_with_a_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bfile = _FakeLob("BFILE", b"\x00" * 10, readable=False)
    state = _Rows([(1, bfile)], [_Col("ID", int), _Col("SCAN", bytes)])
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(QuerySpec(sql="SELECT id, scan FROM t"))
    assert out.rows == [[1, None]]
    assert any("'SCAN'" in w and "BFILE" in w for w in out.warnings), out.warnings


def test_f34_oracle_vectors_are_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sparse = types.SimpleNamespace(
        num_dimensions=10, indices=array.array("I", [1, 3]), values=array.array("d", [1.5, 2.5])
    )
    state = _Rows([(array.array("d", [1.5]), sparse)], [_Col("V", object), _Col("S", object)])
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(QuerySpec(sql="SELECT v, s FROM t"))
    assert out.rows == [["[1.5]", '{"num_dimensions": 10, "indices": [1, 3], "values": [1.5, 2.5]}']]


def test_f34_generic_values_are_capped_and_never_fail_the_row() -> None:
    class _Wide:
        def __str__(self) -> str:
            return "w" * 100_000

    class _Broken:
        def __str__(self) -> str:
            raise RuntimeError("no text form")

    vals, labels, cut = driver_helpers.cell_truncated_json([_Wide(), _Broken(), 7], 8192)
    assert cut is True and len(vals[0].encode()) <= 8192
    assert isinstance(vals[1], str) and "_Broken" in vals[1]
    assert vals[2] == 7 and labels[0] == labels[1] == "text"


# F36: a timed-out statement stops on the server, and a query's own
# timeout is the driver's ceiling.


class _CancelScript:
    def __init__(self) -> None:
        self.executing = threading.Event()
        self.release = threading.Event()
        self.cancels = 0
        self.cancel_on_closed = 0
        self.log: list[Any] = []
        self.conn: Any = None


class _CancelCursor:
    def __init__(self, s: _CancelScript) -> None:
        self._s = s
        self.closed = False
        self.description: list[Any] | None = None

    def execute(self, sql: str, *params: Any) -> None:
        self._s.log.append(("execute", sql))
        if sql.startswith(("SET ", "EXEC sys.sp_describe_first_result_set")):
            return
        self.description = [("v", int, None, None, None, None, True)]
        self._s.executing.set()
        self._s.release.wait(5)
        if self._s.cancels:
            raise _FakePyodbcError("HY008", "[HY008] Operation canceled (0) (SQLExecDirectW)")

    def cancel(self) -> None:
        if self.closed:
            self._s.cancel_on_closed += 1
        self._s.cancels += 1
        self._s.release.set()

    def fetchmany(self, n: int) -> list[Any]:
        return []

    def fetchall(self) -> list[Any]:
        return []

    def nextset(self) -> bool:
        return False

    def close(self) -> None:
        self.closed = True


class _CancelConn:
    def __init__(self, s: _CancelScript) -> None:
        self._s = s
        self.timeout = 0
        self.autocommit = True

    def cursor(self) -> _CancelCursor:
        return _CancelCursor(self._s)

    def rollback(self) -> None:
        self._s.log.append("rollback")

    def close(self) -> None:
        self._s.log.append("close")


def _mssql_cancel(monkeypatch: pytest.MonkeyPatch, s: _CancelScript) -> mssql_module.MssqlConnector:
    def connect(connstr: str, **kwargs: Any) -> _CancelConn:
        conn = _CancelConn(s)
        s.conn = conn
        return conn

    fake = types.SimpleNamespace(
        connect=connect, drivers=lambda: ["ODBC Driver 18 for SQL Server"], Error=_FakePyodbcError
    )
    monkeypatch.setattr(mssql_module, "open_module", lambda *_a, **_k: fake)
    resolved = _resolved({"type": "mssql", "host": "h", "database": "d"})
    return mssql_module.MssqlConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


def test_f36_mssql_cancel_stops_the_running_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    s = _CancelScript()
    conn = _mssql_cancel(monkeypatch, s)
    assert conn.cancel_current() is False, "idle"
    errors: list[BaseException] = []

    def run() -> None:
        try:
            conn.execute_query(QuerySpec(sql="SELECT v FROM big"))
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert s.executing.wait(5)
        assert conn.cancel_current() is True
    finally:
        s.release.set()
        worker.join(5)
    assert s.cancels == 1
    assert errors and isinstance(errors[0], ConnectorError) and "HY008" in str(errors[0])
    assert conn.cancel_current() is False, "the finished query's cursor is gone"
    assert s.cancels == 1 and s.cancel_on_closed == 0
    caps = conn.capabilities()
    assert caps.get(Cap.CANCEL) == caps.get(Cap.SERVER_SIDE_CANCEL) == CapabilityState.UNVERIFIED


def test_f36_mssql_query_timeout_follows_the_query(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _MssqlScript(rows=[(1,)])
    conn = _mssql(monkeypatch, script)
    conn.execute_query(QuerySpec(sql="SELECT v FROM t", timeout_seconds=12.2))
    assert script.conn is not None and script.conn.timeout == 13  # type: ignore[attr-defined]
    conn.execute_query(QuerySpec(sql="SELECT v FROM t", timeout_seconds=600))
    assert script.conn.timeout == 60, "never above the policy's hard timeout"  # type: ignore[attr-defined]
    conn._connect()
    assert script.conn.timeout == 60, "metadata connections keep the hard ceiling"  # type: ignore[attr-defined]


def test_f36_db2_query_timeout_follows_the_query(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([(1,)], [_Col("N", int)])
    conn, fake = _db2(tmp_path, monkeypatch)
    _db2_dbi(monkeypatch, state)
    conn.execute_query(QuerySpec(sql="SELECT N FROM T", timeout_seconds=4.5))
    assert [v for k, v in _dsn_keys(fake.dsns[-1]) if k == "QUERYTIMEOUT"] == ["5"]
    conn.execute_query(QuerySpec(sql="SELECT N FROM T", timeout_seconds=600))
    assert [v for k, v in _dsn_keys(fake.dsns[-1]) if k == "QUERYTIMEOUT"] == ["60"]
    conn._connect()
    assert [v for k, v in _dsn_keys(fake.dsns[-1]) if k == "QUERYTIMEOUT"] == ["60"]
    assert conn.cancel_current() is False


# F37: every engine bounds its connect by connect_timeout_seconds.


def test_f37_db2_connect_timeout_reaches_the_dsn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeIbmDb()
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    resolved = _resolved({"type": "db2", "host": "h", "database": "d", "connect_timeout_seconds": 2.5})
    db2_module.Db2Connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))._connect()
    assert [v for k, v in _dsn_keys(fake.dsns[0]) if k == "CONNECTTIMEOUT"] == ["3"]


def test_f37_oracle_connect_timeout_reaches_the_driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeOracleDb()
    monkeypatch.setattr(oracle_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setattr(oracle_module, "_THICK_STATE", oracle_module.ThickState(), raising=False)
    resolved = _resolved({"type": "oracle", "host": "h", "database": "S", "connect_timeout_seconds": 3})
    oracle_module.OracleConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))._connect()
    assert fake.connect_kwargs[0]["tcp_connect_timeout"] == 3.0
    tns = _tns(tmp_path, f"PROD = {TCPS}\n")
    conn, fake = _oracle(tmp_path, monkeypatch, options=_alias_options(tmp_path, tns, "PROD"))
    conn._connect()
    assert fake.connect_kwargs[0]["tcp_connect_timeout"] == 10.0, "the alias path is bounded too"


def test_f37_mysql_handshake_is_bounded_by_the_connect_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _Rows([], [])
    conn, fake = _my_module(tmp_path, monkeypatch, state, connect_timeout_seconds=0.5)
    handle = conn._connect()
    kw = fake.kwargs[0]
    assert kw["connect_timeout"] == 1, "PyMySQL refuses 0 (int(0.5))"
    assert kw["read_timeout"] == 1, "the handshake read was bounded by the 65 s query read timeout"
    assert handle._read_timeout == 65, "queries still get hard timeout + 5"


_DB2_HUNG_LISTENER_PROBE = r"""
import socket, sys, threading, time
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.db2 import Db2Connector
from universal_db_mcp.security.policy import EffectivePolicy

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)
held = []
threading.Thread(target=lambda: [held.append(listener.accept()[0]) for _ in iter(int, 1)], daemon=True).start()
cfg = ConnectionConfig.model_validate({
    "type": "db2", "host": "127.0.0.1", "port": listener.getsockname()[1], "database": "TESTDB",
    "connect_timeout_seconds": 1, "username_file": sys.argv[1], "password_file": sys.argv[2],
})
resolved = ResolvedConnection("d", cfg)
start = time.monotonic()
health = Db2Connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)).health_check()
print("healthy=%s after %.2fs" % (health.healthy, time.monotonic() - start), flush=True)
"""


def test_f37_db2_hung_listener_fails_within_the_connect_timeout(tmp_path: Path) -> None:
    """The real driver against a listener that accepts and never answers.
    In a child process with a hard timeout: a driver build that ignored
    CONNECTTIMEOUT, or held the GIL through the connect, would otherwise hang
    the whole test run instead of failing this test."""
    pytest.importorskip("ibm_db")
    args = [sys.executable, "-c", _DB2_HUNG_LISTENER_PROBE, _secret(tmp_path, "du", "u"), _secret(tmp_path, "dp", "p")]
    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=1 + 5, cwd=REPO)  # noqa: S603 - this interpreter, a fixed probe
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the connect was still blocked after connect_timeout_seconds + 5 s: {exc.stderr!r}")
    match = re.search(r"healthy=(\w+) after ([0-9.]+)s", run.stdout)
    assert match, (run.stdout, run.stderr[-2000:])
    assert match.group(1) == "False"
    assert float(match.group(2)) < 1 + 2, run.stdout


# =================================================================== round 2
# Review round 2 of this group: values still read whole (Db2 LOBs, the
# numeric and object types), and the SQL Server read-only wording.


class _DescribingIbmDb(_FakeIbmDb):
    """ibm_db stand-in whose prepare describes ``described`` (name, type)
    and never executes; it logs the order handles are released in."""

    def __init__(self, described: list[tuple[str, str]], log: list[str]) -> None:
        super().__init__()
        self.described = described
        self.log = log
        self.prepared: list[str] = []

    def prepare(self, conn: str, sql: str) -> str:
        self.prepared.append(sql)
        return "described"

    def num_fields(self, stmt: str) -> int:
        return len(self.described)

    def field_name(self, stmt: str, i: int) -> str:
        return self.described[i][0]

    def field_type(self, stmt: str, i: int) -> str:
        return self.described[i][1]

    def free_stmt(self, stmt: str) -> bool:
        self.log.append(f"free {stmt}")
        return True

    def close(self, conn: str) -> bool:
        self.log.append("conn.close")
        return True


def _db2_described(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, described: list[tuple[str, str]], rows: list[tuple[Any, ...]]
) -> tuple[db2_module.Db2Connector, _DescribingIbmDb, _Rows]:
    state = _Rows(rows, [_Col(name, None) for name, _kind in described])
    fake = _DescribingIbmDb(described, state.log)
    conn, _ = _db2(tmp_path, monkeypatch, fake=fake)
    _db2_dbi(monkeypatch, state)
    return conn, fake, state


def test_f08_db2_lob_columns_are_cut_on_the_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 2: ibm_db read a CLOB whole even one row at a time: a
    300 MB CLOB with max_rows=1 cost 1196 MB of RSS (live, delta 15 MB now).
    The statement is described by a prepare (nothing runs) and its CLOB,
    DBCLOB, BLOB and XML columns are cut by the server, under their own
    names, in the statement's own order."""
    described = [("ID", "int"), ("DOC", "clob"), ("NDOC", "dbclob"), ("IMG", "blob"), ("X", "xml"), ('A"B', "string")]
    conn, fake, state = _db2_described(tmp_path, monkeypatch, described, [(1, "d", "n", b"i", "<x/>", "s")])
    sql = "SELECT id, doc, ndoc, img, x, ab FROM t WHERE id > ? ORDER BY id WITH UR;"
    out = conn._execute(QuerySpec(sql=sql, parameters=[5], max_cell_bytes=100))
    assert fake.prepared == [sql], "described once, as written"
    assert state.statements == [(
        'SELECT udbmcp_q.c1 AS "ID", SUBSTRING(udbmcp_q.c2, 1, 101, CODEUNITS32) AS "DOC", '
        'SUBSTRING(udbmcp_q.c3, 1, 101, CODEUNITS32) AS "NDOC", SUBSTRING(udbmcp_q.c4, 1, 101, OCTETS) AS "IMG", '
        'SUBSTRING(XMLSERIALIZE(udbmcp_q.c5 AS CLOB(2G)), 1, 101, CODEUNITS32) AS "X", udbmcp_q.c6 AS "A""B" '
        "FROM (\nSELECT id, doc, ndoc, img, x, ab FROM t WHERE id > ? ORDER BY id\n) "
        "AS udbmcp_q(c1, c2, c3, c4, c5, c6) ORDER BY ORDER OF udbmcp_q WITH UR",
        (5,),
    )], "the isolation clause is the outermost statement's"
    assert [c for c, _t in out.columns] == ["ID", "DOC", "NDOC", "IMG", "X", 'A"B']


def test_f08_db2_results_without_lobs_run_as_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, fake, state = _db2_described(tmp_path, monkeypatch, [("ID", "int"), ("NAME", "string")], [(1, "a")])
    out = conn._execute(QuerySpec(sql="SELECT id, name FROM t"))
    assert state.statements == [("SELECT id, name FROM t", None)]
    assert out.rows == [[1, "a"]] and "free described" in state.log


@pytest.mark.parametrize(
    ("body", "main", "tail"),
    [
        ("SELECT doc FROM t WITH UR", "SELECT doc FROM t", "WITH UR"),
        ("SELECT doc FROM t FOR READ ONLY", "SELECT doc FROM t", "FOR READ ONLY"),
        ("SELECT doc FROM t FOR FETCH ONLY WITH CS", "SELECT doc FROM t", "FOR FETCH ONLY WITH CS"),
        ("SELECT doc FROM t FOR READ ONLY OPTIMIZE FOR 5 ROWS WITH UR", "SELECT doc FROM t",
         "FOR READ ONLY OPTIMIZE FOR 5 ROWS WITH UR"),
        ("SELECT doc FROM t OPTIMIZE FOR 1 ROW", "SELECT doc FROM t", "OPTIMIZE FOR 1 ROW"),
        ("SELECT doc FROM t FOR /* c */ READ ONLY", "SELECT doc FROM t", "FOR /* c */ READ ONLY"),
        ("SELECT doc FROM t FETCH FIRST 2 ROWS ONLY", "SELECT doc FROM t FETCH FIRST 2 ROWS ONLY", ""),
        ('SELECT doc AS "ONLY" FROM t', 'SELECT doc AS "ONLY" FROM t', ""),
        ("SELECT 'WITH UR' FROM t", "SELECT 'WITH UR' FROM t", ""),
        ('SELECT doc FROM "WITH" "UR"', 'SELECT doc FROM "WITH" "UR"', ""),
    ],
)
def test_f08_db2_clauses_only_the_outermost_statement_takes_are_moved_out(body: str, main: str, tail: str) -> None:
    """FOR READ ONLY and OPTIMIZE FOR are refused inside a nested table
    expression (SQL0104N live); they are read from tokens, so a quoted name
    or a string is never taken for one."""
    assert db2_module._db2_read_tail(body) == (main, tail)


def test_f08_db2_a_capped_rewrite_db2_refuses_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, _fake, state = _db2_described(tmp_path, monkeypatch, [("DOC", "clob")], [("x",)])
    state.fail = lambda s: RuntimeError(
        "ibm_db_dbi::ProgrammingError: Statement Execute Failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0104N  "
        'An unexpected token "LOCKED DATA" was found.  SQLSTATE=42601 SQLCODE=-104'
    )
    sql = "SELECT doc FROM t SKIP LOCKED DATA"
    with pytest.raises(ConnectorError, match="SUBSTRING") as exc:
        conn._execute(QuerySpec(sql=sql))
    assert exc.value.category == "QUERY_ERROR" and "'DOC'" in str(exc.value)
    assert [s for s, _ in state.statements if s == sql] == [], "the statement never ran with its values uncut"


def test_f08_db2_a_capped_statement_that_times_out_is_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, _fake, state = _db2_described(tmp_path, monkeypatch, [("DOC", "clob")], [("x",)])
    state.fail = lambda s: RuntimeError(
        "[IBM][CLI Driver][DB2/LINUXX8664] SQL0952N  Processing was cancelled due to an interrupt.  "
        "SQLSTATE=57014 SQLCODE=-952"
    )
    with pytest.raises(ConnectorError) as exc:
        conn._execute(QuerySpec(sql="SELECT doc FROM t"))
    assert exc.value.category == "TIMEOUT"


def test_db2_statement_handle_is_released_before_the_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found live in round 2: after any failed statement the next query
    failed with 'Fetch Failure: ' (empty). The failed cursor was freed by
    the garbage collector after its connection closed, which left an error
    set in the driver; it is now closed first, on every path."""
    conn, _fake, state = _db2_described(tmp_path, monkeypatch, [("N", "int")], [(1,)])
    state.fail = lambda s: RuntimeError("[IBM][CLI Driver] SQL0206N  x.  SQLSTATE=42703 SQLCODE=-206")
    with pytest.raises(ConnectorError):
        conn._execute(QuerySpec(sql="SELECT n FROM t"))
    assert state.log.index("cursor.close") < state.log.index("conn.close"), state.log
    state.log.clear()
    state.fail = lambda s: None
    conn._execute(QuerySpec(sql="SELECT n FROM t"))
    assert state.log.index("cursor.close") < state.log.index("conn.close"), state.log


def test_f08_decimal_values_are_capped_like_text() -> None:
    """Review round 2: a PostgreSQL numeric of 131072 digits came back whole
    in one cell, with no cell-truncation warning."""
    vals, labels, cut = driver_helpers.adapt_row([Decimal("9" * 131_072), Decimal("12.50")], 8192)
    assert cut == [0] and labels == ["decimal", "decimal"]
    assert vals[0] == "9" * 8192 and vals[1] == "12.50"


class _FakeObjType:
    def __init__(self, name: str, *, collection: bool, attributes: tuple[str, ...] = ()) -> None:
        self.name = name
        self.iscollection = collection
        self.attributes = [types.SimpleNamespace(name=a) for a in attributes]


class _FakeDbObject:
    """python-oracledb DbObject stand-in: str() is only its repr."""

    def __init__(self, kind: _FakeObjType, elements: list[Any] | None = None, **attributes: Any) -> None:
        self.type = kind
        self._elements = elements or []
        self.reads = 0
        for name, value in attributes.items():
            setattr(self, name, value)

    def first(self) -> int | None:
        return 0 if self._elements else None

    def next(self, index: int) -> int | None:
        return index + 1 if index + 1 < len(self._elements) else None

    def getelement(self, index: int) -> Any:
        self.reads += 1
        return self._elements[index]

    def __str__(self) -> str:
        return f"<oracledb.DbObject {self.type.name} at 0x1>"


def test_f34_oracle_objects_and_collections_are_json_up_to_the_cell_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 2: an object or collection column came back as its repr
    ('<oracledb.DbObject SYS.ODCIVARCHAR2LIST at 0x...>'). Only the elements
    that can still fit the cell limit are converted."""
    varchars = _FakeObjType("ODCIVARCHAR2LIST", collection=True)
    big = _FakeDbObject(varchars, ["x" * 3000 for _ in range(3000)])
    point_type = _FakeObjType("SDO_POINT_TYPE", collection=False, attributes=("X", "Y", "Z"))
    point = _FakeDbObject(point_type, X=1, Y=2.5, Z=None)
    geometry = _FakeDbObject(
        _FakeObjType("SDO_GEOMETRY", collection=False, attributes=("SDO_GTYPE", "SDO_POINT", "SDO_ORDINATES")),
        SDO_GTYPE=2001, SDO_POINT=point,
        SDO_ORDINATES=_FakeDbObject(_FakeObjType("SDO_ORDINATE_ARRAY", collection=True), [1, 2]),
    )
    objects = _FakeDbType("DB_TYPE_OBJECT")
    state = _Rows([(big, geometry)], [_Col("C", objects), _Col("G", objects)])
    out = _ora_exec(tmp_path, monkeypatch, state)._execute(QuerySpec(sql="SELECT c, g FROM t", max_cell_bytes=8192))
    c, g = out.rows[0]
    assert c.startswith('["xxx') and len(c) == 8192
    assert big.reads <= 3, "elements past the cell limit are not converted"
    assert g == '{"SDO_GTYPE": 2001, "SDO_POINT": {"X": 1, "Y": 2.5, "Z": null}, "SDO_ORDINATES": [1, 2]}'
    assert out.truncated and any("'C'" in w for w in out.warnings)


def test_f35_mssql_read_only_limitation_names_what_is_not_detected() -> None:
    """Review round 2: the capability text said only a statement after SET
    NOCOUNT ON goes unnoticed; DDL, TRUNCATE, WAITFOR and COMMIT report no
    rowcount either, and a COMMIT defeats the rollback."""
    resolved = _resolved({"type": "mssql", "host": "h", "database": "d"})
    matrix = mssql_module.MssqlConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)).capabilities()
    detail = next(lim.detail for lim in matrix.limitations if lim.scope == "read_only")
    for word in ("DDL", "TRUNCATE", "WAITFOR", "COMMIT", "NOCOUNT", "guard"):
        assert word in detail, word


@pytest.mark.parametrize(
    ("engine", "words"),
    [
        ("db2", ("CLOB", "XML", "refused")),
        ("mysql", ("derived table", "materialized", "MariaDB", "refused")),
        ("oracle", ("JSON", "LONG", "up to 4")),
    ],
)
def test_f08_capabilities_say_how_values_are_cut(engine: str, words: tuple[str, ...]) -> None:
    """For the operator and the docs: what is cut on the server, and what
    the cut can still cost."""
    options = {"os_authentication": True} if engine == "mysql" else {}
    resolved = _resolved({"type": engine, "host": "h", "database": "d", "options": options})
    policy = EffectivePolicy.build(SecurityConfig(), resolved)
    if engine == "db2":
        matrix = db2_module.Db2Connector(resolved, policy).capabilities()
    elif engine == "mysql":
        matrix = mysql_module.MySQLConnector(resolved, policy).capabilities()
    else:
        matrix = oracle_module.OracleConnector(resolved, policy).capabilities()
    detail = next(lim.detail for lim in matrix.limitations if lim.scope == "query")
    for word in words:
        assert word in detail, word


# =================================================================== wave 2
# Integration wave: what the round-3 reviews found still open.


# F85: a discarded connector releases its pooled metadata session.


class _Closable:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


@pytest.mark.parametrize(("engine", "slot"), [
    ("postgres", "_meta_conn"), ("mysql", "_meta_conn"), ("oracle", "_meta_conn"), ("clickhouse", "_meta_client"),
])
def test_f85_close_releases_the_pooled_metadata_session_once(engine: str, slot: str) -> None:
    from universal_db_mcp.connectors.registry import build_connector

    options = {} if engine == "oracle" else {"os_authentication": True}
    resolved = _resolved({"type": engine, "host": "h", "database": "d", "options": options})
    conn = build_connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    session = _Closable()
    setattr(conn, slot, session)
    conn.close()
    conn.close()
    assert session.closed == 1
    assert getattr(conn, slot) is None
    assert not conn._pool_lock.locked()  # type: ignore[attr-defined]


def test_f85_close_is_part_of_every_connector_and_tolerates_a_failing_close(tmp_path: Path) -> None:
    from universal_db_mcp.connectors.base import DatabaseConnector

    db = tmp_path / "x.db"
    sqlite3.connect(db).close()
    resolved = _resolved({"type": "sqlite", "database": str(db)})
    lite = SQLiteConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))
    assert callable(DatabaseConnector.close)
    lite.close()  # nothing pooled: a no-op

    class _Broken:
        def close(self) -> None:
            raise OSError("socket already gone")

    pg = _resolved({"type": "postgres", "host": "h", "database": "d", "options": {"os_authentication": True}})
    conn = pg_module.PostgresConnector(pg, EffectivePolicy.build(SecurityConfig(), pg))
    conn._meta_conn = _Broken()
    conn.close()
    assert conn._meta_conn is None


# F37 (Oracle): python-oracledb decides Thin or Thick inside the process's
# first connect and holds its driver-mode lock until that connect returns.


class _ModeRecordingOracleDb(_FakeOracleDb):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def enable_thin_mode(self) -> None:
        self.calls.append("enable_thin_mode")

    def init_oracle_client(self, **kwargs: Any) -> None:
        self.calls.append("init_oracle_client")
        super().init_oracle_client(**kwargs)

    def connect(self, **kwargs: Any) -> Any:
        self.calls.append("connect")
        return super().connect(**kwargs)


@pytest.mark.parametrize("thick", [False, True])
def test_f37_oracle_fixes_the_driver_mode_before_it_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, thick: bool
) -> None:
    fake = _ModeRecordingOracleDb()
    conn, _ = _oracle(tmp_path, monkeypatch, options={"thick_mode": thick}, tls=False, fake=fake)
    conn._connect()
    conn._connect()
    if thick:
        assert fake.calls == ["init_oracle_client", "connect", "connect"]
    else:
        assert fake.calls[:2] == ["enable_thin_mode", "connect"]
        assert "init_oracle_client" not in fake.calls


_ORACLE_MODE_LOCK_PROBE = r"""
import socket, sys, threading, time
from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig
from universal_db_mcp.connectors.oracle import OracleConnector
from universal_db_mcp.security.policy import EffectivePolicy

user_file, password_file = sys.argv[1], sys.argv[2]
hung = socket.socket()
hung.bind(("127.0.0.1", 0))
hung.listen(8)  # accepts in the kernel and never answers
closed = socket.socket()
closed.bind(("127.0.0.1", 0))
closed_port = closed.getsockname()[1]
closed.close()  # nothing listens there: connects are refused


def connector(port):
    cfg = ConnectionConfig.model_validate({
        "type": "oracle", "host": "127.0.0.1", "port": port, "database": "FREEPDB1",
        "username_file": user_file, "password_file": password_file, "connect_timeout_seconds": 3,
    })
    resolved = ResolvedConnection("o", cfg)
    return OracleConnector(resolved, EffectivePolicy.build(SecurityConfig(), resolved))


threading.Thread(target=lambda: connector(hung.getsockname()[1])._connect(), daemon=True).start()
time.sleep(1.0)  # the first connect of the process is now inside the driver
start = time.monotonic()
try:
    connector(closed_port)._connect()
except Exception as exc:
    print("second connect failed after %.2fs: %s" % (time.monotonic() - start, type(exc).__name__), flush=True)
"""


def test_f37_oracle_hung_first_connect_does_not_hold_other_connects(tmp_path: Path) -> None:
    """The real driver, in a child process (its mode is process-global and
    the hung connect never returns): while the first connect waits on a
    listener that never answers, a second connect elsewhere must fail on
    its own, not wait for the first one on the driver-mode condition."""
    _real_oracledb()
    args = [sys.executable, "-c", _ORACLE_MODE_LOCK_PROBE, _secret(tmp_path, "u", "u"), _secret(tmp_path, "p", "p")]
    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=20, cwd=REPO)  # noqa: S603 - this interpreter, a fixed probe
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the second connect waited on the first one: {exc.stdout!r} {exc.stderr!r}")
    match = re.search(r"second connect failed after ([0-9.]+)s", run.stdout)
    assert match, (run.stdout, run.stderr[-2000:])
    assert float(match.group(1)) < 5.0, run.stdout


# F26: the catalogs leave system schemas out, except those the administrator
# opened. The resolver permits only what list_tables returns, so leaving an
# allowed one out made security.allowed_system_schemas inert (and the
# guard's own advice to set it false).


def _opened(*schemas: str) -> SecurityConfig:
    return SecurityConfig(allowed_system_schemas=list(schemas))


def test_f26_db2_keeps_a_system_schema_the_administrator_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [*_DB2_ROWS, ("SYSIBM", "SYSDUMMY1", "T", 1)]
    conn, fake = _db2(tmp_path, monkeypatch, fake=_FakeIbmDb(rows=rows), security=_opened("sysibm", "syscat"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert {("SYSIBM", "SYSDUMMY1"), ("SYSIBM", "SYSTABLES"), ("SYSCAT", "TABLES")} <= out
    assert ("SYSIBMINTERNAL", "OPTSTATS") not in out and ("NULLID", "PKG") not in out
    _sql, params = fake.executed[-1]
    assert not {"SYSIBM", "SYSCAT"} & set(params)
    assert conn.list_tables("SYSCAT", {"view"}, None)[0].name == "TABLES"


def test_f26_db2_with_every_system_schema_allowed_binds_no_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    security = _opened(*(s.lower() for s in db2_module._DB2_SYSTEM_SCHEMAS))
    conn, fake = _db2(tmp_path, monkeypatch, fake=_FakeIbmDb(rows=_DB2_ROWS), security=security)
    assert len(conn.list_tables(None, {"table", "view"}, None)) == len(_DB2_ROWS)
    sql, params = fake.executed[-1]
    assert "NOT IN" not in sql and params == ("T", "V")


def test_f26_db2_allowed_schemas_naming_a_system_schema_also_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeIbmDb(rows=_DB2_ROWS)
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    resolved = _resolved({
        "type": "db2", "host": "h", "database": "SAMPLE", "allowed_schemas": ["APP", "SYSCAT"],
        "username_file": _secret(tmp_path, "du", "db2ro"), "password_file": _secret(tmp_path, "dp", "pw"),
    })
    conn = db2_module.Db2Connector(resolved, EffectivePolicy.build(_opened(), resolved))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert ("SYSCAT", "TABLES") in out and ("SYSIBM", "SYSTABLES") not in out


def test_f26_oracle_11g_keeps_an_allowed_dictionary_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [*_ORACLE_ROWS, ("SYS", "DUAL", "TABLE")]
    fake = _FakeOracleDb(version="11.2.0.4.0", rows=rows)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake, security=_opened("sys"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table"}, None)}
    assert {("SYS", "DUAL"), ("SYS", "OBJ$"), ("TRAVEL", "BOOKINGS")} <= out
    assert ("SYSTEM", "HELP") not in out and ("CTXSYS", "DR$THS") not in out
    _sql, params = fake.executed[-1]
    assert "SYS" not in params and "SYSTEM" in params


def test_f26_oracle_12c_adds_the_allowed_owners_to_the_maintained_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeOracleDb(version="19.3.0.0.0", rows=_ORACLE_ROWS)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake, security=_opened("sys"))
    conn.list_tables("SYS", {"table", "view"}, None)
    sql, params = fake.executed[-1]
    kept = "(owner IN (SELECT username FROM sys.all_users WHERE oracle_maintained = 'N') OR owner IN (:"
    assert sql.count(kept) == 2, sql
    assert params.count("SYS") == 4, "each arm binds the allowed owner, then the requested schema"
    assert re.findall(r":(\d+)", sql) == [str(i) for i in range(1, len(params) + 1)]


def test_f26_oracle_default_policy_still_hides_the_dictionary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeOracleDb(version="11.2.0.4.0", rows=_ORACLE_ROWS)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake)
    assert {t.schema for t in conn.list_tables(None, {"table"}, None)} == {"SYSADM_APP", "TRAVEL"}


class _CatalogConn:
    """PostgreSQL (conn.execute) and PyMySQL (cursor) metadata stand-in whose
    catalog applies the connector's system-schema exclusion like the server:
    the bound values after the kinds are the hidden schemas."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.executed: list[tuple[str, list[Any]]] = []

    def _answer(self, sql: str, params: Any) -> list[tuple[Any, ...]]:
        bound = list(params or [])
        self.executed.append((sql, bound))
        if isinstance(bound[0], list):  # PostgreSQL: relkind = ANY(%s), nspname <> ALL(%s)
            kinds, hidden = bound[0], (bound[1] if "<> ALL(" in sql else [])
        else:  # MySQL: table_type IN (%s, ...) AND table_schema NOT IN (%s, ...)
            n = sql.split("table_type IN (", 1)[1].split(")", 1)[0].count("%s")
            kinds, hidden = bound[:n], bound[n:]
        return [r for r in self.rows if r[2] in kinds and r[0] not in hidden]

    def execute(self, sql: str, params: Any = None) -> Any:
        rows = self._answer(sql, params)
        return types.SimpleNamespace(fetchall=lambda: rows)

    def cursor(self) -> Any:
        conn = self

        class _Cur:
            rows: list[tuple[Any, ...]] = []

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: object) -> None:
                return None

            def execute(self, sql: str, params: Any = None) -> None:
                self.rows = conn._answer(sql, params)

            def fetchall(self) -> list[tuple[Any, ...]]:
                return self.rows

        return _Cur()


def _catalog_connector(
    monkeypatch: pytest.MonkeyPatch, engine: str, rows: list[tuple[Any, ...]], security: SecurityConfig
) -> tuple[Any, _CatalogConn]:
    from contextlib import contextmanager

    resolved = _resolved({"type": engine, "host": "h", "database": "d", "options": {"os_authentication": True}})
    policy = EffectivePolicy.build(security, resolved)
    conn = (pg_module.PostgresConnector if engine == "postgres" else mysql_module.MySQLConnector)(resolved, policy)
    catalog = _CatalogConn(rows)

    @contextmanager
    def shared() -> Any:
        yield catalog

    monkeypatch.setattr(conn, "_shared_meta_conn", shared)
    return conn, catalog


_PG_CATALOG = [
    ("information_schema", "tables", "v", None), ("pg_catalog", "pg_class", "r", 400),
    ("pg_toast", "pg_toast_2619", "r", 1), ("public", "orders", "r", 10),
]
_MYSQL_CATALOG = [
    # mysql.help_topic: mysql.user holds credentials, never listed (test_hardening_2026_09_28_credential_views)
    ("information_schema", "TABLES", "SYSTEM VIEW", None), ("mysql", "help_topic", "BASE TABLE", 3),
    ("performance_schema", "threads", "BASE TABLE", 50), ("sys", "sys_config", "BASE TABLE", 6),
    ("testdb", "orders", "BASE TABLE", 10),
]


@pytest.mark.parametrize(("engine", "catalog"), [("postgres", _PG_CATALOG), ("mysql", _MYSQL_CATALOG)])
def test_f26_information_schema_is_listed_when_it_is_allowed(
    monkeypatch: pytest.MonkeyPatch, engine: str, catalog: list[tuple[Any, ...]]
) -> None:
    """security.allowed_system_schemas defaults to [information_schema], and
    the guard permits it; the catalog must then list it too."""
    conn, _ = _catalog_connector(monkeypatch, engine, catalog, _opened("information_schema"))
    out = {(t.schema, t.name.lower(), t.kind) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert ("information_schema", "tables", "view") in out
    assert {s for s, _n, _k in out} == {"information_schema", catalog[-1][0]}


@pytest.mark.parametrize(("engine", "catalog"), [("postgres", _PG_CATALOG), ("mysql", _MYSQL_CATALOG)])
def test_f26_allowed_system_schemas_are_listed_after_the_databases_own(
    monkeypatch: pytest.MonkeyPatch, engine: str, catalog: list[tuple[Any, ...]]
) -> None:
    """Review round 5: MySQL sorts information_schema before every user
    database, so page 1 of a default db_list_tables was 50 of its views and
    no user table. The catalog views an administrator opened now follow the
    database's own objects, each part in the engine's order."""
    rows = [catalog[-1], *catalog[:-1], (catalog[-1][0], "zz_last", catalog[-1][2], 1)]
    conn, _ = _catalog_connector(monkeypatch, engine, rows, _opened("information_schema", "pg_catalog", "mysql"))
    listed = [(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)]
    user = catalog[-1][0]
    assert [s for s, _n in listed[:2]] == [user, user] and listed[1][1] == "zz_last", listed
    assert {s for s, _n in listed[2:]} == {"information_schema", "pg_catalog" if engine == "postgres" else "mysql"}
    assert listed[2:] == [(r[0], r[1]) for r in catalog[:-1] if r[0] in {s for s, _n in listed[2:]}], listed


def test_f26_mssql_lists_the_catalog_views_after_the_databases_own(monkeypatch: pytest.MonkeyPatch) -> None:
    class _CatalogFirst(_MssqlCatalogCursor):
        def execute(self, sql: str, params: list[Any]) -> None:
            super().execute(sql, params)
            self.rows = [r for r in self.rows if r[0] in ("sys", "INFORMATION_SCHEMA")] + [
                r for r in self.rows if r[0] not in ("sys", "INFORMATION_SCHEMA")
            ]

    conn = _mssql(monkeypatch, _MssqlScript())
    conn.policy = EffectivePolicy.build(
        SecurityConfig(allowed_system_schemas=["information_schema", "sys"]), conn.connection
    )
    log: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(
        conn, "_connect", lambda: types.SimpleNamespace(cursor=lambda: _CatalogFirst(log), close=lambda: None)
    )
    assert [t.schema for t in conn.list_tables(None, {"table", "view"}, None)] == [
        "dbo", "app", "sys", "sys", "INFORMATION_SCHEMA"
    ]


@pytest.mark.parametrize(("engine", "catalog"), [("postgres", _PG_CATALOG), ("mysql", _MYSQL_CATALOG)])
def test_f26_system_schemas_stay_hidden_unless_allowed(
    monkeypatch: pytest.MonkeyPatch, engine: str, catalog: list[tuple[Any, ...]]
) -> None:
    conn, _ = _catalog_connector(monkeypatch, engine, catalog, _opened())
    assert {t.schema for t in conn.list_tables(None, {"table", "view"}, None)} == {catalog[-1][0]}
    system = "pg_catalog" if engine == "postgres" else "mysql"
    conn, _ = _catalog_connector(monkeypatch, engine, catalog, _opened(system))
    assert {t.schema for t in conn.list_tables(None, {"table", "view"}, None)} == {system, catalog[-1][0]}


# Wave-3 review (I13): information_schema is open by default, and MySQL's
# PROCESSLIST shows the statement every other session of the shared account
# is running, literals included (INNODB_TRX.trx_query likewise, with the
# PROCESS privilege). The resolver permits only what list_tables returns.

_MYSQL_STATEMENT_VIEWS = [
    ("information_schema", "PROCESSLIST", "SYSTEM VIEW", None),
    ("information_schema", "INNODB_TRX", "SYSTEM VIEW", None),
    ("performance_schema", "processlist", "BASE TABLE", 3),
    ("performance_schema", "events_statements_current", "BASE TABLE", 3),
    ("performance_schema", "events_statements_history_long", "BASE TABLE", 3),
]


def test_i13_mysql_never_lists_the_views_of_other_sessions_statements(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [*_MYSQL_CATALOG, *_MYSQL_STATEMENT_VIEWS]
    conn, _ = _catalog_connector(monkeypatch, "mysql", rows, _opened("information_schema"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert ("information_schema", "TABLES") in out
    assert ("information_schema", "PROCESSLIST") not in out and ("information_schema", "INNODB_TRX") not in out
    assert "performance_schema" not in {s for s, _n in out}


def test_i13_mysql_never_lists_performance_schema_statements_even_where_it_was_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An administrator who names performance_schema opens its tables, but
    not its statement tables (processlist, threads, events_statements_*):
    the policy refuses them whatever is opened (SESSION_SQL_VIEWS), and
    since wave 4 the listing leaves them out too."""
    other = ("performance_schema", "setup_actors", "BASE TABLE", 1)
    rows = [*_MYSQL_CATALOG, *_MYSQL_STATEMENT_VIEWS, other]
    conn, _ = _catalog_connector(monkeypatch, "mysql", rows, _opened("information_schema", "performance_schema"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert (other[0], other[1]) in out
    statements = {(r[0], r[1]) for r in rows if r[0] == "performance_schema" and r != other}
    assert statements and out.isdisjoint(statements), sorted(out)
    assert ("information_schema", "PROCESSLIST") not in out and ("information_schema", "INNODB_TRX") not in out


def test_i13_mysql_never_lists_lock_waits_or_fulltext_words_whatever_is_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wave-3 review: security.allowed_system_schemas is one list for every
    engine, so naming 'sys' for SQL Server's or Oracle's dictionary opens
    MySQL's sys too. Its lock-wait views carry the waiting and blocking
    sessions' statements with their literals (INNODB_TRX.trx_query,
    threads.PROCESSLIST_INFO; MySQL 9.7), and INNODB_FT_INDEX_CACHE/TABLE the
    indexed words of any table the DBA points innodb_ft_aux_table at. None
    is listed, so the resolver never finds one. sys views of normalized
    digests (statement_analysis) stay listed."""
    lock_waits = [
        ("information_schema", "INNODB_FT_INDEX_CACHE", "SYSTEM VIEW", None),
        ("information_schema", "INNODB_FT_INDEX_TABLE", "SYSTEM VIEW", None),
        ("sys", "innodb_lock_waits", "VIEW", None),
        ("sys", "schema_table_lock_waits", "VIEW", None),
        ("sys", "statement_analysis", "VIEW", None),
        ("sys", "x$innodb_lock_waits", "VIEW", None),
        ("sys", "x$schema_table_lock_waits", "VIEW", None),
    ]
    rows = [*_MYSQL_CATALOG, *lock_waits]
    conn, _ = _catalog_connector(monkeypatch, "mysql", rows, _opened("information_schema", "sys"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert ("information_schema", "TABLES") in out and ("sys", "statement_analysis") in out
    assert out.isdisjoint({(r[0], r[1]) for r in lock_waits if r[1] != "statement_analysis"}), sorted(out)


def test_i13_mysql_57_and_mariadb_never_list_locked_key_values_or_cached_statements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wave-3 review round 2: MySQL 5.7 and MariaDB (both supported) keep
    information_schema.INNODB_LOCKS, whose LOCK_DATA holds the key values of
    the rows other transactions have locked, in any table, allowlisted or
    not (with PROCESS); MariaDB's query_cache_info plugin adds
    QUERY_CACHE_INFO, the text of every cached SELECT with its literals.
    Neither is listed under the default information_schema allowance.
    INNODB_LOCK_WAITS holds transaction and lock ids only and stays."""
    mariadb = [
        ("information_schema", "INNODB_LOCKS", "SYSTEM VIEW", None),
        ("information_schema", "INNODB_LOCK_WAITS", "SYSTEM VIEW", None),
        ("information_schema", "QUERY_CACHE_INFO", "SYSTEM VIEW", None),
    ]
    conn, _ = _catalog_connector(monkeypatch, "mysql", [*_MYSQL_CATALOG, *mariadb], _opened("information_schema"))
    out = {(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)}
    assert ("information_schema", "INNODB_LOCK_WAITS") in out and ("information_schema", "TABLES") in out
    assert ("information_schema", "INNODB_LOCKS") not in out, sorted(out)
    assert ("information_schema", "QUERY_CACHE_INFO") not in out, sorted(out)


def test_i13_oracle_lists_an_opened_dictionary_after_the_databases_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review: with SYS opened, 2010 dictionary objects sorted before the 4
    TRAVEL tables, so db_list_tables pages 1 to 40 showed only SYS. Oracle
    now orders like the other engines (own_objects_first)."""
    rows = [("SYS", "DUAL", "TABLE"), ("SYS", "OBJ$", "TABLE"), ("TRAVEL", "BOOKINGS", "TABLE"),
            ("TRAVEL", "TRIPS", "TABLE")]
    fake = _FakeOracleDb(version="11.2.0.4.0", rows=rows)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake, security=_opened("sys"))
    assert [(t.schema, t.name) for t in conn.list_tables(None, {"table"}, None)] == [
        ("TRAVEL", "BOOKINGS"), ("TRAVEL", "TRIPS"), ("SYS", "DUAL"), ("SYS", "OBJ$")
    ]


def test_i13_oracle_orders_owners_as_the_policy_tells_a_dictionary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wave-3 review: the static owner list sorted PDBADMIN, where sites keep
    application tables (DISCOVERY_ONLY_SCHEMAS), after every opened
    dictionary owner, and an opened APEX_nnnnnn owner (a pattern, not in the
    list) among the database's own. The order now follows the policy's
    is_system_schema."""
    rows = [("APEX_230200", "WWV_FLOWS", "TABLE"), ("MDSYS", "SDO_GEOM_METADATA_TABLE", "TABLE"),
            ("PDBADMIN", "APP_ORDERS", "TABLE"), ("TRAVEL", "TRIPS", "TABLE")]
    fake = _FakeOracleDb(version="19.3.0.0.0", rows=rows)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake, security=_opened("mdsys", "apex_230200"))
    assert [(t.schema, t.name) for t in conn.list_tables(None, {"table"}, None)] == [
        ("PDBADMIN", "APP_ORDERS"), ("TRAVEL", "TRIPS"), ("APEX_230200", "WWV_FLOWS"),
        ("MDSYS", "SDO_GEOM_METADATA_TABLE"),
    ]


def test_i13_db2_lists_an_opened_system_schema_after_the_databases_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, _ = _db2(tmp_path, monkeypatch, fake=_FakeIbmDb(rows=_DB2_ROWS), security=_opened("sysibm", "syscat"))
    assert [(t.schema, t.name) for t in conn.list_tables(None, {"table", "view"}, None)] == [
        ("SYSADM_APP", "ORDERS"), ("APP", "CUSTOMERS"), ("SYSCAT", "TABLES"), ("SYSIBM", "SYSTABLES")
    ]


# Db2 value search: ibm_db types the needle's marker from the compared
# column, so an exact match with a needle longer than a CHAR/VARCHAR column
# raised CLI0109E and left the whole table unsearched.


def test_value_search_on_db2_widens_a_graphic_column_as_graphic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 4: Db2 casts graphic to character only in a Unicode
    database, so CAST(<VARGRAPHIC column> AS VARCHAR(32672)) fails a whole
    search chunk with SQL0461N elsewhere. Given the declared type, a
    GRAPHIC or VARGRAPHIC column is widened as VARGRAPHIC."""
    conn, _ = _db2(tmp_path, monkeypatch)
    assert conn.text_expression('"N"', "string", "VARGRAPHIC(20)") == 'CAST("N" AS VARGRAPHIC(16336))'
    assert conn.text_expression('"N"', "string", "graphic(4)") == 'CAST("N" AS VARGRAPHIC(16336))'
    assert conn.text_expression('"N"', "string", "VARCHAR(20)") == 'CAST("N" AS VARCHAR(32672))'


def _db2_on_codepage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codepage: int | None
) -> db2_module.Db2Connector:
    """A Db2 connector that has connected once to a database of this code
    page (None: the driver reports none)."""
    fake = _FakeIbmDb()
    if codepage is not None:
        fake.server_info = lambda _conn: types.SimpleNamespace(DB_CODEPAGE=codepage)  # type: ignore[attr-defined]
    conn, _ = _db2(tmp_path, monkeypatch, fake=fake)
    conn._connect()
    return conn


@pytest.mark.parametrize("codepage", ["never connected", None, 1252, 943])
def test_value_search_on_db2_compares_columns_as_declared_unless_the_database_is_unicode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codepage: Any
) -> None:
    """Review round 5: the server passes no declared type, so every GRAPHIC
    column was searched as CAST(<col> AS VARCHAR(32672)), which Db2 refuses
    outside a Unicode database (SQL0461N) and which failed the whole table's
    search where the uncast column had worked. Without the type, and without
    knowing the database is Unicode, a column is compared as declared."""
    from universal_db_mcp.discovery.types import portable_type
    from universal_db_mcp.server import _value_search_predicates

    if codepage == "never connected":
        conn, _ = _db2(tmp_path, monkeypatch)
    else:
        conn = _db2_on_codepage(tmp_path, monkeypatch, codepage)
    columns = [(types.SimpleNamespace(name=n, data_type=t), portable_type("db2", t)) for n, t in (
        ("NAME_G", "VARGRAPHIC(20)"), ("FULL_NAME", "VARCHAR(120)"),
    )]
    exact, _ = _value_search_predicates(conn, columns, "abc", None, "exact")
    assert exact == ['LOWER("NAME_G") = ?', 'LOWER("FULL_NAME") = ?']


def test_value_search_on_db2_widens_every_string_column_in_a_unicode_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In a Unicode database (code page 1208 or 1200) Db2 casts graphic to
    character, so the widest VARCHAR serves GRAPHIC columns too (live on the
    1208 fixture: CAST(VARGRAPHIC AS VARCHAR(32672)) with a 40-character
    needle matches nothing, where the uncast column raised CLI0109E)."""
    from universal_db_mcp.discovery.types import portable_type
    from universal_db_mcp.server import _value_search_predicates

    for codepage in (1208, 1200):
        conn = _db2_on_codepage(tmp_path, monkeypatch, codepage)
        col = types.SimpleNamespace(name="NAME_G", data_type="VARGRAPHIC(20)")
        exact, _ = _value_search_predicates(conn, [(col, portable_type("db2", col.data_type))], "x" * 40, None, "exact")
        assert exact == ['LOWER(CAST("NAME_G" AS VARCHAR(32672))) = ?'], codepage


def test_db2_code_page_lookup_never_fails_the_connect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeIbmDb()

    def broken(_conn: Any) -> Any:
        raise RuntimeError("SQLGetInfo failed")

    fake.server_info = broken  # type: ignore[attr-defined]
    conn, _ = _db2(tmp_path, monkeypatch, fake=fake)
    assert conn._connect() == "handle"
    assert conn.text_expression('"N"', "string") == '"N"'


def test_value_search_on_db2_types_the_needle_wider_than_any_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.discovery.types import portable_type
    from universal_db_mcp.server import _value_search_predicates

    conn = _db2_on_codepage(tmp_path, monkeypatch, 1208)
    columns = [(types.SimpleNamespace(name=n), portable_type("db2", t)) for n, t in (
        ("SEX", "CHARACTER(1)"), ("FULL_NAME", "VARCHAR(120)"), ("CITIZEN_ID", "INTEGER"),
    )]
    exact, params = _value_search_predicates(conn, columns, "x" * 160, 7, "exact")
    assert exact == [
        'LOWER(CAST("SEX" AS VARCHAR(32672))) = ?',
        'LOWER(CAST("FULL_NAME" AS VARCHAR(32672))) = ?',
        '"CITIZEN_ID" = ?',  # a numeric column keeps its own type: DOUBLE 0.1 still equals the needle 0.1
    ]
    assert params == ["x" * 160, "x" * 160, 7]
    contains, _ = _value_search_predicates(conn, columns[:1], "ab", None, "contains")
    assert contains == ["LOWER(CAST(\"SEX\" AS VARCHAR(32672))) LIKE ? ESCAPE '!'"]


# F08 (Oracle): values python-oracledb decodes whole cost memory for every
# row a fetch carries, and their size is not known before the fetch.


def test_f08_oracle_small_rows_then_large_json_bring_at_most_four_whole_values_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 3: the batch had doubled to 32 on 31 tiny documents, so
    one fetch decoded 32 documents of 6 MB each (maxrss 43 -> 447 MB live)."""
    big = "x" * 20_000  # past the 8192-byte cell limit
    rows = [(i, {"n": i} if i < 31 else {"blob": big}) for i in range(63)]
    state = _Rows(rows, [_Col("N", int), _Col("DOC", _FakeDbType("DB_TYPE_JSON"))])
    out, sizes = _ora_fetch_sizes(tmp_path, monkeypatch, state, QuerySpec(sql="SELECT n, doc FROM t", max_rows=100))
    assert len(out.rows) == 63
    assert max(sizes) <= 4, sizes
    first_large = next(i for i, n in enumerate(sizes) if sum(sizes[:i + 1]) > 31)
    assert set(sizes[first_large + 1:]) <= {1}, "after a value past the cell limit, one row per fetch"


# F08 (PostgreSQL): the value cap re-typed every capped column as text, so
# psycopg no longer loaded JSON: jsonb -> 'name' came back as '"Alice"', a
# number as '30' and JSON null as the string 'null'.


def test_f08_postgres_cap_keeps_json_jsonb_and_records_typed_unless_too_long() -> None:
    desc = [_Col("j", 114), _Col("jb", 3802), _Col("r", 2249), _Col("a", 1007), _Col("t", 25)]
    psycopg = pytest.importorskip("psycopg")
    capped = pg_module._pg_capped_select(
        types.SimpleNamespace(adapters=psycopg.adapters), "SELECT j, jb, r, a, t FROM x", desc, 50, bound=False
    )
    assert capped is not None
    head = capped.split(" FROM (", 1)[0]
    assert head == (
        "SELECT CASE WHEN COALESCE(octet_length(udbmcp_q.c1::text), 0) <= 50 THEN udbmcp_q.c1 "
        "ELSE to_json(left(udbmcp_q.c1::text, 51)) END AS \"j\", "
        "CASE WHEN COALESCE(octet_length(udbmcp_q.c2::text), 0) <= 50 THEN udbmcp_q.c2 "
        "ELSE to_jsonb(left(udbmcp_q.c2::text, 51)) END AS \"jb\", "
        "CASE WHEN COALESCE(octet_length(udbmcp_q.c3::text), 0) <= 50 THEN udbmcp_q.c3 "
        "ELSE ROW(left(udbmcp_q.c3::text, 51)) END AS \"r\", "
        # an array cannot hold its own cut text: compact JSON text, digits exact
        "left(to_json(udbmcp_q.c4)::text, 51) AS \"a\", "
        "left(udbmcp_q.c5::text, 51) AS \"t\""
    )


def test_f08_postgres_typed_cut_keeps_null_and_computes_each_value_once() -> None:
    """Review round 4: 'octet_length(NULL::text) <= N' is NULL, so a NULL
    went to the cut branch, and ROW(left(NULL, N)) is a one-field row: a NULL
    record came back as '[]' (live: 'SELECT CASE WHEN n = 1 THEN (1, 'a')
    END ...'). And PostgreSQL pulled the derived table up into the CASE,
    so a computed document (to_jsonb(t), jsonb_build_object(...)) was built
    two or three times per row; the body is fenced now."""
    desc = [_Col("r", 2249), _Col("jb", 3802), _Col("t", 25)]
    capped = pg_module._pg_capped_select(None, "SELECT r, jb, t FROM x", desc, 50, bound=False)
    assert capped is not None
    assert (
        "CASE WHEN COALESCE(octet_length(udbmcp_q.c1::text), 0) <= 50 THEN udbmcp_q.c1 "
        "ELSE ROW(left(udbmcp_q.c1::text, 51)) END AS \"r\""
    ) in capped
    assert "CASE WHEN COALESCE(octet_length(udbmcp_q.c2::text), 0) <= 50 THEN udbmcp_q.c2 " in capped
    assert capped.endswith(
        "FROM (SELECT * FROM (\nSELECT r, jb, t FROM x\n) AS udbmcp_s OFFSET 0) AS udbmcp_q(c1, c2, c3)"
    )
    # no typed cut: every column is read once already, and the body is not fenced
    plain = pg_module._pg_capped_select(None, "SELECT t FROM x", [_Col("t", 25)], 50, bound=False)
    assert plain is not None and plain.endswith("FROM (\nSELECT t FROM x\n) AS udbmcp_q(c1)")


def test_f08_postgres_capped_json_values_reach_the_caller_as_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """What psycopg loads from the typed branch (a JSON scalar, a document,
    JSON null) is what an uncapped query returned; an oversized value is the
    cut JSON text, flagged."""
    desc = [_Col("name", 3802), _Col("age", 3802), _Col("nil", 3802), _Col("doc", 3802), _Col("big", 3802)]
    state = _Rows([("Alice", 30, None, {"k": [1, 2]}, '"' + "x" * 60)], desc)
    out = _pg(monkeypatch, state)._execute(QuerySpec(sql="SELECT d->'name', d->'age', d->'nil', d, b FROM t",
                                                     max_cell_bytes=50))
    assert out.rows == [["Alice", 30, None, '{"k": [1, 2]}', '"' + "x" * 49]]
    assert out.truncated and "'big'" in out.warnings[-1]


# F37 (Db2 over TLS): CONNECTTIMEOUT bounds a plain connect, but ibm_db's
# connect over TLS to a listener that accepts and never answers never
# returned, holding the worker thread and its executor tokens.


def _free_port() -> int:
    """A loopback port nothing listens on, so a connect is refused at once
    (a bound socket that does not listen drops the SYN on macOS instead)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


class _Listener:
    """A loopback listener that accepts and then does what ``serve`` says
    with each connection (nothing at all by default)."""

    def __init__(self, serve: Callable[[socket.socket], None] | None = None) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.held: list[socket.socket] = []
        self.serve = serve
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client = self.sock.accept()[0]
            except OSError:
                return
            self.held.append(client)
            if self.serve is not None:
                threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def close(self) -> None:
        self.sock.close()
        for s in self.held:
            s.close()


def _db2_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, port: int) -> tuple[db2_module.Db2Connector, _FakeIbmDb]:
    fake = _FakeIbmDb()
    monkeypatch.setattr(db2_module, "open_module", lambda *_a, **_k: fake)
    monkeypatch.setitem(sys.modules, "ibm_db_dbi", types.ModuleType("ibm_db_dbi"))
    ca = tmp_path / "ca.pem"
    ca.write_text("not read by the probe\n", encoding="utf-8")
    resolved = _resolved({
        "type": "db2", "host": "127.0.0.1", "port": port, "database": "TESTDB", "connect_timeout_seconds": 1,
        "tls": {"enabled": True, "verify_server": True, "ca_file": str(ca)},
        "username_file": _secret(tmp_path, "du", "u"), "password_file": _secret(tmp_path, "dp", "p"),
    })
    return db2_module.Db2Connector(resolved, EffectivePolicy.build(SecurityConfig(), resolved)), fake


def test_f37_db2_tls_to_a_silent_listener_is_refused_before_the_driver_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listener = _Listener()
    try:
        conn, fake = _db2_tls(tmp_path, monkeypatch, listener.port)
        start = time.monotonic()
        health = conn.health_check()
        assert time.monotonic() - start < 1 + 1
        assert health.healthy is False
        assert "TLS handshake" in (health.detail or ""), health.detail
        assert fake.dsns == [], "ibm_db.connect is never handed a connect that would not return"
        with pytest.raises(ConnectorError) as exc:
            conn._connect()
        assert getattr(exc.value, "category", "CONNECTION_ERROR") == "CONNECTION_ERROR"
    finally:
        listener.close()


def test_f37_db2_tls_probe_names_a_tcp_timeout_as_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 5: a host that never accepts the TCP connection (a
    firewall that drops SYNs, a wrong address) timed out in the probe's
    socket.create_connection and was reported as a TLS handshake failure,
    with advice to check the SSL port."""
    import socket as socket_module

    def silent(address: tuple[str, int], timeout: float = 0.0) -> socket_module.socket:
        raise TimeoutError("timed out")

    conn, fake = _db2_tls(tmp_path, monkeypatch, 50443)
    monkeypatch.setattr(socket_module, "create_connection", silent)
    with pytest.raises(ConnectorError) as exc:
        conn._connect()
    text = str(exc.value)
    assert "did not accept a TCP connection within 1 s" in text, text
    assert "TLS handshake" not in text and "SSL_SVCENAME" not in text, text
    assert getattr(exc.value, "category", "CONNECTION_ERROR") == "CONNECTION_ERROR"
    assert fake.dsns == []


def test_f37_db2_tls_probe_leaves_other_failures_to_the_driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A refused port, or a peer that drops the handshake, fails at once:
    the Db2 client then reports it in its own words."""
    listener = _Listener(serve=lambda client: client.close())
    try:
        for port in (listener.port, _free_port()):
            conn, fake = _db2_tls(tmp_path, monkeypatch, port)
            conn._connect()
            assert len(fake.dsns) == 1 and "SECURITY=SSL;" in fake.dsns[0]
    finally:
        listener.close()


def _tls_server(tmp_path: Path) -> Any:
    """A server-side TLS context with a throwaway self-signed certificate."""
    import ssl

    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "db2.test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "server.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(tmp_path / "server.pem")
    return server


# What Db2 LUW 12.1 answers a parameterless EXCSAT with (the fixture, live):
# one DSS carrying an EXCSATRD (code point 0x1443).
_DB2_EXCSATRD = bytes.fromhex("000ad003000100041443")


def test_f37_db2_tls_probe_completes_a_real_handshake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A responsive Db2 behind TLS passes, whatever its certificate: the Db2
    client verifies the certificate on the real connect (SSLServerCertificate,
    SSLClientHostnameValidation). The probe asks the server's attributes
    (DRDA EXCSAT, no parameters, no credentials) and needs an answer."""
    server = _tls_server(tmp_path)
    handshakes: list[str] = []
    received: list[bytes] = []

    def serve(client: socket.socket) -> None:
        with server.wrap_socket(client, server_side=True) as tls:
            handshakes.append(str(tls.version()))
            received.append(tls.recv(64))
            tls.sendall(_DB2_EXCSATRD)
            tls.recv(1)  # wait for the probe to close

    listener = _Listener(serve=serve)
    try:
        conn, fake = _db2_tls(tmp_path, monkeypatch, listener.port)
        conn._connect()
        assert len(fake.dsns) == 1
        assert handshakes and handshakes[0].startswith("TLS")
        assert received == [bytes.fromhex("000ad001000100041041")], "one RQSDSS: EXCSAT, nothing else"
    finally:
        listener.close()


def test_f37_db2_tls_peer_silent_after_the_handshake_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round 4: a peer that completes the TLS handshake and then never
    answers DRDA (a TLS-terminating proxy in front of a down Db2, a hung
    instance whose listener still handshakes) passed the probe, and
    ibm_db.connect then stayed blocked past 25 s with connect_timeout 2 s;
    ReceiveTimeout in the DSN did not help."""
    server = _tls_server(tmp_path)
    reads: list[bytes] = []

    def serve(client: socket.socket) -> None:
        with server.wrap_socket(client, server_side=True) as tls:
            while data := tls.recv(64):  # read everything, answer nothing
                reads.append(data)

    listener = _Listener(serve=serve)
    try:
        conn, fake = _db2_tls(tmp_path, monkeypatch, listener.port)
        start = time.monotonic()
        with pytest.raises(ConnectorError, match="did not answer") as exc:
            conn._connect()
        assert time.monotonic() - start < 1 + 1
        assert getattr(exc.value, "category", "CONNECTION_ERROR") == "CONNECTION_ERROR"
        assert fake.dsns == [], "ibm_db.connect is never handed a connect that would not return"
        assert reads, "the handshake completed and the probe asked"
    finally:
        listener.close()


# F08 cost: the MySQL value cap parsed a statement again for every
# select-list entry (review round 3: 0.66 s for 1500 entries against 0.06 s
# for the guard's one parse, 1.24 s for a 145 KB CASE).


def _wide_select(entries: int) -> str:
    items = ", ".join(f"CONCAT(notes, 'a{i}', taster, 'b{i}') AS c{i}" for i in range(entries))
    return f"SELECT {items} FROM cuppings WHERE taster LIKE 'x%' ORDER BY cupping_id LIMIT 10"


def test_f08_mysql_cap_of_a_wide_statement_parses_it_a_few_times_not_once_per_entry(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlglot

    parses: list[int] = []
    real = sqlglot.parse_one

    def counting(sql: str, *args: Any, **kwargs: Any) -> Any:
        parses.append(len(sql))
        return real(sql, *args, **kwargs)

    sql = _wide_select(1300)
    assert 32 * 1024 < len(sql) < 64 * 1024, "wide, and under the guard's 64 KiB"
    description = [_Col(f"c{i}", 252, 10**6) for i in range(1300)]
    conn = _my(monkeypatch, _Rows([], description))
    monkeypatch.setattr(conn, "_limit0_description", lambda *_a: description)
    monkeypatch.setattr(sqlglot, "parse_one", counting)
    plan = conn._value_capped(types.SimpleNamespace(server_version="9.7.0"), sql, None, QuerySpec(sql=sql))
    assert plan is not None and plan.rewrites[0].startswith("SELECT LEFT(CONCAT(notes, 'a0', taster, 'b0'), 8193)")
    # Parses, not seconds: the per-entry re-parsing made about 3,900 of them
    # (1.1 s here, 3.4 s on a slow runner); a wall-clock bound caught neither.
    assert len(parses) <= 8, f"{len(parses)} parses for 1300 entries"
    assert sum(parses) <= 6 * len(sql), "a few passes over the statement's text"


def test_f08_mysql_cap_parses_a_short_statement_once_before_its_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlglot

    parses: list[str] = []
    real = sqlglot.parse_one

    def counting(sql: str, *args: Any, **kwargs: Any) -> Any:
        parses.append(sql)
        return real(sql, *args, **kwargs)

    sql = _wide_select(3)
    description = [_Col(f"c{i}", 252, 10**6) for i in range(3)]
    conn = _my(monkeypatch, _Rows([], description))
    monkeypatch.setattr(conn, "_limit0_description", lambda *_a: description)
    monkeypatch.setattr(sqlglot, "parse_one", counting)
    plan = conn._value_capped(types.SimpleNamespace(server_version="9.7.0"), sql, None, QuerySpec(sql=sql))
    assert plan is not None and plan.rewrites[0].startswith("SELECT LEFT(CONCAT(notes, 'a0', taster, 'b0'), 8193)")
    assert sum(1 for p in parses if p.startswith("SELECT CONCAT")) == 1, "the statement itself is parsed once"


# Wave-3 review round 2 (task 6): the guard admits a bare DUAL as data-free
# (DATA_FREE_TABLES) because Oracle names SYS.DUAL through the PUBLIC synonym
# DUAL - unless the session's current schema holds an object called DUAL,
# which Oracle resolves first. Live: a TRAVEL.DUAL view over TRAVELLERS
# under allowed_schemas [HR] answered SELECT dummy, full_name FROM DUAL with
# a passport number and a name. The connector checks, in the session that
# runs the statement, what a bare DUAL names there.


def _dual_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owned: int, schema: str = "TRAVEL", user: str = "TRAVEL"
) -> tuple[Any, _Rows, _FakeOracleDb]:
    """An Oracle connector logged in as ``user`` whose current schema
    ``schema`` holds ``owned`` objects called DUAL; every other statement
    answers one row, ('X',)."""
    state = _Rows([("X",)], [_Col("DUMMY", str)])
    state.answers[oracle_module._SHADOWED_DUAL] = (
        [(schema, user, owned)], [_Col("SCHEMA", str), _Col("LOGIN", str), _Col("OWNED", int)]
    )
    fake = _OracleExecDb(state)
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=fake)
    return conn, state, fake


_BARE_DUAL = [
    "SELECT dummy, full_name FROM DUAL",
    "select sysdate from dual",
    'SELECT * FROM "DUAL"',
    "SELECT n FROM t JOIN dual d ON 1 = 1",
    "SELECT (SELECT dummy FROM dual) AS d FROM t",
    "WITH x AS (SELECT dummy FROM Dual) SELECT * FROM x",
    "SELECT * FROM dual WHERE ((",  # a text sqlglot cannot read is checked too
]


@pytest.mark.parametrize("sql", _BARE_DUAL)
def test_w3_oracle_refuses_a_bare_dual_the_current_schema_shadows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sql: str
) -> None:
    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=1)
    with pytest.raises(ConnectorError) as err:
        conn.execute_query(QuerySpec(sql=sql))
    text = str(err.value)
    assert "TRAVEL.DUAL" in text and "write SYS.DUAL" in text, text
    assert err.value.category == "AUTHORIZATION_DENIED"
    assert err.value.__cause__ is None and err.value.__context__ is None, "the connector's own text, kept whole"
    assert [s for s, _p in state.statements] == [oracle_module._SHADOWED_DUAL], "the statement never ran"
    assert "close" in state.log


def test_w3_oracle_runs_a_bare_dual_that_reaches_sys_dual_after_checking_its_own_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, state, fake = _dual_session(tmp_path, monkeypatch, owned=0)
    out = conn.execute_query(QuerySpec(sql="SELECT dummy FROM DUAL"))
    assert out.rows == [["X"]]
    assert [s for s, _p in state.statements] == [oracle_module._SHADOWED_DUAL, "SELECT dummy FROM DUAL"]
    assert len(fake.connect_kwargs) == 1, "checked in the session that runs the statement"


def test_w3_oracle_refuses_a_bare_dual_where_the_current_schema_is_not_the_logins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A logon trigger or ALTER SESSION can set CURRENT_SCHEMA to another
    schema, whose private synonyms ALL_OBJECTS does not show this account
    (live, 2026-09-28: with CURRENT_SCHEMA = SYSTEM it listed no SYSTEM
    synonym, while a bare TAB read through SYSTEM.TAB). What a bare DUAL
    names there cannot be told, so it is refused."""
    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=0, schema="APP", user="REPORTER")
    with pytest.raises(ConnectorError) as err:
        conn.execute_query(QuerySpec(sql="SELECT sysdate FROM dual"))
    text = str(err.value)
    assert "current schema APP" in text and "write SYS.DUAL" in text, text
    assert err.value.category == "AUTHORIZATION_DENIED"
    assert [s for s, _p in state.statements] == [oracle_module._SHADOWED_DUAL]


def test_w3_oracle_runs_a_bare_dual_where_the_current_schema_is_sys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SYS's own DUAL is the dummy table, whoever set that schema."""
    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=0, schema="SYS", user="REPORTER")
    assert conn.execute_query(QuerySpec(sql="SELECT dummy FROM dual")).rows == [["X"]]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT n FROM t",
        "SELECT 1 FROM SYS.DUAL",
        'SELECT 1 FROM "SYS"."DUAL"',
        "SELECT n FROM travel.dual",  # qualified: the guard's allowlists decide it
        'SELECT n FROM "dual"',  # another object than DUAL
        "SELECT 'dual' AS word FROM t",
        "SELECT dual.n FROM t dual",
    ],
)
def test_w3_oracle_checks_nothing_for_a_statement_without_a_bare_dual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sql: str
) -> None:
    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=1)
    conn.execute_query(QuerySpec(sql=sql))
    assert [s for s, _p in state.statements] == [sql]


def test_w3_oracle_explain_refuses_a_bare_dual_the_current_schema_shadows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EXPLAIN PLAN does not run the statement, but its plan names the
    shadowing object's tables and predicates."""
    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=1)
    with pytest.raises(ConnectorError, match=r"write SYS\.DUAL"):
        conn.explain("SELECT dummy FROM DUAL", False)
    assert [s for s, _p in state.statements] == [oracle_module._SHADOWED_DUAL]
    assert "close" in state.log

    conn, state, _ = _dual_session(tmp_path, monkeypatch, owned=0)
    conn.explain("SELECT dummy FROM DUAL", False)
    ran = [s for s, _p in state.statements]
    assert ran[0] == oracle_module._SHADOWED_DUAL and ran[1].startswith("EXPLAIN PLAN SET STATEMENT_ID"), ran


def test_w3_oracle_session_probes_read_sys_dual(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The connector's own liveness probes and session read-back name
    SYS.DUAL: a login schema's DUAL (a view, or a synonym whose target was
    dropped) made them read its rows or fail."""
    state = _Rows([(1,)], [_Col("N", int)])
    state.fail = lambda sql: RuntimeError("ORA-00942: table or view does not exist") if "v_$version" in sql else None
    conn, _ = _oracle(tmp_path, monkeypatch, options={}, tls=False, fake=_OracleExecDb(state))
    conn.list_schemas(None, None)
    conn.list_schemas(None, None)  # the second checkout probes the pooled session
    assert conn.health_check().healthy
    named = [s for s, _p in state.statements if "dual" in s.lower()]
    assert len(named) == 3, named  # the checkout probe, the health fallback and the read-back
    assert all("FROM SYS.DUAL" in s for s in named), named
