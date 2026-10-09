"""Findings of the 2026-09-18 correctness and security reviews, pinned.

Correctness: join keys longer than 28 digits and -0; db_explain refuses
parameters it cannot bind and sends the statement text the guard validated
(Db2 tail clauses survive); the value search names the connections it never
reached. Security: the join output is byte-bounded; every federated
statement leaves its own audit record; sequence access and locking table
hints are refused; the Db2 explain cleanup failure is a warning; the
site-check report is private and never overwritten silently; the release
script never implies a key; a pip-running installer without the current
format marker is refused; the doctor compares a copied interpreter with its
base.
"""
from __future__ import annotations

import asyncio
import decimal
import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_db2_isolation_clause import _guard
from test_deb_outdated_installer import REAL_INSTALLER, _run
from test_deb_packaging import _POSIX, _postinst_step1_bootstrap_script, _preinst_sandbox_script
from test_explain_plan_engines import _connector, _Db2Stmt, _FakeIbmDb

from universal_db_mcp.config import load_resolved
from universal_db_mcp.diagnostics import doctor
from universal_db_mcp.diagnostics.site_check import write_report
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.server import AppContext, _join_key, build_server

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ join keys
@pytest.mark.parametrize(
    ("a", "b"),
    [
        (5, decimal.Decimal("5.00")),
        ("5", 5.0),
        ("-0", 0),
        (-0.0, decimal.Decimal("0E+2")),
        (decimal.Decimal("123456789012345678901234567890.5"), "123456789012345678901234567890.5"),
        (10**30, decimal.Decimal("1E+30")),
    ],
)
def test_join_keys_equal_by_value_without_context_rounding(a: Any, b: Any) -> None:
    assert _join_key(a, False) == _join_key(b, False)


def test_join_keys_keep_every_digit_and_never_equate_nan() -> None:
    long_a = decimal.Decimal("1234567890123456789012345678901")  # 31 digits: normalize() would round it
    long_b = decimal.Decimal("1234567890123456789012345678902")
    assert _join_key(long_a, False) != _join_key(long_b, False)
    assert _join_key(long_a, False) == "1234567890123456789012345678901"
    assert _join_key(float("nan"), False) != _join_key(0, False)
    assert _join_key(float("inf"), False) == "inf"


# ------------------------------------------------------------------ guard
def test_guard_refuses_sequence_access_on_every_engine() -> None:
    with pytest.raises(ToolFailure, match="NEXT VALUE FOR"):
        _guard("mssql").validate_select("SELECT NEXT VALUE FOR dbo.seq")
    with pytest.raises(ToolFailure, match="sequence pseudo-column 'NEXTVAL'"):
        _guard("oracle").validate_select("SELECT seq.NEXTVAL FROM dual")
    with pytest.raises(ToolFailure, match="sequence pseudo-column 'currval'"):
        _guard("oracle").validate_select("SELECT s.currval FROM dual")
    with pytest.raises(ToolFailure, match="sequence expressions"):
        _guard("db2").validate_select("SELECT NEXT VALUE FOR APP.SEQ FROM SYSIBM.SYSDUMMY1")
    with pytest.raises(ToolFailure, match="sequence expressions"):
        _guard("db2").validate_select("SELECT PREVVAL FOR APP.SEQ FROM SYSIBM.SYSDUMMY1 WITH UR")
    # postgres nextval() is a function outside the closed allowlist
    with pytest.raises(ToolFailure):
        _guard("postgres").validate_select("SELECT nextval('s')")
    # a plain column that happens to be called nextval on an engine without the pseudo-column
    assert _guard("postgres").validate_select("SELECT nextval FROM app.t").kind == "select"


def test_guard_accepts_only_read_relaxing_table_hints() -> None:
    g = _guard("mssql")
    assert g.validate_select("SELECT a FROM dbo.t WITH (NOLOCK)").kind == "select"
    assert g.validate_select("SELECT a FROM dbo.t WITH (READUNCOMMITTED, READPAST)").kind == "select"
    for hint in ("UPDLOCK", "TABLOCKX", "HOLDLOCK", "XLOCK", "SERIALIZABLE", "NOLOCK, TABLOCK"):
        with pytest.raises(ToolFailure, match="table hint"):
            g.validate_select(f"SELECT a FROM dbo.t WITH ({hint})")


def test_validate_explain_keeps_the_statement_text_as_written() -> None:
    r = _guard("db2").validate_explain("EXPLAIN SELECT * FROM APP.CUSTOMERS OPTIMIZE FOR 10 ROWS WITH UR;")
    assert r.kind == "explain" and r.text == "SELECT * FROM APP.CUSTOMERS OPTIMIZE FOR 10 ROWS WITH UR"
    r = _guard("sqlite").validate_explain("EXPLAIN QUERY PLAN SELECT 1 -- note")
    assert r.text == "SELECT 1 -- note"
    # (EXPLAIN options are no longer dropped from the text: the guard's F89
    # re-renders the accepted ones and refuses FORMAT JSON on PostgreSQL)
    r = _guard("postgres").validate_explain("EXPLAIN SELECT a FROM app.t")
    assert r.text == "SELECT a FROM app.t"


# ------------------------------------------------------------------ tools over sqlite
def _seed(path: Path, *, wide_right: bool) -> None:
    c = sqlite3.connect(path)
    c.executescript(
        """
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, region TEXT);
        INSERT INTO customers VALUES (1, 'Ada-' || replace(hex(zeroblob(24)), '0', 'n'), 'north'),
                                     (2, 'Bo', 'south'), (3, 'Cy', 'north');
        CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id INTEGER, memo TEXT);
        """
    )
    if wide_right:
        c.executemany(
            "INSERT INTO orders VALUES (?,?,?)", [(i, 1, f"memo-{i:03d}-" + "x" * 20) for i in range(1, 201)]
        )
    else:
        c.executemany("INSERT INTO orders VALUES (?,?,?)", [(i, i, f"memo-{i}") for i in range(1, 4)])
    c.commit()
    c.close()


def _app(tmp_path: Path, *, max_response_bytes: int | None = None, wide_right: bool = False) -> AppContext:
    crm, erp = tmp_path / "crm.db", tmp_path / "erp.db"
    _seed(crm, wide_right=False)
    _seed(erp, wide_right=wide_right)
    cfg = tmp_path / "config.yaml"
    security = "security:\n  mask_columns: ['(?i)ssn']\n"
    if max_response_bytes is not None:
        security += f"  max_response_bytes: {max_response_bytes}\n"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        + security
        + f"connections:\n  crm:\n    type: sqlite\n    database: {crm}\n"
        + f"  erp:\n    type: sqlite\n    database: {erp}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return AppContext(app_cfg, resolved)


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, args))
    assert result.structured_content is not None
    return result.structured_content


def _call_failure(server: Any, name: str, args: dict[str, Any]) -> str:
    with pytest.raises(Exception) as info:  # noqa: PT011 - the MCP ToolError text is the assertion
        asyncio.run(server.call_tool(name, args))
    return str(info.value)


def test_explain_refuses_parameters_and_sends_the_validated_text(tmp_path: Path, monkeypatch: Any) -> None:
    app = _app(tmp_path)
    server = build_server(app)
    text = _call_failure(server, "db_explain", {"connection_id": "crm", "sql": "EXPLAIN SELECT 1", "parameters": [1]})
    assert "VALIDATION" in text and "does not bind parameters" in text
    _call(server, "db_explain", {"connection_id": "crm", "sql": "EXPLAIN SELECT 1"})  # connector now cached
    seen: list[tuple[str, bool]] = []

    def fake_explain(sql: str, analyze: bool) -> dict[str, Any]:
        seen.append((sql, analyze))
        return {"raw": "plan", "cleanup_warning": "the explain rows could not be deleted (SQL0551N)"}

    monkeypatch.setattr(app.connectors["crm"], "explain", fake_explain)
    env = _call(server, "db_explain", {"connection_id": "crm", "sql": "EXPLAIN SELECT id FROM customers -- keep"})
    assert seen == [("SELECT id FROM customers -- keep", False)], "the statement goes to the engine as written"
    assert "cleanup_warning" not in env["data"]["plan"]
    assert any("could not be deleted" in w for w in env["warnings"])


def test_db2_explain_reports_a_failed_cleanup_instead_of_hiding_it(tmp_path: Path, monkeypatch: Any) -> None:
    class _Fake(_FakeIbmDb):
        def prepare(self, conn: Any, sql: str) -> _Db2Stmt:
            if sql.startswith("DELETE FROM"):
                self.log.append(sql)
                raise RuntimeError("[IBM][CLI Driver][DB2/LINUX] SQL0551N  ... DELETE ... SQLSTATE=42501")
            return super().prepare(conn, sql)

    conn = _connector("db2", tmp_path)
    fake = _Fake(provisioned=True)
    monkeypatch.setattr(conn, "_module", fake, raising=False)
    monkeypatch.setattr(conn, "_connect", lambda: object())
    plan = conn.explain('SELECT * FROM "MOI"."CITIZENS"', False)
    assert plan["rows"][1]["operator"] == "TBSCAN"
    assert "SQL0551N" in plan["cleanup_warning"] and "DELETE on the explain tables" in plan["cleanup_warning"]
    assert "42501" not in plan["cleanup_warning"] or "SQLSTATE" in plan["cleanup_warning"]
    assert fake.closed


def test_federated_join_output_is_byte_bounded(tmp_path: Path) -> None:
    # one CRM row matches 200 ERP rows: both sides fit the ceiling, the cross product does not
    server = build_server(_app(tmp_path, max_response_bytes=12000, wide_right=True))
    env = _call(
        server, "db_federated_join",
        {
            "left": {"connection": "crm", "sql": "SELECT id, name FROM customers"},
            "right": {"connection": "erp", "sql": "SELECT order_id, customer_id, memo FROM orders"},
            "on": [["id", "customer_id"]], "max_rows": 5000,
        },
    )
    d = env["data"]
    assert d["left"]["truncated"] is False and d["right"]["truncated"] is False
    assert d["truncated"] is True and 0 < len(d["rows"]) < 200
    assert sum(len(json.dumps(r)) for r in d["rows"]) <= 12000
    assert any("byte ceiling" in w and "join output is partial" in w for w in env["warnings"])


def test_federated_query_reports_every_statement_that_ran_and_shrinks_the_budget(tmp_path: Path) -> None:
    server = build_server(_app(tmp_path, max_response_bytes=700, wide_right=True))
    env = _call(
        server, "db_federated_query",
        {"queries": {"erp": "SELECT order_id, memo FROM orders", "crm": "SELECT id, name FROM customers"}},
    )
    d = env["data"]
    ran = [r for r in d["results"] if "rows" in r]
    assert ran and ran[0]["connection"] == "erp" and ran[0]["truncated"] is True, "bounded by its own read, kept"
    assert d["connections_run"] == len(ran) and d["connections_failed"] == 0
    if len(ran) == 1:
        assert d["budget_exhausted"] is True
        assert any("byte ceiling" in w for w in env["warnings"])
    assert d["merged"] is None or d["merged"]["row_count"] == len(d["merged"]["rows"])


def test_federated_tools_audit_every_statement(tmp_path: Path) -> None:
    app = _app(tmp_path)
    server = build_server(app)
    env = _call(server, "db_federated_query", {"sql": "SELECT id FROM customers", "connections": ["crm", "erp"]})
    _call_failure(server, "db_federated_join", {
        "left": {"connection": "crm", "sql": "SELECT id FROM customers"},
        "right": {"connection": "erp", "sql": "DELETE FROM orders"},
        "on": [["id", "order_id"]],
    })
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    by_action: dict[str, list[dict[str, Any]]] = {}
    for rec in lines:
        by_action.setdefault(rec["action"], []).append(rec)
    stmts = by_action["db_federated_query:statement"]
    assert sorted(r["connection_id"] for r in stmts) == ["crm", "erp"]
    assert all(r["request_id"] == env["request_id"] and r["outcome"] == "allow" and r["row_count"] == 3 for r in stmts)
    assert all(r["sql_fingerprint"] for r in stmts)
    join_stmts = by_action["db_federated_join:statement"]
    assert [(r["connection_id"], r["outcome"]) for r in join_stmts] == [("crm", "allow"), ("erp", "deny")]
    assert by_action["db_federated_join"][0]["outcome"] == "deny"


def test_search_names_the_connections_it_never_reached(tmp_path: Path) -> None:
    server = build_server(_app(tmp_path, max_response_bytes=300, wide_right=True))
    env = _call(server, "db_search_values", {"query": "memo-0", "connections": ["erp", "crm"], "match": "prefix"})
    d = env["data"]
    assert d["hits"], "the first connection produced hits before the byte ceiling ended the search"
    assert d["budget_exhausted"] is True
    assert d["connections_not_searched"] == ["crm"] and d["connections_failed"] == []
    assert any("never searched" in w and "crm" in w for w in env["warnings"])
    assert sum(1 for w in env["warnings"] if "response byte ceiling reached" in w) == 1


# ------------------------------------------------------------------ site-check report file
def test_site_check_report_is_private_and_never_overwritten_silently(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    write_report({"a": 1}, str(out))
    if sys.platform != "win32":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        write_report({"a": 2}, str(out))
    assert json.loads(out.read_text(encoding="utf-8")) == {"a": 1}
    write_report({"a": 3}, str(out), force=True)
    assert json.loads(out.read_text(encoding="utf-8")) == {"a": 3}
    write_report({"a": 4}, None)  # no path: nothing written


# ------------------------------------------------------------------ doctor: copied interpreter
def test_doctor_compares_a_venv_interpreter_with_its_base(monkeypatch: Any) -> None:
    check = doctor._venv_interpreter_check()
    if Path(sys.prefix) == Path(sys.base_prefix):
        assert check is None
        return
    assert check is not None and check["check"] == "venv-interpreter"
    assert check["status"] == "ok", check

    class _Proc:
        stdout = "3.99.0\n"

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _Proc())
    drift = doctor._venv_interpreter_check()
    assert drift is not None and drift["status"] == "warning"
    assert "did not follow the OS update" in drift["detail"] and "3.99.0" in drift["detail"]


# ------------------------------------------------------------------ packaging: installer format marker
MARKERLESS_INSTALLER = "\n".join(
    line for line in REAL_INSTALLER.splitlines() if "udbmcp-installer-format" not in line
) + "\n"


def test_the_real_installer_carries_the_current_format_marker() -> None:
    assert "# udbmcp-installer-format: 4\n" in REAL_INSTALLER
    assert "INSTALLER_FORMAT=4" in (ROOT / "packaging/deb/preinst").read_text(encoding="utf-8")
    assert "INSTALLER_FORMAT=4" in (ROOT / "packaging/deb/postinst").read_text(encoding="utf-8")


@_POSIX
def test_preinst_and_postinst_refuse_a_pip_running_installer_without_the_marker(tmp_path: Path) -> None:
    assert "--force-reinstall" in MARKERLESS_INSTALLER and "PIP_FIND_LINKS" in MARKERLESS_INSTALLER
    script, verifier, pubkey = _preinst_sandbox_script(tmp_path)
    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text("# verifier\n", encoding="utf-8")
    pubkey.parent.mkdir(parents=True, exist_ok=True)
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    installer = verifier.parent / "install_offline.sh"
    installer.write_text(MARKERLESS_INSTALLER, encoding="utf-8")
    proc = _run(script)
    assert proc.returncode == 1
    assert "OUTDATED copy" in proc.stderr and "udbmcp-installer-format: 4" in proc.stderr and "ABORTED" in proc.stderr
    installer.write_text(REAL_INSTALLER, encoding="utf-8")
    assert _run(script).returncode == 0

    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin verifier\n", encoding="utf-8")
    (trust / "profiles.py").write_text("# admin registry\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin helper\n", encoding="utf-8")
    post = _postinst_step1_bootstrap_script(tmp_path, strip_root_owner=True)
    (trust / "install_offline.sh").write_text(MARKERLESS_INSTALLER, encoding="utf-8")
    proc = _run(post)
    assert proc.returncode != 0 and "udbmcp-installer-format: 4" in proc.stderr
    (trust / "install_offline.sh").write_text(REAL_INSTALLER, encoding="utf-8")
    assert _run(post).returncode == 0


# ------------------------------------------------------------------ release script: keys are never implied
@_POSIX
def test_release_script_requires_an_explicit_key_pair_or_demo() -> None:
    script = ROOT / "scripts/package/release_usb.sh"
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    env["PATH"] = os.environ.get("PATH", "")
    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=60, env=env, cwd=ROOT
    )
    assert proc.returncode == 1 and "set BOTH UDBMCP_RELEASE_KEY and UDBMCP_PUBKEY" in proc.stderr
    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(script), "--what"], capture_output=True, text=True, timeout=60, env=env, cwd=ROOT
    )
    assert proc.returncode == 2 and "usage:" in proc.stderr
    proc = subprocess.run(  # noqa: S603
        ["/bin/bash", str(script), "--demo"], capture_output=True, text=True, timeout=60,
        env={**env, "UDBMCP_RELEASE_KEY": "k.pem", "UDBMCP_PUBKEY": "p.pem"}, cwd=ROOT,
    )
    assert proc.returncode == 1 and "exclusive" in proc.stderr


# ------------------------------------------------------------------ evidence scripts
def test_live_evidence_never_implies_ddl_consent_and_http_evidence_always_cleans_up() -> None:
    live = (ROOT / "scripts/live_evidence.py").read_text(encoding="utf-8")
    assert "allow_ddl = bool(args.i_know_this_sends_ddl)" in live
    assert 'Path(args.config).name == "config.mockdbs.yaml"' not in live
    http = (ROOT / "scripts/http_client_evidence.py").read_text(encoding="utf-8")
    assert http.index("    try:\n") < http.index("subprocess.Popen(") < http.index('"docker", "run"')
    assert 'f"udbmcp-tls-proxy-{os.getpid()}"' in http and "stderr=stderr_file" in http
