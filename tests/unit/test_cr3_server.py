"""Regressions for the third /code-review max pass over server.py (review of
9c457ec..0ad054b, fixed 2026-10-03), under the owner decision of that day:
masking accepts only the statement shapes it proves and refuses every other
one over a table with masked columns.

- #1: db_federated_query refuses an oversized statement (and set of them)
  before anything lexes it.
- #15: an Oracle statement's :ID binds the parameter named id.
- Masking: a corpus of everyday analytics statements keeps working with
  exact masking (SQLite in process; PostgreSQL 127.0.0.1:5433 and MySQL
  127.0.0.1:3307 loopback fixtures, skipped where not running), and every
  masking repro of the three reviews is masked or refused, never returned.
- #7: a SQLite view definition with a double-quoted word that is no column
  of a table its one FROM reads is withheld.
- The per-call listing memo keeps one connection's listing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from test_cr_fix_server import _call, _no_secret, _on, _proof, _server

from universal_db_mcp import server as srv
from universal_db_mcp.config import load_resolved
from universal_db_mcp.server import AppContext, build_server

REPO = Path(__file__).resolve().parents[2]


def _call_error(server: Any, name: str, args: dict[str, Any]) -> str:
    with pytest.raises(Exception) as info:  # noqa: PT011 - the ToolError text is what is asserted
        _call(server, name, args)
    return str(info.value)


# ------------------------------------------------------------- #1: size caps


def test_an_oversized_federated_statement_is_refused_before_it_is_lexed(tmp_path: Path, monkeypatch: Any) -> None:
    """2 MiB of '--' lines: refused for its size at once, never lexed (the
    lexing pass held the event loop for 12 s before the guard refused it)."""
    server, _app = _server(tmp_path)
    lexed: list[int] = []
    real = srv.code_view

    def spy(sql: str, engine: str) -> str:
        lexed.append(len(sql))
        return real(sql, engine)

    monkeypatch.setattr(srv, "code_view", spy)
    sql = "--\n" * 700_000 + "SELECT 1"
    for parameters in ({"a": 1}, {}, None, [1]):
        started = time.perf_counter()
        text = _call_error(
            server, "db_federated_query", {"sql": sql, "connections": ["shop"], "parameters": parameters}
        )
        assert time.perf_counter() - started < 2.0, "refused at once"
        assert "VALIDATION" in text and "byte limit" in text, text
    text = _call_error(server, "db_federated_query", {"queries": {"shop": sql}, "parameters": {"a": 1}})
    assert "VALIDATION" in text and "byte limit" in text, text
    assert lexed == []


def test_the_federated_statements_together_are_bounded(tmp_path: Path) -> None:
    server, app = _server(tmp_path)
    # five connections' distinct statements, each under the limit, over it together
    statements = {f"c{i}": f"SELECT {i}" + " " * (srv._MAX_SQL_BYTES - 20) for i in range(5)}
    with pytest.raises(srv.ToolFailure, match="together"):
        srv._check_statement_sizes(statements.values())
    srv._check_statement_sizes([next(iter(statements.values()))] * 64)  # one text, sent to many
    text = _call_error(server, "db_federated_query", {"sql": "SELECT 1", "connections": ["nope"]})
    assert "nope" in text


def test_the_parameter_pass_runs_off_the_event_loop_once_per_distinct_text(monkeypatch: Any) -> None:
    calls: list[tuple[str, str]] = []
    real = srv._statement_parameters

    def counting(sql: str, engine: str, parameters: Any) -> Any:
        calls.append((sql, engine))
        return real(sql, engine, parameters)

    monkeypatch.setattr(srv, "_statement_parameters", counting)
    plan = {f"c{i}": ("SELECT :a", "postgres") for i in range(10)} | {"o": ("SELECT :A FROM dual", "oracle")}
    bound = srv._bound_parameters(plan, {"a": 1})
    assert calls == [("SELECT :a", "postgres"), ("SELECT :A FROM dual", "oracle")]
    assert all(v == {"a": 1} for v in bound.values())


# --------------------------------------------------- #15: Oracle bind names


def test_oracle_binds_a_parameter_name_ignoring_case() -> None:
    assert srv._statement_parameters("SELECT :ID AS v FROM dual", "oracle", {"id": 5}) == {"id": 5}
    assert srv._statement_parameters("SELECT :id AS v FROM dual", "oracle", {"ID": 5}) == {"ID": 5}
    # every other driver compares names exactly
    assert srv._statement_parameters("SELECT :ID AS v", "postgres", {"id": 5}) is None
    assert srv._statement_parameters("SELECT :id AS v", "postgres", {"id": 5}) == {"id": 5}


def _oracle_live(tmp_path: Path) -> Any:
    secret = REPO / "out" / "mockdb-secrets" / "oracle.pw"
    if os.environ.get("UDBMCP_LIVE_FIXTURES") != "1":
        pytest.skip("live fixture tests are opt-in: set UDBMCP_LIVE_FIXTURES=1 with the loopback fixtures running")
    try:
        with socket.create_connection(("127.0.0.1", 1522), timeout=1):
            pass
    except OSError:
        pytest.skip("the loopback Oracle fixture (127.0.0.1:1522) is not running")
    if not secret.is_file():
        pytest.skip("the Oracle fixture's password file is not there")
    cfg = (REPO / "config.mockdbs.yaml").read_text(encoding="utf-8")
    if "oracle" not in cfg:
        pytest.skip("no Oracle connection in config.mockdbs.yaml")
    return None


def test_oracle_live_binds_a_federated_parameter_ignoring_case(tmp_path: Path) -> None:
    _oracle_live(tmp_path)
    os.environ.setdefault("UDBMCP_DEMO_ORA_USER", "travel")
    secret = REPO / "out" / "mockdb-secrets" / "oracle.pw"
    mock = (REPO / "config.mockdbs.yaml").read_text(encoding="utf-8")
    block = re.search(r"\n  (\w*ora\w*):\n((?:    .*\n)+)", mock)
    if block is None:
        pytest.skip("no Oracle block in config.mockdbs.yaml")
    body = re.sub(r"password_file: .*", f"password_file: {secret}", block.group(2))
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  max_concurrent_queries: 2\n  require_remote_tls: false\n"
        f"connections:\n  ora:\n{body}",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))
    args = {"queries": {"ora": "SELECT :ID AS v FROM dual"}, "parameters": {"id": 5}}
    env = _call(server, "db_federated_query", args)
    assert env["data"]["connections_run"] == 1, env
    assert env["data"]["results"][0]["rows"] == [[5]], env


# ------------------------------------------------- masking: the SQLite corpus

_CUSTOMERS = ("999-90-1111", "999-90-2222", "999-90-3333")
_CARDS = ("4111-0000-0000-1111", "4111-0000-0000-2222")
_SECRETS = _CUSTOMERS + _CARDS

_SCRIPT = f"""
CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, ssn TEXT, country TEXT,
                        created_at TEXT);
CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, status TEXT, created_at TEXT);
CREATE TABLE cards (card_id INTEGER PRIMARY KEY, customer_id INTEGER, card_number TEXT, holder TEXT);
INSERT INTO customers VALUES (1, 'Ada Lovelace', 'ada@example.invalid', '{_CUSTOMERS[0]}', 'QA', '2024-01-02'),
    (2, 'Alan Turing', 'alan@example.invalid', '{_CUSTOMERS[1]}', 'UK', '2024-02-03'),
    (3, 'Grace Hopper', 'grace@example.invalid', '{_CUSTOMERS[2]}', 'QA', '2024-03-04');
INSERT INTO orders VALUES (10, 1, 12.5, 'paid', '2024-04-01'), (11, 1, 7.0, 'open', '2024-05-01'),
    (12, 2, 30.0, 'paid', '2025-01-01');
INSERT INTO cards VALUES (100, 1, '{_CARDS[0]}', 'ADA L'), (101, 2, '{_CARDS[1]}', 'A TURING');
"""

_JOINED = "customers c JOIN orders o ON o.customer_id = c.customer_id"

# (statement, the output positions masking must mask): everyday analytics
# over tables with masked columns. A value is masked when it is, or is
# computed from, a masked column (a CASE condition, a window's ORDER BY and a
# subquery's WHERE count as computing from it).
SQLITE_CORPUS: list[tuple[str, set[int]]] = [
    ("SELECT * FROM customers", {3}),
    ("SELECT full_name, email FROM customers", set()),
    ("SELECT c.full_name, c.ssn FROM customers c", {1}),
    ("SELECT ssn AS ref FROM customers", {0}),
    ("SELECT country, count(*) AS n FROM customers GROUP BY country ORDER BY n DESC", set()),
    (f"SELECT c.full_name, sum(o.amount) AS total FROM {_JOINED} GROUP BY c.full_name", set()),
    ("SELECT c.*, o.amount FROM customers c LEFT JOIN orders o ON o.customer_id = c.customer_id", {3}),
    (f"SELECT * FROM {_JOINED}", {3}),
    ("SELECT o.order_id, c.full_name FROM orders o JOIN customers c USING (customer_id)", set()),
    ("WITH t AS (SELECT customer_id, sum(amount) AS total FROM orders GROUP BY customer_id) "
     "SELECT c.full_name, t.total FROM customers c JOIN t ON t.customer_id = c.customer_id", set()),
    ("WITH t AS (SELECT * FROM customers WHERE country = 'QA') SELECT * FROM t", {3}),
    ("WITH a AS (SELECT customer_id FROM orders), b AS (SELECT a.customer_id, c.email FROM a "
     "JOIN customers c ON c.customer_id = a.customer_id) SELECT * FROM b", set()),
    ("WITH t(id, who) AS (SELECT customer_id, ssn FROM customers) SELECT t.id, t.who FROM t", {1}),
    ("SELECT full_name, row_number() OVER (PARTITION BY country ORDER BY created_at) AS rn FROM customers", set()),
    ("SELECT full_name, rank() OVER (ORDER BY ssn) AS r FROM customers", {1}),
    ("SELECT c.customer_id, c.full_name, lag(c.full_name) OVER (ORDER BY c.customer_id) AS prev FROM customers c",
     set()),
    ("SELECT upper(full_name) AS name, lower(email) AS mail FROM customers", set()),
    ("SELECT substr(ssn, 1, 3) AS prefix FROM customers", {0}),
    ("SELECT full_name || ' <' || email || '>' AS contact FROM customers", set()),
    ("SELECT coalesce(email, 'none') AS e FROM customers", set()),
    ("SELECT full_name, ssn IS NOT NULL AS has_ssn FROM customers", {1}),
    ("SELECT CASE WHEN country = 'QA' THEN 'local' ELSE 'intl' END AS region, count(*) FROM customers GROUP BY 1",
     set()),
    ("SELECT full_name FROM customers WHERE customer_id IN (SELECT customer_id FROM orders WHERE amount > 10)", set()),
    ("SELECT full_name FROM customers ORDER BY ssn", set()),
    ("SELECT full_name, (SELECT count(*) FROM orders o WHERE o.customer_id = c.customer_id) AS n_orders "
     "FROM customers c", set()),
    ("SELECT (SELECT ssn FROM customers c2 WHERE c2.customer_id = c.customer_id) AS s FROM customers c", {0}),
    ("SELECT full_name FROM customers UNION SELECT holder FROM cards", set()),
    ("SELECT ssn FROM customers UNION ALL SELECT card_number FROM cards", {0}),
    ("SELECT customer_id, full_name FROM customers EXCEPT SELECT customer_id, holder FROM cards", set()),
    ("SELECT DISTINCT country FROM customers", set()),
    ("SELECT status, avg(amount) AS avg_amount, max(amount) FROM orders GROUP BY status HAVING count(*) > 0", set()),
    ("SELECT c.full_name, k.card_number FROM customers c JOIN cards k ON k.customer_id = c.customer_id", {1}),
    ("SELECT c.full_name, k.holder FROM customers c CROSS JOIN cards k", set()),
    ("SELECT k.* FROM cards k", {2}),
    ("SELECT * FROM orders", set()),
    ("SELECT o.status, count(DISTINCT o.customer_id) FROM orders o GROUP BY 1", set()),
    (f"SELECT x.full_name, x.total FROM (SELECT c.full_name, sum(o.amount) AS total FROM {_JOINED} "
     "GROUP BY c.full_name) x WHERE x.total > 5", set()),
    ("SELECT q.* FROM (SELECT customer_id, ssn AS tax FROM customers) q", {1}),
    ("SELECT * FROM (SELECT * FROM customers) t", {3}),
    ("SELECT t.email FROM (SELECT * FROM customers) t WHERE t.country = 'QA'", set()),
    ("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) "
     "SELECT c.full_name, n.i FROM customers c CROSS JOIN n", set()),
    ("SELECT c.full_name, o.order_id FROM customers c LEFT JOIN orders o ON o.customer_id = c.customer_id "
     "WHERE o.order_id IS NULL", set()),
    (f"SELECT c.full_name, max(o.created_at) AS last_order FROM {_JOINED} GROUP BY c.customer_id, c.full_name "
     "ORDER BY last_order DESC LIMIT 5", set()),
    ("SELECT count(*) FROM customers", set()),
    ("SELECT country, group_concat(full_name) AS names FROM customers GROUP BY country", set()),
    ("SELECT country, group_concat(ssn) AS ids FROM customers GROUP BY country", {1}),
    ("SELECT c.full_name AS name, o.amount * 1.1 AS gross FROM customers c, orders o "
     "WHERE c.customer_id = o.customer_id", set()),
    ("SELECT strftime('%Y', created_at) AS yr, count(*) FROM orders GROUP BY yr", set()),
    ("SELECT c.country, count(o.order_id) AS orders, sum(o.amount) AS revenue FROM customers c "
     "LEFT JOIN orders o ON o.customer_id = c.customer_id GROUP BY c.country", set()),
]


def _corpus_server(tmp_path: Path) -> Any:
    db = tmp_path / "corpus.db"
    c = sqlite3.connect(db)
    c.executescript(_SCRIPT)
    c.commit()
    c.close()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  max_concurrent_queries: 4\n"
        f"connections:\n  shop:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def _masked_positions(env: dict[str, Any]) -> set[int]:
    return {i for i, c in enumerate(env["data"]["columns"]) if c["type"].endswith("(masked)")}


def _check_corpus(server: Any, connection: str, corpus: list[tuple[str, set[int]]], secrets: tuple[str, ...]) -> None:
    for sql, masked in corpus:
        try:
            env = _call(server, "db_query", {"connection_id": connection, "sql": sql})
        except Exception as exc:  # noqa: BLE001 - which statement failed is the message
            raise AssertionError(f"{sql}: {exc}") from exc
        assert env["data"]["rows"], sql
        assert _masked_positions(env) == masked, (sql, env["data"]["columns"])
        _no_secret(env["data"]["rows"], secrets)


def test_the_corpus_has_forty_statements() -> None:
    assert len(SQLITE_CORPUS) >= 40


def test_everyday_analytics_over_masked_tables_keep_working_on_sqlite(tmp_path: Path) -> None:
    _check_corpus(_corpus_server(tmp_path), "shop", SQLITE_CORPUS, _SECRETS)


def test_the_corpus_is_proven_before_it_runs(demo_policy: Any) -> None:
    """The analysis alone, over the corpus's catalog: never a refusal."""
    catalog = {
        "customers": ("customer_id", "full_name", "email", "ssn", "country", "created_at"),
        "orders": ("order_id", "customer_id", "amount", "status", "created_at"),
        "cards": ("card_id", "customer_id", "card_number", "holder"),
    }
    policy = _on(demo_policy, "sqlite")
    for sql, masked in SQLITE_CORPUS:
        plan = _proof(policy, sqlglot.parse_one(sql, read="sqlite"), None, catalog)
        assert not isinstance(plan, str), (sql, plan)
        if plan is not None:
            assert {i for i, c in enumerate(plan) if c.tainted} == masked, sql


# ---------------------------------------- masking: live PostgreSQL and MySQL

PG_CORPUS: list[tuple[str, set[int]]] = [
    ("SELECT * FROM ocean.buoys", {1}),
    ("SELECT buoy_id, region FROM ocean.buoys", set()),
    ("SELECT b.callsign, avg(r.sea_temp_c) AS t FROM ocean.buoys b JOIN ocean.readings r ON r.buoy_id = b.buoy_id "
     "GROUP BY b.callsign", {0}),
    ("SELECT b.region, count(*) FROM ocean.buoys b JOIN ocean.readings r USING (buoy_id) GROUP BY b.region", set()),
    ("WITH t AS (SELECT buoy_id, max(wave_height_m) AS w FROM ocean.readings GROUP BY buoy_id) "
     "SELECT b.region, t.w FROM ocean.buoys b JOIN t ON t.buoy_id = b.buoy_id", set()),
    ("SELECT b.*, r.sea_temp_c FROM ocean.buoys b LEFT JOIN ocean.readings r ON r.buoy_id = b.buoy_id LIMIT 5", {1}),
    ("SELECT region, row_number() OVER (PARTITION BY region ORDER BY deployed_on) FROM ocean.buoys", set()),
    ("SELECT upper(callsign) FROM ocean.buoys", {0}),
    ("SELECT callsign::text AS c FROM ocean.buoys", {0}),
    ("SELECT region FROM ocean.buoys UNION SELECT callsign FROM ocean.buoys", {0}),
    ("SELECT buoy_id, (SELECT count(*) FROM ocean.readings r WHERE r.buoy_id = b.buoy_id) AS n FROM ocean.buoys b",
     set()),
    ("SELECT x.* FROM (SELECT buoy_id, callsign AS cs FROM ocean.buoys) x", {1}),
    ("SELECT date_trunc('day', recorded_at) AS d, avg(sea_temp_c) FROM ocean.readings GROUP BY 1 ORDER BY 1 LIMIT 3",
     set()),
    ("SELECT b.buoy_id, b.lat, b.lon FROM ocean.buoys b WHERE b.callsign IS NOT NULL", set()),
    ("SELECT DISTINCT region FROM ocean.buoys", set()),
    ("WITH RECURSIVE n AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM n WHERE i < 3) "
     "SELECT b.region, n.i FROM ocean.buoys b CROSS JOIN n LIMIT 5", set()),
    ("SELECT * FROM ocean.readings LIMIT 3", set()),
    ("SELECT coalesce(callsign, region) AS label FROM ocean.buoys", {0}),
    ("SELECT B.REGION, count(*) FROM ocean.buoys B GROUP BY B.REGION", set()),
    ("SELECT region, string_agg(callsign, ',') FROM ocean.buoys GROUP BY region", {1}),
]

MYSQL_CORPUS: list[tuple[str, set[int]]] = [
    ("SELECT * FROM cuppings", {2}),
    ("SELECT cupping_id, score FROM cuppings", set()),
    ("SELECT r.bean_origin, avg(c.score) AS s FROM cuppings c JOIN roastery_batches r ON r.batch_id = c.batch_id "
     "GROUP BY r.bean_origin", set()),
    ("SELECT c.taster, count(*) FROM cuppings c GROUP BY c.taster", {0}),
    ("WITH t AS (SELECT batch_id, max(score) AS m FROM cuppings GROUP BY batch_id) "
     "SELECT r.process, t.m FROM roastery_batches r JOIN t ON t.batch_id = r.batch_id", set()),
    ("SELECT c.*, r.roast_level FROM cuppings c LEFT JOIN roastery_batches r ON r.batch_id = c.batch_id", {2}),
    ("SELECT cupping_id, rank() OVER (ORDER BY score DESC) AS rk FROM cuppings", set()),
    ("SELECT upper(taster) AS t FROM cuppings", {0}),
    ("SELECT notes FROM cuppings UNION ALL SELECT taster FROM cuppings", {0}),
    ("SELECT batch_id, (SELECT count(*) FROM cuppings c WHERE c.batch_id = r.batch_id) AS n FROM roastery_batches r",
     set()),
    ("SELECT x.* FROM (SELECT cupping_id, taster AS who FROM cuppings) x", {1}),
    ("SELECT CONCAT(taster, ':', score) AS label FROM cuppings", {0}),
    ("SELECT DISTINCT roast_level FROM roastery_batches", set()),
    ("SELECT * FROM roastery_batches", set()),
    ("SELECT r.*, c.score FROM roastery_batches r JOIN cuppings c ON c.batch_id = r.batch_id", set()),
    ("SELECT c.cupping_id, c.taster FROM cuppings c WHERE c.score > 0 ORDER BY c.score DESC LIMIT 3", {1}),
    ("SELECT GROUP_CONCAT(taster) FROM cuppings", {0}),
    ("SELECT Taster FROM cuppings", {0}),
]


def _fixture(port: int, secret_name: str) -> Path:
    if os.environ.get("UDBMCP_LIVE_FIXTURES") != "1":
        pytest.skip("live fixture tests are opt-in: set UDBMCP_LIVE_FIXTURES=1 with the loopback fixtures running")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
    except OSError:
        pytest.skip(f"the loopback fixture on 127.0.0.1:{port} is not running")
    secret = REPO / "out" / "mockdb-secrets" / secret_name
    if not secret.is_file():
        pytest.skip(f"the fixture's password file {secret_name} is not there")
    return secret


def _live(tmp_path: Path, engine: str, port: int, database: str, user_env: str, user: str, secret: Path,
          pattern: str) -> Any:
    os.environ.setdefault(user_env, user)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        "security:\n  max_concurrent_queries: 4\n  require_remote_tls: false\n"
        "  default_deny_objects: true\n  allowed_system_schemas: [information_schema]\n"
        f"  mask_columns: ['{pattern}']\n"
        f"connections:\n  live:\n    type: {engine}\n    host: 127.0.0.1\n    port: {port}\n"
        f"    database: {database}\n    username_env: {user_env}\n    password_file: {secret}\n    read_only: true\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def _pg_secrets(secret: Path) -> tuple[str, ...]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=5433, dbname="postgres",
                         user=os.environ.get("UDBMCP_DEMO_PG_USER", "udbmcp_ro"),
                         password=secret.read_text(encoding="utf-8").strip()) as conn:
        return tuple(str(r[0]) for r in conn.execute("SELECT callsign FROM ocean.buoys").fetchall())


def _mysql_secrets(secret: Path) -> tuple[str, ...]:
    import pymysql

    conn = pymysql.connect(host="127.0.0.1", port=3307, database="testdb",
                           user=os.environ.get("UDBMCP_DEMO_MYSQL_USER", "udbmcp_ro"),
                           password=secret.read_text(encoding="utf-8").strip())
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT taster FROM cuppings")
            return tuple(str(r[0]) for r in cur.fetchall())
    finally:
        conn.close()


def test_everyday_analytics_keep_working_on_live_postgres(tmp_path: Path) -> None:
    secret = _fixture(5433, "pg.pw")
    server = _live(tmp_path, "postgres", 5433, "postgres", "UDBMCP_DEMO_PG_USER", "udbmcp_ro", secret,
                   "(?i)^callsign$")
    _check_corpus(server, "live", PG_CORPUS, _pg_secrets(secret))


def test_everyday_analytics_keep_working_on_live_mysql(tmp_path: Path) -> None:
    secret = _fixture(3307, "mysql.pw")
    server = _live(tmp_path, "mysql", 3307, "testdb", "UDBMCP_DEMO_MYSQL_USER", "udbmcp_ro", secret,
                   "(?i)^taster$")
    _check_corpus(server, "live", MYSQL_CORPUS, _mysql_secrets(secret))


# ---------------------------------- masking: the three reviews' repros

# Every masking repro of review 1 (M1-M4, P1-P4), review 2 (M1/M2/P2/V11-*,
# the decoy CTEs) and review 3 (#2, #4, #5, #6) that the analysis sees
# offline: each is now refused (or, where marked, masked exactly).
_PEOPLE = ("id", "full_name", "ssn")
_REPRO_CATALOG = {
    "customers": ("customer_id", "full_name", "email", "ssn", "country", "created_at"),
    "people": _PEOPLE,
    "accounts": ("id", "x", "y"),
    "buoys": ("buoy_id", "callsign", "region", "lat", "lon", "deployed_on"),
    "readings": ("reading_id", "buoy_id", "recorded_at", "sea_temp_c", "wave_height_m"),
    "subscribers": ("subscriber_id", "full_name", "ssn", "tariff"),
    "cards": ("card_id", "holder", "ssn"),
}

REPROS: list[tuple[str, str]] = [
    # review 1, M1: composite expansion widths
    ("postgres", "SELECT (CAST('(1,a,b,c,d,e)' AS customers)).*, upper(c.ssn), c.* FROM customers c"),
    ("postgres", "SELECT c.*, (CAST('(1,' || c.ssn || ',,,,)' AS customers)).* FROM customers c"),
    ("postgres", "SELECT a.*, (q).* FROM accounts a, (SELECT ssn, ssn FROM customers) AS q(x, y)"),
    ("postgres", "SELECT (q).*, upper(c.ssn) FROM customers c, (SELECT 1 AS k, 2 AS j) q"),
    # M2: aliases that differ only in case
    ("postgres", 'SELECT "A".k FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)'),
    ("postgres", 'SELECT "A".* FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)'),
    ("postgres", 'SELECT to_json("A".*) FROM (SELECT 1 AS k) a, (SELECT ssn FROM customers) "A"(k)'),
    ("postgres", 'SELECT (SELECT "A".k FROM (SELECT 1 AS k) a) FROM (SELECT ssn FROM customers) "A"(k)'),
    ("mysql", "SELECT `A`.k FROM (SELECT 1 AS k) a, (SELECT ssn AS k FROM customers) `A`"),
    ("clickhouse", "SELECT A.k FROM (SELECT 1 AS k) AS a, (SELECT ssn AS k FROM customers) AS A"),
    # M3 / R5: attribute notation, decoy CTEs
    ("postgres", "SELECT x.row_text FROM (SELECT * FROM customers, unnest(ARRAY[1]) u) x"),
    ("postgres", "SELECT x.text FROM (SELECT * FROM customers, unnest(ARRAY[1]) u) x"),
    ("postgres", 'WITH "CUSTOMERS" AS (SELECT 1 AS k) SELECT x.row_text FROM CUSTOMERS x'),
    ("postgres", 'WITH "Foo" AS (SELECT 1 AS k) SELECT x.site_fn FROM customers x'),
    ("postgres", "SELECT b.site_row_fn FROM customers b"),
    # P1: PIVOT/UNPIVOT
    ("mssql", "SELECT p.QA FROM dbo.customers PIVOT (MAX(ssn) FOR country IN ([QA])) AS p"),
    ("mssql", "SELECT u.val FROM dbo.customers UNPIVOT (val FOR col IN (full_name, ssn)) AS u"),
    ("oracle", "SELECT p.x FROM customers PIVOT (MAX(ssn) FOR country IN ('QA' AS x)) p"),
    ("oracle", "SELECT u.val FROM customers UNPIVOT (val FOR col IN (full_name, ssn)) u"),
    # P2: SQLite's engine-made names
    ("sqlite", 'SELECT "x:1" AS y FROM (SELECT full_name AS x, ssn AS x FROM customers) q'),
    ("sqlite", 'SELECT "upper(x)" AS y FROM (SELECT upper(x), full_name AS "upper(x)" FROM '
               "(SELECT ssn AS x, full_name FROM customers) a) b"),
    ("sqlite", 'SELECT "full_name:1" AS y FROM (SELECT a.full_name, b.ssn AS full_name '
               "FROM customers a, customers b) q"),
    ("sqlite", "SELECT x AS y FROM (SELECT (x), full_name AS x FROM (SELECT ssn AS x, full_name FROM customers) a) b"),
    # P3: MATCH_RECOGNIZE; P4: SEARCH/CYCLE
    ("oracle", "SELECT x FROM customers MATCH_RECOGNIZE (ORDER BY customer_id MEASURES FIRST(ssn) AS x "
               "PATTERN (a) DEFINE a AS 1 = 1)"),
    ("postgres", "WITH RECURSIVE t(a) AS (SELECT ssn FROM customers UNION ALL SELECT a FROM t WHERE false) "
                 "CYCLE a SET is_cycle USING path SELECT path FROM t"),
    ("postgres", "WITH RECURSIVE t(a) AS (SELECT ssn FROM customers UNION ALL SELECT a FROM t WHERE false) "
                 "SEARCH DEPTH FIRST BY a SET ord SELECT ord FROM t"),
    # review 2, V11-a: composite stars
    ("postgres", "SELECT ((b).*), upper(b.callsign), b.* FROM buoys b"),
    ("postgres", "SELECT (b.*), upper(b.callsign), b.* FROM buoys b"),
    ("postgres", "SELECT b.* AS buoy_id, upper(b.callsign), b.* FROM buoys b"),
    ("clickhouse", "SELECT (s.*), concat(s.ssn, ''), s.* FROM subscribers s"),
    # V11-b / M2: a spare CTE
    ("postgres", "WITH w AS (SELECT 1 AS k) SELECT x.out FROM (SELECT ssn FROM customers) w(k), "
                 "LATERAL (SELECT w.k AS out) x"),
    ("sqlite", "WITH w AS (SELECT 1 AS k), t(k) AS (SELECT ssn FROM customers) SELECT (SELECT w.k) AS out FROM t AS w"),
    # V11-c: renamed SQLite aliases
    ("sqlite", 'SELECT q."x:1" AS y FROM (SELECT full_name AS x, ssn AS x, email AS "x:1" FROM customers) q'),
    ("sqlite", 'SELECT column1 AS y FROM (SELECT ssn AS "true", c.* FROM customers c) q'),
    ("sqlite", 'SELECT q.column1 AS y FROM (SELECT ssn AS "false", full_name AS column1 FROM customers c) q'),
    ("sqlite", 'WITH t("true", n) AS (SELECT ssn, full_name FROM customers) SELECT column1 AS y FROM t'),
    # V11-d: table functions
    ("postgres", "SELECT u.*, upper(b.callsign), b.* FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(x), buoys b"),
    ("postgres", "SELECT u.*, upper(b.callsign), b.* FROM unnest(ARRAY[1], ARRAY[2]) AS u(x), buoys b"),
    # V11-e: parenthesized joins
    ("postgres", "SELECT * FROM (readings r CROSS JOIN (SELECT callsign FROM buoys) b(j)) x"),
    ("postgres", "SELECT x.j FROM (readings r CROSS JOIN (SELECT callsign FROM buoys) b(j)) x"),
    # V1-a: a CTE spelled otherwise
    ("oracle", "WITH σ AS (SELECT 'a' AS x FROM DUAL UNION ALL SELECT ssn FROM people) SELECT * FROM ς"),
    # review 3, #2: ClickHouse binds a CTE's own name behind an alias, and SEMI-joins it
    ("clickhouse", "WITH w AS (SELECT * REPLACE (ssn AS full_name) FROM people) SELECT w.full_name FROM w AS z"),
    ("clickhouse", "WITH w AS (SELECT id, ssn AS full_name FROM people) SELECT w.full_name FROM w AS z"),
    ("clickhouse", "SELECT t.id, w.full_name FROM people t LEFT SEMI JOIN w ON t.id = w.id"),
    ("clickhouse", "WITH w AS (SELECT id, ssn AS full_name FROM people) "
                   "SELECT t.id, w.full_name FROM people t LEFT SEMI JOIN w ON t.id = w.id"),
    # #4: VALUES composites and parenthesized joins
    ("postgres", "SELECT v.*, upper(p.ssn), p.* FROM (VALUES (('(1,a,b)'::people).*)) v(k), people p"),
    ("postgres", "SELECT x.s FROM ((SELECT 1 AS one) q CROSS JOIN people AS p(i,n,s)) x"),
    ("postgres", "SELECT * FROM (people AS p(i,n,s) CROSS JOIN (SELECT 1) z) x"),
    # #5: colon-led SQLite aliases
    ("sqlite", 'SELECT q.":1" AS y FROM (SELECT full_name AS "", ssn AS "", email AS ":1" FROM customers) q'),
    ("sqlite", 'SELECT ":1" FROM (SELECT ssn AS ":5", ssn AS ":5", full_name AS ":1" FROM customers)'),
    ("sqlite", 'SELECT q.":1" AS y FROM (SELECT ssn AS ":", ssn AS ":", full_name AS ":1" FROM customers) q'),
    # #6: a column list over a miscounted run
    ("postgres", "SELECT * FROM (SELECT v.*, upper(p.ssn), p.* FROM (VALUES (('(1,a,b)'::people).*)) v(k), people p) "
                 "q(a,b)"),
    # review 3, #4 class: column lists on base tables
    ("postgres", "SELECT * FROM (buoys AS r(a, b2) CROSS JOIN readings z) x"),
    ("postgres", "SELECT * FROM (buoys AS r(a, b2)) x"),
    # composite expansion, untuple, COLUMNS(), ARRAY JOIN, LATERAL, APPLY
    ("clickhouse", "SELECT untuple(tuple(t.ssn, t.full_name)), t.subscriber_id AS k FROM subscribers t"),
    ("clickhouse", "SELECT upper(COLUMNS('ss.*')) FROM customers"),
    ("clickhouse", "SELECT upper(x) FROM customers ARRAY JOIN [ssn] AS x"),
    ("tsql", "SELECT y FROM (VALUES (1)) v(x) CROSS APPLY (SELECT TOP 1 ssn AS y FROM customers) z"),
    ("postgres", "SELECT l.y FROM (SELECT ssn AS x FROM customers) q, LATERAL (SELECT x AS y FROM customers c2) l"),
    ("tsql", "SELECT TOP 2 * FROM customers FOR JSON PATH"),
]


@pytest.mark.parametrize(("engine", "sql"), REPROS)
def test_every_review_repro_is_refused_or_masked_whole(demo_policy: Any, engine: str, sql: str) -> None:
    """Each is refused before it runs, or (the single-column ones whose shape
    is an ordinary one) its every column is masked: never a value in clear."""
    policy = _on(demo_policy, "mssql" if engine == "tsql" else engine)
    policy = srv.dataclasses.replace(policy, sensitive_patterns=[
        *policy.sensitive_patterns, re.compile("(?i)^callsign$")
    ])
    try:
        ast = sqlglot.parse_one(sql, read=srv.sqlglot_dialect(policy.engine))
    except sqlglot.errors.SqlglotError:
        return  # the guard refuses what does not parse
    plan = _proof(policy, ast, None, _REPRO_CATALOG)
    assert isinstance(plan, str) or all(c.tainted for c in plan or [None]), (sql, plan)


# repros that are ordinary shapes: masked exactly, never refused
_MASKED_REPROS: list[tuple[str, str, list[str], set[int]]] = [
    # V11-f: ClickHouse names a self-join's second star column s2.x
    ("clickhouse", "SELECT * FROM subscribers s, subscribers s2",
     [*_REPRO_CATALOG["subscribers"], *(f"s2.{c}" for c in _REPRO_CATALOG["subscribers"])], {2, 6}),
    ("clickhouse", "SELECT s.*, s2.* FROM subscribers s, subscribers s2",
     [*_REPRO_CATALOG["subscribers"], *(f"s2.{c}" for c in _REPRO_CATALOG["subscribers"])], {2, 6}),
    # V11-g: a row id may be an INTEGER PRIMARY KEY's value
    ("sqlite", "SELECT rowid AS x FROM cards", ["x"], {0}),
    ("mysql", "SELECT c._rowid AS x FROM cards c", ["x"], {0}),
    # M2 control: the everyday spelling of an alias
    ("postgres", "SELECT C.full_name FROM customers c", ["full_name"], set()),
    # review 2 V11-h: a 63-byte alias and a clean column beside a star
    ("postgres", "SELECT b.*, 1 AS " + "a" * 70 + " FROM buoys b", [*_REPRO_CATALOG["buoys"], "a" * 63], {1}),
]


@pytest.mark.parametrize(("engine", "sql", "columns", "masked"), _MASKED_REPROS)
def test_ordinary_repro_shapes_are_masked_exactly(
    demo_policy: Any, engine: str, sql: str, columns: list[str], masked: set[int]
) -> None:
    policy = _on(demo_policy, engine)
    policy = srv.dataclasses.replace(policy, sensitive_patterns=[
        *policy.sensitive_patterns, re.compile("(?i)^callsign$")
    ])
    ast = sqlglot.parse_one(sql, read=srv.sqlglot_dialect(engine))
    plan = _proof(policy, ast, None, _REPRO_CATALOG)
    assert isinstance(plan, list), (sql, plan)
    assert srv._laid_out(plan, [(c, "t") for c in columns]) == masked


def test_an_anchored_pattern_still_masks_a_qualified_clickhouse_column(demo_policy: Any) -> None:
    """V11-f: ClickHouse reports s2.msisdn, which ^msisdn$ does not match; the
    position is masked by what the column is."""
    policy = srv.dataclasses.replace(_on(demo_policy, "clickhouse"), sensitive_patterns=[re.compile("^msisdn$")])
    ast = sqlglot.parse_one("SELECT s.subscriber_id, s2.msisdn FROM t s, t s2", read="clickhouse")
    plan = _proof(policy, ast, None, {"t": ("subscriber_id", "msisdn")})
    assert isinstance(plan, list)
    assert srv._mask_columns(policy, [("subscriber_id", "t"), ("s2.msisdn", "t")],
                             srv._laid_out(plan, [("subscriber_id", "t"), ("s2.msisdn", "t")])) == {1}


def test_the_sqlite_repros_end_to_end(tmp_path: Path) -> None:
    """Review 2 V11-c and review 3 #5 through db_query: refused, never a value."""
    server = _corpus_server(tmp_path)
    for engine, sql in REPROS:
        if engine != "sqlite":
            continue
        try:
            env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
        except Exception as exc:  # noqa: BLE001 - the refusal's text is what is asserted
            assert "cannot be checked for them" in str(exc) or "VALIDATION" in str(exc), (sql, exc)
            continue
        _no_secret(env, _SECRETS)


# ------------------------------- masking: refusals name what to avoid


@pytest.mark.parametrize(("sql", "reason"), [
    ("SELECT * FROM customers, (VALUES (1)) v(x)", "VALUES"),
    ("SELECT (c).* FROM customers c", "composite expansion"),
    ("SELECT c.* AS x FROM customers c", "a star in parentheses or under an alias"),
    ("SELECT * FROM customers c JOIN orders o USING (customer_id)", "USING or NATURAL"),
    ("SELECT x FROM customers AS c(x)", "column list on the table"),
    ("SELECT c FROM customers c", "is not a column of any FROM item"),
    ('SELECT "Full_Name" FROM customers', "spelled otherwise"),
])
def test_a_refusal_names_the_construct(demo_policy: Any, sql: str, reason: str) -> None:
    catalog = {"customers": ("customer_id", "full_name", "ssn"), "orders": ("order_id", "customer_id")}
    plan = _proof(_on(demo_policy, "postgres"), sqlglot.parse_one(sql, read="postgres"), None, catalog)
    assert isinstance(plan, str) and reason in plan, (sql, plan)


def test_a_refusal_comes_before_the_statement_runs(tmp_path: Path, monkeypatch: Any) -> None:
    from universal_db_mcp.connectors.sqlite import SQLiteConnector

    ran: list[str] = []
    real = SQLiteConnector.execute_query

    def recording(self: Any, spec: Any) -> Any:
        ran.append(spec.sql)
        return real(self, spec)

    monkeypatch.setattr(SQLiteConnector, "execute_query", recording)
    server = _corpus_server(tmp_path)
    text = _call_error(server, "db_query", {"connection_id": "shop", "sql": "SELECT * FROM customers, (VALUES (1))"})
    assert "POLICY_VIOLATION" in text and "cannot be checked for them" in text and "VALUES" in text, text
    assert ran == []


def test_statements_over_tables_without_masked_columns_are_not_analysed(tmp_path: Path) -> None:
    """A statement that reads no table with a masked column behaves as before:
    exotic shapes over clean tables run, and the output names still decide."""
    server = _corpus_server(tmp_path)
    for sql in ("SELECT * FROM orders, (VALUES (1)) v", "SELECT o.* FROM orders o JOIN orders p USING (order_id)",
                "SELECT 'x' AS ssn FROM orders"):
        env = _call(server, "db_query", {"connection_id": "shop", "sql": sql})
        assert env["data"]["rows"], sql
    env = _call(server, "db_query", {"connection_id": "shop", "sql": "SELECT 'x' AS ssn FROM orders"})
    assert _masked_positions(env) == {0}


def test_a_struct_field_with_a_masked_name_is_masked(demo_policy: Any) -> None:
    """A masked name the statement reads through a column of a clean table
    (a ClickHouse tuple's field) makes the statement one to analyse."""
    policy = _on(demo_policy, "clickhouse")
    ast = sqlglot.parse_one("SELECT person.ssn AS x FROM t", read="clickhouse")
    plan = _proof(policy, ast, None, {"t": ("id", "person")})
    assert isinstance(plan, list) and plan[0].tainted


def test_case_rules_bind_exactly(demo_policy: Any) -> None:
    """PostgreSQL folds an unquoted reference to lower case, Oracle to upper
    case; a reference spelled as only another case of a catalog name is
    refused, never bound to it."""
    pg = _on(demo_policy, "postgres")
    ok = _proof(pg, sqlglot.parse_one("SELECT SSN, Full_Name FROM customers", read="postgres"), None,
                {"customers": ("full_name", "ssn")})
    assert isinstance(ok, list) and [c.tainted for c in ok] == [True, False]
    refused = _proof(pg, sqlglot.parse_one('SELECT t."FULL_NAME" FROM customers t', read="postgres"), None,
                     {"customers": ("full_name", "ssn")})
    assert isinstance(refused, str) and "spelled otherwise" in refused, refused
    ora = _on(demo_policy, "oracle")
    ok = _proof(ora, sqlglot.parse_one("SELECT full_name FROM customers", read="oracle"), None,
                {"customers": ("FULL_NAME", "SSN")})
    assert isinstance(ok, list)
    refused = _proof(ora, sqlglot.parse_one('SELECT "full_name" FROM customers', read="oracle"), None,
                     {"customers": ("FULL_NAME", "SSN")})
    assert isinstance(refused, str), refused


def test_a_qualifier_shadowed_in_a_subquery_is_refused_and_a_unique_one_binds(demo_policy: Any) -> None:
    policy = _on(demo_policy, "postgres")
    catalog = {"customers": ("customer_id", "full_name", "ssn"), "orders": ("order_id", "customer_id")}
    sql = ("SELECT c.full_name, (SELECT count(*) FROM orders o WHERE o.customer_id = c.customer_id) "
           "FROM customers c")
    assert isinstance(_proof(policy, sqlglot.parse_one(sql, read="postgres"), None, catalog), list)
    sql = "SELECT (SELECT c.ssn FROM customers C LIMIT 1) FROM customers c"  # same name, both folding to c
    assert isinstance(_proof(policy, sqlglot.parse_one(sql, read="postgres"), None, catalog), list)
    sql = 'SELECT (SELECT "C".ssn FROM customers c LIMIT 1) FROM customers "C"'
    plan = _proof(policy, sqlglot.parse_one(sql, read="postgres"), None, catalog)
    assert isinstance(plan, list) and plan[0].tainted


def test_a_recursive_cte_moving_a_value_between_columns_is_masked(demo_policy: Any) -> None:
    policy = _on(demo_policy, "sqlite")
    sql = ("WITH RECURSIVE t(a, b, n) AS (SELECT full_name, ssn, 0 FROM customers "
           "UNION ALL SELECT b, a, n + 1 FROM t WHERE n < 2) SELECT a, n FROM t")
    plan = _proof(policy, sqlglot.parse_one(sql, read="sqlite"), None, {"customers": ("full_name", "ssn")})
    assert isinstance(plan, list) and [c.tainted for c in plan] == [True, False]


# --------------------------------------- #7: SQLite view-definition literals

_VIEWS = """
CREATE TABLE users (id INTEGER PRIMARY KEY, password TEXT, role TEXT);
CREATE TABLE roles (rid INTEGER PRIMARY KEY, admin TEXT);
CREATE VIEW v_having AS SELECT password, count(*) AS n FROM users GROUP BY password HAVING password <> "Sup3rSecret";
CREATE VIEW v_tvf AS SELECT u.id FROM users u, json_each("[""Sup3rSecret""]") j WHERE u.password = j.value;
CREATE VIEW v_outer AS SELECT id FROM users WHERE password = "admin" AND EXISTS (SELECT 1 FROM roles);
CREATE VIEW v_cols AS SELECT "id", "password" FROM users WHERE "role" IS NOT NULL;
CREATE VIEW v_list("user_id", "password") AS SELECT id, password FROM users;
CREATE VIEW v_plain AS SELECT id FROM users WHERE password IS NOT NULL;
"""


def _views_server(tmp_path: Path) -> Any:
    db = tmp_path / "views.db"
    c = sqlite3.connect(db)
    c.executescript(_VIEWS)
    c.commit()
    c.close()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"security:\n  max_concurrent_queries: 4\nconnections:\n  shop:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    return build_server(AppContext(app_cfg, resolved))


def test_a_sqlite_view_with_a_double_quoted_value_is_withheld_whatever_clause_holds_it(tmp_path: Path) -> None:
    server = _views_server(tmp_path)
    listed = _call(server, "db_list_views", {"connection_id": "shop"})
    defs = {v["name"]: v["definition"] for v in listed["data"]["views"]}
    for name in ("v_having", "v_tvf", "v_outer"):
        assert defs[name] is None, (name, defs[name])
        detail = _call(server, "db_get_table", {"connection_id": "shop", "object_name": name})
        assert detail["data"].get("definition") is None, name
    assert "Sup3rSecret" not in json.dumps(listed)
    # a double-quoted word that is a column of the table the view reads stays a name
    assert defs["v_cols"] is not None and defs["v_plain"] is not None
    # a view's own column list is not one of its table's columns: withheld (fail closed, documented)
    assert defs["v_list"] is None


def test_the_sqlite_view_rule_reads_one_from_clause_only() -> None:
    tables = srv._sqlite_view_tables
    query = srv._sqlite_view_query
    assert tables(query('CREATE VIEW v AS SELECT a FROM t JOIN u ON t.x = u.x'), None) == {("main", "t"), ("main", "u")}
    for sql in ('CREATE VIEW v AS SELECT a FROM t WHERE EXISTS (SELECT 1 FROM u)',
                'CREATE VIEW v AS SELECT a FROM t, json_each(t.j)',
                'CREATE VIEW v AS SELECT a FROM (SELECT a FROM t)',
                'CREATE VIEW v AS SELECT a FROM t UNION SELECT a FROM u',
                'CREATE VIEW v AS WITH w AS (SELECT a FROM t) SELECT a FROM w'):
        q = query(sql)
        assert q is None or tables(q, None) == set(), sql


# ------------------------------------------------ the per-call listing memo


def test_the_call_listing_memo_keeps_one_connection(tmp_path: Path, monkeypatch: Any) -> None:
    """A federated call over many connections held every catalog it read
    until it ended; the memo now keeps the latest connection's only."""
    _server_, app = _server(tmp_path)
    read: list[str] = []

    async def listing(self: Any, policy: Any, connector: Any) -> list[Any]:
        read.append(policy.connection_id)
        return [policy.connection_id]

    monkeypatch.setattr(AppContext, "_tables_for", listing)

    async def calls() -> None:
        token = srv._CALL_LISTINGS.set({})
        try:
            connector, policy = app.connection("shop")
            other = srv.dataclasses.replace(policy, connection_id="other")
            await app.tables_for(policy, connector)
            await app.tables_for(policy, connector)  # the same connection: from the memo
            await app.tables_for(other, connector)
            memo = srv._CALL_LISTINGS.get()
            assert memo is not None and len(memo) == 1 and next(iter(memo))[0] == "other"
            await app.tables_for(policy, connector)  # read again: only one listing is kept
        finally:
            srv._CALL_LISTINGS.reset(token)

    asyncio.run(calls())
    assert read == ["shop", "other", "shop"], read
