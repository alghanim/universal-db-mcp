#!/usr/bin/env python3
"""Version-matrix probe: exercise every connector capability against ONE
server and emit a JSON record of what passed, failed or was skipped.

Runs on the staging machine against a container started by run.sh. Seeds a
small themed schema with the engine's ADMIN account through the raw driver
(privileges are not the subject of this matrix; compatibility is), then
drives the udbmcp connector exactly as the server would: session profile,
catalog listings, bulk columns, indexes, keys, routines, statistics, a
query, the bounded sample, the profiling aggregate, top values, the value
search shape and explain where supported.

Usage: probe.py --engine postgres --host 127.0.0.1 --port 5432 --database vm
                --user admin --password-file /path --label postgres:12 --out result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from universal_db_mcp.config import ConnectionConfig, ResolvedConnection, SecurityConfig  # noqa: E402
from universal_db_mcp.connectors import registry  # noqa: E402
from universal_db_mcp.connectors.base import QuerySpec  # noqa: E402
from universal_db_mcp.discovery.profile import aggregate_select_list, build_profiles  # noqa: E402
from universal_db_mcp.security.policy import EffectivePolicy  # noqa: E402

SEEDS: dict[str, list[str]] = {
    "postgres": [
        "CREATE SCHEMA IF NOT EXISTS vm",
        "CREATE TABLE vm.customers (id integer PRIMARY KEY, email varchar(200), region varchar(50), note text, created timestamp, balance numeric(12,2))",
        "CREATE TABLE vm.orders (id integer PRIMARY KEY, customer_id integer REFERENCES vm.customers(id), total numeric(12,2))",
        "CREATE INDEX ix_orders_customer ON vm.orders(customer_id)",
        "CREATE VIEW vm.v_orders AS SELECT o.id, c.email, o.total FROM vm.orders o JOIN vm.customers c ON c.id = o.customer_id",
        "CREATE FUNCTION vm.f_one() RETURNS integer AS 'SELECT 1' LANGUAGE sql",
        "INSERT INTO vm.customers SELECT g, 'user' || g || '@example.com', CASE WHEN g % 3 = 0 THEN 'north' WHEN g % 3 = 1 THEN 'south' ELSE NULL END, repeat('x', g % 40), now(), g * 1.5 FROM generate_series(1, 300) g",
        "INSERT INTO vm.orders SELECT g, (g % 300) + 1, g * 2.25 FROM generate_series(1, 600) g",
    ],
    "mysql": [
        "CREATE DATABASE IF NOT EXISTS vm",
        "CREATE TABLE vm.customers (id int PRIMARY KEY, email varchar(200), region varchar(50), note text, created datetime, balance decimal(12,2))",
        "CREATE TABLE vm.orders (id int PRIMARY KEY, customer_id int, total decimal(12,2), CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES vm.customers(id))",
        "CREATE INDEX ix_orders_customer ON vm.orders(customer_id)",
        "CREATE VIEW vm.v_orders AS SELECT o.id, c.email, o.total FROM vm.orders o JOIN vm.customers c ON c.id = o.customer_id",
        "@rows",
    ],
    "clickhouse": [
        "CREATE DATABASE IF NOT EXISTS vm",
        "CREATE TABLE vm.customers (id UInt32, email String, region Nullable(String), note String, created DateTime, balance Decimal(12,2)) ENGINE = MergeTree ORDER BY id",
        "CREATE TABLE vm.orders (id UInt32, customer_id UInt32, total Decimal(12,2), INDEX ix_cust customer_id TYPE minmax GRANULARITY 4) ENGINE = MergeTree ORDER BY id",
        "CREATE VIEW vm.v_orders AS SELECT o.id, c.email, o.total FROM vm.orders o JOIN vm.customers c ON c.id = o.customer_id",
        "INSERT INTO vm.customers SELECT number + 1, concat('user', toString(number + 1), '@example.com'), if(number % 3 = 2, NULL, if(number % 3 = 0, 'north', 'south')), repeat('x', toUInt8(number % 40)), now(), (number + 1) * 1.5 FROM numbers(300)",
        "INSERT INTO vm.orders SELECT number + 1, (number % 300) + 1, (number + 1) * 2.25 FROM numbers(600)",
    ],
    "oracle": [
        "CREATE TABLE vm_customers (id NUMBER(10) PRIMARY KEY, email VARCHAR2(200), region VARCHAR2(50), note CLOB, created TIMESTAMP, balance NUMBER(12,2))",
        "CREATE TABLE vm_orders (id NUMBER(10) PRIMARY KEY, customer_id NUMBER(10) REFERENCES vm_customers(id), total NUMBER(12,2))",
        "CREATE INDEX ix_orders_customer ON vm_orders(customer_id)",
        "CREATE VIEW vm_v_orders AS SELECT o.id, c.email, o.total FROM vm_orders o JOIN vm_customers c ON c.id = o.customer_id",
        "CREATE FUNCTION vm_f_one RETURN NUMBER IS BEGIN RETURN 1; END;",
        "INSERT INTO vm_customers SELECT level, 'user' || level || '@example.com', CASE WHEN MOD(level,3)=0 THEN 'north' WHEN MOD(level,3)=1 THEN 'south' ELSE NULL END, RPAD('x', MOD(level,40)+1, 'x'), SYSTIMESTAMP, level * 1.5 FROM dual CONNECT BY level <= 300",
        "INSERT INTO vm_orders SELECT level, MOD(level,300)+1, level * 2.25 FROM dual CONNECT BY level <= 600",
        "COMMIT",
    ],
    "mssql": [
        "IF DB_ID('vm') IS NULL CREATE DATABASE vm",
        "@usevm",
        "CREATE TABLE dbo.customers (id int PRIMARY KEY, email nvarchar(200), region nvarchar(50), note nvarchar(max), created datetime2, balance decimal(12,2))",
        "CREATE TABLE dbo.orders (id int PRIMARY KEY, customer_id int REFERENCES dbo.customers(id), total decimal(12,2))",
        "CREATE INDEX ix_orders_customer ON dbo.orders(customer_id)",
        "CREATE VIEW dbo.v_orders AS SELECT o.id, c.email, o.total FROM dbo.orders o JOIN dbo.customers c ON c.id = o.customer_id",
        "CREATE FUNCTION dbo.f_one() RETURNS int AS BEGIN RETURN 1 END",
        "@rows",
    ],
    "db2": [
        "CREATE SCHEMA VM",
        "CREATE TABLE VM.CUSTOMERS (ID INTEGER NOT NULL PRIMARY KEY, EMAIL VARCHAR(200), REGION VARCHAR(50), NOTE CLOB(1M), CREATED TIMESTAMP, BALANCE DECIMAL(12,2))",
        "CREATE TABLE VM.ORDERS (ID INTEGER NOT NULL PRIMARY KEY, CUSTOMER_ID INTEGER REFERENCES VM.CUSTOMERS(ID), TOTAL DECIMAL(12,2))",
        "CREATE INDEX VM.IX_ORDERS_CUSTOMER ON VM.ORDERS(CUSTOMER_ID)",
        "CREATE VIEW VM.V_ORDERS AS SELECT O.ID, C.EMAIL, O.TOTAL FROM VM.ORDERS O JOIN VM.CUSTOMERS C ON C.ID = O.CUSTOMER_ID",
        "CREATE FUNCTION VM.F_ONE() RETURNS INTEGER LANGUAGE SQL RETURN 1",
        "@rows",
    ],
}


def seed_rows(engine: str) -> list[tuple[str, list[Any]]]:
    rows: list[tuple[str, list[Any]]] = []
    ph = {"mysql": "%s", "mssql": "?", "db2": "?"}[engine]
    tbl_c = {"mysql": "vm.customers", "mssql": "dbo.customers", "db2": "VM.CUSTOMERS"}[engine]
    tbl_o = {"mysql": "vm.orders", "mssql": "dbo.orders", "db2": "VM.ORDERS"}[engine]
    for g in range(1, 301):
        region = "north" if g % 3 == 0 else ("south" if g % 3 == 1 else None)
        rows.append((f"INSERT INTO {tbl_c} VALUES ({ph},{ph},{ph},{ph},{ph},{ph})",
                     [g, f"user{g}@example.com", region, "x" * (g % 40), "2026-01-01 00:00:00", g * 1.5]))
    for g in range(1, 601):
        rows.append((f"INSERT INTO {tbl_o} VALUES ({ph},{ph},{ph})", [g, (g % 300) + 1, g * 2.25]))
    return rows


def seed(engine: str, host: str, port: int, database: str, user: str, password: str) -> str:
    """Create the themed schema with the raw driver; idempotent enough for reruns."""
    if engine == "postgres":
        import psycopg
        with psycopg.connect(host=host, port=port, dbname=database, user=user, password=password, autocommit=True) as c:
            try:
                c.execute("DROP SCHEMA IF EXISTS vm CASCADE")
            except Exception:  # noqa: BLE001
                pass
            for stmt in SEEDS[engine]:
                c.execute(stmt)
        return "seeded"
    if engine == "mysql":
        import pymysql
        c = pymysql.connect(host=host, port=port, user=user, password=password, autocommit=True)
        cur = c.cursor()
        cur.execute("DROP DATABASE IF EXISTS vm")
        for stmt in SEEDS[engine]:
            if stmt == "@rows":
                for sql, params in seed_rows(engine):
                    cur.execute(sql, params)
            else:
                cur.execute(stmt)
        try:
            cur.execute("CREATE FUNCTION vm.f_one() RETURNS int DETERMINISTIC RETURN 1")
        except Exception as exc:  # noqa: BLE001 - binlog policy may forbid; recorded, not fatal
            return f"seeded (routine skipped: {str(exc)[:60]})"
        return "seeded"
    if engine == "clickhouse":
        import clickhouse_connect
        cl = clickhouse_connect.get_client(host=host, port=port, username=user, password=password)
        cl.command("DROP DATABASE IF EXISTS vm")
        for stmt in SEEDS[engine]:
            cl.command(stmt)
        return "seeded"
    if engine == "oracle":
        import oracledb
        opts = {}
        if os.environ.get("VM_ORACLE_THICK"):
            oracledb.init_oracle_client()
        c = oracledb.connect(user=user, password=password, dsn=f"{host}:{port}/{database}", **opts)
        cur = c.cursor()
        for obj in ("VM_V_ORDERS", "VM_F_ONE", "VM_ORDERS", "VM_CUSTOMERS"):
            kind = "VIEW" if obj.startswith("VM_V") else ("FUNCTION" if obj.startswith("VM_F") else "TABLE")
            try:
                cur.execute(f"DROP {kind} {obj}" + (" CASCADE CONSTRAINTS" if kind == "TABLE" else ""))
            except Exception:  # noqa: BLE001
                pass
        for stmt in SEEDS[engine]:
            cur.execute(stmt)
        c.commit()
        return "seeded"
    if engine == "mssql":
        import pyodbc
        cs = (f"Driver={{ODBC Driver 18 for SQL Server}};Server={host},{port};Database=master;"
              f"Uid={user};Pwd={{{password}}};Encrypt=no;TrustServerCertificate=yes")
        c = pyodbc.connect(cs, autocommit=True)
        cur = c.cursor()
        cur.execute("IF DB_ID('vm') IS NOT NULL BEGIN ALTER DATABASE vm SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE vm; END")
        for stmt in SEEDS[engine]:
            if stmt == "@usevm":
                cur.execute("USE vm")
            elif stmt == "@rows":
                for sql, params in seed_rows(engine):
                    cur.execute(sql, params)
            else:
                cur.execute(stmt)
        return "seeded"
    if engine == "db2":
        import ibm_db
        c = ibm_db.connect(f"DATABASE={database};HOSTNAME={host};PORT={port};PROTOCOL=TCPIP;UID={user};PWD={password};", "", "")
        for obj, kind in (("VM.V_ORDERS", "VIEW"), ("VM.F_ONE", "FUNCTION"), ("VM.ORDERS", "TABLE"), ("VM.CUSTOMERS", "TABLE")):
            try:
                ibm_db.exec_immediate(c, f"DROP {kind} {obj}")
            except Exception:  # noqa: BLE001
                pass
        try:
            ibm_db.exec_immediate(c, "DROP SCHEMA VM RESTRICT")
        except Exception:  # noqa: BLE001
            pass
        for stmt in SEEDS[engine]:
            if stmt == "@rows":
                for sql, params in seed_rows(engine):
                    st = ibm_db.prepare(c, sql)
                    ibm_db.execute(st, tuple(params))
            else:
                ibm_db.exec_immediate(c, stmt)
        ibm_db.commit(c)
        return "seeded"
    raise SystemExit(f"no seed for {engine}")


def main() -> int:  # noqa: PLR0915 - a linear probe
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--database", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-seed", action="store_true")
    ap.add_argument("--schema", help="schema holding the seeded tables (engine default when omitted)")
    args = ap.parse_args()
    engine = args.engine
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    record: dict[str, Any] = {"label": args.label, "engine": engine, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}

    def check(name: str, fn: Any) -> Any:
        t0 = time.monotonic()
        try:
            value = fn()
            record["checks"].append({"check": name, "status": "passed", "ms": int((time.monotonic() - t0) * 1000),
                                     "detail": (str(value)[:200] if value is not None else None)})
            return value
        except Exception as exc:  # noqa: BLE001
            record["checks"].append({"check": name, "status": "failed", "ms": int((time.monotonic() - t0) * 1000),
                                     "detail": f"{type(exc).__name__}: {str(exc)[:300]}"})
            return None

    if not args.no_seed:
        check("seed", lambda: seed(engine, args.host, args.port, args.database, args.user, password))

    os.environ["VM_USER"] = args.user
    body: dict[str, Any] = {"type": engine, "host": args.host, "port": args.port, "database": args.database,
                            "username_env": "VM_USER", "password_file": args.password_file}
    if engine == "oracle" and os.environ.get("VM_ORACLE_THICK"):
        body["options"] = {"thick_mode": True}
    cfg = ConnectionConfig.model_validate(body)
    resolved = ResolvedConnection("vm", cfg)
    policy = EffectivePolicy.build(SecurityConfig(require_remote_tls=False, default_deny_objects=False), resolved)
    conn = registry.build_connector(resolved, policy)
    schema = args.schema or {"postgres": "vm", "mysql": "vm", "clickhouse": "vm", "oracle": args.user.upper(),
                             "mssql": "dbo", "db2": "VM"}[engine]
    t_customers = {"oracle": "VM_CUSTOMERS", "db2": "CUSTOMERS"}.get(engine, "customers")
    t_orders = {"oracle": "VM_ORDERS", "db2": "ORDERS"}.get(engine, "orders")

    health = check("health_check", lambda: conn.health_check())
    if health is not None:
        record["server_version"] = health.server_version
        record["session"] = health.session
        if not health.healthy:
            record["checks"].append({"check": "health_healthy", "status": "failed", "detail": health.detail})
            record["healthy"] = False
        else:
            record["healthy"] = True
    check("list_schemas", lambda: len(conn.list_schemas(None, None)))
    tables = check("list_tables", lambda: conn.list_tables(schema, {"table", "view"}, None)) or []
    check("list_tables_has_seed", lambda: [t.name for t in tables if t.name.lower() == t_customers.lower()][0])
    cols = check("list_columns", lambda: conn.list_columns(schema, t_customers)) or []
    check("list_columns_count", lambda: {"columns": len(cols), "expected": 6} if len(cols) == 6 else (_ for _ in ()).throw(AssertionError(f"{len(cols)} columns")))
    check("list_all_columns", lambda: len(conn.list_all_columns(schema)))
    idx = check("list_indexes", lambda: conn.list_indexes(schema, t_orders)) or []
    check("index_on_fk_visible", lambda: [i.name for i in idx if any(c.lower() == "customer_id" for c in i.columns)][0])
    check("primary_key_visible", lambda: [i.name for i in conn.list_indexes(schema, t_customers) if i.primary][0])
    check("get_foreign_keys", lambda: [k.ref_table for k in conn.get_foreign_keys(schema, t_orders)][0])
    check("list_views", lambda: [v.name for v in conn.list_views(schema)][0])
    check("list_routines", lambda: len(conn.list_routines(schema)))
    check("get_statistics", lambda: conn.get_statistics(schema, t_customers))
    q = conn.quote_identifier
    qualified = f"{q(schema)}.{q(t_customers)}"
    check("execute_query_count", lambda: conn.execute_query(QuerySpec(sql=f"SELECT COUNT(*) FROM {qualified}", max_rows=5)).rows[0][0])
    sample_sql = conn.build_sample_query(schema, t_customers, [c.name for c in cols], 200)
    check("sample_query", lambda: len(conn.execute_query(QuerySpec(sql=sample_sql, max_rows=200)).rows))
    select_list, layout = aggregate_select_list(cols, engine, conn.quote_identifier, conn.length_function())
    def _profile() -> Any:
        out = conn.execute_query(QuerySpec(sql=f"SELECT {select_list} FROM ({sample_sql}) s", max_rows=1))
        total, profiles = build_profiles(cols, engine, layout, out.rows[0])
        region = next(p for n, p in profiles.items() if n.lower() == "region")
        assert total == 200 and region.distinct == 2, (total, region.distinct)
        return {"rows": total, "region_distinct": region.distinct, "region_null_ratio": region.null_ratio}
    check("profile_aggregate", _profile)
    region_col = next((c.name for c in cols if c.name.lower() == "region"), "region")
    check("top_values", lambda: conn.execute_query(QuerySpec(sql=conn.build_top_values_query(sample_sql, region_col, 3), max_rows=3)).rows)
    email_col = next((c.name for c in cols if c.name.lower() == "email"), "email")
    where = f"LOWER({q(email_col)}) LIKE {conn.placeholder(1)}"
    check("value_search_like", lambda: conn.execute_query(QuerySpec(
        sql=conn.build_search_query(schema, t_customers, [c.name for c in cols[:3]], where, 5),
        parameters=conn.pack_parameters(["%user12%"]), max_rows=5)).rows[0])
    check("explain", lambda: conn.explain(f"SELECT * FROM {qualified}", False))
    record["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    failed = [c["check"] for c in record["checks"] if c["status"] == "failed"]
    record["summary"] = {"passed": sum(1 for c in record["checks"] if c["status"] == "passed"), "failed": failed}
    Path(args.out).write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(f"{args.label}: {record['summary']['passed']} passed, failed={failed}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(2)
