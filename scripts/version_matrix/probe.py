#!/usr/bin/env python3
"""Version-matrix probe: exercise the connector's metadata, query and
discovery subset against ONE server and emit a JSON record of what passed,
failed or was skipped. Not probed: capabilities(), get_table(),
list_synonyms(), list_catalogs(), cancel, explain(analyze), pagination,
masking, the SQL guard (the probe bypasses default-deny to reach its own
seed), TLS, and the session fail-closed path.

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
        "CREATE UNIQUE INDEX ux_customers_region_email ON vm.customers(region, email)",
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
        "CREATE UNIQUE INDEX ux_customers_region_email ON vm.customers(region, email)",
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
        # an ordinary schema: SYSTEM is Oracle-maintained, which the connector
        # leaves out of its listings by design (the login stays SYSTEM)
        "CREATE USER vm IDENTIFIED BY \"VmSeed_1x\" DEFAULT TABLESPACE users QUOTA UNLIMITED ON users",
        "CREATE TABLE vm.vm_customers (id NUMBER(10) PRIMARY KEY, email VARCHAR2(200), region VARCHAR2(50), note CLOB, created TIMESTAMP, balance NUMBER(12,2))",
        "CREATE TABLE vm.vm_orders (id NUMBER(10) PRIMARY KEY, customer_id NUMBER(10) REFERENCES vm.vm_customers(id), total NUMBER(12,2))",
        "CREATE INDEX vm.ix_orders_customer ON vm.vm_orders(customer_id)",
        "CREATE UNIQUE INDEX vm.ux_customers_region_email ON vm.vm_customers(region, email)",
        "CREATE VIEW vm.vm_v_orders AS SELECT o.id, c.email, o.total FROM vm.vm_orders o JOIN vm.vm_customers c ON c.id = o.customer_id",
        "CREATE FUNCTION vm.vm_f_one RETURN NUMBER IS BEGIN RETURN 1; END;",
        "INSERT INTO vm.vm_customers SELECT level, 'user' || level || '@example.com', CASE WHEN MOD(level,3)=0 THEN 'north' WHEN MOD(level,3)=1 THEN 'south' ELSE NULL END, RPAD('x', MOD(level,40)+1, 'x'), SYSTIMESTAMP, level * 1.5 FROM dual CONNECT BY level <= 300",
        "INSERT INTO vm.vm_orders SELECT level, MOD(level,300)+1, level * 2.25 FROM dual CONNECT BY level <= 600",
        "COMMIT",
    ],
    "mssql": [
        "IF DB_ID('vm') IS NULL CREATE DATABASE vm",
        "@usevm",
        "CREATE TABLE dbo.customers (id int PRIMARY KEY, email nvarchar(200), region nvarchar(50), note nvarchar(max), created datetime2, balance decimal(12,2))",
        "CREATE TABLE dbo.orders (id int PRIMARY KEY, customer_id int REFERENCES dbo.customers(id), total decimal(12,2))",
        "CREATE INDEX ix_orders_customer ON dbo.orders(customer_id)",
        "CREATE UNIQUE INDEX ux_customers_region_email ON dbo.customers(region, email)",
        "CREATE VIEW dbo.v_orders AS SELECT o.id, c.email, o.total FROM dbo.orders o JOIN dbo.customers c ON c.id = o.customer_id",
        "CREATE FUNCTION dbo.f_one() RETURNS int AS BEGIN RETURN 1 END",
        "@rows",
    ],
    "db2": [
        "CREATE SCHEMA VM",
        "CALL SYSPROC.SYSINSTALLOBJECTS('EXPLAIN', 'C', CAST(NULL AS VARCHAR(128)), CAST(NULL AS VARCHAR(128)))",
        "CREATE TABLE VM.CUSTOMERS (ID INTEGER NOT NULL PRIMARY KEY, EMAIL VARCHAR(200), REGION VARCHAR(50), NOTE CLOB(1M), CREATED TIMESTAMP, BALANCE DECIMAL(12,2))",
        "CREATE TABLE VM.ORDERS (ID INTEGER NOT NULL PRIMARY KEY, CUSTOMER_ID INTEGER REFERENCES VM.CUSTOMERS(ID), TOTAL DECIMAL(12,2))",
        "CREATE INDEX VM.IX_ORDERS_CUSTOMER ON VM.ORDERS(CUSTOMER_ID)",
        "CREATE UNIQUE INDEX VM.UX_CUSTOMERS_REGION_EMAIL ON VM.CUSTOMERS(REGION, EMAIL)",
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
    # Inside the no-network probe containers (SQL Server, thick Oracle) there
    # is no git checkout: the runner passes the revision it mounted instead.
    probe_rev = os.environ.get("VM_PROBE_REV", "").strip()
    if not probe_rev:
        try:
            import subprocess
            probe_rev = subprocess.run(  # noqa: S603, S607 - staging-only evidence stamp
                ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False
            ).stdout.strip() or "unknown"
        except Exception:  # noqa: BLE001
            probe_rev = "unknown"
    record: dict[str, Any] = {"label": args.label, "engine": engine, "probe_rev": probe_rev,
                              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}

    def check(name: str, fn: Any) -> Any:
        t0 = time.monotonic()
        try:
            value = fn()
            record["checks"].append({"check": name, "status": "passed", "ms": int((time.monotonic() - t0) * 1000),
                                     "detail": (str(value)[:200] if value is not None else None)})
            return value
        except NotImplementedError as exc:
            # a capability the connector declares unsupported on this engine
            # (ClickHouse foreign keys, Db2 explain without provisioned explain
            # tables): not a compatibility failure
            record["checks"].append({"check": name, "status": "skipped", "ms": int((time.monotonic() - t0) * 1000),
                                     "detail": f"unsupported by design: {str(exc)[:160]}"})
            return None
        except Exception as exc:  # noqa: BLE001
            record["checks"].append({"check": name, "status": "failed", "ms": int((time.monotonic() - t0) * 1000),
                                     "detail": f"{type(exc).__name__}: {str(exc)[:300]}"})
            return None

    if not args.no_seed:
        # Some images report ready a little before their admin password is
        # usable (seen on gvenzl/oracle-xe:21 as ORA-01017 while the very
        # next connection succeeded): retry the seed for up to 90 s.
        def _seed_with_retry() -> str:
            last: Exception | None = None
            for _ in range(9):
                try:
                    return seed(engine, args.host, args.port, args.database, args.user, password)
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    time.sleep(10)
            assert last is not None
            raise last

        check("seed", _seed_with_retry)

    os.environ["VM_USER"] = args.user
    body: dict[str, Any] = {"type": engine, "host": args.host, "port": args.port, "database": args.database,
                            "username_env": "VM_USER", "password_file": args.password_file}
    if engine == "oracle" and os.environ.get("VM_ORACLE_THICK"):
        body["options"] = {"thick_mode": True}
    cfg = ConnectionConfig.model_validate(body)
    resolved = ResolvedConnection("vm", cfg)
    policy = EffectivePolicy.build(SecurityConfig(require_remote_tls=False, default_deny_objects=False), resolved)
    conn = registry.build_connector(resolved, policy)
    schema = args.schema or {"postgres": "vm", "mysql": "vm", "clickhouse": "vm", "oracle": "VM",
                             "mssql": "dbo", "db2": "VM"}[engine]
    t_customers = {"oracle": "VM_CUSTOMERS", "db2": "CUSTOMERS"}.get(engine, "customers")
    t_orders = {"oracle": "VM_ORDERS", "db2": "ORDERS"}.get(engine, "orders")

    def _health() -> Any:
        h = conn.health_check()
        record["server_version"] = h.server_version
        record["session"] = h.session
        if not h.healthy:
            raise AssertionError(f"unhealthy: {h.detail}")
        return h.server_version

    record["healthy"] = check("health_check", _health) is not None
    check("list_schemas", lambda: [x for x in conn.list_schemas(None, None) if x.lower() == schema.lower()][0])
    tables = check("list_tables", lambda: conn.list_tables(schema, {"table", "view"}, None)) or []
    check("list_tables_has_seed", lambda: [t.name for t in tables if t.name.lower() == t_customers.lower()][0])
    cols = check("list_columns", lambda: conn.list_columns(schema, t_customers)) or []
    check("list_columns_count", lambda: {"columns": len(cols), "expected": 6} if len(cols) == 6 else (_ for _ in ()).throw(AssertionError(f"{len(cols)} columns")))
    def _bulk() -> int:
        n = len([c for c in conn.list_all_columns(schema) if c.table.lower() in (t_customers.lower(), t_orders.lower())])
        assert n == 9, f"{n} columns across the two seeded tables, expected 9"
        return n
    check("list_all_columns", _bulk)
    idx = check("list_indexes", lambda: conn.list_indexes(schema, t_orders)) or []
    check("index_on_fk_visible", lambda: [i.name for i in idx if any(c.lower() == "customer_id" for c in i.columns)][0])
    cidx = conn.list_indexes(schema, t_customers) if engine != "clickhouse" else []
    check("primary_key_visible", lambda: [i.name for i in conn.list_indexes(schema, t_customers) if i.primary][0])
    if engine == "clickhouse":
        record["checks"].append({"check": "composite_unique_index", "status": "skipped", "ms": 0,
                                 "detail": "ClickHouse has no unique indexes"})
    else:
        check("composite_unique_index", lambda: [i.name for i in cidx if i.unique and not i.primary
                                                  and [c.lower() for c in i.columns] == ["region", "email"]][0])
    if engine == "clickhouse":
        record["checks"].append({"check": "get_foreign_keys", "status": "skipped", "ms": 0,
                                 "detail": "ClickHouse has no foreign keys; the connector reports none"})
    else:
        check("get_foreign_keys", lambda: [k.ref_table for k in conn.get_foreign_keys(schema, t_orders)][0])
    check("list_views", lambda: [v.name for v in conn.list_views(schema) if "orders" in v.name.lower()][0])
    seed_note = next((c["detail"] for c in record["checks"] if c["check"] == "seed"), "") or ""
    if engine == "clickhouse" or "routine skipped" in seed_note:
        record["checks"].append({"check": "list_routines", "status": "skipped", "ms": 0,
                                 "detail": "no routine seeded on this engine/version"})
    else:
        check("list_routines", lambda: [r.name for r in conn.list_routines(schema) if "one" in r.name.lower()][0])
    check("get_statistics", lambda: conn.get_statistics(schema, t_customers)["row_estimate_source"])
    q = conn.quote_identifier
    qualified = f"{q(schema)}.{q(t_customers)}"
    def _count() -> int:
        n = int(conn.execute_query(QuerySpec(sql=f"SELECT COUNT(*) FROM {qualified}", max_rows=5)).rows[0][0])  # noqa: S608
        assert n == 300, f"COUNT(*) = {n}, expected 300"
        return n
    check("execute_query_count", _count)
    sample_sql = conn.build_sample_query(schema, t_customers, [c.name for c in cols], 200)
    def _sample() -> int:
        n = len(conn.execute_query(QuerySpec(sql=sample_sql, max_rows=200)).rows)
        assert n == 200, f"sample returned {n} rows, expected 200"
        return n
    check("sample_query", _sample)
    select_list, layout = aggregate_select_list(
        cols, engine, conn.quote_identifier, conn.length_expression, conn.substring_expression
    )
    def _profile() -> Any:
        out = conn.execute_query(QuerySpec(sql=f"SELECT {select_list} FROM ({sample_sql}) s", max_rows=1))
        total, profiles = build_profiles(cols, engine, layout, out.rows[0])
        region = next(p for n, p in profiles.items() if n.lower() == "region")
        assert total == 200 and region.distinct == 2, (total, region.distinct)
        return {"rows": total, "region_distinct": region.distinct, "region_null_ratio": region.null_ratio}
    check("profile_aggregate", _profile)
    region_col = next((c.name for c in cols if c.name.lower() == "region"), "region")
    def _top() -> Any:
        rows = conn.execute_query(QuerySpec(sql=conn.build_top_values_query(sample_sql, region_col, 3), max_rows=3)).rows
        values = {str(r[0]) for r in rows}
        # an unordered TOP/LIMIT sample is allocation-order on SQL Server heaps
        # (2017/2019 returned only one region from a 200-row sample), so assert
        # membership and shape, not the exact pair
        assert rows and values <= {"north", "south"} and all(int(r[1]) > 0 for r in rows), rows
        return rows
    check("top_values", _top)
    email_col = next((c.name for c in cols if c.name.lower() == "email"), "email")
    where = f"LOWER({q(email_col)}) LIKE {conn.placeholder(1)}"
    check("value_search_like", lambda: conn.execute_query(QuerySpec(
        sql=conn.build_search_query(schema, t_customers, [c.name for c in cols[:3]], where, 5),
        parameters=conn.pack_parameters(["%user12%"]), max_rows=5)).rows[0])
    def _explain() -> Any:
        plan = conn.explain(f"SELECT * FROM {qualified}", False)  # noqa: S608
        assert isinstance(plan, dict) and plan, "explain returned no plan"
        return list(plan)[:3]
    check("explain", _explain)
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
