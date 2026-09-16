"""PostgreSQL connector (psycopg 3, binary wheel).

Integration status: implemented against psycopg 3 documented APIs; marked
``unverified`` in capabilities until a real instance proves each item (Gate
C). TLS uses the explicit CA file; verification is never disabled.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    ColumnInfo,
    ConnectorError,
    DatabaseConnector,
    HealthInfo,
    IndexInfo,
    KeyInfo,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    TableSummary,
    ViewInfo,
)
from universal_db_mcp.connectors.driver_helpers import (
    cell_truncated_json,
    cell_truncation_warning,
    open_module,
    truncated_column_names,
)
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception
from universal_db_mcp.security.sql_guard import translate_paramstyle


def _pg_type(data_type: Any, char_len: Any, precision: Any, scale: Any) -> str:
    """information_schema.data_type with the declared length/precision folded
    back in ("character varying(200)", "numeric(12,2)"), so the profiler's
    oversized_string / integer_range findings have something to compare."""
    base = str(data_type or "")
    low = base.lower()
    if low in ("character varying", "character", "varchar", "char", "bpchar", "bit", "bit varying") and char_len:
        return f"{base}({int(char_len)})"
    if low in ("numeric", "decimal") and precision:
        return f"{base}({int(precision)},{int(scale or 0)})"
    return base


class PostgresConnector(DatabaseConnector):
    engine = "postgres"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_target: Any = None
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._exec_state_lock = threading.Lock()  # guards _exec_waiters
        self._exec_waiters = 0  # requests queued on _exec_lock, not yet executing
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (probe on checkout)

    @contextmanager
    def _shared_meta_conn(self) -> Iterator[Any]:
        """Reusable metadata connection with probe-on-checkout (spec §7
        connection pooling; bounded to one connection per connector).

        A psycopg connection must never be used as a context manager here:
        ``Connection.__exit__`` *closes* the connection, which would defeat
        pooling. The pool lock is held for the whole ``with`` block — checkout
        probe, execute and fetch — mirroring how ``_exec_lock`` serializes
        queries, so two concurrent metadata callers can never share (and one
        close) the same connection. If the block raises, the connection is
        discarded (closed and dropped, fail closed) rather than reused in an
        uncertain state; the next caller transparently reconnects.
        """
        with self._pool_lock:
            if self._meta_conn is not None:
                try:
                    self._meta_conn.execute("SELECT 1")
                except Exception:  # noqa: BLE001 - stale connection, rebuild
                    self._discard_meta_conn()
            if self._meta_conn is None:
                conn = self._connect()
                conn.autocommit = True
                self._meta_conn = conn
            try:
                yield self._meta_conn
            except BaseException:
                self._discard_meta_conn()
                raise
            finally:
                try:
                    self._meta_conn.rollback()  # release any implicit transaction state
                except Exception:  # noqa: BLE001, S110
                    pass

    def _discard_meta_conn(self) -> None:
        """Close and forget the shared metadata connection (caller holds
        ``_pool_lock``). Close errors are irrelevant: the object is dropped."""
        conn, self._meta_conn = self._meta_conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def _connect(self) -> Any:
        self._module = open_module(
            "psycopg",
            "psycopg[binary] (manylinux cp312 wheel from the bundle wheelhouse)",
        )
        cfg = self.connection.config
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or 5432,
            "dbname": cfg.database,
            "connect_timeout": int(cfg.connect_timeout_seconds),
        }
        if self.connection.username:
            kw["user"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["sslmode"] = "verify-full" if cfg.tls.verify_server else "require"
            kw["sslrootcert"] = cfg.tls.ca_file
            if cfg.tls.client_cert_file:
                kw["sslcert"] = cfg.tls.client_cert_file
            if cfg.tls.client_key_file:
                kw["sslkey"] = cfg.tls.client_key_file
        # Pass-through options for deployments libpq can reach but our schema
        # cannot describe: Kerberos/GSSAPI, service files, and an explicit
        # sslmode when TLS is deliberately off (config refuses one that could
        # weaken an enabled tls block).
        for key in ("gssencmode", "krbsrvname", "service", "passfile", "sslmode"):
            value = cfg.options.get(key)
            if value:
                kw[key] = value
        kw["application_name"] = self.session_profile.application_name
        conn = self._module.connect(**kw)
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile (see security/session.py).

        SET inside psycopg's implicit transaction would be rolled back with
        it, so the statements run with autocommit on and the previous mode is
        restored. Server-side read-only is REQUIRED when requested: it is the
        promise this profile makes. The ceilings are best-effort and recorded.
        """
        prof = self.session_profile
        self._session_reset()
        previous = getattr(conn, "autocommit", None)
        try:
            if previous is False:
                conn.autocommit = True
            if prof.enforce_read_only:
                try:
                    conn.execute("SET default_transaction_read_only = on")
                    self._session_applied("read_only")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required("read-only mode", exc) from exc
            if prof.statement_timeout_seconds:
                ms = int(math.ceil(prof.statement_timeout_seconds * 1000))
                try:
                    conn.execute(f"SET statement_timeout = '{ms}ms'")
                    self._session_applied(f"statement_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    self._session_skipped("statement_timeout", exc)
            if prof.lock_timeout_seconds is not None:
                ms = max(1, int(math.ceil(prof.lock_timeout_seconds * 1000)))  # 0 would DISABLE the ceiling
                try:
                    conn.execute(f"SET lock_timeout = '{ms}ms'")
                    self._session_applied(f"lock_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    self._session_skipped("lock_timeout", exc)
            if prof.isolation:
                level = prof.isolation.replace("_", " ")
                try:
                    conn.execute(f"SET default_transaction_isolation = '{level}'")
                    self._session_applied(f"isolation={prof.isolation}")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required(f"isolation {prof.isolation}", exc) from exc
        finally:
            if previous is False:
                conn.autocommit = previous

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            row = conn.execute(
                "SELECT current_setting('default_transaction_read_only'), "
                "current_setting('statement_timeout'), current_setting('lock_timeout'), "
                "current_setting('application_name'), current_setting('default_transaction_isolation')"
            ).fetchone()
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 5:
            return {}
        keys = ("read_only", "statement_timeout", "lock_timeout", "application_name", "isolation")
        return {k: str(v) for k, v in zip(keys, row, strict=False)}

    def cancel_current(self) -> bool:
        """Request-scoped best-effort cancel of the executing query.

        The executor's deadline hook calls this from a separate thread with no
        request identity, so the only safe discriminator is execution state:
        if another request is still queued on ``_exec_lock``, the deadline that
        fired belongs to the *queued* request, and cancelling the registered
        target would kill an unrelated in-flight query. In that case the hook
        refuses (fail closed): the cancel is lost, but the executor still
        discards the timed-out request's connection and poisons the connector.
        """
        with self._exec_state_lock:
            if self._exec_waiters > 0:
                return False
        target = self._cancel_target
        if target is not None:
            try:
                target.cancel()  # psycopg: server-side cancel via a separate path
                return True
            except Exception:  # noqa: BLE001, S110
                return False
        return False

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="postgres",
            engine_family="postgresql",
            driver="psycopg 3 (binary)",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNSUPPORTED,
                Cap.LIST_ROUTINES: CapabilityState.UNVERIFIED,
                Cap.RELATIONSHIPS: CapabilityState.UNVERIFIED,
                Cap.STATISTICS: CapabilityState.UNVERIFIED,
                Cap.QUERY: CapabilityState.UNVERIFIED,
                Cap.PARAMETERS: CapabilityState.UNVERIFIED,
                Cap.CANCEL: CapabilityState.UNVERIFIED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(scope="explain", detail="EXPLAIN ANALYZE executes and is policy-disabled."),
                Limitation(
                    scope="cancel",
                    detail="psycopg cancel() requests server-side cancellation; the "
                    "executor still discards the connection after a deadline. "
                    "Cancel is skipped while another request is queued, so a "
                    "queued request's deadline can never cancel a running query.",
                ),
            ],
            required_privileges=[
                "CONNECT on the database",
                "USAGE on allowed schemas",
                "SELECT on permitted tables/views",
                "read access to catalog views for metadata (pg_catalog)",
            ],
            unverified_items=[
                "live TLS verify-full against internal CA",
                "server-side cancel under load",
                "row estimates via pg_class.reltuples freshness",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT version()").fetchone()
                session = self.session_report(self._session_readback(conn))
            return HealthInfo(
                healthy=True,
                server_version=(row[0] if row else "")[:40],
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT schema_name FROM information_schema.schemata"
        params: list[Any] = []
        if search:
            sql += " WHERE schema_name ILIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1"
        with self._shared_meta_conn() as conn:
            return [r[0] for r in conn.execute(sql, params).fetchall()]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        types: list[str] = []
        if "table" in kinds:
            types.append("r")
        if "view" in kinds:
            types.append("v")
        if "materialized_view" in kinds:
            types.append("m")
        if "foreign_table" in kinds:
            types.append("f")
        if not types:
            return []
        sql = (
            "SELECT n.nspname, c.relname, c.relkind, "
            "CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = ANY(%s) AND n.nspname NOT IN "
            "('pg_toast','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_temp%%'"
        )
        params: list[Any] = [types]
        if schema:
            sql += " AND n.nspname = %s"
            params.append(schema)
        if search:
            sql += " AND c.relname ILIKE %s"
            params.append(f"%{search}%")
        kind_map = {"r": "table", "v": "view", "m": "materialized_view", "f": "foreign_table"}
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            TableSummary(
                schema=r[0],
                name=r[1],
                kind=kind_map.get(r[2], r[2]),
                row_estimate=int(r[3]) if r[3] else None,
                row_estimate_source="catalog_estimate(pg_class.reltuples)" if r[3] else None,
            )
            for r in rows
        ]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        schema = schema or "public"
        sql = (
            "SELECT column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s "
            "ORDER BY ordinal_position"
        )
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, (schema, table)).fetchall()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=_pg_type(r[1], r[5], r[6], r[7]),
                nullable=r[2] == "YES",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = (
            "SELECT schemaname, viewname, definition FROM pg_views"
            + (" WHERE schemaname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        params: tuple[Any, ...] = (schema,) if schema else ()
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            ViewInfo(schema=r[0], name=r[1], kind="view", definition=r[2], definition_state="available") for r in rows
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []  # PostgreSQL has no synonyms.

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = (
            "SELECT n.nspname, p.proname, CASE WHEN p.prokind = 'p' THEN 'procedure' ELSE 'function' END "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema')"
            + (" AND n.nspname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        # pg_proc.prokind is PostgreSQL 11+, while psycopg 3 supports servers
        # from 10. Without a fallback, db_list_routines is the single tool that
        # dies on an older server while everything else keeps working.
        legacy_sql = (
            "SELECT n.nspname, p.proname, CASE WHEN p.proisagg THEN 'aggregate' ELSE 'function' END "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname NOT IN ('pg_catalog','information_schema')"
            + (" AND n.nspname = %s" if schema else "")
            + " ORDER BY 1, 2"
        )
        params: tuple[Any, ...] = (schema,) if schema else ()
        with self._connect() as conn:
            try:
                rows = conn.execute(sql, params).fetchall()
            except Exception:  # noqa: BLE001 - pre-11 servers lack prokind
                rows = conn.execute(legacy_sql, params).fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2]) for r in rows]

    def text_expression(self, quoted_column: str, portable_name: str) -> str:
        return f"CAST({quoted_column} AS text)" if portable_name == "uuid" else quoted_column

    def placeholder(self, index: int) -> str:
        return "%s"

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        schema = schema or "public"
        sql = (
            "SELECT table_name, column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = %s ORDER BY table_name, ordinal_position"
        )
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, (schema,)).fetchall()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=_pg_type(r[2], r[6], r[7], r[8]),
                       nullable=r[3] == "YES", default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        schema = schema or "public"
        sql = (
            "SELECT t.relname, i.relname, ix.indisunique, ix.indisprimary, a.attname, k.ord, am.amname, "
            "pg_get_indexdef(ix.indexrelid) "
            "FROM pg_index ix JOIN pg_class t ON t.oid = ix.indrelid "
            "JOIN pg_namespace n ON n.oid = t.relnamespace "
            "JOIN pg_class i ON i.oid = ix.indexrelid JOIN pg_am am ON am.oid = i.relam "
            "CROSS JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) "
            "LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum "
            "WHERE n.nspname = %s"
        )
        params: list[Any] = [schema]
        if table:
            sql += " AND t.relname = %s"
            params.append(table)
        sql += " ORDER BY t.relname, i.relname, k.ord"
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, unique, primary, col, _ord, am, definition in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=bool(unique), primary=bool(primary),
                                 kind=str(am), definition=definition, schema=schema, table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col) if col is not None else "(expression)")
        return list(grouped.values())

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        # Query the catalog directly with the schema/table as bound parameters:
        # the previous regclass::text rendering was search_path-dependent
        # (unqualified names for search_path schemas made ref_schema collapse
        # into the table name), ignored the schema argument entirely, and never
        # populated the FK column lists.
        sql = (
            "SELECT con.conname, ns.nspname, cl.relname, rns.nspname, rcl.relname, "
            "a.attname, ra.attname, k.ord "
            "FROM pg_constraint con "
            "JOIN pg_class cl ON cl.oid = con.conrelid "
            "JOIN pg_namespace ns ON ns.oid = cl.relnamespace "
            "JOIN pg_class rcl ON rcl.oid = con.confrelid "
            "JOIN pg_namespace rns ON rns.oid = rcl.relnamespace "
            "CROSS JOIN LATERAL unnest(con.conkey, con.confkey) "
            "WITH ORDINALITY AS k(att, ratt, ord) "
            "JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attnum = k.att "
            "JOIN pg_attribute ra ON ra.attrelid = rcl.oid AND ra.attnum = k.ratt "
            "WHERE con.contype = 'f'"
        )
        params: list[Any] = []
        if schema:
            sql += " AND ns.nspname = %s"
            params.append(schema)
        if table:
            sql += " AND cl.relname = %s"
            params.append(table)
        sql += " ORDER BY con.conname, k.ord"
        with self._shared_meta_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        # Constraint names are unique per (namespace, table) only, so group by
        # the full constraint identity.
        grouped: dict[tuple[str, str, str, str, str], KeyInfo] = {}
        out: list[KeyInfo] = []
        for name, src_schema, src_table, ref_schema, ref_table, col, ref_col, _ord in rows:
            key = (str(name), str(src_schema), str(src_table), str(ref_schema), str(ref_table))
            info = grouped.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key",
                    name=name,
                    columns=[],
                    ref_schema=ref_schema,
                    ref_table=ref_table,
                    ref_columns=[],
                    source_schema=src_schema,
                    source_table=src_table,
                )
                grouped[key] = info
                out.append(info)
            info.columns.append(col)
            info.ref_columns.append(ref_col)
        return out

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        schema = schema or "public"
        with self._shared_meta_conn() as conn:
            row = conn.execute(
                "SELECT CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END, s.n_live_tup, s.last_analyze "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid "
                "WHERE n.nspname = %s AND c.relname = %s",
                (schema, table),
            ).fetchone()
        if not row:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row[0] is not None else None,
            "row_estimate_source": "catalog_estimate(pg_class.reltuples / pg_stat_user_tables)",
            "last_analyze": str(row[2]) if row[2] else None,
            "note": "estimates; freshness depends on the last ANALYZE",
        }

    # Common PostgreSQL type OIDs -> stable labels (driver-derived, not
    # data-derived).
    _PG_OID_TYPES = {
        16: "boolean",
        17: "blob",
        20: "bigint",
        21: "integer",
        23: "integer",
        25: "text",
        700: "real",
        701: "real",
        1700: "decimal",
        1082: "date",
        1083: "time",
        1114: "datetime",
        1184: "datetime",
        2950: "text",
        114: "text",
        3802: "text",
        1043: "text",
        1042: "text",
        18: "text",
    }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_state_lock:
            self._exec_waiters += 1
        try:
            self._exec_lock.acquire()
        finally:
            # The request is no longer queued once it holds the lock: from
            # here on a firing deadline belongs to THIS request, so it must
            # not suppress cancellation any more.
            with self._exec_state_lock:
                self._exec_waiters -= 1
        try:
            return self._execute(spec)
        finally:
            self._exec_lock.release()

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        start = time.monotonic()
        truncated = False
        cell_truncated_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0
        import json

        # psycopg's paramstyle is format/pyformat (%s / %(name)s); the guard
        # also admits :name markers, so rewrite those onto the driver's
        # spelling after validation. A bare '?' reaches the server untouched
        # (JSONB key-exists operator), so qmark is not translated here.
        # Raised before the ConnectorError boundary so a parameter-style
        # mismatch keeps its VALIDATION category.
        sql, parameters = spec.sql, spec.parameters
        if isinstance(parameters, dict):
            sql, parameters = translate_paramstyle(sql, parameters, backslash_escapes=False)
        try:
            conn = self._connect()
            self._cancel_target = conn
        except Exception as exc:
            raise ConnectorError(scrub_exception(exc)) from exc
        try:
            # Server-side (named) cursor: rows stream from the engine and the
            # row/byte ceilings stop the transfer early instead of after the
            # full result has been buffered client-side.
            with conn.cursor(name="udbmcp_query") as cur:
                args: Any = tuple(parameters) if isinstance(parameters, (list, tuple)) else parameters
                cur.execute(sql, args)
                cols = [(d[0], self._PG_OID_TYPES.get(d.type_code, "unknown")) for d in (cur.description or [])]
                col_labels = [c[1] for c in cols]
                while True:
                    batch = cur.fetchmany(200)
                    if not batch:
                        break
                    for raw in batch:
                        vals, labels, _ = cell_truncated_json(raw, spec.max_cell_bytes)
                        cell_truncated_cols.extend(
                            truncated_column_names(cols, raw, spec.max_cell_bytes)
                        )
                        if not col_labels:
                            col_labels = labels
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            break
                        rows.append(vals)
                    if truncated:
                        try:
                            conn.cancel()  # stop server-side work
                        except Exception:  # noqa: BLE001, S110
                            pass
                        break
            warnings: list[str] = []
            if truncated:
                warnings.append("result truncated by limits")
            if cell_truncated_cols:
                # A cell cut to the byte limit must never be reported as an
                # intact result: name the columns (live test 2026-09-11 found
                # this path reporting truncated=false after a silent cut).
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            return QueryOutcome(
                columns=[(c[0], t) for c, t in zip(cols, col_labels or ["unknown"] * len(cols), strict=True)],
                rows=rows,
                truncated=truncated or bool(cell_truncated_cols),
                rows_seen=len(rows),
                elapsed_ms=int((time.monotonic() - start) * 1000),
                warnings=warnings,
            )
        except Exception as exc:
            raise ConnectorError(scrub_exception(exc)) from exc
        finally:
            self._cancel_target = None
            try:
                conn.rollback()  # release the cursor's read transaction
            except Exception:  # noqa: BLE001, S110
                pass
            conn.close()

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError("EXPLAIN ANALYZE is policy-disabled")
        with self._connect() as conn:
            rows = conn.execute("EXPLAIN " + sql).fetchall()
        return {"raw": "\n".join(r[0] for r in rows)}
