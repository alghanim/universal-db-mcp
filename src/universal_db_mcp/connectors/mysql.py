"""MySQL / MariaDB connector (PyMySQL, pure Python).

Integration status: implemented against PyMySQL documented APIs; live
behaviors are marked ``unverified`` until Gate C proves them. TLS uses the
explicit CA file; verification is never disabled. Metadata calls reuse a
lock-guarded pooled connection (spec §7) — PyMySQL connections are not
thread-safe, so the lock is held for the *entire* use of the shared
connection, not just the checkout probe; queries run serialized on fresh
connections so cancellation/discards are well-defined.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    ColumnInfo,
    DatabaseConnector,
    HealthInfo,
    KeyInfo,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    TableSummary,
    ViewInfo,
)
from universal_db_mcp.connectors.driver_helpers import cell_truncated_json, open_module, translated_driver_errors
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception

# PyMySQL FIELD_TYPE codes -> stable column labels (driver-derived, not
# data-derived).
_MYSQL_TYPE_LABELS = {
    0: "decimal",
    1: "integer",
    2: "integer",
    3: "integer",
    4: "real",
    5: "real",
    8: "bigint",
    9: "bigint",
    10: "date",
    12: "datetime",
    13: "time",
    15: "text",
    16: "integer",
    245: "text",
    246: "decimal",
    249: "blob",
    250: "blob",
    251: "blob",
    252: "blob",
    253: "text",
    254: "text",
}


class MySQLConnector(DatabaseConnector):
    engine = "mysql"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._exec_lock = threading.Lock()  # serializes queries (no cancel hook)
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (ping on checkout)

    @contextmanager
    def _shared_meta_conn(self) -> Iterator[Any]:
        """Reusable metadata connection with ping-on-checkout (spec §7
        connection pooling; one connection per connector).

        A PyMySQL connection is a single socket with an unbuffered
        (``SSCursor``) protocol stream and is not thread-safe, so
        ``_pool_lock`` is held for the whole ``with`` block — checkout,
        cursor use and fetch — mirroring how ``_exec_lock`` serializes
        queries. If the block raises, the connection is discarded (closed and
        dropped) rather than reused with a possibly half-read result stream;
        the next caller reconnects.
        """
        with self._pool_lock:
            if self._meta_conn is not None:
                try:
                    self._meta_conn.ping(reconnect=False)
                except Exception:  # noqa: BLE001 - stale connection, rebuild
                    self._discard_meta_conn()
            if self._meta_conn is None:
                self._meta_conn = self._connect()
            try:
                yield self._meta_conn
            except BaseException:
                self._discard_meta_conn()
                raise

    def _discard_meta_conn(self) -> None:
        """Close and forget the shared metadata connection (caller holds
        ``_pool_lock``). Close errors are irrelevant: the object is dropped."""
        conn, self._meta_conn = self._meta_conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def quote_identifier(self, name: str) -> str:
        """MySQL/MariaDB identifier quoting. Double quotes are string
        literals under the default ``sql_mode`` (only ``ANSI_QUOTES`` makes
        them identifiers), so the ANSI default from the base class would turn
        ``SELECT "col" FROM "t"`` into a constant-string select or a syntax
        error. Backticks are always identifiers; an embedded backtick is
        escaped by doubling it."""
        return "`" + name.replace("`", "``") + "`"

    def _connect(self) -> Any:
        self._module = open_module("pymysql", "PyMySQL (pure-Python wheel from the bundle wheelhouse)")
        cfg = self.connection.config
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or 3306,
            "database": cfg.database,
            "connect_timeout": int(cfg.connect_timeout_seconds),
            "charset": "utf8mb4",
            "read_timeout": int(self.policy.hard_query_timeout_seconds) + 5,
            "cursorclass": self._module.cursors.SSCursor,  # streaming; bounded fetch below
            "autocommit": True,  # reads only; no transaction state to leak
        }
        if self.connection.username:
            kw["user"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["ssl"] = {
                "ca": cfg.tls.ca_file,
                "check_hostname": cfg.tls.verify_server,
            }
            if cfg.tls.client_cert_file:
                kw["ssl"]["cert"] = cfg.tls.client_cert_file
            if cfg.tls.client_key_file:
                kw["ssl"]["key"] = cfg.tls.client_key_file
        return self._module.connect(**kw)

    # PyMySQL has no safe out-of-band cancel; the executor reports this
    # truthfully and discards the connection on timeout.
    def cancel_current(self) -> bool:
        return False

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="mysql",
            engine_family="mysql/mariadb",
            driver="PyMySQL",
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
                Cap.CANCEL: CapabilityState.UNSUPPORTED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(
                    scope="cancel",
                    detail="PyMySQL exposes no out-of-band cancellation; on timeout "
                    "the connection is discarded. KILL QUERY via a second connection "
                    "is a documented future option, not implemented in v1.",
                ),
                Limitation(scope="explain", detail="EXPLAIN ANALYZE executes and is policy-disabled."),
            ],
            required_privileges=[
                "SELECT on permitted tables (read-only account)",
                "SHOW VIEW / metadata visibility on permitted schemas",
            ],
            unverified_items=["TLS with internal CA", "streaming cursor truncation behavior"],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION()")
                    row = cur.fetchone()
            finally:
                conn.close()
            ver = row[0] if row else None
            return HealthInfo(
                healthy=True,
                server_version=str(ver),
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT schema_name FROM information_schema.schemata"
        params: list[Any] = []
        if search:
            sql += " WHERE schema_name LIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                return [r[0] for r in cur.fetchall()]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        types: list[str] = []
        if "table" in kinds:
            types.append("BASE TABLE")
        if "view" in kinds:
            types.append("VIEW")
        if not types:
            return []
        sql = (
            "SELECT table_schema, table_name, table_type, table_rows "
            "FROM information_schema.tables WHERE table_type IN (" + ", ".join(["%s"] * len(types)) + ") "
            # System schemas are never permitted data: returning them would
            # turn them into resolver entries under the default config.
            "AND table_schema NOT IN ('mysql','information_schema','performance_schema','sys')"
        )
        params: list[Any] = list(types)
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        if search:
            sql += " AND table_name LIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY 1, 2"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        return [
            TableSummary(
                schema=r[0],
                name=r[1],
                kind="view" if r[2] == "VIEW" else "table",
                row_estimate=int(r[3]) if r[3] is not None else None,
                row_estimate_source="catalog_estimate(information_schema.tables.table_rows)"
                if r[3] is not None
                else None,
            )
            for r in rows
        ]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT column_name, data_type, is_nullable, column_default, ordinal_position "
            "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s "
            "ORDER BY ordinal_position"
        )
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, (schema, table))
                rows = cur.fetchall()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=r[1],
                nullable=r[2] == "YES",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = (
            "SELECT table_schema, table_name, view_definition FROM information_schema.views "
            "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')"
        )
        params: list[Any] = []
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        sql += " ORDER BY 1, 2"
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        return [
            ViewInfo(schema=r[0], name=r[1], kind="view", definition=r[2], definition_state="available") for r in rows
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []  # MySQL/MariaDB has no synonyms.

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = (
            "SELECT routine_schema, routine_name, routine_type FROM information_schema.routines "
            "WHERE routine_schema NOT IN ('mysql','information_schema','performance_schema','sys')"
        )
        params: list[Any] = []
        if schema:
            sql += " AND routine_schema = %s"
            params.append(schema)
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        sql = (
            "SELECT constraint_name, table_schema, table_name, referenced_table_name, "
            "column_name, referenced_column_name FROM information_schema.key_column_usage "
            "WHERE referenced_table_name IS NOT NULL"
        )
        params: list[Any] = []
        if schema:
            sql += " AND table_schema = %s"
            params.append(schema)
        if table:
            sql += " AND table_name = %s"
            params.append(table)
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, params or None)
                rows = cur.fetchall()
        merged: dict[str, KeyInfo] = {}
        for name, tschema, tname, rname, col, rcol in rows:
            k = merged.get(name)
            if k:
                k.columns.append(col)
                k.ref_columns.append(rcol)
            else:
                merged[name] = KeyInfo(
                    kind="foreign_key",
                    name=name,
                    columns=[col],
                    ref_schema=tschema,
                    ref_table=rname,
                    ref_columns=[rcol],
                    source_schema=tschema,
                    source_table=tname,
                )
        return list(merged.values())

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        schema = schema or self.connection.config.database or ""
        sql = (
            "SELECT table_rows, data_length, index_length, update_time "
            "FROM information_schema.tables WHERE table_schema = %s AND table_name = %s"
        )
        with translated_driver_errors():
            with self._shared_meta_conn() as conn, conn.cursor() as cur:
                cur.execute(sql, (schema, table))
                row = cur.fetchone()
        if not row:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row[0] is not None else None,
            "row_estimate_source": "catalog_estimate(information_schema; InnoDB estimates vary)",
            "data_bytes": int(row[1]) if row[1] else None,
            "index_bytes": int(row[2]) if row[2] else None,
            "last_update": str(row[3]) if row[3] else None,
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        with translated_driver_errors():
            conn = self._connect()
            start = time.monotonic()
            truncated = False
            truncation_cause = "row limit"
            rows: list[list[Any]] = []
            approx_bytes = 0
            conn_closed = False
            import json

            # Not a context manager: on truncation Cursor.close() MUST NOT run
            # against a live connection (see below), and the explicit close is
            # easier to make idempotent.
            cur = conn.cursor()
            try:
                # PyMySQL runs ``query % args`` whenever args is not None — an
                # empty tuple included — so an unparameterised statement with a
                # literal '%' (LIKE 'a%') would fail client-side. Pass None
                # when nothing is bound so the SQL is sent verbatim.
                cur.execute(spec.sql, spec.parameters or None)
                cols = [(d[0], "unknown") for d in cur.description or []]
                col_labels = [_MYSQL_TYPE_LABELS.get(d[1], "unknown") for d in (cur.description or [])]
                while True:
                    batch = cur.fetchmany(200)
                    if not batch:
                        break
                    for raw in batch:
                        vals, _labels, _ = cell_truncated_json(raw, spec.max_cell_bytes)
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                            break
                        rows.append(vals)
                    if truncated:
                        # Sever the cursor from the connection BEFORE closing:
                        # SSCursor.close() would otherwise drain the entire
                        # remaining streaming result (there is no way to stop
                        # the server sending it once the cursor stays bound),
                        # turning a bounded fetch into a full transfer. Closing
                        # the connection sends COM_QUIT without draining.
                        cur.connection = None
                        conn.close()
                        conn_closed = True
                        break
                return QueryOutcome(
                    columns=[(c[0], t) for c, t in zip(cols, col_labels or ["unknown"] * len(cols), strict=True)],
                    rows=rows,
                    truncated=truncated,
                    rows_seen=len(rows),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                    warnings=[f"result truncated by {truncation_cause}"] if truncated else [],
                )
            finally:
                try:
                    cur.close()  # no-op on the truncation path: cursor severed above
                except Exception:  # noqa: BLE001, S110
                    pass
                if not conn_closed:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001, S110
                        pass

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError("EXPLAIN ANALYZE is policy-disabled")
        with translated_driver_errors():
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("EXPLAIN " + sql)  # noqa: S608 - validated upstream
                    return {"raw": [[str(c) for c in row] for row in cur.fetchall()]}
            finally:
                conn.close()
