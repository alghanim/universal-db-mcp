"""Oracle connector — python-oracledb Thin mode ONLY.

Thin mode needs no Oracle Client libraries. Thick mode is deliberately not
implemented in this build: no silent mode switching, no Instant Client
download (spec §5). TLS is enforced via an explicit TCPS connect descriptor
plus an administrator-supplied wallet (refusing plaintext fallback). Wallets
and TNS must be provided by the administrator outside distributable
artifacts. Live behaviors are ``unverified`` until Gate C.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    ColumnInfo,
    ConnectorError,
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
from universal_db_mcp.connectors.driver_helpers import cell_truncated_json, open_module
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception


class OracleConnector(DatabaseConnector):
    engine = "oracle"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_target: Any = None
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (probe on checkout)
        if connection.config.options.get("thick_mode"):
            raise ValueError(
                "oracle thick_mode is not supported in this build; use Thin mode "
                "or run a separately reviewed deployment for the Instant Client"
            )

    def _shared_meta_conn(self) -> Any:
        """Lock-guarded reusable metadata connection with probe-on-checkout
        (spec §7 connection pooling; one connection per connector)."""
        with self._pool_lock:
            if self._meta_conn is not None:
                try:
                    with self._meta_conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM DUAL")
                    return self._meta_conn
                except Exception:  # noqa: BLE001, S110 - stale connection, rebuild
                    try:
                        self._meta_conn.close()
                    except Exception:  # noqa: BLE001, S110
                        pass
                    self._meta_conn = None
            self._meta_conn = self._connect()
            return self._meta_conn

    def _connect(self) -> Any:
        self._module = open_module("oracledb", "oracledb (manylinux cp312 wheel; Thin mode)")
        cfg = self.connection.config
        if cfg.tls.enabled:
            # TCPS must be selected by the connect descriptor itself; setting
            # wallet parameters alone leaves the wire protocol as plaintext.
            wallet = cfg.options.get("wallet_location")
            if not wallet:
                raise ConnectorError(
                    "oracle tls.enabled=true requires options.wallet_location "
                    "(administrator-supplied, outside distributable artifacts); "
                    "refusing a plaintext connection"
                )
            dsn = (
                f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST={cfg.host})"
                f"(PORT={cfg.port or 1521}))(CONNECT_DATA=(SERVICE_NAME={cfg.database})))"
            )
        else:
            dsn = f"{cfg.host}:{cfg.port or 1521}/{cfg.database}"  # service_name form
        kw: dict[str, Any] = {
            "user": (self.connection.username.value if self.connection.username else None),
            "password": (self.connection.password.value if self.connection.password else None),
            "dsn": dsn,
        }
        if cfg.tls.enabled:
            kw["wallet_location"] = cfg.options.get("wallet_location")
            if cfg.options.get("tns_admin"):
                kw["config_dir"] = cfg.options.get("tns_admin")
        return self._module.connect(**kw)

    def cancel_current(self) -> bool:
        target = self._cancel_target
        if target is not None:
            try:
                target.cancel()  # oracledb: issues OCI break; Thin-supported
                return True
            except Exception:  # noqa: BLE001, S110
                return False
        return False

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="oracle",
            engine_family="oracle",
            driver="python-oracledb (Thin mode only)",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNVERIFIED,
                Cap.LIST_ROUTINES: CapabilityState.UNVERIFIED,
                Cap.RELATIONSHIPS: CapabilityState.UNVERIFIED,
                Cap.STATISTICS: CapabilityState.UNVERIFIED,
                Cap.QUERY: CapabilityState.UNVERIFIED,
                Cap.PARAMETERS: CapabilityState.UNVERIFIED,
                Cap.CANCEL: CapabilityState.UNVERIFIED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNVERIFIED,
                Cap.EXPLAIN: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(
                    scope="explain",
                    detail="EXPLAIN PLAN writes to a plan table and requires "
                    "administrator-provisioned explain tables; disabled in v1 "
                    "(never auto-created with the read-only identity).",
                ),
                Limitation(
                    scope="modes",
                    detail="Thick mode is not implemented; no Instant Client is bundled or fetched.",
                ),
            ],
            required_privileges=[
                "CREATE SESSION",
                "SELECT on permitted tables/views (or role-granted read access)",
                "object visibility via ALL_* catalog views for permitted schemas",
            ],
            unverified_items=["TCPS/wallet connectivity", "cancel behavior in Thin mode"],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT banner FROM v$version WHERE rownum = 1")
                    row = cur.fetchone()
            finally:
                conn.close()
            return HealthInfo(
                healthy=True,
                server_version=str(row[0])[:60] if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT username FROM all_users"
        params: list[Any] = []
        if search:
            sql += " WHERE username LIKE :1"
            params.append(f"%{search}%")
        sql += " ORDER BY username"
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [r[0] for r in cur.fetchall()]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        params: list[Any] = []
        arms: list[str] = []
        if "table" in kinds:
            arm = "SELECT owner, table_name, 'TABLE' FROM all_tables WHERE 1=1"
            if schema:
                arm += " AND owner = :1"
                params.append(schema)
            if search:
                arm += " AND table_name LIKE :2"
                params.append(f"%{search}%")
            arms.append(arm)
        if "view" in kinds:
            arm = "SELECT owner, view_name, 'VIEW' FROM all_views WHERE 1=1"
            if schema:
                arm += " AND owner = :1"
                params.append(schema)
            if search:
                arm += " AND view_name LIKE :2"
                params.append(f"%{search}%")
            arms.append(arm)
        if not arms:
            return []
        sql = " UNION ALL ".join(arms) + " ORDER BY 1, 2"
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [TableSummary(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        sql = (
            "SELECT column_name, data_type, nullable, data_default, column_id "
            "FROM all_tab_columns WHERE owner = :1 AND table_name = :2 ORDER BY column_id"
        )
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, [schema, table])
            rows = cur.fetchall()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=r[1],
                nullable=r[2] == "Y",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = "SELECT owner, view_name, text FROM all_views"
        params: list[Any] = []
        if schema:
            sql += " WHERE owner = :1"
            params.append(schema)
        sql += " ORDER BY 1, 2"
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [ViewInfo(schema=r[0], name=r[1], kind="view", definition_state="unavailable") for r in rows]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        sql = "SELECT owner, synonym_name, table_owner, table_name, db_link FROM all_synonyms"
        params: list[Any] = []
        if schema:
            sql += " WHERE owner = :1"
            params.append(schema)
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [
            SynonymInfo(
                schema=r[0],
                name=r[1],
                target_schema=r[2],
                target_name=r[3],
                target_kind="remote" if r[4] else "table",
            )
            for r in rows
        ]

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = "SELECT owner, object_name, object_type FROM all_objects WHERE object_type IN ('PROCEDURE','FUNCTION')"
        params: list[Any] = []
        if schema:
            sql += " AND owner = :1"
            params.append(schema)
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        sql = (
            "SELECT a.constraint_name, a.owner, a.table_name, a.r_owner, "
            "b.table_name FROM all_constraints a JOIN all_constraints b "
            "ON a.r_constraint_name = b.constraint_name AND a.r_owner = b.owner "
            "WHERE a.constraint_type = 'R'"
        )
        params: list[Any] = []
        if schema:
            sql += " AND a.owner = :1"
            params.append(schema)
        if table:
            sql += " AND a.table_name = :2"
            params.append(table)
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [
            KeyInfo(
                kind="foreign_key",
                name=r[0],
                columns=[],
                ref_schema=r[3],
                ref_table=r[4],
                source_schema=r[1],
                source_table=r[2],
            )
            for r in rows
        ]

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        sql = "SELECT num_rows, last_analyzed FROM all_tables WHERE owner = :1 AND table_name = :2"
        conn = self._shared_meta_conn()
        with conn.cursor() as cur:
            cur.execute(sql, [schema, table])
            row = cur.fetchone()
        if not row:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row[0] is not None else None,
            "row_estimate_source": "catalog_estimate(all_tables.num_rows)",
            "last_analyzed": str(row[1]) if row[1] else None,
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        conn = self._connect()
        self._cancel_target = conn
        start = time.monotonic()
        truncated = False
        truncation_cause = "row limit"
        rows: list[list[Any]] = []
        approx_bytes = 0
        import json

        try:
            with conn.cursor() as cur:
                cur.execute(spec.sql, spec.parameters or None)
                cols = [(d[0], "unknown") for d in cur.description or []]
                # oracledb description[1] is a Python type object; use its name
                # (driver-derived, not data-derived).
                col_labels = [
                    getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                    for d in (cur.description or [])
                ]
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
                            conn.cancel()  # stop server-side work
                            break
                        rows.append(vals)
                    if truncated:
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
            self._cancel_target = None
            conn.close()

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        raise NotImplementedError("Oracle EXPLAIN PLAN requires a provisioned plan table and is disabled in this build")

    def build_sample_query(self, schema: str | None, table: str, columns: list[str] | None, limit: int) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in columns) if columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} FETCH FIRST {int(limit)} ROWS ONLY"
