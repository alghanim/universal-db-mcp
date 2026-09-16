"""ClickHouse connector (clickhouse-connect).

Implemented against the documented HTTP-native client APIs; live behaviors
marked ``unverified`` until Gate C proves them. TLS via explicit CA. Query
settings are never sent (no relaxations of engine-side limits), and the
server-side result limit is pinned to the policy ceiling so a runaway result
cannot exhaust client memory.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from typing import Any

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    ColumnInfo,
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
    translated_driver_errors,
    truncated_column_names,
)
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception


class ClickHouseConnector(DatabaseConnector):
    engine = "clickhouse"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_query_id: str | None = None  # query_id of the executing query
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._pool_lock = threading.Lock()
        self._meta_client: Any = None  # reused metadata client (probe on checkout)

    def _session_settings(self) -> dict[str, Any]:
        prof = self.session_profile
        self._session_reset()
        settings: dict[str, Any] = {}
        if prof.enforce_read_only:
            settings["readonly"] = 1
            self._session_applied("read_only")
        if prof.statement_timeout_seconds:
            settings["max_execution_time"] = int(math.ceil(prof.statement_timeout_seconds))
            self._session_applied(f"max_execution_time={settings['max_execution_time']}s")
        return settings

    def _session_readback(self, client: Any) -> dict[str, Any]:
        try:
            row = client.query("SELECT getSetting('readonly'), getSetting('max_execution_time')").result_rows
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row[0]) < 2:
            return {}
        return {"readonly": str(row[0][0]), "max_execution_time": str(row[0][1])}

    def _shared_meta_client(self) -> Any:
        """Lock-guarded reusable metadata client with probe-on-checkout
        (spec §7 connection pooling; one client per connector)."""
        with self._pool_lock:
            if self._meta_client is not None:
                try:
                    self._meta_client.query("SELECT 1")
                    return self._meta_client
                except Exception:  # noqa: BLE001, S110 - stale client, rebuild
                    try:
                        self._meta_client.close()
                    except Exception:  # noqa: BLE001, S110
                        pass
                    self._meta_client = None
            self._meta_client = self._connect()
            return self._meta_client

    def _connect(self) -> Any:
        self._module = open_module(
            "clickhouse_connect",
            "clickhouse-connect (wheel from the bundle wheelhouse)",
        )
        cfg = self.connection.config
        kw: dict[str, Any] = {
            "host": cfg.host,
            "port": cfg.port or (8443 if cfg.tls.enabled else 8123),
            "database": cfg.database,
            "connect_timeout": int(cfg.connect_timeout_seconds),
            # Bound the server-side response to the policy ceiling: legal
            # requests are clamped to hard_max_rows before reaching here, so
            # this never truncates a permitted query but does stop a runaway
            # result from exhausting client memory.
            "query_limit": self.policy.hard_max_rows,
            # Session safety profile, applied to EVERY request this client
            # sends: readonly=1 makes the server refuse writes and any
            # SETTINGS override inside agent SQL; max_execution_time is the
            # policy ceiling server-side. client_name is what shows up in
            # system.query_log / system.processes.
            "client_name": self.session_profile.application_name,
            "settings": self._session_settings(),
        }
        if self.connection.username:
            kw["username"] = self.connection.username.value
        if self.connection.password:
            kw["password"] = self.connection.password.value
        if cfg.tls.enabled:
            kw["secure"] = True
            kw["verify"] = bool(cfg.tls.verify_server)
            kw["ca_cert"] = cfg.tls.ca_file
            if cfg.tls.client_cert_file:
                kw["client_cert"] = cfg.tls.client_cert_file
                if self.connection.password:
                    # clickhouse-connect skips Basic auth entirely when a client
                    # certificate is present and tls_mode is unset (mutual-TLS
                    # branch), so a configured password would never be sent.
                    # Asking for 'strict' keeps the certificate for transport
                    # and still sends the credentials.
                    kw["tls_mode"] = "strict"
            if cfg.tls.client_key_file:
                kw["client_cert_key"] = cfg.tls.client_key_file
        return self._module.get_client(**kw)

    def cancel_current(self) -> bool:
        """Best-effort server-side cancel via ``KILL QUERY`` on a separate
        short-lived client.

        clickhouse-connect 1.8.0 exposes no client-side handle (and no
        ``cancel_query`` method) for an in-flight HTTP request, so ``_execute``
        pins a generated ``query_id`` on the executing client and the deadline
        hook kills that exact query out of band. Returns False — cancelling
        nothing — when no query is executing or the KILL itself fails; it
        never guesses.
        """
        qid = self._cancel_query_id
        if qid is None:
            return False
        try:
            killer = self._connect()
        except Exception:  # noqa: BLE001 - cancel must never raise
            return False
        try:
            killer.command("KILL QUERY WHERE query_id = %(qid)s", parameters={"qid": qid})
            return True
        except Exception:  # noqa: BLE001 - best effort; the executor still discards
            return False
        finally:
            try:
                killer.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="clickhouse",
            engine_family="clickhouse",
            driver="clickhouse-connect",
            capabilities={
                Cap.CONNECT: CapabilityState.UNVERIFIED,
                Cap.HEALTH: CapabilityState.UNVERIFIED,
                Cap.LIST_SCHEMAS: CapabilityState.UNVERIFIED,
                Cap.LIST_TABLES: CapabilityState.UNVERIFIED,
                Cap.GET_TABLE: CapabilityState.UNVERIFIED,
                Cap.LIST_COLUMNS: CapabilityState.UNVERIFIED,
                Cap.LIST_VIEWS: CapabilityState.UNVERIFIED,
                Cap.LIST_SYNONYMS: CapabilityState.UNSUPPORTED,
                Cap.LIST_ROUTINES: CapabilityState.UNSUPPORTED,
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
                    scope="metadata",
                    detail="ClickHouse dictionaries/projections are not surfaced in v1.",
                ),
                Limitation(
                    scope="column_types",
                    detail="Column type labels are derived from the first returned row "
                    "when the driver does not expose per-column types on streaming "
                    "results; treat them as hints, not guarantees.",
                ),
            ],
            required_privileges=["SELECT on permitted databases/tables (read-only profile)"],
            unverified_items=[
                "KILL QUERY cancellation by query_id over native transport",
                "TLS verify with internal CA",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            client = self._connect()
            row = client.query("SELECT version()").result_rows
            session = self.session_report(self._session_readback(client))
            return HealthInfo(
                healthy=True,
                server_version=str(row[0][0]) if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT name FROM system.databases"
        params: dict[str, Any] = {}
        if search:
            sql += " WHERE name ILIKE %(s)s"
            params["s"] = f"%{search}%"
        sql += " ORDER BY name"
        with translated_driver_errors():
            client = self._shared_meta_client()
            return [r[0] for r in client.query(sql, parameters=params).result_rows]

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        conds = ["database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema')"]
        params: dict[str, Any] = {}
        if schema:
            conds.append("database = %(db)s")
            params["db"] = schema
        if search:
            conds.append("name ILIKE %(s)s")
            params["s"] = f"%{search}%"
        sql = (
            "SELECT database, name, engine, total_rows FROM system.tables WHERE "
            + " AND ".join(conds)
            + " ORDER BY database, name"
        )
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(sql, parameters=params).result_rows
        out = []
        for db, name, eng, total in rows:
            kind = "view" if str(eng).lower().startswith("view") else "table"
            if kind not in kinds:
                continue
            out.append(
                TableSummary(
                    schema=db,
                    name=name,
                    kind=kind,
                    row_estimate=int(total) if total is not None else None,
                    row_estimate_source="catalog_estimate(system.tables.total_rows)" if total is not None else None,
                )
            )
        return out

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT name, type, is_in_primary_key, comment "
                "FROM system.columns WHERE database = %(db)s AND table = %(t)s "
                "ORDER BY position",
                parameters={"db": schema or self.connection.config.database, "t": table},
            ).result_rows
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=r[1],
                # ClickHouse marks nullable columns as Nullable(T) (and
                # Nullable(Nothing) for the untyped NULL); everything else is
                # NOT NULL. The previous negation reported exactly the inverse.
                nullable=str(r[1]).startswith("Nullable("),
                comment=r[3] or None,
                ordinal=i,
            )
            for i, r in enumerate(rows)
        ]

    def length_function(self) -> str:
        return "length"

    def placeholder(self, index: int) -> str:
        return f"%(p{index})s"

    def pack_parameters(self, values: list[Any]) -> Any:
        return {f"p{i}": v for i, v in enumerate(values, start=1)}

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        db = schema or self.connection.config.database
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT table, name, type, comment, position FROM system.columns "
                "WHERE database = %(db)s ORDER BY table, position",
                parameters={"db": db},
            ).result_rows
        return [
            ColumnInfo(schema=db, table=r[0], name=r[1], data_type=r[2],
                       nullable=str(r[2]).startswith("Nullable("), comment=r[3] or None, ordinal=int(r[4]))
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        """ClickHouse has no secondary B-tree indexes: the MergeTree sorting
        key is what the engine reads by (reported as the primary key), and
        data-skipping indices are the rest."""
        db = schema or self.connection.config.database
        out: list[IndexInfo] = []
        with translated_driver_errors():
            client = self._shared_meta_client()
            sql = "SELECT name, sorting_key, primary_key, engine FROM system.tables WHERE database = %(db)s"
            params: dict[str, Any] = {"db": db}
            if table:
                sql += " AND name = %(t)s"
                params["t"] = table
            for tname, sorting, primary, engine in client.query(sql, parameters=params).result_rows:
                key = primary or sorting
                if key:
                    out.append(IndexInfo(name="(sorting key)", columns=[c.strip() for c in str(key).split(",")],
                                         unique=False, primary=True, kind="sorting_key",
                                         definition=f"{engine} ORDER BY ({sorting})", schema=db, table=tname))
            sql = (
                "SELECT table, name, type, expr, granularity FROM system.data_skipping_indices "
                "WHERE database = %(db)s"
            )
            if table:
                sql += " AND table = %(t)s"
            for tname, iname, itype, expr, gran in client.query(sql, parameters=params).result_rows:
                out.append(IndexInfo(name=iname, columns=[str(expr)], unique=False, primary=False,
                                     kind=f"skipping:{itype}", definition=f"GRANULARITY {gran}",
                                     schema=db, table=tname))
        return out

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        tables = self.list_tables(schema, {"view"}, None)
        return [ViewInfo(schema=t.schema, name=t.name, kind="view", definition_state="not_supported") for t in tables]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        return []

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        return []  # user-defined functions exist but are not surfaced in v1

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        return []  # ClickHouse does not enforce FKs; report empty, not guessed

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        with translated_driver_errors():
            client = self._shared_meta_client()
            rows = client.query(
                "SELECT total_rows, formatReadableSize(total_bytes) FROM system.tables "
                "WHERE database = %(db)s AND name = %(t)s",
                parameters={"db": schema or "", "t": table},
            ).result_rows
        if not rows:
            return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(rows[0][0]) if rows[0][0] is not None else None,
            "row_estimate_source": "catalog_estimate(system.tables)",
            "total_bytes": rows[0][1],
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        with translated_driver_errors():
            client = self._connect()
            # Pin a per-query query_id on the executing client:
            # clickhouse-connect shares this params dict by reference into
            # every HTTP request, and _execute runs one query per dedicated
            # client under _exec_lock, so cancel_current() can KILL exactly
            # this query. If the driver surface ever changes, cancellation
            # becomes unavailable — reported truthfully as False — rather
            # than guessed.
            qid = str(uuid.uuid4())
            try:
                client.params["query_id"] = qid
            except AttributeError:
                qid = None  # type: ignore[assignment]
                self._cancel_query_id = None
            else:
                self._cancel_query_id = qid
            start = time.monotonic()
            truncated = False
            truncation_cause = "row limit"
            cell_truncated_cols: list[str] = []
            rows: list[list[Any]] = []
            approx_bytes = 0
            import json

            try:
                result = client.query(spec.sql, parameters=spec.parameters or None)
                cols = [(n, "unknown") for n in result.column_names]
                labels: list[str] = []
                for raw in result.result_rows:
                    vals, lab, cell_tr = cell_truncated_json(raw, spec.max_cell_bytes)
                    if not labels:
                        labels = lab
                    if cell_tr:
                        cell_truncated_cols.extend(truncated_column_names(cols, raw, spec.max_cell_bytes))
                    approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                    if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                        truncated = True
                        truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                        break
                    rows.append(vals)
                warnings = [f"result truncated by {truncation_cause}"] if truncated else []
                if cell_truncated_cols:
                    truncated = True
                    warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
                return QueryOutcome(
                    columns=[(c[0], t) for c, t in zip(cols, labels or ["unknown"] * len(cols), strict=True)],
                    rows=rows,
                    truncated=truncated,
                    rows_seen=len(rows),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                    warnings=warnings,
                )
            finally:
                self._cancel_query_id = None
                client.close()

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        if analyze:
            raise NotImplementedError("EXPLAIN ANALYZE is policy-disabled")
        with translated_driver_errors():
            client = self._connect()
            try:
                return {"raw": client.query("EXPLAIN " + sql).result_rows}  # noqa: S608 - validated upstream
            finally:
                client.close()
