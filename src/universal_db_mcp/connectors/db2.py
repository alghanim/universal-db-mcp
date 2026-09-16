"""IBM Db2 connector (ibm_db manylinux wheel with bundled clidriver).

Per spec §5:
- LUW only in this build; z/OS and Db2 for i are explicitly NOT implemented
  (different catalog semantics, licensing, and native-client requirements).
- The wheel bundles clidriver; the target never fetches it and IBM_DB_HOME
  is not relied upon.
- Db2 Connect licensing for z/OS/i gateways is an administrator prerequisite
  reported by doctor, never auto-accepted.
- EXPLAIN tables are NOT auto-created with the read-only identity; explain
  stays unsupported until an administrator provisions them (policy §10).
- Package binding is an administrator step; the read-only identity never
  binds packages automatically.
"""

from __future__ import annotations

import functools
import math
import threading
import time
from collections.abc import Callable
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
    translated_driver_errors,
    truncated_column_names,
)
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception


def _meta_translated(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Metadata/catalog methods surface driver failures as ``ConnectorError``.

    ibm_db raises its own exception type for connect/SQL failures; without
    this wrapping a raw driver exception escaped the server's per-connection
    degradation in db_search_metadata and aborted the whole tool call as
    INTERNAL_ERROR instead of a per-connection warning."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with translated_driver_errors():
            return fn(*args, **kwargs)

    return wrapper


def _s(value: Any) -> Any:
    """SYSCAT identifier columns come back CHAR-padded ('MOI     '); every
    name comparison downstream (object resolution, search, quoting) needs
    the trimmed value."""
    return value.rstrip() if isinstance(value, str) else value


class Db2Connector(DatabaseConnector):
    engine = "db2"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._conn: Any = None
        self._exec_lock = threading.Lock()  # serializes queries
        if connection.config.family not in (None, "luw"):
            raise ValueError(
                f"db2 family '{connection.config.family}' is not implemented in this "
                f"build; LUW catalogs and licensing differ from z/OS and Db2 for i"
            )

    def _connect(self) -> Any:
        self._module = open_module(
            "ibm_db",
            "ibm_db (manylinux cp312 wheel with bundled clidriver)",
        )
        import ibm_db_dbi  # type: ignore[import-not-found,import-untyped,unused-ignore] # noqa: F401 - ships with ibm_db

        cfg = self.connection.config
        fields: list[tuple[str, str]] = [
            ("DATABASE", f"{cfg.database}"),
            ("HOSTNAME", f"{cfg.host}"),
            ("PORT", f"{cfg.port or 50000}"),
            ("PROTOCOL", "TCPIP"),
            # What DBAs see in LIST APPLICATIONS / MON_GET_CONNECTION.
            ("CLIENTAPPLNAME", self.session_profile.application_name),
        ]
        if self.session_profile.statement_timeout_seconds:
            # CLI-level statement ceiling, in addition to the client-side cancel.
            fields.append(("QUERYTIMEOUT", str(int(math.ceil(self.session_profile.statement_timeout_seconds)))))
        if auth := cfg.options.get("authentication"):
            # Servers that demand a specific mechanism (Kerberos, TOKEN, AES)
            # otherwise answer SQL30082N reason 17, which reads exactly like
            # the credential bug fixed in 854b50d.
            fields.append(("AUTHENTICATION", str(auth).upper()))
        if cfg.tls.enabled:
            fields.append(("SECURITY", "SSL"))
            if cfg.tls.ca_file:
                fields.append(("SSLServerCertificate", cfg.tls.ca_file))
        # Credentials MUST travel inside the connection string. For a
        # connection-string DSN, ibm_db ignores connect()'s positional
        # user/password arguments, so passing them there sends NO credentials:
        # the server answers SQL30082N reason 17 (UNSUPPORTED FUNCTION) under
        # default negotiation and reason 3 (PASSWORD MISSING) under SERVER auth.
        # Reproduced live 2026-09-15; long misdiagnosed as a server/TLS block.
        if self.connection.username:
            fields.append(("UID", self.connection.username.value))
        if self.connection.password:
            fields.append(("PWD", self.connection.password.value))
        for key, value in fields:
            # No quoting form carries ';' in a CLI connection-string value
            # (raw, braces, doubled braces and quotes were all rejected live);
            # unrefused it would split into extra connection keywords. The
            # message names the keyword only, never the value.
            if ";" in value:
                raise ConnectorError(
                    f"db2 connection value for {key} contains ';', which a Db2 CLI "
                    "connection string cannot carry in any quoting form; change that value"
                )
        dsn = "".join(f"{key}={value};" for key, value in fields)
        conn = self._module.connect(dsn, "", "")
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile.

        The isolation level is the production-safety promise on Db2: an
        ordinary SELECT at the default CS takes share locks and queues behind
        writers, so read-only connections run at UR unless configured
        otherwise, and it is REQUIRED (a refusal fails the connection rather
        than running at CS silently). The agent no longer has to remember
        WITH UR - though the clause still works. The lock ceiling is
        best-effort. Db2 has no session-wide read-only; the guard enforces it.
        """
        prof = self.session_profile
        self._session_reset()
        if prof.isolation:
            try:
                self._module.exec_immediate(conn, f"SET CURRENT ISOLATION = {prof.isolation.upper()}")
                self._session_applied(f"isolation={prof.isolation}")
            except Exception as exc:  # noqa: BLE001
                raise self._session_required(f"isolation {prof.isolation}", exc) from exc
        if prof.lock_timeout_seconds is not None:
            secs = int(math.ceil(prof.lock_timeout_seconds))
            try:
                self._module.exec_immediate(conn, f"SET CURRENT LOCK TIMEOUT = {secs}")
                self._session_applied(f"lock_timeout={secs}s")
            except Exception as exc:  # noqa: BLE001
                self._session_skipped("lock_timeout", exc)

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            stmt = self._module.exec_immediate(
                conn, "VALUES (CURRENT ISOLATION, CURRENT LOCK TIMEOUT, CURRENT CLIENT_APPLNAME)"
            )
            row = self._module.fetch_tuple(stmt)
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 3:
            return {}
        return {
            "isolation": str(row[0]).strip().lower() or "server default",
            "lock_timeout_seconds": str(row[1]),
            "application_name": str(row[2]),
        }

    def _dbi_conn(self) -> Any:
        """ibm_db_dbi wrapper for DB-API access."""
        import ibm_db_dbi

        return ibm_db_dbi.Connection(self._conn) if self._conn else None

    def _fetch_all(self, stmt: Any) -> list[tuple[Any, ...]]:
        """Drain a statement handle into a list of row tuples.

        ibm_db.fetch_tuple returns ``False`` (not ``None``) once the result set
        is exhausted, so the loop stops on any falsy sentinel. A real row is a
        non-empty tuple and therefore always truthy, even when every cell is
        NULL, so no data row can be mistaken for end-of-set.
        """
        rows: list[tuple[Any, ...]] = []
        while row := self._module.fetch_tuple(stmt):
            rows.append(row)
        return rows

    def cancel_current(self) -> bool:
        # ibm_db has no safe out-of-band cancel in this API surface; reported
        # truthfully as unsupported. A SET CLIENT INTERRUPT session option or
        # FORCE APPLICATION path is a documented future option.
        return False

    def build_sample_query(self, schema: str | None, table: str, columns: list[str] | None, limit: int) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in columns) if columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} FETCH FIRST {int(limit)} ROWS ONLY"

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="db2",
            engine_family="db2-luw",
            driver="ibm_db (bundled clidriver)",
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
                Cap.CANCEL: CapabilityState.UNSUPPORTED,
                Cap.SERVER_SIDE_CANCEL: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN: CapabilityState.UNSUPPORTED,
                Cap.EXPLAIN_ANALYZE: CapabilityState.UNSUPPORTED,
                Cap.SAMPLE: CapabilityState.UNVERIFIED,
                Cap.TLS: CapabilityState.UNVERIFIED,
            },
            limitations=[
                Limitation(
                    scope="explain",
                    detail="EXPLAIN requires administrator-provisioned explain "
                    "tables (SYSTOOLS.EXPLAIN_*); never auto-created here. Refused "
                    "until provisioned.",
                ),
                Limitation(
                    scope="licensing",
                    detail="Db2 Connect licensing applies when the target is z/OS "
                    "or Db2 for i through a gateway; the read-only identity never "
                    "runs bind/grant steps.",
                ),
                Limitation(scope="families", detail="z/OS and Db2 for i are not implemented in this build."),
                Limitation(
                    scope="cancel",
                    detail="No out-of-band cancel in this driver surface; connection is discarded on timeout.",
                ),
            ],
            required_privileges=[
                "CONNECT to the database",
                "SELECT on permitted tables/views",
                "catalog visibility (SYSCAT views) for permitted schemas",
            ],
            unverified_items=[
                "bundled-clidriver wheel operation on target (import alone is not a connectivity test)",
                "SSL via SSLServerCertificate file",
                "package binding state for the read-only identity",
            ],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                # SYSIBMADM.ENV_INST_INFO needs EXECUTE on an admin table
                # function that a bare CONNECT+SELECT identity does not have.
                # Version reporting is best-effort; liveness uses SYSDUMMY1,
                # which every connectable account can read.
                row = None
                try:
                    stmt = self._module.exec_immediate(
                        conn, "SELECT service_level FROM SYSIBMADM.ENV_INST_INFO"
                    )
                    row = self._module.fetch_tuple(stmt)
                except Exception:  # noqa: BLE001 - version is optional
                    stmt = self._module.exec_immediate(conn, "SELECT 1 FROM SYSIBM.SYSDUMMY1")
                    self._module.fetch_tuple(stmt)
                session = self.session_report(self._session_readback(conn))
            finally:
                self._module.close(conn)
            return HealthInfo(
                healthy=True,
                server_version=str(row[0]) if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001, S110
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    @_meta_translated
    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        conn = self._connect()
        try:
            sql = "SELECT SCHEMANAME FROM SYSCAT.SCHEMATA"
            if search:
                sql += " WHERE SCHEMANAME LIKE ?"
            sql += " ORDER BY 1"
            stmt = self._module.exec_immediate(conn, sql) if not search else self._module.prepare(conn, sql)
            if search:
                self._module.execute(stmt, (f"%{search}%",))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(_s(row[0]))
            return rows
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        conn = self._connect()
        try:
            types: list[str] = []
            if "table" in kinds:
                types.append("T")
            if "view" in kinds:
                types.append("V")
            if not types:
                return []
            sql = (
                "SELECT TABSCHEMA, TABNAME, TYPE, CARD FROM SYSCAT.TABLES WHERE TYPE IN ("
                + ", ".join(["?"] * len(types))
                + ")"
            )
            params: list[Any] = list(types)
            if schema:
                sql += " AND TABSCHEMA = ?"
                params.append(schema)
            if search:
                sql += " AND TABNAME LIKE ?"
                params.append(f"%{search}%")
            sql += " ORDER BY 1, 2"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            out = []
            while row := self._module.fetch_tuple(stmt):
                kind = "table" if row[2] == "T" else "view"
                if kind not in kinds:
                    continue
                out.append(
                    TableSummary(
                        schema=_s(row[0]),
                        name=_s(row[1]),
                        kind=kind,
                        row_estimate=int(row[3]) if row[3] is not None and row[3] >= 0 else None,
                        row_estimate_source="catalog_estimate(SYSCAT.TABLES.CARD)"
                        if row[3] is not None and row[3] >= 0
                        else None,
                    )
                )
            return out
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT COLNAME, TYPENAME, NULLS, DEFAULT, COLNO FROM SYSCAT.COLUMNS "
                "WHERE TABSCHEMA = ? AND TABNAME = ? ORDER BY COLNO"
            )
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema, table))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            return [
                ColumnInfo(
                    schema=schema,
                    table=table,
                    name=_s(r[0]),
                    data_type=_s(r[1]),
                    nullable=r[2] == "Y",
                    default=r[3],
                    ordinal=r[4],
                )
                for r in rows
            ]
        finally:
            self._module.close(conn)

    def build_search_query(
        self, schema: str | None, table: str, select_columns: list[str], where_sql: str, limit: int
    ) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in select_columns) if select_columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT {cols} FROM {qualified} WHERE {where_sql} FETCH FIRST {int(limit)} ROWS ONLY"

    def build_top_values_query(self, sample_sql: str, column: str, limit: int) -> str:
        q = self.quote_identifier(column)
        return (
            f"SELECT {q} AS v, COUNT(*) AS cnt FROM ({sample_sql}) s "
            f"WHERE {q} IS NOT NULL GROUP BY {q} ORDER BY cnt DESC FETCH FIRST {int(limit)} ROWS ONLY"
        )

    @_meta_translated
    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT TABNAME, COLNAME, TYPENAME, NULLS, DEFAULT, COLNO FROM SYSCAT.COLUMNS "
                "WHERE TABSCHEMA = ? ORDER BY TABNAME, COLNO"
            )
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema,))
            rows = self._fetch_all(stmt)
            return [
                ColumnInfo(schema=schema, table=_s(r[0]), name=_s(r[1]), data_type=_s(r[2]),
                           nullable=r[3] == "Y", default=r[4], ordinal=r[5])
                for r in rows
            ]
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        conn = self._connect()
        try:
            sql = (
                "SELECT i.TABNAME, i.INDNAME, i.UNIQUERULE, ic.COLNAME, ic.COLSEQ, i.INDEXTYPE "
                "FROM SYSCAT.INDEXES i JOIN SYSCAT.INDEXCOLUSE ic "
                "ON ic.INDSCHEMA = i.INDSCHEMA AND ic.INDNAME = i.INDNAME "
                "WHERE i.TABSCHEMA = ?"
            )
            params: list[Any] = [schema]
            if table:
                sql += " AND i.TABNAME = ?"
                params.append(table)
            sql += " ORDER BY i.TABNAME, i.INDNAME, ic.COLSEQ"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = self._fetch_all(stmt)
        finally:
            self._module.close(conn)
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, rule, col, _seq, itype in rows:
            key = (_s(tname), _s(iname))
            info = grouped.get(key)
            if info is None:
                # UNIQUERULE: P = primary key, U = unique, D = duplicates allowed
                info = IndexInfo(name=key[1], columns=[], unique=(_s(rule) in ("P", "U")),
                                 primary=(_s(rule) == "P"), kind=str(_s(itype)).lower(),
                                 schema=schema, table=key[0])
                grouped[key] = info
            info.columns.append(str(_s(col)))
        return list(grouped.values())

    @_meta_translated
    def list_views(self, schema: str | None) -> list[ViewInfo]:
        conn = self._connect()
        try:
            sql = "SELECT VIEWSCHEMA, VIEWNAME, TEXT FROM SYSCAT.VIEWS"
            params: list[Any] = []
            if schema:
                sql += " WHERE VIEWSCHEMA = ?"
                params.append(schema)
            sql += " ORDER BY 1, 2"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            return [ViewInfo(schema=_s(r[0]), name=_s(r[1]), kind="view", definition_state="unavailable") for r in rows]
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        conn = self._connect()
        try:
            sql = "SELECT TABSCHEMA, TABNAME, BASE_TABSCHEMA, BASE_TABNAME FROM SYSCAT.TABLES WHERE TYPE = 'A'"
            params: list[Any] = []
            if schema:
                sql += " AND TABSCHEMA = ?"
                params.append(schema)
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            return [
                SynonymInfo(schema=_s(r[0]), name=_s(r[1]), target_schema=_s(r[2]), target_name=_s(r[3]))
                for r in rows
            ]
        finally:
            self._module.close(conn)

    @_meta_translated
    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        conn = self._connect()
        try:
            sql = "SELECT ROUTINESCHEMA, ROUTINENAME, ROUTINETYPE FROM SYSCAT.ROUTINES"
            params: list[Any] = []
            if schema:
                sql += " WHERE ROUTINESCHEMA = ?"
                params.append(schema)
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = []
            while row := self._module.fetch_tuple(stmt):
                rows.append(row)
            kinds = {"F": "function", "P": "procedure"}
            return [RoutineInfo(schema=_s(r[0]), name=_s(r[1]), kind=kinds.get(_s(r[2]), _s(r[2]))) for r in rows]
        finally:
            self._module.close(conn)

    @_meta_translated
    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        conn = self._connect()
        try:
            # SYSCAT.REFERENCES names the constraint and both tables;
            # SYSCAT.KEYCOLUSE supplies the column lists on both sides
            # (joined by COLSEQ, so composite keys line up). Verified live on
            # Db2 11.5.9 (2026-09-16).
            sql = (
                "SELECT r.CONSTNAME, r.TABSCHEMA, r.TABNAME, r.REFTABSCHEMA, r.REFTABNAME, "
                "k.COLNAME, k.COLSEQ, rk.COLNAME "
                "FROM SYSCAT.REFERENCES r "
                "JOIN SYSCAT.KEYCOLUSE k ON k.CONSTNAME = r.CONSTNAME "
                "AND k.TABSCHEMA = r.TABSCHEMA AND k.TABNAME = r.TABNAME "
                "JOIN SYSCAT.KEYCOLUSE rk ON rk.CONSTNAME = r.REFKEYNAME "
                "AND rk.TABSCHEMA = r.REFTABSCHEMA AND rk.TABNAME = r.REFTABNAME AND rk.COLSEQ = k.COLSEQ"
            )
            params: list[Any] = []
            predicates: list[str] = []
            if schema:
                predicates.append("r.TABSCHEMA = ?")
                params.append(schema)
            if table:
                predicates.append("r.TABNAME = ?")
                params.append(table)
            if predicates:
                sql += " WHERE " + " AND ".join(predicates)
            sql += " ORDER BY r.CONSTNAME, k.COLSEQ"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, tuple(params))
            rows = self._fetch_all(stmt)
        finally:
            self._module.close(conn)
        grouped: dict[tuple[str, str, str], KeyInfo] = {}
        for name, src_schema, src_table, ref_schema, ref_table, col, _seq, ref_col in rows:
            key = (_s(name), _s(src_schema), _s(src_table))
            info = grouped.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key", name=key[0], columns=[], ref_schema=_s(ref_schema), ref_table=_s(ref_table),
                    ref_columns=[], source_schema=key[1], source_table=key[2],
                )
                grouped[key] = info
            info.columns.append(str(_s(col)))
            info.ref_columns.append(str(_s(ref_col)))
        return list(grouped.values())

    @_meta_translated
    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            sql = "SELECT CARD, STATS_TIME FROM SYSCAT.TABLES WHERE TABSCHEMA = ? AND TABNAME = ?"
            stmt = self._module.prepare(conn, sql)
            self._module.execute(stmt, (schema, table))
            row = self._module.fetch_tuple(stmt)
            if not row:
                return {"schema": schema, "table": table, "row_estimate": None, "row_estimate_source": "unavailable"}
            return {
                "schema": schema,
                "table": table,
                "row_estimate": int(row[0]) if row[0] is not None and row[0] >= 0 else None,
                "row_estimate_source": "catalog_estimate(SYSCAT.TABLES.CARD)",
                "stats_time": str(row[1]) if row[1] else None,
            }
        finally:
            self._module.close(conn)

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        import ibm_db_dbi

        raw = self._connect()
        start = time.monotonic()
        truncated = False
        cell_truncated_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0
        import json

        try:
            conn = ibm_db_dbi.Connection(raw)
            cur = conn.cursor()
            cur.execute(spec.sql, tuple(spec.parameters) if isinstance(spec.parameters, list) else spec.parameters)
            cols = [(d[0], "unknown") for d in cur.description or []]
            col_labels = [
                getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                for d in (cur.description or [])
            ]
            while True:
                batch = cur.fetchmany(200)
                if not batch:
                    break
                for r in batch:
                    vals, labels, cell_tr = cell_truncated_json(r, spec.max_cell_bytes)
                    if not col_labels:
                        col_labels = labels
                    if cell_tr:
                        cell_truncated_cols.extend(truncated_column_names(cols, r, spec.max_cell_bytes))
                    approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                    if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                        truncated = True
                        break
                    rows.append(vals)
                if truncated:
                    break
            warnings = ["result truncated by limits"] if truncated else []
            if cell_truncated_cols:
                truncated = True
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            return QueryOutcome(
                columns=[(c[0], t) for c, t in zip(cols, col_labels or ["unknown"] * len(cols), strict=True)],
                rows=rows,
                truncated=truncated,
                rows_seen=len(rows),
                elapsed_ms=int((time.monotonic() - start) * 1000),
                warnings=warnings,
            )
        finally:
            try:
                self._module.close(raw)
            except Exception:  # noqa: BLE001, S110
                pass

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        raise NotImplementedError(
            "Db2 EXPLAIN requires administrator-provisioned explain tables; not provisioned automatically in this build"
        )
