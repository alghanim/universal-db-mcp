"""SQL Server connector (pyodbc + Microsoft ODBC Driver 18).

The Python wheel ships in the bundle; the ODBC driver itself is an
administrator-supplied OS package (EULA acceptance required, spec §5). The
driver's presence is checked at connect time and reported by doctor. Live
behaviors are ``unverified`` until Gate C.

TLS: ODBC Driver 18 has no connection-string keyword for a CA file — it
verifies the server certificate against the OS OpenSSL trust store only
(``ServerCertificate`` is a leaf-certificate pin for ``Encrypt=strict``, not a
CA). ``tls.ca_file`` is therefore honored by requiring, before dialing, that
the pinned CA is installed in that trust store; the connector refuses to
connect otherwise rather than silently verifying against whatever the OS
happens to trust.
"""

from __future__ import annotations

import hashlib
import math
import re
import ssl
import threading
import time
from pathlib import Path
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

ODBC_DRIVER_NAME = "ODBC Driver 18 for SQL Server"


def _mssql_server_value(cfg: Any) -> str:
    """``Server=`` value: host, instance and port.

    A named instance (``host\\INSTANCE``) resolves its port through SQL Server
    Browser on UDP 1434. Appending a port anyway sent the client to the default
    instance instead, which surfaced as a connect timeout that looked like a
    firewall problem - so the port is appended only when the config sets one.
    """
    host = str(cfg.host or "")
    if "\\" in host and cfg.port is None:
        return host
    return f"{host},{cfg.port or 1433}"



def _mssql_type(data_type: Any, char_len: Any, precision: Any, scale: Any) -> str:
    """Fold the declared length/precision back into the type name:
    nvarchar(200), nvarchar(max), decimal(12,2)."""
    base = str(data_type or "")
    low = base.lower()
    if low in ("varchar", "nvarchar", "char", "nchar", "varbinary", "binary") and char_len:
        return f"{base}(max)" if int(char_len) < 0 else f"{base}({int(char_len)})"
    if low in ("decimal", "numeric") and precision:
        return f"{base}({int(precision)},{int(scale or 0)})"
    return base


class MssqlConnector(DatabaseConnector):
    engine = "mssql"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._exec_lock = threading.Lock()  # serializes queries

    @staticmethod
    def _odbc_escape(value: str, field: str = "value") -> str:
        """Brace-quote an ODBC connection-string value, refusing what braces
        cannot carry.

        ODBC has NO escape for a closing brace: Microsoft's grammar states the
        first '}' terminates a braced value. The previous '}}' doubling was
        invented - it truncated the credential and let the remainder be parsed
        as further attributes. Since the driver honors the FIRST occurrence of
        a repeated keyword, an injected Encrypt=no could even beat our own
        Encrypt=yes. Refuse instead (the db2 connector takes the same line for
        ';'), and never echo the value itself.
        """
        if "}" in value:
            raise ConnectorError(
                f"mssql {field} contains '}}', which an ODBC connection string cannot carry in "
                "any quoting form (the first closing brace ends the value and the rest is "
                "parsed as connection attributes); change that value"
            )
        return "{" + value + "}"

    @staticmethod
    def _require_ca_in_os_trust_store(ca_file: str) -> None:
        """Fail closed unless every PEM certificate in ``ca_file`` is already
        a trust anchor of the OS trust store.

        ODBC Driver 18 has no connection-string keyword for a CA bundle — it
        verifies the server certificate against the OS OpenSSL trust store
        only. Emitting a made-up keyword would be silently ignored by the
        driver and fall back to whatever the OS happens to trust, so the
        pinned CA must be installed into that trust store and verified here
        before dialing.
        """
        try:
            pem = Path(ca_file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RuntimeError(
                f"tls.ca_file '{ca_file}' cannot be read: {exc}. ODBC Driver 18 "
                f"verifies server certificates against the OS trust store only, "
                f"so the pinned CA must exist locally and be installed there."
            ) from exc
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, flags=re.DOTALL)
        if not blocks:
            raise RuntimeError(
                f"tls.ca_file '{ca_file}' contains no PEM certificates. ODBC "
                f"Driver 18 verifies server certificates against the OS trust "
                f"store only; tls.ca_file must name the internal CA PEM and "
                f"that CA must be installed into the OS trust store."
            )
        try:
            pinned = {hashlib.sha256(ssl.PEM_cert_to_DER_cert(b)).hexdigest() for b in blocks}
        except ValueError as exc:  # binascii.Error is a ValueError subclass
            raise RuntimeError(f"tls.ca_file '{ca_file}' is not a valid PEM certificate: {exc}") from exc
        trust_anchors = ssl.create_default_context().get_ca_certs(binary_form=True)
        trusted = {hashlib.sha256(der).hexdigest() for der in trust_anchors}
        if not pinned <= trusted:
            # A hashed CApath store (RHEL/SUSE and anything using
            # /etc/ssl/certs/<hash>.0 symlinks) enumerates nothing through
            # get_ca_certs(), so the check above would declare an installed CA
            # missing and refuse a perfectly good deployment. Scan the CApath.
            paths = ssl.get_default_verify_paths()
            for directory in {paths.capath, paths.openssl_capath}:
                if not directory:
                    continue
                try:
                    entries = list(Path(directory).iterdir())
                except OSError:
                    continue
                for entry in entries:
                    try:
                        text = entry.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    for block in re.findall(
                        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, flags=re.DOTALL
                    ):
                        try:
                            trusted.add(hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest())
                        except ValueError:
                            continue
        if not pinned <= trusted:
            raise RuntimeError(
                f"tls.ca_file '{ca_file}' names a CA that is NOT installed in "
                f"the OS trust store. ODBC Driver 18 has no connection-string "
                f"keyword for a CA bundle (it verifies against the OS OpenSSL "
                f"trust store only), so the internal CA PEM must be installed "
                f"into the OS trust store (e.g. update-ca-certificates or the "
                f"system keychain) before connecting; refusing to connect "
                f"against whatever the OS happens to trust."
            )

    def _connect(self) -> Any:
        self._module = open_module("pyodbc", "pyodbc (manylinux cp312 wheel from the bundle wheelhouse)")
        cfg = self.connection.config
        # The driver to use is selectable via options.odbc_driver (config.py
        # declares it) and defaults to Driver 18. Detection must match the
        # EXACT name that will be put into the connection string: accepting a
        # loose "some ODBC SQL Server driver exists" while emitting a hardcoded
        # name made doctor report success and every connect fail with
        # "Can't open lib ...".
        driver_name = str(cfg.options.get("odbc_driver") or ODBC_DRIVER_NAME)
        installed = self._module.drivers()
        if driver_name not in installed:
            raise RuntimeError(
                f"'{driver_name}' is not installed on this machine (installed "
                f"SQL Server ODBC drivers: {[d for d in installed if 'SQL Server' in d] or 'none'}); "
                f"it is an administrator-supplied OS package (see bundle "
                f"os-packages/ and docs/offline-deployment.md) or select the "
                f"installed one via options.odbc_driver. The application cannot download it."
            )
        esc = self._odbc_escape
        # Encryption keywords are emitted BEFORE any config-derived value:
        # ODBC honors the first occurrence of a repeated keyword, so even if a
        # value ever escaped the brace check it could not downgrade TLS.
        parts = [
            f"Driver={esc(driver_name, 'options.odbc_driver')}",
            "Encrypt=yes" if cfg.tls.enabled else "Encrypt=no",
            "TrustServerCertificate=no" if cfg.tls.verify_server else "TrustServerCertificate=yes",
            # host AND port are brace-quoted TOGETHER: quoting the host alone
            # (port outside the braces) makes ODBC Driver 18 mis-parse the
            # attribute and fail the TLS/cert path even with Encrypt=no.
            f"Server={esc(_mssql_server_value(cfg), 'host')}",
            f"Database={esc(cfg.database or '', 'database')}",  # validator guarantees non-None
        ]
        if cfg.tls.enabled and cfg.tls.ca_file:
            # ODBC Driver 18 has no connection-string keyword for a CA bundle;
            # emitting one would be silently dropped and verification would
            # fall back to the OS trust store. Honor tls.ca_file by failing
            # closed unless the pinned CA is installed there.
            self._require_ca_in_os_trust_store(cfg.tls.ca_file)
        if cfg.options.get("trusted_connection"):
            # Windows/Kerberos identity of the service process. On Linux this
            # needs a krb5 configuration and a ticket (kinit) before start;
            # the driver does not fall back to NTLM.
            parts.append("Trusted_Connection=yes")
        else:
            if self.connection.username:
                parts.append(f"Uid={esc(self.connection.username.value, 'Uid')}")
            if self.connection.password:
                parts.append(f"Pwd={esc(self.connection.password.value, 'Pwd')}")
        parts.append(f"APP={esc(self.session_profile.application_name, 'session.application_name')}")
        if str(cfg.options.get("application_intent", "")).lower() == "readonly":
            # Availability Groups route read-intent connections to a readable
            # secondary; on a standalone server the keyword is accepted and
            # has no effect. Opt-in: a secondary may lag the primary.
            parts.append("ApplicationIntent=ReadOnly")
        conn = self._module.connect(
            ";".join(parts), timeout=int(math.ceil(cfg.connect_timeout_seconds))
        )
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile. The isolation level is REQUIRED
        when the profile has one (READ UNCOMMITTED for read-only connections
        by default: ordinary reads take share locks under READ COMMITTED and
        queue behind writers); the lock ceiling is best-effort. The policy's
        hard timeout also becomes the driver's query timeout."""
        prof = self.session_profile
        self._session_reset()
        if prof.statement_timeout_seconds:
            try:
                conn.timeout = int(math.ceil(prof.statement_timeout_seconds))
                self._session_applied(f"statement_timeout={conn.timeout}s")
            except Exception as exc:  # noqa: BLE001
                self._session_skipped("statement_timeout", exc)
        cur = conn.cursor()
        try:
            if prof.isolation:
                level = prof.isolation.replace("_", " ").upper()
                try:
                    cur.execute(f"SET TRANSACTION ISOLATION LEVEL {level}")
                    self._session_applied(f"isolation={prof.isolation}")
                except Exception as exc:  # noqa: BLE001
                    raise self._session_required(f"isolation {prof.isolation}", exc) from exc
            if prof.lock_timeout_seconds is not None:
                ms = int(math.ceil(prof.lock_timeout_seconds * 1000))
                try:
                    cur.execute(f"SET LOCK_TIMEOUT {ms}")
                    self._session_applied(f"lock_timeout={ms}ms")
                except Exception as exc:  # noqa: BLE001
                    self._session_skipped("lock_timeout", exc)
        finally:
            close = getattr(cur, "close", None)
            if callable(close):
                close()

    _ISOLATION_NAMES = {
        0: "unspecified", 1: "read_uncommitted", 2: "read_committed",
        3: "repeatable_read", 4: "serializable", 5: "snapshot",
    }

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT s.transaction_isolation_level, s.program_name, @@LOCK_TIMEOUT "
                "FROM sys.dm_exec_sessions s WHERE s.session_id = @@SPID"
            )
            row = cur.fetchone()
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 3:
            return {}
        return {
            "isolation": self._ISOLATION_NAMES.get(int(row[0]), str(row[0])),
            "application_name": str(row[1]),
            "lock_timeout_ms": str(row[2]),
        }

    # pyodbc exposes no safe out-of-band cancel through this API surface.
    def cancel_current(self) -> bool:
        return False

    def build_sample_query(self, schema: str | None, table: str, columns: list[str] | None, limit: int) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in columns) if columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT TOP {int(limit)} {cols} FROM {qualified}"

    def capabilities(self) -> CapabilityMatrix:
        return CapabilityMatrix(
            engine="mssql",
            engine_family="sqlserver",
            driver="pyodbc + Microsoft ODBC Driver 18 (administrator-supplied)",
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
                    detail="T-SQL plan capture (SET SHOWPLAN_XML) requires a "
                    "separate batch and is not implemented in v1; plans are "
                    "reportedly unsupported rather than approximated.",
                ),
                Limitation(
                    scope="licensing",
                    detail="The ODBC driver is subject to the Microsoft EULA; "
                    "administrator acceptance is a deployment prerequisite.",
                ),
                Limitation(scope="cancel", detail="No out-of-band cancel; connection is discarded on timeout."),
            ],
            required_privileges=[
                "db_datareader on permitted schemas (or equivalent SELECT grants)",
                "VIEW DEFINITION for definitions (optional)",
            ],
            unverified_items=["ODBC driver install detection on target", "TLS via internal CA"],
        )

    def health_check(self) -> HealthInfo:
        start = time.monotonic()
        try:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute("SELECT @@VERSION")
                row = cur.fetchone()
                session = self.session_report(self._session_readback(conn))
            finally:
                conn.close()
            return HealthInfo(
                healthy=True,
                server_version=str(row[0])[:60] if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
            )
        except Exception as exc:  # noqa: BLE001
            return HealthInfo(healthy=False, detail=scrub_exception(exc)[:300])

    def list_schemas(self, catalog: str | None, search: str | None) -> list[str]:
        sql = "SELECT schema_name FROM information_schema.schemata"
        params: list[Any] = []
        if search:
            sql += " WHERE schema_name LIKE ?"
            params.append(f"%{search}%")
        sql += " ORDER BY 1"
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                return [r[0] for r in cur.fetchall()]
            finally:
                conn.close()

    def list_tables(self, schema: str | None, kinds: set[str], search: str | None) -> list[TableSummary]:
        wanted: list[str] = []
        if "table" in kinds:
            wanted.append("BASE TABLE")
        if "view" in kinds:
            wanted.append("VIEW")
        if not wanted:
            return []
        sql = (
            "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_type IN ("
            + ", ".join(["?"] * len(wanted))
            + ")"
        )
        params: list[Any] = list(wanted)
        if schema:
            sql += " AND table_schema = ?"
            params.append(schema)
        if search:
            sql += " AND table_name LIKE ?"
            params.append(f"%{search}%")
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        return [TableSummary(schema=r[0], name=r[1], kind="view" if r[2] == "VIEW" else "table") for r in rows]

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        sql = (
            "SELECT column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = ? AND table_name = ? "
            "ORDER BY ordinal_position"
        )
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, [schema, table])
                rows = cur.fetchall()
            finally:
                conn.close()
        return [
            ColumnInfo(
                schema=schema,
                table=table,
                name=r[0],
                data_type=_mssql_type(r[1], r[5], r[6], r[7]),
                nullable=r[2] == "YES",
                default=r[3],
                ordinal=r[4],
            )
            for r in rows
        ]

    def length_expression(self, quoted_column: str) -> str:
        return f"LEN({quoted_column})"

    def substring_expression(self, quoted_column: str, chars: int) -> str:
        return f"SUBSTRING({quoted_column}, 1, {int(chars)})"

    def escape_like(self, needle: str) -> str:
        # T-SQL LIKE also treats [ as a wildcard-class opener
        return super().escape_like(needle).replace("[", "\\[")

    def text_expression(self, quoted_column: str, portable_name: str) -> str:
        return f"CAST({quoted_column} AS varchar(64))" if portable_name == "uuid" else quoted_column

    def build_search_query(
        self, schema: str | None, table: str, select_columns: list[str], where_sql: str, limit: int
    ) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in select_columns) if select_columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT TOP {int(limit)} {cols} FROM {qualified} WHERE {where_sql}"

    def build_top_values_query(self, sample_sql: str, column: str, limit: int) -> str:
        q = self.quote_identifier(column)
        return (
            f"SELECT TOP {int(limit)} {q} AS v, COUNT(*) AS cnt FROM ({sample_sql}) s "
            f"WHERE {q} IS NOT NULL GROUP BY {q} ORDER BY cnt DESC"
        )

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        sql = (
            "SELECT table_name, column_name, data_type, is_nullable, column_default, ordinal_position, "
            "character_maximum_length, numeric_precision, numeric_scale "
            "FROM information_schema.columns WHERE table_schema = ? ORDER BY table_name, ordinal_position"
        )
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, [schema])
                rows = cur.fetchall()
            finally:
                conn.close()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=_mssql_type(r[2], r[6], r[7], r[8]),
                       nullable=r[3] == "YES", default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        sql = (
            "SELECT t.name, i.name, i.is_unique, i.is_primary_key, i.type_desc, c.name, ic.key_ordinal "
            "FROM sys.indexes i "
            "JOIN sys.tables t ON t.object_id = i.object_id "
            "JOIN sys.schemas s ON s.schema_id = t.schema_id "
            "JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
            "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
            "WHERE i.name IS NOT NULL AND ic.is_included_column = 0 AND s.name = ?"
        )
        params: list[Any] = [schema]
        if table:
            sql += " AND t.name = ?"
            params.append(table)
        sql += " ORDER BY t.name, i.name, ic.key_ordinal"
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, unique, primary, tdesc, col, _ord in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=bool(unique), primary=bool(primary),
                                 kind=str(tdesc).lower(), schema=schema, table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col))
        return list(grouped.values())

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = "SELECT table_schema, table_name FROM information_schema.views"
        params: list[Any] = []
        if schema:
            sql += " WHERE table_schema = ?"
            params.append(schema)
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        return [ViewInfo(schema=r[0], name=r[1], kind="view", definition_state="not_supported") for r in rows]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        # conservative empty until a SQL Server instance verifies the catalog query
        return []  # refined during Gate C; conservative empty until verified

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = "SELECT routine_schema, routine_name, routine_type FROM information_schema.routines"
        params: list[Any] = []
        if schema:
            sql += " WHERE routine_schema = ?"
            params.append(schema)
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        # One row per FK *column*; grouped below into one KeyInfo per constraint.
        sql = (
            "SELECT fk.name, OBJECT_SCHEMA_NAME(fk.parent_object_id), OBJECT_NAME(fk.parent_object_id), "
            "OBJECT_SCHEMA_NAME(fk.referenced_object_id), tr.name, "
            "COL_NAME(fkc.parent_object_id, fkc.parent_column_id), "
            "COL_NAME(fkc.referenced_object_id, fkc.referenced_column_id) "
            "FROM sys.foreign_keys fk "
            "JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id "
            "JOIN sys.tables tp ON fk.parent_object_id = tp.object_id "
            "JOIN sys.tables tr ON fk.referenced_object_id = tr.object_id"
        )
        conditions: list[str] = []
        params: list[Any] = []
        if schema:
            conditions.append("OBJECT_SCHEMA_NAME(fk.parent_object_id) = ?")
            params.append(schema)
        if table:
            conditions.append("OBJECT_NAME(fk.parent_object_id) = ?")
            params.append(table)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY fk.name, fkc.constraint_column_id"
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        # Constraint names are unique per schema only, so group by the full
        # (schema, table, name) triple.
        by_key: dict[tuple[str | None, str | None, str | None], KeyInfo] = {}
        out: list[KeyInfo] = []
        for r in rows:
            key = (r[1], r[2], r[0])
            info = by_key.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key",
                    name=r[0],
                    columns=[],
                    source_schema=r[1],
                    source_table=r[2],
                    ref_schema=r[3],
                    ref_table=r[4],
                )
                by_key[key] = info
                out.append(info)
            info.columns.append(r[5])
            info.ref_columns.append(r[6])
        return out

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        # sys.dm_db_partition_stats row_count is a catalog estimate.
        sql = (
            "SELECT SUM(p.rows) FROM sys.partitions p "
            "JOIN sys.tables t ON p.object_id = t.object_id "
            "WHERE t.name = ? AND p.index_id IN (0,1)"
        )
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, [table])
                row = cur.fetchone()
            finally:
                conn.close()
        return {
            "schema": schema,
            "table": table,
            "row_estimate": int(row[0]) if row and row[0] else None,
            "row_estimate_source": "catalog_estimate(sys.partitions)",
        }

    def execute_query(self, spec: QuerySpec) -> QueryOutcome:
        with self._exec_lock:
            return self._execute(spec)

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        with translated_driver_errors():
            conn = self._connect()
            start = time.monotonic()
            truncated = False
            cell_truncated_cols: list[str] = []
            rows: list[list[Any]] = []
            approx_bytes = 0
            import json

            try:
                cur = conn.cursor()
                if spec.parameters:
                    cur.execute(
                        spec.sql, tuple(spec.parameters) if isinstance(spec.parameters, list) else spec.parameters
                    )
                else:
                    cur.execute(spec.sql)
                cols = [(d[0], "unknown") for d in cur.description or []]
                col_labels = [
                    getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                    for d in (cur.description or [])
                ]
                while True:
                    batch = cur.fetchmany(200)
                    if not batch:
                        break
                    for raw in batch:
                        vals, labels, cell_tr = cell_truncated_json(raw, spec.max_cell_bytes)
                        if not col_labels:
                            col_labels = labels
                        if cell_tr:
                            cell_truncated_cols.extend(truncated_column_names(cols, raw, spec.max_cell_bytes))
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
                conn.close()

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        raise NotImplementedError(
            "T-SQL plan capture requires SET SHOWPLAN_XML in a separate batch; not implemented in this build"
        )
