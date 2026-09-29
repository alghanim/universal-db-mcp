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

import datetime
import hashlib
import math
import re
import ssl
import threading
import time
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

import sqlglot
from sqlglot import TokenType

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import (
    EXPLAIN_ANALYZE_UNSUPPORTED,
    ColumnInfo,
    ConnectorError,
    DatabaseConnector,
    HealthInfo,
    IndexInfo,
    KeyInfo,
    NameBinding,
    QueryOutcome,
    QuerySpec,
    RoutineInfo,
    SynonymInfo,
    SynonymTarget,
    TableSummary,
    ViewInfo,
    own_objects_first,
)
from universal_db_mcp.connectors.driver_helpers import (
    SelectList,
    adapt_row,
    cell_truncation_warning,
    column_names_at,
    next_fetch_size,
    open_module,
    statement_body,
    translated_driver_errors,
)
from universal_db_mcp.discovery.system_schemas import is_session_sql_view
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.redact import scrub_exception

ODBC_DRIVER_NAME = "ODBC Driver 18 for SQL Server"

# With QUOTED_IDENTIFIER OFF (a DSN's QuotedId=No, or a driver that leaves the
# server's user options) "x" is a string where the guard reads an identifier
# (live: SELECT "name" FROM sys.databases returned 'name'). It is the one SET
# option that changes how a batch is parsed; the others (ANSI_NULLS,
# CONCAT_NULL_YIELDS_NULL, ...) change what an expression yields. RAISERROR
# fails the connect when the session does not hold it.
_MSSQL_PIN_READING = (
    "SET QUOTED_IDENTIFIER ON; "
    "IF SESSIONPROPERTY('QUOTED_IDENTIFIER') <> 1 RAISERROR('QUOTED_IDENTIFIER is OFF', 16, 1)"
)

# The schema SQL Server resolves a bare table or view name in: the login's
# default schema, then dbo. Binds one parameter, the object's name.
_BARE_NAME_SCHEMA = (
    "(SELECT TOP (1) s.name FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id "
    "WHERE o.name = ? AND o.type IN ('U', 'V') AND s.name IN (SCHEMA_NAME(), N'dbo') "
    "ORDER BY CASE WHEN s.name = SCHEMA_NAME() THEN 0 ELSE 1 END)"
)


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


def _extra_statement_error(reason: str | None) -> ConnectorError:
    detail = f" (a later statement failed: {reason})" if reason else ""
    return ConnectorError(
        "the batch contained more than one statement; its results are discarded and the "
        f"transaction is rolled back{detail}",
        category=ErrorCategory.POLICY,
    )


_MSSQL_XML = 241  # sys.types.system_type_id of xml
# Schemas of the server's catalog views, which information_schema.tables
# never lists (their canonical spelling: a binary collation compares exactly).
# The connector's own statements spell each view and column as the catalog
# does too: SQL Server compares them as the database collation does, and on a
# CS_AS database information_schema.tables is no object (live, 2022).
_MSSQL_CATALOG_SCHEMAS = ("sys", "INFORMATION_SCHEMA")
# Names looked up per synonym_chains statement: two parameters each, below
# the 2100 SQL Server takes.
_SYNONYM_BATCH = 500


def _mssql_parameter_type(value: Any) -> str:
    """A T-SQL type that ``sp_describe_first_result_set`` can take a bound
    value as (it only reads the result's shape)."""
    if isinstance(value, bool):
        return "bit"
    if isinstance(value, int):
        return "bigint"
    if isinstance(value, float):
        return "float"
    if isinstance(value, Decimal):
        return "decimal(38, 10)"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "varbinary(max)"
    if isinstance(value, datetime.datetime):
        return "datetime2"
    if isinstance(value, datetime.date):
        return "date"
    if isinstance(value, datetime.time):
        return "time"
    return "nvarchar(max)"


def _bracketed(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


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
        self._cursor_lock = threading.Lock()  # guards _running_cursor against close during cancel
        self._running_cursor: Any = None  # the executing query's cursor, for cancel_current

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
        # pyodbc pools connections by default (process-wide, read when the
        # first connection is made): every "new" connection was then the same
        # server session, and SET state leaked from one call into the next
        # (a query's TEXTSIZE into catalog reads, a SET NOCOUNT ON into the
        # detection of smuggled statements). Only this connector uses pyodbc.
        self._module.pooling = False
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
        # SQL Server has no read-only session here: every statement runs in
        # a transaction this connector never commits and rolls back itself.
        # Set explicitly rather than trusting the driver default.
        conn.autocommit = False
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile. The isolation level is REQUIRED
        when the profile has one (READ UNCOMMITTED for read-only connections
        by default: ordinary reads take share locks under READ COMMITTED and
        queue behind writers); the lock ceiling is best-effort. The policy's
        hard timeout, or the shorter timeout of the query the connection is
        opened for, becomes the driver's query timeout (HYT00 at the limit).
        QUOTED_IDENTIFIER ON (_MSSQL_PIN_READING) is required on every
        connection."""
        prof = self.session_profile
        self._session_reset()
        if ceiling := self._statement_ceiling():
            try:
                conn.timeout = ceiling
                self._session_applied(f"statement_timeout={conn.timeout}s")
            except Exception as exc:  # noqa: BLE001
                self._session_skipped("statement_timeout", exc)
        cur = conn.cursor()
        try:
            # What this connector relies on, whatever session it was handed:
            # rowcounts reported (a smuggled statement's rowcount is how it
            # is noticed) and values unbounded (catalog reads need whole
            # definitions; a query sets its own TEXTSIZE).
            cur.execute("SET NOCOUNT OFF; SET TEXTSIZE -1")
            try:
                cur.execute(_MSSQL_PIN_READING)
                self._session_applied("quoted_identifier=on")
            except Exception as exc:  # noqa: BLE001
                raise self._reading_required("QUOTED_IDENTIFIER ON", exc) from exc
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

    def cancel_current(self) -> bool:
        """Cancel the executing statement with pyodbc's Cursor.cancel() (ODBC
        SQLCancel, made to be called from another thread). The slot lock
        keeps the query from closing that cursor under the call."""
        with self._cursor_lock:
            cur = self._running_cursor
            if cur is None:
                return False
            try:
                cur.cancel()
                return True
            except Exception:  # noqa: BLE001 - pyodbc.Error: best effort, the connection is discarded anyway
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
                    detail="Estimated plans come from SET SHOWPLAN_ALL on a private "
                    "connection (nothing executes); the account needs the SHOWPLAN "
                    "database permission (GRANT SHOWPLAN TO <user>), refused with that "
                    "instruction otherwise.",
                ),
                Limitation(
                    scope="licensing",
                    detail="The ODBC driver is subject to the Microsoft EULA; "
                    "administrator acceptance is a deployment prerequisite.",
                ),
                Limitation(
                    scope="cancel",
                    detail="A timed-out statement is cancelled with pyodbc Cursor.cancel() (ODBC "
                    "SQLCancel) and the connection is discarded; each query's own timeout is also the "
                    "driver's statement timeout.",
                ),
                Limitation(
                    scope="query",
                    detail="Values are cut to the cell limit by SET TEXTSIZE; xml result columns are cast "
                    "to nvarchar(max) for it (described first with sp_describe_first_result_set). An xml "
                    "column the statement cannot be rewritten for (a union, a star over several tables, "
                    "FOR XML ... TYPE as the statement's own clause) is refused.",
                ),
                Limitation(
                    scope="read_only",
                    detail="There is no read-only session: every query runs in a transaction that is "
                    "rolled back, and a further statement in the batch is refused when it reports a "
                    "result, a rowcount or an error. A statement that reports none of them (DDL, TRUNCATE, "
                    "WAITFOR, COMMIT, or anything after SET NOCOUNT ON) is not noticed: the rollback undoes "
                    "the transactional ones, a COMMIT in the batch defeats it, and the SQL guard is what "
                    "keeps such batches out.",
                ),
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
        sql = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA"
        params: list[Any] = []
        if search:
            sql += " WHERE SCHEMA_NAME LIKE ?"
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
            "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE IN ("
            + ", ".join(["?"] * len(wanted))
            + ")"
        )
        params: list[Any] = list(wanted)
        if schema:
            sql += " AND TABLE_SCHEMA = ?"
            params.append(schema)
        if search:
            sql += " AND TABLE_NAME LIKE ?"
            params.append(f"%{search}%")
        # The catalog views are not data unless the administrator allowed
        # their schema (security.allowed_system_schemas lists
        # information_schema by default): the resolver permits only what is
        # listed here.
        opened = self._opened_schemas()
        if "view" in kinds and (catalog := [s for s in _MSSQL_CATALOG_SCHEMAS if s.lower() in opened]):
            sql += (
                " UNION ALL SELECT s.name, o.name, 'VIEW' FROM sys.all_objects AS o "
                "JOIN sys.schemas AS s ON s.schema_id = o.schema_id WHERE o.type = 'V' AND s.name IN ("
                + ", ".join(["?"] * len(catalog))
                + ")"
            )
            params.extend(catalog)
            if schema:
                sql += " AND s.name = ?"
                params.append(schema)
            if search:
                sql += " AND o.name LIKE ?"
                params.append(f"%{search}%")
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
                rows = cur.fetchall()
            finally:
                conn.close()
        tables = [
            TableSummary(schema=r[0], name=r[1], kind="view" if r[2] == "VIEW" else "table")
            for r in rows
            if not is_session_sql_view(self.engine, r[0], r[1])
        ]
        return own_objects_first(tables, _MSSQL_CATALOG_SCHEMAS)

    def get_table(self, schema: str | None, name: str) -> dict[str, Any]:
        # A bare name is resolved once, the way SQL Server resolves it, so the
        # columns, keys and estimate all describe that one table.
        if schema is None:
            schema = self._bare_name_schema(name)
        return super().get_table(schema, name)

    def _bare_name_schema(self, name: str) -> str | None:
        """The schema of the table or view a bare ``name`` means; None when
        there is none."""
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(f"SELECT {_BARE_NAME_SCHEMA}", [name])
                row = cur.fetchone()
            finally:
                conn.close()
        return str(row[0]) if row and row[0] is not None else None

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        # A bare name (schema None) is looked up where SQL Server resolves it.
        bare = schema is None
        sql = (
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, ORDINAL_POSITION, "
            "CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION, NUMERIC_SCALE, TABLE_SCHEMA "
            f"FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = {_BARE_NAME_SCHEMA if bare else '?'} "
            "AND TABLE_NAME = ? "
            "ORDER BY ORDINAL_POSITION"
        )
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, [table if bare else schema, table])
                rows = cur.fetchall()
            finally:
                conn.close()
        return [
            ColumnInfo(
                schema=schema if schema is not None else r[8],
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
        return super().escape_like(needle).replace("[", self.LIKE_ESCAPE + "[")

    def text_expression(self, quoted_column: str, portable_name: str, declared_type: str | None = None) -> str:
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
            "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, ORDINAL_POSITION, "
            "CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION, NUMERIC_SCALE "
            "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, ORDINAL_POSITION"
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
        bare = schema is None and bool(table)
        sql = (
            "SELECT t.name, i.name, i.is_unique, i.is_primary_key, i.type_desc, c.name, ic.key_ordinal, s.name "
            "FROM sys.indexes i "
            "JOIN sys.tables t ON t.object_id = i.object_id "
            "JOIN sys.schemas s ON s.schema_id = t.schema_id "
            "JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
            "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
            "WHERE i.name IS NOT NULL AND ic.is_included_column = 0 AND s.name = "
            + (_BARE_NAME_SCHEMA if bare else "?")
        )
        params: list[Any] = [table] if bare else [schema]
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
        for tname, iname, unique, primary, tdesc, col, _ord, sname in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=bool(unique), primary=bool(primary),
                                 kind=str(tdesc).lower(), schema=schema if schema is not None else sname,
                                 table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col))
        return list(grouped.values())

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS"
        params: list[Any] = []
        if schema:
            sql += " WHERE TABLE_SCHEMA = ?"
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

    def synonym_chains(
        self, names: Sequence[tuple[str | None, str]]
    ) -> dict[tuple[str | None, str], list[SynonymTarget]]:
        # the synonym each name is, as SQL Server binds it (SCHEMA_ID, and
        # OBJECT_ID of the name in the synonym's schema, as the database
        # collation compares names: live, a CS_AS database kept ocean.BUOYS
        # FOR sys.objects beside the table ocean.buoys, and case, accent or
        # width folding in Python matches no collation exactly), a bare one of
        # any schema; and what its base object names: its server and database
        # where it names another one (live: dbo.r2_cross FOR
        # master.dbo.spt_values read master's table), else the schema and
        # name OBJECT_ID binds it to in this database, as a statement's name
        # is bound (live: FOR syslogins and FOR HospitalDB.dbo.syslogins are
        # both sys.syslogins). SQL Server refuses a synonym of a synonym at use
        out: dict[tuple[str | None, str], list[SynonymTarget]] = {}
        for at in range(0, len(names), _SYNONYM_BATCH):
            batch = names[at : at + _SYNONYM_BATCH]
            values = ", ".join(
                f"({k}, CAST(? AS nvarchar(128)), CAST(? AS nvarchar(128)))" for k in range(len(batch))
            )
            sql = (
                "SELECT v.i, SCHEMA_NAME(s.schema_id), s.name, PARSENAME(s.base_object_name, 4), "
                "NULLIF(PARSENAME(s.base_object_name, 3), DB_NAME()), "
                "COALESCE(OBJECT_SCHEMA_NAME(b.id), PARSENAME(s.base_object_name, 2)), "
                "COALESCE(OBJECT_NAME(b.id), PARSENAME(s.base_object_name, 1)) "
                f"FROM (VALUES {values}) AS v (i, sch, n) "
                "JOIN sys.synonyms AS s ON (v.sch IS NULL OR s.schema_id = SCHEMA_ID(v.sch)) AND s.object_id = "
                "OBJECT_ID(QUOTENAME(SCHEMA_NAME(s.schema_id)) + N'.' + QUOTENAME(v.n)) "
                "CROSS APPLY (SELECT CASE WHEN PARSENAME(s.base_object_name, 4) IS NULL "
                "AND NULLIF(PARSENAME(s.base_object_name, 3), DB_NAME()) IS NULL "
                "THEN OBJECT_ID(s.base_object_name) END AS id) AS b"
            )
            with translated_driver_errors():
                conn = self._connect()
                try:
                    cur = conn.cursor()
                    cur.execute(sql, [part for schema, name in batch for part in (schema, name)])
                    rows = cur.fetchall()
                finally:
                    conn.close()
            for r in rows:
                target = SynonymTarget(r[5], r[6], ".".join(p for p in (r[3], r[4]) if p) or None)
                chain = out.setdefault(batch[int(r[0])], [])
                if target not in chain:
                    chain.append(target)
        return out

    def name_binding(self) -> NameBinding:
        # a bare name is the login's default schema's object, else dbo's (the
        # compatibility views ahead of both: dictionary_binding); the database
        # collation decides whether names compare ignoring case (its
        # ComparisonStyle's bit 1)
        sql = (
            "SELECT SCHEMA_NAME(), CONVERT(int, COLLATIONPROPERTY(CONVERT(nvarchar(128), "
            "DATABASEPROPERTYEX(DB_NAME(), 'Collation')), 'ComparisonStyle'))"
        )
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, [])
                row = cur.fetchone()
            finally:
                conn.close()
        default = str(row[0])
        schemas = (default,) if default == "dbo" else (default, "dbo")
        return NameBinding(schemas, ignores_case=bool(int(row[1] or 0) & 1))

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE FROM INFORMATION_SCHEMA.ROUTINES"
        params: list[Any] = []
        if schema:
            sql += " WHERE ROUTINE_SCHEMA = ?"
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
        # sys.dm_db_partition_stats row_count is a catalog estimate. A bare
        # name (schema None) is looked up the way SQL Server resolves it: in
        # the login's default schema, then in dbo.
        joins = (
            "FROM sys.partitions p "
            "JOIN sys.tables t ON p.object_id = t.object_id "
            "JOIN sys.schemas s ON s.schema_id = t.schema_id "
        )
        if schema is None:
            sql = f"SELECT SUM(p.rows) {joins}WHERE s.name = {_BARE_NAME_SCHEMA} AND t.name = ? AND p.index_id IN (0,1)"
            params: list[Any] = [table, table]
        else:
            sql = f"SELECT SUM(p.rows) {joins}WHERE s.name = ? AND t.name = ? AND p.index_id IN (0,1)"
            params = [schema, table]
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(sql, params)
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
        with translated_driver_errors(), self._query_connect(spec.timeout_seconds):
            conn = self._connect()
        start = time.monotonic()
        truncated = False
        cell_truncated_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0
        import json

        try:
            with translated_driver_errors(phase="execute"):
                cur = conn.cursor()
                with self._cursor_lock:
                    self._running_cursor = cur
                # The server cuts (max) and text/image values to this many
                # bytes. nvarchar travels as UTF-16, so twice the cell limit
                # still carries max_cell_bytes + 1 characters and every cut is
                # detected here. Queries only: catalog reads need whole
                # definitions.
                cur.execute(f"SET TEXTSIZE {2 * (spec.max_cell_bytes + 1)}")
                params = tuple(spec.parameters) if isinstance(spec.parameters, list) else spec.parameters
                sql = self._xml_cast(cur, spec.sql, params)
                if params:
                    cur.execute(sql, params)
                else:
                    cur.execute(sql)
                cols = [(d[0], "unknown") for d in cur.description or []]
                col_labels = [
                    getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                    for d in (cur.description or [])
                ]
                while True:
                    batch = cur.fetchmany(next_fetch_size(spec.max_rows, len(rows)))
                    if not batch:
                        break
                    for raw in batch:
                        vals, labels, cut = adapt_row(raw, spec.max_cell_bytes)
                        if not col_labels:
                            col_labels = labels
                        cell_truncated_cols.extend(column_names_at(cols, cut))
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            break
                        rows.append(vals)
                    if truncated:
                        break
                if not truncated:
                    # A statement smuggled past the guard shows up here as a
                    # further result (a rowcount or a result set) or as the
                    # error it raised. This only detects it; the rollback
                    # below undoes it. A statement that reports neither (DDL,
                    # TRUNCATE, WAITFOR, COMMIT, anything after SET NOCOUNT
                    # ON) is not noticed: the rollback undoes the
                    # transactional ones and a COMMIT defeats it, so the
                    # guard is what prevents such batches. A truncated result
                    # is not drained: reading on would make the server run
                    # the rest.
                    try:
                        more = cur.nextset()
                    except Exception as exc:  # noqa: BLE001 - the later statement's own error
                        raise _extra_statement_error(scrub_exception(exc)) from exc
                    if more:
                        raise _extra_statement_error(None)
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
            with self._cursor_lock:
                self._running_cursor = None
            try:
                # Explicit, not left to close(): nothing a query did may
                # outlive the call.
                conn.rollback()
            except Exception:  # noqa: BLE001, S110 - close() below discards the transaction too
                pass
            conn.close()

    def _xml_cast(self, cur: Any, sql: str, params: Any) -> str:
        """The statement with its xml result columns cast to nvarchar(max),
        so the session's TEXTSIZE cuts them too; the statement unchanged when
        it returns none. SET TEXTSIZE does not apply to xml: an xml value
        (a table column, CAST(... AS xml), FOR XML ... TYPE) arrived whole.
        An xml column that cannot be cast exactly (a union, a star over
        several tables, FOR XML ... TYPE as the statement's own clause) is
        refused rather than read whole. xml cannot be compared or sorted, so
        the cast changes no ORDER BY or GROUP BY."""
        columns = self._result_columns(cur, sql, params)
        xml = {i for i, (_name, type_id) in enumerate(columns) if type_id == _MSSQL_XML}
        if not xml:
            return sql
        select = SelectList.locate(statement_body(sql, "tsql"), "tsql")
        rewritten = None
        if select is not None and not any(t.token_type == TokenType.FOR for t in select.outer_tokens()):
            rewritten = select.rewrite(
                [name for name, _type in columns], xml, lambda text: f"CAST({text} AS nvarchar(max))", _bracketed
            )
        if rewritten is None:
            named = ", ".join(repr(columns[i][0] or f"column_{i + 1}") for i in sorted(xml))
            raise ConnectorError(
                f"result column(s) {named} are xml, which SQL Server sends whole (SET TEXTSIZE does not "
                "apply to xml) and which this statement cannot be rewritten to cut; select "
                "CAST(<expression> AS nvarchar(max)) instead, or FOR XML without TYPE",
                category=ErrorCategory.QUERY,
            )
        return rewritten

    @staticmethod
    def _result_columns(cur: Any, sql: str, params: Any) -> list[tuple[str | None, int]]:
        """(name, system_type_id) of each column of the statement's result,
        from sp_describe_first_result_set: SQL Server compiles the statement
        and runs nothing. Its '?' markers become declared parameters; a
        statement whose markers cannot be matched to the values is refused
        (it is not run undescribed)."""
        text, declared = sql, []
        if params and not isinstance(params, (list, tuple)):
            return []  # pyodbc refuses what it cannot bind (a dict) before anything runs
        if params:
            try:
                tokens = sqlglot.Dialect.get_or_raise("tsql").tokenize(sql)
            except Exception:  # noqa: BLE001 - sqlglot's TokenError and the like
                tokens = []
            markers = [t for t in tokens if t.token_type == TokenType.PLACEHOLDER]
            if len(markers) != len(params):
                raise ConnectorError(
                    f"the statement's '?' markers could not be matched to the {len(params)} parameter value(s)",
                    category=ErrorCategory.QUERY,
                )
            for i, marker in reversed(list(enumerate(markers, start=1))):
                text = text[: marker.start] + f"@udbmcp_p{i}" + text[marker.end + 1 :]
            declared = [f"@udbmcp_p{i} {_mssql_parameter_type(v)}" for i, v in enumerate(params, start=1)]
        # sys-qualified, as every catalog name this connector reads is
        cur.execute(
            "EXEC sys.sp_describe_first_result_set @tsql = ?, @params = ?", (text, ", ".join(declared) or None)
        )
        rows = cur.fetchall()
        if not rows:
            return []
        fields = [d[0] for d in cur.description]
        name_at, type_at, hidden_at = fields.index("name"), fields.index("system_type_id"), fields.index("is_hidden")
        return [(row[name_at], int(row[type_at])) for row in rows if not row[hidden_at]]

    def explain(self, sql: str, analyze: bool) -> dict[str, Any]:
        """Estimated plan through SET SHOWPLAN_ALL, on a private connection.

        SHOWPLAN_ALL must be the only statement of its batch, so it is sent
        as its own execute; the statement that follows returns the plan
        rowset instead of running. The account needs the SHOWPLAN database
        permission (db_owner and sysadmin have it; otherwise the DBA grants
        `GRANT SHOWPLAN TO <user>`), which the error names when missing.
        """
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        with translated_driver_errors():
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute("SET SHOWPLAN_ALL ON")
                try:
                    try:
                        cur.execute(sql)
                    except Exception as exc:  # noqa: BLE001
                        if "SHOWPLAN" in str(exc).upper() and "PERMISSION" in str(exc).upper():
                            raise ConnectorError(
                                "SQL Server refused the plan: the account lacks the SHOWPLAN database permission "
                                "(a DBA grants it with GRANT SHOWPLAN TO <user>; no data access is involved)"
                            ) from exc
                        raise
                    cols = [d[0] for d in cur.description]
                    rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
                finally:
                    try:
                        cur.execute("SET SHOWPLAN_ALL OFF")
                    except Exception:  # noqa: BLE001, S110 - the private connection is closed right after
                        pass
            finally:
                conn.close()
        wanted = (
            "StmtText", "NodeId", "Parent", "PhysicalOp", "LogicalOp", "EstimateRows", "EstimateIO", "EstimateCPU",
            "TotalSubtreeCost", "Warnings",
        )
        slim = [{k: (str(r[k]) if r.get(k) is not None else None) for k in wanted if k in r} for r in rows]
        text = "\n".join(str(r.get("StmtText") or "") for r in rows)
        return {"raw": text or None, "rows": slim, "method": "SET SHOWPLAN_ALL (estimated plan), not executed"}
