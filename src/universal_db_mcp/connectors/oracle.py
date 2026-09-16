"""Oracle connector — python-oracledb Thin mode by default; Thick mode opt-in.

Thin mode needs no Oracle Client libraries. Thick mode is deliberately not
implemented in this build: no silent mode switching, no Instant Client
download (spec §5). TLS is enforced via an explicit TCPS connect descriptor
plus an administrator-supplied wallet (refusing plaintext fallback). Wallets
and TNS must be provided by the administrator outside distributable
artifacts. Live behaviors are ``unverified`` until Gate C.
"""

from __future__ import annotations

import re
import sys
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


def _tns_entry(tns_admin: str, alias: str) -> str | None:
    """Return the descriptor text for ``alias`` from ``tns_admin``/tnsnames.ora.

    Entries start at column 0 as ``NAME =`` (or ``NAME, OTHER =``) and run
    until the next such line, so the scan keys on unindented lines.
    """
    path = Path(tns_admin) / "tnsnames.ora"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    entries: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line[:1].strip() and "=" in line:
            names = line.split("=", 1)[0]
            current = None
            for name in names.split(","):
                key = name.strip().upper()
                if key:
                    entries.setdefault(key, [])
                    current = current or key
            if current is not None:
                entries[current].append(line.split("=", 1)[1])
        elif current is not None:
            entries[current].append(line)
    body = entries.get(alias.strip().upper())
    return "\n".join(body) if body is not None else None


def _require_tcps_alias(tns_admin: str, alias: str) -> None:
    """Fail closed unless the alias's descriptor selects TCPS.

    tls.enabled means the operator (and the server's require_remote_tls policy)
    were promised an encrypted wire. On the alias path only tnsnames.ora can
    confirm that, so an unreadable file, an unknown alias or a non-TCPS
    PROTOCOL is refused rather than dialed.
    """
    body = _tns_entry(tns_admin, alias)
    if body is None:
        raise ConnectorError(
            f"oracle tls.enabled with options.tns_alias '{alias}', but that alias was not found "
            f"in {Path(tns_admin) / 'tnsnames.ora'}; the descriptor is the only place the wire "
            "protocol can be confirmed, so the connection is refused instead of risking plaintext"
        )
    protocols = {m.upper() for m in re.findall(r"PROTOCOL\s*=\s*([A-Za-z]+)", body)}
    if not protocols or protocols - {"TCPS"}:
        raise ConnectorError(
            f"oracle tls.enabled with options.tns_alias '{alias}', but its descriptor selects "
            f"{sorted(protocols) or ['no PROTOCOL']} instead of TCPS: the credentials would "
            "travel in plaintext while the TLS policy reported compliance. Point the alias at a "
            "TCPS address, or use the host/port/database form with tls.enabled"
        )


class ThickState:
    """Process-global python-oracledb mode.

    init_oracle_client() switches the ENTIRE interpreter to Thick mode and
    cannot be undone, so it runs once under a lock. Config validation refuses
    a mix of thick and thin oracle connections, so one flag decides the process.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.initialized = False


_THICK_STATE = ThickState()


def _thick_client_remedy() -> str:
    """Platform-correct remediation for a client that will not load.

    python-oracledb's own rule (initialization.rst, DPI-1047 troubleshooting):
    on Linux lib_dir must NOT normally be passed - the client has to be on the
    system library search path before the process starts, and daemons reset
    LD_LIBRARY_PATH, so ldconfig is the reliable route. Windows and macOS do
    use lib_dir. One generic message would send half of all admins the wrong
    way.
    """
    if sys.platform.startswith("linux"):
        return (
            "On Linux, put the Instant Client on the system library search path BEFORE the "
            "process starts: write its directory into /etc/ld.so.conf.d/oracle-instantclient.conf "
            "and run ldconfig (preferred: systemd and other daemons reset LD_LIBRARY_PATH), "
            "install libaio, and keep the client under /opt or /usr/local so the loader may open "
            "it. options.lib_dir works only when libclntsh.so resolves its dependencies with "
            "RPATH=$ORIGIN."
        )
    return (
        "Set options.lib_dir to the Instant Client directory for this platform (for example "
        "/opt/oracle/instantclient_23_5) and make sure its architecture matches this interpreter."
    )


def _enable_thick_mode(module: Any, lib_dir: str | None, tns_admin: str | None) -> None:
    """Load the administrator-supplied Oracle Instant Client, once per process."""
    with _THICK_STATE.lock:
        if _THICK_STATE.initialized:
            return
        is_thin = getattr(module, "is_thin_mode", None)
        if callable(is_thin):
            try:
                already_thick = not is_thin()
            except Exception:  # noqa: BLE001 - a driver without the probe is not an error
                already_thick = False
            if already_thick:
                # init_oracle_client() must always be called with the SAME
                # arguments; an embedding process already enabled Thick mode,
                # so re-initializing could raise on an argument mismatch.
                _THICK_STATE.initialized = True
                return
        kwargs: dict[str, Any] = {}
        if lib_dir:
            kwargs["lib_dir"] = lib_dir
        if tns_admin:
            # Thick mode reads tnsnames.ora from the client config dir given here.
            kwargs["config_dir"] = tns_admin
        try:
            module.init_oracle_client(**kwargs)
        except Exception as exc:
            if "DPY-2019" in str(exc):
                # Ordering, not a missing library: the process already made a
                # Thin connection and the driver cannot switch afterwards.
                # Config validation keeps every oracle connection on the same
                # mode, so this means something else dialed Oracle first.
                raise ConnectorError(
                    "oracle thick_mode could not be enabled because this process already used "
                    f"thin mode ({str(exc).strip()[:120]}). Thick mode is process-global and must "
                    "be enabled before the first oracle connection: make sure every oracle "
                    "connection in the config sets options.thick_mode: true, then restart the "
                    "server so no thin connection precedes it"
                ) from exc
            raise ConnectorError(
                "oracle thick_mode is enabled but the Oracle Instant Client could not be "
                f"loaded ({str(exc).strip()[:160]}). The client is Oracle-licensed and "
                f"administrator-supplied, never shipped in our artifacts. {_thick_client_remedy()}"
            ) from exc
        _THICK_STATE.initialized = True


class OracleConnector(DatabaseConnector):
    engine = "oracle"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_target: Any = None
        self._exec_lock = threading.Lock()  # serializes queries: cancel slot correctness
        self._pool_lock = threading.Lock()
        self._meta_conn: Any = None  # reused metadata connection (probe on checkout)

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
        self._module = open_module("oracledb", "oracledb (manylinux cp312 wheel; Thin or Thick mode)")
        cfg = self.connection.config
        opts = cfg.options
        if opts.get("thick_mode"):
            # Process-global: config validation guarantees every oracle
            # connection agrees on the mode before we get here.
            _enable_thick_mode(self._module, opts.get("lib_dir"), opts.get("tns_admin"))
        if opts.get("tns_alias"):
            # The alias carries its own descriptor from tnsnames.ora; host/port
            # in the config are not used to reach it. That also means the ALIAS
            # decides the wire protocol, so tls.enabled has to be checked
            # against the descriptor - otherwise the policy gate and doctor
            # would report TLS compliance while a TCP alias sent the
            # credentials in plaintext.
            alias_kw: dict[str, Any] = {
                "user": (self.connection.username.value if self.connection.username else None),
                "password": (self.connection.password.value if self.connection.password else None),
                "dsn": opts["tns_alias"],
            }
            if cfg.tls.enabled:
                _require_tcps_alias(opts["tns_admin"], opts["tns_alias"])
                alias_kw["wallet_location"] = opts.get("wallet_location")
            if not opts.get("thick_mode"):
                # Thin mode resolves tnsnames.ora through connect(config_dir=);
                # Thick mode was given the directory in init_oracle_client().
                alias_kw["config_dir"] = opts["tns_admin"]
            return self._dial(alias_kw)
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
            connect_data = (
                f"(SID={opts['sid']})" if opts.get("sid") else f"(SERVICE_NAME={cfg.database})"
            )
            dsn = (
                f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST={cfg.host})"
                f"(PORT={cfg.port or 1521}))(CONNECT_DATA={connect_data}))"
            )
        elif opts.get("sid"):
            # Pre-12c databases register a SID, which the easy-connect service
            # form cannot express; a full descriptor can.
            dsn = (
                f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={cfg.host})"
                f"(PORT={cfg.port or 1521}))(CONNECT_DATA=(SID={opts['sid']})))"
            )
        else:
            dsn = f"{cfg.host}:{cfg.port or 1521}/{cfg.database}"  # service_name form
        kw: dict[str, Any] = {
            "user": (self.connection.username.value if self.connection.username else None),
            "password": (self.connection.password.value if self.connection.password else None),
            "dsn": dsn,
        }
        if cfg.tls.enabled:
            kw["wallet_location"] = opts.get("wallet_location")
            if opts.get("wallet_password"):
                # An orapki wallet protected by a password (ewallet.p12 and the
                # PEM exported from it) cannot be opened without this.
                kw["wallet_password"] = opts["wallet_password"]
        if opts.get("tns_admin") and not opts.get("thick_mode"):
            kw["config_dir"] = opts.get("tns_admin")
        return self._dial(kw)

    def _dial(self, kw: dict[str, Any]) -> Any:
        """connect() with the driver's account-level refusals translated into
        remediation the operator can act on."""
        try:
            conn = self._module.connect(**kw)
        except Exception as exc:
            text = str(exc)
            if "DPY-3015" in text:
                # Seen live 2026-09-15: an account carrying ONLY the legacy 10G
                # verifier. Thin mode supports 11G/12C verifiers only, so name
                # both the server-side and the client-side remedy.
                raise ConnectorError(
                    f"oracle refused this account's password verifier ({text.strip()[:120]}). "
                    "Thin mode supports 11G and 12C verifiers only. Either ask the DBA to run "
                    "ALTER USER <user> IDENTIFIED BY <new password> so a modern verifier is "
                    "generated (sec_case_sensitive_logon must not be FALSE), or set "
                    "options.thick_mode: true with an administrator-supplied Oracle Instant "
                    "Client (options.lib_dir), which still accepts the 10G verifier."
                ) from exc
            raise
        self._configure_session(conn)
        return conn

    def _configure_session(self, conn: Any) -> None:
        """Apply the session safety profile.

        Oracle readers never block writers and there is no session-wide
        read-only (SET TRANSACTION READ ONLY is per transaction and does not
        stop DDL), so the guard stays the write enforcement and the profile
        reports that. What Oracle does offer: module/action/client identifier
        for the DBA's session views, a call timeout, and serializable
        isolation on request.
        """
        prof = self.session_profile
        self._session_reset()
        try:
            conn.module = "udbmcp"
            conn.action = prof.connection_id[:32]
            conn.client_identifier = prof.application_name[:64]
            self._session_applied(f"client_identifier={prof.application_name}")
        except Exception as exc:  # noqa: BLE001
            self._session_skipped("client_identifier", exc)
        if prof.statement_timeout_seconds:
            try:
                conn.call_timeout = int(prof.statement_timeout_seconds * 1000)
                self._session_applied(f"call_timeout={conn.call_timeout}ms")
            except Exception as exc:  # noqa: BLE001
                self._session_skipped("call_timeout", exc)
        if prof.isolation == "serializable":
            try:
                with conn.cursor() as cur:
                    cur.execute("ALTER SESSION SET ISOLATION_LEVEL = SERIALIZABLE")
                self._session_applied("isolation=serializable")
            except Exception as exc:  # noqa: BLE001
                raise self._session_required("isolation serializable", exc) from exc

    def _session_readback(self, conn: Any) -> dict[str, Any]:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sys_context('USERENV','MODULE'), sys_context('USERENV','CLIENT_IDENTIFIER') "
                    "FROM dual"
                )
                row = cur.fetchone()
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 2:
            return {}
        return {"module": str(row[0]), "client_identifier": str(row[1])}

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
            driver="python-oracledb (Thin mode; opt-in Thick mode via admin-supplied Instant Client)",
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
                    detail=(
                        "Thick mode is opt-in (options.thick_mode + administrator-supplied "
                        "Oracle Instant Client, never bundled or fetched); Thin mode is the "
                        "default and refuses accounts that carry only the legacy 10G password "
                        "verifier."
                    ),
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
                    # v$version is an administrative view: the least-privilege
                    # account our own docs prescribe (CREATE SESSION + table
                    # SELECTs) cannot read it. Reporting such a connection as
                    # unhealthy sent operators chasing connectivity problems
                    # that did not exist, so the version is best-effort and the
                    # liveness probe is privilege-free.
                    row = None
                    try:
                        cur.execute("SELECT banner FROM v$version WHERE rownum = 1")
                        row = cur.fetchone()
                    except Exception:  # noqa: BLE001 - version is optional
                        cur.execute("SELECT 1 FROM DUAL")
                        cur.fetchone()
                session = self.session_report(self._session_readback(conn))
            finally:
                conn.close()
            return HealthInfo(
                healthy=True,
                server_version=str(row[0])[:60] if row else None,
                latency_ms=int((time.monotonic() - start) * 1000),
                session=session,
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
        with translated_driver_errors():
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
        with translated_driver_errors():
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
        with translated_driver_errors():
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

    def placeholder(self, index: int) -> str:
        return f":{index}"

    def build_search_query(
        self, schema: str | None, table: str, select_columns: list[str], where_sql: str, limit: int
    ) -> str:
        cols = ", ".join(self.quote_identifier(c) for c in select_columns) if select_columns else "*"
        qualified = (
            f"{self.quote_identifier(schema)}.{self.quote_identifier(table)}"
            if schema
            else self.quote_identifier(table)
        )
        return f"SELECT * FROM (SELECT {cols} FROM {qualified} WHERE {where_sql}) WHERE ROWNUM <= {int(limit)}"

    def build_top_values_query(self, sample_sql: str, column: str, limit: int) -> str:
        q = self.quote_identifier(column)
        inner = (
            f"SELECT {q} AS v, COUNT(*) AS cnt FROM ({sample_sql}) s "
            f"WHERE {q} IS NOT NULL GROUP BY {q} ORDER BY cnt DESC"
        )
        return f"SELECT * FROM ({inner}) WHERE ROWNUM <= {int(limit)}"

    def list_all_columns(self, schema: str | None) -> list[ColumnInfo]:
        sql = (
            "SELECT table_name, column_name, data_type, nullable, data_default, column_id "
            "FROM all_tab_columns WHERE owner = :1 ORDER BY table_name, column_id"
        )
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, [schema])
                rows = cur.fetchall()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=r[2], nullable=r[3] == "Y",
                       default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        sql = (
            "SELECT i.table_name, i.index_name, i.uniqueness, ic.column_name, ic.column_position, i.index_type, "
            "(SELECT MAX(c.constraint_type) FROM all_constraints c "
            " WHERE c.owner = i.owner AND c.index_name = i.index_name AND c.constraint_type = 'P') "
            "FROM all_indexes i JOIN all_ind_columns ic "
            "ON ic.index_owner = i.owner AND ic.index_name = i.index_name "
            "WHERE i.table_owner = :1"
        )
        params: list[Any] = [schema]
        if table:
            sql += " AND i.table_name = :2"
            params.append(table)
        sql += " ORDER BY i.table_name, i.index_name, ic.column_position"
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        grouped: dict[tuple[str, str], IndexInfo] = {}
        for tname, iname, uniq, col, _pos, itype, pk in rows:
            info = grouped.get((tname, iname))
            if info is None:
                info = IndexInfo(name=iname, columns=[], unique=(str(uniq).upper() == "UNIQUE"),
                                 primary=(pk == "P"), kind=str(itype).lower(), schema=schema, table=tname)
                grouped[(tname, iname)] = info
            info.columns.append(str(col))
        return list(grouped.values())

    def list_views(self, schema: str | None) -> list[ViewInfo]:
        sql = "SELECT owner, view_name, text FROM all_views"
        params: list[Any] = []
        if schema:
            sql += " WHERE owner = :1"
            params.append(schema)
        sql += " ORDER BY 1, 2"
        with translated_driver_errors():
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
        with translated_driver_errors():
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
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        return [RoutineInfo(schema=r[0], name=r[1], kind=r[2].lower()) for r in rows]

    def get_foreign_keys(self, schema: str | None, table: str | None) -> list[KeyInfo]:
        # ALL_CONS_COLUMNS on both sides, matched by POSITION so composite
        # keys line up; the previous statement returned no column names at
        # all, which left relationship inference with empty key lists.
        sql = (
            "SELECT a.constraint_name, a.owner, a.table_name, a.r_owner, b.table_name, "
            "ac.column_name, bc.column_name, ac.position "
            "FROM all_constraints a "
            "JOIN all_constraints b ON a.r_constraint_name = b.constraint_name AND a.r_owner = b.owner "
            "JOIN all_cons_columns ac ON ac.owner = a.owner AND ac.constraint_name = a.constraint_name "
            "JOIN all_cons_columns bc ON bc.owner = b.owner AND bc.constraint_name = b.constraint_name "
            "AND bc.position = ac.position "
            "WHERE a.constraint_type = 'R'"
        )
        params: list[Any] = []
        if schema:
            sql += " AND a.owner = :1"
            params.append(schema)
        if table:
            sql += f" AND a.table_name = :{len(params) + 1}"
            params.append(table)
        sql += " ORDER BY a.constraint_name, ac.position"
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        grouped: dict[tuple[str, str, str], KeyInfo] = {}
        for name, owner, tname, r_owner, r_table, col, ref_col, _pos in rows:
            key = (str(name), str(owner), str(tname))
            info = grouped.get(key)
            if info is None:
                info = KeyInfo(
                    kind="foreign_key", name=name, columns=[], ref_schema=r_owner, ref_table=r_table,
                    ref_columns=[], source_schema=owner, source_table=tname,
                )
                grouped[key] = info
            info.columns.append(str(col))
            info.ref_columns.append(str(ref_col))
        return list(grouped.values())

    def get_statistics(self, schema: str | None, table: str) -> dict[str, Any]:
        sql = "SELECT num_rows, last_analyzed FROM all_tables WHERE owner = :1 AND table_name = :2"
        with translated_driver_errors():
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
        with translated_driver_errors():
            conn = self._connect()
            self._cancel_target = conn
            start = time.monotonic()
            truncated = False
            truncation_cause = "row limit"
            cell_truncated_cols: list[str] = []
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
                            vals, _labels, cell_tr = cell_truncated_json(raw, spec.max_cell_bytes)
                            if cell_tr:
                                cell_truncated_cols.extend(truncated_column_names(cols, raw, spec.max_cell_bytes))
                            approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                            if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                                truncated = True
                                truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                                conn.cancel()  # stop server-side work
                                break
                            rows.append(vals)
                        if truncated:
                            break
                warnings = [f"result truncated by {truncation_cause}"] if truncated else []
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
        # ROWNUM, not FETCH FIRST: the latter is 12c syntax and Thick mode
        # reaches Oracle 11.2, exactly the servers that still carry 10G
        # verifiers. ROWNUM is valid on every supported release.
        return f"SELECT * FROM (SELECT {cols} FROM {qualified}) WHERE ROWNUM <= {int(limit)}"
