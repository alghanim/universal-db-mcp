"""Oracle connector — python-oracledb Thin mode by default; Thick mode opt-in.

Thin mode needs no Oracle Client libraries. Thick mode is deliberately not
implemented in this build: no silent mode switching, no Instant Client
download (spec §5). TLS is enforced via an explicit TCPS connect descriptor
plus an administrator-supplied wallet (refusing plaintext fallback). Wallets
and TNS must be provided by the administrator outside distributable
artifacts. Live behaviors are ``unverified`` until Gate C.
"""

from __future__ import annotations

import array
import json
import re
import sys
import threading
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import sqlglot
from sqlglot import TokenType, exp

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
    FETCH_BATCH,
    adapt_row,
    cell_truncation_warning,
    column_names_at,
    next_fetch_size,
    open_module,
    synonym_chains,
    synonym_names_refused_view,
    translated_driver_errors,
)
from universal_db_mcp.discovery.system_schemas import SYSTEM_SCHEMAS, is_data_free_table, is_session_sql_view
from universal_db_mcp.models.capabilities import Cap, CapabilityMatrix, CapabilityState, Limitation
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy, unquoted_name
from universal_db_mcp.security.redact import scrub_exception


def _net_quoted(field: str, value: str) -> str:
    """Double-quote a value for an Oracle Net connect descriptor.

    python-oracledb writes MY_WALLET_DIRECTORY and SSL_SERVER_CERT_DN
    unquoted, which Oracle Net misreads once a path holds a space or a
    parenthesis. A double quote cannot be carried inside the quotes, and
    ')(' or a control character would start a new descriptor clause wherever
    the value ended up unquoted, so those are refused.
    """
    if '"' in value or ")(" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConnectorError(
            f"oracle {field} contains a double quote, ')(' or a control character, which an Oracle "
            "Net connect descriptor cannot carry safely; change that value"
        )
    return f'"{value}"'


def _tls_security(wallet: str) -> str:
    """The SECURITY clause of a TCPS descriptor: host-name matching and the
    wallet. It has to be IN the descriptor: Thick mode hands the descriptor
    to the Oracle Client unchanged (thick_mode_dsn_passthrough), so wallet
    keywords given to connect() never reach it."""
    return (
        "(SECURITY=(SSL_SERVER_DN_MATCH=ON)"
        f"(MY_WALLET_DIRECTORY={_net_quoted('options.wallet_location', wallet)}))"
    )


def _as_list(value: Any) -> list[Any]:
    """ConnectParams reports one value per description, flattened when there is one."""
    return value if isinstance(value, list) else [value]


def _tcps_alias_descriptor(module: Any, tns_admin: str, alias: str, wallet: str) -> str:
    """Resolve ``alias`` with python-oracledb's own tnsnames.ora reader and
    return the TCPS descriptor to dial in its place.

    tls.enabled means the operator (and the server's require_remote_tls
    policy) were promised an encrypted wire. The check reads the alias the
    way the driver does (IFILE includes, the last definition winning,
    multi-name entries, continuation lines), and the checked descriptor,
    not the alias, is dialed so nothing can resolve it differently later.
    Anything that cannot be confirmed is refused rather than dialed.
    """
    quoted_wallet = _net_quoted("options.wallet_location", wallet)
    try:
        params = module.ConnectParams(config_dir=tns_admin)
        params.parse_connect_string(alias)
    except Exception as exc:  # noqa: BLE001 - any resolution failure is a refusal
        reason = scrub_exception(exc)[:160]
        code = getattr(exc.args[0] if exc.args else None, "full_code", None)
        if code in ("DPY-4000", "DPY-4026"):  # no such alias, no readable tnsnames.ora
            detail = (
                f"the alias could not be found in {Path(tns_admin) / 'tnsnames.ora'} ({reason}). An alias "
                "that only a directory server (LDAP) resolves cannot be checked: use the host/port/database "
                "form with tls.enabled"
            )
        else:
            detail = (
                f"python-oracledb could not parse its entry in {Path(tns_admin) / 'tnsnames.ora'} ({reason}). "
                "Its reader does not take some Oracle Client spellings that the Client itself accepts: write "
                "SSL_VERSION as TLSv1.2 or TLSv1.3, and SSL_CIPHER_SUITES without parentheses"
            )
        raise ConnectorError(
            f"oracle tls.enabled with options.tns_alias '{alias}', but {detail}. The descriptor is the only "
            "place the wire protocol can be confirmed, so the connection is refused instead of risking plaintext"
        ) from exc
    protocols = [str(p).lower() for p in _as_list(params.protocol)]
    if not protocols or any(p != "tcps" for p in protocols):
        raise ConnectorError(
            f"oracle tls.enabled with options.tns_alias '{alias}', but its descriptor selects "
            f"{sorted(set(protocols)) or ['no PROTOCOL']} instead of TCPS only: the credentials would "
            "travel in plaintext while the TLS policy reported compliance. Point the alias at TCPS "
            "addresses only, or use the host/port/database form with tls.enabled"
        )
    if not all(_as_list(params.ssl_server_dn_match)):
        raise ConnectorError(
            f"oracle tls.enabled with options.tns_alias '{alias}', but its descriptor turns "
            "SSL_SERVER_DN_MATCH off: any certificate the CA issued, for any host, would be "
            "accepted. Remove that setting from the alias"
        )
    params.set(wallet_location=wallet)
    descriptor: str = params.get_connect_string()
    # The driver renders these values unquoted; Oracle Net needs the quotes.
    descriptor = descriptor.replace(f"(MY_WALLET_DIRECTORY={wallet})", f"(MY_WALLET_DIRECTORY={quoted_wallet})")
    for dn in {dn for dn in _as_list(params.ssl_server_cert_dn) if dn}:
        descriptor = descriptor.replace(
            f"(SSL_SERVER_CERT_DN={dn})", f"(SSL_SERVER_CERT_DN={_net_quoted('SSL_SERVER_CERT_DN', dn)})"
        )
    return descriptor


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


def _enable_thin_mode(module: Any) -> None:
    """Fix Thin mode before connecting. Left to itself, python-oracledb
    decides the mode inside the process's first connect and holds its
    driver-mode lock until that connect returns, so one listener that
    accepts and never answers blocked every other Oracle connect, healthy
    servers included. Fixing the mode takes no network round trip, and once
    it is fixed the lock is never waited on again (a no-op from then on)."""
    enable = getattr(module, "enable_thin_mode", None)
    if callable(enable):
        enable()


# Dictionary owners list_tables leaves out on servers before 12c, where
# ALL_USERS has no ORACLE_MAINTAINED flag to ask instead.
_ORACLE_SYSTEM_OWNERS = tuple(sorted(s.upper() for s in SYSTEM_SCHEMAS["oracle"]))
# Names looked up per synonym_chains statement: two binds each, far below
# Oracle's limit, however many a statement at the size ceiling names.
_SYNONYM_BATCH = 200


def _server_major(conn: Any) -> int | None:
    """Major release of the connected server from python-oracledb's
    Connection.version ('19.3.0.0.0'); None when it cannot be read."""
    try:
        return int(str(conn.version).split(".", 1)[0])
    except (AttributeError, ValueError):
        return None


# Types python-oracledb decodes whole on fetch, for every row the fetch
# carries, before the cell limit can apply: native JSON, LONG, LONG RAW,
# object and collection types, and XMLType in Thick mode (Thin reads an
# XMLType past a few KB through a LOB: 20 rows of 6 MB, 40 MB maxrss live).
_DECODED_WHOLE = frozenset({"DB_TYPE_JSON", "DB_TYPE_LONG", "DB_TYPE_LONG_RAW", "DB_TYPE_OBJECT"})
_DECODED_WHOLE_THICK = _DECODED_WHOLE | {"DB_TYPE_XMLTYPE"}
# Most rows a fetch of such values carries (see _execute): their size is
# unknown until they are decoded, so this is the most large values one
# round trip can bring (32 small rows then 32 documents of 6 MB: 404 MB).
_WHOLE_BATCH_MAX = 4
_TEXT_LOBS = frozenset({"DB_TYPE_CLOB", "DB_TYPE_NCLOB"})
_BINARY_LOBS = frozenset({"DB_TYPE_BLOB", "DB_TYPE_BFILE"})
_UNREADABLE_BFILE = object()


def _is_dbobject(v: Any) -> bool:
    """A python-oracledb DbObject: its type is a DbObjectType (a LOB's type
    is a DbType, which has no iscollection)."""
    return getattr(getattr(v, "type", None), "iscollection", None) is not None


def _dbobject_value(obj: Any, max_cell_bytes: int, budget: list[int]) -> Any:
    """A DbObject (an object type, a VARRAY, a nested table) as the dict or
    list its JSON form needs: str() of one is only its repr. Elements are
    converted only while that form can still fit the cell limit (``budget``
    counts down the characters left); the ones after cannot survive the cut,
    which the form, already longer than the limit, still shows."""
    kind = obj.type
    if kind.iscollection:
        items: list[Any] = []
        index = obj.first()
        while index is not None and budget[0] > 0:
            items.append(_dbobject_element(obj.getelement(index), max_cell_bytes, budget))
            index = obj.next(index)
        return items
    fields: dict[str, Any] = {}
    for attribute in kind.attributes:
        if budget[0] <= 0:
            break
        fields[attribute.name] = _dbobject_element(getattr(obj, attribute.name), max_cell_bytes, budget)
    return fields


def _dbobject_element(v: Any, max_cell_bytes: int, budget: list[int]) -> Any:
    if _is_dbobject(v):
        return _dbobject_value(v, max_cell_bytes, budget)
    cell = _oracle_cell(v, max_cell_bytes)
    cell = None if cell is _UNREADABLE_BFILE else cell
    budget[0] -= len(json.dumps(cell, default=str)) + 1
    return cell


def _oracle_cell(v: Any, max_cell_bytes: int) -> Any:
    """python-oracledb values the generic adapter cannot bound.

    A LOB is read only up to one unit past the cell limit (characters for
    CLOB/NCLOB, bytes for BLOB/BFILE), enough for the cut to show; str(lob)
    would read it whole (and fails on a BLOB). A BFILE the server cannot
    open is ``_UNREADABLE_BFILE``. VECTOR values (array.array, SparseVector)
    and objects and collections (DbObject) become the lists and dicts their
    JSON form needs.
    """
    if _is_dbobject(v):
        return _dbobject_value(v, max_cell_bytes, [max_cell_bytes + 1])
    lob = getattr(getattr(v, "type", None), "name", None)
    if lob in _TEXT_LOBS or lob in _BINARY_LOBS:
        try:
            size = v.size()
            empty: str | bytes = "" if lob in _TEXT_LOBS else b""
            return v.read(1, min(size, max_cell_bytes + 1)) if size else empty
        except Exception:  # noqa: BLE001 - a missing file or directory grant
            if lob == "DB_TYPE_BFILE":
                return _UNREADABLE_BFILE
            raise
    if isinstance(v, array.array):
        return v.tolist()
    if hasattr(v, "num_dimensions") and hasattr(v, "indices") and hasattr(v, "values"):
        return {"num_dimensions": v.num_dimensions, "indices": list(v.indices), "values": list(v.values)}
    return v


def _oracle_type(data_type: Any, char_len: Any, precision: Any, scale: Any) -> str:
    """VARCHAR2(200), NUMBER(12,2), NUMBER(10); NUMBER with no precision stays
    bare (an unconstrained float), as do TIMESTAMP(6) and friends."""
    base = str(data_type or "")
    up = base.upper()
    if up in ("VARCHAR2", "NVARCHAR2", "CHAR", "NCHAR", "RAW") and char_len:
        return f"{base}({int(char_len)})"
    if up == "NUMBER" and precision is not None:
        return f"{base}({int(precision)},{int(scale)})" if scale else f"{base}({int(precision)})"
    return base


# The guard lets every statement read a bare DUAL (DATA_FREE_TABLES), which
# Oracle names SYS.DUAL through the PUBLIC synonym only when the session's
# current schema holds no object of that name: a table, view or private
# synonym called DUAL there is read in its place, past the allowlists and
# masking (review, 2026-09-28: a TRAVEL.DUAL view over TRAVELLERS answered
# FROM DUAL under allowed_schemas [HR]). Any object of that name counts; one
# in another namespace (an index) only costs the bare spelling. SYS's own
# DUAL is the dummy table. ALL_OBJECTS shows every object of the login's own
# schema, but not another schema's private synonyms (live: with a logon's
# CURRENT_SCHEMA = SYSTEM it listed none, while a bare TAB read through
# SYSTEM.TAB), so a current schema other than the login's is not answered.
# The check names SYS.ALL_OBJECTS: a bare ALL_OBJECTS is looked up in the
# same current schema first (review, 2026-09-28: a TRAVEL.ALL_OBJECTS view
# with no rows made TRAVEL.DUAL pass the check). sys_context is a built-in
# no schema function can shadow.
_SHADOWED_DUAL = (
    "SELECT sys_context('USERENV', 'CURRENT_SCHEMA'), sys_context('USERENV', 'SESSION_USER'), COUNT(*) "
    "FROM sys.all_objects "
    "WHERE owner = sys_context('USERENV', 'CURRENT_SCHEMA') AND object_name = 'DUAL' AND owner <> 'SYS'"
)
_DUAL_WORD = re.compile(r"(?i)\bdual\b")


def _names_bare_dual(sql: str) -> bool:
    """Whether ``sql`` reads a DUAL no schema names, spelled as the guard
    admits one (unquoted in any case, or "DUAL"); True for a statement that
    mentions the word and that sqlglot cannot read. A DUAL named with a
    database link ("DUAL"@lnk, sqlglot's alias Parameter) is another
    database's, which the local session's answer says nothing about: it is
    never this bare DUAL (_db_link refuses it)."""
    if not _DUAL_WORD.search(sql):
        return False
    try:
        tree = sqlglot.parse_one(sql, read="oracle")
    except Exception:  # noqa: BLE001 - sqlglot's errors, and whatever else a parser raises
        return True
    return any(
        isinstance(t.this, exp.Identifier)
        and not t.args.get("db")
        and not t.args.get("catalog")
        and t.find(exp.Parameter) is None
        and is_data_free_table("oracle", None, t.name if t.this.quoted else unquoted_name("oracle", t.name))
        for t in tree.find_all(exp.Table)
    )


# Tokens that carry an '@' as data: literals, quoted identifiers (Oracle
# takes any character in one) and optimizer hints (query block names, as in
# FULL(@sel$2 t)). Comments never become tokens.
_DATA_TOKENS = frozenset({
    TokenType.STRING, TokenType.NATIONAL_STRING, TokenType.RAW_STRING, TokenType.BIT_STRING,
    TokenType.HEX_STRING, TokenType.BYTE_STRING, TokenType.HEREDOC_STRING, TokenType.UNICODE_STRING,
    TokenType.IDENTIFIER, TokenType.HINT,
})


def _db_link(sql: str) -> str | None:
    """What names a database link in ``sql``: the first token with an '@'
    outside a literal, a quoted identifier, a hint and a comment (t@lnk,
    "T"@lnk, t @lnk, t/**/@lnk, t@ lnk); the statement itself when it cannot
    be tokenized, or when it holds an alternative-quoted literal (q'{...}',
    nq'!...!'), which sqlglot reads as the name q and ordinary strings, so
    code Oracle reads after that literal can sit inside one of those strings
    (review, 2026-09-28: SELECT q'{'}', n FROM t@lnk --'); None when there
    is none. Oracle SQL has no other use for an '@' (its binds are :name)."""
    if "@" not in sql:
        return None
    try:
        tokens = sqlglot.tokenize(sql, read="oracle")
    except Exception:  # noqa: BLE001 - sqlglot's errors, and whatever else a tokenizer raises
        return sql
    for token in tokens:
        if token.token_type in _DATA_TOKENS:
            continue
        if token.text.lower() in ("q", "nq") and sql[token.end + 1 : token.end + 2] == "'":
            return sql
        if "@" in token.text:
            return token.text
    return None


class OracleConnector(DatabaseConnector):
    engine = "oracle"

    def __init__(self, connection: ResolvedConnection, policy: EffectivePolicy) -> None:
        super().__init__(connection, policy)
        self._module: Any = None
        self._cancel_target: Any = None
        # Set by cancel_current while a query is in progress: a break
        # reaches only a call in progress, so the statement, which starts
        # after a round trip of its own, looks here first.
        self._cancelled = threading.Event()
        self._executing = False
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
                        cur.execute("SELECT 1 FROM SYS.DUAL")
                    return self._meta_conn
                except Exception:  # noqa: BLE001, S110 - stale connection, rebuild
                    self._discard_meta_conn()
            self._meta_conn = self._connect()
            return self._meta_conn

    def _discard_meta_conn(self) -> None:
        """Close and forget the shared metadata connection (caller holds
        ``_pool_lock``). Close errors are irrelevant: the object is dropped."""
        conn, self._meta_conn = self._meta_conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass

    def close(self) -> None:
        with self._pool_lock:
            self._discard_meta_conn()

    def _connect(self) -> Any:
        self._module = open_module("oracledb", "oracledb (manylinux cp312 wheel; Thin or Thick mode)")
        cfg = self.connection.config
        opts = cfg.options
        if opts.get("thick_mode"):
            # Process-global: config validation guarantees every oracle
            # connection agrees on the mode before we get here.
            _enable_thick_mode(self._module, opts.get("lib_dir"), opts.get("tns_admin"))
        else:
            _enable_thin_mode(self._module)
        tls_kw: dict[str, Any] = {}
        if cfg.tls.enabled:
            wallet = opts.get("wallet_location")
            if not wallet:
                raise ConnectorError(
                    "oracle tls.enabled=true requires options.wallet_location "
                    "(administrator-supplied, outside distributable artifacts); "
                    "refusing a plaintext connection"
                )
            tls_kw["wallet_location"] = wallet
            if opts.get("wallet_password"):
                # An orapki wallet protected by a password (ewallet.p12 and the
                # PEM exported from it) cannot be opened without this.
                tls_kw["wallet_password"] = opts["wallet_password"]
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
                **tls_kw,
            }
            if cfg.tls.enabled:
                alias_kw["dsn"] = _tcps_alias_descriptor(
                    self._module, opts["tns_admin"], opts["tns_alias"], tls_kw["wallet_location"]
                )
            if not opts.get("thick_mode"):
                # Thin mode resolves tnsnames.ora through connect(config_dir=);
                # Thick mode was given the directory in init_oracle_client().
                alias_kw["config_dir"] = opts["tns_admin"]
            return self._dial(alias_kw)
        if cfg.tls.enabled:
            # TCPS must be selected by the connect descriptor itself; setting
            # wallet parameters alone leaves the wire protocol as plaintext.
            connect_data = (
                f"(SID={opts['sid']})" if opts.get("sid") else f"(SERVICE_NAME={cfg.database})"
            )
            dsn = (
                f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST={cfg.host})"
                f"(PORT={cfg.port or 1521}))(CONNECT_DATA={connect_data})"
                f"{_tls_security(tls_kw['wallet_location'])})"
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
            **tls_kw,
        }
        if opts.get("tns_admin") and not opts.get("thick_mode"):
            kw["config_dir"] = opts.get("tns_admin")
        return self._dial(kw)

    def _dial(self, kw: dict[str, Any]) -> Any:
        """connect() with the driver's account-level refusals translated into
        remediation the operator can act on."""
        try:
            # Thin mode's default is 20 s, longer than the metadata and health
            # deadlines: a down host then read as a query timeout. Thick mode
            # with a pass-through descriptor ignores it.
            conn = self._module.connect(
                **kw, tcp_connect_timeout=float(self.connection.config.connect_timeout_seconds)
            )
        except Exception as exc:
            text = str(exc)
            if "DPY-3015" in text:
                # Seen live 2026-09-15 (account carrying ONLY the 10G verifier)
                # and 2026-09-20 (Oracle 12c account carrying 10G 11G 12C, where
                # sec_case_sensitive_logon=FALSE made the server authenticate
                # with 10G anyway). Thin mode implements 11G/12C only, so name
                # what to check and both remedies.
                raise ConnectorError(
                    f"oracle authenticated this session with the legacy 10G verifier, which thin mode "
                    f"does not implement ({text.strip()[:120]}). Check both: "
                    "SELECT password_versions FROM dba_users WHERE username = '<user>' (only '10G' means "
                    "the account has no modern verifier), and SHOW PARAMETER sec_case_sensitive_logon "
                    "(FALSE forces the 10G path even when the account carries 11G and 12C). The client-side "
                    "fix for every case is options.thick_mode: true with an administrator-supplied Oracle "
                    "Instant Client, which still accepts the old protocol and needs no server change. "
                    "Server-side alternatives, both of which affect other clients: ALTER USER <user> "
                    "IDENTIFIED BY <new password> to generate a modern verifier, or "
                    "ALTER SYSTEM SET sec_case_sensitive_logon = TRUE."
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
        isolation on request. No session setting changes how Oracle reads
        statement text (strings take no backslash escapes, q'[...]' and
        quoted identifiers are always on; NLS settings convert values, they
        do not lex), so there is none to hold where the guard parses.
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
                    "FROM SYS.DUAL"
                )
                row = cur.fetchone()
        except Exception:  # noqa: BLE001 - reporting only
            return {}
        if not row or len(row) < 2:
            return {}
        return {"module": str(row[0]), "client_identifier": str(row[1])}

    def _refuse_db_link(self, sql: str) -> None:
        """Refuse ``sql`` when it names a database link (_db_link), before a
        session is opened. An object read through one is another database's,
        which no allowlist of this connection governs, whatever name the
        guard resolved it to here (review, 2026-09-28: "DUAL"@lnk, t @lnk and
        t/**/@lnk passed the guard and reached Oracle as link reads)."""
        if _db_link(sql) is not None:
            raise ConnectorError(
                f"database links (@link) are not permitted on connection '{self.connection.name}': the statement "
                "names an object with '@' outside a string, a quoted name or a comment, which Oracle reads on "
                "another database (with a q'...' literal, any '@' counts: where that literal ends is not read "
                "here)",
                category=ErrorCategory.POLICY,
            )

    def _refuse_shadowed_dual(self, conn: Any, sql: str) -> None:
        """Refuse ``sql`` when it reads a bare DUAL (_names_bare_dual) that
        this session resolves to an object of its current schema, not to
        SYS.DUAL, or where that cannot be told (_SHADOWED_DUAL). Asked in
        the session that runs it."""
        if not _names_bare_dual(sql):
            return
        with conn.cursor() as cur:
            cur.execute(_SHADOWED_DUAL)
            schema, login, owned = cur.fetchone()
        refusal = f"a bare DUAL on connection '{self.connection.name}'"
        if owned:
            raise ConnectorError(
                f"{refusal} names {schema}.DUAL, an object of the session's current schema, not the dummy "
                f"table SYS.DUAL every connection may read; write SYS.DUAL, or {schema}.DUAL for that object, "
                "which the allowlists then decide",
                category=ErrorCategory.AUTHZ,
            )
        if schema not in (login, "SYS"):
            raise ConnectorError(
                f"{refusal} is looked up in the session's current schema {schema}, set at logon for the "
                f"account {login}, which cannot see every object of that schema: a DUAL there would be read in "
                "place of the dummy table SYS.DUAL; write SYS.DUAL",
                category=ErrorCategory.AUTHZ,
            )

    def cancel_current(self) -> bool:
        if self._executing:
            self._cancelled.set()
        target = self._cancel_target
        if target is not None:
            try:
                target.cancel()  # oracledb: issues OCI break; Thin-supported
                return True
            except Exception:  # noqa: BLE001, S110
                return False
        return self._executing  # still connecting: the statement will not start

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
                    detail="EXPLAIN PLAN writes into PLAN_TABLE, the session-private "
                    "global temporary table every account has since 10g (nothing is "
                    "provisioned or created); rows are deleted after read-back and the "
                    "statement never executes.",
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
                Limitation(
                    scope="query",
                    detail="CLOB, NCLOB, BLOB and BFILE values are read through their locators up to the "
                    "cell limit. Native JSON, LONG, LONG RAW and object or collection values (XMLType in "
                    "Thick mode) are decoded whole by the driver: such a result starts at one row per fetch "
                    f"and doubles it up to {_WHOLE_BATCH_MAX} while those values stay within the cell limit, so a "
                    f"result whose first rows are small can still bring up to {_WHOLE_BATCH_MAX} large values at "
                    f"once. Such a result takes a round trip per {_WHOLE_BATCH_MAX} rows at most (about 250 for "
                    "1000 rows, some 25 s at a 100 ms round-trip time): over a slow link, ask for fewer rows.",
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
                    # liveness probe is privilege-free. SYS.V_$VERSION is
                    # what the PUBLIC synonym V$VERSION names; a login
                    # schema's own V$VERSION would be read before it.
                    row = None
                    try:
                        cur.execute("SELECT banner FROM sys.v_$version WHERE rownum = 1")
                        row = cur.fetchone()
                    except Exception:  # noqa: BLE001 - version is optional
                        cur.execute("SELECT 1 FROM SYS.DUAL")
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
        sql = "SELECT username FROM sys.all_users"
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
        if not kinds & {"table", "view"}:
            return []
        params: list[Any] = []

        def bind(value: Any) -> str:
            params.append(value)
            return f":{len(params)}"

        with translated_driver_errors():
            conn = self._shared_meta_conn()
            # Dictionary owners are not data unless the administrator allowed
            # them: returning them would turn them into resolver entries under
            # the default config. 12c and later flag them; older servers get
            # the known list.
            major = _server_major(conn)
            maintained = major is not None and major >= 12
            opened = sorted(s.upper() for s in self._opened_schemas())
            hidden = [o for o in _ORACLE_SYSTEM_OWNERS if o not in opened]
            arms: list[str] = []
            for kind, view, name_col in (
                ("TABLE", "sys.all_tables", "table_name"), ("VIEW", "sys.all_views", "view_name")
            ):
                if kind.lower() not in kinds:
                    continue
                conds: list[str] = []
                if maintained:
                    kept = "owner IN (SELECT username FROM sys.all_users WHERE oracle_maintained = 'N')"
                    if opened:
                        kept = f"({kept} OR owner IN ({', '.join(bind(o) for o in opened)}))"
                    conds.append(kept)
                elif hidden:
                    conds.append("owner NOT IN (" + ", ".join(bind(o) for o in hidden) + ")")
                if schema:
                    conds.append(f"owner = {bind(schema)}")
                if search:
                    conds.append(f"{name_col} LIKE {bind(f'%{search}%')}")
                where = " WHERE " + " AND ".join(conds) if conds else ""
                arms.append(f"SELECT owner, {name_col}, '{kind}' FROM {view}{where}")
            sql = " UNION ALL ".join(arms) + " ORDER BY 1, 2"
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        tables = [
            TableSummary(schema=r[0], name=r[1], kind=r[2].lower())
            for r in rows
            if not is_session_sql_view(self.engine, r[0], r[1])
        ]
        # a dictionary owner as the policy tells one: the APEX_nnnnnn pattern
        # too, and not PDBADMIN, where sites keep application tables
        return own_objects_first(tables, self.policy.is_system_schema)

    def list_columns(self, schema: str | None, table: str) -> list[ColumnInfo]:
        sql = (
            "SELECT column_name, data_type, nullable, data_default, column_id, "
            "char_length, data_precision, data_scale "
            "FROM sys.all_tab_columns WHERE owner = :1 AND table_name = :2 ORDER BY column_id"
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
                data_type=_oracle_type(r[1], r[5], r[6], r[7]),
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
            "SELECT table_name, column_name, data_type, nullable, data_default, column_id, "
            "char_length, data_precision, data_scale "
            "FROM sys.all_tab_columns WHERE owner = :1 ORDER BY table_name, column_id"
        )
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, [schema])
                rows = cur.fetchall()
        return [
            ColumnInfo(schema=schema, table=r[0], name=r[1], data_type=_oracle_type(r[2], r[6], r[7], r[8]),
                       nullable=r[3] == "Y", default=r[4], ordinal=r[5])
            for r in rows
        ]

    def list_indexes(self, schema: str | None, table: str | None) -> list[IndexInfo]:
        sql = (
            "SELECT i.table_name, i.index_name, i.uniqueness, ic.column_name, ic.column_position, i.index_type, "
            "(SELECT MAX(c.constraint_type) FROM sys.all_constraints c "
            " WHERE c.owner = i.owner AND c.index_name = i.index_name AND c.constraint_type = 'P') "
            "FROM sys.all_indexes i JOIN sys.all_ind_columns ic "
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
        sql = "SELECT owner, view_name, text FROM sys.all_views"
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
        return [
            ViewInfo(schema=r[0], name=r[1], kind="view", definition_state="unavailable")
            for r in rows
            if not is_session_sql_view(self.engine, r[0], r[1])
        ]

    def list_synonyms(self, schema: str | None) -> list[SynonymInfo]:
        sql = "SELECT owner, synonym_name, table_owner, table_name, db_link FROM sys.all_synonyms"
        params: list[Any] = []
        if schema:
            # the owner's synonyms, and each local synonym they name in turn,
            # whoever owns it, or the PUBLIC one of its name: read to follow a
            # chain, not listed
            sql += (
                " START WITH owner = :1 CONNECT BY NOCYCLE owner IN (PRIOR table_owner, 'PUBLIC')"
                " AND synonym_name = PRIOR table_name AND PRIOR db_link IS NULL"
            )
            params.append(schema)
        with translated_driver_errors():
            conn = self._shared_meta_conn()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        targets = {(r[0], r[1]): (r[2], r[3]) for r in rows}
        listed = {(r[0], r[1]): r for r in rows if not schema or r[0] == schema}
        return [
            SynonymInfo(
                schema=r[0],
                name=r[1],
                target_schema=r[2],
                target_name=r[3],
                target_kind="remote" if r[4] else "table",
            )
            for r in listed.values()
            # a PUBLIC synonym (V$SQL, ALL_TAB_HISTOGRAMS) names the SYS view it points to, and a
            # synonym may name one through others (APP.S2 -> APP.S1 -> PUBLIC.V$SQL)
            if not synonym_names_refused_view(self.engine, (r[0], r[1]), (r[2], r[3]), targets, "PUBLIC")
        ]

    def synonym_chains(
        self, names: Sequence[tuple[str | None, str]]
    ) -> dict[tuple[str | None, str], list[SynonymTarget]]:
        # each name as the statement looks it up (exactly: TRAVEL."Bookings"
        # is not TRAVEL.BOOKINGS), a bare one of any owner; then each synonym
        # a row names in turn, and the PUBLIC one of its name (a target that
        # is no object is read through it). A synonym's database link is
        # kept: its target is another database's (live: TRAVEL.R2_REMOTE FOR
        # R2OWN.PAYROLL@R2_LOOP read the table over the link)
        rows: list[Any] = []
        for at in range(0, len(names), _SYNONYM_BATCH):
            params: list[Any] = []
            starts = []
            for schema, name in names[at : at + _SYNONYM_BATCH]:
                params.append(name)
                cond = f"synonym_name = :{len(params)}"
                if schema is not None:
                    params.append(schema)
                    cond += f" AND owner = :{len(params)}"
                starts.append(f"({cond})")
            sql = (
                "SELECT owner, synonym_name, table_owner, table_name, db_link FROM sys.all_synonyms START WITH "
                + " OR ".join(starts)
                + " CONNECT BY NOCYCLE owner IN (PRIOR table_owner, 'PUBLIC') AND synonym_name = PRIOR table_name"
                " AND PRIOR db_link IS NULL"
            )
            with translated_driver_errors():
                conn = self._shared_meta_conn()
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    rows += cur.fetchall()
        targets = {(r[0], r[1]): SynonymTarget(r[2], r[3], r[4]) for r in rows}
        return synonym_chains(names, targets, lambda n: n, "PUBLIC")

    def name_binding(self) -> NameBinding:
        # a bare name is the current schema's object, else a PUBLIC synonym's
        # (the current schema is the login's unless a logon trigger sets it),
        # asked of a new session as each statement runs on one: the shared
        # metadata session keeps what its logon set
        with translated_driver_errors():
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM sys.dual")
                    row = cur.fetchone()
            finally:
                conn.close()
        return NameBinding((str(row[0]),))

    def list_routines(self, schema: str | None) -> list[RoutineInfo]:
        sql = (
            "SELECT owner, object_name, object_type FROM sys.all_objects "
            "WHERE object_type IN ('PROCEDURE','FUNCTION')"
        )
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
            "FROM sys.all_constraints a "
            "JOIN sys.all_constraints b ON a.r_constraint_name = b.constraint_name AND a.r_owner = b.owner "
            "JOIN sys.all_cons_columns ac ON ac.owner = a.owner AND ac.constraint_name = a.constraint_name "
            "JOIN sys.all_cons_columns bc ON bc.owner = b.owner AND bc.constraint_name = b.constraint_name "
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
        sql = "SELECT num_rows, last_analyzed FROM sys.all_tables WHERE owner = :1 AND table_name = :2"
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
            self._cancelled.clear()
            self._executing = True
            try:
                return self._execute(spec)
            finally:
                self._executing = False

    def _execute(self, spec: QuerySpec) -> QueryOutcome:
        self._refuse_db_link(spec.sql)
        with translated_driver_errors():
            conn = self._connect()
        self._cancel_target = conn
        start = time.monotonic()
        truncated = False
        truncation_cause = "row limit"
        cell_truncated_cols: list[str] = []
        unreadable_cols: list[str] = []
        rows: list[list[Any]] = []
        approx_bytes = 0

        try:
            with translated_driver_errors(phase="execute"):
                self._refuse_shadowed_dual(conn, spec.sql)
            with translated_driver_errors(phase="execute"), conn.cursor() as cur:
                # python-oracledb fetches prefetchrows rows with the execute
                # and arraysize rows per round trip after it: neither may
                # exceed what decides truncation. The execute's rows come
                # before the columns are known: two, so a single row and the
                # end of the result take one round trip.
                cur.prefetchrows = 2
                cur.arraysize = next_fetch_size(spec.max_rows, 0)
                if self._cancelled.is_set():
                    # the deadline fired during the connect or the check above
                    raise ConnectorError(
                        "the statement was cancelled before it started", category=ErrorCategory.TIMEOUT
                    )
                cur.execute(spec.sql, spec.parameters or None)
                decoded_whole = _DECODED_WHOLE if getattr(conn, "thin", True) else _DECODED_WHOLE_THICK
                whole = {i for i, d in enumerate(cur.description or []) if getattr(d[1], "name", None) in decoded_whole}
                # Values decoded whole cost memory for every row a fetch
                # carries: such a result starts at one row per fetch, doubles
                # it (up to _WHOLE_BATCH_MAX) while those values stay within
                # the cell limit, and is back at one row for the rest of the
                # result once one does not. One row at a time cost a round
                # trip per row (1000 small JSON rows: 0.47 s instead of 0.06 s
                # on loopback, 20-50 s over a WAN).
                batch_size = 1 if whole else FETCH_BATCH
                oversized = False
                cols = [(d[0], "unknown") for d in cur.description or []]
                # oracledb description[1] is a Python type object; use its name
                # (driver-derived, not data-derived).
                col_labels = [
                    getattr(d[1], "__name__", "unknown").lower() if d[1] is not None else "unknown"
                    for d in (cur.description or [])
                ]
                while True:
                    cur.arraysize = min(batch_size, next_fetch_size(spec.max_rows, len(rows)))
                    batch = cur.fetchmany(cur.arraysize)
                    if not batch:
                        break
                    for raw in batch:
                        cells = [_oracle_cell(v, spec.max_cell_bytes) for v in raw]
                        unreadable = [i for i, c in enumerate(cells) if c is _UNREADABLE_BFILE]
                        unreadable_cols.extend(column_names_at(cols, unreadable))
                        vals, _labels, cut = adapt_row(
                            [None if c is _UNREADABLE_BFILE else c for c in cells], spec.max_cell_bytes
                        )
                        cell_truncated_cols.extend(column_names_at(cols, cut))
                        oversized = oversized or not whole.isdisjoint(cut)
                        approx_bytes += len(json.dumps(vals, default=str).encode("utf-8"))
                        if len(rows) >= spec.max_rows or approx_bytes > spec.max_response_bytes:
                            truncated = True
                            truncation_cause = "row limit" if len(rows) >= spec.max_rows else "byte limit"
                            conn.cancel()  # stop server-side work
                            break
                        rows.append(vals)
                    # a value decoded whole must not stay alive while the
                    # next row is fetched
                    del batch, raw, cells
                    if truncated:
                        break
                    if whole:
                        batch_size = 1 if oversized else min(batch_size * 2, _WHOLE_BATCH_MAX)
            warnings = [f"result truncated by {truncation_cause}"] if truncated else []
            if cell_truncated_cols:
                truncated = True
                warnings.append(cell_truncation_warning(cell_truncated_cols, spec.max_cell_bytes))
            if unreadable_cols:
                warnings.append(
                    f"BFILE value(s) in column(s) {', '.join(repr(n) for n in dict.fromkeys(unreadable_cols))} "
                    "could not be read by the database server (missing file or directory access) and are null"
                )
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
        """EXPLAIN PLAN into PLAN_TABLE, read back through DBMS_XPLAN.

        Since Oracle 10g PLAN_TABLE is a public synonym for SYS.PLAN_TABLE$,
        a global temporary table every session can write: nothing has to be
        provisioned and the rows vanish when this private session closes.
        The statement is never executed. A locked-down account that lacks
        the synonym gets the database's own error, named as such. PLAN_TABLE
        alone of the dictionary names read here stays unqualified: it names
        what EXPLAIN PLAN writes into, a login schema's own PLAN_TABLE where
        there is one.
        """
        if analyze:
            raise NotImplementedError(EXPLAIN_ANALYZE_UNSUPPORTED)
        self._refuse_db_link(sql)
        statement_id = "udbmcp_" + uuid.uuid4().hex[:20]
        with translated_driver_errors():
            conn = self._connect()
            try:
                # the plan names what a shadowing DUAL reads, and its predicates
                self._refuse_shadowed_dual(conn, sql)
                with conn.cursor() as cur:
                    # the statement id is our own hex token, not user text
                    cur.execute(f"EXPLAIN PLAN SET STATEMENT_ID = '{statement_id}' FOR {sql}")  # noqa: S608
                    cur.execute(
                        "SELECT id, parent_id, depth, operation, options, object_owner, object_name, "
                        "cardinality, bytes, cost, access_predicates, filter_predicates "
                        "FROM plan_table WHERE statement_id = :1 ORDER BY id",
                        [statement_id],
                    )
                    cols = [d[0].lower() for d in cur.description]
                    rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
                    try:
                        cur.execute(
                            "SELECT plan_table_output FROM TABLE(SYS.DBMS_XPLAN.DISPLAY('PLAN_TABLE', :1, 'TYPICAL'))",
                            [statement_id],
                        )
                        text = [r[0] for r in cur.fetchall()]
                    except Exception:  # noqa: BLE001 - the structured rows are the contract; the text is a courtesy
                        text = []
                    try:
                        cur.execute("DELETE FROM plan_table WHERE statement_id = :1", [statement_id])
                    except Exception:  # noqa: BLE001, S110 - session-private GTT rows die with the session anyway
                        pass
            finally:
                conn.close()
        return {
            "raw": "\n".join(text) if text else None,
            "rows": rows,
            "method": "EXPLAIN PLAN (PLAN_TABLE), not executed",
        }

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
