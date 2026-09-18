"""Dialect-aware SQL safety service.

Parser rules are defense-in-depth on top of mandatory read-only database
accounts. Design:

- Exactly one permitted statement; nested CTEs and subqueries are inspected
  by walking the whole AST, so a modifying CTE inside a SELECT is caught.
- A top-level ``SELECT`` is NOT automatically safe: unknown functions are
  denied (``exp.Anonymous``), dangerous functions are denied by name, table
  functions are denied, ``SELECT INTO`` is denied, executable comments are
  denied.
- Objects are resolved conservatively against the connection's allowlist via
  an injected resolver; unresolved objects are denied, not waved through.
- EXPLAIN / SHOW / DESCRIBE are validated through dedicated, dialect-scoped
  policies, never by prefix-matching arbitrary SQL.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import sqlglot
from sqlglot import exp

from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy

# Statement roots that may be executed through db_query (after the AST walk).
_ALLOWED_ROOTS = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)

# Any node of these types anywhere in the AST is a hard deny. This covers DML,
# DDL, transaction control, session settings, attachment, and privilege
# changes, including the same statements nested inside CTEs.
_DENIED_NODES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.TruncateTable,
    exp.Grant,
    exp.Set,
    exp.SetItem,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Use,
    exp.Attach,
    exp.Detach,
    exp.Pragma,
    exp.Command,
    exp.Copy,
    exp.LoadData,
    exp.Into,
    exp.Lock,  # FOR UPDATE / FOR SHARE: locking reads are side effects, not reads
)

# Unknown-function handling is strict (Anonymous => deny). These known names
# are additionally denied by name even if a dialect maps them to a class.
_DANGEROUS_FUNCTIONS = {
    "load_extension",
    "readfile",
    "writefile",
    "read_textfile",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "dblink",
    "dblink_exec",
    "postgres_fdw",
    "file_fdw",
    "lo_import",
    "lo_export",
    "lo_get",
    "lo_put",
    "query_to_xml",
    "dbms_sql",
    "dbms_java",
    "utl_file",
    "utl_http",
    "utl_tcp",
    "utl_smtp",
    "httprequest",
    "benchmark",
    "sleep",
    "get_lock",
    "release_lock",
    "load_file",
    "sys_exec",
    "sys_eval",
    "sp_executesql",
    "sp_oacreate",
    "xp_cmdshell",
    "xp_regread",
    "xp_regwrite",
    "openrowset",
    "openquery",
    "exec",
    "execute",
    "shell",
    "eval",
    "system",
    "copy_expert",
}

# MySQL-style executable comments: /*! ... */ executes on matching versions.
_EXECUTABLE_COMMENT = re.compile(r"/\*!")

_PLACEHOLDER_OK = re.compile(r"^[%?$:@][0-9a-zA-Z_]*$")

# DBAPI format/pyformat placeholders: positional ``%s`` and named
# ``%(name)s``. The lookahead keeps ``%s`` from matching the start of a
# longer identifier-like token; ``%(name)s`` is fully delimited already.
_PYFORMAT_NAMED_RE = re.compile(r"%\([A-Za-z_][A-Za-z0-9_$]*\)s")
_PYFORMAT_POS_RE = re.compile(r"%s(?![0-9a-zA-Z_$\"'`\]])")
# SQLAlchemy-style named placeholders ``:name``. The lookarounds keep
# PostgreSQL's ``::`` cast operator (and ``x :`` chains) out of the match.
_NAMED_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_$]*)(?!:)")
_QMARK_RE = re.compile(r"\?")


def _rewrite_code_segments(
    sql: str,
    transform: Callable[[str], str],
    *,
    backslash_escapes: bool,
) -> tuple[str, str]:
    """Rewrite the code segments of ``sql`` and return a pair:

    1. ``sql`` with ``transform`` applied to every code segment, leaving
       string literals ('...'), quoted identifiers ("...", `...`, [...])
       and comments (-- ..., /- * ... */) verbatim — so a placeholder-shaped
       token inside a literal is never rewritten;
    2. a same-length "code view" where literals and comments are blanked to
       spaces — placeholder DETECTION must run against this view, because a
       ``?`` or ``%s`` inside a literal is data, not a placeholder.

    ``backslash_escapes`` selects the string-literal escaping rules: MySQL
    (and its drivers) treat ``\\'`` as an escaped quote;
    standard-conforming PostgreSQL does not. Being wrong in either
    direction only *skips* a rewrite (a stray placeholder survives), which
    then fails at parse time or in the driver — a rewrite is never
    fabricated inside a literal.
    """
    out: list[str] = []
    view: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(sql)

    def flush() -> None:
        if buf:
            out.append(transform("".join(buf)))
            view.append("".join(buf))
            buf.clear()

    def blank(span: str) -> None:
        out.append(span)
        view.append(" " * len(span))

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1 : i + 2]
        if ch == "-" and nxt == "-":
            flush()
            j = sql.find("\n", i)
            j = n if j == -1 else j + 1
            blank(sql[i:j])
            i = j
        elif ch == "/" and nxt == "*":
            flush()
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(sql[i:j])
            i = j
        elif ch in ("'", '"', "`", "["):
            quote = "]" if ch == "[" else ch
            flush()
            start = i
            i += 1
            while i < n:
                c = sql[i]
                if backslash_escapes and c == "\\":
                    i += 2
                    continue
                if c == quote:
                    if sql[i + 1 : i + 2] == quote:  # doubled quote escape
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            span = sql[start:i]
            out.append(span)  # literals pass through untouched ...
            view.append(" " * len(span))  # ... and are invisible to detection
        else:
            buf.append(ch)
            i += 1
    flush()
    return "".join(out), "".join(view)


def mask_pyformat_placeholders(sql: str) -> str:
    """Rewrite format/pyformat placeholders (``%s``, ``%(name)s``) to qmark
    (``?``) outside literals.

    sqlglot's tokenizer reads ``%`` as the modulo operator in most dialects
    (mysql, clickhouse, oracle, t-sql, sqlite), so a statement using the
    driver's own paramstyle cannot be parsed there; the postgres dialect is
    the only one that tokenizes ``%s`` as a placeholder natively. The guard
    parses the original text first and only falls back to this masked text
    when that parse fails, so nothing that parsed before changes. The masked
    AST still goes through the full validation walk, where ``exp.Placeholder``
    is an opaque parameter marker and every other check (denied constructs,
    dangerous/unknown functions, object resolution) applies unchanged.
    """
    rewritten, _ = _rewrite_code_segments(
        sql, lambda seg: _PYFORMAT_POS_RE.sub("?", _PYFORMAT_NAMED_RE.sub("?", seg)),
        backslash_escapes=True,
    )
    return rewritten


def translate_paramstyle(
    sql: str,
    parameters: Any,
    *,
    backslash_escapes: bool,
    qmark_is_placeholder: bool = True,
) -> tuple[str, Any]:
    """Translate a validated statement's placeholders into the format/
    pyformat paramstyle its DBAPI driver expects (PyMySQL and psycopg both
    use ``%s`` / ``%(name)s``), based on how the values were supplied.

    The guard tolerates qmark/named placeholders as opaque parameter
    markers; this maps them 1:1 onto the driver's spelling AFTER validation,
    outside literals, so it cannot bypass guard checks (same statement, same
    placeholders, different syntax). Combinations that cannot be mapped
    unambiguously — values whose shape does not match the placeholder style
    in the statement — are rejected instead of being handed to the driver to
    misformat. ``qmark_is_placeholder=False`` (psycopg: ``?`` is never a
    placeholder there, it reaches the server as the JSONB key-exists
    operator) leaves ``?`` alone entirely.
    """
    if parameters is None:
        return sql, None
    _, view = _rewrite_code_segments(sql, lambda seg: seg, backslash_escapes=backslash_escapes)

    if isinstance(parameters, dict):
        if _PYFORMAT_POS_RE.search(view) or (qmark_is_placeholder and _QMARK_RE.search(view)):
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                "named parameters were supplied but the statement uses "
                "positional placeholders (%s"
                + (" or ?" if qmark_is_placeholder else "")
                + "); use :name / %(name)s placeholders or positional values",
            )
        missing = {m.group(1) for m in _NAMED_RE.finditer(view) if m.group(1) not in parameters}
        if missing:
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"statement references parameter names that were not supplied: {sorted(missing)}",
            )
        rewritten, _ = _rewrite_code_segments(
            sql,
            lambda seg: _NAMED_RE.sub(lambda m: "%(" + m.group(1) + ")s", seg),
            backslash_escapes=backslash_escapes,
        )
        return rewritten, parameters
    if isinstance(parameters, (list, tuple)):
        if _NAMED_RE.search(view) or _PYFORMAT_NAMED_RE.search(view):
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                "positional parameters were supplied but the statement uses "
                "named placeholders (:name or %(name)s); supply a mapping instead",
            )
        if _PYFORMAT_POS_RE.search(view):
            if qmark_is_placeholder and _QMARK_RE.search(view):
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    "statement mixes positional placeholder styles (? and %s); use one style",
                )
            return sql, parameters  # already format paramstyle: pass through
        if not qmark_is_placeholder or not _QMARK_RE.search(view):
            return sql, parameters  # nothing to translate
        rewritten, _ = _rewrite_code_segments(
            sql, lambda seg: _QMARK_RE.sub("%s", seg), backslash_escapes=backslash_escapes
        )
        return rewritten, parameters
    # Anything else is passed through unchanged; the driver reports the
    # mismatch the same way it did before this translation existed.
    return sql, parameters


def sqlglot_dialect(engine: str) -> str:
    """Map a config engine type to the sqlglot dialect used for validation/rendering."""
    return _DIALECT_MAP.get(engine, engine)


# Engine names from config -> sqlglot dialect names. sqlglot has no 'mssql'
# (its T-SQL dialect is 'tsql') and no DB2 dialect; DB2 statements are parsed
# under the postgres dialect for validation, and any parse failure is a
# denial, never approval (documented in docs/driver-matrix.md).
_DIALECT_MAP = {"mssql": "tsql", "db2": "postgres"}

# Upper bound for a single submitted statement. Guards the event loop and
# sqlglot from pathological input; legitimate reads are far below this.
_MAX_SQL_BYTES = 65536


class ObjectResolver(Protocol):
    """Returns True when (schema, name) is authorized on the connection.
    Implementations must be conservative: unknown => False."""

    def resolve(self, schema: str | None, name: str) -> bool: ...


@dataclass(slots=True)
class ObjectRef:
    schema: str | None
    name: str
    catalog: str | None


@dataclass(slots=True)
class GuardResult:
    ast: exp.Expression
    tables: list[ObjectRef] = field(default_factory=list)
    kind: str = "select"  # select | explain | show


def _deny(message: str) -> ToolFailure:
    return ToolFailure(ErrorCategory.POLICY, message)


def _func_name(node: Any) -> str | None:
    if isinstance(node, exp.Anonymous):
        return node.name
    if isinstance(node, exp.Func):
        return node.sql_name()
    return None


# Db2 read-only tail clauses. sqlglot has no Db2 dialect (statements are parsed
# under postgres), so `SELECT ... WITH UR` - the standard Db2 reporting idiom
# that avoids lock waits - failed to parse and every such query was denied.
# These clauses only choose an isolation level or state read intent; none of
# them can write. They are removed for VALIDATION only: the executor sends the
# original text, so Db2 still receives the clause.
_DB2_READ_TAIL = re.compile(
    r"\s+(?:"
    r"FOR\s+(?:READ|FETCH)\s+ONLY"
    r"|OPTIMIZE\s+FOR\s+\d+\s+ROWS?"
    r"|WITH\s+(?:UR|CS)"
    r")\s*$",
    re.IGNORECASE,
)
# RS/RR take and KEEP row or table locks for the statement: on a read-only
# connection they would let the agent opt out of the session profile's UR
# (the "never hold locks on production" promise), so they are refused.
_DB2_LOCKING_ISOLATION = re.compile(r"\bWITH\s+(?:RS|RR)\s*$", re.IGNORECASE)
# `USE AND KEEP <mode> LOCKS` takes real locks (SHARE/UPDATE/EXCLUSIVE) and is
# not a read-only hint, so it is never stripped and never allowed.
_DB2_LOCK_TAIL = re.compile(r"\bUSE\s+AND\s+KEEP\s+\w+\s+LOCKS?\b", re.IGNORECASE)


class SqlGuard:
    def __init__(
        self,
        dialect: str,
        policy: EffectivePolicy,
        resolver: ObjectResolver | None = None,
    ) -> None:
        self._engine = dialect  # pre-mapping: db2 needs engine-specific handling
        self._dialect = _DIALECT_MAP.get(dialect, dialect)
        self._policy = policy
        self._resolver = resolver

    # ---- shared core -----------------------------------------------------

    @staticmethod
    def _strip_db2_read_tail(sql: str) -> str:
        """Remove Db2 read-only tail clauses before parsing (validation only).

        Anchored at the end of the statement, so nothing arbitrary can hide
        behind one: a second statement after the clause leaves the tail
        unmatched and the full text is parsed (and refused) as submitted.
        """
        if _DB2_LOCK_TAIL.search(sql):
            raise _deny(
                "Db2 locking clause 'USE AND KEEP ... LOCKS' is not permitted on a read-only "
                "connection; use the isolation clause alone (for example WITH UR)"
            )
        if _DB2_LOCKING_ISOLATION.search(sql.rstrip()):
            raise _deny(
                "Db2 isolation clause WITH RS/RR holds locks for the statement and is not permitted "
                "on a read-only connection (the session runs at UR by default; WITH UR/CS are accepted)"
            )
        for _ in range(4):  # FOR READ ONLY + OPTIMIZE FOR n ROWS + WITH UR can combine
            trimmed = _DB2_READ_TAIL.sub("", sql, count=1).rstrip()
            if trimmed == sql:
                break
            sql = trimmed
        return sql


    def _parse_single(self, sql: str, kind: str) -> exp.Expression:
        if "\x00" in sql:
            raise _deny("statement contains a NUL byte")
        if len(sql) > _MAX_SQL_BYTES:
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"statement exceeds the {_MAX_SQL_BYTES} byte limit",
            )
        if _EXECUTABLE_COMMENT.search(sql):
            raise _deny("executable comments (/*! ... */) are not permitted")
        stripped = sql.strip().rstrip(";").strip()
        if not stripped:
            raise ToolFailure(ErrorCategory.VALIDATION, "empty statement")
        if self._engine == "db2":
            stripped = self._strip_db2_read_tail(stripped)
        # Primary parse: the text exactly as submitted. Only if that fails do
        # we retry a view with format/pyformat placeholders (%s, %(name)s)
        # masked to qmark — sqlglot's tokenizer reads '%' as modulo in most
        # dialects, which used to make the drivers' own paramstyle
        # unvalidatable. The masked view can only turn a placeholder into
        # another placeholder, and whatever AST it yields goes through the
        # same full walk below, so this fallback never approves anything the
        # statement-shaped validation would otherwise deny.
        candidates = [stripped]
        masked = mask_pyformat_placeholders(stripped)
        if masked != stripped:
            candidates.append(masked)
        last_exc: Exception | None = None
        for candidate in candidates:
            try:
                statements = sqlglot.parse(candidate, read=self._dialect)
                break
            except (sqlglot.errors.ParseError, ValueError, RecursionError) as exc:
                last_exc = exc
        else:
            # A parser failure (or unsupported dialect / pathological nesting)
            # is never approval.
            raise _deny(
                f"statement could not be parsed under the '{self._dialect}' dialect; "
                f"refusing unvalidated SQL ({last_exc})"
            ) from last_exc
        if len(statements) != 1:
            raise _deny("exactly one statement is permitted")
        root = statements[0]
        if root is None:
            raise _deny("statement could not be parsed")
        return cast(exp.Expression, root)

    def _walk_validate(self, root: exp.Expression) -> list[ObjectRef]:
        cte_aliases: set[str] = set()
        for cte in root.find_all(exp.CTE):
            cte_aliases.add(cte.alias_or_name.lower())

        refs: list[ObjectRef] = []
        for node in root.walk():
            if isinstance(node, _DENIED_NODES):
                raise _deny(f"statement contains a disallowed construct ({type(node).__name__})")
            if isinstance(node, exp.Select) and node.args.get("into"):
                raise _deny("SELECT INTO is not permitted")
            if isinstance(node, (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)) and node.args.get(
                "settings"
            ):
                raise _deny("query SETTINGS clauses are not permitted (engine limits cannot be altered)")
            if isinstance(node, (exp.Func, exp.Anonymous)):
                name = _func_name(node)
                if name and name.lower() in _DANGEROUS_FUNCTIONS:
                    raise _deny(f"function '{name.lower()}' is not permitted")
                if isinstance(node, exp.Anonymous):
                    raise _deny(
                        f"unknown or unsupported function '{name}' is not permitted (function allowlist is closed)"
                    )
            if isinstance(node, exp.Table):
                inner = node.this
                if not isinstance(inner, exp.Identifier):
                    raise _deny("table functions and dynamic table expressions are not permitted")
                name = node.name
                if "@" in name:
                    # Oracle DB links (table@link) and any other remote-object
                    # syntax folded into identifiers: cross-server reads must
                    # never bypass policy (spec §9).
                    raise _deny("database links / remote-object references (@link) are not permitted")
                schema = node.db or None
                catalog = node.catalog or None
                # A CTE can only ever be referenced by its UNqualified name;
                # a schema- or catalog-qualified reference always names a real
                # object, so it must never be skipped just because a CTE alias
                # happens to shadow the bare name (authz bypass otherwise).
                if schema is None and catalog is None and name.lower() in cte_aliases:
                    continue
                self._check_ref(schema, name, catalog)
                refs.append(ObjectRef(schema=schema, name=name, catalog=catalog))
        return refs

    def _check_ref(self, schema: str | None, name: str, catalog: str | None) -> None:
        # SQLite allows reads of its catalog tables (sqlite_master et al.)
        # because metadata tools rely on them; nothing else in sqlite_master
        # context is writable through the read-only file handle anyway.
        if self._dialect == "sqlite" and name.lower().startswith("sqlite_"):
            return
        if catalog:
            if self._dialect == "sqlite":
                # SQLite may read its implicit "main" catalog only; anything
                # else implies ATTACH, which is disabled.
                if catalog.lower() not in ("main",):
                    raise _deny(f"catalog '{catalog}' is not permitted (attachment is disabled)")
            else:
                # A catalog-qualified (3-part) reference such as
                # otherdb.dbo.table names a different database on the same
                # server. Neither the schema allowlist nor the resolver sees
                # the catalog, so letting it through would allow cross-database
                # reads. The guard cannot confirm the catalog equals the
                # connection's configured database, so every such reference is
                # denied (fail-closed).
                raise _deny(
                    f"catalog-qualified reference '{catalog}' is not permitted on connection "
                    f"'{self._policy.connection_id}'; queries may only read this "
                    f"connection's configured database"
                )
        if schema is not None and not (self._dialect == "sqlite" and schema.lower() in ("main", "temp")):
            # sqlite main/temp is its only attached schema; the schema-allowlist
            # check would be meaningless there, so fall through to object-level
            # default-deny below.
            self._policy.check_object(schema, name)
        if not self._policy.default_deny_objects:
            return
        if self._resolver is None or not self._resolver.resolve(schema, name):
            raise _deny(
                f"object '{name}' could not be resolved to a permitted object "
                f"on connection '{self._policy.connection_id}'; qualify it with "
                f"an allowed schema or ask the administrator to grant access"
            )
        if schema is None:
            # Defense in depth: an unqualified name binds to SOME schema; every
            # candidate must itself be permitted, and ambiguity is refused.
            schemas_for = getattr(self._resolver, "schemas_for", None)
            if callable(schemas_for):
                candidates = {s for s in schemas_for(name) if s}
                if len(candidates) > 1:
                    raise _deny(f"object '{name}' exists in several schemas; qualify it with a schema")
                for cand in candidates:
                    self._policy.check_object(cand, name)

    # ---- public validation entry points ----------------------------------

    def validate_select(self, sql: str) -> GuardResult:
        root = self._parse_single(sql, "query")
        if not isinstance(root, _ALLOWED_ROOTS):
            raise _deny(f"only read statements are permitted here; this statement parsed as {type(root).__name__}")
        refs = self._walk_validate(root)
        return GuardResult(ast=root, tables=refs, kind="select")

    def validate_explain(self, sql: str) -> GuardResult:
        """EXPLAIN goes through its own dialect-scoped policy. Execution-capable
        variants (ANALYZE) require explicit policy."""
        text = sql.strip().rstrip(";").strip()
        if self._dialect == "sqlite":
            m = re.match(r"^EXPLAIN(\s+QUERY\s+PLAN)?\s+(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("sqlite EXPLAIN requires: EXPLAIN [QUERY PLAN] <select>")
            root = self._parse_single(m.group(2), "explain")
        elif self._dialect in ("postgres", "clickhouse"):
            # PostgreSQL option syntax: EXPLAIN [(option [, ...])] statement
            # (e.g. EXPLAIN (FORMAT JSON) SELECT ...), plus the bare-token
            # legacy form EXPLAIN [ANALYZE] statement.
            m = re.match(r"^EXPLAIN\s*(\([^)]*\))?\s*(?:(ANALYZE)\s+)?(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("EXPLAIN requires: EXPLAIN [(option [, ...])] [ANALYZE] <statement>")
            options = m.group(1) or ""
            # ANALYZE executes the statement (as does the WAL option); both
            # are gated behind the same explicit policy.
            analyze_requested = bool(m.group(2)) or bool(re.search(r"\b(?:ANALYZE|WAL)\b", options, re.I))
            if analyze_requested and not self._policy.allow_explain_analyze:
                raise _deny(
                    "EXPLAIN ANALYZE executes the statement and is disabled by policy; use EXPLAIN without ANALYZE"
                )
            root = self._parse_single(m.group(3), "explain")
        elif self._dialect == "mysql":
            m = re.match(r"^EXPLAIN\s+(ANALYZE\s+)?(?:FORMAT\s*=\s*(\w+)\s+)?(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("EXPLAIN requires: EXPLAIN [ANALYZE] [FORMAT=x] <statement>")
            if m.group(1) and not self._policy.allow_explain_analyze:
                raise _deny("EXPLAIN ANALYZE is disabled by policy")
            root = self._parse_single(m.group(3), "explain")
        elif self._dialect in ("oracle", "tsql"):
            # No native "EXPLAIN <stmt>" on these engines: the tool accepts the
            # portable spelling and the connector captures the plan its own way
            # (Oracle EXPLAIN PLAN into PLAN_TABLE, SQL Server SET SHOWPLAN_ALL),
            # never executing the statement. There is no ANALYZE variant.
            m = re.match(r"^EXPLAIN\s+(?:(ANALYZE)\s+)?(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("EXPLAIN requires: EXPLAIN <select statement>")
            if m.group(1):
                raise _deny(
                    "EXPLAIN ANALYZE is not available on this engine: plans are captured without "
                    "executing the statement; use EXPLAIN <statement>"
                )
            root = self._parse_single(m.group(2), "explain")
        else:
            raise ToolFailure(
                ErrorCategory.CAPABILITY,
                f"EXPLAIN is not supported for dialect '{self._dialect}' in this "
                f"build; see the driver matrix for per-engine plan capabilities",
            )
        if not isinstance(root, _ALLOWED_ROOTS):
            raise _deny("EXPLAIN requires a read statement inside")
        refs = self._walk_validate(root)
        return GuardResult(ast=root, tables=refs, kind="explain")

    def validate_show(self, sql: str) -> GuardResult:
        """Strict per-dialect allowlists for SHOW/DESCRIBE-style commands."""
        text = sql.strip().rstrip(";").strip()
        ident = r"[A-Za-z_][A-Za-z0-9_$]*"
        qual = rf"{ident}(\s*\.\s*{ident})?"
        patterns: list[str] = []
        if self._dialect == "mysql":
            patterns = [
                r"^SHOW\s+(DATABASES|SCHEMAS)$",
                rf"^SHOW\s+TABLES(\s+FROM\s+{ident})?$",
                rf"^SHOW\s+COLUMNS(\s+FROM\s+{qual})?$",
                rf"^SHOW\s+INDEX(\s+FROM\s+{qual})?$",
                rf"^(DESC|DESCRIBE)\s+{qual}$",
            ]
        elif self._dialect == "clickhouse":
            patterns = [
                r"^SHOW\s+(DATABASES|TABLES)$",
                rf"^(DESC|DESCRIBE)\s+(TABLE\s+)?{qual}$",
            ]
        elif self._dialect == "postgres":
            if re.match(r"^SHOW\s+ALL$", text, re.I):
                raise _deny("SHOW ALL is not on the allowed list; query specific settings")
            patterns = [rf"^SHOW\s+{ident}$"]
        else:
            raise ToolFailure(
                ErrorCategory.CAPABILITY,
                f"SHOW/DESCRIBE is not supported for dialect '{self._dialect}' in this build",
            )
        for pat in patterns:
            if re.match(pat, text, re.I):
                return GuardResult(ast=self._parse_single(text, "show"), kind="show")
        raise _deny("this SHOW/DESCRIBE form is not on the allowed list; use the metadata tools for catalog discovery")

    # Convenience used by db_validate_query.
    def validate_any(self, sql: str, operation: str = "query") -> GuardResult:
        if operation == "explain":
            head = sql.strip().lstrip("(")
            if re.match(r"^EXPLAIN\b", head, re.I):
                return self.validate_explain(sql)
            raise ToolFailure(ErrorCategory.VALIDATION, "operation=explain requires an EXPLAIN statement")
        head = sql.strip().lstrip("(")
        if re.match(r"^(SHOW|DESC|DESCRIBE)\b", head, re.I):
            return self.validate_show(sql)
        return self.validate_select(sql)


class StaticResolver:
    """Resolver backed by a pre-fetched set of permitted (schema, name) pairs.
    Unqualified names are allowed if they exist in any permitted schema."""

    def __init__(self, objects: set[tuple[str | None, str]]) -> None:
        self._objects = objects
        self._unqualified = {name.lower() for _, name in objects}

    def resolve(self, schema: str | None, name: str) -> bool:
        if schema is None:
            return name.lower() in self._unqualified
        return (schema.lower(), name.lower()) in self._objects
