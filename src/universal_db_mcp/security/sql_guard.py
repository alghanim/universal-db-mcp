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
from sqlglot import Token, TokenType, exp
from sqlglot.dialects.dialect import Dialect

from universal_db_mcp.discovery.system_schemas import (
    dictionary_binding,
    is_data_free_table,
    loose_name,
    value_columns,
)
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security.policy import EffectivePolicy, check_not_session_sql, unquoted_name

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
# SQL Server table hints that only relax locking for a read. Every other
# hint (HOLDLOCK, SERIALIZABLE, REPEATABLEREAD, UPDLOCK, XLOCK, TABLOCK[X],
# PAGLOCK, ROWLOCK, ...) takes or escalates locks and is refused.
_ALLOWED_TABLE_HINTS = frozenset({"NOLOCK", "READUNCOMMITTED", "READPAST", "NOWAIT"})
# Db2 sequence expressions: sqlglot's postgres reader cannot parse them (so
# they are refused anyway); this names the refusal and survives a parser
# that learns them.
_DB2_SEQUENCE = re.compile(r"\b(?:NEXT|PREVIOUS)\s+VALUE\s+FOR\b|\b(?:NEXTVAL|PREVVAL)\s+FOR\b", re.I)

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

# MySQL-style executable comments: /*! ... */ executes on matching versions,
# and MariaDB also executes /*M! ... */. sqlglot discards both bodies as
# comments, so anything inside would bypass every check below. Lowercase m is
# not executable on MariaDB; refusing it too costs nothing.
_EXECUTABLE_COMMENT = re.compile(r"/\*[Mm]?!")
# MariaDB `SET STATEMENT var=value FOR <stmt>` overrides session variables for
# one statement (transaction_read_only, max_statement_time): it would undo the
# server-side READ ONLY session and the statement ceiling.
_SET_STATEMENT = re.compile(r"\bSET\s+STATEMENT\b", re.IGNORECASE)
# MySQL comments from '#' to the end of the line; the shared literal scanner
# does not know '#', so the SET STATEMENT check blanks these itself.
_MYSQL_HASH_COMMENT = re.compile(r"#[^\n]*")

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


# Microsoft's T-SQL reserved keywords ("Reserved Keywords (Transact-SQL)").
# sqlglot reads an unquoted one after a projection or table as an AS-less
# alias, so `SELECT 1 DELETE FROM dbo.t COMMIT` validates as ONE Select, while
# SQL Server, which needs no separator between batch statements, runs a
# SELECT, a DELETE and a COMMIT. SQL Server rejects these words as unquoted
# aliases, so refusing them loses no valid query; [DELETE] / "DELETE" stay
# allowed. DISK, DUMP, LOAD, PRECISION and SECURITYAUDIT are on Microsoft's
# list but are left out: SQL Server 2022 accepts them as unquoted column and
# table aliases (checked with sys.dm_exec_describe_first_result_set), so it
# reads them exactly as sqlglot does. Only T-SQL is checked: every other
# connector sends one statement per call and its server reads such a word as
# an alias just as sqlglot does, so refusing (for example) the ClickHouse OHLC
# aliases `open` / `close` there would only lose valid queries.
_TSQL_RESERVED_KEYWORDS = frozenset(
    """
    ADD ALL ALTER AND ANY AS ASC AUTHORIZATION BACKUP BEGIN BETWEEN BREAK BROWSE BULK BY CASCADE
    CASE CHECK CHECKPOINT CLOSE CLUSTERED COALESCE COLLATE COLUMN COMMIT COMPUTE CONSTRAINT
    CONTAINS CONTAINSTABLE CONTINUE CONVERT CREATE CROSS CURRENT CURRENT_DATE CURRENT_TIME
    CURRENT_TIMESTAMP CURRENT_USER CURSOR DATABASE DBCC DEALLOCATE DECLARE DEFAULT DELETE DENY
    DESC DISTINCT DISTRIBUTED DOUBLE DROP ELSE END ERRLVL ESCAPE EXCEPT EXEC EXECUTE
    EXISTS EXIT EXTERNAL FETCH FILE FILLFACTOR FOR FOREIGN FREETEXT FREETEXTTABLE FROM FULL
    FUNCTION GOTO GRANT GROUP HAVING HOLDLOCK IDENTITY IDENTITY_INSERT IDENTITYCOL IF IN INDEX
    INNER INSERT INTERSECT INTO IS JOIN KEY KILL LEFT LIKE LINENO MERGE NATIONAL NOCHECK
    NONCLUSTERED NOT NULL NULLIF OF OFF OFFSETS ON OPEN OPENDATASOURCE OPENQUERY OPENROWSET
    OPENXML OPTION OR ORDER OUTER OVER PERCENT PIVOT PLAN PRIMARY PRINT PROC PROCEDURE
    PUBLIC RAISERROR READ READTEXT RECONFIGURE REFERENCES REPLICATION RESTORE RESTRICT RETURN
    REVERT REVOKE RIGHT ROLLBACK ROWCOUNT ROWGUIDCOL RULE SAVE SCHEMA SELECT
    SEMANTICKEYPHRASETABLE SEMANTICSIMILARITYDETAILSTABLE SEMANTICSIMILARITYTABLE SESSION_USER
    SET SETUSER SHUTDOWN SOME STATISTICS SYSTEM_USER TABLE TABLESAMPLE TEXTSIZE THEN TO TOP TRAN
    TRANSACTION TRIGGER TRUNCATE TRY_CONVERT TSEQUAL UNION UNIQUE UNPIVOT UPDATE UPDATETEXT USE
    USER VALUES VARYING VIEW WAITFOR WHEN WHERE WHILE WITH WRITETEXT
    """.split()
)
# Code points SQL Server's tokenizer takes as a separator while sqlglot folds
# them into the neighbouring identifier: `SELECT 1\x10COMMIT` validates as a
# Select aliased '\x10COMMIT', which the keyword check above never matches, and
# SQL Server runs a SELECT and a COMMIT. Observed live on SQL Server 2022 for
# 0x01-0x08, 0x0E-0x1B and U+200B; the other C0 controls (bar tab, LF, CR) and
# U+FEFF are refused as well. No T-SQL needs them outside a literal, quoted
# identifier or comment, which keep them.
_TSQL_HIDDEN_SEPARATOR = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\u200b\ufeff]")
# Tokens sqlglot reads as one identifier but SQL Server ends early: a money
# literal ($1, or any of the 33 other currency symbols it accepts, alone or
# with digits) or a binary literal (0x1) directly followed by a keyword.
# `SELECT $1EXEC sp_who` validates as a column aliased sp_who, and SQL Server
# runs `SELECT $1` and `EXEC sp_who` (compiled under SHOWPLAN_ALL on SQL
# Server 2022, which also gave the currency list below). A regular identifier
# starts with a letter, '_', '@' or '#', so an unquoted token that starts with
# anything else is refused unless SQL Server reads all of it as one token too:
# a whole money or binary literal, or a $ pseudo-column such as $IDENTITY.
# '$' is also an identifier character to SQL Server (DISTINCT$1EXEC is one
# column), but none of the other 33 symbols is: it ends the identifier and
# starts a money literal wherever it stands, so `SELECT DISTINCT\u20ac1EXEC sp_who`
# is DISTINCT, the literal \u20ac1 and an EXEC (SHOWPLAN_ALL, SQL Server 2022),
# while sqlglot reads one column aliased sp_who. Such a symbol after the first
# character refuses the token as well.
_TSQL_OTHER_CURRENCY = r"\u00a2-\u00a5\u09f2\u09f3\u0e3f\u17db\u20a0-\u20b1\ufdfc\ufe69\uff04\uffe0\uffe1\uffe5\uffe6"
_TSQL_CURRENCY = "$" + _TSQL_OTHER_CURRENCY
_TSQL_WHOLE_TOKEN = re.compile(rf"[{_TSQL_CURRENCY}][0-9]*|0[xX][0-9A-Fa-f]*|\$[A-Za-z][A-Za-z0-9_]*")
_TSQL_SPLITS_IDENTIFIER = re.compile(rf"[{_TSQL_OTHER_CURRENCY}]")
# SQL Server's lexer also carries a money or float literal over characters
# sqlglot splits off as tokens of their own: a '.' after the currency symbol
# or its digits ($1., and after spaces, $ .), a sign after a bare currency
# symbol ($-, $ -) and a sign straight after the exponent marker (1e-). With
# no digits after that character the literal ends on it and the next word
# starts a statement of its own, while sqlglot reads the '.' or sign as an
# operator and the word as its operand: SHOWPLAN_ALL on SQL Server 2022
# compiles `SELECT $1.DELETE FROM t`, `SELECT $ -DELETE FROM t` and
# `SELECT 1e-DELETE FROM t` as a SELECT and a DELETE. The literal is whole
# only when sqlglot's next token is its digits, adjacent: _TSQL_DIGITS after a
# '.' or an exponent sign, _TSQL_SIGNED_MONEY after a money sign.
_TSQL_MONEY_TOKEN = re.compile(rf"[{_TSQL_CURRENCY}][0-9]*")
_TSQL_DIGITS = re.compile(r"[0-9]+")
_TSQL_SIGNED_MONEY = re.compile(r"[0-9]+(?:\.[0-9]*)?")
# SQL Server compares names under the database collation, which reads a name
# outside printable ASCII as another (live, SQL Server 2022 on
# SQL_Latin1_General_CP1_CI_AS, review of 2026-09-28): it ignores 21,228 BMP
# code points outright (Ethiopic, Tibetan, Arabic tatweel, lone surrogates and
# more) and a trailing blank or U+3000, and reads full-width letters, small
# capitals (ʀ, ɴ), super- and subscripts and ligatures (æ, þ, ß, ﬁ) as ASCII;
# other collations fold accents or kana too. SELECT ＭＲＮ returned a masked
# column in clear, and sys.ｓｙｓcacheobjects other sessions' SQL. No
# normalization stands in for a collation, so a name there is printable ASCII
# without a trailing blank. Literals and comments keep any text, and a money
# literal (£1) its currency symbol (_TSQL_WHOLE_TOKEN).
_TSQL_LITERAL_TOKENS = frozenset({
    TokenType.STRING, TokenType.NATIONAL_STRING, TokenType.UNICODE_STRING, TokenType.RAW_STRING,
    TokenType.HEREDOC_STRING, TokenType.BIT_STRING, TokenType.HEX_STRING, TokenType.BYTE_STRING, TokenType.HINT,
})
# Oracle upper-cases an unquoted name by Unicode's rules, so these two name an
# ASCII letter there (live: user_tableſ reads USER_TABLES, ınıtial_extent is
# INITIAL_EXTENT); ß, ẞ, the Kelvin sign, ligatures and İ stay as they are.
_ORACLE_FOLDS_ONTO_ASCII = frozenset("ıſ")  # ı -> I, ſ -> S

# Engine names from config -> sqlglot dialect names. sqlglot has no 'mssql'
# (its T-SQL dialect is 'tsql') and no DB2 dialect; DB2 statements are parsed
# under the postgres dialect for validation, and any parse failure is a
# denial, never approval (documented in docs/driver-matrix.md).
_DIALECT_MAP = {"mssql": "tsql", "db2": "postgres"}

# Engines where two schema names that differ only in case, once an unquoted
# one is folded (unquoted_name), always name two schemas: PostgreSQL, Oracle
# and Db2 by their identifier rules, ClickHouse always, and MySQL on its
# default Linux setting (lower_case_table_names=0), where a database is a
# directory. On SQL Server the collation decides, so only a namesake the
# catalog lists proves it there; SQLite ignores case.
_CASE_EXACT_SCHEMA_ENGINES = frozenset({"postgres", "oracle", "db2", "clickhouse", "mysql"})

# Under default-deny, engines where a table named in another spelling than
# the catalog's, once an unquoted name is folded, is another object or none
# (_check_listed_spelling): PostgreSQL, Oracle and Db2 by their identifier
# rules, ClickHouse always. A synonym beside the listed table is one:
# Oracle's TRAVEL."travellers" FOR ALL_TAB_COL_STATISTICS passed as the
# listed TRAVEL.TRAVELLERS and returned a masked column's low and high
# values (live, re-attack round 2). On SQL Server the database collation
# decides, which the server asks (ListedBinding.folded); MySQL keeps no
# object the listing leaves out of a database it lists in a table's
# namespace, so another case reads the listed table or none.
_CASE_EXACT_NAME_ENGINES = frozenset({"postgres", "oracle", "db2", "clickhouse"})
# Engines that look a bare table name up in a schema of the session's
# choosing, where objects the listing leaves out come first or instead (a
# dictionary, synonyms, PUBLIC synonyms, public aliases): the server asks the
# session which (ListedBinding.bare). MySQL and ClickHouse look one up in the
# connection's database alone, whose tables and views the listing holds.
_SESSION_BOUND_ENGINES = frozenset({"postgres", "oracle", "mssql", "db2"})
# How each engine reads a name, for the refusal
_NAME_RULES = {
    "postgres": "PostgreSQL reads a quoted name as written and folds an unquoted one to lower case",
    "oracle": "Oracle reads a quoted name as written and folds an unquoted one to upper case",
    "db2": "Db2 reads a delimited name as written and folds an ordinary one to upper case",
    "clickhouse": "ClickHouse compares names exactly",
}

# Nodes that name a column or a table. After IN without parentheses such a
# name is a table to ClickHouse and SQLite; a placeholder there (ClickHouse's
# {ids:Array(UInt64)}, a driver's %(p)s) is bound as a value, and a constant
# is read as one.
_NAME_NODES = (exp.Column, exp.Dot, exp.Identifier, exp.Var, exp.Table, exp.Star)
_VALUE_PARAMETERS = (exp.Placeholder, exp.Parameter)

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
    # the schema and name the engine looks up for it (SqlGuard._looked_up):
    # TRAVEL."Bookings" is not TRAVEL.bookings on Oracle (server._check_synonyms)
    looked_up: tuple[str | None, str] | None = None


@dataclass(frozen=True, slots=True)
class ListedBinding:
    """A table name default-deny matched to the listed ``schema``.``name``
    (as the catalog spells them) that the engine reads for it only where the
    session binds names so, which the server asks the database
    (server._check_bindings, DatabaseConnector.name_binding): a bare one
    (``bare``) where ``schema`` is the first schema the session looks bare
    names up in, one spelled in another case (``folded``, SQL Server) where
    the database collation ignores case. ``written`` is the name as the
    statement spells it, ``spelled`` the listed one as a statement would."""

    written: str
    schema: str
    name: str
    spelled: str
    bare: bool
    folded: bool


@dataclass(slots=True)
class GuardResult:
    ast: exp.Expression
    tables: list[ObjectRef] = field(default_factory=list)
    kind: str = "select"  # select | explain | show
    # explain only: the inner statement exactly as the caller wrote it (the
    # text this validation parsed), preceded by the validated EXPLAIN options
    # re-rendered ('(COSTS OFF) ' on PostgreSQL, 'FORMAT=JSON ' on MySQL).
    # db_explain sends THIS to the engine, not a re-rendering of the AST,
    # which would drop the clauses sqlglot does not carry (Db2 WITH UR /
    # OPTIMIZE FOR n ROWS).
    text: str | None = None


def _deny(message: str) -> ToolFailure:
    return ToolFailure(ErrorCategory.POLICY, message)


def _deny_tsql_hidden_statements(root: exp.Expression) -> None:
    """Refuse text that sqlglot folds into the SELECT but SQL Server would run
    as a statement of its own (see _TSQL_RESERVED_KEYWORDS): an unquoted
    reserved keyword taken as an alias, and a FETCH clause without its
    ROWS ONLY tail (sqlglot reads `SELECT 1 FETCH c` as a row limit; SQL
    Server reads a cursor FETCH, and a trailing ROWS never parses there)."""
    for node in root.find_all(exp.Alias, exp.TableAlias, exp.Fetch):
        if isinstance(node, exp.Alias):
            idents = [node.args.get("alias")]
        elif isinstance(node, exp.TableAlias):
            idents = [node.this, *node.columns]
        else:
            if node.args.get("limit_options") is None:
                raise _deny(
                    "FETCH is only permitted as ORDER BY ... OFFSET n ROWS FETCH {FIRST|NEXT} n ROWS ONLY "
                    "on this engine"
                )
            continue
        for ident in idents:
            if isinstance(ident, exp.Identifier) and not ident.quoted and ident.name.upper() in _TSQL_RESERVED_KEYWORDS:
                raise _deny(
                    f"reserved keyword '{ident.name}' is not permitted as an unquoted alias: SQL Server "
                    f"would run it as a separate statement; quote it as [{ident.name}] if it is an alias"
                )


def _deny_tsql_fused_literals(sql: str, tokens: list[Token]) -> None:
    """Refuse an unquoted identifier token SQL Server would end early (see
    _TSQL_WHOLE_TOKEN): the literal it starts with, or a currency symbol
    after its first character, ends it there, and the text after it runs as
    a statement of its own."""
    for token in tokens:
        if token.token_type not in (TokenType.VAR, TokenType.IDENTIFIER):
            continue
        text = token.text
        if sql[token.start : token.end + 1] != text:
            continue  # [quoted] or "quoted": one identifier on both readings
        if (
            text[:1].isalpha() or text[:1] in "_@#" or _TSQL_WHOLE_TOKEN.fullmatch(text)
        ) and not _TSQL_SPLITS_IDENTIFIER.search(text, 1):
            continue
        raise _deny(
            f"unquoted '{text}' is not permitted: SQL Server splits it at a money or binary literal and "
            f"would run the rest as a separate statement; put spaces around the literal, or quote an "
            f"identifier as [{text}]"
        )


def _deny_tsql_split_literals(sql: str, tokens: list[Token]) -> None:
    """Refuse a money or float literal SQL Server carries over a '.', '+' or
    '-' that sqlglot keeps as a token of its own (see _TSQL_MONEY_TOKEN),
    unless the literal's digits follow it. A quoted identifier may follow
    instead: SQL Server reads it as the literal's alias, never a statement."""
    signs = (TokenType.DASH, TokenType.PLUS)
    for i, token in enumerate(tokens[:-1]):
        sep = tokens[i + 1]
        if token.token_type == TokenType.NUMBER:
            # 1e- / 1.5E+: sqlglot keeps an exponent's own digits in the NUMBER
            if token.text[-1:] not in "eE" or sep.token_type not in signs or sep.start != token.end + 1:
                continue
            digits = _TSQL_DIGITS
        elif (
            token.token_type in (TokenType.VAR, TokenType.IDENTIFIER)
            and sql[token.start : token.end + 1] == token.text
            and _TSQL_MONEY_TOKEN.fullmatch(token.text)
        ):
            if sep.token_type == TokenType.DOT:
                digits = _TSQL_DIGITS
            elif sep.token_type in signs and len(token.text) == 1:
                # only a bare currency symbol takes a sign: $1-x is a subtraction
                digits = _TSQL_SIGNED_MONEY
            else:
                continue
        else:
            continue
        end, after = sep, tokens[i + 2 : i + 4]
        if digits is _TSQL_SIGNED_MONEY and after and after[0].token_type == TokenType.DOT:
            if after[0].start == sep.end + 1:  # $-.5: the '.' belongs to the literal as well
                end, after, digits = after[0], after[1:], _TSQL_DIGITS
        nxt = after[0] if after else None
        if nxt is not None and (
            (nxt.token_type == TokenType.IDENTIFIER and sql[nxt.start : nxt.end + 1] != nxt.text)
            or (nxt.token_type == TokenType.NUMBER and nxt.start == end.end + 1 and digits.fullmatch(nxt.text))
        ):
            continue
        literal = sql[token.start : end.end + 1]
        raise _deny(
            f"'{literal}' is not permitted: SQL Server reads a money or float literal up to this "
            f"'{end.text}' and would run the word after it as a separate statement; write the literal "
            f"with its digits (for example $1.00, $-1 or 1e-5)"
        )


def _tsql_plain(text: str) -> bool:
    return text.isascii() and text.isprintable() and not text.endswith(" ")


def _tsql_loose_name(name: str) -> ToolFailure:
    return _deny(
        f"the name {ascii(name)} is not permitted on SQL Server: its collation reads a name outside printable "
        f"ASCII, or with a trailing blank, as another (it ignores many characters and reads full-width and "
        f"small-capital letters and ligatures as ASCII ones), so no check here could tell which column or "
        f"object it names; write it in printable ASCII without a trailing blank"
    )


def _deny_tsql_loose_tokens(tokens: list[Token]) -> None:
    """Refuse code outside printable ASCII on SQL Server (_TSQL_LITERAL_TOKENS):
    a name, and a word sqlglot takes for a keyword that SQL Server does not
    (sqlglot reads ſelect as SELECT). Aliases written as strings are names
    too; _check_name sees them in the tree."""
    for token in tokens:
        if token.token_type in _TSQL_LITERAL_TOKENS:
            continue
        if token.token_type == TokenType.VAR and _TSQL_WHOLE_TOKEN.fullmatch(token.text):
            continue  # a money literal, or a $ pseudo-column
        if not _tsql_plain(token.text):
            raise _tsql_loose_name(token.text)


def _deny_clickhouse_identifier_escapes(sql: str, tokens: list[Token]) -> None:
    """Refuse a quoted identifier with a backslash in it on ClickHouse, which
    decodes \\xHH, \\n, \\0, \\\\ and the rest in a backquoted or double-quoted
    name as it does in a string, while sqlglot keeps the text as written
    (live, 26.3: `on\\x65` in database system reads system.one). Every check
    compared another name than the one ClickHouse reads: `msisd\\x6e` AS x
    returned a masked column in clear, and system.`query_lo\\x67` other
    sessions' SQL (review, 2026-09-28). Checked on the source text, since
    sqlglot's own reading drops the backslash of \\` and \\"."""
    for token in tokens:
        if token.token_type == TokenType.IDENTIFIER and "\\" in sql[token.start : token.end + 1]:
            raise _deny(
                f"the quoted identifier {sql[token.start : token.end + 1]} is not permitted: ClickHouse decodes "
                f"backslash escapes in a quoted identifier, so it would read a name other than the one written; "
                f"write the name without escape sequences (a backquote inside backquotes is doubled: ``)"
            )


def _deny_unicode_escape_identifiers(sql: str, tokens: list[Token]) -> None:
    """Refuse a Unicode-escape identifier, U&"..." (or u&), on PostgreSQL,
    which decodes it, while sqlglot reads the column U, '&' and a quoted
    name as written: U&"sea_temp_\\0063" returned the masked sea_temp_c in
    clear (live, review of 2026-09-28). The three tokens are adjacent in
    the text, as PostgreSQL's lexer needs them; a U&'...' string is a
    token of its own and stays. Db2, validated as PostgreSQL, reads U & "..."
    (live: SQL0206N on the column U), so refusing it there loses nothing.
    No other engine decodes a name: T-SQL, Oracle, MySQL and SQLite double
    a quote and nothing else, and ClickHouse's backslash escapes are
    refused above."""
    for u, amp, ident in zip(tokens, tokens[1:], tokens[2:], strict=False):
        if (
            u.token_type == TokenType.VAR
            and sql[u.start : u.end + 1] in ("U", "u")
            and amp.token_type == TokenType.AMP
            and amp.start == u.end + 1
            and ident.token_type == TokenType.IDENTIFIER
            and ident.start == amp.end + 1
            and sql[ident.start] == '"'
        ):
            raise _deny(
                f"the identifier {sql[u.start : ident.end + 1]} is not permitted: PostgreSQL decodes the Unicode "
                f"escapes of a U&\"...\" name and the validator does not, so it would read a name other than the "
                f"one written (Db2 is validated as PostgreSQL); write the name itself, in double quotes where it "
                f"needs them"
            )


def _deny_postgres_at_operators(tokens: list[Token]) -> None:
    """Refuse the '@' sqlglot reads as a parameter on PostgreSQL, where it is
    an operator: @ x is the absolute value of the column x (live, review of
    2026-09-28: SELECT @ sea_temp_c returned the masked column in clear, the
    validator seeing a parameter and no column), and it ends @@@ and ^@.
    Its placeholder is $n, a '$' token; @>, <@, @@ and @? are tokens of
    their own, parsed as the operators they are."""
    if any(token.token_type == TokenType.PARAMETER and token.text == "@" for token in tokens):
        raise _deny(
            "'@' is not permitted on PostgreSQL outside the operators @>, <@, @@ and @?: PostgreSQL reads @ x as "
            "the absolute value of the column x (and @@@, ^@ as operators on it), which the validator reads as a "
            "parameter, so no check sees the column; write abs(x)"
        )


_DATABASE_LINKS = "database links / remote-object references (@link) are not permitted"


def _deny_oracle_database_links(sql: str, tokens: list[Token]) -> None:
    """Refuse an '@' in Oracle code: it names a database link however it is
    spaced or quoted, and sqlglot reads "T"@lnk, t @lnk and t/**/@lnk as a
    table aliased @lnk, so a table the allowlists permit, DUAL included,
    was read on a remote database (live, review of 2026-09-28: ORA-02019).
    Oracle has no other '@' outside a literal, a quoted identifier, a
    comment or a hint (whose @query_block names no database)."""
    for token in tokens:
        text = sql[token.start : token.end + 1]
        if token.token_type in _TSQL_LITERAL_TOKENS or (token.token_type == TokenType.IDENTIFIER and text[:1] == '"'):
            continue
        if "@" in text:
            raise _deny(
                f"{_DATABASE_LINKS}: Oracle reads '@' outside a literal, a quoted name or a comment as a link to "
                f"another database, which no allowlist here covers"
            )


# ClickHouse evaluates the function in(v, t) as v IN t, reading the table t,
# and after IN sqlglot reads `x IN in(v, db.t)` as In(this=In(x),
# expressions=[v, db.t]): an IN with nothing after it, inside one whose list
# holds db.t as a column (live, 26.3: 1 IN in(0, system.one) is 1, past a
# closed system schema). No engine reads IN without a right-hand side as
# sqlglot does, so it is refused everywhere, as is IN straight after IN.
_FUNCTIONAL_IN = (
    "IN with nothing after it, or IN right after IN, is not permitted: it is how the validator reads "
    "x IN in(v, t), and ClickHouse evaluates the function in(v, t) as v IN t, which reads the table t past "
    "every check on the tables a statement reads; write x IN (SELECT <column> FROM <schema>.<table>) or a list"
)
# ClickHouse functions that read the table or dictionary an argument names:
# the IN family (notIn, globalIn, nullIn, inIgnoreSet, ... live, 26.3),
# joinGet (a Join table), the dict* functions (a dictionary, whose source
# may be any table of the server) and hasColumnInTable. Unknown to sqlglot
# today, so refused as such anyway; named here to survive a parser that
# learns them (_names_a_table_argument).
_CLICKHOUSE_TABLE_ARGUMENT_FUNCTIONS = re.compile(
    r"(?:global)?(?:not)?(?:null)?in(?:ignoreset)?|joinget(?:ornull)?|dict\w*|hascolumnintable"
)
_TABLE_ARGUMENT_HINT = "write x [NOT] IN (SELECT <column> FROM <schema>.<table>), or a JOIN"
# MySQL's @@name and SQL Server's @@NAME read the server's configuration and
# its host: data directory, host name, file paths (review, 2026-09-28). The
# function spellings (SERVERPROPERTY, current_setting) are refused as
# unknown functions already. The server's version is not among the reasons:
# db_test_connection reports it to any caller, and version() stays allowed.
_SERVER_VARIABLES = (
    "server and session variables (@@name) are not permitted: they read the server's configuration and its "
    "host (data directory, host name, file paths); the server version is reported by db_test_connection"
)


def _names_a_table_argument(name: str) -> bool:
    """``name`` is one of _CLICKHOUSE_TABLE_ARGUMENT_FUNCTIONS as ClickHouse
    spells it (joinGet) or as sqlglot names a function class it learns:
    sql_name() spells the class name in snake case (has() already comes
    back as ARRAY_CONTAINS), so a JoinGet class would read JOIN_GET."""
    return _CLICKHOUSE_TABLE_ARGUMENT_FUNCTIONS.fullmatch(name.lower().replace("_", "")) is not None


def _deny_in_after_in(tokens: list[Token]) -> None:
    for before, token in zip(tokens, tokens[1:], strict=False):
        if before.token_type == TokenType.IN and token.token_type == TokenType.IN:
            raise _deny(_FUNCTIONAL_IN)


def _clickhouse_from_names(select: exp.Select) -> frozenset[str]:
    """The names a qualifier binds to in ``select``'s FROM and JOINs, as
    ClickHouse binds them (live, 26.3): each item's alias, and a table's own
    name, aliased or not. An ARRAY JOIN's alias names a value, as do a
    select alias, a WITH <expression> AS name and a CTE the FROM does not
    name: ClickHouse reads a.b as the table a.b where a is only one of
    those, and where a table may stand."""
    items: list[exp.Expr] = []
    from_ = select.args.get("from_")
    if isinstance(from_, exp.From):
        items.append(from_.this)
    items += [j.this for j in select.args.get("joins") or [] if str(j.args.get("kind") or "").upper() != "ARRAY"]
    names: set[str] = set()
    for item in items:
        if item.alias:
            names.add(item.alias)
        if isinstance(item, exp.Table) and isinstance(item.this, exp.Identifier):
            names.add(item.name)
    return frozenset(names)


def _clickhouse_value_names(select: exp.Select) -> frozenset[str]:
    """The names ``select`` gives values rather than tables - its ARRAY JOIN
    aliases, select aliases and WITH <expression> AS name - which make a.b
    the subcolumn b of that value in an expression (live, 26.3: n.x of
    ARRAY JOIN arr AS n, t.x of a named tuple t) and the table a.b where a
    table may stand."""
    names = {j.this.alias for j in select.args.get("joins") or [] if str(j.args.get("kind") or "").upper() == "ARRAY"}
    names |= {e.alias for e in select.expressions if isinstance(e, exp.Alias)}
    with_ = select.args.get("with_")
    if isinstance(with_, exp.With):
        names |= {cte.alias for cte in with_.expressions if cte.args.get("scalar")}
    return frozenset(names - {""})


# a column-shaped a.b no FROM item in reach binds, as the table a.b, and
# whether a is a value's name in reach (_clickhouse_value_names)
_ClickHouseUnbound = tuple[exp.Table, bool]


def _clickhouse_unbound_columns(root: exp.Expr) -> dict[int, _ClickHouseUnbound]:
    """Each column-shaped a.b whose qualifier a no FROM item in reach names
    (_clickhouse_from_names of the query it stands in and of the queries
    around it), by id, as the table a.b. Where a table may stand -
    in(v, a.b), after IN, joinGet's first argument - ClickHouse binds a
    name that is no column to a table (live, 26.3: 1 IN in(0, system.one)
    read system.one), and sqlglot has placed such tables in shapes no other
    check saw; a FROM item named a binds a.b as its column, and ClickHouse
    refuses one it lacks. Three or more parts are never a table there
    ("Expected identifier to contain 1 or 2 parts").

    A query's FROM items are in reach of its expressions and of the
    subqueries in them (and so of a CTE or derived table inside one), and
    of a WITH <expression> AS name; not of its CTE bodies nor of the
    derived tables in its FROM, which ClickHouse resolves in the scope
    around the query (live, 26.3: in WITH c AS (SELECT 0 IN ((system.one AS
    z)) AS x) SELECT c.x FROM c, numbers(1) AS system, and with the same
    subquery in the FROM ahead of numbers(1) AS system, system.one was read
    as the table; a derived table after it binds the name, and fails:
    ClickHouse has no lateral joins)."""
    unbound: dict[int, _ClickHouseUnbound] = {}
    empty: frozenset[str] = frozenset()
    pending: list[tuple[exp.Expr, frozenset[str], frozenset[str]]] = [(root, empty, empty)]
    while pending:  # a long UNION is one deep tree: no recursion
        node, names, values = pending.pop()
        if isinstance(node, exp.Column):
            table, column = node.args.get("table"), node.this
            if (
                isinstance(table, exp.Identifier)
                and isinstance(column, exp.Identifier)
                and not node.args.get("db")
                and not node.args.get("catalog")
                and table.name not in names
            ):
                unbound[id(node)] = (exp.Table(this=column.copy(), db=table.copy()), table.name in values)
            continue
        if not isinstance(node, exp.Select):
            pending.extend((child, names, values) for child in node.iter_expressions())
            continue
        around = (names, values)
        inside = (names | _clickhouse_from_names(node), values | _clickhouse_value_names(node))
        for child in node.iter_expressions():
            if isinstance(child, exp.With):
                for cte in child.iter_expressions():
                    pending.append((cte, *(inside if cte.args.get("scalar") else around)))
            elif isinstance(child, (exp.From, exp.Join)):
                for part in child.iter_expressions():
                    derived = part is child.this and isinstance(part, exp.Subquery)
                    pending.append((part, *(around if derived else inside)))
            else:
                pending.append((child, *inside))
    return unbound


# Dialects where sqlglot, like the engine, reads '#' as a line comment.
_HASH_COMMENT_DIALECTS = frozenset({"mysql", "clickhouse"})


def _deny_comment_disagreements(sql: str, tokens: list[Token], dialect: str) -> None:
    """Refuse text whose comments the engine bounds differently from sqlglot.

    Every check in this module sees sqlglot's tokens, while the engine runs
    the text, so the engine must skip exactly what sqlglot skipped: the
    whitespace and comments between two tokens. Checked live on each fixture
    engine, the two disagree in two ways:
    - sqlglot ends a line comment at a bare CR. MySQL, Oracle, Db2, SQLite
      and ClickHouse read on to the next LF, so after `-- x\\r'`
      sqlglot sees a quoted alias where the engine runs `UNION SELECT ...`.
      SQL Server does end it at the CR, but the T-SQL hidden-separator check
      reads such a comment on to the LF.
    - MySQL (and MariaDB, by its documentation) opens a -- comment only when
      whitespace or a control character follows it: `id = 1 --1 UNION
      SELECT ...` runs there as `1 - -1 UNION ...`.
    Block comments nest on the same engines for both. A nested opener is
    refused anyway, rather than relying on that staying true.
    """
    pos = 0
    for token in tokens:
        if token.token_type == TokenType.HINT:
            continue  # /*+ ... */ is comment text to the engine: checked below as skipped text
        if token.start > pos:
            _check_skipped_text(sql, pos, token.start, dialect)
        pos = max(pos, token.end + 1)
    _check_skipped_text(sql, pos, len(sql), dialect)


def _check_skipped_text(sql: str, start: int, end: int, dialect: str) -> None:
    i = start
    while i < end:
        if sql[i].isspace():
            i += 1
        elif sql.startswith("/*", i):
            close = sql.find("*/", i + 2, end)
            if close == -1 or sql.find("/*", i + 2, close) != -1:
                raise _deny(
                    "nested or unterminated block comments are not permitted: engines disagree on where they end"
                )
            i = close + 2
        elif sql.startswith("--", i) or (sql[i] == "#" and dialect in _HASH_COMMENT_DIALECTS):
            follower = sql[i + 2 : i + 3]
            if dialect == "mysql" and sql[i] == "-" and follower > " " and follower != "\x7f":
                raise _deny(
                    "'--' without a following space is not a comment on MySQL/MariaDB (it reads as two minus "
                    "signs) but the validator reads it as one; write '-- ' or /* */ for a comment"
                )
            newline = sql.find("\n", i, end)
            if newline == -1 and end < len(sql):
                raise _deny(
                    "a line comment ended by a bare carriage return (CR without LF) is not permitted: "
                    "engines disagree on whether it ends there, so the text after it would not be validated"
                )
            i = end if newline == -1 else newline + 1
        else:
            raise _deny(
                f"text at offset {i} was skipped by the validator but is not whitespace or a comment; "
                f"refusing unvalidated SQL"
            )


def _func_name(node: Any) -> str | None:
    if isinstance(node, exp.Anonymous):
        return node.name
    if isinstance(node, exp.Func):
        return node.sql_name()
    return None


def _deny_with_after_set_operator(root: exp.Expression) -> None:
    """Refuse a WITH written after UNION, INTERSECT or EXCEPT without
    parentheses around its query. sqlglot hangs it over every branch after
    that operator; ClickHouse, the one engine that accepts the text, applies
    it to the SELECT it precedes alone (live, 26.3: in SELECT 1 UNION ALL
    WITH t AS (...) SELECT * FROM t UNION ALL SELECT * FROM t the last t is
    the table), so the guard took a table for the CTE. PostgreSQL, MySQL,
    SQLite and Oracle (ORA-32034) reject the text."""
    for with_ in root.find_all(exp.With):
        if isinstance(with_.parent, exp.SetOperation) and isinstance(with_.parent.parent, exp.SetOperation):
            raise _deny(
                "a WITH after UNION, INTERSECT or EXCEPT is not permitted without parentheses around its query: "
                "engines differ over the branches it covers; write (WITH ... SELECT ...) as that branch, or the "
                "WITH ahead of the whole statement"
            )


# ClickHouse binds a FROM item's name to a CTE its own way (live, 26.3.3): a
# CTE sees the others of its WITH, declared before it or after it, but not
# itself, nor one it is being resolved through - there the name reads the
# table (or a CTE of an enclosing query) - except in the recursion of WITH
# RECURSIVE (clickhouse_recursive_branches). A WITH ahead of a set operation
# is copied into the branches after the first, without RECURSIVE
# (clickhouse_copies_with).
_CLICKHOUSE_CTE_NOTE = (
    "a CTE of that name does not cover this reference: ClickHouse reads the table there (a CTE covers the "
    "query its WITH belongs to, names are case-sensitive, WITH <expression> AS name names a value, and a CTE "
    "names itself only after the first branch of a WITH RECURSIVE ... UNION ALL body)"
)


def _cte_name(cte: exp.CTE) -> str | None:
    """The name a relation CTE declares, as written; None for ClickHouse's
    WITH <expression> AS name, which names a value."""
    alias = cte.args.get("alias")
    if cte.args.get("scalar") or not isinstance(alias, exp.TableAlias) or not isinstance(alias.this, exp.Identifier):
        return None
    return str(alias.this.this)


def clickhouse_copies_with(with_: exp.With) -> bool:
    """Whether ClickHouse copies ``with_`` into the branches of a set
    operation after the first (live, 26.3): it heads the UNION, INTERSECT
    or EXCEPT, or its query is, in parentheses, the first operand of one.
    The copies are not RECURSIVE."""
    node = with_.parent
    if isinstance(node, exp.SetOperation):
        return True
    while node is not None and isinstance(node.parent, exp.Subquery) and not node.parent.alias:
        node = node.parent
    return node is not None and isinstance(node.parent, exp.SetOperation) and node.arg_key == "this"


def clickhouse_recursive_branches(cte: exp.CTE) -> list[exp.Expr]:
    """The branches of ``cte``'s body in which ClickHouse binds the CTE's own
    name to the CTE: under WITH RECURSIVE, with a UNION ALL body (a union in
    parentheses flattened into it), every branch after the first. The first,
    the anchor, reads the table of that name, as any other body does; so
    does a WITH ClickHouse copies (clickhouse_copies_with)."""
    with_ = cte.parent
    if not isinstance(with_, exp.With) or not with_.recursive or clickhouse_copies_with(with_):
        return []
    branches: list[exp.Expr] = []
    pending: list[exp.Expr] = [cte.this]
    while pending:  # a long UNION is one deep tree: no recursion
        node = pending.pop()
        inner = node.this if isinstance(node, exp.Subquery) and not node.alias else None
        if isinstance(inner, exp.SetOperation) and not inner.args.get("with_"):
            pending.append(inner)
        elif isinstance(node, exp.SetOperation):
            if not isinstance(node, exp.Union) or node.args.get("distinct") is not False:
                return []  # ClickHouse recurses through UNION ALL alone
            pending += [node.expression, node.this]
        else:
            branches.append(node)
    return branches[1:]


# What ClickHouse binds a bare FROM item to: None for the table of its name,
# else (the CTE whose body names it, or None from a query's own FROM, the CTE)
_ClickHouseBinding = tuple[exp.CTE | None, exp.CTE] | None


def _clickhouse_binding(
    table: exp.Table,
    name: str,
    declared: dict[int, dict[str, exp.CTE]],
    branch_of: dict[int, tuple[str, exp.CTE]],
    memo: dict[tuple[int, str], _ClickHouseBinding],
) -> _ClickHouseBinding:
    """What ClickHouse binds the bare FROM item ``table`` to by ``name``. Up
    from it, the first query whose WITH declares the name binds it, but a
    CTE's own body skips the CTE itself outside its recursion. ``declared``:
    per WITH, the CTE of each name; ``branch_of``: each recursive branch's
    CTE and name; ``memo``: the answer from each node walked so far, per
    name (a long UNION is one deep tree its branches share)."""
    walked: list[tuple[int, str]] = []
    node: exp.Expr = table
    found: _ClickHouseBinding = None
    while node.parent is not None:
        if (id(node), name) in memo:
            found = memo[(id(node), name)]
            break
        walked.append((id(node), name))
        recursion = branch_of.get(id(node))
        if recursion is not None and recursion[0] == name:
            found = (recursion[1], recursion[1])
            break
        parent = node.parent
        if isinstance(parent, exp.With) and isinstance(node, exp.CTE):
            cte = declared[id(parent)].get(name)
            if cte is not None and cte is not node:
                found = (node, cte)
                break
        else:
            with_ = parent.args.get("with_")
            if isinstance(with_, exp.With) and node is not with_ and name in declared[id(with_)]:
                found = (None, declared[id(with_)][name])
                break
        node = parent
    for key in walked:
        memo[key] = found
    return found


def _deny_clickhouse_rebinding(
    table: exp.Table,
    binding: _ClickHouseBinding,
    decls: dict[str, list[exp.CTE]],
    spans: dict[int, tuple[int, int]],
    placed: dict[int, tuple[int, exp.CTE | None]],
) -> None:
    """Refuse a bare name in a CTE's body that another CTE of the statement
    declares as well, unless the body binds it itself. ClickHouse resolves a
    CTE's body where the CTE is used, not where it is written (live, 26.3.3,
    review of 2026-09-28): in WITH b AS (...), processes AS (SELECT * FROM b)
    SELECT query FROM (WITH b AS (SELECT * FROM processes) SELECT * FROM
    processes), processes' b is the inner b, whose processes is being resolved
    and so reads the table - system.processes past default-deny, while the
    guard bound every name where it is written. Such a name is bound (by
    _clickhouse_binding) outside the body, so the body can be used where a
    CTE of that name declared elsewhere covers it instead; one it binds inside
    keeps that binding wherever it is used, and a CTE the reference lies in
    is skipped by ClickHouse wherever that is."""
    position, body = placed[id(table)]
    if body is None:
        return  # outside every CTE's body: bound where it is written
    bound = binding[1] if binding is not None else None
    start, end = spans[id(body)]
    if bound is not None and start < spans[id(bound)][0] <= end:
        return
    for other in decls[table.name]:
        first, last = spans[id(other)]
        if other is bound or first <= position <= last:
            continue
        raise _deny(
            f"the CTE {_cte_name(body)} reads '{table.name}', which the statement declares as a CTE elsewhere as "
            f"well: not permitted on ClickHouse, which resolves a CTE's body where the CTE is used, not where it is "
            f"written, so that other CTE can stand in for it there (and through it a name being resolved reads "
            f"its table); give the CTEs distinct names"
        )


def _cte_spans(
    root: exp.Expr, ctes: set[int]
) -> tuple[dict[int, tuple[int, int]], dict[int, tuple[int, exp.CTE | None]]]:
    """Pre-order positions in ``root``: for each CTE whose id is in ``ctes``
    the span its subtree covers, and for each Table its position and the
    innermost of those CTEs it lies in (None outside all of them)."""
    spans: dict[int, tuple[int, int]] = {}
    tables: dict[int, tuple[int, exp.CTE | None]] = {}
    open_ctes: list[tuple[exp.CTE, int]] = []
    order = 0
    pending: list[tuple[exp.Expr, bool]] = [(root, False)]
    while pending:  # a long UNION is one deep tree: no recursion
        node, closing = pending.pop()
        if closing:
            cte, start = open_ctes.pop()
            spans[id(cte)] = (start, order)
            continue
        order += 1
        if isinstance(node, exp.Table):
            tables[id(node)] = (order, open_ctes[-1][0] if open_ctes else None)
        if isinstance(node, exp.CTE) and id(node) in ctes:
            open_ctes.append((node, order))
            pending.append((node, True))
        pending.extend((child, False) for child in node.iter_expressions())
    return spans, tables


def _cte_cycle(edges: dict[int, list[exp.CTE]]) -> list[exp.CTE]:
    """CTEs that name each other round a cycle, or none. ``edges``: from each
    CTE's id, the other CTEs of its WITH its body names."""
    state: dict[int, bool] = {}  # False while on the path, True once done
    for start in edges:
        if start in state:
            continue
        path: list[int] = [start]
        state[start] = False
        ctes: dict[int, exp.CTE] = {}
        pending = [iter(edges[start])]
        while pending:
            cte = next(pending[-1], None)
            if cte is None:
                state[path.pop()] = True
                pending.pop()
            elif state.get(id(cte)) is False:
                return [ctes[key] for key in path[path.index(id(cte)) + 1 :]] + [cte]
            elif id(cte) not in state:
                state[id(cte)] = False
                ctes[id(cte)] = cte
                path.append(id(cte))
                pending.append(iter(edges.get(id(cte), ())))
    return []


# Db2 read-only tail clauses. sqlglot has no Db2 dialect (statements are parsed
# under postgres), so `SELECT ... WITH UR` - the standard Db2 reporting idiom
# that avoids lock waits - failed to parse and every such query was denied.
# These clauses only choose an isolation level or state read intent; none of
# them can write. They are removed for VALIDATION only: the executor sends the
# original text, so Db2 still receives the clause.
# The pattern starts at the keyword behind a fixed-width lookbehind, never at
# a leading \s+: the unanchored sub() retried \s+ from every position of a
# whitespace run, O(n^2) with the GIL held (~25 s for one 64 KiB statement).
# A possessive \s++ is still quadratic. The caller's rstrip() removes the
# whitespace the old leading \s+ used to consume.
_DB2_READ_TAIL = re.compile(
    r"(?<=\s)(?:"
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

# EXPLAIN options that only shape the printed plan and never execute the
# statement. db_explain sends 'EXPLAIN ' + GuardResult.text, so the validated
# options are re-rendered into that text: dropping them would silently return
# a different plan than the one asked for. PostgreSQL FORMAT JSON is left out
# because the connector renders text plans (a json-typed plan fails there).
_PG_EXPLAIN_FLAGS = frozenset({"COSTS", "VERBOSE", "SETTINGS", "SUMMARY", "GENERIC_PLAN"})
_PG_EXPLAIN_FORMATS = frozenset({"TEXT", "XML", "YAML"})
_PG_EXPLAIN_BOOLEANS = frozenset({"TRUE", "FALSE", "ON", "OFF", "1", "0"})
_PG_EXPLAIN_OPTION = re.compile(r"\s*([A-Za-z_]+)(?:\s+([A-Za-z0-9_]+))?\s*")
_MYSQL_EXPLAIN_FORMATS = frozenset({"TRADITIONAL", "JSON", "TREE"})
# ANALYZE with allow_explain_analyze on: the option list and the bare keyword
# are refused alike, never dropped from the text (the caller would get a plain
# plan in place of the executed one it asked for).
_EXPLAIN_ANALYZE_UNSUPPORTED = (
    "EXPLAIN option 'ANALYZE' is not supported by db_explain: plans are captured without executing the "
    "statement; use EXPLAIN <statement>"
)


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
        # (statement, its names, whether it reads every column): _statement_columns
        self._columns_of: tuple[exp.Expression, frozenset[str], bool] | None = None
        # the names default-deny matched to listed tables that the server checks against how the
        # session binds names (_check_listed_spelling), from every statement this guard validated
        self.bindings: list[ListedBinding] = []

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

    def _postgres_explain_options(self, options: str) -> str:
        """Re-render a validated PostgreSQL option list, '(...)', for the engine."""
        if self._engine != "postgres":
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"EXPLAIN option lists are not supported on engine '{self._engine}'; use EXPLAIN <statement>",
            )
        rendered: list[str] = []
        for item in options[1:-1].split(","):
            m = _PG_EXPLAIN_OPTION.fullmatch(item)
            name, value = (m.group(1).upper(), (m.group(2) or "").upper()) if m else ("", "")
            if name == "FORMAT" and value == "JSON":
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    "EXPLAIN option FORMAT JSON is not available through db_explain on PostgreSQL; "
                    "use FORMAT YAML or FORMAT XML for a structured plan",
                )
            if name in ("ANALYZE", "ANALYSE"):
                raise ToolFailure(ErrorCategory.VALIDATION, _EXPLAIN_ANALYZE_UNSUPPORTED)
            if (name == "FORMAT" and value in _PG_EXPLAIN_FORMATS) or (
                name in _PG_EXPLAIN_FLAGS and (not value or value in _PG_EXPLAIN_BOOLEANS)
            ):
                rendered.append(f"{name} {value}".rstrip())
                continue
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"EXPLAIN option '{item.strip()}' is not supported by db_explain; accepted: "
                f"FORMAT TEXT|XML|YAML and COSTS, VERBOSE, SETTINGS, SUMMARY, GENERIC_PLAN [boolean]",
            )
        return "(" + ", ".join(rendered) + ") "

    def _parse_single(self, sql: str, kind: str) -> exp.Expression:
        if "\x00" in sql:
            raise _deny("statement contains a NUL byte")
        if len(sql) > _MAX_SQL_BYTES:
            raise ToolFailure(
                ErrorCategory.VALIDATION,
                f"statement exceeds the {_MAX_SQL_BYTES} byte limit",
            )
        if _EXECUTABLE_COMMENT.search(sql):
            raise _deny("executable comments (/*! ... */, /*M! ... */) are not permitted")
        stripped = sql.strip().rstrip(";").strip()
        if not stripped:
            raise ToolFailure(ErrorCategory.VALIDATION, "empty statement")
        if self._dialect == "tsql":
            # Checked on the submitted text, not `stripped`: str.strip() eats
            # 0x0B, 0x0C and 0x1C-0x1F, and the server sends the original.
            _, code_view = _rewrite_code_segments(sql, lambda seg: seg, backslash_escapes=False)
            hidden = _TSQL_HIDDEN_SEPARATOR.search(code_view)
            if hidden:
                raise _deny(
                    f"control or zero-width character U+{ord(hidden.group()):04X} is not permitted outside "
                    f"a string literal or quoted identifier: SQL Server reads it as a statement separator"
                )
        if self._dialect == "mysql":
            # Defense in depth: sqlglot already falls back to a denied Command
            # for a leading SET STATEMENT; this names the refusal and does not
            # depend on that fallback. Literals and comments are blanked first.
            _, code_view = _rewrite_code_segments(stripped, lambda seg: seg, backslash_escapes=True)
            code_view = _MYSQL_HASH_COMMENT.sub(lambda m: " " * len(m.group()), code_view)
            if _SET_STATEMENT.search(code_view):
                raise _deny(
                    "SET STATEMENT ... FOR is not permitted: it overrides session variables "
                    "(transaction_read_only, max_statement_time) for the statement"
                )
        if self._engine == "db2":
            if _DB2_SEQUENCE.search(stripped):
                raise _deny("sequence expressions (NEXT VALUE FOR ...) are not permitted: they advance the sequence")
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
                # sqlglot.parse, with the tokens kept for the comment check below
                dialect = Dialect.get_or_raise(self._dialect)
                tokens = dialect.tokenize(candidate)
                statements = dialect.parser().parse(tokens, candidate)
                break
            except (sqlglot.errors.SqlglotError, ValueError, RecursionError) as exc:
                # SqlglotError is the base of ParseError and of the tokenizer's
                # TokenError (unterminated literal, comment or [identifier]),
                # which used to escape as INTERNAL_ERROR instead of a denial.
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
        if not isinstance(root, exp.Command):
            # A Command's tokens do not map back onto its text, and nothing
            # but validate_show (whose text has no comments) accepts one.
            _deny_comment_disagreements(candidate, tokens, self._dialect)
        _deny_in_after_in(tokens)
        if self._dialect == "clickhouse":
            _deny_clickhouse_identifier_escapes(candidate, tokens)
        if self._dialect == "postgres":
            _deny_unicode_escape_identifiers(candidate, tokens)
            _deny_postgres_at_operators(tokens)
        if self._dialect == "oracle":
            _deny_oracle_database_links(candidate, tokens)
        if self._dialect == "tsql":
            _deny_tsql_fused_literals(candidate, tokens)
            _deny_tsql_split_literals(candidate, tokens)
            _deny_tsql_hidden_statements(cast(exp.Expression, root))
            _deny_tsql_loose_tokens(tokens)
        return cast(exp.Expression, root)

    def _walk_validate(self, root: exp.Expression) -> list[ObjectRef]:
        _deny_with_after_set_operator(root)
        cte_aliases: set[str] = set()
        for cte in root.find_all(exp.CTE):
            cte_aliases.add(cte.alias_or_name.lower())
        # ClickHouse: exactly the bare names it binds to a CTE; elsewhere every
        # name a CTE declares (the server checks those out of reach)
        cte_refs = self._clickhouse_cte_refs(root) if self._dialect == "clickhouse" else None
        for placeholder in root.find_all(exp.Placeholder):
            # checked before the walk reaches a FROM item it names
            kind = placeholder.args.get("kind")
            if isinstance(kind, str) and kind.lower() == "identifier":
                raise _deny(
                    "ClickHouse identifier parameters ({name:Identifier}) are not permitted: the table or "
                    "column they name is bound after validation; write the name in the statement"
                )

        for ident in root.find_all(exp.Identifier):
            # before any table check, which would compare the name as written
            self._check_name(ident)
        unbound = _clickhouse_unbound_columns(root) if self._dialect == "clickhouse" else {}

        refs: list[ObjectRef] = []
        for node in root.walk():
            if isinstance(node, _DENIED_NODES):
                raise _deny(f"statement contains a disallowed construct ({type(node).__name__})")
            if isinstance(node, exp.SessionParameter) or (
                isinstance(node, exp.Parameter) and isinstance(node.this, exp.Parameter)
            ):
                raise _deny(_SERVER_VARIABLES)
            if isinstance(node, exp.Parameter):
                self._check_parameter(node)
            if id(node) in unbound:
                self._check_unbound_column(unbound[id(node)], root, refs)
            if isinstance(node, exp.NextValueFor):
                # a read that advances a sequence is a write
                raise _deny("sequence access (NEXT VALUE FOR) is not permitted: it advances the sequence")
            if isinstance(node, exp.WithTableHint):
                for hint in node.expressions:
                    hint_name = hint.name if isinstance(hint, exp.Var | exp.Identifier | exp.Column) else hint.sql()
                    if hint_name.upper() not in _ALLOWED_TABLE_HINTS:
                        raise _deny(
                            f"table hint '{hint_name}' is not permitted on a read-only connection "
                            f"(only NOLOCK, READUNCOMMITTED, READPAST and NOWAIT are accepted)"
                        )
            if (
                isinstance(node, exp.Column)
                and self._engine in ("oracle", "db2")
                and node.name.lower() in ("nextval", "currval")
            ):
                raise _deny(f"sequence pseudo-column '{node.name}' is not permitted: it advances or reads a sequence")
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
                if name and self._dialect == "clickhouse" and _names_a_table_argument(name):
                    raise _deny(
                        f"function '{name}' is not permitted on ClickHouse: it names a table or dictionary in its "
                        f"arguments and reads it, past every check on the tables a statement reads; "
                        + _TABLE_ARGUMENT_HINT
                    )
                if isinstance(node, exp.Anonymous):
                    raise _deny(
                        f"unknown or unsupported function '{name}' is not permitted (function allowlist is closed)"
                    )
            if isinstance(node, exp.In):
                self._check_in(node)
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
                named_like_a_cte = schema is None and catalog is None and name.lower() in cte_aliases
                if named_like_a_cte and (cte_refs is None or id(node) in cte_refs):
                    self._check_cte_namesake(node, root)
                    continue
                if self._dialect == "mysql" and schema is None and catalog is None and not inner.quoted:
                    if name.upper() == "DUAL":
                        continue  # MySQL's FROM DUAL names no table; a table called dual must be quoted
                if catalog is None and self._data_free(node):
                    refs.append(ObjectRef(schema=schema, name=name, catalog=None, looked_up=self._looked_up_ref(node)))
                    continue
                try:
                    self._authorize_table(node, root)
                except ToolFailure as exc:
                    if not named_like_a_cte:
                        raise
                    # ClickHouse reads the table here (_clickhouse_cte_refs)
                    text = str(exc).removeprefix(f"{exc.category}: ")
                    raise ToolFailure(exc.category, f"{text}; {_CLICKHOUSE_CTE_NOTE}") from exc
                refs.append(ObjectRef(schema=schema, name=name, catalog=catalog, looked_up=self._looked_up_ref(node)))
        return refs

    def _authorize_table(self, table: exp.Table, root: exp.Expression) -> None:
        """The checks a table the statement reads goes through: the views no
        allowlist opens first, then the value columns of a column catalog,
        qualification under an allowlist, the schema's spelling, and the
        policy and resolver (_check_ref), on the dictionary object the engine
        reads in its place where it reads one (_check_bound)."""
        schema, name, catalog = table.db or None, table.name, table.catalog or None
        # before any other verdict: whatever else opens it, it stays closed
        check_not_session_sql(self._engine, schema, name, columns_checked=True)
        self._check_value_columns(schema, name, root, table)
        # any other bare name is a table the engine binds to a schema of
        # its choosing: under an allowlist the statement must name it
        # (otherdb..t names a catalog, which _check_ref refuses as such)
        if schema is None and catalog is None and self._policy.allowed_schemas and self._dialect != "sqlite":
            raise self._unqualified_table(table)
        if schema is not None and catalog is None:
            self._check_schema_case(table.args["db"], table)
        bound = dictionary_binding(self._engine, schema, name) if catalog is None else None
        if bound is not None:
            # the engine reads the dictionary view, whatever else holds the name
            self._check_bound(table, bound, root)
            return
        self._check_ref(schema, name, catalog, root, table)

    def _check_bound(self, table: exp.Table, bound: tuple[str, str], root: exp.Expression) -> None:
        """Authorize ``table`` as the dictionary object the engine reads for
        it (dictionary_binding): SQL Server's dbo.syslogins, and a bare
        syslogins, read sys.syslogins ahead of any object of the name, with
        or without an allowlist (live, re-attack round 2)."""
        schema, name = bound
        try:
            self._check_ref(schema, name, None, root, exp.table_(exp.to_identifier(name), db=exp.to_identifier(schema)))
        except ToolFailure as exc:
            shown = f"{table.db}.{table.name}" if table.db else table.name
            raise ToolFailure(
                exc.category,
                f"'{shown}' is SQL Server's compatibility view {schema}.{name}, which it reads under dbo and bare "
                "ahead of any other object of the name: " + str(exc).removeprefix(f"{exc.category}: "),
            ) from exc

    def _check_unbound_column(self, unbound: _ClickHouseUnbound, root: exp.Expression, refs: list[ObjectRef]) -> None:
        """Authorize a ClickHouse a.b no FROM item in reach binds as the
        table a.b (_clickhouse_unbound_columns). Where a names a value (an
        ARRAY JOIN, select or WITH alias), a.b that passes is that value's
        subcolumn, not a table the statement reads: every place a table may
        stand is refused on its own (_check_in, _FUNCTIONAL_IN,
        _names_a_table_argument), so it is left out of the references."""
        table, value = unbound
        try:
            self._authorize_table(table, root)
        except ToolFailure as exc:
            written = f"{table.db}.{table.name}"
            text = str(exc).removeprefix(f"{exc.category}: ")
            if value:
                hint = (
                    f"'{written}' is qualified by '{table.db}', which names a value here (an ARRAY JOIN, select or "
                    f"WITH alias), and ClickHouse reads such a name as the table {written} where a table may stand "
                    f"(in(x, {written})): name a tuple's element by its index ({table.db}.1)"
                )
            else:
                hint = (
                    f"'{written}' is qualified by no table this query reads, and ClickHouse reads such a name as the "
                    f"table {written} where a table may stand (in(x, {written})): qualify a column or subcolumn with "
                    f"the alias or name of its table (<table>.{written}), and name a tuple's element by its index "
                    f"({table.db}.1)"
                )
            raise ToolFailure(exc.category, f"{text}; {hint}") from exc
        if not value:
            refs.append(ObjectRef(schema=table.db, name=table.name, catalog=None, looked_up=self._looked_up_ref(table)))

    def _check_parameter(self, node: exp.Parameter) -> None:
        """Refuse an '@' parameter where the engine reads no parameter:
        MySQL's user variables and Oracle's database links (T-SQL's @name
        and SQLite's are parameters; PostgreSQL's operators are refused on
        the tokens, _deny_postgres_at_operators)."""
        if self._dialect == "mysql":
            raise _deny(
                "user variables (@name) are not permitted on MySQL: one keeps a value on the pooled session from "
                "one statement to the next, where it comes back past the masking of the statement that read it; "
                "pass values as parameters (%s, :name)"
            )
        if self._dialect == "oracle":
            raise _deny(f"{_DATABASE_LINKS}: Oracle reads '@' as a link to another database")

    def _check_value_columns(self, schema: str | None, name: str, root: exp.Expression, table: exp.Table) -> None:
        """Refuse a statement reading a column catalog that carries each
        column's low and high values (COLUMN_VALUE_COLUMNS) when it names one
        of those columns anywhere, reads every column (* or t.*; COUNT(*)
        reads none), or renames the catalog's columns by position with a
        column list after ``table``'s alias (Db2 ran syscat.columns AS c (c0,
        ..., c57), c18 being HIGH2KEY; review, round 2)."""
        carried = value_columns(self._engine, schema, name)
        if not carried:
            return
        alias = table.args.get("alias")
        renamed = isinstance(alias, exp.TableAlias) and bool(alias.columns)
        names, every = self._statement_columns(root)
        if names.isdisjoint(carried) and not every and not renamed:
            return
        shown = f"{schema}.{name}" if schema else name
        raise _deny(
            f"'{shown}' carries each column's low and high values "
            f"({', '.join(sorted(c.upper() for c in carried))}), which would hand back values column masking "
            f"hides: name the columns you need, without those, without * and without a column list after its "
            f"alias (which renames them by position)"
        )

    def _statement_columns(self, root: exp.Expression) -> tuple[frozenset[str], bool]:
        """Every name in ``root`` (loose_name), and whether it reads every
        column somewhere (* or t.* outside COUNT): read once per statement,
        the first time a column catalog with value columns is met. A walk
        per reference took 70 s for one 64 KiB statement naming COLS 5500
        times (review, round 2)."""
        cached = self._columns_of
        if cached is None or cached[0] is not root:
            names = frozenset(loose_name(n) for n in {ident.name for ident in root.find_all(exp.Identifier)})
            every = any(
                not isinstance(star.parent.parent if isinstance(star.parent, exp.Column) else star.parent, exp.Count)
                for star in root.find_all(exp.Star)
            )
            cached = self._columns_of = (root, names, every)
        return cached[1], cached[2]

    def _check_cte_namesake(self, table: exp.Table, root: exp.Expression) -> None:
        """The value columns of a bare name the walk takes for a CTE's, as
        the name itself and in each schema the catalog places it in
        (_check_ref's candidates). The server checks one that no CTE in
        reach declares by its name alone (_validate_in_scope: SELECT 1 FROM
        <name>), which names none of this statement's columns: on Oracle,
        FROM (WITH cols AS (...) SELECT ...) x, cols c read the PUBLIC
        synonym COLS, a masked column's LOW_VALUE and HIGH_VALUE with it
        (live, review, round 2). A CTE so named that reads such a column,
        or *, is refused as well."""
        name = table.name
        schemas_for = getattr(self._resolver, "schemas_for", None)
        candidates = sorted(s for s in schemas_for(name) if s) if callable(schemas_for) else []
        try:
            for schema in (None, *candidates):
                self._check_value_columns(schema, name, root, table)
        except ToolFailure as exc:
            text = str(exc).removeprefix(f"{exc.category}: ")
            raise ToolFailure(
                exc.category,
                f"{text}; a CTE of the name '{name}' does not change this, as the engine reads the catalog "
                f"wherever no CTE in reach declares the name: give the CTE another name",
            ) from exc

    def _clickhouse_cte_refs(self, root: exp.Expression) -> set[int]:
        """The bare FROM items ClickHouse binds to a CTE (_clickhouse_binding),
        by id: any other bare name reads a table and goes through the table
        checks. Every name some CTE of the statement declared was skipped,
        so WITH RECURSIVE payroll AS (SELECT * FROM payroll) read the table
        payroll past default-deny and allowed_schemas (review, 2026-09-28).
        Refused: CTEs naming each other, which ClickHouse binds by the order
        it resolves them in (the table for one of the names), a WITH
        ClickHouse copies into later branches of a set operation
        (clickhouse_copies_with) where sqlglot does not, or where the copies
        lose RECURSIVE, and a name a CTE's body reads from outside it that
        another CTE declares too (_deny_clickhouse_rebinding)."""
        declared: dict[int, dict[str, exp.CTE]] = {}
        branch_of: dict[int, tuple[str, exp.CTE]] = {}
        for with_ in root.find_all(exp.With):
            names = declared[id(with_)] = {}
            for cte in with_.expressions:
                cte_name = _cte_name(cte)
                if cte_name is not None:
                    names.setdefault(cte_name, cte)
            if names and clickhouse_copies_with(with_):
                if not isinstance(with_.parent, exp.SetOperation):
                    raise _deny(
                        "a WITH in parentheses at the start of a UNION, INTERSECT or EXCEPT is not permitted on "
                        "ClickHouse, which applies it to the branches after the parentheses too; write the WITH "
                        "ahead of the whole set operation"
                    )
                if with_.recursive and any(
                    not t.db and not t.catalog and t.name == cte_name
                    for cte_name, cte in names.items()
                    for t in cte.this.find_all(exp.Table)
                ):
                    raise _deny(
                        "WITH RECURSIVE ahead of a UNION, INTERSECT or EXCEPT recurses only in the first branch "
                        "on ClickHouse: the branches after it get a copy without RECURSIVE, where the CTE's own "
                        "name reads the table of that name; put the set operation in a subquery, WITH RECURSIVE "
                        "... SELECT ... FROM (SELECT ... UNION ALL SELECT ...)"
                    )
            for cte_name, cte in names.items():
                for branch in clickhouse_recursive_branches(cte):
                    branch_of[id(branch)] = (cte_name, cte)
        named = {cte_name for names in declared.values() for cte_name in names}
        if not named:
            return set()
        decls: dict[str, list[exp.CTE]] = {}
        for names in declared.values():
            for cte_name, cte in names.items():
                decls.setdefault(cte_name, []).append(cte)
        spans, placed = _cte_spans(root, {id(cte) for ctes in decls.values() for cte in ctes})
        memo: dict[tuple[int, str], _ClickHouseBinding] = {}
        refs: set[int] = set()
        edges: dict[int, list[exp.CTE]] = {}
        for table in root.find_all(exp.Table):
            if not isinstance(table.this, exp.Identifier) or table.db or table.catalog or table.name not in named:
                continue
            binding = _clickhouse_binding(table, table.name, declared, branch_of, memo)
            _deny_clickhouse_rebinding(table, binding, decls, spans, placed)
            if binding is None:
                continue
            refs.add(id(table))
            source, cte = binding
            if source is not None and source is not cte:
                edges.setdefault(id(source), []).append(cte)
        cycle = _cte_cycle(edges)
        if cycle:
            raise _deny(
                f"the CTEs {', '.join(str(_cte_name(cte)) for cte in cycle)} name each other, which is not "
                "permitted on ClickHouse: it reads the table of one of those names, which one depending on the "
                "order it resolves them in; write a recursion in its own CTE's WITH RECURSIVE ... UNION ALL body, "
                "and qualify a table named like a CTE with its database"
            )
        return refs

    def _check_name(self, ident: exp.Identifier) -> None:
        """Refuse a name the engine reads as another name, which every check
        here would compare in the spelling written (review, 2026-09-28): on
        SQL Server one outside printable ASCII (_TSQL_LITERAL_TOKENS), a
        string alias included; a Db2 delimited name with trailing blanks,
        which Db2 drops ("IBMREQD " AS X returned a masked column in clear,
        SYSIBMADM."MON_CURRENT_SQL " other sessions' SQL); an unquoted Oracle
        name with a letter Oracle upper-cases to ASCII (v$ſql is V$SQL)."""
        name = ident.name
        money = not ident.quoted and _TSQL_WHOLE_TOKEN.fullmatch(name)  # sqlglot's column £1 is a literal
        if self._dialect == "tsql" and not _tsql_plain(name) and not money:
            raise _tsql_loose_name(name)
        if self._engine == "db2" and name != name.rstrip():
            raise _deny(
                f"the delimited name {ascii(name)} is not permitted on Db2, which drops the blanks at its end and "
                f"reads it as \"{name.rstrip()}\"; write the name without them"
            )
        if self._engine == "oracle" and not ident.quoted and not _ORACLE_FOLDS_ONTO_ASCII.isdisjoint(name):
            raise _deny(
                f"the unquoted name {ascii(name)} is not permitted on Oracle, which upper-cases its ı or ſ to an "
                f"ASCII letter and reads it as {name.upper()}; write the ASCII letter, or quote the name to mean it "
                f"exactly"
            )

    def _looked_up(self, ident: exp.Identifier) -> str:
        """The name the engine looks up for ``ident``: as written when
        quoted, folded (unquoted_name) when not."""
        return ident.name if ident.quoted else unquoted_name(self._engine, ident.name)

    def _looked_up_ref(self, table: exp.Table) -> tuple[str | None, str]:
        """The schema (None for none) and name the engine looks up for
        ``table`` (_looked_up)."""
        db = table.args.get("db")
        schema = self._looked_up(db) if isinstance(db, exp.Identifier) else table.db or None
        return schema, self._looked_up(table.this) if isinstance(table.this, exp.Identifier) else table.name

    def _data_free(self, table: exp.Table) -> bool:
        """``table`` names one of the engine's DATA_FREE_TABLES (Oracle's
        DUAL, Db2's SYSIBM.SYSDUMMY1-4), by the names the engine looks up."""
        db = table.args.get("db")
        if db is not None and not isinstance(db, exp.Identifier):
            return False
        schema = self._looked_up(db) if db is not None else None
        return is_data_free_table(self._engine, schema, self._looked_up(table.this))

    def _check_in(self, node: exp.In) -> None:
        """Refuse a table named on the right of IN. ClickHouse reads `x IN t`,
        `x IN db.t` and `x IN (db.t)` as `x IN (SELECT * FROM db.t)`, and
        SQLite reads `x IN t` the same way, but sqlglot parses the name as a
        column (In.field, or a one-element list), so no table check saw it: a
        membership test on any table, allowlist or not (live, 2026-09-28). The
        other engines reject a name after IN without parentheses, so refusing
        it loses nothing there; in parentheses it is a column to them, while
        ClickHouse binds a lone name to a table before a column of that name,
        whatever parentheses and aliases stand around it (x IN ((t AS z))).
        A value in that place names nothing (_NAME_NODES) and stays allowed:
        ClickHouse's `x IN {ids:Array(UInt64)}`, a driver's `x IN %(p)s`.
        An IN with nothing after it is sqlglot's reading of the functional
        in() (_FUNCTIONAL_IN), refused on every engine."""
        how = "write IN (SELECT <column> FROM <schema>.<table>)"
        if not any(node.args.get(arg) for arg in ("expressions", "query", "field", "unnest")):
            raise _deny(_FUNCTIONAL_IN)
        field = node.args.get("field")
        if field is not None and any(
            isinstance(n, _NAME_NODES) for n in field.walk(prune=lambda n: isinstance(n, _VALUE_PARAMETERS))
        ):
            raise _deny(f"a name after IN without parentheses is not permitted: it reads a table; {how}")
        if self._dialect == "clickhouse" and not node.args.get("query") and len(node.expressions) == 1:
            item = node.expressions[0]
            # ClickHouse drops parentheses, an alias and a unary plus (as sqlglot does) around that one
            # item (live, 26.3: 0 IN ((one AS z)) read system.one with database system)
            while isinstance(item, (exp.Paren, exp.Alias)):
                item = item.this
            if isinstance(item, (exp.Column, exp.Dot)):
                raise _deny(
                    f"IN (<name>) with a single name is not permitted on ClickHouse: it reads the table of "
                    f"that name; {how}, or compare a column with ="
                )

    def _unqualified_table(self, table: exp.Table) -> ToolFailure:
        """Under a schema allowlist a statement names the schema of every
        table it reads (owner decision 2026-09-27). The engine binds a bare
        name itself - PostgreSQL's search_path, the current database on MySQL
        and ClickHouse, the current schema and synonyms on Oracle and Db2, the
        default schema on SQL Server - so a name the catalog lists in an
        allowed schema (ocean.buoys) could still read a namesake elsewhere
        (public.buoys). SQLite has one schema and is exempt. The refusal
        offers the qualified spelling, quoted as written, in each permitted
        schema the catalog lists the table in, or else any allowed schema."""
        allowed = sorted(self._policy.allowed_schemas)
        permitted = self._policy.allowed_schemas | self._policy.allowed_system_schemas
        schemas_for = getattr(self._resolver, "schemas_for", None)
        listed = schemas_for(table.name) if callable(schemas_for) else set()
        homes = sorted({s for s in listed if s and s.lower() in permitted})
        spellings_of = getattr(self._resolver, "schema_spellings", None)

        def spelled(schema: str) -> list[str]:
            # as the catalog spells it where the listing says (a mixed-case
            # PostgreSQL schema needs its quotes), else as the allowlist does
            exact = sorted(spellings_of(schema)[0]) if callable(spellings_of) else []
            if exact:
                return [self._spelled(table, s) for s in exact]
            return [self._spelled(table, schema, exact=False)]

        if homes:
            hint = "write " + " or ".join(s for home in homes for s in spelled(home))
        elif is_data_free_table(self._engine, "SYSIBM", self._looked_up(table.this)):
            # Db2 binds a bare SYSDUMMY1 to CURRENT SCHEMA, not to the dummy table
            hint = f"on Db2 it is SYSIBM.{table.name}: write SYSIBM.{table.name}"
        else:
            hint = f"qualify it with an allowed schema, for example {spelled(allowed[0])[0]}"
        return ToolFailure(
            ErrorCategory.AUTHZ,
            f"unqualified table '{table.name}' is not permitted: connection '{self._policy.connection_id}' "
            f"allows only schemas [{', '.join(allowed)}], so every table must name its schema (the engine "
            f"would otherwise choose it); {hint}",
        )

    def _spelled(self, table: exp.Table | None, schema: str, *, exact: bool = True) -> str:
        """``table``'s name, as written, in ``schema`` (the schema alone with
        no table); with ``exact``, the schema quoted where the engine would
        fold it to another name."""
        ident = exp.to_identifier(schema)
        if exact and unquoted_name(self._engine, schema) != schema:
            ident.set("quoted", True)
        if table is None:
            return ident.sql(dialect=self._dialect)
        return exp.table_(table.this.copy(), db=ident).sql(dialect=self._dialect)

    def _check_schema_case(self, ident: exp.Expression | None, table: exp.Table | None = None) -> None:
        """Under a schema allowlist, refuse a schema named in a spelling the
        listing does not hold where the engine reads it as a schema of its
        own. Every policy check folds case, so under allowed_schemas [ocean]
        "Ocean".secrets passed them all, default-deny or not, while
        PostgreSQL read the schema "Ocean" (review, 2026-09-28). The name
        compared is the one the engine looks up: a quoted identifier as
        written, an unquoted one folded (unquoted_name). On
        _CASE_EXACT_SCHEMA_ENGINES it must be a spelling the listing holds;
        elsewhere only where the catalog also holds a namesake the policy
        does not admit (EffectivePolicy.shadowed_spellings). A resolver
        without catalog spellings (StaticResolver) leaves this to the
        policy's case-insensitive match. ``ident`` is the schema as written,
        ``table`` the object it qualifies (SHOW TABLES FROM names none)."""
        spellings_of = getattr(self._resolver, "schema_spellings", None)
        if (
            not self._policy.allowed_schemas
            or self._dialect == "sqlite"
            or not isinstance(ident, exp.Identifier)
            or not callable(spellings_of)
        ):
            return
        named = self._looked_up(ident)
        if self._engine in ("mysql", "clickhouse") and named.lower() == "information_schema":
            # MySQL reads INFORMATION_SCHEMA in any case (live; PERFORMANCE_SCHEMA
            # is error 1049), and ClickHouse serves the same views as both
            # INFORMATION_SCHEMA.TABLES and information_schema.tables
            return
        spellings, namesakes = spellings_of(named)
        if named in spellings or not (namesakes or (spellings and self._engine in _CASE_EXACT_SCHEMA_ENGINES)):
            return
        refusal = (
            f"schema '{named}' is not permitted on connection '{self._policy.connection_id}': schema names that "
            f"differ only in case name different schemas here"
        )
        if not spellings:
            raise ToolFailure(
                ErrorCategory.AUTHZ,
                f"{refusal}, and the catalog holds this one in spellings the allowlist does not name exactly; "
                f"an administrator can write the entry as the catalog spells it",
            )
        raise ToolFailure(
            ErrorCategory.AUTHZ,
            f"{refusal}, and the permitted one is spelled {', '.join(sorted(spellings))}; write "
            + " or ".join(self._spelled(table, s) for s in sorted(spellings)),
        )

    def _check_ref(
        self, schema: str | None, name: str, catalog: str | None, root: exp.Expression, table: exp.Table
    ) -> None:
        # SQLite reserves sqlite_* for its catalog: sqlite_schema (sqlite_master)
        # holds every table's full DDL, DEFAULT literals of sensitive columns
        # included. The connector's catalog (PRAGMA table_list), and so the
        # resolver, lists them as ordinary tables, so default-deny refuses
        # them by name. The metadata tools read the catalog through the
        # connector, never through this guard.
        if self._dialect == "sqlite" and name.lower().startswith("sqlite_") and self._policy.default_deny_objects:
            raise _deny(
                f"SQLite catalog table '{name}' is not readable through a query on connection "
                f"'{self._policy.connection_id}'; use db_list_tables / db_get_table for metadata"
            )
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
            self._check_object(schema, name)
        # Without default-deny only a schema allowlist restricts objects, and
        # it must bind unqualified names too. On every engine but SQLite such
        # a name never gets here (_unqualified_table); a SQLite one, which
        # can only bind to main, goes through the resolver and the candidate
        # re-authorization below.
        if not self._policy.default_deny_objects and (schema is not None or not self._policy.allowed_schemas):
            if schema is None:
                # Nothing restricts user schemas here, but the engine's
                # dictionaries stay closed: a bare name the catalog places in
                # a system schema (ALL_USERS, pg_roles) is authorized there.
                schemas_for = getattr(self._resolver, "schemas_for", None)
                if callable(schemas_for):
                    for cand in schemas_for(name):
                        if cand and self._policy.is_system_schema(cand):
                            self._check_value_columns(cand, name, root, table)
                            self._check_object(cand, name)
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
                    self._check_value_columns(cand, name, root, table)
                    self._check_object(cand, name)
        self._check_listed_spelling(table)

    def _check_listed_spelling(self, table: exp.Table) -> None:
        """Default-deny: the engine reads the listed object the resolver
        matched ``table`` to only as it looks the name up (_looked_up), which
        the resolver's match ignored: case, and for a bare name the schema.
        Refused where another spelling names another object or none
        (_CASE_EXACT_NAME_ENGINES) and a bare pg_ name PostgreSQL reads from
        pg_catalog first (every relation there is named so, live, 17: an
        ocean.pg_settings in the listing made a bare pg_settings pg_catalog's
        pass); the rest the server checks against how the session binds
        names (ListedBinding). A resolver without catalog spellings
        (StaticResolver) leaves this to its own match; SQLite ignores case
        and lists every object."""
        spellings_of = getattr(self._resolver, "listed_spellings", None)
        if not callable(spellings_of) or self._dialect == "sqlite":
            return
        db = table.args.get("db")
        schema = self._looked_up(db) if isinstance(db, exp.Identifier) else None
        name = self._looked_up(table.this)
        found: list[tuple[str, str]] = sorted(spellings_of(schema, name))
        exact = [(s, n) for s, n in found if n == name and schema in (None, s)]
        # ClickHouse serves the same views as INFORMATION_SCHEMA.TABLES and information_schema.tables
        folded = not exact and not (self._engine == "clickhouse" and (schema or "").lower() == "information_schema")
        bare = schema is None and self._engine in _SESSION_BOUND_ENGINES
        pg_first = schema is None and self._engine == "postgres" and name.startswith("pg_")
        refused = folded and (self._engine in _CASE_EXACT_NAME_ENGINES or not found)
        if not (refused or pg_first or bare or (folded and self._engine == "mssql")):
            return
        listed = (exact or found or [(schema or "", name)])[0]
        # the names as written and as the catalog spells them, for the refusal or the server's check
        spelled = exp.table_(self._exact_ident(listed[1]), db=self._exact_ident(listed[0])).sql(dialect=self._dialect)
        written = exp.table_(table.this.copy(), db=db.copy() if isinstance(db, exp.Identifier) else None).sql(
            dialect=self._dialect
        )
        if refused:
            rule = _NAME_RULES.get(self._engine, "the catalog lists no object of this spelling")
            raise _deny(
                f"table {written} is not spelled as the catalog lists it on connection "
                f"'{self._policy.connection_id}' ({spelled}): {rule}, so it names another object than the listed "
                f"one, or none; write {spelled}"
            )
        if pg_first and listed[0] != "pg_catalog":
            raise _deny(
                f"the bare name {written} is read from pg_catalog first: PostgreSQL searches pg_catalog before "
                f"the search_path, whatever else the catalog lists under the name; write {spelled}"
            )
        if bare or (folded and self._engine == "mssql"):
            self.bindings.append(ListedBinding(written, listed[0], listed[1], spelled, bare, folded))

    def _exact_ident(self, name: str) -> exp.Identifier:
        """``name`` as a statement names it exactly: quoted where the engine
        would fold it to another name."""
        ident = exp.to_identifier(name)
        if unquoted_name(self._engine, name) != name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$#]*", name):
            ident.set("quoted", True)
        return ident

    def _check_object(self, schema: str, name: str) -> None:
        """The policy's verdict on an object whose value columns
        _check_value_columns has checked in the statement."""
        if value_columns(self._engine, schema, name):
            self._policy.check_object(schema, name, columns_checked=True)
        else:
            self._policy.check_object(schema, name)

    # ---- public validation entry points ----------------------------------

    def validate_select(self, sql: str) -> GuardResult:
        root = self._parse_single(sql, "query")
        if not isinstance(root, _ALLOWED_ROOTS):
            raise _deny(f"only read statements are permitted here; this statement parsed as {type(root).__name__}")
        refs = self._walk_validate(root)
        return GuardResult(ast=root, tables=refs, kind="select")

    def validate_explain(self, sql: str) -> GuardResult:
        """EXPLAIN goes through its own dialect-scoped policy. Execution-capable
        variants (ANALYZE) are never run: refused by policy while
        allow_explain_analyze is off, as unsupported when it is on."""
        text = sql.strip().rstrip(";").strip()
        options = ""  # PostgreSQL option list as written, validated after the statement
        mysql_format: str | None = None
        bare_analyze = False  # EXPLAIN ANALYZE <statement>, refused after the statement
        if self._dialect == "sqlite":
            m = re.match(r"^EXPLAIN(\s+QUERY\s+PLAN)?\s+(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("sqlite EXPLAIN requires: EXPLAIN [QUERY PLAN] <select>")
            inner = m.group(2)
            root = self._parse_single(inner, "explain")
        elif self._dialect in ("postgres", "clickhouse"):
            # PostgreSQL option syntax: EXPLAIN [(option [, ...])] statement
            # (e.g. EXPLAIN (FORMAT YAML) SELECT ...), plus the bare-token
            # legacy form EXPLAIN [ANALYZE [VERBOSE]] statement, ANALYSE being
            # PostgreSQL's other spelling. A parenthesized statement,
            # EXPLAIN (SELECT 1) UNION ..., is not an option list.
            m = re.match(
                r"^EXPLAIN\s*(\((?!\s*(?:(?:SELECT|WITH|VALUES|TABLE)\b|\())[^)]*\))?\s*"
                r"(?:(ANALY[SZ]E)(?:\s+VERBOSE)?\s+)?(.+)$",
                text,
                re.I | re.S,
            )
            if not m:
                raise _deny("EXPLAIN requires: EXPLAIN [(option [, ...])] [ANALYZE] <statement>")
            options = m.group(1) or ""
            bare_analyze = bool(m.group(2))
            # ANALYZE executes the statement (as does the WAL option); both
            # are gated behind the same explicit policy.
            analyze_requested = bare_analyze or bool(re.search(r"\b(?:ANALY[SZ]E|WAL)\b", options, re.I))
            if analyze_requested and not self._policy.allow_explain_analyze:
                raise _deny(
                    "EXPLAIN ANALYZE executes the statement and is disabled by policy; use EXPLAIN without ANALYZE"
                )
            inner = m.group(3)
            root = self._parse_single(inner, "explain")
        elif self._dialect == "mysql":
            m = re.match(r"^EXPLAIN\s+(ANALYZE\s+)?(?:FORMAT\s*=\s*(\w+)\s+)?(.+)$", text, re.I | re.S)
            if not m:
                raise _deny("EXPLAIN requires: EXPLAIN [ANALYZE] [FORMAT=x] <statement>")
            bare_analyze = bool(m.group(1))
            if bare_analyze and not self._policy.allow_explain_analyze:
                raise _deny("EXPLAIN ANALYZE is disabled by policy")
            mysql_format = m.group(2)
            inner = m.group(3)
            root = self._parse_single(inner, "explain")
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
            inner = m.group(2)
            root = self._parse_single(inner, "explain")
        else:
            raise ToolFailure(
                ErrorCategory.CAPABILITY,
                f"EXPLAIN is not supported for dialect '{self._dialect}' in this "
                f"build; see the driver matrix for per-engine plan capabilities",
            )
        if not isinstance(root, _ALLOWED_ROOTS):
            raise _deny("EXPLAIN requires a read statement inside")
        refs = self._walk_validate(root)
        if bare_analyze:
            raise ToolFailure(ErrorCategory.VALIDATION, _EXPLAIN_ANALYZE_UNSUPPORTED)
        prefix = self._postgres_explain_options(options) if options else ""
        if mysql_format is not None:
            if mysql_format.upper() not in _MYSQL_EXPLAIN_FORMATS:
                raise ToolFailure(
                    ErrorCategory.VALIDATION,
                    f"EXPLAIN FORMAT={mysql_format} is not supported; use FORMAT=TRADITIONAL, JSON or TREE",
                )
            prefix = f"FORMAT={mysql_format.upper()} "
        return GuardResult(ast=root, tables=refs, kind="explain", text=prefix + inner.strip().rstrip(";").strip())

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
                ast = self._parse_single(text, "show")
                return GuardResult(ast=ast, tables=self._show_objects(ast), kind="show")
        raise _deny("this SHOW/DESCRIBE form is not on the allowed list; use the metadata tools for catalog discovery")

    def _show_objects(self, ast: exp.Expression) -> list[ObjectRef]:
        """The object a SHOW/DESCRIBE names, through the checks a FROM item
        gets. Nothing runs these (db_query refuses them), but db_validate_query
        called DESCRIBE hr.salaries valid under allowed_schemas [testdb] and a
        bare DESCRIBE cuppings too (review, 2026-09-28)."""
        if isinstance(ast, exp.Describe):
            return self._walk_validate(ast)
        if isinstance(ast, exp.Show):
            target, db = ast.args.get("target"), ast.args.get("db")
            if isinstance(target, exp.Identifier):  # SHOW COLUMNS / INDEX FROM [db.]table
                schema = db.copy() if isinstance(db, exp.Identifier) else None
                return self._walk_validate(exp.Table(this=target.copy(), db=schema))
            if isinstance(db, exp.Identifier):  # SHOW TABLES FROM db
                self._check_schema_case(db)
                self._policy.check_object(db.name, "*")
        return []

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

    def schemas_for(self, name: str) -> set[str]:
        """The schemas a bare name lives in, so the guard re-authorizes the
        schema an unqualified reference binds to (as the server's resolver)."""
        return {s.lower() for s, n in self._objects if s and n.lower() == name.lower()}
