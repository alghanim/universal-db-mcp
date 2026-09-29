"""SQL guard regressions from the 2026-09-27 security/production review.

Each section names the finding it pins. The statements are the review's
triggers; the guards are built the way the server builds them (SecurityConfig
defaults through EffectivePolicy.build) unless a section says otherwise.
"""

from __future__ import annotations

import re
import time
from typing import Any

import pytest

from universal_db_mcp.config import ConnectionConfig, SecurityConfig
from universal_db_mcp.errors import ToolFailure
from universal_db_mcp.models.responses import ErrorCategory
from universal_db_mcp.security import sql_guard
from universal_db_mcp.security.policy import EffectivePolicy
from universal_db_mcp.security.sql_guard import SqlGuard, StaticResolver

ENGINES = ["sqlite", "postgres", "mysql", "mssql", "oracle", "clickhouse", "db2"]


def _policy(
    engine: str, security: SecurityConfig | None = None, allowed_schemas: list[str] | None = None
) -> EffectivePolicy:
    body: dict[str, Any] = {"type": engine, "database": "d", "username_env": "U"}
    if engine != "sqlite":
        body["host"] = "h"
    if allowed_schemas is not None:
        body["allowed_schemas"] = allowed_schemas
    cfg = ConnectionConfig.model_validate(body)
    return EffectivePolicy.build(security or SecurityConfig(), type("R", (), {"config": cfg, "name": "c"})())


def _guard(engine: str, resolver: StaticResolver | None = None) -> SqlGuard:
    return SqlGuard(engine, _policy(engine), resolver)


def _assert_policy_denied(fn: Any, *args: Any) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        fn(*args)
    assert info.value.category == ErrorCategory.POLICY, str(info.value)
    return info.value


# ---- F04: Db2 read-tail regex must not backtrack quadratically --------------

_MAX = sql_guard._MAX_SQL_BYTES


def _fill(prefix: str, ch: str, suffix: str) -> str:
    """prefix + a run of ``ch`` + suffix, exactly at the statement size cap."""
    sql = prefix + ch * (_MAX - len(prefix) - len(suffix)) + suffix
    assert len(sql) == _MAX
    return sql


_DB2_WS_PAYLOADS = {
    "literal": ("SELECT '", " ", "' FROM t"),
    "block_comment": ("SELECT 1 /*", "\n", "*/ FROM t"),
    "invalid_sql": ("x", " ", "y"),
}


def _timed(fn: Any, *args: Any) -> float:
    t0 = time.perf_counter()
    try:
        fn(*args)
    except ToolFailure:
        pass
    return time.perf_counter() - t0


@pytest.mark.parametrize("case", sorted(_DB2_WS_PAYLOADS))
@pytest.mark.parametrize("entry", ["validate_select", "validate_any", "validate_explain"])
def test_f04_db2_whitespace_run_is_linear(case: str, entry: str) -> None:
    """A 64 KiB whitespace run (in a literal, in a comment, or in text that is
    not SQL at all) used to cost ~25 s of GIL-holding regex backtracking."""
    prefix, ch, suffix = _DB2_WS_PAYLOADS[case]
    if entry == "validate_explain":
        prefix = "EXPLAIN " + prefix
    sql = _fill(prefix, ch, suffix)
    guard = SqlGuard("db2", _policy("db2"), None)
    elapsed = _timed(getattr(guard, entry), sql)
    assert elapsed < 1.0, f"{entry}({case}) took {elapsed:.2f}s"


def test_f04_read_tail_regex_alone_is_fast() -> None:
    sql = _fill("SELECT '", " ", "' FROM t")
    t0 = time.perf_counter()
    assert sql_guard._DB2_READ_TAIL.sub("", sql, count=1) == sql
    assert time.perf_counter() - t0 < 0.1


def test_f04_pre_parse_regexes_do_not_start_with_a_quantifier() -> None:
    """Unanchored search/sub patterns must begin at a keyword (or a fixed-width
    lookaround), never at an unbounded quantifier like \\s+."""
    for rx in (
        sql_guard._DB2_READ_TAIL,
        sql_guard._DB2_LOCKING_ISOLATION,
        sql_guard._DB2_LOCK_TAIL,
        sql_guard._DB2_SEQUENCE,
        sql_guard._EXECUTABLE_COMMENT,
    ):
        assert not rx.pattern.startswith(("\\s", "(?:\\s", "\\W", ".")), rx.pattern


@pytest.mark.parametrize(
    "sql,expected",
    [
        ("SELECT * FROM T WITH UR", "SELECT * FROM T"),
        ("SELECT * FROM T\nWITH\tUR", "SELECT * FROM T"),
        ("SELECT * FROM T FOR READ ONLY OPTIMIZE FOR 1 ROW WITH UR", "SELECT * FROM T"),
        ("SELECT * FROM T FOR FETCH ONLY WITH CS", "SELECT * FROM T"),
        ("SELECT * FROM T WITH UR WITH UR WITH UR WITH UR WITH UR", "SELECT * FROM T WITH UR"),
        # never stripped: not at the end, no whitespace before, or inside a literal
        ("SELECT * FROM T WITH UR; DROP TABLE X", "SELECT * FROM T WITH UR; DROP TABLE X"),
        ("SELECT * FROM TWITH UR", "SELECT * FROM TWITH UR"),
        ("WITH UR", "WITH UR"),
        ("SELECT 'x WITH UR' FROM T", "SELECT 'x WITH UR' FROM T"),
    ],
)
def test_f04_read_tail_strip_semantics_unchanged(sql: str, expected: str) -> None:
    assert SqlGuard._strip_db2_read_tail(sql) == expected


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM APP.CUSTOMERS WITH RS",
        "SELECT * FROM APP.CUSTOMERS WITH RR",
        "SELECT * FROM APP.CUSTOMERS WITH RS USE AND KEEP EXCLUSIVE LOCKS",
        "SELECT * FROM APP.CUSTOMERS WITH UR; DROP TABLE x",
    ],
)
def test_f04_db2_locking_and_stacked_tails_still_refused(sql: str) -> None:
    guard = SqlGuard("db2", _policy("db2", SecurityConfig(default_deny_objects=False)), None)
    _assert_policy_denied(guard.validate_select, sql)


def test_f04_db2_read_tail_still_accepted() -> None:
    guard = SqlGuard("db2", _policy("db2", SecurityConfig(default_deny_objects=False)), None)
    assert guard.validate_select("SELECT * FROM APP.CUSTOMERS OPTIMIZE FOR 10 ROWS WITH UR").kind == "select"


# ---- F91: tokenizer errors are a policy denial, not INTERNAL_ERROR ----------


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("sql", ["SELECT 'abc FROM t", "SELECT 1 /* x FROM t"])
def test_f91_unterminated_literal_or_comment_is_denied(engine: str, sql: str) -> None:
    exc = _assert_policy_denied(_guard(engine).validate_select, sql)
    assert "could not be parsed" in str(exc)


@pytest.mark.parametrize("engine", ["sqlite", "mssql"])
def test_f91_unterminated_bracket_identifier_is_denied(engine: str) -> None:
    exc = _assert_policy_denied(_guard(engine).validate_select, "SELECT [abc FROM t")
    assert "could not be parsed" in str(exc)


def test_f91_tokenizer_error_through_explain_is_denied() -> None:
    _assert_policy_denied(_guard("postgres").validate_explain, "EXPLAIN SELECT 'abc FROM t")


# ---- F03: MariaDB executable comments and SET STATEMENT ---------------------


def _mysql_guard() -> SqlGuard:
    return _guard("mysql", StaticResolver({(None, "customers"), ("d", "customers")}))


_F03_DENIED = [
    "SELECT id FROM customers /*M!50000 UNION SELECT secret FROM hr.salaries */",
    "SELECT id /*M!, (SELECT 1) */ FROM customers",
    "SELECT 1 /*M! , SLEEP(5) */",
    "SELECT 1 /*M!100000 ,2 */",
    "SELECT 1 /*m! ,2 */",
    "/*M! SET STATEMENT max_statement_time=0 FOR */ SELECT id FROM customers",
    "SET STATEMENT max_statement_time=0 FOR SELECT 1",
    "SELECT /*!50000 * */ FROM customers",
]


@pytest.mark.parametrize("sql", _F03_DENIED)
def test_f03_mariadb_executable_comment_denied(sql: str) -> None:
    _assert_policy_denied(_mysql_guard().validate_select, sql)


@pytest.mark.parametrize("sql", _F03_DENIED)
def test_f03_mariadb_executable_comment_denied_through_explain(sql: str) -> None:
    _assert_policy_denied(_mysql_guard().validate_explain, "EXPLAIN " + sql)


def test_f03_deny_message_names_both_forms() -> None:
    exc = _assert_policy_denied(_mysql_guard().validate_select, "SELECT 1 /*M! ,2 */")
    assert "/*M! ... */" in str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        "SET STATEMENT transaction_read_only=0 FOR SELECT id FROM customers",
        "set   statement\nmax_statement_time=0 for select 1",
    ],
)
def test_f03_set_statement_named_refusal(sql: str) -> None:
    exc = _assert_policy_denied(_mysql_guard().validate_select, sql)
    assert "SET STATEMENT" in str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 /* note */",
        "SELECT 1 /* M! note */",
        "SELECT 'SET STATEMENT x=1 FOR' AS s FROM customers",
        "SELECT id FROM customers -- SET STATEMENT max_statement_time=0 FOR",
    ],
)
def test_f03_ordinary_comments_and_literals_still_allowed(sql: str) -> None:
    assert _mysql_guard().validate_select(sql).kind == "select"


# ---- F02: T-SQL reserved keywords absorbed as AS-less aliases ---------------

# Microsoft's reserved statement keywords the review requires at minimum.
_TSQL_STATEMENT_KEYWORDS = (
    "DELETE INSERT UPDATE MERGE TRUNCATE DROP CREATE ALTER GRANT REVOKE DENY COMMIT ROLLBACK SAVE BEGIN "
    "TRAN TRANSACTION SHUTDOWN RECONFIGURE CHECKPOINT REVERT BACKUP RESTORE KILL EXEC EXECUTE WAITFOR "
    "DBCC USE SET DECLARE PRINT RAISERROR SETUSER READTEXT WRITETEXT UPDATETEXT RETURN BREAK CONTINUE "
    "GOTO IF WHILE OPEN CLOSE FETCH DEALLOCATE BULK"
).split()


def _mssql_guard() -> SqlGuard:
    return _guard("mssql", StaticResolver({("dbo", "t")}))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 DELETE FROM dbo.t",
        "SELECT 1 DELETE FROM dbo.t COMMIT",
        "SELECT id DELETE FROM dbo.t WHERE 1=1",
        "SELECT * FROM dbo.t DELETE",
        "SELECT 1 SHUTDOWN",
        "SELECT 1 CHECKPOINT",
        "SELECT 1 RECONFIGURE",
        "SELECT 1 REVERT",
        "SELECT 1 COMMIT",
        "SELECT 1 KILL",
        "SELECT 1 BACKUP",
        "SELECT 1 EXEC",
        "SELECT 1 WAITFOR",
    ],
)
def test_f02_tsql_keyword_alias_is_denied(sql: str) -> None:
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize("kw", _TSQL_STATEMENT_KEYWORDS)
@pytest.mark.parametrize(
    "template",
    [
        "SELECT 1 {kw} FROM dbo.t",  # column alias
        "SELECT * FROM dbo.t {kw}",  # table alias
        "SELECT * FROM (SELECT 1 AS a) {kw}",  # derived-table alias
        "SELECT * FROM (SELECT 1 AS a) d({kw})",  # derived-table column alias
        "SELECT id FROM dbo.t WHERE id IN (SELECT 1 {kw})",  # nested
        "select 1 {lower} from dbo.t",  # case-insensitive
    ],
)
def test_f02_tsql_keyword_alias_positions(kw: str, template: str) -> None:
    sql = template.format(kw=kw, lower=kw.lower())
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize(
    "sql",
    [
        # sqlglot reads these as a row limit; SQL Server reads a cursor FETCH
        "SELECT 1 FETCH c",
        "SELECT id FROM dbo.t FETCH c",
        "SELECT id FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH c",
        "SELECT id FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH NEXT c",
        "SELECT id FROM dbo.t FETCH",
    ],
)
def test_f02_tsql_fetch_without_rows_only_is_denied(sql: str) -> None:
    _assert_policy_denied(_mssql_guard().validate_select, sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY",
        "SELECT id FROM dbo.t ORDER BY id OFFSET 10 ROWS FETCH FIRST 1 ROW ONLY",
        "SELECT id FROM dbo.t ORDER BY id OFFSET 5 ROWS",
        "SELECT id FROM dbo.t ORDER BY id OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
        # sqlglot hangs this FETCH on the second SELECT and the OFFSET on the UNION
        "SELECT id FROM dbo.t UNION SELECT id FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY",
        "SELECT * FROM (SELECT id FROM dbo.t ORDER BY id OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY) d",
        "SELECT TOP 5 id FROM dbo.t",
    ],
)
def test_f02_tsql_paging_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"


def test_f02_reserved_set_covers_the_required_minimum() -> None:
    assert set(_TSQL_STATEMENT_KEYWORDS) <= sql_guard._TSQL_RESERVED_KEYWORDS


def test_f02_deny_message_names_the_keyword() -> None:
    exc = _assert_policy_denied(_mssql_guard().validate_select, "SELECT 1 DELETE FROM dbo.t COMMIT")
    assert "DELETE" in str(exc)
    assert "[DELETE]" in str(exc)  # tells the model how to quote it


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 AS [DELETE] FROM dbo.t",
        'SELECT 1 AS "DELETE" FROM dbo.t',
        "SELECT id total FROM dbo.t",
        "SELECT c.id FROM dbo.t c",
        "SELECT * FROM dbo.t [COMMIT]",
        "SELECT d.[open] FROM (SELECT 1 AS [open]) d",
        "WITH x(a) AS (SELECT 1) SELECT a FROM x",
        "SELECT deleted_at FROM dbo.t",
        # on Microsoft's list, but SQL Server 2022 accepts them as unquoted aliases
        "SELECT id AS precision, id load FROM dbo.t",
        "SELECT disk.id FROM dbo.t disk",
    ],
)
def test_f02_quoted_and_ordinary_aliases_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"


@pytest.mark.parametrize("engine", ["postgres", "clickhouse", "mysql", "sqlite", "oracle", "db2"])
def test_f02_other_dialects_keep_keyword_aliases(engine: str) -> None:
    """The differential is T-SQL's separator-free batch: every other connector
    sends one statement per call and its grammar reads the word as an alias,
    exactly as sqlglot does. OHLC aliases (open/close) must keep working."""
    guard = SqlGuard(engine, _policy(engine, SecurityConfig(default_deny_objects=False)), None)
    assert guard.validate_select("SELECT 1 AS open, 2 AS close").kind == "select"


# Review round 1: SQL Server separates tokens on these code points, sqlglot
# folds them into the neighbouring identifier ('\x10DELETE' is not DELETE).
# 0x01-0x08, 0x0E-0x1B and U+200B were observed live; 0x0B-0x0D's non-CR/LF
# members, 0x1C-0x1F and U+FEFF are refused defensively.
_TSQL_HIDDEN_SEPARATORS = [chr(c) for c in (*range(0x01, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20))] + [
    "\u200b",
    "\ufeff",
]


@pytest.mark.parametrize("sep", _TSQL_HIDDEN_SEPARATORS, ids=lambda s: f"U+{ord(s):04X}")
@pytest.mark.parametrize(
    "template",
    [
        "SELECT 1{x}DELETE FROM dbo.t {x}COMMIT",
        "SELECT 1{x}DELETE FROM dbo.t",
        "SELECT 1 DELETE FROM dbo.t{x}COMMIT",
        "SELECT id{x}DELETE FROM dbo.t WHERE 1=1",
        "SELECT * FROM dbo.t{x}DELETE",
        "SELECT 1{x}COMMIT",
        "SELECT 1 a{x}COMMIT",
        "SELECT 1 AS a{x}SHUTDOWN",
        "SELECT 1{x}DELETE{x}FROM{x}dbo.t",
    ],
)
def test_f02_tsql_hidden_separator_is_denied(sep: str, template: str) -> None:
    sql = template.format(x=sep)
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


def test_f02_tsql_hidden_separator_message_names_the_code_point() -> None:
    exc = _assert_policy_denied(_mssql_guard().validate_select, "SELECT 1\x10DELETE FROM dbo.t \x10COMMIT")
    assert "U+0010" in str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        # data, not code: literals and comments keep them (a quoted identifier is a
        # name, which must be printable ASCII on SQL Server: see below)
        "SELECT 'a\x10b' AS v FROM dbo.t",
        "SELECT N'x\u200by' AS v FROM dbo.t",
        "SELECT 1 /* \x10 */ FROM dbo.t",
        "SELECT 1 -- \x10\nFROM dbo.t",
        # ordinary whitespace is unaffected
        "SELECT\tid\r\nFROM\ndbo.t",
    ],
)
def test_f02_tsql_separator_in_data_or_plain_whitespace_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"


@pytest.mark.parametrize("engine", ["postgres", "clickhouse", "mysql", "sqlite", "oracle", "db2"])
def test_f02_hidden_separator_check_is_tsql_only(engine: str) -> None:
    guard = SqlGuard(engine, _policy(engine, SecurityConfig(default_deny_objects=False)), None)
    try:
        guard.validate_select("SELECT 1\x10")
    except ToolFailure as exc:
        assert "U+0010" not in str(exc)


# Integration wave: sqlglot reads '$1EXEC' and '0x1DELETE' as one identifier;
# SQL Server ends the money or binary literal there and runs the keyword as a
# statement of its own. Compiled live under SHOWPLAN_ALL on SQL Server 2022:
# 'SELECT $1EXEC sp_who' is a SELECT and an EXECUTE PROC, and each of the 34
# currency symbols SQL Server accepts ($, EUR, GBP, fullwidth $, ...) splits
# the same way, with digits or alone ('SELECT €SELECT 2').
# 0x1ADD and 0x1DBCC are one binary literal on both readings (see the controls)
_FUSED = [
    (prefix, kw)
    for prefix in ("$1", "0x1", "0x0")
    for kw in sorted(sql_guard._TSQL_RESERVED_KEYWORDS)
    if not (prefix.startswith("0x") and set(kw) <= set("ABCDEF"))
]


@pytest.mark.parametrize("prefix,kw", _FUSED)
def test_f02_tsql_literal_fused_with_a_keyword_is_denied(prefix: str, kw: str) -> None:
    sql = f"SELECT {prefix}{kw} FROM dbo.t"
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT $1EXEC sp_who",
        "SELECT $1SELECT 2 AS b",
        "SELECT 0x1SELECT 2 AS b",
        "SELECT 0xSELECT 2 AS b",
        "SELECT 0X1DELETE FROM dbo.t",
        "SELECT id FROM dbo.t WHERE id = $1EXEC sp_who",
        "SELECT id FROM dbo.t WHERE id IN (SELECT $1COMMIT)",
        "SELECT 1 + $1WAITFOR DELAY '00:00:05'",
        "SELECT €1SELECT 2 AS b",
        "SELECT £1DELETE FROM dbo.t",
        "SELECT ＄1EXEC sp_who",
        "SELECT ₩1SHUTDOWN",
        "SELECT €SELECT 2 AS b",
        "SELECT ¥DELETE FROM dbo.t",
        # sqlglot splits these itself; they must stay refused
        "SELECT $1.5SELECT 2 AS b",
        "SELECT $.5SELECT 2 AS b",
        "SELECT 1e5SELECT 2 AS b",
    ],
)
def test_f02_tsql_fused_literal_shapes_are_denied(sql: str) -> None:
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize(
    "sql,token",
    [
        ("SELECT $1EXEC sp_who", "$1EXEC"),
        ("SELECT $1DELETE FROM dbo.t", "$1DELETE"),
        ("SELECT 0x1DELETE FROM dbo.t", "0x1DELETE"),
        ("SELECT €1DELETE FROM dbo.t", "€1DELETE"),
    ],
)
def test_f02_tsql_fused_literal_message_names_the_token(sql: str, token: str) -> None:
    exc = _assert_policy_denied(_mssql_guard().validate_select, sql)
    assert f"'{token}'" in str(exc) and f"[{token}]" in str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        # whole literals, quoted identifiers and ordinary spellings
        "SELECT $1 AS m",
        "SELECT -$1.25 AS m",
        "SELECT 0x1F AS b",
        "SELECT 0x AS b",
        "SELECT 0x1ADD AS b",
        "SELECT £1 AS m",
        "SELECT id FROM dbo.t WHERE id = $1",
        "SELECT [$1EXEC] FROM dbo.t",
        'SELECT "$1EXEC" FROM dbo.t',
        "SELECT 1 AS [$1EXEC]",
        "SELECT a$1 FROM dbo.t",
        # SQL Server reads a number and an alias here, as sqlglot does (live)
        "SELECT 1_SELECT",
        "SELECT 0b1SELECT",
        # a $ pseudo-column is one token on both readings
        "SELECT TOP 1 $IDENTITY FROM dbo.t",
    ],
)
def test_f02_tsql_whole_literals_and_quoted_identifiers_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"
    assert _mssql_guard().validate_explain("EXPLAIN " + sql).kind == "explain"


def test_f02_fused_literal_check_is_tsql_only() -> None:
    # $1 is a placeholder on PostgreSQL, not a money literal
    guard = SqlGuard("postgres", _policy("postgres", SecurityConfig(default_deny_objects=False)), None)
    assert guard.validate_select("SELECT a FROM app.t WHERE b = $1").kind == "select"


# Integration review round 1: a currency symbol INSIDE a token that starts with
# a letter. sqlglot reads 'DISTINCT€1EXEC' as one column; SQL Server ends the
# identifier at the symbol (only '$' is an identifier character to it), reads
# DISTINCT, the money literal €1 and a new statement. SHOWPLAN_ALL on SQL
# Server 2022 compiles 'SELECT DISTINCT€1EXEC sp_who' as a SELECT and an
# EXECUTE PROC, and 'SELECT DISTINCT$1EXEC' as one (unknown) column.
_MIDTOKEN_CURRENCY = list("¢£¤¥৲৳฿៛₠₡₢₣₤₥₦₧₨₩₪₫€₭₮₯₰₱﷼﹩＄￠￡￥￦")


def test_f02_midtoken_currency_list_matches_the_guard() -> None:
    """The 33 symbols above plus '$' are exactly the guard's currency class."""
    cls = f"[{sql_guard._TSQL_CURRENCY}]"
    bmp = {chr(c) for c in range(0x10000) if not 0xD800 <= c <= 0xDFFF and re.fullmatch(cls, chr(c))}
    assert len(_MIDTOKEN_CURRENCY) == 33
    assert bmp == {"$", *_MIDTOKEN_CURRENCY}


@pytest.mark.parametrize("symbol", _MIDTOKEN_CURRENCY, ids=lambda s: f"U+{ord(s):04X}")
@pytest.mark.parametrize("prefix", ["DISTINCT", "ALL", "distinct"])
def test_f02_tsql_currency_inside_a_token_is_denied(symbol: str, prefix: str) -> None:
    guard = _mssql_guard()
    missed = []
    for kw in sorted(sql_guard._TSQL_RESERVED_KEYWORDS):
        for template in ("SELECT {p}{c}1{kw} FROM dbo.t", "SELECT {p}{c}{kw} FROM dbo.t"):
            sql = template.format(p=prefix, c=symbol, kw=kw)
            for fn, text in ((guard.validate_select, sql), (guard.validate_explain, "EXPLAIN " + sql)):
                try:
                    fn(text)
                except ToolFailure as exc:
                    if exc.category != ErrorCategory.POLICY:
                        missed.append((text, exc.category))
                else:
                    missed.append((text, "ALLOWED"))
    assert not missed, missed[:10]


@pytest.mark.parametrize(
    "sql",
    [
        # the review's live shapes (two statements under SHOWPLAN_ALL)
        "SELECT DISTINCT€1EXEC sp_who",
        "SELECT ALL£1EXEC sp_who",
        "SELECT DISTINCT¥EXEC sp_who",
        "SELECT DISTINCT＄1EXEC sp_who",
        "SELECT DISTINCT€1SELECT 2 AS b",
        "SELECT DISTINCT€1COMMIT",
        "SELECT DISTINCT€1SHUTDOWN",
        "SELECT DISTINCT€1RECONFIGURE",
        "SELECT DISTINCT€1CHECKPOINT",
        "SELECT DISTINCT€1DELETE FROM dbo.t",
        "SELECT DISTINCT€1EXEC xp_cmdshell",
        "SELECT DISTINCT€1WAITFOR DELAY '00:00:01'",
        # the literal ends on a '.' or sign sqlglot splits off
        "SELECT DISTINCT€1.EXEC sp_who",
        "SELECT DISTINCT€-EXEC sp_who",
        "SELECT DISTINCT€ -EXEC sp_who",
        "SELECT DISTINCT€+EXEC sp_who",
        # nested, set operation and CTE positions
        "SELECT 1 AS a UNION SELECT DISTINCT€1EXEC sp_who",
        "WITH x AS (SELECT 1 AS a) SELECT DISTINCT€1EXEC sp_who",
        "SELECT id FROM dbo.t WHERE id IN (SELECT DISTINCT€1EXEC sp_who)",
        # other keyword prefixes, a qualified name, a parameter or temp-table sigil
        "SELECT CASE WHEN 1 = 1 THEN€1 ELSE€2 END AS m",
        "SELECT 1 AS a WHERE NOT€1=1",
        "SELECT x.y€1EXEC sp_who FROM dbo.t x",
        "SELECT @v€1EXEC sp_who",
        "SELECT #v€1EXEC sp_who",
        "SELECT a$€1EXEC sp_who",
        "SELECT 1a€1EXEC sp_who",
        # the symbol hides a FROM clause: t2 is not a permitted object
        "SELECT DISTINCT€1FROM t2",
        "SELECT DISTINCT€1FROM secret_t",
        # a bare symbol that is a whole token after the first letter
        "SELECT DISTINCT€",
        "SELECT DISTINCT€1 AS m",
    ],
)
def test_f02_tsql_midtoken_currency_shapes_are_denied(sql: str) -> None:
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize(
    "sql,token",
    [
        ("SELECT DISTINCT€1EXEC sp_who", "DISTINCT€1EXEC"),
        ("SELECT ALL£1EXEC sp_who", "ALL£1EXEC"),
        ("SELECT DISTINCT€1.EXEC sp_who", "DISTINCT€1"),
        ("SELECT DISTINCT€-EXEC sp_who", "DISTINCT€"),
    ],
)
def test_f02_tsql_midtoken_currency_message_names_the_token(sql: str, token: str) -> None:
    exc = _assert_policy_denied(_mssql_guard().validate_select, sql)
    assert f"'{token}'" in str(exc) and f"[{token}]" in str(exc), str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        # a space before the literal: one SELECT on SQL Server 2022 as well
        "SELECT DISTINCT €1 AS m",
        "SELECT ALL £1 AS m",
        "SELECT CASE WHEN 1 = 1 THEN €1 ELSE €2 END AS m",
        # '$' is an identifier character to SQL Server: one (unknown) column
        "SELECT a$1 FROM dbo.t",
        "SELECT a$1EXEC FROM dbo.t",
        "SELECT a$b$c FROM dbo.t",
        # literals and comments keep any symbol
        "SELECT N'DISTINCT€1EXEC' AS s",
        "SELECT 'a£1' AS s FROM dbo.t",
        "SELECT 1 AS m /* DISTINCT€1EXEC */",
        "SELECT 1 AS m -- DISTINCT€1EXEC\n",
    ],
)
def test_f02_tsql_currency_outside_a_token_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"
    assert _mssql_guard().validate_explain("EXPLAIN " + sql).kind == "explain"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 AS [a\x01b] FROM dbo.t",
        'SELECT 1 AS "a\ufeffb" FROM dbo.t',
        "SELECT [a€1] FROM dbo.t",
        'SELECT "a€1EXEC" FROM dbo.t',
        "SELECT 1 AS [DISTINCT€1EXEC]",
    ],
)
def test_f02_tsql_a_quoted_name_is_not_split_but_must_be_printable_ascii(sql: str) -> None:
    """Neither a separator nor a currency symbol splits a quoted identifier.
    It is a name, though, and SQL Server's collation ignores or folds such
    characters in one (fix-up round 2, 2026-09-28): printable ASCII only."""
    for validate, prefix in ((_mssql_guard().validate_select, ""), (_mssql_guard().validate_explain, "EXPLAIN ")):
        exc = _assert_policy_denied(validate, prefix + sql)
        assert "collation" in str(exc) and "statement" not in str(exc), str(exc)


@pytest.mark.parametrize("engine", ["postgres", "clickhouse", "mysql", "sqlite", "oracle", "db2"])
def test_f02_midtoken_currency_check_is_tsql_only(engine: str) -> None:
    guard = SqlGuard(engine, _policy(engine, SecurityConfig(default_deny_objects=False)), None)
    try:
        guard.validate_select("SELECT a€1 FROM t")
    except ToolFailure as exc:
        assert "money" not in str(exc)


# SQL Server's lexer carries a money or float literal over characters sqlglot
# splits off as tokens of their own: the '.' after money digits, a sign after
# a bare currency symbol (after spaces too) and a sign after the exponent
# marker. With no digits after it the literal ends on that character, and the
# next word starts a statement: SHOWPLAN_ALL on SQL Server 2022 compiles
# 'SELECT $1.DELETE FROM t', 'SELECT $-DELETE ...', 'SELECT $ .DELETE ...'
# and 'SELECT 1e-DELETE ...' as a SELECT and a DELETE, while sqlglot reads a
# qualified column or a subtraction.
_SPLIT_LITERAL_PREFIXES = [
    *("$1.", "$.", "€1.", "¢.", "$ ."),  # money '.'
    *("$-", "$+", "£-", "$ -"),  # sign after a bare currency symbol
    *("1e-", "1e+", "1.5E-", "1.e+", ".5e-"),  # sign after the exponent marker
]


@pytest.mark.parametrize("prefix", _SPLIT_LITERAL_PREFIXES)
@pytest.mark.parametrize(
    "template", ["SELECT {sql} FROM dbo.t", "SELECT id FROM dbo.t WHERE id = {sql}", "SELECT 1 AS a, {sql}"]
)
def test_f02_tsql_literal_ending_on_a_split_separator_is_denied(prefix: str, template: str) -> None:
    guard = _mssql_guard()
    missed = []
    for kw in sorted(sql_guard._TSQL_RESERVED_KEYWORDS):
        sql = template.format(sql=prefix + kw)
        for fn, text in ((guard.validate_select, sql), (guard.validate_explain, "EXPLAIN " + sql)):
            try:
                fn(text)
            except ToolFailure as exc:
                if exc.category != ErrorCategory.POLICY:
                    missed.append((text, exc.category))
            else:
                missed.append((text, "ALLOWED"))
    assert not missed, missed[:10]


@pytest.mark.parametrize(
    "sql",
    [
        # the live shapes from the review, and a comment or line break after the separator
        "SELECT $1.DELETE FROM dbo.t",
        "SELECT $1.EXEC sp_who",
        "SELECT $1.SHUTDOWN",
        "SELECT $-SHUTDOWN",
        "SELECT ¥-DELETE FROM dbo.t",
        "SELECT ＄+EXEC sp_who",
        "SELECT 1E-SHUTDOWN",
        "SELECT 1.5e+COMMIT",
        "SELECT $1./**/DELETE FROM dbo.t",
        "SELECT $-/**/DELETE FROM dbo.t",
        "SELECT 1e-/**/DELETE FROM dbo.t",
        "SELECT $1.\nDELETE FROM dbo.t",
        "SELECT $1. -- x\nDELETE FROM dbo.t",
        "SELECT 1e+\nSHUTDOWN",
        "SELECT $- DELETE FROM dbo.t",
        "SELECT $ - DELETE FROM dbo.t",
        "SELECT 1e- DELETE FROM dbo.t",
        "SELECT $-.DELETE FROM dbo.t",
        "SELECT a FROM (SELECT $1.DELETE FROM dbo.t) d",
        "SELECT TOP 1 id FROM dbo.t WHERE id = $-DELETE dbo.t",
        # a gap SQL Server does not bridge (tab, comment) is refused all the same
        "SELECT $\t-DELETE FROM dbo.t",
        "SELECT $/**/-DELETE FROM dbo.t",
        # sqlglot's number token runs past SQL Server's literal
        "SELECT $1.5.DELETE FROM dbo.t",
        "SELECT $1.5e-DELETE FROM dbo.t",
    ],
)
def test_f02_tsql_split_literal_shapes_are_denied(sql: str) -> None:
    _assert_policy_denied(_mssql_guard().validate_select, sql)
    _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)


@pytest.mark.parametrize(
    "sql,literal",
    [
        ("SELECT $1.DELETE FROM dbo.t", "$1."),
        ("SELECT $-SHUTDOWN", "$-"),
        ("SELECT $ -SHUTDOWN", "$ -"),
        ("SELECT 1e-DELETE FROM dbo.t", "1e-"),
        ("SELECT .5e+COMMIT", "5e+"),
    ],
)
def test_f02_tsql_split_literal_message_names_the_literal(sql: str, literal: str) -> None:
    exc = _assert_policy_denied(_mssql_guard().validate_select, sql)
    assert f"'{literal}'" in str(exc), str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        # one SELECT on SQL Server 2022 as well (SHOWPLAN_ALL)
        "SELECT $1.5 AS m",
        "SELECT $1.50 AS m",
        "SELECT $.5 AS m",
        "SELECT $-1.5 AS m",
        "SELECT $+1 AS m",
        "SELECT $-.5 AS m",
        "SELECT $ -1.5 AS m",
        "SELECT -$1.25 AS m",
        "SELECT €1.5 AS m",
        "SELECT 1e-5 AS x",
        "SELECT 1.5e+3 AS x",
        "SELECT 1E+10 AS x",
        "SELECT .5e-3 AS x",
        "SELECT 1e AS x",
        "SELECT 1 - $2 AS m",
        "SELECT $1 - $2 AS m",
        "SELECT id FROM dbo.t WHERE id > $1.5 - 1e-3",
        "SELECT $1.[x] FROM dbo.t",
        "SELECT $1. [x] FROM dbo.t",
        "SELECT $-[x] FROM dbo.t",
        'SELECT $1."x" FROM dbo.t',
    ],
)
def test_f02_tsql_whole_money_and_float_literals_still_allowed(sql: str) -> None:
    assert _mssql_guard().validate_select(sql).kind == "select"
    assert _mssql_guard().validate_explain("EXPLAIN " + sql).kind == "explain"


@pytest.mark.parametrize("engine", ["postgres", "clickhouse", "mysql", "sqlite", "oracle", "db2"])
def test_f02_split_literal_check_is_tsql_only(engine: str) -> None:
    guard = SqlGuard(engine, _policy(engine, SecurityConfig(default_deny_objects=False)), None)
    assert guard.validate_select("SELECT 1e-5 - a FROM t").kind == "select"


# ---- F06: a schema allowlist binds unqualified names with default-deny off ---

# 'tsql' in the review is the mssql engine
_F06_ENGINES = ["postgres", "mysql", "oracle", "mssql", "db2"]


def _nodeny_guard(engine: str, allowed: list[str], objects: set[tuple[str | None, str]] | None) -> SqlGuard:
    policy = _policy(engine, SecurityConfig(default_deny_objects=False), allowed_schemas=allowed)
    return SqlGuard(engine, policy, None if objects is None else StaticResolver(objects))


def _assert_refused(fn: Any, *args: Any) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        fn(*args)
    assert info.value.category in (ErrorCategory.AUTHZ, ErrorCategory.POLICY), str(info.value)
    return info.value


@pytest.mark.parametrize("engine", _F06_ENGINES)
def test_f06_unqualified_name_bound_outside_the_allowlist_is_refused(engine: str) -> None:
    # the only 'salaries' the catalog knows is hr.salaries; the engine would bind it there
    guard = _nodeny_guard(engine, ["sales"], {("hr", "salaries")})
    _assert_refused(guard.validate_select, "SELECT * FROM salaries")
    _assert_refused(guard.validate_explain, "EXPLAIN SELECT * FROM salaries")


@pytest.mark.parametrize("engine", _F06_ENGINES)
def test_f06_unqualified_name_in_an_allowed_schema_must_be_qualified(engine: str) -> None:
    # owner decision 2026-09-27: the engine, not the catalog, binds a bare name
    # (a namesake elsewhere on the search path), so under an allowlist it is refused
    guard = _nodeny_guard(engine, ["sales"], {("sales", "salaries")})
    exc = _assert_refused(guard.validate_select, "SELECT * FROM salaries")
    assert exc.category == ErrorCategory.AUTHZ and "write sales.salaries" in str(exc)
    assert guard.validate_select("SELECT * FROM sales.salaries").kind == "select"


@pytest.mark.parametrize("engine", _F06_ENGINES)
def test_f06_qualified_name_outside_the_allowlist_is_still_refused(engine: str) -> None:
    guard = _nodeny_guard(engine, ["sales"], {("hr", "salaries"), ("sales", "salaries")})
    exc = _assert_refused(guard.validate_select, "SELECT * FROM hr.salaries")
    assert exc.category == ErrorCategory.AUTHZ


@pytest.mark.parametrize("engine", _F06_ENGINES)
def test_f06_empty_allowlist_keeps_default_deny_off_unchanged(engine: str) -> None:
    # no allowlist, no default-deny: nothing consults the catalog (not even a resolver)
    guard = _nodeny_guard(engine, [], None)
    assert guard.validate_select("SELECT * FROM salaries").kind == "select"


def test_f06_postgres_pg_roles_is_refused_under_an_allowlist() -> None:
    guard = _nodeny_guard("postgres", ["ocean"], {("ocean", "buoys")})
    _assert_refused(guard.validate_select, "SELECT rolname FROM pg_roles")
    _assert_refused(guard.validate_select, "SELECT rolname FROM pg_catalog.pg_roles")
    assert guard.validate_select("SELECT buoy_id FROM ocean.buoys").kind == "select"


def test_f06_no_resolver_under_an_allowlist_refuses_unqualified_names() -> None:
    guard = _nodeny_guard("oracle", ["TRAVEL"], None)
    exc = _assert_refused(guard.validate_select, "SELECT username FROM ALL_USERS")
    assert "qualify it with an allowed schema" in str(exc)
    assert guard.validate_select("SELECT * FROM TRAVEL.BOOKINGS").kind == "select"


def test_f06_ambiguous_unqualified_name_is_refused() -> None:
    guard = _nodeny_guard("postgres", ["sales", "archive"], {("sales", "t"), ("archive", "t")})
    exc = _assert_refused(guard.validate_select, "SELECT * FROM t")
    assert "write archive.t or sales.t" in str(exc)


def test_f06_cte_names_are_not_catalog_objects() -> None:
    guard = _nodeny_guard("postgres", ["sales"], {("sales", "orders")})
    sql = "WITH recent AS (SELECT * FROM sales.orders) SELECT count(*) FROM recent"
    assert guard.validate_select(sql).kind == "select"


# ---- F25: system schemas need allowed_system_schemas, allowlist or not ------


def _assert_authz_denied(fn: Any, *args: Any) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        fn(*args)
    assert info.value.category == ErrorCategory.AUTHZ, str(info.value)
    return info.value


@pytest.mark.parametrize(
    "engine,schema,name",
    [
        ("db2", "SYSCAT", "DBAUTH"),
        ("db2", "SYSIBMADM", "AUTHORIZATIONIDS"),
        ("oracle", "SYS", "ALL_USERS"),
        ("oracle", "SYS", "USER_PASSWORD_LIMITS"),
        ("postgres", "pg_catalog", "pg_roles"),
        ("mysql", "mysql", "db"),  # mysql.user and sys.sql_logins hold credentials: refused before the schema
        ("mssql", "sys", "server_principals"),
        ("clickhouse", "system", "users"),
    ],
)
def test_f25_system_schema_denied_with_an_empty_allowlist(engine: str, schema: str, name: str) -> None:
    policy = _policy(engine)  # code defaults: allowed_schemas [], allowed_system_schemas [information_schema]
    assert not policy.allowed_schemas
    exc = _assert_authz_denied(policy.check_object, schema, name)
    assert f"schema '{schema}'" in str(exc) and "allowed_system_schemas" in str(exc)


@pytest.mark.parametrize(
    "engine,schema", [("db2", "MOI"), ("oracle", "TRAVEL"), ("postgres", "public"), ("mysql", "testdb")]
)
def test_f25_user_schema_still_passes_with_an_empty_allowlist(engine: str, schema: str) -> None:
    _policy(engine).check_object(schema, "t")


def test_f25_allowed_system_schemas_opens_a_system_schema() -> None:
    security = SecurityConfig(allowed_system_schemas=["information_schema", "SYSCAT"])
    _policy("db2", security).check_object("SYSCAT", "TABLES")
    _policy("db2", security).check_object("syscat", "tables")
    _assert_authz_denied(_policy("db2", security).check_object, "SYSIBMADM", "AUTHORIZATIONIDS")


def test_f25_information_schema_stays_readable_by_default() -> None:
    for engine in ("postgres", "mysql", "mssql", "clickhouse"):
        _policy(engine).check_object("information_schema", "tables")
        _policy(engine).check_object("INFORMATION_SCHEMA", "TABLES")


def test_f25_an_allowlist_that_names_a_system_schema_is_an_explicit_allowance() -> None:
    _policy("mysql", allowed_schemas=["performance_schema"]).check_object("performance_schema", "accounts")
    _assert_authz_denied(_policy("mysql", allowed_schemas=["testdb"]).check_object, "mysql", "db")


def test_f25_is_system_schema_compares_folded_and_stripped() -> None:
    policy = _policy("oracle")
    assert policy.is_system_schema("SYS") and policy.is_system_schema(" sys ") and policy.is_system_schema("VecSys")
    assert not policy.is_system_schema("TRAVEL") and not policy.is_system_schema(None)


@pytest.mark.parametrize(
    "engine,schema",
    [
        ("oracle", "apex_050000 "),
        ("oracle", " SYS"),
        ("oracle", "ODM\t"),
        ("db2", " SYSCAT "),
        ("postgres", "pg_catalog "),
    ],
)
def test_f25_system_schema_helpers_agree_with_the_policy_on_padded_names(engine: str, schema: str) -> None:
    """Discovery's filter and the policy fold the same way: stripped and lower-cased."""
    from universal_db_mcp.discovery.system_schemas import is_listed_system_schema, is_system_object

    assert _policy(engine).is_system_schema(schema)
    assert is_listed_system_schema(engine, schema)
    assert is_system_object(engine, schema, "t")


def test_f25_guard_refuses_sys_qualified_and_unqualified() -> None:
    guard = _guard("oracle", StaticResolver({("sys", "all_users"), ("travel", "bookings")}))
    _assert_authz_denied(guard.validate_select, "SELECT * FROM SYS.ALL_USERS")
    # the bare name binds to SYS: the candidate re-authorization refuses it
    _assert_authz_denied(guard.validate_select, "SELECT username FROM ALL_USERS")
    _assert_authz_denied(guard.validate_explain, "EXPLAIN SELECT username FROM ALL_USERS")
    assert guard.validate_select("SELECT * FROM bookings").kind == "select"


def test_f25_guard_refuses_db2_catalog_under_code_defaults() -> None:
    guard = _guard("db2", StaticResolver({("syscat", "dbauth"), ("moi", "citizens")}))
    _assert_authz_denied(guard.validate_select, "SELECT GRANTEE, DBADMAUTH FROM SYSCAT.DBAUTH")
    _assert_authz_denied(guard.validate_select, "SELECT GRANTEE FROM DBAUTH WITH UR")
    assert guard.validate_select("SELECT * FROM MOI.CITIZENS WITH UR").kind == "select"


def test_f25_system_schema_lists_are_complete() -> None:
    from universal_db_mcp.discovery.system_schemas import SYSTEM_SCHEMAS

    # Oracle-maintained users seen on 23ai (ALL_USERS.ORACLE_MAINTAINED = 'Y') and pre-12c owners
    assert {
        "vecsys",
        "baassys",
        "dgpdb_int",
        "dvf",
        "ggsharedcap",
        "gsmcatuser",
        "gsmuser",
        "mddata",
        "gsmrootuser",
        "oracle_ocm",
        "si_informtn_schema",
        "exfsys",
        "sysman",
        "mgmt_view",
        # 10g/11g owners: Ultra Search, Data Mining, Transparent Session Migration
        "wksys",
        "wk_test",
        "wkproxy",
        "dmsys",
        "tsmsys",
        # 9i/10gR1: Data Mining before DMSYS, and the Windows MTS owner
        "odm",
        "odm_mtr",
        "mtssys",
        # 9i JServer and trace owners, which an 11.2 database upgraded from 9i can still carry
        "aurora$jis$utility$",
        "aurora$orb$unauthenticated",
        "ose$http$admin",
        "tracesvr",
        # APEX / HTML DB accounts outside the APEX_nnnnnn / FLOWS_nnnnnn pattern
        "apex_listener",
        "apex_rest_public_user",
        "apex_instance_admin_user",
        "htmldb_public_user",
    } <= SYSTEM_SCHEMAS["oracle"]
    # Db2 SYSCAT.SCHEMATA entries owned by SYSIBM
    assert {"sysibminternal", "sysibmts", "nullid", "sqlj"} <= SYSTEM_SCHEMAS["db2"]


@pytest.mark.parametrize("schema", ["FLOWS_030000", "flows_020100", "APEX_050000", "APEX_240200", " apex_040200 "])
def test_f25_versioned_apex_owners_are_system_schemas(schema: str) -> None:
    """APEX installs one owner per release (FLOWS_nnnnnn before 3.2,
    APEX_nnnnnn since); no list can name them all, so they match by pattern."""
    from universal_db_mcp.discovery.system_schemas import is_system_object

    policy = _policy("oracle")
    assert policy.is_system_schema(schema)
    _assert_authz_denied(policy.check_object, schema, "WWV_FLOWS")
    assert is_system_object("oracle", schema.strip(), "WWV_FLOWS")
    guard = _guard("oracle", StaticResolver({(schema.strip().lower(), "wwv_flows")}))
    _assert_authz_denied(guard.validate_select, f"SELECT * FROM {schema.strip()}.WWV_FLOWS")
    opened = _policy("oracle", SecurityConfig(allowed_system_schemas=[schema.strip()]))
    opened.check_object(schema.strip(), "WWV_FLOWS")


@pytest.mark.parametrize("schema", ["APEX_APP", "APEX_05000", "APEX_0500000", "MYAPEX_050000", "FLOWS", "APEX_05000A"])
def test_f25_apex_pattern_does_not_close_user_schemas(schema: str) -> None:
    from universal_db_mcp.discovery.system_schemas import is_system_object

    policy = _policy("oracle")
    assert not policy.is_system_schema(schema)
    policy.check_object(schema, "T")
    assert not is_system_object("oracle", schema, "T")


def test_f25_apex_pattern_is_oracle_only() -> None:
    from universal_db_mcp.discovery.system_schemas import is_system_object

    for engine in ("postgres", "mysql", "mssql", "db2", "clickhouse"):
        assert not _policy(engine).is_system_schema("apex_050000")
        assert not is_system_object(engine, "apex_050000", "t")


def test_f25_every_listed_system_schema_is_enforced() -> None:
    """Parity: every engine in SYSTEM_SCHEMAS, every schema it lists (less the
    discovery-only ones, which round 2 opened: see the pdbadmin test)."""
    from universal_db_mcp.discovery.system_schemas import DISCOVERY_ONLY_SCHEMAS, SYSTEM_SCHEMAS

    default_open = {s.lower() for s in SecurityConfig().allowed_system_schemas}
    for engine, schemas in SYSTEM_SCHEMAS.items():
        policy = _policy(engine)
        for schema in schemas - DISCOVERY_ONLY_SCHEMAS.get(engine, frozenset()):
            assert policy.is_system_schema(schema), (engine, schema)
            if schema in default_open:
                policy.check_object(schema, "x")
            else:
                _assert_authz_denied(policy.check_object, schema.upper(), "x")
            opened = _policy(engine, SecurityConfig(allowed_system_schemas=[schema]))
            opened.check_object(schema, "x")
    assert SYSTEM_SCHEMAS["sqlite"] == frozenset()


# ---- F20: SQLite's catalog tables are not exempt from the object policy -----

# what PRAGMA table_list (the SQLite connector's list_tables) reports, catalog included
_SQLITE_CATALOG = {
    ("main", "users"),
    ("main", "sqlite_schema"),
    ("main", "sqlite_sequence"),
    ("main", "sqlite_stat1"),
}


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT sql FROM sqlite_master",
        "SELECT sql FROM sqlite_master WHERE name = 'users'",
        "SELECT name FROM sqlite_schema",
        "SELECT sql FROM main.sqlite_schema",
        "SELECT sql FROM SQLITE_MASTER",
        'SELECT sql FROM "sqlite_master"',
        "SELECT sql FROM sqlite_temp_master",
        "SELECT sql FROM temp.sqlite_temp_schema",
        "SELECT * FROM sqlite_sequence",
        "SELECT * FROM sqlite_stat1",
        "SELECT * FROM sqlite_dbpage",
        "SELECT u.id FROM users u JOIN sqlite_master m ON m.name = 'users'",
    ],
)
@pytest.mark.parametrize("catalog", ["user_tables", "pragma_table_list"])
def test_f20_sqlite_catalog_tables_are_refused(sql: str, catalog: str) -> None:
    objects = {("main", "users"), (None, "users")} if catalog == "user_tables" else _SQLITE_CATALOG
    guard = _guard("sqlite", StaticResolver(objects))
    _assert_refused(guard.validate_select, sql)
    _assert_refused(guard.validate_explain, "EXPLAIN QUERY PLAN " + sql)


def test_f20_sqlite_user_tables_still_readable() -> None:
    guard = _guard("sqlite", StaticResolver(_SQLITE_CATALOG))
    assert guard.validate_select("SELECT id FROM users").kind == "select"
    assert guard.validate_select("SELECT id FROM main.users").kind == "select"


def test_f20_sqlite_catalog_readable_once_default_deny_is_off() -> None:
    # the administrator's explicit opt-out of object-level default-deny
    guard = SqlGuard("sqlite", _policy("sqlite", SecurityConfig(default_deny_objects=False)), None)
    assert guard.validate_select("SELECT sql FROM sqlite_master").kind == "select"


def test_f20_sqlite_metadata_tools_still_work_end_to_end(tmp_path: Any) -> None:
    import asyncio
    import json
    import sqlite3

    from universal_db_mcp.config import load_resolved
    from universal_db_mcp.server import AppContext, build_server

    db = tmp_path / "app.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT,"
        " password TEXT DEFAULT 'changeme-default-secret');"
        "INSERT INTO users (login) VALUES ('alice'); ANALYZE;"
    )
    conn.commit()
    conn.close()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "application:\n  transport: stdio\n"
        f"  audit_path: {tmp_path / 'audit.jsonl'}\n"
        f"  metadata_cache_path: {tmp_path / 'cache.sqlite'}\n"
        f"connections:\n  app:\n    type: sqlite\n    database: {db}\n",
        encoding="utf-8",
    )
    app_cfg, resolved = load_resolved(cfg)
    server = build_server(AppContext(app_cfg, resolved))

    def call(name: str, args: dict[str, Any]) -> Any:
        return asyncio.run(server.call_tool(name, {"connection_id": "app", **args}))

    tables = call("db_list_tables", {}).structured_content["data"]
    assert "users" in json.dumps(tables, default=str)
    assert call("db_get_table", {"object_name": "users"}).structured_content["data"]["columns"]
    assert call("db_list_columns", {"object_name": "users"}).structured_content["data"]["columns"]
    assert call("db_query", {"sql": "SELECT login FROM users"}).structured_content["data"]["rows"] == [["alice"]]
    for sql in (
        "SELECT sql FROM sqlite_master WHERE name = 'users'",
        "SELECT sql FROM sqlite_schema",
        "SELECT * FROM sqlite_sequence",
        "SELECT * FROM sqlite_stat1",
    ):
        with pytest.raises(Exception) as info:  # noqa: PT011 - the MCP ToolError text is the assertion
            call("db_query", {"sql": sql})
        assert "POLICY_VIOLATION" in str(info.value) or "AUTHORIZATION_DENIED" in str(info.value), sql
        assert "changeme-default-secret" not in str(info.value)


# ---- F89: EXPLAIN options reach the engine or are refused, never dropped ----
# The choice pinned here (next to test_validate_explain_keeps_the_statement_
# text_as_written): GuardResult.text carries the validated, re-rendered option
# list, because db_explain sends 'EXPLAIN ' + text.


def _explain_guard(engine: str, **security: Any) -> SqlGuard:
    return SqlGuard(engine, _policy(engine, SecurityConfig(default_deny_objects=False, **security)), None)


def _assert_validation_error(fn: Any, *args: Any) -> ToolFailure:
    with pytest.raises(ToolFailure) as info:
        fn(*args)
    assert info.value.category == ErrorCategory.VALIDATION, str(info.value)
    return info.value


@pytest.mark.parametrize(
    "sql,text",
    [
        ("EXPLAIN (FORMAT YAML) SELECT buoy_id FROM ocean.buoys", "(FORMAT YAML) SELECT buoy_id FROM ocean.buoys"),
        ("EXPLAIN (FORMAT XML) SELECT 1", "(FORMAT XML) SELECT 1"),
        ("EXPLAIN (format text) SELECT 1", "(FORMAT TEXT) SELECT 1"),
        ("EXPLAIN (COSTS OFF) SELECT 1", "(COSTS OFF) SELECT 1"),
        ("explain ( verbose , costs false ) select 1;", "(VERBOSE, COSTS FALSE) select 1"),
        ("EXPLAIN (SETTINGS ON, SUMMARY, COSTS 0) SELECT 1", "(SETTINGS ON, SUMMARY, COSTS 0) SELECT 1"),
        ("EXPLAIN(GENERIC_PLAN)SELECT 1 WHERE 1 = $1", "(GENERIC_PLAN) SELECT 1 WHERE 1 = $1"),
        ("EXPLAIN SELECT 1", "SELECT 1"),
        # a parenthesized statement is not an option list
        ("EXPLAIN (SELECT 1) UNION (SELECT 2)", "(SELECT 1) UNION (SELECT 2)"),
        ("EXPLAIN (COSTS OFF) (SELECT 1) UNION (SELECT 2)", "(COSTS OFF) (SELECT 1) UNION (SELECT 2)"),
    ],
)
def test_f89_postgres_explain_options_are_carried(sql: str, text: str) -> None:
    assert _explain_guard("postgres").validate_explain(sql).text == text


def test_f89_postgres_format_json_is_refused_not_dropped() -> None:
    # the PostgreSQL connector renders text plans; a json-typed plan would fail there
    exc = _assert_validation_error(_explain_guard("postgres").validate_explain, "EXPLAIN (FORMAT JSON) SELECT 1")
    assert "FORMAT YAML" in str(exc)


@pytest.mark.parametrize(
    "options",
    [
        "BUFFERS",
        "TIMING",
        "SERIALIZE",
        "MEMORY",
        "FORMAT",
        "FORMAT CSV",
        "COSTS MAYBE",
        "COSTS 'off'",
        "",
        "COSTS OFF,",
        "FORMAT YAML TEXT",
        "COSTS=OFF",
    ],
)
def test_f89_postgres_unsupported_options_are_refused(options: str) -> None:
    exc = _assert_validation_error(_explain_guard("postgres").validate_explain, f"EXPLAIN ({options}) SELECT 1")
    assert "EXPLAIN option" in str(exc)


@pytest.mark.parametrize("options", ["ANALYZE", "ANALYZE TRUE", "WAL", "COSTS OFF, ANALYZE"])
def test_f89_executing_options_stay_denied(options: str) -> None:
    _assert_policy_denied(_explain_guard("postgres").validate_explain, f"EXPLAIN ({options}) SELECT 1")
    # allowing EXPLAIN ANALYZE by policy does not smuggle it through the option list
    _assert_validation_error(
        _explain_guard("postgres", allow_explain_analyze=True).validate_explain, f"EXPLAIN ({options}) SELECT 1"
    )


@pytest.mark.parametrize(
    "engine,sql",
    [
        ("postgres", "EXPLAIN ANALYZE SELECT 1"),
        ("postgres", "explain analyze select 1"),
        ("postgres", "EXPLAIN (COSTS OFF) ANALYZE SELECT 1"),
        ("clickhouse", "EXPLAIN ANALYZE SELECT 1"),
        ("mysql", "EXPLAIN ANALYZE SELECT 1"),
        ("mysql", "EXPLAIN ANALYZE FORMAT=TREE SELECT 1"),
    ],
)
def test_f89_bare_analyze_is_refused_not_dropped(engine: str, sql: str) -> None:
    """The keyword form used to be accepted and removed from GuardResult.text:
    the caller asked for an executed plan and silently got a plain one."""
    exc = _assert_policy_denied(_explain_guard(engine).validate_explain, sql)
    assert "disabled by policy" in str(exc)
    allowed = _explain_guard(engine, allow_explain_analyze=True)
    exc = _assert_validation_error(allowed.validate_explain, sql)
    assert "ANALYZE" in str(exc)


def test_f89_bare_analyze_and_the_option_give_one_message() -> None:
    allowed = _explain_guard("postgres", allow_explain_analyze=True)
    bare = _assert_validation_error(allowed.validate_explain, "EXPLAIN ANALYZE SELECT 1")
    option = _assert_validation_error(allowed.validate_explain, "EXPLAIN (ANALYZE) SELECT 1")
    assert str(bare) == str(option)


@pytest.mark.parametrize(
    "engine,sql",
    [
        ("postgres", "EXPLAIN ANALYSE SELECT 1"),
        ("postgres", "EXPLAIN (ANALYSE) SELECT 1"),
        ("postgres", "EXPLAIN (COSTS OFF, analyse true) SELECT 1"),
        ("postgres", "EXPLAIN ANALYZE VERBOSE SELECT 1"),
        ("postgres", "EXPLAIN analyse verbose SELECT 1"),
        ("clickhouse", "EXPLAIN ANALYSE SELECT 1"),
        ("clickhouse", "EXPLAIN ANALYZE VERBOSE SELECT 1"),
    ],
)
def test_f89_analyse_spelling_and_legacy_verbose_get_the_analyze_refusals(engine: str, sql: str) -> None:
    """PostgreSQL's ANALYSE spelling and its legacy EXPLAIN ANALYZE VERBOSE
    form are refused with the same category and message as plain ANALYZE:
    'disabled by policy' with the flag off, the one 'not supported' message
    with it on (they used to fall through to an option or parse error)."""
    exc = _assert_policy_denied(_explain_guard(engine).validate_explain, sql)
    assert "disabled by policy" in str(exc)
    allowed = _explain_guard(engine, allow_explain_analyze=True)
    exc = _assert_validation_error(allowed.validate_explain, sql)
    assert str(exc) == str(_assert_validation_error(allowed.validate_explain, "EXPLAIN ANALYZE SELECT 1"))


def test_f89_analyse_option_list_is_gated_on_clickhouse_too() -> None:
    _assert_policy_denied(_explain_guard("clickhouse").validate_explain, "EXPLAIN (ANALYSE) SELECT 1")


def test_f89_legacy_verbose_after_analyze_still_denies_a_write_first() -> None:
    allowed = _explain_guard("postgres", allow_explain_analyze=True)
    _assert_policy_denied(allowed.validate_explain, "EXPLAIN ANALYZE VERBOSE DELETE FROM t")


@pytest.mark.parametrize("engine", ["postgres", "mysql"])
def test_f89_bare_analyze_statement_denial_comes_first(engine: str) -> None:
    allowed = _explain_guard(engine, allow_explain_analyze=True)
    _assert_policy_denied(allowed.validate_explain, "EXPLAIN ANALYZE DELETE FROM t")


def test_f89_policy_denial_of_the_statement_comes_before_option_errors() -> None:
    _assert_policy_denied(_explain_guard("postgres").validate_explain, "EXPLAIN (FORMAT JSON) DELETE FROM t")


@pytest.mark.parametrize("engine", ["db2", "clickhouse"])
def test_f89_option_lists_are_refused_on_engines_without_them(engine: str) -> None:
    exc = _assert_validation_error(_explain_guard(engine).validate_explain, "EXPLAIN (COSTS OFF) SELECT 1")
    assert engine in str(exc)
    assert _explain_guard(engine).validate_explain("EXPLAIN SELECT 1").text == "SELECT 1"


@pytest.mark.parametrize(
    "sql,text",
    [
        ("EXPLAIN FORMAT=JSON SELECT COUNT(*) FROM testdb.t", "FORMAT=JSON SELECT COUNT(*) FROM testdb.t"),
        ("explain format = tree select 1", "FORMAT=TREE select 1"),
        ("EXPLAIN FORMAT=TRADITIONAL SELECT 1", "FORMAT=TRADITIONAL SELECT 1"),
        ("EXPLAIN SELECT 1", "SELECT 1"),
    ],
)
def test_f89_mysql_explain_format_is_carried(sql: str, text: str) -> None:
    assert _explain_guard("mysql").validate_explain(sql).text == text


def test_f89_mysql_unknown_format_is_refused_and_analyze_stays_denied() -> None:
    exc = _assert_validation_error(_explain_guard("mysql").validate_explain, "EXPLAIN FORMAT=XML SELECT 1")
    assert "FORMAT=XML" in str(exc)
    _assert_policy_denied(_explain_guard("mysql").validate_explain, "EXPLAIN ANALYZE FORMAT=TREE SELECT 1")


# ---- F90: sql_fingerprint's literal patterns are linear in memory -----------


def _old_sql_fingerprint(sql: str) -> str:
    """The pre-fix implementation, kept as the reference for stability."""
    import hashlib
    import re

    s = re.sub(r"'(?:[^']|'')*'", "?", sql)
    s = re.sub(r'"(?:[^"]|"")*"', "?", s)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def _peak_mb_and_secs(fn: Any, *args: Any) -> tuple[float, float]:
    import tracemalloc

    tracemalloc.start()
    try:
        t0 = time.perf_counter()
        fn(*args)
        secs = time.perf_counter() - t0
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return peak / 1e6, secs


@pytest.mark.parametrize("quote", ["'", '"'])
def test_f90_unterminated_literal_fingerprint_is_bounded(quote: str) -> None:
    from universal_db_mcp.security.redact import sql_fingerprint

    peak_mb, secs = _peak_mb_and_secs(sql_fingerprint, quote + "a" * 2_000_000)
    assert peak_mb < 50 and secs < 1.0, (peak_mb, secs)


@pytest.mark.parametrize("quote", ["'", '"'])
def test_f90_literal_patterns_alone_are_linear_in_memory(quote: str) -> None:
    # the regex itself, not only the length cap: ~300 MB on 2M chars before the fix
    from universal_db_mcp.security import redact

    pattern = redact._SQ_LITERAL if quote == "'" else redact._DQ_LITERAL
    peak_mb, secs = _peak_mb_and_secs(pattern.sub, "?", quote + "a" * 2_000_000)
    assert peak_mb < 50 and secs < 1.0, (peak_mb, secs)


_F90_SAMPLES = [
    "SELECT * FROM t WHERE id = 42 AND name = 'bob'",
    "select * from t where id = 7 and name = 'alice'",
    "SELECT 'it''s' AS s, \"Col\"\"Name\" FROM t",
    "SELECT a FROM t WHERE b IN (1, 2.5, 3) -- note",
    'SELECT "x" FROM "Sales"."Orders" WHERE note = \'\'',
    "SELECT '' , '''' , 'a''' , '''b' FROM dual",
    "SELECT 1",
    "  SELECT\n\t*\nFROM   t  ",
    "SELECT * FROM t WHERE s = 'unterminated",
    'SELECT * FROM t WHERE s = "unterminated',
    "SELECT 'a' 'b' \"c\" \"d\" FROM t",
    "SELECT x FROM t WHERE y = 'O''Brien' AND z = 3.14159",
    "EXPLAIN (FORMAT YAML) SELECT buoy_id FROM ocean.buoys",
    "SELECT * FROM t1 JOIN t2 ON t1.a = t2.b WHERE t1.c > 100",
    "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
    'SELECT "it\'s" FROM t WHERE \'say "hi"\' = s',
    "SELECT 'x'''",
    "SELECT ''''''",
    "SELECT col1, col2 FROM schema1.table2 WHERE col3 LIKE '%abc%' ORDER BY 1 DESC LIMIT 10",
    "SELECT 1 /* 'x' */ , \"\" FROM t",
]


@pytest.mark.parametrize("sql", _F90_SAMPLES)
def test_f90_fingerprints_of_ordinary_statements_are_unchanged(sql: str) -> None:
    from universal_db_mcp.security.redact import sql_fingerprint

    assert sql_fingerprint(sql) == _old_sql_fingerprint(sql)


def test_f90_unrolled_patterns_match_the_old_ones() -> None:
    import random
    import re

    from universal_db_mcp.security import redact

    rng = random.Random(90)  # noqa: S311 - a reproducible fuzz corpus, not a secret
    for old, new in ((r"'(?:[^']|'')*'", redact._SQ_LITERAL), (r'"(?:[^"]|"")*"', redact._DQ_LITERAL)):
        for _ in range(20000):
            s = "".join(rng.choice("''\"\"ab 1") for _ in range(rng.randint(0, 14)))
            assert new.sub("?", s) == re.sub(old, "?", s), s


def test_f90_oversized_statement_fingerprint_keeps_its_length() -> None:
    from universal_db_mcp.security.redact import sql_fingerprint

    head = "SELECT " + "x" * 70_000
    assert sql_fingerprint(head) != sql_fingerprint(head + "y")
    assert sql_fingerprint(head).startswith("sha256:")


# ---- F87: lexer escape branches and the per-dialect refusal battery --------


def _qmark_to_pyformat(segment: str) -> str:
    return segment.replace("?", "%s")


def test_f87_backslash_escape_keeps_the_literal_closed() -> None:
    sql = "note = 'it\\'s ?' AND id = ?"
    literal = "'it\\'s ?'"
    rewritten, view = sql_guard._rewrite_code_segments(sql, _qmark_to_pyformat, backslash_escapes=True)
    assert rewritten == "note = 'it\\'s ?' AND id = %s"  # the ? inside the literal is data
    start = sql.index(literal)
    assert len(view) == len(sql) and view[start : start + len(literal)] == " " * len(literal)
    assert view.count("?") == 1
    assert sql_guard.translate_paramstyle(sql, [7], backslash_escapes=True) == (
        "note = 'it\\'s ?' AND id = %s",
        [7],
    )


@pytest.mark.parametrize("backslash_escapes", [False, True])
def test_f87_doubled_quote_escape_keeps_the_literal_closed(backslash_escapes: bool) -> None:
    sql = "SELECT 'a''b?' , ?"
    literal = "'a''b?'"
    rewritten, view = sql_guard._rewrite_code_segments(sql, _qmark_to_pyformat, backslash_escapes=backslash_escapes)
    assert rewritten == "SELECT 'a''b?' , %s"
    assert view == "SELECT " + " " * len(literal) + " , ?"
    assert view.count("?") == 1
    assert sql_guard.translate_paramstyle(sql, (1,), backslash_escapes=backslash_escapes) == (
        "SELECT 'a''b?' , %s",
        (1,),
    )


def test_f87_doubled_closing_bracket_keeps_the_identifier_closed() -> None:
    # for ' " ` a doubled quote reads the same as close-and-reopen; for [...]
    # only the doubled-quote branch keeps ]] inside the identifier
    sql = "SELECT [a]]b?] , ?"
    rewritten, view = sql_guard._rewrite_code_segments(sql, _qmark_to_pyformat, backslash_escapes=False)
    assert rewritten == "SELECT [a]]b?] , %s"
    assert view == "SELECT " + " " * len("[a]]b?]") + " , ?"


def test_f87_quoted_identifiers_and_comments_are_never_rewritten() -> None:
    sql = 'SELECT "c?", `d?`, [e?] FROM t -- ?\nWHERE a = ? /* ? */'
    rewritten, view = sql_guard._rewrite_code_segments(sql, _qmark_to_pyformat, backslash_escapes=False)
    assert rewritten == 'SELECT "c?", `d?`, [e?] FROM t -- ?\nWHERE a = %s /* ? */'
    assert view.count("?") == 1 and len(view) == len(sql)


def test_f87_named_parameters_translate_outside_literals() -> None:
    sql = "SELECT * FROM t WHERE a = :a AND s = ':b' AND c::text = :c"
    assert sql_guard.translate_paramstyle(sql, {"a": 1, "c": 2}, backslash_escapes=False) == (
        "SELECT * FROM t WHERE a = %(a)s AND s = ':b' AND c::text = %(c)s",
        {"a": 1, "c": 2},
    )


@pytest.mark.parametrize(
    "sql,params,qmark,needle",
    [
        ("SELECT ? , :a", {"a": 1}, True, "positional placeholders (%s or ?)"),
        ("SELECT %s , :a", {"a": 1}, False, "positional placeholders (%s)"),
        ("SELECT :a , :b", {"a": 1}, True, "not supplied: ['b']"),
        ("SELECT :a", [1], True, "named placeholders"),
        ("SELECT %(a)s", [1], True, "named placeholders"),
        ("SELECT ?, %s", [1, 2], True, "mixes positional placeholder styles"),
    ],
)
def test_f87_paramstyle_mismatches_are_validation_errors(sql: str, params: Any, qmark: bool, needle: str) -> None:
    with pytest.raises(ToolFailure) as info:
        sql_guard.translate_paramstyle(sql, params, backslash_escapes=False, qmark_is_placeholder=qmark)
    assert info.value.category == ErrorCategory.VALIDATION
    assert needle in str(info.value)


def test_f87_paramstyle_pass_through_cases() -> None:
    tp = sql_guard.translate_paramstyle
    assert tp("SELECT 1", None, backslash_escapes=False) == ("SELECT 1", None)
    assert tp("SELECT %s", [1], backslash_escapes=False) == ("SELECT %s", [1])
    # psycopg: ? is the JSONB key-exists operator, never a placeholder
    assert tp("SELECT d ? 'k', %s", [1], backslash_escapes=False, qmark_is_placeholder=False) == (
        "SELECT d ? 'k', %s",
        [1],
    )
    assert tp("SELECT 1", [], backslash_escapes=False) == ("SELECT 1", [])
    assert tp("SELECT ?", "odd", backslash_escapes=False) == ("SELECT ?", "odd")


# per engine: (schema, table, a table in a schema outside the allowlist)
_F87_OBJECTS: dict[str, tuple[str | None, str, str | None]] = {
    "sqlite": (None, "customers", None),
    "postgres": ("ocean", "buoys", "reporting.secret"),
    "mysql": ("testdb", "cuppings", "hr.salaries"),
    "clickhouse": ("telecom", "cdr", "hr.salaries"),
    "oracle": ("TRAVEL", "BOOKINGS", "HR.SALARIES"),
    "mssql": ("dbo", "patients", "hr.salaries"),
    "db2": ("MOI", "CITIZENS", "HR.SALARIES"),
}
_F87_TABLE_FUNCTION = {
    "sqlite": "SELECT * FROM json_each('[1]')",
    "postgres": "SELECT * FROM generate_series(1, 2)",
    "mysql": "SELECT * FROM JSON_TABLE('[1]', '$[*]' COLUMNS (a INT PATH '$')) AS jt",
    "clickhouse": "SELECT * FROM numbers(2)",
    "oracle": "SELECT * FROM TABLE(sys.odcinumberlist(1, 2))",
    "mssql": "SELECT * FROM STRING_SPLIT('a,b', ',')",
    "db2": "SELECT * FROM TABLE(SYSPROC.ENV_GET_INST_INFO()) AS t",
}
_F87_SET = {
    "sqlite": "SET x = 1",
    "postgres": "SET work_mem = '64MB'",
    "mysql": "SET @a = 1",
    "clickhouse": "SET max_threads = 1",
    "oracle": "SET TRANSACTION READ ONLY",
    "mssql": "SET NOCOUNT ON",
    "db2": "SET CURRENT SCHEMA MOI",
}
_F87_DANGEROUS = {
    "sqlite": "load_extension('x')",
    "postgres": "pg_sleep(1)",
    "mysql": "SLEEP(1)",
    "clickhouse": "sleep(1)",
    "oracle": "UTL_HTTP(1)",
    "mssql": "xp_cmdshell('dir')",
    "db2": "load_file('x')",
}
_F87_SEQUENCE = {
    "sqlite": "SELECT nextval('s1') AS v",
    "postgres": "SELECT nextval('s1') AS v",
    "mysql": "SELECT NEXT VALUE FOR s1 AS v FROM {q}",
    "clickhouse": "SELECT nextval('s1') AS v",
    "oracle": "SELECT s1.NEXTVAL AS v FROM {q}",
    "mssql": "SELECT NEXT VALUE FOR dbo.s1 AS v",
    "db2": "SELECT NEXTVAL FOR MOI.S1 AS v FROM {q}",
}
_F87_LOCKING = {
    "sqlite": "SELECT * FROM {q} FOR UPDATE",
    "postgres": "SELECT * FROM {q} FOR UPDATE",
    "mysql": "SELECT * FROM {q} FOR SHARE",
    "clickhouse": "SELECT * FROM {q} FOR UPDATE",
    "oracle": "SELECT * FROM {q} FOR UPDATE",
    "mssql": "SELECT * FROM {q} WITH (UPDLOCK)",
    "db2": "SELECT * FROM {q} WITH RS",
}


def _f87_cases(engine: str) -> list[tuple[str, str, ErrorCategory, str | None]]:
    """(claim, statement, refusal category, message fragment when uniform)."""
    schema, table, other = _F87_OBJECTS[engine]
    q = f"{schema}.{table}" if schema else table
    policy, authz = ErrorCategory.POLICY, ErrorCategory.AUTHZ
    cases = [
        ("one statement", f"SELECT 1 AS a FROM {q}; SELECT 2 AS b FROM {q}", policy, "exactly one statement"),
        ("parse failure", f"SELEC * FORM {q}", policy, None),
        ("modifying CTE", f"WITH x AS (DELETE FROM {q} WHERE 1=0) SELECT * FROM x", policy, "disallowed construct"),
        ("unknown function", f"SELECT no_such_fn(1) AS v FROM {q}", policy, "unknown or unsupported function"),
        ("dangerous function", f"SELECT {_F87_DANGEROUS[engine]} AS v FROM {q}", policy, "is not permitted"),
        ("table function", _F87_TABLE_FUNCTION[engine], policy, "table functions"),
        ("executable comment", f"SELECT /*!50000 1 */ AS v FROM {q}", policy, "executable comments"),
        ("SELECT INTO", f"SELECT * INTO copy_t FROM {q}", policy, "SELECT INTO"),
        ("SET", _F87_SET[engine], policy, None),
        (
            "unresolvable object",
            f"SELECT * FROM {schema + '.' if schema else ''}no_such_table_x",
            policy,
            "could not be resolved",
        ),
        ("catalog-qualified", f"SELECT * FROM otherdb.{schema or 'main'}.{table}", policy, "catalog"),
        ("sequence", _F87_SEQUENCE[engine].format(q=q), policy, None),
        ("DML root", f"DELETE FROM {q} WHERE 1=0", policy, None),
        ("DDL root", f"DROP TABLE {q}", policy, None),
        ("locking read", _F87_LOCKING[engine].format(q=q), policy, None),
    ]
    if other:
        cases.append(("schema allowlist", f"SELECT * FROM {other}", authz, "is not permitted on connection"))
    return cases


def _f87_guard(engine: str) -> SqlGuard:
    schema, table, _ = _F87_OBJECTS[engine]
    policy = _policy(engine, allowed_schemas=None if schema is None else [schema])
    objects = {(None, table.lower()), ((schema or "main").lower(), table.lower())}
    return SqlGuard(engine, policy, StaticResolver(objects))


_F87_BATTERY = [(engine, *case) for engine in ENGINES for case in _f87_cases(engine)]


@pytest.mark.parametrize(
    "engine,claim,sql,category,fragment", _F87_BATTERY, ids=[f"{c[0]}-{c[1]}" for c in _F87_BATTERY]
)
def test_f87_refusal_battery(engine: str, claim: str, sql: str, category: ErrorCategory, fragment: str | None) -> None:
    guard = _f87_guard(engine)
    for validate, text in ((guard.validate_select, sql), (guard.validate_explain, "EXPLAIN " + sql)):
        with pytest.raises(ToolFailure) as info:
            validate(text)
        assert info.value.category == category, (claim, str(info.value))
        if fragment is not None:
            assert fragment in str(info.value), (claim, str(info.value))


@pytest.mark.parametrize("engine", ENGINES)
def test_f87_battery_control_read_is_allowed(engine: str) -> None:
    schema, table, _ = _F87_OBJECTS[engine]
    sql = f"SELECT COUNT(*) AS n FROM {schema + '.' if schema else ''}{table}"
    guard = _f87_guard(engine)
    assert guard.validate_select(sql).kind == "select"
    assert guard.validate_explain("EXPLAIN " + sql).kind == "explain"


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize(
    "template",
    [
        "EXPLAIN ANALYZE SELECT * FROM {q}",
        "EXPLAIN DELETE FROM {q}",
        "EXPLAIN INSERT INTO {q} VALUES (1)",
        "EXPLAIN UPDATE {q} SET a = 1",
    ],
)
def test_f87_explain_analyze_and_hidden_writes_are_refused(engine: str, template: str) -> None:
    schema, table, _ = _F87_OBJECTS[engine]
    q = f"{schema}.{table}" if schema else table
    _assert_policy_denied(_f87_guard(engine).validate_explain, template.format(q=q))


@pytest.mark.parametrize(
    "engine,sql,category",
    [
        ("mysql", "SHOW GRANTS", ErrorCategory.POLICY),
        ("mysql", "SHOW PROCESSLIST", ErrorCategory.POLICY),
        ("clickhouse", "SHOW GRANTS", ErrorCategory.POLICY),
        ("clickhouse", "SHOW PROCESSLIST", ErrorCategory.POLICY),
        ("postgres", "SHOW ALL", ErrorCategory.POLICY),
        ("sqlite", "SHOW TABLES", ErrorCategory.CAPABILITY),
        ("oracle", "SHOW TABLES", ErrorCategory.CAPABILITY),
        ("mssql", "SHOW TABLES", ErrorCategory.CAPABILITY),
    ],
)
def test_f87_show_allowlist_refusals(engine: str, sql: str, category: ErrorCategory) -> None:
    with pytest.raises(ToolFailure) as info:
        _f87_guard(engine).validate_any(sql)
    assert info.value.category == category, str(info.value)


# ---- Review round 2: the server skips exactly the text sqlglot skipped ------

# Observed live on every loopback fixture: a bare CR ends a -- comment for
# sqlglot, PostgreSQL and SQL Server, while MySQL, Oracle, Db2, SQLite and
# ClickHouse read on to the next LF ('SELECT 1 AS a -- x\r, 2 AS b\n' returns
# one column there). MySQL/MariaDB start a -- comment only when whitespace or
# a control character follows ('SELECT 1 --1' returns 2). sqlglot reads both
# as comments, so the text behind them was never validated.

_R2_OBJECTS = {engine: ("app.t", "hr.s") for engine in ENGINES if engine != "sqlite"} | {"sqlite": ("t", "s")}


def _r2_guard(engine: str) -> SqlGuard:
    """app.t is readable; hr.s (s on SQLite) is refused whenever the guard sees it."""
    if engine == "sqlite":
        return _guard("sqlite", StaticResolver({("main", "t")}))
    return SqlGuard(engine, _policy(engine, allowed_schemas=["app"]), StaticResolver({("app", "t"), ("hr", "s")}))


def _r2_both_entries_refused(engine: str, sql: str) -> list[ToolFailure]:
    guard = _r2_guard(engine)
    return [
        _assert_policy_denied(guard.validate_select, sql),
        _assert_policy_denied(guard.validate_explain, "EXPLAIN " + sql),
    ]


_R2_LINE_OPENERS = [(engine, "--") for engine in ENGINES] + [("mysql", "#"), ("clickhouse", "#")]


@pytest.mark.parametrize("engine,opener", _R2_LINE_OPENERS)
def test_r2_bare_cr_line_comment_cannot_hide_a_union(engine: str, opener: str) -> None:
    t, s = _R2_OBJECTS[engine]
    # sqlglot: SELECT id FROM t '<string>' ; the engine: a comment, then a UNION reading s
    sql = f"SELECT id FROM {t} {opener} x\r'\nUNION SELECT secret FROM {s} -- '"
    for exc in _r2_both_entries_refused(engine, sql):
        assert "carriage return" in str(exc)
    # the same UNION in plain sight is refused as well (the hidden form is not a new read path)
    with pytest.raises(ToolFailure):
        _r2_guard(engine).validate_select(f"SELECT id FROM {t} UNION SELECT secret FROM {s}")


@pytest.mark.parametrize("engine,opener", _R2_LINE_OPENERS)
def test_r2_bare_cr_line_comment_before_code_is_refused(engine: str, opener: str) -> None:
    t, _ = _R2_OBJECTS[engine]
    _r2_both_entries_refused(engine, f"SELECT id {opener} note\rFROM {t}")
    _r2_both_entries_refused(engine, f"{opener} lead\rSELECT id FROM {t}")


@pytest.mark.parametrize("engine,opener", _R2_LINE_OPENERS)
@pytest.mark.parametrize(
    "template",
    [
        "SELECT id FROM {t} {o} note\r\nWHERE id = 1",
        "SELECT id {o} note\r\nFROM {t}",
        "{o} lead\r\nSELECT id FROM {t}",
        "{o} lead\nSELECT id FROM {t}",
        "SELECT id FROM {t} {o} trailing",
        "SELECT id FROM {t} {o} trailing\r\n",
        "SELECT id FROM {t} {o} a\r {o} b\nWHERE id = 1",
        "SELECT id FROM {t} {o} it's\nWHERE id = 1",
        "/* a -- b */ SELECT id FROM {t}",
        "SELECT id /* x\r y */ FROM {t}",
    ],
)
def test_r2_ordinary_line_comments_still_allowed(engine: str, opener: str, template: str) -> None:
    t, _ = _R2_OBJECTS[engine]
    sql = template.format(t=t, o=opener)
    guard = _r2_guard(engine)
    assert guard.validate_select(sql).kind == "select"
    assert guard.validate_explain("EXPLAIN " + sql).kind == "explain"


@pytest.mark.parametrize("sep", _TSQL_HIDDEN_SEPARATORS, ids=lambda s: f"U+{ord(s):04X}")
@pytest.mark.parametrize("tail", ["COMMIT", "DELETE FROM dbo.t", "SHUTDOWN"])
def test_r2_tsql_cr_ended_comment_hides_no_separator(sep: str, tail: str) -> None:
    """SQL Server compiles 'SELECT 1 -- note\\r\\x10COMMIT' to a SELECT and a
    COMMIT (SHOWPLAN, live): its -- comment ends at the CR, as sqlglot's does."""
    for sql in (f"SELECT 1 -- note\r{sep}{tail}", f"SELECT 1 FROM dbo.t -- note\r{sep}{tail}"):
        _assert_policy_denied(_mssql_guard().validate_select, sql)
        _assert_policy_denied(_mssql_guard().validate_explain, "EXPLAIN " + sql)
    # after CRLF the separator is code on every reading and names its code point
    exc = _assert_policy_denied(_mssql_guard().validate_select, f"SELECT 1 -- note\r\n{sep}{tail}")
    assert f"U+{ord(sep):04X}" in str(exc)


_R2_MYSQL_DASHDASH_DENIED = [
    "SELECT id FROM app.t WHERE id = 1 --1 UNION SELECT secret FROM hr.s\n",
    "SELECT id FROM app.t WHERE id = 1 --1 OR 1=1\n",
    "SELECT 1 --1\n",
    "SELECT 1 --1",
    "SELECT id FROM app.t --x\n",
    "SELECT 1 --'\nUNION SELECT secret FROM hr.s -- '",
    "SELECT 1 -- x\n",
    "--x\nSELECT id FROM app.t",
]


@pytest.mark.parametrize("sql", _R2_MYSQL_DASHDASH_DENIED)
def test_r2_mysql_dash_dash_without_whitespace_is_refused(sql: str) -> None:
    for exc in _r2_both_entries_refused("mysql", sql):
        assert "'--'" in str(exc)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM app.t -- note",
        "SELECT id FROM app.t --\tnote\n",
        "SELECT id FROM app.t --\nWHERE id = 1",
        "SELECT id FROM app.t --",
        "SELECT id FROM app.t --\x01note\n",
        "SELECT '--1' AS s FROM app.t",
        "SELECT 1 AS `a--1` FROM app.t",
        "SELECT id FROM app.t /* --1 */",
        "SELECT id FROM app.t # --1\n",
        "SELECT id - -1 FROM app.t",
    ],
)
def test_r2_mysql_spaced_dash_dash_and_quoted_dashes_still_allowed(sql: str) -> None:
    guard = _r2_guard("mysql")
    assert guard.validate_select(sql).kind == "select"
    assert guard.validate_explain("EXPLAIN " + sql).kind == "explain"


@pytest.mark.parametrize("engine", [e for e in ENGINES if e != "mysql"])
def test_r2_other_engines_read_dash_dash_as_a_comment(engine: str) -> None:
    # PostgreSQL, Oracle, Db2, SQLite, ClickHouse and SQL Server end '--1' as a comment (live)
    t, _ = _R2_OBJECTS[engine]
    assert _r2_guard(engine).validate_select(f"SELECT id FROM {t} --1\n").kind == "select"


@pytest.mark.parametrize("engine", ENGINES)
def test_r2_nested_block_comment_is_refused(engine: str) -> None:
    t, s = _R2_OBJECTS[engine]
    # nesting engines (PostgreSQL, Db2, SQL Server, ClickHouse) read one comment;
    # the others end it at the first */ -- whichever reading, the UNION is refused
    sql = f"SELECT id FROM {t} /* /* */ UNION SELECT secret FROM {s} -- */"
    guard = _r2_guard(engine)
    for validate, text in ((guard.validate_select, sql), (guard.validate_explain, "EXPLAIN " + sql)):
        with pytest.raises(ToolFailure) as info:
            validate(text)
        assert info.value.category in (ErrorCategory.AUTHZ, ErrorCategory.POLICY), str(info.value)
    _r2_both_entries_refused(engine, f"SELECT id FROM {t} /* a /* b */ c */")


def test_r2_mysql_hash_comment_hides_set_statement_words_only() -> None:
    guard = _mysql_guard()
    assert guard.validate_select("SELECT id FROM customers # SET STATEMENT max_statement_time=0 FOR\n").kind == "select"
    exc = _assert_policy_denied(guard.validate_select, "SET STATEMENT max_statement_time=0 FOR SELECT 1 # x\n")
    assert "SET STATEMENT" in str(exc)


def test_r2_separator_pattern_is_written_with_escapes() -> None:
    from pathlib import Path

    source = Path(sql_guard.__file__).read_text(encoding="utf-8")
    assert "\u200b" not in source and "\ufeff" not in source
    for ch in ("\u200b", "\ufeff", "\x10", "\x1f"):
        assert sql_guard._TSQL_HIDDEN_SEPARATOR.search(ch), repr(ch)
    for ch in ("\t", "\n", "\r", " "):
        assert not sql_guard._TSQL_HIDDEN_SEPARATOR.search(ch), repr(ch)


# ---- Review round 2: F25 with default-deny off and no allowlist -------------


def test_r2_f25_unqualified_dictionary_name_refused_without_an_allowlist() -> None:
    guard = _nodeny_guard("oracle", [], {("sys", "all_users"), ("travel", "bookings")})
    _assert_authz_denied(guard.validate_select, "SELECT username FROM ALL_USERS")
    _assert_authz_denied(guard.validate_explain, "EXPLAIN SELECT username FROM ALL_USERS")
    _assert_authz_denied(guard.validate_select, "SELECT username FROM SYS.ALL_USERS")
    assert guard.validate_select("SELECT * FROM bookings").kind == "select"
    # default-deny is off: a name the catalog does not know still passes
    assert guard.validate_select("SELECT * FROM unknown_table").kind == "select"

    pg = _nodeny_guard("postgres", [], {("pg_catalog", "pg_roles"), ("public", "t")})
    _assert_authz_denied(pg.validate_select, "SELECT rolname FROM pg_roles")
    _assert_authz_denied(pg.validate_select, "SELECT 1 FROM public.t WHERE 1 IN (SELECT 1 FROM pg_roles)")


def test_r2_f25_allowed_system_schema_opens_the_unqualified_name() -> None:
    policy = _policy("oracle", SecurityConfig(default_deny_objects=False, allowed_system_schemas=["sys"]))
    guard = SqlGuard("oracle", policy, StaticResolver({("sys", "all_users")}))
    assert guard.validate_select("SELECT username FROM ALL_USERS").kind == "select"


def test_r2_f25_without_an_allowlist_user_names_keep_the_old_behaviour() -> None:
    # a bare name in two user schemas is not ambiguous-refused when nothing restricts schemas
    guard = _nodeny_guard("postgres", [], {("sales", "t"), ("archive", "t")})
    assert guard.validate_select("SELECT * FROM t").kind == "select"
    # no resolver: nothing can place the bare name, so it passes (documented limitation)
    assert _nodeny_guard("postgres", [], None).validate_select("SELECT rolname FROM pg_roles").kind == "select"


def test_r2_f25_pdbadmin_is_a_user_schema_but_discovery_still_skips_it() -> None:
    from universal_db_mcp.discovery.system_schemas import is_system_object

    policy = _policy("oracle")
    assert not policy.is_system_schema("PDBADMIN")
    policy.check_object("PDBADMIN", "T")
    guard = _guard("oracle", StaticResolver({("pdbadmin", "t")}))
    assert guard.validate_select("SELECT * FROM PDBADMIN.T").kind == "select"
    assert is_system_object("oracle", "PDBADMIN", "t")
    # the Oracle-maintained owners stay closed
    _assert_authz_denied(policy.check_object, "SYS", "T")
    _assert_authz_denied(policy.check_object, "FLOWS_FILES", "WWV_FLOW_FILE_OBJECTS$")
