"""Gate C: isolated internal-database integration tests.

Each engine's tests are env-gated: when a fixture endpoint is provided, the
tests run against the REAL driver; when absent they are skipped with an
explicit 'blocked' reason so IMPLEMENTATION_STATUS.md can record them as
not_run rather than passing vacuously.

Fixtures must be internal endpoints with no public route (the orchestrator
script stands up containerized engines on a Docker --internal network and
publishes only to host loopback).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent.parent / "src"
sys.path.insert(0, str(SRC))

from universal_db_mcp.config import (  # noqa: E402
    ConnectionConfig,
    ResolvedConnection,
    SecurityConfig,  # noqa: E402
)
from universal_db_mcp.connectors import registry  # noqa: E402
from universal_db_mcp.connectors.base import QuerySpec  # noqa: E402
from universal_db_mcp.security.policy import EffectivePolicy  # noqa: E402

POLICY_SECURITY = SecurityConfig()


def make_policy(conn: ResolvedConnection) -> EffectivePolicy:
    return EffectivePolicy.build(POLICY_SECURITY, conn)


def conn_from_env(name: str, **cfg: object) -> ResolvedConnection | None:
    host = os.environ.get(f"UDBMCP_TEST_{name.upper()}_HOST")
    if not host:
        return None
    base: dict[str, object] = {
        "type": name,
        "host": host,
        "database": os.environ.get(f"UDBMCP_TEST_{name.upper()}_DB", "test"),
    }
    base.update(cfg)
    user = os.environ.get(f"UDBMCP_TEST_{name.upper()}_USER", "udbmcp_ro")
    pw = os.environ.get(f"UDBMCP_TEST_{name.upper()}_PASSWORD", "udbmcp_ro_pw")
    os.environ[f"UDBMCP_TEST_{name.upper()}_USER_ENV"] = user
    base["username_env"] = f"UDBMCP_TEST_{name.upper()}_USER_ENV"
    import tempfile
    from pathlib import Path as P

    if pw:  # engines like ClickHouse may allow an empty password
        pwf = P(tempfile.mkstemp(suffix=".pw")[1])
        pwf.write_text(pw)
        pwf.chmod(0o600)
        base["password_file"] = str(pwf)
    return ResolvedConnection(f"test_{name}", ConnectionConfig.model_validate(base))


BLOCK_REASON = "fixture endpoint not provided (set UDBMCP_TEST_*_HOST); integration not run"


def block_reason(name: str) -> str:
    """The recorded skip reason must state the TRUE cause of a block.

    The Gate C orchestrator exports UDBMCP_TEST_<NAME>_BLOCKED when it stood
    the fixture up but could not hand it to the client (e.g. the pinned
    ibm_db clidriver fails its auth probe under emulation, or the themed
    seed failed) — in those cases the endpoint env is deliberately withheld
    and a generic 'endpoint not provided' message would misattribute the
    block in the evidence log."""
    blocked = os.environ.get(f"UDBMCP_TEST_{name.upper()}_BLOCKED")
    if blocked:
        return f"blocked: {blocked}"
    return BLOCK_REASON


# --------------------------------------------------------------------- postgres


@pytest.fixture()
def postgres_conn() -> object:
    c = conn_from_env("postgres", port=int(os.environ.get("UDBMCP_TEST_POSTGRES_PORT", "5432")))
    if c is None:
        pytest.skip(block_reason("postgres"))
    return c


@pytest.mark.integration
def test_postgres_roundtrip(postgres_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(postgres_conn, make_policy(postgres_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1::int", max_rows=5))
    assert out.rows == [[1]]
    schemas = connector.list_schemas(None, None)
    assert "public" in schemas


@pytest.mark.integration
def test_postgres_db_side_permission_denial(postgres_conn) -> None:  # type: ignore[no-untyped-def]
    """Spec 14-E: prove the DATABASE refuses what the parser would refuse
    anyway — the read-only role lacks grants on a locked-down table."""
    from universal_db_mcp.connectors.base import ConnectorError

    connector = registry.build_connector(postgres_conn, make_policy(postgres_conn))  # type: ignore[arg-type]
    # reporting.secret exists (fixture creates it) but udbmcp_ro has no SELECT
    # grant; object allowlists are bypassed deliberately here to reach the DB.
    with pytest.raises(ConnectorError) as exc:
        connector.execute_query(QuerySpec(sql="SELECT * FROM reporting.secret", max_rows=5))
    assert "permission" in str(exc.value).lower() or "denied" in str(exc.value).lower()


# ------------------------------------------------------------------------ mysql


@pytest.fixture()
def mysql_conn() -> object:
    c = conn_from_env("mysql", port=int(os.environ.get("UDBMCP_TEST_MYSQL_PORT", "3306")))
    if c is None:
        pytest.skip(block_reason("mysql"))
    return c


@pytest.mark.integration
def test_mysql_roundtrip(mysql_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(mysql_conn, make_policy(mysql_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1", max_rows=5))
    assert out.rows == [[1]]


@pytest.mark.integration
def test_mysql_never_lists_the_views_of_other_sessions_statements(mysql_conn) -> None:  # type: ignore[no-untyped-def]
    """information_schema is open by default, and its PROCESSLIST shows the
    statement every session of the shared account is running (INNODB_TRX's
    trx_query likewise, with PROCESS): never listed, so never resolved. Nor
    are INNODB_FT_INDEX_CACHE and _TABLE, the indexed words of whichever
    table innodb_ft_aux_table names."""
    connector = registry.build_connector(mysql_conn, make_policy(mysql_conn))  # type: ignore[arg-type]
    listed = {(t.schema.lower(), t.name.lower()) for t in connector.list_tables(None, {"table", "view"}, None)}
    assert ("information_schema", "tables") in listed and ("information_schema", "innodb_ft_config") in listed
    never = {"processlist", "innodb_trx", "innodb_ft_index_cache", "innodb_ft_index_table"}
    assert not {("information_schema", n) for n in never} & listed


def _after_the_databases_own(schemas: list[str | None], system: set[str]) -> bool:
    """Every entry of a ``system`` schema follows every other entry."""
    flags = [s in system for s in schemas]
    return any(flags) and flags == sorted(flags)


# ------------------------------------------------------------------- clickhouse


@pytest.fixture()
def clickhouse_conn() -> object:
    c = conn_from_env("clickhouse", port=int(os.environ.get("UDBMCP_TEST_CLICKHOUSE_PORT", "8123")))
    if c is None:
        pytest.skip(block_reason("clickhouse"))
    return c


@pytest.mark.integration
def test_clickhouse_roundtrip(clickhouse_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(clickhouse_conn, make_policy(clickhouse_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1", max_rows=5))
    assert out.rows == [[1]]


# ----------------------------------------------------------------------- oracle


@pytest.fixture()
def oracle_conn() -> object:
    c = conn_from_env("oracle", port=int(os.environ.get("UDBMCP_TEST_ORACLE_PORT", "1521")))
    if c is None:
        pytest.skip(block_reason("oracle"))
    return c


@pytest.mark.integration
def test_oracle_roundtrip(oracle_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(oracle_conn, make_policy(oracle_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1 FROM dual", max_rows=5))
    assert out.rows == [[1]]


@pytest.mark.integration
def test_oracle_lists_an_opened_dictionary_after_the_databases_own(oracle_conn) -> None:  # type: ignore[no-untyped-def]
    """With SYS opened, its ~2000 objects sorted before the account's own, so
    db_list_tables' first pages held no user table."""
    policy = EffectivePolicy.build(SecurityConfig(allowed_system_schemas=["information_schema", "sys"]), oracle_conn)
    connector = registry.build_connector(oracle_conn, policy)  # type: ignore[arg-type]
    listed = connector.list_tables(None, {"table", "view"}, None)
    assert _after_the_databases_own([t.schema for t in listed], {"SYS"}), [t.schema for t in listed[:5]]


@pytest.mark.integration
def test_oracle_asks_the_session_what_a_bare_dual_names(oracle_conn) -> None:  # type: ignore[no-untyped-def]
    """The guard lets every statement read a bare DUAL as SYS.DUAL; a DUAL of
    the login schema's own would be read in its place. The connector asks
    the session that runs the statement (none here, so the dummy table
    answers), and the question itself is valid SQL on the server."""
    from universal_db_mcp.connectors import oracle as oracle_module

    connector = registry.build_connector(oracle_conn, make_policy(oracle_conn))  # type: ignore[arg-type]
    out = connector.execute_query(QuerySpec(sql="SELECT dummy FROM DUAL", max_rows=5))
    assert out.rows == [["X"]]
    raw = connector._connect()  # type: ignore[attr-defined]
    try:
        with raw.cursor() as cur:
            cur.execute(oracle_module._SHADOWED_DUAL)
            schema, login, owned = cur.fetchone()
    finally:
        raw.close()
    assert schema == login and owned == 0, (schema, login, owned)


# ------------------------------------------------------------------------ mssql


@pytest.fixture()
def mssql_conn() -> object:
    c = conn_from_env("mssql", port=int(os.environ.get("UDBMCP_TEST_MSSQL_PORT", "1433")))
    if c is None:
        pytest.skip(block_reason("mssql"))
    return c


@pytest.mark.integration
def test_mssql_roundtrip(mssql_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(mssql_conn, make_policy(mssql_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1", max_rows=5))
    assert out.rows == [[1]]


@pytest.mark.integration
def test_mssql_lists_the_allowed_information_schema(mssql_conn) -> None:  # type: ignore[no-untyped-def]
    """information_schema.tables never lists the INFORMATION_SCHEMA views;
    allowed by default (security.allowed_system_schemas), they are listed
    from the catalog so the resolver permits them. sys stays hidden."""
    _skip_if_driver_missing("mssql")
    connector = registry.build_connector(mssql_conn, make_policy(mssql_conn))  # type: ignore[arg-type]
    listed = {(t.schema, t.name.upper()) for t in connector.list_tables(None, {"table", "view"}, None)}
    assert ("INFORMATION_SCHEMA", "TABLES") in listed
    assert not [s for s, _n in listed if s == "sys"]


# -------------------------------------------------------------------------- db2


@pytest.fixture()
def db2_conn() -> object:
    c = conn_from_env("db2", port=int(os.environ.get("UDBMCP_TEST_DB2_PORT", "50000")))
    if c is None:
        pytest.skip(block_reason("db2"))
    return c


@pytest.mark.integration
def test_db2_roundtrip(db2_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(db2_conn, make_policy(db2_conn))  # type: ignore[arg-type]
    health = connector.health_check()
    assert health.healthy, health.detail
    out = connector.execute_query(QuerySpec(sql="SELECT 1 FROM SYSIBM.SYSDUMMY1", max_rows=5))
    assert out.rows == [[1]]


@pytest.mark.integration
def test_db2_lists_an_opened_system_schema_after_the_databases_own(db2_conn) -> None:  # type: ignore[no-untyped-def]
    policy = EffectivePolicy.build(SecurityConfig(allowed_system_schemas=["sysibm", "syscat"]), db2_conn)
    connector = registry.build_connector(db2_conn, policy)  # type: ignore[arg-type]
    listed = connector.list_tables(None, {"table", "view"}, None)
    assert _after_the_databases_own([t.schema for t in listed], {"SYSIBM", "SYSCAT"}), [t.schema for t in listed[:5]]


# ------------------------------------------------- themed fixture data (Gate C round 2)
# Each engine carries DISTINCT mock data so a cross-engine result swap is
# impossible to miss: postgres=oceanographic buoys, mysql=coffee roastery,
# clickhouse=telecom call data records, oracle=air travellers,
# mssql=hospital clinical records, db2=ministry of interior civil registry.


def _skip_if_driver_missing(engine: str) -> None:
    """Skip honestly when the client image lacks the driver stack."""
    import importlib

    if engine == "oracle":
        try:
            importlib.import_module("oracledb")
        except ImportError:
            pytest.skip("oracledb wheel not present in test client image")
    elif engine == "mssql":
        try:
            pyodbc = importlib.import_module("pyodbc")
        except ImportError:
            pytest.skip("pyodbc wheel not present in test client image")
        if not any("ODBC Driver 18" in d for d in pyodbc.drivers()):
            pytest.skip("msodbcsql18 not installed in test client image")
    elif engine == "db2":
        try:
            importlib.import_module("ibm_db")
        except ImportError:
            pytest.skip("ibm_db wheel not present in test client image")


@pytest.mark.integration
def test_postgres_ocean_buoy_data(postgres_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(postgres_conn, make_policy(postgres_conn))  # type: ignore[arg-type]
    out = connector.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM ocean.readings", max_rows=5))
    assert out.rows == [[60]]
    names = connector.execute_query(
        QuerySpec(sql="SELECT callsign FROM ocean.buoys WHERE region = 'Red Sea'", max_rows=5))
    assert names.rows == [["MB-CHARLIE"]]


@pytest.mark.integration
def test_mysql_roastery_data(mysql_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(mysql_conn, make_policy(mysql_conn))  # type: ignore[arg-type]
    out = connector.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM roastery_batches", max_rows=5))
    assert out.rows == [[5]]
    light = connector.execute_query(
        QuerySpec(sql="SELECT COUNT(*) FROM roastery_batches WHERE roast_level = 'light'", max_rows=5))
    assert light.rows == [[2]]


@pytest.mark.integration
def test_postgres_capped_null_record_and_json_stay_null(postgres_conn) -> None:  # type: ignore[no-untyped-def]
    """Review round 4: the value cap turned a NULL anonymous record into a
    one-field row ('[]'); NULL json and jsonb must stay NULL too."""
    connector = registry.build_connector(postgres_conn, make_policy(postgres_conn))  # type: ignore[arg-type]
    out = connector.execute_query(QuerySpec(
        sql="SELECT CASE WHEN n = 1 THEN (1, 'a') END AS r, CASE WHEN n = 1 THEN '{\"k\": 1}'::jsonb END AS jb, "
        "CASE WHEN n = 1 THEN '\"x\"'::json END AS j, n FROM (VALUES (1), (2)) AS v(n) ORDER BY n",
        max_rows=5,
    ))
    assert out.rows[1] == [None, None, None, 2], out.rows
    assert out.rows[0][2] == "x" and out.rows[0][3] == 1


@pytest.mark.integration
def test_clickhouse_values_that_decode_past_the_budget_are_refused(clickhouse_conn) -> None:  # type: ignore[no-untyped-def]
    """Review round 4: 7.9M empty strings (8 MB on the wire, within the
    stream budget) grew the server by 190 MB; they are refused before the
    driver builds them."""
    from universal_db_mcp.connectors.base import ConnectorError

    connector = registry.build_connector(clickhouse_conn, make_policy(clickhouse_conn))  # type: ignore[arg-type]
    sql = (
        "SELECT arrayMap(o -> arrayMap(x -> x, splitByChar(',', repeat(',', 987499))), "
        "splitByChar(',', repeat(',', 7))) AS a"
    )
    with pytest.raises(ConnectorError) as exc:
        connector.execute_query(QuerySpec(sql=sql, max_rows=1))
    assert exc.value.category == "LIMIT_EXCEEDED" and "decodes to more than" in str(exc.value)


@pytest.mark.integration
def test_clickhouse_lists_the_allowed_information_schema(clickhouse_conn) -> None:  # type: ignore[no-untyped-def]
    """security.allowed_system_schemas defaults to [information_schema]: the
    resolver permits only listed objects, so the listing must carry it."""
    connector = registry.build_connector(clickhouse_conn, make_policy(clickhouse_conn))  # type: ignore[arg-type]
    listed = connector.list_tables(None, {"table", "view"}, None)
    assert {"information_schema", "INFORMATION_SCHEMA"} <= {t.schema for t in listed}
    assert "system" not in {t.schema for t in listed}


@pytest.mark.integration
def test_clickhouse_cdr_data(clickhouse_conn) -> None:  # type: ignore[no-untyped-def]
    connector = registry.build_connector(clickhouse_conn, make_policy(clickhouse_conn))  # type: ignore[arg-type]
    out = connector.execute_query(QuerySpec(sql="SELECT count() FROM telecom.cdr", max_rows=5))
    assert out.rows == [[250000]]
    shortest = connector.execute_query(QuerySpec(sql="SELECT min(duration_sec) FROM telecom.cdr", max_rows=5))
    assert shortest.rows == [[5]]


@pytest.mark.integration
def test_oracle_travellers_data(oracle_conn) -> None:  # type: ignore[no-untyped-def]
    _skip_if_driver_missing("oracle")
    connector = registry.build_connector(oracle_conn, make_policy(oracle_conn))  # type: ignore[arg-type]
    assert connector.health_check().healthy
    out = connector.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM bookings", max_rows=5))
    assert out.rows == [[18]]
    first_class = connector.execute_query(
        QuerySpec(
            sql=(
                "SELECT f.flight_no FROM bookings b JOIN travellers t ON t.traveller_id = b.traveller_id "
                "JOIN flights f ON f.flight_id = b.flight_id WHERE b.cabin_class = 'first'"
            ),
            max_rows=5,
        )
    )
    assert first_class.rows == [["EK202"]]


@pytest.mark.integration
def test_mssql_hospital_data(mssql_conn) -> None:  # type: ignore[no-untyped-def]
    _skip_if_driver_missing("mssql")
    connector = registry.build_connector(mssql_conn, make_policy(mssql_conn))  # type: ignore[arg-type]
    assert connector.health_check().healthy
    out = connector.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM dbo.Admissions", max_rows=5))
    assert out.rows == [[6]]
    neo = connector.execute_query(
        QuerySpec(
            sql=(
                "SELECT p.FullName, d.Name FROM dbo.Admissions a "
                "JOIN dbo.Patients p ON p.PatientId = a.PatientId "
                "JOIN dbo.Departments d ON d.DepartmentId = a.DepartmentId "
                "WHERE a.AdmissionId = 3"
            ),
            max_rows=5,
        )
    )
    assert neo.rows == [["Rosa Delgado", "Neonatology"]]


@pytest.mark.integration
def test_db2_moi_data(db2_conn) -> None:  # type: ignore[no-untyped-def]
    _skip_if_driver_missing("db2")
    connector = registry.build_connector(db2_conn, make_policy(db2_conn))  # type: ignore[arg-type]
    assert connector.health_check().healthy
    out = connector.execute_query(QuerySpec(sql="SELECT COUNT(*) FROM MOI.CITIZENS", max_rows=5))
    assert out.rows == [[6]]
    plate = connector.execute_query(
        QuerySpec(
            sql="SELECT PLATE FROM MOI.VEHICLE_REGISTRATIONS WHERE CITIZEN_ID = 6",
            max_rows=5,
        )
    )
    assert plate.rows == [["D 90934"]]
