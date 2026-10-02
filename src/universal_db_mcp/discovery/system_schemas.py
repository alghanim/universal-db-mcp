"""Engine catalogs and system schemas that discovery skips by default.

Value search and relationship inference walk every permitted table; without
this list they spend their budget on SYSIBM, pg_catalog or CTXSYS and report
"relationships" between catalog views. The same list, less
DISCOVERY_ONLY_SCHEMAS, is the policy's notion of a system schema: one is
readable only when security.allowed_system_schemas (or the connection's
allowed_schemas) names it.
"""

from __future__ import annotations

import re
import unicodedata

SYSTEM_SCHEMAS: dict[str, frozenset[str]] = {
    "postgres": frozenset({"pg_catalog", "information_schema", "pg_toast"}),
    "mysql": frozenset({"mysql", "sys", "performance_schema", "information_schema"}),
    "mssql": frozenset({"sys", "information_schema", "guest", "db_owner", "db_accessadmin",
                        "db_securityadmin", "db_ddladmin", "db_backupoperator", "db_datareader",
                        "db_datawriter", "db_denydatareader", "db_denydatawriter"}),
    # Oracle-maintained users (ALL_USERS.ORACLE_MAINTAINED = 'Y') through 23ai,
    # plus the 9i/10g/11g owners from before that flag existed (the 9i JServer
    # and trace owners survive an upgrade to 11.2).
    "oracle": frozenset({"sys", "system", "ctxsys", "mdsys", "xdb", "outln", "dbsnmp", "appqossys",
                         "ordsys", "orddata", "ordplugins", "wmsys", "olapsys", "lbacsys", "dvsys",
                         "audsys", "gsmadmin_internal", "ojvmsys", "dbsfwuser", "ggsys", "remote_scheduler_agent",
                         "sysbackup", "sysdg", "syskm", "sysrac", "sys$umf", "dip", "anonymous", "xs$null",
                         "apex_public_user", "flows_files", "pdbadmin",
                         "vecsys", "baassys", "dgpdb_int", "dvf", "ggsharedcap", "gsmcatuser", "gsmuser",
                         "gsmrootuser", "mddata", "oracle_ocm", "si_informtn_schema",
                         "exfsys", "sysman", "mgmt_view", "owbsys", "owbsys_audit", "spatial_csw_admin_usr",
                         "spatial_wfs_admin_usr", "apex_030200", "apex_040000", "apex_040200",
                         "wksys", "wk_test", "wkproxy", "dmsys", "tsmsys", "flows_030000", "apex_050000",
                         "odm", "odm_mtr", "mtssys",
                         "aurora$jis$utility$", "aurora$orb$unauthenticated", "ose$http$admin", "tracesvr",
                         "apex_listener", "apex_rest_public_user", "apex_instance_admin_user",
                         "htmldb_public_user"}),
    # every schema SYSCAT.SCHEMATA reports with owner SYSIBM on a fresh database
    "db2": frozenset({"sysibm", "syscat", "sysstat", "sysproc", "sysibmadm", "sysfun", "systools",
                      "nullid", "sqlj", "syspublic", "sysibminternal", "sysibmts"}),
    "clickhouse": frozenset({"system", "information_schema"}),
    "sqlite": frozenset(),
}

# Skipped by discovery but not engine-maintained, so the policy does not treat
# them as system schemas: DBCA and the Free/XE images create PDBADMIN as the
# PDB's local administrator, and sites keep application tables there.
DISCOVERY_ONLY_SCHEMAS: dict[str, frozenset[str]] = {
    "oracle": frozenset({"pdbadmin"}),
}

# Owners a release names after itself, so no list can hold them all: Oracle
# APEX installs one per version (FLOWS_030000 before 3.2, APEX_050000 since).
# The common versions stay in SYSTEM_SCHEMAS as well, for the Oracle
# connector's pre-12c catalog filter, which binds that list.
SYSTEM_SCHEMA_PATTERNS: dict[str, re.Pattern[str]] = {
    "oracle": re.compile(r"(?:apex|flows)_[0-9]{6}"),
}

SYSTEM_TABLE_PREFIXES: dict[str, tuple[str, ...]] = {
    "sqlite": ("sqlite_",),
    "oracle": ("dr$", "sys_", "bin$", "mlog$", "rupd$"),
    "postgres": ("pg_",),
}


def loose_name(name: str) -> str:
    """``name`` folded further than any engine compares names, for the lists
    that refuse or hide an object: compatibility forms decomposed (full-width
    letters, ligatures, ſ), accents and other marks dropped, case folded
    through upper case (ı is I), surrounding blanks stripped. Engines read
    such spellings as the listed name (live, 2026-09-28): MySQL finds
    information_schema.PROCESSLIST as proceſſlist, processlıst and
    PROCESSLİST; SQL Server finds sys.syscacheobjects as sys.ｓｙｓcacheobjects
    and sys.[syscacheobjects ]; Db2 drops a delimited name's trailing blanks;
    Oracle reads an unquoted v$ſql as V$SQL. A list matched on this refuses
    more spellings than an engine reads, never fewer. SQL Server's collations
    fold more than this, which is why the guard admits only printable ASCII
    names there."""
    decomposed = unicodedata.normalize("NFKD", name)
    unmarked = "".join(ch for ch in decomposed if not unicodedata.category(ch).startswith("M"))
    return unmarked.upper().lower().strip()


def is_listed_system_schema(engine: str, schema: str) -> bool:
    """``schema`` (in any spelling loose_name folds to one) is in
    SYSTEM_SCHEMAS or matches the engine's SYSTEM_SCHEMA_PATTERNS."""
    folded = loose_name(schema)
    if folded in SYSTEM_SCHEMAS.get(engine, frozenset()):
        return True
    pattern = SYSTEM_SCHEMA_PATTERNS.get(engine)
    return pattern is not None and pattern.fullmatch(folded) is not None


# Dictionary tables that hold no data, readable on every connection whatever
# the allowlists open (owner decision 2026-09-28): Oracle's SYS.DUAL, which a
# bare DUAL names through its PUBLIC synonym, and Db2's SYSIBM.SYSDUMMY1-4 (a
# bare SYSDUMMY1 is CURRENT SCHEMA's). Nothing else of SYS or SYSIBM opens.
# (schema, name) exactly as the engine looks them up, None for a bare name.
DATA_FREE_TABLES: dict[str, frozenset[tuple[str | None, str]]] = {
    "oracle": frozenset({(None, "DUAL"), ("SYS", "DUAL")}),
    "db2": frozenset({("SYSIBM", f"SYSDUMMY{n}") for n in range(1, 5)}),
}


def is_data_free_table(engine: str, schema: str | None, name: str) -> bool:
    """``schema.name`` is one of the engine's DATA_FREE_TABLES, compared
    exactly: a quoted "sys"."dual" is another object."""
    return (schema, name) in DATA_FREE_TABLES.get(engine, frozenset())


# SQL Server's compatibility views, which it binds under dbo and bare as
# well as under sys, ahead of any other object of the name: dbo.syslogins
# returned the server's logins with no synonym or allowlist entry for sys,
# and after CREATE TABLE dbo.sysusers, FROM dbo.sysusers still read the view
# (live, SQL Server 2022: every view and table of sys that OBJECT_ID finds
# as dbo.<name>; guest.<name> finds none).
_MSSQL_COMPATIBILITY_VIEWS = frozenset({
    "sysaltfiles", "syscacheobjects", "syscharsets", "syscolumns", "syscomments", "sysconfigures",
    "sysconstraints", "syscurconfigs", "syscursorcolumns", "syscursorrefs", "syscursors", "syscursortables",
    "sysdatabases", "sysdepends", "sysdevices", "sysfilegroups", "sysfiles", "sysforeignkeys",
    "sysfulltextcatalogs", "sysindexes", "sysindexkeys", "syslanguages", "syslockinfo", "syslogins",
    "sysmembers", "sysmessages", "sysobjects", "sysoledbusers", "sysopentapes", "sysperfinfo", "syspermissions",
    "sysprocesses", "sysprotects", "sysreferences", "sysremotelogins", "sysservers", "systypes", "sysusers",
})


def dictionary_binding(engine: str, schema: str | None, name: str) -> tuple[str, str] | None:
    """The dictionary object the engine reads for ``schema.name`` (or a bare
    ``name``) whatever else the catalog holds under it, compared as
    loose_name folds names: SQL Server's compatibility views
    (_MSSQL_COMPATIBILITY_VIEWS) under dbo or bare are sys's. None for any
    other name, which the engine binds as the catalog places it."""
    folded = loose_name(name)
    if engine == "mssql" and folded in _MSSQL_COMPATIBILITY_VIEWS and (schema is None or loose_name(schema) == "dbo"):
        return "sys", folded
    return None


# Dictionary views and logs that show OTHER sessions' statements as they were
# sent - SQL text with its literals, bind values, plan predicates holding
# them, the error text a failed statement quotes - or the values those
# sessions hold (locked key values, user variables), so a masked column's
# value in someone else's WHERE clause or INSERT would come back in clear;
# and MySQL's full-text index views, the words of a table of any schema.
# The policy refuses them whatever security.allowed_system_schemas or
# allowed_schemas says, and the server leaves them out of every listing.
# Each pattern matches "schema.name" as loose_name folds it; one that also
# matches a bare name is a view the engine binds a bare name to unasked
# (PostgreSQL searches pg_catalog first, Oracle's PUBLIC synonyms name the
# SYS views, SQL Server keeps sysprocesses readable unqualified), and names
# an engine or an extension gives its own objects wherever they were created
# (Oracle's views, Db2's explain tables, PostgreSQL's statement-statistics
# extensions) are matched in any schema. Checked against each fixture's
# catalog (2026-09-28, the columns named like query, sql, stmt, statement,
# text, bind, predicate, message or exception), read again by an account that
# sees every dictionary object (Oracle as SYSTEM: the catalog role's views,
# which the unprivileged account does not see) and with every PUBLIC synonym
# of a listed view under another name (ALL_OUTLINES, CDB_AUTOSTS_SQLTEXT):
# the views that carry statements or their values, including the account's
# own audit trail (every agent sharing the account). Views of the caller's
# own session (pg_prepared_statements, OPTIMIZER_TRACE, PLAN_TABLE$), ones
# holding only normalized digests or handles, object definitions, install
# and upgrade scripts, and the exception text of background work (merges,
# replication, dictionary loads) are not listed. A synonym (Db2: an alias)
# naming a listed view, directly or through others, is refused and left out
# as the view is (the connectors' synonym listings, and
# server._check_synonyms where default-deny does not refuse every unlisted
# name); a view an administrator builds over one is theirs to grant.
SESSION_SQL_VIEWS: dict[str, re.Pattern[str]] = {
    "mysql": re.compile(
        # MariaDB's query_cache_info: every cached SELECT; innodb_ft_index_*: the indexed
        # words of whichever table innodb_ft_aux_table names, allowlisted or not
        r"information_schema\.(?:processlist|innodb_trx|innodb_locks|query_cache_info|innodb_ft_index_(?:cache|table))"
        r"|performance_schema\.(?:processlist|threads|events_statements_\w+|prepared_statements_instances"
        r"|data_locks|user_variables_by_thread|error_log)"
        r"|sys\.(?:x\$)?(?:processlist|session|innodb_lock_waits|schema_table_lock_waits)"
        r"|mysql\.(?:general_log|slow_log)"
    ),
    "postgres": re.compile(
        # pg_show_plans: every running statement's plan with its literals; pg_store_plans: the stored ones
        r"(?:pg_catalog\.)?pg_stat_activity"
        r"|(?:[^.]+\.)?(?:pg_stat_statements|pg_stat_monitor|pg_qualstats\w*|pg_show_plans|pg_store_plans\w*)"
    ),
    # a log table an upgrade changed is kept renamed with a numeric suffix (query_log_0)
    "clickhouse": re.compile(
        r"system\.(?:processes|query_cache|asynchronous_inserts|mutations|distributed_ddl_queue|errors"
        # zookeeper: a replicated table's queue entries hold the inserted rows' block ids and mutation SQL
        r"|zookeeper"
        r"|(?:query_log|query_thread_log|query_views_log|text_log|error_log|opentelemetry_span_log"
        r"|asynchronous_insert_log|crash_log|zookeeper_log)(?:_\d+)?)"
    ),
    "oracle": re.compile(
        r"(?:[^.]+\.)?(?:"
        r"g?v_?\$(?:session|sql|sqlarea|sqlarea_plan_hash|sqltext|sqltext_with_newlines|sqlstats|open_cursor"
        r"|sql_monitor|sql_bind_capture|sql_plan|sql_plan_statistics_all|logmnr_contents|diag_trace_file_contents"
        # the alert log (ORA- messages quote the failing statement) and the result cache's cached statements
        r"|diag_alert_ext|result_cache_objects"
        # 23ai: readable by an unprivileged account (live, 2026-09-28); other_xml holds the peeked binds
        r"|all_sql_bind_capture|all_sql_monitor|recent_sql_monitor|(?:all_)?sql_plan_monitor|sql_history"
        r"|advisor_current_sqlplan"
        # cursor text, audit records and 10046/10053 trace payloads, to the catalog role
        r"|db_object_cache|sql_shared_memory|sqlstats_plan_hash|unified_audit_trail(?:_tbl)?|xml_audit_trail"
        r"|diag_sql_trace_records|diag_opt_trace_records"
        # to the catalog role: every cursor's plan, the mapped, redirected and test-case SQL, undo SQL
        r"|all_sql_plan|mapped_sql|sql_local_last_exec|sql_redirection|sql_testcases|flashback_txn_mods)"
        # the undo SQL of other transactions holds their rows' values
        r"|flashback_transaction_query"
        r"|(?:dba|cdb)_(?:hist|awrapp)_(?:app_)?(?:sqltext|sqlbind|sql_plan|sqlstat|reports|reports_details)"
        r"|awr_(?:root|pdb|cdb|base)_(?:app_)?(?:sqltext|sqlbind|sql_plan|sqlstat)"
        r"|(?:cdb_)?unified_audit_trail|(?:dba|cdb)_(?:fga_audit_trail|common_audit_trail)"
        r"|(?:dba|cdb|user)_audit_(?:trail|object|statement|exists)"
        r"|(?:dba|cdb|all|user)_sqlset_(?:statements|binds|plans)"
        r"|(?:dba|cdb|user)_sqltune_(?:binds|plans)"
        r"|(?:dba|cdb|user)_advisor_(?:sqlw_stmts|sqla_wk_stmts|sqlplans|objects)"  # objects: attr4, a SQL's text
        r"|(?:dba|cdb)_sql_(?:plan_baselines|profiles|patches|quarantine)"
        r"|(?:dba|cdb|all|user)_(?:outlines|resumable|cq_notification_queries|parallel_execute_tasks)"
        # the automatic SQL tuning set (and its AUTOSTS synonyms), translated, refused, failed, firewalled
        # and captured statements, Database Vault's and Enterprise Manager's copies, stored outlines
        r"|(?:dba|cdb)_auto(?:sqlset|sts)_(?:sqltext|sqlplan|sqlstat)"
        r"|(?:dba|cdb|all|user)_sql_translations|(?:dba|cdb)_(?:lockdown_errors|sql_error_mitigations|wi_statements)"
        r"|(?:dba|cdb)_sql_firewall_(?:allowed_sql|capture_logs|sql_logs|violations)"
        r"|(?:dba|cdb)_workload_(?:capture_sqltext|long_sqltext|replay_ifsla|sql_map)"
        r"|dv\$(?:configuration|enforcement)_audit|dba_dv_simulation_log|mgmt_(?:baseline_sql|response_baseline)"
        r"|mview\$_adv_(?:pretty|workload)|ku\$_outline_view"
        # the base tables under them
        r"|aud\$|fga_log\$(?:for_export(?:_tbl)?)?|aud\$unified|sql\$text(?:_datapump(?:_tbl)?)?"
        r"|sqlobj\$(?:plan|auxdata)(?:_datapump(?:_tbl)?)?|wrhs?\$_(?:app_|awrapp_)?(?:sqltext|sqlstat|sql_plan)(?:_bl)?"
        r"|wri\$_sqlset_(?:statements|binds|plans|plan_lines|workspace_plans)|wri\$_sts_sqltext"
        r"|wri\$_adv_(?:sqlt_plans|sqlw_stmts|automv_mv_(?:cand|samp))|swr\$_(?:sqltext|sqlplan|sqlstat\w*)"
        r"|ac_ver\$_sql(?:plans|set_plans|set_statements)"
        r"|wrr\$_(?:capture_(?:long_)?sqltext|capture_sql_tmp|replay_ifsla|replay_sql_(?:binds|map|text))"
        r"|ol\$|sqltxl_sql\$|lockdown_error\$|diag\$_sql_error|wi\$_statement|fw\$sql_log|sql_log\$"
        r"|simulation_log\$|pdb_sync_stmt\$|dbms_parallel_execute_task\$|data_pump_xpl_table\$"
        r")"
    ),
    "mssql": re.compile(
        r"sys\.(?:dm_exec_sessions|dm_exec_requests|dm_exec_connections|dm_exec_requests_history"
        r"|dm_exec_distributed_request_steps|dm_exec_distributed_sql_requests"
        r"|dm_pdw_exec_requests|dm_pdw_request_steps|dm_pdw_sql_requests"
        r"|query_store_query_text|query_store_plan|dm_xe_session_targets"
        r"|plan_persist_query_text|plan_persist_plan)"  # the Query Store's base tables (admin connection)
        r"|(?:sys\.|dbo\.)?(?:sysprocesses|syscacheobjects)"
    ),
    "db2": re.compile(
        r"sysibmadm\.(?:mon_current_sql|mon_pkg_cache_summary|mon_lockwaits|long_running_sql|snapdyn_sql"
        r"|snapstmt|snapsubsection|top_dynamic_sql|query_prep_cost)"
        # EXPLAIN PLAN (db_explain included) and db2advis keep the statement and its predicates
        r"|(?:[^.]+\.)?(?:explain_statement|explain_predicate|advise_workload|advise_mqt)"
    ),
}


# Column statistics: a column's own values, taken from its data - histogram
# buckets, most common values, low and high keys - so a masked column comes
# back in clear wherever the optimizer keeps statistics on it (live, review of
# 2026-09-28: MySQL's COLUMN_STATISTICS under the default
# allowed_system_schemas, PostgreSQL's pg_stats with pg_catalog opened, and a
# bare pg_stats without it). Refused and left out of listings like
# SESSION_SQL_VIEWS, matched the same way (PostgreSQL searches pg_catalog
# first, Oracle's PUBLIC synonyms name the SYS views), the base tables too.
# Oracle's are SYS objects and PUBLIC synonyms of them, matched bare, under
# SYS or under "PUBLIC" (Oracle reads "PUBLIC".COLS as the synonym, live),
# so an application's TRAVEL.COLS stays its own table (review, round 2).
# Checked against each fixture's catalog, read by an account that sees every
# dictionary object (review, 2026-09-28: the objects with a column named
# like LOW_VALUE, HIGH_VALUE, LOWVAL, HIVAL, ENDPOINT*, EPVALUE*, MIN/MAX
# VALUE, COLVALUE, HIGH2KEY or MOST_COMMON_*, and every PUBLIC synonym of one
# under another name: ALL_HISTOGRAMS, COLS).
_ORACLE_DICTIONARY = r"(?:(?:sys|public)\.)?"
COLUMN_STATISTICS_VIEWS: dict[str, re.Pattern[str]] = {
    # MariaDB's mysql.column_stats (min_value, max_value, histogram), MySQL's dictionary table
    "mysql": re.compile(r"information_schema\.column_statistics|mysql\.(?:column_stats|column_statistics)"),
    "postgres": re.compile(r"(?:pg_catalog\.)?(?:pg_stats(?:_ext(?:_exprs)?)?|pg_statistic(?:_ext_data)?)"),
    "oracle": re.compile(
        _ORACLE_DICTIONARY + r"(?:"
        r"(?:all|dba|cdb|user)_(?:tab|part|subpart)_(?:histograms|col_statistics)"
        # *_HISTOGRAMS: the PUBLIC synonyms of *_TAB_HISTOGRAMS
        r"|(?:all|dba|cdb|user)_(?:col_pending_stats|tab_histgrm_pending_stats|histograms)"
        r"|histgrm\$|hist_head\$|finalhist\$|wri\$_optstat_(?:histhead|histgrm)_history"
        # readable by PUBLIC (live: EXU10ASCU returned a masked column's low and high values), and the
        # export and Data Pump views of the same values
        r"|sqt_tab_col_statistics|exu\d*(?:asc|hst)u?|ku\$_\w*(?:histgrm|col_stats)\w*_view"
        # In-Memory: each compression unit's lowest and highest value of a column
        r"|g?v_?\$im_(?:col|imecol)_cu"
        # DBMS_COMPARISON: the index values it scanned between and those of the rows that differ
        r"|_?(?:dba|cdb|user)_comparison(?:_scan_values|_row_dif)?|comparison(?:_scan_val|_row_dif)?\$"
        r")"
    ),
    # SYSSTAT.COLUMNS is the updatable copy of SYSCAT.COLUMNS' statistics; the SYSIBM
    # tables under them, and Db2 for z/OS's own statistics tables
    "db2": re.compile(
        r"(?:syscat|sysstat)\.(?:coldist|colgroupdist)|sysstat\.columns"
        r"|sysibm\.(?:syscoldist|syscolgroupdist|syscolstats|syscoldiststats|syskeytgtdist|syskeytgtdiststats"
        r"|syskeytargetstats)"
    ),
    # a columnstore segment's min_data_id / max_data_id are the values of a value-encoded column
    # (syscscolsegments: its base table, over the admin connection)
    "mssql": re.compile(r"sys\.(?:column_store_segments|dm_db_stats_histogram|syscscolsegments)"),
}

# Stored credentials: password hashes and verifiers, and the connections the
# database keeps to other servers with the passwords they log in with -
# foreign-data-wrapper user mappings, servers and foreign tables, database
# links, linked and federated servers, a replica's source, named
# collections, an authentication method's bind password. A credential is
# not the catalog metadata an opened system schema is for (live, re-attack
# of 2026-09-28: under the default allowed_system_schemas
# [information_schema], PostgreSQL's user_mapping_options returned a
# postgres_fdw mapping's password in clear to the mapped login, and
# foreign_server_options the remote host and database; round 2:
# foreign_table_options a file_fdw table's program with a feed's password in
# it, to a login granted the table, and pg_foreign_table the same to any
# login), and masking cannot hide it: it sits in a generic value column
# such as option_value. Refused
# and left out of listings like SESSION_SQL_VIEWS, matched the same way,
# the base tables too. Checked against each fixture's catalog (2026-09-28,
# read by an account that sees every dictionary object: the objects with a
# column named like password, passwd, pwd, secret, verifier, credential,
# conninfo, provider string or options): the ones that hold a secret, or a
# stored connection's target beside it. Not listed: views that carry no
# secret (PostgreSQL's pg_roles and pg_user show ********, Db2's
# SYSCAT.USEROPTIONS shows REMOTE_PASSWORD as ********, SQL Server's
# syslogins and sysusers a NULL password, ClickHouse's system.users no hash),
# the names of stored credentials and mappings without their options, and
# Oracle's DBA_USERS.PASSWORD, which holds a hash only on releases before
# 11g, older than any client the connector ships can reach. A secret in a
# server setting (PostgreSQL's primary_conninfo, which pg_settings and
# pg_file_settings show to pg_read_all_settings) is not listed either, nor
# the options of a foreign table's columns in PostgreSQL's core
# pg_attribute (attfdwoptions, which information_schema.column_options
# shows and is listed): pg_catalog opens only when an administrator names
# it.
CREDENTIAL_VIEWS: dict[str, re.Pattern[str]] = {
    "postgres": re.compile(
        # the option views and the helpers under them (the options: host, dbname, user, password; a
        # foreign table's and its columns': file_fdw's program, a Multicorn db_url with user:password)
        r"information_schema\.(?:user_mapping_options|foreign_server_options|foreign_data_wrapper_options"
        r"|foreign_table_options|column_options"
        r"|_pg_user_mappings|_pg_foreign_servers|_pg_foreign_data_wrappers|_pg_foreign_tables"
        r"|_pg_foreign_table_columns)"
        # their catalogs (pg_foreign_table is readable by PUBLIC), the roles' verifiers, a subscription's
        # connection string and pg_hba.conf's options, an LDAP bind password among them (superuser)
        r"|(?:pg_catalog\.)?(?:pg_user_mappings?|pg_foreign_server|pg_foreign_data_wrapper|pg_foreign_table"
        r"|pg_authid|pg_shadow|pg_subscription|pg_hba_file_rules)"
    ),
    # MariaDB's global_priv holds its accounts' authentication_string; servers (FEDERATED) and
    # slave_master_info (a replica's source) hold passwords in clear, and
    # replication_connection_configuration the same source's host and account
    "mysql": re.compile(
        r"mysql\.(?:user|global_priv|password_history|servers|slave_master_info)"
        r"|performance_schema\.replication_connection_configuration"
    ),
    # login hashes (live: sa's, to sa), linked servers' provider strings and remote logins, their
    # compatibility views (bound bare and under dbo, live) and the base tables (admin connection)
    "mssql": re.compile(
        r"sys\.(?:sql_logins|servers|linked_logins|remote_logins|syslnklgns|sysxlgns|sysowners)"
        r"|(?:sys\.|dbo\.)?(?:sysservers|sysoledbusers)"
    ),
    "oracle": re.compile(
        _ORACLE_DICTIONARY + r"(?:"
        r"user\$|user_history\$|link\$|scheduler\$_credential|cdb_local_adminauth\$|xs\$verifiers|default_pwd\$"
        r"|java\$runtime\$exec\$user\$|ddl_requests_pwd"
        # database links (their host and remote user; USER_DB_LINKS' password before 10.2), and 23ai's
        # V$DATABASE_LINK of every link, to the catalog role
        r"|(?:all|dba|cdb|user)_db_links|g?v_?\$database_link"
        # the export and Data Pump views: EXU8USRU and EXU*LNKU are readable by PUBLIC (live: the
        # account's own hash, which a 10G verifier keeps in PASSWORD), the rest to the export role
        r"|exu\d*(?:usr|lnk)u?|exu8(?:phs|rol)|ku\$_(?:10_1_)?dblink_view"
        r"|ku\$_(?:user|role|credential|psw_hist_list|xsprin)_view"
        r")"
    ),
    # federated user mappings, server and wrapper options, and Db2 for z/OS's outbound passwords
    "db2": re.compile(
        r"syscat\.(?:useroptions|serveroptions|wrapoptions)"
        r"|sysibm\.(?:sysuseroptions|sysserveroptions|syswrapoptions|usernames)"
    ),
    "clickhouse": re.compile(r"system\.named_collections"),
}

# information_schema views that carry other objects' SQL and literals: view
# and routine bodies, trigger statements, event bodies, check clauses, and
# columns', parameters', attributes' and domains' DEFAULT expressions (a
# masked column's default literal among them). information_schema is open by
# default (security.allowed_system_schemas), and these hand back the
# definitions of every schema the account sees, allowlisted or not (review
# T1, live: hr's view SQL and a masked column's DEFAULT '999-90-1111' under
# allowed_schemas [shop]). Refused and left out of listings like
# SESSION_SQL_VIEWS, as before information_schema was listed; the views that
# hold names only (TABLES, SCHEMATA, KEY_COLUMN_USAGE, ...) stay readable,
# and db_list_columns and db_list_views describe the allowlisted objects.
# Not listed: information_schema.PARTITIONS (a partition's bounds, the
# documented residual beside COLUMN_VALUE_COLUMNS).
DEFINITION_VIEWS: dict[str, re.Pattern[str]] = {
    # INNODB_COLUMNS.DEFAULT_VALUE: the default of a column added instantly
    "mysql": re.compile(
        r"information_schema\.(?:views|routines|columns|triggers|events|check_constraints|innodb_columns)"
    ),
    "postgres": re.compile(
        r"information_schema\.(?:views|routines|columns|triggers|check_constraints|parameters|attributes|domains)"
    ),
    "clickhouse": re.compile(r"information_schema\.(?:views|columns)"),
    "mssql": re.compile(r"information_schema\.(?:views|routines|columns|check_constraints|domains)"),
}

# Catalog views that describe every column and carry its lowest and highest
# values beside the description: Oracle's *_TAB_COLUMNS (LOW_VALUE,
# HIGH_VALUE, raw bytes of the value) and COLS, the PUBLIC synonym of
# USER_TAB_COLUMNS, bare, under SYS or under "PUBLIC" (as
# COLUMN_STATISTICS_VIEWS), and Db2's SYSCAT.COLUMNS and
# SYSCAT.SYSCOLUMNS_UNION (HIGH2KEY, LOW2KEY). A statement reads one only
# without those columns (the guard); a tool that reads every column of an
# object (sample, profile) not at all.
#
# Not listed, a documented residual: the bounds of a table's partitions,
# which hold values of the partitioning column - Oracle's *_TAB_PARTITIONS,
# *_TAB_SUBPARTITIONS, *_IND_PARTITIONS and *_IND_SUBPARTITIONS (HIGH_VALUE,
# HIGH_VALUE_CLOB, HIGH_VALUE_JSON), Db2's SYSCAT.DATAPARTITIONS and
# SYSIBM.SYSDATAPARTITIONS (LOWVALUE, HIGHVALUE), MySQL's
# information_schema.PARTITIONS (PARTITION_DESCRIPTION), PostgreSQL's
# pg_class.relpartbound, SQL Server's sys.partition_range_values, and
# ClickHouse's system.parts and the views of the same parts (partition,
# min_date, max_date, min_time, max_time).
COLUMN_VALUE_COLUMNS: dict[str, tuple[re.Pattern[str], frozenset[str]]] = {
    "oracle": (
        re.compile(
            _ORACLE_DICTIONARY
            + r"(?:(?:all|dba|cdb|user)_(?:tab_columns|tab_cols|tab_cols_v\$|nested_table_cols)|cols)"
        ),
        frozenset({"low_value", "high_value"}),
    ),
    "db2": (
        re.compile(r"syscat\.(?:columns|syscolumns_union)|sysibm\.(?:syscolumns|syskeytargets)"),
        frozenset({"high2key", "low2key"}),
    ),
}


def _shown(schema: str | None, name: str) -> str:
    return f"{loose_name(schema)}.{loose_name(name)}" if schema else loose_name(name)


def is_column_statistics_view(engine: str, schema: str | None, name: str) -> bool:
    """``schema.name`` (or a bare ``name``) is one of the engine's
    COLUMN_STATISTICS_VIEWS, in any spelling loose_name folds to one."""
    pattern = COLUMN_STATISTICS_VIEWS.get(engine)
    return pattern is not None and pattern.fullmatch(_shown(schema, name)) is not None


def value_columns(engine: str, schema: str | None, name: str) -> frozenset[str]:
    """The columns of ``schema.name`` that hold other columns' values
    (COLUMN_VALUE_COLUMNS), as loose_name folds them; empty for any other
    object."""
    entry = COLUMN_VALUE_COLUMNS.get(engine)
    if entry is None or entry[0].fullmatch(_shown(schema, name)) is None:
        return frozenset()
    return entry[1]


def is_credential_view(engine: str, schema: str | None, name: str) -> bool:
    """``schema.name`` (or a bare ``name``) is one of the engine's
    CREDENTIAL_VIEWS, in any spelling loose_name folds to one."""
    pattern = CREDENTIAL_VIEWS.get(engine)
    return pattern is not None and pattern.fullmatch(_shown(schema, name)) is not None


def is_definition_view(engine: str, schema: str | None, name: str) -> bool:
    """``schema.name`` is one of the engine's DEFINITION_VIEWS, in any
    spelling loose_name folds to one."""
    pattern = DEFINITION_VIEWS.get(engine)
    return pattern is not None and pattern.fullmatch(_shown(schema, name)) is not None


def is_session_sql_view(engine: str, schema: str | None, name: str) -> bool:
    """``schema.name`` (or a bare ``name``) is one of the engine's
    SESSION_SQL_VIEWS, COLUMN_STATISTICS_VIEWS, CREDENTIAL_VIEWS or
    DEFINITION_VIEWS, in any spelling loose_name folds to one: a view that
    hands back values masking hides, or credentials, refused to every tool
    and left out of every listing."""
    pattern = SESSION_SQL_VIEWS.get(engine)
    matched = pattern is not None and pattern.fullmatch(_shown(schema, name)) is not None
    return (
        matched
        or is_column_statistics_view(engine, schema, name)
        or is_credential_view(engine, schema, name)
        or is_definition_view(engine, schema, name)
    )


def is_system_object(engine: str, schema: str | None, table: str) -> bool:
    if schema and is_listed_system_schema(engine, schema):
        return True
    low = table.lower()
    return any(low.startswith(p) for p in SYSTEM_TABLE_PREFIXES.get(engine, ()))
