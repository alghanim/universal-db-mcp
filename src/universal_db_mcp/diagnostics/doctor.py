"""Doctor: checks installed artifacts and effective policy without any
network access. Local prerequisite checks never require database credentials
(connectivity probes are opt-in via ``--connectivity``)."""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
import sys
from ctypes.util import find_library
from pathlib import Path
from typing import Any
from urllib.parse import quote

from universal_db_mcp.config import AppConfig, ConnectionConfig, ResolvedConnection, load_config
from universal_db_mcp.connectors import registry

# The bearer-token PATH the package postinstalls provision for the systemd /
# launchd daemon (which forces --transport http on the command line and
# receives this path via UDBMCP_HTTP_BEARER_TOKEN_FILE — an env var an admin
# shell does not have). doctor validates it whenever the file exists, even if
# THIS config says stdio. Module-level so tests can point it at a tmp file.
# Platform-aware: the MSI service action provisions the token next to the
# machine-wide config under %ProgramData%\UniversalDB MCP\ (service.ps1), so a
# POSIX-only path would make doctor validate a file nothing runs on Windows.


def service_token_path() -> Path:
    from universal_db_mcp.agents.core import system_config_dir

    return system_config_dir() / "http-token"


SERVICE_TOKEN_PATH = service_token_path()

CHECKS: list[dict[str, Any]] = []

MSSQL_ODBC_DRIVER = "ODBC Driver 18 for SQL Server"


def _bundle_profile() -> str:
    """Identity of the bundle this installation came from, for reporting.

    Sources, in order: the ``UDBMCP_BUNDLE_MANIFEST`` environment variable
    (explicit override), the bundle ``manifest.json`` the installer copies
    next to the venv (``<venv>/../manifest.json``), and — when neither is
    available (e.g. a development checkout, or a bundle built without a
    manifest) — an honest description of the running platform. The doctor
    must never report a hardcoded profile name it did not verify: claiming
    ``linux-x86_64-ubuntu24.04-cp312`` on a Windows host would be a lie, not
    a diagnostic."""
    manifest = _bundle_manifest()
    profile = manifest.get("profile") if manifest else None
    if isinstance(profile, str) and profile:
        return profile
    return f"{platform.system()}/{platform.machine()} cpython {platform.python_version()}"


def _venv_interpreter_check() -> dict[str, Any] | None:
    """The offline installer creates the venv with `python -m venv --copies`
    (so the rollback verifier can prove the tree is self-contained): the venv
    carries its own COPY of the interpreter, and an OS python update does not
    reach it. Compare the running interpreter with the base it was copied from
    and say so when they drift; a re-run of the installer refreshes the copy."""
    if Path(sys.prefix) == Path(sys.base_prefix):
        return None  # not a venv
    cfg = Path(sys.prefix) / "pyvenv.cfg"
    if not cfg.is_file():
        return None
    keys: dict[str, str] = {}
    for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip()
    base: Path | None = None
    if keys.get("executable"):
        base = Path(keys["executable"])
    elif keys.get("home"):
        base = Path(keys["home"]) / "python3"
    copied = not Path(sys.executable).is_symlink()
    how = "a copy of the interpreter (installed with --copies)" if copied else "a symlink to the interpreter"
    if base is None or not base.exists():
        return _check("venv-interpreter", True, f"venv carries {how}; base interpreter not found to compare against")
    try:
        proc = subprocess.run(  # noqa: S603 - the interpreter pyvenv.cfg names, fixed argv
            [str(base), "-c", "import platform; print(platform.python_version())"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        base_version = proc.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return _check("venv-interpreter", True, f"venv carries {how}; base interpreter {base} could not be run ({exc})")
    running = platform.python_version()
    if base_version and base_version != running:
        return _check(
            "venv-interpreter",
            False,
            f"venv runs CPython {running} while the base interpreter {base} is now {base_version}: {how} did not "
            "follow the OS update; re-run the offline installer (or reinstall the package) to refresh it",
        )
    return _check(
        "venv-interpreter", True, f"CPython {running} matches the base interpreter {base}; venv carries {how}"
    )


def _bundle_manifest() -> dict[str, Any] | None:
    """The installed bundle's manifest.json, or None (development checkout,
    unreadable or corrupt file)."""
    manifest_path: Path | None = None
    env_manifest = os.environ.get("UDBMCP_BUNDLE_MANIFEST")
    if env_manifest:
        manifest_path = Path(env_manifest)
    else:
        # scripts/install_offline.sh installs the verified bundle's
        # manifest.json at $TARGET/manifest.json, i.e. one level above the
        # venv that contains this interpreter. Derive the venv root from
        # sys.prefix: real venvs symlink bin/python to the base interpreter,
        # so Path(sys.executable).resolve() would land in the base
        # interpreter's own directory, unrelated to the install target.
        if Path(sys.prefix) != Path(sys.base_prefix):
            candidate = Path(sys.prefix).parent / "manifest.json"
            if candidate.is_file():
                manifest_path = candidate
    if manifest_path is None or not manifest_path.is_file():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _mssql_odbc_remediation() -> str:
    """Platform-correct remediation for a missing msodbcsql18 OS driver.

    The .deb closure vendored in the bundle's ``os-packages/`` directory is
    Linux-only; on Windows and macOS the driver is an administrator-supplied
    MSI/pkg that the bundle cannot redistribute."""
    if sys.platform == "win32":
        return (
            "install Microsoft ODBC Driver 18 for SQL Server (msodbcsql MSI, "
            "administrator-supplied) via ODBC Administrator"
        )
    if sys.platform == "darwin":
        return "install msodbcsql18.pkg (administrator-supplied) + unixodbc (Homebrew) via ODBC Manager"
    return (
        "install the .deb closure shipped in the bundle os-packages/ directory (dpkg only, no "
        "network) — scripts/install_offline.sh does this in dependency order"
    )


def _check(name: str, ok: bool, detail: str, *, fatal: bool = False) -> dict[str, Any]:
    return {"check": name, "status": "ok" if ok else ("fatal" if fatal else "warning"), "detail": detail}


def _mssql_odbc_driver_check(conn_name: str, pyodbc_mod: Any) -> dict[str, Any]:
    """OS-level ODBC driver check: the pyodbc wheel can import while the
    underlying 'ODBC Driver 18 for SQL Server' library is not registered with
    unixODBC (otherwise only detected at connect time)."""
    key = f"connection-{conn_name}-odbc-driver"
    if pyodbc_mod is None:
        return _check(
            key,
            False,
            "cannot verify the OS-level ODBC driver until the pyodbc wheel is importable; "
            + _mssql_odbc_remediation(),
            fatal=True,
        )
    try:
        drivers = [str(d) for d in pyodbc_mod.drivers()]
    except Exception as exc:  # noqa: BLE001
        return _check(key, False, f"could not query the unixODBC driver list: {exc}", fatal=True)
    if any(d.startswith(MSSQL_ODBC_DRIVER) for d in drivers):
        return _check(key, True, f"'{MSSQL_ODBC_DRIVER}' registered with unixODBC")
    detected = ", ".join(drivers) if drivers else "none"
    return _check(
        key,
        False,
        f"'{MSSQL_ODBC_DRIVER}' is not registered with the platform ODBC driver manager "
        f"(detected drivers: {detected}); {_mssql_odbc_remediation()}",
        fatal=True,
    )



def _session_check(name: str, conn: ConnectionConfig) -> dict[str, Any]:
    """Describe the resolved session safety profile of one connection."""
    from universal_db_mcp.security.session import READ_ONLY_DEFAULT_ISOLATION, SERVER_READ_ONLY_AVAILABLE

    s = conn.session
    isolation = s.isolation or (READ_ONLY_DEFAULT_ISOLATION.get(conn.type) if conn.read_only else None)
    parts = [f"isolation={isolation or 'server default'}"]
    if s.enforce_read_only and conn.read_only:
        parts.append(
            "read-only=server-side (enforced)" if SERVER_READ_ONLY_AVAILABLE.get(conn.type)
            else "read-only=SQL guard (engine has no session switch)"
        )
    else:
        parts.append("read-only=SQL guard only")
    parts.append(
        f"lock_timeout={s.lock_timeout_seconds}s"
        if s.lock_timeout_seconds is not None
        else "lock_timeout=server default"
    )
    parts.append("statement_timeout=policy" if s.statement_timeout_from_policy else "statement_timeout=none")
    enforced = [x for x in (isolation if conn.type in ("db2", "mssql") else None,
                            "read-only" if s.enforce_read_only and conn.read_only
                            and SERVER_READ_ONLY_AVAILABLE.get(conn.type) else None) if x]
    detail = "; ".join(parts) + (f"; the server must accept: {', '.join(enforced)} (fail-closed)" if enforced else "")
    return _check(f"session-{name}", True, detail)

def run_doctor(config_path: str | None, connectivity: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    # --- platform baseline ---------------------------------------------------
    profile = _bundle_profile()
    py_ok = sys.version_info[:2] == (3, 12)
    py_detail = f"running CPython {platform.python_version()} " + (
        f"matches the {profile} profile" if py_ok else f"profile {profile} expects CPython 3.12.x"
    )
    results.append(_check("python-version", py_ok, py_detail, fatal=True))
    results.append(
        _check(
            "platform",
            True,
            f"{platform.system()} {platform.release()} {platform.machine()} "
            f"(bundle profile: {profile})",
        )
    )
    manifest = _bundle_manifest()
    if manifest is not None:
        # The one line an operator compares with the release stick after an
        # upgrade: the commit the installed payload was built from.
        results.append(
            _check(
                "installed-release",
                True,
                f"release {manifest.get('release')} source_rev {manifest.get('source_rev')} "
                f"(built {manifest.get('created')})",
            )
        )
    else:
        results.append(_check("installed-release", True, "no bundle manifest next to this venv (development checkout)"))
    interp = _venv_interpreter_check()
    if interp is not None:
        results.append(interp)

    # --- application wheel import -------------------------------------------
    try:
        import universal_db_mcp  # noqa: F401

        results.append(_check("application-wheel", True, f"universal_db_mcp {universal_db_mcp.__version__} importable"))
    except Exception as exc:  # noqa: BLE001
        results.append(_check("application-wheel", False, f"import failed: {exc}", fatal=True))

    # --- core runtime deps ---------------------------------------------------
    for mod in ("mcp", "yaml", "sqlglot"):
        try:
            __import__(mod)
            results.append(_check(f"dep-{mod}", True, "importable"))
        except Exception as exc:  # noqa: BLE001
            results.append(_check(f"dep-{mod}", False, f"missing: {exc}", fatal=True))

    # --- config --------------------------------------------------------------
    cfg: AppConfig | None = None
    if not config_path:
        config_path = os.environ.get("UDBMCP_CONFIG")
    if not config_path:
        results.append(_check("config", False, "no config path: pass --config or set UDBMCP_CONFIG", fatal=True))
    else:
        p = Path(config_path)
        if not p.exists():
            results.append(_check("config", False, f"config file '{p}' not found", fatal=True))
        else:
            try:
                cfg = load_config(p)
                results.append(_check("config", True, f"loaded '{p}': {len(cfg.connections)} connection(s)"))
            except Exception as exc:  # noqa: BLE001
                results.append(_check("config", False, str(exc), fatal=True))

    # --- per-connection local prerequisites (no credentials needed) ----------
    if cfg:
        for name, conn in cfg.connections.items():
            # secret references resolve without the DB (password files/env)
            try:
                ResolvedConnection(name, conn)
                results.append(_check(f"connection-{name}-secrets", True, "secret references resolvable"))
            except Exception as exc:  # noqa: BLE001
                results.append(_check(f"connection-{name}-secrets", False, str(exc), fatal=True))

            # TLS material
            if conn.tls.enabled and conn.tls.ca_file:
                ca = Path(conn.tls.ca_file)
                if not ca.exists():
                    results.append(_check(f"connection-{name}-ca", False, f"CA file '{ca}' not found", fatal=True))
                else:
                    results.append(_check(f"connection-{name}-ca", True, f"CA file '{ca}' present"))

            # SQLite data file presence + readability
            if conn.type == "sqlite":
                if not conn.database:
                    results.append(
                        _check(
                            f"connection-{name}-file",
                            False,
                            "sqlite connection has no 'database' file path configured",
                            fatal=True,
                        )
                    )
                else:
                    dbp = Path(conn.database)
                    if not dbp.exists():
                        results.append(
                            _check(f"connection-{name}-file", False, f"data file '{dbp}' not found", fatal=True)
                        )
                    elif not os.access(dbp, os.R_OK):
                        results.append(
                            _check(
                                f"connection-{name}-file",
                                False,
                                f"data file '{dbp}' not readable by current user",
                                fatal=True,
                            )
                        )
                    else:
                        results.append(_check(f"connection-{name}-file", True, f"data file '{dbp}' readable"))

            # oracle: wallet material that the connector will require at
            # connect time (Thin mode, TCPS). A missing wallet directory is a
            # guaranteed CONNECTION_ERROR on first use.
            if conn.type == "oracle":
                wallet = conn.options.get("wallet_location")
                if isinstance(wallet, str) and wallet:
                    wp = Path(wallet)
                    if not wp.is_dir():
                        results.append(
                            _check(
                                f"connection-{name}-oracle-wallet",
                                False,
                                f"oracle wallet directory '{wp}' not found (options.wallet_location)",
                                fatal=True,
                            )
                        )
                    elif not conn.options.get("thick_mode") and not (wp / "ewallet.pem").is_file():
                        # Thin mode reads a PEM wallet only. An orapki wallet
                        # directory (cwallet.sso / ewallet.p12) passes a
                        # directory-exists check and then fails at connect
                        # time with a raw driver error, so doctor looked green
                        # while the connection could never work.
                        results.append(
                            _check(
                                f"connection-{name}-oracle-wallet",
                                False,
                                f"oracle wallet directory '{wp}' has no ewallet.pem; Thin mode reads "
                                "a PEM wallet only (export it from the orapki wallet, or enable "
                                "options.thick_mode to use cwallet.sso/ewallet.p12)",
                                fatal=True,
                            )
                        )
                    else:
                        results.append(
                            _check(f"connection-{name}-oracle-wallet", True, f"wallet directory '{wp}' present")
                        )
                tns_admin = conn.options.get("tns_admin")
                if isinstance(tns_admin, str) and tns_admin and not Path(tns_admin).is_dir():
                    results.append(
                        _check(
                            f"connection-{name}-oracle-tns-admin",
                            False,
                            f"oracle tns_admin directory '{tns_admin}' not found",
                            fatal=True,
                        )
                    )

                # Thick mode: the administrator-supplied Instant Client is the
                # only client-side way to authenticate an account that carries
                # just the legacy 10G verifier. doctor checks the DIRECTORY
                # only - loading the client would switch this whole process to
                # Thick mode permanently, which a diagnostic must never do.
                if conn.options.get("thick_mode"):
                    lib_dir = conn.options.get("lib_dir")
                    if isinstance(lib_dir, str) and lib_dir:
                        present = Path(lib_dir).is_dir()
                        results.append(
                            _check(
                                f"connection-{name}-oracle-instant-client",
                                present,
                                (
                                    f"Instant Client directory '{lib_dir}' present"
                                    if present
                                    else f"oracle thick_mode: Instant Client directory '{lib_dir}' "
                                    "not found (options.lib_dir); the client is Oracle-licensed and "
                                    "administrator-supplied"
                                ),
                                fatal=not present,
                            )
                        )
                    else:
                        # Ask the LOADER whether it can see the client. This
                        # reads the loader cache; it does not dlopen anything,
                        # because loading the client would switch this process
                        # to Thick mode permanently - never a side effect of a
                        # diagnostic.
                        found = find_library("clntsh")
                        results.append(
                            _check(
                                f"connection-{name}-oracle-instant-client",
                                bool(found),
                                (
                                    f"Instant Client visible to the loader ({found})"
                                    if found
                                    else "oracle thick_mode is set but the loader cannot see "
                                    "libclntsh: unzip the administrator-supplied Instant Client "
                                    "under /opt, add its directory to /etc/ld.so.conf.d/ and run "
                                    "ldconfig (systemd clears LD_LIBRARY_PATH, so ldconfig is the "
                                    "route that survives)"
                                ),
                            )
                        )
                # A TNS alias is unresolvable without tnsnames.ora in tns_admin.
                tns_alias = conn.options.get("tns_alias")
                if isinstance(tns_alias, str) and tns_alias and isinstance(tns_admin, str) and tns_admin:
                    names = Path(tns_admin) / "tnsnames.ora"
                    results.append(
                        _check(
                            f"connection-{name}-oracle-tnsnames",
                            names.is_file(),
                            (
                                f"tnsnames.ora present for alias '{tns_alias}'"
                                if names.is_file()
                                else f"oracle tns_alias '{tns_alias}' needs '{names}', which is missing"
                            ),
                            fatal=not names.is_file(),
                        )
                    )

            # session safety profile, resolved OFFLINE from the config: what
            # this connection will ask the server for right after connecting
            # (docs/session-safety.md). Shown so an operator sees "db2 runs at
            # UR" or "postgres read-only server-side" before an upgrade, and
            # which of those the server must accept (fail-closed) vs may skip.
            results.append(_session_check(name, conn))
            # driver availability: our connector class AND the real vendor
            # module (a registered class can exist while the driver wheel is
            # absent; the tool layer would fail with DRIVER_MISSING).
            _DRIVER_MODULES = {
                "postgres": "psycopg",
                "mysql": "pymysql",
                "clickhouse": "clickhouse_connect",
                "oracle": "oracledb",
                "mssql": "pyodbc",
                "db2": "ibm_db",
            }
            try:
                registry.connector_class(conn.type)
            except Exception as exc:  # noqa: BLE001
                results.append(_check(f"connection-{name}-driver", False, f"{exc}", fatal=True))
                continue
            driver_mod: str | None = _DRIVER_MODULES.get(conn.type)
            pyodbc_mod: Any = None
            if driver_mod is None:
                results.append(_check(f"connection-{name}-driver", True, f"engine '{conn.type}' needs no driver wheel"))
            else:
                try:
                    pyodbc_mod = __import__(driver_mod)
                    results.append(_check(f"connection-{name}-driver", True, f"driver '{driver_mod}' importable"))
                except Exception:  # noqa: BLE001
                    detail = (
                        f"vendor driver '{driver_mod}' not importable: install the pinned "
                        f"wheel from the offline bundle wheelhouse (no network)"
                    )
                    if conn.type == "mssql":
                        detail += f"; the OS-level ODBC driver behind the wheel: {_mssql_odbc_remediation()}"
                    results.append(_check(f"connection-{name}-driver", False, detail, fatal=True))

            # the OS-level driver behind the wheel (mssql only): report a
            # missing msodbcsql18 registration before any connection attempt
            if conn.type == "mssql":
                results.append(_mssql_odbc_driver_check(name, pyodbc_mod))

            # require_remote_tls compliance
            if cfg.security.require_remote_tls and conn.type != "sqlite" and not conn.tls.enabled:
                results.append(
                    _check(
                        f"connection-{name}-tls",
                        False,
                        "security.require_remote_tls=true but connection tls.enabled=false",
                        fatal=True,
                    )
                )

    # --- audit / cache paths writable ---------------------------------------
    if cfg:
        for label, path in (
            ("audit-path", cfg.application.audit_path),
            ("metadata-cache-path", cfg.application.metadata_cache_path),
        ):
            if not path:
                results.append(_check(label, True, "not configured (feature disabled)"))
                continue
            fp = Path(path)
            fatal = label == "metadata-cache-path" or (
                label == "audit-path" and cfg.application.audit_fail_closed
            )
            if fp.is_dir():
                results.append(_check(label, False, f"'{path}' is a directory, not a file", fatal=True))
                continue
            if fp.exists():
                # Probe the configured file itself: parent-dir writability is
                # not file writability (e.g. a root-owned 0444 audit.jsonl).
                if not os.access(fp, os.W_OK):
                    results.append(
                        _check(
                            label,
                            False,
                            f"'{path}' exists but is not writable by the current user",
                            fatal=fatal,
                        )
                    )
                    continue
                if label == "metadata-cache-path":
                    # The cache opens the file as SQLite; a corrupted
                    # (non-SQLite) file is fatal at startup.
                    import sqlite3

                    try:
                        # Percent-encode the path: a raw '?' or '#' in the
                        # configured path would be parsed as URI query/
                        # fragment, probing a DIFFERENT file than the one
                        # configured (fail-open on this fatal gate).
                        cache_conn = sqlite3.connect(
                            f"file:{quote(str(fp), safe='/\\')}?mode=rw", uri=True
                        )
                        try:
                            cache_conn.execute("PRAGMA schema_version")
                        finally:
                            cache_conn.close()
                    except sqlite3.Error as exc:
                        results.append(
                            _check(label, False, f"'{path}' is not a usable SQLite cache file: {exc}", fatal=True)
                        )
                        continue
                results.append(_check(label, True, f"'{path}' writable"))
            else:
                # Never create directories as a side effect of a diagnostic
                # (a typo'd path must be surfaced, not silently materialized).
                parent = fp.parent
                if not parent.is_dir() or not os.access(parent, os.W_OK):
                    results.append(
                        _check(
                            label,
                            False,
                            f"parent directory '{parent}' of '{path}' does not exist or is not writable",
                            fatal=fatal,
                        )
                    )
                else:
                    results.append(_check(label, True, f"'{path}' absent; parent directory '{parent}' is writable"))

        # HTTP deployment: the bearer token file is the only authentication on
        # the listener; verify it exists, is a non-empty regular file and is
        # not group/world readable.
        # ALSO validate the SYSTEM SERVICE's token when this config says
        # stdio: the systemd/launchd daemon forces --transport http on the
        # command line and receives the token path from
        # UDBMCP_HTTP_BEARER_TOKEN_FILE (an env var an admin shell does not
        # have), so gating solely on cfg.application.transport would never
        # reach these checks on a real package deployment. The conventional
        # provisioned path (/etc/universal-db-mcp/http-token, written by the
        # package postinstalls) is therefore validated whenever it exists.
        _service_token = SERVICE_TOKEN_PATH
        _service_token_exists = _service_token.is_file()
        if cfg.application.transport == "http" or _service_token_exists:
            token_path = cfg.application.http_bearer_token_file
            if not token_path and _service_token_exists:
                token_path = str(_service_token)
            if not token_path:
                results.append(
                    _check(
                        "http-bearer-token",
                        False,
                        "application.transport=http requires application.http_bearer_token_file",
                        fatal=True,
                    )
                )
            else:
                tp = Path(token_path)
                if not tp.exists() or not tp.is_file():
                    results.append(
                        _check("http-bearer-token", False, f"bearer token file '{tp}' not found", fatal=True)
                    )
                elif sys.platform == "win32":
                    # The POSIX mode bits carry no meaning here and the check
                    # is skipped; saying "safe permissions" would be a claim
                    # about a file that was never inspected. NTFS ACLs are the
                    # real control and are the administrator's responsibility.
                    results.append(
                        _check(
                            "http-bearer-token",
                            True,
                            f"bearer token file '{tp}' present; permissions NOT verified on "
                            "Windows (NTFS ACLs are administrator-managed)",
                        )
                    )
                elif stat.S_IMODE(tp.stat().st_mode) & 0o077:
                    mode = stat.S_IMODE(tp.stat().st_mode)
                    results.append(
                        _check(
                            "http-bearer-token",
                            False,
                            f"bearer token file '{tp}' is group/world readable ({stat.filemode(mode)})",
                            fatal=True,
                        )
                    )
                else:
                    results.append(
                        _check(
                            "http-bearer-token", True, f"bearer token file '{tp}' present with safe permissions"
                        )
                    )

        # unsafe secret-file perms double-check (belt and braces)
        for name, conn in cfg.connections.items():
            for secret_file in (conn.password_file, conn.username_file):
                if not secret_file:
                    continue
                pf = Path(secret_file)
                if pf.exists():
                    import sys as _sys

                    if _sys.platform != "win32":
                        mode = stat.S_IMODE(pf.stat().st_mode)
                        if mode & 0o077:
                            results.append(
                                _check(
                                    f"connection-{name}-secret-perms",
                                    False,
                                    f"'{pf}' is group/world readable ({stat.filemode(mode)})",
                                    fatal=True,
                                )
                            )

    # --- optional connectivity probes ---------------------------------------
    if connectivity and cfg:
        # Opt-in bounded TCP reachability probe (no credentials are sent).
        import socket

        default_ports = {
            "postgres": 5432,
            "mysql": 3306,
            "clickhouse": 8123,
            "oracle": 1521,
            "mssql": 1433,
            "db2": 50000,
        }
        for name, conn in cfg.connections.items():
            if conn.type == "sqlite" or not conn.host:
                continue
            port = conn.port or default_ports.get(conn.type, 0)
            try:
                with socket.create_connection((conn.host, port), timeout=min(conn.connect_timeout_seconds, 5.0)):
                    results.append(
                        _check(
                            f"connection-{name}-reachable",
                            True,
                            f"TCP connect to {conn.host}:{port} succeeded (no credentials sent)",
                        )
                    )
            except OSError as exc:
                results.append(
                    _check(f"connection-{name}-reachable", False, f"cannot reach {conn.host}:{port}: {exc}", fatal=True)
                )

    fatal_results = [r for r in results if r["status"] == "fatal"]
    return {
        "healthy": not fatal_results,
        "checks": results,
        "fatal_count": len(fatal_results),
    }
