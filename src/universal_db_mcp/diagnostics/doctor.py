"""Doctor: checks installed artifacts and effective policy without any
network access. Local prerequisite checks never require database credentials
(connectivity probes are opt-in via ``--connectivity``)."""

from __future__ import annotations

import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any

from universal_db_mcp.config import AppConfig, ResolvedConnection, load_config
from universal_db_mcp.connectors import registry

CHECKS: list[dict[str, Any]] = []

MSSQL_ODBC_DRIVER = "ODBC Driver 18 for SQL Server"


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
            "cannot verify the OS-level ODBC driver until the pyodbc wheel is importable; the "
            "driver package (msodbcsql18 + unixodbc) ships in the bundle os-packages/ directory "
            "— run scripts/install_offline.sh, which installs it with dpkg (no network)",
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
        f"'{MSSQL_ODBC_DRIVER}' is not registered with unixODBC (detected drivers: {detected}); "
        "install the .deb closure shipped in the bundle os-packages/ directory (dpkg only, no "
        "network) — scripts/install_offline.sh does this in dependency order",
        fatal=True,
    )


def run_doctor(config_path: str | None, connectivity: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    # --- platform baseline ---------------------------------------------------
    py_ok = sys.version_info[:2] == (3, 12)
    py_detail = f"running CPython {platform.python_version()} " + (
        "matches the linux-x86_64-ubuntu24.04-cp312 profile" if py_ok else "profile expects CPython 3.12.x"
    )
    results.append(_check("python-version", py_ok, py_detail, fatal=True))
    results.append(
        _check(
            "platform",
            True,
            f"{platform.system()} {platform.release()} {platform.machine()} "
            f"(bundle profile is linux-x86_64 glibc; other platforms are "
            f"different profiles)",
        )
    )

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
                dbp = Path(conn.database or "")
                if not dbp.exists():
                    results.append(_check(f"connection-{name}-file", False, f"data file '{dbp}' not found", fatal=True))
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
                        detail += (
                            "; the OS-level ODBC driver package (msodbcsql18 + unixodbc) ships in "
                            "the bundle os-packages/ directory — run scripts/install_offline.sh"
                        )
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
            parent = Path(path).parent
            try:
                parent.mkdir(parents=True, exist_ok=True)
                probe = parent / f".udbmcp-doctor-probe-{os.getpid()}"
                probe.write_text("x")
                probe.unlink()
                results.append(_check(label, True, f"'{path}' writable"))
            except OSError as exc:
                results.append(
                    _check(
                        label,
                        False,
                        f"cannot write to '{parent}': {exc}",
                        fatal=(label == "audit-path" and cfg.application.audit_fail_closed),
                    )
                )

        # unsafe secret-file perms double-check (belt and braces)
        for name, conn in cfg.connections.items():
            if conn.password_file:
                pf = Path(conn.password_file)
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

    fatal = [r for r in results if r["status"] == "fatal"]
    return {
        "healthy": not fatal,
        "checks": results,
        "fatal_count": len(fatal),
    }
