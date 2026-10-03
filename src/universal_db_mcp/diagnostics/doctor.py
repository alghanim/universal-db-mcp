"""Doctor: checks installed artifacts and effective policy without any
network access. Local prerequisite checks never require database credentials
(connectivity probes are opt-in via ``--connectivity``; the ClickHouse memory
limit check is the one of them that logs in, to read the account's profile)."""

from __future__ import annotations

import errno
import json
import os
import platform
import shlex
import stat
import subprocess
import sys
from ctypes.util import find_library
from pathlib import Path
from typing import Any
from urllib.parse import quote

from universal_db_mcp.config import (
    AppConfig,
    ConnectionConfig,
    ResolvedConnection,
    darwin_state_directory_acl_problems,
    darwin_state_file_acl_problems,
    default_audit_path,
    is_system_config,
    load_config,
    win32_secret_file_problems,
)
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
    if manifest_path is None:
        return None
    try:
        if not manifest_path.is_file():
            return None
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # also below a directory this user cannot search
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


def _failure_detail(exc: BaseException) -> str:
    """str(exc) for the report, except a decode error's: the codec's message
    quotes the offending byte and its offset, and the file may be a secret."""
    if isinstance(exc, UnicodeError):
        return "a file it reads is not valid UTF-8 text"
    return str(exc)


def _expanded(path: str) -> Path | None:
    """*path* with a leading ``~`` or ``~user`` expanded, as the SQLite
    connector opens it; None for a ``~user`` that names no account (pathlib
    raises RuntimeError there, which no OSError handler catches)."""
    try:
        return Path(path).expanduser()
    except RuntimeError:
        return None


def _state_acl_problems(path: Path) -> list[str]:
    """What macOS extended ACLs let other accounts do to the state file *path*
    (the audit log or the metadata cache), its sidecars (lock, rotated
    backups, SQLite journals) and its directory: read, change, delete or
    re-permission a file; add, delete or rename files in the directory; or
    give every new file an inheritable entry (the rules the server applies,
    config.darwin_state_file_acl_problems and
    darwin_state_directory_acl_problems)."""
    return [problem for _name, problem in _state_acl_findings(path)]


def _state_acl_findings(path: Path) -> list[tuple[Path, str]]:
    """_state_acl_problems, each with the path whose ACL is at fault."""
    problems: list[tuple[Path, str]] = []
    directory = path.parent
    try:
        names = os.listdir(directory)
    except OSError:
        return []  # the path checks above report a directory that cannot be read
    stem = path.name
    for name in sorted(names):
        rest = name[len(stem) :] if name.startswith(stem) else None
        if rest is None or not (rest == "" or rest in (".lock", "-wal", "-shm", "-journal") or (
            rest[:1] == "." and rest[1:].isdigit()
        )):
            continue
        member = directory / name
        if member.is_symlink() or not member.is_file():
            continue  # the audit checks refuse links; only regular files are read
        problems += [(member, f"'{member}': {problem}") for problem in _acl_problems(member)]
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return problems
    try:
        found = [(directory, f"'{directory}': {problem}") for problem in darwin_state_directory_acl_problems(fd)]
    except OSError as exc:
        found = [(directory, f"'{directory}': its access control list cannot be read ({exc.strerror or exc})")]
    finally:
        os.close(fd)
    return found + problems  # the directory first: chmod -N on it stops new files inheriting


def _acl_problems(path: Path) -> list[str]:
    """darwin_state_file_acl_problems, with an ACL that cannot be read as one."""
    try:
        return darwin_state_file_acl_problems(path)
    except OSError as exc:
        return [f"its access control list cannot be read ({exc.strerror or exc})"]


def _uninspectable(exc: OSError, path: object = None) -> str:
    """Detail for a path a probe could not stat. Python 3.12's Path.exists(),
    is_dir(), is_file() and is_symlink() re-raise access denied (and a name
    too long, for one) rather than answer False: access denied is anything
    below a directory this user cannot search, such as the MSI's
    SYSTEM/Administrators-only %ProgramData%\\UniversalDB MCP or a service's
    private secrets directory."""
    target = exc.filename if exc.filename is not None else path
    if not isinstance(exc, PermissionError):
        return f"'{target}' cannot be inspected ({exc.strerror or exc})"
    return (
        f"'{target}' cannot be inspected by this user ({exc.strerror or exc}); run doctor as an administrator "
        "or as the account the server runs as"
    )


def _audit_file_problem(p: Path) -> str:
    """Why AuditLog would refuse the existing log or lock file *p* ('' when
    it would not): it never opens one through a symlink or as a second name
    (hard link) of another file."""
    if p.is_symlink():
        return "is a symlink, which the audit log refuses"
    try:
        st = p.stat()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        return f"cannot be inspected ({exc})"
    if not stat.S_ISREG(st.st_mode):
        return "is not a regular file"
    if st.st_nlink > 1:
        return f"has {st.st_nlink} hard links, which the audit log refuses"
    return ""


# flock answers when the filesystem has no locking (an NFS or SMB share
# mounted without it); ENOTSUP and EOPNOTSUPP differ on macOS
_NO_FILE_LOCKS = {errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOLCK}


def _audit_lock_problem(log: Path) -> str:
    """Why the rotation lock beside the audit log *log* cannot be taken ('' when
    it can). Every append holds an exclusive lock on this sidecar (opened
    O_NOFOLLOW, created on first use), so locking is actually tried: a share
    mounted without it answers ENOTSUP or ENOLCK. The probe creates nothing:
    it locks the lock file, else the log, else (a fresh install) the
    directory, where only an answer that locking is unsupported counts."""
    lock = Path(f"{log}.lock")
    if problem := _audit_file_problem(lock):
        return f"audit rotation lock '{lock}' {problem}"
    exists = lock.exists()
    if exists and not os.access(lock, os.R_OK | os.W_OK):
        return f"audit rotation lock '{lock}' is not readable and writable by the current user"
    if not exists and not os.access(log.parent, os.W_OK):
        return f"audit rotation lock '{lock}' cannot be created (directory not writable)"
    if sys.platform == "win32":
        return ""
    import fcntl

    target = lock if exists else log if log.exists() else log.parent
    try:
        # doctor runs as root, in the server account's directory: a file is
        # opened without following a link swapped in since the check above
        fd = os.open(target, os.O_RDONLY if target == log.parent else os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        return f"'{target}' cannot be opened ({exc})"
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    except BlockingIOError:
        return ""  # a running server holds it right now: locking works
    except OSError as exc:
        if target == log.parent and exc.errno not in _NO_FILE_LOCKS:
            return ""  # a directory may refuse a lock a file would take
        code = errno.errorcode.get(exc.errno, str(exc.errno)) if exc.errno is not None else type(exc).__name__
        return (
            f"audit rotation lock '{lock}' cannot be locked ({code}: {exc.strerror or exc}); the audit "
            "path must be on a filesystem with file locking"
        )
    finally:
        os.close(fd)
    return ""


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
    if not s.enforce_read_only and SERVER_READ_ONLY_AVAILABLE.get(conn.type):
        # A documented opt-out, but db_list_connections still reports the
        # connection read-only: say that only the SQL guard stops a write.
        return _check(
            f"session-{name}",
            False,
            detail + f"; session.enforce_read_only=false turns off the server-side read-only session "
            f"{conn.type} supports, so only the SQL guard refuses writes",
        )
    return _check(f"session-{name}", True, detail)

_CH_MEMORY_REMEDY = (
    "Set a limit on the account itself: ALTER USER <user> SETTINGS max_memory_usage = 2147483648, or ALTER "
    "SETTINGS PROFILE <profile> SETTINGS max_memory_usage = 2147483648 (or <max_memory_usage> in the profile "
    "of users.xml); or use a profile with readonly=2, which accepts the connector's own per-query limit"
)


def _clickhouse_memory_check(
    name: str, conn: ConnectionConfig, security: Any, connectivity: bool
) -> dict[str, Any]:
    """How one ClickHouse statement's server memory is bounded. The connector
    sends max_memory_usage (options.max_memory_usage, 2 GiB by default) with
    every request where the account's profile accepts settings; a readonly=1
    profile refuses them all, and without a limit of its own one statement can
    take the server's whole memory. Offline this says what will be sent; with
    --connectivity it connects (sending the connection's credentials) and reads
    the account's profile: readonly=1 without a profile limit is FATAL unless
    options.memory_limit_from_profile acknowledges it."""
    from universal_db_mcp.connectors.clickhouse import DEFAULT_MAX_MEMORY_USAGE, ClickHouseConnector
    from universal_db_mcp.security.policy import EffectivePolicy

    key = f"connection-{name}-memory-limit"
    acknowledged = conn.options.get("memory_limit_from_profile") is True
    raw = conn.options.get("max_memory_usage")
    cap = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else DEFAULT_MAX_MEMORY_USAGE
    sends = f"sends max_memory_usage={cap} with every query where the account's profile accepts settings"
    if not connectivity:
        return _check(
            key,
            True,
            f"{sends}; a readonly=1 profile refuses it (run doctor --connectivity to check the account)"
            + ("; options.memory_limit_from_profile: true relies on the account's own limit there"
               if acknowledged else ""),
        )
    try:
        resolved = ResolvedConnection(name, conn)
        status = ClickHouseConnector(resolved, EffectivePolicy.build(security, resolved)).memory_limit()
    except Exception as exc:  # noqa: BLE001 - a diagnostic reports, it never ends in a traceback
        return _check(key, False, f"could not read the account's settings profile: {_failure_detail(exc)}")
    if status["sent"]:
        return _check(key, True, f"{sends}: the account's profile (readonly={status['readonly'] or '0'}) accepts it")
    if status["profile_limit"]:
        return _check(
            key, True, f"the account's profile limits each query to max_memory_usage={status['profile_limit']}"
        )
    if acknowledged:
        return _check(
            key,
            True,
            f"{status['why']}; the profile sets no max_memory_usage, and options.memory_limit_from_profile: true "
            "acknowledges that the account's own limits bound a query's memory",
        )
    return _check(
        key,
        False,
        f"{status['why']}, and the profile sets no max_memory_usage: one statement can use all of the server's "
        f"memory. {_CH_MEMORY_REMEDY}; then set "
        f"connections.{name}.options.memory_limit_from_profile: true to acknowledge the account-level limit",
        fatal=True,
    )


def run_doctor(config_path: str | None, connectivity: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    try:
        _run_checks(results, config_path, connectivity)
    except OSError as exc:
        # Each probe of a configured path reports its own failure; this is the
        # net under them: a report that says where it stopped, not a traceback.
        results.append(_check("doctor", False, f"stopped before every check ran: {_uninspectable(exc)}", fatal=True))
    except Exception as exc:  # noqa: BLE001 - a diagnostic reports, it never ends in a traceback
        results.append(
            _check(
                "doctor",
                False,
                f"stopped before every check ran: {type(exc).__name__}: {_failure_detail(exc)}",
                fatal=True,
            )
        )
    fatal_results = [r for r in results if r["status"] == "fatal"]
    return {
        "healthy": not fatal_results,
        "checks": results,
        "fatal_count": len(fatal_results),
    }


def _run_checks(results: list[dict[str, Any]], config_path: str | None, connectivity: bool) -> None:
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
        try:
            problem = "" if p.exists() else f"config file '{p}' not found"
        except OSError as exc:
            # `doctor --config` naming the machine-wide config, run by a user
            # who may not look into its folder
            problem = f"config file {_uninspectable(exc, p)}"
        if problem:
            results.append(_check("config", False, problem, fatal=True))
        else:
            try:
                cfg = load_config(p)
                results.append(_check("config", True, f"loaded '{p}': {len(cfg.connections)} connection(s)"))
            except Exception as exc:  # noqa: BLE001
                results.append(_check("config", False, _failure_detail(exc), fatal=True))

    # --- per-connection local prerequisites (no credentials needed) ----------
    if cfg:
        for name, conn in cfg.connections.items():
            # secret references resolve without the DB (password files/env)
            try:
                ResolvedConnection(name, conn)
                results.append(_check(f"connection-{name}-secrets", True, "secret references resolvable"))
            except Exception as exc:  # noqa: BLE001
                results.append(_check(f"connection-{name}-secrets", False, _failure_detail(exc), fatal=True))

            # local files this connection names: one this user may not look
            # into ends this connection's file checks, not the report
            try:
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
                    elif (dbp := _expanded(conn.database)) is None:
                        results.append(
                            _check(
                                f"connection-{name}-file",
                                False,
                                f"data file '{conn.database}' starts with a ~user that names no account on this "
                                "machine, so the connector cannot open it; use an absolute path",
                                fatal=True,
                            )
                        )
                    else:
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
                        if conn.tls.enabled and (
                            '"' in wallet or ")(" in wallet or any(ord(c) < 32 or ord(c) == 127 for c in wallet)
                        ):
                            # The connector writes the path, double-quoted, into
                            # the TCPS connect descriptor and refuses at connect
                            # time what the quotes cannot carry.
                            results.append(
                                _check(
                                    f"connection-{name}-oracle-wallet",
                                    False,
                                    "oracle options.wallet_location contains a double quote, ')(' or a control "
                                    "character, which an Oracle Net connect descriptor cannot carry safely; the "
                                    "connector refuses to connect until the directory is renamed",
                                    fatal=True,
                                )
                            )
                        elif not wp.is_dir():
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
                        elif conn.options.get("thick_mode") and conn.tls.enabled and not (wp / "cwallet.sso").is_file():
                            # The Oracle Client opens the wallet without a
                            # password (options.wallet_password is Thin-only), so
                            # Thick mode needs the auto-login cwallet.sso.
                            results.append(
                                _check(
                                    f"connection-{name}-oracle-wallet",
                                    False,
                                    f"oracle wallet directory '{wp}' has no cwallet.sso; Thick mode reads an "
                                    "auto-login wallet only (orapki wallet create -wallet <dir> -auto_login, "
                                    "or add -auto_login to the existing wallet)",
                                    fatal=True,
                                )
                            )
                        elif conn.tls.enabled:
                            alias = conn.options.get("tns_alias")
                            target = f"the host tns_alias '{alias}' names" if alias else f"host '{conn.host}'"
                            results.append(
                                _check(
                                    f"connection-{name}-oracle-wallet",
                                    True,
                                    f"wallet directory '{wp}' present; the connect descriptor sets "
                                    f"SSL_SERVER_DN_MATCH=ON, so the server certificate must match {target}",
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
            except OSError as exc:
                results.append(_check(f"connection-{name}-files", False, _uninspectable(exc), fatal=True))

            # session safety profile, resolved OFFLINE from the config: what
            # this connection will ask the server for right after connecting
            # (docs/session-safety.md). Shown so an operator sees "db2 runs at
            # UR" or "postgres read-only server-side" before an upgrade, and
            # which of those the server must accept (fail-closed) vs may skip.
            results.append(_session_check(name, conn))
            if conn.type == "clickhouse":
                results.append(_clickhouse_memory_check(name, conn, cfg.security, connectivity))
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
        # The machine-wide config on Windows is the service's: see below.
        win32_service = sys.platform == "win32" and is_system_config(p)
        for label, path in (
            ("audit-path", cfg.application.audit_path),
            ("metadata-cache-path", cfg.application.metadata_cache_path),
        ):
            if not path:
                if label == "audit-path":
                    # load_config always sets one; only a config built in
                    # code can get here, and it records nothing
                    results.append(
                        _check(
                            label,
                            False,
                            "auditing is off: application.audit_path is not set",
                            fatal=cfg.application.audit_fail_closed,
                        )
                    )
                else:
                    results.append(_check(label, True, "not configured (feature disabled)"))
                continue
            fp = Path(path)
            fatal = label == "metadata-cache-path" or (
                label == "audit-path" and cfg.application.audit_fail_closed
            )
            defaulted = label == "audit-path" and cfg.application.audit_path_default is not None
            try:
                if fp.is_dir():
                    results.append(_check(label, False, f"'{path}' is a directory, not a file", fatal=True))
                    continue
                if label == "audit-path" and (log_problem := _audit_file_problem(fp)):
                    results.append(
                        _check(label, False, f"'{path}' {log_problem}; no audit record can be written", fatal=fatal)
                    )
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
                    # a writable log is no use if the lock cannot be taken
                    if label == "audit-path" and (lock_problem := _audit_lock_problem(fp)):
                        results.append(
                            _check(label, False, f"{lock_problem}; no audit record can be written", fatal=fatal)
                        )
                        continue
                    # the server also writes beside the file: rotation renames
                    # the log, SQLite creates its -wal/-journal files
                    if not os.access(fp.parent, os.W_OK):
                        needs = (
                            "rotation renames the log once it reaches audit_max_bytes, and from then on no "
                            "audit record can be written"
                            if label == "audit-path"
                            else "SQLite creates its -wal and -journal files beside the cache, so the server "
                            "cannot open it"
                        )
                        results.append(
                            _check(
                                label,
                                False,
                                f"'{path}' is writable but its directory '{fp.parent}' is not: {needs}",
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
                    if defaulted and win32_service and not parent.exists():
                        # The MSI creates logs\ and grants a dedicated service
                        # account Modify on it; that account may only read the
                        # folder above, so it cannot create logs\ itself.
                        results.append(
                            _check(
                                label,
                                False,
                                f"'{path}' absent and its directory '{parent}' does not exist: LocalSystem creates "
                                "it on the first audited call, but a dedicated service account cannot (it may only "
                                f"read '{parent.parent}'); repair or reinstall the MSI, which creates it with Modify "
                                "for that account",
                            )
                        )
                    elif defaulted and not parent.exists():
                        # the server creates the default directory (0700) itself
                        anchor = next((a for a in parent.parents if a.exists()), parent.anchor)
                        creatable = Path(anchor).is_dir() and os.access(anchor, os.W_OK)
                        results.append(
                            _check(
                                label,
                                creatable,
                                f"'{path}' absent; its directory '{parent}' will be created (0700) on the "
                                f"first audited call"
                                if creatable
                                else f"'{path}' cannot be created: '{anchor}' is not a writable directory",
                                fatal=fatal,
                            )
                        )
                    elif not parent.is_dir() or not os.access(parent, os.W_OK):
                        results.append(
                            _check(
                                label,
                                False,
                                f"parent directory '{parent}' of '{path}' does not exist or is not writable",
                                fatal=fatal,
                            )
                        )
                    elif label == "audit-path" and (lock_problem := _audit_lock_problem(fp)):
                        results.append(
                            _check(label, False, f"{lock_problem}; no audit record can be written", fatal=fatal)
                        )
                    else:
                        results.append(_check(label, True, f"'{path}' absent; parent directory '{parent}' is writable"))
            except OSError as exc:
                results.append(_check(label, False, _uninspectable(exc, path), fatal=fatal))
        if win32_service:
            # os.access ignores NTFS ACLs and doctor runs elevated, so
            # "writable" says nothing about a dedicated service account
            # (NetworkService, say), which may only read the config folder:
            # the MSI grants it Modify on logs\ (the default audit directory)
            # alone, and SQLite also writes its journal beside the cache.
            logs_dir = default_audit_path(p)[0].parent
            state_dirs = {
                label: Path(path).parent
                for label, path in (
                    ("audit-path", cfg.application.audit_path),
                    ("metadata-cache-path", cfg.application.metadata_cache_path),
                )
                if path
            }
            for r in results:
                if r["check"] in state_dirs and r["status"] == "ok":
                    r["status"] = "warning"
                    r["detail"] += (
                        f"; unverified: the service account needs write access to '{state_dirs[r['check']]}' "
                        f"(the MSI grants a dedicated account Modify on '{logs_dir}' only), and doctor cannot "
                        "evaluate NTFS ACLs for another account"
                    )
        if (default_note := cfg.application.audit_path_default) is not None:
            for r in results:
                if r["check"] == "audit-path":
                    r["detail"] += f" (application.audit_path is unset: default in the {default_note})"

        # The cached table lists become the guard's permitted-object set, so
        # the server refuses (and disables) a cache another local user could
        # have written; report the same owner/mode verdict here. POSIX only:
        # on Windows the state directory's ACL is the control. As root the
        # service account is unknown, so the owner is reported, not compared.
        cache_path = cfg.application.metadata_cache_path
        if cache_path and sys.platform != "win32":
            from universal_db_mcp.services.metadata import TransientCacheCheckError, cache_file_problems

            cp = Path(cache_path)
            euid = os.geteuid()
            transient = ""
            try:
                problems = cache_file_problems(cp, owner_uid=None if euid == 0 else euid)
            except TransientCacheCheckError as exc:
                problems, transient = [], str(exc.strerror)
            if transient:
                results.append(
                    _check("metadata-cache-perms", False, f"{transient} (re-run doctor; the server checks again)")
                )
            elif problems:
                results.append(
                    _check(
                        "metadata-cache-perms",
                        False,
                        "; ".join(problems) + " (the server will not use this cache)",
                        fatal=True,
                    )
                )
            elif cp.is_file():
                st = cp.stat()
                results.append(
                    _check(
                        "metadata-cache-perms",
                        True,
                        f"'{cp}' owned by uid {st.st_uid}, mode {stat.filemode(st.st_mode)}",
                    )
                )
            elif cp.parent.is_dir():
                results.append(
                    _check("metadata-cache-perms", True, f"'{cp}' absent; directory '{cp.parent}' is private")
                )

        # macOS: the state files' privacy is read from their mode bits (0600),
        # which an extended ACL does not show: an inheritable 'everyone allow
        # read' on the state directory made the audit log (the SQL text) and
        # its backups readable by every local user, and 'allow write' let them
        # rewrite the cached object lists the guard trusts.
        if sys.platform == "darwin":
            for label, state_path in (
                ("audit-path-acl", cfg.application.audit_path),
                ("metadata-cache-acl", cfg.application.metadata_cache_path),
            ):
                if state_path and (findings := _state_acl_findings(Path(state_path))):
                    named = " ".join(shlex.quote(str(name)) for name in dict.fromkeys(n for n, _p in findings))
                    results.append(
                        _check(
                            label,
                            False,
                            "exposed to other local users by an access control list: "
                            f"{'; '.join(problem for _n, problem in findings)}; remove the access control "
                            f"lists with: chmod -N {named}",
                            fatal=True,
                        )
                    )

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
        try:
            _service_token_exists = _service_token.is_file()
        except OSError as exc:
            # The MSI makes %ProgramData%\UniversalDB MCP SYSTEM/Administrators-
            # only and Python 3.12's is_file() re-raises access denied: another
            # account's token is not this user's to verify, whatever --config is.
            _service_token_exists = False
            results.append(
                _check(
                    "service-bearer-token",
                    False,
                    f"the service's bearer token '{_service_token}' may be present but is not verifiable by this "
                    f"user ({exc.strerror or exc}); run doctor as an administrator to check it",
                )
            )
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
                try:
                    tp_mode = stat.S_IMODE(tp.stat().st_mode) if tp.is_file() else None
                    tp_problem = ""
                except OSError as exc:
                    tp_mode, tp_problem = None, f"cannot be inspected by this user ({exc.strerror or exc})"
                if tp_problem:
                    results.append(
                        _check("http-bearer-token", False, f"bearer token file '{tp}' {tp_problem}", fatal=True)
                    )
                elif tp_mode is None:
                    results.append(
                        _check("http-bearer-token", False, f"bearer token file '{tp}' not found", fatal=True)
                    )
                elif sys.platform == "win32":
                    # POSIX mode bits mean nothing on NTFS: the DACL and the
                    # owner are the control, checked as serve checks them.
                    problems = win32_secret_file_problems(tp)
                    results.append(
                        _check(
                            "http-bearer-token",
                            not problems,
                            f"bearer token file '{tp}' is exposed to other local users: {'; '.join(problems)}"
                            if problems
                            else f"bearer token file '{tp}' present; its ACL grants no other local user access",
                            fatal=True,
                        )
                    )
                elif tp_mode & 0o077:
                    results.append(
                        _check(
                            "http-bearer-token",
                            False,
                            f"bearer token file '{tp}' is group/world readable ({stat.filemode(tp_mode)})",
                            fatal=True,
                        )
                    )
                elif acl_problems := _acl_problems(tp):
                    results.append(
                        _check(
                            "http-bearer-token",
                            False,
                            f"bearer token file '{tp}' is exposed to other local users: {'; '.join(acl_problems)}",
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
            for secret_file in (conn.password_file, conn.username_file, conn.options.get("wallet_password_file")):
                if not secret_file:
                    continue
                pf = Path(secret_file)
                try:
                    if not pf.exists():
                        continue
                    if sys.platform == "win32":
                        problems = win32_secret_file_problems(pf)
                        if problems:
                            results.append(
                                _check(
                                    f"connection-{name}-secret-perms",
                                    False,
                                    f"'{pf}' is exposed to other local users: {'; '.join(problems)}",
                                    fatal=True,
                                )
                            )
                        continue
                    mode = stat.S_IMODE(pf.stat().st_mode)
                except OSError as exc:
                    # a service's private secrets directory, say
                    results.append(
                        _check(f"connection-{name}-secret-perms", False, _uninspectable(exc, pf), fatal=True)
                    )
                    continue
                if mode & 0o077:
                    results.append(
                        _check(
                            f"connection-{name}-secret-perms",
                            False,
                            f"'{pf}' is group/world readable ({stat.filemode(mode)})",
                            fatal=True,
                        )
                    )
                elif acl_problems := _acl_problems(pf):
                    results.append(
                        _check(
                            f"connection-{name}-secret-perms",
                            False,
                            f"'{pf}' is exposed to other local users: {'; '.join(acl_problems)}",
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
            except (OSError, ValueError) as exc:
                # ValueError: a UnicodeError for a name IDNA cannot encode
                # (an empty or over-long label: db..example.com)
                results.append(
                    _check(f"connection-{name}-reachable", False, f"cannot reach {conn.host}:{port}: {exc}", fatal=True)
                )
