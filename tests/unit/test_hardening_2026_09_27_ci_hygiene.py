"""CI and repository-hygiene regressions from the 2026-09-27 security/production review.

F63: the tree carries no developer home or agent scratch paths, and the mock
configs load from any checkout with the secret files the fixture script writes
(the SQL Server fixture is reached through a db_datareader login with SHOWPLAN,
not sa).
F64: on every push to main and every pull request, one job on a GitHub-hosted
Ubuntu 24.04 runner installs the locked dependencies, then runs the unit suite,
ruff, mypy, the lock check and the dependency audit, in that order and exactly
as pinned here, with nothing around them (env, defaults, the setup actions'
commits and inputs, the runner, pytest config, hooks, skips and autouse
fixtures in a conftest or a helper it can import, an autouse fixture in code
outside tests/, pytest plugins, Python startup hooks, source in a codec ruff
does not read, compiled modules, tool caches, stubs, package archives,
directories and ignore files a tool skips) that could skip a check, swallow a
failure or deselect a test, and no link in the tree; the suite's own code is
reviewed as code, not by this gate. The gate reads the source as written and
runs inside the pytest run it guards: it catches the ordinary ways to weaken
CI, not code written to defeat it (a change that keeps this file from being
collected, or skips its tests, switches it off with the rest); every
commit pushed to main gets its own result, and no pull request's run cancels
another's; the suite's venv gets a hashed pip, read from its file as pip and
uv read it, so the bundle builder's tests run, and in CI the suite fails
without the runner's pwsh, so the MSI custom-action tests run too; every
action is pinned to a commit SHA, no token gets write access by default, and
only a job that runs deploy-pages alone may write to Pages.

The fixture script only ever runs against a copy under tmp_path with a fake
``docker`` on PATH; no container, and nothing under the real out/, is touched.
"""

from __future__ import annotations

import ast
import fnmatch
import importlib.metadata
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize
import tomllib
import types
from collections.abc import Collection, Iterable, Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml
from _pytest.config.findpaths import load_config_dict_from_file

from universal_db_mcp.config import load_config, load_resolved
from universal_db_mcp.security import redact

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
MOCK_CONFIGS = ("config.mockdbs.yaml", "config.scale.yaml")
FIXTURE_SCRIPT = Path("scripts") / "fixtures" / "start_mock_dbs.sh"

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="bash fixture script; run on linux/macos")


# ------------------------------------------------------------------ F63: no developer or scratch paths


# A home directory on macOS, Linux (also as a Windows or WSL share path) or
# Windows (any case, also with JSON-escaped backslashes); group 1 is the
# account name, two words for Windows' legacy profile folders.
_HOME_PATH = re.compile(
    r"(?:/Users/|/home/|\\+home\\+|\b(?i:[a-z]:(?:\\+|/)users(?:\\+|/)))((?i:all users|default user)|[\w.$<>-]+)"
)
# Accounts that are nobody's real home: a test's or a document's made-up
# user, the Db2 fixture image's instance owner, the service accounts (Linux
# udbmcp; macOS _udbmcp, via dscl in packaging/pkg/postinstall), the profile
# folders Windows and macOS create on every machine, and the GitHub runner's.
_PLACEHOLDER_ACCOUNTS = frozenset(
    name.casefold()
    for name in ("me", "you", "<you>", "user", "db2inst1", "_udbmcp", "udbmcp", "$SERVICE_USER")
    + ("All Users", "Default User", "Default", "Public", "Shared", "runner")
)
# The path of a URL with a host ('https://example.com/Users/list') is no one's
# home; a file:/// URL has no host and still names one.
_URL_BEFORE = re.compile(r"\b[A-Za-z][\w+.-]*://[^/\s\"'<>]+[^\s\"'<>]*\Z")
# A per-user temp directory, or an agent's scratch directory (for any uid,
# and as the flattened project-dir name: -Users-<name>-, -home-<name>-,
# C--Users-<name>-).
_SCRATCH_PATH = re.compile(r"/var/folders/|pytest-of-|/tmp/claude-\d+|(?<![\w.])-(?:Users|home)-[\w.-]+-")


def _private_paths(line: str) -> list[str]:
    homes = [
        m.group(0)
        for m in _HOME_PATH.finditer(line)
        if m.group(1).casefold() not in _PLACEHOLDER_ACCOUNTS and not _URL_BEFORE.search(line, 0, m.start())
    ]
    return homes + [m.group(0) for m in _SCRATCH_PATH.finditer(line)]


@pytest.mark.parametrize(
    "leak",
    [
        "/Users/jane/src/app/out/mockdb-secrets/pg.pw",
        "/home/jane/src/app/out/mockdb-secrets/pg.pw",
        r"C:\Users\jane\src\app",
        r'"C:\\Users\\jane\\src\\app"',  # as JSON writes it
        "C:/Users/jane/src/app",
        r"c:\users\jane\app",
        "c:/users/jane/app",
        r"\\wsl$\Ubuntu\home\jane\app",
        "file:///Users/jane/src/app",
        "/Volumes/Macintosh HD/Users/jane/app",
        "/home/jane.doe/app",
        "/private/tmp/claude-1000/<project>/<session>/scratchpad/x",
        "/tmp/claude-1000/<project>/x",  # noqa: S108
        "<scratch>/-Users-jane-src-app/x",
        "<scratch>/-home-jane-src-app/x",
        "<scratch>/C--Users-jane-src-app/x",
        "/private/var/folders/xy/abc/T/pytest-of-jane/pytest-3/x",
        "/tmp/pytest-of-runner/pytest-0/x",  # noqa: S108
    ],
)
def test_the_private_path_scan_recognizes_home_and_scratch_paths_on_every_os(leak: str) -> None:
    assert _private_paths(leak)


@pytest.mark.parametrize(
    "line",
    [
        'dscl . -create "/Users/$SERVICE_USER" UniqueID "$USER_UID"',
        'assert any("/Users/_udbmcp" in ln for ln in actions)',
        "docker cp db2fixture:/home/db2inst1/server.crt .",
        "Manual certificate copy uses /home/db2inst1; the image's instance home is elsewhere",
        "password_file: /home/<you>/.universal-db-mcp/secrets/legacy_ora.password",
        '"other-config": block.replace(FAKE_CONFIG, "/home/me/.universal-db-mcp/config.yaml"),',
        'windows = "C:\\\\Users\\\\me\\\\AppData\\\\Roaming"',
        "password_file: out/mockdb-secrets/pg.pw",
        "/etc/universal-db-mcp/config.yaml",
        # Profile folders every Windows or macOS machine has, and a hosted runner's home.
        r"# not the path's spelling: C:\Users\All Users (a link)",
        r'"C:\\Users\\All Users\\universal-db-mcp"',
        r"C:\Users\Public\Documents",
        r"C:\Users\Default\NTUSER.DAT",
        r"c:\users\default user\appdata",
        "/Users/Shared/udbmcp",
        "/home/runner/work/universalDB-MCP/universalDB-MCP",
        "/Users/runner/work/x",
        "/home/udbmcp/.config",
        # A URL's path, and prose that is not a flattened project dir.
        "https://example.com/Users/list",
        "see https://github.com/org/repo/tree/main/home/docs",
        "a work-from-home-policy-draft",
    ],
)
def test_the_private_path_scan_allows_made_up_container_and_service_accounts(line: str) -> None:
    assert not _private_paths(line)


def _tree_files(root: Path = REPO) -> list[str]:
    """Tracked files plus untracked files git would pick up (not ignored)."""
    git = shutil.which("git")
    if git is None or not (root / ".git").exists():
        pytest.skip("needs a git checkout to list the tree")
    proc = subprocess.run(  # noqa: S603 - fixed argv, read-only git query
        [git, "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
        timeout=60,
    )
    return sorted({name for name in proc.stdout.decode("utf-8").split("\0") if name})


def test_no_file_in_the_tree_carries_a_developer_home_or_agent_scratch_path() -> None:
    this_file = Path(__file__).resolve().relative_to(REPO).as_posix()
    hits: list[str] = []
    for name in _tree_files():
        path = REPO / name
        if name == this_file or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary (fonts, images)
        for lineno, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), start=1):
            if _private_paths(line):
                hits.append(f"{name}:{lineno}: {line.strip()[:160]}")
    assert not hits, "developer or scratch paths in the tree:\n" + "\n".join(hits)


def _path_values(node: Any, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _path_values(v, str(k))
    elif isinstance(node, list):
        for v in node:
            yield from _path_values(v, key)
    elif isinstance(node, str) and (key.endswith("_path") or key.endswith("_file")):
        yield key, node


@pytest.mark.parametrize("config_name", MOCK_CONFIGS)
def test_mock_configs_name_only_paths_relative_to_the_checkout(config_name: str) -> None:
    raw = yaml.safe_load((REPO / config_name).read_text(encoding="utf-8"))
    paths = list(_path_values(raw))
    assert any(key == "password_file" for key, _ in paths)
    for key, value in paths:
        assert not Path(value).is_absolute() and not value.startswith("~"), f"{config_name}: {key}: {value}"


def _run_fixture_script(tmp_path: Path) -> tuple[Path, str, str]:
    """Run a copy of the fixture script in a fresh checkout under tmp_path with
    a fake docker that only logs its arguments. Returns (checkout, docker log,
    the script's output)."""
    checkout = tmp_path / "checkout"
    (checkout / FIXTURE_SCRIPT.parent).mkdir(parents=True)
    shutil.copy2(REPO / FIXTURE_SCRIPT, checkout / FIXTURE_SCRIPT)
    shutil.copytree(REPO / FIXTURE_SCRIPT.parent / "seed", checkout / FIXTURE_SCRIPT.parent / "seed")
    for name in MOCK_CONFIGS:
        shutil.copy2(REPO / name, checkout / name)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$FAKE_DOCKER_LOG"\nexit 0\n', encoding="utf-8")
    docker.chmod(0o755)
    log = tmp_path / "docker.log"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        "FAKE_DOCKER_LOG": str(log),
    }
    bash = shutil.which("bash")
    assert bash is not None
    proc = subprocess.run(  # noqa: S603 - fixed argv, script copied under tmp_path
        [bash, str(checkout / FIXTURE_SCRIPT)], env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return checkout, log.read_text(encoding="utf-8"), proc.stdout


@_POSIX_ONLY
def test_a_fresh_checkout_loads_the_mock_configs_with_the_secrets_the_fixture_script_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout, _, _ = _run_fixture_script(tmp_path)
    secrets = checkout / "out" / "mockdb-secrets"
    assert secrets.is_dir(), "start_mock_dbs.sh must write the secret files the mock config reads"
    for secret in secrets.iterdir():
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600, secret.name

    # The resolved passwords are what the fixture script wrote into this
    # checkout, not files at some other machine's absolute path.
    monkeypatch.setattr(redact, "_REGISTERED_SECRETS", [])
    monkeypatch.chdir(checkout)
    for env in ("PG", "MYSQL", "CH", "ORA", "MSSQL", "DB2"):
        monkeypatch.setenv(f"UDBMCP_DEMO_{env}_USER", f"ci_hygiene_{env.lower()}")
    for config_name in MOCK_CONFIGS:
        _, resolved = load_resolved(checkout / config_name)
        assert resolved
        for name, conn in resolved.items():
            assert conn.config.password_file is not None and conn.password is not None
            expected = (secrets / Path(conn.config.password_file).name).read_text(encoding="utf-8")
            assert conn.password.value == expected, f"{config_name}: {name}"


def _sqlcmd_statements(log: str) -> list[str]:
    """Every T-SQL statement the fixture script passes to sqlcmd -Q, with the
    brackets and double quotes around names dropped, whitespace collapsed and
    case folded."""
    statements: list[str] = []
    for line in log.splitlines():
        if "sqlcmd" in line and " -Q " in line:
            for statement in line.split(" -Q ", 1)[1].split(";"):
                normalized = " ".join(re.sub(r'[\[\]"]', "", statement).split()).casefold()
                if normalized:
                    statements.append(normalized)
    return statements


@_POSIX_ONLY
def test_the_mock_sql_server_connection_logs_in_as_a_db_datareader_login_not_sa(tmp_path: Path) -> None:
    checkout, log, _ = _run_fixture_script(tmp_path)
    sa_password = re.search(r"MSSQL_SA_PASSWORD=(\S+)", log)
    login = re.search(r"CREATE LOGIN (\w+) WITH PASSWORD = N'([^']+)'", log)
    assert sa_password is not None and login is not None, log
    reader, reader_password = login.groups()
    assert reader.lower() != "sa"

    # The reader gets exactly these, in any spelling: a login, its database
    # user, db_datareader, and SHOWPLAN (read-only, no data access) so that
    # db_explain works. Any other GRANT, role membership or sp_add*member
    # (e.g. sysadmin, db_owner, CONTROL SERVER, INSERT on a schema) fails.
    who = re.escape(reader.casefold())
    allowed = {
        "login": rf"create login {who} with password = n'[^']+'",
        "user": rf"create user {who} for login {who}",
        "db_datareader": rf"alter role db_datareader add member {who}",
        "showplan": rf"grant showplan to {who}",
    }
    privileged = re.compile(rf"\b{who}\b|\bgrant\b|\bsp_add\w*|\balter\s+(server\s+)?role\b")
    granted: set[str] = set()
    for statement in _sqlcmd_statements(log):
        if not privileged.search(statement):
            continue
        kinds = [kind for kind, pattern in allowed.items() if re.fullmatch(pattern, statement)]
        assert kinds, f"the reader's setup has an unexpected statement: {statement}"
        granted.update(kinds)
    assert granted == set(allowed), granted
    seed = (REPO / FIXTURE_SCRIPT.parent / "seed" / "mssql_hospital.sql").read_text(encoding="utf-8")
    assert not re.search(r"\bgrant\b|\bsp_add\w*|\balter\s+(server\s+)?role\b", seed, re.I)

    mssql = load_config(checkout / "config.mockdbs.yaml").connections["mock_mssql"]
    assert mssql.password_file is not None
    written = (checkout / "out" / "mockdb-secrets" / Path(mssql.password_file).name).read_text(encoding="utf-8")
    assert written == reader_password
    assert written != sa_password.group(1)


@_POSIX_ONLY
def test_the_fixture_script_prints_the_user_names_the_mock_configs_read(tmp_path: Path) -> None:
    # config.mockdbs.yaml names no users (username_env), so the script says
    # which to export; after this change SQL Server's is the reader login, not sa.
    _, log, output = _run_fixture_script(tmp_path)
    exported = dict(re.findall(r"\b(UDBMCP_DEMO_\w+_USER)=(\S+)", output))
    for config_name in MOCK_CONFIGS:
        for conn in load_config(REPO / config_name).connections.values():
            assert conn.username_env in exported, f"{config_name}: {conn.username_env} is not printed"
    for var, pattern in {
        "UDBMCP_DEMO_PG_USER": r"CREATE ROLE (\w+) LOGIN",
        "UDBMCP_DEMO_MYSQL_USER": r"MYSQL_USER=(\S+)",
        "UDBMCP_DEMO_MSSQL_USER": r"CREATE LOGIN (\w+) WITH PASSWORD",
    }.items():
        created = re.search(pattern, log)
        assert created is not None, pattern
        assert exported[var] == created.group(1), var
    assert exported["UDBMCP_DEMO_MSSQL_USER"].lower() != "sa"


# ------------------------------------------------------------------ F64: CI workflow and action hygiene


class _UniqueKeyLoader(yaml.SafeLoader):
    """A SafeLoader that refuses a mapping with a repeated key. PyYAML keeps
    the last one; whichever one GitHub reads, this test must read the same."""


def _unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    keys = [loader.construct_object(key, deep=True) for key, _ in node.value]
    repeated = sorted({str(key) for key in keys if keys.count(key) > 1})
    assert not repeated, f"line {node.start_mark.line + 1}: repeated keys {repeated}"
    return loader.construct_mapping(node, deep=True)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _load_yaml(text: str) -> Any:
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass


def _workflows() -> dict[str, dict[str, Any]]:
    found = {p.name: _load_yaml(p.read_text(encoding="utf-8")) for p in sorted(WORKFLOWS.glob("*.y*ml"))}
    assert found, "no workflows"
    return found


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    assert isinstance(on, dict)
    return on


def _steps(workflow: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for job in workflow["jobs"].values():
        yield from job.get("steps", [])


def _gating_workflows() -> dict[str, dict[str, Any]]:
    return {name: wf for name, wf in _workflows().items() if {"push", "pull_request"} <= set(_triggers(wf))}


def _strings(node: object) -> Iterator[str]:
    """Every string in parsed YAML, keys and values."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)
    elif isinstance(node, str):
        yield node


def _script(run: object) -> str:
    """A step's script, one command per line: continuations joined, indentation
    and repeated blanks dropped."""
    lines = re.sub(r"\\\n", " ", str(run)).splitlines()
    return "\n".join(" ".join(line.split()) for line in lines if line.strip())


# Everything the gating job runs, each script exactly as written: an added
# flag ('-k', '--ignore', '--exit-zero', '--fix', '--ignore-vuln'), a prefix
# ('echo', '!'), a wrapper ('|| true', 'if ...; then :; fi') or another
# command in the step changes the script and fails the test, and so does a
# step that runs anything else. Changing CI's commands means changing these.
# The install: the locked project, then pip from one exact, hashed pin
# (`uv sync` makes a venv without pip, and the bundle builder's tests need it).
_CI_PIP = ".github/ci-pip-requirements.txt"
_INSTALL = (
    "uv sync --locked --all-extras\n"
    f"uv pip install --python .venv/bin/python --require-hashes -r {_CI_PIP}"
)
# The unit suite runs in two jobs at once. 'checks' runs tests/unit without the
# files it --ignore's, then the other checks; 'installer-tests' runs exactly
# those files. The two lists must name the same files, each once, so every test
# runs once; a test file in neither list runs in 'checks'.
_JOBS = ("checks", "installer-tests")
_UNIT_RUN = re.compile(r"\.venv/bin/python -m pytest tests/unit((?: --ignore=tests/unit/test_\w+\.py)+)")
_SPLIT_RUN = re.compile(r"\.venv/bin/python -m pytest((?: tests/unit/test_\w+\.py)+)")
_CHECKS = (
    ".venv/bin/ruff check src tests scripts",
    ".venv/bin/mypy --strict src",
    ".venv/bin/python scripts/prepare_offline_bundle.py --check-locks",
)
# The audit: everything uv.lock installs (every extra, the test and lint
# tools too), CI's pip, then every lock the offline bundle ships, one
# pip-audit each. The version and the date admit no shell ('||true', '$(...)').
_VERSION = r"\d+(?:\.\d+)*"
_TIMESTAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
_AUDIT = re.compile(
    r"uv export --locked --no-emit-project --format requirements-txt --all-extras"
    r' > "\$RUNNER_TEMP/ci-requirements\.txt"\n'
    r'for requirements in "\$RUNNER_TEMP/ci-requirements\.txt" '
    rf"{re.escape(_CI_PIP)} requirements/locks/\*\.txt; do\n"
    rf"uvx --from pip-audit=={_VERSION} --exclude-newer {_TIMESTAMP}"
    r' pip-audit --strict --require-hashes --disable-pip -r "\$requirements"\n'
    r"done"
)
# The one condition a step may carry: a check runs after an earlier check
# failed, as long as the install worked and the run was not cancelled.
_AFTER_THE_INSTALL = "${{ !cancelled() && steps.sync.outcome == 'success' }}"
# The keys the gating workflow, its jobs and its steps may carry: none that
# could swallow a check's exit status, skip it or change what it runs. That
# leaves out env at every level (BASH_ENV runs a file before each script, e.g.
# "trap 'exit 0' EXIT"; PYTEST_ADDOPTS, SHELLOPTS, UV_*), defaults (a 'bash {0}'
# shell drops -e), continue-on-error, a job's if, container and services (another
# image's shell), a step's shell and working-directory.
_WORKFLOW_KEYS = frozenset({"name", "on", True, "permissions", "concurrency", "jobs"})  # YAML 1.1: on is True
_JOB_KEYS = frozenset({"name", "runs-on", "timeout-minutes", "permissions", "steps"})
# A GitHub-hosted runner of the offline bundle's target profile, whose image
# ships the pwsh the MSI custom-action tests run under; a self-hosted runner's
# .env file sets variables such as BASH_ENV for every step.
_RUNNER = "ubuntu-24.04"
_RUN_STEP_KEYS = frozenset({"name", "id", "if", "timeout-minutes", "run"})
_USES_STEP_KEYS = frozenset({"name", "id", "uses", "with"})
# The actions the job uses before its own scripts, with the inputs each gets
# (GitHub passes each as a string), every one and nothing else: a checkout
# 'ref' or 'repository' would test other code than the pushed commit, and a
# 'path' or 'sparse-checkout' another tree; uv is one release checked against
# its published checksum, on the target profile's Python, with no cache a
# pull request could have written. Each is the reviewed commit of its release
# (checkout v7.0.1, setup-uv v10.2.0): these run before every check and could
# append BASH_ENV to $GITHUB_ENV, so another SHA, a Dependabot bump too, fails
# here until someone reviews that commit and puts it here.
_SETUP_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": {"persist-credentials": "false"},
    "astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7": {
        "version": r"\d+\.\d+\.\d+",
        "checksum": "[0-9a-f]{64}",
        "python-version": r"3\.12",
        "enable-cache": "false",
    },
}


def _assert_keys(where: str, node: dict[Any, Any], allowed: frozenset[Any]) -> None:
    extra = set(node) - allowed
    assert not extra, f"{where}: {sorted(map(str, extra))} (allowed: {sorted(map(str, allowed))})"


def _assert_the_workflow_gates_every_change(name: str, text: str) -> None:
    # Printable ASCII and newlines only. This test's parser (YAML 1.1) ends a
    # line at NEL, LS and PS, which YAML 1.2 keeps as text, and _script splits
    # on Unicode spaces, which bash keeps inside a word: either could hide a
    # '|| true' from this test that GitHub's runner still executes.
    # The same for the parsed values, which a double-quoted scalar's escapes
    # ('\_' is a no-break space, '\N' a NEL) can fill from ASCII text.
    ascii_text = re.compile(r"[ -~\n]*")
    assert ascii_text.fullmatch(text), f"{name}: a character other than printable ASCII or a newline"
    wf = _load_yaml(text)
    escaped = [value for value in _strings(wf) if not ascii_text.fullmatch(value)]
    assert not escaped, f"{name}: a value with a character other than printable ASCII or a newline: {escaped}"
    # Every pull request, whatever its base branch, on every activity that
    # brings new code; and every push to main (no '!main' after it)...
    push, pull_request = (_triggers(wf)[event] or {} for event in ("push", "pull_request"))
    assert not pull_request, f"{name}: pull_request is filtered: {pull_request}"
    branches = push.get("branches", ["main"])
    assert set(push) <= {"branches"} and isinstance(branches, list), f"{name}: push: {push}"
    assert "main" in branches and not any(str(b).startswith("!") for b in branches), f"{name}: push: {push}"
    # ...and a failing check fails the run: nothing swallows its exit status,
    # skips it or narrows it. The default shell is 'bash -e' in the checkout's root.
    _assert_keys(name, wf, _WORKFLOW_KEYS)
    # Two jobs, each of which sets up, installs, then runs its checks in this
    # order: a check's condition reads the install's outcome from its own job's
    # steps, and before the install ran, or in another job, that is null and
    # the check is skipped.
    assert sorted(wf["jobs"]) == sorted(_JOBS), f"{name}: jobs {sorted(wf['jobs'])}, not {sorted(_JOBS)}"
    runs = {job_name: _job_runs(f"{name}:{job_name}", job) for job_name, job in wf["jobs"].items()}
    setup = [*_SETUP_ACTIONS, _INSTALL]
    checks, split = runs["checks"], runs["installer-tests"]
    unit = _UNIT_RUN.fullmatch(checks[len(setup)]) if len(checks) > len(setup) else None
    listed = _SPLIT_RUN.fullmatch(split[len(setup)]) if len(split) > len(setup) else None
    assert unit, f"{name}:checks: no unit test step of the form {_UNIT_RUN.pattern}: {checks}"
    assert listed, f"{name}:installer-tests: no test step of the form {_SPLIT_RUN.pattern}: {split}"
    expected = [*setup, unit.group(0), *_CHECKS, _AUDIT.pattern]
    assert checks == expected, f"{name}:checks: runs {checks}, not {expected}"
    assert split == [*setup, listed.group(0)], f"{name}:installer-tests: runs {split}"
    # Every test runs once: checks leaves out exactly the files installer-tests runs.
    ignored = unit.group(1).replace("--ignore=", "").split()
    files = listed.group(1).split()
    assert len(set(ignored)) == len(ignored) and len(set(files)) == len(files), f"{name}: a file is named twice"
    assert set(ignored) == set(files), (
        f"{name}: checks leaves out {sorted(set(ignored) - set(files))} that installer-tests does not run,"
        f" and installer-tests runs {sorted(set(files) - set(ignored))} that checks runs too"
    )
    missing = [file for file in files if not (REPO / file).is_file()]
    assert not missing, f"{name}: installer-tests names files that do not exist: {missing}"


def _job_runs(where: str, job: dict[str, Any]) -> list[str]:
    """What one job runs, step by step, after checking that nothing in the job
    can skip a step, swallow its exit status or change what it runs."""
    _assert_keys(where, job, _JOB_KEYS)
    assert job.get("runs-on") == _RUNNER, f"{where}: runs-on {job.get('runs-on')!r}, not {_RUNNER}"
    runs: list[str] = []
    for step in job.get("steps", []):
        label = f"{where}: {step.get('name', step.get('uses', step.get('run')))}"
        if "uses" in step:
            _assert_keys(label, step, _USES_STEP_KEYS)
            action = str(step["uses"])
            assert action in _SETUP_ACTIONS, f"{label}: not a reviewed setup action"
            inputs, patterns = step.get("with") or {}, _SETUP_ACTIONS[action]
            _assert_keys(f"{label}: with", inputs, frozenset(patterns))
            for key, pattern in patterns.items():
                value = inputs.get(key)
                value = str(value).lower() if isinstance(value, bool) else value
                assert isinstance(value, str) and re.fullmatch(pattern, value), f"{label}: with: {key}: {value!r}"
            runs.append(action)
            continue
        _assert_keys(label, step, _RUN_STEP_KEYS)
        script = _script(step.get("run", ""))
        if script == _INSTALL:
            # The checks' condition reads this step's outcome by its id.
            assert step.get("id") == "sync" and "if" not in step, label
        else:
            assert step.get("if", _AFTER_THE_INSTALL) == _AFTER_THE_INSTALL, f"{label}: if: {step['if']}"
        runs.append(_AUDIT.pattern if _AUDIT.fullmatch(script) else script)
    return runs


# The files pytest reads its options from, in the order it looks for them in
# each directory from the tests' common ancestor up: for CI's 'pytest
# tests/unit', tests/unit, tests, then the root. A pytest.ini or pytest.toml
# there (even empty) replaces pyproject.toml; tox.ini and setup.cfg count with
# their pytest section. Which of them configure pytest, and with what, is
# what pytest's own loader says: its ini parser also ends a line at FF, VT, RS
# or NEL, and pyproject.toml's [tool.pytest] wins over an empty
# [tool.pytest.ini_options].
_PYTEST_CONFIG_FILES = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)
# The options pytest's config may set: none that narrows collection (-m, -k,
# --lf, -p no:..., -c, -o, python_files, python_functions, norecursedirs) or
# puts another tree first on sys.path (pythonpath). addopts may only change
# what pytest prints.
_PYTEST_OPTIONS = frozenset({"testpaths", "addopts", "markers", "minversion", "filterwarnings", "xfail_strict"})
_PYTEST_ADDOPT = re.compile(r"-q+|-v+|-r\w+|--strict-markers|--strict-config|--tb=\w+|--durations=\d+")


# What pytest reads from a conftest besides fixtures: collection settings and
# hooks (pytest_collection_modifyitems, pytest_sessionfinish, ...), any of
# which could deselect a test or turn a failure into exit 0. A support module
# (a conftest, or a module under tests/ that pytest collects no tests from,
# such as a helper, which a conftest can import) may not bind one of these
# names or import one from a module (a star import could), spell one in a
# string or bytes (a dotted 'conftest.collect_ignore', which MonkeyPatch.setattr
# resolves, too), or write a module's namespace (globals(), setattr(sys.modules
# [...]), a frame's f_globals, a function's __globals__, ...) or run code from
# a string, which could build one at run time in its own or a conftest's.
_CONFTEST_HOOK = re.compile(r"pytest_\w*|collect_ignore\w*")
_SPELLED_HOOK = re.compile(rf"(?<!\w)(?:{_CONFTEST_HOOK.pattern})")
# These builtins by name, or as attributes (builtins.exec, a builtin
# function's __self__.globals)...
_NAMESPACE_BUILTINS = frozenset(
    {"globals", "vars", "locals", "setattr", "exec", "eval", "compile", "__import__", "__builtins__"}
)
# ...and these attributes, or names imported from their modules.
_NAMESPACE_ATTRIBUTES = frozenset(
    {"__dict__", "modules", "import_module", "getmodule", "f_globals", "f_locals", "f_builtins", "__globals__",
     "__self__"}
)
# Nor may a support module import a module that runs another file's code as a
# module (runpy, importlib and all of it, pkgutil, zipimport: a test module's
# autouse fixture, or a data file this gate and ruff never read), resolves a
# dotted name to any object (pydoc.locate('builtins.exec')) or runs code from
# a string or bytes (builtins, code, codeop, marshal, and pickle's GLOBAL, as
# shelve loads it). These lists name the routes known; a new one is suite
# code, reviewed as code.
_CODE_RUNNERS = frozenset(
    {"builtins", "runpy", "importlib", "pkgutil", "zipimport", "code", "codeop", "marshal", "pydoc", "pickle",
     "_pickle", "shelve"}
)
# What turns a failing run into exit 0 from inside it: pytest.exit(returncode=0)
# or os._exit(0) (e.g. in a session fixture's teardown), an os.exec* that
# replaces the pytest process, a session's exitstatus or its testsfailed count.
# No conftest or test module refers to one by name; a name built at run time
# (getattr(os, "_ex" + "it")) is suite code, reviewed as code.
_RUN_ENDERS = frozenset(
    {"exit", "_exit", "Exit", "exitstatus", "testsfailed"}
    | {"execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe"}
)
# A support module's `raise SystemExit` or `quit(0)` at import time (in a
# conftest, or a helper one imports) ends pytest with status 0 before
# collection finishes, running no test and printing nothing. A test module may
# name them: there pytest reports the exit as an error.
_SUPPORT_RUN_ENDERS = frozenset({"SystemExit", "quit"})
# What skips or xfails tests from a support module, a conftest's fixture or a
# helper one calls: pytest.skip, xfail or importorskip, a skip or xfail marker
# (add_marker("xfail") by its name too), or an exception pytest takes for a
# skip (unittest.SkipTest too). pytest still exits 0. A test module skips its
# own tests, where its reader sees it.
_SKIPPERS = frozenset({"skip", "skipif", "xfail", "importorskip", "Skipped", "XFailed", "SkipTest"})
# An autouse fixture in a support module runs for tests it never names, and
# drops one with no skip (request.node.obj = ..., an xfail in the test's
# stash): a support module has none, as a keyword or a string, and imports
# no test module, whose own autouse fixtures a conftest would run for every
# test below it, and none of pytest's internals (_pytest: the stash keys,
# the outcomes). Code outside tests/ (src/, scripts/, any other .py), which a
# conftest can import too, has no import of pytest and spells no autouse,
# however it would get pytest (__import__('pytest'), sys.modules). What
# a fixture does to a test that asks for it by name, and what a function
# does when a test or a fixture calls it, is suite code, reviewed as code.
# Except the test itself: a fixture can be requested for tests that never
# name it (anyio's plugin requests anyio_backend, which tests/conftest.py
# defines, for every anyio test), so a support module stores no attribute by
# the name pytest runs a test through (request.node.obj, runtest, function).
_AUTOUSE = "autouse"
_TEST_REPLACERS = frozenset({"obj", "_obj", "runtest", "function"})
_PYTEST_PACKAGES = frozenset({"pytest", "_pytest"})
# The modules pytest collects tests from: its default python_files, which the
# options above leave as it is.
_TEST_MODULES = ("test_*", "*_test")
# What Python runs at startup from any directory on sys.path (src/ is, through
# the editable install): 'import sitecustomize' finds a module or a package.
_STARTUP_HOOKS = ("sitecustomize*", "usercustomize*", "*.pth")
# The files Python imports as a module, a sourceless .pyc and an extension too.
_IMPORTABLE = (".py", ".pyw", ".pyc", ".so", ".pyd")
# Compiled code Python runs in place of the source beside it, the only file
# ruff and mypy read: an extension module wins over a .py of its name, and an
# unchecked-hash .pyc in __pycache__ is used without comparing it with the
# source. Anywhere in the tree, and pytest's cache (--lf, --sw) too.
_COMPILED = (".pyc", ".pyo", ".so", ".pyd")
_CACHE_DIRS = ("__pycache__", ".pytest_cache")
# The directories pytest's collection never enters: its default norecursedirs
# (the options below leave it as it is), and one that holds a virtualenv.
_PYTEST_SKIPPED_DIRS = ("*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}")
_VENV_MARKERS = ("pyvenv.cfg", "conda-meta/history")


def _in_dirs(name: str, patterns: Collection[str]) -> bool:
    """Whether a directory on a file's path matches one of the patterns."""
    return any(fnmatch.fnmatchcase(part, pattern) for part in name.split("/")[:-1] for pattern in patterns)


def _bound_names(tree: ast.AST, *, strings: bool) -> set[str]:
    """Every name a module defines, assigns or imports from another module
    (an 'import x' binds a module, which pytest never takes for a hook), and
    with strings every string or bytes constant it spells."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Store):
            names.add(node.id if isinstance(node, ast.Name) else node.attr)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif strings and isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            names.add(node.value if isinstance(node.value, str) else node.value.decode("utf-8", "replace"))
    return names


def _referenced_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    """The names (with the ones a module imports) and the attributes a module
    refers to."""
    names: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.alias):
            names.add(node.name.rpartition(".")[2])
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
    return names, attributes


def _imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    """The top-level packages a module imports from, and every part of each
    dotted name it imports ('from unit import test_x' may import a module)."""
    packages: set[str] = set()
    parts: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            dotted = [alias.name for alias in node.names]
            packages.update(name.partition(".")[0] for name in dotted)
        elif isinstance(node, ast.ImportFrom):
            dotted = [node.module or "", *(alias.name for alias in node.names)]
            if not node.level and node.module:
                packages.add(node.module.partition(".")[0])
        else:
            continue
        parts.update(part for name in dotted for part in name.split("."))
    return packages, parts


def _shadows(name: str, taken: set[str]) -> bool:
    """Whether a file is a module that `python -m pytest` (the root first on
    sys.path), `python scripts/x.py` (scripts/) or pytest's collection (each
    test directory) imports in place of a module Python or the venv has."""
    parent, _, file = name.rpartition("/")
    if not file.endswith(_IMPORTABLE):
        return False
    module = file.partition(".")[0]
    if module == "__init__":
        parent, _, module = parent.rpartition("/")
    return parent == "" or ((parent in ("scripts", "tests") or parent.startswith("tests/")) and module in taken)


def _assert_pytest_selects_every_test(root: Path, files: Collection[str]) -> None:
    # Nothing but pytest's own config decides what runs, or with what exit
    # status: no hook, skip or autouse fixture in a conftest or a helper under
    # tests/, no autouse fixture in any module but a test module, no plugin
    # that a test module or the project loads, no startup hook, no module that
    # replaces one pytest imports. The suite's own code is reviewed as code:
    # a name built at run time, a file written at run time, and what a
    # function outside tests/ does when a test or a fixture calls it.
    for name in files:
        if not name.endswith(".py"):
            continue
        path = root / name
        conftest = path.name == "conftest.py"
        suite = conftest or name.startswith("tests/")
        # The code Python runs: the source in the codec its coding line names.
        try:
            tree = ast.parse(path.read_bytes(), name)
        except SyntaxError:
            if suite:
                raise
            continue  # Python cannot import it either.
        packages, parts = _imports(tree)
        test_module = suite and not conftest and any(fnmatch.fnmatchcase(path.stem, p) for p in _TEST_MODULES)
        support = suite and not test_module
        names = _bound_names(tree, strings=not test_module)
        referenced, attributes = _referenced_names(tree)
        if not test_module:
            keywords = {node.arg for node in ast.walk(tree) if isinstance(node, ast.keyword) and node.arg}
            assert _AUTOUSE not in names | referenced | attributes | keywords, f"{name}: an autouse fixture"
        if not suite:
            assert not (found := sorted(packages & _PYTEST_PACKAGES)), f"{name}: imports {found} outside tests/"
            continue
        found = sorted(filter(_SPELLED_HOOK.search, names) if support else names & {"pytest_plugins"})
        assert not found, f"{name}: {found}"
        stars = [
            node.lineno for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.names[0].name == "*"
        ]
        assert not stars, f"{name}: a star import on line {stars}"
        assert not (found := sorted((referenced | attributes) & _RUN_ENDERS)), f"{name}: ends the run: {found}"
        if support:
            found = sorted(
                (referenced | attributes) & (_NAMESPACE_BUILTINS | _NAMESPACE_ATTRIBUTES) | packages & _CODE_RUNNERS
            )
            assert not found, f"{name}: writes names or runs code at run time: {found}"
            found = sorted((referenced | attributes) & _SUPPORT_RUN_ENDERS)
            assert not found, f"{name}: ends the run at import: {found}"
            stored = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store)}
            assert not (found := sorted(stored & _TEST_REPLACERS)), f"{name}: replaces a test: {found}"
            found = sorted((names | referenced | attributes) & _SKIPPERS)
            assert not found, f"{name}: skips or xfails tests: {found}"
            found = sorted(
                {part for part in parts for pattern in _TEST_MODULES if fnmatch.fnmatchcase(part, pattern)}
                | packages & {"_pytest"}
            )
            assert not found, f"{name}: imports a test module or pytest's internals: {found}"
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8")).get("project", {})
    assert "pytest11" not in project.get("entry-points", {}), "pyproject.toml registers a pytest plugin"
    # Startup code anywhere in the tree (a hatch dev-mode-dirs or force-include
    # could put any directory on sys.path), and a venv committed beside it,
    # whose site-packages `uv sync` keeps.
    startup = [
        name
        for name in files
        if name.startswith(".venv/")
        or any(fnmatch.fnmatchcase(part, pattern) for part in name.split("/") for pattern in _STARTUP_HOOKS)
    ]
    assert not startup, f"code Python runs at startup, or a committed venv: {startup}"
    compiled = [name for name in files if name.endswith(_COMPILED) or _in_dirs(name, _CACHE_DIRS)]
    assert not compiled, f"compiled code or a cache Python or pytest reads in place of the source: {compiled}"
    taken = {*sys.stdlib_module_names, *importlib.metadata.packages_distributions(), "universal_db_mcp"}
    assert not (shadowing := sorted(name for name in files if _shadows(name, taken))), f"shadowing: {shadowing}"
    # A test module where pytest's collection never looks.
    unvisited = [
        name
        for name in files
        if (name.startswith("tests/") and _in_dirs(name, _PYTEST_SKIPPED_DIRS))
        or any(name == marker or name.endswith(f"/{marker}") for marker in _VENV_MARKERS)
    ]
    assert not unvisited, f"in a directory pytest does not collect from: {unvisited}"

    configs = {
        name: config
        for name in sorted(files)
        if PurePosixPath(name).name in _PYTEST_CONFIG_FILES
        and ("/" not in name or name.startswith("tests/"))
        and (config := load_config_dict_from_file(root / name)) is not None
    }
    assert list(configs) == ["pyproject.toml"], (
        f"pytest reads its options from {list(configs)}, not pyproject.toml alone"
    )
    options = {key: config.value for key, config in configs["pyproject.toml"].items()}
    assert set(options) <= _PYTEST_OPTIONS, f"pytest options {sorted(set(options) - _PYTEST_OPTIONS)}"
    addopts = options.get("addopts", [])
    assert isinstance(addopts, str | list), f"pytest addopts {addopts!r}"
    for option in shlex.split(addopts) if isinstance(addopts, str) else addopts:
        assert isinstance(option, str) and _PYTEST_ADDOPT.fullmatch(option), f"pytest addopts {option!r}"
    # A warning filter's category with a module path imports that module.
    filters = options.get("filterwarnings", [])
    assert isinstance(filters, str | list), f"pytest filterwarnings {filters!r}"
    for spec in filters.splitlines() if isinstance(filters, str) else filters:
        category = (str(spec).split(":") + ["", "", ""])[2].strip()
        assert re.fullmatch(r"(?:pytest\.)?\w*", category), f"pytest filterwarnings {spec!r}"


# The config ruff and mypy read is pyproject.toml's, and ruff's for scripts/
# also the file-scoped waivers in scripts/ruff.toml. A root mypy.ini or
# .mypy.ini replaces [tool.mypy] (ignore_errors = True turns `mypy --strict
# src` green); ruff reads the nearest ruff.toml, .ruff.toml or pyproject.toml
# with [tool.ruff] above each file it checks.
_MYPY = {"python_version": "3.12", "strict": True, "mypy_path": "src"}
_RUFF_KEYS = frozenset({"line-length", "target-version", "src", "lint"})
_RUFF_LINT_KEYS = frozenset({"select", "extend-select", "ignore", "per-file-ignores"})
_RUFF_SELECT = frozenset({"E", "F", "I", "UP", "B", "S", "ASYNC"})
# A waiver names one rule, never 'ALL' or a whole family such as 'S'.
_RUFF_RULE = re.compile(r"[A-Z]+\d{3,4}")
# What `ruff check src tests scripts` and `mypy --strict src` read.
_CHECKED = ("src/", "tests/", "scripts/")
_SOURCES = (".py", ".pyi", ".ipynb")
# The directories ruff leaves out by default (its exclude list) and the ones
# mypy never enters (dot-directories, __pycache__, site-packages,
# node_modules): a module there goes unchecked and still imports.
_UNCHECKED_DIRS = (
    ".*",
    "__pycache__",
    "__pypackages__",
    "_build",
    "buck-out",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
)
# A cache that calls a module unchanged and clean: mypy trusts an entry whose
# hash and size match, whatever the checkout's mtimes.
_TOOL_CACHES = (".mypy_cache", ".ruff_cache")
# The codecs Python reads a source file in that ruff reads it in too.
_UTF_8 = ("utf-8", "utf-8-sig")


def _source_codec(path: Path) -> str:
    """The codec Python reads a source file in (PEP 263)."""
    with path.open("rb") as source:
        return tokenize.detect_encoding(source.readline)[0]


def _ignored_by_git(root: Path, names: Sequence[str]) -> list[str]:
    """The names the checkout's .gitignore files match, as git reads them (a
    pattern for a leading directory too, a tracked file too), with no one's
    global excludes: ruff skips each of them."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git to read .gitignore")
    with tempfile.TemporaryDirectory() as scratch:
        # A repository of its own, without templates, so only the checkout's files count.
        subprocess.run(  # noqa: S603 - fixed argv, an empty repository under a temp dir
            [git, "init", "-q", "--bare", "--template=", scratch], check=True, capture_output=True, timeout=60
        )
        proc = subprocess.run(  # noqa: S603 - fixed argv, read-only git query
            [git, "-c", f"core.excludesFile={os.devnull}", f"--git-dir={scratch}", f"--work-tree={root}"]
            + ["check-ignore", "--no-index", "--stdin", "-z"],
            input="".join(f"{name}\0" for name in names).encode("utf-8"),
            capture_output=True,
            timeout=60,
        )
    assert proc.returncode in (0, 1), proc.stderr.decode("utf-8", "replace")  # 1: nothing is ignored
    return sorted(filter(None, proc.stdout.decode("utf-8").split("\0")))


def _assert_ruff_and_mypy_report_every_error(root: Path, files: Collection[str]) -> None:
    others = [
        name
        for name in files
        if (PurePosixPath(name).name in ("ruff.toml", ".ruff.toml") and name != "scripts/ruff.toml")
        or name in ("mypy.ini", ".mypy.ini")
        or (name == "setup.cfg" and re.search(r"^\[mypy", (root / name).read_text(encoding="utf-8"), re.M))
        or (
            name.endswith("/pyproject.toml")
            and "ruff" in tomllib.loads((root / name).read_text(encoding="utf-8")).get("tool", {})
        )
    ]
    assert not others, f"ruff or mypy config besides pyproject.toml and scripts/ruff.toml: {others}"
    # Code the checks never read, or read something else in place of: a
    # module in a directory ruff or mypy skip; an ignore file, which ruff
    # honours even for a tracked file (.ignore, which git does not read, and
    # .gitignore below); a stub, which mypy checks in place of the .py beside
    # it, or takes a library's types from; another module in src/, which mypy
    # (mypy_path) reads before the venv; a tool's cache.
    unchecked = [
        name
        for name in files
        if (name.startswith(_CHECKED) and _in_dirs(name, _UNCHECKED_DIRS))
        or PurePosixPath(name).name == ".ignore"
        or name.endswith(".pyi")
        or (name.startswith("src/") and not name.startswith("src/universal_db_mcp/"))
        or _in_dirs(name, _TOOL_CACHES)
    ]
    assert not unchecked, f"code ruff or mypy leave unchecked, or read in its place: {unchecked}"
    # ruff reads every file as UTF-8, and Python in the codec a coding line on
    # its first two lines names: in UTF-7, what ruff reads as a comment is code.
    encoded = [
        name
        for name in files
        if name.startswith(_CHECKED) and name.endswith(".py") and _source_codec(root / name) not in _UTF_8
    ]
    assert not encoded, f"code Python reads in another codec than ruff's UTF-8: {encoded}"
    if any(PurePosixPath(name).name == ".gitignore" for name in files):
        sources = [name for name in files if name.startswith(_CHECKED) and name.endswith(_SOURCES)]
        assert not (ignored := _ignored_by_git(root, sources)), f"code .gitignore hides from ruff: {ignored}"
    tool = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]
    assert tool.get("mypy") == _MYPY, f"[tool.mypy] {tool.get('mypy')}, not {_MYPY}"
    ruff = tool.get("ruff", {})
    lint = ruff.get("lint", {})
    _assert_keys("[tool.ruff]", ruff, _RUFF_KEYS)
    _assert_keys("[tool.ruff.lint]", lint, _RUFF_LINT_KEYS)
    assert ruff.get("line-length", 88) <= 120, f"[tool.ruff] line-length {ruff['line-length']}"
    assert _RUFF_SELECT <= set(lint.get("select", [])), f"[tool.ruff.lint] select {lint.get('select')}"
    waived = [*lint.get("ignore", []), *(rule for rules in lint.get("per-file-ignores", {}).values() for rule in rules)]
    scripts = tomllib.loads((root / "scripts" / "ruff.toml").read_text(encoding="utf-8"))
    assert set(scripts) == {"extend", "lint"}, f"scripts/ruff.toml {sorted(scripts)}"
    assert scripts["extend"] == "../pyproject.toml", f"scripts/ruff.toml extends {scripts['extend']!r}"
    assert set(scripts["lint"]) == {"per-file-ignores"}, f"scripts/ruff.toml [lint] {sorted(scripts['lint'])}"
    for pattern, rules in scripts["lint"]["per-file-ignores"].items():
        # A waiver there names one file, never a directory or a glob.
        assert f"scripts/{pattern}" in files, f"scripts/ruff.toml: {pattern} is not a file in scripts/"
        waived += rules
    broad = sorted({rule for rule in waived if not _RUFF_RULE.fullmatch(rule)})
    assert not broad, f"ruff waivers of more than one rule: {broad}"


# What `uv sync` runs: hatchling, from the index under the pinned build
# constraints, builds this package, and every other package is a file from
# PyPI of that project with the lock's hash. Code from the checkout that ran
# during the install (a hatch build or metadata hook, an in-tree backend, a
# path dependency) could append BASH_ENV or PYTEST_ADDOPTS to $GITHUB_ENV for
# every later step.
_HATCHLING = re.compile(r"hatchling(?:(?:[<>]=?|[=!~]=)[\d.]+)?(?:,(?:[<>]=?|[=!~]=)[\d.]+)*")
_HATCH = {"build": {"targets": {"wheel": {"packages": ["src/universal_db_mcp"]}}}}
_PINNED = re.compile(r"[A-Za-z0-9][\w.-]*==[\w.]+")
_PYPI_FILES = "https://files.pythonhosted.org/packages/"
# What pip and uv install a package from: a wheel, an egg or an sdist. They
# take one from the checkout only through a find-links, a path or a file: URL,
# which the checks here admit none of; the tree carries none either.
_PACKAGE_ARCHIVES = (".whl", ".egg", ".zip", ".tar", ".tgz", ".tbz", ".txz", ".tlz") + tuple(
    f".tar.{compression}" for compression in ("gz", "bz2", "xz", "zst", "lz", "lzma")
)


def _distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _assert_the_install_runs_no_code_from_the_checkout(root: Path, files: Collection[str]) -> None:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    build = pyproject.get("build-system", {})
    assert set(build) == {"requires", "build-backend"}, f"[build-system] {sorted(build)}"
    assert build["build-backend"] == "hatchling.build", f"[build-system] build-backend {build['build-backend']!r}"
    requires = build["requires"]
    assert len(requires) == 1 and _HATCHLING.fullmatch(requires[0]), f"[build-system] requires {requires}"
    assert pyproject["tool"].get("hatch") == _HATCH, f"[tool.hatch] {pyproject['tool'].get('hatch')}, not {_HATCH}"
    uv = pyproject["tool"].get("uv", {})
    _assert_keys("[tool.uv]", uv, frozenset({"build-constraint-dependencies"}))
    loose = [pin for pin in uv.get("build-constraint-dependencies", []) if not _PINNED.fullmatch(pin)]
    assert not loose, f"[tool.uv] build constraints that pin no one release: {loose}"
    # hatchling also reads a hatch.toml beside pyproject.toml, and uv a uv.toml.
    assert not (found := sorted({"hatch.toml", "uv.toml"} & set(files))), f"build config: {found}"
    archives = sorted(name for name in files if name.lower().endswith(_PACKAGE_ARCHIVES))
    assert not archives, f"package archives in the tree: {archives}"
    project = _distribution(pyproject["project"]["name"])
    for package in tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))["package"]:
        name = _distribution(package["name"])
        source = {"editable": "."} if name == project else {"registry": "https://pypi.org/simple"}
        assert package.get("source") == source, f"uv.lock: {name}: source {package.get('source')}"
        for url in [wheel["url"] for wheel in package.get("wheels", [])] + [package.get("sdist", {}).get("url", "")]:
            file = url.rpartition("/")[2]
            sdist = re.sub(r"\.(?:tar\.gz|zip)$", "", file)
            owner = file.split("-")[0] if file.endswith(".whl") else sdist.rpartition("-")[0]
            assert not url or (url.startswith(_PYPI_FILES) and _distribution(owner) == name), f"uv.lock: {name}: {url}"


def _assert_the_checkout_runs_every_check(root: Path, files: Collection[str]) -> None:
    # No links: the checks above read each file by the name git lists, while
    # pytest collects through a link to a directory (with the plugins the
    # test modules behind it load), Python imports and mypy checks through
    # it, and ruff never lints what is behind it.
    links = sorted(name for name in files if (root / name).is_symlink())
    assert not links, f"links in the tree: {links}"
    _assert_pytest_selects_every_test(root, files)
    _assert_ruff_and_mypy_report_every_error(root, files)
    _assert_the_install_runs_no_code_from_the_checkout(root, files)


def test_a_workflow_runs_the_unit_suite_ruff_and_mypy_on_every_push_and_pull_request() -> None:
    gating = _gating_workflows()
    assert gating, "no workflow runs on both push and pull_request"
    for name in gating:
        _assert_the_workflow_gates_every_change(name, (WORKFLOWS / name).read_text(encoding="utf-8"))


_UNIT_STEP = "      - name: Unit tests\n"
_PYTEST_RUN = ".venv/bin/python -m pytest tests/unit \\\n"
# The last line of the checks job's unit test command, and the installer-tests job.
_LAST_IGNORE = "--ignore=tests/unit/test_hardening_gates.py\n"
_SPLIT_JOB = "  installer-tests:\n    runs-on: ubuntu-24.04\n"
_SPLIT_STEP = "      - name: Installer and packaging tests\n"
_SPLIT_PYTEST = ".venv/bin/python -m pytest \\\n"
_EXCLUDE_NEWER = "--exclude-newer 2026-09-27T00:00:00Z"
_PERMISSIONS = "permissions:\n  contents: read\n"
_CHECKOUT_WITH = "          persist-credentials: false\n"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (_UNIT_STEP, _UNIT_STEP + "        if: github.event_name == 'push'\n"),
        (_UNIT_STEP, _UNIT_STEP + "        if: ${{ !github.event.pull_request.head.repo.fork }}\n"),
        (_UNIT_STEP, _UNIT_STEP + "        env:\n          PYTEST_ADDOPTS: --collect-only\n"),
        (_PERMISSIONS, _PERMISSIONS + "\nenv:\n  PYTEST_ADDOPTS: --co\n"),
        ("    timeout-minutes: 45\n", "    timeout-minutes: 30\n    env:\n      UV_NO_SYNC: '1'\n"),
        (_PYTEST_RUN, _PYTEST_RUN.replace(" \\\n", " -k 'not guard' \\\n")),
        (_PYTEST_RUN, _PYTEST_RUN.replace(" \\\n", " --ignore=tests/unit/test_sql_guard.py \\\n")),
        (_PYTEST_RUN, "if " + _PYTEST_RUN),
        (_PYTEST_RUN, "! " + _PYTEST_RUN),
        (_LAST_IGNORE, _LAST_IGNORE.replace("\n", "; then :; fi\n")),
        (_LAST_IGNORE, _LAST_IGNORE.replace("\n", " && echo ok\n          echo done\n")),
        (_LAST_IGNORE, _LAST_IGNORE.replace("\n", " || true\n")),
        # The split: a file left out of checks that installer-tests does not run,
        # a file run by both, a narrowed or skipped installer-tests, a third job.
        ("            tests/unit/test_cr3_msi.py \\\n", ""),
        ("            --ignore=tests/unit/test_cr3_msi.py \\\n", ""),
        ("            tests/unit/test_cr3_msi.py \\\n", "            tests/unit/test_cr3_msj.py \\\n"),
        (_SPLIT_PYTEST, _SPLIT_PYTEST.replace(" \\\n", " -k 'not msi' \\\n")),
        (_SPLIT_PYTEST, _SPLIT_PYTEST.replace(" \\\n", " --collect-only \\\n")),
        (_SPLIT_STEP, _SPLIT_STEP + "        if: github.event_name == 'push'\n"),
        (_SPLIT_STEP, _SPLIT_STEP + "        continue-on-error: true\n"),
        (_SPLIT_JOB, _SPLIT_JOB + "    continue-on-error: true\n"),
        (_SPLIT_JOB, _SPLIT_JOB + "    if: false\n"),
        (_SPLIT_JOB, "  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo\n\n" + _SPLIT_JOB),
        (_UNIT_STEP, "      - run: rm tests/unit/test_sql_guard.py\n" + _UNIT_STEP),
        (_UNIT_STEP, "      - uses: ./.github/actions/prepare\n" + _UNIT_STEP),
        ("ruff check src tests scripts", "ruff check --exit-zero src tests scripts"),
        ("ruff check src tests scripts", "ruff check --fix src tests scripts"),
        ("run: .venv/bin/mypy", "run: echo .venv/bin/mypy"),
        ("run: .venv/bin/python scripts/prepare", "run: echo .venv/bin/python scripts/prepare"),
        ("pip-audit --strict", "pip-audit --ignore-vuln PYSEC-0000-0 --strict"),
        ('-r "$requirements"', '-r "$requirements" || true'),
        ("--all-extras \\\n", "--extra pg \\\n"),
        ("  pull_request:\n", "  pull_request:\n    types: [closed]\n"),
        ("  pull_request:\n", "  pull_request:\n    branches: [does-not-exist]\n"),
        ("    branches: [main]\n", "    branches: [release]\n"),
        ("        id: sync\n", "        id: install\n"),
        (
            "          uv sync --locked --all-extras\n",
            '          uv sync --locked --all-extras && echo X=1 >> "$GITHUB_ENV"\n',
        ),
        ("    timeout-minutes: 45\n", "    timeout-minutes: 30\n    continue-on-error: true\n"),
        (_UNIT_STEP, _UNIT_STEP + "        continue-on-error: true\n"),
        (_UNIT_STEP, _UNIT_STEP + "        shell: bash {0}\n"),
        (_UNIT_STEP, _UNIT_STEP + "        working-directory: site\n"),
        # A file bash sources before every script ("trap 'exit 0' EXIT"), at
        # any level, and other shell or tool settings.
        (_PERMISSIONS, _PERMISSIONS + "\nenv:\n  BASH_ENV: .github/ci-env.sh\n"),
        ("    timeout-minutes: 45\n", "    timeout-minutes: 30\n    env:\n      BASH_ENV: .github/ci-env.sh\n"),
        (_UNIT_STEP, _UNIT_STEP + "        env:\n          BASH_ENV: .github/ci-env.sh\n"),
        (_UNIT_STEP, _UNIT_STEP + "        env:\n          SHELLOPTS: posix\n"),
        (_PERMISSIONS, _PERMISSIONS + "\ndefaults:\n  run:\n    shell: bash {0}\n"),
        # Another commit, repository or tree than the one pushed; another image's shell.
        (_CHECKOUT_WITH, _CHECKOUT_WITH + "          ref: " + "0" * 40 + "\n"),
        (_CHECKOUT_WITH, _CHECKOUT_WITH + "          repository: a/fork\n"),
        (_CHECKOUT_WITH, _CHECKOUT_WITH + "          path: other\n"),
        ("    timeout-minutes: 45\n", "    timeout-minutes: 30\n    container:\n      image: python:3.12\n"),
        ("          enable-cache: false\n", "          enable-cache: false\n          working-directory: site\n"),
        # pip from the index, unpinned and unhashed.
        (f"--require-hashes -r {_CI_PIP}", "pip"),
        # Shell in the audit's pinned values: pip-audit never runs, or a file
        # bash sources before every later step.
        (_EXCLUDE_NEWER, _EXCLUDE_NEWER + "||true;true"),
        (_EXCLUDE_NEWER, _EXCLUDE_NEWER + "$(echo${IFS}BASH_ENV=/dev/null>>$GITHUB_ENV)"),
        # Filters that leave pushes to main without a run.
        ("    branches: [main]\n", "    branches: [main, '!main']\n"),
        ("    branches: [main]\n", "    branches: mainline\n"),
        # A self-hosted runner's .env sets variables (BASH_ENV) for every step.
        ("runs-on: ubuntu-24.04", "runs-on: [self-hosted]"),
        ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
        # YAML 1.1 (this test's parser) ends a line at NEL, so it reads what
        # follows as a comment; a YAML 1.2 parser keeps it, and bash then runs
        # 'pytest tests/unit<NEL># || true', which exits 0.
        (_LAST_IGNORE, _LAST_IGNORE.replace("\n", "\x85# || true\n")),
        ("ruff check src tests scripts", "ruff check src tests\u00a0scripts"),
        # The same characters from a double-quoted scalar's escapes (\_ is a
        # no-break space), and a step that names its run twice.
        ("run: .venv/bin/ruff check src tests scripts", 'run: ".venv/bin/ruff check src tests\\_scripts"'),
        (_UNIT_STEP, _UNIT_STEP + "        run: exit 0\n"),
        # A uv other than the one release checked against its checksum, another
        # Python, or a cache a pull request could have written.
        ('          checksum: "', '          # checksum: "'),
        ('          version: "0.11.16"\n', '          version: "latest"\n'),
        ('          version: "0.11.16"\n', '          version: ">=0.11"\n'),
        ('          python-version: "3.12"\n', '          python-version: "3.13"\n'),
        ("          enable-cache: false\n", "          enable-cache: true\n"),
        # A setup action's commit other than the reviewed one, however well-formed.
        ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@" + "a" * 40),
        ("astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7", "astral-sh/setup-uv@" + "0" * 40),
    ],
)
def test_the_ci_gate_rejects_a_ci_yml_that_passes_without_running_every_check(old: str, new: str) -> None:
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    _assert_the_workflow_gates_every_change("ci.yml", text)
    assert old in text
    with pytest.raises(AssertionError):
        _assert_the_workflow_gates_every_change("ci.yml", text.replace(old, new, 1))


@pytest.mark.parametrize(
    "layout",
    [
        # Every check before the install, the unit tests with the checks' condition.
        {"checks": "setup unit checks install"},
        # The four checks after the unit tests before the install.
        {"checks": "setup checks install unit"},
        # The checks in a job with no install: a step's steps.* context is its own job's.
        {"install": "setup install", "checks": "setup unit checks"},
    ],
)
def test_the_ci_gate_rejects_checks_that_run_before_the_install_or_in_another_job(layout: dict[str, str]) -> None:
    # Each check's condition reads the install's outcome, which is null before
    # the install ran or in another job: the check is skipped and the job passes.
    wf = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
    job_name, job = "checks", wf["jobs"]["checks"]
    steps: list[dict[str, Any]] = job["steps"]
    install = next(step for step in steps if step.get("id") == "sync")
    unit = next(step for step in steps if step.get("name") == "Unit tests")
    parts = {
        "setup": [step for step in steps if "uses" in step],
        "install": [install],
        "unit": [{**unit, "if": _AFTER_THE_INSTALL}],
        "checks": steps[steps.index(unit) + 1 :],
    }

    def regrouped(jobs: dict[str, str]) -> str:
        grouped = {
            name: {**job, "steps": [s for part in order.split() for s in parts[part]]} for name, order in jobs.items()
        }
        # installer-tests stays as it is: the regrouped job is the checks job.
        with_split: dict[str, Any] = {**grouped, "installer-tests": wf["jobs"]["installer-tests"]}
        return yaml.safe_dump({**wf, "jobs": with_split}, sort_keys=False)

    _assert_the_workflow_gates_every_change("ci.yml", regrouped({job_name: "setup install unit checks"}))
    with pytest.raises(AssertionError):
        _assert_the_workflow_gates_every_change("ci.yml", regrouped(layout))


# A checkout with the project's layout and settings, for the gate's own tests.
_BUILD_SYSTEM = '[build-system]\nrequires = ["hatchling>=1.27"]\nbuild-backend = "hatchling.build"\n'
_HATCH_SECTION = '[tool.hatch.build.targets.wheel]\npackages = ["src/universal_db_mcp"]\n'
_UV_SECTION = '[tool.uv]\nbuild-constraint-dependencies = ["hatchling==1.32.4"]\n'
_PYTEST_SECTION = '[tool.pytest.ini_options]\ntestpaths = ["tests"]\naddopts = "-q"\nmarkers = ["integration: x"]\n'
_ADDOPTS = 'addopts = "-q"\n'
_RUFF_SECTION = (
    '[tool.ruff]\nline-length = 120\n\n[tool.ruff.lint]\nselect = ["E", "F", "I", "UP", "B", "S", "ASYNC"]\n'
    'ignore = ["S101"]\n\n[tool.ruff.lint.per-file-ignores]\n"tests/*" = ["S105"]\n'
)
_MYPY_SECTION = '[tool.mypy]\npython_version = "3.12"\nstrict = true\nmypy_path = "src"\n'
_PYPROJECT = "\n".join(
    (
        _BUILD_SYSTEM,
        '[project]\nname = "universal-db-mcp"\nversion = "0.1.0"\n',
        _HATCH_SECTION,
        _UV_SECTION,
        _PYTEST_SECTION,
        _RUFF_SECTION,
        _MYPY_SECTION,
    )
)
_PYPI = 'source = { registry = "https://pypi.org/simple" }'
_WHEEL = "https://files.pythonhosted.org/packages/ab/cd/pyyaml-6.0.3-cp312-cp312-manylinux_2_28_x86_64.whl"
_UV_LOCK = (
    f'version = 1\n\n[[package]]\nname = "pyyaml"\nversion = "6.0.3"\n{_PYPI}\n'
    f'wheels = [{{ url = "{_WHEEL}", hash = "sha256:{"0" * 64}" }}]\n\n'
    '[[package]]\nname = "universal-db-mcp"\nversion = "0.1.0"\nsource = { editable = "." }\n'
)
_SCRIPTS_WAIVER = '"tool.py" = ["S607"]'
_SCRIPTS_RUFF = f'extend = "../pyproject.toml"\n\n[lint.per-file-ignores]\n# S607: why\n{_SCRIPTS_WAIVER}\n'
_CHECKOUT = {
    "pyproject.toml": _PYPROJECT,
    "uv.lock": _UV_LOCK,
    "scripts/ruff.toml": _SCRIPTS_RUFF,
    "scripts/tool.py": "",
    "scripts/lib/helper.py": "",
    "src/universal_db_mcp/__init__.py": "",
    "tests/conftest.py": "import pytest\n",
    "tests/unit/test_x.py": "",
}


def _checkout(root: Path, path: str, old: str, new: str) -> None:
    """Write the checkout under root, check the gate passes it, then change
    one file (old -> new; a file the checkout lacks starts empty)."""
    for name, text in _CHECKOUT.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    _assert_the_checkout_runs_every_check(root, _files(root))
    target = root / path
    text = target.read_text(encoding="utf-8") if target.exists() else ""
    assert old in text
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def _files(root: Path) -> list[str]:
    """The names under root as git lists them: a link is one name, never followed."""
    paths: list[Path] = []
    for folder, dirs, files in os.walk(root):
        paths += [Path(folder, name) for name in files]
        paths += [Path(folder, name) for name in dirs if Path(folder, name).is_symlink()]
    return sorted(path.relative_to(root).as_posix() for path in paths)


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        ("pyproject.toml", _ADDOPTS, "addopts = \"-q -m 'not integration and not guard'\"\n"),
        ("pyproject.toml", _ADDOPTS, 'addopts = "-q --lf --lfnf=none"\n'),
        ("pyproject.toml", _ADDOPTS, 'addopts = "-q -p no:unittest"\n'),
        ("pyproject.toml", _ADDOPTS, 'addopts = "-q -k guard"\n'),
        ("pyproject.toml", _ADDOPTS, 'addopts = "-q --ignore-glob=*guard*"\n'),
        ("pyproject.toml", _ADDOPTS, 'addopts = "-q -c elsewhere.ini"\n'),
        ("pyproject.toml", _ADDOPTS, _ADDOPTS + 'python_functions = ["test_a*"]\n'),
        ("pyproject.toml", _ADDOPTS, _ADDOPTS + 'pythonpath = ["shadow"]\n'),
        # A warning category is imported by its module, as -p imports a plugin.
        ("pyproject.toml", _ADDOPTS, _ADDOPTS + 'filterwarnings = ["ignore::tests.shadow.Warning"]\n'),
        ("pyproject.toml", _PYTEST_SECTION, '[tool.pytest]\naddopts = ["-q", "-m", "not guard"]\n'),
        # pytest reads [tool.pytest] when the [tool.pytest.ini_options] beside
        # it is empty, and looks above the checkout when neither has a key.
        (
            "pyproject.toml",
            _PYTEST_SECTION,
            '[tool.pytest]\naddopts = ["-q", "-m", "not guard"]\n\n[tool.pytest.ini_options]\n',
        ),
        (
            "pyproject.toml",
            _PYTEST_SECTION,
            '[tool.pytest]\naddopts = ["-q", "-k", "not guard"]\n\n[tool.pytest.ini_options]\n',
        ),
        ("pyproject.toml", _PYTEST_SECTION, "[tool.pytest]\n"),
        ("pytest.ini", "", "[pytest]\naddopts = -m 'not guard'\n"),
        ("tests/.pytest.ini", "", ""),
        ("tests/unit/pytest.toml", "", ""),
        ("tests/tox.ini", "", "[pytest]\naddopts = -k guard\n"),
        ("setup.cfg", "", "[tool:pytest]\naddopts = -k guard\n"),
        ("tests/unit/pyproject.toml", "", '[tool.pytest.ini_options]\naddopts = "-k guard"\n'),
        # pytest's ini parser also ends a line at FF, VT, RS and NEL.
        ("tests/unit/tox.ini", "", "[tox]\x0c[pytest]\naddopts = -k 'not guard'\n"),
        ("tests/tox.ini", "", "[tox]\x0b[pytest]\naddopts = -k 'not guard'\n"),
        ("tests/unit/setup.cfg", "", "[metadata]\x85[tool:pytest]\naddopts = -k 'not guard'\n"),
        ("tests/unit/tox.ini", "", "[tox]\x1e[pytest]\naddopts = -k 'not guard'\n"),
        # A conftest's collection settings and hooks, however it binds them.
        ("tests/unit/conftest.py", "", 'collect_ignore = ["test_sql_guard.py"]\n'),
        ("tests/conftest.py", "", 'collect_ignore_glob: list[str] = ["unit/*guard*"]\n'),
        ("tests/unit/conftest.py", "", 'globals()["collect_ignore"] = ["test_sql_guard.py"]\n'),
        ("conftest.py", "", "def pytest_collection_modifyitems(items):\n    items.clear()\n"),
        ("tests/conftest.py", "", "def pytest_sessionfinish(session):\n    session.exitstatus = 0\n"),
        ("tests/unit/conftest.py", "", "from shadow import pytest_ignore_collect\n"),
        ("tests/unit/conftest.py", "", 'pytest_plugins = ["shadow"]\n'),
        # A plugin a test module loads, or the project registers.
        ("tests/unit/test_guard.py", "", 'pytest_plugins = ["shadow"]\n'),
        ("pyproject.toml", _PYPROJECT, _PYPROJECT + '[project.entry-points.pytest11]\nshadow = "shadow"\n'),
        # Code Python runs at startup from a directory on sys.path (src/ is, via
        # the editable install), e.g. atexit.register(lambda: os._exit(0)).
        ("src/sitecustomize.py", "", "import atexit, os\natexit.register(lambda: os._exit(0))\n"),
        ("usercustomize.py", "", ""),
        ("scripts/sitecustomize/__init__.py", "", ""),
        ("src/shadow.pth", "", "import shadow\n"),
        # ...from any directory, e.g. one a hatch dev-mode-dirs adds, or a venv
        # committed beside the checkout, which `uv sync` keeps.
        ("packaging/sitecustomize.py", "", "import atexit, os\natexit.register(lambda: os._exit(0))\n"),
        (".venv/lib/python3.12/site-packages/zz_ci.pth", "", "import shadow\n"),
        (".venv/pyvenv.cfg", "", "home = /usr/bin\n"),
        # A hook or collect_ignore a conftest gets without spelling its name.
        ("tests/conftest.py", "", "from helpers import *  # noqa: F403\n"),
        ("tests/unit/test_x.py", "", "from helpers import *  # noqa: F403\n"),
        ("tests/conftest.py", "", 'globals()[b"collect_ignore".decode()] = ["unit/test_guard.py"]\n'),
        ("tests/conftest.py", "", 'globals()["collect" + "_ignore"] = ["unit/test_guard.py"]\n'),
        ("tests/conftest.py", "", 'import sys\nsetattr(sys.modules[__name__], "collect" + "_ignore", ["unit"])\n'),
        # Suite code that ends the run early, or with exit status 0.
        (
            "tests/conftest.py",
            "import pytest\n",
            'import pytest\n\n@pytest.fixture(autouse=True, scope="session")\n'
            'def _done():\n    yield\n    pytest.exit("done", returncode=0)\n',
        ),
        ("tests/unit/test_x.py", "", "import os\n\ndef test_last():\n    os._exit(0)\n"),
        ("tests/unit/test_x.py", "", "from os import _exit as stop\n"),
        ("tests/unit/test_x.py", "", "def test_last(request):\n    request.session.testsfailed = 0\n"),
        ("tests/conftest.py", "", "def _finish(session):\n    session.exitstatus = 0\n"),
        # ...or that replaces the pytest process with one that exits 0.
        (
            "tests/conftest.py",
            "import pytest\n",
            'import os\nimport sys\n\nimport pytest\n\n@pytest.fixture(autouse=True, scope="session")\n'
            'def _done():\n    yield\n    os.execv(sys.executable, [sys.executable, "-c", "pass"])\n',
        ),
        ("tests/unit/test_x.py", "", "from os import execlp as stop\n"),
        # A conftest fixture that skips or xfails the tests it picks: pytest
        # exits 0, with no -m, -k or hook.
        (
            "tests/unit/conftest.py",
            "",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _flaky(request):\n"
            "    if 'guard' in request.node.nodeid:\n        pytest.skip('flaky on CI')\n",
        ),
        (
            "tests/conftest.py",
            "import pytest\n",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _known():\n    pytest.xfail('known')\n",
        ),
        (
            "tests/conftest.py",
            "import pytest\n",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _known(request):\n"
            "    request.node.add_marker('xfail')\n",
        ),
        ("tests/conftest.py", "", "from pytest import importorskip as needs\n"),
        ("tests/conftest.py", "", "import unittest\n\ndef _off():\n    raise unittest.SkipTest('off')\n"),
        ("tests/conftest.py", "", "from _pytest.outcomes import Skipped as Off\n"),
        # ...or that it gets from another module under tests/: an autouse
        # fixture it imports from a helper or a test module, or a helper one
        # of its fixtures calls.
        (
            "tests/unit/helpers_flaky.py",
            "",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _flaky(request):\n"
            "    if 'guard' in request.node.nodeid:\n        pytest.skip('flaky on CI')\n",
        ),
        ("tests/unit/helpers_gate.py", "", "import pytest\n\ndef gate(request):\n    pytest.skip('flaky on CI')\n"),
        ("tests/conftest.py", "", "from unit.test_fixtures import _flaky  # noqa: F401\n"),
        ("tests/unit/conftest.py", "", "from . import test_fixtures  # noqa: F401\n"),
        # An autouse fixture there runs for tests it never names, and needs no
        # skip to drop one: it can swap the test's function, or xfail it
        # through pytest's internals.
        (
            "tests/conftest.py",
            "import pytest\n",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _ok(request):\n"
            "    request.node.obj = lambda **_: None\n",
        ),
        ("tests/unit/helpers_x.py", "", "import pytest\n\nfixture = pytest.fixture(**{'autouse': True})\n"),
        ("tests/conftest.py", "", "from _pytest.skipping import Xfail, xfailed_key  # noqa: F401\n"),
        # A fixture or a skip from code outside tests/, which a conftest can
        # import too.
        ("scripts/lib/helper.py", "", "import pytest\n"),
        ("src/universal_db_mcp/__init__.py", "", "from _pytest.outcomes import skip  # noqa: F401\n"),
        # A conftest writes its namespace through a frame's globals or locals,
        # a function's __globals__, or its module (inspect finds it, sys.modules
        # holds it); a helper writes a conftest's.
        ("tests/unit/conftest.py", "", "import sys\n\nsys._getframe(0).f_globals['collect' + '_ignore'] = ['x']\n"),
        ("tests/unit/conftest.py", "", "import sys\n\nsys._getframe(0).f_locals['collect' + '_ignore'] = ['x']\n"),
        ("tests/unit/conftest.py", "", "(lambda: 0).__globals__['collect' + '_ignore'] = ['test_guard.py']\n"),
        (
            "tests/unit/conftest.py",
            "",
            "import inspect\n\nobject.__setattr__(inspect.getmodule(lambda: 0), 'collect' + '_ignore', ['x'])\n",
        ),
        (
            "tests/unit/conftest.py",
            "",
            "from sys import modules\n\nmodules[__name__].__setattr__('collect' + '_ignore', ['test_guard.py'])\n",
        ),
        (
            "tests/unit/helpers_x.py",
            "",
            "import sys\n\nsys.modules['conftest'].collect_ignore = ['unit/test_guard.py']\n",
        ),
        # ...or reaches a namespace builtin as an attribute (of the builtins
        # module, or of a builtin function's __self__), or names a hook in a
        # dotted string that MonkeyPatch.setattr resolves.
        (
            "tests/unit/conftest.py",
            "",
            'import builtins\n\nbuiltins.exec("import pytest\\n\\n@pytest.fixture(autouse=True)\\n'
            "def _f():\\n    pytest.skip('flaky')\\n\")  # noqa: S102\n",
        ),
        ("tests/unit/conftest.py", "", "len.__self__.exec(\"collect_ignore = ['test_guard.py']\")\n"),
        ("tests/unit/helpers_x.py", "", "run = len.__self__\n"),
        ("tests/unit/conftest.py", "", "import builtins\n\nbuiltins.globals()['collect' + '_ignore'] = ['x']\n"),
        (
            "tests/conftest.py",
            "import pytest\n",
            "import pytest\n\npytest.MonkeyPatch().setattr('conftest.collect_ignore', ['x'], raising=False)\n",
        ),
        # ...or runs another file's code as a module (a test module's autouse
        # fixture, a data file ruff and this gate never read).
        (
            "tests/conftest.py",
            "",
            "import runpy\nfrom pathlib import Path\n\n"
            "_flaky = runpy.run_path(str(Path(__file__).parent / 'unit' / 'test_fixtures.py'))['_flaky']\n",
        ),
        (
            "tests/conftest.py",
            "",
            "import importlib.util\nfrom pathlib import Path\n\n"
            "_s = importlib.util.spec_from_file_location('fx', str(Path(__file__).parent / 'fx.txt'))\n",
        ),
        # An autouse fixture in code outside tests/, however it gets pytest: a
        # conftest's plain import of it runs it for every test below.
        (
            "src/universal_db_mcp/__init__.py",
            "",
            "pytest = __import__('pytest')\n\n\n@pytest.fixture(autouse=True)\ndef _flaky() -> None:\n"
            "    pytest.skip('flaky on CI')\n",
        ),
        (
            "scripts/lib/helper.py",
            "",
            "import sys\n\npytest = sys.modules['pytest']\nfixture = pytest.fixture(autouse=True)\n",
        ),
        # Python runs a module in the codec its coding line names: in UTF-7
        # this comment is a collect_ignore.
        ("tests/unit/conftest.py", "", "# -*- coding: utf-7 -*-\n# +AAo-collect_ignore = ['test_guard.py']\n"),
        # A namespace builtin as an attribute (a lambda's __builtins__), and a
        # hook spelled inside a dotted string: each rule alone catches one.
        (
            "tests/unit/conftest.py",
            "",
            "(lambda: 0).__builtins__['exec'](\"import pytest\\n\\n@pytest.fixture(autouse=True)\\n"
            "def _f(request):\\n    if 'guard' in request.node.nodeid:\\n        pytest.skip('flaky')\\n\")\n",
        ),
        (
            "tests/unit/conftest.py",
            "",
            "from unittest import mock\n\n"
            "mock.patch('conftest.collect_ignore', ['test_guard.py'], create=True).start()\n",
        ),
        # A frame's builtins, a name resolver and a pickle's GLOBAL run a string too.
        (
            "tests/conftest.py",
            "",
            "import sys\n\nsys._getframe(0).f_builtins['exec'](\"import pytest\\n\\n"
            "@pytest.fixture(autouse=True)\\ndef _f():\\n    pytest.skip('flaky')\\n\")\n",
        ),
        ("tests/conftest.py", "", "import pydoc\n\npydoc.locate('builtins.exec')('x = 1')\n"),
        ("tests/conftest.py", "", "import pickle\n\npickle.loads(b'cbuiltins\\nexec\\n(Vx = 1\\ntR.')\n"),
        # Ending the run with status 0 at import: in a conftest, or a helper it imports.
        ("tests/conftest.py", "", "import pytest\n\nraise SystemExit\n"),
        ("tests/conftest.py", "", "quit(0)\n"),
        ("tests/helpers_boot.py", "", "import os\n\nif os.environ.get('CI'):\n    raise SystemExit(0)\n"),
        # The fixture anyio's plugin requests for every anyio test, rewriting the test it runs for.
        (
            "tests/conftest.py",
            "",
            "import pytest\n\n\n@pytest.fixture\ndef anyio_backend(request: pytest.FixtureRequest) -> str:\n"
            "    request.node.obj = lambda **_: None\n    return 'asyncio'\n",
        ),
        ("tests/conftest.py", "", "def _setup(request):\n    request.node.runtest = lambda: None\n"),
        # `python -m pytest` puts the root first on sys.path, `python scripts/x.py`
        # scripts/, and pytest each test directory: a module there by a name
        # Python or the venv has replaces it (pytest, its internals, a library).
        ("pytest.py", "", "raise SystemExit(0)\n"),
        ("pytest/__init__.py", "", ""),
        ("_pytest/__init__.py", "", ""),
        ("pluggy.py", "", ""),
        ("packaging/__init__.py", "", ""),
        ("pytest.pyc", "", ""),
        ("scripts/json.py", "", ""),
        ("tests/unit/yaml.py", "", ""),
        ("tests/unit/universal_db_mcp/__init__.py", "", ""),
        # A test module where pytest's collection never looks.
        ("tests/unit/build/test_guard.py", "", ""),
        ("tests/unit/dist/test_guard.py", "", ""),
        ("tests/unit/.cases/test_guard.py", "", ""),
        ("tests/unit/legacy.egg/test_guard.py", "", ""),
        ("tests/unit/pyvenv.cfg", "", "home = /usr/bin\n"),
        ("tests/unit/conda-meta/history", "", ""),
        # Compiled code Python runs in place of the source beside it, the only
        # file ruff and mypy read: an unchecked-hash .pyc (never compared with
        # its source), a sourceless .pyc, an extension module.
        ("src/universal_db_mcp/__pycache__/__init__.cpython-312.pyc", "", ""),
        ("tests/unit/__pycache__/helpers.cpython-312.pyc", "", ""),
        ("scripts/lib/__pycache__/helper.cpython-312.pyc", "", ""),
        ("src/universal_db_mcp/server.pyc", "", ""),
        ("tests/unit/helpers.pyo", "", ""),
        ("src/universal_db_mcp/server.cpython-312-x86_64-linux-gnu.so", "", ""),
        ("src/universal_db_mcp/server.pyd", "", ""),
        # The cache --lf and --sw read.
        (".pytest_cache/v/cache/lastfailed", "", "{}\n"),
    ],
)
def test_the_ci_gate_rejects_a_pytest_config_that_deselects_tests(
    tmp_path: Path, path: str, old: str, new: str
) -> None:
    _checkout(tmp_path, path, old, new)
    with pytest.raises(AssertionError):
        _assert_pytest_selects_every_test(tmp_path, _files(tmp_path))


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        # A module that only imports a plugin library registers nothing.
        ("tests/conftest.py", "", "import pytest_asyncio\n"),
        ("tests/conftest.py", "", "from pytest_mock import MockerFixture\n"),
        # A test module may spell a hook's name as data, and skip its own tests.
        ("tests/unit/test_x.py", "", 'NAME = "pytest_plugins"\n'),
        ("tests/unit/test_x.py", "", 'import pytest\n\npytestmark = pytest.mark.skipif(True, reason="x")\n'),
        # A test module's SystemExit is reported by pytest (rc 3 at import, 1 in a test).
        ("tests/unit/test_x.py", "", "def test_cli() -> None:\n    raise SystemExit(2)\n"),
        (
            "tests/unit/test_x.py",
            "",
            "import pytest\n\n@pytest.fixture(autouse=True)\ndef _slow():\n    pytest.skip('slow')\n",
        ),
        # A helper's fixture that a test asks for by name, code outside tests/
        # that only names pytest, and a coding line that names UTF-8.
        (
            "tests/unit/helpers_fixtures.py",
            "",
            "import pytest\n\n@pytest.fixture\ndef handle():\n    return object()\n",
        ),
        ("tests/conftest.py", "", "from unit.helpers_fixtures import handle  # noqa: F401\n"),
        ("scripts/tool.py", "", "# needs the dev tools (build, pytest)\nTOOLS = ('pytest',)\n"),
        ("tests/unit/conftest.py", "", "# -*- coding: utf-8 -*-\n"),
        ("pyproject.toml", _ADDOPTS, _ADDOPTS + 'filterwarnings = ["error", "ignore::DeprecationWarning"]\n'),
        ("pyproject.toml", _ADDOPTS, _ADDOPTS + 'filterwarnings = ["ignore::pytest.PytestRemovedIn10Warning"]\n'),
        # Modules whose names nothing else has.
        ("scripts/profiles.py", "", ""),
        ("tests/unit/helpers.py", "", ""),
        # Test directories whose names only begin like one pytest skips.
        ("tests/unit/builders/test_y.py", "", ""),
        ("tests/unit/distinct/test_y.py", "", ""),
        # A tox.ini or setup.cfg with no pytest section, as pytest parses it.
        ("tox.ini", "", "[tox]\nenv_list = py312\n\n[testenv]\ncommands = pytest -k guard\n"),
        ("tests/setup.cfg", "", "[metadata]\x0cname = x\n"),
    ],
)
def test_the_ci_gate_accepts_suite_code_that_changes_nothing_it_guards(
    tmp_path: Path, path: str, old: str, new: str
) -> None:
    _checkout(tmp_path, path, old, new)
    _assert_pytest_selects_every_test(tmp_path, _files(tmp_path))


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        # A build hook, an in-tree backend or a path dependency runs during
        # `uv sync` with $GITHUB_ENV writable: it could set BASH_ENV for every
        # later step. hatchling also reads hatch.toml, and uv reads uv.toml.
        ("pyproject.toml", _HATCH_SECTION, _HATCH_SECTION + '\n[tool.hatch.build.hooks.custom]\npath = "hook.py"\n'),
        ("pyproject.toml", _HATCH_SECTION, _HATCH_SECTION + '\n[tool.hatch.metadata.hooks.custom]\npath = "hook.py"\n'),
        ("pyproject.toml", _HATCH_SECTION, _HATCH_SECTION + 'dev-mode-dirs = ["src", "packaging"]\n'),
        (
            "pyproject.toml",
            _HATCH_SECTION,
            _HATCH_SECTION + '\n[tool.hatch.build.targets.wheel.force-include]\n"packaging/x.pth" = "x.pth"\n',
        ),
        ("pyproject.toml", 'build-backend = "hatchling.build"\n', 'build-backend = "ci"\nbackend-path = ["."]\n'),
        ("pyproject.toml", '["hatchling>=1.27"]', '["hatchling>=1.27", "ci-helper==1.0"]'),
        ("pyproject.toml", _UV_SECTION, _UV_SECTION + '\n[tool.uv.sources]\nshadow = { path = "packaging/shadow" }\n'),
        ("pyproject.toml", _UV_SECTION, _UV_SECTION + '\n[[tool.uv.index]]\nurl = "https://example.invalid/simple"\n'),
        ("pyproject.toml", _UV_SECTION, _UV_SECTION + 'no-build-isolation = true\n'),
        ("pyproject.toml", '"hatchling==1.32.4"', '"hatchling>=1.32"'),
        ("hatch.toml", "", '[build.hooks.custom]\npath = "hook.py"\n'),
        ("uv.toml", "", 'index-url = "https://example.invalid/simple"\n'),
        # A locked package from anywhere but a PyPI file of that project.
        ("uv.lock", _PYPI, 'source = { path = "packaging/pyyaml" }'),
        ("uv.lock", _PYPI, 'source = { registry = "https://example.invalid/simple" }'),
        ("uv.lock", "https://files.pythonhosted.org/packages/", "https://example.invalid/packages/"),
        ("uv.lock", "/pyyaml-6.0.3-", "/shadow-6.0.3-"),
        ("uv.lock", 'source = { editable = "." }', 'source = { editable = "packaging" }'),
        # A package archive a find-links, a path or a file: URL could install.
        (".github/wheels/pip-26.2.1-py3-none-any.whl", "", ""),
        ("packaging/shadow-1.0.tar.gz", "", ""),
        ("packaging/Shadow-1.0.ZIP", "", ""),
    ],
)
def test_the_ci_gate_rejects_a_build_config_that_runs_code_from_the_checkout(
    tmp_path: Path, path: str, old: str, new: str
) -> None:
    _checkout(tmp_path, path, old, new)
    with pytest.raises(AssertionError):
        _assert_the_install_runs_no_code_from_the_checkout(tmp_path, _files(tmp_path))


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        # mypy reads mypy.ini or .mypy.ini before pyproject.toml; per-module or
        # plugin settings in [tool.mypy] can switch its errors off.
        ("mypy.ini", "", "[mypy]\nignore_errors = True\n"),
        (".mypy.ini", "", "[mypy]\nignore_errors = True\n"),
        ("setup.cfg", "", "[mypy]\nignore_errors = True\n"),
        ("pyproject.toml", _MYPY_SECTION, _MYPY_SECTION + "ignore_errors = true\n"),
        ("pyproject.toml", _MYPY_SECTION, _MYPY_SECTION + 'exclude = ["server"]\n'),
        ("pyproject.toml", _MYPY_SECTION, _MYPY_SECTION + 'plugins = ["shadow"]\n'),
        (
            "pyproject.toml",
            _MYPY_SECTION,
            _MYPY_SECTION + '[[tool.mypy.overrides]]\nmodule = "*"\nignore_errors = true\n',
        ),
        ("pyproject.toml", "strict = true", "strict = false"),
        # ruff reads the nearest ruff.toml, .ruff.toml or pyproject.toml with
        # [tool.ruff] above each file it checks.
        ("src/universal_db_mcp/ruff.toml", "", '[lint]\nignore = ["ALL"]\n'),
        ("tests/ruff.toml", "", ""),
        (".ruff.toml", "", '[lint.per-file-ignores]\n"src/*" = ["ALL"]\n'),
        ("scripts/lib/pyproject.toml", "", "[tool.ruff]\n"),
        ("pyproject.toml", "line-length = 120\n", 'line-length = 120\nextend-exclude = ["src"]\n'),
        ("pyproject.toml", "line-length = 120\n", 'line-length = 120\ninclude = ["*.pyi"]\n'),
        ("pyproject.toml", "line-length = 120\n", "line-length = 120\nfix = true\n"),
        ("pyproject.toml", "line-length = 120\n", "line-length = 1000\n"),
        ("pyproject.toml", 'ignore = ["S101"]', 'ignore = ["S101", "ALL"]'),
        ("pyproject.toml", 'ignore = ["S101"]', 'ignore = ["S"]'),
        ("pyproject.toml", 'ignore = ["S101"]', 'ignore = ["S101"]\nextend-ignore = ["S"]'),
        ("pyproject.toml", '"B", "S", "ASYNC"]', '"B", "ASYNC"]'),
        ("pyproject.toml", '"tests/*" = ["S105"]', '"tests/*" = ["ALL"]'),
        # scripts/ruff.toml waives one rule for one file, and nothing else.
        ("scripts/ruff.toml", "[lint.per-file-ignores]\n", 'extend-exclude = ["*.py"]\n\n[lint.per-file-ignores]\n'),
        (
            "scripts/ruff.toml",
            "[lint.per-file-ignores]\n",
            '[lint]\nextend-ignore = ["ALL"]\n\n[lint.per-file-ignores]\n',
        ),
        ("scripts/ruff.toml", 'extend = "../pyproject.toml"', 'extend = "../elsewhere.toml"'),
        ("scripts/ruff.toml", _SCRIPTS_WAIVER, '"tool.py" = ["ALL"]'),
        ("scripts/ruff.toml", _SCRIPTS_WAIVER, '"tool.py" = ["S"]'),
        ("scripts/ruff.toml", _SCRIPTS_WAIVER, '"*.py" = ["S607"]'),
        ("scripts/ruff.toml", _SCRIPTS_WAIVER, '"lib" = ["S607"]'),
        # Files ruff leaves out without a word: under dist/ or venv/, or named
        # by .gitignore (a tracked file too).
        ("src/universal_db_mcp/dist/server.py", "", "import os\n"),
        ("scripts/venv/tool.py", "", "import os\n"),
        (".gitignore", "", "src/universal_db_mcp/__init__.py\n"),
        ("tests/unit/.gitignore", "", "test_*.py\n"),
        # ...or by a .ignore file, which git does not read.
        (".ignore", "", "src/\n"),
        ("src/universal_db_mcp/.ignore", "", "*.py\n"),
        # A tool's cache that calls a module unchanged and clean: mypy trusts
        # an entry whose hash and size match, whatever the checkout's mtimes.
        (".mypy_cache/3.12/cache.0.db", "", ""),
        (".mypy_cache/CACHEDIR.TAG", "", ""),
        (".ruff_cache/0.16.6/123", "", ""),
        # mypy checks a stub in place of the .py beside it, and takes a
        # library's types from a stub in the root or a module in src/ (its path).
        ("src/universal_db_mcp/__init__.pyi", "", ""),
        ("sqlglot.pyi", "", "def __getattr__(name: str) -> object: ...\n"),
        ("src/sqlglot.py", "", "from typing import Any\n\n\ndef __getattr__(name: str) -> Any: ...\n"),
        # ruff reads every file as UTF-8; Python reads one in the codec its
        # coding line names, and in UTF-7 this comment is code.
        ("scripts/tool.py", "", "# -*- coding: utf-7 -*-\n# +AAo-eval(input())\n"),
        ("src/universal_db_mcp/__init__.py", "", "# vim: set fileencoding=latin-1 :\n"),
    ],
)
def test_the_ci_gate_rejects_a_lint_or_type_check_config_that_hides_errors(
    tmp_path: Path, path: str, old: str, new: str
) -> None:
    _checkout(tmp_path, path, old, new)
    with pytest.raises(AssertionError):
        _assert_ruff_and_mypy_report_every_error(tmp_path, _files(tmp_path))


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        # What this repository ignores, which names no source file.
        (".gitignore", "", "__pycache__/\n*.py[cod]\n*.egg-info/\ndist/\nbuild/\n.venv/\n.mypy_cache/\nsecrets/\n"),
        # A package directory whose name only begins like one ruff skips.
        ("src/universal_db_mcp/distribution/x.py", "", ""),
        # A coding line that names UTF-8, and one past the second line, which
        # Python does not read.
        ("scripts/tool.py", "", "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"),
        ("scripts/tool.py", "", '"""Tool."""\n\n# coding: latin-1\n'),
    ],
)
def test_the_ci_gate_accepts_a_lint_config_that_hides_nothing(tmp_path: Path, path: str, old: str, new: str) -> None:
    _checkout(tmp_path, path, old, new)
    _assert_ruff_and_mypy_report_every_error(tmp_path, _files(tmp_path))


def _checked_files(root: Path) -> list[str]:
    """The names git lists in the checkout under root that the checks read:
    its files and its links (git lists a link to a directory as one name)."""
    return [name for name in _tree_files(root) if (root / name).is_symlink() or (root / name).is_file()]


def test_nothing_in_the_checkout_changes_what_the_checks_run_or_report() -> None:
    _assert_the_checkout_runs_every_check(REPO, _checked_files(REPO))


_LINKS = pytest.mark.skipif(sys.platform == "win32", reason="creating a symlink needs a privilege on Windows")
# A link to a directory with a test module that loads a plugin, which could
# deselect any test; one to a package with code ruff would flag; one to a file.
_LINKED = [
    ("packaging/more/test_z.py", 'pytest_plugins = ["zz_more_plugin"]\n', "tests/unit/more", "../../packaging/more"),
    (
        "packaging/hidden/bad.py",
        'import subprocess\n\nsubprocess.call("x", shell=True)\n',
        "src/universal_db_mcp/sub",
        "../../packaging/hidden",
    ),
    ("packaging/test_y.py", "", "tests/unit/test_y.py", "../../packaging/test_y.py"),
]


@_LINKS
@pytest.mark.parametrize(("path", "text", "link", "target"), _LINKED)
def test_the_ci_gate_rejects_a_link_in_the_tree(tmp_path: Path, path: str, text: str, link: str, target: str) -> None:
    # pytest collects through a link to a directory (and the plugins the
    # modules behind it load), Python imports and mypy checks through it,
    # and ruff never lints what is behind it.
    _checkout(tmp_path, path, "", text)
    (tmp_path / link).symlink_to(target)
    with pytest.raises(AssertionError, match="links in the tree"):
        _assert_the_checkout_runs_every_check(tmp_path, _files(tmp_path))


@_LINKS
def test_the_check_on_the_real_tree_keeps_the_links_git_lists(tmp_path: Path) -> None:
    # git lists a link to a directory as one name, which is not a file.
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git to list the tree")
    path, text, link, target = _LINKED[0]
    _checkout(tmp_path, path, "", text)
    (tmp_path / link).symlink_to(target)
    subprocess.run(  # noqa: S603 - fixed argv, a repository under tmp_path
        [git, "init", "-q", "--template=", str(tmp_path)], check=True, capture_output=True, timeout=60
    )
    assert link in _checked_files(tmp_path)
    with pytest.raises(AssertionError, match="links in the tree"):
        _assert_the_checkout_runs_every_check(tmp_path, _checked_files(tmp_path))


# The pytest plugins the installed distributions bring (pytest11 entry points),
# as 'name = module': anyio's, from the locked dependencies. Another one fails
# the check below until someone reviews it and adds it here.
_PYTEST_PLUGINS = frozenset({"anyio = anyio.pytest_plugin"})


def _module_of(plugin: object) -> str:
    if isinstance(plugin, types.ModuleType):
        return plugin.__name__
    return (plugin if isinstance(plugin, type) else type(plugin)).__module__


def _assert_the_session_runs_only_reviewed_hooks(config: pytest.Config) -> None:
    # The checks above read the tree; this one asks the session it runs in,
    # which also sees a hook or a collect_ignore that a conftest got at run
    # time (a star import, a name it built): every hook is pytest's own or a
    # reviewed plugin's, and no conftest holds a hook's or collect_ignore's name.
    # It does not look at fixtures: the tree checks above cover autouse ones.
    installed = {f"{ep.name} = {ep.value}" for ep in importlib.metadata.entry_points(group="pytest11")}
    assert installed <= _PYTEST_PLUGINS, f"pytest plugins no one reviewed: {sorted(installed - _PYTEST_PLUGINS)}"
    reviewed = {plugin.partition(" = ")[2].partition(":")[0] for plugin in _PYTEST_PLUGINS}
    manager = config.pluginmanager
    foreign = sorted(
        f"{hook} from {impl.plugin_name}"
        for hook, caller in vars(manager.hook).items()
        for impl in caller.get_hookimpls()
        if (module := _module_of(impl.plugin)).partition(".")[0] != "_pytest" and module not in reviewed
    )
    assert not foreign, f"hooks from outside pytest and the reviewed plugins: {foreign}"
    for plugin in manager.get_plugins():
        if isinstance(plugin, types.ModuleType) and Path(plugin.__file__ or "").name == "conftest.py":
            found = sorted(filter(_CONFTEST_HOOK.fullmatch, vars(plugin)))
            assert not found, f"{plugin.__file__}: {found}"


def test_the_running_session_has_only_pytests_own_hooks_and_the_reviewed_plugins(pytestconfig: pytest.Config) -> None:
    _assert_the_session_runs_only_reviewed_hooks(pytestconfig)


@pytest.mark.parametrize(
    ("conftest", "reported"),
    [
        ("", None),
        ("from helpers import *  # noqa: F403\n", "pytest_collection_modifyitems"),
        ('globals()[b"collect_ignore".decode()] = ["nothing.py"]\n', "collect_ignore"),
    ],
)
def test_the_session_check_sees_what_a_conftest_registers_at_run_time(
    tmp_path: Path, conftest: str, reported: str | None
) -> None:
    # A nested run whose conftest gets a hook through a star import, or a
    # collect_ignore by a name it builds at run time; its one test asks the
    # session it runs in.
    (tmp_path / "helpers.py").write_text("def pytest_collection_modifyitems(items):\n    pass\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(conftest, encoding="utf-8")
    (tmp_path / "test_session.py").write_text(
        "import importlib.util\n\n"
        f"spec = importlib.util.spec_from_file_location('ci_hygiene', {str(Path(__file__).resolve())!r})\n"
        "ci_hygiene = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(ci_hygiene)\n\n\n"
        "def test_session(pytestconfig):\n"
        "    ci_hygiene._assert_the_session_runs_only_reviewed_hooks(pytestconfig)\n",
        encoding="utf-8",
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, a test tree under tmp_path
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_session.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if reported is None:
        assert proc.returncode == 0, proc.stdout + proc.stderr
    else:
        assert proc.returncode == 1 and reported in proc.stdout, proc.stdout + proc.stderr


# A GitHub Actions expression, enough of one to work out which runs share a
# concurrency group: contexts, string literals, true/false, !, ==, != (on two
# operands of one type; strings compare case-insensitively), && and || (which
# yield an operand, as in JavaScript) and parentheses.
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_EXPRESSION_TOKEN = re.compile(r"\s*(?:(==|!=|&&|\|\||[!()])|'((?:[^']|'')*)'|([A-Za-z_][\w.-]*))\s*")


def _evaluate(expression: str, context: dict[str, str]) -> object:
    matches = list(_EXPRESSION_TOKEN.finditer(expression))
    assert "".join(m.group(0) for m in matches) == expression, f"unsupported expression: {expression!r}"
    tokens: list[tuple[str, object]] = []
    for m in matches:
        operator, literal, name = m.groups()
        if operator:
            tokens.append((operator, None))
        elif literal is not None:
            tokens.append(("value", literal.replace("''", "'")))
        elif name in ("true", "false"):
            tokens.append(("value", name == "true"))
        else:
            assert name in context, f"{expression!r}: {name} is not a context this test knows"
            tokens.append(("value", context[name]))
    tokens.append(("end", None))
    pos = 0

    def take() -> tuple[str, object]:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def operand() -> object:
        kind, value = take()
        if kind == "!":
            return not operand()
        if kind == "(":
            value = either()
            assert take()[0] == ")", expression
        else:
            assert kind == "value", expression
        return value

    def comparison() -> object:
        left = operand()
        while tokens[pos][0] in ("==", "!="):
            negate = take()[0] == "!="
            right = operand()
            # GitHub converts operands of two types to numbers ('' and false
            # are both 0), which this evaluator does not model.
            assert type(left) is type(right), f"{expression!r}: compares {left!r} with {right!r}"
            if isinstance(left, str) and isinstance(right, str):
                left, right = left.casefold(), right.casefold()
            left = (left == right) != negate
        return left

    def both() -> object:
        left = comparison()
        while tokens[pos][0] == "&&":
            take()
            right = comparison()
            left = left and right
        return left

    def either() -> object:
        left = both()
        while tokens[pos][0] == "||":
            take()
            right = both()
            left = left or right
        return left

    value = either()
    assert tokens[pos][0] == "end", expression
    return value


def _concurrency(setting: Any, **github: str) -> tuple[str, bool] | None:
    """The group and cancel-in-progress a workflow's or a job's concurrency
    setting gives a run with these github.* contexts, or None when runs are
    never grouped."""
    if setting is None:
        return None
    if isinstance(setting, str):
        setting = {"group": setting}
    context = {f"github.{key}": value for key, value in github.items()}

    def text(m: re.Match[str]) -> str:
        value = _evaluate(m.group(1), context)
        return str(value).lower() if isinstance(value, bool) else str(value)

    cancel = setting.get("cancel-in-progress", False)
    if isinstance(cancel, str):
        whole = _EXPRESSION.fullmatch(cancel.strip())
        assert whole, f"cancel-in-progress: {cancel!r}"
        cancel = _evaluate(whole.group(1), context)
    return _EXPRESSION.sub(text, str(setting["group"])), bool(cancel)


def _assert_main_keeps_every_result(name: str, wf: dict[str, Any]) -> None:
    # A group holds one running and one pending run: when a newer run joins,
    # GitHub cancels the pending one even with cancel-in-progress false. So two
    # commits pushed to main must never share a group, and no run on main may
    # cancel another.
    push = {"event_name": "push", "ref": "refs/heads/main", "head_ref": "", "workflow": "CI"}
    first, second = (
        _concurrency(wf.get("concurrency"), **push, sha=sha, run_id=run)
        for sha, run in (("1" * 40, "101"), ("2" * 40, "102"))
    )
    if first is None or second is None:
        return  # runs are never grouped, so none is cancelled
    assert first[0] != second[0], f"{name}: two pushes to main share the concurrency group {first[0]!r}"
    assert not (first[1] or second[1]), f"{name}: a run on main cancels the one before it"


def _assert_pull_requests_never_share_a_group(name: str, wf: dict[str, Any]) -> None:
    # Two pull requests from forks whose branches have one name (GitHub's web
    # editor names each 'patch-1') must not share a group either: each would
    # cancel the other's run.
    first, second = (
        _concurrency(
            wf.get("concurrency"),
            event_name="pull_request",
            ref=f"refs/pull/{number}/merge",
            head_ref="patch-1",
            workflow="CI",
            sha=sha,
            run_id=run,
        )
        for number, sha, run in ((1, "3" * 40, "103"), (2, "4" * 40, "104"))
    )
    if first is None or second is None:
        return  # runs are never grouped, so none is cancelled
    assert first[0] != second[0], f"{name}: two pull requests share the concurrency group {first[0]!r}"


_CONCURRENCY_GROUP = "  group: ci-${{ github.event_name == 'pull_request' && github.ref || github.sha }}\n"
_CANCEL_IN_PROGRESS = "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (_CONCURRENCY_GROUP, "  group: ci-${{ github.ref }}\n"),
        (_CONCURRENCY_GROUP, "  group: ci-${{ github.workflow }}\n"),
        (_CONCURRENCY_GROUP, "  group: ci-${{ github.event_name == 'push' && github.ref || github.sha }}\n"),
        (_CONCURRENCY_GROUP, "  group: ci\n"),
        (_CANCEL_IN_PROGRESS, "  cancel-in-progress: true\n"),
        (_CANCEL_IN_PROGRESS, "  cancel-in-progress: ${{ github.event_name != 'pull_request' }}\n"),
        (_CANCEL_IN_PROGRESS, "  cancel-in-progress: ${{ !(github.event_name == 'PULL_REQUEST') }}\n"),
        # GitHub compares '' with false as numbers (0 == 0): every push to main
        # would land in 'ci-main'.
        (
            _CONCURRENCY_GROUP,
            "  group: ci-${{ github.event_name == 'pull_request' && github.ref"
            " || github.head_ref == false && 'main' || github.sha }}\n",
        ),
    ],
)
def test_the_concurrency_check_rejects_a_setting_that_can_drop_a_run_on_main(old: str, new: str) -> None:
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    _assert_main_keeps_every_result("ci.yml", yaml.safe_load(text))
    assert old in text
    with pytest.raises(AssertionError):
        _assert_main_keeps_every_result("ci.yml", yaml.safe_load(text.replace(old, new, 1)))


@pytest.mark.parametrize(
    "group",
    [
        "ci-${{ github.head_ref || github.sha }}",
        "ci-${{ github.event_name == 'pull_request' && github.head_ref || github.sha }}",
        "ci-${{ github.event_name == 'pull_request' && 'pr' || github.sha }}",
    ],
)
def test_the_concurrency_check_rejects_a_group_two_pull_requests_share(group: str) -> None:
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    _assert_pull_requests_never_share_a_group("ci.yml", yaml.safe_load(text))
    assert _CONCURRENCY_GROUP in text
    mutated = yaml.safe_load(text.replace(_CONCURRENCY_GROUP, f"  group: {group}\n", 1))
    _assert_main_keeps_every_result("ci.yml", mutated)
    with pytest.raises(AssertionError):
        _assert_pull_requests_never_share_a_group("ci.yml", mutated)


def test_each_pull_request_runs_in_its_own_concurrency_group() -> None:
    for name, wf in _gating_workflows().items():
        _assert_pull_requests_never_share_a_group(name, wf)


def test_a_hung_test_cannot_cancel_the_other_checks_and_main_keeps_every_result() -> None:
    for name, wf in _gating_workflows().items():
        for job_name, job in wf["jobs"].items():
            tests = [s for s in job.get("steps", []) if re.search(r"\bpytest\b", str(s.get("run", "")))]
            if not tests:
                continue
            # A step timeout fails the step and the later checks still run; the
            # job timeout would cancel the job, and every '!cancelled()' check with it.
            for step in tests:
                assert int(step.get("timeout-minutes", 0)) > 0, f"{name}:{job_name}: no step timeout"
                assert int(step["timeout-minutes"]) < int(job.get("timeout-minutes", 360)), f"{name}:{job_name}"
        # Every commit pushed to main gets its own result.
        _assert_main_keeps_every_result(name, wf)
    _assert_no_other_run_joins_a_ci_group(_workflows())


def _assert_no_other_run_joins_a_ci_group(workflows: dict[str, dict[str, Any]]) -> None:
    # Concurrency groups belong to the repository, and their names compare
    # case-insensitively. CI's start with a fixed prefix, and no other
    # workflow's or job's group starts with it, on any event that runs it.
    gating = {name for name, wf in workflows.items() if {"push", "pull_request"} <= set(_triggers(wf))}
    prefixes: list[str] = []
    for name in gating:
        setting = workflows[name].get("concurrency")
        if setting is None:
            continue  # CI's runs are never grouped, so no other run can cancel one
        group = str(setting.get("group", "") if isinstance(setting, dict) else setting)
        prefix = group.partition("${{")[0]
        assert prefix, f"{name}: the concurrency group {group!r} starts with no fixed prefix"
        prefixes.append(prefix.casefold())
    for name, wf in workflows.items():
        if name in gating:
            continue
        settings = {name: wf.get("concurrency")}
        settings.update((f"{name}:{job_name}", job.get("concurrency")) for job_name, job in wf["jobs"].items())
        for event in _triggers(wf):
            ref = "refs/pull/1/merge" if event.startswith("pull_request") else "refs/heads/main"
            context = {"event_name": event, "ref": ref, "sha": "1" * 40, "head_ref": "", "run_id": "101"}
            for where, setting in settings.items():
                resolved = _concurrency(setting, **context, workflow=str(wf.get("name", name)))
                group = resolved[0].casefold() if resolved else ""
                assert not group.startswith(tuple(prefixes)) or not resolved, f"{where}: on {event}, in {group!r}"


_PAGES_CONCURRENCY = "concurrency:\n  group: pages\n  cancel-in-progress: false\n"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (_PAGES_CONCURRENCY, "concurrency:\n  group: ci-${{ github.sha }}\n  cancel-in-progress: true\n"),
        (_PAGES_CONCURRENCY, "concurrency: CI-${{ github.sha }}\n"),
        ("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    concurrency: ci-${{ github.sha }}\n"),
    ],
)
def test_no_other_workflow_can_join_a_ci_concurrency_group(old: str, new: str) -> None:
    # Concurrency groups belong to the repository: another workflow's run in
    # CI's group for a commit cancels CI's pending run for it (and, with
    # cancel-in-progress, its running one).
    workflows = _workflows()
    _assert_no_other_run_joins_a_ci_group(workflows)
    text = (WORKFLOWS / "pages.yml").read_text(encoding="utf-8")
    assert old in text
    with pytest.raises(AssertionError):
        _assert_no_other_run_joins_a_ci_group({**workflows, "pages.yml": _load_yaml(text.replace(old, new, 1))})


def test_ci_audits_the_shipped_locks_and_fails_when_they_are_stale() -> None:
    for name, wf in _gating_workflows().items():
        commands = [str(step.get("run", "")) for step in _steps(wf)]
        assert any(re.search(r"\bprepare_offline_bundle\.py --check-locks\b", c) for c in commands), name
        audits = [c for c in commands if "pip-audit" in c]
        assert any("requirements/locks/" in c and "--require-hashes" in c for c in audits), name
        # pip-audit comes from one pinned release whose dependencies resolve
        # from a fixed point in time, not from whatever the index serves today.
        for command in audits:
            for tool in re.findall(r"\buvx\b[^\n]*", command):
                assert re.search(rf"--from[ =]pip-audit=={_VERSION}(?!\S)", tool), tool
                assert re.search(rf"--exclude-newer[ =]{_TIMESTAMP}(?!\S)", tool), tool


def test_the_weekly_audit_runs_ci_s_audit_on_a_schedule() -> None:
    """audit.yml runs CI's audit step, pinned the same way, every week: an
    advisory against a pinned version fails a run between commits too."""
    workflows = _workflows()
    audit = workflows["audit.yml"]
    triggers = _triggers(audit)
    assert set(triggers) == {"schedule", "workflow_dispatch"}, triggers
    (schedule,) = triggers["schedule"]
    assert re.fullmatch(r"\d{1,2} \d{1,2} \* \* [0-6]", schedule["cron"]), f"not weekly: {schedule}"
    _assert_keys("audit.yml", audit, _WORKFLOW_KEYS)
    ((job_name, job),) = audit["jobs"].items()
    # The same rules as CI's jobs: nothing can skip the audit or swallow its status.
    assert _job_runs(f"audit.yml:{job_name}", job) == [*_SETUP_ACTIONS, _AUDIT.pattern]

    def audits(steps: Iterable[dict[str, Any]]) -> list[str]:
        return [script for step in steps if _AUDIT.fullmatch(script := _script(step.get("run", "")))]

    assert audits(job["steps"]) == audits(_steps(workflows["ci.yml"])), "the weekly audit differs from CI's"


def test_ci_gives_the_unit_suite_a_hashed_pip_so_the_bundle_builder_tests_run() -> None:
    # `uv sync` makes a venv without pip, and the offline bundle builder's tests
    # (test_hardening_2026_09_27_packaging.py) skip without one: the install
    # step adds pip from one exact pin with its hashes, the audit covers it and
    # Dependabot bumps it.
    for name, wf in _gating_workflows().items():
        installs = [_script(step["run"]) for step in _steps(wf) if step.get("id") == "sync"]
        assert installs == [_INSTALL] * len(wf["jobs"]), f"{name}: {installs}"
        assert any(_AUDIT.fullmatch(_script(step.get("run", ""))) for step in _steps(wf)), name
    pin = _ci_pip_pin(REPO / _CI_PIP)
    dependabot = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    tracked = {(u["package-ecosystem"], u["directory"]) for u in dependabot["updates"]}
    assert ("pip", "/" + Path(_CI_PIP).parent.as_posix()) in tracked, tracked
    # In CI this suite runs in that venv, with that pip.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        _assert_pip_runs([sys.executable], pin)


def _ci_pip_pin(path: Path) -> str:
    """The pip release a CI pip requirements file pins, with the file read as
    uv (CI's install) and pip (whose parser pip-audit uses) read it: anything
    else in it, an install option above all, fails, and so does a coding line,
    under which pip would read it differently."""
    # Python's text read turns CRLF and a lone CR into a newline: pip and uv
    # end a line at each too.
    text = path.read_text(encoding="utf-8")
    # pip and pip-audit's parser decode the file in the codec a PEP 263 coding
    # line names (utf-7, unicode_escape), where '+AAo-' or '\x0a' in a comment
    # is a newline to them alone: uv reads UTF-8, as this check does. pip
    # splits at b'\n' first, so a CR-only file is one "first line": any
    # coding declaration anywhere is refused.
    assert not re.search(r"coding[:=]", text), f"{_CI_PIP}: a coding declaration, which pip and pip-audit honour"
    # Printable ASCII and newlines only: lstrip and \d below would also take a
    # no-break space for an indent and an Arabic-Indic digit for a digit,
    # where pip and uv may not. FF, VT and NEL fail here too; splitlines below
    # would end a line at each, as pip does.
    assert re.fullmatch(r"[ -~\n]*", text), f"{_CI_PIP}: a character other than printable ASCII or a newline"
    # pip and uv end a continuation at a comment line: pip then reads the pin
    # without its hashes and the --hash lines apart, and uv fails to parse.
    assert not re.search(r"\\\n *#", text), f"{_CI_PIP}: a comment line inside a continued line"
    # Comment lines out first, then the continuations joined: a comment line
    # ends at its newline even after a trailing backslash, and the line after
    # it is read on its own.
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    requirements = _script(body).splitlines()
    assert len(requirements) == 1, f"{_CI_PIP}: {requirements}"
    # One exact pin with its hashes, and no trailing comment: pip continues one
    # that ends in a backslash, uv does not.
    pinned = re.fullmatch(r"pip==([\d.]+)(?: --hash=sha256:[0-9a-f]{64})+", requirements[0])
    assert pinned, f"{_CI_PIP}: {requirements[0]}"
    return pinned.group(1)


# Changes to CI's pip requirements, each as (old, new) on the file; an empty
# old appends new to the pin's last line.
_TO_THE_PIN = ""


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # pip and uv end a comment line at its newline, a trailing backslash
        # too, and obey the line after it: an index, a directory of wheels, or
        # another file of requirements or constraints.
        ("#", "# see below \\\n--index-url https://example.invalid/simple\n#"),
        ("#", "# see below \\\n--extra-index-url https://example.invalid/simple\n#"),
        ("#", "# see below \\\n--no-index --find-links .github/wheels\n#"),
        ("#", "# see below \\\n-r ../requirements/extra.txt\n#"),
        ("#", "  # see below \\\n-c ../requirements/constraints.txt\n#"),
        (_TO_THE_PIN, " \\\n    # see below \\\n--find-links .github/wheels\n"),
        # A trailing comment that ends in a backslash: pip folds the next line
        # into it, uv obeys that line.
        (_TO_THE_PIN, " # pinned \\\n--index-url https://example.invalid/simple\n"),
        # pip also ends a line at FF, VT and NEL, uv at a lone CR.
        ("#", "# see below\x0c--index-url https://example.invalid/simple\n#"),
        ("#", "# see below\x0b--index-url https://example.invalid/simple\n#"),
        ("#", "# see below\x85--index-url https://example.invalid/simple\n#"),
        ("#", "# see below\r--index-url https://example.invalid/simple\n#"),
        # A comment line inside the pin's continuation: pip and uv end the
        # continuation there, pip reads an unhashed pin and uv fails.
        (" \\\n", " \\\n# reviewed 2026-09-28\n"),
        (" \\\n", " \\\n    # see below\n"),
        # Text outside ASCII, where str's lstrip and \d read more than pip or
        # uv may: a comment line indented with a no-break space inside the
        # pin's continuation, a version in Arabic-Indic digits.
        (" \\\n", " \\\n\xa0# see below \\\n"),
        ("pip==", "pip==\u0661"),
        # A coding line: pip and pip-audit decode the file in that codec, uv
        # in UTF-8, so only pip and the audit read the index option or the
        # other requirement hidden in a comment, or audit another package.
        ("#", "# -*- coding: utf-7 -*-\n# see +AAo---index-url https://example.invalid/simple\n#"),
        ("#", "# -*- coding: unicode_escape -*-\n# see \\x0a--index-url https://example.invalid/simple\n#"),
        ("#", "# pip for CI (file coding: utf-7)\n#"),
        # An option, or another requirement, in plain sight.
        ("#", "--find-links .github/wheels\n#"),
        ("pip==", "setuptools==80.9.0 --hash=sha256:" + "0" * 64 + "\npip=="),
    ],
)
def test_the_ci_pip_check_reads_the_file_as_pip_and_uv_do(tmp_path: Path, old: str, new: str) -> None:
    # An option this check missed could install a pip from anywhere, and a
    # .pth inside it runs at every interpreter start in CI's venv.
    text = (REPO / _CI_PIP).read_text(encoding="utf-8")
    assert old in text
    changed = tmp_path / "requirements.txt"
    changed.write_bytes((text.replace(old, new, 1) if old else text.rstrip("\n") + new).encode("utf-8"))
    with pytest.raises(AssertionError):
        _ci_pip_pin(changed)


@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_the_ci_pip_check_ends_a_line_at_a_cr_as_pip_and_uv_do(tmp_path: Path, newline: str) -> None:
    # pip and uv end a line at CRLF and at a lone CR, and so does Python's
    # text read: the file with those line ends pins the same pip.
    text = (REPO / _CI_PIP).read_text(encoding="utf-8")
    changed = tmp_path / "requirements.txt"
    changed.write_bytes(text.replace("\n", newline).encode("utf-8"))
    assert _ci_pip_pin(changed) == _ci_pip_pin(REPO / _CI_PIP)


def _assert_pip_runs(python: Sequence[str], pin: str) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter, or a test's stand-in
        [*python, "-m", "pip", "--version"], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0 and proc.stdout.startswith(f"pip {pin} "), f"{python}: {proc.stdout}{proc.stderr}"


@pytest.mark.parametrize(
    ("status", "output", "runs"),
    [
        (0, "pip 26.2.1 from /venv/lib/python3.12/site-packages/pip (python 3.12)", True),
        (1, "pip 26.2.1 from /venv/lib/python3.12/site-packages/pip (python 3.12)", False),
        (0, "pip 26.2.10 from /venv/lib/python3.12/site-packages/pip (python 3.12)", False),
        (0, "", False),
    ],
)
def test_the_pip_check_runs_pip_as_the_bundle_builder_tests_do(
    tmp_path: Path, status: int, output: str, runs: bool
) -> None:
    # pip's metadata can name the pin while `python -m pip` fails to run, and
    # the bundle builder's tests then skip: the check runs pip, as they do.
    python = tmp_path / "python.py"
    python.write_text(f"import sys\nprint({output!r})\nsys.exit({status})\n", encoding="utf-8")
    if runs:
        _assert_pip_runs([sys.executable, str(python)], "26.2.1")
    else:
        with pytest.raises(AssertionError):
            _assert_pip_runs([sys.executable, str(python)], "26.2.1")


def test_ci_runs_the_msi_custom_action_tests_under_pwsh() -> None:
    # The MSI custom-action tests run the real .ps1 scripts under the pwsh on
    # PATH, and skip where there is none (test_hardening_2026_09_27_msi.py,
    # test_msi_ca_executed_failclosed.py, test_msi_packaging.py). CI's runner
    # image ships PowerShell 7, so there they run; should it stop, this fails
    # CI rather than let them skip.
    if os.environ.get("GITHUB_ACTIONS") != "true":
        pytest.skip("checks CI's runner; elsewhere the MSI custom-action tests may skip without pwsh")
    pwsh = shutil.which("pwsh")
    _assert_pwsh_runs([pwsh] if pwsh else None)


def _assert_pwsh_runs(pwsh: Sequence[str] | None) -> None:
    assert pwsh, "no pwsh on PATH: the MSI custom-action tests skip"
    proc = subprocess.run(  # noqa: S603 - fixed argv: the pwsh on PATH, or a test's stand-in
        [*pwsh, "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    major = proc.stdout.strip()
    runs = proc.returncode == 0 and re.fullmatch(r"[0-9]+", major) is not None and int(major) >= 7
    assert runs, f"{pwsh}: does not run as PowerShell 7 or later: {proc.stdout}{proc.stderr}"


@pytest.mark.parametrize(
    ("status", "output", "runs"),
    [
        (0, "7\n", True),
        (0, "5\n", False),
        (1, "7\n", False),
        (0, "", False),
        (None, "", False),  # no pwsh on PATH
    ],
)
def test_the_pwsh_check_runs_pwsh_as_the_msi_tests_do(
    tmp_path: Path, status: int | None, output: str, runs: bool
) -> None:
    pwsh = tmp_path / "pwsh.py"
    pwsh.write_text(f"import sys\nsys.stdout.write({output!r})\nsys.exit({status})\n", encoding="utf-8")
    command = None if status is None else [sys.executable, str(pwsh)]
    if runs:
        _assert_pwsh_runs(command)
    else:
        with pytest.raises(AssertionError):
            _assert_pwsh_runs(command)


def test_no_workflow_runs_on_pull_request_target() -> None:
    for name, wf in _workflows().items():
        assert "pull_request_target" not in _triggers(wf), name


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    uses: list[tuple[str, str]] = []
    for name, wf in _workflows().items():
        uses += [(name, job["uses"]) for job in wf["jobs"].values() if "uses" in job]
        uses += [(name, step["uses"]) for step in _steps(wf) if "uses" in step]
    assert uses
    for name, ref in uses:
        if ref.startswith("./"):
            continue  # an action in this repository, pinned by the checkout itself
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{name}: {ref} is not pinned to a commit SHA"


# The release publish jobs: container.yml's image job pushes to GitHub
# Packages and stores a provenance attestation; its registry job lists the
# release in the MCP Registry with a GitHub OIDC token. Each may write exactly
# these, on a published release or a manual run only (never code from a push
# or a pull request), with no action but the reviewed commits listed: every
# step of a job gets its token.
# Scorecard (scorecard.yml) publishes its results with an OIDC token and
# uploads them to code scanning: on a push to main, a schedule or by hand.
_CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
_RELEASE_TRIGGERS = frozenset({"release", "workflow_dispatch"})
_WRITER_JOBS: dict[tuple[str, str], tuple[frozenset[str], frozenset[str], frozenset[str]]] = {
    ("container.yml", "image"): (
        frozenset({"packages", "id-token", "attestations"}),
        frozenset({_CHECKOUT_ACTION, "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"}),
        _RELEASE_TRIGGERS,
    ),
    ("container.yml", "registry"): (frozenset({"id-token"}), frozenset({_CHECKOUT_ACTION}), _RELEASE_TRIGGERS),
    ("scorecard.yml", "analysis"): (
        frozenset({"security-events", "id-token"}),
        frozenset({
            _CHECKOUT_ACTION,
            "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc",
            "github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d",
        }),
        frozenset({"push", "schedule", "branch_protection_rule", "workflow_dispatch"}),
    ),
}


def _assert_tokens_are_read_only_unless_a_job_needs_more(workflows: dict[str, dict[str, Any]]) -> None:
    for name, wf in workflows.items():
        top = wf.get("permissions")
        assert isinstance(top, dict), f"{name}: set workflow-level permissions explicitly (read-only or {{}})"
        assert all(v in ("read", "none") for v in top.values()), f"{name}: workflow-level write {top}"
        for job_name, job in wf["jobs"].items():
            perms = job.get("permissions", {})
            assert isinstance(perms, dict), f"{name}:{job_name}: {perms}"
            writes = {k for k, v in perms.items() if v == "write"}
            if not writes:
                continue
            if (name, job_name) in _WRITER_JOBS:
                allowed_writes, allowed_actions, allowed_triggers = _WRITER_JOBS[(name, job_name)]
                assert writes == allowed_writes, f"{name}:{job_name}: {writes}"
                triggers = _triggers(wf)
                assert set(triggers) <= allowed_triggers, f"{name}: runs on {sorted(triggers)}"
                if "push" in triggers:  # code that is on main, never a branch or a tag
                    assert triggers["push"] == {"branches": ["main"]}, f"{name}: push {triggers['push']}"
                actions = {str(s["uses"]) for s in job.get("steps", []) if "uses" in s}
                assert actions <= allowed_actions, f"{name}:{job_name}: {sorted(actions - allowed_actions)}"
                continue
            # Otherwise only the Pages deploy may write, only what deploy-pages
            # needs, and in a job that runs deploy-pages alone: every step of
            # a job gets its token, and the OIDC token request.
            assert writes <= {"pages", "id-token"}, f"{name}:{job_name}: {writes}"
            steps = [str(s.get("uses", s.get("run", ""))) for s in job.get("steps", [])]
            assert len(steps) == 1 and steps[0].startswith("actions/deploy-pages@"), f"{name}:{job_name}: {steps}"


def test_workflow_tokens_are_read_only_unless_a_job_needs_more() -> None:
    _assert_tokens_are_read_only_unless_a_job_needs_more(_workflows())


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # code from a push or a pull request with the package-writing token
        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"),
        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n"),
        # a write it does not need, or a write moved to the whole workflow
        ("      attestations: write\n", "      attestations: write\n      contents: write\n"),
        ("permissions: {}\n", "permissions:\n  packages: write\n"),
        # an action other than the reviewed commits
        ("actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
         "actions/attest-build-provenance@" + "0" * 40),
        ("      - name: Check the release tag\n", "      - uses: docker/login-action@" + "1" * 40 + "\n"
         "      - name: Check the release tag\n"),
        # the registry job: only an OIDC token, only the checkout
        ("    permissions:\n      contents: read\n      id-token: write\n    env:\n",
         "    permissions:\n      contents: read\n      id-token: write\n      packages: write\n    env:\n"),
        ("      - name: Install mcp-publisher\n",
         "      - uses: actions/setup-node@" + "2" * 40 + "\n      - name: Install mcp-publisher\n"),
    ],
)
def test_the_container_job_cannot_widen_its_token(old: str, new: str) -> None:
    workflows = _workflows()
    _assert_tokens_are_read_only_unless_a_job_needs_more(workflows)
    text = (WORKFLOWS / "container.yml").read_text(encoding="utf-8")
    assert old in text
    with pytest.raises(AssertionError):
        _assert_tokens_are_read_only_unless_a_job_needs_more(
            {**workflows, "container.yml": _load_yaml(text.replace(old, new, 1))}
        )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"),
        ("    branches: [main]\n", "    branches: ['**']\n"),
        ("      id-token: write\n", "      id-token: write\n      contents: write\n"),
        (
            "      - uses: ossf/scorecard-action@",
            "      - uses: actions/setup-python@" + "3" * 40 + "\n      - uses: ossf/scorecard-action@",
        ),
    ],
)
def test_the_scorecard_job_cannot_widen_its_token(old: str, new: str) -> None:
    workflows = _workflows()
    _assert_tokens_are_read_only_unless_a_job_needs_more(workflows)
    text = (WORKFLOWS / "scorecard.yml").read_text(encoding="utf-8")
    assert old in text
    with pytest.raises(AssertionError):
        _assert_tokens_are_read_only_unless_a_job_needs_more(
            {**workflows, "scorecard.yml": _load_yaml(text.replace(old, new, 1))}
        )


def test_checkouts_do_not_leave_the_token_in_the_git_config() -> None:
    for name, wf in _workflows().items():
        for step in _steps(wf):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False, name


def test_dependabot_tracks_the_python_dependencies_and_the_action_pins() -> None:
    config = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert config["version"] == 2
    ecosystems = {u["package-ecosystem"] for u in config["updates"]}
    assert {"pip", "github-actions"} <= ecosystems


def test_dependabot_skips_every_release_past_a_pyproject_cap() -> None:
    """A capped dependency moves past its cap by review: a weekly bump past it
    fails the lock check, or (the uv ecosystem) widens the cap itself."""
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extras = project["optional-dependencies"].values()
    requirements = [*project["dependencies"], *(r for extra in extras for r in extra)]
    caps: dict[str, Version] = {}
    for text in requirements:
        requirement = Requirement(text)
        for spec in requirement.specifier:
            if spec.operator == "<":
                bound = Version(spec.version)
            elif spec.operator == "~=":
                release = Version(spec.version).release[:-1]
                bound = Version(".".join(map(str, (*release[:-1], release[-1] + 1))))
            else:
                continue
            name = canonicalize_name(requirement.name)
            caps[name] = min(bound, caps.get(name, bound))
    assert {"uvicorn", "h11", "sqlglot", "clickhouse-connect"} <= caps.keys()
    config = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    locked = {("uv", "/"), ("pip", "/requirements")}
    python = [u for u in config["updates"] if (u["package-ecosystem"], u["directory"]) in locked]
    assert len(python) == 2
    for update in python:
        ignored: dict[str, Version] = {}
        for rule in update.get("ignore", []):
            for versions in rule["versions"]:
                assert versions.startswith(">="), rule
                ignored[canonicalize_name(rule["dependency-name"])] = Version(versions[2:])
        for capped, bound in caps.items():
            where = update["directory"]
            assert capped in ignored and ignored[capped] <= bound, f"{where}: {capped} >= {bound} is not ignored"


def test_scripts_ruff_config_extends_the_project_config_with_file_scoped_ignores() -> None:
    text = (REPO / "scripts" / "ruff.toml").read_text(encoding="utf-8")
    config = tomllib.loads(text)
    assert config["extend"] == "../pyproject.toml"
    ignores = config["lint"]["per-file-ignores"]
    assert ignores
    for pattern, rules in ignores.items():
        # A security rule is waived file by file, never for the whole directory.
        assert "*" not in pattern, pattern
        assert (REPO / "scripts" / pattern).is_file(), pattern
        assert rules
    # Each waiver carries its reason on the line above it.
    for match in re.finditer(r'^"[^"]+"\s*=', text, re.M):
        before = text[: match.start()].rstrip("\n").splitlines()
        assert before and before[-1].lstrip().startswith("#"), match.group(0)


def test_the_mcp_registry_entry_names_the_image_the_container_workflow_labels() -> None:
    """server.json lists the published image in the MCP Registry, which accepts
    it only when the image's io.modelcontextprotocol.server.name label equals
    the entry's name; container.yml writes that label and the release version."""
    entry = json.loads((REPO / "server.json").read_text(encoding="utf-8"))
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert entry["name"] == "io.github.alghanim/universal-db-mcp"
    assert len(entry["description"]) <= 100
    assert entry["version"] == project["version"]
    (package,) = entry["packages"]
    assert package["registryType"] == "oci" and package["transport"] == {"type": "stdio"}
    assert package["identifier"] == f"ghcr.io/alghanim/universal-db-mcp:{project['version']}"
    workflow = (WORKFLOWS / "container.yml").read_text(encoding="utf-8")
    assert '--label "io.modelcontextprotocol.server.name=io.github.$GITHUB_REPOSITORY"' in workflow
    assert '"io.github.$GITHUB_REPOSITORY"' in workflow, "the registry job checks the name against the label"
