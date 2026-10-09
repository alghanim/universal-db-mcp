"""Re-attack, round 3 (2026-09-29): no root job acts by name in a directory the
service account can write.

The .pkg installed a newsyslog(8) rule, ``/var/log/universal-db-mcp/*.log
_udbmcp:_udbmcp 640 7 10240 * GJ``, at /etc/newsyslog.d/udbmcp.conf. macOS runs
newsyslog as root every hour, and a rotation renames every archive slot, then
chmods and chowns it by name, following a symlink there (it imports chmod and
chown, not the l-variants). /var/log/universal-db-mcp belongs to _udbmcp, so a
compromised server planted http.log.0.bz2 .. .6.bz2 as links to root's files,
grew a *.log past 10 MB, and the next run handed each target to _udbmcp
(reproduced with /usr/sbin/newsyslog on the shipped rule: every linked target
was chmodded and chgrpped, the control file was not).

The class is root acting by name in a directory the service account can write.
Installer steps are pinned in test_hardening_2026_09_28_converge_packaging;
this file covers the rest:

1. nothing shipped makes root run a job on a schedule (a newsyslog or logrotate
   rule, a cron or at table, a periodic script, a systemd timer), and every
   service definition runs as the service account;
1b. launchd opens a job's StandardOutPath and StandardErrorPath itself, as
   root, following a symlink there: the .pkg kept them in the service
   account's log directory, so a link planted at server.log led root's open
   to any file. No path launchd opens for a shipped job is in a directory the
   service account can write, and the .pkg makes the one it uses root's;
2. the .pkg removes the rule an earlier release installed, and fails closed
   when it cannot;
3. the daemon keeps the files launchd appends its stdout and stderr to under a
   cap itself, as the service account, and empties only a regular file with
   one link that account owns (never one launchd reached through a link);
4. doctor, which the runbook runs under sudo, opens the audit lock without
   following a link that was swapped in after its check.
"""

from __future__ import annotations

import io
import logging
import os
import plistlib
import re
import shlex
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import test_pkg_postinstall_executed_failclosed as executed
from test_hardening_2026_09_27_cli_transport import restore_logging  # noqa: F401 - fixture
from test_pkg_postinstall_executed_failclosed import (
    _actions,
    _build_bundle,
    _build_shims,
    _pubkey_stub,
    _run_postinstall,
    _verifier_stub,
)

from universal_db_mcp.diagnostics import doctor

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="launchd, newsyslog and POSIX descriptors")

REPO = Path(__file__).resolve().parents[2]
PACKAGING = REPO / "packaging"
PLIST = PACKAGING / "launchd" / "com.udbmcp.server.plist"
_XML_COMMENT = re.compile(rb"<!--.*?-->", re.S)

# The rule the releases before this one installed (packaging/launchd/udbmcp.newsyslog.conf).
_OLD_RULE = "/var/log/universal-db-mcp/*.log\t_udbmcp:_udbmcp\t640\t7\t10240\t*\tGJ\n"


# ---- 1. nothing shipped makes root run a job on a schedule ---------------------------------------

# Where a file makes root run something on a schedule. LaunchDaemons are checked by their UserName.
_ROOT_JOB_PLACE = (
    r"/etc/(?:newsyslog\.(?:d|conf)|logrotate\.(?:d|conf)|cron(?:tab|\.[a-z]+)|periodic)\b"
    r"|/var/at/|/usr/lib/cron/|/etc/systemd/system/[^\s\"']*\.timer\b"
)
_PLACING_COMMANDS = {"install", "cp", "ln", "mv", "tee", "ditto", "rsync", "touch", "crontab"}
_REDIRECT_INTO_ROOT_JOB_PLACE = re.compile(r">{1,2}\|?\s*\"?(?:" + _ROOT_JOB_PLACE + ")")
_LEADING_KEYWORDS = {"if", "elif", "then", "else", "do", "while", "until", "!", "{", "(", "sudo", "$sudo_ok"}
_ASSIGNMENT = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)="([^"$`]*)"\s*$')
_WINDOWS_SCHEDULED_TASK = re.compile(r"Register-ScheduledTask|New-ScheduledTask|\bschtasks\b", re.I)


def _root_job_placements(text: str) -> list[str]:
    """The lines of shell *text* that put a file where root runs it on a schedule (or install a
    crontab). Variables assigned a literal path in the text are expanded first."""
    assigned = {m.group(1): m.group(2) for line in text.splitlines() if (m := _ASSIGNMENT.match(line))}
    found = []
    for line in text.splitlines():
        code = line.split(" #", 1)[0]
        if code.lstrip().startswith("#"):
            continue
        expanded = re.sub(
            r"\$\{?([A-Z_][A-Z0-9_]*)\}?", lambda m: assigned.get(m.group(1), m.group(0)), code
        )
        if _REDIRECT_INTO_ROOT_JOB_PLACE.search(expanded):
            found.append(line)
            continue
        for segment in re.split(r"&&|\|\||[;|]", expanded):
            words = segment.split()
            while words and words[0] in _LEADING_KEYWORDS:
                words.pop(0)
            if not words or words[0] not in _PLACING_COMMANDS:
                continue
            if words[0] == "crontab" and words[1:2] == ["-l"]:
                continue
            if words[0] == "crontab" or re.search(_ROOT_JOB_PLACE, segment):
                found.append(line)
                break
    return found


@pytest.mark.parametrize(
    ("text", "places"),
    [
        # the old postinstall step 6b, its two lines
        ('NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"\n'
         'elif install -d -m 0755 -o root -g wheel "$(dirname "$NEWSYSLOG_DST")" 2>/dev/null \\\n'
         '     && install -m 0644 -o root -g wheel "$NEWSYSLOG_SRC" "$NEWSYSLOG_DST" 2>/dev/null; then\n', True),
        ("cp udbmcp.logrotate /etc/logrotate.d/universal-db-mcp\n", True),
        ('$sudo_ok install -m 0644 "$X" /etc/logrotate.d/udbmcp\n', True),
        ("ln -sf /usr/local/universal-db-mcp/rotate /etc/periodic/daily/500.udbmcp\n", True),
        ("echo '0 * * * * root /usr/local/bin/rotate' > /etc/cron.d/udbmcp\n", True),
        ('printf "%s" "$RULE" >> "/etc/newsyslog.conf"\n', True),
        ("install -m 0644 rotate.timer /etc/systemd/system/udbmcp-rotate.timer\n", True),
        ("crontab -u root /tmp/udbmcp.cron\n", True),
        # removing, testing for or naming one places nothing
        ('NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"\nrm -f -- "$NEWSYSLOG_DST" || fail "x"\n', False),
        ('NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"\nif [ -e "$NEWSYSLOG_DST" ]; then\n', False),
        ('NEWSYSLOG_DST="/etc/newsyslog.d/udbmcp.conf"\necho "could not install $NEWSYSLOG_DST" >&2\n', False),
        ("# install -m 0644 x /etc/newsyslog.d/udbmcp.conf\n", False),
        ("crontab -l\n", False),
        ('install -m 0644 "$PLIST_SRC" "$LAUNCH_DEST/com.udbmcp.server.plist"\n', False),
        ("install -d -o udbmcp -g udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp\n", False),
    ],
)
def test_the_root_job_placement_detector(text: str, places: bool) -> None:
    assert bool(_root_job_placements(text)) is places


def _shipped_text_files() -> list[Path]:
    files = []
    for top in (PACKAGING, REPO / "scripts"):
        for path in sorted(top.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            files.append(path)
    return files


def test_no_shipped_file_is_a_rotation_rule_or_scheduled_job() -> None:
    named = [
        str(p.relative_to(REPO)) for p in _shipped_text_files()
        if re.search(r"newsyslog|logrotate|cron|periodic|\.timer$", p.name, re.I)
    ]
    assert named == [], named


@pytest.mark.parametrize("path", _shipped_text_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_no_installer_build_or_service_script_places_a_root_job(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    where = path.relative_to(REPO)
    if path.suffix in {"", ".sh"}:  # the deb and pkg maintainer scripts, the installers, the builds
        assert _root_job_placements(text) == [], f"{where}: root runs this on a schedule"
    elif path.suffix == ".py":
        assert not re.search(_ROOT_JOB_PLACE, text), f"{where}: names where root runs jobs on a schedule"
    elif path.suffix in {".ps1", ".wxs"}:
        assert not _WINDOWS_SCHEDULED_TASK.search(text), f"{where}: a scheduled task"


def test_the_shipped_service_definitions_run_as_the_service_account() -> None:
    """A LaunchDaemon without UserName, or a unit without User=, is root's."""
    plists = sorted(PACKAGING.rglob("*.plist"))
    assert plists == [PLIST], plists
    plist = plistlib.loads(_XML_COMMENT.sub(b"", PLIST.read_bytes()))
    assert plist["UserName"] == "_udbmcp"
    units = sorted(PACKAGING.rglob("*.service")) + sorted(PACKAGING.rglob("*.timer"))
    assert [u.name for u in units] == ["universal-db-mcp.service"], units
    users = [ln.split("=", 1)[1].strip() for ln in units[0].read_text(encoding="utf-8").splitlines()
             if ln.startswith("User=")]
    assert users == ["udbmcp"], users


# ---- 1b. launchd opens nothing for a shipped job where the service account can write -------------

PKG_POSTINSTALL = PACKAGING / "pkg" / "postinstall"
_SERVICE_DIRS = {"/var/lib/universal-db-mcp", "/var/log/universal-db-mcp"}
# launchd, as root, opens (O_CREAT for the output files), binds or watches these for a job by name.
_LAUNCHD_PATH_KEYS = ("StandardInPath", "StandardOutPath", "StandardErrorPath", "WatchPaths", "QueueDirectories")


def _launchd_paths(job: dict[str, Any]) -> list[str]:
    """The paths launchd itself opens, binds or watches for the job *job* (a loaded plist)."""
    paths: list[str] = []
    for key in _LAUNCHD_PATH_KEYS:
        value = job.get(key)
        paths += [value] if isinstance(value, str) else list(value or ())
    keep_alive = job.get("KeepAlive")
    if isinstance(keep_alive, dict):
        paths += list(keep_alive.get("PathState") or {})
    for entry in (job.get("Sockets") or {}).values():
        paths += [s["SockPathName"] for s in (entry if isinstance(entry, list) else [entry]) if "SockPathName" in s]
    return paths


def _launchd_path_problems(job: dict[str, Any], service_dirs: set[str], root_dirs: set[str]) -> list[str]:
    """Each path launchd opens for *job* that is in (or below) a directory the service account owns,
    or not directly in one the installer makes root's. /dev/null is neither."""
    problems = []
    for path in _launchd_paths(job):
        if path == "/dev/null":
            continue
        inside = sorted(d for d in service_dirs if path == d or path.startswith(f"{d}/"))
        if inside:
            problems.append(f"{path}: in {inside[0]}, which the service account can write")
        elif os.path.dirname(path) not in root_dirs:
            problems.append(f"{path}: not in a directory the installer makes root's")
    return problems


def _postinstall_directories() -> dict[str, set[str]]:
    """The directories the .pkg postinstall creates with install -d, by the owner it gives them
    (root when it names none: postinstall runs as root)."""
    text = PKG_POSTINSTALL.read_text(encoding="utf-8")
    assigned = {m.group(1): m.group(2) for line in text.splitlines() if (m := _ASSIGNMENT.match(line))}
    owners: dict[str, set[str]] = {}
    for line in text.splitlines():
        code = line.split(" #", 1)[0].split("||", 1)[0]
        made = re.match(r"\s*install -d\s(.*)$", re.sub(r"\s[0-9]*>\S*", "", code))
        if not made:
            continue
        words = shlex.split(re.sub(r"\$\{?([A-Z_][A-Z0-9_]*)\}?", lambda m: assigned.get(m.group(1), m.group(0)),
                                   made.group(1)))
        owner, dirs = "root", []
        while words:
            word = words.pop(0)
            if word == "-o":
                owner = words.pop(0)
            elif word in ("-g", "-m"):
                words.pop(0)
            else:
                dirs.append(word)
        owners.setdefault(owner, set()).update(dirs)
    return owners


_SOME_ROOT_DIRS = {"/Library/Logs/universal-db-mcp", "/usr/local/universal-db-mcp"}


@pytest.mark.parametrize(
    ("job", "flagged"),
    [
        # the shipped plist before this fix: both in the directory _udbmcp owns
        ({"StandardOutPath": "/var/log/universal-db-mcp/server.log",
          "StandardErrorPath": "/var/log/universal-db-mcp/server.err.log"}, True),
        # a subdirectory there: the account renames it and puts its own in its place
        ({"StandardErrorPath": "/var/log/universal-db-mcp/launchd/server.err.log"}, True),
        ({"StandardInPath": "/var/lib/universal-db-mcp/stdin"}, True),
        ({"WatchPaths": ["/var/log/universal-db-mcp/http.log"]}, True),
        ({"QueueDirectories": ["/var/lib/universal-db-mcp/queue"]}, True),
        ({"KeepAlive": {"PathState": {"/var/lib/universal-db-mcp/run": True}}}, True),
        ({"Sockets": {"Listener": {"SockPathName": "/var/lib/universal-db-mcp/mcp.sock"}}}, True),
        ({"Sockets": {"Listener": [{"SockPathName": "/var/log/universal-db-mcp/mcp.sock"}]}}, True),
        # a directory nothing makes root's
        ({"StandardErrorPath": "/Library/Logs/elsewhere/server.err.log"}, True),
        ({"StandardOutPath": "/dev/null", "StandardErrorPath": "/Library/Logs/universal-db-mcp/server.err.log"}, False),
        # the daemon opens its own log, as the service account
        ({"EnvironmentVariables": {"UDBMCP_HTTP_LOG_FILE": "/var/log/universal-db-mcp/http.log"}}, False),
        ({"KeepAlive": {"SuccessfulExit": False}}, False),
    ],
)
def test_the_launchd_path_detector(job: dict[str, Any], flagged: bool) -> None:
    assert bool(_launchd_path_problems(job, _SERVICE_DIRS, _SOME_ROOT_DIRS)) is flagged


def test_the_postinstall_directory_reader() -> None:
    owners = _postinstall_directories()
    assert _SERVICE_DIRS <= owners.pop("_udbmcp"), owners
    assert set(owners) == {"root"}, owners
    assert {"/usr/local/universal-db-mcp", "/etc/universal-db-mcp", "/usr/local/bin"} <= owners["root"], owners


def test_launchd_opens_nothing_for_a_shipped_job_in_a_directory_the_service_account_can_write() -> None:
    """The .pkg's plist is the only launchd job shipped; the directories come from the postinstall
    that creates them."""
    owners = _postinstall_directories()
    service_dirs = owners.pop("_udbmcp")
    root_dirs = set().union(*owners.values())
    for path in sorted(PACKAGING.rglob("*.plist")):
        job = plistlib.loads(_XML_COMMENT.sub(b"", path.read_bytes()))
        assert _launchd_paths(job), f"{path.name}: launchd keeps the daemon's stdout and stderr"
        assert _launchd_path_problems(job, service_dirs, root_dirs) == [], path.name


# ---- 2. the .pkg removes the rule an earlier release installed -----------------------------------


@pytest.fixture(autouse=True)
def _alias_in_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    """The executed harness leaves the CLI alias at /usr/local/bin/udbmcp; these runs put it in the
    sandbox's shim directory instead."""
    rewrites = [*executed._PATH_REWRITES, (r'^ALIAS="/usr/local/bin/udbmcp"$', 'ALIAS="{shim}/udbmcp"')]
    monkeypatch.setattr(executed, "_PATH_REWRITES", rewrites)


def _upgrade_sandbox(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A passing postinstall sandbox with an earlier release's rule and its payload copy left in
    place. Returns (bundle, installed rule, payload copy)."""
    bundle = _build_bundle(tmp_path)
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    _build_shims(tmp_path)
    (tmp_path / "com.udbmcp.server.plist").write_text("<plist/>", encoding="utf-8")
    rule = tmp_path / "etc" / "newsyslog.d" / "udbmcp.conf"
    rule.parent.mkdir(parents=True)
    rule.write_text(_OLD_RULE, encoding="utf-8")
    payload_copy = tmp_path / "prefix" / "share" / "udbmcp.newsyslog.conf"
    payload_copy.write_text(_OLD_RULE, encoding="utf-8")
    return bundle, rule, payload_copy


def test_the_upgrade_removes_the_newsyslog_rule_an_earlier_release_installed(tmp_path: Path) -> None:
    bundle, rule, payload_copy = _upgrade_sandbox(tmp_path)
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert not rule.exists() and not rule.is_symlink(), out
    assert not payload_copy.exists(), out
    assert f"removed {rule}" in out, out
    assert rule.parent.is_dir(), "the system's newsyslog.d itself is left alone"


def test_a_fresh_install_places_no_rotation_rule(tmp_path: Path) -> None:
    bundle, rule, payload_copy = _upgrade_sandbox(tmp_path)
    rule.unlink()
    payload_copy.unlink()
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert not rule.exists() and "newsyslog" not in "\n".join(_actions(tmp_path)), out
    assert "newsyslog" not in out, out


def test_a_rule_that_cannot_be_removed_aborts_the_install_before_the_daemon_starts(tmp_path: Path) -> None:
    bundle, rule, _payload_copy = _upgrade_sandbox(tmp_path)
    rule.unlink()
    rule.mkdir()  # rm -f refuses a directory
    (rule / "keep").write_text("x", encoding="utf-8")
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert f"FAIL: could not remove {rule}" in out, out
    assert not [a for a in _actions(tmp_path) if a.startswith("LAUNCHCTL bootstrap")], out


# ---- 2b. the .pkg makes the directory launchd opens the daemon's output files in root's ------------


def _launchd_output_files(tmp_path: Path) -> tuple[Path, list[str]]:
    """(the sandbox's stand-in for the directory, the file names) the plist names for launchd's
    StandardOutPath and StandardErrorPath, checked against the directory postinstall provisions."""
    job = plistlib.loads(_XML_COMMENT.sub(b"", PLIST.read_bytes()))
    paths = [job["StandardOutPath"], job["StandardErrorPath"]]
    provisioned = re.findall(r'^LAUNCHD_LOG_DIR="([^"]+)"$', PKG_POSTINSTALL.read_text(encoding="utf-8"), re.M)
    assert [os.path.dirname(p) for p in paths] == provisioned * 2, (paths, provisioned)
    return executed._launchd_log_dir(tmp_path), [os.path.basename(p) for p in paths]


def _bootstrapped_at(actions: list[str]) -> int:
    return next(i for i, action in enumerate(actions) if action.startswith("LAUNCHCTL bootstrap"))


def test_a_fresh_install_creates_launchds_output_files_where_only_root_can_write(tmp_path: Path) -> None:
    bundle, _rule, _payload_copy = _upgrade_sandbox(tmp_path)
    directory, names = _launchd_output_files(tmp_path)
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    actions = _actions(tmp_path)
    made = actions.index(f"INSTALL -d -m 0755 -o root -g wheel {directory}")
    created = [actions.index(f"INSTALL -m 0640 -o _udbmcp -g _udbmcp /dev/null {directory / n}") for n in names]
    assert made < min(created) and max(created) < _bootstrapped_at(actions), actions
    assert sorted(p.name for p in directory.iterdir()) == sorted(names)


def test_an_upgrade_keeps_launchds_output_files_and_hands_them_to_the_service_account(tmp_path: Path) -> None:
    """launchd creates a missing one as root: the daemon caps only a file its account owns."""
    bundle, _rule, _payload_copy = _upgrade_sandbox(tmp_path)
    directory, names = _launchd_output_files(tmp_path)
    directory.mkdir(parents=True)
    for name in names:
        (directory / name).write_text(f"{name} of the last start\n", encoding="utf-8")
    log = tmp_path / "shim-actions.log"
    executed._write_shim(tmp_path / "shim-bin", "chown", f'#!/bin/bash\nprintf \'CHOWN %s\\n\' "$*" >> "{log}"\n')
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    actions = _actions(tmp_path)
    for name in names:
        assert (directory / name).read_text(encoding="utf-8") == f"{name} of the last start\n"
        assert (directory / name).stat().st_mode & 0o777 == 0o640
        assert actions.index(f"CHOWN _udbmcp:_udbmcp {directory / name}") < _bootstrapped_at(actions), actions
    assert not [a for a in actions if a.startswith("INSTALL -m 0640")], actions


@pytest.mark.parametrize("case", ["directory-link", "file-link", "file-fifo", "writable-above"])
def test_launchds_output_directory_that_is_not_roots_alone_aborts_before_the_daemon_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    bundle, _rule, _payload_copy = _upgrade_sandbox(tmp_path)
    directory, names = _launchd_output_files(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    victim = elsewhere / "master.passwd"
    victim.write_text("root:*:0:0::0:0:System Administrator:/var/root:/bin/sh\n", encoding="utf-8")
    victim.chmod(0o600)
    directory.parent.mkdir(parents=True)
    if case == "directory-link":
        directory.symlink_to(elsewhere)
        expected = f"FAIL: {directory} is a symlink"
    elif case == "writable-above":
        # find(1) reports the directory above it as another account's (the check itself is the one
        # every root-run interpreter passes, exercised in test_hardening_2026_09_27_packaging)
        find = executed._write_shim(
            tmp_path, "find-flags-above", f'#!/bin/sh\n[ "$1" != "{directory.parent}" ] || echo "$1"\nexit 0\n'
        )
        rewrites = [(p, f'FIND="{find}"' if p.startswith("^FIND=") else r) for p, r in executed._PATH_REWRITES]
        monkeypatch.setattr(executed, "_PATH_REWRITES", rewrites)
        expected = f"FAIL: {directory.parent} is not owned by root, or another account can write to it"
    else:
        directory.mkdir()
        if case == "file-link":
            (directory / names[1]).symlink_to(victim)
        else:
            os.mkfifo(directory / names[0])
        expected = f"FAIL: {directory / names[1 if case == 'file-link' else 0]} is not a regular file"
    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert expected in out, out
    assert not [a for a in _actions(tmp_path) if a.startswith("LAUNCHCTL bootstrap")], out
    assert victim.read_text(encoding="utf-8").startswith("root:*:0:0:") and victim.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in elsewhere.iterdir()) == ["master.passwd"]


# ---- 3. the daemon caps the files launchd appends its output to ----------------------------------

_CAP = 1024
_FILL = b"~"


def _over_cap(path: Path, *, append: bool = True) -> int:
    """*path* filled past the cap, opened for writing at its end like launchd's StandardErrorPath
    (O_APPEND) or like a shell's > redirect that has written that much (no O_APPEND)."""
    path.write_bytes(_FILL * (_CAP * 3))
    flags = os.O_WRONLY | (os.O_APPEND if append else 0)
    fd = os.open(path, flags)
    os.lseek(fd, 0, os.SEEK_END)
    return fd


@pytest.mark.parametrize("append", [True, False], ids=["O_APPEND", "no-O_APPEND"])
def test_output_over_the_cap_is_emptied_and_later_writes_start_at_the_top(tmp_path: Path, append: bool) -> None:
    from universal_db_mcp.http_protocol import cap_service_output

    path = tmp_path / "server.err.log"
    fd = _over_cap(path, append=append)
    try:
        cap_service_output((fd,), _CAP)
        os.write(fd, b"CONFIG_ERROR: next start\n")
    finally:
        os.close(fd)
    text = path.read_bytes()
    assert _FILL not in text and b"\0" not in text, text[:80]
    assert text.startswith(b"universal-db-mcp: emptied this file at 3072 bytes"), text
    assert text.endswith(b"CONFIG_ERROR: next start\n") and len(text) < _CAP, text


def test_output_under_the_cap_a_pipe_and_a_closed_descriptor_are_left_alone(tmp_path: Path) -> None:
    from universal_db_mcp.http_protocol import cap_service_output

    path = tmp_path / "server.log"
    path.write_bytes(_FILL * _CAP)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    read_end, write_end = os.pipe()
    closed = os.open(os.devnull, os.O_WRONLY)
    os.close(closed)
    try:
        os.write(write_end, b"y" * (_CAP * 3))
        cap_service_output((fd, write_end, closed), _CAP)
        assert path.read_bytes() == _FILL * _CAP
        assert os.read(read_end, _CAP * 4) == b"y" * (_CAP * 3)
    finally:
        for descriptor in (fd, read_end, write_end):
            os.close(descriptor)


@pytest.mark.parametrize("case", ["another-account", "second-link"])
def test_output_that_is_not_the_daemons_own_single_link_file_is_never_emptied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """launchd opens StandardOutPath and StandardErrorPath as root and follows a link there, so a
    descriptor it hands the daemon may be any file: the re-attack planted server.log as a link to a
    root file (in a plist that still names the service account's directory) and the cap emptied it.
    It empties only a regular file with one link that the daemon's own account owns: one it could
    empty by name anyway."""
    from universal_db_mcp.http_protocol import cap_service_output

    victim = tmp_path / "master.passwd"
    victim.write_bytes(_FILL * (_CAP * 3))
    name = tmp_path / "server.log"
    if case == "another-account":
        name.symlink_to(victim)
        daemon = os.geteuid() + 1
        monkeypatch.setattr(os, "geteuid", lambda: daemon)  # the file is not the daemon's account's
    else:
        os.link(victim, name)
    fd = os.open(name, os.O_WRONLY | os.O_APPEND)  # what launchd hands over, opened through the name
    try:
        cap_service_output((fd,), _CAP)
    finally:
        os.close(fd)
    assert victim.read_bytes() == _FILL * (_CAP * 3)


def _serve_without_config(tmp_path: Path, *, log_file_env: bool) -> tuple[Path, Path, int]:
    """One start of the launchd daemon that fails before it reads a config (the crash-loop case:
    launchd restarts it every ThrottleInterval), its stdout and stderr appended to files already
    past LOG_FILE_MAX_BYTES as launchd opens them."""
    from universal_db_mcp.http_protocol import LOG_FILE_ENV, LOG_FILE_MAX_BYTES

    out, err = tmp_path / "server.log", tmp_path / "server.err.log"
    for path in (out, err):
        path.write_bytes(_FILL * (LOG_FILE_MAX_BYTES + 1))
    env = {k: v for k, v in os.environ.items() if not k.startswith("UDBMCP_")}
    if log_file_env:
        env[LOG_FILE_ENV] = str(tmp_path / "http.log")
    with open(out, "ab") as stdout, open(err, "ab") as stderr:
        proc = subprocess.run(  # noqa: S603 - fixed argv, the interpreter running the tests
            [sys.executable, "-m", "universal_db_mcp", "serve", "--transport", "http"],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, cwd=tmp_path, timeout=120,
            check=False,
        )
    return out, err, proc.returncode


def test_the_daemon_caps_its_output_files_before_it_prints_anything(tmp_path: Path) -> None:
    out, err, returncode = _serve_without_config(tmp_path, log_file_env=True)
    assert returncode == 1
    text = err.read_text(encoding="utf-8")
    assert "~" not in text and text.startswith("universal-db-mcp: emptied this file at"), text[:200]
    assert text.rstrip().endswith("CONFIG_ERROR: no configuration; pass --config or set UDBMCP_CONFIG"), text
    assert out.read_text(encoding="utf-8").startswith("universal-db-mcp: emptied this file at")


def test_output_files_are_not_touched_outside_the_service_environment(tmp_path: Path) -> None:
    """Without UDBMCP_HTTP_LOG_FILE (set by the service definitions) the files are the caller's."""
    from universal_db_mcp.http_protocol import LOG_FILE_MAX_BYTES

    out, err, returncode = _serve_without_config(tmp_path, log_file_env=False)
    assert returncode == 1
    assert out.stat().st_size == LOG_FILE_MAX_BYTES + 1
    assert err.read_bytes().startswith(_FILL * (LOG_FILE_MAX_BYTES + 1))
    assert b"CONFIG_ERROR: no configuration" in err.read_bytes()


@pytest.fixture
def stderr_file(tmp_path: Path) -> Iterator[tuple[Path, io.TextIOWrapper]]:
    """A stream like the daemon's sys.stderr under launchd: a regular file opened O_APPEND. The test
    installs it (pytest resets sys.stderr between a fixture and the test)."""
    path = tmp_path / "server.err.log"
    path.write_bytes(b"")
    stream = io.TextIOWrapper(
        io.FileIO(os.open(path, os.O_WRONLY | os.O_APPEND), "w"), encoding="utf-8", write_through=True
    )
    try:
        yield path, stream
    finally:
        stream.close()


@pytest.mark.usefixtures("restore_logging")
def test_an_error_record_never_takes_the_daemon_stderr_past_the_cap(
    tmp_path: Path, stderr_file: tuple[Path, io.TextIOWrapper], monkeypatch: pytest.MonkeyPatch
) -> None:
    from universal_db_mcp.http_protocol import LOG_FILE_ENV, LOG_FILE_MAX_BYTES, configure_http_logging

    path, stream = stderr_file
    monkeypatch.setattr(sys, "stderr", stream)
    configure_http_logging({LOG_FILE_ENV: str(tmp_path / "http.log")})
    logging.getLogger("uvicorn.error").error("first")
    assert "first" in path.read_text(encoding="utf-8")
    with path.open("ab") as fh:
        fh.write(_FILL * LOG_FILE_MAX_BYTES)
    logging.getLogger("uvicorn.error").error("second")
    text = path.read_text(encoding="utf-8")
    assert "~" not in text and "first" not in text, text[:200]
    assert text.startswith("universal-db-mcp: emptied this file at") and "second" in text, text
    assert "second" in (tmp_path / "http.log").read_text(encoding="utf-8")


# ---- 4. doctor opens the audit lock without following a link -------------------------------------


def test_the_audit_lock_probe_never_opens_a_link_swapped_in_after_its_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """doctor runs under sudo and checks the lock beside the audit log (in the service account's
    directory) before it opens it: a name swapped for a link in between is refused, not followed."""
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    victim = tmp_path / "master.passwd"
    victim.write_text("root:*:0:0::0:0:System Administrator:/var/root:/bin/sh\n", encoding="utf-8")
    Path(f"{log}.lock").symlink_to(victim)
    monkeypatch.setattr(doctor, "_audit_file_problem", lambda _p: "")  # the check passed; then the swap
    problem = doctor._audit_lock_problem(log)
    assert problem.startswith(f"'{log}.lock' cannot be opened"), problem
