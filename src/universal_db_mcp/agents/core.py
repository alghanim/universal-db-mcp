"""Agent-harness registration adapters (``universal_db_mcp configure-agents``).

Each adapter module detects one installed AI-agent harness on the local
machine and, after explicit confirmation at the CLI layer, registers the
universal-db MCP server into that harness's config file. Shared primitives
live here so every adapter behaves identically:

* :class:`AgentStatus` — the four fail-closed-aware states.
* :class:`Plan` — a printable description of exactly what would be added.
* :func:`backup_path` — timestamped ``.bak`` sibling path.
* :func:`load_json_or_fail_closed` — parse-or-report helper that never
  raises and never silently overwrites malformed user state.
* :func:`load_yaml_or_fail_closed` — the same fail-closed contract for
  YAML-config harnesses.
* :func:`write_private_backup` / :func:`atomic_write_text` /
  :func:`ensure_directory` — the only ways an adapter writes: a private,
  exclusive-create backup, an atomic replace (or, for a file the adapter
  found absent, an exclusive create) and a ``mkdir -p`` that keeps the
  user's ownership under ``sudo``; :func:`ensure_replaceable` refuses a
  config the write may not touch before its backup is made, and
  :func:`unreplaceable_reason` lets detection report it first.
* :data:`SERVER_ARGS` / :func:`is_legacy_entry` / :func:`starts_without_isolation`
  — the launch arguments every registration uses, the one pre-``-I`` shape an
  adapter may upgrade, and how any other launch without ``-I`` is recognized
  (:func:`isolation_advice` says where its ``-I`` goes, and
  :func:`other_unisolated_note` names such launches the adapter leaves alone).
* :func:`absolute_override` / :func:`absolute_interpreter` /
  :func:`require_isolated_import` / :func:`app_data_base` /
  :func:`windows_env_dir` — path and launch-command resolution shared by
  every adapter.
* :class:`AgentConfigError` — typed fail-closed error for infrastructure
  problems (e.g. an adapter module that cannot be imported).

``Plan`` is a superset of the fields used by the individual adapters
(single- vs multi-file harnesses, JSON vs generated-config harnesses);
adapters populate only the fields that apply to them.
"""

from __future__ import annotations

import contextlib
import enum
import errno
import functools
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any, NamedTuple

from universal_db_mcp.errors import ConfigError


class AgentConfigError(Exception):
    """Fail-closed error in the agent-registration infrastructure itself.

    Raised by the adapter registry (for example when an adapter module cannot
    be imported). This is distinct from a harness's ``unknown_state_fail_closed``
    status: an :class:`AgentConfigError` means the CLI cannot even evaluate the
    harness, so it reports the problem and never writes to that harness.
    """


class AgentStatus(enum.Enum):
    """State of one agent harness on this machine."""

    NOT_INSTALLED = "not_installed"
    INSTALLED_UNCONFIGURED = "installed_unconfigured"
    CONFIGURED = "configured"
    UNKNOWN_STATE_FAIL_CLOSED = "unknown_state_fail_closed"


@dataclass(frozen=True)
class Plan:
    """What an adapter would do / did, for printing at the CLI layer.

    Common fields (every adapter sets ``agent`` and ``status``):

    * ``agent`` — adapter name (``"cline"``, ``"cursor"``, ...).
    * ``status`` — the detected / resulting :class:`AgentStatus`.
    * ``config_path`` — the primary config file (single-file harnesses).
    * ``summary`` / ``description`` — human-readable explanation.
    * ``config_block`` / ``block`` — the exact bytes that would be added,
      pretty-printed; empty when no write would happen. In a fail-closed
      state this carries the operator-inspection block instead.
    * ``entry`` / ``server_block`` — the dict written under the harness's
      ``mcpServers`` key; never contains secrets.

    Multi-file harnesses (e.g. Claude Code's user + project scopes) use the
    plural ``config_paths`` / ``backup_paths``; ``action`` describes the
    write mode for generated-config harnesses (``"none"``,
    ``"append-registration"``, ...).
    """

    agent: str
    status: AgentStatus
    config_path: Path | None = None
    config_paths: tuple[Path, ...] = ()
    backup_paths: tuple[Path, ...] = ()
    action: str = ""
    summary: str = ""
    description: str = ""
    config_block: str = ""
    block: str = ""
    entry: dict[str, Any] = field(default_factory=dict)
    server_block: dict[str, Any] = field(default_factory=dict)


# Launch arguments written into every registration. ``-I`` (isolated mode)
# keeps the harness's working directory, PYTHONPATH and the user site off
# sys.path: harnesses spawn stdio servers from the open project, and with a
# bare ``-m`` a project's yaml.py or universal_db_mcp/ ran inside the server
# process that holds the database credentials. The venv's own site-packages
# (and its .pth files, including an editable install) still load.
SERVER_ARGS: tuple[str, ...] = ("-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio")

# What earlier releases wrote. An entry that differs from today's ONLY in
# these args is this tool's own registration and may be upgraded in place.
LEGACY_SERVER_ARGS: tuple[str, ...] = SERVER_ARGS[1:]


def is_legacy_entry(existing: Any, desired: Mapping[str, Any]) -> bool:
    """True when ``existing`` is ``desired`` with the pre-``-I`` args.

    Deliberately narrow: command, env and every other key must be exactly
    what would be written now. Any other differing entry stays
    operator-managed state and keeps failing closed.
    """
    return isinstance(existing, dict) and existing == {**desired, "args": list(LEGACY_SERVER_ARGS)}


def holds_legacy_entry(path: Path, servers_key: str, server_key: str, desired: Mapping[str, Any]) -> bool:
    """True when the JSON config at ``path`` holds ``desired`` with the pre-``-I``
    args under ``servers_key``/``server_key`` (what ``apply`` would replace).

    False when the file is absent, unreadable or shaped differently.
    """
    data, _error = load_json_or_fail_closed(path)
    servers = data.get(servers_key) if data is not None else None
    return isinstance(servers, dict) and is_legacy_entry(servers.get(server_key), desired)


# What ``-m`` may name to start this package: the package or one of its modules.
_OUR_MODULE = re.compile(r"universal_db_mcp(?:\.\w+)*")

# A Python interpreter named inside a wrapper's args (``env python3 ...``,
# ``uv run python ...``), by its file name: python3, python3.12, pythonw,
# pypy3, python.exe, or the Windows ``py`` launcher.
_INTERPRETER = re.compile(r"(?:python|pypy)[0-9.]*t?w?|pyw?", re.IGNORECASE)


def _opens_interpreter_options(arg: Any) -> bool:
    """True when the options of a Python interpreter follow ``arg`` in a
    wrapper's args: the interpreter itself, or the ``run`` of ``uv run``
    (poetry, pipenv, hatch and pdm alike), whose options and ``--module``
    stand for ``python -m`` (:func:`_run_launch`)."""
    if not isinstance(arg, str):
        return False
    name = re.split(r"[\\/]", arg)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return arg == "run" or _INTERPRETER.fullmatch(name) is not None


# What :func:`_module_launch` returns for options that settle without starting
# this package unisolated: as its isolated launch (``-I``, then ``-m
# universal_db_mcp``), or otherwise (``-c``, ``-m`` naming another module).
_ISOLATED, _SETTLED = -2, -1

# The options of ``uv run`` that take a value (``uv run --help``), as the
# separate word after them unless attached (``--python=3.12``, ``-p3.12``);
# every other option is a flag. ``-m``/``--module`` is one: the command after
# the options is then the module uv runs with ``python -m``.
_RUN_VALUE_OPTIONS = frozenset(
    """
    --allow-insecure-host --cache-dir --color --config-file --config-setting --config-settings-package
    --default-index --directory --env-file --exclude-newer --exclude-newer-package --extra --extra-index-url
    --find-links --fork-strategy --group --index --index-strategy --index-url --keyring-provider --link-mode
    --no-binary-package --no-build-isolation-package --no-build-package --no-extra --no-group
    --no-sources-package --only-group --package --prerelease --project --python --python-platform
    --python-preference --refresh-package --reinstall-package --resolution --upgrade-group --upgrade-package
    --with --with-editable --with-requirements
    """.split()
)
_RUN_VALUE_FLAGS = "CPfipw"  # their short forms: -C, -P, -f, -i, -p, -w


def _run_launch(args: list[Any], start: int) -> int | None:
    """Read ``args[start:]`` as the options of ``uv run`` and the command after them.

    Returns the index of that command when ``-m``/``--module`` (alone, or in a
    group such as ``-qm``) came first and it is this package,
    :data:`_SETTLED` when it is another module, and None otherwise: without
    ``--module`` the command is a program, which :func:`_launch_in` reads as
    usual (``uv run --python 3.12 python -m ...``).
    """
    module = False
    index = start
    while index < len(args):
        arg = args[index]
        if not isinstance(arg, str) or arg == "-" or not arg.startswith("-"):
            break
        index += 1
        if arg == "--":
            break
        if arg.startswith("--"):
            module = module or arg == "--module"
            if arg in _RUN_VALUE_OPTIONS:
                index += 1
            continue
        for position, flag in enumerate(arg[1:], start=1):
            module = module or flag == "m"
            if flag in _RUN_VALUE_FLAGS:
                if position == len(arg) - 1:  # the value is the next word unless attached
                    index += 1
                break
    if not module or index >= len(args):
        return None
    command = args[index]
    return index if isinstance(command, str) and _OUR_MODULE.fullmatch(command) else _SETTLED


def _module_launch(args: list[Any], start: int) -> int | None:
    """Read ``args[start:]`` as a Python interpreter's options.

    Returns the index of the option that runs this package with ``-m`` when
    no ``-I`` came before it, :data:`_ISOLATED` when one did,
    :data:`_SETTLED` when the options settle otherwise (``-c``, or ``-m``
    naming another module), and None when anything else comes first: a
    script, stdin, ``--`` or a wrapper's own operand.
    """
    isolated = False
    index = start
    while index < len(args):
        arg, option = args[index], index
        if not isinstance(arg, str) or not arg.startswith("-") or arg in ("-", "--"):
            return None
        index += 1
        if arg.startswith("--"):
            if arg == "--check-hash-based-pycs":
                index += 1
            continue
        for position, flag in enumerate(arg[1:], start=1):
            if flag == "I":
                isolated = True
            elif flag in "cmWX":  # the rest of the argument, or the next one, is the value
                value = arg[position + 1 :]
                if not value and index < len(args):
                    value, index = args[index], index + 1
                if flag == "m" and isinstance(value, str) and _OUR_MODULE.fullmatch(value):
                    return _ISOLATED if isolated else option
                if flag in "cm":
                    return _SETTLED
                break
    return None


def _launch_in(words: list[Any], first: int) -> tuple[int, int] | None:
    """``(start, option)`` from the first reading of ``words`` that settles
    (:func:`_module_launch`, or :func:`_run_launch` after ``run``): where the
    interpreter's (or ``uv run``'s) options begin and the ``-m`` (for ``uv
    run``, the module) that starts this package without ``-I`` (negative when
    they settle otherwise); None when no reading settles.

    The interpreter is a word (see :func:`_opens_interpreter_options`) or,
    for ``first`` 0, the entry's command, whose options ``words`` (its
    ``args``) may start with; ``first`` 1 is for a command line, whose first
    word is the program.
    """
    for start in range(first, len(words)):
        if start and not _opens_interpreter_options(words[start - 1]):
            continue
        read = _run_launch if start and words[start - 1] == "run" else _module_launch
        option = read(words, start)
        if option is not None:
            return start, option
    return None


# How many command lines deep, each quoted inside the one before
# (``bash -c "sh -c 'python3 -m ...'"``) or substituted into it, a launch is
# looked for.
_NESTING = 4

# A word of a command line (unquoted text and quoted strings, up to a blank,
# a parenthesis, a redirection or a backtick) or what separates its commands.
_SHELL_TOKEN = re.compile(r"""(?:[^\s;&|()<>`'"]|'[^']*'|"[^"]*")+|[;&|\n]""")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


def _substitutions(text: str) -> list[str]:
    """The command lines that ``text`` substitutes, outside single quotes:
    ``$(...)`` (bash's ``<(...)``, ``>(...)``) up to its matching parenthesis
    and a backtick up to the next. The shell runs each before the command
    holding it. Only the outermost; those nested in them are inside."""
    bodies: list[str] = []
    single = double = False
    index = 0
    while index < len(text):
        char = text[index]
        if single:
            single = char != "'"
        elif char == "'" and not double:
            single = True
        elif char == '"':
            double = not double
        elif char == "`":
            end = text.find("`", index + 1)
            end = len(text) if end < 0 else end
            bodies.append(text[index + 1 : end])
            index = end
        elif char in "$<>" and text.startswith("(", index + 1):
            depth, end = 0, index + 1
            while end < len(text):
                depth += {"(": 1, ")": -1}.get(text[end], 0)
                if not depth:
                    break
                end += 1
            bodies.append(text[index + 2 : end])
            index = end
        index += 1
    return bodies


def _command_segments(text: str, nesting: int = _NESTING) -> list[list[str]]:
    """The commands of the command line ``text``, each as its words, closely
    enough to find a Python launch in them: split into commands at a shell's
    ``;``, ``&``, ``|`` and line breaks, and into words at blanks, parentheses,
    redirections and backticks, without their quotes. A quoted string stays
    one word, blanks and separators included; backslashes are kept, so a
    Windows path stays whole. The command lines it substitutes
    (:func:`_substitutions`, up to ``nesting`` deep) come first, as commands
    of their own; their words also stay in the command holding them."""
    segments: list[list[str]] = [[]]
    for token in _SHELL_TOKEN.finditer(text):
        word = token.group()
        if word in (";", "&", "|", "\n"):
            segments.append([])
        else:
            segments[-1].append(_QUOTED.sub(lambda quoted: quoted.group()[1:-1], word))
    substituted = [
        words for body in (_substitutions(text) if nesting else []) for words in _command_segments(body, nesting - 1)
    ]
    return [*substituted, *(words for words in segments if words)]


class _Launch(NamedTuple):
    """Where an entry starts this package without ``-I`` (:func:`_unisolated_launch`)."""

    words: list[Any]  # what was read: "args", a command's words, or "command"'s followed by "args"
    start: int  # where the interpreter's (or ``uv run``'s) options begin in ``words``
    option: int  # the ``-m`` in ``words`` (after ``run``: the module uv's ``--module`` runs)
    listed: int  # where the "args" items begin in ``words`` (``len(words)`` when none are in it)
    text: str  # what holds ``words[:listed]``: '"command"' or :data:`_ARGS_LINE`


# Where a command line held in "args" is (a shell's -c string, PowerShell's -Command args).
_ARGS_LINE = 'the command line in "args"'


def _scan(words: list[Any], first: int, listed: int, text: str, depth: int) -> _Launch | None:
    """Where the command ``words`` starts this package without ``-I`` (the
    first reading that settles, from ``first``: :func:`_launch_in`) or where a
    word that is itself a command line does (``sh -c "..."``, a quoted ``cmd
    /c`` line, ``env -S "..."``), up to ``depth`` command lines deep. When
    that reading is its isolated launch, only the words before it are read:
    the later ones are the server's own args. ``listed`` and ``text`` go into
    a launch found in ``words`` itself; a command line in ``words[listed:]``
    is :data:`_ARGS_LINE`.
    """
    found = _launch_in(words, first)
    if found is not None and found[1] >= 0:
        return _Launch(words, *found, listed, text)
    if depth:
        before = words[: found[0]] if found is not None and found[1] == _ISOLATED else words
        for index, word in enumerate(before):
            if isinstance(word, str) and len(word.split()) > 1:
                launch = _scan_line(word, text if index < listed else _ARGS_LINE, depth - 1)
                if launch is not None:
                    return launch
    return None


def _scan_line(line: str, text: str, depth: int) -> _Launch | None:
    """:func:`_scan` for every command of the command line ``line``, in ``text``."""
    for words in _command_segments(line):
        launch = _scan(words, 1, len(words), text, depth)
        if launch is not None:
            return launch
    return None


# PowerShell (powershell.exe, pwsh) runs the args after -Command, or a prefix
# of it such as -c, as one command line: they are joined with blanks.
_POWERSHELL = re.compile(r"(?:powershell|pwsh)(?:\.exe)?", re.IGNORECASE)


def _powershell_command_line(args: list[Any], command: Any) -> str | None:
    """The command line PowerShell ``command`` runs from ``args``; None when
    ``command`` is not PowerShell or ``args`` hold no ``-Command``."""
    if not (isinstance(command, str) and _POWERSHELL.fullmatch(re.split(r"[\\/]", command)[-1])):
        return None
    for index, arg in enumerate(args):
        if isinstance(arg, str) and len(arg) > 1 and "-command".startswith(arg.lower()):
            return " ".join(str(rest) for rest in args[index + 1 :])
    return None


def _unisolated_launch(args: Any, command: Any = None) -> _Launch | None:
    """Where the entry with ``command`` and ``args`` starts this package without ``-I``.

    Read, in turn: a ``command`` that is a whole command line
    (``"python3 -m universal_db_mcp serve"``, which a harness runs through a
    shell, its last command followed by ``args``), every command of it; the
    command line PowerShell's ``-Command`` makes of ``args``; ``args`` as the
    options of the interpreter or wrapper in ``command``. In each, an argument
    or word that is itself a whole command line (``sh -c "exec python3 -m
    ..."``, ``cmd /c``) is read too (:func:`_scan`).
    """
    items = args if isinstance(args, list) else []
    segments = _command_segments(command) if isinstance(command, str) else []
    if sum(map(len, segments)) > 1:
        segments[-1] = [*segments[-1], *items]
        for index, words in enumerate(segments):
            listed = len(words) - len(items) if index == len(segments) - 1 else len(words)
            launch = _scan(words, 1, listed, '"command"', _NESTING)
            if launch is not None:
                return launch
        if any(_launch_in(words, 1) is not None for words in segments):
            return None  # a python launch in the command line settles otherwise
    line = _powershell_command_line(items, command)
    if line is not None:
        return _scan_line(line, _ARGS_LINE, _NESTING)
    return _scan(items, 0, 0, _ARGS_LINE, _NESTING)


def starts_without_isolation(args: Any, command: Any = None) -> bool:
    """True when the entry's interpreter ``args`` (with its ``command``) run
    this package with ``-m`` and no earlier ``-I``.

    Such a server has the harness's working directory first on ``sys.path``
    (see :data:`SERVER_ARGS`). The options are read the way Python reads
    them: ``-I`` may share an argument with other flags (``-IB``, ``-Im``), the
    module may be attached (``-muniversal_db_mcp``) or be a submodule
    (``universal_db_mcp.__main__``), and ``-X``/``-W`` take a value. A launch
    through ``env`` or ``uv run`` counts too: its options follow the
    interpreter (or ``run``) inside ``args``, and ``uv run --module`` (``-m``)
    runs the module after uv's own options, which take their values
    (``uv run --python 3.12 -m ...``). So does one inside a command line
    held in one string, a shell's ``-c`` argument or the ``command`` itself,
    in any of its commands (``python3 -c ... && exec python3 -m ...``), in
    one it substitutes (``$(...)``, backticks) and in a command line quoted
    inside it (``bash -c "sh -c '...'"``, ``cmd /c "..."``, ``env -S
    "..."``), and one in the args after PowerShell's ``-Command``. What
    follows an isolated launch is the server's own args and is not read.
    """
    return _unisolated_launch(args, command) is not None


def isolation_advice(args: Any, command: Any = None) -> str:
    """How to add ``-I`` to the launch in ``args`` and ``command`` (:func:`starts_without_isolation`).

    Through a wrapper, a leading ``-I`` would be the wrapper's option, so it
    goes right before the ``-m`` instead, in the string that holds it when
    that is a command line. ``uv run``'s ``-m`` is uv's own: ``python -I``
    goes right before it when the module follows it; otherwise (``--module``,
    uv's options in between) uv's option goes and ``python -I -m`` comes
    right before the module.
    """
    launch = _unisolated_launch(args, command)
    if launch is None:
        return 'add "-I" as the first "args" item'
    words, start, option, listed, text = launch
    insert, drop = ["-I"], ""
    if start and words[start - 1] == "run":  # ``option`` is the module uv runs
        if words[option - 1] == "-m":
            insert, option = ["python", "-I"], option - 1
        else:
            insert, drop = ["python", "-I", "-m"], "drop uv's --module (-m) option and "
    elif start == listed:
        return 'add "-I" as the first "args" item'
    if option < listed:  # inside a command line (one string, or PowerShell's -Command args)
        added, where = f'"{" ".join(insert)}"', text
    else:
        added, where = ", ".join(f'"{word}"' for word in insert), '"args"'
    verb = "add" if insert == ["-I"] else "insert"
    return f'{drop}{verb} {added} right before "{words[option]}" in {where}'


def unisolated_entry_note(path: Path, servers_key: str, server_key: str) -> str:
    """What a fail-closed summary adds when the JSON config at ``path`` holds,
    under ``servers_key``/``server_key``, an entry that starts the server
    without ``-I`` (:func:`starts_without_isolation`); ``""`` otherwise.

    Such an entry is not this tool's legacy one (that is upgraded), so it is
    left alone, and the operator must learn why it matters.
    """
    data, _error = load_json_or_fail_closed(path)
    servers = data.get(servers_key) if data is not None else None
    entry = servers.get(server_key) if isinstance(servers, dict) else None
    if not (isinstance(entry, dict) and starts_without_isolation(entry.get("args"), entry.get("command"))):
        return ""
    return (
        "; the existing entry starts the server without -I (isolated mode), so files in the open project "
        f"can run inside it; {isolation_advice(entry.get('args'), entry.get('command'))}"
    )


def unisolated_launches(servers: Any, skip: str | None = None) -> list[str]:
    """Names of the entries in the ``servers`` mapping, other than ``skip``,
    that start this package without ``-I`` (:func:`starts_without_isolation`)."""
    if not isinstance(servers, dict):
        return []
    return [
        str(name)
        for name, entry in servers.items()
        if name != skip
        and isinstance(entry, dict)
        and starts_without_isolation(entry.get("args"), entry.get("command"))
    ]


def unisolated_launches_note(path: Path, names: list[str]) -> str:
    """What a plan or result adds for ``names``, other entries in ``path`` that
    start this package without ``-I``; ``""`` when there are none.

    The adapter adds its own entry beside them and never edits them (they are
    the operator's), so the operator must learn that they stay exploitable.
    """
    if not names:
        return ""
    return (
        f"; WARNING: {path} also holds {', '.join(names)}, which start universal_db_mcp without -I "
        "(isolated mode), so files in the open project can run inside it; this tool leaves them as "
        'they are: have each one run python with "-I" before its "-m"'
    )


def other_unisolated_note(path: Path, servers_key: str, server_key: str) -> str:
    """:func:`unisolated_launches_note` for the entries under ``servers_key`` in
    the JSON config at ``path``, other than ``server_key`` (this tool's own);
    ``""`` when the file is absent or does not parse."""
    data, _error = load_json_or_fail_closed(path)
    servers = data.get(servers_key) if data is not None else None
    names = [f'"{servers_key}"["{name}"]' for name in unisolated_launches(servers, server_key)]
    return unisolated_launches_note(path, names)


def backup_path(target: Path) -> Path:
    """Timestamped sibling backup path for ``target`` (never overwrites)."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return target.parent / f"{target.name}.bak.{stamp}"


# Create-only, never through a symlink: a file or link already sitting at the
# path fails the open instead of being written through.
_EXCLUSIVE_CREATE = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
)

# The stamp :func:`backup_path` appends after ``<name>.bak.`` (every release).
_BACKUP_STAMP = re.compile(r"\d{8}T\d{12}Z")


def _group_decides_access(mode: int) -> bool:
    """True when ``mode`` gives the file's group other access than everyone else."""
    return (mode >> 3) & 0o7 != mode & 0o7


def _fill(fd: int, data: bytes, *, mode: int, owner: os.stat_result | None) -> None:
    """Give ``fd`` ``mode`` (and ``owner``'s ids), write ``data``, fsync; closes ``fd``.

    As root the file takes ``owner``'s uid and gid (a sudo run must not leave
    the user's config root-owned); otherwise only the group is kept, which
    fails for a group this user is not in. The file then keeps the group it
    was created with, which is refused (``PermissionError``) where ``mode``
    gives the group other access than everyone else
    (:func:`_refuse_regrouping`).
    """
    with os.fdopen(fd, "wb") as fh:
        if sys.platform != "win32":
            os.fchmod(fh.fileno(), mode)
            if owner is not None:
                as_root = os.geteuid() == 0
                try:
                    os.fchown(fh.fileno(), owner.st_uid if as_root else -1, owner.st_gid)
                except PermissionError as exc:
                    if as_root:
                        raise
                    created = os.fstat(fh.fileno()).st_gid
                    if created != owner.st_gid and _group_decides_access(mode):
                        raise PermissionError(
                            f"the new file could not be given group {owner.st_gid} ({exc}), and group "
                            f"{created} would change who may read it; edit the file by hand, then re-run"
                        ) from exc
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _fsync_directory(directory: Path) -> None:
    """Make a create/rename in ``directory`` durable (POSIX; best effort)."""
    if sys.platform == "win32":
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_private_backup(source: Path, backup: Path) -> None:
    """Copy ``source``'s bytes into a NEW file ``backup`` only its owner can read.

    Harness configs hold other MCP servers' env values (API tokens), and a
    backup created under the umask came out 0644 beside a 0600 original. The
    backup gets the original's permission bits capped at 0600, and the
    exclusive, no-follow create makes a file or symlink planted at the
    backup path fail the write (``OSError``) instead of being written through.
    Earlier backups of ``source`` that are group/other-readable are then
    tightened too (:func:`_tighten_earlier_backups`).
    """
    data = source.read_bytes()
    st = source.stat()
    fd = os.open(backup, _EXCLUSIVE_CREATE, 0o600)
    try:
        _fill(fd, data, mode=stat.S_IMODE(st.st_mode) & 0o600, owner=st)
    except BaseException:
        with contextlib.suppress(OSError):
            backup.unlink()
        raise
    _fsync_directory(backup.parent)
    _tighten_earlier_backups(source, backup.parent, st.st_uid)


def _tighten_earlier_backups(source: Path, directory: Path, owner_uid: int) -> None:
    """Drop group/other access from earlier ``<source>.bak.<stamp>`` files.

    Releases before :func:`write_private_backup` left them at 0644 beside a
    0600 config, and nothing ever prunes them. Best effort: only regular files
    with exactly this module's backup name, owned by ``source``'s owner, are
    touched, and a symlink at such a name is never followed.
    """
    if sys.platform == "win32":
        return
    prefix = f"{source.name}.bak."
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not (name.startswith(prefix) and _BACKUP_STAMP.fullmatch(name[len(prefix) :])):
            continue
        with contextlib.suppress(OSError):
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_uid == owner_uid and st.st_mode & 0o077:
                    os.fchmod(fd, stat.S_IMODE(st.st_mode) & 0o600)
            finally:
                os.close(fd)


# Windows' "another program has the file open" (not a permission of this user).
_ERROR_SHARING_VIOLATION = 32

# FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE (<winnt.h>).
_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4


def _is_writable_file(real: Path) -> bool:
    """True when this user may write ``real``.

    On Windows ``os.access`` sees only the read-only attribute, not the ACL (a
    config an administrator or Intune deployed read-only for the user), so the
    file is opened for writing instead, without truncating it. That open is
    Win32's ``CreateFile``: ``os.open`` goes through the C runtime, which
    reports a sharing violation as EACCES without the Windows code. A sharing
    violation leaves the verdict to the replace, which retries it.
    """
    if sys.platform == "win32":
        import _winapi

        try:
            handle = _winapi.CreateFile(
                str(real), _winapi.GENERIC_WRITE, _FILE_SHARE_ALL, _winapi.NULL, _winapi.OPEN_EXISTING, 0, _winapi.NULL
            )
        except PermissionError as exc:
            return getattr(exc, "winerror", None) == _ERROR_SHARING_VIOLATION
        _winapi.CloseHandle(handle)
        return True
    return os.access(real, os.W_OK)


# macOS ``acl_type_t`` of the ACL ``ls -le`` lists (<sys/acl.h>).
_ACL_TYPE_EXTENDED = 0x00000100


def _darwin_acl_entries(path: Path) -> list[tuple[str, str, frozenset[str], str]] | None:
    """The entries of ``path``'s macOS extended ACL, as ``acl_to_text`` spells
    them: ``(tag:uuid, allow|deny, flags, permissions)``; None when it has none.
    A probe that fails for any other reason raises ``OSError``."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_get_link_np.argtypes = (ctypes.c_char_p, ctypes.c_int)
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    acl = libc.acl_get_link_np(os.fsencode(path), _ACL_TYPE_EXTENDED)
    if not acl:
        code = ctypes.get_errno()
        if code in (errno.ENOENT, errno.ENOTSUP, errno.EOPNOTSUPP):
            return None
        raise OSError(code, os.strerror(code), str(path))
    try:
        text = libc.acl_to_text(acl, None)
        if not text:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(path))
        try:
            lines = ctypes.string_at(text).decode("utf-8", "replace").splitlines()
        finally:
            libc.acl_free(ctypes.c_void_p(text))
    finally:
        libc.acl_free(ctypes.c_void_p(acl))
    entries = []
    for line in lines[1:]:  # after the "!#acl 1" header: tag:uuid:name:id:kind[,flags]:permissions
        fields = line.split(":")
        if len(fields) < 4:
            raise OSError(f"{path} has an access control list entry this tool cannot read: {line!r}")
        kind, *flags = fields[-2].split(",")
        entries.append((f"{fields[0]}:{fields[1]}", kind, frozenset(flags), fields[-1]))
    return entries


# The value of Linux's system.posix_acl_access / system.posix_acl_default
# (<linux/posix_acl_xattr.h>): a 4-byte version, then (tag, perm, id) entries.
_POSIX_ACL_ENTRY = struct.Struct("<HHI")
_ACL_USER_OBJ, _ACL_GROUP_OBJ, _ACL_MASK, _ACL_OTHER = 0x01, 0x04, 0x10, 0x20

# The flags only a directory's entry carries, which decide what its new files inherit.
_DARWIN_INHERITANCE_FLAGS = frozenset(
    {"inherited", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"}
)


def _posix_acl_extras(raw: bytes) -> list[tuple[int, int, int]]:
    """The entries of the POSIX ACL ``raw`` that the mode bits do not carry:
    all but the owner's, the mask's and other's (and, without a mask, the
    owning group's), sorted."""
    size = _POSIX_ACL_ENTRY.size
    entries = [_POSIX_ACL_ENTRY.unpack_from(raw, offset) for offset in range(4, len(raw) - size + 1, size)]
    carried = {_ACL_USER_OBJ, _ACL_OTHER}
    carried.add(_ACL_MASK if any(entry[0] == _ACL_MASK for entry in entries) else _ACL_GROUP_OBJ)
    return sorted(entry for entry in entries if entry[0] not in carried)


def _posix_acl(path: Path, attribute: str) -> bytes:
    """The POSIX ACL ``attribute`` of ``path`` (Linux); empty when it has none.
    A probe that fails for any other reason raises ``OSError``."""
    try:
        value: bytes = getattr(os, "getxattr")(path, attribute)  # noqa: B009 - Linux only
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            return b""  # none, or a filesystem without extended attributes
        raise
    return value


def _access_control_lists(real: Path) -> tuple[list[Any], list[Any]]:
    """``real``'s access control list and the one its directory gives every
    file created in it (the replace's temp file too), comparably: equal when
    the replace leaves who may read and write ``real`` as it is. Empty for none.

    Linux: the entries the mode bits do not carry (the temp file is given the
    same mode) of ``real``'s POSIX ACL and of the directory's default ACL.
    macOS: the extended ACL's entries, and the directory's ``file_inherit``
    entries as a new file inherits them. Both are empty elsewhere: on Windows
    the ACL is not checked. A probe that fails for any other reason than
    "none here" raises ``OSError``.
    """
    if hasattr(os, "getxattr"):  # Linux only
        return (
            _posix_acl_extras(_posix_acl(real, "system.posix_acl_access")),
            _posix_acl_extras(_posix_acl(real.parent, "system.posix_acl_default")),
        )
    if sys.platform == "darwin":
        given = [
            (who, kind, (flags - _DARWIN_INHERITANCE_FLAGS) | {"inherited"}, permissions)
            for who, kind, flags, permissions in _darwin_acl_entries(real.parent) or []
            if "file_inherit" in flags
        ]
        return _darwin_acl_entries(real) or [], given
    return [], []


def _nearest_existing(path: Path) -> Path:
    """``path``, or its nearest ancestor that exists."""
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def _refuse_unwritable_directory(directory: Path, write: str) -> None:
    """Raise when this user may not create files in ``directory``, as ``write``
    (the replace's temp file, or the create) does.

    Not on Windows, where ``os.access`` calls every directory writable: the
    write itself decides there, as before.
    """
    if sys.platform != "win32" and not os.access(directory, os.W_OK | os.X_OK):
        raise PermissionError(
            f"{directory} is not writable by this user, and {write} creates a file there; "
            "make it writable (or edit the config by hand), then re-run"
        )


def _refuse_foreign_symlink(path: Path) -> None:
    """As root, raise when a symlink on ``path`` that a user owns leads to
    something that user does not own.

    Root may write anywhere, so under ``sudo configure-agents`` a link the
    user planted in their own config tree (``~/.cursor/mcp.json`` ->
    ``/etc/sudoers.d/x``, ``~/.config`` -> ``/etc``) had root replace, create
    or ``mkdir`` there. Such a link must lead to its owner's own file or
    directory (a dangling one: to its owner's nearest existing directory);
    links root owns (``/var`` -> ``private/var``) are followed as before. A
    TOCTOU swap of a directory for a link meanwhile is not covered.
    """
    if sys.platform == "win32" or os.geteuid() != 0:
        return
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            return  # the rest does not exist yet
        if not stat.S_ISLNK(st.st_mode) or st.st_uid == 0:
            continue
        resolved = Path(os.path.realpath(current))
        if _nearest_existing(resolved).stat().st_uid != st.st_uid:
            raise PermissionError(
                f"{current} is a symlink to {resolved}, which its owner (uid {st.st_uid}) does not own, "
                "and as root this tool does not write through it; run configure-agents as that user "
                "(without sudo), or replace the link with the file"
            )


def refuse_foreign_read(path: Path) -> None:
    """As root, raise ``PermissionError`` when reading ``path`` would read a
    file a user can have root show them: one reached through their symlink to
    something they do not own (:func:`_refuse_foreign_symlink`), or one with
    more than one name (a hard link) that the owner of its directory does not
    own. ``sudo configure-agents --dry-run`` printed a root-only file a user
    linked in as their harness config. Without root, reads are the user's own
    and nothing is checked.
    """
    if sys.platform == "win32" or os.geteuid() != 0:
        return
    _refuse_foreign_symlink(path)
    real = Path(os.path.realpath(path))
    try:
        st = real.stat()
        directory = real.parent.stat()
    except OSError:
        return  # nothing there to read: the read itself reports it
    if st.st_nlink > 1 and st.st_uid != directory.st_uid:
        raise PermissionError(
            f"{real} has {st.st_nlink} hard links and belongs to uid {st.st_uid}, not to the owner of "
            f"{real.parent} (uid {directory.st_uid}), and as root this tool does not read it; run "
            "configure-agents as that user (without sudo), or replace the link with the file"
        )


def read_config_bytes(path: Path) -> bytes:
    """``path``'s bytes; as root, only a file the owner of its directory may
    read themselves (``OSError`` otherwise).

    Without root this is ``path.read_bytes()``. As root (``sudo
    configure-agents``) the checks of :func:`refuse_foreign_read` run first
    (for their messages); then the path is opened one component at a time
    from the root directory's descriptor (:func:`_open_walking`), never by
    name: each directory is opened without following a link, a symlink met
    on the way is resolved by this walk, and one a user owns must lead to
    something that user owns. So a directory swapped for a link after the
    checks (a race the user can run in their own home) is either refused or
    walked under the same rule, and nothing is re-resolved by name. What was
    opened is checked on the descriptors: a regular file which, in a
    directory a user owns, is that user's or one its permission bits let
    that user read, and which has one name unless the directory's owner owns
    it (a hard link the user made to a root-only file).
    """
    if sys.platform == "win32" or os.geteuid() != 0:
        return path.read_bytes()
    refuse_foreign_read(path)
    directory_fd, fd = _open_walking(os.path.abspath(path))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path} is not a regular file")
        directory = os.fstat(directory_fd)
        owner = directory.st_uid
        if st.st_nlink > 1 and st.st_uid != owner:
            raise PermissionError(
                f"{path} has {st.st_nlink} hard links and belongs to uid {st.st_uid}, not to the owner of "
                f"its directory (uid {owner}), and as root this tool does not read it; run configure-agents "
                "as that user (without sudo), or replace the link with the file"
            )
        if owner != 0 and st.st_uid != owner and not _bits_allow(st, owner, directory.st_gid, 4):
            raise PermissionError(
                f"{path} belongs to uid {st.st_uid} and the owner of its directory (uid {owner}) may not "
                "read it, and as root this tool does not read it for them; run configure-agents as that "
                "user (without sudo), or give them the file (chown)"
            )
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
        os.close(directory_fd)


# A marker among the components _open_walking still has to walk: once the
# components of a link's target are walked, what they reached must belong to
# the link's owner (the uid it carries).
class _OwnedBy(int):
    pass


def _open_walking(absolute: str) -> tuple[int, int]:
    """(descriptor of the directory holding it, descriptor of it) for the
    absolute path *absolute*, opened component by component from ``/`` with
    O_NOFOLLOW relative to the directory opened before: nothing is resolved
    by name twice, so no component can be swapped between a check and the
    open. A symlink is read where it is (readlink relative to its
    directory's descriptor) and its target walked the same way; one a user
    (not root) owns must lead to something that user owns. At most
    _MAX_LINKS links are followed (ELOOP past that)."""
    nofollow = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    stack = [os.open("/", os.O_RDONLY | os.O_DIRECTORY)]
    pending: list[str | _OwnedBy] = list(reversed(absolute.split("/")))
    links = 0
    try:
        while pending:
            part = pending.pop()
            if isinstance(part, _OwnedBy):
                reached = os.fstat(stack[-1])
                if reached.st_uid != part:
                    raise PermissionError(
                        f"{absolute} goes through a symlink owned by uid {int(part)} that leads to something "
                        f"uid {reached.st_uid} owns, and as root this tool does not read through it; run "
                        "configure-agents as that user (without sudo), or replace the link with the file"
                    )
                continue
            if part in ("", "."):
                continue
            if part == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                continue
            if not stat.S_ISDIR(os.fstat(stack[-1]).st_mode):
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), absolute)
            try:
                stack.append(os.open(part, nofollow, dir_fd=stack[-1]))
                continue
            except OSError as exc:
                if exc.errno != errno.ELOOP:
                    raise
            link = os.stat(part, dir_fd=stack[-1], follow_symlinks=False)
            if not stat.S_ISLNK(link.st_mode):
                raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), absolute)
            target = os.readlink(part, dir_fd=stack[-1])
            again = os.stat(part, dir_fd=stack[-1], follow_symlinks=False)
            if (again.st_ino, again.st_uid) != (link.st_ino, link.st_uid):
                raise OSError(f"{absolute} changed while it was being read; re-run")
            links += 1
            if links > _MAX_LINKS:
                raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), absolute)
            if link.st_uid != 0:
                pending.append(_OwnedBy(link.st_uid))
            pending.extend(reversed(target.split("/")))
            if target.startswith("/"):
                while len(stack) > 1:
                    os.close(stack.pop())
        if len(stack) < 2:
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), absolute)
        fd = stack.pop()
        return stack.pop(), fd
    finally:
        for leftover in stack:
            os.close(leftover)


# links followed on the way to a file (the kernel's own limit, MAXSYMLINKS)
_MAX_LINKS = 40


def read_config_text(path: Path) -> str:
    """:func:`read_config_bytes` decoded as UTF-8 (``UnicodeDecodeError``), with
    universal newlines as ``Path.read_text`` reads them."""
    return read_config_bytes(path).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def describe_read_error(exc: BaseException) -> str:
    """What a fail-closed report says about a config that could not be read:
    for one that is not UTF-8, the line, never the byte or its offset (the
    codec's message quotes both, and harness configs hold other servers'
    tokens)."""
    if isinstance(exc, UnicodeDecodeError):
        from universal_db_mcp.config import describe_decode_error

        return describe_decode_error(exc)
    return str(exc)


def _refuse_regrouping(real: Path, st: os.stat_result) -> None:
    """Without root, raise when the replace would give ``real`` (``st``: its
    stat) another group, where its mode gives that group other access than
    everyone else (0640, 0660).

    The temp file takes ``real``'s group only when this user is in it;
    otherwise it keeps the group it was created with: the directory's on macOS
    and BSD (and in a set-group-ID directory on Linux), this process's own on
    Linux. A ``runner:secret`` 0640 config came back ``runner:runner``, and
    ``secret``'s members could no longer read it.
    """
    if sys.platform == "win32" or os.geteuid() == 0 or not _group_decides_access(stat.S_IMODE(st.st_mode)):
        return
    if st.st_gid == os.getegid() or st.st_gid in os.getgroups():
        return
    directory = real.parent.stat()
    inherited = not sys.platform.startswith("linux") or directory.st_mode & stat.S_ISGID
    created = directory.st_gid if inherited else os.getegid()
    if created != st.st_gid:
        raise PermissionError(
            f"{real} belongs to group {st.st_gid}, which this user is not in, and replacing it would give "
            f"it group {created}, changing who may read it; edit it by hand, then re-run"
        )


def _refuse_unreplaceable(real: Path, st: os.stat_result) -> None:
    """Raise when the atomic replace of ``real`` (``st``: its stat) must not happen.

    See :func:`atomic_write_text` for the refusals.
    """
    if not _is_writable_file(real):
        raise PermissionError(
            f"{real} is not writable by this user, and replacing it would override that; "
            "make it writable (or edit it by hand), then re-run"
        )
    if sys.platform != "win32" and os.geteuid() not in (0, st.st_uid):
        raise PermissionError(
            f"{real} is owned by another user (uid {st.st_uid}), and replacing it would make it "
            "yours; edit it as its owner, then re-run"
        )
    _refuse_regrouping(real, st)
    if st.st_nlink > 1:
        raise OSError(
            f"{real} has {st.st_nlink} hard links, and replacing it would leave the other names "
            "with the old content; edit it by hand, or make the other names symlinks"
        )
    try:
        own, given = _access_control_lists(real)
    except OSError as exc:
        raise OSError(f"{real} could not be checked for an access control list ({exc})") from exc
    if own != given:
        raise OSError(
            f"{real} has an access control list other than the one its directory gives every new file, "
            "and replacing it would drop it (the new file takes the mode bits and that inherited list "
            "only); edit it by hand, then re-run"
            if own
            else f"{real} has no access control list, but its directory gives every new file one, and "
            "replacing it would give it that list, changing who may read it; edit it by hand, then re-run"
        )
    _refuse_unwritable_directory(real.parent, f"replacing {real}")


def ensure_replaceable(target: Path) -> None:
    """Raise ``OSError`` now when writing ``target`` would be refused or could
    not happen: :func:`atomic_write_text` would refuse to replace the existing
    file (read-only, another user's, in a group it would lose, hard-linked,
    with an ACL the replace would change), its directory (for a missing ``target``, the nearest
    existing one) is not writable, or, as root, a user's symlink on the way
    leads elsewhere.

    Adapters call it before :func:`write_private_backup`, so a refused config
    leaves no backup behind.
    """
    _refuse_foreign_symlink(target)
    real = Path(os.path.realpath(target))
    try:
        st = real.stat()
    except FileNotFoundError:
        _refuse_unwritable_directory(_nearest_existing(real.parent), f"creating {real}")
        return
    _refuse_unreplaceable(real, st)


def unreplaceable_reason(target: Path) -> str | None:
    """Why :func:`ensure_replaceable` refuses ``target``, or None.

    Detection reports such a config fail-closed, so a dry run, ``--json``
    (``writable``) and the macOS app never offer a write that ``apply`` would
    refuse.
    """
    try:
        ensure_replaceable(target)
    except OSError as exc:
        return str(exc)
    return None


def _create_exclusively(real: Path, data: bytes) -> None:
    """Create ``real`` at 0600 holding ``data``; fail if anything is already there."""
    try:
        fd = os.open(real, _EXCLUSIVE_CREATE, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(
            f"{real} appeared after it was found absent (another program wrote it meanwhile) "
            "and was left as it is; re-run to add the registration to it"
        ) from exc
    try:
        _fill(fd, data, mode=0o600, owner=real.parent.stat())
    except BaseException:
        with contextlib.suppress(OSError):
            real.unlink()
        raise


def atomic_write_text(target: Path, payload: str, *, create: bool = False) -> None:
    """Replace ``target``'s content with ``payload``; never truncate it in place.

    A symlinked target is written through: the link is resolved and the file
    it points to is replaced, so the link itself survives. An existing file
    is replaced atomically - the payload goes to a temp file in the same
    directory with the original's mode and group (and owner, as root), is
    fsynced and then ``os.replace``d over it - so ENOSPC, a kill or a power
    loss leaves the old bytes or the new ones, never an empty file. A missing
    file is created exclusively at 0600, so one that appears meanwhile is
    never clobbered. Raises ``OSError`` with the target untouched on any
    failure.

    ``create`` is the caller's own "absent, so create" decision: the file is
    then only ever created, and one that appeared since the caller looked
    (the harness writing its first config) fails with ``FileExistsError``
    instead of being replaced by content built without it.

    The replace needs a writable directory beside the (resolved) target
    (checked first, as :func:`ensure_replaceable` does for detection), and
    it cannot replace a path that is itself a mount point (a single-file bind
    mount: ``EBUSY``). A hard-linked file is refused: the replace would give
    this name a new inode and leave the other names with the old bytes. All
    three fail closed as above; such a file has to be edited by hand.

    The replace needs no write permission on the file itself, so that is
    checked first: a file this user may not write (made read-only by the
    operator, or by a Windows ACL), or one another user owns (a managed config
    in a user-writable directory, which the replace would hand to this user),
    is refused with ``PermissionError`` unless running as root. So is, without
    root, a file in a group this user is not in whose mode gives that group
    other access than everyone else (0640): the temp file could not be given
    that group (:func:`_refuse_regrouping`). So is, as root, a path through a
    user's symlink to something that user does not own
    (:func:`_refuse_foreign_symlink`). A file whose POSIX (Linux) or extended
    (macOS) access control list differs from the one its directory gives every
    new file, having none included, is refused with ``OSError``: the temp file
    inherits the directory's, and the new inode carries no other
    (:func:`_access_control_lists`).
    """
    _refuse_foreign_symlink(target)
    real = Path(os.path.realpath(target))
    data = payload.encode("utf-8")
    try:
        st = None if create else real.stat()
    except FileNotFoundError:
        st = None
    if st is None:
        _create_exclusively(real, data)
    else:
        _refuse_unreplaceable(real, st)
        fd, tmp_name = tempfile.mkstemp(dir=real.parent, prefix=f".{real.name}.", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            _fill(fd, data, mode=stat.S_IMODE(st.st_mode), owner=st)
            try:
                os.replace(tmp, real)
            except PermissionError:
                if sys.platform != "win32":
                    raise
                # Windows refuses the replace while another process holds
                # the file open without FILE_SHARE_DELETE; retry once.
                time.sleep(0.2)
                os.replace(tmp, real)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
    _fsync_directory(real.parent)


def ensure_directory(directory: Path, *, mode: int = 0o777) -> None:
    """``mkdir -p directory``, keeping the user's ownership under ``sudo``.

    As root, every directory this creates takes the uid and gid of its
    nearest existing ancestor: a root-owned ``Claude/`` made by a
    ``sudo configure-agents`` also made the config written into it
    root-owned (see :func:`atomic_write_text`), and the user's harness could
    not read it. Nor does root ``mkdir`` through a user's symlink to a
    directory that user does not own (:func:`_refuse_foreign_symlink`).
    """
    _refuse_foreign_symlink(directory)
    missing: list[Path] = []
    probe = directory
    while not probe.exists() and probe.parent != probe:
        missing.append(probe)
        probe = probe.parent
    directory.mkdir(mode=mode, parents=True, exist_ok=True)
    if sys.platform == "win32" or not missing or os.geteuid() != 0:
        return
    owner = probe.stat()
    for created in reversed(missing):
        os.chown(created, owner.st_uid, owner.st_gid, follow_symlinks=False)


def absolute_override(value: str, variable: str, *, must_exist: bool = True) -> str:
    """Absolute form of an operator path override (``UDBMCP_CONFIG``, ...).

    Registrations are global: a harness spawns the server from whichever
    project is open, so a relative value would be resolved against THAT
    directory and let the open repository choose the config (or the
    interpreter). A relative value is anchored at this process's working
    directory; with ``must_exist`` it must name an existing file there, or
    the override is refused (``CONFIG_ERROR``). Symlinks are deliberately not
    resolved: a venv's ``bin/python`` is a link to the base interpreter, and
    following it would drop the venv. A ``~user`` naming no account is
    refused (``CONFIG_ERROR``) too.
    """
    try:
        path = Path(value).expanduser()
    except RuntimeError as exc:  # pathlib: "Could not determine home directory."
        raise ConfigError(
            f"{variable}={value!r} starts with a ~user that names no account on this machine ({exc}); "
            f"set {variable} to an absolute path"
        ) from exc
    if path.is_absolute():
        return str(path)
    anchored = Path(os.path.abspath(path))
    if must_exist and not anchored.is_file():
        raise ConfigError(
            f"{variable}={value!r} is a relative path and {anchored} is not a file; "
            f"agent registrations are global, so set {variable} to an absolute path"
        )
    return str(anchored)


def absolute_interpreter(value: str, variable: str, env: Mapping[str, str]) -> str:
    """Absolute form of an interpreter override (``UDBMCP_VENV_PYTHON``).

    A value containing a directory separator is a path (see
    :func:`absolute_override`). A bare name such as ``python3`` is what a shell
    finds on ``PATH`` (``env["PATH"]``): it is looked up there now and that
    match is registered, never a same-named file in the working directory. A
    name not on ``PATH``, or found only through an entry that means the working
    directory (``.``, an empty entry, Windows' implicit current directory),
    is refused (``CONFIG_ERROR``).
    """
    separators = [os.sep] if os.altsep is None else [os.sep, os.altsep]
    if value.startswith("~") or any(sep in value for sep in separators):
        return absolute_override(value, variable)
    found = shutil.which(value, path=env.get("PATH"))
    if found is None:
        raise ConfigError(
            f"{variable}={value!r} is not a path and is not on PATH; "
            f"agent registrations are global, so set {variable} to an absolute path"
        )
    if not os.path.isabs(found):
        raise ConfigError(
            f"{variable}={value!r} is found only through a PATH entry relative to the working "
            f"directory ({found}); agent registrations are global, so set {variable} to an absolute path"
        )
    return found


@functools.cache
def _isolated_import_problem(python: str) -> str | None:
    """Why ``python -I`` cannot import the server, or None when it can.

    The server module, not just the package: ``universal_db_mcp/__init__``
    imports nothing, so dependencies (mcp, yaml, pydantic, sqlglot) found only
    in the user site passed the probe and failed at every harness start.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - the interpreter a registration would launch
            [python, "-I", "-c", "import universal_db_mcp.server"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    if proc.returncode == 0:
        return None
    lines = proc.stderr.strip().splitlines()
    return lines[-1] if lines else f"exit status {proc.returncode}"


def require_isolated_import(python: str) -> None:
    """Refuse (``CONFIG_ERROR``) to register ``python`` when it cannot start the server.

    Every registration launches ``<python> -I -m universal_db_mcp``, and ``-I``
    leaves the user site-packages, ``PYTHONPATH`` and the working directory off
    ``sys.path``: a ``pip install --user`` into a system or Homebrew python
    registered cleanly and then died at every harness start. The exact import
    is tried once per interpreter and process. Adapters call this for the
    interpreter they pick themselves; an explicit ``UDBMCP_VENV_PYTHON`` is
    the operator's choice and is not checked.
    """
    problem = _isolated_import_problem(python)
    if problem is not None:
        raise ConfigError(
            f"{python} -I cannot import universal_db_mcp.server ({problem}); every registration starts "
            "the server in isolated mode, which skips the user site-packages and PYTHONPATH. Install the "
            "package and its dependencies into a virtual environment (or set UDBMCP_VENV_PYTHON to a "
            "venv python that has them), then re-run"
        )


def app_data_base(env: Mapping[str, str], home: Path, platform: str | None = None) -> Path:
    """Per-user application-config root (what Electron apps call ``appData``).

    ``%APPDATA%`` on Windows (folder redirection moves it off the profile),
    ``$XDG_CONFIG_HOME`` or ``~/.config`` on Linux and other POSIX systems,
    and ``~/Library/Application Support`` on macOS. ``platform`` defaults to
    the running ``sys.platform``.
    """
    p = sys.platform if platform is None else platform
    if p == "darwin":
        return home / "Library" / "Application Support"
    if p == "win32":
        return windows_env_dir(env, "APPDATA") or home / "AppData" / "Roaming"
    xdg = env.get("XDG_CONFIG_HOME", "").strip()
    # XDG base-directory spec: a relative value is invalid and ignored.
    if xdg and Path(xdg).is_absolute():
        return Path(xdg)
    return home / ".config"


def windows_env_dir(env: Mapping[str, str], variable: str) -> Path | None:
    """The Windows folder ``env[variable]`` names (``APPDATA``, ``LOCALAPPDATA``),
    or None when it is unset or not an absolute path.

    A relative value would resolve against the CLI's working directory (the
    open project), and so would a drive path such as C:\\...\\Roaming on a
    POSIX host (Claude Desktop probes the Windows location on every OS) and,
    on Windows, a root-relative \\Users\\... without a drive, which
    ntpath.isabs accepts before Python 3.13 (pathlib does not).
    """
    value = env.get(variable, "").strip()
    if value and (Path(value).is_absolute() or (sys.platform == "win32" and PureWindowsPath(value).is_absolute())):
        return Path(value)
    return None


def load_json_or_fail_closed(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read ``path`` as a JSON object, reporting problems instead of raising.

    Returns ``(data, None)`` on success or ``(None, reason)`` when the file
    is missing, unreadable, malformed, or not a JSON object. Callers treat
    the failure case as fail-closed: report, never overwrite. As root, a
    file a user's link leads to is not read at all (:func:`refuse_foreign_read`).
    """
    try:
        raw = read_config_text(path)
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{path} could not be read: {describe_read_error(exc)}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, f"{path} does not contain a JSON object at the top level"
    return data, None


def load_problem_note(path: Path) -> str:
    """``" (why)"`` when :func:`load_json_or_fail_closed` cannot load ``path``
    (missing, unreadable, refused as root, malformed), else ``""``: what a
    fail-closed summary says about the file instead of showing it."""
    _data, error = load_json_or_fail_closed(path)
    return f" ({error})" if error else ""


def fail_closed_block(
    target: Path, servers_key: str, server_key: str, intended: Mapping[str, Any] | None = None
) -> str:
    """What a fail-closed plan or result prints about the JSON config ``target``.

    The registration this tool would add (``intended``) and the entry
    ``target`` holds now under ``servers_key``/``server_key``, and never the
    rest of the file: harness configs hold other MCP servers' env values (API
    tokens), and a dry run's output ends up in terminals, logs and support
    tickets. A file that cannot be read or parsed is described, not shown
    (the error names the line and column); as root, one a user's link leads
    to is not read at all (:func:`load_json_or_fail_closed`).
    """
    lines: list[str] = []
    if intended is not None:
        lines += [
            f"# this tool would add to {target} (nothing is written while it fails closed):",
            json.dumps({servers_key: {server_key: dict(intended)}}, indent=2, sort_keys=True),
        ]
    data, error = load_json_or_fail_closed(target)
    servers = data.get(servers_key) if data is not None else None
    if data is None:
        lines.append(f"# {error}; its contents are not shown (they may hold other servers' secrets)")
    elif servers_key in data and not isinstance(servers, dict):
        lines.append(f'# "{servers_key}" in {target} is not an object; the rest of the file is not shown')
    elif isinstance(servers, dict) and server_key in servers:
        lines += [
            f'# "{servers_key}"["{server_key}"] in {target} now (its other entries are not shown):',
            json.dumps({servers_key: {server_key: servers[server_key]}}, indent=2, sort_keys=True),
        ]
    else:
        lines.append(f'# {target} holds no "{servers_key}"["{server_key}"] entry (its other entries are not shown)')
    return "\n".join(lines)


def load_yaml_or_fail_closed(path: Path) -> tuple[Any | None, str | None]:
    """Read ``path`` as YAML, reporting problems instead of raising.

    Same fail-closed contract as :func:`load_json_or_fail_closed`: returns
    ``(data, None)`` on success or ``(None, reason)`` when the file is
    missing, unreadable, or malformed. Unlike the JSON helper, the top-level
    document is returned as-is (YAML harness configs may legitimately be
    sequences, e.g. the dsh patch layer).
    """
    try:
        raw = read_config_text(path)
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{path} could not be read: {describe_read_error(exc)}"
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover — PyYAML is a hard dependency
        return None, f"PyYAML is not available: {exc}"
    try:
        data = yaml.safe_load(raw)
    except Exception as exc:
        from universal_db_mcp.config import describe_yaml_error

        return None, f"{path} is not valid YAML: {describe_yaml_error(exc)}"
    return data, None


# ---------------------------------------------------------------------------
# per-user harness config resolution + seeding
# ---------------------------------------------------------------------------

# The root-owned system deployment. It belongs to the launchd/systemd service
# account (mode 0640, group = service account) and is NOT readable by a normal
# user - harness (stdio) spawns run as the logged-in user and died right after
# connecting with "Permission denied" when pointed at it (seen live
# 2026-09-14). Resolution therefore checks READABILITY, not mere existence.
#
# Platform-aware: the MSI installs the machine-wide deployment under
# %ProgramData%\UniversalDB MCP\ (packaging/msi/udbmcp.wxs, CommonAppDataFolder);
# the POSIX path is what the deb/pkg installers and the service units use. A
# POSIX-only constant made every Windows CLI path silently fall through to the
# per-user config.
SYSTEM_CONFIG_DIR_WIN32 = ("UniversalDB MCP",)  # relative to %ProgramData%


def system_config_dir() -> Path:
    """Root/administrator-owned deployment directory for the running platform."""
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")).joinpath(*SYSTEM_CONFIG_DIR_WIN32)
    return Path("/etc/universal-db-mcp")


def system_config_path() -> Path:
    """The system deployment's config file (``config.yaml``) for this platform."""
    return system_config_dir() / "config.yaml"


SYSTEM_CONFIG_PATH = system_config_path()
PER_USER_CONFIG_DIR = ".universal-db-mcp"

_SEED_CONFIG_TEMPLATE = """\
# Per-user configuration for universal-db-mcp harness (stdio) spawns, seeded
# by `configure-agents`, which registers this file when the system
# deployment's config ({system_path}) is absent or your user cannot read it.
# Agents start the server as you, so your spawns get their own config, state
# and audit log. Add connections below (secrets are referenced via *_env /
# password_file, never inlined) and validate with:
#   udbmcp doctor --config {config_path}
application:
  transport: stdio
  metadata_cache_path: {metadata_path}
  audit_path: {audit_path}
"""


def resolve_harness_config_path(
    env: Mapping[str, str], home: Path, *, strict: bool = False, for_harness: bool = False
) -> str:
    """Config path advertised to a per-user harness (stdio) spawn.

    Harness spawns run AS THE LOGGED-IN USER, so the advertised path must be
    readable by that user. Resolution order: explicit ``UDBMCP_CONFIG`` from
    the current environment (the operator's override - their responsibility),
    then the system deployment when it exists AND is readable, then the
    per-user default (which :func:`ensure_per_user_harness_config` seeds on
    apply).

    ``for_harness`` - what the adapters and the seed pass - judges that
    readability as the user the harness runs as (:func:`_harness_user_can_read`),
    which differs from this process under ``sudo`` or an elevated Windows
    prompt; without it (``doctor``, ``add-connection``) it is this process's own.

    The result is always absolute, even for a relative override (see
    :func:`absolute_override`) or a relative ``home``: registrations are
    global, and a relative path would be resolved in whichever project the
    harness has open. ``strict`` - what the adapters pass before writing a
    registration - also refuses an override that names no existing file;
    the default stays lenient because ``add-connection`` creates that file.
    """
    from_env = env.get("UDBMCP_CONFIG", "").strip()
    if from_env:
        return absolute_override(from_env, "UDBMCP_CONFIG", must_exist=strict)
    if for_harness:
        readable = _harness_user_can_read(SYSTEM_CONFIG_PATH, home)
    else:
        readable = _is_readable_file(SYSTEM_CONFIG_PATH)
    if readable:
        return os.path.abspath(SYSTEM_CONFIG_PATH)
    return os.path.abspath(home / PER_USER_CONFIG_DIR / "config.yaml")


def _is_readable_file(path: Path) -> bool:
    """True when this user can read ``path``, a regular file.

    A probe that is itself denied means "not readable": the MSI's
    ``%ProgramData%\\UniversalDB MCP`` folder is SYSTEM/Administrators-only, so
    stat() of the config inside it raises for everyone else. On Windows
    ``os.access`` ignores ACLs, so the file is opened instead.
    """
    try:
        if not path.is_file():
            return False
        if sys.platform == "win32":
            with open(path, "rb"):
                return True
        return os.access(path, os.R_OK)
    except OSError:
        return False


def _harness_user_can_read(path: Path, home: Path) -> bool:
    """True when the user a harness under ``home`` runs as can read ``path``.

    That is this process's user (:func:`_is_readable_file`), except:

    * as root (``sudo configure-agents``), which reads every file: the harness
      runs as ``home``'s owner, whose permission bits are checked instead
      (:func:`_mode_bits_allow_read`; an ACL is not consulted, so a config
      only an ACL opens to that user falls back to the per-user one);
    * with an elevated Windows token, which opens the administrators-only
      deployment that the user's own harness (started from the filtered
      token) cannot: the system deployment is not advertised from it.
    """
    if sys.platform == "win32":
        return not _windows_token_is_elevated() and _is_readable_file(path)
    if os.geteuid() != 0:
        return _is_readable_file(path)
    try:
        owner = home.stat()
    except OSError:
        return False
    if owner.st_uid == 0:
        return _is_readable_file(path)
    return _mode_bits_allow_read(path, owner.st_uid, owner.st_gid)


def _mode_bits_allow_read(path: Path, uid: int, home_gid: int) -> bool:
    """Whether ``uid`` may, by the permission bits, search every directory
    above ``path`` and read it, a regular file. Its groups come from the user
    database (``home_gid`` alone when ``uid`` has no entry there)."""
    groups = _user_groups(uid, home_gid)
    real = Path(os.path.realpath(path))
    try:
        for node, want in ((real, 4), *((parent, 1) for parent in real.parents)):
            if not _bits_allow(node.stat(), uid, home_gid, want, groups):
                return False
        return stat.S_ISREG(real.stat().st_mode)
    except OSError:
        return False


def _user_groups(uid: int, fallback_gid: int) -> set[int]:
    """``uid``'s groups from the user database (``fallback_gid`` alone when
    it has no entry there)."""
    import pwd

    try:
        user = pwd.getpwuid(uid)
        return set(os.getgrouplist(user.pw_name, user.pw_gid))
    except (KeyError, OSError):
        return {fallback_gid}


def _bits_allow(st: os.stat_result, uid: int, fallback_gid: int, want: int, groups: set[int] | None = None) -> bool:
    """Whether the permission bits of ``st`` give ``uid`` the access ``want``
    (4 read, 1 search), as the owner, a group member or everyone else."""
    if groups is None:
        groups = _user_groups(uid, fallback_gid)
    shift = 6 if st.st_uid == uid else 3 if st.st_gid in groups else 0
    return ((st.st_mode >> shift) & want) == want


def _windows_token_is_elevated() -> bool:
    """True when this Windows process runs with an administrator's full token."""
    try:
        import ctypes

        return bool(getattr(ctypes, "windll").shell32.IsUserAnAdmin())  # noqa: B009 - Windows only
    except (AttributeError, OSError):
        return False


def ensure_per_user_harness_config(
    env: Mapping[str, str], home: Path, *, named: bool = False
) -> tuple[Path | None, str]:
    """Seed the per-user harness config when the advertised path needs it.

    Only-if-absent: an existing per-user config is never clobbered. Returns
    ``(created_path, note)``; ``created_path`` is None when the advertised
    config needs no seeding (explicit env override, readable system
    deployment, or the per-user file already exists). With ``named`` the
    caller has read an existing registration that names the per-user config,
    which is then seeded whatever this environment would advertise.
    """
    advertised = resolve_harness_config_path(env, home, for_harness=True)
    per_user = Path(os.path.abspath(home / PER_USER_CONFIG_DIR / "config.yaml"))
    if not named and advertised != str(per_user):
        return None, f"advertised config needs no seeding ({advertised})"
    present = (None, "per-user config already present (left untouched)")
    if per_user.is_file():
        return present
    parent = per_user.parent
    ensure_directory(parent, mode=0o700)
    try:
        atomic_write_text(
            per_user,
            _SEED_CONFIG_TEMPLATE.format(
                system_path=SYSTEM_CONFIG_PATH,
                config_path=per_user,
                metadata_path=parent / "metadata.sqlite",
                audit_path=parent / "audit.jsonl",
            ),
            create=True,
        )
    except FileExistsError:
        return present  # written meanwhile (an add-connection in another shell)
    return per_user, "seeded per-user config (0600; state and audit are per-user)"
