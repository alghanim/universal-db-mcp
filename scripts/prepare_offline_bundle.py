#!/usr/bin/env python3
"""Stage A: assemble the offline release bundle on the authorized staging
machine (network access allowed HERE ONLY; the bundle itself never touches a
public endpoint at install or runtime).

What it does:
1. Builds the application wheel without build isolation, in a private venv
   holding the hash-locked build backend (requirements/locks/build.txt).
2. Downloads exactly the target profile's committed, hashed dependency lock
   (requirements/locks/<profile>.txt, see scripts/profiles.py), connector
   wheels included, with pip isolated from every inherited setting, and fails
   unless the downloaded wheels ARE that lock. --refresh-locks recompiles the
   locks with uv from requirements/runtime.in; --check-locks is the release
   gate that they are current.
3. Emits a fully pinned, hashed runtime.lock (application wheel included).
4. Generates a CycloneDX-format SBOM from the wheelhouse.
5. Vendors the pre-staged OS package closure (unixODBC stack + Microsoft
   ODBC Driver 18 .debs, staged under out/os-packages-ubuntu24.04/) into
   os-packages/ and records name/hash/order metadata in the manifest.
6. Writes manifest.json, SHA256SUMS, and (when a signing key is provided) a
   detached Ed25519 signature over SHA256SUMS.

Driver licensing (Db2 Connect, Microsoft ODBC EULA) is an administrator
prerequisite; where a licensed artifact cannot be redistributed, the manifest
declares it 'administrator_supplied' and readiness checks will report it.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import NamedTuple

PROJECT = Path(__file__).resolve().parent.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scripts.profiles import LINUX_PROFILE_NAME, PROFILES, Profile, get_profile  # noqa: E402  (repo-relative import)

CONNECTOR_WHEELS = {
    "core": ["mcp", "PyYAML", "sqlglot"],
    "postgres": ["psycopg[binary]"],
    # The extras carry the authentication plugins, which no other package
    # pulls in: ed25519 -> PyNaCl (the default for many MariaDB accounts) and
    # rsa -> cryptography (MySQL 8.0's caching_sha2_password). Without them a
    # site hits a RuntimeError naming a package that cannot be installed
    # offline. runtime.in only CONSTRAINS versions; what gets downloaded is
    # this list, so pinning a package there alone never shipped it.
    "mysql": ["PyMySQL[ed25519,rsa]"],
    "clickhouse": ["clickhouse-connect"],
    "oracle": ["oracledb"],
    "mssql": ["pyodbc"],
    "db2": ["ibm-db"],
}

# The dependency closure is never resolved at build time. Every wheel comes
# from the target profile's committed hashed lock, fetched by pip with no
# inherited PIP_* setting or pip.conf, with --no-deps and --require-hashes,
# from PYPI_SIMPLE unless --index-url names another index (which can then only
# serve the locked bytes). The locks are compiled from requirements/runtime.in
# plus the CONNECTOR_WHEELS extras by --refresh-locks.
PYPI_SIMPLE = "https://pypi.org/simple"
LOCK_DIR = PROJECT / "requirements" / "locks"
RUNTIME_IN = PROJECT / "requirements" / "runtime.in"
BUILD_LOCK = LOCK_DIR / "build.txt"
LOCK_REFRESH_COMMAND = "python scripts/prepare_offline_bundle.py --refresh-locks"
LOCKED_PIP_FLAGS = ("--isolated", "--no-deps", "--require-hashes", "--only-binary=:all:")
_LOCK_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]*)\])?(==([^\s;\\]+))?")
_LOCK_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")
_REQ_SPLIT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?(.*)$")

WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")

# dpkg dependency order for the Microsoft ODBC Driver 18 / unixODBC closure.
# Order matters: msodbcsql18's postinst invokes `odbcinst`, so the unixODBC
# stack must be configured first. Packages not listed here are installed
# first (they can only be prerequisites this table does not model).
OS_PACKAGE_INSTALL_ORDER = {
    "libkeyutils1": 0,
    "libkrb5support0": 1,
    "libk5crypto3": 2,
    "libkrb5-3": 3,
    "libltdl7": 4,
    "unixodbc-common": 5,
    "libodbc2": 6,
    "libodbcinst2": 7,
    "unixodbc": 8,
    "odbcinst": 9,
    "msodbcsql18": 10,
}


def scrubbed_env() -> dict[str, str]:
    """The environment of every pip, build and uv subprocess.

    No inherited PIP_* or UV_* setting (index URLs, find-links, trusted hosts,
    config files) and no pip configuration file at all, so the command line
    alone decides where artifacts come from: a PIP_INDEX_URL or pip.conf on the
    staging host used to choose what was locked and signed.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_"))}
    env["PIP_CONFIG_FILE"] = os.devnull
    return env


def sh(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=scrubbed_env() if env is None else env)
    if res.returncode != 0:
        print(res.stdout[-2000:])
        print(res.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return res


def sign_sha256sums(out: Path, signing_key: str) -> str:
    """Produce out/SIGNATURE: a detached Ed25519 signature over SHA256SUMS.

    OpenSSL 3.x's `pkeyutl -rawin` cannot read a non-seekable stdin pipe
    ('unable to determine file size for oneshot operation' — Ed25519 is a
    one-shot signer and pkeyutl needs a seekable -in), so the data is passed
    through -in/-out files exactly as scripts/verify_bundle.py does on the
    verification side. If the host openssl still refuses Ed25519 (e.g.
    LibreSSL), the python cryptography package signs instead — but the
    fallback is announced and the implementation that produced SIGNATURE is
    returned, so release provenance is never implicit.

    Returns the name of the implementation that produced SIGNATURE.
    """
    sums_path = out / "SHA256SUMS"
    sig_path = out / "SIGNATURE"
    data = sums_path.read_bytes()
    sig_path.unlink(missing_ok=True)  # never leave a partial artifact behind
    sig = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", signing_key, "-rawin",
         "-in", str(sums_path), "-out", str(sig_path)],
        capture_output=True,
    )
    if sig.returncode == 0:
        print("signed with openssl pkeyutl (Ed25519)")
        return "openssl"
    # Loud, explicit fallback: report why the primary path failed so the
    # release record shows which implementation signed the bundle.
    err = sig.stderr.decode(errors="replace").strip()[:200]
    print(f"WARNING: openssl Ed25519 signing failed ({err!r}); "
          "falling back to the python cryptography package")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(Path(signing_key).read_bytes(), password=None)
        sig_path.write_bytes(key.sign(data))
    except ImportError as exc:
        sig_path.unlink(missing_ok=True)
        raise SystemExit(
            f"signing failed: openssl error {err!r} and "
            f"no cryptography fallback installed ({exc})"
        )
    print("signed with python cryptography (host openssl lacks Ed25519 pkeyutl)")
    return "python-cryptography"


def wheel_meta(path: Path) -> tuple[str, str]:
    m = WHEEL_RE.match(path.name)
    if not m:
        raise SystemExit(f"unexpected artifact (not a binary wheel): {path.name}")
    name = m.group("name").replace("_", "-").lower()
    return name, m.group("ver")


def check_signing_conflict(signing_key: str | None, allow_missing: bool) -> None:
    """Refuse --allow-missing-connectors together with --signing-key.

    A signed release can never ship a knowingly incomplete wheelhouse: either
    complete the closure or build unsigned.
    """
    if allow_missing and signing_key:
        raise SystemExit(
            "--allow-missing-connectors cannot be combined with --signing-key: "
            "a signed release can never ship a knowingly incomplete wheelhouse. "
            "Complete the closure, or build without the signing key."
        )


def require_complete_wheelhouse(missing: list[str], profile_name: str, allow_missing: bool) -> None:
    """Fail loud when top-level connector wheels are missing from the closure."""
    if missing and not allow_missing:
        raise SystemExit(
            f"incomplete wheelhouse for profile '{profile_name}': missing connector "
            f"wheels {missing}. The affected connectors cannot pass readiness checks "
            "on targets. Re-run with --allow-missing-connectors to record them in "
            "manifest.json and continue (unsigned bundles only)."
        )


def check_os_package_closure(
    connectors: list[str],
    os_packages: list[dict[str, object]],
    profile: Profile,
    signing_key: str | None,
) -> bool:
    """Fail loud (signed) or warn loudly (unsigned) on an incomplete .deb closure.

    Mirrors BOTH scripts/verify_bundle.py closure rules for declared os_packages:

    1. Any bundle declaring msodbcsql18 must also declare the unixODBC stack
       (unixodbc): msodbcsql18's postinst invokes `odbcinst`, so the driver
       cannot be configured without it. The verifier refuses such a bundle
       unconditionally — there is no administrator_supplied fallback once the
       driver .deb is shipped — so a signed build fails here rather than
       producing a release that could never pass verification in the air gap,
       and an unsigned build proceeds only with a loud warning.
    2. When mssql is selected on a profile that stages an OS-package closure,
       the staged directory must actually contain msodbcsql18: the verifier
       refuses any bundle whose manifest selects mssql without msodbcsql18
       among the declared os_packages. A signed build therefore fails here —
       the mirror of check_signing_conflict's "a signed release can never ship
       a knowingly incomplete wheelhouse". Unsigned builds keep the documented
       administrator_supplied fallback, but loudly, never silently.

    Returns True when the vendored closure includes the mssql ODBC driver.
    """
    names = {str(e["package"]) for e in os_packages}
    driver_vendored = "msodbcsql18" in names
    # Rule 1 — applies whenever .debs are declared at all, exactly like the
    # verifier (which only exempts rule 2 for the entirely-absent case).
    if driver_vendored and "unixodbc" not in names:
        msg = (
            f"staged OS-package closure for profile '{profile.name}' declares "
            "msodbcsql18 without the unixODBC stack (unixodbc): the driver's "
            "postinst invokes `odbcinst`, so scripts/verify_bundle.py refuses "
            "any bundle that declares msodbcsql18 without unixodbc. "
        )
        if signing_key:
            raise SystemExit(
                msg + "A signed release can never ship a knowingly incomplete "
                "OS-package closure: stage the full closure (see "
                "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md), or build without the signing key."
            )
        print("WARNING: " + msg + "The bundle will fail scripts/verify_bundle.py "
              "on the target; stage the unixODBC stack .debs before release.",
              file=sys.stderr)
    if "mssql" not in connectors or not profile.os_packages_staging:
        return driver_vendored
    if driver_vendored:
        return True
    state = (
        f"missing entirely (no .debs found in {profile.os_packages_staging}/)"
        if not os_packages
        else "incomplete (msodbcsql18 is not among the staged .debs)"
    )
    msg = (
        f"staged OS-package closure for profile '{profile.name}' is {state}: "
        "the MSSQL connector would be demoted to administrator_supplied in "
        "manifest.json, and scripts/verify_bundle.py refuses a bundle that "
        "selects mssql without msodbcsql18 among the declared os_packages. "
    )
    if signing_key:
        raise SystemExit(
            msg + "A signed release can never ship a knowingly incomplete "
            "OS-package closure: stage the full closure (see "
            "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md), or build without the signing key."
        )
    print("WARNING: " + msg + "The bundle will declare the Microsoft ODBC "
          "driver administrator_supplied.", file=sys.stderr)
    return False


class LockEntry(NamedTuple):
    """One pinned package of a hashed lock (uv pip compile --generate-hashes)."""

    name: str  # canonical (PEP 503) project name
    version: str
    hashes: frozenset[str]  # every sha256 the lock accepts for this version
    via: tuple[str, ...]  # the '# via' annotation: requiring packages, or '-r <input>'


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_path(profile: Profile) -> Path:
    return LOCK_DIR / f"{profile.name}.txt"


def _shown(path: Path) -> str:
    return path.relative_to(PROJECT).as_posix() if path.is_relative_to(PROJECT) else str(path)


def parse_lock(text: str) -> dict[str, LockEntry]:
    """Parse a hashed requirements lock in uv's pip-compile output format.

    Raises ValueError on a line that is not an exact == pin, or a second pin
    of the same project.
    """
    raw: list[tuple[str, str, set[str], list[str]]] = []
    in_via = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not line[0].isspace() and not stripped.startswith("#"):
            m = _LOCK_REQ_RE.match(stripped)
            if m is None or m.group(4) is None:
                raise ValueError(f"not an exact == pin: {stripped[:60]}")
            name = canonical_name(m.group(1))
            if any(name == seen[0] for seen in raw):
                raise ValueError(f"{name} is pinned twice")
            raw.append((name, m.group(4), set(), []))
            in_via = False
        elif not raw:
            continue  # the header
        elif stripped.startswith("# via"):
            rest = stripped[len("# via"):].strip()
            if rest:
                raw[-1][3].append(rest)
            in_via = not rest  # a bare '# via' opens a list of '#   <parent>' lines
            continue
        elif stripped.startswith("#"):
            if in_via:
                raw[-1][3].append(stripped.lstrip("#").strip())
            continue
        raw[-1][2].update(_LOCK_HASH_RE.findall(stripped))
    return {name: LockEntry(name, version, frozenset(hashes), tuple(via)) for name, version, hashes, via in raw}


def _requirement_lines(path: Path) -> list[str]:
    lines = (line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line]


def runtime_pins(runtime_in: Path | None = None) -> dict[str, str]:
    """{canonical name: version} of the exact pins in requirements/runtime.in."""
    pins: dict[str, str] = {}
    for line in _requirement_lines(runtime_in or RUNTIME_IN):
        m = _LOCK_REQ_RE.match(line)
        if m is not None and m.group(4) is not None:
            pins[canonical_name(m.group(1))] = m.group(4)
    return pins


def lock_input(runtime_in: Path | None = None) -> str:
    """What the profile locks are compiled from.

    requirements/runtime.in, with the extras the bundle downloads
    (CONNECTOR_WHEELS: PyMySQL[ed25519,rsa], psycopg[binary]) added to the
    matching pins, and any connector package runtime.in does not pin.
    """
    extras: dict[str, set[str]] = {}
    for pkg in (p for pkgs in CONNECTOR_WHEELS.values() for p in pkgs):
        name, _, rest = pkg.partition("[")
        extras.setdefault(canonical_name(name), set()).update(e for e in rest.rstrip("]").split(",") if e)
    lines: list[str] = []
    for line in _requirement_lines(runtime_in or RUNTIME_IN):
        m = _REQ_SPLIT_RE.match(line)
        if m is None:
            raise SystemExit(f"unreadable requirement in requirements/runtime.in: {line}")
        name, own, rest = m.groups()
        wanted = extras.pop(canonical_name(name), set()) | {e.strip() for e in (own or "").split(",") if e.strip()}
        lines.append(f"{name}[{','.join(sorted(wanted))}]{rest}" if wanted else f"{name}{rest}")
    # what is left in extras: connector packages runtime.in does not pin
    lines += [
        pkg for pkgs in CONNECTOR_WHEELS.values() for pkg in pkgs if canonical_name(pkg.partition("[")[0]) in extras
    ]
    return "\n".join(lines) + "\n"


def lock_input_digest(runtime_in: Path | None = None) -> str:
    return hashlib.sha256(lock_input(runtime_in).encode()).hexdigest()


def lock_problems(profile: Profile, runtime_in: Path | None = None, lock: Path | None = None) -> list[str]:
    """Why the profile's committed lock cannot be used as it is (empty: it can)."""
    runtime_in = runtime_in or RUNTIME_IN
    lock = lock or lock_path(profile)
    if not lock.is_file():
        return [f"{_shown(lock)} is missing"]
    text = lock.read_text(encoding="utf-8")
    try:
        entries = parse_lock(text)
    except ValueError as exc:
        return [f"{_shown(lock)}: {exc}"]
    problems = [f"{_shown(lock)}: {name} has no --hash" for name, entry in entries.items() if not entry.hashes]
    for name, version in runtime_pins(runtime_in).items():
        entry = entries.get(name)
        if entry is None:
            problems.append(f"{_shown(lock)} has no {name} (requirements/runtime.in pins {name}=={version})")
        elif entry.version != version:
            problems.append(f"{_shown(lock)} pins {name}=={entry.version}, requirements/runtime.in pins {version}")
    digest = lock_input_digest(runtime_in)
    if f"# input-sha256: {digest}" not in text:
        problems.append(
            f"{_shown(lock)} was not compiled from the current requirements/runtime.in and CONNECTOR_WHEELS "
            f"extras (input-sha256 {digest[:16]}...)"
        )
    return problems


def build_lock_problems(lock: Path | None = None) -> list[str]:
    """Why the build-backend lock cannot build this project (empty: it can)."""
    from packaging.requirements import Requirement  # staging machine: comes with the dev tools (build, pytest)

    lock = lock or BUILD_LOCK
    if not lock.is_file():
        return [f"{_shown(lock)} is missing"]
    try:
        entries = parse_lock(lock.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"{_shown(lock)}: {exc}"]
    problems = [f"{_shown(lock)}: {name} has no --hash" for name, entry in entries.items() if not entry.hashes]
    for spec in ("build", *build_requires()):
        req = Requirement(spec)
        entry = entries.get(canonical_name(req.name))
        if entry is None:
            problems.append(f"{_shown(lock)} has no {req.name} (needed to build the application wheel)")
        elif not req.specifier.contains(entry.version, prereleases=True):
            problems.append(f"{_shown(lock)} pins {req.name}=={entry.version}, pyproject.toml requires {req}")
    return problems


def build_requires() -> list[str]:
    pyproject = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    return list(pyproject["build-system"]["requires"])


def lock_resolver(text: str) -> str | None:
    """The uv version --refresh-locks recorded in a lock, if any."""
    m = re.search(r"^# resolver: (.+)$", text, flags=re.MULTILINE)
    return m.group(1).strip() if m else None


def lock_closure(entries: dict[str, LockEntry], connectors: list[str]) -> list[LockEntry]:
    """The lock entries the selected connectors need: their CONNECTOR_WHEELS
    packages and everything the lock's '# via' annotations show they pull in."""
    children: dict[str, set[str]] = {}
    for entry in entries.values():
        for parent in entry.via:
            if not parent.startswith("-"):
                children.setdefault(canonical_name(parent), set()).add(entry.name)
    roots = [canonical_name(pkg.partition("[")[0]) for c in connectors for pkg in CONNECTOR_WHEELS[c]]
    absent = sorted({root for root in roots if root not in entries})
    if absent:
        raise SystemExit(f"the dependency lock has no entry for {absent}; run {LOCK_REFRESH_COMMAND}")
    keep: set[str] = set()
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name not in keep:
            keep.add(name)
            todo.extend(children.get(name, ()))
    return [entries[name] for name in sorted(keep)]


def format_requirements(entries: list[LockEntry]) -> str:
    return "".join(
        f"{e.name}=={e.version}" + "".join(f" --hash=sha256:{h}" for h in sorted(e.hashes)) + "\n" for e in entries
    )


def pip_download_command(
    profile: Profile, wheelhouse: Path, requirements: Path, index_url: str = PYPI_SIMPLE
) -> list[str]:
    """Build the pip download command for the profile's target interpreter.

    Only what *requirements* (hashed exact pins) names, from *index_url*
    alone, with no inherited configuration. Multiple --platform flags (e.g.
    both macOS tags) are passed as repeated flags, which pip accepts.
    """
    cmd = [sys.executable, "-m", "pip", "download", *LOCKED_PIP_FLAGS, "--index-url", index_url]
    for plat in profile.pip_platforms:
        cmd += ["--platform", plat]
    cmd += [
        "--implementation", "cp",
        "--python-version", profile.python_version,
        "--abi", profile.abi,
        "--dest", str(wheelhouse),
        "-r", str(requirements),
    ]
    return cmd


def wheelhouse_problems(wheels: list[Path], entries: list[LockEntry]) -> list[str]:
    """Differences between downloaded wheels and the lock entries they must be."""
    expected = {entry.name: entry for entry in entries}
    seen: set[str] = set()
    problems: list[str] = []
    for wheel in wheels:
        name, version = wheel_meta(wheel)
        name = canonical_name(name)
        entry = expected.get(name)
        if entry is None or name in seen:
            problems.append(f"{wheel.name} is not a wheel the lock names")
            continue
        seen.add(name)
        if version != entry.version:
            problems.append(f"{wheel.name}: the lock pins {name}=={entry.version}")
        elif hashlib.sha256(wheel.read_bytes()).hexdigest() not in entry.hashes:
            problems.append(f"{wheel.name}: its sha256 is not one the lock accepts")
    problems += [
        f"{name}=={expected[name].version} is locked but was not downloaded" for name in sorted(set(expected) - seen)
    ]
    return problems


def download_closure(profile: Profile, entries: list[LockEntry], workdir: Path, index_url: str) -> list[Path]:
    """Download exactly *entries* for the profile and prove the result IS them."""
    workdir.mkdir(parents=True, exist_ok=True)
    requirements = workdir / "closure.txt"
    requirements.write_text(format_requirements(entries), encoding="utf-8")
    cmd = pip_download_command(profile, workdir / "wheels", requirements, index_url)
    print("+", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True, env=scrubbed_env())
    if res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:], file=sys.stderr)
        raise SystemExit(
            "pip download failed for the target profile (every wheel must match the committed hashed lock)"
        )
    wheels = sorted((workdir / "wheels").glob("*.whl"))
    problems = wheelhouse_problems(wheels, entries)
    if problems:
        raise SystemExit("the downloaded wheelhouse does not match the lock: " + "; ".join(problems))
    return wheels


def build_app_wheel(workdir: Path, index_url: str) -> Path:
    """Build the application wheel with the hash-locked build backend.

    `python -m build` used to install whatever hatchling (and hatchling's
    dependencies) the inherited index served into an isolated environment.
    The backend now comes from requirements/locks/build.txt, installed with
    --require-hashes into a private venv, and the build runs there with
    --no-isolation.
    """
    venv = workdir / "build-venv"
    sh([sys.executable, "-m", "venv", str(venv)])
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    sh([str(python), "-m", "pip", "install", *LOCKED_PIP_FLAGS, "--index-url", index_url, "-r", str(BUILD_LOCK)])
    sh([str(python), "-m", "build", "--wheel", "--no-isolation", "--outdir", str(workdir / "dist"), str(PROJECT)])
    wheels = list((workdir / "dist").glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


def check_locks() -> int:
    """--check-locks: 0 when every committed lock is current, else 1."""
    problems = [p for profile in PROFILES.values() for p in lock_problems(profile)] + build_lock_problems()
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        print(f"Refresh them with '{LOCK_REFRESH_COMMAND}' (network), review the diff and commit it.", file=sys.stderr)
        return 1
    print(f"locks: {len(PROFILES)} profile locks and the build lock match requirements/runtime.in and pyproject.toml")
    return 0


def _stamp_lock(path: Path, what: str, resolver: str, digest: str | None) -> None:
    """Record, under uv's header, what a lock is for, what resolved it and from which input."""
    lines = path.read_text(encoding="utf-8").splitlines()
    head = 2 if lines[:1] == ["# This file was autogenerated by uv via the following command:"] else 0
    stamp = [f"# lock for: {what}", f"# resolver: {resolver}"]
    if digest is not None:
        stamp.append(f"# input-sha256: {digest}")
    path.write_text("\n".join([*lines[:head], *stamp, *lines[head:]]) + "\n", encoding="utf-8")


def refresh_locks(index_url: str) -> None:
    """--refresh-locks: recompile every committed lock with uv (network).

    uv keeps the versions already in an existing lock wherever the input still
    allows them; delete a lock to re-resolve it from scratch.
    """
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("--refresh-locks needs uv on PATH (https://docs.astral.sh/uv/)")
    resolver = sh([uv, "--version"]).stdout.strip()
    compile_cmd = [
        uv, "pip", "compile", "--quiet", "--no-config", "--generate-hashes", "--only-binary", ":all:",
        "--index-url", index_url, "--custom-compile-command", LOCK_REFRESH_COMMAND,
    ]
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "runtime.in").write_text(lock_input(), encoding="utf-8")
        for profile in PROFILES.values():
            env = scrubbed_env()
            macos = [tuple(int(v) for v in m.groups()) for p in profile.pip_platforms
                     if (m := re.match(r"macosx_(\d+)_(\d+)_", p))]
            if macos:  # uv otherwise assumes its oldest macOS; ibm_db ships macosx_14_0 wheels only
                env["MACOSX_DEPLOYMENT_TARGET"] = "{}.{}".format(*max(macos))
            sh([*compile_cmd, "--python-version", profile.python_version, "--python-platform", profile.lock_platform,
                "--output-file", str(lock_path(profile)), "runtime.in"], cwd=Path(td), env=env)
            _stamp_lock(lock_path(profile), f"{profile.name} (--python-platform {profile.lock_platform})",
                        resolver, lock_input_digest())
        (Path(td) / "build.in").write_text("\n".join(["build", *build_requires()]) + "\n", encoding="utf-8")
        # the build backend runs on the staging host: a universal lock for the
        # project's oldest supported Python
        sh([*compile_cmd, "--universal", "--python-version", PROFILES[LINUX_PROFILE_NAME].python_version,
            "--output-file", str(BUILD_LOCK), "build.in"], cwd=Path(td))
        _stamp_lock(BUILD_LOCK, "the build backend of the application wheel (universal)", resolver, None)
    print(f"locks refreshed with {resolver}: review 'git diff {_shown(LOCK_DIR)}' and commit it")


def connectors_arg(value: str) -> str:
    """Validate and normalize the --connectors argument at the argparse boundary.

    Unknown or padded values ('trino', ' postgres') must fail as a clean
    argparse error (exit code 2), not as a raw KeyError deep inside the build.
    """
    names = [c.strip() for c in value.split(",") if c.strip()]
    unknown = sorted({c for c in names if c not in CONNECTOR_WHEELS})
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown connector(s): {', '.join(unknown)} "
            f"(valid choices: {', '.join(sorted(CONNECTOR_WHEELS))})"
        )
    if not names:
        raise argparse.ArgumentTypeError(
            "no connectors selected ('core' is always included regardless)"
        )
    return ",".join(names)


def release_seq_arg(value: str) -> int:
    """--release-seq / UDBMCP_RELEASE_SEQ: a non-negative integer."""
    try:
        seq = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"release sequence must be an integer, got {value!r}") from None
    if seq < 0:
        raise argparse.ArgumentTypeError(f"release sequence must not be negative, got {seq}")
    return seq


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="linux-x86_64-ubuntu24.04-cp312", choices=sorted(PROFILES),
                    help="target profile (see scripts/profiles.py)")
    ap.add_argument("--out", help="bundle output directory (required unless --check-locks/--refresh-locks)")
    ap.add_argument("--connectors", default="core,postgres,mysql,clickhouse,oracle,mssql,db2",
                    type=connectors_arg,
                    help="comma list; 'core' is always included")
    ap.add_argument("--allow-missing-connectors", action="store_true",
                    help="record missing connector wheels in the manifest and continue "
                         "instead of failing; refused together with --signing-key")
    ap.add_argument("--signing-key", default=None, help="PEM file with an Ed25519 private key (staging only)")
    ap.add_argument("--source-rev", default=os.environ.get("UDBMCP_SOURCE_REV") or None,
                    help="source revision recorded in manifest.json. Default: git HEAD of "
                         "this repository (UDBMCP_SOURCE_REV as an environment override); "
                         "falls back to the sentinel 'unknown' with a WARNING when git is "
                         "unavailable, the tree is not a repository, or no commit exists — "
                         "package versions derived from 'unknown' cannot be tied to a "
                         "source revision.")
    ap.add_argument("--release-seq", type=release_seq_arg,
                    default=os.environ.get("UDBMCP_RELEASE_SEQ") or None,
                    help="integer release_seq recorded in manifest.json; the installers refuse a "
                         "bundle whose release_seq is lower than the installed one. Default: the "
                         "committer timestamp (UNIX seconds) of --source-rev, "
                         "UDBMCP_RELEASE_SEQ as an environment override; omitted with a WARNING "
                         "when --source-rev is not a commit of this repository.")
    ap.add_argument("--index-url", default=PYPI_SIMPLE,
                    help="package index for the locked wheels and the locked build backend (default: "
                         "%(default)s). Inherited PIP_* settings and pip.conf are ignored; a mirror can only "
                         "serve the bytes requirements/locks/ hashes.")
    ap.add_argument("--check-locks", action="store_true",
                    help="check that requirements/locks/ holds a current hashed lock for every profile and "
                         "for the build backend, then exit (1 when one is missing or out of date)")
    ap.add_argument("--refresh-locks", action="store_true",
                    help="recompile requirements/locks/ with uv from requirements/runtime.in, the "
                         "CONNECTOR_WHEELS extras and pyproject.toml's build-system (network), then exit")
    return ap


def detect_git_rev(repo: Path = PROJECT) -> str | None:
    """Return the git HEAD revision of the repository containing *repo*, or
    None when git is unavailable, the path is not inside a git work tree, or
    HEAD is unborn (no commits yet). Never raises."""
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout.strip() or None


def resolve_source_rev(explicit: str | None) -> str:
    """Resolve the manifest source_rev.

    Order: an explicit --source-rev / UDBMCP_SOURCE_REV wins, then the
    automatically captured git HEAD. When the revision cannot be determined,
    fall back to the 'unknown' sentinel LOUDLY (stderr WARNING) so a bundle
    without provenance never passes unnoticed — never silently.
    """
    if explicit:
        return explicit
    rev = detect_git_rev()
    if rev:
        return rev
    print(
        "WARNING: could not determine the source revision automatically (git "
        "unavailable, not a git repository, or no commits yet); manifest "
        "source_rev will be the sentinel 'unknown'. Package versions derived "
        "from it cannot be tied to any source revision — pass --source-rev "
        "or set UDBMCP_SOURCE_REV to record one.",
        file=sys.stderr,
    )
    return "unknown"


def resolve_release_seq(explicit: int | None, source_rev: str) -> int | None:
    """Resolve the manifest release_seq (the anti-rollback order of releases).

    An explicit --release-seq / UDBMCP_RELEASE_SEQ wins. Otherwise it is the
    committer timestamp of source_rev, so it grows with every commit and a
    rebuild of an old commit keeps its old place. None (no release_seq, which
    the verifier treats as older than any sequenced release) with a WARNING
    when source_rev is not a commit of this repository.
    """
    if explicit is not None:
        return explicit
    try:
        res = subprocess.run(  # noqa: S603 - fixed git argv, the revision is the builder's own
            ["git", "-C", str(PROJECT), "show", "-s", "--format=%ct", f"{source_rev}^{{commit}}", "--"],  # noqa: S607
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    else:
        if res.returncode == 0 and res.stdout.strip().isdigit():
            return int(res.stdout.strip())
    print(
        f"WARNING: source_rev {source_rev!r} is not a commit of this repository, so the "
        "manifest carries no release_seq. Installers treat such a bundle as OLDER than any "
        "installed release that has one (anti-rollback); pass --release-seq to order it.",
        file=sys.stderr,
    )
    return None


def stage_os_packages(out: Path, staging: Path) -> list[dict[str, object]]:
    """Vendor the staged .deb closure into the bundle's os-packages/ directory.

    The closure is acquired once on the staging machine (where network access
    is allowed) into out/os-packages-ubuntu24.04/ together with a SHA256SUMS
    manifest, and is copied verbatim here so the bundle is self-contained and
    hash-pinned end to end. The bundle-wide SHA256SUMS (written later, over
    the whole tree) covers every copied file.

    Returns manifest 'os_packages' entries sorted into dpkg dependency order.
    """
    debs = sorted(staging.glob("*.deb")) if staging.is_dir() else []
    if not debs:
        return []

    staged: dict[str, str] = {}
    sums_file = staging / "SHA256SUMS"
    if sums_file.exists():
        for line in sums_file.read_text().splitlines():
            if line.strip():
                digest, _, fname = line.partition("  ")
                staged[fname.strip()] = digest

    # Fail loud on a declared-but-absent staged .deb: SHA256SUMS is copied
    # verbatim into the bundle below, so silently dropping the file would
    # ship a bundle whose os-packages/SHA256SUMS declares a .deb it does not
    # contain — a signed release that could never pass verification.
    missing_staged = sorted(
        name for name in staged
        if name.endswith(".deb") and not (staging / name).is_file()
    )
    if missing_staged:
        raise SystemExit(
            "staged OS-package closure is incomplete: staging SHA256SUMS "
            f"declares {missing_staged} but the file(s) are absent from "
            f"{staging}. Re-stage the missing .deb(s) (or regenerate the "
            "staging SHA256SUMS) before building."
        )

    entries: list[dict[str, object]] = []
    for deb in debs:
        digest = hashlib.sha256(deb.read_bytes()).hexdigest()
        expected = staged.get(deb.name)
        if expected and expected != digest:
            raise SystemExit(
                f"staged OS package does not match its SHA256SUMS entry: {deb.name}"
            )
        # deb filenames are <package>_<version>_<arch>.deb; underscores cannot
        # appear inside a Debian package name or version, so this split is safe.
        pkg, version, arch = (deb.name[: -len(".deb")].split("_", 2) + ["unknown", "unknown"])[:3]
        entries.append({
            "package": pkg,
            "version": version,
            "architecture": arch,
            "file": deb.name,
            "path": f"os-packages/{deb.name}",
            "sha256": digest,
            "size": deb.stat().st_size,
            "install_order": OS_PACKAGE_INSTALL_ORDER.get(pkg, -1),
        })
    entries.sort(key=lambda e: (int(str(e["install_order"])), str(e["file"])))

    dest = out / "os-packages"
    for e in entries:
        shutil.copy2(staging / str(e["file"]), dest / str(e["file"]))
    if sums_file.exists():
        shutil.copy2(sums_file, dest / "SHA256SUMS")
    return entries


def main() -> None:
    ap = build_arg_parser()
    args = ap.parse_args()
    if args.check_locks:
        raise SystemExit(check_locks())
    if args.refresh_locks:
        refresh_locks(args.index_url)
        return
    if not args.out:
        ap.error("--out is required (unless --check-locks or --refresh-locks)")
    check_signing_conflict(args.signing_key, args.allow_missing_connectors)
    source_rev = resolve_source_rev(args.source_rev)
    if args.signing_key and source_rev == "unknown":
        print(
            "WARNING: signing a bundle whose manifest source_rev is the sentinel "
            "'unknown': the signature attests the payload bytes but ties them to "
            "no source revision. Pass --source-rev (or UDBMCP_SOURCE_REV) to "
            "record one.",
            file=sys.stderr,
        )
    release_seq = resolve_release_seq(args.release_seq, source_rev)
    profile = get_profile(args.profile)
    lock = lock_path(profile)
    problems = lock_problems(profile) + build_lock_problems()
    if problems:
        raise SystemExit(
            "the committed dependency locks cannot be used: " + "; ".join(problems)
            + f". Run '{LOCK_REFRESH_COMMAND}' (network), review the diff and commit it."
        )

    connectors = ["core"] + [c for c in args.connectors.split(",") if c != "core"]
    missing: list[str] = []

    out = Path(args.out) / f"universal-db-mcp-0.1.0-{args.profile}"
    if out.exists():
        shutil.rmtree(out)
    for d in ("requirements", "wheelhouse", "native-drivers", "os-packages", "images",
              "installers", "config-templates", "licenses", "sbom", "docs", "tests",
              "test-evidence"):
        (out / d).mkdir(parents=True)

    # 1. application wheel (hash-locked build backend, no build isolation) ------
    with tempfile.TemporaryDirectory() as td:
        app_wheel = build_app_wheel(Path(td), args.index_url)
        app_wheel_name = app_wheel.name
        shutil.copy2(app_wheel, out / "wheelhouse" / app_wheel_name)

    # 2. dependency closure: exactly the profile's committed hashed lock --------
    # A rebuild cannot ship different (unreviewed) transitive versions, and a
    # wheel the index serves that the lock does not hash fails the build here,
    # before anything is locked or signed.
    lock_bytes = lock.read_bytes()
    lock_text = lock_bytes.decode("utf-8")
    closure = lock_closure(parse_lock(lock_text), connectors)
    with tempfile.TemporaryDirectory() as td:
        for wheel in download_closure(profile, closure, Path(td), args.index_url):
            shutil.copy2(wheel, out / "wheelhouse" / wheel.name)

    # record which top-level connector wheels actually landed, and fail loud
    # when any are missing (a signed release can never ship a knowingly
    # incomplete wheelhouse; see --allow-missing-connectors)
    wheelhouse = sorted((out / "wheelhouse").glob("*.whl"))
    names = {wheel_meta(w)[0] for w in wheelhouse}
    for c in connectors:
        for pkg in CONNECTOR_WHEELS[c]:
            if pkg.split("[")[0].lower().replace("_", "-") not in names:
                missing.append(pkg)
    require_complete_wheelhouse(missing, profile.name, args.allow_missing_connectors)

    # 3. runtime.lock (every wheel, hashed; application wheel included) --------
    lines = [
        "# Generated by scripts/prepare_offline_bundle.py — do not edit.",
        f"# profile: {args.profile}",
        "# install with: pip install --no-index --no-cache-dir --find-links=<wheelhouse> "
        "--only-binary=:all: --require-hashes -r runtime.lock",
    ]
    for w in wheelhouse:
        name, ver = wheel_meta(w)
        digest = hashlib.sha256(w.read_bytes()).hexdigest()
        lines.append(f"{name}=={ver} --hash=sha256:{digest}")
    (out / "requirements" / "runtime.lock").write_text("\n".join(lines) + "\n")

    # 4. SBOM (CycloneDX 1.5, hand-generated from the wheelhouse) ---------------
    components = []
    for w in wheelhouse:
        name, ver = wheel_meta(w)
        components.append({
            "type": "library", "name": name, "version": ver,
            "purl": f"pkg:pypi/{name}@{ver}",
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(w.read_bytes()).hexdigest()}],
        })
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "note": "Generated from the offline bundle wheelhouse. Vulnerability "
                    "data must be refreshed by re-running the scan on the staging "
                    "machine; this SBOM does not stay current by itself.",
        },
        "components": components,
    }
    (out / "sbom" / "cyclonedx.json").write_text(json.dumps(sbom, indent=2))

    # 5. supporting files --------------------------------------------------------
    for f in ("docs",):
        for doc in (PROJECT / f).glob("*.md"):
            shutil.copy2(doc, out / "docs" / doc.name)
    for doc in (PROJECT.glob("*.md")):
        if doc.name != "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md":
            shutil.copy2(doc, out / doc.name)
    shutil.copy2(PROJECT / "config.example.yaml", out / "config-templates" / "config.yaml")
    shutil.copy2(PROJECT / "examples" / "sqlite-demo" / "create_demo.py", out / "config-templates" / "create_demo.py")
    shutil.copy2(PROJECT / "examples" / "sqlite-demo" / "config.template.yaml", out / "config-templates" / "config.template.yaml")
    # Reference copies ONLY. The executable verifier/installer travel in the
    # separate trusted-tools/ output (same channel as the public key) and are
    # installed under /usr/local/lib/udbmcp-trust; install_offline.sh refuses
    # to run from inside a bundle, so a tampered bundle cannot verify itself.
    shutil.copy2(PROJECT / "scripts" / "verify_bundle.py", out / "installers" / "verify_bundle.py")
    shutil.copy2(PROJECT / "scripts" / "install_offline.sh", out / "installers" / "install_offline.sh")
    (out / "installers" / "README.md").write_text(
        "# Reference copies only\n\nThese files are included for auditing. Do NOT execute them from\n"
        "here: the installer refuses to run from inside a bundle. Use the copies\n"
        "distributed in `trusted-tools/` over the same trusted channel as the\n"
        "release public key (see docs/offline-deployment.md, 'Trust bootstrap').\n"
    )
    trusted = Path(args.out) / "trusted-tools"
    trusted.mkdir(parents=True, exist_ok=True)
    trusted_lib = trusted / "lib"
    trusted_lib.mkdir(exist_ok=True)
    # The container-mode image loader is a trusted tool too: it refuses to run
    # from inside a bundle and loads only a verified private copy of it.
    for name in ("verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh",
                 "profiles.py", "load_images_offline.sh"):
        shutil.copy2(PROJECT / "scripts" / name, trusted / name)
    # install_offline.sh / upgrade_offline.sh source lib/os_packages.sh from
    # the directory they run from; a trusted-tools copy without the helper
    # makes every install abort after verification ("shared OS-package
    # helper not found") — shipped 2026-09-11 and caught by Gate A/B.
    shutil.copy2(PROJECT / "scripts" / "lib" / "os_packages.sh", trusted_lib / "os_packages.sh")
    trusted_names = (
        "verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh",
        "profiles.py", "lib/os_packages.sh", "load_images_offline.sh",
    )
    (trusted / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((trusted / n).read_bytes()).hexdigest()}  {n}\n"
            for n in trusted_names
        )
    )
    ops = out / "operations"
    ops.mkdir(exist_ok=True)
    for op in ("upgrade_offline.sh", "rollback_offline.sh", "load_images_offline.sh", "doctor.sh"):
        shutil.copy2(PROJECT / "scripts" / op, ops / op)
    shutil.copy2(PROJECT / "packaging" / "systemd" / "universal-db-mcp.service", ops / "universal-db-mcp.service")
    shutil.copy2(PROJECT / "packaging" / "compose.offline.yaml", ops / "compose.offline.yaml")
    shutil.copy2(PROJECT / "scripts" / "in_container_test.sh", out / "tests" / "in_container_test.sh")
    shutil.copy2(PROJECT / "scripts" / "protocol_probe.py", out / "tests" / "protocol_probe.py")
    (out / "tests" / "README.md").write_text(
        "# Bundle test profile\n\nRun `in_container_test.sh` inside a clean, "
        "network-restricted Ubuntu 24.04 container matching the profile. See "
        "docs/acceptance-tests.md.\n"
    )
    # 5b. OS packages: vendor the staged .deb closure (unixODBC stack +
    #     Microsoft ODBC Driver 18) when mssql is selected, so install targets
    #     never need apt, a vendor repository, or any network access.
    os_packages: list[dict[str, object]] = []
    if "mssql" in connectors and profile.os_packages_staging:
        os_packages = stage_os_packages(out, PROJECT / profile.os_packages_staging)
    mssql_driver_vendored = check_os_package_closure(
        connectors, os_packages, profile, args.signing_key,
    )
    if mssql_driver_vendored and os_packages:
        (out / "os-packages" / "README.md").write_text(
            "# OS packages\n\nThis bundle ships a pre-staged, hash-pinned OS package "
            "closure for the MSSQL connector (unixODBC stack + Microsoft ODBC Driver 18 "
            "for SQL Server). Files and hashes are recorded in manifest.json "
            "(os_packages) and covered by the bundle-wide SHA256SUMS. "
            "scripts/install_offline.sh installs them with dpkg only — no apt, no "
            "vendor repository, no network — in the recorded dependency order. "
            "EULA acceptance for the Microsoft driver is an administrator "
            "responsibility on the staging side.\n"
        )
    else:
        (out / "os-packages" / "README.md").write_text(
            "# OS packages\n\nPlace administrator-acquired OS packages here "
            "(e.g. Microsoft ODBC driver .deb files, after EULA acceptance). "
            "The application never adds vendor repositories on targets.\n"
        )
    # universal-db-mcp's own license (Apache-2.0) and the NOTICE it requires
    for name in ("LICENSE", "NOTICE"):
        shutil.copy2(PROJECT / name, out / "licenses" / name)
    (out / "licenses" / "README.md").write_text(
        "# Licenses\n\nLICENSE and NOTICE are universal-db-mcp's own (Apache-2.0). "
        "The third-party wheels are listed in sbom/cyclonedx.json and each carries "
        "its own license files. Vendor driver "
        "licenses (IBM, Microsoft, Oracle) are NOT included; administrators "
        "must hold the required entitlements.\n"
    )

    # 6. manifest ----------------------------------------------------------------
    admin_supplied: dict[str, str] = {}
    if "db2" in connectors:
        admin_supplied["db2_connect_license"] = "Db2 Connect client licensing if connecting to z/OS or i"
    if "mssql" in connectors and not mssql_driver_vendored:
        admin_supplied["mssql_odbc_driver"] = (
            f"Microsoft ODBC Driver 18 for SQL Server ({profile.odbc_driver_package}) + EULA acceptance"
        )
    build_backend = parse_lock(BUILD_LOCK.read_text(encoding="utf-8"))
    manifest = {
        "release": "0.1.0",
        "profile": args.profile,
        "source_rev": source_rev,
        # anti-rollback order, covered by the signed SHA256SUMS: the verifier
        # refuses a bundle whose release_seq is below the installed one's
        "release_seq": release_seq,
        "created": datetime.datetime.now(datetime.UTC).isoformat(),
        "build_tools": {
            "python": platform.python_version(),
            "pip": sh([sys.executable, "-m", "pip", "--version"]).stdout.split()[1],
            # the pinned inputs: the build backend, and the locks with the uv that resolved them
            "build": build_backend["build"].version,
            "hatchling": build_backend["hatchling"].version,
            "uv": lock_resolver(lock_text),
            "runtime_lock": _shown(lock),
            "runtime_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "build_lock_sha256": hashlib.sha256(BUILD_LOCK.read_bytes()).hexdigest(),
        },
        "target": dict(profile.manifest_target),
        "selected_connectors": connectors,
        "connector_wheel_status": {
            "included": sorted(names), "missing_from_closure": missing,
        },
        "os_packages": {
            "install_order": [str(e["file"]) for e in os_packages],
            "packages": os_packages,
        } if os_packages else {},
        "administrator_supplied": admin_supplied,
        "omitted_optional_components": ["trino", "duckdb", "mongodb", "thick-mode-oracle-client"],
        "image_identity": None,
        "verification": "python3 /usr/local/lib/udbmcp-trust/verify_bundle.py --bundle <this-dir> --pubkey <trusted-key> (verifier from the trusted channel, never from this bundle)",
        "wheels": [
            {"name": wheel_meta(w)[0], "version": wheel_meta(w)[1], "file": w.name,
             "sha256": hashlib.sha256(w.read_bytes()).hexdigest(), "size": w.stat().st_size}
            for w in wheelhouse
        ],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # 7. checksums + signature ----------------------------------------------------
    sums = []
    for f in sorted(out.rglob("*")):
        if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE"):
            rel = f.relative_to(out)
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {rel}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")

    if args.signing_key:
        sign_sha256sums(out, args.signing_key)

    print(f"\nbundle ready: {out}")
    print(f"source_rev: {source_rev}")
    print(f"release_seq: {release_seq if release_seq is not None else 'none (older than any sequenced release)'}")
    print(f"wheels: {len(wheelhouse)}  missing connector artifacts: {missing or 'none'}")
    if os_packages:
        print(f"os packages: {len(os_packages)} vendored into os-packages/ (hash-pinned in manifest)")
    if missing:
        print("NOTE: missing artifacts are recorded in manifest.json; the affected")
        print("connectors cannot pass readiness checks until they are supplied.")


if __name__ == "__main__":
    main()
