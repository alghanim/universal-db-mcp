#!/usr/bin/env python3
"""Set the release version everywhere it is written down.

    python scripts/bump_version.py --check     # every reference names pyproject.toml's version
    python scripts/bump_version.py 0.2.0       # rewrite them all, then --check

pyproject.toml's [project].version is the source of truth. The bundle builder
reads it at build time (the signed manifest's "release", which the .deb, .pkg
and MSI builders take their versions from); the files below cannot read it, so
they carry a copy that this script keeps in step. A FILES entry must match
exactly once; a DOCS pattern names a release artifact (an image tag, a bundle,
.pkg, .msi or .deb file name) and may match any number of times. History that
names an old release in other words ("signed from v0.1.0 on") is left alone.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_V = r"(?P<v>\d+\.\d+\.\d+)"

# (path, pattern with a group "v"): each must match exactly once
FILES: tuple[tuple[str, str], ...] = (
    ("pyproject.toml", rf'(?m)^version = "{_V}"$'),
    ("src/universal_db_mcp/__init__.py", rf'(?m)^__version__ = "{_V}"$'),
    ("uv.lock", rf'(?m)^name = "udbmcp"\nversion = "{_V}"$'),
    ("packaging/compose.offline.yaml", rf"(?m)^    image: udbmcp/universal-db-mcp:{_V}-"),
    ("packaging/deb/control", rf"(?m)^Version: {_V}$"),
    ("packaging/msi/udbmcp.wxs", rf'<\?define ProductVersion = "{_V}" \?>'),
    ("packaging/pkg/postinstall", rf"<key>CFBundleShortVersionString</key>\n\s*<string>{_V}</string>"),
)

# patterns naming a release artifact, any number of matches per document
DOCS: tuple[str, ...] = (
    rf"universal-db-mcp:{_V}",       # ghcr.io/... and udbmcp/... image tags
    rf"universal-db-mcp-{_V}-",      # bundle directories, .pkg and .msi names
    rf"universal-db-mcp_{_V}\+",     # .deb names
    rf"<small>v{_V} ·",              # the landing page footer
)
DOC_FILES: tuple[str, ...] = ("README.md", "docs/*.md", "site/index.html")


def project_version() -> str:
    pyproject = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(pyproject["project"]["version"])


def _doc_paths(root: Path) -> list[Path]:
    return sorted(p for pattern in DOC_FILES for p in root.glob(pattern))


def _server_json_versions(root: Path) -> list[tuple[str, str]]:
    """(where, version) for server.json's version and its OCI image tag."""
    server = json.loads((root / "server.json").read_text(encoding="utf-8"))
    found = [("server.json version", str(server["version"]))]
    for i, package in enumerate(server["packages"]):
        if package["registryType"] == "oci":
            found.append((f"server.json packages[{i}] image tag", package["identifier"].rpartition(":")[2]))
    return found


def check(root: Path = PROJECT) -> list[str]:
    """Every reference that does not name pyproject.toml's version."""
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    problems: list[str] = []
    for rel, pattern in FILES:
        found = [m.group("v") for m in re.finditer(pattern, (root / rel).read_text(encoding="utf-8"))]
        if len(found) != 1:
            problems.append(f"{rel}: expected one version reference, found {len(found)}")
        elif found[0] != version:
            problems.append(f"{rel}: {found[0]} (pyproject.toml has {version})")
    problems += [f"{where}: {v} (pyproject.toml has {version})"
                 for where, v in _server_json_versions(root) if v != version]
    for path in _doc_paths(root):
        text = path.read_text(encoding="utf-8")
        for pattern in DOCS:
            for m in re.finditer(pattern, text):
                if m.group("v") != version:
                    line = text.count("\n", 0, m.start()) + 1
                    problems.append(f"{path.relative_to(root)}:{line}: {m.group(0)!r} (pyproject.toml has {version})")
    return problems


def _replace(pattern: str, text: str, version: str) -> str:
    return re.sub(pattern, lambda m: m.group(0)[: m.start("v") - m.start()] + version
                  + m.group(0)[m.end("v") - m.start():], text)


def bump(version: str, root: Path = PROJECT) -> None:
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"version must be MAJOR.MINOR.PATCH, got {version!r}")
    for rel, pattern in FILES:
        path = root / rel
        path.write_text(_replace(pattern, path.read_text(encoding="utf-8"), version), encoding="utf-8")
    server_path = root / "server.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    server["version"] = version
    for package in server["packages"]:
        if package["registryType"] == "oci":
            package["identifier"] = f"{package['identifier'].rpartition(':')[0]}:{version}"
    server_path.write_text(json.dumps(server, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for path in _doc_paths(root):
        text = path.read_text(encoding="utf-8")
        for pattern in DOCS:
            text = _replace(pattern, text, version)
        path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("version", nargs="?", help="the new MAJOR.MINOR.PATCH version")
    ap.add_argument("--check", action="store_true", help="only report references that disagree")
    args = ap.parse_args(argv)
    if args.version is None and not args.check:
        ap.error("give a version, or --check")
    if args.version is not None:
        bump(args.version)
    problems = check()
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(f"version {project_version()}: every reference agrees")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
