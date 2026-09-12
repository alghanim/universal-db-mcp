"""Provenance regression tests: manifest.source_rev must never be the bundle
builder's "unknown" sentinel (or an unparseable value) inside any package.

Gap (completeness critic round 2, round-1 carry-over): every bundle built by
scripts/prepare_offline_bundle.py without an explicit --source-rev /
UDBMCP_SOURCE_REV records manifest.source_rev = "unknown". The signature then
attests the payload bytes but ties them to NO source revision, and the
downstream .deb version (universal-db-mcp_0.1.0~<rev>_amd64.deb) leaks the
sentinel into dpkg's package database.

ROOT FIX ROUTING: the sentinel default and the missing fail-loud rule live in
scripts/prepare_offline_bundle.py (auto-capture the rev; refuse "unknown"
when --signing-key is set). That file is owned by the concurrent builder
workflow, so the fix is ROUTED there, not done unilaterally. What is locked
in HERE is the downstream fail-closed guard in scripts/package/build_deb.sh:
a manifest whose source_rev is the sentinel (or empty/charset-invalid) can
never again produce a package.

Trust invariants under test (never broken):
  - fail closed: any provenance failure aborts the build (nonzero) before
    the docker/baseline step and without producing an artifact;
  - the guard runs AFTER reading the SIGNED manifest (never from the staging
    host) and BEFORE anything is staged or built.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_BUILD_DEB = _PROJECT / "scripts" / "package" / "build_deb.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def _noncomment(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _make_bundle(tmp_path: Path, source_rev: str | None) -> Path:
    """Minimal bundle whose manifest passes the target sanity checks and
    reaches the provenance guard (no SIGNATURE needed: the guard runs before
    the unsigned-bundle check, hence before docker and any staging)."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "release": "0.1.0",
        "target": {"os": "ubuntu-24.04", "arch": "x86_64", "python": "3.12", "abi": "cp312"},
    }
    if source_rev is not None:
        manifest["source_rev"] = source_rev
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle


def _run_build_deb(bundle: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    pubkey = tmp_path / "release.pub.pem"
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    return subprocess.run(  # noqa: S603 - fixed args, local script
        ["/bin/bash", str(_BUILD_DEB), str(bundle), "--pubkey", str(pubkey)],
        capture_output=True, text=True, timeout=120,
    )


# ------------------------------------------------------------------ static


def test_build_deb_passes_bash_syntax_check() -> None:
    _bash_n(_BUILD_DEB)


def test_build_deb_guard_reads_source_rev_from_signed_manifest_before_version_derivation() -> None:
    """The guard must sit between reading the manifest fields and deriving the
    deb version, and must route the root fix to the bundle builder."""
    code = _noncomment(_read(_BUILD_DEB))
    read_at = code.index('SOURCE_REV="$(sed -n \'2p\' "$FIELDS_TMP")"')
    guard_at = code.index("manifest source_rev is the builder sentinel 'unknown'")
    version_at = code.index('DEB_VERSION="${RELEASE}~${SOURCE_REV}"')
    assert read_at < guard_at < version_at, (
        "the provenance guard must run after SOURCE_REV is read from the "
        "manifest and before the deb version is derived"
    )
    # Root fix is owned elsewhere: the guard must SAY so, and must not try to
    # silently invent a revision on the staging host.
    assert "prepare_offline_bundle.py" in code
    assert "Rebuild the bundle with a real --source-rev" in code


# --------------------------------------------------------------- functional


@_POSIX
def test_build_deb_refuses_sentinel_unknown_source_rev(tmp_path: Path) -> None:
    """The 'unknown' sentinel must abort the build fail-closed with a
    diagnostic that names the remedy, before any artifact exists."""
    bundle = _make_bundle(tmp_path, source_rev="unknown")
    proc = _run_build_deb(bundle, tmp_path)
    assert proc.returncode == 1, f"expected fail closed, got rc=0: {proc.stdout}"
    assert "source_rev is the builder sentinel 'unknown'" in proc.stderr
    assert "Rebuild the bundle with a real --source-rev" in proc.stderr
    assert "fail closed" in proc.stderr
    # No version line may have been derived from the sentinel manifest.
    assert "0.1.0~unknown" not in proc.stdout


@_POSIX
def test_build_deb_refuses_charset_invalid_source_rev(tmp_path: Path) -> None:
    """A revision that could never be a valid dpkg version component must be
    refused loudly instead of flowing into DEBIAN/control."""
    bundle = _make_bundle(tmp_path, source_rev="bad rev!")
    proc = _run_build_deb(bundle, tmp_path)
    assert proc.returncode == 1
    assert "characters invalid in a dpkg version" in proc.stderr


@_POSIX
def test_build_deb_refuses_missing_source_rev_field(tmp_path: Path) -> None:
    bundle = _make_bundle(tmp_path, source_rev=None)
    proc = _run_build_deb(bundle, tmp_path)
    assert proc.returncode == 1
    assert "could not read release/target" in proc.stderr


@_POSIX
def test_build_deb_accepts_real_source_rev_and_proceeds(tmp_path: Path) -> None:
    """Positive case: a genuine revision (git sha or the documented
    UTC-timestamp fallback) passes the guard; the build then continues to the
    NEXT fail-closed check (unsigned bundle), proving the guard neither
    misfires nor rewrites the revision."""
    for real_rev in ("30f9479927a5cbcd24ca238878ba1e184dcfff6e", "20260912T135300Z"):
        bundle = _make_bundle(tmp_path / real_rev[:8], source_rev=real_rev)
        proc = _run_build_deb(bundle, tmp_path / real_rev[:8])
        assert proc.returncode == 1, f"{real_rev}: guard must not reject a real revision"
        assert "source_rev" not in proc.stderr, (
            f"{real_rev}: the provenance guard must not fire on a real revision ({proc.stderr})"
        )
        assert "UNSIGNED" in proc.stderr, (
            f"{real_rev}: build should have proceeded to the signature check"
        )
