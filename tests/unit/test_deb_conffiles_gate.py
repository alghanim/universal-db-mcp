"""Regression tests for the conffiles gate in scripts/package/build_deb.sh.

Gap locked out here (completeness-critic round 1): build_deb.sh degraded a
missing packaging/deb/conffiles template to a build-time NOTE ("nothing is
registered as a dpkg conffile") — a soft fallback for a plan-listed Phase 4
input, leaving the deliberate no-conffile deviation of
/etc/universal-db-mcp/config.yaml unenforced: nothing verified that postinst
still seeds the config only-if-absent or that postrm still deletes it on purge.

Design under test (documented in build_deb.sh, packaging/deb/postrm and
docs/offline-deployment.md — the config is NOT a dpkg conffile on purpose, so
it can be seeded udbmcp:udbmcp 0640 only-if-absent):

  1. conffiles PRESENT  -> every entry must point at a file in the staged
     payload; anything else (e.g. re-registering the /etc config path) aborts
     the build (dpkg would treat it as a conffile deleted by the packager).
  2. conffiles ABSENT (the required state) -> the compensating controls are
     verified at build time: postinst's only-if-absent seeding and postrm's
     purge/removal + remove/retention behavior must both be present.

Trust invariants (never broken): the gate only strengthens fail-closed
behavior; it never stages key material, never executes payload, and aborts
(non-zero) without producing an artifact on any failure.
"""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell/mode semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_BUILD_DEB = _PROJECT / "scripts" / "package" / "build_deb.sh"
_DEB_DIR = _PROJECT / "packaging" / "deb"


def _build_deb_text() -> str:
    return _BUILD_DEB.read_text(encoding="utf-8")


def _gate_block() -> str:
    """Extract the executable conffiles-gate block from build_deb.sh.

    Runs from the CONFFILES_SRC= assignment up to the next staging section
    ("# --- control:"), so the test exercises the real gate code verbatim.
    """
    text = _build_deb_text()
    start = text.index("CONFFILES_SRC=")
    end = text.index("# --- control:")
    return text[start:end]


def _run_gate(tmp_path: Path, *, postinst: str, postrm: str, conffiles: str | None) -> subprocess.CompletedProcess[str]:
    """Run the extracted gate block in a sandbox with MAINT_DIR/DEBROOT
    rewritten to tmp paths. Everything else is verbatim build_deb.sh code."""
    maint = tmp_path / "maint"
    maint.mkdir()
    debroot = tmp_path / "debroot"
    (debroot / "DEBIAN").mkdir(parents=True)
    (debroot / "DEBIAN" / "postinst").write_text(postinst, encoding="utf-8")
    (debroot / "DEBIAN" / "postrm").write_text(postrm, encoding="utf-8")
    if conffiles is not None:
        (maint / "conffiles").write_text(conffiles, encoding="utf-8")

    script = tmp_path / "gate.sh"
    script.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'die() { echo "FAIL: $*" >&2; exit 1; }\n'
        f"MAINT_DIR={maint}\n"
        f"DEBROOT={debroot}\n"
        + _gate_block()
        + 'echo GATE-OK\n',
        encoding="utf-8",
    )
    return subprocess.run(  # noqa: S603 - fixed args, local sandbox script
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=60
    )


# Real compensating controls, used verbatim by the pass cases.
_REAL_POSTINST = (_DEB_DIR / "postinst").read_text(encoding="utf-8")
_REAL_POSTRM = (_DEB_DIR / "postrm").read_text(encoding="utf-8")


# ------------------------------------------------------------------- static


def test_build_deb_passes_bash_syntax_check() -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(_BUILD_DEB)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def test_no_soft_note_fallback_for_missing_conffiles() -> None:
    """The defect under test: absence of the conffiles template must be a
    verified, documented state — never a build-time NOTE warning."""
    assert "NOTE: $MAINT_DIR/conffiles not present" not in _build_deb_text()
    assert "nothing is registered as a dpkg conffile" not in _build_deb_text()


def test_gate_fails_loud_on_payload_foreign_conffile_entries() -> None:
    code = "\n".join(line for line in _gate_block().splitlines() if not line.lstrip().startswith("#"))
    assert "[ -e \"$DEBROOT$_conffile_path\" ]" in code
    assert "is NOT in the staged deb payload" in code
    assert "deleted by the packager" in code


def test_gate_verifies_both_compensating_controls() -> None:
    code = "\n".join(line for line in _gate_block().splitlines() if not line.lstrip().startswith("#"))
    assert 'grep -qF \'if [ ! -e "$CONFIG" ]; then\' "$DEBROOT/DEBIAN/postinst"' in code
    assert 'grep -qF \'rm -f "$CONFIG_FILE"\' "$DEBROOT/DEBIAN/postrm"' in code
    # Retention on remove must be checked too, not just purge deletion.
    assert 'grep -qF \'are retained\' "$DEBROOT/DEBIAN/postrm"' in code


def test_conffiles_template_is_deliberately_absent() -> None:
    """The required repo state: no packaging/deb/conffiles template exists (the
    deviation from the plan's Phase 4 file list, enforced — not fallen into)."""
    assert not (_DEB_DIR / "conffiles").exists()


# --------------------------------------------------------------- functional


@_POSIX
def test_gate_passes_with_real_maintainer_scripts_and_no_conffiles(tmp_path: Path) -> None:
    """The shipped state: real postinst/postrm compensate for the absent
    conffiles template, so the gate must accept the build."""
    proc = _run_gate(tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM, conffiles=None)
    assert proc.returncode == 0, proc.stderr
    assert "GATE-OK" in proc.stdout
    assert not (tmp_path / "debroot" / "DEBIAN" / "conffiles").exists()


@_POSIX
def test_gate_stages_payload_backed_conffiles_with_comments_stripped(tmp_path: Path) -> None:
    """If a conffiles template is ever reintroduced, entries backed by staged
    payload files are accepted, comments are stripped, mode is 0644."""
    staged = "/usr/share/universal-db-mcp/systemd/universal-db-mcp.service"
    (tmp_path / "debroot" / staged.lstrip("/")).parent.mkdir(parents=True)
    (tmp_path / "debroot" / staged.lstrip("/")).write_text("# unit\n", encoding="utf-8")
    conffiles = f"# a comment line\n\n{staged}\n  # indented comment\n"
    proc = _run_gate(tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM, conffiles=conffiles)
    assert proc.returncode == 0, proc.stderr
    staged_conffiles = tmp_path / "debroot" / "DEBIAN" / "conffiles"
    assert staged_conffiles.read_text(encoding="utf-8") == staged + "\n"
    assert stat.S_IMODE(staged_conffiles.stat().st_mode) == 0o644


@_POSIX
def test_gate_fails_closed_on_conffile_entry_missing_from_payload(tmp_path: Path) -> None:
    """Re-registering the postinst-seeded /etc config path (or any path not in
    the payload) must abort the build, not ship a conffile dpkg would treat as
    packager-deleted."""
    proc = _run_gate(
        tmp_path,
        postinst=_REAL_POSTINST,
        postrm=_REAL_POSTRM,
        conffiles="/etc/universal-db-mcp/config.yaml\n",
    )
    assert proc.returncode == 1
    assert "NOT in the staged deb payload" in proc.stderr
    assert "ABORTED" not in proc.stderr or "FAIL:" in proc.stderr  # died via die()


@_POSIX
def test_gate_fails_closed_on_comments_only_conffiles_template(tmp_path: Path) -> None:
    proc = _run_gate(
        tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM, conffiles="# nothing but comments\n\n"
    )
    assert proc.returncode == 1
    assert "no path entries after comment stripping" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postinst_loses_only_if_absent_seeding(tmp_path: Path) -> None:
    stripped = "\n".join(
        line for line in _REAL_POSTINST.splitlines() if 'if [ ! -e "$CONFIG" ]; then' not in line
    )
    proc = _run_gate(tmp_path, postinst=stripped, postrm=_REAL_POSTRM, conffiles=None)
    assert proc.returncode == 1
    assert "only-if-absent config seeding" in proc.stderr
    assert "ONLY mechanism installing the default config" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postinst_loses_bundle_template_source(tmp_path: Path) -> None:
    stripped = "\n".join(
        line for line in _REAL_POSTINST.splitlines() if "config-templates/config.yaml" not in line
    )
    proc = _run_gate(tmp_path, postinst=stripped, postrm=_REAL_POSTRM, conffiles=None)
    assert proc.returncode == 1
    assert "config-templates/" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postrm_loses_purge_deletion(tmp_path: Path) -> None:
    stripped = "\n".join(line for line in _REAL_POSTRM.splitlines() if 'rm -f "$CONFIG_FILE"' not in line)
    proc = _run_gate(tmp_path, postinst=_REAL_POSTINST, postrm=stripped, conffiles=None)
    assert proc.returncode == 1
    assert "no longer deletes the seeded config on purge" in proc.stderr
    assert "purge would leave it behind forever" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postrm_loses_remove_retention(tmp_path: Path) -> None:
    stripped = "\n".join(line for line in _REAL_POSTRM.splitlines() if "are retained" not in line)
    proc = _run_gate(tmp_path, postinst=_REAL_POSTINST, postrm=stripped, conffiles=None)
    assert proc.returncode == 1
    assert "conffile retention on remove" in proc.stderr


@_POSIX
def test_failed_gate_never_produces_an_artifact(tmp_path: Path) -> None:
    """Fail closed: a gate failure aborts the build, and the real script's
    EXIT trap discards the entire staged debroot — so no half-verified
    DEBIAN/conffiles can ever reach dpkg-deb."""
    proc = _run_gate(
        tmp_path,
        postinst=_REAL_POSTINST,
        postrm=_REAL_POSTRM,
        conffiles="/etc/universal-db-mcp/config.yaml\n",
    )
    assert proc.returncode == 1
    assert "NOT in the staged deb payload" in proc.stderr
    # The gate runs BEFORE the container build step: the abort happens while
    # the payload is still just a throwaway mktemp root.
    text = _build_deb_text()
    assert text.index("CONFFILES_SRC=") < text.index('dpkg-deb --root-owner-group --build /debroot "/dist/$DEB_FILE"')
    # And the whole staged root is discarded on any abort (fail closed).
    assert "trap cleanup EXIT INT TERM" in text
