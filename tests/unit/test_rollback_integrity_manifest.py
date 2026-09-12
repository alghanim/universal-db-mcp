"""Rollback integrity gate: rollback_offline.sh must NOT execute venv.previous
unless it matches the SHA256 manifest upgrade_offline.sh records at demotion
time.

Regression for the trusted-tools rollback path: it used to swap in
venv.previous and immediately execute ``bin/python -m universal_db_mcp
doctor`` on directory-ownership trust alone — exactly in the failure
scenarios where on-disk state is least trustworthy. The contract now:

- upgrade_offline.sh records ``$TARGET/venv.previous.sha256`` BEFORE renaming
  the current venv to venv.previous (so an upgrade killed between the two
  operations still leaves a verifiable tree), and discards the stale manifest
  together with the depth-1 release;
- rollback_offline.sh re-hashes the tree with the same recipe and fails
  closed — BEFORE any rename and before the doctor call — on a missing or
  mismatched manifest, leaving venv.previous untouched and executing nothing.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
ROLLBACK = SCRIPTS / "rollback_offline.sh"
UPGRADE = SCRIPTS / "upgrade_offline.sh"


# --------------------------------------------------------------------- helpers


def _bash_n(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed args, repo script under test
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )


def _manifest(tree: Path) -> str:
    """Manifest exactly as the scripts record it: relative paths (the tree is
    renamed after verification), LC_ALL=C byte order, NUL-safe traversal,
    ``sha256sum``-style ``<hash>  <path>`` lines. Pure Python so the test does
    not depend on which hash tool the host provides."""
    rels = sorted(
        "./" + p.relative_to(tree).as_posix()
        for p in tree.rglob("*")
        if p.is_file() and not p.is_symlink()
    )
    lines = [f"{hashlib.sha256((tree / r[2:]).read_bytes()).hexdigest()}  {r}" for r in rels]
    return "".join(line + "\n" for line in lines)


def _make_previous_venv(target: Path, python_body: str) -> Path:
    """Create (or overwrite) <target>/venv.previous/bin/python with the stub."""
    bin_dir = target / "venv.previous" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    py = bin_dir / "python"
    py.write_text(python_body, encoding="utf-8")
    py.chmod(0o755)
    return py


def _run_rollback(tmp_path: Path, target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["UDBMCP_CONFIG_DIR"] = str(tmp_path / "etc")
    env["UDBMCP_STATE_DIR"] = str(tmp_path / "varlib")
    env.pop("UDBMCP_CONFIG", None)
    env.pop("UDBMCP_DOCTOR_RC", None)
    return subprocess.run(  # noqa: S603 - fixed args, repo script under test
        ["/bin/bash", str(ROLLBACK), str(target), str(tmp_path / "backups"), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


# ------------------------------------------------------------------- syntax


def test_rollback_offline_script_passes_bash_syntax_check() -> None:
    proc = _bash_n(ROLLBACK)
    assert proc.returncode == 0, proc.stderr


def test_upgrade_offline_script_passes_bash_syntax_check() -> None:
    proc = _bash_n(UPGRADE)
    assert proc.returncode == 0, proc.stderr


# ------------------------------------------------------- upgrade-side contract


def test_upgrade_offline_records_rollback_manifest_before_demoting_venv() -> None:
    """The manifest must be recorded BEFORE the current venv is renamed to
    venv.previous — an upgrade killed between the two operations has to leave
    a verifiable venv.previous behind — and the stale manifest of the
    discarded depth-1 release must be removed with the release itself."""
    text = UPGRADE.read_text(encoding="utf-8")
    demote_idx = text.index('mv "$TARGET/venv" "$TARGET/venv.previous"')
    record_idx = text.index("venv.previous.sha256")
    assert record_idx < demote_idx, "manifest must be recorded before the demotion rename"
    assert 'rm -f "$TARGET/venv.previous.sha256"' in text, (
        "the stale manifest of the discarded release must be removed with it"
    )
    assert "sort -z" in text and "find . -type f -print0" in text, (
        "manifest recipe must be deterministic and NUL-safe"
    )


# ------------------------------------------------------- rollback-side behavior


def test_rollback_executes_previous_venv_that_matches_its_manifest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Happy path: a venv.previous whose content matches the recorded manifest
    is restored AND executed (the doctor stub runs, proving the payload was
    executed after — and only after — verification passed)."""
    target = tmp_path / "t"
    marker = tmp_path / "doctor-ran"
    _make_previous_venv(target, f'#!/bin/sh\ncase "$*" in *doctor*) touch {marker};; esac\nexit 0\n')
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (target / "venv" / "bin" / "python").exists(), "venv.previous must be restored in place"
    assert not (target / "venv.previous").exists()
    assert marker.exists(), "the verified venv must actually be executed (doctor call)"


def test_rollback_refuses_tampered_previous_venv_and_never_executes_it(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The critic's canary scenario: bin/python inside venv.previous is
    replaced after the manifest was recorded. The rollback must exit nonzero,
    must never execute the payload (canary never created), and must leave the
    on-disk state exactly as found — no swap, no venv.failed displacement."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")
    # Tamper AFTER the manifest was recorded, the way an attacker would.
    _make_previous_venv(target, f"#!/bin/sh\ntouch {canary}\nexit 0\n")
    assert not canary.exists()

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode != 0, "a tampered venv.previous must fail the rollback closed"
    assert not canary.exists(), "the tampered payload must never be executed"
    assert "manifest" in (proc.stdout + proc.stderr).lower()
    # nothing was moved: the demoted tree and the manifest are still in place,
    # and no current venv was displaced to venv.failed
    assert (target / "venv.previous" / "bin" / "python").exists()
    assert (target / "venv.previous.sha256").exists()
    assert not (target / "venv").exists()
    assert not (target / "venv.failed").exists()


def test_rollback_refuses_previous_venv_without_manifest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A venv.previous with no recorded manifest cannot be verified at all —
    under fail-closed discipline that is a verification failure, not a free
    pass. Rollback must refuse to execute it (canary stays cold) and leave
    the tree untouched."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, f"#!/bin/sh\ntouch {canary}\nexit 0\n")
    assert not (target / "venv.previous.sha256").exists()

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode != 0, "an unverifiable venv.previous must fail the rollback closed"
    assert not canary.exists(), "an unverifiable payload must never be executed"
    assert (target / "venv.previous" / "bin" / "python").exists()
    assert not (target / "venv").exists()


def test_rollback_refuses_previous_venv_with_extra_planted_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Tampering is not limited to overwriting bin/python: a planted file (a
    sitecustomize.py, a shadowed module) must trip the manifest check too."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, f'#!/bin/sh\ncase "$*" in *doctor*) touch {canary};; esac\nexit 0\n')
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")
    planted = target / "venv.previous" / "lib" / "sitecustomize.py"
    planted.parent.mkdir(parents=True)
    # Payload content is irrelevant: the rollback must refuse to execute the
    # tree at all, so the canary is never created regardless of this text.
    planted.write_text(f"# would-be payload; must never run\n# canary: {canary}\n", encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode != 0
    assert not canary.exists(), "the planted payload must never be executed"
    assert planted.exists(), "the tree is preserved for analysis, never touched by the rollback"


def test_rollback_integrity_gate_runs_before_any_rename(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Source-level: the verification call must sit before BOTH the current
    venv -> venv.failed displacement and the venv.previous -> venv restore,
    so a failed gate leaves the on-disk state exactly as found."""
    text = ROLLBACK.read_text(encoding="utf-8")
    gate_idx = text.index("udbmcp_verify_previous_venv || exit 1")
    failed_idx = text.index('mv "$TARGET/venv" "$TARGET/venv.failed"')
    restore_idx = text.index('mv "$TARGET/venv.previous" "$TARGET/venv"')
    doctor_idx = text.index('"$TARGET/venv/bin/python" -m universal_db_mcp doctor')
    assert gate_idx < failed_idx < restore_idx < doctor_idx, (
        "verify-then-use: the manifest gate must precede the swap and the doctor call"
    )
