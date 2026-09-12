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

Residual (round-2 critic finding, documented and accepted — see the script's
trust-model header): rollback restores an ALREADY-INSTALLED tree, so no check
on that path can re-anchor the payload to the signed bundle. The co-located
manifest shares a writable root with the tree it authenticates, so an actor
able to tamper venv.previous can regenerate it. Mitigation pinned here: a
verified rollback anchors the manifest OUTSIDE the swap tree
(<etc>/venv-rollback.sha256, overridable via UDBMCP_ROLLBACK_MANIFEST); that
external anchor is authoritative — a tampered tree with a regenerated
co-located manifest fails closed against it — and every later round of the
same regeneration trick is defeated.
"""

from __future__ import annotations

import hashlib
import os
import shutil
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
    # rollback_offline.sh honors UDBMCP_ROLLBACK_MANIFEST to relocate the
    # external anchor; an ambient value would redirect the anchor away from
    # tmp_path/etc and break the anchor tests (and write outside the sandbox).
    env.pop("UDBMCP_ROLLBACK_MANIFEST", None)
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
    # Anchor to the recording command itself, NOT to the first mention of
    # "venv.previous.sha256": that first mention is the stale-manifest
    # `rm -f` of the discarded release, which must also precede the rename —
    # but proving the *recording* precedes it requires indexing the recipe.
    record_idx = text.index(
        'find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$1/venv.previous.sha256"'
    )
    assert record_idx < demote_idx, "manifest must be recorded before the demotion rename"
    # The stale manifest of the discarded release is discarded with it, and
    # that removal also precedes the recording (it is the first mention).
    stale_idx = text.index('rm -f "$TARGET/venv.previous.sha256"')
    assert stale_idx < record_idx, "stale manifest must be removed before the new one is recorded"
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


# ------------------------------------------------ external anchor (gap 23)


def test_rollback_anchors_verified_manifest_outside_swap_tree(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """After a verified rollback the manifest must be anchored OUTSIDE the
    swap tree (default: the root-owned config dir), where a writer of
    venv.previous cannot regenerate it."""
    target = tmp_path / "t"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    anchor = tmp_path / "etc" / "venv-rollback.sha256"
    assert anchor.exists(), "a verified rollback must anchor the manifest outside the swap tree"
    assert anchor.read_text(encoding="utf-8") == (target / "venv.previous.sha256").read_text(
        encoding="utf-8"
    ), "the anchor must record exactly the manifest that passed verification"


def test_rollback_external_anchor_defeats_regenerated_colocated_manifest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The critic's residual scenario: venv.previous AND its co-located
    manifest are both rewritten with the same recipe (find|sort|sha256sum).
    Against the external anchor recorded by the previous verified rollback
    this must fail closed: nonzero exit, payload never executed, tree left
    exactly as found."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    # Round 1: verified rollback anchors the manifest outside the swap tree.
    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not canary.exists()

    # Round 2: the restored tree is demoted again (content unchanged by a
    # rename), then tampered, and the CO-LOCATED manifest regenerated with
    # the same recipe — everything inside the swap tree now "verifies".
    (target / "venv").rename(target / "venv.previous")
    _make_previous_venv(target, f"#!/bin/sh\ntouch {canary}\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "a regenerated co-located manifest must not defeat the external anchor"
    assert not canary.exists(), "the tampered payload must never be executed"
    assert "does not match" in out and "anchor" in out.lower()
    # nothing was moved and the anchor was not weakened
    assert (target / "venv.previous" / "bin" / "python").exists()
    assert not (target / "venv").exists()
    assert (tmp_path / "etc" / "venv-rollback.sha256").exists()


def test_rollback_external_anchor_is_authoritative_without_colocated_manifest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """When the external anchor is present it is the sole authority: the
    rollback proceeds even if the co-located manifest was removed entirely
    (and conversely a mismatching anchor fails closed regardless of what the
    co-located manifest says)."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, f'#!/bin/sh\ncase "$*" in *doctor*) touch {canary};; esac\nexit 0\n')
    (tmp_path / "etc").mkdir(parents=True)
    (tmp_path / "etc" / "venv-rollback.sha256").write_text(
        _manifest(target / "venv.previous"), encoding="utf-8"
    )
    assert not (target / "venv.previous.sha256").exists()

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert canary.exists(), "the anchor-verified payload must be executed (doctor call)"
    assert not (target / "venv.previous").exists()


def test_rollback_without_anchor_proceeds_on_regenerated_manifest_but_says_so_and_anchors(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """This test PINS the documented residual, honestly: with NO external
    anchor, a tree tampered together with a regenerated co-located manifest
    passes the gate and IS executed — rollback of an already-installed tree
    cannot re-verify a signature without the original bundle, and the
    co-located manifest shares the tree's writable root. The rollback must
    not stay silent about it: it must state the residual on stderr and anchor
    the manifest outside the swap tree, so the SAME trick fails on every
    later round (pinned by
    test_rollback_external_anchor_defeats_regenerated_colocated_manifest)."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")
    # Tamper AFTER recording, and regenerate the co-located manifest with the
    # same recipe — the critic's exact bypass.
    _make_previous_venv(target, f"#!/bin/sh\ntouch {canary}\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert canary.exists(), (
        "pins the documented residual: without an external anchor the "
        "regenerated co-located manifest is not detectable"
    )
    assert "co-located" in out and "anchor" in out.lower(), (
        "the residual must be stated on the rollback output, never silent"
    )
    assert (tmp_path / "etc" / "venv-rollback.sha256").exists(), (
        "the residual round must still anchor the manifest for the next round"
    )


# ---------------------------------------------- symlink containment (gate bypass fix)


def test_rollback_refuses_out_of_tree_symlink_entrypoint(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Regression (symlink gate bypass): the manifest recipes hash regular
    files only, so bin/python — a symlink in real venvs — is covered by no
    integrity reference. Retargeting it to an out-of-tree payload while
    regenerating the co-located manifest used to pass BOTH integrity
    references and execute the attacker's payload. Every symlink under the
    tree must now resolve back INSIDE it; anything else fails closed before
    any rename, leaving the tree exactly as found."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    evil = tmp_path / "evil"
    evil.mkdir()
    evil_py = evil / "py"
    evil_py.write_text(f"#!/bin/sh\ntouch {canary}\nexit 0\n", encoding="utf-8")
    evil_py.chmod(0o755)

    prev = target / "venv.previous"
    (prev / "bin").mkdir(parents=True)
    (prev / "lib").mkdir()
    (prev / "lib" / "keep.txt").write_text("harmless\n", encoding="utf-8")
    (prev / "bin" / "python").symlink_to(evil_py)
    (target / "venv.previous.sha256").write_text(_manifest(prev), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "an out-of-tree symlink entrypoint must fail the gate closed"
    assert not canary.exists(), "the out-of-tree payload must never be executed"
    assert "symlink" in out.lower() or "links" in out.lower(), "the failure must name the containment check"
    # nothing was moved: tree, manifest, and no swap
    assert (prev / "bin" / "python").is_symlink()
    assert (target / "venv.previous.sha256").exists()
    assert not (target / "venv").exists()
    assert not (target / "venv.failed").exists()


def test_rollback_accepts_in_tree_symlink_entrypoint(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Real venvs ship bin/python -> python3.x INSIDE the tree; the containment
    gate must not break that happy path. A symlink whose final target is a
    regular file covered by the manifest is safe and must be executed."""
    target = tmp_path / "t"
    marker = tmp_path / "doctor-ran"
    prev = target / "venv.previous"
    (prev / "bin").mkdir(parents=True)
    real_py = prev / "bin" / "python3.12"
    real_py.write_text(
        f'#!/bin/sh\ncase "$*" in *doctor*) touch {marker};; esac\nexit 0\n', encoding="utf-8"
    )
    real_py.chmod(0o755)
    (prev / "bin" / "python").symlink_to("python3.12")
    (target / "venv.previous.sha256").write_text(_manifest(prev), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert marker.exists(), "the verified in-tree entrypoint must actually run (doctor call)"


# ------------------------------------------ stale external anchor (availability fix)


def test_rollback_re_anchor_recovers_legitimate_tree_after_stale_anchor(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Regression (stale anchor deadlock): the external anchor is written only
    by a verified rollback and is never refreshed when a later upgrade demotes
    a DIFFERENT venv.previous, so every future rollback of a legitimate tree
    failed closed against the stale anchor — with recovery advice that did
    nothing. The scripted recovery is the explicit operator opt-in --re-anchor:
    it re-verifies against the co-located manifest (the documented residual,
    announced on stderr), executes only on a match, and re-anchors the
    verified manifest outside the swap tree. Without the flag the behavior is
    unchanged: the anchor stays authoritative and the gate fails closed."""
    target = tmp_path / "t"
    marker = tmp_path / "doctor-ran"
    anchor = tmp_path / "etc" / "venv-rollback.sha256"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    # Round 1: verified rollback anchors manifest(v1).
    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert anchor.exists()
    manifest_v1 = anchor.read_text(encoding="utf-8")

    # A later upgrade demotes a different, legitimate release (the depth-1
    # window discarded v1 and its co-located manifest) and records a correct
    # manifest for it.
    shutil.rmtree(target / "venv")
    (target / "venv.previous.sha256").unlink()
    _make_previous_venv(target, f'#!/bin/sh\ncase "$*" in *doctor*) touch {marker};; esac\nexit 0\n')
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")
    manifest_v3 = (target / "venv.previous.sha256").read_text(encoding="utf-8")
    assert manifest_v3 != manifest_v1

    # Without the flag: still fails closed against the stale anchor.
    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, "the stale anchor must stay authoritative without --re-anchor"
    assert not marker.exists()
    assert "does not match" in out
    assert "--re-anchor" in out, "the failure must describe a recovery that actually works"

    # With --re-anchor: verifies against the co-located manifest, executes,
    # and re-anchors the verified manifest.
    proc = _run_rollback(tmp_path, target, "--re-anchor")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert marker.exists(), "the legitimate tree must be executed once it verifies"
    assert anchor.read_text(encoding="utf-8") == manifest_v3, (
        "--re-anchor must re-anchor the manifest that passed verification"
    )


def test_rollback_re_anchor_still_fails_closed_on_mismatched_tree(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """--re-anchor is an operator opt-in to the documented residual, NOT a
    skip button: a tree that does not match the co-located manifest must
    still fail closed with the payload never executed, and --re-anchor with
    no co-located manifest at all must refuse rather than execute."""
    target = tmp_path / "t"
    canary = tmp_path / "canary"
    _make_previous_venv(target, "#!/bin/sh\nexit 0\n")
    (target / "venv.previous.sha256").write_text(_manifest(target / "venv.previous"), encoding="utf-8")

    proc = _run_rollback(tmp_path, target)
    assert proc.returncode == 0, proc.stdout + proc.stderr  # round 1 anchors

    # Tamper after the anchor was recorded, colocated manifest NOT regenerated:
    # neither reference matches, so --re-anchor must fail closed too.
    (target / "venv").rename(target / "venv.previous")
    _make_previous_venv(target, f"#!/bin/sh\ntouch {canary}\nexit 0\n")
    proc = _run_rollback(tmp_path, target, "--re-anchor")
    assert proc.returncode != 0, "--re-anchor must never skip verification"
    assert not canary.exists(), "the tampered payload must never be executed"
    assert (target / "venv.previous" / "bin" / "python").exists()

    # And with no co-located manifest at all, --re-anchor has nothing to
    # re-verify against and must refuse.
    (target / "venv.previous.sha256").unlink()
    proc = _run_rollback(tmp_path, target, "--re-anchor")
    assert proc.returncode != 0, "--re-anchor without a co-located manifest must refuse"
    assert not canary.exists()


# ------------------------------- restore-config must not regress the external anchor


def _make_config_backup(tmp_path: Path, anchor_content: str, config_body: str) -> Path:
    """A pre-upgrade backup exactly as upgrade_offline.sh records it: a
    wholesale ``cp -a`` of the configuration directory, so it contains
    whatever venv-rollback.sha256 existed at backup time — including a stale
    one."""
    backup = tmp_path / "backups" / "pre-upgrade-20260101T000000Z"
    etc = backup / "universal-db-mcp"
    etc.mkdir(parents=True)
    (etc / "config.yaml").write_text(config_body, encoding="utf-8")
    (etc / "venv-rollback.sha256").write_text(anchor_content, encoding="utf-8")
    return backup


def test_rollback_restore_config_preserves_verified_anchor(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Regression (availability): --restore-config replaces the ENTIRE
    configuration directory with the copy upgrade_offline.sh took at upgrade
    time, which contains whatever venv-rollback.sha256 existed THEN. It used
    to silently regress the external anchor — the manifest that just passed
    verification — to the backup's stale copy, deadlocking the NEXT rollback
    against an anchor only --re-anchor could escape. The anchor is trust
    state, not configuration: after a verified rollback + --restore-config it
    must still record exactly the verified manifest, and the next rollback
    must succeed WITHOUT --re-anchor."""
    target = tmp_path / "t"
    marker = tmp_path / "doctor-ran"
    anchor = tmp_path / "etc" / "venv-rollback.sha256"
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    (etc / "config.yaml").write_text("live: pre-rollback\n", encoding="utf-8")
    _make_previous_venv(target, f'#!/bin/sh\ncase "$*" in *doctor*) touch {marker};; esac\nexit 0\n')
    colocated = target / "venv.previous.sha256"
    colocated.write_text(_manifest(target / "venv.previous"), encoding="utf-8")
    verified_manifest = colocated.read_text(encoding="utf-8")
    # The backup carries an anchor from an OLDER release: exactly what
    # upgrade_offline.sh's cp -a froze at upgrade time.
    backup = _make_config_backup(tmp_path, "stale-anchor-from-backup\n", "backup: config\n")
    assert backup.exists()

    # Verified rollback + config restore in one run.
    proc = _run_rollback(tmp_path, target, "--restore-config")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert marker.exists(), "the verified venv must be executed before the config restore"
    # The configuration really was restored (the fix must not degrade the
    # restore itself), and the displaced live config is preserved.
    assert (etc / "config.yaml").read_text(encoding="utf-8") == "backup: config\n"
    preserved = sorted((tmp_path / "backups").glob("pre-rollback-*/universal-db-mcp/config.yaml"))
    assert preserved and preserved[-1].read_text(encoding="utf-8") == "live: pre-rollback\n"
    # THE FIX: the anchor is not regressed to the backup's stale copy.
    assert anchor.exists(), "the external anchor must survive the configuration restore"
    assert anchor.read_text(encoding="utf-8") != "stale-anchor-from-backup\n", (
        "--restore-config must never reinstate the backup's stale anchor"
    )
    assert anchor.read_text(encoding="utf-8") == verified_manifest, (
        "the anchor must keep recording exactly the manifest that passed verification"
    )

    # Round 2: the restored tree is demoted again (rename only, content
    # unchanged) — the next rollback must NOT deadlock against a stale anchor,
    # i.e. it must succeed without --re-anchor.
    (target / "venv").rename(target / "venv.previous")
    proc = _run_rollback(tmp_path, target)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "--re-anchor" not in out, "no re-anchor opt-in may be needed after a config restore"


def test_rollback_restore_config_without_rollback_keeps_live_anchor(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """--restore-config with no venv.previous to roll back (the config-only
    failure path) must also leave the live anchor untouched: the backup's
    stale copy is excluded, the live one preserved."""
    target = tmp_path / "t"
    anchor = tmp_path / "etc" / "venv-rollback.sha256"
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    (etc / "config.yaml").write_text("live: current\n", encoding="utf-8")
    anchor.write_text("live-anchor-content\n", encoding="utf-8")
    _make_config_backup(tmp_path, "stale-anchor-from-backup\n", "backup: config\n")
    assert not (target / "venv.previous").exists()

    proc = _run_rollback(tmp_path, target, "--restore-config")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert (etc / "config.yaml").read_text(encoding="utf-8") == "backup: config\n", (
        "the configuration restore itself must still happen"
    )
    assert anchor.read_text(encoding="utf-8") == "live-anchor-content\n", (
        "the live external anchor must not be replaced by the backup's stale copy"
    )
    assert "stale-anchor-from-backup" not in out
