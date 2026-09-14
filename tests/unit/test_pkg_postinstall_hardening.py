"""Regression tests for the pkg:postinstall hardening fixes (artifact pkg:postinstall).

These are pure text-content gates (no root, no installer, no bash execution)
on ``packaging/pkg/postinstall`` and ``packaging/launchd/com.udbmcp.server.plist``
that pin the three defects found by adversarial review:

1. launchd label consistency: the plist ``Label`` that launchd actually
   registers the job under must equal the label postinstall drives
   ``launchctl bootout/bootstrap/print`` with AND the installed plist filename
   stem — otherwise every reinstall/upgrade targets a nonexistent label.
2. Interpreter integrity: postinstall must re-validate EXACTLY the CPython
   candidates preinstall approved (framework / /usr/local/bin), never a PATH
   search that could resolve ``python3.12`` to an unvalidated, non-root-owned
   interpreter executed as root and anchoring the venv's python symlink.
3. launchctl bootstrap must fail closed: no swallowed bootout failure and no
   "already bootstrapped — left running" tolerance that could mask a failed
   upgrade (stale daemon on the OLD plist reported as success).

Ownership note: this file does not modify tests owned by other workflows; it
only READS the producer files. Pure stdlib + pytest, runs on any platform.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from xml.parsers.expat import ExpatError

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

POSTINSTALL = REPO_ROOT / "packaging" / "pkg" / "postinstall"
PREINSTALL = REPO_ROOT / "packaging" / "pkg" / "preinstall"
PLIST = REPO_ROOT / "packaging" / "launchd" / "com.udbmcp.server.plist"

LABEL = "com.udbmcp.server"
FRAMEWORK_PY = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
USR_LOCAL_PY = "/usr/local/bin/python3"

_XML_COMMENT = re.compile(rb"<!--.*?-->", re.DOTALL)


def _postinstall_text() -> str:
    assert POSTINSTALL.is_file(), f"missing producer file: {POSTINSTALL}"
    return POSTINSTALL.read_text(encoding="utf-8")


def _postinstall_code() -> str:
    """Script text with pure comment lines removed (comments document the
    failure modes and must not trip content gates aimed at behavior)."""
    return "\n".join(ln for ln in _postinstall_text().splitlines() if not ln.lstrip().startswith("#"))


def _preinstall_text() -> str:
    assert PREINSTALL.is_file(), f"missing producer file: {PREINSTALL}"
    return PREINSTALL.read_text(encoding="utf-8")


def _plist_label() -> str:
    assert PLIST.is_file(), f"missing producer file: {PLIST}"
    raw = PLIST.read_bytes()
    try:
        data = plistlib.loads(raw)
    except ExpatError:
        # The shipped plist documents a known '--'-in-comment deviation (see
        # tests/unit/test_pkg_packaging.py); launchd/plutil accept it. Parse
        # the comment-stripped document, exactly like launchd effectively does.
        data = plistlib.loads(_XML_COMMENT.sub(b"", raw))
    assert isinstance(data, dict)
    label = data.get("Label")
    assert isinstance(label, str), "plist Label must be a string"
    return label


# --------------------------------------------------------------------------
# 1. launchd label consistency (bootout/bootstrap/print must hit a live label)
# --------------------------------------------------------------------------


def test_postinstall_label_matches_plist_label_and_filename_stem() -> None:
    """launchd keys the job on the plist Label, not the filename. postinstall's
    LABEL (bootout/bootstrap/print) must equal BOTH the plist Label and the
    installed filename stem /Library/LaunchDaemons/<Label>.plist — a mismatch
    makes the upgrade bootout a no-op and breaks every reinstall."""
    text = _postinstall_text()
    m_label = re.search(r'^LABEL="([^"]+)"$', text, re.MULTILINE)
    assert m_label, 'postinstall must define LABEL="..."'
    m_plist = re.search(r'^PLIST="/Library/LaunchDaemons/([^"/]+)\.plist"$', text, re.MULTILINE)
    assert m_plist, 'postinstall must define PLIST="/Library/LaunchDaemons/<stem>.plist"'
    assert m_label.group(1) == _plist_label() == m_plist.group(1), (
        "postinstall LABEL, the plist Label key and the installed plist "
        "filename stem must all be identical "
        f"(LABEL={m_label.group(1)!r}, plist Label={_plist_label()!r}, "
        f"filename stem={m_plist.group(1)!r})"
    )
    assert m_label.group(1) == LABEL, f"the service label is pinned to {LABEL!r}"


def test_postinstall_uses_label_variable_for_every_launchctl_operation() -> None:
    """Every launchctl target in postinstall goes through "system/$LABEL" (or
    `system "$PLIST"` for bootstrap) — no hardcode anywhere can drift from the
    LABEL definition again."""
    code = _postinstall_code()
    for op in ("bootout", "bootstrap", "print"):
        ops = re.findall(rf"launchctl {op}\b[^\n]*", code)
        assert ops, f"postinstall must use launchctl {op}"
        for line in ops:
            normalized = line.replace('"', "")
            assert "system/$LABEL" in normalized or "system $PLIST" in normalized, (
                f"launchctl {op} must target system/$LABEL (or system $PLIST for bootstrap), got: {line.strip()!r}"
            )


# --------------------------------------------------------------------------
# 2. interpreter: re-validate exactly preinstall's candidates, never PATH
# --------------------------------------------------------------------------


def test_postinstall_does_not_select_interpreter_via_path_search() -> None:
    """`command -v python3.12` can resolve to a Homebrew/per-user interpreter
    preinstall never validated (and that root then executes while the venv's
    python symlink anchors on it). Interpreter selection must be restricted to
    the preinstall-approved absolute paths."""
    text = _postinstall_code()
    assert not re.search(r"command -v python", text), (
        "postinstall must not look the interpreter up on PATH; it must "
        "re-validate exactly the preinstall-approved absolute paths"
    )


def test_postinstall_revalidates_the_exact_preinstall_candidates() -> None:
    """The candidate list in postinstall must be exactly what preinstall
    validated (framework python3, then /usr/local/bin/python3), each checked
    for the 3.12 minor version before use."""
    pre = _preinstall_text()
    post = _postinstall_text()
    assert FRAMEWORK_PY in pre and USR_LOCAL_PY in pre, (
        "preinstall must validate the framework and /usr/local/bin candidates"
    )
    for candidate in (FRAMEWORK_PY, USR_LOCAL_PY):
        assert candidate in post, f"postinstall must re-validate {candidate} — the exact path preinstall approved"
    # The 3.12 gate travels with the candidates (defense in depth: even the
    # validated path is re-checked for the minor version the wheelhouse needs).
    assert "sys.version_info[:2] == (3, 12)" in post, (
        "postinstall must assert CPython 3.12.x for the selected interpreter"
    )


# --------------------------------------------------------------------------
# 3. launchctl bootstrap fails closed (no masked failed upgrade)
# --------------------------------------------------------------------------


def test_postinstall_bootout_failure_is_not_swallowed() -> None:
    """`launchctl bootout ... || true` followed by a print-tolerance made a
    stuck/stale daemon on the OLD plist report install success. bootout on an
    already-bootstrapped label must be attempted only after print confirms the
    daemon is loaded, and its failure must abort the install."""
    text = _postinstall_text()
    bootouts = [ln for ln in text.splitlines() if "launchctl bootout" in ln]
    assert bootouts, "postinstall must bootout an already-bootstrapped label before re-bootstrap"
    for line in bootouts:
        assert "|| true" not in line, f"bootout failure must not be swallowed (fail closed), got: {line.strip()!r}"
    # The bootout is gated: only attempted when print shows the label loaded.
    gate = re.search(r'if launchctl print "system/\$LABEL"[^\n]*\n(.*?)fi\n', text, re.DOTALL)
    assert gate, "bootout must be gated on `launchctl print system/$LABEL` (upgrade detection)"
    assert "launchctl bootout" in gate.group(1), "the gated block must contain the bootout (fresh installs skip it)"


def test_postinstall_bootstrap_failure_is_fatal_no_already_bootstrapped_tolerance() -> None:
    """A failed `launchctl bootstrap` must abort the install. The previous
    print-based tolerance could leave a stale daemon running the OLD plist
    while the payload/venv beneath it were already replaced — a masked failed
    upgrade. The tolerance text must be gone. bootstrap now RETRIES (bounded)
    against the live bootout->bootstrap teardown race (seen 2026-09-13: an
    immediate re-register after bootout failed and left the service
    unloaded), but exhausted retries must still fail into the fail() helper."""
    text = _postinstall_text()
    assert "already bootstrapped" not in text, "the 'already bootstrapped — left running' tolerance must be removed"
    m = re.search(r'until launchctl bootstrap system "\$PLIST" 2>/dev/null; do', text)
    assert m, "bootstrap must run in a bounded retry loop (bootout teardown is asynchronous)"
    assert 'failed after 3 attempts' in text, "exhausted retries must name the bound"
    m2 = re.search(r'"\$bootstrap_attempt" -ge 3 \]; then\n\s*fail ', text)
    assert m2, "exhausted bootstrap retries must fail into fail() — bootstrap failures abort the install"


# --------------------------------------------------------------------------
# sanity: the fixes did not disturb the documented trust-model pins
# --------------------------------------------------------------------------


def test_postinstall_keeps_verify_before_execute_and_pubkey_refusals() -> None:
    """The hardening must not have touched the trust invariants: verifier runs
    with the admin pubkey BEFORE pip/launchctl, and verifier/pubkey inside the
    bundle are refused."""
    text = _postinstall_code()
    verify_idx = text.index("--pubkey")
    assert text.index("-m pip") > verify_idx, "verifier must run before any pip use"
    assert text.index("launchctl") > verify_idx, "verifier must run before any launchctl use"
    assert "refusing to verify with a verifier inside the bundle" in text
    assert "refusing to verify with a pubkey shipped inside the bundle" in text


def test_postinstall_and_preinstall_pass_bash_n() -> None:
    """Syntax gate for both pkg scripts (skipped where bash is unavailable)."""
    import shutil
    import subprocess

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available on this host")
    for script in (POSTINSTALL, PREINSTALL):
        proc = subprocess.run(  # noqa: S603 - fixed args, local script
            [bash, "-n", str(script)], capture_output=True, text=True, timeout=60
        )
        assert proc.returncode == 0, f"bash -n {script.name}: {proc.stderr}"
