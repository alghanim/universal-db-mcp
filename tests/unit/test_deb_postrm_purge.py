"""Regression tests for the deb postrm purge contract (artifact deb:prerm_postrm).

Two verified defects are locked out here:

1. install_offline.sh publishes /opt/universal-db-mcp/manifest.json next to
   the venv (scripts/install_offline.sh:211). That file is NOT dpkg-owned, so
   postrm must remove it on `purge` — otherwise the guarded parent `rmdir`
   always fails silently and a stale manifest.json survives `dpkg -P`.
2. install_offline.sh never writes inside the installed bundle tree: it stages
   into a private `mktemp -d` directory under /var/tmp removed by an EXIT trap
   (scripts/install_offline.sh:134-138), and dpkg deletes the dpkg-owned
   bundle tree before postrm purge runs. postrm must therefore carry no dead
   bundle-tree rm -rf and must not claim the installer writes into the bundle.

Style follows tests/unit/test_deb_packaging.py: content assertions on the
maintainer script plus extract-and-run functional tests in a sandbox with the
hardcoded paths rewritten, no docker required.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")

_POSTRM = Path(__file__).resolve().parents[2] / "packaging" / "deb" / "postrm"


def _read_postrm() -> str:
    return _POSTRM.read_text(encoding="utf-8")


def _executable_lines(text: str) -> str:
    """Strip full-line comments so assertions apply to code, not documentation."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _sandbox_postrm(tmp_path: Path) -> Path:
    """Copy postrm verbatim with its hardcoded paths rewritten into a sandbox.

    Both path literals appear in the assignments AND in the bare `rmdir`
    commands, so a plain string replacement rewrites every executable use.
    """
    text = _read_postrm()
    text = text.replace("/opt/universal-db-mcp", str(tmp_path / "opt" / "universal-db-mcp"))
    text = text.replace("/usr/share/universal-db-mcp", str(tmp_path / "usr" / "share" / "universal-db-mcp"))
    # The config (a dpkg conffile, also seeded only-if-absent by postinst)
    # lives under /etc: rewrite it too so the sandbox purge can never touch
    # the real host /etc.
    text = text.replace("/etc/universal-db-mcp", str(tmp_path / "etc" / "universal-db-mcp"))
    # The deployed unit + drop-in dir (postinst-installed) and the unit hash
    # record are purged too: rewrite them so the sandbox purge never touches
    # the host's /etc/systemd/system or /var/lib.
    text = text.replace("/etc/systemd/system", str(tmp_path / "etc" / "systemd" / "system"))
    text = text.replace("/var/lib/universal-db-mcp", str(tmp_path / "var" / "lib" / "universal-db-mcp"))
    script = tmp_path / "postrm.sh"
    script.write_text(text, encoding="utf-8")
    return script


def _run_postrm(script: Path, action: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed args, local sandbox script
        ["/bin/bash", str(script), action], capture_output=True, text=True, timeout=60, env=dict(os.environ)
    )


def _rmdir_supports_ignore_fail() -> bool:
    """postrm targets Ubuntu (GNU coreutils). BSD rmdir (macOS) lacks
    --ignore-fail-on-non-empty, so the guarded parent rmdir can only be
    exercised positively where the GNU option exists."""
    proc = subprocess.run(["/bin/rmdir", "--help"], capture_output=True, text=True, timeout=30)  # noqa: S603
    return "--ignore-fail-on-non-empty" in proc.stdout + proc.stderr


def _install_generated_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    """Mimic install_offline.sh's post-unpack artifacts inside the sandbox."""
    opt = tmp_path / "opt" / "universal-db-mcp"
    venv = opt / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("# venv payload\n", encoding="utf-8")
    manifest = opt / "manifest.json"
    manifest.write_text('{"release": "0.1.0"}\n', encoding="utf-8")
    return venv, manifest


# ------------------------------------------------------------------ content


def test_postrm_purge_removes_manifest_in_executable_code() -> None:
    """manifest.json is installer-generated and not dpkg-owned: purge must rm it."""
    code = _executable_lines(_read_postrm())
    assert 'MANIFEST_FILE="/opt/universal-db-mcp/manifest.json"' in code
    assert 'rm -f "$MANIFEST_FILE"' in code


def test_postrm_has_no_dead_bundle_tree_cleanup() -> None:
    """dpkg owns and deletes the bundle tree; the installer never writes into
    it, so postrm must contain no bundle-tree rm -rf (removed dead code)."""
    code = _executable_lines(_read_postrm())
    assert "BUNDLE" not in code


def test_postrm_header_does_not_claim_installer_writes_inside_bundle() -> None:
    """The removed header premise was false: install_offline.sh stages into a
    private mktemp -d directory and never writes inside the bundle tree."""
    text = _read_postrm()
    assert "staging/re-verify" not in text
    assert "writes inside the bundle" not in text


# --------------------------------------------------------------- functional


@_POSIX
def test_postrm_purge_removes_venv_manifest_and_empty_parents(tmp_path: Path) -> None:
    script = _sandbox_postrm(tmp_path)
    venv, manifest = _install_generated_artifacts(tmp_path)

    proc = _run_postrm(script, "purge")
    assert proc.returncode == 0, proc.stderr
    assert not venv.exists(), "purge must remove the installer-built venv"
    assert not manifest.exists(), "purge must remove the installer-published manifest.json"
    parent = tmp_path / "opt" / "universal-db-mcp"
    if _rmdir_supports_ignore_fail():
        assert not parent.exists(), "parent dir must be rmdir'd once manifest.json no longer blocks it"
    else:
        # BSD rmdir rejects the GNU option; the `|| true` guard must keep the
        # purge non-fatal (fail-safe: never delete a parent with rm -r).
        assert parent.exists()
    assert "purged" in proc.stdout


@_POSIX
def test_postrm_purge_deletes_seeded_config_but_keeps_admin_pubkey(tmp_path: Path) -> None:
    """The config is a dpkg conffile (deleted on purge by dpkg itself) and is
    also seeded only-if-absent by postinst — postrm's purge deletion of it is
    belt and braces for that seeded fallback copy. The admin's keys/ directory
    (out-of-band release public key) must survive a purge untouched."""
    script = _sandbox_postrm(tmp_path)
    etc = tmp_path / "etc" / "universal-db-mcp"
    (etc / "keys").mkdir(parents=True)
    config = etc / "config.yaml"
    config.write_text("# admin-edited config\n", encoding="utf-8")
    pubkey = etc / "keys" / "release.pub.pem"
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nadmin key\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = _run_postrm(script, "purge")
    assert proc.returncode == 0, proc.stderr
    assert not config.exists(), "purge must delete the postinst-seeded config"
    assert pubkey.read_text().startswith("-----BEGIN PUBLIC KEY-----"), (
        "purge must never touch the admin release pubkey"
    )
    assert (etc / "keys").is_dir(), "purge must keep /etc/universal-db-mcp/keys"
    assert etc.exists(), "non-empty /etc/universal-db-mcp (keys/ inside) must survive the guarded rmdir"


@_POSIX
def test_postrm_remove_retains_seeded_config(tmp_path: Path) -> None:
    script = _sandbox_postrm(tmp_path)
    etc = tmp_path / "etc" / "universal-db-mcp"
    etc.mkdir(parents=True)
    config = etc / "config.yaml"
    config.write_text("# admin-edited config\n", encoding="utf-8")

    proc = _run_postrm(script, "remove")
    assert proc.returncode == 0, proc.stderr
    assert config.exists(), "remove keeps the seeded config (purge deletes it)"


@_POSIX
def test_postrm_purge_leaves_unrelated_files_and_parents_alone(tmp_path: Path) -> None:
    script = _sandbox_postrm(tmp_path)
    venv, manifest = _install_generated_artifacts(tmp_path)
    opt = tmp_path / "opt" / "universal-db-mcp"
    share = tmp_path / "usr" / "share" / "universal-db-mcp"
    unrelated_opt = opt / "unrelated-under-opt.txt"
    unrelated_share = share / "unrelated-under-share.txt"
    opt.mkdir(parents=True, exist_ok=True)
    share.mkdir(parents=True, exist_ok=True)
    unrelated_opt.write_text("keep me\n", encoding="utf-8")
    unrelated_share.write_text("keep me too\n", encoding="utf-8")

    proc = _run_postrm(script, "purge")
    assert proc.returncode == 0, proc.stderr
    assert not venv.exists() and not manifest.exists()
    assert unrelated_opt.read_text() == "keep me\n"
    assert unrelated_share.read_text() == "keep me too\n"
    assert opt.exists() and share.exists(), "non-empty parents must survive the guarded rmdir"


@_POSIX
def test_postrm_remove_retains_venv_and_manifest(tmp_path: Path) -> None:
    script = _sandbox_postrm(tmp_path)
    venv, manifest = _install_generated_artifacts(tmp_path)

    proc = _run_postrm(script, "remove")
    assert proc.returncode == 0, proc.stderr
    assert venv.exists() and manifest.exists(), "remove keeps installer-generated files for fast reinstall"
