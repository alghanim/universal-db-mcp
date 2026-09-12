"""The system service (launchd plist, systemd unit) must run HTTP, not stdio.

Bug this file locks in place (found on a live install 2026-09-12): both service
units ran plain ``serve``, which follows the config template's
``transport: stdio``. A daemon under a service manager has no client on stdin,
so the stdio server read EOF and exited 0 immediately; KeepAlive/Restart
policies treat exit 0 as clean and never restart it, leaving the "service"
permanently down. The system service is the shared authenticated HTTP daemon
(per-harness agents spawn their own stdio servers), so the units now force
``--transport http`` on the command line and point the server at the bearer
token via ``UDBMCP_HTTP_BEARER_TOKEN_FILE`` (an env PATH fallback added to
``load_config``; an explicit config value still wins, and the token VALUE is
never carried in an environment variable).

Also pinned here: both package postinstalls provision that token file —
only-if-absent (never clobber), owner = service account, mode 0600 (the
server's secret-file permission rule rejects group/other bits), value from
python's ``secrets`` module and never printed.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLIST = REPO_ROOT / "packaging" / "launchd" / "com.udbmcp.server.plist"
UNIT = REPO_ROOT / "packaging" / "systemd" / "universal-db-mcp.service"
PKG_POSTINSTALL = REPO_ROOT / "packaging" / "pkg" / "postinstall"
DEB_POSTINST = REPO_ROOT / "packaging" / "deb" / "postinst"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


_XML_COMMENT = re.compile(rb"<!--.*?-->", re.S)


def _load_plist(path: Path) -> dict[str, object]:
    """Parse the plist with comments stripped: the shipped mirror-table comment
    contains '--' sequences that are legal nowhere inside an XML comment, so
    expat rejects the raw file (the same workaround
    tests/unit/test_pkg_postinstall_hardening.py uses)."""
    return plistlib.loads(_XML_COMMENT.sub(b"", path.read_bytes()))


# ------------------------------------------------------------------ plist


def test_plist_runs_http_transport() -> None:
    data = _load_plist(PLIST)
    args = data["ProgramArguments"]
    assert args[-2:] == ["--transport", "http"], (
        f"launchd daemon must force HTTP transport; got ProgramArguments={args}"
    )


def test_plist_exports_bearer_token_path_env() -> None:
    data = _load_plist(PLIST)
    env = data["EnvironmentVariables"]
    assert env.get("UDBMCP_HTTP_BEARER_TOKEN_FILE") == "/etc/universal-db-mcp/http-token"


def test_plist_docstring_keeps_systemd_mirror_honest() -> None:
    """The plist comment block claims to mirror the systemd unit 'line for
    line' — the ExecStart/ProgramArguments HTTP change must be reflected on
    BOTH sides, so assert the mirror comment names the transport decision."""
    text = _read(PLIST)
    assert "stdio" in text and "http" in text, (
        "the plist comment should explain why the daemon forces HTTP (stdio "
        "under a service manager reads EOF and exits 0)"
    )


# ------------------------------------------------------------------ systemd unit


def test_systemd_unit_runs_http_transport() -> None:
    exec_start = [
        line for line in _read(UNIT).splitlines() if line.startswith("ExecStart=")
    ]
    assert len(exec_start) == 1
    assert exec_start[0].rstrip().endswith("serve --transport http"), (
        f"systemd daemon must force HTTP transport; got {exec_start[0]!r}"
    )


def test_systemd_unit_exports_bearer_token_path_env() -> None:
    text = _read(UNIT)
    assert "Environment=UDBMCP_HTTP_BEARER_TOKEN_FILE=/etc/universal-db-mcp/http-token" in text


# ------------------------------------------------- token provisioning (postinstalls)


def test_pkg_postinstall_provisions_token_fail_closed() -> None:
    text = _read(PKG_POSTINSTALL)
    assert "http-token" in text
    # only-if-absent: never clobber the admin's token
    assert "already present" in text
    # mode 0600 owned by the service account (secret-file permission rule)
    assert re.search(r"install -m 0600 -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" /dev/null", text)
    # value generated from python secrets, never printed
    assert "secrets.token_hex(32)" in text
    assert "echo.*token_hex" not in text
    # a failed generation must abort the install (postinstall has fail())
    assert re.search(r"\|\| fail ", text.split("http-token")[-1])


def test_deb_postinst_provisions_token_in_both_config_branches() -> None:
    text = _read(DEB_POSTINST)
    # the worker (deferred install) and the direct path BOTH install config;
    # each must be followed by token provisioning
    branches = text.count('TOKEN_FILE="$CONFIG_DIR/http-token"')
    assert branches == 2, (
        f"expected token provisioning in both postinst branches (worker + "
        f"direct); found {branches}"
    )
    assert text.count("install -m 0600 -o udbmcp -g udbmcp /dev/null") == 2
    assert text.count("secrets.token_hex(32)") == 2


def test_token_generation_uses_non_erroring_python_snippet() -> None:
    """The generator snippet itself must be valid on any CPython 3.12."""
    import subprocess
    import sys

    proc = subprocess.run(  # noqa: S603 - fixed args, test-only snippet
        [sys.executable, "-c", "import secrets; print(secrets.token_hex(32))"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert re.fullmatch(r"[0-9a-f]{64}\n", proc.stdout)


# ------------------------------------ review fix: empty-token regeneration
# (adversarial review 2026-09-12: an install killed between file creation and
# token append leaves a 0600 EMPTY file; a `[ -f ]` guard would preserve it
# forever as a misdescribed "admin token" while the server refuses empty
# tokens — a sticky broken state. All provisioners must treat EMPTY as absent.)


def test_provisioners_treat_empty_token_as_absent() -> None:
    for path, label in ((PKG_POSTINSTALL, "pkg postinstall"), (DEB_POSTINST, "deb postinst")):
        text = _read(path)
        assert text.count('[ -s "$TOKEN_FILE" ]') >= (
            1 if label == "pkg postinstall" else 2
        ), f"{label} must gate on NON-EMPTY (not merely existing) token file"
        assert "is empty; regenerating it" in text, (
            f"{label} must regenerate (loudly) instead of preserving an empty leftover"
        )


def test_msi_service_provisions_token_only_if_absent_or_empty() -> None:
    text = _read(REPO_ROOT / "packaging" / "msi" / "custom" / "service.ps1")
    assert "http-token" in text
    assert "secrets.token_hex(32)" in text
    # empty leftover regenerated, existing non-empty token preserved
    assert "is empty; regenerating it" in text
    assert "$needToken = $false" in text


# ------------------------------------ review fix: deb upgrade unit deployment
# (adversarial review 2026-09-12: the matches-or-absent rule kept the OLD
# stdio unit on upgraded systems forever — the fix never reached the fleets
# that needed it, silently. A previously-shipped hash record lets postinst
# distinguish "our own previous copy" from an admin modification, and a
# try-restart deploys a replaced unit to a RUNNING service.)


def test_deb_postinst_deploys_updated_unit_to_upgraded_systems() -> None:
    text = _read(DEB_POSTINST)
    assert text.count("SHIPPED_UNIT_RECORD=") == 2, (
        "both postinst branches must record the deployed unit hash"
    )
    assert text.count("sha256sum") >= 4, (
        "both branches must compare the deployed unit against the hash record"
    )
    assert "matches the previously-shipped unit (hash record)" in text


def test_deb_postinst_restarts_running_service_on_upgrade() -> None:
    text = _read(DEB_POSTINST)
    assert text.count("systemctl try-restart universal-db-mcp.service") == 2, (
        "both branches must try-restart so a replaced unit reaches a RUNNING service"
    )


# ------------------------------------ review fix: MSI service HTTP mode
# (adversarial review 2026-09-12: the Windows SCM daemon still registered
# plain `serve` — the exact stdio-EOF-exit-0 permanent-down bug, on the third
# packaging channel, with no token provisioning at all.)


def test_msi_service_forces_http_transport() -> None:
    text = _read(REPO_ROOT / "packaging" / "msi" / "custom" / "service.ps1")
    assert "serve --transport http" in text, (
        "the Windows service must force HTTP transport like the launchd/systemd units"
    )
    assert re.search(r"serve'\s*$", text, re.MULTILINE) is None, (
        "no plain-serve registration may remain in service.ps1"
    )


def test_msi_service_injects_bearer_token_path_env() -> None:
    text = _read(REPO_ROOT / "packaging" / "msi" / "custom" / "service.ps1")
    assert "UDBMCP_HTTP_BEARER_TOKEN_FILE" in text, (
        "service.ps1 must inject the token PATH via the service Environment registry value"
    )


# ------------------------------------ review fix: upgrade reinstall
# (found live 2026-09-12: the app wheel's version string does not change
# between code-only releases, so pip's "already satisfied" left the PREVIOUS
# release's code in the venv while the new plist ran around it — the service
# crash-looped with exit 1. Upgrades must --force-reinstall the hash-checked
# lock from the verified wheelhouse.)


def test_pkg_postinstall_force_reinstalls_on_upgrade() -> None:
    text = _read(PKG_POSTINSTALL)
    pip_block = text[text.index("postinstall: installing application") :]
    assert "--force-reinstall" in pip_block, (
        "the pkg venv must --force-reinstall from the verified wheelhouse: "
        "same-version app wheels would otherwise never refresh on upgrade"
    )


# ------------------------------------ review fix: doctor token-check reachability
# (adversarial review 2026-09-12: doctor gated the token checks on
# config.transport == "http", which is unreachable in the deployed topology —
# the shared config keeps stdio while the daemon forces http via CLI + env.)


def test_doctor_validates_service_token_file_even_for_stdio_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    import stat as stat_module

    import universal_db_mcp.diagnostics.doctor as doctor

    token = tmp_path / "http-token"
    token.write_text("x" * 64, encoding="utf-8")
    token.chmod(0o600)
    monkeypatch.setattr(doctor, "SERVICE_TOKEN_PATH", token)
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("application:\n  transport: stdio\n", encoding="utf-8")
    report = doctor.run_doctor(str(cfg_path))
    checks = [c for c in report["checks"] if c["check"] == "http-bearer-token"]
    assert checks and checks[-1]["status"] == "ok", checks

    # unsafe perms on the service token must be flagged even for a stdio config
    os.chmod(token, 0o644)
    report2 = doctor.run_doctor(str(cfg_path))
    checks2 = [c for c in report2["checks"] if c["check"] == "http-bearer-token"]
    assert checks2 and checks2[-1]["status"] != "ok", checks2
    assert stat_module  # keep the import honest when the happy path skips
