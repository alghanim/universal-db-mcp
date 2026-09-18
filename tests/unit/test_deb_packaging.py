"""Deb packaging regression tests: packaging/deb/{control,preinst,postinst,conffiles,prerm,postrm}.

Content assertions + functional (extract-and-run) tests, no docker required.

Trust invariants under test (see docs/offline-deployment.md and the approved
plan, Phase 4):
  1. no package may execute payload before a trusted verify_bundle.py --pubkey
     run has passed (postinst delegates to the ONE trusted installer);
  2. the release pubkey is NEVER shipped inside any package;
  3. pip installs are --no-index --require-hashes with PIP_CONFIG_FILE
     neutralized — inherited from install_offline.sh, never re-implemented;
  4. fail closed on every verification failure (set -e / explicit exit 1).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell/mode semantics; run on linux/macos")


def _deb_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "packaging" / "deb"


def _read(name: str) -> str:
    return (_deb_dir() / name).read_text(encoding="utf-8")


def _executable_lines(text: str) -> str:
    """Strip full-line comments so assertions apply to code, not documentation."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------- control


def test_control_depends_python3_venv_libc() -> None:
    text = _read("control")
    depends_line = next(line for line in text.splitlines() if line.startswith("Depends:"))
    assert "python3 (>= 3.12~)" in depends_line
    assert "python3-venv" in depends_line
    assert "libc6 (>= 2.36)" in depends_line


def test_control_package_identity_and_recommends() -> None:
    text = _read("control")
    assert "Package: universal-db-mcp" in text
    assert "Recommends: systemd" in text


def test_control_documents_verify_before_execute_and_never_ships_pubkey() -> None:
    text = _read("control")
    assert "verify" in text.lower()
    assert "never shipped inside this package" in text


# ------------------------------------------------------------------- conffiles


def test_config_is_a_dpkg_conffile_registered_and_payload_backed() -> None:
    """/etc/universal-db-mcp/config.yaml IS a dpkg conffile (plan Phase 4).

    dpkg places it at unpack time, preserves admin edits on upgrade, keeps
    it on `remove` and deletes it on `purge`. build_deb.sh REQUIRES the
    conffiles template via its fail-loud gate and stages the config into the
    payload from the verified bundle's config-templates/ copy (mode 0644 so
    the udbmcp service account can read it). postinst's only-if-absent
    seeding stays as the fallback for a conffile an admin deleted before an
    upgrade (asserted by test_postinst_config_installed_only_if_absent; the
    build gate itself is exercised end-to-end by tests/unit/
    test_deb_conffiles_gate.py). The systemd unit, by contrast, is
    deliberately NOT dpkg-managed: it must never be staged at
    etc/systemd/system in the payload, so admin edits to the unit survive
    upgrades (postinst installs it to /etc/systemd/system instead)."""
    conffiles = _deb_dir() / "conffiles"
    assert conffiles.exists(), "packaging/deb/conffiles is a required plan Phase 4 input"
    entries = [line.strip() for line in conffiles.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    assert entries == ["/etc/universal-db-mcp/config.yaml"], f"unexpected dpkg conffiles entries: {entries}"
    # build_deb.sh must stage the config conffile into the payload (a
    # conffile entry without a backing file is "deleted by the packager").
    build = (Path(__file__).resolve().parents[2] / "scripts" / "package" / "build_deb.sh").read_text(encoding="utf-8")
    assert 'install -m 0644 "$CONFIG_TEMPLATE" "$DEBROOT/etc/universal-db-mcp/config.yaml"' in build
    # The systemd unit is NOT staged at etc/systemd/system on purpose.
    assert "etc/systemd/system/universal-db-mcp.service" not in build


# -------------------------------------------------------------------- postinst


def test_postinst_passes_bash_syntax_check() -> None:
    _bash_n(_deb_dir() / "postinst")


def test_postinst_delegates_to_trusted_installer_and_never_reimplements_pip() -> None:
    """The ONE installer implementation lives in scripts/install_offline.sh;
    postinst must call it, not fork the venv/pip logic (invariant 3)."""
    code = _executable_lines(_read("postinst"))
    assert 'bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"' in code
    # No re-implementation: no direct pip / venv / hash-pin usage in executable code.
    assert "pip install" not in code
    assert "python3 -m venv" not in code
    assert "--require-hashes" not in code
    assert "--no-index" not in code
    assert "PIP_CONFIG_FILE" not in code


def test_postinst_passes_pubkey_via_env_and_fails_closed_without_it() -> None:
    """install_offline.sh refuses to run without UDBMCP_RELEASE_PUBKEY; postinst
    must supply it AND check the admin-installed key itself (fail closed)."""
    code = _executable_lines(_read("postinst"))
    assert 'UDBMCP_RELEASE_PUBKEY="$PUBKEY"' in code
    assert 'if [ ! -f "$PUBKEY" ]; then' in code
    # Fail closed with the out-of-band-distribution diagnostic.
    assert "exit 1" in code.split('if [ ! -f "$PUBKEY" ]; then', 1)[1].split("\nfi\n", 1)[0]


def test_postinst_verifies_payload_before_any_execution_or_service_start() -> None:
    code = _executable_lines(_read("postinst"))
    verify_at = code.index('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE"')
    config_at = code.index('if [ ! -e "$CONFIG" ]; then')
    enable_at = code.index("systemctl enable --now")
    assert verify_at < config_at < enable_at, "verify payload -> install config -> enable service"


def test_postinst_config_installed_only_if_absent() -> None:
    code = _executable_lines(_read("postinst"))
    branch = code.split('if [ ! -e "$CONFIG" ]; then', 1)[1].split("\nfi\n", 1)[0]
    # 0755 root:root dir: the udbmcp service account must be able to traverse
    # to the 0640 udbmcp:udbmcp config file (the unit runs as User=udbmcp).
    assert "install -d -m 755" in branch
    assert "install -m 640" in branch
    assert "$BUNDLE/config-templates/config.yaml" in branch


def test_postinst_systemctl_calls_are_guarded_container_safe() -> None:
    code = _executable_lines(_read("postinst"))
    assert re.search(r"systemctl daemon-reload 2>/dev/null \|\|", code)
    assert re.search(r"if systemctl enable --now universal-db-mcp\.service 2>/dev/null; then", code)
    assert "WARNING: could not enable/start" in code


def test_postinst_never_executes_anything_from_inside_the_bundle() -> None:
    """Invariant 1: payload must not be executed — only ever passed as an
    argument to the trusted installer or copied with `install`."""
    code = _executable_lines(_read("postinst"))
    assert not re.search(r'(bash|sh|python3?)\s+.*"\$BUNDLE/', code)
    assert not re.search(r'"\$BUNDLE/.*"\s*\|', code)


def test_postinst_set_e_fail_closed() -> None:
    assert re.search(r"^set -e\b", _read("postinst"), flags=re.MULTILINE)


# --------------------------------------------------------------------- preinst


def test_preinst_passes_bash_syntax_check() -> None:
    _bash_n(_deb_dir() / "preinst")


def test_preinst_does_not_reference_bundle_payload_in_executable_code() -> None:
    """dpkg unpacks AFTER preinst: the payload path cannot exist yet, and any
    verifier run against a copy inside the package would prove nothing."""
    code = _executable_lines(_read("preinst"))
    assert "/usr/share/universal-db-mcp" not in code
    # It checks for the verifier's presence; it must never RUN it here.
    assert not re.search(r"python3?\s+.*\$VERIFIER", code)
    assert "--pubkey" not in code


def test_preinst_checks_both_trust_prerequisites_fail_closed() -> None:
    text = _read("preinst")
    code = _executable_lines(text)
    assert 'if [ ! -r "$VERIFIER" ]; then' in code
    assert 'if [ ! -r "$PUBKEY" ]; then' in code
    assert code.count("exit 1") >= 2
    assert re.search(r"^set -eu\b", text, flags=re.MULTILINE)


def _preinst_sandbox_script(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Copy preinst with its hardcoded trust paths rewritten into a sandbox.

    Only the three path constants are rewritten (the heredoc instructions are
    inert echoed text); every executable statement is otherwise verbatim.
    """
    trust_dir = tmp_path / "udbmcp-trust"
    keys_dir = tmp_path / "udbmcp-keys"
    pubkey = keys_dir / "release.pub.pem"
    text = _read("preinst")
    text = text.replace("/usr/local/lib/udbmcp-trust", str(trust_dir))
    text = text.replace("/etc/universal-db-mcp/keys/release.pub.pem", str(pubkey))
    # Sanity: the actual trust-path assignments (not the inert heredoc text,
    # which legitimately quotes the real /etc and /usr/local paths as
    # instructions) must have been rewritten into the sandbox.
    assert f'TRUST_DIR="{trust_dir}"' in text
    assert f'PUBKEY="{pubkey}"' in text
    script = tmp_path / "preinst.sh"
    script.write_text(text, encoding="utf-8")
    return script, trust_dir / "verify_bundle.py", pubkey


@_POSIX
def test_preinst_functional_fails_closed_without_verifier_then_without_pubkey(tmp_path: Path) -> None:
    script, verifier, pubkey = _preinst_sandbox_script(tmp_path)

    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 1
    assert "trusted verifier not found" in proc.stderr
    assert "ABORTED" in proc.stderr

    verifier.parent.mkdir(parents=True, exist_ok=True)
    verifier.write_text("# verifier\n", encoding="utf-8")
    # Verifier now present but the pubkey still absent: the SECOND prerequisite
    # must produce its own fail-closed diagnostic.
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 1
    assert "release public key not found" in proc.stderr
    assert "NOT shipped inside any package" in proc.stderr


@_POSIX
def test_preinst_functional_fails_closed_when_verifier_unreadable(tmp_path: Path) -> None:
    script, verifier, pubkey = _preinst_sandbox_script(tmp_path)
    verifier.parent.mkdir(parents=True)
    verifier.write_text("# verifier\n", encoding="utf-8")
    pubkey.parent.mkdir(parents=True)
    pubkey.write_text("key\n", encoding="utf-8")
    verifier.chmod(0)
    try:
        proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    finally:
        verifier.chmod(0o644)
    assert proc.returncode == 1
    assert "trusted verifier not found" in proc.stderr


@_POSIX
def test_preinst_functional_succeeds_when_both_prerequisites_present(tmp_path: Path) -> None:
    script, verifier, pubkey = _preinst_sandbox_script(tmp_path)
    verifier.parent.mkdir(parents=True)
    verifier.write_text("# verifier\n", encoding="utf-8")
    pubkey.parent.mkdir(parents=True)
    pubkey.write_text("key\n", encoding="utf-8")
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 0, proc.stderr
    assert "trust prerequisites present" in proc.stdout
    # Readability, not the exec bit, is the gate for the admin-installed verifier.
    assert "Payload verification happens in postinst" in proc.stdout


# ------------------------------------------- postinst functional (extract-and-run)


def _postinst_step1_bootstrap_script(tmp_path: Path, *, strip_root_owner: bool) -> Path:
    """Extract postinst's step-1 admin trust-dir completeness gate (variable
    definitions + the `# --- step 1` block) verbatim, with paths rewritten
    into a sandbox.

    strip_root_owner drops `-o root -g root` so the block can run on a
    non-root CI host; modes (-m) and all ordering/fail-closed logic untouched.
    """
    text = _read("postinst")
    lines = text.splitlines()
    step1 = next(i for i, line in enumerate(lines) if line.startswith("# --- step 1"))
    step2 = next(i for i, line in enumerate(lines) if line.startswith("# --- step 2"))
    defs = [line for line in lines[:step1] if re.match(r"^[A-Z_]+=/", line)]
    block = lines[step1:step2]
    rewritten = []
    for line in defs + block:
        # Sandbox EVERY path constant (TRUST_DIR lives under /usr/local/lib,
        # not /usr/share), so the block can never touch the real host tree.
        match = re.match(r"^([A-Z_]+)=/.+$", line)
        if match:
            line = f"{match.group(1)}={tmp_path / match.group(1).lower()}"
        if strip_root_owner:
            line = re.sub(r"-o root -g root ", "", line)
        rewritten.append(line)
    script = tmp_path / "postinst_step1.sh"
    script.write_text("#!/bin/bash\nset -e\n" + "\n".join(rewritten) + "\n", encoding="utf-8")
    return script


@_POSIX
def test_postinst_step1_functional_fails_closed_without_admin_trust_dir(tmp_path: Path) -> None:
    """A MISSING admin trust dir must abort step 1 (fail closed): the package
    NEVER bootstraps /usr/local/lib/udbmcp-trust from its own payload, so
    nothing may be created at the trust-dir path and the deb-shipped
    trusted-tools copy (present here, as in a real deb) must be left alone."""
    tools = tmp_path / "trusted_tools"
    (tools / "lib").mkdir(parents=True)
    (tools / "verify_bundle.py").write_text("# deb-shipped verifier\n", encoding="utf-8")
    (tools / "profiles.py").write_text("# deb-shipped profiles\n", encoding="utf-8")
    (tools / "install_offline.sh").write_text("# deb-shipped installer\n", encoding="utf-8")
    (tools / "lib" / "os_packages.sh").write_text("# deb-shipped lib\n", encoding="utf-8")

    script = _postinst_step1_bootstrap_script(tmp_path, strip_root_owner=False)
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0
    assert "trusted tool missing from the admin trust dir" in proc.stderr
    # Fail closed: the trust dir was never created and the deb-shipped copy
    # (inert reference material) was never read, copied or executed.
    assert not (tmp_path / "trust_dir").exists()
    assert (tools / "verify_bundle.py").read_text() == "# deb-shipped verifier\n"


@_POSIX
def test_postinst_step1_functional_fails_closed_on_incomplete_admin_trust_dir(tmp_path: Path) -> None:
    """An admin trust dir missing one file must abort: the deb payload HAS the
    missing file (present here with a distinguishing marker) and must NOT
    supply it — completing from the deb would let a tampered package install
    its own verifier/installer/lib as root."""
    tools = tmp_path / "trusted_tools"
    (tools / "lib").mkdir(parents=True)
    for rel in ("verify_bundle.py", "profiles.py", "install_offline.sh", "lib/os_packages.sh"):
        path = tools / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# deb-shipped copy\n", encoding="utf-8")

    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin verifier\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("# admin installer\n", encoding="utf-8")
    # profiles.py and lib/os_packages.sh deliberately missing from the ADMIN dir.

    script = _postinst_step1_bootstrap_script(tmp_path, strip_root_owner=True)
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0
    assert "trusted tool missing from the admin trust dir" in proc.stderr
    # The missing files were NOT completed from the deb payload...
    assert not (trust / "profiles.py").exists()
    assert not (trust / "lib" / "os_packages.sh").exists()
    # ...and the admin-provided files are byte-identical.
    assert (trust / "verify_bundle.py").read_text() == "# admin verifier\n"
    assert (trust / "install_offline.sh").read_text() == "# admin installer\n"


@_POSIX
def test_postinst_step1_functional_accepts_complete_admin_trust_dir(tmp_path: Path) -> None:
    """A complete admin trust dir passes step 1: every file is left
    byte-identical (the package never writes to the trust dir) and the flow
    proceeds."""
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("# admin-installed newer verifier\n", encoding="utf-8")
    for rel in ("profiles.py", "install_offline.sh", "lib/os_packages.sh"):
        (trust / rel).write_text("# admin-installed copy\n", encoding="utf-8")
    before = sorted(str(p.relative_to(trust)) for p in trust.rglob("*") if p.is_file())

    script = _postinst_step1_bootstrap_script(tmp_path, strip_root_owner=True)
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 0, proc.stderr
    assert "admin trust dir complete" in proc.stdout
    after = sorted(str(p.relative_to(trust)) for p in trust.rglob("*") if p.is_file())
    assert after == before, "trust dir contents changed during the completeness check"
    assert (trust / "verify_bundle.py").read_text() == "# admin-installed newer verifier\n"


def _postinst_pubkey_check_script(tmp_path: Path) -> Path:
    """Extract postinst's pubkey trust-prerequisite block verbatim."""
    text = _read("postinst")
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if 'if [ ! -f "$PUBKEY" ]; then' in line)
    end = next(i for i in range(start, len(lines)) if lines[i] == "fi")
    block = "\n".join(lines[start : end + 1])
    script = tmp_path / "postinst_pubkey.sh"
    script.write_text(f'#!/bin/bash\nset -e\nPUBKEY={tmp_path / "release.pub.pem"}\n{block}\n', encoding="utf-8")
    return script


@_POSIX
def test_postinst_pubkey_prerequisite_functional_fail_closed_and_pass(tmp_path: Path) -> None:
    script = _postinst_pubkey_check_script(tmp_path)

    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode != 0
    assert "release public key not found" in proc.stderr
    assert "NEVER shipped inside the package" in proc.stderr

    (tmp_path / "release.pub.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n", encoding="utf-8"
    )
    proc = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True, timeout=60)  # noqa: S603
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------- prerm / postrm (cheap)


@_POSIX
@pytest.mark.parametrize("name", ["prerm", "postrm"])
def test_maint_scripts_pass_bash_syntax_check(name: str) -> None:
    _bash_n(_deb_dir() / name)


@_POSIX
@pytest.mark.parametrize("name", ["prerm", "postrm"])
def test_maint_scripts_refuse_to_act_without_dpkg_action(name: str) -> None:
    """Invoked outside dpkg (no action argument) they must fail closed."""
    env = dict(os.environ)
    proc = subprocess.run(  # noqa: S603 - fixed args, local script
        ["/bin/bash", str(_deb_dir() / name)], capture_output=True, text=True, timeout=60, env=env
    )
    assert proc.returncode == 1
    assert "refusing to act" in proc.stderr


def test_install_offline_normalizes_venv_modes() -> None:
    """Seen live (Ubuntu, 2026-09-15): the installing context's umask leaked
    into the venv (0700 root:root) and the udbmcp service died with 203/EXEC
    'Permission denied' - the interpreter was fine, the SERVICE ACCOUNT just
    could not traverse into the tree. install_offline.sh must normalize the
    venv modes unconditionally after the build: dirs traversable (755), files
    readable (644), bin executables (755) - read+traverse only, never write -
    and BEFORE anything that hands the venv to a service or the PATH alias."""
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "scripts" / "install_offline.sh").read_text(
        encoding="utf-8"
    )
    assert 'find "$VENV_BUILD" -type d -exec chmod 755' in text  # the tree being built (venv or venv.new-*)
    assert 'find "$VENV_BUILD" -type f -exec chmod 644' in text
    assert 'find "$VENV_BUILD/bin" -type f -exec chmod 755' in text
    assert text.index("-type d -exec chmod 755") < text.index("udbmcp CLI alias"), (
        "the venv must be normalized before the PATH alias step exposes it"
    )
