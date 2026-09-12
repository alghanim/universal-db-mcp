"""Regression tests for the deb postinst deferred-install fix (deb:postinst).

Defects fixed (verifier lenses, deb:postinst artifact):

P1: the postinst ran install_offline.sh synchronously inside the dpkg-held
    critical section; install_offline.sh installs the bundle's os-packages/
    closure with `dpkg -i` (lib/os_packages.sh), which deadlocks against the
    outer dpkg ("dpkg frontend lock was locked by another process") — every
    `dpkg -i` of the deb failed at configure. Fix: when the unpacked bundle
    ships os-packages/*.deb, postinst verifies the payload SYNCHRONOUSLY
    with the trusted verifier (tamper still fails configure — fail closed at
    the dpkg level) and hands the install to a detached worker that waits
    for the dpkg fcntl locks to be released before running the ONE installer.

P2 (reversed by the completeness-critic round-2 fix): the postinst used to
    self-bootstrap the trust dir from the deb-shipped trusted-tools copy when
    the dir was absent, and "complete" a partial admin install from it. That
    copy travels on the SAME channel as the payload it would verify, so a
    tampered package could ship a verifier that prints PASSED (or an
    installer that skips verification) and get it installed to the root-owned
    trust path and executed there. Fix: the postinst NEVER writes to
    /usr/local/lib/udbmcp-trust; an absent or incomplete admin trust dir
    aborts the configure step with bootstrap instructions, and the
    deb-shipped copy is inert reference material. The dedicated regression
    tests live in tests/unit/test_deb_postinst_no_self_bootstrap.py; the
    structural guard here covers the deferred flow end to end.

Trust invariants re-checked here (never broken by the fix):
  1. no package executes payload before a trusted verify_bundle.py --pubkey
     run has passed (now enforced synchronously in postinst, and again by
     install_offline.sh in the worker);
  2. the release pubkey is never shipped inside the package (unchanged);
  3. pip hardening is inherited from install_offline.sh, never re-implemented;
  4. fail closed on every verification failure (sync verify aborts configure;
     the worker records 'failed' and never installs a unit / enables the
     service unless the trusted install succeeded).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics; run on linux/macos")

_DEB = Path(__file__).resolve().parents[2] / "packaging" / "deb"
_POSTINST = _DEB / "postinst"


def _read_postinst() -> str:
    return _POSTINST.read_text(encoding="utf-8")


def _executable_lines(text: str) -> str:
    """Strip full-line comments so assertions apply to code, not documentation."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _worker_script(text: str) -> str:
    """Extract the embedded deferred-worker script from the postinst heredoc."""
    match = re.search(r"<<'WORKER_EOF'\n(.*?)\nWORKER_EOF\n", text, flags=re.DOTALL)
    assert match, "deferred worker heredoc not found in postinst"
    return match.group(1)


def _bash_n(path: Path) -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


# ------------------------------------------------------------------- structure


@_POSIX
def test_postinst_passes_bash_syntax_check(tmp_path: Path) -> None:
    _bash_n(_POSTINST)


@_POSIX
def test_worker_script_extracts_and_passes_bash_syntax_check(tmp_path: Path) -> None:
    worker = tmp_path / "worker.sh"
    worker.write_text(_worker_script(_read_postinst()), encoding="utf-8")
    _bash_n(worker)


@_POSIX
def test_deferred_mode_triggers_only_when_bundle_ships_os_packages() -> None:
    code = _executable_lines(_read_postinst())
    assert 'if compgen -G "$BUNDLE/os-packages/*.deb" >/dev/null; then' in code, (
        "the deferred branch must be gated on the payload actually shipping os-packages/*.deb"
    )


@_POSIX
def test_deferred_mode_verifies_synchronously_before_spawning_worker() -> None:
    """Order in executable code: sync trusted verify -> (worker heredoc with
    the installer call) -> spawn -> sync-path installer call. Proves the
    tamper check still aborts configure BEFORE any installer/worker runs."""
    code = _executable_lines(_read_postinst())
    verify_at = code.index('"$TRUST_DIR/verify_bundle.py" --bundle "$BUNDLE" --pubkey "$PUBKEY"')
    installer_sig = 'bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"'
    installer_calls = [m.start() for m in re.finditer(re.escape(installer_sig), code)]
    assert len(installer_calls) == 2, "installer must be called exactly twice: in the worker and on the sync path"
    spawn_at = code.index("setsid --fork")
    sync_verify, worker_installer, sync_installer = verify_at, installer_calls[0], installer_calls[1]
    assert sync_verify < worker_installer < spawn_at < sync_installer, (
        "deferred branch must verify synchronously first; the installer call may only exist "
        "inside the worker heredoc (written before spawn); sync path follows the branch"
    )
    # The deferred branch ends with exit 0 before the synchronous path begins.
    assert code.index("exit 0", spawn_at) < sync_installer


@_POSIX
def test_worker_waits_for_dpkg_locks_and_installs_unit_only_after_installer() -> None:
    """P1 core: the worker must not touch the dpkg database (no nested
    `dpkg -i`) and must run the ONE installer only after its lock probe;
    unit/config/enable come only after the installer succeeded."""
    code = _executable_lines(_worker_script(_read_postinst()))
    probe_at = code.index("dpkg_locks_free")
    installer_at = code.index('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"')
    unit_at = code.index('install -m 644 -o root -g root "$UNIT_SRC" "$UNIT_DST"')
    enable_at = code.index("systemctl enable --now")
    assert probe_at < installer_at < unit_at < enable_at
    # The worker itself never invokes dpkg as a command (no nested dpkg -i).
    assert "dpkg -i" not in code
    assert not re.search(r"(?m)^\s*dpkg\b", code), (
        "worker must not run dpkg directly; the closure is installed by install_offline.sh"
    )
    # Fail-closed bookkeeping: a nonzero exit marks the status file 'failed'.
    assert "echo failed >" in code
    assert "echo success >" in code


@_POSIX
def test_worker_runs_installer_with_pubkey_and_never_reimplements_pip() -> None:
    code = _executable_lines(_worker_script(_read_postinst()))
    assert 'UDBMCP_RELEASE_PUBKEY="$PUBKEY"' in code
    for forbidden in ("pip install", "python3 -m venv", "--require-hashes", "--no-index", "PIP_CONFIG_FILE"):
        assert forbidden not in code, f"worker must not re-implement installer hardening ({forbidden})"


@_POSIX
def test_step1_never_writes_to_the_trust_dir() -> None:
    """P2 (reversed): the trust dir is an ADMIN prerequisite. Step 1 must only
    CHECK it (fail closed), never install/copy anything into it from the deb
    payload, and must never reference the deb-shipped trusted-tools copy at
    all (that copy rides on the same channel as the payload it would
    verify — bootstrapping or completing the trust dir from it would let a
    tampered package run its own verifier/installer as root)."""
    text = _read_postinst()
    code = _executable_lines(text)
    step1 = code.split("# --- step 1", 1)[1].split("# --- step 2", 1)[0]
    assert "trusted tool missing from the admin trust dir" in step1
    assert "exit 1" in step1
    assert not re.search(r"(?m)^\s*install\s", step1), "step 1 must not install/copy anything"
    assert not re.search(r"(?m)^\s*cp\s", step1), "step 1 must not copy anything"
    assert "TRUSTED_TOOLS" not in code, (
        "postinst must never reference the deb-shipped trusted-tools copy in executable code"
    )


# ------------------------------------------- P2 functional (extract-and-run)
# The step-1 fail-closed completeness gate (missing trust dir / incomplete
# admin trust dir / complete admin trust dir) is covered functionally in
# tests/unit/test_deb_packaging.py (step-1 extract-and-run) and in
# tests/unit/test_deb_postinst_no_self_bootstrap.py (full-postinst sandbox,
# incl. the poisoned-deb-verifier case). Nothing here completes the trust dir
# anymore: the package never writes to it.


# ------------------------------------------- P1 functional (full sandbox run)


def _deferred_sandbox_postinst(tmp_path: Path) -> Path:
    """Rewrite the WHOLE postinst into a sandbox: every path constant points
    into tmp_path, dpkg's lock files become sandbox files, systemctl/flock/
    setsid become sandbox shims, and root/udbmcp ownership flags are dropped
    so the flow can run as a non-root test user. Ordering, gating and all
    fail-closed logic are untouched."""
    text = _read_postinst()
    lines = text.splitlines()
    rewritten = []
    for line in lines:
        match = re.match(r"^([A-Z_]+)=/.+$", line)
        if match:
            line = f"{match.group(1)}={tmp_path / match.group(1).lower()}"
        line = line.replace("/var/lib/dpkg/lock-frontend", str(tmp_path / "dpkg" / "lock-frontend"))
        line = line.replace("/var/lib/dpkg/lock", str(tmp_path / "dpkg" / "lock"))
        line = line.replace("/run/udbmcp-deferred-install.lock", str(tmp_path / "run" / "udbmcp-deferred-install.lock"))
        # The /var/tmp path is the postinst's literal being rewritten into the sandbox.
        line = line.replace(
            "/var/tmp/udbmcp-postinst-worker.XXXXXX",  # noqa: S108
            str(tmp_path / "tmp" / "udbmcp-postinst-worker.XXXXXX"),
        )
        line = line.replace("systemctl ", "sbx-systemctl ")
        line = line.replace("flock -n", "sbx-flock -n")
        line = line.replace("setsid --fork", "sbx-setsid --fork")
        line = re.sub(r"-o root -g root ", "", line)
        line = re.sub(r"-o udbmcp -g udbmcp ", "", line)
        rewritten.append(line)
    script = tmp_path / "postinst_sbx.sh"
    script.write_text("#!/bin/bash\n" + "\n".join(rewritten) + "\n", encoding="utf-8")
    return script


def _make_shims(tmp_path: Path) -> None:
    """Sandbox shims: systemctl always fails (exercises both guarded call
    sites), flock always succeeds (single-flight is covered structurally),
    setsid --fork backgrounds the worker so it outlives the postinst."""
    shim = tmp_path / "shims"
    shim.mkdir(exist_ok=True)
    (shim / "sbx-systemctl").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (shim / "sbx-flock").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (shim / "sbx-setsid").write_text(
        "#!/bin/sh\n" '[ "$1" = "--fork" ] && shift\n' '"$@" </dev/null >/dev/null 2>&1 &\n' "exit 0\n",
        encoding="utf-8",
    )
    for path in shim.iterdir():
        path.chmod(0o755)


@_POSIX
def test_deferred_flow_functional_verifies_then_installs_after_dpkg_locks_release(tmp_path: Path) -> None:
    """End-to-end P1 regression, no root and no docker:
    - the payload ships os-packages/*.deb -> postinst must take the deferred
      branch, run the trusted verify SYNCHRONOUSLY (marker written even while
      the outer dpkg 'holds' the locks), spawn the worker and exit 0;
    - the worker must WAIT for the locks (a stub installer that probes them
      exits 42 if any is still held) and only then 'install';
    - unit/config are installed and the status file ends 'success';
    - P2 (reversed): the COMPLETE admin trust dir is used as-is — the package
      never completes it from the deb-shipped (inert) copy.
    """
    # --- sandbox payload ------------------------------------------------------
    bundle = tmp_path / "bundle"
    (bundle / "os-packages").mkdir(parents=True)
    (bundle / "os-packages" / "dummy_1.0_amd64.deb").write_bytes(b"deb")
    (bundle / "config-templates").mkdir()
    (bundle / "config-templates" / "config.yaml").write_text("# template\n", encoding="utf-8")
    (bundle / "operations").mkdir()
    (bundle / "operations" / "universal-db-mcp.service").write_text("[Unit]\n", encoding="utf-8")

    # Deb-shipped trusted-tools payload: INERT reference material (postinst
    # never reads, copies or executes it — see the no-self-bootstrap tests).
    tools = tmp_path / "trusted_tools"
    (tools / "lib").mkdir(parents=True)
    (tools / "verify_bundle.py").write_text("# deb-shipped verifier\n", encoding="utf-8")
    (tools / "profiles.py").write_text("# deb-shipped profiles\n", encoding="utf-8")
    (tools / "install_offline.sh").write_text("# deb-shipped installer\n", encoding="utf-8")
    (tools / "lib" / "os_packages.sh").write_text("# deb-shipped lib\n", encoding="utf-8")

    # Admin trust dir: the COMPLETE admin bootstrap (verifier, profiles.py,
    # installer, lib/os_packages.sh — the package never completes a partial
    # dir from the deb payload, so the sandbox must start complete).
    # The stub verifier records the synchronous verification; the stub
    # installer fails (42) if any dpkg lock is still held — the P1 deadlock.
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text(
        "import pathlib, sys\n"
        f'pathlib.Path("{tmp_path}/verify-marker").write_text("verified\\n")\n'
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    (trust / "install_offline.sh").write_text(
        "#!/bin/bash\n"
        "set -eu\n"
        "python3 - <<'PY'\n"
        "import fcntl, sys\n"
        f'for path in ("{tmp_path}/dpkg/lock-frontend", "{tmp_path}/dpkg/lock"):\n'
        '    fh = open(path, "r+")\n'
        "    try:\n"
        "        fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "        fcntl.lockf(fh, fcntl.LOCK_UN)\n"
        "    except OSError:\n"
        "        sys.exit(42)\n"
        "    finally:\n"
        "        fh.close()\n"
        "PY\n"
        'mkdir -p "$2"\n'
        f'touch "{tmp_path}/install-marker"\n',
        encoding="utf-8",
    )
    (trust / "install_offline.sh").chmod(0o755)
    (trust / "profiles.py").write_text("# admin-installed profiles.py\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin-installed lib\n", encoding="utf-8")

    (tmp_path / "unit_src").write_text("[Unit]\nDescription=u\n", encoding="utf-8")
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    (tmp_path / "dpkg").mkdir()
    (tmp_path / "dpkg" / "lock-frontend").touch()
    (tmp_path / "dpkg" / "lock").touch()
    (tmp_path / "run").mkdir()
    (tmp_path / "tmp").mkdir()
    _make_shims(tmp_path)

    # --- simulate the outer dpkg holding its fcntl locks ----------------------
    holder = tmp_path / "holder.py"
    holder.write_text(
        "import fcntl, os, sys, time\n"
        "fds = []\n"
        f'for p in ("{tmp_path}/dpkg/lock-frontend", "{tmp_path}/dpkg/lock"):\n'
        '    fh = open(p, "r+")\n'
        "    fcntl.lockf(fh, fcntl.LOCK_EX)\n"
        "    fds.append(fh)\n"
        f'while not os.path.exists("{tmp_path}/release-dpkg"):\n'
        "    time.sleep(0.05)\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    holder_proc = subprocess.Popen(  # noqa: S603 - fixed args, local helper
        [sys.executable, str(holder)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        script = _deferred_sandbox_postinst(tmp_path)
        env = dict(os.environ)
        env["PATH"] = f"{tmp_path / 'shims'}{os.pathsep}{env.get('PATH', '')}"
        proc = subprocess.run(  # noqa: S603
            ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
        )
        assert proc.returncode == 0, f"postinst failed: {proc.stderr}\n{proc.stdout}"
        assert "verifying the unpacked payload via the trusted verifier" in proc.stdout
        assert "deferring" in proc.stdout or "runs after dpkg exits" in proc.stdout
        assert "postinst complete: payload VERIFIED" in proc.stdout
        # Synchronous verification ran while the locks were still held.
        assert (tmp_path / "verify-marker").read_text() == "verified\n"
        status = tmp_path / "status"
        assert status.read_text().strip() in {"running", "deferred", "success"}

        # Release the "outer dpkg" and wait for the deferred worker to finish.
        (tmp_path / "release-dpkg").write_text("go\n")
        marker = tmp_path / "install-marker"
        for _ in range(600):
            if marker.exists():
                break
            time_sleep(0.1)
        assert marker.exists(), "deferred worker never ran the installer after the locks were released"
        for _ in range(600):
            if status.read_text().strip() == "success":
                break
            time_sleep(0.1)
        assert status.read_text().strip() == "success", (tmp_path / "log").read_text()
    finally:
        (tmp_path / "release-dpkg").write_text("done\n")
        holder_proc.wait(timeout=30)

    # Worker installed unit + config only after the (stub) installer succeeded.
    assert (tmp_path / "unit_dst").read_text() == "[Unit]\nDescription=u\n"
    assert (tmp_path / "config_dir" / "config.yaml").read_text() == "# template\n"
    # P2 (reversed): the admin trust dir was used AS-IS — every file
    # byte-identical, nothing completed from the deb-shipped (inert) copy.
    assert (trust / "lib" / "os_packages.sh").read_text() == "# admin-installed lib\n"
    assert (trust / "profiles.py").read_text() == "# admin-installed profiles.py\n"
    assert (trust / "verify_bundle.py").read_text().startswith("import pathlib")
    assert (trust / "install_offline.sh").read_text().startswith("#!/bin/bash")
    # The worker cleaned up its own script copy.
    leftovers = list((tmp_path / "tmp").glob("udbmcp-postinst-worker.*"))
    assert leftovers == [], "worker script must delete itself"


def time_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)
