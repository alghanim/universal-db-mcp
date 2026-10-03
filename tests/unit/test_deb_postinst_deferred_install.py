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

P3 (masked-failure surface, completeness-critic gap 9): dpkg marks the
package installed ('ii') as soon as the deferred-mode postinst exits 0,
while the real install still runs in the detached worker — on worker
failure dpkg's database cannot be corrected retroactively (dpkg has already
exited; there is no safe out-of-band downgrade of a completed 'ii'). The
failure is therefore surfaced where it operationally binds:
  - the worker writes 'failed' to the status file + log and never installs
    the unit or enables the service on failure;
  - BEFORE spawning the worker, postinst installs a systemd ExecStartPre
    guard drop-in (/etc/systemd/system/universal-db-mcp.service.d/
    deferred-install-guard.conf) that refuses to start the service unless
    the status file says 'success' — fail closed on every other state
    ('deferred', 'running', 'failed', garbage); a missing status file means
    nothing was deferred (synchronous installs complete inside postinst),
    so the start is allowed;
  - the worker records 'success' BEFORE `systemctl enable --now` (the
    guard-gated start triggered by enable must already see 'success'; the
    only step after the write is the best-effort enable call);
  - the synchronous path clears a stale status file, so a guard left by a
    previous deferred attempt cannot block a freshly completed install.
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
    # Split the RAW text on the step-marker comments (they are comments, so
    # they are gone from `code`), then strip comments from the block.
    step1 = _executable_lines(text.split("# --- step 1", 1)[1].split("# --- step 2", 1)[0])
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


# ------------------------------------------- P3 structural (masked-failure surface)


@_POSIX
def test_deferred_branch_installs_guard_drop_in_before_spawning_worker() -> None:
    """P3: the deferred branch must install the ExecStartPre guard drop-in
    SYNCHRONOUSLY (a failure aborts the configure step) and BEFORE spawning
    the worker — so even a worker that dies before writing anything leaves
    the service gated. The guard must fail closed: only an explicit
    'success' status allows a start; every other state (and the diagnostic)
    refuses it, while a missing status file (synchronous install) allows."""
    code = _executable_lines(_read_postinst())
    guard_at = code.index('cat > "$UNIT_DROPIN"')
    spawn_at = code.index("setsid --fork")
    assert guard_at < spawn_at, "guard drop-in must be installed before the worker is spawned"
    assert 'install -d -m 755' in code[guard_at - 200 : guard_at], "guard dir must be created"
    # The drop-in block (between the cat and the spawn) carries the guard.
    block = code[guard_at:spawn_at]
    assert "ExecStartPre=/bin/sh -ec" in block
    assert 'if [ -f "$STATUS" ]' in block, "a missing status file (sync install) must allow the start"
    assert 'grep -qx success "$STATUS"' in block, "only an explicit 'success' may allow the start"
    assert "exit 1" in block, "any other status must refuse the start (fail closed)"
    assert "refusing to start" in block, "the refusal must carry a diagnostic"
    # After a deferred FAILURE dpkg already holds the package as configured, so
    # `dpkg --configure` answers "already installed and configured": the only
    # retry that respawns the worker is a fresh `dpkg -i` (code review, 2026-09-17).
    assert "dpkg -i <the release .deb>" in block, "the diagnostic must point at the retry that works"
    assert "dpkg --configure universal-db-mcp" not in block, "dpkg --configure is a dead end after a deferred failure"
    # The guard is live immediately: postinst reloads the manager (guarded,
    # container-safe) right after installing the drop-in.
    assert code.index("systemctl daemon-reload", guard_at) < spawn_at


@_POSIX
def test_worker_records_success_before_enabling_the_service() -> None:
    """P3 ordering inside the worker: 'success' must hit the status file
    BEFORE `systemctl enable --now` — the start that enable triggers is
    gated by the ExecStartPre guard, which only passes on 'success'. Every
    step that can fail the worker (installer, unit, config) runs before the
    write under set -eu; only the best-effort enable call follows it."""
    worker = _executable_lines(_worker_script(_read_postinst()))
    success_at = worker.index('echo success > "$STATUS"')
    enable_at = worker.index("systemctl enable --now")
    installer_at = worker.index('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"')
    assert installer_at < success_at < enable_at


@_POSIX
def test_sync_path_clears_stale_deferred_status() -> None:
    """The synchronous path must clear a stale deferred-install status file
    (possibly 'failed' from a previous attempt) BEFORE it restarts or enables
    the service.

    Corrected 2026-09-15: the clear used to run at the very end, after
    `enable --now`, so this install's own service start was refused by the
    guard drop-in describing an install that had already finished. The
    install itself is complete by then - everything that can fail ran above
    under set -eu - so clearing first is safe and is what makes the start
    work."""
    code = _executable_lines(_read_postinst())
    clear_at = code.index('rm -f -- "$STATUS"')
    sync_enable_at = code.rindex("systemctl enable --now")
    sync_installer_calls = [
        m.start() for m in re.finditer(re.escape('bash "$TRUST_DIR/install_offline.sh" "$BUNDLE" "$TARGET"'), code)
    ]
    assert sync_installer_calls[-1] < clear_at < sync_enable_at, (
        "the stale-status clear must follow the install and precede the service start"
    )


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
        # The unit-hash record lives under /var/lib on a real target (root,
        # coreutils guaranteed); in the sandbox it must land in tmp_path.
        line = line.replace(
            "mkdir -p /var/lib/universal-db-mcp",
            f"mkdir -p {tmp_path / 'var_lib_universal_db_mcp'}",
        )
        line = re.sub(r"-o root -g root ", "", line)
        line = re.sub(r"-o udbmcp -g udbmcp ", "", line)
        rewritten.append(line)
    script = tmp_path / "postinst_sbx.sh"
    script.write_text("#!/bin/bash\n" + "\n".join(rewritten) + "\n", encoding="utf-8")
    return script


def _make_shims(tmp_path: Path) -> None:
    """Sandbox shims: systemctl always fails (exercises both guarded call
    sites) and logs every invocation, flock always succeeds (single-flight
    is covered structurally), setsid --fork backgrounds the worker so it
    outlives the postinst."""
    shim = tmp_path / "shims"
    shim.mkdir(exist_ok=True)
    calls = tmp_path / "systemctl-calls.log"
    (shim / "sbx-systemctl").write_text(
        "#!/bin/sh\n" f'printf "%s\\n" "$*" >> "{calls}"\n' "exit 1\n", encoding="utf-8"
    )
    (shim / "sbx-flock").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    # coreutils' sha256sum exists on the deb target (Essential) but not on the
    # macOS test host: shim it onto shasum(1) so the unit-hash record path is
    # exercised on both.
    (shim / "sha256sum").write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n', encoding="utf-8")
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
    (bundle / "manifest.json").write_text('{"release_seq": 5}\n', encoding="utf-8")  # every verified bundle has one
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
        # The postinst's proof gate requires the verifier's explicit
        # PASSED line; exit 0 alone is what a truncated verifier yields.
        'print("bundle verification PASSED")\n'
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
        'cp "$1/manifest.json" "$2/manifest.json"\n'  # the real installer publishes the verified manifest
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
    # The worker cleaned up its own script copy. It deletes itself in its EXIT
    # trap, after writing 'success' and running the (shimmed) systemctl calls,
    # so give it a moment to finish instead of racing it.
    for _ in range(100):
        leftovers = list((tmp_path / "tmp").glob("udbmcp-postinst-worker.*"))
        if not leftovers:
            break
        time_sleep(0.1)
    assert leftovers == [], "worker script must delete itself"


def _extract_guard_command(dropin: Path) -> str:
    """Pull the shell payload out of the guard drop-in's ExecStartPre line."""
    for line in dropin.read_text(encoding="utf-8").splitlines():
        if line.startswith("ExecStartPre="):
            prefix = "ExecStartPre=/bin/sh -ec '"
            assert line.startswith(prefix), f"unexpected ExecStartPre form: {line}"
            assert line.endswith("'"), f"unexpected ExecStartPre form: {line}"
            return line[len(prefix) : -1]
    raise AssertionError("guard drop-in carries no ExecStartPre")


@_POSIX
def test_worker_failure_leaves_guard_block_service_and_no_enable(tmp_path: Path) -> None:
    """P3 end-to-end, the critic's masked-failure scenario: an upgrade where
    a previous install left the unit in /etc/systemd/system, the new deferred
    worker FAILS (stub installer exits 1 after the dpkg locks free). Then:
    - the status file ends 'failed' and the log records it (nothing
      unverified executed);
    - the admin unit is untouched and the service was never enabled — but
      dpkg still shows 'ii' (postinst exited 0), which is exactly why the
      guard exists;
    - the guard drop-in (installed synchronously by postinst before the
      spawn) EXISTS and its ExecStartPre command refuses to start on
      'failed'/'running'/'deferred'/garbage status, allows it once the file
      says 'success' or is absent (sync install completed)."""
    bundle = tmp_path / "bundle"
    (bundle / "os-packages").mkdir(parents=True)
    (bundle / "os-packages" / "dummy_1.0_amd64.deb").write_bytes(b"deb")
    (bundle / "manifest.json").write_text('{"release_seq": 5}\n', encoding="utf-8")  # every verified bundle has one
    (bundle / "config-templates").mkdir()
    (bundle / "config-templates" / "config.yaml").write_text("# template\n", encoding="utf-8")
    (bundle / "operations").mkdir()
    (bundle / "operations" / "universal-db-mcp.service").write_text("[Unit]\n", encoding="utf-8")

    tools = tmp_path / "trusted_tools"
    (tools / "lib").mkdir(parents=True)
    (tools / "verify_bundle.py").write_text("# deb-shipped verifier\n", encoding="utf-8")
    (tools / "profiles.py").write_text("# deb-shipped profiles\n", encoding="utf-8")
    (tools / "install_offline.sh").write_text("# deb-shipped installer\n", encoding="utf-8")
    (tools / "lib" / "os_packages.sh").write_text("# deb-shipped lib\n", encoding="utf-8")

    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text(
        "import pathlib, sys\n"
        f'pathlib.Path("{tmp_path}/verify-marker").write_text("verified\\n")\n'
        # The postinst's proof gate requires the verifier's explicit
        # PASSED line; exit 0 alone is what a truncated verifier yields.
        'print("bundle verification PASSED")\n'
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    (trust / "install_offline.sh").write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")  # the FAILURE
    (trust / "install_offline.sh").chmod(0o755)
    (trust / "profiles.py").write_text("# admin-installed profiles.py\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# admin-installed lib\n", encoding="utf-8")

    # Upgrade scenario: a previous install left an (admin-owned) unit in place.
    (tmp_path / "unit_dst").write_text("# admin-customized unit\n", encoding="utf-8")
    (tmp_path / "pubkey").write_text("-----BEGIN PUBLIC KEY-----\nsbx\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    (tmp_path / "run").mkdir()
    (tmp_path / "tmp").mkdir()
    _make_shims(tmp_path)

    script = _deferred_sandbox_postinst(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{tmp_path / 'shims'}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(  # noqa: S603 - fixed args, local helper
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )
    # postinst exits 0 => dpkg marks the package installed ('ii') even though
    # the real install is still pending/failed — the masked-failure surface.
    assert proc.returncode == 0, f"postinst failed: {proc.stderr}\n{proc.stdout}"
    assert "deferred-install guard installed" in proc.stdout

    # Wait for the worker to fail and record it.
    status = tmp_path / "status"
    for _ in range(600):
        if status.exists() and status.read_text().strip() == "failed":
            break
        time_sleep(0.1)
    assert status.read_text().strip() == "failed", (tmp_path / "log").read_text()

    # Fail closed at the service level: the admin unit was never touched and
    # the service was never enabled (no `enable` among the systemctl calls).
    assert (tmp_path / "unit_dst").read_text() == "# admin-customized unit\n"
    calls = (tmp_path / "systemctl-calls.log").read_text(encoding="utf-8")
    assert "enable" not in calls, f"service must not be enabled after a failed install: {calls}"

    # The guard drop-in is in place and binds the service to the status file.
    dropin = tmp_path / "unit_dropin_dir" / "deferred-install-guard.conf"
    assert dropin.exists(), "postinst must install the guard even though the worker failed"
    guard = _extract_guard_command(dropin)

    def run_guard() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed args, guard extracted from the postinst under test
            ["/bin/sh", "-ec", guard], capture_output=True, text=True, timeout=30
        )

    # Fail closed on every non-success state...
    for bad in ("failed", "running", "deferred", "garbage"):
        status.write_text(f"{bad}\n", encoding="utf-8")
        res = run_guard()
        assert res.returncode != 0, f"guard must refuse to start on status {bad!r}"
        assert "refusing to start" in res.stderr
    # ...and allow a start only on explicit success or no deferred state.
    status.write_text("success\n", encoding="utf-8")
    assert run_guard().returncode == 0
    status.unlink()
    assert run_guard().returncode == 0


def time_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


# ----------------------------- CGR#84: audit files an older release left owned by root


def _as_this_account(script: Path) -> str:
    """The repair's root-owned predicate and service account pointed at the test account: a
    non-root test cannot create root-owned files, so the files the test account owns stand in."""
    import pwd

    me = pwd.getpwuid(os.getuid()).pw_name
    text = script.read_text(encoding="utf-8")
    assert text.count("\nROOT = 0\n") == 1 and text.count('"$LOG_DIR" udbmcp') == 1
    text = text.replace("\nROOT = 0\n", f"\nROOT = {os.getuid()}\n")
    text = text.replace('"$LOG_DIR" udbmcp', f'"$LOG_DIR" {me}').replace("id udbmcp ", f"id {me} ")
    script.write_text(text, encoding="utf-8")
    return me


@_POSIX
def test_upgrade_hands_root_owned_audit_files_back_to_the_service_account(tmp_path: Path) -> None:
    """A root site check of an older release could leave audit.jsonl, its .lock sidecar or a
    rotated backup owned by root; the service then fails every audited call (audit_fail_closed).
    The postinst hands back only regular, single-link audit files: the service account owns the
    directory, so a symlink or a second link to another file is never chowned."""
    bundle = tmp_path / "bundle"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "config-templates" / "config.yaml").write_text("# template\n", encoding="utf-8")
    trust = tmp_path / "trust_dir"
    (trust / "lib").mkdir(parents=True)
    (trust / "verify_bundle.py").write_text("print('bundle verification PASSED')\n", encoding="utf-8")
    (trust / "install_offline.sh").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    (trust / "profiles.py").write_text("# profiles\n", encoding="utf-8")
    (trust / "lib" / "os_packages.sh").write_text("# lib\n", encoding="utf-8")
    (tmp_path / "unit_src").write_text("[Unit]\n", encoding="utf-8")
    (tmp_path / "pubkey").write_text("key\n", encoding="utf-8")
    logs = tmp_path / "log_dir"
    logs.mkdir()
    for name in ("audit.jsonl", "audit.jsonl.lock", "audit.jsonl.1", "server.log"):
        (logs / name).write_text("x\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("not an audit file\n", encoding="utf-8")
    os.link(elsewhere, logs / "audit.jsonl.2")  # a second link to another file
    (logs / "audit.jsonl.3").symlink_to(elsewhere)
    (logs / "audit.jsonl.4").mkdir()
    (logs / "audit.jsonl.1").chmod(0o444)  # read-only for its owner, but the writer opens it read-write
    # a link to a file only root may change (/etc/sudoers): root's, with one link, so only
    # O_NOFOLLOW keeps the repair from handing it to the account that made the link
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    sudoers.chmod(0o440)
    (logs / "audit.jsonl.9").symlink_to(sudoers)
    _make_shims(tmp_path)
    script = _deferred_sandbox_postinst(tmp_path)
    me = _as_this_account(script)
    env = {**os.environ, "PATH": f"{tmp_path / 'shims'}{os.pathsep}{os.environ.get('PATH', '')}"}
    proc = subprocess.run(  # noqa: S603 - sandboxed copy of a repo script
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    handed = re.findall(rf"^==> {re.escape(str(logs))}/(\S+) was owned by root; handed back to {me}$",
                        proc.stdout, flags=re.MULTILINE)
    assert handed == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.lock"], proc.stdout
    assert (logs / "audit.jsonl.1").stat().st_mode & 0o777 == 0o600  # the audit writer's own mode
    assert sudoers.stat().st_mode & 0o777 == 0o440 and sudoers.stat().st_nlink == 1
    # the repair runs before the installer and the service start
    assert proc.stdout.index("handed back") < proc.stdout.index("postinst complete")


@_POSIX
def test_audit_ownership_repair_is_skipped_before_the_service_account_exists(tmp_path: Path) -> None:
    """A first install has neither the account nor the log directory: nothing to hand back."""
    code = _executable_lines(_read_postinst())
    repair = code.index('python3 -I -S - "$LOG_DIR" udbmcp')
    guard = code.rindex('if [ -d "$LOG_DIR" ] && id udbmcp >/dev/null 2>&1; then', 0, repair)
    assert code[guard:repair].count("\n") == 1, "the guard must open the block the repair runs in"
    # best effort: a failed repair warns, it never aborts the configure step
    assert code[repair:].split("\n", 1)[0].endswith(
        '|| echo "WARNING: could not hand root-owned audit files in $LOG_DIR back to the service account" >&2'
    )
