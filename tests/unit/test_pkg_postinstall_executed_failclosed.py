"""EXECUTED fail-closed regression tests for ``packaging/pkg/postinstall``.

Gap 13 (completeness critic, /tmp/gaps_final.json): pkg postinstall is the
macOS verify-before-execute gate, yet it was guarded only by regex content
gates (test_pkg_packaging.py, test_pkg_postinstall_hardening.py). A mutant
that swallowed the verifier's fatal ``|| { fail ... }`` branch passed every
content gate while letting a tampered payload reach service-account
provisioning and a pip install from an unverified wheelhouse.

This file EXECUTES postinstall in a sandbox -- the extract-and-run pattern of
test_hardening_gates.py::test_p0_installer_refuses_to_run_from_inside_bundle,
extended the way the deb tests (test_deb_packaging.py) and the sibling
test_pkg_postinstall_functional_failclosed.py do:

- hardcoded path constants (PREFIX, CONFIG_DIR, STATE_DIR, LOG_DIR, PLIST and
  the two CPython 3.12 candidate paths) are sed-rewritten into ``tmp_path``;
  the trust inputs need no rewrite: postinstall reads them from
  ``UDBMCP_VERIFIER``/``UDBMCP_RELEASE_PUBKEY`` (never from the bundle);
- the trusted verifier is a stub under tmp_path, OUTSIDE the bundle;
- ``dscl``/``launchctl``/``install``/``python3``/``python312-sandbox`` are PATH
  shims that log every invocation: the real macOS directory service, launchd
  and root-owned ``install -o root`` are never touched, and the suite runs
  unprivileged (no root, no real install). ``python3`` is a TRIPWIRE: since the
  interpreter-selection fix, postinstall must never PATH-search python3, so
  any PYTHON3 log line fails the positive control. The verifier runs under the
  ``python312-sandbox`` shim (the rewritten preinstall-approved candidate).

Coverage split vs the sibling file (test_pkg_postinstall_functional_failclosed,
committed with the feature): that file owns the four refusal cases plus the
tight fatal-branch text gate; THIS file re-pins the fatal branch (mutation-kill
anchor), adds the two refusals the sibling does not exercise -- a pubkey
shipped INSIDE the bundle (trust invariant 2, postinstall's second containment
``case``) and a bundle payload missing manifest.json -- and adds the positive
control the sibling's failing shims cannot express: with a verifier that
prints PASSED, postinstall must actually REACH provisioning (dscl account
creation, hashed offline pip install into the venv, smoke check, launchctl
bootstrap) -- proving the gate is verify-then-provision, not fail-always.

Pure stdlib + pytest; POSIX-only like the sibling pkg tests.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess  # noqa: S404 - executes the sandboxed postinstall copy only
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="macOS .pkg packaging is POSIX-only"
)

PROJECT = Path(__file__).resolve().parents[2]
POSTINSTALL = PROJECT / "packaging" / "pkg" / "postinstall"

# Mutation-kill anchors: these are the exact lines whose absence/regression the
# executed tests below detect behaviorally; the text gates fail fast and name
# the regression if the producer script is ever restructured.
_FATAL_VERIFY_BRANCH = re.compile(
    r'\$VEXEC "\$VERIFIER" --bundle "\$BUNDLE" --pubkey "\$PUBKEY"\s*\|\|\s*\{\s*\n'
    r'\s*fail "bundle verification FAILED'
)
_PUBKEY_INSIDE_BUNDLE_REFUSAL = re.compile(
    r'fail "refusing to verify with a pubkey shipped inside the bundle'
)
_VERIFIER_INSIDE_BUNDLE_REFUSAL = re.compile(
    r'fail "refusing to verify with a verifier inside the bundle'
)

_PATH_REWRITES = [
    (r'^PREFIX="/usr/local/universal-db-mcp"$', 'PREFIX="{prefix}"'),
    (r'^CONFIG_DIR="/etc/universal-db-mcp"$', 'CONFIG_DIR="{etc}"'),
    (r'^STATE_DIR="/var/lib/universal-db-mcp"$', 'STATE_DIR="{state}"'),
    (r'^LOG_DIR="/var/log/universal-db-mcp"$', 'LOG_DIR="{log}"'),
    (r'^PLIST="/Library/LaunchDaemons/com\.udbmcp\.server\.plist"$', 'PLIST="{plist}"'),
    # PATH: the sandbox shim dir must win over /usr/bin, where the REAL dscl /
    # launchctl / install live — otherwise the positive control would touch the
    # host's directory service (or fail on its root-only ownership flags).
    (
        r'^PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:\$PATH"$',
        'PATH="{shim}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"',
    ),
    # The interpreter candidates are absolute paths with no env override: point
    # both at the sandbox PY shim (the venv/pip/smoke steps run through it).
    (
        r'^FRAMEWORK_PY="/Library/Frameworks/Python\.framework/Versions/3\.12/bin/python3"$',
        'FRAMEWORK_PY="{pyshim}"',
    ),
    (r'^USR_LOCAL_PY="/usr/local/bin/python3"$', 'USR_LOCAL_PY="{pyshim}"'),
    # The GUI app assembly must land inside the sandbox, not the real
    # /Applications.
    (
        r'^APP_DIR="/Applications/Configure UniversalDB MCP\.app"$',
        'APP_DIR="{app_dir}"',
    ),
]


def _require_script() -> str:
    assert POSTINSTALL.is_file(), f"missing producer file: {POSTINSTALL}"
    return POSTINSTALL.read_text(encoding="utf-8")


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _sandbox_postinstall(tmp_path: Path) -> Path:
    """Copy postinstall with its hardcoded paths rewritten into tmp_path."""
    text = _require_script()
    dirs = {
        "prefix": str(tmp_path / "prefix"),
        "etc": str(tmp_path / "etc"),
        "state": str(tmp_path / "state"),
        "log": str(tmp_path / "log"),
        "plist": str(tmp_path / "com.udbmcp.server.plist"),
        "shim": str(tmp_path / "shim-bin"),
        "pyshim": str(tmp_path / "shim-bin" / "python312-sandbox"),
        "app_dir": str(tmp_path / "applications" / "Configure UniversalDB MCP.app"),
    }
    for pattern, replacement in _PATH_REWRITES:
        new_text, n = re.subn(pattern, replacement.format(**dirs), text, flags=re.MULTILINE)
        assert n == 1, f"path-rewrite pattern matched {n} times (expected 1): {pattern}"
        text = new_text
    script = tmp_path / "postinstall_sbx.sh"
    script.write_text(text, encoding="utf-8")
    _make_executable(script)
    return script


def _write_shim(bin_dir: Path, name: str, body: str) -> Path:
    shim = bin_dir / name
    shim.write_text(body, encoding="utf-8")
    _make_executable(shim)
    return shim


def _build_shims(tmp_path: Path) -> Path:
    """PATH shims so the sandbox never touches the host: dscl/launchctl/install
    log and simulate; python3 is a tripwire (postinstall must never PATH-search
    it — any PYTHON3 log line fails the executed tests); python312-sandbox is
    the rewritten preinstall-approved candidate: it emulates the CPython 3.12
    prerequisite checks and `python -m venv` (skipping options such as
    --copies), is the venv python, and executes the trusted verifier stub via
    UDBMCP_SANDBOX_PYTHON."""
    bin_dir = tmp_path / "shim-bin"
    bin_dir.mkdir(exist_ok=True)
    actions = tmp_path / "shim-actions.log"  # every shimmed invocation, in order

    _write_shim(
        bin_dir,
        "python3",
        "#!/bin/bash\n"
        '# TRIPWIRE: postinstall must never PATH-search python3 (the verifier\n'
        '# runs under the preinstall-validated candidate). Any PYTHON3 log line\n'
        '# fails the executed tests below.\n'
        'printf \'PYTHON3 %s\\n\' "$*" >> "' + str(actions) + '"\n'
        'if [ -z "${UDBMCP_SANDBOX_PYTHON:-}" ]; then\n'
        '  echo "sandbox python3 shim: UDBMCP_SANDBOX_PYTHON not set" >&2; exit 99\n'
        "fi\n"
        'exec "${UDBMCP_SANDBOX_PYTHON}" "$@"\n',
    )

    _write_shim(
        bin_dir,
        "python312-sandbox",
        "#!/bin/bash\n"
        "# The rewritten preinstall-approved CPython 3.12 candidate: runs the\n"
        "# 3.12/ensurepip `-c` prerequisite probes, builds the venv (emulated,\n"
        "# `--copies` and other options skipped) and EXECUTES THE TRUSTED\n"
        "# VERIFIER STUB (postinstall runs the verifier under this interpreter,\n"
        "# never a PATH-searched python3) by delegating to the real backend.\n"
        'printf \'PY %s\\n\' "$*" >> "' + str(actions) + '"\n'
        'if [ "$1" = "-c" ]; then exit 0; fi   # version/ensurepip checks pass\n'
        'if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then\n'
        "  shift 2\n"
        '  vdir=""\n'
        '  while [ $# -gt 0 ]; do\n'
        '    case "$1" in\n'
        '      -*) : ;;                     # venv options (e.g. --copies)\n'
        '      *) [ -z "$vdir" ] && vdir="$1" ;;\n'
        "    esac\n"
        "    shift\n"
        "  done\n"
        '  if [ -z "$vdir" ]; then\n'
        '    echo "python312-sandbox: no venv directory in $*" >&2; exit 99\n'
        "  fi\n"
        '  mkdir -p "$vdir/bin"\n'
        "  cat > \"$vdir/bin/python\" <<VENV_EOF\n"
        "#!/bin/bash\n"
        # the \$* below must survive the unquoted heredoc literally, so the
        # venv python logs ITS OWN args, not the venv-creation args
        "printf 'VENV-PY %s\\n' \"\\$*\" >> \"" + str(actions) + '"\n'
        "exit 0\n"
        "VENV_EOF\n"
        '  chmod +x "$vdir/bin/python"\n'
        "  exit 0\n"
        "fi\n"
        '# anything else is the verifier stub executing under this interpreter:\n'
        '# delegate so the stub\'s exit code/output behave.\n'
        'if [ -z "${UDBMCP_SANDBOX_PYTHON:-}" ]; then\n'
        '  echo "sandbox python312-sandbox shim: UDBMCP_SANDBOX_PYTHON not set" >&2; exit 99\n'
        "fi\n"
        'exec "${UDBMCP_SANDBOX_PYTHON}" "$@"\n',
    )

    _write_shim(
        bin_dir,
        "dscl",
        "#!/bin/bash\n"
        "# Stateful dscl emulator: -create records the node, -read succeeds only\n"
        "# for recorded nodes (so postinstall's final account check passes).\n"
        'printf \'DSCL %s\\n\' "$*" >> "' + str(actions) + '"\n'
        'STATE="' + str(tmp_path / "dscl-created") + '"\n'
        'if [ "$1" = "." ] && [ "$2" = "-list" ]; then exit 0; fi\n'
        'if [ "$1" = "." ] && [ "$2" = "-read" ]; then\n'
        '  if [ -f "$STATE" ] && grep -qxF "$3" "$STATE"; then\n'
        '    echo "PrimaryGroupID: 421"; exit 0\n'
        "  fi\n"
        "  exit 1\n"
        "fi\n"
        'if [ "$1" = "." ] && [ "$2" = "-create" ]; then\n'
        '  echo "$3" >> "$STATE"; exit 0\n'
        "fi\n"
        "exit 0\n",
    )

    _write_shim(
        bin_dir,
        "launchctl",
        "#!/bin/bash\n"
        'printf \'LAUNCHCTL %s\\n\' "$*" >> "' + str(actions) + '"\n'
        'case "$1" in\n'
        "  print) exit 1 ;;      # daemon not bootstrapped yet\n"
        "  bootstrap | bootout) exit 0 ;;\n"
        "esac\n"
        "exit 0\n",
    )

    _write_shim(
        bin_dir,
        "install",
        "#!/bin/bash\n"
        "# install(1) without root: -d creates dirs, otherwise cp src dst;\n"
        "# -m/-o/-g are logged and ignored (the sandbox is unprivileged).\n"
        'printf \'INSTALL %s\\n\' "$*" >> "' + str(actions) + '"\n'
        "dirs=0; paths=()\n"
        "while [ $# -gt 0 ]; do\n"
        '  case "$1" in\n'
        '    -d) dirs=1 ;;\n'
        '    -m | -o | -g) shift ;;\n'
        "    -*) : ;;\n"
        '    *) paths+=("$1") ;;\n'
        "  esac\n"
        "  shift\n"
        "done\n"
        'if [ "$dirs" = 1 ]; then mkdir -p "${paths[@]}"; else\n'
        '  src="${paths[0]}"; dst="${paths[${#paths[@]}-1]}"\n'
        '  mkdir -p "$(dirname "$dst")"; cp "$src" "$dst"\n'
        "fi\n",
    )
    return bin_dir


def _actions(tmp_path: Path) -> list[str]:
    log = tmp_path / "shim-actions.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _build_bundle(tmp_path: Path, *, manifest: bool = True) -> Path:
    """Minimal unpacked payload at <prefix>/bundle (the pkg postinstall target)."""
    bundle = tmp_path / "prefix" / "bundle"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "requirements").mkdir(parents=True)
    (bundle / "wheelhouse").mkdir(parents=True)
    if manifest:
        (bundle / "manifest.json").write_text("{}\n", encoding="utf-8")
    (bundle / "config-templates" / "config.yaml").write_text("# sandbox template\n", encoding="utf-8")
    (bundle / "requirements" / "runtime.lock").write_text("# sandbox lock\n", encoding="utf-8")
    # The GUI app script is payload material staged BESIDE the bundle (by
    # build_pkg.sh) at <prefix>/share/; the app-assembly step fails closed
    # without it.
    share = tmp_path / "prefix" / "share"
    share.mkdir(parents=True, exist_ok=True)
    (share / "configure_agents_app.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return bundle


def _verifier_stub(tmp_path: Path, name: str, *, exit_code: int, output: str = "") -> Path:
    stub = tmp_path / "trust" / name
    stub.parent.mkdir(parents=True, exist_ok=True)
    body = "import sys\n"
    if output:
        body += f"print({output!r})\n"
    if exit_code:
        body += 'print("SIGNATURE MISMATCH: sandbox tampered payload", file=sys.stderr)\n'
    body += f"sys.exit({exit_code})\n"
    stub.write_text(body, encoding="utf-8")
    return stub


def _pubkey_stub(tmp_path: Path, *, name: str = "release.pub.pem") -> Path:
    key = tmp_path / "keys" / name
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(
        "-----BEGIN PUBLIC KEY-----\nSANDBOX-NOT-A-REAL-KEY\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )
    return key


def _run_postinstall(
    tmp_path: Path,
    bundle: Path,
    *,
    pubkey: Path | None,
    verifier: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["UDBMCP_SANDBOX_PYTHON"] = sys.executable  # the python3 shim's real backend
    env["UDBMCP_VERIFIER"] = str(verifier or (tmp_path / "trust" / "verify_bundle.py"))
    if pubkey is not None:
        env["UDBMCP_RELEASE_PUBKEY"] = str(pubkey)
    else:
        env.pop("UDBMCP_RELEASE_PUBKEY", None)
    env["PATH"] = f"{tmp_path / 'shim-bin'}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    script = _sandbox_postinstall(tmp_path)
    return subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=120, env=env
    )


# --------------------------------------------------------------------------
# text gates: pin the exact lines the executed tests detect behaviorally
# --------------------------------------------------------------------------


def test_fatal_verifier_branch_is_pinned() -> None:
    assert _FATAL_VERIFY_BRANCH.search(_require_script()), (
        "postinstall must keep the fatal `|| { fail \"bundle verification FAILED ...\" }` "
        "branch on the verifier invocation; swallowing it (e.g. into `|| echo`) lets an "
        "unverified payload proceed into provisioning"
    )


def test_in_bundle_trust_refusals_are_pinned() -> None:
    text = _require_script()
    assert _VERIFIER_INSIDE_BUNDLE_REFUSAL.search(text), "in-bundle verifier refusal missing"
    assert _PUBKEY_INSIDE_BUNDLE_REFUSAL.search(text), "in-bundle pubkey refusal missing"


# --------------------------------------------------------------------------
# executed fail-closed cases (no root, no real install)
# --------------------------------------------------------------------------


def test_executed_tampered_payload_aborts_before_provisioning(tmp_path: Path) -> None:
    """Trust invariant 1, executed: verifier exit 3 (tampered payload) must
    abort with the canonical diagnostic BEFORE any provisioning shim fires and
    without building a venv from the unverified wheelhouse."""
    bundle = _build_bundle(tmp_path)
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=3)
    _pubkey_stub(tmp_path)
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"tampered payload must fail closed:\n{out}"
    assert "FAIL: bundle verification FAILED" in out, f"canonical diagnostic required:\n{out}"
    assert "SIGNATURE MISMATCH" in out, "the sandbox verifier's complaint must be surfaced"
    actions = _actions(tmp_path)
    assert not any(
        ln.startswith(("DSCL", "LAUNCHCTL", "VENV-PY", "PY -m venv", "INSTALL")) for ln in actions
    ), f"nothing may be provisioned after a failed verification:\n{actions}"
    # interpreter-selection fix: even the verifier must not run via a
    # PATH-searched python3 (the PYTHON3 shim is a tripwire)
    assert not any(ln.startswith("PYTHON3") for ln in actions), (
        f"the verifier must run under the preinstall-validated interpreter, "
        f"never a PATH-searched python3:\n{actions}"
    )
    assert not (tmp_path / "prefix" / "venv").exists(), "no venv from an unverified payload"


def test_executed_missing_verifier_refuses(tmp_path: Path) -> None:
    _build_bundle(tmp_path)
    _pubkey_stub(tmp_path)
    _build_shims(tmp_path)
    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(tmp_path / "trust" / "absent-verify_bundle.py")  # never created
    env["UDBMCP_RELEASE_PUBKEY"] = str(_pubkey_stub(tmp_path))
    env["PATH"] = f"{tmp_path / 'shim-bin'}:/usr/bin:/bin"

    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(_sandbox_postinstall(tmp_path))],
        capture_output=True, text=True, timeout=120, env=env,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"missing verifier must fail closed:\n{out}"
    assert "trusted verifier not found" in out, f"canonical diagnostic required:\n{out}"
    assert _actions(tmp_path) == []


def test_executed_missing_pubkey_refuses_without_in_bundle_fallback(tmp_path: Path) -> None:
    """Trust invariant 2, executed: the admin pubkey is absent (trust bootstrap
    skipped) and a decoy key sits INSIDE the bundle — postinstall must refuse,
    never fall back to the attacker-controlled key."""
    bundle = _build_bundle(tmp_path)
    (bundle / "release.pub.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nIN-BUNDLE-DECOY\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    _build_shims(tmp_path)

    env = dict(os.environ)
    env["UDBMCP_VERIFIER"] = str(tmp_path / "trust" / "verify_bundle.py")
    env["UDBMCP_RELEASE_PUBKEY"] = str(tmp_path / "keys" / "absent.pub.pem")  # never created
    env["PATH"] = f"{tmp_path / 'shim-bin'}:/usr/bin:/bin"
    proc = subprocess.run(  # noqa: S603 - fixed args, sandboxed copy
        ["/bin/bash", str(_sandbox_postinstall(tmp_path))],
        capture_output=True, text=True, timeout=120, env=env,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"missing pubkey must fail closed:\n{out}"
    assert "release pubkey not found" in out, f"canonical diagnostic required:\n{out}"
    assert "IN-BUNDLE-DECOY" not in out, "the decoy key must not be read as a fallback"
    assert _actions(tmp_path) == []


def test_executed_verifier_inside_bundle_is_refused(tmp_path: Path) -> None:
    """A verifier shipped inside the payload (SUBDIRECTORY placement) is
    refused even when it exists and prints PASSED. The bundle-ROOT placement
    (dirname == bundle_real) — an edge the original `"$bundle_real"/*`
    pattern let through — is covered by
    test_executed_verifier_at_bundle_root_is_refused below."""
    bundle = _build_bundle(tmp_path)
    in_bundle = _verifier_stub(
        bundle / "attacker-tools", "verify_bundle.py", exit_code=0, output="bundle verification PASSED"
    )
    _pubkey_stub(tmp_path)
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path), verifier=in_bundle)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"in-bundle verifier must be refused:\n{out}"
    assert "refusing to verify with a verifier inside the bundle" in out, (
        f"canonical diagnostic required:\n{out}"
    )
    assert _actions(tmp_path) == []


def test_executed_pubkey_inside_bundle_is_refused(tmp_path: Path) -> None:
    """Trust invariant 2, second containment, executed: a release pubkey SHIPPED
    INSIDE the bundle authenticates nothing (the tampered bundle ships its own
    key); postinstall must refuse it even though the file exists and is
    pointed at explicitly."""
    bundle = _build_bundle(tmp_path)
    # Subdirectory placement; the bundle-ROOT placement edge (dirname ==
    # bundle_real) is covered by test_executed_pubkey_at_bundle_root_is_refused.
    in_bundle_key = bundle / "keys" / "release.pub.pem"
    in_bundle_key.parent.mkdir(parents=True, exist_ok=True)
    in_bundle_key.write_text(
        "-----BEGIN PUBLIC KEY-----\nIN-BUNDLE\n-----END PUBLIC KEY-----\n", encoding="utf-8"
    )
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=in_bundle_key)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"in-bundle pubkey must be refused:\n{out}"
    assert "refusing to verify with a pubkey shipped inside the bundle" in out, (
        f"canonical diagnostic required:\n{out}"
    )
    assert _actions(tmp_path) == []


def test_executed_verifier_at_bundle_root_is_refused(tmp_path: Path) -> None:
    """Regression (root placement): the containment pattern used to be
    `"$bundle_real"/*`, which requires a path component AFTER the bundle —
    a verifier sitting DIRECTLY at the payload root (dirname == bundle_real)
    escaped the check and a tampered bundle could get its always-PASSED fake
    verifier executed as the trust gate. The pattern must also refuse the
    bundle root itself."""
    bundle = _build_bundle(tmp_path)
    in_bundle = _verifier_stub(
        bundle, "verify_bundle.py", exit_code=0, output="bundle verification PASSED"
    )
    _pubkey_stub(tmp_path)
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path), verifier=in_bundle)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"in-bundle verifier at the bundle root must be refused:\n{out}"
    assert "refusing to verify with a verifier inside the bundle" in out, (
        f"canonical diagnostic required:\n{out}"
    )
    assert _actions(tmp_path) == []


def test_executed_pubkey_at_bundle_root_is_refused(tmp_path: Path) -> None:
    """Regression (root placement), second containment: a release pubkey
    shipped DIRECTLY at the bundle root (dirname == bundle_real) used to
    escape the `"$bundle_real"/*` pattern; it must be refused like any other
    in-bundle trust material."""
    bundle = _build_bundle(tmp_path)
    in_bundle_key = bundle / "release.pub.pem"  # directly at the bundle root
    in_bundle_key.write_text(
        "-----BEGIN PUBLIC KEY-----\nIN-BUNDLE-ROOT\n-----END PUBLIC KEY-----\n", encoding="utf-8"
    )
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=in_bundle_key)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"in-bundle pubkey at the bundle root must be refused:\n{out}"
    assert "refusing to verify with a pubkey shipped inside the bundle" in out, (
        f"canonical diagnostic required:\n{out}"
    )
    assert _actions(tmp_path) == []


def test_executed_missing_bundle_payload_refuses(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path, manifest=False)
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    _pubkey_stub(tmp_path)
    _build_shims(tmp_path)

    proc = _run_postinstall(tmp_path, bundle, pubkey=_pubkey_stub(tmp_path))

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"missing bundle payload must fail closed:\n{out}"
    assert "bundle payload missing" in out, f"canonical diagnostic required:\n{out}"
    assert _actions(tmp_path) == []


# --------------------------------------------------------------------------
# executed positive control: verification passing must reach provisioning
# --------------------------------------------------------------------------


def test_executed_passing_verification_reaches_provisioning(tmp_path: Path) -> None:
    """Positive control (the sibling refusal tests cannot express this): with a
    verifier that prints PASSED, postinstall must ACTUALLY provision — service
    account via dscl, a venv built and filled by a hashed --no-index pip run
    against the bundle wheelhouse (invariant 3), the smoke check, config
    install and the launchctl bootstrap — i.e. the gate is
    verify-then-provision, not fail-always. The plist prerequisite is staged at
    the rewritten path; dscl/launchctl/install are the logging shims."""
    bundle = _build_bundle(tmp_path)
    _verifier_stub(tmp_path, "verify_bundle.py", exit_code=0, output="bundle verification PASSED")
    pubkey = _pubkey_stub(tmp_path)
    _build_shims(tmp_path)
    plist = tmp_path / "com.udbmcp.server.plist"
    plist.write_text("<plist/>", encoding="utf-8")

    proc = _run_postinstall(tmp_path, bundle, pubkey=pubkey)

    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"passing verification must complete the install:\n{out}"
    assert "FAIL" not in out, f"no failure diagnostics expected:\n{out}"
    assert "bundle verification PASSED" in out

    actions = _actions(tmp_path)
    joined = "\n".join(actions)
    # interpreter-selection fix tripwire: NOTHING may run via a PATH-searched
    # python3 — the verifier executes under the preinstall-validated candidate
    # (the python312-sandbox shim), never the python3 shim.
    assert not any(ln.startswith("PYTHON3") for ln in actions), (
        f"postinstall must never execute a PATH-searched python3 as root:\n{joined}"
    )
    # doctor-hook fix: the venv python must be a real copy, not a symlink
    # (doctor resolves sys.executable and would escape a symlinked venv).
    assert "PY -m venv --copies" in joined, (
        f"venv must be created with --copies so doctor finds $PREFIX/manifest.json:\n{joined}"
    )
    # provisioning happened, in order, strictly AFTER verification passed:
    assert "PY -m venv" in joined, f"venv creation expected:\n{joined}"
    pip_lines = [ln for ln in actions if ln.startswith("VENV-PY -m pip")]
    assert pip_lines, f"hashed offline pip install expected:\n{joined}"
    pip_line = pip_lines[0]
    for flag in ("--no-index", "--require-hashes", "--no-cache-dir", "--only-binary=:all:"):
        assert flag in pip_line, f"pip must stay offline+hashed ({flag} missing):\n{pip_line}"
    assert f"--find-links={bundle / 'wheelhouse'}" in pip_line, (
        f"pip must install from the verified bundle wheelhouse only:\n{pip_line}"
    )
    assert "-r" in pip_line and "runtime.lock" in pip_line, (
        f"pip must install exactly the runtime.lock resolution:\n{pip_line}"
    )
    assert any("universal_db_mcp version" in ln for ln in actions if ln.startswith("VENV-PY")), (
        f"smoke check expected after the install:\n{joined}"
    )
    assert any("DSCL" in ln and "-create" in ln and "/Users/_udbmcp" in ln for ln in actions), (
        f"service account provisioning expected:\n{joined}"
    )
    assert any(
        ln.startswith("LAUNCHCTL bootstrap system") and ln.endswith(str(plist)) for ln in actions
    ), f"launchd bootstrap expected:\n{joined}"
    # config installed from the verified bundle (never clobbering: file was absent)
    assert any("INSTALL" in ln and "config.yaml" in ln for ln in actions), (
        f"config template install expected:\n{joined}"
    )
    # the verifier ran BEFORE any provisioning shim: it logs through the
    # python312-sandbox shim (the validated candidate), executing the stub.
    first_provision = next(i for i, ln in enumerate(actions) if ln.startswith(("PY -m venv", "DSCL", "INSTALL")))
    verifier_calls = [
        i for i, ln in enumerate(actions) if ln.startswith("PY ") and "verify_bundle.py" in ln
    ]
    assert verifier_calls and verifier_calls[0] < first_provision, (
        f"verify-then-provision order broken:\n{joined}"
    )
