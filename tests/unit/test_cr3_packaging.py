"""Packaging regressions from the third /code-review max pass (review of 9c457ec..0ad054b).

A7-1  dpkg undoes an upgrade whose unpack failed after the preinst passed (a file conflict, a full disk):
      it runs this package's postrm and then the INSTALLED release's postinst with abort-upgrade. A
      postinst from before 9c457ec configures again and spawns a worker that re-installs the installed
      release over venv.previous. The lock holder that stops it moved from the preinst (which only saw its
      own refusals) to the postrm, which dpkg runs first on every path that undoes an upgrade.
A7-2  the installed postinst's abort-* branch overwrote a running first-install worker's 'running' with
      'failed' and exited 1 (dpkg 'iU') when an admin retried `dpkg -i` before that worker built the venv.
A7-3  the preinst's `exec 9>>lock 2>/dev/null` silenced its stderr for good; the postinst's
      `read ... < "$OWNER" 2>/dev/null` printed an error for a missing owner file.

The dpkg sequences run in a throwaway container (UDBMCP_DOCKER_TESTS=1) from the project's baseline image
(it has python3, which the postinst and its worker run): real dpkg, this tree's maintainer scripts verbatim,
3867e4c's as the installed pre-9c457ec release, and stub trust tools (the verifier prints PASSED; the
installer models staging and build-then-switch). Everything else runs on the host below tmp_path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_cr_fix_packaging import _between

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash-based POSIX test")

REPO = Path(__file__).resolve().parents[2]
DEB = REPO / "packaging" / "deb"
PREINST = DEB / "preinst"
POSTINST = DEB / "postinst"
POSTRM = DEB / "postrm"

_LOCK = "/run/udbmcp-deferred-install.lock"
_OWNER = "/run/udbmcp-deferred-install.owner"
_STATUS = "/var/log/universal-db-mcp-install.status"
_VENV_PYTHON = "/opt/universal-db-mcp/venv/bin/python"

# flock(1) as these scripts use it ('flock -n <fd>'): macOS has none.
# Started by the interpreter running the tests: PATH below holds only the shims, /usr/bin and /bin,
# where a Linux image with Python in /usr/local/bin has no python3.
_FLOCK_SHIM = """import fcntl, sys
args = [a for a in sys.argv[1:] if a != "-n"]
try:
    fcntl.flock(int(args[0]), fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(1)
"""

_HOLD_LOCK = """import fcntl, sys, time
f = open(sys.argv[1], "a")
fcntl.flock(f, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(120)
"""


def _shims(tmp_path: Path) -> dict[str, str]:
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    (shims / "flock").write_text(f"#!{sys.executable}\n" + _FLOCK_SHIM, encoding="utf-8")
    (shims / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/systemctl.log"\nexit 0\n', encoding="utf-8")
    (shims / "setsid").write_text(f'#!/bin/sh\necho "setsid $*" >> "{tmp_path}/setsid.log"\nexit 0\n', encoding="utf-8")
    for shim in shims.iterdir():
        shim.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("DPKG_")}
    env["PATH"] = f"{shims}:/usr/bin:/bin"
    return env


class _Site:
    """The postinst's abort-* block with its /run, /var/log and /opt paths moved below tmp_path."""

    def __init__(self, tmp_path: Path, *, venv: bool, status: str) -> None:
        self.tmp = tmp_path
        self.lock = tmp_path / "deferred.lock"
        self.owner = tmp_path / "deferred.owner"
        self.status = tmp_path / "status"
        self.status.write_text(status + "\n", encoding="utf-8")
        venv_python = tmp_path / "opt" / "venv" / "bin" / "python"
        if venv:
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
            venv_python.chmod(0o755)
        block = _between(POSTINST.read_text(encoding="utf-8"), 'case "${1:-}" in', "esac")
        proc_cmdline = '"/proc/$abort_worker/cmdline"'
        for old, new in ((_VENV_PYTHON, venv_python), (_STATUS, self.status), (_LOCK, self.lock),
                         (_OWNER, self.owner), (proc_cmdline, f'"{tmp_path}{proc_cmdline[1:]}'),
                         ("[ -d /run/systemd/system ]", "true")):
            assert old in block, old
            block = block.replace(old, str(new))
        self.block = block
        self.env = _shims(tmp_path)
        self.holders: list[subprocess.Popen[str]] = []

    def hold_lock(self, *, worker: bool) -> int:
        """A process that holds the lock; *worker*: its /proc cmdline is a deferred worker's."""
        proc = subprocess.Popen(  # noqa: S603 - a test process that holds the lock
            [sys.executable, "-c", _HOLD_LOCK, str(self.lock)], stdout=subprocess.PIPE, text=True
        )
        self.holders.append(proc)
        assert proc.stdout is not None and proc.stdout.readline().strip() == "held"
        self.cmdline(proc.pid, worker=worker)
        return proc.pid

    def cmdline(self, pid: int | str, *, worker: bool) -> None:
        worker_script = "/var/tmp/udbmcp-postinst-worker.Ab12Cd"  # noqa: S108 - a /proc cmdline, no file
        argv = ["/bin/bash", worker_script] if worker else ["sleep", "300"]
        (self.tmp / "proc" / str(pid)).mkdir(parents=True, exist_ok=True)
        (self.tmp / "proc" / str(pid) / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")

    def run(self, action: str = "abort-upgrade") -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - postinst's own block
            ["/bin/bash", "-c", self.block + 'echo "FELL THROUGH"\n', "postinst", action, "3.0"],
            env=self.env, capture_output=True, text=True, timeout=60, check=False,
        )

    def systemctl_calls(self) -> list[str]:
        log = self.tmp / "systemctl.log"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def close(self) -> None:
        for proc in self.holders:
            proc.kill()
            proc.wait(timeout=10)


@pytest.fixture
def site_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[_Site] = []

    def make(*, venv: bool, status: str) -> _Site:
        made.append(_Site(tmp_path, venv=venv, status=status))
        return made[-1]

    yield make
    for site in made:
        site.close()


# ---- A7-2: dpkg's abort-* while a deferred install of this release still runs -------------------------


@pytest.mark.parametrize("action", ["abort-upgrade", "abort-remove", "abort-deconfigure"])
def test_a72_a_running_worker_is_left_to_finish(site_factory, action: str) -> None:  # type: ignore[no-untyped-def]
    """A first install's worker has not built the venv yet when the admin retries `dpkg -i`: the retry's
    preinst refuses and dpkg runs this postinst with abort-upgrade. 'running' stays, the exit is 0 (dpkg
    keeps 'installed'), and nothing is started: the worker starts the service on success."""
    site = site_factory(venv=False, status="running")
    pid = site.hold_lock(worker=True)
    site.owner.write_text(f"{pid} 0123abcd\n", encoding="utf-8")
    proc = site.run(action)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FELL THROUGH" not in proc.stdout
    assert site.status.read_text(encoding="utf-8") == "running\n"
    assert f"leaves the deferred install (pid {pid})" in proc.stderr, proc.stderr
    assert "FAIL" not in proc.stderr
    assert site.systemctl_calls() == []


def test_a72_with_the_venv_in_place_a_running_worker_is_still_left_alone(site_factory) -> None:  # type: ignore[no-untyped-def]
    site = site_factory(venv=True, status="running")
    pid = site.hold_lock(worker=True)
    site.owner.write_text(f"{pid} 0123abcd\n", encoding="utf-8")
    proc = site.run()
    assert proc.returncode == 0, proc.stderr
    assert site.status.read_text(encoding="utf-8") == "running\n"
    assert site.systemctl_calls() == []  # the deferred-install guard would refuse the start anyway


@pytest.mark.parametrize(
    "case",
    [
        "no-owner-lock-held",  # the postrm's unwind holder of the refused package holds the lock, names nothing
        "dead-owner-lock-free",  # a worker that was killed (SIGKILL: no EXIT trap) left its name behind
        "reused-pid-lock-held",  # that name's pid is another process now, and the postrm's holder has the lock
        "worker-pid-lock-free",  # a worker's pid, but the lock is free: not the install the owner names
        "garbage-owner-lock-held",
        "nothing",
    ],
)
def test_a72_the_runbooks_deleted_venv_still_says_failed(site_factory, case: str) -> None:  # type: ignore[no-untyped-def]
    """The V3-m behaviour stays: with no worker of this release running, a missing venv is recorded as
    'failed' and the script fails (dpkg 'unpacked'), whatever else holds the lock or the owner file says."""
    site = site_factory(venv=False, status="running" if case == "dead-owner-lock-free" else "success")
    if case == "no-owner-lock-held":
        site.hold_lock(worker=False)
    elif case == "dead-owner-lock-free":
        dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],  # noqa: S603
                              capture_output=True, text=True, check=True).stdout.strip()
        site.owner.write_text(f"{dead} 0123abcd\n", encoding="utf-8")
        site.lock.touch()
    elif case == "reused-pid-lock-held":
        pid = site.hold_lock(worker=False)
        site.owner.write_text(f"{pid} 0123abcd\n", encoding="utf-8")
    elif case == "worker-pid-lock-free":
        site.cmdline(os.getpid(), worker=True)
        site.owner.write_text(f"{os.getpid()} 0123abcd\n", encoding="utf-8")
        site.lock.touch()
    elif case == "garbage-owner-lock-held":
        site.hold_lock(worker=False)
        site.owner.write_text("1; touch /tmp/x\n", encoding="utf-8")
    proc = site.run()
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FELL THROUGH" not in proc.stdout
    assert site.status.read_text(encoding="utf-8") == "failed\n"
    assert "now says 'failed'" in proc.stderr and "sudo dpkg --configure universal-db-mcp" in proc.stderr
    assert "No such file" not in proc.stderr, proc.stderr  # a missing owner file is not an error


def test_a72_with_the_venv_and_no_worker_the_service_is_started_again(site_factory) -> None:  # type: ignore[no-untyped-def]
    site = site_factory(venv=True, status="success")
    proc = site.run()
    assert proc.returncode == 0, proc.stderr
    assert site.status.read_text(encoding="utf-8") == "success\n"
    assert "start universal-db-mcp" in site.systemctl_calls()


# ---- A7-1: the unwind holder lives in the postrm -------------------------------------------------------


def _postrm_with(tmp_path: Path) -> Path:
    text = POSTRM.read_text(encoding="utf-8")
    assert f"DEFERRED_LOCK={_LOCK}\n" in text
    script = tmp_path / "postrm"
    script.write_text(text.replace(f"DEFERRED_LOCK={_LOCK}\n", f"DEFERRED_LOCK={tmp_path}/deferred.lock\n"),
                      encoding="utf-8")
    return script


def test_a71_postrm_abort_upgrade_hands_the_lock_to_a_holder_under_dpkg(tmp_path: Path) -> None:
    script = _postrm_with(tmp_path)
    env = _shims(tmp_path)
    env["DPKG_MAINTSCRIPT_NAME"] = "postrm"
    proc = subprocess.run(  # noqa: S603 - the package's postrm, its lock below tmp_path
        ["/bin/bash", str(script), "abort-upgrade", "1.1", "2.0"],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    calls = (tmp_path / "setsid.log").read_text(encoding="utf-8")
    assert calls.startswith("setsid --fork /bin/bash -c ") and "udbmcp-unwind-holder" in calls, calls
    assert "kept from starting an install worker" in proc.stderr  # A7-3: the notice reaches dpkg's output
    assert (tmp_path / "deferred.lock").exists()


@pytest.mark.parametrize("action", ["upgrade", "failed-upgrade", "abort-install", "remove"])
def test_a71_no_other_postrm_action_takes_the_lock(tmp_path: Path, action: str) -> None:
    script = _postrm_with(tmp_path)
    env = _shims(tmp_path)
    env["DPKG_MAINTSCRIPT_NAME"] = "postrm"
    proc = subprocess.run(  # noqa: S603 - the package's postrm, its lock below tmp_path
        ["/bin/bash", str(script), action, "1.1"], env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert not (tmp_path / "setsid.log").exists() and not (tmp_path / "deferred.lock").exists()


def test_a71_outside_dpkg_postrm_abort_upgrade_spawns_nothing(tmp_path: Path) -> None:
    script = _postrm_with(tmp_path)
    proc = subprocess.run(  # noqa: S603 - the package's postrm, its lock below tmp_path
        ["/bin/bash", str(script), "abort-upgrade", "1.1", "2.0"],
        env=_shims(tmp_path), capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert not (tmp_path / "setsid.log").exists() and not (tmp_path / "deferred.lock").exists()


def test_a71_an_unopenable_lock_never_fails_the_postrm(tmp_path: Path) -> None:
    script = _postrm_with(tmp_path)
    script.write_text(script.read_text(encoding="utf-8").replace(
        f"DEFERRED_LOCK={tmp_path}/deferred.lock\n", f"DEFERRED_LOCK={tmp_path}/missing-dir/deferred.lock\n"),
        encoding="utf-8")
    env = _shims(tmp_path)
    env["DPKG_MAINTSCRIPT_NAME"] = "postrm"
    proc = subprocess.run(  # noqa: S603 - the package's postrm, its lock below tmp_path
        ["/bin/bash", str(script), "abort-upgrade", "1.1", "2.0"],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr  # a failing postrm abort-upgrade leaves the package half-installed
    assert proc.stderr == "", proc.stderr
    assert not (tmp_path / "setsid.log").exists()


def test_a73_the_preinst_keeps_its_stderr_and_holds_no_lock() -> None:
    text = PREINST.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"(?m)^\s*trap\s", code) and "setsid" not in code and "exec 9" not in code
    for line in code.splitlines():  # no fd-redirecting exec that also points stderr away for good
        assert not (line.lstrip().startswith("exec ") and "2>" in line), line


def test_a73_a_missing_owner_file_prints_nothing(tmp_path: Path) -> None:
    fn = _between(POSTINST.read_text(encoding="utf-8"), "deferred_worker_installs() {", "\n}\n")
    proc = subprocess.run(  # noqa: S603 - postinst's own function
        ["/bin/bash", "-c", f"DEFERRED_OWNER={tmp_path}/missing\n{fn}\ndeferred_worker_installs abc; echo rc=$?"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.stdout.strip() == "rc=1" and proc.stderr == "", proc.stderr


# ---- the dpkg sequences, in a container ------------------------------------------------------------------

_IMAGE = "udbmcp-baseline:ubuntu24.04-cp312"
_OLD_REV = "3867e4c"  # a pre-9c457ec release: its postinst ignores abort-upgrade and configures again


def _image_present() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    proc = subprocess.run([docker, "image", "inspect", _IMAGE], capture_output=True, check=False)  # noqa: S603
    return proc.returncode == 0


_DOCKER = pytest.mark.skipif(
    os.environ.get("UDBMCP_DOCKER_TESTS") != "1" or not _image_present(),
    reason=f"runs dpkg in throwaway containers: set UDBMCP_DOCKER_TESTS=1 (needs docker and {_IMAGE})",
)

_LIB = r"""# helpers for the throwaway-container scenarios. Never run on a real host.
check() { if eval "$2"; then echo "CHECK $1 ok"; else echo "CHECK $1 FAIL"; fi; }
state() { dpkg-query -W -f='${Version} ${db:Status-Abbrev}' universal-db-mcp 2>/dev/null | tr -s ' ' | sed 's/ $//'; }
st() { cat /var/log/universal-db-mcp-install.status 2>/dev/null || echo '<none>'; }
rel_of() { sed -n 2p "$1" 2>/dev/null | sed 's/# release //'; }
venvs() { echo "$(rel_of /opt/universal-db-mcp/venv/bin/python)/$(rel_of /opt/universal-db-mcp/venv.previous/bin/python)"; }
mkpkg() {  # name version variant out [extra-path:size]
  local d s; d=$(mktemp -d); mkdir -p "$d/DEBIAN"
  printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: t <t@example.invalid>\nDescription: sim\n' "$1" "$2" > "$d/DEBIAN/control"
  if [ "$1" = universal-db-mcp ]; then
    for s in preinst postinst prerm postrm; do
      [ -f "/w/scripts/$3/$s" ] || continue
      printf '#!/bin/bash\necho "%s-%s $*" >> /tmp/maint.log\nexec /bin/bash /w/scripts/%s/%s "$@"\n' "$3$2" "$s" "$3" "$s" > "$d/DEBIAN/$s"
      chmod 755 "$d/DEBIAN/$s"
    done
    local B="$d/usr/share/universal-db-mcp/bundle"
    mkdir -p "$B/os-packages" "$B/config-templates" "$B/operations" "$d/usr/share/universal-db-mcp/systemd"
    echo "$2" > "$B/release"
    printf '{"release": "%s"}\n' "$2" > "$B/manifest.json"
    echo dummy > "$B/os-packages/dummy.deb"
    echo "connections: {}" > "$B/config-templates/config.yaml"
    printf '[Service]\nExecStart=/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp serve --transport http\n' > "$B/operations/universal-db-mcp.service"
    cp "$B/operations/universal-db-mcp.service" "$d/usr/share/universal-db-mcp/systemd/"
  fi
  if [ -n "${5:-}" ]; then
    local p="${5%%:*}" n="${5##*:}"
    mkdir -p "$d/$(dirname "$p")"; head -c "$n" /dev/urandom > "$d/$p"
  fi
  dpkg-deb --build --root-owner-group "$d" "$4" >/dev/null
}
wait_for() { local _; for _ in $(seq 1 "$2"); do eval "$1" && return 0; sleep 1; done; return 1; }
worker_alive() { local f; for f in /proc/[0-9]*/cmdline; do grep -a -q udbmcp-postinst-worker "$f" 2>/dev/null && return 0; done; return 1; }
installed_ok() { wait_for "grep -q 'installer-done rel=$1' /tmp/maint.log && grep -qx success /var/log/universal-db-mcp-install.status && ! worker_alive" 120; }
lock_free() { flock -n -w 5 /run/udbmcp-deferred-install.lock true; }
mkdir -p /usr/local/lib/udbmcp-trust/lib /etc/universal-db-mcp/keys
cp /w/trust/verify_bundle.py /w/trust/profiles.py /w/trust/install_offline.sh /usr/local/lib/udbmcp-trust/
cp /w/trust/os_packages.sh /usr/local/lib/udbmcp-trust/lib/
chmod 755 /usr/local/lib/udbmcp-trust/install_offline.sh
echo "-----BEGIN PUBLIC KEY-----" > /etc/universal-db-mcp/keys/release.pub.pem
touch /tmp/maint.log
echo 1 > /tmp/installer-sleep
"""  # noqa: E501 - shell lines

_VERIFIER_STUB = """# stub of the trusted verifier: certifies whatever bundle it is given
print("bundle verification PASSED")
"""

_INSTALLER_STUB = r"""#!/bin/bash
# udbmcp-installer-format: 4
# udbmcp-installer-format: 3
# stub of the trusted installer: models staging, build-then-switch (venv.previous) and publishing only.
set -eu
BUNDLE="$1"; TARGET="$2"
stage="$(mktemp -d /var/tmp/stage.XXXXXX)"
cp -a "$BUNDLE/." "$stage/"
rel="$(cat "$stage/release")"
echo "installer-start rel=$rel" >> /tmp/maint.log
sleep "$(cat /tmp/installer-sleep)"
id udbmcp >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin udbmcp
mkdir -p "$TARGET"; rm -rf "$TARGET/venv.new"; mkdir -p "$TARGET/venv.new/bin"
printf '#!/bin/sh\n# release %s\n' "$rel" > "$TARGET/venv.new/bin/python"; chmod 755 "$TARGET/venv.new/bin/python"
if [ -d "$TARGET/venv" ]; then rm -rf "$TARGET/venv.previous"; mv "$TARGET/venv" "$TARGET/venv.previous"; fi
mv "$TARGET/venv.new" "$TARGET/venv"
cp "$stage/manifest.json" "$TARGET/manifest.json"
rm -rf "$stage"
echo "installer-done rel=$rel" >> /tmp/maint.log
"""

# The unpack of this tree's 2.0 fails after its preinst passed; the installed 1.1 is a pre-9c457ec release.
_UNPACK_FAILS = r"""#!/bin/bash
set -u
. /w/lib.sh
MODE="$1"
mkpkg universal-db-mcp 1.0 old /tmp/r10.deb
mkpkg universal-db-mcp 1.1 old /tmp/r11.deb
mkpkg universal-db-mcp 2.0 head /tmp/r20.deb
if [ "$MODE" = conflict ]; then
  mkpkg other 1.0 x /tmp/other.deb usr/share/conflict/file:16
  dpkg -i /tmp/other.deb >/dev/null 2>&1
  mkpkg universal-db-mcp 2.0 head /tmp/r20bad.deb usr/share/conflict/file:16
else  # /usr/share/universal-db-mcp is a 1 MiB tmpfs: the 3 MB file does not fit
  mkpkg universal-db-mcp 2.0 head /tmp/r20bad.deb usr/share/universal-db-mcp/bundle/wheels/big.whl:3000000
fi
dpkg -i /tmp/r10.deb >/dev/null 2>&1; installed_ok 1.0
dpkg -i /tmp/r11.deb >/dev/null 2>&1; installed_ok 1.1
check before '[ "$(state)" = "1.1 ii" ] && [ "$(venvs)" = 1.1/1.0 ]'
: > /tmp/maint.log
dpkg -i /tmp/r20bad.deb > /tmp/a.out 2>&1; rc=$?
cat /tmp/a.out; cat /tmp/maint.log
check preinst_passed 'grep -q "trust prerequisites present" /tmp/a.out'
check unpack_failed '[ $rc -ne 0 ] && grep -q -i -E "trying to overwrite|no space left" /tmp/a.out'
check postrm_then_old_postinst_abort_upgrade 'grep -A1 "^head2.0-postrm abort-upgrade 1.1 2.0" /tmp/maint.log | grep -q "^old1.1-postinst abort-upgrade 2.0"'
check holder_notice 'grep -q "kept from starting an install worker" /tmp/a.out'
check old_postinst_spawned_no_worker 'grep -q "not spawning a second worker" /tmp/a.out'
sleep 5
check no_reinstall_of_the_old_release '! grep -q installer-start /tmp/maint.log && ! worker_alive'
wait_for '! worker_alive' 90  # (a worker the old postinst did spawn would replace venv.previous by now)
check rollback_point_kept '[ "$(venvs)" = 1.1/1.0 ]'
check old_release_still_installed '[ "$(state)" = "1.1 ii" ] && [ "$(st)" = success ]'
check lock_released_after_dpkg lock_free
[ "$MODE" = conflict ] && dpkg -r other >/dev/null 2>&1
[ "$MODE" = conflict ] || rm -f /usr/share/universal-db-mcp/bundle/wheels/big.whl* 2>/dev/null
dpkg -i /tmp/r20.deb > /tmp/b.out 2>&1; rc=$?
check retry_upgrades_at_once '[ $rc -eq 0 ] && [ "$(state)" = "2.0 ii" ]'
installed_ok 2.0
check upgraded_over_the_kept_rollback_point '[ "$(venvs)" = 2.0/1.1 ] && [ "$(st)" = success ]'
"""  # noqa: E501 - shell lines

# This tree's preinst refuses (format-3-only trust installer): the review-2 V3-d path, now held by the postrm.
_PREINST_REFUSES = r"""#!/bin/bash
set -u
. /w/lib.sh
mkpkg universal-db-mcp 1.1 old /tmp/r11.deb
mkpkg universal-db-mcp 2.0 head /tmp/r20.deb
dpkg -i /tmp/r11.deb >/dev/null 2>&1; installed_ok 1.1
T=/usr/local/lib/udbmcp-trust/install_offline.sh
cp $T /tmp/installer.good
sed -i '/^# udbmcp-installer-format: 4$/d' $T
echo '# PIP_FIND_LINKS --force-reinstall' >> $T
: > /tmp/maint.log
dpkg -i /tmp/r20.deb > /tmp/a.out 2>&1; rc=$?
cat /tmp/a.out; cat /tmp/maint.log
check refused '[ $rc -ne 0 ] && grep -q "udbmcp-installer-format: 4" /tmp/a.out && grep -q "ABORTED" /tmp/a.out'
check holder_notice 'grep -q "kept from starting an install worker" /tmp/a.out'
check old_postinst_spawned_no_worker 'grep -q "not spawning a second worker" /tmp/a.out'
sleep 5
check no_reinstall '! grep -q installer-start /tmp/maint.log && ! worker_alive && [ "$(venvs)" = 1.1/ ]'
check lock_released_after_dpkg lock_free
cp /tmp/installer.good $T
dpkg -i /tmp/r20.deb > /tmp/b.out 2>&1; rc=$?
check retry_upgrades_at_once '[ $rc -eq 0 ] && [ "$(state)" = "2.0 ii" ]'
installed_ok 2.0
check upgraded '[ "$(venvs)" = 2.0/1.1 ]'
"""

# A7-2: the same package again while the first install's worker has not built the venv.
_RETRY_DURING_FIRST_INSTALL = r"""#!/bin/bash
set -u
. /w/lib.sh
mkpkg universal-db-mcp 3.0 head /tmp/r30.deb
echo 45 > /tmp/installer-sleep
dpkg -i /tmp/r30.deb > /tmp/a.out 2>&1; rc=$?
check first_install_deferred '[ $rc -eq 0 ] && [ "$(state)" = "3.0 ii" ] && [ "$(st)" = running ]'
dpkg -i /tmp/r30.deb > /tmp/b.out 2>&1; rc=$?
cat /tmp/b.out; cat /tmp/maint.log
check retry_refused_by_the_preinst '[ $rc -ne 0 ] && grep -q "still running" /tmp/b.out'
check abort_left_the_worker_alone 'grep -q "leaves the deferred install (pid" /tmp/b.out && ! grep -q "now says .failed." /tmp/b.out'
check still_installed '[ "$(state)" = "3.0 ii" ]'
check status_still_running '[ "$(st)" = running ] && worker_alive'
check no_holder_while_the_worker_runs '! grep -q "kept from starting" /tmp/b.out'
installed_ok 3.0
check worker_finished '[ "$(state)" = "3.0 ii" ] && [ "$(st)" = success ] && [ "$(venvs)" = 3.0/ ]'
"""  # noqa: E501 - shell lines

# The runbook's package rollback: the venv is deleted, then the older package's preinst refuses.
_RUNBOOK_ROLLBACK = r"""#!/bin/bash
set -u
. /w/lib.sh
mkpkg universal-db-mcp 3.0 head /tmp/r30.deb
mkpkg universal-db-mcp 1.5 refusing /tmp/r15.deb
dpkg -i /tmp/r30.deb >/dev/null 2>&1; installed_ok 3.0
rm -rf /opt/universal-db-mcp/venv
sleep 300 & live=$!
echo "$live abc" > /run/udbmcp-deferred-install.owner  # a live pid that holds no lock is not a worker
dpkg -i /tmp/r15.deb > /tmp/a.out 2>&1
cat /tmp/a.out
check holder_did_not_count_as_a_worker 'grep -q "kept from starting" /tmp/a.out && ! grep -q "leaves the deferred install" /tmp/a.out'
check unpacked_and_failed '[ "$(state)" = "3.0 iU" ] && [ "$(st)" = failed ]'
kill $live; rm -f /run/udbmcp-deferred-install.owner
sleep 2
dpkg --configure universal-db-mcp > /tmp/c.out 2>&1; rc=$?
check configure_reinstalls '[ $rc -eq 0 ] && [ "$(state)" = "3.0 ii" ]'
installed_ok 3.0
check recovered '[ "$(venvs)" = 3.0/ ] && [ "$(st)" = success ]'
"""  # noqa: E501 - shell lines


def _git_show(rev_path: str) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    proc = subprocess.run(  # noqa: S603 - read-only git object lookup
        [git, "-C", str(REPO), "show", rev_path], capture_output=True, text=True, timeout=60, check=False
    )
    return proc.stdout if proc.returncode == 0 else None


def _inputs(tmp_path: Path) -> Path:
    w = tmp_path / "w"
    for variant in ("head", "old", "refusing"):
        (w / "scripts" / variant).mkdir(parents=True)
    (w / "trust").mkdir()
    for name in ("preinst", "postinst", "prerm", "postrm"):
        shutil.copy2(DEB / name, w / "scripts" / "head" / name)
        old = _git_show(f"{_OLD_REV}:packaging/deb/{name}")
        if old is None:
            pytest.skip(f"git object {_OLD_REV} is not available")
        (w / "scripts" / "old" / name).write_text(old, encoding="utf-8")
    (w / "scripts" / "refusing" / "preinst").write_text("#!/bin/bash\necho 'older preinst: refused' >&2\nexit 1\n")
    shutil.copy2(DEB / "postrm", w / "scripts" / "refusing" / "postrm")
    (w / "trust" / "verify_bundle.py").write_text(_VERIFIER_STUB, encoding="utf-8")
    (w / "trust" / "profiles.py").write_text("# stub\n", encoding="utf-8")
    (w / "trust" / "os_packages.sh").write_text("# stub\n", encoding="utf-8")
    (w / "trust" / "install_offline.sh").write_text(_INSTALLER_STUB, encoding="utf-8")
    (w / "lib.sh").write_text(_LIB, encoding="utf-8")
    for name, text in (("unpack_fails.sh", _UNPACK_FAILS), ("preinst_refuses.sh", _PREINST_REFUSES),
                       ("retry.sh", _RETRY_DURING_FIRST_INSTALL), ("runbook.sh", _RUNBOOK_ROLLBACK)):
        (w / name).write_text(text, encoding="utf-8")
    return w


_SCENARIOS: dict[str, tuple[list[str], list[str], set[str]]] = {
    # name: (extra docker args, script + args, checks that must be present)
    "conflict": ([], ["unpack_fails.sh", "conflict"],
                 {"unpack_failed", "postrm_then_old_postinst_abort_upgrade", "rollback_point_kept",
                  "retry_upgrades_at_once"}),
    "enospc": (["--tmpfs", "/usr/share/universal-db-mcp:size=1m"], ["unpack_fails.sh", "enospc"],
               {"unpack_failed", "no_reinstall_of_the_old_release", "rollback_point_kept"}),
    "refusal": ([], ["preinst_refuses.sh"], {"refused", "old_postinst_spawned_no_worker", "lock_released_after_dpkg"}),
    "retry": ([], ["retry.sh"], {"abort_left_the_worker_alone", "status_still_running", "worker_finished"}),
    "runbook": ([], ["runbook.sh"], {"holder_did_not_count_as_a_worker", "unpacked_and_failed", "recovered"}),
}


@_DOCKER
def test_dpkg_sequences_in_containers(tmp_path: Path) -> None:
    w = _inputs(tmp_path)
    docker = shutil.which("docker")
    assert docker is not None
    running = {
        name: subprocess.Popen(  # noqa: S603 - throwaway container, no network
            [docker, "run", "--rm", "--network", "none", "--platform", "linux/amd64", *extra,
             "-v", f"{w}:/w:ro", _IMAGE, "bash", f"/w/{script[0]}", *script[1:]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for name, (extra, script, _) in _SCENARIOS.items()
    }
    problems = []
    for name, proc in running.items():
        out, _ = proc.communicate(timeout=900)
        checks = dict(line.split()[1:3] for line in out.splitlines() if line.startswith("CHECK "))
        failed = sorted(check for check, result in checks.items() if result != "ok")
        missing = _SCENARIOS[name][2] - set(checks)
        if not checks or failed or missing:
            problems.append(f"--- {name}: failed={failed} missing={sorted(missing)}\n{out}")
    assert not problems, "\n".join(problems)
