"""Regression tests for the conffiles gate in scripts/package/build_deb.sh.

Gap fixed (completeness-critic round 1, index 2): packaging/deb/conffiles was
never written, so the built .deb registered no dpkg conffile and build_deb.sh
degraded the missing template to a build-time NOTE ("nothing is registered as
a dpkg conffile").

Design under test (plan Phase 4): /etc/universal-db-mcp/config.yaml IS a dpkg
conffile.

  1. packaging/deb/conffiles exists and registers exactly
     /etc/universal-db-mcp/config.yaml.
  2. build_deb.sh stages the config INTO the payload at
     etc/universal-db-mcp/config.yaml (from the verified bundle's
     config-templates/ copy) — a conffile entry whose file is missing from
     the payload would be treated by dpkg as "deleted by the packager".
  3. The conffiles template is REQUIRED at build time: absence is a hard
     failure, never a NOTE.
  4. Every staged entry must be payload-backed (verified at build time).
  5. postinst's only-if-absent seeding and postrm's purge deletion /
     remove-retention stay in place (fallback for a deleted conffile;
     belt-and-braces purge cleanup).

The functional tests run the REAL gate block verbatim (extracted from
build_deb.sh with MAINT_DIR/DEBROOT rewritten) and one docker-free END-TO-END
run of the whole build_deb.sh (stub trusted verifier + fake docker shim) that
captures the staged DEBIAN/ tree the container would have received — proving
a built .deb declares the conffile without needing docker in the unit suite.

Trust invariants (never broken): the gate only strengthens fail-closed
behavior; it never stages key material, never executes payload, and aborts
(non-zero) without producing an artifact on any failure.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell/mode semantics; run on linux/macos")

_PROJECT = Path(__file__).resolve().parents[2]
_BUILD_DEB = _PROJECT / "scripts" / "package" / "build_deb.sh"
_DEB_DIR = _PROJECT / "packaging" / "deb"
_CONFFILES_ENTRY = "/etc/universal-db-mcp/config.yaml"


def _build_deb_text() -> str:
    return _BUILD_DEB.read_text(encoding="utf-8")


def _noncomment(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _gate_block() -> str:
    """Extract the executable conffiles-gate block from build_deb.sh.

    Runs from the CONFFILES_SRC= assignment up to the next staging section
    ("# --- control:"), so the test exercises the real gate code verbatim.
    """
    text = _build_deb_text()
    start = text.index("CONFFILES_SRC=")
    end = text.index("# --- control:")
    return text[start:end]


def _run_gate(
    tmp_path: Path,
    *,
    postinst: str,
    postrm: str,
    conffiles: str | None,
    stage_config: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run the extracted gate block in a sandbox with MAINT_DIR/DEBROOT
    rewritten to tmp paths. Everything else is verbatim build_deb.sh code.
    Mirrors the builder's own staging: the config conffile is placed in the
    payload before the gate runs (unless stage_config=False)."""
    maint = tmp_path / "maint"
    maint.mkdir()
    debroot = tmp_path / "debroot"
    (debroot / "DEBIAN").mkdir(parents=True)
    (debroot / "DEBIAN" / "postinst").write_text(postinst, encoding="utf-8")
    (debroot / "DEBIAN" / "postrm").write_text(postrm, encoding="utf-8")
    if stage_config:
        config = debroot / "etc" / "universal-db-mcp" / "config.yaml"
        config.parent.mkdir(parents=True)
        config.write_text("# demo config\n", encoding="utf-8")
    if conffiles is not None:
        (maint / "conffiles").write_text(conffiles, encoding="utf-8")

    script = tmp_path / "gate.sh"
    script.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'die() { echo "FAIL: $*" >&2; exit 1; }\n'
        f"MAINT_DIR={maint}\n"
        f"DEBROOT={debroot}\n"
        + _gate_block()
        + 'echo GATE-OK\n',
        encoding="utf-8",
    )
    return subprocess.run(  # noqa: S603 - fixed args, local sandbox script
        ["/bin/bash", str(script)], capture_output=True, text=True, timeout=60
    )


# Real maintainer scripts, used verbatim by the pass cases.
_REAL_POSTINST = (_DEB_DIR / "postinst").read_text(encoding="utf-8")
_REAL_POSTRM = (_DEB_DIR / "postrm").read_text(encoding="utf-8")


# ------------------------------------------------------------------ static


def test_build_deb_passes_bash_syntax_check() -> None:
    proc = subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(_BUILD_DEB)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def test_conffiles_template_exists_and_registers_the_config() -> None:
    """The plan Phase 4 deliverable: the template exists and its only entry
    (after the comment lines dpkg-deb cannot parse) is the config path."""
    template = _DEB_DIR / "conffiles"
    assert template.exists(), "packaging/deb/conffiles is a required plan Phase 4 input"
    entries = [
        line.strip()
        for line in template.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert entries == [_CONFFILES_ENTRY], f"unexpected conffiles entries: {entries}"


def test_no_soft_note_fallback_for_missing_conffiles() -> None:
    """The defect under test: absence of the conffiles template must be a hard
    build failure — never a build-time NOTE warning."""
    assert "NOTE: $MAINT_DIR/conffiles not present" not in _build_deb_text()
    assert "nothing is registered as a dpkg conffile" not in _build_deb_text()


def test_gate_fails_loud_on_payload_foreign_conffile_entries() -> None:
    code = "\n".join(line for line in _gate_block().splitlines() if not line.lstrip().startswith("#"))
    assert "[ -f \"$CONFFILES_SRC\" ]" in code, "the template must be REQUIRED (no soft fallback)"
    assert "[ -e \"$DEBROOT$_conffile_path\" ]" in code
    assert "is NOT in the staged deb payload" in code
    assert "deleted by the packager" in code


def test_gate_verifies_postinst_and_postrm_config_semantics() -> None:
    code = "\n".join(line for line in _gate_block().splitlines() if not line.lstrip().startswith("#"))
    assert 'grep -qF \'if [ ! -e "$CONFIG" ]; then\' "$DEBROOT/DEBIAN/postinst"' in code
    assert 'grep -qF \'rm -f "$CONFIG_FILE"\' "$DEBROOT/DEBIAN/postrm"' in code
    # Retention on remove must be checked too, not just purge deletion.
    assert 'grep -qF \'are retained\' "$DEBROOT/DEBIAN/postrm"' in code


def test_builder_stages_the_config_before_the_gate_and_the_container_build() -> None:
    """Ordering: the config is staged into the payload (so the entry-exists
    check can pass), then the conffiles gate runs, then dpkg-deb builds —
    a gate failure aborts BEFORE any artifact exists (fail closed)."""
    code = _noncomment(_build_deb_text())
    stage = 'install -m 0644 "$CONFIG_TEMPLATE" "$DEBROOT/etc/universal-db-mcp/config.yaml"'
    assert stage in code, "build_deb.sh must stage the config conffile into the payload"
    assert code.index(stage) < code.index("CONFFILES_SRC="), "stage the config BEFORE the conffiles gate"
    assert code.index("CONFFILES_SRC=") < code.index(
        'dpkg-deb --root-owner-group --build /debroot "/dist/$DEB_FILE"'
    ), "the gate must abort before the container build"


# --------------------------------------------------------------- functional


@_POSIX
def test_gate_stages_the_conffile_with_comments_stripped(tmp_path: Path) -> None:
    """The shipped state: the real template is rendered into DEBIAN/conffiles
    with comments/blank lines stripped and mode 0644 — i.e. the built .deb
    declares the conffile."""
    proc = _run_gate(
        tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM,
        conffiles=(_DEB_DIR / "conffiles").read_text(encoding="utf-8"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "GATE-OK" in proc.stdout
    staged = tmp_path / "debroot" / "DEBIAN" / "conffiles"
    assert staged.read_text(encoding="utf-8") == _CONFFILES_ENTRY + "\n"
    assert stat.S_IMODE(staged.stat().st_mode) == 0o644


@_POSIX
def test_gate_fails_closed_when_conffiles_template_is_missing(tmp_path: Path) -> None:
    """The original defect: a missing template used to degrade to a NOTE. It
    must now abort the build."""
    proc = _run_gate(tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM, conffiles=None)
    assert proc.returncode == 1
    assert "conffiles template missing" in proc.stderr
    assert not (tmp_path / "debroot" / "DEBIAN" / "conffiles").exists()


@_POSIX
def test_gate_fails_closed_on_conffile_entry_missing_from_payload(tmp_path: Path) -> None:
    """Any entry not backed by the staged payload (e.g. a typo'd path) must
    abort the build, not ship a conffile dpkg would treat as
    packager-deleted."""
    proc = _run_gate(
        tmp_path,
        postinst=_REAL_POSTINST,
        postrm=_REAL_POSTRM,
        conffiles="/etc/universal-db-mcp/other.yaml\n",
    )
    assert proc.returncode == 1
    assert "NOT in the staged deb payload" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_config_not_staged(tmp_path: Path) -> None:
    """If the builder ever loses the config staging line, the config entry
    becomes payload-foreign and the gate must catch it."""
    proc = _run_gate(
        tmp_path,
        postinst=_REAL_POSTINST,
        postrm=_REAL_POSTRM,
        conffiles=_CONFFILES_ENTRY + "\n",
        stage_config=False,
    )
    assert proc.returncode == 1
    assert "NOT in the staged deb payload" in proc.stderr
    assert _CONFFILES_ENTRY in proc.stderr


@_POSIX
def test_gate_fails_closed_on_comments_only_conffiles_template(tmp_path: Path) -> None:
    proc = _run_gate(
        tmp_path, postinst=_REAL_POSTINST, postrm=_REAL_POSTRM, conffiles="# nothing but comments\n\n"
    )
    assert proc.returncode == 1
    assert "no path entries after comment stripping" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postinst_loses_only_if_absent_seeding(tmp_path: Path) -> None:
    stripped = "\n".join(
        line for line in _REAL_POSTINST.splitlines() if 'if [ ! -e "$CONFIG" ]; then' not in line
    )
    proc = _run_gate(
        tmp_path, postinst=stripped, postrm=_REAL_POSTRM,
        conffiles=(_DEB_DIR / "conffiles").read_text(encoding="utf-8"),
    )
    assert proc.returncode == 1
    assert "only-if-absent config seeding" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postinst_loses_bundle_template_source(tmp_path: Path) -> None:
    stripped = "\n".join(
        line for line in _REAL_POSTINST.splitlines() if "config-templates/config.yaml" not in line
    )
    proc = _run_gate(
        tmp_path, postinst=stripped, postrm=_REAL_POSTRM,
        conffiles=(_DEB_DIR / "conffiles").read_text(encoding="utf-8"),
    )
    assert proc.returncode == 1
    assert "config-templates/" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postrm_loses_purge_deletion(tmp_path: Path) -> None:
    stripped = "\n".join(line for line in _REAL_POSTRM.splitlines() if 'rm -f "$CONFIG_FILE"' not in line)
    proc = _run_gate(
        tmp_path, postinst=_REAL_POSTINST, postrm=stripped,
        conffiles=(_DEB_DIR / "conffiles").read_text(encoding="utf-8"),
    )
    assert proc.returncode == 1
    assert "no longer deletes the config on purge" in proc.stderr


@_POSIX
def test_gate_fails_closed_when_postrm_loses_remove_retention(tmp_path: Path) -> None:
    stripped = "\n".join(line for line in _REAL_POSTRM.splitlines() if "are retained" not in line)
    proc = _run_gate(
        tmp_path, postinst=_REAL_POSTINST, postrm=stripped,
        conffiles=(_DEB_DIR / "conffiles").read_text(encoding="utf-8"),
    )
    assert proc.returncode == 1
    assert "conffile retention on remove" in proc.stderr


@_POSIX
def test_failed_gate_never_produces_an_artifact(tmp_path: Path) -> None:
    """Fail closed: a gate failure aborts the build, and the real script's
    EXIT trap discards the entire staged debroot — so no half-verified
    DEBIAN/conffiles can ever reach dpkg-deb."""
    proc = _run_gate(
        tmp_path,
        postinst=_REAL_POSTINST,
        postrm=_REAL_POSTRM,
        conffiles="/etc/universal-db-mcp/missing.yaml\n",
    )
    assert proc.returncode == 1
    assert "NOT in the staged deb payload" in proc.stderr
    # The gate runs BEFORE the container build step: the abort happens while
    # the payload is still just a throwaway mktemp root.
    text = _build_deb_text()
    assert text.index("CONFFILES_SRC=") < text.index('dpkg-deb --root-owner-group --build /debroot "/dist/$DEB_FILE"')
    # And the whole staged root is discarded on any abort (fail closed).
    assert "trap cleanup EXIT INT TERM" in text


# ------------------------------------------------------- end-to-end (no docker)


_DOCKER_SHIM = r"""#!/bin/bash
# Fake docker for the docker-free end-to-end test: accepts `image inspect`
# and `run --rm -v <debroot>:... -v <outdir>:... <image> dpkg-deb ...`.
# The run simulates a successful dpkg-deb build: it captures the staged
# DEBIAN/ tree (and the staged config) for inspection and writes the output
# .deb file.
set -eu
case "$1" in
  image) exit 0 ;;  # image inspect <name>: always present
  run)
    debroot=""; outdir=""
    prev=""
    for arg in "$@"; do
      case "$prev" in
        -v) [ -z "$debroot" ] && debroot="${arg%%:*}" || outdir="${arg%%:*}" ;;
      esac
      prev="$arg"
    done
    [ -n "$debroot" ] && [ -n "$outdir" ] || { echo "shim: missing mounts" >&2; exit 1; }
    if [ -n "${UDBMCP_CAPTURE_DIR:-}" ]; then
      mkdir -p "$UDBMCP_CAPTURE_DIR"
      cp -a "$debroot/DEBIAN" "$UDBMCP_CAPTURE_DIR/DEBIAN"
      cp -a "$debroot/etc" "$UDBMCP_CAPTURE_DIR/etc"
    fi
    out="${@: -1}"           # last arg: /dist/<name>.deb as passed by the builder
    out="${out#/dist}"       # map the container mount back to the host dir
    out="$outdir$out"
    mkdir -p "$(dirname "$out")"
    echo "fake-deb" > "$out"
    ;;
  *) echo "shim: unexpected docker subcommand $1" >&2; exit 1 ;;
esac
"""


@_POSIX
def test_end_to_end_build_declares_the_conffile(tmp_path: Path) -> None:
    """Docker-free END-TO-END run of the REAL build_deb.sh: a stub trusted
    verifier (the unit suite must not sign or verify anything real) and a
    fake docker shim let the whole script run to completion. The staged
    DEBIAN/ tree the container would receive must contain a DEBIAN/conffiles
    declaring exactly /etc/universal-db-mcp/config.yaml, and the payload must
    carry the staged config file backing that entry."""
    # -- fixture: minimal "signed" bundle the stub verifier accepts ---------
    bundle = tmp_path / "bundle"
    (bundle / "config-templates").mkdir(parents=True)
    (bundle / "manifest.json").write_text(
        '{"release": "0.1.0", "source_rev": "testsrc", "created": "2026-09-18T13:05:00+00:00", '
        '"target": {"os": "ubuntu-24.04", "arch": "x86_64"}}\n',
        encoding="utf-8",
    )
    (bundle / "SIGNATURE").write_text("stub\n", encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("stub\n", encoding="utf-8")
    (bundle / "config-templates" / "config.yaml").write_text("# demo config\n", encoding="utf-8")

    # -- stub trusted verifier OUTSIDE the bundle (never an in-bundle one) --
    trusted = tmp_path / "trusted-tools"
    (trusted / "lib").mkdir(parents=True)
    (trusted / "verify_bundle.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    (trusted / "profiles.py").write_text("", encoding="utf-8")
    (trusted / "install_offline.sh").write_text("", encoding="utf-8")
    (trusted / "lib" / "os_packages.sh").write_text("", encoding="utf-8")

    # -- fake docker on PATH -------------------------------------------------
    shim_bin = tmp_path / "shim-bin"
    shim_bin.mkdir()
    (shim_bin / "docker").write_text(_DOCKER_SHIM, encoding="utf-8")
    (shim_bin / "docker").chmod(0o755)
    capture = tmp_path / "captured-debian"

    outdir = tmp_path / "dist"
    env = dict(os.environ)
    env["PATH"] = f"{shim_bin}{os.pathsep}{env['PATH']}"
    env["UDBMCP_TRUST_DIR"] = str(trusted)
    env["UDBMCP_CAPTURE_DIR"] = str(capture)
    pubkey = tmp_path / "release.pub.pem"
    pubkey.write_text("-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    proc = subprocess.run(  # noqa: S603 - fixed args, local end-to-end sandbox run
        ["/bin/bash", str(_BUILD_DEB), str(bundle), "--pubkey", str(pubkey), "--out", str(outdir)],
        capture_output=True, text=True, timeout=120, env=env,
    )
    assert proc.returncode == 0, f"build failed: {proc.stderr}\n{proc.stdout}"
    built = list(outdir.glob("universal-db-mcp_*.deb"))
    assert built, f"no artifact produced: {proc.stdout}"

    # The container would have received a DEBIAN/conffiles declaring the config
    declared = (capture / "DEBIAN" / "conffiles").read_text(encoding="utf-8")
    assert declared == _CONFFILES_ENTRY + "\n", f"built deb must declare the conffile, got: {declared!r}"
    # ... backed by the staged config file in the payload ...
    assert (capture / "etc" / "universal-db-mcp" / "config.yaml").is_file()
    # ... alongside the maintainer scripts and the manifest-derived control.
    for member in ("control", "preinst", "postinst", "prerm", "postrm"):
        assert (capture / "DEBIAN" / member).is_file(), f"DEBIAN/{member} missing from the staged package"
    control = (capture / "DEBIAN" / "control").read_text(encoding="utf-8")
    # monotonic scheme: <release>+<build stamp from manifest.created>.g<rev7>
    assert "Version: 0.1.0+202609181305.gtestsrc" in control
