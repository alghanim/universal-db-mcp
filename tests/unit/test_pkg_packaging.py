"""Phase 3 regression tests for the macOS .pkg packaging (artifact: pkg:tests).

These tests run WITHOUT root, docker or a real ``installer`` run. They pin the
trust model of the .pkg at three layers:

1. ``scripts/package/build_pkg.sh`` must refuse to build from an unsigned
   bundle (trust invariant 1: no package may ever contain payload that the
   admin's trusted-channel ``verify_bundle.py --pubkey`` run has not cleared).
2. The launchd plist must mirror the systemd unit line for line (UserName,
   Umask 63 == 0077 octal, ``-m universal_db_mcp serve`` program arguments,
   ``UDBMCP_CONFIG`` environment) and must lint with ``plutil``.
3. ``packaging/pkg/preinstall`` / ``postinstall`` must fail closed on missing
   trust prerequisites, re-verify the payload via the trusted verifier with
   the admin pubkey BEFORE any pip/launchctl use, neutralize the hostile pip
   environment (``PIP_CONFIG_FILE=/dev/null``, ``--no-index --require-hashes``)
   and install the config file ONLY-IF-ABSENT.

Trust invariant 2 (the release public key is NEVER shipped inside a package —
the admin distributes it out-of-band) is asserted against the packaging tree.

Ownership note: this file tests producer scripts owned by the pkg-builder
workflow (``scripts/package/build_pkg.sh``, ``packaging/pkg/{preinstall,
postinstall}``, ``packaging/launchd/com.udbmcp.server.plist``). Producer files
that have not landed yet cause an HONEST skip with a named reason — never a
silent pass. ``preinstall`` hardcodes its trust paths (no env override), so
its missing-prerequisite path is exercised functionally only on hosts where
the trust material is genuinely absent; that limitation is stated in the test.

Pattern copied from tests/unit/test_hardening_gates.py: bash -n syntax gates,
grep-based content gates on the script text, and extract-and-run functional
tests with tmp_path sandboxes.
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from xml.parsers.expat import ExpatError

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

BUILD_PKG = REPO_ROOT / "scripts" / "package" / "build_pkg.sh"
PREINSTALL = REPO_ROOT / "packaging" / "pkg" / "preinstall"
POSTINSTALL = REPO_ROOT / "packaging" / "pkg" / "postinstall"
PLIST = REPO_ROOT / "packaging" / "launchd" / "com.udbmcp.server.plist"
SYSTEMD_UNIT = REPO_ROOT / "packaging" / "systemd" / "universal-db-mcp.service"

TRUST_VERIFIER_PATH = "/usr/local/lib/udbmcp-trust/verify_bundle.py"
ADMIN_PUBKEY_PATH = "/etc/universal-db-mcp/keys/release.pub.pem"
CONFIG_PATH = "/etc/universal-db-mcp/config.yaml"
PAYLOAD_PREFIX = "/usr/local/universal-db-mcp"

_WIN32_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="macOS .pkg packaging is POSIX-only")


def _require(path: Path) -> Path:
    """Return *path*, or SKIP with an honest, named reason when the producer
    file has not landed yet (it is owned by the concurrent pkg-builder
    workflow). A pending producer must never look like a passing test."""
    if not path.is_file():
        try:
            where = str(path.relative_to(REPO_ROOT))
        except ValueError:  # pragma: no cover - always under REPO_ROOT here
            where = str(path)
        pytest.skip(f"{where} does not exist yet (pkg-builder artifact pending)")
    return path


def _resolve_shell_vars(lines: list[str]) -> list[str]:
    """Substitute the script's own `NAME="..."` assignments into later lines
    (e.g. CONFIG="$CONFIG_DIR/config.yaml"), iterating until the definitions
    themselves converge so chained vars (PREFIX -> BUNDLE, CONFIG_DIR ->
    CONFIG) resolve like the shell would. Command substitutions, nested
    expansions and $-refs to undefined names are left untouched; the loop is
    capped so a (hypothetical) definition cycle cannot hang the test."""
    var_ref = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)")

    defs: dict[str, str] = {}
    for ln in lines:
        m = re.match(r'^\s*([A-Z_][A-Z0-9_]*)="([^"]*)"\s*$', ln)
        if m:
            defs[m.group(1)] = m.group(2)

    def sub(text: str) -> str:
        return var_ref.sub(lambda m: defs.get(m.group(1) or m.group(2), m.group(0)), text)

    for _ in range(5):  # converge chained definitions
        changed = False
        for key, value in list(defs.items()):
            new = sub(value)
            if new != value:
                defs[key] = new
                changed = True
        if not changed:
            break

    out: list[str] = []
    for ln in lines:
        for _ in range(5):
            new = sub(ln)
            if new == ln:
                break
            ln = new
        out.append(ln)
    return out


def _logical_lines(text: str) -> list[str]:
    """Script text as logical command lines: backslash-newline continuations
    joined (so a multi-line pip command is ONE line for flag checks) and
    comment-only lines dropped (so prose in comments cannot satisfy or defeat
    a gate). Limitation, stated honestly: a trailing comment on a command line
    stays in the line; gate regexes below tolerate that."""
    text = text.replace("\\\n", " ")
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _bash_n(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed args, local script syntax check
        ["/bin/bash", "-n", str(path)], capture_output=True, text=True, timeout=120
    )


# --------------------------------------------------------------------------
# syntax gates
# --------------------------------------------------------------------------


@_WIN32_ONLY
@pytest.mark.parametrize(
    "relpath",
    [
        "scripts/package/build_pkg.sh",
        "packaging/pkg/preinstall",
        "packaging/pkg/postinstall",
    ],
)
def test_pkg_shell_scripts_pass_bash_syntax_check(relpath: str) -> None:
    proc = _bash_n(_require(REPO_ROOT / relpath))
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------
# build_pkg.sh: unsigned bundles are refused before anything is built
# --------------------------------------------------------------------------


def _make_unsigned_bundle(tmp_path: Path) -> tuple[Path, Path]:
    """A minimal well-formed-but-UNSIGNED bundle dir (no SIGNATURE file) plus
    a dummy admin pubkey argument (never used — the refusal must fire before
    any crypto, because there is nothing to verify against)."""
    bundle = tmp_path / "bundle"
    (bundle / "trusted-tools").mkdir(parents=True)
    (bundle / "wheelhouse").mkdir()
    (bundle / "manifest.json").write_text('{"release": "0.1.0", "target": {"os": "macos"}}\n', encoding="utf-8")
    (bundle / "SHA256SUMS").write_text("", encoding="utf-8")
    # deliberately NO SIGNATURE file
    pubkey = tmp_path / "release.pub.pem"
    pubkey.write_text(
        "-----BEGIN PUBLIC KEY-----\nTESTONLY\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )
    return bundle, pubkey


@_WIN32_ONLY
def test_build_pkg_refuses_unsigned_bundle(tmp_path: Path) -> None:
    """FUNCTIONAL (extract-and-run): build_pkg.sh against a bundle without a
    SIGNATURE must exit nonzero, say why (signature/verification failure), and
    produce NO .pkg artifact (trust invariant 1)."""
    script = _require(BUILD_PKG)
    bundle, pubkey = _make_unsigned_bundle(tmp_path)

    proc = subprocess.run(  # noqa: S603 - fixed args, tmp_path sandbox
        ["/bin/bash", str(script), str(bundle), "--pubkey", str(pubkey), "--out", str(tmp_path / "dist")],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
        # keep the script's build log inside the sandbox too (the script
        # supports this env override for its evidence dir)
        env={**os.environ, "UDBMCP_PACKAGE_EVIDENCE_DIR": str(tmp_path / "evidence")},
    )
    out = proc.stdout + proc.stderr

    assert proc.returncode != 0, (
        f"build_pkg.sh must REFUSE an unsigned bundle (no SIGNATURE file); it exited 0. stdout:\n{proc.stdout}"
    )
    assert re.search(r"(?i)sign|verif", out), f"the refusal must state the signature/verification reason, got:\n{out}"
    produced = sorted(tmp_path.rglob("*.pkg"))
    assert produced == [], f"no .pkg may be built from an unsigned bundle, found {produced}"


@_WIN32_ONLY
def test_build_pkg_verifies_bundle_before_pkgbuild() -> None:
    """Content gate (invariant 1): in build_pkg.sh the trusted-channel
    verifier invocation (with the admin --pubkey) must appear BEFORE the first
    pkgbuild/productbuild use — a package is only ever assembled from an
    already-verified payload."""
    text = "\n".join(_logical_lines(_require(BUILD_PKG).read_text(encoding="utf-8")))
    assert "verify_bundle.py" in text, "build_pkg.sh must run the trusted verifier"
    assert "--pubkey" in text, "the verifier must be given the admin pubkey"
    assert "pkgbuild" in text, "build_pkg.sh must assemble the .pkg via pkgbuild"
    # Order on the actual INVOCATION, not the first textual mention of
    # "verify_bundle.py": in build_pkg.sh that first mention is the
    # VERIFIER= variable-definition line, which would satisfy a naive
    # index() even if the real verifier run were moved after pkgbuild.
    m = re.search(r'"\$\{?PYTHON_BIN\}?"\s+"\$\{?VERIFIER\}?"', text)
    assert m, (
        'build_pkg.sh must actually invoke the verifier as "$PYTHON_BIN" "$VERIFIER" ... '
        "(a VERIFIER= definition alone verifies nothing)"
    )
    first_verify = text.index(m.group(0))
    first_build = text.index("pkgbuild")
    assert first_verify < first_build, "build_pkg.sh must verify the source bundle BEFORE any pkgbuild step"


@_WIN32_ONLY
def test_build_pkg_installs_plist_into_launchdaemons() -> None:
    """The package installs the launchd plist at the system daemon location
    (non-relocatable package: absolute paths are load-bearing)."""
    text = _require(BUILD_PKG).read_text(encoding="utf-8")
    assert "/Library/LaunchDaemons" in text, "the plist must be installed into /Library/LaunchDaemons/"
    assert "com.udbmcp.server.plist" in text, "build_pkg.sh must ship packaging/launchd/com.udbmcp.server.plist"


# --------------------------------------------------------------------------
# launchd plist: mirrors the systemd unit line for line
# --------------------------------------------------------------------------


_XML_COMMENT = re.compile(rb"<!--.*?-->", re.DOTALL)


def _load_plist() -> dict[str, object]:
    """Parse the plist the way launchd sees it.

    KNOWN, DOCUMENTED deviation: the header comment contains long '--' runs,
    which the XML spec forbids inside comments — strict XML parsers
    (plistlib/expat, xmllint) reject the raw file, while launchd and plutil
    (the only parsers that matter for a /Library/LaunchDaemons plist) accept
    it. The repo's own pkg gate makes the same call and says so in
    scripts/package/test_package_pkg.sh (it extracts values with plutil, not
    plistlib). We therefore parse the comment-stripped document, and the
    deviation itself is pinned by
    test_launchd_plist_known_strict_xml_deviation_is_bounded — so if the
    comment is ever fixed (or the file breaks in a NEW way), that test moves
    with it."""
    _require(PLIST)
    try:
        with PLIST.open("rb") as fh:
            data = plistlib.load(fh)
    except ExpatError:
        stripped = _XML_COMMENT.sub(b"", PLIST.read_bytes())
        data = plistlib.loads(stripped)
    assert isinstance(data, dict), f"plist root must be a dict, got {type(data)}"
    return data


def test_launchd_plist_parses_and_pins_service_identity() -> None:
    data = _load_plist()
    # Label must equal the installed filename stem: launchd registers the job
    # under the plist's Label key, NOT the filename, and packaging/pkg/
    # postinstall drives launchctl with LABEL="com.udbmcp.server"
    # (bootout/bootstrap/print). A mismatch breaks every reinstall/upgrade.
    assert data.get("Label") == "com.udbmcp.server"
    assert data.get("Label") == PLIST.stem, (
        "plist Label must match the installed filename stem "
        "/Library/LaunchDaemons/<Label>.plist (postinstall bootout/bootstrap/print rely on it)"
    )
    # systemd User=udbmcp -> launchd UserName=_udbmcp (the service account
    # postinstall creates via dscl/sysadminctl)
    assert data.get("UserName") == "_udbmcp"
    # launchd Umask is DECIMAL: systemd UMask=0077 (octal) == 63 decimal
    # (0o77 == 63). A wrong radix here silently widens audit-file perms.
    assert data.get("Umask") == 63 == 0o77
    env = data.get("EnvironmentVariables")
    assert isinstance(env, dict), "EnvironmentVariables must be a dict"
    assert env.get("UDBMCP_CONFIG") == CONFIG_PATH


def test_postinstall_launchctl_label_matches_plist_label() -> None:
    """Cross-file gate (reinstall/upgrade abort class): postinstall drives
    launchctl with its LABEL=... variable, but launchd registers the job under
    the PLIST's Label key — NOT the filename and NOT the pkg identifier. If
    postinstall's LABEL differs from the plist Label, 'launchctl bootout
    system/<wrong>' is a silent no-op, 'launchctl bootstrap' fails EEXIST (the
    service is still loaded under the plist Label), and the fallback
    'launchctl print system/<wrong>' can never succeed — every reinstall or
    upgrade over a running service aborts the installer and the plist refresh
    never happens. postinstall's LABEL must therefore equal the plist Label,
    and every launchctl invocation in postinstall must target it (or the plist
    file, whose installed filename stem is the same label)."""
    data = _load_plist()
    plist_label = data.get("Label")
    assert isinstance(plist_label, str), "plist Label must be a string"

    raw = _require(POSTINSTALL).read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*LABEL="([^"]*)"\s*$', raw)
    assert m, 'postinstall must pin the launchd service label as LABEL="..."'
    assert m.group(1) == plist_label, (
        f"postinstall LABEL={m.group(1)!r} != plist Label {plist_label!r}: "
        "launchd keys the service by the plist's Label key, so launchctl "
        "bootout/print with the wrong label are silent no-ops and bootstrap "
        "fails EEXIST on every reinstall/upgrade over a running service"
    )

    # And the launchctl invocations must actually USE that label (after the
    # script's own variable substitutions): print/bootout target
    # "system/$LABEL", bootstrap targets the plist installed under the Label
    # stem. Only real command lines are checked (a fail/echo message that
    # merely mentions launchctl is not an invocation).
    lines = _resolve_shell_vars(_logical_lines(raw))
    service_ref = f'"system/{plist_label}"'
    plist_ref = f'"/Library/LaunchDaemons/{plist_label}.plist"'
    invocations = []
    for ln in lines:
        s = re.sub(r"^(?:if|!)\s+", "", ln.strip())
        if s.startswith("launchctl"):
            invocations.append(s)
    assert invocations, "postinstall must invoke launchctl to manage the service"
    for s in invocations:
        if "bootstrap" in s:
            assert plist_ref in s, f"launchctl bootstrap must target the plist installed under the Label stem, got: {s}"
        else:
            assert service_ref in s, f"launchctl call must target {service_ref} (the plist Label), got: {s}"
    # The stale-daemon refresh path must exist and target the right label:
    # without a successful bootout an upgraded plist is never picked up.
    assert any("bootout" in s for s in invocations), (
        "postinstall must bootout the running daemon before re-bootstrapping"
    )


def test_launchd_plist_program_arguments_run_the_verified_venv() -> None:
    """ExecStart mirror: the daemon runs the venv interpreter built by
    postinstall AFTER verification — never a payload script executed directly."""
    data = _load_plist()
    args = data.get("ProgramArguments")
    assert isinstance(args, list) and all(isinstance(a, str) for a in args), (
        "ProgramArguments must be an array of strings"
    )
    assert args[0].startswith(f"{PAYLOAD_PREFIX}/venv/bin/python"), (
        f"must run the installed venv python under {PAYLOAD_PREFIX}, got {args[0]}"
    )
    assert args[-5:] == ["-m", "universal_db_mcp", "serve", "--transport", "http"], (
        "program arguments must end with '-m universal_db_mcp serve --transport http' "
        "(a daemon under launchd has no stdin client; stdio would exit 0 immediately), "
        f"got {args}"
    )


def test_launchd_plist_keepalive_and_boot_semantics() -> None:
    """systemd Restart=on-failure -> KeepAlive{SuccessfulExit=false} (a clean
    exit is NOT restarted); RestartSec=5 -> ThrottleInterval 5;
    WantedBy=multi-user.target -> RunAtLoad true."""
    data = _load_plist()
    keep_alive = data.get("KeepAlive")
    assert isinstance(keep_alive, dict), "KeepAlive must be a dict"
    assert keep_alive.get("SuccessfulExit") is False, "Restart=on-failure semantics: a clean exit must NOT be restarted"
    assert data.get("RunAtLoad") is True
    assert data.get("ThrottleInterval") == 5


def test_launchd_plist_documents_the_honest_launchd_delta() -> None:
    """launchd has NO ProtectSystem equivalent — the plan requires the delta
    to be documented in the plist, not hidden."""
    text = _require(PLIST).read_text(encoding="utf-8")
    assert "ProtectSystem" in text, "the missing ProtectSystem sandbox must be documented in the plist"


def test_launchd_plist_lints_with_plutil() -> None:
    """Native macOS validation, when plutil is available (it is on every
    macOS host; skipped elsewhere)."""
    _require(PLIST)
    plutil = shutil.which("plutil")
    if plutil is None:
        pytest.skip("plutil not available on this host")
    proc = subprocess.run(  # noqa: S603 - fixed args, local plist lint
        [plutil, "-lint", str(PLIST)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_launchd_plist_known_strict_xml_deviation_is_bounded() -> None:
    """Pins the known deviation documented in _load_plist: the header comment
    contains '--' runs, which the XML spec forbids inside comments, so strict
    parsers (plistlib/expat, xmllint) reject the raw file while launchd and
    plutil accept it. The deviation must stay confined to the comment: with
    comments stripped, the document must be well-formed and carry the real
    values. If the owner rewrites the comment without '--' runs, this test
    keeps passing (the raw file simply parses)."""
    _require(PLIST)
    raw = PLIST.read_bytes()
    strict_rejects = False
    try:
        plistlib.loads(raw)
    except ExpatError:
        strict_rejects = True

    stripped = plistlib.loads(_XML_COMMENT.sub(b"", raw))
    assert stripped.get("Label") == "com.udbmcp.server"
    assert stripped.get("Umask") == 63

    if strict_rejects:
        # the '--'-in-comment form is currently shipped; the deviation is
        # inside the comment ONLY (the stripped document parsed above)
        assert b"<key>" in raw and b"--" in raw.split(b"<plist", 1)[0], (
            "strict-parse failure must come from the header comment"
        )


def test_launchd_plist_mirrors_systemd_unit_values() -> None:
    """Cross-check the plist against packaging/systemd/universal-db-mcp.service:
    the umask radix, the config env, the program tail and the restart policy
    must agree (paths legitimately differ: /opt on Linux, /usr/local on macOS)."""
    unit_text = _require(SYSTEMD_UNIT).read_text(encoding="utf-8")
    data = _load_plist()

    m = re.search(r"^UMask=(\S+)", unit_text, re.MULTILINE)
    assert m, "systemd unit must pin UMask"
    assert int(m.group(1), 8) == data.get("Umask"), (
        f"systemd UMask={m.group(1)} (octal) must equal launchd Umask (decimal)"
    )
    assert f"Environment=UDBMCP_CONFIG={CONFIG_PATH}" in unit_text

    m = re.search(r"^ExecStart=(\S+) -m universal_db_mcp serve --transport http$", unit_text, re.MULTILINE)
    assert m, "systemd ExecStart must be '<venv python> -m universal_db_mcp serve --transport http'"
    args = data["ProgramArguments"]
    assert isinstance(args, list)
    assert args[-4:-2] == ["universal_db_mcp", "serve"], "launchd and systemd must run the same module entrypoint"
    assert args[-2:] == ["--transport", "http"], "launchd and systemd must force the same transport"
    # both sides must point the server at the bearer-token PATH the same way
    assert "Environment=UDBMCP_HTTP_BEARER_TOKEN_FILE=" in unit_text
    assert data["EnvironmentVariables"].get("UDBMCP_HTTP_BEARER_TOKEN_FILE")
    assert "Restart=on-failure" in unit_text


# --------------------------------------------------------------------------
# preinstall: trust prerequisites only, fail closed
# --------------------------------------------------------------------------


@_WIN32_ONLY
def test_preinstall_checks_both_trust_prerequisites_and_fails_closed() -> None:
    """Content gate: preinstall must guard the trusted-channel verifier AND
    the admin pubkey (plus the empty-key case) with explicit `exit 1`s, and
    must state that the release public key is never shipped in the package."""
    raw = _require(PREINSTALL).read_text(encoding="utf-8")
    text = "\n".join(_resolve_shell_vars(_logical_lines(raw)))
    assert TRUST_VERIFIER_PATH in text, "preinstall must check the trusted verifier at its fixed runbook path"
    assert ADMIN_PUBKEY_PATH in text, "preinstall must check the admin-distributed release pubkey path"
    # fail-closed guards: verifier present, pubkey present, pubkey non-empty.
    # The pubkey guards may appear with the variable or with the resolved
    # runbook path, depending on substitution order.
    pubkey_arg = rf"(?:\$PUBKEY|{re.escape(ADMIN_PUBKEY_PATH)})"
    assert re.search(r'\[\s*!\s*-f\s+"(?:\$VERIFIER|' + re.escape(TRUST_VERIFIER_PATH) + r')"\s*\]', text), (
        "missing-verifier guard absent"
    )
    assert re.search(rf'\[\s*!\s*-f\s+"{pubkey_arg}"\s*\]', text), "missing-pubkey guard absent"
    assert re.search(rf'\[\s*!\s*-s\s+"{pubkey_arg}"\s*\]', text), "empty-pubkey guard absent ([ ! -s ])"
    assert raw.count("exit 1") >= 3, "every failed prerequisite must exit 1 (fail closed)"
    assert "NEVER shipped" in raw, (
        "preinstall must state that the release pubkey is never shipped inside the package (trust invariant 2)"
    )


# The one read under the prefix preinstall may make: the INSTALLED release's
# manifest.json, parsed as JSON by the interpreter it proved root's, isolated.
_INSTALLED_MANIFEST_READ = re.compile(r"\"\$PY\" -I -S -c '(import json, sys\n[^']*)' \"\$INSTALLED_MANIFEST\"")


def _preinstall_payload_uses(raw: str) -> list[str]:
    """Everything in the preinstall text that installs, runs or reaches the payload.

    The anti-rollback check reads the installed release's manifest.json before the
    payload lands; that one read is allowed, and nothing else under the prefix."""
    lines = _logical_lines(raw)
    joined = "\n".join(_resolve_shell_vars(lines))
    uses = [f"runs {tool}" for tool in ("pip", "launchctl") if re.search(rf"\b{tool}\b", joined)]
    for match in re.finditer(re.escape(PAYLOAD_PREFIX) + r"([^\s\"';|&)]*)", joined):
        if match.group(1) not in ("", "/manifest.json"):  # the prefix's definition, the installed manifest
            uses.append(f"reaches {match.group(0)}")
    uses += [
        f"names the prefix: {ln.strip()}"
        for ln in lines
        if re.search(r"\$\{?PREFIX\b", ln) and ln.strip() != 'INSTALLED_MANIFEST="$PREFIX/manifest.json"'
    ]
    reads = _INSTALLED_MANIFEST_READ.findall(raw)
    if len(reads) > 1 or any(re.search(r"\bimport\b(?! json, sys\n)|\b(exec|eval|subprocess|os)\b", r) for r in reads):
        uses.append(f'the installed manifest is not read once, as JSON, by "$PY" -I -S: {reads}')
    rest = _logical_lines(_INSTALLED_MANIFEST_READ.sub("<read>", raw))
    uses += [
        f"uses the installed manifest: {ln.strip()}"
        for ln in rest
        if "$INSTALLED_MANIFEST" in ln
        and not ln.lstrip().startswith("echo ")
        and '[ -f "$INSTALLED_MANIFEST" ]' not in ln
    ]
    return uses


@_WIN32_ONLY
def test_preinstall_never_touches_or_executes_payload() -> None:
    """A pkg preinstall runs BEFORE the payload is unpacked: it must not
    reference, install, or execute anything from the bundle payload (no pip,
    no launchctl, no payload path). Word-boundary matched, so 'pipefail'
    cannot false-positive. Its one look under the prefix is the INSTALLED
    release's manifest.json (anti-rollback before the payload lands), read
    as JSON by the root-validated interpreter."""
    assert _preinstall_payload_uses(_require(PREINSTALL).read_text(encoding="utf-8")) == []


@_WIN32_ONLY
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("\nexit 0\n", '\n"$PREFIX/venv/bin/python" -I -m universal_db_mcp version\nexit 0\n'),
        ("\nexit 0\n", '\ncp "/usr/local/universal-db-mcp/bundle/manifest.json" /tmp/m\nexit 0\n'),
        ("\nexit 0\n", '\nBUNDLE="$PREFIX/bundle"\nexit 0\n'),
        ("\nexit 0\n", '\nsource "$INSTALLED_MANIFEST"\nexit 0\n'),
        ("\nexit 0\n", "\npython3 -c 'import json, sys' \"$INSTALLED_MANIFEST\"\nexit 0\n"),
        ("\nexit 0\n", "\npip install x\nexit 0\n"),
        ('"$PY" -I -S -c \'import json, sys', '"$PY" -c \'import json, sys'),
        ("import json, sys\n", "import json, sys\nimport subprocess\n"),
    ],
    ids=[
        "venv",
        "bundle-path",
        "prefix-var",
        "sourced-manifest",
        "other-python",
        "pip",
        "read-not-isolated",
        "read-imports-more",
    ],
)
def test_the_preinstall_payload_gate_still_sees_every_other_use(old: str, new: str) -> None:
    """Allowing the manifest read must not open the gate: every other payload use is still caught."""
    raw = _require(PREINSTALL).read_text(encoding="utf-8")
    assert raw.count(old) == 1, old
    assert _preinstall_payload_uses(raw.replace(old, new)) != []


@_WIN32_ONLY
def test_preinstall_functionally_fails_closed_without_trust_bootstrap(tmp_path: Path) -> None:
    """FUNCTIONAL (extract-and-run): on a host without the trust bootstrap,
    preinstall must exit nonzero with the canonical 'FAIL' diagnostic and the
    out-of-band bootstrap instructions.

    HONEST LIMITATION: preinstall hardcodes its trust paths (no env override),
    so this real execution is only possible where the trust material is
    genuinely absent — on a bootstrapped host the test skips rather than
    faking a path. The missing-pubkey and empty-key branches are covered by
    the content gates above; they cannot be reached functionally here without
    first installing a trusted verifier at the hardcoded root path.

    The trust paths stay the real ones; only the config directory moves into
    tmp_path. A failed preinstall removes the one-shot downgrade flag there on
    its way out, and run by root against the real path it would remove the
    host's /etc/universal-db-mcp/allow-downgrade.
    """
    script = _require(PREINSTALL)
    if os.path.exists(TRUST_VERIFIER_PATH):
        pytest.skip(
            "this host HAS a trusted verifier at the hardcoded "
            f"{TRUST_VERIFIER_PATH}; the absent-prerequisite path cannot be "
            "simulated (preinstall hardcodes its paths)"
        )
    real_config_dir = 'CONFIG_DIR="/etc/universal-db-mcp"\n'
    text = script.read_text(encoding="utf-8")
    assert text.count(real_config_dir) == 1 and text.count("/etc/universal-db-mcp/allow-downgrade") == 0
    sandboxed = tmp_path / "preinstall"
    sandboxed.write_text(text.replace(real_config_dir, f'CONFIG_DIR="{tmp_path}"\n'), encoding="utf-8")
    flag = tmp_path / "allow-downgrade"
    flag.write_text("0\n", encoding="utf-8")

    proc = subprocess.run(  # noqa: S603 - a copy of the repo script; it writes only below tmp_path
        ["/bin/bash", str(sandboxed)], capture_output=True, text=True, timeout=120
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"preinstall must fail closed when the trust bootstrap is absent:\n{out}"
    assert "FAIL" in out, f"refusal must carry the canonical FAIL diagnostic:\n{out}"
    assert "sudo install" in out, f"refusal must carry the trust-bootstrap instructions:\n{out}"
    # and it must have failed on the FIRST (verifier) prerequisite
    assert TRUST_VERIFIER_PATH in out
    assert not flag.exists(), "the failed attempt uses up the flag in the directory the copy names"


# --------------------------------------------------------------------------
# postinstall: verify-then-execute, hostile pip env, only-if-absent config
# --------------------------------------------------------------------------


def _postinstall_lines() -> list[str]:
    return _logical_lines(_require(POSTINSTALL).read_text(encoding="utf-8"))


def _pip_install_lines(lines: list[str]) -> list[str]:
    """Command lines that invoke pip install (word-boundary matched, so
    'installing'/'udbmcp_install_os_packages' prose does not match)."""
    return [
        ln
        for ln in lines
        if re.search(r"\bpip\b", ln) and re.search(r"\binstall\b", ln) and not ln.lstrip().startswith("echo")
    ]


@_WIN32_ONLY
def test_postinstall_verifies_payload_before_any_use() -> None:
    """Trust invariant 1, content gate: the trusted verifier invocation with
    the admin --pubkey must come BEFORE the first pip install and BEFORE any
    launchctl use — nothing executes or even builds from the payload before
    verification has passed."""
    lines = _postinstall_lines()
    joined = "\n".join(lines)
    assert "verify_bundle.py" in joined, "postinstall must run the trusted verifier"
    assert "--pubkey" in joined, "the verifier must be given the admin pubkey"
    pip_lines = _pip_install_lines(lines)
    assert pip_lines, "postinstall must build the venv from the wheelhouse"
    # Order on the actual INVOCATION, not the first textual mention of
    # "verify_bundle.py": in postinstall that first mention is the
    # VERIFIER= variable-definition line, which would satisfy a naive
    # index() even if the real verifier run were moved after pip/launchctl.
    m = re.search(r'(?:\$\{?VEXEC\}?|"\$\{?PYTHON_BIN\}?")\s+"\$\{?VERIFIER\}?"', joined)
    assert m, (
        'postinstall must actually invoke the verifier ($VEXEC "$VERIFIER" ... or '
        '"$PYTHON_BIN" "$VERIFIER" ...) — a VERIFIER= definition alone verifies nothing'
    )
    first_verify = joined.index(m.group(0))
    first_pip = joined.index(pip_lines[0])
    assert first_verify < first_pip, (
        f"the verifier must run BEFORE the first pip install (verify at {first_verify}, pip at {first_pip})"
    )
    assert "launchctl" in joined, "postinstall must bootstrap the launchd service"
    assert first_verify < joined.index("launchctl"), "the verifier must run BEFORE launchctl bootstraps the service"


@_WIN32_ONLY
def test_postinstall_pip_is_no_index_require_hashes_and_isolated() -> None:
    """Trust invariant 3, content gate: EVERY pip install in postinstall runs
    --no-index against the wheelhouse with --require-hashes, with the
    inherited pip environment neutralized (PIP_CONFIG_FILE=/dev/null)."""
    lines = _postinstall_lines()
    joined = "\n".join(lines)
    assert "PIP_CONFIG_FILE=/dev/null" in joined, (
        "the hostile inherited pip env must be neutralized (PIP_CONFIG_FILE=/dev/null)"
    )
    pip_lines = _pip_install_lines(lines)
    assert pip_lines, "expected at least one pip install in postinstall"
    for ln in pip_lines:
        assert "--no-index" in ln, f"pip install without --no-index: {ln}"
        assert "--require-hashes" in ln, f"pip install without --require-hashes: {ln}"


@_WIN32_ONLY
def test_postinstall_config_installed_only_if_absent() -> None:
    """The admin's config is never overwritten: the config.yaml install must
    be guarded by an only-if-absent test (a [ ! -f ] guard or an equivalent
    || fallback) near the copy."""
    lines = _resolve_shell_vars(_postinstall_lines())
    assert any(CONFIG_PATH in ln for ln in lines), f"postinstall must provision {CONFIG_PATH}"
    for i, ln in enumerate(lines):
        if CONFIG_PATH not in ln:
            continue
        if not re.search(r"\b(install|cp)\b", ln):
            continue
        window = "\n".join(lines[max(0, i - 6) : i + 6])
        if re.search(r"!\s*-f\s+[^\n]*config\.yaml", window) or re.search(r"\[\s*!\s*-f\s+\"\$\w+\"\s*\]", window):
            return
    pytest.fail(
        "the config.yaml install in postinstall is not only-if-absent "
        "(no [ ! -f ] guard found near the install/cp line)"
    )


@_WIN32_ONLY
def test_postinstall_creates_service_account_and_hardened_dirs() -> None:
    """The _udbmcp service account is created (dscl/sysadminctl) and the state
    and log dirs are installed 0750 (admin-performed hardening that launchd
    cannot express — documented plist delta)."""
    joined = "\n".join(_postinstall_lines())
    assert re.search(r"\bdscl\b|\bsysadminctl\b", joined), (
        "postinstall must create the _udbmcp service account via dscl/sysadminctl"
    )
    assert "_udbmcp" in joined
    assert "0750" in joined, "state/log dirs must be installed 0750 (launchd cannot express this)"
    assert "launchctl" in joined and "bootstrap" in joined, "postinstall must launchctl bootstrap the system service"


# --------------------------------------------------------------------------
# trust invariant 2: no key material ever ships inside a package
# --------------------------------------------------------------------------


@_WIN32_ONLY
@pytest.mark.parametrize(
    "script",
    [BUILD_PKG, PREINSTALL, POSTINSTALL],
    ids=["build_pkg.sh", "preinstall", "postinstall"],
)
def test_pkg_scripts_never_embed_or_copy_key_material(script: Path) -> None:
    text = _require(script).read_text(encoding="utf-8")
    assert "BEGIN PUBLIC KEY" not in text, (
        f"{script.name} embeds key material — the release pubkey is distributed out-of-band ONLY (trust invariant 2)"
    )
    assert not re.search(r"(?m)^\s*(?:sudo\s+)?(?:cp|install|ditto)\b[^\n]*\.pem", text), (
        f"{script.name} copies a .pem into the package payload"
    )


def test_packaging_tree_ships_no_key_files() -> None:
    """No key/certificate files may exist anywhere under packaging/ — the
    admin's release pubkey lives at /etc/universal-db-mcp/keys/ out-of-band."""
    key_files = [
        p
        for p in (REPO_ROOT / "packaging").rglob("*")
        if p.is_file() and p.suffix in {".pem", ".pub", ".key", ".crt", ".p12", ".pfx"}
    ]
    assert key_files == [], f"key material must never ship inside a package: {key_files}"
