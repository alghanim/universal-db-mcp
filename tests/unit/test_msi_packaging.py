"""Phase 5 regression tests for the Windows .msi packaging (artifact: msi:tests).

These tests run WITHOUT dotnet/wix and WITHOUT any Windows machine — they pin
the trust model of the MSI at the authoring level:

1. ``packaging/msi/udbmcp.wxs``: perMachine scope, MajorUpgrade, the per-machine
   CPython 3.12 RegistrySearch/LaunchCondition, the ProgramData config component
   with NeverOverwrite, and the DELIBERATE ABSENCE of ServiceInstall (with the
   explaining comment) — the venv python.exe does not exist at authoring time,
   so the service is registered by deferred ``sc.exe`` custom actions instead.
2. Every PowerShell custom action in ``packaging/msi/custom/`` fails closed
   (``$ErrorActionPreference = 'Stop'`` and a nonzero exit path).
3. ``verify.ps1`` runs the ADMIN-installed trusted ``verify_bundle.py --pubkey``
   from OUTSIDE the bundle and executes nothing from the payload before that
   verification passes (trust invariant 1), with containment guards so a
   tampered bundle cannot "verify itself".
4. ``venv.ps1`` builds the venv with pip ``--no-index --require-hashes`` from the
   bundle wheelhouse only, with the hostile pip environment neutralized
   (``PIP_CONFIG_FILE = 'NUL'``, proxy/index vars scrubbed, ``--isolated``,
   ``--only-binary=:all:`` so no setup.py is ever executed) (trust invariant 3).
5. ``service.ps1`` registers the service via ``sc.exe`` with failure recovery
   (restart actions), mirroring the systemd unit's ``Restart=on-failure``.
6. THE WIRING ITSELF: the deferred actions are real authored
   ``CustomAction`` elements scheduled by ``InstallExecuteSequence`` —
   deferred, ``Impersonate="no"``, ``Return="check"``, sequenced verify ->
   venv -> doctor -> service with the verify action first — and the five
   ``.ps1`` scripts actually SHIP inside the MSI (``ScriptsDir`` components).
   Comment prose claiming actions are "wired up" never satisfies these
   gates: only authored, comment-stripped XML can sequence an action, so a
   wxs whose actions exist only in comments fails here (that silent
   producer gap is exactly what this suite exists to prevent).

Trust invariant 2 (the release public key is NEVER shipped inside a package —
the admin distributes it out-of-band) is asserted against the whole
``packaging/msi`` tree.

Ownership note: this file tests producer files owned by the msi-builder
workflow (``packaging/msi/**``). A producer file that has not landed yet causes
an HONEST skip with a named reason — never a silent pass. PowerShell syntax
checks run only where ``pwsh`` is available (e.g. a Windows host); content
gates are pure text/XML and run everywhere.

Pattern copied from tests/unit/test_pkg_packaging.py and
tests/unit/test_deb_packaging.py: comment-stripped content gates (so prose in
comments can neither satisfy nor defeat a gate) plus structural XML checks.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# xml.etree (expat) is used on a FIRST-PARTY repo file (packaging/msi/udbmcp.wxs)
# that we author and review; it declares no DTD/entities, and CPython's expat
# ships the billion-laughs protections. defusedxml is not a project dependency
# and this test must not add one — the trust boundary for packaging content is
# the signed-bundle verification pipeline, not this parser.

REPO_ROOT = Path(__file__).resolve().parents[2]

MSI_DIR = REPO_ROOT / "packaging" / "msi"
WXS = MSI_DIR / "udbmcp.wxs"
CUSTOM_DIR = MSI_DIR / "custom"
VERIFY_PS1 = CUSTOM_DIR / "verify.ps1"
VENV_PS1 = CUSTOM_DIR / "venv.ps1"
SERVICE_PS1 = CUSTOM_DIR / "service.ps1"

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"

# Every custom action the wxs / build_msi.sh wiring is expected to ship. Files
# owned by the concurrent msi-builder workflow; a missing one skips honestly.
KNOWN_CUSTOM_ACTIONS = ("verify.ps1", "venv.ps1", "doctor.ps1", "service.ps1", "uninstall.ps1")

# The deferred (and rollback) custom actions the wxs must wire, with the
# script each one runs. The install chain IS the trust model: verify first,
# then venv (still no payload run), then doctor (FIRST payload execution),
# then service registration of verified, doctor-healthy payload only.
DEFERRED_INSTALL_ACTIONS = (
    ("VerifyBundleCA", "verify.ps1"),
    ("BuildVenvCA", "venv.ps1"),
    ("DoctorSmokeCA", "doctor.ps1"),
    ("RegisterServiceCA", "service.ps1"),
)
# Uninstall mirror (runs only on REMOVE="ALL") and the rollback twin that
# undoes a half-registered service when any install action fails.
DEFERRED_UNINSTALL_ACTION = ("RemoveServiceCA", "uninstall.ps1")
ROLLBACK_ACTION = ("RollbackRemoveServiceCA", "uninstall.ps1")
# The commit action that removes the rollback copy of the installed-release
# record once the install has succeeded.
COMMIT_ACTION = ("CommitReleaseRecordCA", "uninstall.ps1")

BUILD_MSI_SH = REPO_ROOT / "scripts" / "package" / "build_msi.sh"

_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _require(path: Path) -> Path:
    """Return *path*, or SKIP with an honest, named reason when the producer
    file (or directory) has not landed yet (it is owned by the concurrent
    msi-builder workflow). A pending producer must never look like a passing
    test. Directories are accepted (is_file() would wrongly skip them)."""
    if not path.exists():
        try:
            where = str(path.relative_to(REPO_ROOT))
        except ValueError:  # pragma: no cover - always under REPO_ROOT here
            where = str(path)
        pytest.skip(f"{where} does not exist yet (msi-builder artifact pending)")
    return path


def _read_wxs() -> str:
    return _require(WXS).read_text(encoding="utf-8")


def _wxs_code_text() -> str:
    """The .wxs with XML comments stripped, so gates apply to authored XML —
    never to the (extensive) trust-model prose in the comments."""
    return _XML_COMMENT.sub("", _read_wxs())


def _wxs_root() -> ET.Element:
    """Parse the .wxs (WiX v4/v5 namespace) into an ElementTree root."""
    try:
        return ET.fromstring(_wxs_code_text())  # noqa: S314 - first-party repo file, no DTD/entities (see module note)
    except ET.ParseError as exc:  # pragma: no cover - structural regression guard
        raise AssertionError(f"udbmcp.wxs does not parse as XML after comment stripping: {exc}") from exc


def _localname(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _iter_local(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if _localname(el) == name]


def _ps_code_lines(text: str) -> list[str]:
    """PowerShell code as logical lines: backtick-newline continuations joined
    (so a multi-line pip command is ONE line for flag checks) and comment-only
    lines dropped (so the trust-model prose in the headers cannot satisfy or
    defeat a gate). Limitation, stated honestly: a trailing comment on a code
    line stays in the line; gate regexes below tolerate that."""
    text = re.sub(r"`\r?\n", " ", text)  # backtick line continuation
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _ps_code_text(path: Path) -> str:
    return "\n".join(_ps_code_lines(_require(path).read_text(encoding="utf-8")))


def _invocation_lines(lines: list[str]) -> list[str]:
    """PowerShell lines that invoke an external command via the call operator
    (`& ...`), in EITHER form: line-initial (`& cmd ...`) or as the right-hand
    side of an assignment (`$x = & cmd ...`) — both execute the command, so a
    trust gate must see both (search-anchored, like the bundle-dir-as-command
    gate in test_verify_bundle_dir_is_only_ever_an_argument_never_a_command).
    Cmdlets (Test-Path, Join-Path, Get-Command, ...) are NOT external processes
    and are excluded."""
    return [ln for ln in lines if re.search(r"(?<!\w)&\s", ln)]


# --------------------------------------------------------------------------
# udbmcp.wxs: well-formed authoring
# --------------------------------------------------------------------------


def test_wxs_parses_as_strict_xml() -> None:
    """The authored .wxs must be well-formed XML (the WiX compiler's first
    requirement; this is the same check `xmllint --noout` gives on the
    staging host, run natively here)."""
    _require(WXS)
    ET.fromstring(WXS.read_text(encoding="utf-8"))  # noqa: S314 - first-party repo file, no DTD/entities (see module note)


def test_wxs_package_is_permachine_with_frozen_upgradecode() -> None:
    """Scope="perMachine" (the WiX v4/v5 name of InstallScope="perMachine") and
    a fixed UpgradeCode (frozen across the product line so upgrades/downgrades
    are detected)."""
    pkg = _iter_local(_wxs_root(), "Package")
    assert len(pkg) == 1, "exactly one Package element expected"
    attrs = pkg[0].attrib
    assert attrs.get("Scope") == "perMachine", f"Package Scope must be perMachine, got {attrs.get('Scope')!r}"
    assert attrs.get("UpgradeCode"), "Package must carry a fixed UpgradeCode"
    assert attrs.get("Version") == "$(var.ProductVersion)", "version comes from build_msi.sh via -define"


def test_wxs_has_major_upgrade_with_downgrade_block() -> None:
    major = _iter_local(_wxs_root(), "MajorUpgrade")
    assert len(major) == 1, "exactly one MajorUpgrade element expected"
    assert major[0].get("DowngradeErrorMessage"), "MajorUpgrade must block downgrades with a message"


def test_wxs_installfolder_is_under_the_64bit_program_files_root() -> None:
    """The whole install tree (INSTALLFOLDER, and with it BundleDir/ScriptsDir)
    must live under the 64-bit Program Files root
    (<StandardDirectory Id="ProgramFiles64Folder">) — the x64 payload and the
    default paths the action scripts derive ($env:ProgramFiles\\UniversalDB MCP)
    depend on it. A producer regression relocating the tree under a 32-bit or
    per-user root must fail here."""
    root = _wxs_root()
    holders = [
        el for el in _iter_local(root, "StandardDirectory")
        if any(d.get("Id") == "INSTALLFOLDER" for d in _iter_local(el, "Directory"))
    ]
    assert len(holders) == 1, f"INSTALLFOLDER must be authored under exactly one standard directory, got {len(holders)}"
    assert holders[0].get("Id") == "ProgramFiles64Folder", (
        f"INSTALLFOLDER must be a child of StandardDirectory Id='ProgramFiles64Folder' "
        f"(the 64-bit Program Files root), got {holders[0].get('Id')!r}"
    )


def test_wxs_launch_condition_requires_permachine_cpython312() -> None:
    """Prerequisite gate: a per-machine python.org CPython 3.12 (PEP 514,
    HKLM\\SOFTWARE\\Python\\PythonCore\\3.12\\InstallPath), read from the
    64-bit registry view, wired into a Launch element that also keeps
    uninstall/repair working ('Installed OR').

    WiX v4/v5 spelling (verified against the real compiler): RegistrySearch
    uses Bitness="always64" (v3's Win64 attribute is rejected with WIX0004)
    and the gate is <Launch> (v3's <LaunchCondition> child of Package is
    rejected with WIX0005)."""
    root = _wxs_root()
    searches = [el for el in _iter_local(root, "RegistrySearch") if "PythonCore\\3.12" in (el.get("Key") or "")]
    assert searches, "a RegistrySearch for SOFTWARE\\Python\\PythonCore\\3.12\\InstallPath is required"
    rs = searches[0]
    assert rs.get("Root") == "HKLM", "the prerequisite is a PER-MACHINE CPython (HKLM), not a per-user install"
    assert rs.get("Bitness") == "always64", "the x64 MSI must read the 64-bit registry view (WiX v4 Bitness)"
    assert "Win64" not in rs.attrib, "Win64 is a WiX v3 attribute (WIX0004) and must not return"
    prop_id = None
    for el in root.iter():
        if rs in list(el):  # direct parent (ET elements compare by identity)
            prop_id = el.get("Id")
            break
    assert prop_id, "the RegistrySearch must feed a Property"
    launches = _iter_local(root, "Launch")
    assert launches, "the CPython 3.12 prerequisite must be enforced by a Launch element (WiX v4 spelling)"
    conditions = [c.get("Condition") or "" for c in launches]
    assert any(prop_id in cond and "Installed" in cond for cond in conditions), (
        f"ONE Launch condition must hold BOTH the RegistrySearch property {prop_id} AND 'Installed' "
        f"(uninstall/repair must keep working); splitting them into separate Launch elements would "
        f"block fresh installs, got conditions: {conditions!r}"
    )


def test_wxs_config_component_under_programdata_is_never_overwrite() -> None:
    """Machine-wide config at ProgramData\\UniversalDB MCP\\config.yaml,
    NeverOverwrite="yes": upgrades and repairs never clobber admin-edited
    configuration (mirrors the .deb conffile and pkg install-only-if-absent).

    C:\\ProgramData is the MSI standard directory CommonAppDataFolder
    (WiX error WIX0021 rejects any other Id under StandardDirectory)."""
    root = _wxs_root()
    programdata = [el for el in _iter_local(root, "StandardDirectory") if el.get("Id") == "CommonAppDataFolder"]
    assert programdata, "a ProgramDataFolder directory tree is required"
    comps = _iter_local(programdata[0], "Component")
    config_comps = [
        c for c in comps if any((f.get("Name") == "config.yaml") for f in _iter_local(c, "File"))
    ]
    assert config_comps, "ProgramData tree must install config.yaml"
    comp = config_comps[0]
    assert comp.get("NeverOverwrite") == "yes", "config.yaml must be NeverOverwrite (admin edits survive upgrades)"
    assert comp.get("Guid"), "the config component needs a stable GUID so MSI tracks the file across upgrades"
    files = [f for f in _iter_local(comp, "File") if f.get("Name") == "config.yaml"]
    assert files[0].get("KeyPath") == "yes", "config.yaml must be the component KeyPath"


def test_wxs_has_no_serviceinstall_and_explains_why() -> None:
    """WiX ServiceInstall/ServiceControl are DELIBERATELY ABSENT: the venv
    python.exe the service runs does not exist at MSI-authoring time (it is
    created by a custom action), so the service is registered by deferred
    sc.exe custom actions instead. The absence must be structural (not just an
    accident of naming) AND the explaining comment must stay in the file."""
    root = _wxs_root()
    for name in ("ServiceInstall", "ServiceControl", "Service"):
        assert _iter_local(root, name) == [], f"no {name} element may appear in udbmcp.wxs"
    code = _wxs_code_text()
    for name in ("ServiceInstall", "ServiceControl"):
        assert name not in code, f"{name} must not appear in the authored XML (comments excluded)"
    raw = _read_wxs()
    assert "ServiceInstall" in raw, "the comment explaining the deliberate absence of ServiceInstall must be kept"
    comment_text = " ".join(m.group(0) for m in _XML_COMMENT.finditer(raw))
    assert "custom action" in comment_text and "authoring time" in comment_text, (
        "the ServiceInstall comment must explain the reason: the venv python.exe is created by a "
        "custom action and does not exist at authoring time (deferred sc.exe actions instead)"
    )


def test_wxs_documents_sc_exe_service_registration() -> None:
    """The replacement mechanism (deferred sc.exe create/failure custom
    actions) must be named in the wxs, including the failure-recovery
    configuration that mirrors systemd Restart=on-failure."""
    raw = _read_wxs()
    assert "sc.exe create" in raw and "sc.exe failure" in raw, (
        "the wxs must document the deferred sc.exe create/failure custom actions that replace ServiceInstall"
    )
    assert "Restart=on-failure" in raw, "the systemd restart-policy mirror must be referenced"


def test_wxs_harvested_payload_components_cannot_run_early() -> None:
    """The signed bundle is harvested by build_msi.sh (heat) into
    harvest.wxi as plain components under BundleDir. The wxs must reference it
    as a ComponentGroupRef and must NOT attach conditions/custom actions to
    the payload that could run bundle bits early (trust invariant 1)."""
    code = _wxs_code_text()
    assert 'Id="HarvestedBundleComponents"' in code, "the harvested signed-bundle payload must be referenced"
    assert "<ComponentGroupRef" in code, "the payload is a ComponentGroupRef, not hand-authored components"
    assert "<ComponentGroup " not in code, "payload components are generated (harvest.wxi), not authored inline"
    assert "<?include" in code and "harvest.wxi" in code, "harvest.wxi must be included at build time"


# --------------------------------------------------------------------------
# udbmcp.wxs: the deferred custom actions are AUTHORED, SCHEDULED XML
# --------------------------------------------------------------------------


def _build_msi_code() -> str:
    """build_msi.sh with full-line comments dropped (header prose cannot
    satisfy a gate); code lines keep any trailing comments."""
    return "\n".join(
        ln for ln in _require(BUILD_MSI_SH).read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )


def _deferred_actions(root: ET.Element) -> dict[str, ET.Element]:
    """CustomAction elements that actually execute at install time (deferred,
    rollback or commit). An immediate type-51 property assignment has no
    Execute attribute and is excluded."""
    return {
        ca.get("Id"): ca
        for ca in _iter_local(root, "CustomAction")
        if ca.get("Execute") in ("deferred", "rollback", "commit")
    }


def _install_sequence_elements(root: ET.Element) -> dict[str, ET.Element]:
    """The <Custom> scheduling elements inside InstallExecuteSequence, keyed
    by the action they schedule."""
    seq = _iter_local(root, "InstallExecuteSequence")
    assert seq, (
        "udbmcp.wxs must author an InstallExecuteSequence: comments cannot sequence actions, only <Custom> elements can"
    )
    return {el.get("Action"): el for el in seq[0] if _localname(el) == "Custom"}


def test_wxs_wires_the_deferred_custom_actions_as_authored_xml() -> None:
    """The deferred actions are real CustomAction ELEMENTS (parsed with
    comments stripped), each running its .ps1 via powershell.exe with
    Impersonate="no" (LocalSystem: per-machine writes and sc.exe need it) and
    Return="check" (any nonzero exit — verify.ps1 fails closed on every
    verification failure — aborts and rolls back the install). A wxs whose
    only mention of the actions is a comment must fail here, and so must a
    wxs that grew an unreviewed extra deferred action."""
    root = _wxs_root()
    deferred = _deferred_actions(root)
    expected = dict(DEFERRED_INSTALL_ACTIONS)
    expected[DEFERRED_UNINSTALL_ACTION[0]] = DEFERRED_UNINSTALL_ACTION[1]
    expected[ROLLBACK_ACTION[0]] = ROLLBACK_ACTION[1]
    expected[COMMIT_ACTION[0]] = COMMIT_ACTION[1]
    assert set(deferred) == set(expected), (
        f"the deferred/rollback custom action set changed: got {sorted(deferred)}, expected {sorted(expected)} — "
        "review the change and update this gate; an unreviewed action must not ship silently"
    )
    for action_id, script in expected.items():
        ca = deferred[action_id]
        assert ca.get("Impersonate") == "no", (
            f"{action_id} must run impersonate=no (LocalSystem), got {ca.get('Impersonate')!r}"
        )
        if action_id == COMMIT_ACTION[0]:
            # it runs once the install has committed: nothing is left to roll back
            assert ca.get("Return") == "ignore", f"{action_id} must use Return=ignore"
        else:
            assert ca.get("Return") == "check", f"{action_id} must use Return=check so a nonzero exit fails the install"
        exe = ca.get("ExeCommand") or ""
        assert re.search(rf'-File\s+"\[INSTALLFOLDER\]scripts\\{re.escape(script)}"', exe), (
            f"{action_id} must run packaging/msi/custom/{script} from the installed ScriptsDir, got: {exe!r}"
        )
        assert ca.get("Property") == "POWERSHELLEXE", (
            f"{action_id} must run through the POWERSHELLEXE property (set by the SetPowerShellExe action), "
            "not an arbitrary or caller-influenceable executable"
        )
    for action_id, _ in DEFERRED_INSTALL_ACTIONS + (DEFERRED_UNINSTALL_ACTION,):
        assert deferred[action_id].get("Execute") == "deferred", f"{action_id} must be a deferred action"
    assert deferred[ROLLBACK_ACTION[0]].get("Execute") == "rollback", (
        "RollbackRemoveServiceCA must be a rollback action (it undoes a half-registered service)"
    )
    assert deferred[COMMIT_ACTION[0]].get("Execute") == "commit", (
        "CommitReleaseRecordCA must be a commit action (it runs only once the install succeeded)"
    )


def test_wxs_verify_action_runs_only_the_trusted_verifier_arguments() -> None:
    """The verify custom action passes the installed bundle path to
    verify.ps1 (via -CustomActionData BUNDLE_DIR=...) and nothing else that
    could pre-execute payload: no venv interpreter, no wheelhouse code, no
    python from the bundle."""
    deferred = _deferred_actions(_wxs_root())
    assert "VerifyBundleCA" in deferred, "the VerifyBundleCA custom action must be authored in the wxs"
    exe = deferred["VerifyBundleCA"].get("ExeCommand") or ""
    assert "BUNDLE_DIR=[INSTALLFOLDER]bundle" in exe, (
        "the verify action must pass the installed bundle dir as CustomActionData"
    )
    for forbidden in ("venv\\python.exe", "python.exe\"", "wheelhouse", "-m universal_db_mcp"):
        assert forbidden not in exe, (
            f"the verify action must not reference executable payload: {forbidden!r} in {exe!r}"
        )


def test_wxs_powershell_exe_is_pinned_to_the_system_path() -> None:
    """POWERSHELLEXE — the executable every deferred action runs through — is
    assigned unconditionally (immediate action) to the inbox Windows
    PowerShell at its fixed system path, so nothing the caller does can
    redirect the deferred actions to a different interpreter."""
    root = _wxs_root()
    setters = [ca for ca in _iter_local(root, "CustomAction") if ca.get("Id") == "SetPowerShellExe"]
    assert setters, "an immediate SetPowerShellExe action must define POWERSHELLEXE for the deferred actions"
    value = setters[0].get("Value") or ""
    assert value.endswith("WindowsPowerShell\\v1.0\\powershell.exe"), (
        f"POWERSHELLEXE must be the inbox system powershell.exe at a fixed path, got: {value!r}"
    )
    assert setters[0].get("Execute") is None, (
        "SetPowerShellExe must be immediate (script-generation time), not deferred"
    )


def test_wxs_installexecutesequence_schedules_verify_before_any_payload_action() -> None:
    """THE trust ordering, enforced on the scheduling elements (not prose):
    VerifyBundleCA runs after InstallFiles (the bundle must be on disk to be
    verified) and STRICTLY BEFORE venv, doctor and service — nothing that
    uses the payload may run before the trusted verify_bundle.py action has
    passed (trust invariant 1). A later re-wiring that runs payload first
    turns this test red."""
    sequence = _install_sequence_elements(_wxs_root())
    after = {action: el.get("After") for action, el in sequence.items() if el.get("After")}
    assert after.get("VerifyBundleCA") == "InstallFiles", (
        "VerifyBundleCA must be scheduled after InstallFiles (the installed bundle must exist when it is verified)"
    )
    assert after.get("BuildVenvCA") == "VerifyBundleCA", "venv build must run only AFTER the verify action passed"
    assert after.get("DoctorSmokeCA") == "BuildVenvCA", (
        "doctor smoke (FIRST payload execution) must run only AFTER the venv build"
    )
    assert after.get("RegisterServiceCA") == "DoctorSmokeCA", (
        "service registration must run only AFTER the doctor smoke validated the install"
    )


def test_wxs_install_path_actions_are_conditioned_off_uninstall() -> None:
    """Every install-path action is conditioned with NOT REMOVE so the
    uninstall sequence runs only the service-removal mirror (and never
    re-verifies/rebuilds anything), and every one of them fails the install
    on a nonzero exit (Return=check is asserted separately)."""
    elements = _install_sequence_elements(_wxs_root())
    for action_id, _ in DEFERRED_INSTALL_ACTIONS + (ROLLBACK_ACTION,):
        el = elements.get(action_id)
        assert el is not None, f"{action_id} must be scheduled in InstallExecuteSequence"
        assert el.get("Condition") == "NOT REMOVE", (
            f"{action_id} must run on install/repair only (Condition='NOT REMOVE'), got {el.get('Condition')!r}"
        )


def test_wxs_uninstall_and_rollback_mirrors_are_scheduled() -> None:
    """sc.exe is not transactional, so BOTH mirrors must be scheduled, not
    merely implemented: the rollback twin is scheduled IMMEDIATELY BEFORE
    RegisterServiceCA (Windows Installer pairs a rollback action with the
    deferred action that directly follows it — placed anywhere later it would
    protect the wrong action) so a failing install removes the half-configured
    service, and the uninstall action stops/deletes the service BEFORE
    RemoveFiles deletes the uninstall.ps1 file that action itself runs."""
    elements = _install_sequence_elements(_wxs_root())
    rollback = elements.get(ROLLBACK_ACTION[0])
    assert rollback is not None, "RollbackRemoveServiceCA must be scheduled in the install script"
    assert rollback.get("Before") == "RegisterServiceCA", (
        "the rollback twin must be scheduled directly before RegisterServiceCA "
        "(MSI pairs a rollback action with the deferred action that follows it)"
    )
    removal = elements.get(DEFERRED_UNINSTALL_ACTION[0])
    assert removal is not None, "RemoveServiceCA must be scheduled in InstallExecuteSequence"
    assert removal.get("Before") == "RemoveFiles", (
        "the uninstall mirror must run before RemoveFiles deletes the uninstall.ps1 file it executes"
    )
    assert removal.get("Condition") == 'REMOVE="ALL"', (
        f"the uninstall mirror must run on REMOVE=ALL only, got {removal.get('Condition')!r}"
    )


def test_wxs_ships_the_custom_action_scripts_outside_the_bundle() -> None:
    """The five .ps1 implementations must SHIP inside the MSI as components
    under ScriptsDir (referenced by the Main feature), and ScriptsDir must be
    a SIBLING of BundleDir — never inside the bundle — because verify.ps1
    refuses to run from inside the bundle it would verify."""
    root = _wxs_root()
    dirs = {d.get("Id"): d for d in _iter_local(root, "Directory")}
    assert "ScriptsDir" in dirs, "the ScriptsDir directory must be authored in the wxs"
    scripts_dir = dirs["ScriptsDir"]
    ancestors = set()
    parent_map = {child: parent for parent in root.iter() for child in parent}
    node = scripts_dir
    while node in parent_map:
        node = parent_map[node]
        ancestors.add(node.get("Id"))
    assert "BundleDir" not in ancestors, (
        "ScriptsDir must live OUTSIDE the bundle directory "
        "(a verifier shipped in the payload would be a tampered verifier)"
    )
    files = {
        f.get("Name"): f
        for c in _iter_local(scripts_dir, "Component")
        for f in _iter_local(c, "File")
    }
    for name in KNOWN_CUSTOM_ACTIONS:
        f = files.get(name)
        assert f is not None, f"{name} must ship inside the MSI as a ScriptsDir component"
        assert "$(var.CustomActionScriptsDir)" in (f.get("Source") or ""), (
            f"{name} must be sourced from the build-provided CustomActionScriptsDir"
        )
    feature = [el for el in _iter_local(root, "Feature") if el.get("Id") == "Main"]
    assert feature, "the Main feature must exist"
    refs = {r.get("Id") for r in _iter_local(feature[0], "ComponentRef")}
    comp_ids = {c.get("Id") for c in _iter_local(scripts_dir, "Component")}
    assert comp_ids and comp_ids <= refs, (
        f"every ScriptsDir component must be referenced by the Main feature (unreferenced: {comp_ids - refs})"
    )


def test_build_msi_defines_custom_action_scripts_dir_and_stages_every_action_script() -> None:
    """build_msi.sh must stage ALL five action scripts (a missing one fails
    the build), pass the staged dir to the wxs via -define
    CustomActionScriptsDir, and run the same no-key-material scan over the
    staged scripts as over the payload — they ship inside the package too."""
    code = _build_msi_code()
    assert 'CustomActionScriptsDir=$CUSTOM_STAGE' in code, (
        "build_msi.sh must pass -define CustomActionScriptsDir=<staged custom scripts> to wix build"
    )
    staged = re.search(r"for ps1 in ((?:verify|venv|doctor|service|uninstall)\.ps1[;\s]+){5}", code)
    assert staged, (
        "build_msi.sh must stage ALL five custom action scripts (verify/venv/doctor/service/uninstall) — "
        "a missing one is a packaging bug: fail closed"
    )
    staged_names = set(re.findall(r"(verify|venv|doctor|service|uninstall)\.ps1", staged.group(0)))
    assert staged_names == {"verify", "venv", "doctor", "service", "uninstall"}, (
        f"the five staged scripts must be DISTINCT (got {sorted(staged_names)}): "
        "repeating one name must not substitute for a missing action script"
    )
    assert 'find_pubkey_material "$CUSTOM_STAGE"' in code, (
        "the staged custom action scripts must get the same pubkey-material scan as the payload"
    )


# --------------------------------------------------------------------------
# every custom action ps1: fail-closed policy
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", KNOWN_CUSTOM_ACTIONS)
def test_custom_action_fails_closed_policy(name: str) -> None:
    """EVERY custom action PowerShell script must set
    $ErrorActionPreference = 'Stop' (cmdlet failures become terminating errors)
    AND have a nonzero exit path (exit 1) so the deferred action with
    Return="check" rolls the install back (trust invariant 4: fail closed)."""
    code = _ps_code_text(CUSTOM_DIR / name)
    assert re.search(r"\$ErrorActionPreference\s*=\s*'Stop'", code), (
        f"{name} must set $ErrorActionPreference = 'Stop' in code (not only in comments)"
    )
    assert re.search(r"(?m)^\s*exit\s+1\b", code), f"{name} must have a nonzero exit path (exit 1) to fail the install"


def test_every_ps1_present_in_custom_dir_fails_closed() -> None:
    """Catch-all so a FUTURE custom action (doctor.ps1, rollback twins, ...)
    cannot sneak in without the fail-closed policy: $ErrorActionPreference =
    'Stop' AND a nonzero exit path (exit 1), the same policy the three known
    actions are held to — with Return="check", only a real nonzero exit makes
    msiexec roll back. Iterates whatever is actually on disk; skips honestly
    if the directory has not landed yet."""
    _require(CUSTOM_DIR)
    ps1_files = sorted(CUSTOM_DIR.glob("*.ps1"))
    assert ps1_files, "packaging/msi/custom must ship at least the verify/venv/service custom actions"
    for ps1 in ps1_files:
        code = _ps_code_text(ps1)
        assert re.search(r"\$ErrorActionPreference\s*=\s*'Stop'", code), (
            f"{ps1.name} must set $ErrorActionPreference = 'Stop'"
        )
        assert re.search(r"(?m)^\s*exit\s+1\b", code), (
            f"{ps1.name} must have a nonzero exit path (exit 1) to fail the install"
        )


@pytest.mark.parametrize("name", KNOWN_CUSTOM_ACTIONS)
def test_custom_action_powershell_syntax(name: str) -> None:
    """Native PowerShell syntax validation via the language parser, when pwsh
    is available (e.g. on a Windows host or the delivered gate machine). Skipped
    honestly on hosts without pwsh — the content gates above still run."""
    script = _require(CUSTOM_DIR / name)
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh is None:
        pytest.skip("pwsh/powershell not available on this host; content gates still apply")
    cmd = (
        "$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{script}', [ref]$null, [ref]$e) | Out-Null; "
        "if ($e -and $e.Count) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 } exit 0"
    )
    proc = subprocess.run(  # noqa: S603 - fixed args, local syntax check
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, f"{name} has PowerShell syntax errors: {proc.stdout}{proc.stderr}"


# --------------------------------------------------------------------------
# verify.ps1: trusted-channel verification BEFORE any payload execution
# --------------------------------------------------------------------------


def _verify_code() -> str:
    return _ps_code_text(VERIFY_PS1)


def _verify_lines() -> list[str]:
    return _ps_code_lines(_require(VERIFY_PS1).read_text(encoding="utf-8"))


def test_verify_runs_trusted_verifier_from_outside_the_bundle_with_pubkey() -> None:
    """Trust invariant 1: the action runs the ADMIN-installed trusted
    verify_bundle.py (resolved from a trust directory OUTSIDE the bundle, e.g.
    C:\\Program Files\\udbmcp-trust) with the admin-distributed --pubkey. The
    verifier is NEVER taken from the payload it would verify."""
    code = _verify_code()
    assert "verify_bundle.py" in code, "verify.ps1 must run the trusted verify_bundle.py"
    assert "--pubkey" in code, "the verifier must be given the admin pubkey"
    assert "udbmcp-trust" in code, "the verifier must be resolved from the admin trust directory outside the bundle"
    assert "Join-Path $TrustDir 'verify_bundle.py'" in code, (
        "the verifier path must come from the trust dir, not the bundle"
    )


def test_verify_first_process_invocation_is_the_trusted_verifier() -> None:
    """Nothing external is executed before the verifier EXCEPT the pinned
    interpreter's own version probe: verify.ps1 resolves the per-machine
    CPython 3.12 exclusively from the admin-only HKLM PEP 514 hive (never
    py.exe/PATH/HKCU -- a local non-admin can register a per-user interpreter)
    and proves it is 3.12 before executing the trusted verifier with it. The
    probe is an inline -c version check on that admin-owned interpreter whose
    exit code is the ONLY decision input -- no bundle-derived path or content
    is involved (run isolated, -I, like every LocalSystem python run). The
    first invocation touching bundle/trust material must still be the
    verifier run itself."""
    invocations = _invocation_lines(_verify_lines())
    assert invocations, "verify.ps1 must invoke the trusted verifier"
    first = invocations[0]
    verifier_run = [ln for ln in invocations if "$Verifier" in ln]
    assert verifier_run, "verify.ps1 must run the trusted verifier"
    assert "--bundle" in verifier_run[0] and "--pubkey" in verifier_run[0], (
        f"verifier invocation lacks its arguments: {verifier_run[0]}")
    if "$Verifier" not in first:
        assert re.search(
            r"&\s*\$pyExe\s+-I\s+-c\s+'import sys; sys\.exit\(0 if sys\.version_info\[:2\] == \(3, 12\) else 1\)'",
            first,
        ), (f"the only invocation allowed before the trusted verifier is the "
            f"HKLM-pinned interpreter's cp312 version probe, got: {first}")
        for subject in ("$BundleDir", "$TrustDir", "$PubKey", "$Verifier"):
            assert subject not in first, (
                f"the pre-verifier version probe must not touch {subject}: {first}")


def test_verify_bundle_dir_is_only_ever_an_argument_never_a_command() -> None:
    """The installed bundle directory is only ever READ (passed as the
    verifier's --bundle argument or existence-tested). No line may invoke
    anything derived from it."""
    for ln in _verify_lines():
        if "$BundleDir" in ln and re.search(r"(?<!\w)&\s*\$BundleDir", ln):
            pytest.fail(f"the bundle directory is used as a COMMAND (payload execution): {ln}")
        # no invocation whose command expression resolves inside the bundle;
        # the ONE permitted exception is the cp312 version probe of the
        # HKLM-pinned per-machine interpreter (inline -c check, no bundle- or
        # trust-derived content on the command line)
        if re.search(r"&\s*\$pyExe", ln) and "$Verifier" not in ln:
            assert "sys.version_info" in ln and "$BundleDir" not in ln, (
                f"an interpreter is invoked for something other than the trusted "
                f"verifier or the pinned interpreter's version probe: {ln}")


def test_verify_containment_guards_reject_in_bundle_trust_material() -> None:
    """Defense in depth: a tampered bundle ships its own verifier/key and
    'verifies' itself — so the trust directory, the release pubkey, the python
    interpreter AND the running script itself must each be refused if they
    resolve inside the bundle directory."""
    code = _verify_code()
    for subject in ("$TrustDir", "$PubKey", "$pyExe", "$PSCommandPath"):
        pattern = rf"Test-InsideDir\s+{re.escape(subject)}\s+\$BundleDir"
        assert re.search(pattern, code), f"missing containment guard for {subject} inside the bundle"
        # the guard must fail closed: a Fail call must exist in the script for it
    assert code.count("Fail \"") >= 4, "each containment violation must produce a fail-closed diagnostic"


def test_verify_fails_closed_on_every_non_passing_verifier_outcome() -> None:
    """Trust invariant 4: nonzero verifier exit, a FAIL line, or a missing
    'bundle verification PASSED' proof each abort the install. Exit code alone
    is not trusted — success requires explicit proof."""
    code = _verify_code()
    assert re.search(r"\$verifierExit\s+-ne\s+0", code), "a nonzero verifier exit must fail the install"
    assert "(?m)^FAIL:" in code, "verifier FAIL diagnostics must fail the install"
    assert "'bundle verification PASSED'" in code and "-notmatch" in code, (
        "success requires the verifier's explicit 'bundle verification PASSED' proof, not just exit 0"
    )
    assert "exit 0" in code, "verify.ps1 must reach exit 0 ONLY on the verified path"


def test_verify_pubkey_is_never_embedded() -> None:
    """Trust invariant 2: the release public key is distributed out-of-band by
    the admin — no key material may be embedded in the script."""
    raw = _require(VERIFY_PS1).read_text(encoding="utf-8")
    assert "BEGIN PUBLIC KEY" not in raw, "verify.ps1 embeds key material — the pubkey is admin-distributed out-of-band"
    assert "out-of-band" in raw, "the script must state the out-of-band key distribution model"


# --------------------------------------------------------------------------
# venv.ps1: hashed, no-index wheelhouse-only install, hostile pip env neutralized
# --------------------------------------------------------------------------


def _venv_code() -> str:
    return _ps_code_text(VENV_PS1)


def _venv_pip_install_lines() -> list[str]:
    """Actual pip-install invocation lines (backtick continuations already
    joined): the venv python running `-m pip ... install`. A prose mention of
    pip (e.g. a Fail diagnostic) is NOT an invocation."""
    lines = _ps_code_lines(_require(VENV_PS1).read_text(encoding="utf-8"))
    return [ln for ln in lines if re.search(r"&\s*\$VenvPython", ln) and "-m pip" in ln and " install " in ln]


def test_venv_pip_is_no_index_require_hashes_from_wheelhouse_only() -> None:
    """Trust invariant 3: EVERY pip install runs --no-index --require-hashes
    against the bundle wheelhouse only (via --find-links), pinned by the signed
    runtime.lock, with --isolated so ambient pip env/config cannot override the
    command-line policy."""
    pip_lines = _venv_pip_install_lines()
    assert pip_lines, "venv.ps1 must install the application from the bundle wheelhouse"
    for ln in pip_lines:
        assert "--no-index" in ln, f"pip install without --no-index: {ln}"
        assert "--require-hashes" in ln, f"pip install without --require-hashes: {ln}"
        assert "--find-links=$Wheelhouse" in ln, f"pip install must source ONLY the bundle wheelhouse: {ln}"
        assert "--isolated" in ln, f"pip install must run --isolated (ambient env cannot weaken policy): {ln}"
        assert "$Lock" in ln, f"pip install must resolve from the signed runtime.lock: {ln}"


def test_venv_no_sdist_or_setuppy_execution() -> None:
    """--only-binary=:all: forbids sdists, so no setup.py from the wheelhouse
    is ever executed — payload code is first run by the (later) doctor smoke
    action, after verification has passed."""
    pip_lines = _venv_pip_install_lines()
    assert pip_lines, "expected a pip install in venv.ps1"
    for ln in pip_lines:
        assert "--only-binary=:all:" in ln, f"pip install must forbid sdist/setup.py execution: {ln}"


def test_venv_neutralizes_hostile_pip_environment() -> None:
    """PIP_CONFIG_FILE points at the NUL device (Windows equivalent of the
    /dev/null used by install_offline.sh and the pkg postinstall), and inherited
    index/proxy variables are scrubbed before pip runs."""
    code = _venv_code()
    assert "$env:PIP_CONFIG_FILE = 'NUL'" in code, (
        "the hostile inherited pip config must be neutralized with PIP_CONFIG_FILE=NUL"
    )
    for hostile in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "http_proxy", "https_proxy", "HTTPS_PROXY"):
        assert hostile in code, f"inherited {hostile} must be scrubbed before pip runs"
    assert "$env:PIP_NO_INDEX = '1'" in code, "PIP_NO_INDEX must back the command-line --no-index"


def test_venv_defers_to_the_verify_action_and_executes_no_payload() -> None:
    """venv.ps1 performs NO trust decision of its own: it documents that it must
    be scheduled AFTER the trusted verify_bundle.py action has passed, and it
    never executes anything from the bundle (wheels are unpacked by pip, the
    interpreter is the machine's CPython, not the bundle's)."""
    raw = _require(VENV_PS1).read_text(encoding="utf-8")
    assert "verify_bundle.py" in raw, (
        "venv.ps1 must document its scheduling dependency on the trusted verify_bundle.py custom action"
    )
    for ln in _invocation_lines(_ps_code_lines(raw)):
        assert "$BundleDir" not in ln, f"venv.ps1 must not execute anything from the bundle: {ln}"
        assert "venv\\python.exe" not in ln or "-m pip" in ln or "-m venv" in ln, (
            f"unexpected direct venv-python invocation: {ln}"
        )


# --------------------------------------------------------------------------
# service.ps1: deferred sc.exe registration with failure recovery
# --------------------------------------------------------------------------


def _service_code() -> str:
    return _ps_code_text(SERVICE_PS1)


def test_service_registers_via_sc_exe_with_autostart() -> None:
    """The service is registered by deferred sc.exe custom actions (ServiceInstall
    is impossible: the venv python.exe does not exist at authoring time), with
    start= auto mirroring the systemd unit's auto-start. service.ps1 invokes
    sc.exe through Invoke-Tool and builds the argument string dynamically
    ('create ' + $ServiceName + ' binPath= ...'), so the gates match that
    construction."""
    code = _service_code()
    assert re.search(r"ScExe\s*=\s*Join-Path\s+\$env:SystemRoot\s+'System32\\sc\.exe'", code), (
        "service.ps1 must resolve the system sc.exe (System32), not a PATH lookup"
    )
    assert re.search(r"if \(-not \$ServiceName\) \{ \$ServiceName = 'udbmcp' \}", code), (
        "the service name must default to 'udbmcp' (applied after the documented "
        "UDBMCP_SERVICE_NAME environment fallback)"
    )
    assert re.search(r"'create\s+'\s*\+\s*\$ServiceName", code), "service.ps1 must run 'sc.exe create <service>'"
    assert re.search(r"start=\s*auto", code), "the service must be created with start= auto"
    assert "binPath=" in code, "the service must point at the custom-action-created venv interpreter (binPath=)"
    assert "-m universal_db_mcp serve" in code, "binPath must run the verified venv module entrypoint"
    assert "serve --transport http" in code, (
        "the SCM daemon has no stdin client: it must force HTTP transport "
        "(stdio would read EOF and exit 0; failure recovery only fires on nonzero exit)"
    )


def test_service_configures_failure_recovery() -> None:
    """Failure recovery (sc.exe failure ...) mirrors systemd Restart=on-failure:
    restart actions with a reset period, so a crashed server is restarted by the
    service control manager."""
    code = _service_code()
    assert re.search(r"'failure\s+'\s*\+\s*\$ServiceName", code), (
        "service.ps1 must configure sc.exe failure recovery for the service"
    )
    assert re.search(r"reset=\s*\d+", code), "failure recovery needs a failure counter reset period"
    assert re.search(r"actions=\s*restart/\d+", code), "failure actions must restart the service after an interval"


def test_service_uninstall_mirrors_with_stop_and_delete() -> None:
    """Uninstall/upgrade must stop AND delete the service (sc.exe stop / sc.exe
    delete) — the mirror of the deferred create action — and a failing install
    must clean up the half-configured service (sc.exe is not transactional).
    Each verb is asserted separately: a producer emitting only one of them
    must fail here."""
    code = _service_code()
    # helpers take the service name as a $Name parameter; argument fragments
    # appear with either quote style ('create ' + $ServiceName / "stop " + $Name)
    for verb in ("stop", "delete"):
        svc_arg = rf"['\"]{verb}\s+['\"]\s*\+\s*(?:\$ServiceName|\$Name)"
        assert re.search(svc_arg, code), f"uninstall/upgrade path must run sc.exe {verb} on the service"
    assert re.search(r"\bRemove-ServiceBestEffort\b", code), (
        "a failing install must best-effort remove the half-configured service before exiting nonzero"
    )


# --------------------------------------------------------------------------
# trust invariant 2 across the whole packaging/msi tree
# --------------------------------------------------------------------------


def test_msi_tree_ships_no_key_files_and_no_embedded_keys() -> None:
    """No key/certificate files may exist anywhere under packaging/msi, and no
    text file may embed PEM material — the admin distributes the release pubkey
    out-of-band ONLY."""
    _require(MSI_DIR)
    key_files = [
        p for p in MSI_DIR.rglob("*") if p.is_file() and p.suffix in {".pem", ".pub", ".key", ".crt", ".p12", ".pfx"}
    ]
    assert key_files == [], f"key material must never ship inside the MSI: {key_files}"
    for text_file in [p for p in MSI_DIR.rglob("*") if p.is_file()]:
        assert "BEGIN PUBLIC KEY" not in text_file.read_text(encoding="utf-8", errors="replace"), (
            f"{text_file.name} embeds key material — the release pubkey is distributed out-of-band only"
        )
