#!/usr/bin/env python3
"""Stage A: assemble the offline release bundle on the authorized staging
machine (network access allowed HERE ONLY; the bundle itself never touches a
public endpoint at install or runtime).

What it does:
1. Builds the application wheel.
2. Downloads the complete dependency closure as wheels for the target
   profile (see scripts/profiles.py), including connector wheels.
3. Emits a fully pinned, hashed runtime.lock (application wheel included).
4. Generates a CycloneDX-format SBOM from the wheelhouse.
5. Vendors the pre-staged OS package closure (unixODBC stack + Microsoft
   ODBC Driver 18 .debs, staged under out/os-packages-ubuntu24.04/) into
   os-packages/ and records name/hash/order metadata in the manifest.
6. Writes manifest.json, SHA256SUMS, and (when a signing key is provided) a
   detached Ed25519 signature over SHA256SUMS.

Driver licensing (Db2 Connect, Microsoft ODBC EULA) is an administrator
prerequisite; where a licensed artifact cannot be redistributed, the manifest
declares it 'administrator_supplied' and readiness checks will report it.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from scripts.profiles import PROFILES, Profile, get_profile  # noqa: E402  (repo-relative import)

CONNECTOR_WHEELS = {
    "core": ["mcp", "PyYAML", "sqlglot"],
    "postgres": ["psycopg[binary]"],
    "mysql": ["PyMySQL"],
    "clickhouse": ["clickhouse-connect"],
    "oracle": ["oracledb"],
    "mssql": ["pyodbc"],
    "db2": ["ibm-db"],
}

WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")

# dpkg dependency order for the Microsoft ODBC Driver 18 / unixODBC closure.
# Order matters: msodbcsql18's postinst invokes `odbcinst`, so the unixODBC
# stack must be configured first. Packages not listed here are installed
# first (they can only be prerequisites this table does not model).
OS_PACKAGE_INSTALL_ORDER = {
    "libkeyutils1": 0,
    "libkrb5support0": 1,
    "libk5crypto3": 2,
    "libkrb5-3": 3,
    "libltdl7": 4,
    "unixodbc-common": 5,
    "libodbc2": 6,
    "libodbcinst2": 7,
    "unixodbc": 8,
    "odbcinst": 9,
    "msodbcsql18": 10,
}


def sh(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)  # type: ignore[arg-type]
    if res.returncode != 0:
        print(res.stdout[-2000:])
        print(res.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return res


def sign_sha256sums(out: Path, signing_key: str) -> str:
    """Produce out/SIGNATURE: a detached Ed25519 signature over SHA256SUMS.

    OpenSSL 3.x's `pkeyutl -rawin` cannot read a non-seekable stdin pipe
    ('unable to determine file size for oneshot operation' — Ed25519 is a
    one-shot signer and pkeyutl needs a seekable -in), so the data is passed
    through -in/-out files exactly as scripts/verify_bundle.py does on the
    verification side. If the host openssl still refuses Ed25519 (e.g.
    LibreSSL), the python cryptography package signs instead — but the
    fallback is announced and the implementation that produced SIGNATURE is
    returned, so release provenance is never implicit.

    Returns the name of the implementation that produced SIGNATURE.
    """
    sums_path = out / "SHA256SUMS"
    sig_path = out / "SIGNATURE"
    data = sums_path.read_bytes()
    sig_path.unlink(missing_ok=True)  # never leave a partial artifact behind
    sig = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", signing_key, "-rawin",
         "-in", str(sums_path), "-out", str(sig_path)],
        capture_output=True,
    )
    if sig.returncode == 0:
        print("signed with openssl pkeyutl (Ed25519)")
        return "openssl"
    # Loud, explicit fallback: report why the primary path failed so the
    # release record shows which implementation signed the bundle.
    err = sig.stderr.decode(errors="replace").strip()[:200]
    print(f"WARNING: openssl Ed25519 signing failed ({err!r}); "
          "falling back to the python cryptography package")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(Path(signing_key).read_bytes(), password=None)
        sig_path.write_bytes(key.sign(data))
    except ImportError as exc:
        sig_path.unlink(missing_ok=True)
        raise SystemExit(
            f"signing failed: openssl error {err!r} and "
            f"no cryptography fallback installed ({exc})"
        )
    print("signed with python cryptography (host openssl lacks Ed25519 pkeyutl)")
    return "python-cryptography"


def wheel_meta(path: Path) -> tuple[str, str]:
    m = WHEEL_RE.match(path.name)
    if not m:
        raise SystemExit(f"unexpected artifact (not a binary wheel): {path.name}")
    name = m.group("name").replace("_", "-").lower()
    return name, m.group("ver")


def check_signing_conflict(signing_key: str | None, allow_missing: bool) -> None:
    """Refuse --allow-missing-connectors together with --signing-key.

    A signed release can never ship a knowingly incomplete wheelhouse: either
    complete the closure or build unsigned.
    """
    if allow_missing and signing_key:
        raise SystemExit(
            "--allow-missing-connectors cannot be combined with --signing-key: "
            "a signed release can never ship a knowingly incomplete wheelhouse. "
            "Complete the closure, or build without the signing key."
        )


def require_complete_wheelhouse(missing: list[str], profile_name: str, allow_missing: bool) -> None:
    """Fail loud when top-level connector wheels are missing from the closure."""
    if missing and not allow_missing:
        raise SystemExit(
            f"incomplete wheelhouse for profile '{profile_name}': missing connector "
            f"wheels {missing}. The affected connectors cannot pass readiness checks "
            "on targets. Re-run with --allow-missing-connectors to record them in "
            "manifest.json and continue (unsigned bundles only)."
        )


def check_os_package_closure(
    connectors: list[str],
    os_packages: list[dict[str, object]],
    profile: Profile,
    signing_key: str | None,
) -> bool:
    """Fail loud (signed) or warn loudly (unsigned) on an incomplete .deb closure.

    Mirrors BOTH scripts/verify_bundle.py closure rules for declared os_packages:

    1. Any bundle declaring msodbcsql18 must also declare the unixODBC stack
       (unixodbc): msodbcsql18's postinst invokes `odbcinst`, so the driver
       cannot be configured without it. The verifier refuses such a bundle
       unconditionally — there is no administrator_supplied fallback once the
       driver .deb is shipped — so a signed build fails here rather than
       producing a release that could never pass verification in the air gap,
       and an unsigned build proceeds only with a loud warning.
    2. When mssql is selected on a profile that stages an OS-package closure,
       the staged directory must actually contain msodbcsql18: the verifier
       refuses any bundle whose manifest selects mssql without msodbcsql18
       among the declared os_packages. A signed build therefore fails here —
       the mirror of check_signing_conflict's "a signed release can never ship
       a knowingly incomplete wheelhouse". Unsigned builds keep the documented
       administrator_supplied fallback, but loudly, never silently.

    Returns True when the vendored closure includes the mssql ODBC driver.
    """
    names = {str(e["package"]) for e in os_packages}
    driver_vendored = "msodbcsql18" in names
    # Rule 1 — applies whenever .debs are declared at all, exactly like the
    # verifier (which only exempts rule 2 for the entirely-absent case).
    if driver_vendored and "unixodbc" not in names:
        msg = (
            f"staged OS-package closure for profile '{profile.name}' declares "
            "msodbcsql18 without the unixODBC stack (unixodbc): the driver's "
            "postinst invokes `odbcinst`, so scripts/verify_bundle.py refuses "
            "any bundle that declares msodbcsql18 without unixodbc. "
        )
        if signing_key:
            raise SystemExit(
                msg + "A signed release can never ship a knowingly incomplete "
                "OS-package closure: stage the full closure (see "
                "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md), or build without the signing key."
            )
        print("WARNING: " + msg + "The bundle will fail scripts/verify_bundle.py "
              "on the target; stage the unixODBC stack .debs before release.",
              file=sys.stderr)
    if "mssql" not in connectors or not profile.os_packages_staging:
        return driver_vendored
    if driver_vendored:
        return True
    state = (
        f"missing entirely (no .debs found in {profile.os_packages_staging}/)"
        if not os_packages
        else "incomplete (msodbcsql18 is not among the staged .debs)"
    )
    msg = (
        f"staged OS-package closure for profile '{profile.name}' is {state}: "
        "the MSSQL connector would be demoted to administrator_supplied in "
        "manifest.json, and scripts/verify_bundle.py refuses a bundle that "
        "selects mssql without msodbcsql18 among the declared os_packages. "
    )
    if signing_key:
        raise SystemExit(
            msg + "A signed release can never ship a knowingly incomplete "
            "OS-package closure: stage the full closure (see "
            "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md), or build without the signing key."
        )
    print("WARNING: " + msg + "The bundle will declare the Microsoft ODBC "
          "driver administrator_supplied.", file=sys.stderr)
    return False


def pip_download_command(profile: Profile, pkgs: list[str], wheelhouse: Path, constraints: Path) -> list[str]:
    """Build the pip download command for the profile's target interpreter.

    Multiple --platform flags (e.g. both macOS tags) are passed as repeated
    flags, which pip accepts.
    """
    cmd = [sys.executable, "-m", "pip", "download", "--only-binary=:all:"]
    for plat in profile.pip_platforms:
        cmd += ["--platform", plat]
    cmd += [
        "--implementation", "cp",
        "--python-version", profile.python_version,
        "--abi", profile.abi,
        "--dest", str(wheelhouse),
        "-c", str(constraints),
        *pkgs,
    ]
    return cmd


def connectors_arg(value: str) -> str:
    """Validate and normalize the --connectors argument at the argparse boundary.

    Unknown or padded values ('trino', ' postgres') must fail as a clean
    argparse error (exit code 2), not as a raw KeyError deep inside the build.
    """
    names = [c.strip() for c in value.split(",") if c.strip()]
    unknown = sorted({c for c in names if c not in CONNECTOR_WHEELS})
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown connector(s): {', '.join(unknown)} "
            f"(valid choices: {', '.join(sorted(CONNECTOR_WHEELS))})"
        )
    if not names:
        raise argparse.ArgumentTypeError(
            "no connectors selected ('core' is always included regardless)"
        )
    return ",".join(names)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="linux-x86_64-ubuntu24.04-cp312", choices=sorted(PROFILES),
                    help="target profile (see scripts/profiles.py)")
    ap.add_argument("--out", required=True, help="bundle output directory")
    ap.add_argument("--connectors", default="core,postgres,mysql,clickhouse,oracle,mssql,db2",
                    type=connectors_arg,
                    help="comma list; 'core' is always included")
    ap.add_argument("--allow-missing-connectors", action="store_true",
                    help="record missing connector wheels in the manifest and continue "
                         "instead of failing; refused together with --signing-key")
    ap.add_argument("--signing-key", default=None, help="PEM file with an Ed25519 private key (staging only)")
    ap.add_argument("--source-rev", default=os.environ.get("UDBMCP_SOURCE_REV") or None,
                    help="source revision recorded in manifest.json. Default: git HEAD of "
                         "this repository (UDBMCP_SOURCE_REV as an environment override); "
                         "falls back to the sentinel 'unknown' with a WARNING when git is "
                         "unavailable, the tree is not a repository, or no commit exists — "
                         "package versions derived from 'unknown' cannot be tied to a "
                         "source revision.")
    return ap


def detect_git_rev(repo: Path = PROJECT) -> str | None:
    """Return the git HEAD revision of the repository containing *repo*, or
    None when git is unavailable, the path is not inside a git work tree, or
    HEAD is unborn (no commits yet). Never raises."""
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout.strip() or None


def resolve_source_rev(explicit: str | None) -> str:
    """Resolve the manifest source_rev.

    Order: an explicit --source-rev / UDBMCP_SOURCE_REV wins, then the
    automatically captured git HEAD. When the revision cannot be determined,
    fall back to the 'unknown' sentinel LOUDLY (stderr WARNING) so a bundle
    without provenance never passes unnoticed — never silently.
    """
    if explicit:
        return explicit
    rev = detect_git_rev()
    if rev:
        return rev
    print(
        "WARNING: could not determine the source revision automatically (git "
        "unavailable, not a git repository, or no commits yet); manifest "
        "source_rev will be the sentinel 'unknown'. Package versions derived "
        "from it cannot be tied to any source revision — pass --source-rev "
        "or set UDBMCP_SOURCE_REV to record one.",
        file=sys.stderr,
    )
    return "unknown"


def stage_os_packages(out: Path, staging: Path) -> list[dict[str, object]]:
    """Vendor the staged .deb closure into the bundle's os-packages/ directory.

    The closure is acquired once on the staging machine (where network access
    is allowed) into out/os-packages-ubuntu24.04/ together with a SHA256SUMS
    manifest, and is copied verbatim here so the bundle is self-contained and
    hash-pinned end to end. The bundle-wide SHA256SUMS (written later, over
    the whole tree) covers every copied file.

    Returns manifest 'os_packages' entries sorted into dpkg dependency order.
    """
    debs = sorted(staging.glob("*.deb")) if staging.is_dir() else []
    if not debs:
        return []

    staged: dict[str, str] = {}
    sums_file = staging / "SHA256SUMS"
    if sums_file.exists():
        for line in sums_file.read_text().splitlines():
            if line.strip():
                digest, _, fname = line.partition("  ")
                staged[fname.strip()] = digest

    # Fail loud on a declared-but-absent staged .deb: SHA256SUMS is copied
    # verbatim into the bundle below, so silently dropping the file would
    # ship a bundle whose os-packages/SHA256SUMS declares a .deb it does not
    # contain — a signed release that could never pass verification.
    missing_staged = sorted(
        name for name in staged
        if name.endswith(".deb") and not (staging / name).is_file()
    )
    if missing_staged:
        raise SystemExit(
            "staged OS-package closure is incomplete: staging SHA256SUMS "
            f"declares {missing_staged} but the file(s) are absent from "
            f"{staging}. Re-stage the missing .deb(s) (or regenerate the "
            "staging SHA256SUMS) before building."
        )

    entries: list[dict[str, object]] = []
    for deb in debs:
        digest = hashlib.sha256(deb.read_bytes()).hexdigest()
        expected = staged.get(deb.name)
        if expected and expected != digest:
            raise SystemExit(
                f"staged OS package does not match its SHA256SUMS entry: {deb.name}"
            )
        # deb filenames are <package>_<version>_<arch>.deb; underscores cannot
        # appear inside a Debian package name or version, so this split is safe.
        pkg, version, arch = (deb.name[: -len(".deb")].split("_", 2) + ["unknown", "unknown"])[:3]
        entries.append({
            "package": pkg,
            "version": version,
            "architecture": arch,
            "file": deb.name,
            "path": f"os-packages/{deb.name}",
            "sha256": digest,
            "size": deb.stat().st_size,
            "install_order": OS_PACKAGE_INSTALL_ORDER.get(pkg, -1),
        })
    entries.sort(key=lambda e: (int(str(e["install_order"])), str(e["file"])))

    dest = out / "os-packages"
    for e in entries:
        shutil.copy2(staging / str(e["file"]), dest / str(e["file"]))
    if sums_file.exists():
        shutil.copy2(sums_file, dest / "SHA256SUMS")
    return entries


def main() -> None:
    args = build_arg_parser().parse_args()
    check_signing_conflict(args.signing_key, args.allow_missing_connectors)
    source_rev = resolve_source_rev(args.source_rev)
    if args.signing_key and source_rev == "unknown":
        print(
            "WARNING: signing a bundle whose manifest source_rev is the sentinel "
            "'unknown': the signature attests the payload bytes but ties them to "
            "no source revision. Pass --source-rev (or UDBMCP_SOURCE_REV) to "
            "record one.",
            file=sys.stderr,
        )
    profile = get_profile(args.profile)

    connectors = ["core"] + [c for c in args.connectors.split(",") if c != "core"]
    missing: list[str] = []

    out = Path(args.out) / f"universal-db-mcp-0.1.0-{args.profile}"
    if out.exists():
        shutil.rmtree(out)
    for d in ("requirements", "wheelhouse", "native-drivers", "os-packages", "images",
              "installers", "config-templates", "licenses", "sbom", "docs", "tests",
              "test-evidence"):
        (out / d).mkdir(parents=True)

    # 1. application wheel -----------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        sh([sys.executable, "-m", "build", "--wheel", "--outdir", td, str(PROJECT)])
        app_wheels = list(Path(td).glob("*.whl"))
        assert len(app_wheels) == 1, app_wheels
        app_wheel_name = app_wheels[0].name
        shutil.copy2(app_wheels[0], out / "wheelhouse" / app_wheel_name)

    # 2. dependency closure ----------------------------------------------------
    pkgs = [p for c in connectors for p in CONNECTOR_WHEELS[c]]
    # Constrain resolution to the reviewed pins in requirements/runtime.in so
    # a rebuild cannot silently ship different (undocumented) versions.
    constraints = Path(tempfile.mkstemp(suffix=".txt")[1])
    # pip rejects extras in constraint files, so strip [extras] while keeping
    # the pinned version (the extra is still requested on the command line).
    import re as _re

    constraints.write_text(
        "\n".join(
            _re.sub(r"([A-Za-z0-9._-]+)\[[^\]]*\]", r"\1", line.split(" #")[0].strip())
            for line in (PROJECT / "requirements" / "runtime.in").read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
        + "\n"
    )
    cmd = pip_download_command(profile, pkgs, out / "wheelhouse", constraints)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:], file=sys.stderr)
        raise SystemExit("pip download failed for the target profile")

    # record which top-level connector wheels actually landed, and fail loud
    # when any are missing (a signed release can never ship a knowingly
    # incomplete wheelhouse; see --allow-missing-connectors)
    wheelhouse = sorted((out / "wheelhouse").glob("*.whl"))
    names = {wheel_meta(w)[0] for w in wheelhouse}
    for c in connectors:
        for pkg in CONNECTOR_WHEELS[c]:
            if pkg.split("[")[0].lower().replace("_", "-") not in names:
                missing.append(pkg)
    require_complete_wheelhouse(missing, profile.name, args.allow_missing_connectors)

    # 3. runtime.lock (every wheel, hashed; application wheel included) --------
    lines = [
        "# Generated by scripts/prepare_offline_bundle.py — do not edit.",
        f"# profile: {args.profile}",
        "# install with: pip install --no-index --no-cache-dir --find-links=<wheelhouse> "
        "--only-binary=:all: --require-hashes -r runtime.lock",
    ]
    for w in wheelhouse:
        name, ver = wheel_meta(w)
        digest = hashlib.sha256(w.read_bytes()).hexdigest()
        lines.append(f"{name}=={ver} --hash=sha256:{digest}")
    (out / "requirements" / "runtime.lock").write_text("\n".join(lines) + "\n")

    # 4. SBOM (CycloneDX 1.5, hand-generated from the wheelhouse) ---------------
    components = []
    for w in wheelhouse:
        name, ver = wheel_meta(w)
        components.append({
            "type": "library", "name": name, "version": ver,
            "purl": f"pkg:pypi/{name}@{ver}",
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(w.read_bytes()).hexdigest()}],
        })
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "note": "Generated from the offline bundle wheelhouse. Vulnerability "
                    "data must be refreshed by re-running the scan on the staging "
                    "machine; this SBOM does not stay current by itself.",
        },
        "components": components,
    }
    (out / "sbom" / "cyclonedx.json").write_text(json.dumps(sbom, indent=2))

    # 5. supporting files --------------------------------------------------------
    for f in ("docs",):
        for doc in (PROJECT / f).glob("*.md"):
            shutil.copy2(doc, out / "docs" / doc.name)
    for doc in (PROJECT.glob("*.md")):
        if doc.name != "BUILD_UNIVERSAL_DB_MCP_AIRGAPPED.md":
            shutil.copy2(doc, out / doc.name)
    shutil.copy2(PROJECT / "config.example.yaml", out / "config-templates" / "config.yaml")
    shutil.copy2(PROJECT / "examples" / "sqlite-demo" / "create_demo.py", out / "config-templates" / "create_demo.py")
    shutil.copy2(PROJECT / "examples" / "sqlite-demo" / "config.template.yaml", out / "config-templates" / "config.template.yaml")
    # Reference copies ONLY. The executable verifier/installer travel in the
    # separate trusted-tools/ output (same channel as the public key) and are
    # installed under /usr/local/lib/udbmcp-trust; install_offline.sh refuses
    # to run from inside a bundle, so a tampered bundle cannot verify itself.
    shutil.copy2(PROJECT / "scripts" / "verify_bundle.py", out / "installers" / "verify_bundle.py")
    shutil.copy2(PROJECT / "scripts" / "install_offline.sh", out / "installers" / "install_offline.sh")
    (out / "installers" / "README.md").write_text(
        "# Reference copies only\n\nThese files are included for auditing. Do NOT execute them from\n"
        "here: the installer refuses to run from inside a bundle. Use the copies\n"
        "distributed in `trusted-tools/` over the same trusted channel as the\n"
        "release public key (see docs/offline-deployment.md, 'Trust bootstrap').\n"
    )
    trusted = Path(args.out) / "trusted-tools"
    trusted.mkdir(parents=True, exist_ok=True)
    trusted_lib = trusted / "lib"
    trusted_lib.mkdir(exist_ok=True)
    for name in ("verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh",
                 "profiles.py"):
        shutil.copy2(PROJECT / "scripts" / name, trusted / name)
    # install_offline.sh / upgrade_offline.sh source lib/os_packages.sh from
    # the directory they run from; a trusted-tools copy without the helper
    # makes every install abort after verification ("shared OS-package
    # helper not found") — shipped 2026-09-11 and caught by Gate A/B.
    shutil.copy2(PROJECT / "scripts" / "lib" / "os_packages.sh", trusted_lib / "os_packages.sh")
    trusted_names = (
        "verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh",
        "profiles.py", "lib/os_packages.sh",
    )
    (trusted / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((trusted / n).read_bytes()).hexdigest()}  {n}\n"
            for n in trusted_names
        )
    )
    ops = out / "operations"
    ops.mkdir(exist_ok=True)
    for op in ("upgrade_offline.sh", "rollback_offline.sh", "load_images_offline.sh", "doctor.sh"):
        shutil.copy2(PROJECT / "scripts" / op, ops / op)
    shutil.copy2(PROJECT / "packaging" / "systemd" / "universal-db-mcp.service", ops / "universal-db-mcp.service")
    shutil.copy2(PROJECT / "packaging" / "compose.offline.yaml", ops / "compose.offline.yaml")
    shutil.copy2(PROJECT / "scripts" / "in_container_test.sh", out / "tests" / "in_container_test.sh")
    shutil.copy2(PROJECT / "scripts" / "protocol_probe.py", out / "tests" / "protocol_probe.py")
    (out / "tests" / "README.md").write_text(
        "# Bundle test profile\n\nRun `in_container_test.sh` inside a clean, "
        "network-restricted Ubuntu 24.04 container matching the profile. See "
        "docs/acceptance-tests.md.\n"
    )
    # 5b. OS packages: vendor the staged .deb closure (unixODBC stack +
    #     Microsoft ODBC Driver 18) when mssql is selected, so install targets
    #     never need apt, a vendor repository, or any network access.
    os_packages: list[dict[str, object]] = []
    if "mssql" in connectors and profile.os_packages_staging:
        os_packages = stage_os_packages(out, PROJECT / profile.os_packages_staging)
    mssql_driver_vendored = check_os_package_closure(
        connectors, os_packages, profile, args.signing_key,
    )
    if mssql_driver_vendored and os_packages:
        (out / "os-packages" / "README.md").write_text(
            "# OS packages\n\nThis bundle ships a pre-staged, hash-pinned OS package "
            "closure for the MSSQL connector (unixODBC stack + Microsoft ODBC Driver 18 "
            "for SQL Server). Files and hashes are recorded in manifest.json "
            "(os_packages) and covered by the bundle-wide SHA256SUMS. "
            "scripts/install_offline.sh installs them with dpkg only — no apt, no "
            "vendor repository, no network — in the recorded dependency order. "
            "EULA acceptance for the Microsoft driver is an administrator "
            "responsibility on the staging side.\n"
        )
    else:
        (out / "os-packages" / "README.md").write_text(
            "# OS packages\n\nPlace administrator-acquired OS packages here "
            "(e.g. Microsoft ODBC driver .deb files, after EULA acceptance). "
            "The application never adds vendor repositories on targets.\n"
        )
    (out / "licenses" / "README.md").write_text(
        "# Licenses\n\nWheel licenses are recorded in the SBOM. Vendor driver "
        "licenses (IBM, Microsoft, Oracle) are NOT included; administrators "
        "must hold the required entitlements.\n"
    )

    # 6. manifest ----------------------------------------------------------------
    admin_supplied: dict[str, str] = {}
    if "db2" in connectors:
        admin_supplied["db2_connect_license"] = "Db2 Connect client licensing if connecting to z/OS or i"
    if "mssql" in connectors and not mssql_driver_vendored:
        admin_supplied["mssql_odbc_driver"] = (
            f"Microsoft ODBC Driver 18 for SQL Server ({profile.odbc_driver_package}) + EULA acceptance"
        )
    manifest = {
        "release": "0.1.0",
        "profile": args.profile,
        "source_rev": source_rev,
        "created": datetime.datetime.now(datetime.UTC).isoformat(),
        "build_tools": {
            "python": platform.python_version(),
            "pip": sh([sys.executable, "-m", "pip", "--version"]).stdout.split()[1],
        },
        "target": dict(profile.manifest_target),
        "selected_connectors": connectors,
        "connector_wheel_status": {
            "included": sorted(names), "missing_from_closure": missing,
        },
        "os_packages": {
            "install_order": [str(e["file"]) for e in os_packages],
            "packages": os_packages,
        } if os_packages else {},
        "administrator_supplied": admin_supplied,
        "omitted_optional_components": ["trino", "duckdb", "mongodb", "thick-mode-oracle-client"],
        "image_identity": None,
        "verification": "python3 /usr/local/lib/udbmcp-trust/verify_bundle.py --bundle <this-dir> --pubkey <trusted-key> (verifier from the trusted channel, never from this bundle)",
        "wheels": [
            {"name": wheel_meta(w)[0], "version": wheel_meta(w)[1], "file": w.name,
             "sha256": hashlib.sha256(w.read_bytes()).hexdigest(), "size": w.stat().st_size}
            for w in wheelhouse
        ],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # 7. checksums + signature ----------------------------------------------------
    sums = []
    for f in sorted(out.rglob("*")):
        if f.is_file() and f.name not in ("SHA256SUMS", "SIGNATURE"):
            rel = f.relative_to(out)
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {rel}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")

    if args.signing_key:
        sign_sha256sums(out, args.signing_key)

    print(f"\nbundle ready: {out}")
    print(f"source_rev: {source_rev}")
    print(f"wheels: {len(wheelhouse)}  missing connector artifacts: {missing or 'none'}")
    if os_packages:
        print(f"os packages: {len(os_packages)} vendored into os-packages/ (hash-pinned in manifest)")
    if missing:
        print("NOTE: missing artifacts are recorded in manifest.json; the affected")
        print("connectors cannot pass readiness checks until they are supplied.")


if __name__ == "__main__":
    main()
