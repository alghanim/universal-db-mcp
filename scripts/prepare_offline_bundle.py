#!/usr/bin/env python3
"""Stage A: assemble the offline release bundle on the authorized staging
machine (network access allowed HERE ONLY; the bundle itself never touches a
public endpoint at install or runtime).

What it does:
1. Builds the application wheel.
2. Downloads the complete dependency closure as wheels for the target
   profile (linux x86_64 / cp312 / manylinux), including connector wheels.
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


def wheel_meta(path: Path) -> tuple[str, str]:
    m = WHEEL_RE.match(path.name)
    if not m:
        raise SystemExit(f"unexpected artifact (not a binary wheel): {path.name}")
    name = m.group("name").replace("_", "-").lower()
    return name, m.group("ver")


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
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="linux-x86_64-ubuntu24.04-cp312", choices=["linux-x86_64-ubuntu24.04-cp312"])
    ap.add_argument("--out", required=True, help="bundle output directory")
    ap.add_argument("--connectors", default="core,postgres,mysql,clickhouse,oracle,mssql,db2",
                    help="comma list; 'core' is always included")
    ap.add_argument("--signing-key", default=None, help="PEM file with an Ed25519 private key (staging only)")
    ap.add_argument("--source-rev", default=os.environ.get("UDBMCP_SOURCE_REV", "unknown"))
    args = ap.parse_args()

    pyver, abi, plat = "3.12", "cp312", "manylinux2014_x86_64"
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
        sh([str(Path(sys.executable).parent / "python"), "-m", "build", "--wheel",
            "--outdir", td, str(PROJECT)])
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
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--only-binary=:all:",
        "--platform", plat, "--implementation", "cp",
        "--python-version", pyver, "--abi", abi,
        "--dest", str(out / "wheelhouse"),
        "-c", str(constraints),
        *pkgs,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:], file=sys.stderr)
        raise SystemExit("pip download failed for the target profile")

    # record which top-level connector wheels actually landed
    wheelhouse = sorted((out / "wheelhouse").glob("*.whl"))
    names = {wheel_meta(w)[0] for w in wheelhouse}
    for c in connectors:
        for pkg in CONNECTOR_WHEELS[c]:
            if pkg.split("[")[0].lower().replace("_", "-") not in names:
                missing.append(pkg)

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
    for name in ("verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh"):
        shutil.copy2(PROJECT / "scripts" / name, trusted / name)
    (trusted / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((trusted / n).read_bytes()).hexdigest()}  {n}\n"
            for n in ("verify_bundle.py", "install_offline.sh", "upgrade_offline.sh", "rollback_offline.sh")
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
    if "mssql" in connectors:
        os_packages = stage_os_packages(out, PROJECT / "out" / "os-packages-ubuntu24.04")
    if os_packages:
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
    if "mssql" in connectors and not os_packages:
        admin_supplied["mssql_odbc_driver"] = (
            "Microsoft ODBC Driver 18 for SQL Server (.deb) + EULA acceptance"
        )
    manifest = {
        "release": "0.1.0",
        "profile": args.profile,
        "source_rev": args.source_rev,
        "created": datetime.datetime.now(datetime.UTC).isoformat(),
        "build_tools": {
            "python": platform.python_version(),
            "pip": sh([sys.executable, "-m", "pip", "--version"]).stdout.split()[1],
        },
        "target": {"os": "ubuntu-24.04", "arch": "x86_64", "python": "3.12", "abi": "cp312"},
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
        data = (out / "SHA256SUMS").read_bytes()
        sig = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", args.signing_key, "-rawin"],
            input=data, capture_output=True
        )
        if sig.returncode == 0:
            (out / "SIGNATURE").write_bytes(sig.stdout)
        else:
            # Staging hosts with LibreSSL reject Ed25519 pkeyutl -rawin; fall
            # back to the python cryptography package (same primitive).
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key

                key = load_pem_private_key(Path(args.signing_key).read_bytes(), password=None)
                (out / "SIGNATURE").write_bytes(key.sign(data))
                print("signed with python cryptography (host openssl lacks Ed25519 pkeyutl)")
            except ImportError as exc:
                raise SystemExit(
                    f"signing failed: openssl error {sig.stderr.decode()[:200]!r} and "
                    f"no cryptography fallback installed ({exc})"
                )

    print(f"\nbundle ready: {out}")
    print(f"wheels: {len(wheelhouse)}  missing connector artifacts: {missing or 'none'}")
    if os_packages:
        print(f"os packages: {len(os_packages)} vendored into os-packages/ (hash-pinned in manifest)")
    if missing:
        print("NOTE: missing artifacts are recorded in manifest.json; the affected")
        print("connectors cannot pass readiness checks until they are supplied.")


if __name__ == "__main__":
    main()
