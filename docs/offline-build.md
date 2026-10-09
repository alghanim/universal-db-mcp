# Offline build (Stage A — authorized staging machine only)

## Rules

- Network-enabled acquisition happens ONLY on the staging machine, as an
  explicit operator action. It is never a side effect of install/start.
- The staging machine is never bridged into production as a relay.
- Every wheel, including the application wheel, is pinned and hashed in the
  bundle's `requirements/runtime.lock`. Source installs are impossible on
  targets (`--only-binary=:all:` + hash-checked lock).

## Dependency locks and the build backend

Stage A downloads exactly the committed lock of the target profile,
`requirements/locks/<profile>.txt`, with every hash checked, and runs pip
isolated from `PIP_*` variables and `pip.conf`, so inherited index settings
are ignored. The application wheel is built with the locked build backend
(`requirements/locks/build.txt`: hatchling and its dependencies) and
`--no-isolation`. `--index-url` exists for a mirror, which can then only
serve the locked bytes. `pyproject.toml` pins the same backend closure for
`uv sync`/`uv build` through `[tool.uv] build-constraint-dependencies`.
`--check-locks` is the release gate (`release_usb.sh` and CI run it): it fails
when a lock is missing or no longer matches `requirements/runtime.in`.

To bump a dependency: edit `requirements/runtime.in`, run
`python scripts/prepare_offline_bundle.py --refresh-locks` (needs `uv` and the
network), re-lock `uv.lock` to the same versions, and review and commit both.
Delete a lock to re-resolve its transitive dependencies. The supported series
are held in `pyproject.toml`: uvicorn 0.52.4-0.53.x and h11 0.16.x (the HTTP
listener subclasses uvicorn's h11 protocol), clickhouse-connect 1.8.x (the
stream budget uses one of its seams), sqlglot 30.18.x (the guard is tested on
it), with floors `cryptography>=50` and, in the `mysql` extra,
`PyMySQL[ed25519,rsa]>=1.2.0` and `PyNaCl>=1.6.2`. The Windows bundle also
ships the `pywin32` and `tzdata` wheels its dependencies need there. ibm-db
stays on 3.2.x: 3.3.0 ships only `manylinux_2_34` Linux wheels, so the Linux
profile (resolved for `manylinux2014`, glibc 2.17) cannot lock it, and taking
it would raise the bundle's glibc floor to 2.34. `.github/dependabot.yml`
skips every release past these caps (and ibm-db 3.3); its grouped runtime
pull requests stay red until the locks are refreshed as above.

**Residual trust:** the lock hashes are whatever the index advertises when
the locks are refreshed, so an upstream release that is already compromised
at that moment would be locked too: review the lock diff before committing
it. `pip` and `uv` on the staging host are not themselves hash-pinned, and the
build venv uses `ensurepip`'s bundled pip. The manifest's `build_tools` fields
are provenance records; the verifier does not check them.

## Release order (anti-rollback)

Every signed bundle's `manifest.json` carries an integer `release_seq`, by
default the committer timestamp of `--source-rev` (`--release-seq` or
`UDBMCP_RELEASE_SEQ` overrides it). The installers refuse a bundle whose
`release_seq` is lower than the installed release's; a bundle without one
counts as older than any sequenced release, and the builder warns when
`--source-rev` is not a commit of this repository. The MSI derives its
`ProductVersion` from it, and the `.pkg` scripts carry it.

Without `--installed-manifest`, the verifier compares a bundle whose profile
is this machine's with this machine's installed release on its own
(`/opt/universal-db-mcp/manifest.json` on Linux,
`/usr/local/universal-db-mcp/manifest.json` on macOS,
`C:\Program Files\UniversalDB MCP\manifest.json` on Windows), so a release
installed on a build machine of the same platform would decide whether a
build passes. The release gates and build scripts therefore pass
`--no-installed-manifest` (`build_deb.sh`, `build_pkg.sh`, `build_msi.sh`,
`test_package_deb.sh`, `test_package_pkg.sh`, `test_upgrade_offline.sh`);
without `--installed-manifest`, a verification with
`--allow-platform-mismatch` never checks the order either. Those scripts need
this release's verifier: an older bundle's `trusted-tools/verify_bundle.py`
stops with `unrecognized arguments: --no-installed-manifest`.

## Package identity

The wheel's author, the `.deb` maintainer and the MSI's publisher are
`universal-db-mcp maintainers`. Debian requires an address in `Maintainer`,
so the `.deb` carries `maintainers@universal-db-mcp.invalid`, a reserved
name that reaches nobody: it is not a contact. Security reports go through
GitHub private vulnerability reporting (`SECURITY.md`).

## Release stick

`scripts/package/release_usb.sh` builds the signed bundles, the `.deb` and
`.pkg` through their gates, and `dist/usb-ubuntu-<sha7>/`. It writes
`SHA256SUMS` over every file of that folder and `SHA256SUMS.sig`, an Ed25519
signature of the list made with the release key, and checks the signature
with the trusted verifier's code before it finishes. Every stick carries
`trust-bootstrap-linux/RELEASE`, the Linux bundle's `release_seq`, on that
signed list; the build fails without an integer `release_seq`, and the
site's `bootstrap.sh` refuses a stick older than the release it recorded
(`docs/site-upgrade-runbook.md`, step 1). `--sign-stick <dir>` (re)signs an
existing stick folder without building, and fails on a malformed `RELEASE`.
The stick must hold
regular files only (a symlink, FIFO or device fails the release), and the
metadata a Mac or Windows writes (`._*`, `.DS_Store`, volume folders) is not
signed. The site checks `SHA256SUMS.sig` with its installed key before
anything from the stick runs (`docs/site-upgrade-runbook.md`). Copy a
finished bundle plainly (`cp -R`, `rsync` without `--link-dest`): the
verifier refuses a bundle holding any link, FIFO or device, and one whose
`SHA256SUMS` or `SIGNATURE` has a second hard link (`cp -al`).

## Procedure

```bash
# 1. (optional but recommended) generate a signing key pair once
openssl genpkey -algorithm ed25519 -out udbmcp-release.pem
openssl pkey -in udbmcp-release.pem -pubout -out udbmcp-release.pub.pem
# Distribute the PUBLIC key to targets through your existing trust process.

# 2. build the bundle
.venv/bin/python scripts/prepare_offline_bundle.py \
  --out out/bundle \
  --source-rev "$(git rev-parse HEAD 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)" \
  --signing-key udbmcp-release.pem

# 3. build + export the platform baseline image (OS + CPython 3.12 only);
#    refreshes manifest image_identity + SHA256SUMS and re-signs SIGNATURE.
#    It fails closed if the bundle already carries a SIGNATURE and
#    UDBMCP_RELEASE_KEY is unset (a stale signature would not verify).
UDBMCP_RELEASE_KEY=udbmcp-release.pem bash scripts/prepare_baseline_image.sh

# 4. container-mode application image (optional mode)
docker build --platform linux/amd64 -t udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312 \
  -f packaging/Dockerfile out/bundle/universal-db-mcp-0.1.0-linux-x86_64-ubuntu24.04-cp312
docker save udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312 \
  -o out/bundle/universal-db-mcp-*/images/universal-db-mcp.tar

# 4b. the image tar changed the bundle: refresh SHA256SUMS + SIGNATURE over
#     the finished bundle (re-runs the baseline export; docker cache makes
#     the rebuild a no-op). Skip only if step 4 was skipped.
UDBMCP_RELEASE_KEY=udbmcp-release.pem bash scripts/prepare_baseline_image.sh

# 5. verify the finished bundle (what the target will run)
#    Run the trusted-tools/ copy: it travels OUTSIDE the bundle on the same
#    trusted channel as the public key and carries profiles.py (the
#    target-profile registry the verifier requires). The copy inside the
#    bundle's installers/ directory is a reference for auditing only —
#    executing it fails closed (no registry), and a bundle must never
#    verify itself anyway. On a staging host whose platform differs from
#    the bundle profile, add --allow-platform-mismatch (staging-side
#    integrity/authenticity check only); on the actual install target,
#    run WITHOUT it. On a build machine where a release of the bundle's own
#    profile is installed, add --no-installed-manifest, or that release
#    decides the check (never on the install target).
.venv/bin/python out/bundle/trusted-tools/verify_bundle.py \
  --bundle out/bundle/universal-db-mcp-* --pubkey udbmcp-release.pub.pem
```

## Per-profile Stage A build matrix

The profile registry `scripts/profiles.py` drives the builder and the
verifier. The default profile (`linux-x86_64-ubuntu24.04-cp312`) is unchanged:
its Stage A flow is exactly the `## Procedure` block above, verbatim —
including the baseline-image export/refresh (steps 3 and 4b), the optional
container-mode application image (step 4), and the final trusted-channel
`verify_bundle.py --pubkey` run (step 5).

Windows and macOS have **no baseline image and no OS-package staging**
(targets install natively), so their Stage A reduces to the bundle build plus
the same final verification:

```
# windows-x86_64-cp312 (win_amd64; no OS-package staging, no baseline image)
.venv/bin/python scripts/prepare_offline_bundle.py \
  --profile windows-x86_64-cp312 --out out/bundle-win \
  --source-rev "$(git rev-parse HEAD 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)" \
  --signing-key udbmcp-release.pem

# macos-arm64-cp312 (macosx_11_0_arm64 + macosx_14_0_arm64 via repeated
# --platform; no OS-package staging, no baseline image)
.venv/bin/python scripts/prepare_offline_bundle.py \
  --profile macos-arm64-cp312 --out out/bundle-macos \
  --source-rev "$(git rev-parse HEAD 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)" \
  --signing-key udbmcp-release.pem

# verification (all profiles): run the trusted-tools/ copy from the trusted
# channel exactly as in step 5 above, against that profile's bundle
# directory. Do not use the reference copy inside the bundle's installers/
# directory — it fails closed without the profiles.py registry.
.venv/bin/python out/bundle-win/trusted-tools/verify_bundle.py \
  --bundle out/bundle-win/universal-db-mcp-* --pubkey udbmcp-release.pub.pem
```

### Fail-loud missing-wheel rule

Missing top-level connector wheels fail the build (SystemExit naming the
wheels and profile) — they are no longer merely recorded as a NOTE in the
manifest. The only escape hatch is `--allow-missing-connectors`, which
records the gaps and proceeds; and that flag is refused when `--signing-key`
is set:

```
--allow-missing-connectors cannot be combined with --signing-key: ...
Complete the closure, or build without the signing key.
```

A signed release can never ship a knowingly incomplete wheelhouse. If the
closure genuinely cannot be completed, the unsigned escape-hatch bundle must
go through the same trusted-channel verification before use, and its manifest
carries the missing-wheel list for the administrator to resolve out-of-band.

### Correction: ibm-db on macOS arm64

An earlier revision of this document treated Db2 (ibm-db) as unavailable on
macOS arm64. That is no longer true: **ibm-db 3.2.9 ships a
`macosx_14_0_arm64` wheel**, so the Db2 connector rides in the macOS
wheelhouse under the `macos-arm64-cp312` profile. The clidriver is bundled
with the wheel; the runtime round-trip remains unverified on all platforms,
and the builder's fail-loud rule is the backstop if PyPI drifts.

### Building the Windows .msi (Windows staging host required)

The .msi compile step can only succeed on Windows. WiX v4–v7 reject every
`Directory/@Name` on a Unix host (`error WIX0389: ... is not a relative
path`), and WiX itself warns that **all behavior on non-Windows hosts is
undefined** — an MSI linked under undefined behavior would not be shippable
even if it built. On a Unix staging host `scripts/package/build_msi.sh`
therefore fails closed at the compile step only, AFTER the full pre-compile
pipeline has run and passed (trusted-channel verification of the signed
bundle, staging, deterministic harvest, xmllint validation) — so every step
except the final compile is already proven and reusable (recorded in
`out/package-evidence/msi/`).

On a Windows staging host (Git Bash — **not WSL**: WSL uses the Linux .NET
runtime and hits the same WIX0389):

1. Install the .NET 8 SDK, then `dotnet tool install --global wix`.
2. If the `wix` shim reports "You must install .NET to run this application",
   set `DOTNET_ROOT` to the SDK directory (e.g.
   `export DOTNET_ROOT="/c/Program Files/dotnet"`) before running the script.
3. Run the same script: `bash scripts/package/build_msi.sh
   <signed-windows-bundle-dir> --pubkey <release.pub.pem>`. It verifies the
   bundle with the `trusted-tools/` verifier beside the bundle (or the one in
   `UDBMCP_TRUST_DIR`), passing
   `--allow-platform-mismatch --no-installed-manifest`, so that verifier must
   be this release's.
4. Run `scripts/test_package_msi.ps1` on that machine (msiexec install with
   logging, service query, doctor, stdio protocol probe, tamper negative, and
   the ACL, token-squat, anti-rollback, launch-condition and repair checks)
   and only then update the ledger's Windows row from `not_run` to the
   observed result.

This procedure has **not** been exercised on a Windows host in this
environment (none was available); the ledger records the Windows .msi as
authored-but-not-built with the install gate `not_run` until step 4 passes.

## What the bundle contains

- `manifest.json` — release, source rev, profile, dependency closure with
  hashes/sizes, selected connectors, **missing connector artifacts**,
  administrator-supplied prerequisites, image identity, verification steps.
- `requirements/runtime.lock` — every wheel with sha256, installable only
  from the local wheelhouse.
- `wheelhouse/` — the complete binary-wheel closure for
  linux-x86_64/cp312/manylinux2014 (42 wheels in the current build).
- `images/` — baseline and application image tars + checksums.
- `sbom/cyclonedx.json` — SBOM with a freshness note; vulnerability data
  must be re-scanned per release, never assumed current.
- `os-packages/` — administrator-supplied OS packages (e.g. Microsoft ODBC
  .deb after EULA acceptance).
- `SIGNATURE` — detached Ed25519 signature over `SHA256SUMS`, verified
  offline against an independently distributed public key. No online
  transparency log or timestamp service is used or required.

## Signing key trust

The bundle signature proves publisher authenticity only if the target
obtains the public key through an already-trusted channel (your config
management, HSM-held key ceremony, etc.). If no key is distributed, the
verifier states plainly that authenticity is unproven.
