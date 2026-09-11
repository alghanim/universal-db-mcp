# Offline build (Stage A — authorized staging machine only)

## Rules

- Network-enabled acquisition happens ONLY on the staging machine, as an
  explicit operator action. It is never a side effect of install/start.
- The staging machine is never bridged into production as a relay.
- Every wheel, including the application wheel, is pinned and hashed in
  `requirements/runtime.lock`. Source installs are impossible on targets
  (`--only-binary=:all:` + hash-checked lock).

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
.venv/bin/python out/bundle/universal-db-mcp-*/installers/verify_bundle.py \
  --bundle out/bundle/universal-db-mcp-* --pubkey udbmcp-release.pub.pem
```

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
