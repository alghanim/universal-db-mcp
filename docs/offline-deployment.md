# Offline deployment (Stage B — inside the air gap)

## Prerequisites (verified platform baseline)

- Ubuntu 24.04, linux x86_64 (this profile; others are separate profiles).
- CPython 3.12 + venv: included in the bundle's baseline image for container
  mode; for native mode install from your approved internal mirror BEFORE
  transferring the bundle (record the exact patch version in the release
  record).
- Container engine (container mode): use the version in your approved
  baseline; the bundle's images are loaded with `docker load`, never pulled.

## Trust bootstrap (before install)

The verifier and installer must NOT come from inside the bundle they verify: a
tampered bundle would simply ship a verifier that prints PASSED. Install both
from the same trusted channel as the release public key, at a root-owned path
outside the bundle. The copies in the bundle's `installers/` directory are
reference copies only and are never executed.

```bash
sudo install -d -m 755 /usr/local/lib/udbmcp-trust
sudo install -m 644 <trusted-channel>/verify_bundle.py /usr/local/lib/udbmcp-trust/
sudo install -m 755 <trusted-channel>/install_offline.sh /usr/local/lib/udbmcp-trust/
```

Install the release public key at the path used throughout this runbook:

```bash
sudo install -d -m 755 /etc/universal-db-mcp /etc/universal-db-mcp/keys
sudo install -m 644 <trusted-path>/udbmcp-release.pub.pem /etc/universal-db-mcp/keys/release.pub.pem
```

## Native mode install

```bash
# transfer bundle into the air gap (approved media)
# optional pre-check with the bundle's reference copy (the installer itself
# re-verifies with the trusted copy from the trust bootstrap above):
python3 installers/verify_bundle.py --bundle <bundle-dir> --pubkey udbmcp-release.pub.pem

# The installer HARD-REQUIRES the release public key and exits 1 without it:
# an unsigned/unverified bundle must never be installed.
export UDBMCP_RELEASE_PUBKEY=/etc/universal-db-mcp/keys/release.pub.pem
# sudo strips the environment, so pass the variable through explicitly:
sudo UDBMCP_RELEASE_PUBKEY="$UDBMCP_RELEASE_PUBKEY" \
  bash /usr/local/lib/udbmcp-trust/install_offline.sh <bundle-dir> /opt/universal-db-mcp
```

The installer:
1. verifies integrity and the Ed25519 signature (the key is mandatory:
   `UDBMCP_RELEASE_PUBKEY` must point at the trusted public key PEM),
2. checks the platform baseline (fails fast on wrong Python/ABI),
3. creates a fresh venv and installs with
   `--no-index --no-cache-dir --find-links=<wheelhouse> --only-binary=:all:
   --require-hashes`, with hostile inherited pip config neutralized
   (`PIP_CONFIG_FILE=/dev/null`, index env vars overridden).

Missing wheel / OS package / licensed driver: the verifier and doctor fail
with the exact artifact named. Nothing downloads; nothing falls back.

## OS packages (Microsoft ODBC Driver 18 for SQL Server)

The bundle ships the SQL Server ODBC driver packages for the target profile
(ubuntu 24.04 amd64): `msodbcsql18` and its `unixodbc` dependencies are
staged in bundle `os-packages/` with sha256 hashes recorded in
`SHA256SUMS` (staged and wired into the builder/installer; included in the
next bundle build). The installer installs them automatically with `dpkg`
in dependency order (`odbcinst`/`libodbc2`/`libodbcinst2`/`unixodbc-common`
before `unixodbc`/`msodbcsql18`), offline — no repository access — and
idempotently: packages already installed at the required version are left
untouched, so re-running the installer is safe.

**EULA:** installing the `msodbcsql18` package constitutes accepting the
Microsoft ODBC driver EULA. The bundle merely carries the package; the
acceptance decision belongs to the administrator and is recorded at install
time.

After install, `doctor` reports driver presence explicitly: it checks for
the installed ODBC Driver 18 and names it in its output, so a missing or
mismatched driver is reported as the specific failing artifact rather than
surfacing later as an opaque connection error.

## Configure

```bash
# The installer creates the udbmcp service account and the state directories.
# The release public key was already installed under /etc/universal-db-mcp/keys
# during the trust bootstrap (it must exist BEFORE the installer runs).
sudo install -o udbmcp -g udbmcp -m 640 bundle/config-templates/config.yaml /etc/universal-db-mcp/config.yaml
sudo install -o udbmcp -g udbmcp -m 600 <secret> /run/secrets/<connection>_password
# edit /etc/universal-db-mcp/config.yaml for your connections
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
```

Doctor checks wheels, TLS material, secret-file permissions, writable paths,
and policy consistency — no database credentials required.

## Service

```bash
sudo install -m 644 bundle/operations/universal-db-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now universal-db-mcp
```

The unit runs as the dedicated `udbmcp` account with a hardened sandbox
(read-only FS, explicit writable paths, no privileges).

## Container mode

```bash
docker load -i <bundle>/images/udbmcp-baseline-ubuntu24.04-cp312.tar
docker load -i <bundle>/images/universal-db-mcp.tar
docker image inspect udbmcp/universal-db-mcp:0.1.0-linux-x86_64-ubuntu24.04-cp312  # identity check
docker network create --internal udbmcp-internal   # admin-managed
docker compose -f packaging/compose.offline.yaml up -d
```

`pull_policy: never` — an absent image fails locally; no registry contact.

## Claude Code registration

See `docs/claude-code-integration.md` and `examples/claude-code/.mcp.json`.
