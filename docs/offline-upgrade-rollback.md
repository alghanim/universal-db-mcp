# Offline upgrade and rollback runbook

## Upgrade

```bash
# 1. acquire the NEW signed bundle (staging) and transfer into the air gap
# 2. preflight + install (atomic venv switch, config/state backup first)
sudo bash <bundle>/operations/upgrade_offline.sh <new-bundle-dir> /opt/universal-db-mcp
# 3. validate
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor
sudo systemctl restart universal-db-mcp
```

Properties:

- The old venv is preserved at `/opt/universal-db-mcp/venv.previous`.
- Configuration and metadata cache are backed up to
  `/var/backups/universal-db-mcp/pre-upgrade-<ts>/`.
- An interrupted upgrade leaves `venv.new-*` behind and the running venv
  untouched; re-running the script discards the partial venv and rebuilds.
- Dependencies are installed ONLY from the new bundle's hashed wheelhouse.
- Both scripts REQUIRE `UDBMCP_RELEASE_PUBKEY` and verify the bundle
  signature before touching anything.

## Rollback

```bash
sudo bash <bundle>/operations/rollback_offline.sh /opt/universal-db-mcp
sudo systemctl restart universal-db-mcp
```

Restores the previous venv and (if present) the latest config/state backup.

## Importing security fixes

Security updates enter the air gap the same way as releases: a refreshed
signed bundle built on the staging machine with re-scanned SBOM/vulnerability
data. Record the scan date; do not assume offline scan databases stay
current. Never "hotfix" dependencies inside the air gap by downloading.

## Evidence expectations

Record upgrade/rollback exercises (success + deliberate-interruption) in
`test-evidence/` per docs/acceptance-tests.md §G.
