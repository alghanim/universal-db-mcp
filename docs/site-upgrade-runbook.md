# Site runbook: upgrade in place, or erase and reinstall (Ubuntu, air-gapped)

For the release folder `usb-ubuntu-ab90e02/` (built from commit ab90e02,
27 tools). Every command runs on the air-gapped Ubuntu host, offline, as an
administrator with `sudo`. Nothing here touches any database server.

What is on the stick:

| Path | Purpose |
|---|---|
| `SHA256SUMS` | checksums of every other file on the stick |
| `universal-db-mcp_0.1.0~ab90e02…_amd64.deb` | the package (its payload is the signed offline bundle) |
| `trust-bootstrap-linux/` | the trusted verifier, installer and release public key; `bootstrap.sh` installs them |
| `oracle-instantclient/` | Oracle Instant Client 19.28 + `libaio`, only for thick-mode Oracle connections |

Which path to take:

- **Path A, upgrade in place**: keeps `/etc/universal-db-mcp/config.yaml`,
  the per-user config under `~/.universal-db-mcp/`, the audit log and the
  metadata cache. This is the normal path.
- **Path B, erase and reinstall**: use it when the current install is in an
  unknown state (a failed earlier upgrade, a venv that still runs old code,
  a status file stuck at `failed` or `running`). It deletes the venv and the
  system config; the runbook backs the config up first.

Both paths share step 0 and step 1, and both end with the same verification.

## Step 0: verify the stick, record what is installed

```bash
cd /media/$USER/*/usb-ubuntu-ab90e02        # or wherever the stick is mounted
sha256sum -c SHA256SUMS                      # every line must end in ": OK"

# what is installed right now (keep this output; it is your rollback reference)
dpkg -s universal-db-mcp | grep -E '^(Status|Version)'
sudo cat /opt/universal-db-mcp/manifest.json 2>/dev/null | python3 -c 'import json,sys; m=json.load(sys.stdin); print("installed source_rev:", m.get("source_rev"))'
cat /var/log/universal-db-mcp-install.status 2>/dev/null   # success / failed / running / absent
systemctl is-active universal-db-mcp || true
```

If `sha256sum -c` reports anything other than `OK`, stop: the stick is
damaged or altered. Use another copy.

## Step 1 (always): refresh the trusted tools from the stick

The package never installs its own verifier or installer; it runs the copies
under `/usr/local/lib/udbmcp-trust/`. Those copies are what changed between
releases (the fix that stops an upgrade from keeping old code lives in
`install_offline.sh`), so this step is mandatory on every upgrade, not only
on a fresh machine:

```bash
sudo bash trust-bootstrap-linux/bootstrap.sh
```

It installs `verify_bundle.py`, `profiles.py`, `install_offline.sh`,
`lib/os_packages.sh` to `/usr/local/lib/udbmcp-trust/` and the release
public key to `/etc/universal-db-mcp/keys/release.pub.pem`, and prints what
it did. It is safe to run twice.

## Path A: upgrade in place

```bash
# 1. stop the service (the package would do it; doing it first keeps the log clean)
sudo systemctl stop universal-db-mcp 2>/dev/null || true

# 2. install with dpkg, NOT apt
sudo dpkg -i universal-db-mcp_0.1.0~ab90e0238ea1e44b66fa22386ed80721eb29cf3f_amd64.deb
```

Expect and accept these during the install:

- `dpkg: warning: downgrading universal-db-mcp from 0.1.0~f77a… to 0.1.0~ab90e…`
  is normal. Package versions carry the commit hash and dpkg compares them
  as text, so a newer build can sort "lower". dpkg proceeds anyway; `apt`
  would refuse, which is why the command uses `dpkg -i`.
- If dpkg asks what to do with `/etc/universal-db-mcp/config.yaml`
  ("configuration file ... modified"), answer `N` (keep your current
  version). Your connections and security block are in that file; the
  shipped default is only a template.
- `dpkg -i` returns BEFORE the install is finished. The payload is verified
  synchronously, then a root worker waits for dpkg to release its locks and
  runs the trusted installer (venv rebuild with `--force-reinstall`, ODBC
  driver packages, smoke check). The service refuses to start until that
  worker records `success`.

```bash
# 3. wait for the deferred install to finish (usually one to three minutes)
watch -n 5 cat /var/log/universal-db-mcp-install.status      # leave when it says: success
tail -n 40 /var/log/universal-db-mcp-install.log              # on 'failed', the reason is here

# 4. start the service (postinst enables it; a restart picks up the new venv for sure)
sudo systemctl restart universal-db-mcp
```

If the status stays `running` for more than 10 minutes, or says `failed`,
read the log, fix the cause it names (a missing file in the trust dir, a
full disk, a locked dpkg), then re-run the configure step:
`sudo dpkg --configure universal-db-mcp`. If it fails twice, switch to
Path B; nothing half-installed is ever left executable.

## Path B: erase the current install and reinstall clean

```bash
# 1. back up everything you may want back (config, keys, per-user config)
STAMP=$(date +%F-%H%M)
sudo cp -a /etc/universal-db-mcp /root/udbmcp-etc-backup-$STAMP
cp -a ~/.universal-db-mcp ~/udbmcp-user-backup-$STAMP 2>/dev/null || true
sudo cp -a /var/lib/universal-db-mcp /root/udbmcp-state-backup-$STAMP   # audit + cache, optional

# 2. stop and purge the package (purge is not stopped by the package itself)
sudo systemctl stop universal-db-mcp 2>/dev/null || true
sudo systemctl disable universal-db-mcp 2>/dev/null || true
sudo dpkg -P universal-db-mcp

# 3. remove what purge leaves behind on purpose (old venvs, staging, cache)
sudo rm -rf /opt/universal-db-mcp /usr/share/universal-db-mcp
sudo rm -f /var/log/universal-db-mcp-install.status /var/log/universal-db-mcp-install.log
sudo rm -f /var/lib/universal-db-mcp/metadata.sqlite      # metadata cache only; the audit log stays
# the release public key under /etc/universal-db-mcp/keys/ is never removed by purge; keep it

# 4. trusted tools (step 1 above, run it again if you skipped it), then install
sudo bash trust-bootstrap-linux/bootstrap.sh
sudo dpkg -i universal-db-mcp_0.1.0~ab90e0238ea1e44b66fa22386ed80721eb29cf3f_amd64.deb
watch -n 5 cat /var/log/universal-db-mcp-install.status      # leave when it says: success

# 5. put your configuration back (the fresh install seeded only the template)
sudo cp /root/udbmcp-etc-backup-$STAMP/config.yaml /etc/universal-db-mcp/config.yaml
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
sudo cp -a /root/udbmcp-etc-backup-$STAMP/http-token /etc/universal-db-mcp/ 2>/dev/null || true
# password files referenced by the config (password_file:) live wherever you put them; purge does not touch them

# 6. start
sudo systemctl restart universal-db-mcp
```

Your per-user config (`~/.universal-db-mcp/config.yaml`) and the Claude Code
registration are not part of the package and survive the purge untouched.

## Oracle thick mode (only for the account with the legacy 10G verifier, or an 11g server)

Skip this if every Oracle connection already works. Otherwise install the
Instant Client from the stick; the commands are safe to repeat:

```bash
cd oracle-instantclient
sudo dpkg -i libaio1t64_*.deb
ls /usr/lib/x86_64-linux-gnu/libaio.so.1 2>/dev/null || \
  sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1
sudo mkdir -p /opt/oracle
sudo unzip -o instantclient-basiclite-linux.x64-19.28.zip -d /opt/oracle
echo /opt/oracle/instantclient_19_28 | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf
sudo ldconfig
ldconfig -p | grep libclntsh          # must print a line
```

Then in the connection's config block set `options: {thick_mode: true}`
(no `lib_dir` on Linux) and restart the service. Every Oracle connection in
one config must use the same mode: thick mode is process-wide.

## Verify (both paths)

```bash
# the installed code is the new release
sudo cat /opt/universal-db-mcp/manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["source_rev"])'
#   -> ab90e0238ea1e44b66fa22386ed80721eb29cf3f
grep -c db_review_schema /opt/universal-db-mcp/venv/lib/python3.12/site-packages/universal_db_mcp/server.py
#   -> a number greater than 0 (the two new tools are in the installed venv, not only in the package)

# the service
systemctl status universal-db-mcp --no-pager | head -5
sudo -u udbmcp /opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config /etc/universal-db-mcp/config.yaml

# the per-user config that Claude Code (stdio) uses, if you have one
/opt/universal-db-mcp/venv/bin/python -m universal_db_mcp doctor --config ~/.universal-db-mcp/config.yaml
```

Then start a new Claude Code session and ask it to run `db_test_connection`
on each connection. The reply now carries a `session` block: Db2 shows
`isolation: ur` and `lock_timeout_seconds: 5`, PostgreSQL and MySQL show
`read_only_verified: true`, SQL Server shows `read_uncommitted`. Also ask for
`db_review_schema` on one connection: it is one of the two new tools and
returns prioritized findings with evidence.

## What changed for an existing site (read before the first query)

Full list in `docs/offline-upgrade-rollback.md`; the ones that can surprise
you:

- **Every read-only connection now gets a server session profile**: Db2 runs
  at `UR`, SQL Server at `READ UNCOMMITTED`, PostgreSQL and MySQL are put
  into read-only mode server-side, lock waits are capped at 5 s and
  statements at `security.hard_query_timeout_seconds`. Two of these fail
  closed: a server that refuses the read-only setting refuses the connection
  with a clear message, and the per-connection `session:` block is the
  opt-out.
- **Db2 statements may end in `WITH UR` or `WITH CS`; `WITH RS`/`WITH RR` are
  refused** because they hold locks.
- **`db_get_catalog` and `db_list_indexes` no longer list system catalogs**
  (Oracle dictionary views, Db2 SYSCAT) unless asked with `include_system`.
- **`schema.table` object names work everywhere** (they were denied before).
- **Two new tools**: `db_review_schema` and `db_document_schema`.

## Rollback

The package path rebuilds the venv in place, so there is no `venv.previous`
to swap back to. Rolling back means installing the previous stick's package
with exactly these steps (its own `trust-bootstrap-linux/` first, then
`dpkg -i`, then wait for `success`). Keep the previous stick until the new
release has run for a while.
