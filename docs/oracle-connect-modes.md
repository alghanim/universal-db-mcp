# Oracle connect modes (udbmcp, air-gapped)

Covers the Oracle cases that a plain `host:port/service` connection cannot
reach: legacy password verifiers, pre-12c SIDs, `tnsnames.ora` aliases, and
TLS. Related: `docs/driver-matrix.md`, `docs/offline-deployment.md`.

## 1. `DPY-3015: password verifier type 0x939 is not supported`

The server is authenticating this session with the legacy 10G verifier, and
python-oracledb in Thin mode (our default) implements the 11G and 12C
verifiers only. It is not a wrong password and not a network problem.

**Two different server states produce it**, so check both before choosing a
remedy:

```sql
-- 1. what the account carries
SELECT username, password_versions FROM dba_users WHERE username = '<USER>';
--    '10G' alone        -> the account has no modern verifier
--    '10G 11G 12C'      -> the account is fine; the server is choosing 10G, see 2

-- 2. whether the server forces the old, case-insensitive logon path
SHOW PARAMETER sec_case_sensitive_logon
--    FALSE -> the server authenticates with the 10G verifier whatever the
--             account carries, and Thin mode is refused. Reported from a
--             site running Oracle 12c, 2026-09-20.
```

A third possibility, when both look right: the server's `sqlnet.ora` pins
`SQLNET.ALLOWED_LOGON_VERSION_SERVER` low (8 or 10). That file is not
visible through `v$parameter`; it lives in `$ORACLE_HOME/network/admin/`
on the database host.

Thick mode (remedy B) fixes every one of these cases without a server
change, because Oracle's own client still speaks the old protocol.

Two remedies, either is sufficient.

**A. Server side (no client change, but it affects every application on
that database).** If `sec_case_sensitive_logon` is FALSE, the DBA sets it
back to TRUE (`ALTER SYSTEM SET sec_case_sensitive_logon = TRUE`), which
makes passwords case-sensitive again for every client and locks out any
account that still carries only a 10G verifier. If instead the account has
no modern verifier, the DBA regenerates the password hash:

```sql
SHOW PARAMETER sec_case_sensitive_logon    -- must NOT be FALSE
ALTER USER <USER> IDENTIFIED BY <new password>;
SELECT username, password_versions FROM dba_users WHERE username = '<USER>';
-- must now list 11G or 12C
```

If the account still comes back `10G` only, the server's
`SQLNET.ALLOWED_LOGON_VERSION_SERVER` is pinned low. That setting lives in
the server's `sqlnet.ora` file, not in `v$parameter`, and cannot be changed
with `ALTER SYSTEM`. Values of 11 or lower generate 10G, 11G and 12C
verifiers; 12 generates 11G and 12C. Raising it locks out any other account
that still has only a 10G verifier, so it is a DBA decision.

**B. Client side: Thick mode.** Thick mode uses Oracle's Instant Client,
which still accepts the 10G verifier. It is Oracle-licensed and
**administrator-supplied**: it is never shipped inside our bundles or
packages, and accepting Oracle's licence is an administrative decision.

Air-gapped delivery, mirroring the trust bootstrap:

1. On the staging machine (the only machine with network access), download the
   Instant Client for the target platform from Oracle and accept the licence
   there. The **19** line is the widest choice: it reaches servers from 11.2
   through current, and python-oracledb supports client libraries from 19.
2. Carry it on the same trusted channel (USB) as the release, together with
   `libaio` (the client links against it and a minimal Ubuntu does not have
   it). On Ubuntu 24.04 the package is `libaio1t64`, which ships
   `libaio.so.1t64`, so the client also needs a `libaio.so.1` symlink.
3. Install it so the LOADER can find it, which on Linux means `ldconfig`, not
   `options.lib_dir`:

```bash
sudo dpkg -i libaio1t64_*.deb
ls /usr/lib/x86_64-linux-gnu/libaio.so.1 2>/dev/null || \
  sudo ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1
sudo mkdir -p /opt/oracle
sudo unzip instantclient-basiclite-linux.x64-19.28.zip -d /opt/oracle
echo /opt/oracle/instantclient_19_28 | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf
sudo ldconfig
ldconfig -p | grep libclntsh     # must print a match
```

   Keep the client under `/opt` or `/usr/local`: the loader refuses libraries
   in unsafe paths such as a user's home directory. Use `ldconfig` rather than
   `LD_LIBRARY_PATH`, which systemd clears for the service.

4. Point the connection at it:

```yaml
connections:
  legacy_ora:
    type: oracle
    host: 10.x.x.x
    port: 1521
    database: ORCLPDB1          # service name
    username_file: /home/<you>/.universal-db-mcp/secrets/legacy_ora.username
    password_file: /home/<you>/.universal-db-mcp/secrets/legacy_ora.password
    read_only: true
    options:
      thick_mode: true          # and NO lib_dir on Linux: see step 3
```

5. `udbmcp doctor` reports `connection-<name>-oracle-instant-client`. It checks
   the directory only: loading the client would switch the whole process to
   Thick mode, which a diagnostic must never do as a side effect.

**Thick mode is process-global.** `init_oracle_client()` switches the entire
server process, so the config refuses a mix: either every oracle connection
sets `thick_mode: true`, or none does. It also cannot be enabled after the
process has already made a Thin connection (`DPY-2019`), which is why the rule
is all-or-nothing rather than per connection. Restart the service after
switching a deployment to Thick mode.

## 2. Pre-12c databases that register a SID

Easy-connect (`host:port/service`) cannot express a SID. Use:

```yaml
    options:
      sid: ORCL
```

The connector then builds a full connect descriptor with `(SID=ORCL)`. The
`database:` field is unused in this form but still required by the schema.

## 3. `tnsnames.ora` aliases

```yaml
    options:
      tns_alias: PRODDB
      tns_admin: /etc/universal-db-mcp/tns     # directory holding tnsnames.ora
```

The alias carries its own descriptor, so `host`, `port` and `database` are not
used to reach the database. `tns_admin` is mandatory with an alias, and
`doctor` fails closed when `tnsnames.ora` is missing. This is also the way to
reach RAC services and LDAP-resolved descriptors that a DBA hands over as an
alias. In Thin mode the directory is passed per connection; in Thick mode it
is given to the Instant Client at initialization.

## 4. TLS (TCPS)

```yaml
    tls:
      enabled: true
    options:
      wallet_location: /etc/universal-db-mcp/oracle-wallet
```

`tls.enabled` alone is refused without a wallet: setting wallet parameters
without selecting TCPS would leave the wire in plaintext, so the connector
builds a TCPS descriptor and requires the administrator-supplied wallet. A
`sid` may be combined with TLS; the descriptor then carries `(SID=...)`.

## Evidence status

| Item | Status | Evidence |
|---|---|---|
| Service-name, legacy SID and `tnsnames.ora` alias connects | passed (live) | `test-evidence/oracle-connect-modes/` against Oracle 23ai Free on this host |
| `DPY-3015` mapped to an error naming both remedies | passed (unit) | `tests/unit/test_oracle_connect_modes.py` with a driver fake |
| Thick mode initialization, single init, fail-closed diagnostics | passed (unit) | same file |
| Thick mode against an account carrying ONLY the 10G verifier (Oracle 18c XE, `password_versions = '10G'`) | **passed (live)** | `test-evidence/oracle-thick-mode/`: through `OracleConnector`, Thin fails with exactly `DPY-3015 ... 0x939` and Thick connects and returns query rows. Nothing changed on the server between the two runs. |
| Thick mode against an Oracle 11.2 server | passed (live) | same evidence file: Thin cannot reach 11.x at all (`DPY-3010`, below the Thin floor); Thick connects with Instant Client 19.28 loaded via `ldconfig` in a no-network container |
| Thick mode enabled after a Thin connection in the same process | refused with the ordering explained (`DPY-2019`) | unit-tested; the config's all-or-nothing rule prevents it in a real deployment |
| TLS/TCPS with a wallet | `not_run` | no wallet-enabled Oracle fixture |
