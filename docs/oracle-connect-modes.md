# Oracle connect modes (udbmcp, air-gapped)

Covers the Oracle cases that a plain `host:port/service` connection cannot
reach: legacy password verifiers, pre-12c SIDs, `tnsnames.ora` aliases, and
TLS. Related: `docs/driver-matrix.md`, `docs/offline-deployment.md`.

## 1. `DPY-3015: password verifier type 0x939 is not supported`

The account carries **only the 10G password verifier**. python-oracledb in
Thin mode (our default) supports the 11G and 12C verifiers only. Verifier
`0x939` is 10G; it is not a wrong password and not a network problem.

Confirm on the server:

```sql
SELECT username, password_versions FROM dba_users WHERE username = '<USER>';
-- '10G' alone  -> Thin mode will refuse this account
-- '11G 12C'    -> Thin mode is fine
```

Two remedies, either is sufficient.

**A. Server side (preferred, no client change).** The DBA regenerates the
password hash:

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
   Instant Client **Basic** package for the target platform from Oracle and
   accept the licence there.
2. Carry it on the same trusted channel (USB) as the release, and unpack it on
   the target, e.g. `/opt/oracle/instantclient_23_5`. On Linux the client also
   needs `libaio`; install it from the OS packages already on the channel.
3. Point the connection at it:

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
      thick_mode: true
      lib_dir: /opt/oracle/instantclient_23_5
```

4. `udbmcp doctor` reports `connection-<name>-oracle-instant-client`. It checks
   the directory only: loading the client would switch the whole process to
   Thick mode, which a diagnostic must never do as a side effect.

**Thick mode is process-global.** `init_oracle_client()` switches the entire
server process, so the config refuses a mix: either every oracle connection
sets `thick_mode: true`, or none does.

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
| Thick mode live round trip against a real 10G-verifier account | `not_run` | no Oracle Instant Client on the staging host (licensed, admin-supplied), and Oracle 21c+ desupported the 10G verifier so the fixture cannot create such an account |
| TLS/TCPS with a wallet | `not_run` | no wallet-enabled Oracle fixture |
