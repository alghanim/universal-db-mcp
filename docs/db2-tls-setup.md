# Db2 TLS enablement runbook (udbmcp, air-gapped)

Status: operational runbook for the Db2 Gate C remediation. Companion script:
`scripts/db2-enable-tls.sh`. Related: `docs/driver-matrix.md` (Db2 Gate C
status), `docs/offline-deployment.md`, `docs/security.md`.

## Is TLS required? (root cause corrected 2026-09-15)

**No, not for logins.** This runbook was written while every remote login
from the pinned `ibm_db` 3.2.9 client failed with
`SQL30082N  Security processing failed with reason "17"`. Per IBM's
SQL30082N reason-code table, **reason 17 is UNSUPPORTED FUNCTION**: the
server rejected the security mechanism the client proposed. The cause was
the connector, not the server or the client library: it passed the
username and password as `ibm_db.connect` positional arguments, which
ibm_db ignores for connection-string DSNs, so no credentials were ever
sent. The same bug yields reason 3 (PASSWORD MISSING) when SERVER
authentication is forced. Since the fix the connector sends `UID`/`PWD`
inside the connection string; plaintext TCP logins against Db2 11.5.9 with
`AUTHENTICATION=SERVER` then succeed, and a wrong password returns reason
24 (`test-evidence/integration-db2-credentials-fix/`).

If reason 17 still appears on a fixed build, it is a genuine mechanism
mismatch. First diagnostic when it appears:
`db2 get dbm cfg | grep -E 'AUTHENTICATION|SRVCON_AUTH|ALTERNATE_AUTH_ENC'`.

Use this runbook when policy requires encrypting Db2 traffic in transit.
The server's default `security.require_remote_tls: true` refuses non-TLS
remote connections, so either enable Db2 TLS with this recipe or set that
policy to `false` knowingly. It is in-transit hardening, not a login fix.

## Evidence status (read before relying on this recipe)

This runbook is **not** proven end-to-end. What has and has not been
demonstrated, in the terms used by `docs/acceptance-tests.md`
(`passed` / `failed` / `blocked` / `not_run`):

| Item | Status | Evidence |
|---|---|---|
| Server side — ICU shim, GSKit key database + self-signed certificate, certificate extraction (steps 1, 2, 4) | demonstrated (manual) | Run by hand against local fixture containers (Db2 12.1 and 11.5.9) while writing this runbook. No machine-readable evidence is committed under `test-evidence/`. |
| Server side — `db2 update dbm cfg using SSL_*` + instance restart (step 3) | run (manual), unverified | Run by hand; `db2 get dbm cfg` showed the `SSL_*` values afterwards. Whether the SSL listener actually opened was **not** checked. |
| Server side — `DB2COMM` registry variable including `SSL` (step 3) | `not_run` | The original recipe omitted this step; without it Db2 never opens the `SSL_SVCENAME` listener. Added after review; not re-run here. |
| Client side — `ibm_db` connect over TLS returns a handle (no `SQL30082N`) | `not_run` | **Not demonstrated in this environment.** The session notes behind this runbook record the client still failing with `SQL30082N reason 17` after the server-side steps; that attempt predates the `DB2COMM` fix, was not diagnosed (listener never opened / client fell back to plaintext / label mismatch are all open), and is not reproducible from this repository. |
| Db2 live round-trip through the connector (plaintext TCP) | passed (direct run) | Blocked until the 2026-09-15 credential-passing fix, now passed against the local Db2 11.5.9 fixture: `test-evidence/integration-db2-credentials-fix/`. Gate C orchestrator not re-run; see `docs/driver-matrix.md`. |

**What closes the `not_run` items.** On a machine that can reach a Db2
instance configured with this recipe (including the `DB2COMM` step):

1. `db2set -i <instance> DB2COMM` prints a value containing `SSL` and
   `ss -ltn` shows the `SSL_SVCENAME` port listening after `db2start`.
2. The client one-liner under *Verification* returns a connection handle.
3. The Gate C integration run (`tests/integration`) passes health and
   roundtrip for a `type: db2` entry with `tls.enabled: true`, and the run log
   plus `results.json` are committed under `test-evidence/integration-gateC/`.
4. The Db2 row in `docs/driver-matrix.md` is moved from `unverified` to
   `verified` in the same change.

Until then treat this document as the **server-side half** of the remediation
and keep Db2 recorded as `blocked` in the acceptance evidence.

## Prerequisites

- Administrator shell access to the machine running the Db2 container (or the
  native LUW host itself), with `docker` on PATH for container mode.
- **Staged unsuffixed ICU 70 libraries — only if your GSKit build needs
  them.** The ICU shim exists for GSKit builds that probe for unsuffixed
  ICU 70 `.so` names; that was observed on the **Db2 12.1** image. On the
  project's Db2 **11.5.9** fixture (GSKit 8), GSKit runs with only
  `$HOME/sqllib/lib64/gskit` on `LD_LIBRARY_PATH` and **no ICU shim**:
  `-keydb -create ... -stash` and `-cert -create` both succeeded without it.
  The failure you get with no `LD_LIBRARY_PATH` at all is
  `libgsk8km_64.so: cannot open shared object file`, which is fixed by
  putting `$HOME/sqllib/lib64/gskit` first on `LD_LIBRARY_PATH` — it is not
  an ICU problem. If your GSKit *does* hit an ICU load error (see
  Troubleshooting), stage these four files, from any Ubuntu 22.04-based
  image (e.g. `mcr.microsoft.com/mssql/server:2022-latest`, at
  `/usr/lib/x86_64-linux-gnu/`):
  - `libicudata.so.70.1`
  - `libicui18n.so.70.1`
  - `libicuio.so.70.1`
  - `libicuuc.so.70.1`
- A chosen key-database password (stashed on the server, never leaves it) and
  a free TCP port for the SSL service (default `50001`).
- For the client side: the udbmcp bundle with the `ibm-db` wheel, and Db2
  Connect / client licensing as an administrator prerequisite (see
  `config.example.yaml`, Db2 example).

### Air-gapped staging note (read before starting)

**The air-gapped target never downloads anything.** If the ICU shim is needed
(see Prerequisites), the ICU `.so` files must be staged by the administrator:
extract them on an internet-connected machine (`docker create` + `docker cp`
from the Ubuntu 22.04-based image, or any equivalent offline copy), then move
them into the air-gapped environment alongside the rest of the udbmcp bundle.
Same for the udbmcp script itself. Nothing in this runbook performs a fetch.

## Step-by-step: containerized fixture

The script `scripts/db2-enable-tls.sh` automates the following steps and is
idempotent (safe to re-run; it reuses an existing keydb/cert and only
restarts the instance when the configuration actually changed):

```console
# 1. ONLY if the GSKit build needs the ICU shim (see Prerequisites: not
#    needed on the Db2 11.5.9 / GSKit 8 fixture) — stage it inside the
#    container and make it FIRST on LD_LIBRARY_PATH, ahead of
#    $HOME/sqllib/lib64/gskit. Those GSKit builds need UNSUFFIXED ICU names:
mkdir -p staging-icu70 && cp /path/to/staged/libicu*.so.70.1 staging-icu70/

# 2. Run the script:
scripts/db2-enable-tls.sh \
  --container db2fixture \
  --password '<keydb-password>' \
  --ssl-port 50001 \
  --icu-source-dir ./staging-icu70 \
  --cert-out /etc/universal-db-mcp/certs/db2-server.crt \
  --client-host 127.0.0.1 \
  --database SAMPLE
```

The script prints the exact YAML connection block to paste into the udbmcp
config at the end (shown below). If you prefer to run the steps by hand, this
is what it does (inside the container, as the instance owner, e.g.
`db2inst1`):

1. **ICU shim (only when the GSKit build needs it — see Prerequisites)** —
   copy the four `.so.70.1` files into a shim directory
   (e.g. `$HOME/udbmcp-icu70`), create versioned symlinks
   `libicu{data,i18n,io,uc}.so.70 -> .so.70.1`, and put that directory FIRST
   on `LD_LIBRARY_PATH`, followed by `$HOME/sqllib/lib64/gskit`. On the Db2
   11.5.9 fixture the shim can be skipped entirely; GSKit then runs with just
   `$HOME/sqllib/lib64/gskit` on `LD_LIBRARY_PATH`:
   ```bash
   export LD_LIBRARY_PATH="$HOME/udbmcp-icu70:$HOME/sqllib/lib64/gskit:$LD_LIBRARY_PATH"
   ```
2. **Key database + self-signed certificate** — use
   `$HOME/sqllib/gskit/bin/gsk8capicmd_64` (GSKit 8 images) or
   `gsk9certutil_64` (GSKit 9):
   ```bash
   gsk8capicmd_64 -keydb -create -db $HOME/server.kdb -pw '<keydb-password>' -stash
   # Try '-cert -create' first (GSKit 9 and current GSKit 8 builds); older
   # GSKit 8 builds reject it and only accept the legacy '-cert -selfsign'.
   gsk8capicmd_64 -cert -create -db $HOME/server.kdb -pw '<keydb-password>' \
       -label udbmcp_self -size 2048 -expire 3650 -dn CN=udbmcp-test \
     || gsk8capicmd_64 -cert -selfsign -db $HOME/server.kdb -pw '<keydb-password>' \
       -label udbmcp_self -size 2048 -expire 3650 -dn CN=udbmcp-test
   ```
3. **Registry variable + DBM configuration + instance restart**. Setting
   `SSL_SVCENAME` alone is **not** enough: Db2 only opens the SSL listener
   when the `DB2COMM` registry variable includes `SSL`. Keep `TCPIP` in the
   value so the existing plaintext `SVCENAME` port keeps working:
   ```bash
   source $HOME/sqllib/db2profile
   db2set -i db2inst1 DB2COMM=SSL,TCPIP     # db2inst1 = the instance name
   db2 update dbm cfg using SSL_SVR_KEYDB $HOME/server.kdb \
       SSL_SVR_STASH $HOME/server.sth SSL_SVR_LABEL udbmcp_self \
       SSL_SVCENAME 50001
   db2stop force && db2start
   ```
   Then confirm the registry value took and that the SSL port is actually
   listening (this is the check the original recipe lacked):
   ```bash
   db2set -i db2inst1 DB2COMM               # expect a value containing SSL
   ss -ltn | grep -E ':50001\b'             # or: netstat -ltn | grep 50001
   ```
   If nothing listens on the port after `db2start`, inspect
   `db2diag -l Severe,Error | tail -50` for GSKit / SSL initialisation errors
   (wrong keydb path, missing stash, label not in keydb) before touching the
   client.
4. **Extract the certificate** for the client:
   ```bash
   gsk8capicmd_64 -cert -extract -db $HOME/server.kdb -pw '<keydb-password>' \
       -label udbmcp_self -target $HOME/server.crt -format ascii
   ```
   then copy it off the container (`docker cp db2fixture:/home/db2inst1/server.crt ...`).

## Step-by-step: native LUW instance

The script never reaches over the network (air-gapped discipline): run it in
`--host` mode and it prints the exact commands for the administrator to run
**on the Db2 host itself**, as the instance owner:

```console
scripts/db2-enable-tls.sh --host db2.internal.example --ssl-port 50001 --database SAMPLE
```

The command sequence is identical to the container case (ICU shim — only when
the GSKit build needs it — under `$HOME/udbmcp-icu70`, keydb + cert,
`db2set -i <instance> DB2COMM=SSL,TCPIP`,
`db2 update dbm cfg`, `db2stop force && db2start`, listener check with
`ss -ltn`, `-cert -extract`), with two differences:

- If the ICU shim is needed, its source is a directory the administrator
  staged on that host (never downloaded there).
- The extracted `server.crt` must be carried off the host to the MCP target
  by the administrator (secure copy of your choice) — that file is the
  client's `ca_file`.

## Client configuration (udbmcp YAML)

Point the connection at the **SSL service port** (`SSL_SVCENAME`), not the
plaintext `SVCENAME`, and pin the extracted certificate. The block goes under
the top-level `connections:` key (the config schema is strict — unknown
top-level keys such as `databases:` are rejected; see `config.example.yaml`):

```yaml
connections:
  sample_db2:
    type: db2
    family: luw
    host: 127.0.0.1          # or the native host / published container endpoint
    port: 50001              # must be SSL_SVCENAME's port
    database: SAMPLE
    username_env: DB2_USER
    password_file: /run/secrets/sample_db2_password
    tls:
      enabled: true
      verify_server: true
      ca_file: /etc/universal-db-mcp/certs/db2-server.crt
    allowed_schemas: [UDBMCP_RO]   # the read-only account's schema; see the
                                   # warning below before ever writing []
    read_only: true
```

**Warning — `allowed_schemas: []` is NOT deny-all.** The policy treats an
empty list as "the administrator did not restrict schemas"
(`EffectivePolicy.schema_allowed` in `src/universal_db_mcp/security/policy.py`),
so the agent can list and query every schema the Db2 account has access to.
Always name the schemas you intend to expose (the script-generated block may
still print `[]`; replace it before pasting).

The connector appends `SECURITY=SSL` and `SSLServerCertificate=<ca_file>` to
the connection string when `tls.enabled` is true.

## Verification

Server side:

```console
scripts/db2-enable-tls.sh --container db2fixture --verify-only
# or on the host, as the instance owner:
db2set -i db2inst1 DB2COMM                          # must contain SSL
db2 get dbm cfg | grep -E 'SSL_SVCENAME|SSL_SVR_KEYDB|SSL_SVR_LABEL'
ss -ltn | grep -E ':50001\b'                       # the SSL port must be listening
```

Client side — `ibm_db` connect one-liner. **Status: `not_run` in this
environment** (see *Evidence status*); this is the check that Gate C was
blocking, and success here is what un-blocks the live-capability verification
recorded in `docs/driver-matrix.md`:

```console
python3 -c "import ibm_db; print(ibm_db.connect('DATABASE=SAMPLE;HOSTNAME=127.0.0.1;PORT=50001;PROTOCOL=TCPIP;UID=<user>;PWD=<pw>;SECURITY=SSL;SSLServerCertificate=/etc/universal-db-mcp/certs/db2-server.crt;','',''))"
```

A returned connection handle (no `SQL30082N`) means the TLS path accepts
REMOTE password authentication. Then run the connector's normal probe /
`tests` against this connection entry and commit the evidence as described
under *Evidence status*. A failure here must be recorded as `failed` (with
the SQLSTATE / reason code), not silently left as `not_run`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `gsk8capicmd_64: error while loading shared libraries: libgsk8km_64.so: cannot open shared object file` (or any other `libgsk8*.so` load failure) | The GSKit directory is not on `LD_LIBRARY_PATH` at all (not an ICU problem) | `export LD_LIBRARY_PATH="$HOME/sqllib/lib64/gskit:$LD_LIBRARY_PATH"` before every GSKit call. On Db2 11.5.x (GSKit 8) this alone is sufficient — no ICU shim needed. |
| `gsk8capicmd_64: error while loading shared libraries: libicuuc.so.70: cannot open shared object file` (observed on the Db2 12.1 image's GSKit) | That GSKit build probes for unsuffixed ICU 70 libs and the shim dir is missing or not first on `LD_LIBRARY_PATH` | Stage `libicu{data,i18n,io,uc}.so.70.1`, symlink `.so.70 -> .so.70.1`, and export `LD_LIBRARY_PATH="$HOME/udbmcp-icu70:$HOME/sqllib/lib64/gskit:$LD_LIBRARY_PATH"` before every GSKit call. With GSKit 9 the binary is `gsk9certutil_64`; prefer `-cert -create` and fall back to the legacy `-cert -selfsign` on older GSKit 8 builds. |
| `db2 get dbm cfg` shows `SSL_SVCENAME` empty (or `SSL_SVR_KEYDB` empty) | TLS was never enabled on this instance | Run `scripts/db2-enable-tls.sh` without `--verify-only` (or the manual step 3), then `db2stop force && db2start`. |
| `SSL_SVCENAME` is set but nothing listens on that port after `db2start` (`ss -ltn` shows no `:50001`; client gets `SQL30081N` / connection refused) | `DB2COMM` does not include `SSL`, so the instance started without the SSL listener — `db2 update dbm cfg` alone never opens it | `db2set -i db2inst1 DB2COMM=SSL,TCPIP`, then `db2stop force && db2start`; confirm with `db2set -i db2inst1 DB2COMM` and `ss -ltn`. If it still does not listen, read `db2diag -l Severe,Error` for GSKit errors. |
| Client gets `Connection refused` / `SQL30081N` with the SSL listener up | The client port points at the plaintext `SVCENAME` (typically 50000/50002), not the SSL service port | Set the YAML `port:` to the `SSL_SVCENAME` value (e.g. 50001). `SVCENAME` and `SSL_SVCENAME` are separate settings; both can listen simultaneously. |
| udbmcp refuses the config with an "extra fields not permitted" / unknown key error mentioning `databases` | The connection block was pasted under a `databases:` key; the strict schema only accepts `connections:` | Move the entry under `connections:` exactly as shown above. |
| `SQL30082N reason 17` still appears over TLS | A udbmcp build older than the 2026-09-15 credential-passing fix sends no credentials at all, so upgrade first. Otherwise the client is not actually negotiating SSL (missing `tls.enabled` / connector fell back to plaintext / SSL listener never opened so the client hit the plaintext port), or the certificate label in `SSL_SVR_LABEL` does not exist in the keydb | First confirm the listener is up (previous rows). Then confirm `SSL_SVR_LABEL` matches a label listed by `gsk8capicmd_64 -cert -list -db $HOME/server.kdb -pw ...`; confirm the YAML has `tls.enabled: true` and `ca_file` pointing at the extracted `server.crt`. |
| `SQL30081N` / protocol error right after enabling SSL | Client connecting with TLS to the plaintext port or vice versa | Match port to protocol: plaintext port <-> no `tls`, SSL port <-> `tls.enabled: true`. |
| Certificate verification failure on the client (`verify_server: true`) | `ca_file` does not match the server certificate (old extraction, wrong host's cert) | Re-extract with `-cert -extract -format ascii` from the keydb actually referenced by `SSL_SVR_KEYDB` and redeploy the file. |
