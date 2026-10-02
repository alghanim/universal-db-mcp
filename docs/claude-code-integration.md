# Registering the server with Claude Code and other agents

This server is model-agnostic: it never calls an LLM. Claude Code (or another
MCP client) is the client; the internal model gateway is a separate,
independently managed dependency of the client, never of this server.

## 1. Register with `configure-agents` (recommended)

Run it as the user who runs the agent, not with `sudo`:

```bash
udbmcp configure-agents              # detect, show the plan, ask before each write
udbmcp configure-agents --dry-run    # show what would be written; never prompts or writes
udbmcp configure-agents --agent claude-code --yes   # one harness, no prompt (scripts)
```

`udbmcp` is the CLI alias the installers link into `/usr/local/bin`. Without
it, use the venv's interpreter with `-m universal_db_mcp`:

| Install | Interpreter the registration names |
|---|---|
| `.deb` or `install_offline.sh` (Linux) | `/opt/universal-db-mcp/venv/bin/python` |
| `.pkg` (macOS) | `/usr/local/universal-db-mcp/venv/bin/python` |
| `.msi` (Windows) | `C:\Program Files\UniversalDB MCP\venv\Scripts\python.exe` |
| development checkout | `<checkout>/.venv/bin/python` |

It detects Claude Code, Claude Desktop, Cursor, VS Code, Cline and the
DeepSeek harness (`dsh`). For Claude Code it writes the user scope,
`~/.claude.json` (top-level `mcpServers`), which covers every project. A
project `.mcp.json` is shared through the repository, so it never creates
one and never adds this machine's paths to one: it rewrites the `.mcp.json`
of the directory it runs in only to upgrade this tool's own entry from a
release before `-I` (same paths, only the args change), and otherwise
reports it `left as it is`. The entry it writes:

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "stdio",
      "command": "/opt/universal-db-mcp/venv/bin/python",
      "args": ["-I", "-m", "universal_db_mcp", "serve", "--transport", "stdio"],
      "env": { "UDBMCP_CONFIG": "/home/<you>/.universal-db-mcp/config.yaml" }
    }
  }
}
```

Restart the agent afterwards. The entry holds no secret: only the launch
command and the config path.

### Which config the registration uses

A stdio registration runs the server as your user, so the config it names must
be readable by you. `configure-agents` picks, in order:

1. `UDBMCP_CONFIG` from your environment. A relative value is resolved against
   the current directory and must name an existing file (otherwise every
   installed harness fails closed with `CONFIG_ERROR: UDBMCP_CONFIG=<value> is
   a relative path and <abs> is not a file`); the registration always stores
   the absolute path. Prefer an absolute path.
2. The system config (`/etc/universal-db-mcp/config.yaml`, or
   `%ProgramData%\UniversalDB MCP\config.yaml` on Windows), only if your user
   can read it.
3. Otherwise the per-user config `~/.universal-db-mcp/config.yaml`, which it
   creates (mode 0600) with its own metadata cache and audit log under
   `~/.universal-db-mcp/` when it does not exist yet.

The system config is what the HTTP service reads, and a stdio registration
must not name it: its audit log and metadata cache under
`/var/log/universal-db-mcp` and `/var/lib/universal-db-mcp` belong to the
service account, so a server started as your user refuses every tool call
with `CONFIG_ERROR: audit log write to '/var/log/universal-db-mcp/audit.jsonl'
failed and application.audit_fail_closed=true; operation refused`. The `.pkg`
installs it mode 0640 for the service account, and `docs/offline-deployment.md`
installs it the same way for the tarball, so other users cannot read it and
the per-user config is registered. The `.deb` ships it as a dpkg conffile,
`root:root` 0644, readable by every user, so on a `.deb` host
`configure-agents` would register it. There, give the file to the service
account before anyone runs `configure-agents` (`add-connection` on the system
config needs the same change):

```bash
sudo chown root:udbmcp /etc/universal-db-mcp/config.yaml && sudo chmod 640 /etc/universal-db-mcp/config.yaml
```

After that change, a registration made while the file was readable still
names it, and the server it starts exits with `Permission denied`. Remove
that `universal-db` entry by hand and re-run `configure-agents`: it refuses
to replace an entry that names another config (see below). Add your own
connections to the per-user config with `udbmcp add-connection` (it defaults
to the same file) and check it with
`udbmcp doctor --config ~/.universal-db-mcp/config.yaml`.
Under `sudo configure-agents` the system config is registered only if the
target user can read it by its permission bits; from an elevated Windows
prompt the ProgramData config is never registered. In both cases the per-user
config is registered and seeded instead.

### Isolated mode (`-I`)

Every registration starts the server with `python -I`: the open project's
directory, `PYTHONPATH` and the user site-packages stay off `sys.path`, so a
`yaml.py`, `mcp/` or `universal_db_mcp/` in the project cannot run inside the
server. The venv's own site-packages, an editable install's `.pth` included,
still load. Before it registers an interpreter it picked itself,
`configure-agents` checks that
`<python> -I -c "import universal_db_mcp.server"` succeeds; an interpreter
that finds the package or its dependencies only through the user site or
`PYTHONPATH` is refused with `CONFIG_ERROR: <python> -I cannot import
universal_db_mcp.server ...`. Install into a virtual environment, or set
`UDBMCP_VENV_PYTHON` to a venv interpreter, which is not probed (an absolute
path is recommended; a bare name is resolved on `PATH` at configure time and
stored absolute).

An existing `universal-db` entry that starts the server without `-I` is
reported, with where the `-I` goes:

- `add "-I" as the first "args" item` for a direct python launch;
- `add "-I" right before "-m" in "args"` for a launch through `env` or
  `uv run python`;
- `insert "python", "-I" right before "-m" in "args"` for `uv run -m` (uv's
  own options before `-m` are read with their values: `uv run --python 3.12
  -m ...`, `--project X`, `--with X`, `--env-file X`);
- `drop uv's --module (-m) option and insert "python", "-I", "-m" right before
  "universal_db_mcp" in "args"` for `uv run --module`, or uv options between
  `-m` and the module;
- the same advice ending `in the command line in "args"` or `in "command"`
  when the launch sits in a command line held in one string (for example
  `add "-I" right before "-m" in the command line in "args"`).

Command lines are read wherever a launch can hide: a shell's `-c` string
(`sh -c`, `bash -lc`), `cmd /c`, the args after PowerShell's `-Command`, a
`"command"` that is a whole command line, and `env -S`. Every command of such
a line counts (after `;`, `&&`, `||`, `|` or a line break), as do command
lines quoted inside it (`bash -c "sh -c '...'"`, up to 4 levels) and
`$(...)`, `<(...)` and backtick substitutions, even after an isolated launch,
because the shell runs them first. Otherwise what follows an isolated launch
is the server's own args and is not read. Not recognized: an interpreter
named only through a shell variable or positional parameter (`bash -c 'exec
"$0" -m universal_db_mcp' python3`, or `sh -c 'exec "$@"'` with the
interpreter and `-m` as separate `"args"` items), an interpreter behind a
wrapper or in a command line whose file name does not look like python
(`python3-intel64`), `python -m runpy universal_db_mcp`, PowerShell's
`-EncodedCommand`, and uv options that `uv run --help` (uv 0.11.16) does not
list.

Other hand-written entries in the same file that launch this package without
`-I` (for Claude Code also per-project servers in `~/.claude.json`) get a
`WARNING` naming them; they are never edited. A `dsh` row with this server's
id that launches it without `-I`, in any of these forms, fails closed, except
the exact row an earlier release of this tool wrote, which is upgraded.

### What it refuses, and why (fail closed)

Nothing is written without an explicit `y` on a terminal, or `--yes`. A
harness is reported `unknown_state_fail_closed`, with `refusing to write:
<reason>`, when writing would override protection or someone else's state:

- a config that is unreadable, malformed, or holds a different `universal-db`
  entry (edit or remove that entry by hand, then re-run). The one exception
  is this tool's own registration from an earlier release, identical except
  for the missing `-I`, which is upgraded in place;
- a config this user may not write, one owned by another user (a non-root
  run), one with several hard links, or one in a directory this user cannot
  write (for an absent config, its nearest existing parent; not checked on
  Windows);
- a config whose access control list (Linux `setfacl`, macOS `chmod +a`)
  differs from the one its directory gives every new file, in either
  direction: one with an ACL of its own (`has an access control list other
  than the one its directory gives every new file, and replacing it would
  drop it ...`), or one with none in a directory with a default ACL
  (`setfacl -d`) or `file_inherit` entries (`has no access control list, but
  its directory gives every new file one, and replacing it would give it that
  list, changing who may read it ...`). A config whose ACL is exactly the
  inherited one is written and keeps it; an ACL that cannot be read refuses
  with `could not be checked for an access control list`;
- in a non-root run on Linux or macOS, a config in a group this user is not
  in, whose mode gives that group access of its own (0640, 0660), where the
  replacement would get another group (`belongs to group <gid>, which this
  user is not in, and replacing it would give it group <gid2>, changing who
  may read it ...`). A 0600 or 0644 config in a foreign group is written, and
  may come back in your own group (Linux) or its directory's (macOS), which
  changes no access;
- under `sudo`, a symlink on the path that a user owns and that points to
  something that user does not own, or a file with several hard links that
  the owner of its directory does not own: as root such a file is not even
  read (a dry run printed a root-only file a user had linked in);
- a config another program created after `configure-agents` found it absent
  (re-run to add the registration to it).

A failed-closed harness prints the reason (a parse error names the line and
column) and, under `details:`, the registration it would add and the
`universal-db` entry the file holds now, never the file's other entries:
those hold other MCP servers' env values (API tokens), and the output ends
up in terminals and logs. For `dsh`, only the rows for this server's id are
shown. A `UDBMCP_CONFIG` the `dsh` registration cannot use (a relative path
naming no file) fails closed at detection, before a write is offered.

In these cases no backup is made and the file is left as it is. Make the file
writable by, and owned by, the user who runs `configure-agents` (a hard link
can become a symlink; `chgrp` a config to a group you are in, or run as a
member of its group; make its ACL match its directory's), or add the printed
block by hand. On Windows only write access is tested (a Win32 write open,
so an ACL that denies write counts), and ACLs are not compared; a config
another program holds open is not refused: the replace is retried once after
0.2 s and otherwise fails closed, naming the `.bak`. A config that is a
single-file bind mount (for example `~/.claude.json` mounted into a
devcontainer) cannot be replaced atomically: the write fails, the file is left
as it was, and the block to add by hand is printed.

Every write first copies an existing file to `<file>.bak.<UTC stamp>`, private
(0600) and never pruned, then replaces the file atomically: a failed write
leaves it unchanged. New files are created 0600, and a symlinked config (a
dotfiles repository, for example) stays a symlink. A `.bak` may hold other MCP
servers' tokens: delete the old ones once you have checked the result.

Harness config locations follow the platform: `%APPDATA%` on Windows
(an `APPDATA` that is not an absolute Windows path is ignored, falling back to
`%USERPROFILE%\AppData\Roaming`), `$XDG_CONFIG_HOME` (an absolute value
only) or `~/.config` on Linux, `~/Library/Application Support` on macOS. Under `sudo`, directories it has to
create are given to the owner of their nearest existing parent; running it as
the logged-in user is still the recommended way.

The macOS "Configure UniversalDB MCP" app runs the same command (before
this release its dialogs did not compile and the app exited without
registering anything or showing a dialog; it now works). When no
harness can be configured and one failed (detection error, or a config that
needs a manual fix), it shows a stop dialog with the Terminal command for the
diagnostic and exits 1; otherwise it lists the failed harnesses as not
configurable and reports each as `FAILED` in its result dialog, again with
exit status 1.

A harness fails closed when its adapter raised during detection or planning,
or when it reports `unknown_state_fail_closed` (the cases above). A missing
harness config is not one: it is `installed_unconfigured` and writable.
Nothing is ever written to a harness that failed closed.

Exit status: `0` on success, for plain detection and for `--yes --dry-run`
(a failed-closed harness is reported, not fatal); `1` when a confirmed write
did not happen (the adapter refused, raised or crashed), the registration
was written but the per-user config it names could not be seeded (`FAIL
CLOSED: the per-user harness config the registration names could not be
seeded ...`; with `--json` the harness carries `seed_error`), or a write
needs `--yes` and stdin is not a terminal; `2` for an unknown `--agent`, or when a
harness failed closed and either `--agent` names it (also with `--dry-run`
and for plain detection) or `--yes` was given without `--dry-run`. Under
`--yes` the other writable harnesses are still applied first, and exit `2`
takes precedence over `1`. Exit `2` prints `CONFIG_ERROR: <names> failed
closed (the reason is shown for each); nothing was written there` on stderr.

`--json` never prompts and never writes unless `--yes` is also given. Its
top-level `errors` counts every harness that failed closed; each harness
reports `writable: false` when it would be refused, and `backups` lists the
`.bak` files a write created. A harness's `status` is `adapter_error` when
its adapter module cannot be loaded, `fail_closed` for any other exception
the adapter raised (most often the `ConfigError` of a relative
`UDBMCP_CONFIG` that names no file, or of an interpreter that cannot import
the server under `-I`), and `unknown_state_fail_closed` for the config
states above.

### After upgrading from an earlier release

Registrations written by releases before `-I` show as
`installed_unconfigured`. Re-run `udbmcp configure-agents` (or the macOS
"Configure UniversalDB MCP" app) to rewrite them; each rewrite makes a
`.bak`. Earlier releases created `~/.claude.json` backups at 0644: run
`chmod 600` on the config and on its old `.bak.*` files, or delete them.

## 2. The isolation boundary

A stdio server shares your account's files and environment with the agent
that launched it. An agent that can run shell commands or read files can read
the credentials in `~/.universal-db-mcp/secrets/` and connect to the database
directly, outside the SQL guard, masking and audit. `configure-agents` prints
a `NOTICE` saying so after it writes a registration, and `add-connection`
prints it whenever it writes secret files for any config other than the
system config, whatever that config's `transport`, naming the account the
files belong to (under `sudo`, the account they were given to). Give every
connection a SELECT-only database login limited to its `allowed_schemas` (on
Db2, `db_explain` also needs INSERT, SELECT and DELETE on the explain tables:
`docs/driver-matrix.md`), or, when credentials must stay out of the agent's
reach, run the server as a service under its own account in HTTP mode and
register it over HTTP.

`configure-agents` writes stdio registrations only. An HTTP registration is
written by hand; the `headers` entry is mandatory, because the listener
answers 401 to every request without the token:

```json
{
  "mcpServers": {
    "universal-db": {
      "type": "http",
      "url": "https://udbmcp.internal.example/mcp",
      "headers": { "Authorization": "Bearer <contents of the service's http-token>" }
    }
  }
}
```

The service reads the system config; see `docs/offline-deployment.md` for the
token, the reverse proxy and the `Host` header rule.

## 3. Internal model gateway (client side, operator-supplied)

```bash
# Values and credentials are supplied by the organization's operator.
export ANTHROPIC_BASE_URL="https://llm-gateway.internal.example"
export ANTHROPIC_MODEL="glm5.3-flash"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Set the credential variable required by the local gateway securely.
```

Requirements on the gateway path (validate against the pinned client
version; a bare OpenAI-compatible chat endpoint does NOT prove this):

- Anthropic Messages API compatibility, including streaming, tool
  definitions, and tool-call/result round trips.
- All model-selection paths (auxiliary/fast-model routes, fallbacks) resolve
  to approved internal models or are disabled.
- No cloud dependency and no public fallback in the gateway itself.

## 4. Offline hardening of the client

`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` covers documented nonessential
traffic but not every feature request. For the pinned client also disable,
via supported settings:

- web search / fetch tools
- external MCP servers and marketplace access
- remote-control and other network-capable features

Confirm with network monitoring on a representative session (Gate D/E
harness). Preserve security checks for anything left enabled.

## 5. End-to-end qualification (Gate F)

Record separately from MCP-server offline compliance. With public egress
blocked, ask the agent to: list a configured database, inspect one table,
run one small authorized read query through MCP. Verify real tool calling,
usable results, streaming, fallback routing, and the absence of public
network attempts. A raw HTTP call to the model is not a substitute.

If the pinned client cannot complete startup/authentication offline, record
an end-to-end deployment blocker: it is a client/gateway issue, not an
MCP-server defect, and must not be concealed.

## Status in this build

The MCP-server side (the stdio registration above and `configure-agents`) is
implemented and covered by the Gate B protocol probe and the adapter unit
tests. Gate F end-to-end qualification has NOT been run in this environment:
it requires the organization's pinned Claude Code version and internal
gateway. See `IMPLEMENTATION_STATUS.md`.
