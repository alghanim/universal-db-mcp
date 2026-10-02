#!/bin/bash
# Configure UniversalDB MCP - native-dialog front end for `configure-agents`.
#
# Runs as the LOGGED-IN USER, never root: agent harness configs are per-user
# files (the launchd daemon's postinstall has no business touching them). The
# app is a thin wrapper exec'ing this script, which is staged root-owned in
# the verified package payload (/usr/local/universal-db-mcp/share/) and is
# not user-writable.
#
# Consent model (mirrors configure-agents' ask-before-write contract):
#   1. Detection is read-only (`--json` never prompts, never writes).
#   2. The user picks harnesses in a native checkbox dialog (empty selection
#      or Cancel writes nothing and exits).
#   3. A confirm dialog states that timestamped .bak backups precede writes.
#   4. Only then is `--json --yes` passed PER SELECTED HARNESS; a refused or
#      failed apply is reported in the result dialog and the script exits 1.
# Written configs never contain secrets (the adapter contract; the server's
# bearer token lives only in the root-owned system key path).
#
# BASH/APPLESCRIPT TRAPS (each once broke this script - keep the guards):
#   * NO apostrophes anywhere inside the osascript heredoc: within a $( )
#     substitution, bash's parser trips over an apostrophe even in a heredoc
#     body and swallows the rest of the script. The possessive
#     "AppleScript possessive" delimiter syntax is therefore spelled with the
#     apostrophe-free genitive: `text item delimiters of AppleScript`.
#   * `chosen as text` joins with the CURRENT delimiters (empty by default!):
#     without setting them first, a multi-selection becomes ONE concatenated
#     bogus name (verified on Darwin 25).
#   * `display dialog` takes `with title "..." with icon note`: the shorthand
#     `with icon note title "..."` does not compile (-2740), and osascript
#     then exits non-zero with no dialog, so the app ended silently and
#     registered nothing. Every snippet is compiled by a unit test.
set -u

VENV_PY="/usr/local/universal-db-mcp/venv/bin/python"
TITLE="Configure UniversalDB MCP"

fail_dialog() {
  osascript -e "display dialog \"$1\" buttons {\"OK\"} default button \"OK\" with title \"$TITLE\" with icon stop" >/dev/null 2>&1
  exit 1
}

info_dialog() {
  osascript -e "display dialog \"$1\" buttons {\"OK\"} default button \"OK\" with title \"$TITLE\" with icon note" >/dev/null 2>&1
}

[ -x "$VENV_PY" ] || fail_dialog "UniversalDB MCP is not installed at /usr/local/universal-db-mcp. Install the package first."

# --- step 1: read-only detection ---------------------------------------------
detect_json="$("$VENV_PY" -m universal_db_mcp configure-agents --json 2>/dev/null)" \
  || fail_dialog "Agent detection failed. Run this in Terminal for the diagnostic:
/usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp configure-agents"

# The configurable set, sanitized to the fixed adapter name charset. A PARSE
# failure here is an ERROR (never "nothing to configure"): a broken payload
# must not masquerade as all-set. Neither may a harness configure-agents
# cannot configure (adapter error, or a config it refuses to touch): those
# come back as FAILED:<name> rows.
rows="$(printf '%s' "$detect_json" | "$VENV_PY" -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as exc:
    print("PARSE_ERROR:" + str(exc))
    raise SystemExit(3)
for h in data.get("harnesses", []):
    name = h.get("agent")
    if not (isinstance(name, str) and name.replace("-", "").isalnum()):
        continue
    if h.get("writable"):
        print(name)
    elif h.get("status") in ("adapter_error", "fail_closed", "unknown_state_fail_closed"):
        print("FAILED:" + name)
')"
rows_rc=$?
if [ "$rows_rc" -ne 0 ] || [ "${rows#PARSE_ERROR}" != "$rows" ]; then
  fail_dialog "Agent detection output unreadable. Run this in Terminal for the diagnostic:
/usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp configure-agents"
fi
failed_names="$(printf '%s\n' "$rows" | sed -n 's/^FAILED://p')"
failed="$(printf '%s\n' "$failed_names" | awk 'NF {printf "%s%s", sep, $0; sep=", "}')"
rows="$(printf '%s\n' "$rows" | sed '/^FAILED:/d')"

if [ -z "$rows" ]; then
  [ -z "$failed" ] || fail_dialog "UniversalDB MCP cannot configure: $failed (detection failed, or the existing config needs a manual fix). Run this in Terminal for the diagnostic:
/usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp configure-agents"
  info_dialog "No configurable agent harnesses found: nothing new is installed, or every detected harness already has UniversalDB MCP registered."
  exit 0
fi
prompt="UniversalDB MCP can be registered with these detected AI agent harnesses. Choose which ones:"
[ -z "$failed" ] || prompt="$prompt

Not listed, because configure-agents cannot configure them (run it in Terminal for the diagnostic): $failed"

# --- step 2: consent dialog 1 - which harnesses ------------------------------
# AppleScript list literal from sanitized rows: {"a", "b"}.
as_list="$(printf '%s\n' "$rows" | awk '{printf "%s\"%s\"", sep, $0; sep=", "}')"
selected="$(osascript <<APPLESCRIPT
set harnessList to {$as_list}
set chosen to choose from list harnessList with title "$TITLE" with prompt "$prompt" with multiple selections allowed
if chosen is false then return "CANCELLED"
set text item delimiters of AppleScript to "|"
return chosen as text
APPLESCRIPT
)" || exit 0
# Cancel returns false; OK with NOTHING selected returns an empty list -
# both write nothing and exit quietly.
[ "$selected" = "CANCELLED" ] && exit 0
[ -z "$selected" ] && exit 0

# --- step 3: consent dialog 2 - confirm before ANY write ---------------------
pretty="${selected//|/, }"
osascript -e "display dialog \"Register UniversalDB MCP with: $pretty?

Each config file gets a timestamped .bak backup before anything is written; re-running never duplicates entries.\" buttons {\"Cancel\", \"Configure\"} default button \"Configure\" with title \"$TITLE\" with icon note" >/dev/null || exit 0

# --- step 4: apply per selected harness (--yes is the recorded consent) ------
# stderr is NOT merged into the JSON payload: the success path parses stdout
# only, so a stray warning can never corrupt the report.
report=""
rc_all=0
IFS='|' read -r -a AGENTS <<< "$selected"
for agent in "${AGENTS[@]}"; do
  apply_rc=0
  out="$("$VENV_PY" -m universal_db_mcp configure-agents --agent "$agent" --json --yes 2>/dev/null)" || apply_rc=$?
  if [ "$apply_rc" -eq 0 ]; then
    line="$("$VENV_PY" -c '
import json, sys
data = json.load(sys.stdin)
applied = data.get("applied") or [{}]
a = applied[0]
detail = str(a.get("summary") or a.get("detail") or "no change")
print(str(a.get("status", "?")) + ": " + detail.replace(chr(34), chr(39)))
' <<< "$out")" || line=""
    if [ -n "$line" ]; then
      report="$report
$agent - $line"
    else
      report="$report
$agent - applied"
    fi
  else
    report="$report
$agent - FAILED: run in Terminal for the diagnostic:
  /usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp configure-agents --agent $agent"
    rc_all=1
  fi
done
# Harnesses that could not be offered are failures too.
while IFS= read -r agent; do
  [ -n "$agent" ] || continue
  report="$report
$agent - FAILED: not configurable here; run in Terminal for the diagnostic:
  /usr/local/universal-db-mcp/venv/bin/python -m universal_db_mcp configure-agents --agent $agent"
  rc_all=1
done <<< "$failed_names"

# Strip characters that would break the AppleScript string literal: both the
# quote AND the backslash (a lone backslash escapes the closing quote and
# silently kills the result dialog).
report="${report//\"/}"
report="${report//\\/}"
info_dialog "Done.$report"
exit "$rc_all"
