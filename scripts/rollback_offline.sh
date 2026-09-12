#!/usr/bin/env bash
# Roll back to the previous venv left by upgrade_offline.sh, or restore the
# configuration backup from a failed upgrade. Local-only.
#
# The venv swap is always performed. Restoring the pre-upgrade configuration
# and metadata overwrites live state (which may hold post-upgrade edits made
# AFTER that backup was taken), so it requires the explicit --restore-config
# flag. When it runs, the live configuration is displaced to
# <backup-root>/pre-rollback-<ts>/ and preserved — never deleted — and the
# backup is validated through the restored venv before anything is moved.
#
# Verify-then-use: the restored venv is executed (doctor below) exactly in the
# failure scenarios where on-disk state is least trustworthy, so nothing under
# it runs until it matches an integrity manifest. A missing or mismatched
# manifest fails closed: the rollback aborts with venv.previous preserved and
# nothing executed.
#
# TRUST MODEL ON THE ROLLBACK PATH, stated in full:
#
# Rollback restores an ALREADY-INSTALLED tree. The original signed bundle is
# not present on this host at rollback time, so no check on this path can
# re-anchor the payload to the bundle signature.
#
#   Guaranteed: the payload executed here is byte-identical to the tree that
#   last passed this gate (the tree upgrade_offline.sh demoted, or the tree a
#   previous rollback verified), and the executed entry point cannot escape
#   the tree: the manifest recipes hash regular files only, so every symlink
#   under the tree must resolve back INSIDE it (udbmcp_symlinks_contained)
#   before anything under the tree is executed — an out-of-tree symlink
#   retarget fails the gate closed.
#
#   Not guaranteed: protection against an attacker who can already write both
#   the swap tree AND the external anchor location — such an attacker
#   (effectively root) can rewrite the tree, the manifests, this script, the
#   systemd unit and the trusted verifier alike, and no on-host check stops
#   that actor. Reinstall from the signed bundle (whose signature IS verified
#   on the install/upgrade path) to re-anchor cleanly.
set -euo pipefail

usage() {
  echo "usage: rollback_offline.sh [target-dir] [backup-root] [--restore-config] [--re-anchor]" >&2
}

TARGET=""
BACKUP_ROOT=""
RESTORE_CONFIG=0
RE_ANCHOR=0
for arg in "$@"; do
  case "$arg" in
    --restore-config) RESTORE_CONFIG=1 ;;
    --re-anchor) RE_ANCHOR=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [ -z "$TARGET" ]; then TARGET="$arg"
      elif [ -z "$BACKUP_ROOT" ]; then BACKUP_ROOT="$arg"
      else usage; exit 2
      fi ;;
  esac
done
: "${TARGET:=/opt/universal-db-mcp}"
: "${BACKUP_ROOT:=/var/backups/universal-db-mcp}"
# Overridable only so this script can be exercised against a sandbox in the
# unit tests; production uses the defaults.
ETC_DIR="${UDBMCP_CONFIG_DIR:-/etc/universal-db-mcp}"
STATE_DIR="${UDBMCP_STATE_DIR:-/var/lib/universal-db-mcp}"
# External integrity anchor for the rollback payload: intentionally OUTSIDE
# the swap tree ($TARGET), in the root-owned configuration directory, so a
# writer of venv.previous cannot regenerate it. Overridable only so this
# script can be exercised against a sandbox in the unit tests.
ROLLBACK_ANCHOR="${UDBMCP_ROLLBACK_MANIFEST:-$ETC_DIR/venv-rollback.sha256}"
UDBMCP_VERIFIED_MANIFEST=""

# Re-verify the demoted venv BEFORE anything under it is executed, using the
# same recipe the manifests are recorded with (relative paths, because the
# tree is renamed after verification, deterministic order, NUL-safe). Two
# integrity references, strongest first:
#
# 1. External anchor — "${UDBMCP_ROLLBACK_MANIFEST:-$ETC_DIR/venv-rollback.sha256}".
#    Written by a previous successful rollback AFTER the tree passed
#    verification, and living OUTSIDE the swap tree in the root-owned
#    configuration directory, where a writer of venv.previous cannot follow
#    (unless they are root there too). Authoritative when present: a
#    mismatching anchor fails the rollback closed even if the co-located
#    manifest was regenerated to match a tampered tree. The one exception is
#    the explicit operator opt-in --re-anchor (below), for the legitimate
#    case the anchor cannot distinguish: a LATER upgrade demoted a different
#    venv.previous past the depth-1 window, so the anchor refers to a tree
#    that no longer exists and would otherwise deadlock every future
#    rollback. --re-anchor re-verifies against the co-located manifest — the
#    documented residual, announced loudly on stderr — never skips
#    verification, and re-anchors the verified manifest on success.
# 2. Co-located manifest — $TARGET/venv.previous.sha256, recorded by
#    upgrade_offline.sh before the demotion rename. This is the documented
#    residual (see the trust model above): it shares a writable root with the
#    tree it authenticates, so anyone able to tamper venv.previous can
#    regenerate it with the same recipe. It closes drift / corruption /
#    interrupted-upgrade cases only. When it is the sole reference, the
#    rollback says so on stderr and re-anchors the verified manifest outside
#    the swap tree, so the same regeneration trick fails on every later round.
#
# The manifest lives OUTSIDE the tree it hashes so hashing never includes
# itself. Every verification failure — no manifest at all, unreadable tree,
# hashing tool unavailable, content mismatch, a symlink escaping the tree —
# returns nonzero and the caller aborts BEFORE any rename and BEFORE the
# doctor call executes anything under the tree.
#
# Symlink containment: the manifest recipes (here and in upgrade_offline.sh)
# hash regular files only, so a symlink inside the tree is covered by NO
# integrity reference — yet the executed entry point, bin/python, IS a
# symlink in real venvs. A writer of the swap tree could retarget that
# symlink to an out-of-tree payload and have it executed through a gate that
# passes on both integrity references. udbmcp_symlinks_contained closes that
# gap as part of this same gate.
udbmcp_hash_tree() {
  _hash_cmd=""
  if command -v sha256sum >/dev/null 2>&1; then
    _hash_cmd="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    _hash_cmd="shasum -a 256"
  else
    echo "FAIL: neither sha256sum nor shasum is available; cannot verify $1" >&2
    return 1
  fi
  _hashes="$(mktemp "${TMPDIR:-/tmp}/udbmcp-rollback-verify.XXXXXX")" || return 1
  if ! (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 $_hash_cmd) > "$_hashes"; then
    rm -f "$_hashes"
    echo "FAIL: hashing $1 failed; refusing to execute it" >&2
    return 1
  fi
  printf '%s\n' "$_hashes"
}

# Fail closed unless EVERY symlink under the tree resolves back INSIDE the
# tree: a link whose target escapes it, a dangling link, or a link cycle
# aborts the rollback before anything under the tree is executed. A link that
# stays inside the tree is safe — its final target is a regular file covered
# by the manifest — so real venvs (bin/python -> python3.x) still pass.
# readlink -f fully canonicalizes the target, so ".."-style escapes through
# in-tree components are caught too.
udbmcp_symlinks_contained() {
  _link_canon="$(cd "$1" && pwd -P)" || return 1
  _bad_links="$(mktemp "${TMPDIR:-/tmp}/udbmcp-rollback-links.XXXXXX")" || return 1
  : > "$_bad_links"
  while IFS= read -r -d '' _link; do
    _link_dest="$(readlink -f -- "$_link" 2>/dev/null)" || _link_dest=""
    case "$_link_dest" in
      "$_link_canon"|"$_link_canon"/*) ;;
      *) printf '%s\n' "$_link" >> "$_bad_links" ;;
    esac
  done < <(find "$1" -type l -print0)
  if [ -s "$_bad_links" ]; then
    echo "FAIL: symlinks inside $1 are dangling, cyclic, or resolve OUTSIDE the" >&2
    echo "      tree; the integrity manifests hash regular files only, so an" >&2
    echo "      out-of-tree link could execute unverified content through this" >&2
    echo "      gate. Offending links:" >&2
    sed 's/^/        /' "$_bad_links" >&2
    rm -f "$_bad_links"
    return 1
  fi
  rm -f "$_bad_links"
  return 0
}

udbmcp_verify_previous_venv() {
  _anchor="${UDBMCP_ROLLBACK_MANIFEST:-$ETC_DIR/venv-rollback.sha256}"
  _colocated="$TARGET/venv.previous.sha256"
  _reference=""
  if [ -f "$_anchor" ]; then
    _reference="$_anchor"
  elif [ -f "$_colocated" ]; then
    _reference="$_colocated"
    echo "WARN: no external rollback anchor at $_anchor; verifying against the" >&2
    echo "      co-located manifest recorded by upgrade_offline.sh. That manifest" >&2
    echo "      lives in the same writable tree as venv.previous, so this closes" >&2
    echo "      drift/corruption/interrupted-upgrade cases but CANNOT stop an" >&2
    echo "      attacker who can rewrite the tree (rollback of an already-installed" >&2
    echo "      tree cannot re-verify the bundle signature without the original" >&2
    echo "      bundle). A verified rollback anchors the manifest at $_anchor" >&2
    echo "      so this regeneration trick fails on every later round." >&2
  else
    echo "FAIL: no integrity manifest at $_colocated and no external anchor at" >&2
    echo "      $_anchor; refusing to execute venv.previous" >&2
    echo "      rollback executes venv.previous only after it verifies against the" >&2
    echo "      SHA256 manifest recorded by upgrade_offline.sh; re-run" >&2
    echo "      upgrade_offline.sh to rebuild both, or reinstall from the signed bundle." >&2
    return 1
  fi
  _actual="$(udbmcp_hash_tree "$TARGET/venv.previous")"
  if [ -z "$_actual" ]; then
    return 1
  fi
  if ! udbmcp_symlinks_contained "$TARGET/venv.previous"; then
    rm -f "$_actual"
    return 1
  fi
  _matched=0
  if cmp -s "$_actual" "$_reference"; then _matched=1; fi
  # Explicit operator opt-in only: the external anchor is written by a
  # verified rollback and is never refreshed when a later upgrade demotes a
  # different venv.previous, so after upgrades move past the anchored release
  # every rollback of a LEGITIMATE tree would fail closed forever against a
  # stale anchor. --re-anchor re-verifies against the co-located manifest —
  # the documented residual — and re-anchors the verified manifest on
  # success. It never skips verification and never runs silently.
  if [ "$_matched" -eq 0 ] && [ "$_reference" = "$_anchor" ] && [ "$RE_ANCHOR" -eq 1 ]; then
    if [ ! -f "$_colocated" ]; then
      rm -f "$_actual"
      echo "FAIL: --re-anchor needs the co-located manifest at $_colocated to" >&2
      echo "      re-verify against; none found. Reinstall from the signed bundle." >&2
      return 1
    fi
    echo "WARN: --re-anchor: the external anchor does not match this tree; re-verifying" >&2
    echo "      against the CO-LOCATED manifest ($_colocated), which shares the swap" >&2
    echo "      tree's writable root — this is the documented residual, NOT anchor-" >&2
    echo "      grade assurance. Run it only after confirming out of band that" >&2
    echo "      venv.previous is the legitimate demoted release; on success the" >&2
    echo "      verified manifest is re-anchored at $_anchor." >&2
    _reference="$_colocated"
    if cmp -s "$_actual" "$_reference"; then _matched=1; fi
  fi
  if [ "$_matched" -eq 0 ]; then
    rm -f "$_actual"
    echo "FAIL: $TARGET/venv.previous does not match its integrity reference" >&2
    echo "      ($_reference); refusing to execute it. The tree is left in place" >&2
    if [ "$_reference" = "$_anchor" ]; then
      echo "      for analysis. The external anchor is authoritative and only a" >&2
      echo "      verified rollback rewrites it — an upgrade that later demoted a" >&2
      echo "      different venv.previous never refreshes it, so a legitimate new" >&2
      echo "      tree fails here too. If you have confirmed OUT OF BAND that this" >&2
      echo "      tree is the legitimate demoted release, re-run with --re-anchor" >&2
      echo "      to re-verify against the co-located manifest and re-anchor;" >&2
      echo "      otherwise reinstall from the signed bundle. Do NOT hand-edit" >&2
      echo "      the anchor to force a rollback." >&2
    else
      echo "      for analysis; reinstall from the signed bundle instead." >&2
    fi
    return 1
  fi
  rm -f "$_actual"
  UDBMCP_VERIFIED_MANIFEST="$_reference"
}

# Re-anchor the manifest that just passed verification OUTSIDE the swap tree
# (root-owned configuration directory), so the next verification of this tree
# cannot be defeated by regenerating the co-located manifest. Defense in
# depth, not a precondition: the tree already passed the gate, so a failure to
# write the anchor is a warning, never an abort.
udbmcp_anchor_verified_manifest() {
  [ -n "$UDBMCP_VERIFIED_MANIFEST" ] || return 0
  [ "$UDBMCP_VERIFIED_MANIFEST" != "$ROLLBACK_ANCHOR" ] || return 0
  if ! mkdir -p "$(dirname "$ROLLBACK_ANCHOR")" 2>/dev/null; then
    echo "WARN: cannot create $(dirname "$ROLLBACK_ANCHOR"); the verified manifest" >&2
    echo "      is NOT anchored outside the swap tree" >&2
    return 0
  fi
  if ! cp "$UDBMCP_VERIFIED_MANIFEST" "$ROLLBACK_ANCHOR.new.$$" 2>/dev/null \
    || ! mv "$ROLLBACK_ANCHOR.new.$$" "$ROLLBACK_ANCHOR" 2>/dev/null; then
    rm -f "$ROLLBACK_ANCHOR.new.$$" 2>/dev/null || true
    echo "WARN: could not write $ROLLBACK_ANCHOR; the verified manifest is NOT" >&2
    echo "      anchored outside the swap tree" >&2
    return 0
  fi
  chmod 0644 "$ROLLBACK_ANCHOR" 2>/dev/null || true
  echo "    verified manifest anchored at $ROLLBACK_ANCHOR for the next rollback"
}

if systemctl list-unit-files 2>/dev/null | grep -q universal-db-mcp; then systemctl stop universal-db-mcp || true; fi
if [ -d "$TARGET/venv.previous" ]; then
  # Integrity gate BEFORE any rename and before the doctor call below executes
  # the payload: a tampered or drifted venv.previous must never run, and a
  # failed gate must leave the tree exactly as found.
  udbmcp_verify_previous_venv || exit 1
  udbmcp_anchor_verified_manifest
  echo "==> rolling back venv"
  # An upgrade killed between its two renames leaves NO current venv at all;
  # under set -e that used to abort here, before venv.previous was restored,
  # leaving the service's ExecStart path missing.
  if [ -d "$TARGET/venv" ]; then
    rm -rf "$TARGET/venv.failed"
    mv "$TARGET/venv" "$TARGET/venv.failed"
  else
    echo "    no current venv (upgrade interrupted mid-switch); restoring venv.previous in place"
  fi
  mv "$TARGET/venv.previous" "$TARGET/venv"
  # doctor resolves the config as args.config or $UDBMCP_CONFIG and fails
  # closed with "no config path" when neither is set; pass it explicitly so
  # the rollback is not aborted by its own validation after the venv swap.
  "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
    --config "${UDBMCP_CONFIG:-$ETC_DIR/config.yaml}"
  if [ -d "$TARGET/venv.failed" ]; then
    echo "==> rollback complete (failed venv kept at $TARGET/venv.failed for analysis)"
  else
    echo "==> rollback complete"
  fi
else
  echo "no $TARGET/venv.previous found"
fi

LATEST_BACKUP="$(ls -1dt "$BACKUP_ROOT"/pre-upgrade-* 2>/dev/null | head -1 || true)"
if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/universal-db-mcp/config.yaml" ]; then
  if [ "$RESTORE_CONFIG" -ne 1 ]; then
    echo "NOTE: a configuration backup exists at $LATEST_BACKUP, but --restore-config was not given;"
    echo "      the live configuration is left untouched (venv-only rollback)."
  else
    echo "==> restoring configuration from $LATEST_BACKUP (validated before anything is displaced)"
    rm -rf "$ETC_DIR.new"
    cp -a "$LATEST_BACKUP/universal-db-mcp" "$ETC_DIR.new"
    # The backup is a wholesale copy of the configuration directory taken at
    # upgrade time, so it contains whatever venv-rollback.sha256 existed THEN.
    # The external anchor is trust state, not configuration: a verified
    # rollback just anchored the manifest that passed verification there, and
    # letting --restore-config silently replace it with the backup's stale
    # copy would deadlock the NEXT rollback against an anchor only --re-anchor
    # could escape. The anchor is therefore excluded from the restored copy,
    # and the pre-restore anchor is put back afterwards. The snapshot is
    # staged NEXT TO $ETC_DIR (not inside it) so the displacement below
    # cannot carry it away; the final move is a rename within the same
    # directory, hence atomic, and never aborts the restore.
    _anchor_in_etc=0
    _anchor_restore=""
    case "$ROLLBACK_ANCHOR" in
      "$ETC_DIR"/*)
        _anchor_in_etc=1
        rm -f "$ETC_DIR.new/${ROLLBACK_ANCHOR#"$ETC_DIR"/}"
        if [ -f "$ROLLBACK_ANCHOR" ]; then
          _anchor_restore="${ETC_DIR}.anchor-restore.$$"
          cp "$ROLLBACK_ANCHOR" "$_anchor_restore" 2>/dev/null || _anchor_restore=""
        fi
        ;;
    esac
    if [ -x "$TARGET/venv/bin/python" ]; then
      UDBMCP_CONFIG="$ETC_DIR.new/config.yaml" "$TARGET/venv/bin/python" -m universal_db_mcp doctor \
        || {
          echo "FAIL: the backup configuration failed validation; live configuration left untouched" >&2
          rm -rf "$ETC_DIR.new"
          exit 1
        }
    else
      echo "WARN: $TARGET/venv/bin/python not executable; restoring the backup without validation" >&2
    fi
    # The live configuration may contain edits made after the backup (new
    # connections, rotated CA paths); it is moved aside and KEPT, never
    # deleted, so a wrong rollback is itself reversible.
    PRE_ROLLBACK="$BACKUP_ROOT/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$PRE_ROLLBACK"
    if [ -d "$ETC_DIR" ]; then mv "$ETC_DIR" "$PRE_ROLLBACK/universal-db-mcp"; fi
    mv "$ETC_DIR.new" "$ETC_DIR"
    echo "    previous live configuration preserved at $PRE_ROLLBACK/universal-db-mcp"
    if [ -n "$_anchor_restore" ]; then
      if mv "$_anchor_restore" "$ROLLBACK_ANCHOR" 2>/dev/null; then
        chmod 0644 "$ROLLBACK_ANCHOR" 2>/dev/null || true
        echo "    external rollback anchor preserved at $ROLLBACK_ANCHOR (the backup's stale copy was excluded)"
      else
        rm -f "$_anchor_restore" 2>/dev/null || true
        echo "WARN: could not restore the external rollback anchor at $ROLLBACK_ANCHOR;" >&2
        echo "      the next rollback verifies against the co-located manifest and re-anchors on success" >&2
      fi
    elif [ "$_anchor_in_etc" -eq 1 ] && [ -n "$UDBMCP_VERIFIED_MANIFEST" ] \
      && [ "$UDBMCP_VERIFIED_MANIFEST" != "$ROLLBACK_ANCHOR" ]; then
      # The anchor directory was restored but no pre-restore anchor survived
      # to put back, while a verified rollback DID produce a manifest (still
      # co-located outside the restored directory): re-anchor it, so the
      # restore cannot leave the anchor regressed or missing.
      udbmcp_anchor_verified_manifest
    fi
  fi
elif [ -n "$LATEST_BACKUP" ]; then
  echo "WARN: backup at $LATEST_BACKUP has no config.yaml; leaving live configuration untouched"
fi

if [ "$RESTORE_CONFIG" -eq 1 ] && [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/metadata.sqlite" ]; then
  mkdir -p "$STATE_DIR"
  if [ -f "$STATE_DIR/metadata.sqlite" ]; then
    cp "$STATE_DIR/metadata.sqlite" "$STATE_DIR/metadata.sqlite.pre-rollback"
  fi
  cp "$LATEST_BACKUP/metadata.sqlite" "$STATE_DIR/metadata.sqlite"
fi

echo "==> restart the service (systemctl restart universal-db-mcp)"
