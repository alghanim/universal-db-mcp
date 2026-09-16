#!/usr/bin/env python3
"""Render test-evidence/version-matrix/*.json as the markdown table the
ledger carries. Rows come only from JSON records; nothing is inferred."""

from __future__ import annotations

import json
import sys
from pathlib import Path

EV = Path(__file__).resolve().parents[2] / "test-evidence" / "version-matrix"

rows = []
for f in sorted(EV.glob("*.json")):
    d = json.loads(f.read_text(encoding="utf-8"))
    if "summary" not in d:
        rows.append((d.get("engine", "?"), d.get("label", f.name), "", "not_run", d.get("reason", "")))
        continue
    checks = d["checks"]
    passed = sum(1 for c in checks if c["status"] == "passed")
    skipped = [c["check"] for c in checks if c["status"] == "skipped"]
    failed = d["summary"]["failed"]
    session = d.get("session") or {}
    sess = ""
    if session:
        iso = session.get("isolation") or "default"
        ro = "server-ro" if session.get("read_only_enforced") else "guard-ro"
        sess = f"{iso}/{ro}"
    status = "passed" if not failed else "failed: " + ", ".join(failed)
    if skipped:
        status += f" (skipped: {', '.join(skipped)})"
    rows.append((d["engine"], d["label"], str(d.get("server_version") or "")[:34], f"{passed}/{len(checks)}", status, sess))

print("| Engine | Image | Server reports | Checks | Result | Session |")
print("|---|---|---|---|---|---|")
for r in rows:
    r = tuple(r) + ("",) * (6 - len(r))
    print(f"| {r[0]} | `{r[1]}` | {r[2]} | {r[3]} | {r[4]} | {r[5]} |")
if len(sys.argv) > 1 and sys.argv[1] == "--failed-details":
    for f in sorted(EV.glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        for c in d.get("checks", []):
            if c["status"] == "failed":
                print(f"\n{d['label']} / {c['check']}: {c['detail'][:300]}")
