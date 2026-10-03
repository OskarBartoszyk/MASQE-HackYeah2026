#!/usr/bin/env python3
"""Show that the audit log is tamper-evident.

Plays an insider with direct access to the database file: rewrites the newest
BLOCK decision to ALLOW, bypassing the gateway. The console (Events page) and
GET /v1/audit/verify then report the record as modified. --undo restores the
original value and the chain verifies again, unless the gateway wrote to that
record in between: then the edit was caught and stays recorded for good
(evidence is never erased; make reset-data starts a fresh log).

    python3 scripts/tamper_demo.py          # tamper
    python3 scripts/tamper_demo.py --undo   # restore
"""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import sys
import urllib.request

DB = pathlib.Path(os.getenv("MASQE_DB", "data/masqe.db"))
STATE = DB.with_name("tamper-demo.json")
GATEWAY = os.getenv("MASQE_URL", "http://127.0.0.1:8080")


def verify() -> None:
    req = urllib.request.Request(GATEWAY + "/v1/audit/verify", headers={"Authorization": "Bearer secops-demo-key"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.load(r)
    except OSError as exc:
        print(f"(gateway not reachable at {GATEWAY}: {exc}; open the console's Events page instead)")
        return
    print(f"GET /v1/audit/verify -> {result['status'].upper()} ({result['entries']} entries, {result['problem_count']} problems)")
    for p in result["problems"][:5]:
        print(f"  {p['kind']:16} {p['record']}  {p['detail']}")


def main() -> int:
    if not DB.exists():
        print(f"No database at {DB}. Start MASQE (make run) and send some traffic first.")
        return 1
    db = sqlite3.connect(DB)
    if "--undo" in sys.argv:
        if not STATE.exists():
            print("Nothing to undo.")
            return 1
        saved = json.loads(STATE.read_text())
        db.execute("UPDATE audit_events SET decision=? WHERE id=?", (saved["decision"], saved["id"]))
        db.commit()
        STATE.unlink()
        print(f"Restored event {saved['id']} to {saved['decision']}.")
    else:
        if STATE.exists():
            print("Already tampered; run with --undo first.")
            return 1
        # A settled event: its async explanation already arrived.
        row = db.execute("SELECT id, user_id, action FROM audit_events WHERE decision='BLOCK' AND explanation NOT LIKE '%\"status\":\"pending\"%' ORDER BY timestamp DESC LIMIT 1").fetchone()
        if not row:
            print("No BLOCK decision in the log yet. Send an attack first, e.g. the Playground's 'Exfiltration attempt'.")
            return 1
        STATE.write_text(json.dumps({"id": row[0], "decision": "BLOCK"}))
        db.execute("UPDATE audit_events SET decision='ALLOW' WHERE id=?", (row[0],))
        db.commit()
        print(f"Insider edit: event {row[0]} ({row[1]}, {row[2]}) rewritten from BLOCK to ALLOW directly in {DB}.")
    db.close()
    verify()
    return 0


if __name__ == "__main__":
    sys.exit(main())
