"""Clean up and deduplicate self-protection alert flooding in Centralium DB.

Keeps 1 clean record per unique file for "Agent file modified" incidents
and findings (and unexpected file findings), dropping duplicate records.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path


def cleanup_db(db_path: Path) -> dict[str, int]:
    if not db_path.exists():
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    before_incidents = cursor.execute("SELECT count(*) FROM incidents").fetchone()[0]
    before_findings = cursor.execute("SELECT count(*) FROM findings").fetchone()[0]
    before_events = cursor.execute("SELECT count(*) FROM events").fetchone()[0]

    print("Before cleanup:")
    print(f"  Incidents: {before_incidents}")
    print(f"  Findings:  {before_findings}")
    print(f"  Events:    {before_events}")

    # 1. Deduplicate "Agent file modified" incidents and findings
    inc_rows = cursor.execute("""
        SELECT incident_id, created_at, event_ids, finding_ids, ai_analysis_id, actions
        FROM incidents
        WHERE title = 'Agent file modified'
        ORDER BY created_at ASC
    """).fetchall()

    file_to_inc: dict[str, list[dict]] = {}
    for inc_id, created_at, eids_str, fids_str, ai_id, acts_str in inc_rows:
        fids = json.loads(fids_str) if fids_str else []
        fid = fids[0] if fids else None
        fpath = None
        if fid:
            frow = cursor.execute("SELECT details FROM findings WHERE finding_id = ?", (fid,)).fetchone()
            if frow and frow[0]:
                try:
                    fdetails = json.loads(frow[0])
                    fpath = fdetails.get("file")
                except (json.JSONDecodeError, KeyError, TypeError):
                    fpath = None
        if not fpath:
            fpath = f"unknown_{inc_id}"

        file_to_inc.setdefault(fpath, []).append({
            "incident_id": inc_id,
            "created_at": created_at,
            "event_ids": json.loads(eids_str) if eids_str else [],
            "finding_ids": fids,
            "ai_analysis_id": ai_id,
            "actions": json.loads(acts_str) if acts_str else [],
        })

    del_inc_ids: list[str] = []
    del_finding_ids: list[str] = []
    del_event_ids: list[str] = []
    del_action_ids: list[str] = []
    del_ai_ids: list[str] = []

    for _fpath, items in file_to_inc.items():
        # Keep items[0]
        for dup in items[1:]:
            del_inc_ids.append(dup["incident_id"])
            del_finding_ids.extend(dup["finding_ids"])
            del_event_ids.extend(dup["event_ids"])
            del_action_ids.extend(dup["actions"])
            if dup["ai_analysis_id"]:
                del_ai_ids.append(dup["ai_analysis_id"])

    # 2. Deduplicate "SP-FILE-UNEXPECTED" findings
    unexp_rows = cursor.execute("""
        SELECT finding_id, timestamp, event_id, details
        FROM findings
        WHERE rule_id = 'SP-FILE-UNEXPECTED'
        ORDER BY timestamp ASC
    """).fetchall()

    file_to_unexp: dict[str, list[dict]] = {}
    for fid, ts, eid, d_str in unexp_rows:
        fpath = None
        if d_str:
            try:
                d = json.loads(d_str)
                fpath = d.get("file")
            except (json.JSONDecodeError, KeyError, TypeError):
                fpath = None
        if not fpath:
            fpath = f"unknown_{fid}"
        file_to_unexp.setdefault(fpath, []).append({
            "finding_id": fid,
            "timestamp": ts,
            "event_id": eid,
        })

    for _fpath, items in file_to_unexp.items():
        for dup in items[1:]:
            del_finding_ids.append(dup["finding_id"])
            if dup["event_id"]:
                del_event_ids.append(dup["event_id"])

    # Perform deletions in transaction
    if del_inc_ids:
        cursor.executemany("DELETE FROM incidents WHERE incident_id = ?", [(i,) for i in del_inc_ids])
    if del_finding_ids:
        cursor.executemany("DELETE FROM findings WHERE finding_id = ?", [(f,) for f in del_finding_ids])
    if del_event_ids:
        cursor.executemany("DELETE FROM events WHERE event_id = ?", [(e,) for e in del_event_ids])
    if del_action_ids:
        cursor.executemany("DELETE FROM response_actions WHERE action_id = ?", [(a,) for a in del_action_ids])
    if del_ai_ids:
        cursor.executemany("DELETE FROM ai_analysis WHERE analysis_id = ?", [(a,) for a in del_ai_ids])

    conn.commit()

    after_incidents = cursor.execute("SELECT count(*) FROM incidents").fetchone()[0]
    after_findings = cursor.execute("SELECT count(*) FROM findings").fetchone()[0]
    after_events = cursor.execute("SELECT count(*) FROM events").fetchone()[0]

    print("\nAfter cleanup:")
    print(f"  Incidents: {after_incidents} (removed {len(del_inc_ids)})")
    print(f"  Findings:  {after_findings} (removed {len(del_finding_ids)})")
    print(f"  Events:    {after_events} (removed {len(del_event_ids)})")

    cursor.execute("VACUUM")
    conn.close()

    return {
        "incidents_before": before_incidents,
        "incidents_after": after_incidents,
        "findings_before": before_findings,
        "findings_after": after_findings,
    }


if __name__ == "__main__":
    target_db = Path("data/centralium.db")
    if len(sys.argv) > 1:
        target_db = Path(sys.argv[1])
    cleanup_db(target_db)
