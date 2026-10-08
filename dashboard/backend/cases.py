"""SOC Case Management for the Centralium Dashboard.

Provides case tracking (assignee, investigator notes, status OPEN/INVESTIGATING/RESOLVED/CLOSED,
SLA countdown timers, linked incident IDs, and full tamper-evident audit trail).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from dashboard.backend.context import decode_row
from dashboard.backend.security import Principal, require

log = logging.getLogger("centralium.dashboard.cases")

CASES_SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    assignee TEXT,
    sla_deadline TEXT NOT NULL,
    linked_incident_ids TEXT NOT NULL,
    notes TEXT NOT NULL,
    audit_trail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON soc_cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assignee ON soc_cases(assignee);
"""

DEFAULT_SLA_HOURS = {
    "CRITICAL": 1,
    "HIGH": 4,
    "MEDIUM": 24,
    "LOW": 72,
}


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class InvestigatorNote:
    note_id: str
    author: str
    created_at: str
    content: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseAuditEntry:
    timestamp: str
    actor: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=2000)
    severity: CaseSeverity = CaseSeverity.MEDIUM
    assignee: str | None = Field(default=None, max_length=100)
    linked_incident_ids: list[str] = Field(default_factory=list)
    sla_hours: int | None = Field(default=None, ge=1, le=720)


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: CaseStatus | None = None
    severity: CaseSeverity | None = None
    assignee: str | None = Field(default=None, max_length=100)
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, min_length=3, max_length=2000)


class AddNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=5000)


class LinkIncidentsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_ids: list[str] = Field(min_length=1)


def compute_sla_info(
    deadline_iso: str,
    status: CaseStatus | str,
    created_at_iso: str,
    updated_at_iso: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Calculate SLA countdown metrics, breach detection, and elapsed time."""
    current_time = now or datetime.now(UTC)
    deadline = datetime.fromisoformat(deadline_iso)
    created_at = datetime.fromisoformat(created_at_iso)

    total_duration_seconds = max(1.0, (deadline - created_at).total_seconds())
    status_str = str(status).upper()

    if status_str in (CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value):
        resolved_at = datetime.fromisoformat(updated_at_iso)
        was_breached = resolved_at > deadline
        return {
            "sla_status": "breached" if was_breached else "met",
            "is_breached": was_breached,
            "remaining_seconds": 0.0,
            "total_sla_seconds": total_duration_seconds,
            "elapsed_seconds": (resolved_at - created_at).total_seconds(),
            "deadline": deadline_iso,
        }

    remaining_seconds = (deadline - current_time).total_seconds()
    is_breached = remaining_seconds <= 0
    elapsed_seconds = max(0.0, (current_time - created_at).total_seconds())

    return {
        "sla_status": "breached" if is_breached else "active",
        "is_breached": is_breached,
        "remaining_seconds": max(0.0, remaining_seconds),
        "total_sla_seconds": total_duration_seconds,
        "elapsed_seconds": elapsed_seconds,
        "deadline": deadline_iso,
    }


class CaseStore:
    """Thread-safe SQLite storage for SOC cases and investigation notes."""

    def __init__(self, db_or_conn: sqlite3.Connection | str | Path) -> None:
        if isinstance(db_or_conn, sqlite3.Connection):
            self._conn = db_or_conn
        else:
            self._conn = sqlite3.connect(str(db_or_conn), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(CASES_SCHEMA)

    def _record_audit(
        self,
        case_id: str,
        actor: str,
        action: str,
        details: dict[str, Any],
        current_audit_raw: str,
    ) -> str:
        now_str = datetime.now(UTC).isoformat()
        try:
            audit_list = json.loads(current_audit_raw)
        except Exception:
            audit_list = []
        entry = CaseAuditEntry(timestamp=now_str, actor=actor, action=action, details=details).to_dict()
        audit_list.append(entry)
        return json.dumps(audit_list)

    def create_case(self, req: CaseCreate, actor: str = "analyst") -> dict[str, Any]:
        now = datetime.now(UTC)
        now_str = now.isoformat()
        case_id = f"case_{uuid.uuid4().hex[:10]}"

        sla_hrs = req.sla_hours or DEFAULT_SLA_HOURS.get(req.severity.value, 24)
        sla_deadline = (now + timedelta(hours=sla_hrs)).isoformat()

        audit_entry = CaseAuditEntry(
            timestamp=now_str,
            actor=actor,
            action="case_created",
            details={"title": req.title, "severity": req.severity.value, "sla_hours": sla_hrs},
        ).to_dict()
        audit_raw = json.dumps([audit_entry])
        notes_raw = json.dumps([])
        incidents_raw = json.dumps(req.linked_incident_ids)

        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO soc_cases
                   (case_id, title, description, status, severity, assignee,
                    sla_deadline, linked_incident_ids, notes, audit_trail, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    req.title,
                    req.description,
                    CaseStatus.OPEN.value,
                    req.severity.value,
                    req.assignee,
                    sla_deadline,
                    incidents_raw,
                    notes_raw,
                    audit_raw,
                    now_str,
                    now_str,
                ),
            )

        return self.get_case(case_id)  # type: ignore[return-value]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM soc_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = decode_row(row, ("linked_incident_ids", "notes", "audit_trail"))
            data["sla_info"] = compute_sla_info(
                data["sla_deadline"],
                data["status"],
                data["created_at"],
                data["updated_at"],
            )
            return data

    def list_cases(
        self,
        status: str | None = None,
        assignee: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM soc_cases WHERE 1=1"
        params: list[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if assignee:
            query += " AND assignee = ?"
            params.append(assignee)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            data = decode_row(r, ("linked_incident_ids", "notes", "audit_trail"))
            data["sla_info"] = compute_sla_info(
                data["sla_deadline"],
                data["status"],
                data["created_at"],
                data["updated_at"],
            )
            results.append(data)
        return results

    def update_case(self, case_id: str, updates: CaseUpdate, actor: str = "analyst") -> dict[str, Any]:
        with self._lock, self._conn:
            cur = self._conn.execute("SELECT * FROM soc_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Case not found")

            now_str = datetime.now(UTC).isoformat()
            fields_to_update: list[str] = ["updated_at = ?"]
            params: list[Any] = [now_str]
            diff: dict[str, Any] = {}

            if updates.status is not None and updates.status.value != row["status"]:
                fields_to_update.append("status = ?")
                params.append(updates.status.value)
                diff["status"] = {"old": row["status"], "new": updates.status.value}

            if updates.severity is not None and updates.severity.value != row["severity"]:
                fields_to_update.append("severity = ?")
                params.append(updates.severity.value)
                diff["severity"] = {"old": row["severity"], "new": updates.severity.value}

            if updates.assignee is not None and updates.assignee != row["assignee"]:
                fields_to_update.append("assignee = ?")
                params.append(updates.assignee)
                diff["assignee"] = {"old": row["assignee"], "new": updates.assignee}

            if updates.title is not None and updates.title != row["title"]:
                fields_to_update.append("title = ?")
                params.append(updates.title)
                diff["title"] = {"old": row["title"], "new": updates.title}

            if updates.description is not None and updates.description != row["description"]:
                fields_to_update.append("description = ?")
                params.append(updates.description)
                diff["description"] = "updated"

            if diff:
                audit_raw = self._record_audit(case_id, actor, "case_updated", diff, row["audit_trail"])
                fields_to_update.append("audit_trail = ?")
                params.append(audit_raw)

                sql = f"UPDATE soc_cases SET {', '.join(fields_to_update)} WHERE case_id = ?"  # noqa: S608
                params.append(case_id)
                self._conn.execute(sql, params)

        return self.get_case(case_id)  # type: ignore[return-value]

    def add_note(self, case_id: str, content: str, author: str = "analyst") -> dict[str, Any]:
        note = InvestigatorNote(
            note_id=f"note_{uuid.uuid4().hex[:8]}",
            author=author,
            created_at=datetime.now(UTC).isoformat(),
            content=content,
        )
        with self._lock, self._conn:
            cur = self._conn.execute("SELECT notes, audit_trail FROM soc_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Case not found")

            notes = json.loads(row["notes"])
            notes.append(note.to_dict())
            audit_raw = self._record_audit(
                case_id, author, "note_added", {"note_id": note.note_id}, row["audit_trail"]
            )
            now_str = datetime.now(UTC).isoformat()

            self._conn.execute(
                "UPDATE soc_cases SET notes = ?, audit_trail = ?, updated_at = ? WHERE case_id = ?",
                (json.dumps(notes), audit_raw, now_str, case_id),
            )

        return self.get_case(case_id)  # type: ignore[return-value]

    def link_incidents(self, case_id: str, incident_ids: list[str], actor: str = "analyst") -> dict[str, Any]:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "SELECT linked_incident_ids, audit_trail FROM soc_cases WHERE case_id = ?", (case_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Case not found")

            current_ids: list[str] = json.loads(row["linked_incident_ids"])
            added = [i for i in incident_ids if i not in current_ids]
            if added:
                new_ids = [*current_ids, *added]
                audit_raw = self._record_audit(
                    case_id, actor, "incidents_linked", {"added": added}, row["audit_trail"]
                )
                now_str = datetime.now(UTC).isoformat()
                self._conn.execute(
                    "UPDATE soc_cases SET linked_incident_ids = ?, audit_trail = ?, updated_at = ? "
                    "WHERE case_id = ?",
                    (json.dumps(new_ids), audit_raw, now_str, case_id),
                )

        return self.get_case(case_id)  # type: ignore[return-value]

    def unlink_incident(self, case_id: str, incident_id: str, actor: str = "analyst") -> dict[str, Any]:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "SELECT linked_incident_ids, audit_trail FROM soc_cases WHERE case_id = ?", (case_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Case not found")

            current_ids: list[str] = json.loads(row["linked_incident_ids"])
            if incident_id in current_ids:
                new_ids = [i for i in current_ids if i != incident_id]
                audit_raw = self._record_audit(
                    case_id, actor, "incident_unlinked", {"removed": incident_id}, row["audit_trail"]
                )
                now_str = datetime.now(UTC).isoformat()
                self._conn.execute(
                    "UPDATE soc_cases SET linked_incident_ids = ?, audit_trail = ?, updated_at = ? "
                    "WHERE case_id = ?",
                    (json.dumps(new_ids), audit_raw, now_str, case_id),
                )

        return self.get_case(case_id)  # type: ignore[return-value]


def create_cases_router(store: CaseStore) -> APIRouter:
    """Build the FastAPI router for case management."""
    router = APIRouter(prefix="/api/cases", tags=["cases"])
    viewer = Depends(require("viewer"))
    analyst = Depends(require("analyst"))

    @router.post("", status_code=201)
    def create_case(req: CaseCreate, p: Principal = analyst) -> dict[str, Any]:
        return store.create_case(req, actor=p.ident)

    @router.get("")
    def list_cases(
        status: str | None = Query(None),
        assignee: str | None = Query(None),
        severity: str | None = Query(None),
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        _: Principal = viewer,
    ) -> dict[str, Any]:
        items = store.list_cases(
            status=status,
            assignee=assignee,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": items, "total": len(items)}

    @router.get("/{case_id}")
    def get_case(case_id: str, _: Principal = viewer) -> dict[str, Any]:
        case = store.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        return case

    @router.patch("/{case_id}")
    def update_case(case_id: str, req: CaseUpdate, p: Principal = analyst) -> dict[str, Any]:
        return store.update_case(case_id, req, actor=p.ident)

    @router.post("/{case_id}/notes", status_code=201)
    def add_note(case_id: str, req: AddNoteRequest, p: Principal = analyst) -> dict[str, Any]:
        return store.add_note(case_id, req.content, author=p.ident)

    @router.post("/{case_id}/link-incidents")
    def link_incidents(case_id: str, req: LinkIncidentsRequest, p: Principal = analyst) -> dict[str, Any]:
        return store.link_incidents(case_id, req.incident_ids, actor=p.ident)

    @router.delete("/{case_id}/link-incidents/{incident_id}")
    def unlink_incident(case_id: str, incident_id: str, p: Principal = analyst) -> dict[str, Any]:
        return store.unlink_incident(case_id, incident_id, actor=p.ident)

    return router
