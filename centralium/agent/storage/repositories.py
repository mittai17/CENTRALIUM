"""Typed repository helpers over :class:`Database` (model <-> row mapping).

Other modules should use these instead of writing SQL against core tables so the
row format stays in one place. Everything is parameterized.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from centralium.agent.models import (
    ActionResult,
    AIAnalysis,
    Finding,
    Incident,
    MLResult,
    NormalizedEvent,
)
from centralium.agent.storage.database import Database

LIST_KINDS = frozenset({"sha256", "path", "process", "ip", "domain", "signer", "parent_child"})


def _j(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---------------------------------------------------------------- events
    def add_event(self, ev: NormalizedEvent) -> None:
        d = ev.model_dump(mode="json")
        d["raw_metadata"] = _j(d["raw_metadata"])
        self.db.insert("events", d, on_conflict="IGNORE")

    def get_event(self, event_id: str) -> NormalizedEvent | None:
        r = self.db.query_one("SELECT * FROM events WHERE event_id = ?", (event_id,))
        if r is None:
            return None
        d = dict(r)
        d["raw_metadata"] = json.loads(d["raw_metadata"] or "{}")
        return NormalizedEvent.model_validate(d)

    def recent_events(self, limit: int = 100, event_type: str | None = None) -> list[dict[str, Any]]:
        if event_type:
            rows = self.db.query(
                "SELECT * FROM events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit),
            )
        else:
            rows = self.db.query("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- findings
    def add_finding(self, f: Finding, incident_id: str | None = None) -> None:
        self.db.insert(
            "findings",
            {
                "finding_id": f.finding_id,
                "event_id": f.event_id,
                "timestamp": f.timestamp.isoformat(),
                "source": f.source.value,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "score": f.score,
                "confidence": f.confidence,
                "known_malicious": int(f.known_malicious),
                "mitre_techniques": _j(f.mitre_techniques),
                "attack_stage": f.attack_stage.value if f.attack_stage else None,
                "details": _j(f.details),
                "incident_id": incident_id,
            },
            on_conflict="REPLACE",
        )

    def findings_for_event(self, event_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM findings WHERE event_id = ? ORDER BY timestamp", (event_id,)
            )
        ]

    # ---------------------------------------------------------------- incidents
    def save_incident(self, inc: Incident) -> None:
        self.db.insert(
            "incidents",
            {
                "incident_id": inc.incident_id,
                "created_at": inc.created_at.isoformat(),
                "updated_at": inc.updated_at.isoformat(),
                "host_id": inc.host_id,
                "title": inc.title,
                "status": inc.status,
                "risk_score": inc.risk_score,
                "band": inc.band.value,
                "attack_stage": inc.attack_stage.value if inc.attack_stage else None,
                "mitre_techniques": _j(inc.mitre_techniques),
                "event_ids": _j(inc.event_ids),
                "finding_ids": _j(inc.finding_ids),
                "summary": inc.summary,
                "ai_analysis_id": inc.ai_analysis_id,
                "actions": _j(inc.actions),
            },
            on_conflict="REPLACE",
        )

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        r = self.db.query_one("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return dict(r) if r else None

    def list_incidents(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.db.query(
                "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit)
            )
        else:
            rows = self.db.query("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- ML / AI / actions
    def add_ml_result(self, event_id: str, r: MLResult, latency_ms: float = 0.0) -> None:
        self.db.insert(
            "ml_results",
            {
                "event_id": event_id,
                "timestamp": Database.now(),
                "anomaly_score": r.anomaly_score,
                "classification": r.classification,
                "classification_confidence": r.classification_confidence,
                "top_features": _j(r.top_features),
                "model_version": r.model_version,
                "feature_version": r.feature_version,
                "latency_ms": latency_ms,
            },
        )

    def add_ai_analysis(self, a: AIAnalysis) -> None:
        self.db.insert(
            "ai_analysis",
            {
                "analysis_id": a.analysis_id,
                "event_id": a.event_id,
                "timestamp": a.timestamp.isoformat(),
                "available": int(a.available),
                "role": a.role,
                "model_name": a.model_name,
                "verdict_json": a.verdict.model_dump_json() if a.verdict else None,
                "latency_ms": a.latency_ms,
                "rag_sources": _j(a.rag_sources),
                "error": a.error,
            },
            on_conflict="REPLACE",
        )

    def add_action(self, a: ActionResult) -> None:
        self.db.insert(
            "response_actions",
            {
                "action_id": a.action_id,
                "timestamp": a.timestamp.isoformat(),
                "action": a.action.value,
                "status": a.status.value,
                "target": _j(a.target),
                "detail": a.detail,
                "event_id": a.event_id,
                "incident_id": a.incident_id,
            },
            on_conflict="REPLACE",
        )

    def list_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.db.query("SELECT * FROM response_actions ORDER BY timestamp DESC LIMIT ?", (limit,))
        ]

    # ---------------------------------------------------------------- allow / block lists
    def _list_add(
        self, table: str, kind: str, value: str, reason: str, added_by: str, expires_at: str | None
    ) -> None:
        if kind not in LIST_KINDS:
            raise ValueError(f"invalid list kind {kind!r}; allowed: {sorted(LIST_KINDS)}")
        self.db.insert(
            table,
            {
                "kind": kind,
                "value": value.lower() if kind == "sha256" else value,
                "reason": reason,
                "added_by": added_by,
                "added_at": Database.now(),
                "expires_at": expires_at,
            },
            on_conflict="REPLACE",
        )

    def _list_has(self, table: str, kind: str, value: str) -> bool:
        v = value.lower() if kind == "sha256" else value
        r = self.db.query_one(
            f"SELECT expires_at FROM {table} WHERE kind = ? AND value = ?",  # noqa: S608 (internal table)
            (kind, v),
        )
        if r is None:
            return False
        exp = r["expires_at"]
        return not (exp and datetime.fromisoformat(exp) < datetime.now(UTC))

    def add_allowlist(
        self, kind: str, value: str, reason: str = "", added_by: str = "system", expires_at: str | None = None
    ) -> None:
        self._list_add("allowlist", kind, value, reason, added_by, expires_at)

    def is_allowlisted(self, kind: str, value: str) -> bool:
        return self._list_has("allowlist", kind, value)

    def add_blocklist(
        self, kind: str, value: str, reason: str = "", added_by: str = "system", expires_at: str | None = None
    ) -> None:
        self._list_add("blocklist", kind, value, reason, added_by, expires_at)

    def is_blocklisted(self, kind: str, value: str) -> bool:
        return self._list_has("blocklist", kind, value)

    # ---------------------------------------------------------------- IOC cache
    def upsert_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        *,
        threat_type: str = "",
        confidence: float = 1.0,
        expires_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        now = Database.now()
        self.db.execute(
            "INSERT INTO ioc_cache (ioc_type, value, source, threat_type, confidence, first_seen,"
            " last_seen, expires_at, metadata) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(ioc_type, value, source) DO UPDATE SET last_seen=excluded.last_seen, "
            "threat_type=excluded.threat_type, confidence=excluded.confidence, "
            "expires_at=excluded.expires_at, metadata=excluded.metadata",
            (
                ioc_type,
                value.lower() if ioc_type == "sha256" else value,
                source,
                threat_type,
                confidence,
                now,
                now,
                expires_at,
                _j(metadata or {}),
            ),
        )

    def lookup_ioc(self, ioc_type: str, value: str) -> list[dict[str, Any]]:
        v = value.lower() if ioc_type == "sha256" else value
        rows = self.db.query(
            "SELECT * FROM ioc_cache WHERE ioc_type = ? AND value = ? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (ioc_type, v, Database.now()),
        )
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- sync queue (minimal)
    def enqueue_sync(self, payload: dict[str, Any], dedup_key: str | None = None) -> bool:
        """Durably enqueue; returns False if ``dedup_key`` already queued."""
        n = self.db.execute(
            "INSERT OR IGNORE INTO sync_queue (dedup_key, payload, created_at, status) "
            "VALUES (?,?,?, 'pending')",
            (dedup_key, _j(payload), Database.now()),
        )
        return n > 0

    def pending_sync_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM sync_queue WHERE status='pending'") or 0)

    # ---------------------------------------------------------------- counters for dashboards
    def counts(self) -> dict[str, int]:
        return {
            t: self.db.count(t)
            for t in ("events", "findings", "incidents", "ml_results", "ai_analysis", "response_actions")
        }
