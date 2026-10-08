"""Analyst feedback loop for SOC analysts and model learning.

* Records analyst feedback (True Positive, False Positive, Benign Expected) on findings.
* Persists feedback with rich provenance in SQLite table ``analyst_feedback``.
* Generates baseline and allowlist suggestions (never auto-applied; strictly requires
  admin confirmation before being inserted into allowlist/baselines).
* Exports versioned retraining datasets with provenance and SHA-256 integrity digests.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from centralium.agent.storage import Database

log = logging.getLogger("centralium.ml.feedback")


class FeedbackType(StrEnum):
    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    BENIGN_EXPECTED = "BENIGN_EXPECTED"


class SuggestionKind(StrEnum):
    ALLOWLIST = "allowlist"
    BASELINE = "baseline"


class SuggestionStatus(StrEnum):
    PENDING_REVIEW = "PENDING_REVIEW"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


@dataclass
class FeedbackSuggestion:
    suggestion_id: str
    feedback_id: str
    kind: SuggestionKind
    target_type: str
    target_value: str
    reason: str
    status: SuggestionStatus = SuggestionStatus.PENDING_REVIEW
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    applied_at: str | None = None
    applied_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "feedback_id": self.feedback_id,
            "kind": self.kind.value if isinstance(self.kind, SuggestionKind) else str(self.kind),
            "target_type": self.target_type,
            "target_value": self.target_value,
            "reason": self.reason,
            "status": self.status.value if isinstance(self.status, SuggestionStatus) else str(self.status),
            "created_at": self.created_at,
            "applied_at": self.applied_at,
            "applied_by": self.applied_by,
        }


@dataclass
class AnalystFeedbackRecord:
    feedback_id: str
    finding_id: str
    event_id: str
    analyst: str
    feedback_type: FeedbackType
    comment: str
    created_at: str
    rule_id: str | None = None
    severity: str | None = None
    features_snapshot: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    status: str = "recorded"

    def to_dict(self) -> dict[str, Any]:
        return {
            "feedback_id": self.feedback_id,
            "finding_id": self.finding_id,
            "event_id": self.event_id,
            "analyst": self.analyst,
            "feedback_type": self.feedback_type.value
            if isinstance(self.feedback_type, FeedbackType)
            else str(self.feedback_type),
            "comment": self.comment,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "features_snapshot": self.features_snapshot,
            "provenance": self.provenance,
            "status": self.status,
        }


@dataclass
class RetrainingDataset:
    dataset_id: str
    sample_count: int
    positive_count: int
    negative_count: int
    feature_names: list[str]
    samples: list[dict[str, Any]]
    sha256_digest: str
    output_path: str | None
    created_at: str


class AnalystFeedbackStore:
    """Manages recording of analyst feedback, rule/baseline suggestions, and retraining sets."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    analyst TEXT NOT NULL, feedback_type TEXT NOT NULL, comment TEXT,
                    created_at TEXT NOT NULL, rule_id TEXT, severity TEXT,
                    features_snapshot TEXT, provenance TEXT, status TEXT NOT NULL DEFAULT 'recorded')"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_finding ON analyst_feedback(finding_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_event ON analyst_feedback(event_id)")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS feedback_suggestions (
                    suggestion_id TEXT PRIMARY KEY, feedback_id TEXT NOT NULL, kind TEXT NOT NULL,
                    target_type TEXT NOT NULL, target_value TEXT NOT NULL, reason TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING_REVIEW', created_at TEXT NOT NULL,
                    applied_at TEXT, applied_by TEXT,
                    FOREIGN KEY (feedback_id) REFERENCES analyst_feedback(feedback_id))"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_suggestions_status ON feedback_suggestions(status)")

    def record_feedback(
        self,
        finding_id: str,
        event_id: str,
        analyst: str,
        feedback_type: FeedbackType | str,
        comment: str = "",
        rule_id: str | None = None,
        severity: str | None = None,
        features_snapshot: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> AnalystFeedbackRecord:
        """Record analyst verdict on a finding with audit provenance."""
        if isinstance(feedback_type, str):
            ft_clean = feedback_type.upper().strip()
            if ft_clean in {"TP", "TRUE_POSITIVE"}:
                ft = FeedbackType.TRUE_POSITIVE
            elif ft_clean in {"FP", "FALSE_POSITIVE"}:
                ft = FeedbackType.FALSE_POSITIVE
            elif ft_clean in {"BENIGN_EXPECTED", "BENIGN", "EXPECTED"}:
                ft = FeedbackType.BENIGN_EXPECTED
            else:
                raise ValueError(f"Invalid feedback type: {feedback_type}")
        else:
            ft = feedback_type

        # Fetch finding details if not provided
        if rule_id is None or severity is None:
            frow = self.db.query_one(
                "SELECT rule_id, severity FROM findings WHERE finding_id = ?",
                (finding_id,),
            )
            if frow:
                rule_id = rule_id or frow["rule_id"]
                severity = severity or frow["severity"]

        # Fetch event telemetry if features_snapshot or provenance empty
        features = dict(features_snapshot or {})
        prov = dict(provenance or {})
        if not features:
            erow = self.db.query_one(
                "SELECT * FROM events WHERE event_id = ?",
                (event_id,),
            )
            if erow:
                for k in (
                    "process_name",
                    "executable_path",
                    "command_line",
                    "hash_sha256",
                    "signer",
                    "destination_ip",
                    "destination_port",
                    "domain",
                    "user",
                ):
                    if erow[k] is not None:
                        features[k] = erow[k]
                prov.setdefault("host_id", erow["host_id"])
                prov.setdefault("event_timestamp", erow["timestamp"])

        prov.setdefault("recorded_by", analyst)
        prov.setdefault("recorded_at", datetime.now(UTC).isoformat())

        feedback_id = f"fb-{uuid.uuid4().hex[:12]}"
        rec = AnalystFeedbackRecord(
            feedback_id=feedback_id,
            finding_id=finding_id,
            event_id=event_id,
            analyst=analyst,
            feedback_type=ft,
            comment=comment,
            created_at=datetime.now(UTC).isoformat(),
            rule_id=rule_id,
            severity=severity,
            features_snapshot=features,
            provenance=prov,
            status="recorded",
        )

        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO analyst_feedback (
                    feedback_id, finding_id, event_id, analyst, feedback_type, comment,
                    created_at, rule_id, severity, features_snapshot, provenance, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rec.feedback_id,
                    rec.finding_id,
                    rec.event_id,
                    rec.analyst,
                    rec.feedback_type.value,
                    rec.comment,
                    rec.created_at,
                    rec.rule_id,
                    rec.severity,
                    json.dumps(rec.features_snapshot),
                    json.dumps(rec.provenance),
                    rec.status,
                ),
            )

        self.db.audit.append(
            actor=analyst,
            event_type="ANALYST_FEEDBACK_RECORDED",
            details={
                "feedback_id": rec.feedback_id,
                "finding_id": rec.finding_id,
                "feedback_type": rec.feedback_type.value,
                "rule_id": rec.rule_id,
            },
        )
        return rec

    def get_feedback(self, feedback_id: str) -> AnalystFeedbackRecord | None:
        row = self.db.query_one("SELECT * FROM analyst_feedback WHERE feedback_id = ?", (feedback_id,))
        if not row:
            return None
        return self._row_to_record(row)

    def list_feedback(
        self,
        feedback_type: FeedbackType | str | None = None,
        limit: int = 100,
    ) -> list[AnalystFeedbackRecord]:
        sql = "SELECT * FROM analyst_feedback"
        params: list[Any] = []
        if feedback_type:
            ft = feedback_type.value if isinstance(feedback_type, FeedbackType) else feedback_type
            sql += " WHERE feedback_type = ?"
            params.append(ft)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self.db.query(sql, params)
        return [self._row_to_record(r) for r in rows]

    def _row_to_record(self, row: Any) -> AnalystFeedbackRecord:
        return AnalystFeedbackRecord(
            feedback_id=row["feedback_id"],
            finding_id=row["finding_id"],
            event_id=row["event_id"],
            analyst=row["analyst"],
            feedback_type=FeedbackType(row["feedback_type"]),
            comment=row["comment"] or "",
            created_at=row["created_at"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            features_snapshot=json.loads(row["features_snapshot"]) if row["features_snapshot"] else {},
            provenance=json.loads(row["provenance"]) if row["provenance"] else {},
            status=row["status"],
        )

    def generate_suggestions(self, feedback_id: str) -> list[FeedbackSuggestion]:
        """Derive candidate allowlist and baseline suggestions from FP / Benign feedback.

        CRITICAL REQUIREMENT: Suggestions are strictly generated in PENDING_REVIEW state.
        They are NEVER automatically applied into runtime allowlists or baselines.
        """
        fb = self.get_feedback(feedback_id)
        if not fb:
            raise ValueError(f"Feedback not found: {feedback_id}")

        if fb.feedback_type == FeedbackType.TRUE_POSITIVE:
            # TPs do not generate allowlist or baseline suggestions
            return []

        suggestions: list[FeedbackSuggestion] = []
        features = fb.features_snapshot

        # 1. Process name / executable path allowlist suggestion
        proc = features.get("process_name")
        exe = features.get("executable_path")
        if proc:
            s_id = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.ALLOWLIST,
                    target_type="process_name",
                    target_value=str(proc),
                    reason=f"Analyst {fb.analyst} labelled finding as {fb.feedback_type.value}: {fb.comment}",
                )
            )
            # Baseline suggestion for normal process
            s_id_base = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id_base,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.BASELINE,
                    target_type="process",
                    target_value=str(proc),
                    reason=f"Baseline normal process candidate from analyst feedback {fb.feedback_id}",
                )
            )
        elif exe:
            s_id = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.ALLOWLIST,
                    target_type="executable_path",
                    target_value=str(exe),
                    reason=f"Analyst {fb.analyst} labelled finding as {fb.feedback_type.value}: {fb.comment}",
                )
            )

        # 2. SHA-256 hash allowlist suggestion
        h = features.get("hash_sha256")
        if h and len(str(h)) == 64:
            s_id_hash = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id_hash,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.ALLOWLIST,
                    target_type="sha256",
                    target_value=str(h),
                    reason=f"Known benign executable digest per {fb.feedback_id}",
                )
            )

        # 3. Destination domain or IP baseline suggestion
        dom = features.get("domain")
        dst_ip = features.get("destination_ip")
        if dom:
            s_id_dom = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id_dom,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.BASELINE,
                    target_type="destination_domain",
                    target_value=str(dom),
                    reason=f"Routine network destination suggested by {fb.analyst}",
                )
            )
        elif dst_ip:
            s_id_ip = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id_ip,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.BASELINE,
                    target_type="destination_ip",
                    target_value=str(dst_ip),
                    reason=f"Routine IP destination suggested by {fb.analyst}",
                )
            )

        # 4. Signer allowlist suggestion
        signer = features.get("signer")
        if signer:
            s_id_sig = f"sug-{uuid.uuid4().hex[:12]}"
            suggestions.append(
                FeedbackSuggestion(
                    suggestion_id=s_id_sig,
                    feedback_id=fb.feedback_id,
                    kind=SuggestionKind.ALLOWLIST,
                    target_type="signer",
                    target_value=str(signer),
                    reason=f"Trusted signer suggested by analyst {fb.analyst}",
                )
            )

        # Store suggestions in SQLite with PENDING_REVIEW status
        with self.db.transaction() as conn:
            for s in suggestions:
                conn.execute(
                    """INSERT INTO feedback_suggestions (
                        suggestion_id, feedback_id, kind, target_type, target_value,
                        reason, status, created_at, applied_at, applied_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        s.suggestion_id,
                        s.feedback_id,
                        s.kind.value,
                        s.target_type,
                        s.target_value,
                        s.reason,
                        s.status.value,
                        s.created_at,
                        s.applied_at,
                        s.applied_by,
                    ),
                )

        return suggestions

    def list_suggestions(
        self,
        status: SuggestionStatus | str | None = None,
        feedback_id: str | None = None,
    ) -> list[FeedbackSuggestion]:
        sql = "SELECT * FROM feedback_suggestions WHERE 1=1"
        params: list[Any] = []
        if status:
            st = status.value if isinstance(status, SuggestionStatus) else status
            sql += " AND status = ?"
            params.append(st)
        if feedback_id:
            sql += " AND feedback_id = ?"
            params.append(feedback_id)
        sql += " ORDER BY created_at DESC"
        rows = self.db.query(sql, params)
        return [
            FeedbackSuggestion(
                suggestion_id=r["suggestion_id"],
                feedback_id=r["feedback_id"],
                kind=SuggestionKind(r["kind"]),
                target_type=r["target_type"],
                target_value=r["target_value"],
                reason=r["reason"] or "",
                status=SuggestionStatus(r["status"]),
                created_at=r["created_at"],
                applied_at=r["applied_at"],
                applied_by=r["applied_by"],
            )
            for r in rows
        ]

    def confirm_suggestion(
        self,
        suggestion_id: str,
        admin_user: str,
        confirmation_note: str = "",
    ) -> bool:
        """Admin confirmation required to apply a suggestion into allowlist or baselines.

        Guarantees that an unconfirmed suggestion is NEVER auto-applied.
        """
        row = self.db.query_one(
            "SELECT * FROM feedback_suggestions WHERE suggestion_id = ?",
            (suggestion_id,),
        )
        if not row:
            raise ValueError(f"Suggestion not found: {suggestion_id}")
        if row["status"] != SuggestionStatus.PENDING_REVIEW.value:
            raise ValueError(f"Suggestion is already {row['status']}")

        now_str = datetime.now(UTC).isoformat()
        kind = row["kind"]
        target_type = row["target_type"]
        target_value = row["target_value"]

        with self.db.transaction() as conn:
            # 1. Update suggestion status
            conn.execute(
                """UPDATE feedback_suggestions
                   SET status = ?, applied_at = ?, applied_by = ?
                   WHERE suggestion_id = ?""",
                (SuggestionStatus.CONFIRMED.value, now_str, admin_user, suggestion_id),
            )

            # 2. If allowlist, write to allowlist table
            if kind == SuggestionKind.ALLOWLIST.value:
                # Use insert or ignore to avoid primary/unique key conflicts
                conn.execute(
                    """INSERT OR IGNORE INTO allowlist (kind, value, reason, added_by, added_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        target_type,
                        target_value,
                        f"Admin-confirmed from feedback {row['feedback_id']}: {confirmation_note}",
                        admin_user,
                        now_str,
                    ),
                )

        # 3. Write tamper-evident audit record
        self.db.audit.append(
            actor=admin_user,
            event_type="FEEDBACK_SUGGESTION_CONFIRMED",
            details={
                "suggestion_id": suggestion_id,
                "kind": kind,
                "target_type": target_type,
                "target_value": target_value,
                "note": confirmation_note,
            },
        )
        return True

    def reject_suggestion(
        self,
        suggestion_id: str,
        admin_user: str,
        rejection_reason: str = "",
    ) -> bool:
        """Admin rejection of a proposed suggestion."""
        row = self.db.query_one(
            "SELECT * FROM feedback_suggestions WHERE suggestion_id = ?",
            (suggestion_id,),
        )
        if not row:
            raise ValueError(f"Suggestion not found: {suggestion_id}")

        with self.db.transaction() as conn:
            conn.execute(
                """UPDATE feedback_suggestions
                   SET status = ?, applied_at = ?, applied_by = ?
                   WHERE suggestion_id = ?""",
                (
                    SuggestionStatus.REJECTED.value,
                    datetime.now(UTC).isoformat(),
                    admin_user,
                    suggestion_id,
                ),
            )

        self.db.audit.append(
            actor=admin_user,
            event_type="FEEDBACK_SUGGESTION_REJECTED",
            details={
                "suggestion_id": suggestion_id,
                "reason": rejection_reason,
            },
        )
        return True

    def create_retraining_dataset(
        self,
        output_path: Path | str | None = None,
    ) -> RetrainingDataset:
        """Construct a labelled dataset from analyst feedback with complete provenance."""
        records = self.list_feedback(limit=10000)
        samples: list[dict[str, Any]] = []
        pos_count = 0
        neg_count = 0

        feature_keys: set[str] = set()

        for rec in records:
            # Label mapping: TP -> 1, FP / BENIGN_EXPECTED -> 0
            label = 1 if rec.feedback_type == FeedbackType.TRUE_POSITIVE else 0
            if label == 1:
                pos_count += 1
            else:
                neg_count += 1

            sample_features = rec.features_snapshot or {}
            for k in sample_features:
                feature_keys.add(k)

            sample_entry = {
                "feedback_id": rec.feedback_id,
                "finding_id": rec.finding_id,
                "event_id": rec.event_id,
                "label": label,
                "label_name": rec.feedback_type.value,
                "features": sample_features,
                "provenance": {
                    **rec.provenance,
                    "analyst": rec.analyst,
                    "created_at": rec.created_at,
                    "rule_id": rec.rule_id,
                    "severity": rec.severity,
                },
            }
            samples.append(sample_entry)

        dataset_id = f"ds-{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(UTC).isoformat()
        dataset_content = {
            "dataset_id": dataset_id,
            "created_at": now_str,
            "sample_count": len(samples),
            "positive_count": pos_count,
            "negative_count": neg_count,
            "feature_names": sorted(feature_keys),
            "samples": samples,
        }

        blob = json.dumps(dataset_content, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()

        out_path_str: str | None = None
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(blob)
            out_path_str = str(p)

        return RetrainingDataset(
            dataset_id=dataset_id,
            sample_count=len(samples),
            positive_count=pos_count,
            negative_count=neg_count,
            feature_names=sorted(feature_keys),
            samples=samples,
            sha256_digest=digest,
            output_path=out_path_str,
            created_at=now_str,
        )


__all__ = [
    "AnalystFeedbackRecord",
    "AnalystFeedbackStore",
    "FeedbackSuggestion",
    "FeedbackType",
    "RetrainingDataset",
    "SuggestionKind",
    "SuggestionStatus",
]
