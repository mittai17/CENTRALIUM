"""Versioned ML model registry with SHA-256 verification, Ed25519 signing,
shadow-mode evaluation, and audited promotion / rollback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from centralium.agent.interfaces import BehaviorResult
from centralium.agent.models import MLResult, NormalizedEvent
from centralium.agent.storage import Database

log = logging.getLogger("centralium.ml.registry")


@dataclass
class ModelMetadata:
    model_name: str
    version: str
    artifact_path: str
    sha256: str
    created_at: str
    metrics: dict[str, float] = field(default_factory=dict)
    signature_ed25519: str | None = None
    public_key_ed25519: str | None = None
    is_active: bool = False
    is_shadow: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "artifact_path": self.artifact_path,
            "sha256": self.sha256,
            "created_at": self.created_at,
            "metrics": self.metrics,
            "signature_ed25519": self.signature_ed25519,
            "public_key_ed25519": self.public_key_ed25519,
            "is_active": self.is_active,
            "is_shadow": self.is_shadow,
            "metadata": self.metadata,
        }


def sign_digest(digest: bytes | str, private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign an artifact SHA-256 digest with an Ed25519 private key, returning base64 signature."""
    raw = digest.encode("utf-8") if isinstance(digest, str) else digest
    sig = private_key.sign(raw)
    return base64.b64encode(sig).decode("ascii")


def verify_digest_signature(
    digest: bytes | str,
    signature_b64: str,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify Ed25519 signature against an artifact digest."""
    raw = digest.encode("utf-8") if isinstance(digest, str) else digest
    try:
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, raw)
        return True
    except (InvalidSignature, ValueError, Exception) as exc:
        log.warning("Ed25519 signature verification failed: %s", exc)
        return False


class ModelRegistry:
    """Thread-safe SQLite-backed model registry for versioning, signing, promotion and rollback."""

    def __init__(self, db: Database, storage_dir: Path | str | None = None) -> None:
        self.db = db
        self.storage_dir = (
            Path(storage_dir) if storage_dir else Path(tempfile.gettempdir()) / "centralium_models"
        )
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_table()

    def _ensure_table(self) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ml_model_registry (
                    model_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metrics TEXT,
                    signature TEXT,
                    public_key TEXT,
                    is_active INTEGER NOT NULL DEFAULT 0,
                    is_shadow INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT,
                    PRIMARY KEY (model_name, version)
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ml_reg_active ON ml_model_registry(model_name, is_active)"
            )

    def register_model(
        self,
        model_name: str,
        version: str,
        artifact_bytes: bytes,
        metrics: dict[str, float] | None = None,
        signing_key: ed25519.Ed25519PrivateKey | None = None,
        public_key_b64: str | None = None,
        metadata: dict[str, Any] | None = None,
        is_active: bool = False,
        is_shadow: bool = False,
    ) -> ModelMetadata:
        """Store versioned model artifact with SHA-256 and optional Ed25519 cryptographic signature."""
        digest = hashlib.sha256(artifact_bytes).hexdigest()

        # Save artifact file
        artifact_filename = f"{model_name}_{version}_{digest[:10]}.bin"
        artifact_path = self.storage_dir / artifact_filename
        artifact_path.write_bytes(artifact_bytes)

        sig_b64: str | None = None
        pub_b64 = public_key_b64

        if signing_key is not None:
            sig_b64 = sign_digest(digest, signing_key)
            if pub_b64 is None:
                pub_bytes = signing_key.public_key().public_bytes_raw()
                pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

        now_str = datetime.now(UTC).isoformat()
        meta = ModelMetadata(
            model_name=model_name,
            version=version,
            artifact_path=str(artifact_path),
            sha256=digest,
            created_at=now_str,
            metrics=metrics or {},
            signature_ed25519=sig_b64,
            public_key_ed25519=pub_b64,
            is_active=is_active,
            is_shadow=is_shadow,
            metadata=metadata or {},
        )

        with self.db.transaction() as conn:
            if is_active:
                conn.execute(
                    "UPDATE ml_model_registry SET is_active = 0 WHERE model_name = ?",
                    (model_name,),
                )
            conn.execute(
                """INSERT OR REPLACE INTO ml_model_registry (
                    model_name, version, artifact_path, sha256, created_at,
                    metrics, signature, public_key, is_active, is_shadow, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    meta.model_name,
                    meta.version,
                    meta.artifact_path,
                    meta.sha256,
                    meta.created_at,
                    json.dumps(meta.metrics),
                    meta.signature_ed25519,
                    meta.public_key_ed25519,
                    1 if meta.is_active else 0,
                    1 if meta.is_shadow else 0,
                    json.dumps(meta.metadata),
                ),
            )

        self.db.audit.append(
            actor="system",
            event_type="MODEL_REGISTERED",
            details={
                "model_name": model_name,
                "version": version,
                "sha256": digest,
                "signed": sig_b64 is not None,
            },
        )
        return meta

    def get_model(self, model_name: str, version: str) -> ModelMetadata | None:
        row = self.db.query_one(
            "SELECT * FROM ml_model_registry WHERE model_name = ? AND version = ?",
            (model_name, version),
        )
        if not row:
            return None
        return self._row_to_metadata(row)

    def get_active_model(self, model_name: str) -> ModelMetadata | None:
        row = self.db.query_one(
            "SELECT * FROM ml_model_registry WHERE model_name = ? AND is_active = 1",
            (model_name,),
        )
        if not row:
            return None
        return self._row_to_metadata(row)

    def list_models(self, model_name: str | None = None) -> list[ModelMetadata]:
        sql = "SELECT * FROM ml_model_registry"
        params: list[Any] = []
        if model_name:
            sql += " WHERE model_name = ?"
            params.append(model_name)
        sql += " ORDER BY created_at DESC"
        return [self._row_to_metadata(r) for r in self.db.query(sql, params)]

    def verify_model_integrity(self, model_name: str, version: str) -> bool:
        """Verify artifact SHA-256 digest on disk and Ed25519 signature if present."""
        meta = self.get_model(model_name, version)
        if not meta:
            return False
        p = Path(meta.artifact_path)
        if not p.exists():
            log.error("Artifact missing on disk: %s", meta.artifact_path)
            return False

        data = p.read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != meta.sha256:
            log.error("SHA256 mismatch for %s %s: %s != %s", model_name, version, actual_sha, meta.sha256)
            return False

        if meta.signature_ed25519 and meta.public_key_ed25519:
            try:
                pub_bytes = base64.b64decode(meta.public_key_ed25519)
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                if not verify_digest_signature(actual_sha, meta.signature_ed25519, pub_key):
                    return False
            except Exception as exc:
                log.error("Failed to verify Ed25519 signature: %s", exc)
                return False

        return True

    def promote_model(
        self,
        model_name: str,
        target_version: str,
        admin_user: str,
        reason: str,
    ) -> ModelMetadata:
        """Promote a candidate model to active status through an audited admin action."""
        if not self.verify_model_integrity(model_name, target_version):
            raise ValueError(f"Integrity check failed for {model_name}:{target_version}")

        current_active = self.get_active_model(model_name)
        from_version = current_active.version if current_active else "none"

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE ml_model_registry SET is_active = 0, is_shadow = 0 WHERE model_name = ?",
                (model_name,),
            )
            conn.execute(
                """UPDATE ml_model_registry
                   SET is_active = 1, is_shadow = 0
                   WHERE model_name = ? AND version = ?""",
                (model_name, target_version),
            )

        self.db.audit.append(
            actor=admin_user,
            event_type="MODEL_PROMOTION",
            details={
                "model_name": model_name,
                "from_version": from_version,
                "to_version": target_version,
                "reason": reason,
            },
        )
        promoted = self.get_model(model_name, target_version)
        assert promoted is not None
        return promoted

    def rollback_model(
        self,
        model_name: str,
        target_version: str,
        admin_user: str,
        reason: str,
    ) -> ModelMetadata:
        """Rollback active model to a prior verified version through an audited admin action."""
        if not self.verify_model_integrity(model_name, target_version):
            raise ValueError(f"Integrity check failed for rollback target {model_name}:{target_version}")

        current_active = self.get_active_model(model_name)
        from_version = current_active.version if current_active else "none"

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE ml_model_registry SET is_active = 0 WHERE model_name = ?",
                (model_name,),
            )
            conn.execute(
                """UPDATE ml_model_registry
                   SET is_active = 1, is_shadow = 0
                   WHERE model_name = ? AND version = ?""",
                (model_name, target_version),
            )

        self.db.audit.append(
            actor=admin_user,
            event_type="MODEL_ROLLBACK",
            details={
                "model_name": model_name,
                "from_version": from_version,
                "to_version": target_version,
                "reason": reason,
            },
        )
        rolled = self.get_model(model_name, target_version)
        assert rolled is not None
        return rolled

    def _row_to_metadata(self, row: Any) -> ModelMetadata:
        return ModelMetadata(
            model_name=row["model_name"],
            version=row["version"],
            artifact_path=row["artifact_path"],
            sha256=row["sha256"],
            created_at=row["created_at"],
            metrics=json.loads(row["metrics"]) if row["metrics"] else {},
            signature_ed25519=row["signature"],
            public_key_ed25519=row["public_key"],
            is_active=bool(row["is_active"]),
            is_shadow=bool(row["is_shadow"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )


# =========================================================================
# Shadow-mode evaluation
# =========================================================================


@dataclass
class ShadowEventComparison:
    event_id: str
    active_anomaly_score: float | None
    candidate_anomaly_score: float | None
    active_classification: str | None
    candidate_classification: str | None
    active_confidence: float | None
    candidate_confidence: float | None
    active_latency_ms: float
    candidate_latency_ms: float
    concordance: bool
    score_delta: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "active_anomaly_score": self.active_anomaly_score,
            "candidate_anomaly_score": self.candidate_anomaly_score,
            "active_classification": self.active_classification,
            "candidate_classification": self.candidate_classification,
            "active_confidence": self.active_confidence,
            "candidate_confidence": self.candidate_confidence,
            "active_latency_ms": self.active_latency_ms,
            "candidate_latency_ms": self.candidate_latency_ms,
            "concordance": self.concordance,
            "score_delta": self.score_delta,
        }


@dataclass
class ShadowComparisonReport:
    total_events: int
    concordance_rate: float
    mean_score_deviation: float
    max_score_deviation: float
    active_avg_latency_ms: float
    candidate_avg_latency_ms: float
    disagreement_count: int
    recommendation: str
    sample_disagreements: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "concordance_rate": self.concordance_rate,
            "mean_score_deviation": self.mean_score_deviation,
            "max_score_deviation": self.max_score_deviation,
            "active_avg_latency_ms": self.active_avg_latency_ms,
            "candidate_avg_latency_ms": self.candidate_avg_latency_ms,
            "disagreement_count": self.disagreement_count,
            "recommendation": self.recommendation,
            "sample_disagreements": self.sample_disagreements,
        }


class ShadowEvaluator:
    """Evaluates candidate model in shadow-mode alongside active production model.

    CRITICAL SAFETY GUARANTEE:
    Candidate model scores incoming events in parallel WITHOUT acting. It never
    triggers response actions, alters novelty, or modifies system policy.
    Only the active model's decision is returned to the pipeline.
    """

    def __init__(
        self,
        active_scorer: Callable[[NormalizedEvent, BehaviorResult], MLResult | None],
        candidate_scorer: Callable[[NormalizedEvent, BehaviorResult], MLResult | None],
    ) -> None:
        self.active_scorer = active_scorer
        self.candidate_scorer = candidate_scorer
        self.history: list[ShadowEventComparison] = []

    def evaluate(
        self,
        event: NormalizedEvent,
        behavior: BehaviorResult,
    ) -> tuple[MLResult | None, ShadowEventComparison]:
        """Score event with active model (acted upon) and candidate model (shadow-only)."""
        # 1. Score with active model (real)
        t0 = time.perf_counter()
        active_res = self.active_scorer(event, behavior)
        active_lat = (time.perf_counter() - t0) * 1000.0

        # 2. Score with candidate model (shadow - strictly side-effect free)
        t1 = time.perf_counter()
        candidate_res = self.candidate_scorer(event, behavior)
        candidate_lat = (time.perf_counter() - t1) * 1000.0

        act_ano = active_res.anomaly_score if active_res else None
        cand_ano = candidate_res.anomaly_score if candidate_res else None
        act_clf = active_res.classification if active_res else None
        cand_clf = candidate_res.classification if candidate_res else None
        act_conf = active_res.classification_confidence if active_res else None
        cand_conf = candidate_res.classification_confidence if candidate_res else None

        concordance = act_clf == cand_clf
        score_delta = abs((cand_ano or 0.0) - (act_ano or 0.0))

        comp = ShadowEventComparison(
            event_id=event.event_id,
            active_anomaly_score=act_ano,
            candidate_anomaly_score=cand_ano,
            active_classification=act_clf,
            candidate_classification=cand_clf,
            active_confidence=act_conf,
            candidate_confidence=cand_conf,
            active_latency_ms=round(active_lat, 2),
            candidate_latency_ms=round(candidate_lat, 2),
            concordance=concordance,
            score_delta=round(score_delta, 4),
        )
        self.history.append(comp)

        # Return ONLY active result to pipeline for decisions
        return active_res, comp

    def generate_report(self) -> ShadowComparisonReport:
        """Produce an automatic side-by-side evaluation comparison report."""
        n = len(self.history)
        if n == 0:
            return ShadowComparisonReport(
                total_events=0,
                concordance_rate=1.0,
                mean_score_deviation=0.0,
                max_score_deviation=0.0,
                active_avg_latency_ms=0.0,
                candidate_avg_latency_ms=0.0,
                disagreement_count=0,
                recommendation="NO_DATA",
                sample_disagreements=[],
            )

        concordant = sum(1 for h in self.history if h.concordance)
        concordance_rate = concordant / n
        score_deltas = [h.score_delta for h in self.history]
        mean_delta = sum(score_deltas) / n
        max_delta = max(score_deltas)

        active_lat = sum(h.active_latency_ms for h in self.history) / n
        cand_lat = sum(h.candidate_latency_ms for h in self.history) / n

        disagreements = [h for h in self.history if not h.concordance]

        # Recommendation policy
        if concordance_rate >= 0.90 and mean_delta < 0.20:
            rec = "READY_FOR_PROMOTION"
        elif concordance_rate < 0.75:
            rec = "HIGH_DISAGREEMENT_NEEDS_REVIEW"
        else:
            rec = "BORDERLINE_NEEDS_FURTHER_EVALUATION"

        return ShadowComparisonReport(
            total_events=n,
            concordance_rate=round(concordance_rate, 4),
            mean_score_deviation=round(mean_delta, 4),
            max_score_deviation=round(max_delta, 4),
            active_avg_latency_ms=round(active_lat, 2),
            candidate_avg_latency_ms=round(cand_lat, 2),
            disagreement_count=len(disagreements),
            recommendation=rec,
            sample_disagreements=[d.to_dict() for d in disagreements[:10]],
        )


__all__ = [
    "ModelMetadata",
    "ModelRegistry",
    "ShadowComparisonReport",
    "ShadowEvaluator",
    "ShadowEventComparison",
    "sign_digest",
    "verify_digest_signature",
]
