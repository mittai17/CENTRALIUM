"""Unit tests for Phase 2E: Model registry, Ed25519 signatures, shadow-mode evaluation,
and audited promotion / rollback.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from centralium.agent.interfaces import BehaviorResult
from centralium.agent.ml.registry import (
    ModelRegistry,
    ShadowEvaluator,
    sign_digest,
    verify_digest_signature,
)
from centralium.agent.models import EventType, MLResult, NormalizedEvent
from centralium.agent.storage import Database


@pytest.fixture
def registry_env(tmp_path: Path):
    db = Database(tmp_path / "registry.db")
    storage = tmp_path / "models"
    reg = ModelRegistry(db, storage_dir=storage)
    return db, reg, storage


def test_model_registration_and_integrity(registry_env):
    _db, reg, _storage = registry_env

    # 1. Generate Ed25519 keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    artifact_payload = b"test_model_artifact_weights_and_ecdf_v1"

    meta = reg.register_model(
        model_name="behavioral_rf",
        version="v1.0.0",
        artifact_bytes=artifact_payload,
        metrics={"f1": 0.94, "precision": 0.96},
        signing_key=private_key,
        metadata={"framework": "scikit-learn", "features_version": "v1"},
        is_active=True,
    )

    assert meta.model_name == "behavioral_rf"
    assert meta.version == "v1.0.0"
    assert meta.is_active is True
    assert meta.signature_ed25519 is not None
    assert meta.public_key_ed25519 is not None

    # Integrity verification must pass
    assert reg.verify_model_integrity("behavioral_rf", "v1.0.0") is True

    # 2. Tampering detection: modify artifact on disk
    artifact_path = Path(meta.artifact_path)
    artifact_path.write_bytes(b"tampered_payload_injected")

    # Integrity check must fail immediately
    assert reg.verify_model_integrity("behavioral_rf", "v1.0.0") is False


def test_ed25519_signature_utilities():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    sig = sign_digest(digest, priv)
    assert isinstance(sig, str)
    assert verify_digest_signature(digest, sig, pub) is True

    # Bad digest must fail
    assert verify_digest_signature("different_digest", sig, pub) is False

    # Corrupt signature string
    assert verify_digest_signature(digest, "bad_sig_base64", pub) is False


def test_audited_promotion_and_rollback(registry_env):
    db, reg, _storage = registry_env

    # Register v1 as active
    reg.register_model(
        model_name="anomaly_iforest",
        version="v1.0.0",
        artifact_bytes=b"model_weights_v1",
        metrics={"auc_roc": 0.91},
        is_active=True,
    )

    # Register candidate v2 as inactive
    reg.register_model(
        model_name="anomaly_iforest",
        version="v2.0.0",
        artifact_bytes=b"model_weights_v2",
        metrics={"auc_roc": 0.96},
        is_active=False,
    )

    assert reg.get_active_model("anomaly_iforest").version == "v1.0.0"

    # Promote v2.0.0 with admin audit
    promoted = reg.promote_model(
        model_name="anomaly_iforest",
        target_version="v2.0.0",
        admin_user="secops_admin",
        reason="Improved AUC-ROC on retrained feedback dataset",
    )
    assert promoted.version == "v2.0.0"
    assert reg.get_active_model("anomaly_iforest").version == "v2.0.0"

    # Verify audit log recorded promotion
    audit_prom = db.query_one(
        "SELECT * FROM audit_log WHERE event_type = 'MODEL_PROMOTION' ORDER BY seq DESC LIMIT 1"
    )
    assert audit_prom is not None
    assert audit_prom["actor"] == "secops_admin"
    p_details = json.loads(audit_prom["details"])
    assert p_details["from_version"] == "v1.0.0"
    assert p_details["to_version"] == "v2.0.0"

    # Roll back to v1.0.0 with admin audit
    rolled = reg.rollback_model(
        model_name="anomaly_iforest",
        target_version="v1.0.0",
        admin_user="secops_lead",
        reason="Observed anomaly threshold divergence in production",
    )
    assert rolled.version == "v1.0.0"
    assert reg.get_active_model("anomaly_iforest").version == "v1.0.0"

    audit_roll = db.query_one(
        "SELECT * FROM audit_log WHERE event_type = 'MODEL_ROLLBACK' ORDER BY seq DESC LIMIT 1"
    )
    assert audit_roll is not None
    assert audit_roll["actor"] == "secops_lead"
    r_details = json.loads(audit_roll["details"])
    assert r_details["from_version"] == "v2.0.0"
    assert r_details["to_version"] == "v1.0.0"


def test_shadow_mode_evaluation():
    # Active model scorer
    def active_model(event: NormalizedEvent, behavior: BehaviorResult) -> MLResult:
        return MLResult(
            anomaly_score=0.25,
            classification="benign",
            classification_confidence=0.92,
            top_features=[("cmd_length", 0.3)],
            model_version="v1.0.0",
        )

    # Candidate model scorer (shadow)
    def candidate_model(event: NormalizedEvent, behavior: BehaviorResult) -> MLResult:
        # Candidate agrees on benign but scores anomaly slightly higher
        return MLResult(
            anomaly_score=0.30,
            classification="benign",
            classification_confidence=0.95,
            top_features=[("cmd_length", 0.4)],
            model_version="v2.0.0",
        )

    evaluator = ShadowEvaluator(active_scorer=active_model, candidate_scorer=candidate_model)

    event = NormalizedEvent(
        event_id="ev-shadow-1",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="notepad.exe",
    )
    behavior = BehaviorResult()

    returned_result, comparison = evaluator.evaluate(event, behavior)

    # CRITICAL: pipeline only receives active result
    assert returned_result.model_version == "v1.0.0"
    assert returned_result.anomaly_score == 0.25

    # Side-by-side comparison tracks both
    assert comparison.active_anomaly_score == 0.25
    assert comparison.candidate_anomaly_score == 0.30
    assert comparison.concordance is True
    assert comparison.score_delta == pytest.approx(0.05, abs=1e-3)

    # Feed more events, some with disagreement
    def dissenting_candidate(event: NormalizedEvent, behavior: BehaviorResult) -> MLResult:
        return MLResult(
            anomaly_score=0.88,
            classification="malware",
            classification_confidence=0.82,
            top_features=[("entropy", 0.9)],
            model_version="v2.0.0",
        )

    evaluator.candidate_scorer = dissenting_candidate
    for i in range(2, 6):
        ev = NormalizedEvent(
            event_id=f"ev-shadow-{i}",
            timestamp=datetime.now(UTC),
            event_type=EventType.PROCESS_START,
            process_name="calc.exe",
        )
        evaluator.evaluate(ev, behavior)

    report = evaluator.generate_report()
    assert report.total_events == 5
    assert report.concordance_rate == 0.2  # 1 agreement out of 5
    assert report.disagreement_count == 4
    assert report.recommendation == "HIGH_DISAGREEMENT_NEEDS_REVIEW"
    assert len(report.sample_disagreements) > 0
