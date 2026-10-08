"""Unit tests for Phase 2E: Active learning queue and model uncertainty ranking."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from centralium.agent.ml.active_learning import (
    ActiveLearningQueue,
    QueueItemStatus,
    UncertaintyFactor,
    calculate_entropy,
    compute_uncertainty_score,
)
from centralium.agent.models import EventType, MLResult, NormalizedEvent


def test_entropy_calculation():
    # Maximum entropy at 0.5
    h_mid = calculate_entropy(0.5)
    assert h_mid == pytest.approx(1.0, abs=1e-3)

    # Minimum entropy at extremes 0.0 and 1.0
    h_low = calculate_entropy(0.01)
    h_high = calculate_entropy(0.99)
    assert h_low < 0.15
    assert h_high < 0.15


def test_uncertainty_scoring_categories():
    # 1. Ambiguous decision boundary (confidence near 0.5)
    score1, factor1 = compute_uncertainty_score(
        anomaly_score=0.3,
        classification_confidence=0.52,
        classification="malware",
    )
    assert score1 > 0.50
    assert factor1 in (UncertaintyFactor.HIGH_ENTROPY, UncertaintyFactor.BOUNDARY_PROXIMITY)

    # 2. Strong epistemic conflict: high anomaly score (0.85) with confident benign classifier (0.90)
    score2, factor2 = compute_uncertainty_score(
        anomaly_score=0.85,
        classification_confidence=0.90,
        classification="benign",
    )
    assert score2 > 0.35
    assert factor2 == UncertaintyFactor.ANOMALY_CLASSIFIER_CONFLICT

    # 3. High certainty: low anomaly and very confident benign
    score3, _ = compute_uncertainty_score(
        anomaly_score=0.05,
        classification_confidence=0.98,
        classification="benign",
    )
    assert score3 < 0.15


def test_active_learning_queue_ranking_and_lifecycle():
    queue = ActiveLearningQueue(capacity=10, min_uncertainty=0.25)

    ev_ambiguous = NormalizedEvent(
        event_id="ev-ambig",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="rundll32.exe",
    )
    ml_ambiguous = MLResult(
        anomaly_score=0.45,
        classification="suspicious",
        classification_confidence=0.51,  # near 0.5 -> max entropy
    )

    ev_conflict = NormalizedEvent(
        event_id="ev-conflict",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="svchost.exe",
    )
    ml_conflict = MLResult(
        anomaly_score=0.92,
        classification="benign",
        classification_confidence=0.85,
    )

    ev_certain = NormalizedEvent(
        event_id="ev-certain",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="explorer.exe",
    )
    ml_certain = MLResult(
        anomaly_score=0.02,
        classification="benign",
        classification_confidence=0.99,
    )

    # 1. Enqueue events
    item1 = queue.enqueue_event(ev_ambiguous, ml_ambiguous)
    item2 = queue.enqueue_event(ev_conflict, ml_conflict)
    item3 = queue.enqueue_event(ev_certain, ml_certain)

    # Certain event must be filtered out
    assert item1 is not None
    assert item2 is not None
    assert item3 is None
    assert len(queue) == 2

    # 2. Ranking: high uncertainty first
    ranked = queue.get_ranked_queue(limit=5)
    assert len(ranked) == 2
    assert ranked[0].uncertainty_score >= ranked[1].uncertainty_score

    # 3. Analyst assignment & labelling lifecycle
    top_item = ranked[0]
    assert top_item.status == QueueItemStatus.QUEUED

    assigned_ok = queue.assign_to_analyst(top_item.item_id, analyst="analyst_alice")
    assert assigned_ok is True
    assert top_item.status == QueueItemStatus.ASSIGNED
    assert top_item.assigned_analyst == "analyst_alice"

    label_ok = queue.submit_label(top_item.item_id, label="TRUE_POSITIVE", analyst="analyst_alice")
    assert label_ok is True
    assert top_item.status == QueueItemStatus.LABELED
    assert top_item.analyst_label == "TRUE_POSITIVE"

    # 4. Dismissal
    dismiss_ok = queue.dismiss(ranked[1].item_id)
    assert dismiss_ok is True
    assert ranked[1].status == QueueItemStatus.DISMISSED


def test_queue_capacity_and_eviction():
    queue = ActiveLearningQueue(capacity=3, min_uncertainty=0.10)

    # Add 3 items with increasing uncertainty
    for i, conf in enumerate([0.70, 0.60, 0.55]):
        ev = NormalizedEvent(
            event_id=f"ev-{i}",
            timestamp=datetime.now(UTC),
            event_type=EventType.PROCESS_START,
            process_name="cmd.exe",
        )
        ml = MLResult(
            anomaly_score=0.4,
            classification="unknown",
            classification_confidence=conf,
        )
        queue.enqueue_event(ev, ml)

    assert len(queue) == 3

    # Add 4th item with maximum uncertainty (conf = 0.50)
    ev_top = NormalizedEvent(
        event_id="ev-top",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="powershell.exe",
    )
    ml_top = MLResult(
        anomaly_score=0.9,
        classification="unknown",
        classification_confidence=0.50,
    )
    new_item = queue.enqueue_event(ev_top, ml_top)

    assert new_item is not None
    # Capacity must not exceed 3
    assert len(queue) == 3
    # ev-0 (lowest uncertainty) was evicted
    assert queue.get_item("ev-0") is None
    ranked = queue.get_ranked_queue()
    assert ranked[0].event_id == "ev-top"
