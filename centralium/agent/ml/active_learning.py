"""Active learning queue for SOC analysts.

Ranks incoming events by model uncertainty:
1. Entropy near 0.5 (high decision boundary ambiguity).
2. High anomaly score with low classifier confidence (epistemic conflict between unsupervised
   and supervised models).
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from centralium.agent.models import MLResult, NormalizedEvent

log = logging.getLogger("centralium.ml.active_learning")

DEFAULT_MIN_UNCERTAINTY = 0.30
DEFAULT_QUEUE_CAPACITY = 500


class UncertaintyFactor(StrEnum):
    HIGH_ENTROPY = "HIGH_ENTROPY"
    ANOMALY_CLASSIFIER_CONFLICT = "ANOMALY_CLASSIFIER_CONFLICT"
    BOUNDARY_PROXIMITY = "BOUNDARY_PROXIMITY"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"


class QueueItemStatus(StrEnum):
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    LABELED = "LABELED"
    DISMISSED = "DISMISSED"


def calculate_entropy(prob: float) -> float:
    """Calculate binary Shannon entropy normalized into [0, 1].

    Maximum entropy = 1.0 at prob = 0.5; minimum entropy = 0.0 at prob = 0.0 or 1.0.
    """
    p = max(1e-9, min(1.0 - 1e-9, float(prob)))
    h = -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))
    return float(max(0.0, min(1.0, h)))


def compute_uncertainty_score(
    anomaly_score: float | None,
    classification_confidence: float | None,
    classification: str | None = None,
) -> tuple[float, UncertaintyFactor]:
    """Calculate model uncertainty combining Shannon entropy and model conflict.

    Returns:
        (uncertainty_score in [0, 1], primary_uncertainty_factor)
    """
    ano = float(anomaly_score) if anomaly_score is not None else 0.0
    conf = float(classification_confidence) if classification_confidence is not None else 0.5

    # 1. Entropy component (peaks when confidence is near 0.5)
    entropy = calculate_entropy(conf)

    # 2. Epistemic conflict: high anomaly score while classifier confidence is low or benign
    is_benign = str(classification or "").lower() in {"benign", "normal", "clean"}
    conflict = ano * conf if is_benign and ano > 0.5 else ano * (1.0 - conf)

    # Composite weighted score
    uncertainty = 0.55 * entropy + 0.45 * conflict
    uncertainty = float(max(0.0, min(1.0, uncertainty)))

    # Determine primary factor
    if conflict > 0.45 and ano > 0.5:
        factor = UncertaintyFactor.ANOMALY_CLASSIFIER_CONFLICT
    elif entropy > 0.8:
        factor = UncertaintyFactor.HIGH_ENTROPY
    elif abs(conf - 0.5) < 0.15:
        factor = UncertaintyFactor.BOUNDARY_PROXIMITY
    else:
        factor = UncertaintyFactor.LOW_CONFIDENCE

    return round(uncertainty, 4), factor


@dataclass
class ActiveLearningItem:
    item_id: str
    event_id: str
    timestamp: str
    process_name: str | None
    anomaly_score: float
    classification: str
    confidence: float
    uncertainty_score: float
    primary_factor: UncertaintyFactor
    features: dict[str, Any] = field(default_factory=dict)
    status: QueueItemStatus = QueueItemStatus.QUEUED
    assigned_analyst: str | None = None
    analyst_label: str | None = None
    enqueued_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "process_name": self.process_name,
            "anomaly_score": round(self.anomaly_score, 4),
            "classification": self.classification,
            "confidence": round(self.confidence, 4),
            "uncertainty_score": round(self.uncertainty_score, 4),
            "primary_factor": self.primary_factor.value
            if isinstance(self.primary_factor, UncertaintyFactor)
            else str(self.primary_factor),
            "features": self.features,
            "status": self.status.value if isinstance(self.status, QueueItemStatus) else str(self.status),
            "assigned_analyst": self.assigned_analyst,
            "analyst_label": self.analyst_label,
            "enqueued_at": self.enqueued_at,
        }


class ActiveLearningQueue:
    """Bounded, priority-ranked queue for analyst labelling of uncertain events."""

    def __init__(
        self,
        capacity: int = DEFAULT_QUEUE_CAPACITY,
        min_uncertainty: float = DEFAULT_MIN_UNCERTAINTY,
    ) -> None:
        self.capacity = capacity
        self.min_uncertainty = min_uncertainty
        self._items: dict[str, ActiveLearningItem] = {}  # item_id -> item
        self._event_ids: dict[str, str] = {}  # event_id -> item_id for dedup

    def __len__(self) -> int:
        return len(self._items)

    def enqueue_event(
        self,
        event: NormalizedEvent,
        ml_result: MLResult,
        features: dict[str, Any] | None = None,
    ) -> ActiveLearningItem | None:
        """Evaluate event uncertainty and enqueue if above threshold."""
        if event.event_id in self._event_ids:
            return None  # already enqueued

        ano_score = ml_result.anomaly_score
        conf = ml_result.classification_confidence
        clf = ml_result.classification

        uncertainty, factor = compute_uncertainty_score(
            anomaly_score=ano_score,
            classification_confidence=conf,
            classification=clf,
        )

        if uncertainty < self.min_uncertainty:
            return None

        # Build item
        item_id = f"al-{uuid.uuid4().hex[:12]}"
        item = ActiveLearningItem(
            item_id=item_id,
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
            process_name=event.process_name,
            anomaly_score=ano_score or 0.0,
            classification=clf or "unknown",
            confidence=conf or 0.5,
            uncertainty_score=uncertainty,
            primary_factor=factor,
            features=features or {},
            status=QueueItemStatus.QUEUED,
        )

        # Enforce capacity
        if len(self._items) >= self.capacity:
            # Evict item with lowest uncertainty score among QUEUED items
            queued_items = [it for it in self._items.values() if it.status == QueueItemStatus.QUEUED]
            if queued_items:
                min_item = min(queued_items, key=lambda x: x.uncertainty_score)
                if min_item.uncertainty_score < item.uncertainty_score:
                    del self._items[min_item.item_id]
                    self._event_ids.pop(min_item.event_id, None)
                else:
                    return None  # new item has lower priority than all queued items
            else:
                return None

        self._items[item_id] = item
        self._event_ids[event.event_id] = item_id
        return item

    def get_ranked_queue(
        self,
        limit: int = 50,
        status: QueueItemStatus | str | None = None,
    ) -> list[ActiveLearningItem]:
        """Return candidates ordered by uncertainty score descending."""
        items = list(self._items.values())
        if status:
            target_status = status.value if isinstance(status, QueueItemStatus) else str(status)
            items = [it for it in items if str(it.status) == target_status]
        # Rank by uncertainty score descending
        items.sort(key=lambda it: it.uncertainty_score, reverse=True)
        return items[:limit]

    def get_item(self, item_id: str) -> ActiveLearningItem | None:
        return self._items.get(item_id)

    def assign_to_analyst(self, item_id: str, analyst: str) -> bool:
        item = self._items.get(item_id)
        if not item:
            return False
        item.status = QueueItemStatus.ASSIGNED
        item.assigned_analyst = analyst
        return True

    def submit_label(self, item_id: str, label: str, analyst: str) -> bool:
        item = self._items.get(item_id)
        if not item:
            return False
        item.status = QueueItemStatus.LABELED
        item.analyst_label = label
        item.assigned_analyst = analyst
        return True

    def dismiss(self, item_id: str) -> bool:
        item = self._items.get(item_id)
        if not item:
            return False
        item.status = QueueItemStatus.DISMISSED
        return True

    def clear(self) -> None:
        self._items.clear()
        self._event_ids.clear()


__all__ = [
    "ActiveLearningItem",
    "ActiveLearningQueue",
    "QueueItemStatus",
    "UncertaintyFactor",
    "calculate_entropy",
    "compute_uncertainty_score",
]
