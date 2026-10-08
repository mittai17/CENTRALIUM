"""Feature distribution drift monitoring via Population Stability Index (PSI)
and Kolmogorov-Smirnov (KS) statistics.

* Compares incoming behavioral feature distributions against baseline reference distributions.
* Emits drift metrics and alerts when PSI or KS statistics exceed operational thresholds.
* Strictly enforces: "Never claim accuracy without labels" - explicitly disclaims accuracy
  claims in drift reports when ground-truth labels are absent.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import numpy as np
from scipy import stats  # type: ignore[import-untyped]

log = logging.getLogger("centralium.ml.drift")

# Operational thresholds
PSI_WARNING_THRESHOLD = 0.10
PSI_ALERT_THRESHOLD = 0.25
KS_ALERT_THRESHOLD = 0.20
MIN_OBSERVATIONS_FOR_DRIFT = 20


def calculate_psi(
    reference: Sequence[float] | np.ndarray,
    incoming: Sequence[float] | np.ndarray,
    num_bins: int = 10,
    epsilon: float = 1e-4,
) -> float:
    """Calculate Population Stability Index (PSI) between reference and incoming distributions."""
    ref_arr = np.asarray(reference, dtype=np.float64)
    inc_arr = np.asarray(incoming, dtype=np.float64)

    if len(ref_arr) == 0 or len(inc_arr) == 0:
        return 0.0

    # If all reference values are constant
    if np.all(ref_arr == ref_arr[0]):
        if np.all(inc_arr == ref_arr[0]):
            return 0.0
        return 1.0

    # Adapt number of bins to sample size to avoid small-sample quantization noise
    effective_bins = min(num_bins, max(2, min(len(ref_arr), len(inc_arr)) // 20))

    # Create bin edges using quantiles from reference distribution
    percentiles = np.linspace(0, 100, effective_bins + 1)
    bin_edges = np.percentile(ref_arr, percentiles)
    bin_edges = np.unique(bin_edges)  # remove duplicate edges for discrete values

    if len(bin_edges) < 2:
        return 0.0

    # Ensure boundaries cover incoming range
    bin_edges[0] = min(bin_edges[0], np.min(inc_arr)) - 1e-5
    bin_edges[-1] = max(bin_edges[-1], np.max(inc_arr)) + 1e-5

    ref_counts, _ = np.histogram(ref_arr, bins=bin_edges)
    inc_counts, _ = np.histogram(inc_arr, bins=bin_edges)

    ref_pct = ref_counts / len(ref_arr)
    inc_pct = inc_counts / len(inc_arr)

    # Avoid zero division and log(0) with small smoothing epsilon
    ref_pct = np.clip(ref_pct, epsilon, 1.0)
    inc_pct = np.clip(inc_pct, epsilon, 1.0)

    # Re-normalize after clip
    ref_pct /= np.sum(ref_pct)
    inc_pct /= np.sum(inc_pct)

    psi_value = np.sum((inc_pct - ref_pct) * np.log(inc_pct / ref_pct))
    return float(max(0.0, psi_value))


def calculate_ks(
    reference: Sequence[float] | np.ndarray,
    incoming: Sequence[float] | np.ndarray,
) -> tuple[float, float]:
    """Calculate two-sample Kolmogorov-Smirnov statistic and p-value."""
    ref_arr = np.asarray(reference, dtype=np.float64)
    inc_arr = np.asarray(incoming, dtype=np.float64)

    if len(ref_arr) == 0 or len(inc_arr) == 0:
        return 0.0, 1.0

    try:
        res = stats.ks_2samp(ref_arr, inc_arr)
        return float(res.statistic), float(res.pvalue)
    except Exception as exc:
        log.warning("KS computation error: %s", exc)
        return 0.0, 1.0


@dataclass
class FeatureDriftMetric:
    feature_name: str
    psi: float
    ks_statistic: float
    ks_p_value: float
    drift_detected: bool
    severity: str  # "NONE", "MODERATE", "HIGH"
    sample_count: int
    reference_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "psi": round(self.psi, 4),
            "ks_statistic": round(self.ks_statistic, 4),
            "ks_p_value": round(self.ks_p_value, 6),
            "drift_detected": self.drift_detected,
            "severity": self.severity,
            "sample_count": self.sample_count,
            "reference_count": self.reference_count,
        }


@dataclass
class DriftAlert:
    alert_id: str
    feature_name: str
    severity: str
    message: str
    psi: float
    ks_statistic: float
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "feature_name": self.feature_name,
            "severity": self.severity,
            "message": self.message,
            "psi": round(self.psi, 4),
            "ks_statistic": round(self.ks_statistic, 4),
            "timestamp": self.timestamp,
        }


@dataclass
class DriftReport:
    timestamp: str
    features_evaluated: int
    drifting_features_count: int
    max_psi: float
    max_ks: float
    overall_status: str  # "HEALTHY", "WARNING", "DRIFT_ALERT"
    feature_metrics: dict[str, FeatureDriftMetric]
    alerts: list[DriftAlert]
    never_claim_accuracy_without_labels: bool = True
    accuracy_disclaimer: str = (
        "Accuracy cannot be calculated or claimed from feature drift alone without "
        "verified ground-truth labels. Drift indicates behavioral distribution changes."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "features_evaluated": self.features_evaluated,
            "drifting_features_count": self.drifting_features_count,
            "max_psi": round(self.max_psi, 4),
            "max_ks": round(self.max_ks, 4),
            "overall_status": self.overall_status,
            "never_claim_accuracy_without_labels": self.never_claim_accuracy_without_labels,
            "accuracy_disclaimer": self.accuracy_disclaimer,
            "feature_metrics": {k: v.to_dict() for k, v in self.feature_metrics.items()},
            "alerts": [a.to_dict() for a in self.alerts],
            "dashboard_card": {
                "card_title": "ML Model Drift & Health",
                "health_status": self.overall_status,
                "drifting_count": self.drifting_features_count,
                "max_psi": round(self.max_psi, 4),
                "accuracy_status": "UNMEASURED_WITHOUT_LABELS",
                "last_evaluated": self.timestamp,
            },
        }


class FeatureDriftMonitor:
    """Monitors live behavioral feature streams against training reference distributions."""

    def __init__(
        self,
        window_size: int = 1000,
        psi_threshold: float = PSI_ALERT_THRESHOLD,
        ks_threshold: float = KS_ALERT_THRESHOLD,
    ) -> None:
        self.window_size = window_size
        self.psi_threshold = psi_threshold
        self.ks_threshold = ks_threshold
        self.reference_distributions: dict[str, np.ndarray] = {}
        self.incoming_buffers: dict[str, deque[float]] = {}

    def set_reference_distribution(
        self,
        feature_name: str,
        values: Sequence[float] | np.ndarray,
    ) -> None:
        """Register the training / baseline reference distribution for a feature."""
        arr = np.asarray(values, dtype=np.float64)
        if len(arr) == 0:
            return
        self.reference_distributions[feature_name] = arr
        if feature_name not in self.incoming_buffers:
            self.incoming_buffers[feature_name] = deque(maxlen=self.window_size)

    def record_feature_value(self, feature_name: str, value: float) -> None:
        """Record an incoming feature observation from live telemetry."""
        if not np.isfinite(value):
            return
        if feature_name not in self.incoming_buffers:
            self.incoming_buffers[feature_name] = deque(maxlen=self.window_size)
        self.incoming_buffers[feature_name].append(float(value))

    def record_event_features(self, features: dict[str, float]) -> None:
        """Record multiple feature values from an event's feature dictionary."""
        for name, val in features.items():
            if isinstance(val, (int, float)):
                self.record_feature_value(name, float(val))

    def evaluate_feature(self, feature_name: str) -> FeatureDriftMetric:
        """Evaluate PSI and KS drift for a single feature."""
        ref = self.reference_distributions.get(feature_name)
        inc = self.incoming_buffers.get(feature_name)

        if ref is None or inc is None or len(inc) < MIN_OBSERVATIONS_FOR_DRIFT:
            return FeatureDriftMetric(
                feature_name=feature_name,
                psi=0.0,
                ks_statistic=0.0,
                ks_p_value=1.0,
                drift_detected=False,
                severity="NONE",
                sample_count=len(inc) if inc is not None else 0,
                reference_count=len(ref) if ref is not None else 0,
            )

        inc_arr = np.array(inc, dtype=np.float64)
        psi = calculate_psi(ref, inc_arr)
        ks_stat, ks_p = calculate_ks(ref, inc_arr)

        if psi >= self.psi_threshold or ks_stat >= self.ks_threshold:
            severity = "HIGH"
            drift_detected = True
        elif psi >= PSI_WARNING_THRESHOLD:
            severity = "MODERATE"
            drift_detected = True
        else:
            severity = "NONE"
            drift_detected = False

        return FeatureDriftMetric(
            feature_name=feature_name,
            psi=psi,
            ks_statistic=ks_stat,
            ks_p_value=ks_p,
            drift_detected=drift_detected,
            severity=severity,
            sample_count=len(inc_arr),
            reference_count=len(ref),
        )

    def evaluate_all(self) -> DriftReport:
        """Evaluate drift across all monitored features and generate a comprehensive report."""
        now_str = datetime.now(UTC).isoformat()
        metrics: dict[str, FeatureDriftMetric] = {}
        alerts: list[DriftAlert] = []

        # Evaluate all registered reference features
        for feat_name in self.reference_distributions:
            m = self.evaluate_feature(feat_name)
            metrics[feat_name] = m
            if m.drift_detected:
                alert_id = f"drift-{uuid.uuid4().hex[:10]}"
                msg = (
                    f"Drift detected in feature '{feat_name}': PSI={m.psi:.3f} "
                    f"(threshold={self.psi_threshold}), KS={m.ks_statistic:.3f} (p={m.ks_p_value:.4f})"
                )
                alerts.append(
                    DriftAlert(
                        alert_id=alert_id,
                        feature_name=feat_name,
                        severity=m.severity,
                        message=msg,
                        psi=m.psi,
                        ks_statistic=m.ks_statistic,
                        timestamp=now_str,
                    )
                )

        drifting_count = len(alerts)
        max_psi = max([m.psi for m in metrics.values()], default=0.0)
        max_ks = max([m.ks_statistic for m in metrics.values()], default=0.0)

        if any(m.severity == "HIGH" for m in metrics.values()):
            overall = "DRIFT_ALERT"
        elif any(m.severity == "MODERATE" for m in metrics.values()):
            overall = "WARNING"
        else:
            overall = "HEALTHY"

        return DriftReport(
            timestamp=now_str,
            features_evaluated=len(metrics),
            drifting_features_count=drifting_count,
            max_psi=max_psi,
            max_ks=max_ks,
            overall_status=overall,
            feature_metrics=metrics,
            alerts=alerts,
        )


__all__ = [
    "DriftAlert",
    "DriftReport",
    "FeatureDriftMetric",
    "FeatureDriftMonitor",
    "calculate_ks",
    "calculate_psi",
]
