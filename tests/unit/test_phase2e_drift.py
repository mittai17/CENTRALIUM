"""Unit tests for Phase 2E: Behavioral feature distribution drift monitoring (PSI / KS)
and model health reporting.
"""

from __future__ import annotations

import numpy as np

from centralium.agent.ml.drift import (
    FeatureDriftMonitor,
    calculate_ks,
    calculate_psi,
)


def test_psi_and_ks_identical_distributions():
    # Exactly identical distribution -> PSI ~ 0, KS stat = 0
    ref = np.random.default_rng(42).normal(loc=10.0, scale=2.0, size=200)
    inc = ref.copy()

    psi = calculate_psi(ref, inc)
    ks_stat, ks_p = calculate_ks(ref, inc)

    assert psi < 0.05
    assert ks_stat == 0.0
    assert ks_p == 1.0


def test_psi_and_ks_significant_drift():
    # Reference centered at 10, incoming shifted far away to 50
    rng = np.random.default_rng(42)
    ref = rng.normal(loc=10.0, scale=2.0, size=300)
    inc = rng.normal(loc=50.0, scale=5.0, size=300)

    psi = calculate_psi(ref, inc)
    ks_stat, ks_p = calculate_ks(ref, inc)

    assert psi > 0.50  # Very high PSI
    assert ks_stat > 0.80  # Very high KS separation
    assert ks_p < 0.001


def test_feature_drift_monitor_stable_case():
    monitor = FeatureDriftMonitor(psi_threshold=0.25, ks_threshold=0.20)
    rng = np.random.default_rng(123)

    # Reference training distributions
    ref_cmd_len = rng.normal(loc=50.0, scale=10.0, size=500)
    ref_entropy = rng.uniform(low=4.0, high=6.5, size=500)

    monitor.set_reference_distribution("command_length", ref_cmd_len)
    monitor.set_reference_distribution("file_entropy", ref_entropy)

    # Stream incoming values from same distribution
    for _ in range(100):
        monitor.record_event_features(
            {
                "command_length": float(rng.normal(loc=50.0, scale=10.0)),
                "file_entropy": float(rng.uniform(low=4.0, high=6.5)),
            }
        )

    report = monitor.evaluate_all()
    assert report.overall_status == "HEALTHY"
    assert report.drifting_features_count == 0
    assert len(report.alerts) == 0

    # CRITICAL INVARIANT: Never claim accuracy without ground-truth labels
    assert report.never_claim_accuracy_without_labels is True
    assert "labels" in report.accuracy_disclaimer.lower()
    assert report.to_dict()["dashboard_card"]["accuracy_status"] == "UNMEASURED_WITHOUT_LABELS"


def test_feature_drift_monitor_drifting_alert():
    monitor = FeatureDriftMonitor(psi_threshold=0.25, ks_threshold=0.20)
    rng = np.random.default_rng(999)

    # Baseline reference: normal user commands (short, standard entropy)
    ref_bytes = rng.normal(loc=100.0, scale=15.0, size=500)
    monitor.set_reference_distribution("network_bytes_out", ref_bytes)

    # Attacker activity or environmental shift: massive exfiltration data
    for _ in range(80):
        monitor.record_event_features({"network_bytes_out": float(rng.normal(loc=5000.0, scale=500.0))})

    report = monitor.evaluate_all()
    assert report.overall_status == "DRIFT_ALERT"
    assert report.drifting_features_count == 1
    assert len(report.alerts) == 1

    alert = report.alerts[0]
    assert alert.feature_name == "network_bytes_out"
    assert alert.severity == "HIGH"
    assert alert.psi > 0.25
    assert alert.ks_statistic > 0.20

    # Ensure dashboard card reflects the drift alert
    card = report.to_dict()["dashboard_card"]
    assert card["health_status"] == "DRIFT_ALERT"
    assert card["drifting_count"] == 1
