"""Measures (does not hard-assert) ML inference latency using the committed default models."""

from __future__ import annotations

import time

import pytest

from centralium.agent.ml import create_ml_engine
from ml.features.schema import FEATURE_NAMES

pytestmark = pytest.mark.performance


def test_ml_inference_latency_measured(record_property: pytest.RecordProperty) -> None:
    engine = create_ml_engine()
    if not engine.available():
        pytest.skip("no models")
    feats = dict.fromkeys(FEATURE_NAMES, 0.1)
    for _ in range(20):
        engine.predict_features(feats)
    n = 300
    t0 = time.perf_counter()
    for _ in range(n):
        engine.predict_features(feats)
    per_ms = (time.perf_counter() - t0) / n * 1000
    record_property("ml_ms_per_event", per_ms)
    assert per_ms < 500  # sanity ceiling only; real numbers: python -m ml.cli benchmark
