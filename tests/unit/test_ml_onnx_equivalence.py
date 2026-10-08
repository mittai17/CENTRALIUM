"""Equivalence tests comparing Scikit-Learn MLEngine and ONNX Runtime MLEngine.

Asserts exact functional and numerical alignment on anomaly scores,
classification labels, confidences, and top feature contributions.
"""

from __future__ import annotations

import numpy as np
import pytest

from centralium.agent.ml import OnnxMLEngine, SklearnMLEngine, create_ml_engine
from ml.features.schema import FEATURE_NAMES


@pytest.fixture(scope="module")
def engines():
    sk = SklearnMLEngine(use_onnx=False)
    on = OnnxMLEngine()
    if not sk.available() or not on.available():
        pytest.skip("ML or ONNX models not available")
    return sk, on


def test_onnx_engine_availability_and_info(engines):
    _sk, on = engines
    assert on.available() is True
    info = on.info()
    assert info["available"] is True
    assert "onnx" in info["model_version"]
    assert info["runtime"] == "onnxruntime"


def test_sklearn_engine_use_onnx_delegation():
    sk_onnx = SklearnMLEngine(use_onnx=True)
    assert sk_onnx.available() is True
    assert sk_onnx.use_onnx is True
    info = sk_onnx.info()
    assert info["runtime"] == "onnxruntime"

    engine_factory = create_ml_engine(use_onnx=True)
    assert engine_factory.available() is True


@pytest.mark.parametrize(
    "pattern_name, value_bias",
    [
        ("zero_baseline", 0.0),
        ("benign_typical", 0.1),
        ("suspicious_elevated", 0.7),
        ("extreme_attack", 2.5),
    ],
)
def test_ml_onnx_equivalence_across_feature_distributions(engines, pattern_name, value_bias):
    sk, on = engines

    rng = np.random.RandomState(hash(pattern_name) % (2**31))
    features = {name: float(max(0.0, value_bias + rng.randn() * 0.2)) for name in FEATURE_NAMES}

    res_sk = sk.predict_features(features)
    res_on = on.predict_features(features)

    assert res_sk is not None
    assert res_on is not None

    # 1. Anomaly score alignment within floating-point tolerance
    assert abs(res_sk.anomaly_score - res_on.anomaly_score) < 1e-4, (
        f"Anomaly score mismatch for {pattern_name}: sklearn={res_sk.anomaly_score}, onnx={res_on.anomaly_score}"
    )

    # 2. Classifier predicted class match
    assert res_sk.classification == res_on.classification, (
        f"Classification mismatch for {pattern_name}: sklearn={res_sk.classification}, onnx={res_on.classification}"
    )

    # 3. Classifier confidence score alignment within tolerance
    assert abs(res_sk.classification_confidence - res_on.classification_confidence) < 1e-4, (
        f"Confidence mismatch for {pattern_name}: sklearn={res_sk.classification_confidence}, onnx={res_on.classification_confidence}"
    )

    # 4. Top features agreement (primary contributing feature must match)
    if res_sk.top_features and res_on.top_features:
        assert res_sk.top_features[0][0] == res_on.top_features[0][0], (
            f"Top feature mismatch: sklearn={res_sk.top_features[0]}, onnx={res_on.top_features[0]}"
        )
