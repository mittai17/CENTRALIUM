from __future__ import annotations

import json
import shutil
from pathlib import Path

import numpy as np
import pytest

from centralium.agent.interfaces import BehaviorResult, MLEngine
from centralium.agent.ml import SklearnMLEngine, create_ml_engine
from centralium.agent.models import EventType, MLResult, NormalizedEvent
from ml.datasets.replay import generate_replay
from ml.datasets.scenarios import BENIGN, SCENARIOS
from ml.datasets.synthetic import generate_samples, write_dataset
from ml.evaluation.evaluate import evaluate
from ml.evaluation.metrics import NOT_ENOUGH, binary_report
from ml.features import schema
from ml.training.data import DatasetError, group_split, load_dataset, split_dataset
from ml.training.train import ANOMALY_FILE, load_bundle

pytestmark = pytest.mark.ml
SEED = 7


# ------------------------------------------------------------------ determinism
def test_generator_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    ma, mb = write_dataset(a, seed=3, scale=0.2), write_dataset(b, seed=3, scale=0.2)
    assert ma["dataset_version"] == mb["dataset_version"]
    assert (a / "samples.jsonl").read_bytes() == (b / "samples.jsonl").read_bytes()
    assert write_dataset(tmp_path / "c", seed=4, scale=0.2)["dataset_version"] != ma["dataset_version"]
    assert ma["synthetic"] is True


def test_replay_deterministic_and_valid() -> None:
    a, b = generate_replay(1, 1), generate_replay(1, 1)
    assert a == b
    for e in a:
        NormalizedEvent(**e)
        assert e["raw_metadata"]["synthetic"] is True
    assert {e["raw_metadata"]["scenario"] for e in a} == {s.name for s in SCENARIOS}


def test_training_deterministic(small_data: Path, tmp_path: Path) -> None:
    from ml.training.train import train_classifier

    parts = split_dataset(load_dataset(small_data), SEED)
    train_classifier(parts["train"], tmp_path / "m1", SEED)
    train_classifier(parts["train"], tmp_path / "m2", SEED)
    b1, _ = load_bundle(tmp_path / "m1", "classifier_rf.joblib")
    b2, _ = load_bundle(tmp_path / "m2", "classifier_rf.joblib")
    x = parts["test"].X[:50]
    assert np.array_equal(b1["model"].predict_proba(x), b2["model"].predict_proba(x))


# ------------------------------------------------------------------ leakage
def test_no_group_leakage_between_splits(small_data: Path) -> None:
    parts = split_dataset(load_dataset(small_data), SEED)
    g = {k: set(v.groups.tolist()) for k, v in parts.items()}
    assert not (g["train"] & g["val"]) and not (g["train"] & g["test"]) and not (g["val"] & g["test"])
    assert sum(len(v) for v in parts.values()) == len(load_dataset(small_data))
    for v in parts.values():
        assert len(v) > 0


def test_every_scenario_in_train_and_test(small_data: Path) -> None:
    parts = split_dataset(load_dataset(small_data), SEED)
    names = {s.name for s in SCENARIOS}
    assert set(parts["train"].scenarios.tolist()) == names
    assert set(parts["test"].scenarios.tolist()) == names


def test_group_split_requires_enough_groups() -> None:
    with pytest.raises(DatasetError):
        group_split(np.array(["a", "b"]), np.array(["s", "s"]), 1)


def test_anomaly_trained_on_benign_train_only_and_scaler_train_only(small_data: Path, trained: Path) -> None:
    parts = split_dataset(load_dataset(small_data), SEED)
    bundle, meta = load_bundle(trained, ANOMALY_FILE)
    benign_train = parts["train"].X[parts["train"].labels == BENIGN]
    assert np.allclose(bundle["scaler"].mean_, benign_train.mean(axis=0))
    assert meta["n_train_rows"] == len(benign_train)
    assert meta["trained_on"] == "benign train rows only"


# ------------------------------------------------------------------ schema / metadata
def test_schema_versioning_and_metadata(trained: Path) -> None:
    assert len(schema.FEATURE_NAMES) == len(set(schema.FEATURE_NAMES)) == schema.N_FEATURES
    assert set(schema.FEATURE_FAMILIES) == {"process", "network", "file", "behavior", "ransomware"}
    for f in ("anomaly_iforest", "classifier_rf"):
        meta = json.loads((trained / f"{f}.meta.json").read_text())
        for key in (
            "model_version",
            "trained_at",
            "feature_schema_version",
            "dataset_version",
            "hyperparameters",
        ):
            assert meta[key]
        assert meta["feature_schema_version"] == schema.FEATURE_SCHEMA_VERSION
        assert meta["dataset_synthetic"] is True


def test_schema_version_mismatch_refused(trained: Path, tmp_path: Path) -> None:
    shutil.copytree(trained, tmp_path / "m")
    p = tmp_path / "m" / "anomaly_iforest.meta.json"
    meta = json.loads(p.read_text())
    meta["feature_schema_version"] = "0.0.1"
    p.write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="schema"):
        load_bundle(tmp_path / "m", ANOMALY_FILE)
    assert not SklearnMLEngine(tmp_path / "m").info()["models"].get("anomaly")


def test_tampered_artifact_refused(trained: Path, tmp_path: Path) -> None:
    shutil.copytree(trained, tmp_path / "m")
    with (tmp_path / "m" / ANOMALY_FILE).open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(ValueError, match="sha256"):
        load_bundle(tmp_path / "m", ANOMALY_FILE)


def test_vectorize_tolerates_missing_and_bad_values() -> None:
    vec, cov = schema.vectorize(
        {"powershell_use": 1, "bogus": 5, "child_count": float("nan"), "dns_entropy": "x"}
    )
    assert vec.shape == (schema.N_FEATURES,) and np.isfinite(vec).all()
    assert cov == pytest.approx(1 / schema.N_FEATURES)
    vec2, _ = schema.vectorize({"net_conn_count": 1e9})
    assert vec2[schema.FEATURE_INDEX["net_conn_count"]] == schema.CAPS[schema.FEATURE_INDEX["net_conn_count"]]


# ------------------------------------------------------------------ runtime inference
def _ev() -> NormalizedEvent:
    return NormalizedEvent(event_type=EventType.PROCESS_START, process_name="x", source="test")


def test_inference_ranges_and_explanations(small_data: Path, trained: Path) -> None:
    engine = SklearnMLEngine(trained)
    assert isinstance(engine, MLEngine)
    test = split_dataset(load_dataset(small_data), SEED)["test"]
    for row in test.X[:200]:
        feats = dict(zip(schema.FEATURE_NAMES, map(float, row), strict=True))
        r = engine.predict(_ev(), BehaviorResult(features=feats))
        assert isinstance(r, MLResult)
        assert 0.0 <= r.anomaly_score <= 1.0
        assert 0.0 <= r.classification_confidence <= 1.0
        assert r.classification in {*(s.label for s in SCENARIOS)}
        assert 1 <= len(r.top_features) <= 5
        assert all(n in schema.FEATURE_NAMES and v >= 0 for n, v in r.top_features)
        assert r.model_version != "none" and r.feature_version == schema.FEATURE_SCHEMA_VERSION


def test_ransomware_profile_scores_higher_than_benign(trained: Path) -> None:
    engine = SklearnMLEngine(trained)
    ransom = {
        "file_modify_rate": 800,
        "file_rename_rate": 500,
        "ext_mutation": 0.9,
        "file_write_entropy": 7.8,
        "write_burst": 0.95,
        "rename_burst": 0.9,
        "entropy_increase": 0.9,
        "shadow_copy_activity": 1,
        "file_ext_change_rate": 0.9,
    }
    base = dict(zip(schema.FEATURE_NAMES, map(float, schema.DEFAULTS), strict=True))
    r = engine.predict_features({**base, **ransom})
    b = engine.predict_features(base)
    assert r is not None and b is not None
    assert r.classification == "ransomware"
    assert r.anomaly_score > b.anomaly_score


def test_partial_features_ok_but_no_overlap_returns_none(trained: Path) -> None:
    engine = SklearnMLEngine(trained)
    assert engine.predict_features({"unknown_feature_a": 1.0}) is None
    assert engine.predict(_ev(), BehaviorResult(features={})) is None


def test_missing_models_fallback(tmp_path: Path) -> None:
    engine = SklearnMLEngine(tmp_path / "nope")
    assert engine.available() is False
    assert (
        engine.predict_features({"powershell_use": 1.0, **dict.fromkeys(schema.FEATURE_NAMES, 0.0)}) is None
    )
    assert engine.model_version == "none"
    assert engine.info()["available"] is False and engine.load_errors


def test_install_default_models(tmp_path: Path) -> None:
    engine = create_ml_engine(tmp_path / "models", auto_install=True)
    assert engine.available()
    assert (tmp_path / "models" / "classifier_rf.meta.json").exists()


def test_committed_default_models_load() -> None:
    engine = create_ml_engine()
    assert engine.available(), engine.load_errors


# ------------------------------------------------------------------ metrics honesty
def test_metrics_refuse_tiny_or_one_class_data() -> None:
    r = binary_report(np.array([1, 0, 1]), np.array([1, 0, 0]), np.array([0.9, 0.1, 0.4]))
    assert r["status"] == NOT_ENOUGH and "precision" not in r and "roc_auc" not in r
    only_benign = binary_report(np.zeros(100, int), np.zeros(100, int))
    assert only_benign["status"] == NOT_ENOUGH


def test_metrics_values_correct() -> None:
    y = np.array([1] * 20 + [0] * 80)
    pred = np.array([1] * 15 + [0] * 5 + [1] * 8 + [0] * 72)
    r = binary_report(y, pred, np.where(y == 1, 0.8, 0.2))
    assert r["status"] == "ok"
    assert r["precision"] == pytest.approx(15 / 23) and r["recall"] == pytest.approx(0.75)
    assert r["false_positive_rate"] == pytest.approx(0.1)
    assert r["confusion_matrix"]["matrix"] == [[72, 8], [5, 15]]
    assert r["roc_auc"] == 1.0


def test_evaluation_report_labels_synthetic_and_missing_models(
    small_data: Path, trained: Path, tmp_path: Path
) -> None:
    rep = evaluate(trained, small_data, "test")
    assert rep["synthetic_data"] is True and "SYNTHETIC" in rep["disclaimer"]
    assert rep["anomaly"]["status"] == "ok" and 0 <= rep["anomaly"]["roc_auc"] <= 1
    empty = evaluate(tmp_path / "none", small_data, "val")
    assert empty["anomaly"]["status"] == NOT_ENOUGH and empty["classifier"]["status"] == NOT_ENOUGH


def test_generator_yields_all_scenarios_with_expected_labels() -> None:
    seen = {(s.scenario, s.label) for s in generate_samples(1, 0.05, 2)}
    assert seen == {(s.name, s.label) for s in SCENARIOS}
