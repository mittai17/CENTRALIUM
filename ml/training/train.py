"""Model training: Isolation Forest (benign only) and Random Forest classifier."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from ml.datasets.scenarios import BENIGN
from ml.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ml.training.data import Dataset, DatasetError

ANOMALY_FILE = "anomaly_iforest.joblib"
CLASSIFIER_FILE = "classifier_rf.joblib"
ECDF_POINTS = 1001
DEFAULT_SEED = 1337
MIN_TRAIN_ROWS = 200

IF_PARAMS: dict[str, Any] = {"n_estimators": 100, "max_samples": 256, "contamination": "auto"}
RF_PARAMS: dict[str, Any] = {
    "n_estimators": 60,
    "max_depth": 12,
    "min_samples_leaf": 5,
    "class_weight": "balanced_subsample",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _short(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:8]


def raw_anomaly(model: IsolationForest, Xs: np.ndarray) -> np.ndarray:
    return np.asarray(-model.score_samples(Xs))  # higher = more anomalous


def calibrated_score(ecdf: np.ndarray, raw: np.ndarray) -> np.ndarray:
    """Empirical CDF of raw scores of benign TRAIN rows: fraction of benign rows less anomalous.

    Output in [0,1]; 0.95 means "more anomalous than 95% of benign training windows".
    """
    return np.asarray(np.interp(raw, ecdf, np.linspace(0.0, 1.0, len(ecdf)), left=0.0, right=1.0))


def _write(path: Path, bundle: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    meta = {**meta, "artifact": path.name, "artifact_sha256": sha256_file(path)}
    path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return meta


def _base_meta(
    kind: str, ds_meta: dict[str, Any], params: dict[str, Any], seed: int, n_train: int
) -> dict[str, Any]:
    return {
        "model_kind": kind,
        "model_version": f"{kind}-{FEATURE_SCHEMA_VERSION}-{str(ds_meta['dataset_version'])[-10:]}"
        f"-{_short(params)}",
        "trained_at": datetime.now(UTC).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "dataset_version": ds_meta["dataset_version"],
        "dataset_synthetic": bool(ds_meta.get("synthetic", False)),
        "hyperparameters": params,
        "random_seed": seed,
        "n_train_rows": n_train,
        "sklearn_version": sklearn.__version__,
        "joblib_trust_note": "artifact_sha256 is verified on load; only load models you produced.",
    }


def train_anomaly(train: Dataset, val: Dataset, models_dir: Path, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Fit scaler + IsolationForest on BENIGN TRAIN rows only; calibrate on benign train;
    pick the alert threshold on benign VAL (target FPR 5%). Test data is never touched."""
    benign = train.X[train.labels == BENIGN]
    vbenign = val.X[val.labels == BENIGN]
    if len(benign) < MIN_TRAIN_ROWS or len(vbenign) < 50:
        raise DatasetError(
            f"Not enough validated data: benign train={len(benign)}, benign val={len(vbenign)}"
        )
    scaler = StandardScaler().fit(benign)
    model = IsolationForest(**IF_PARAMS, random_state=seed).fit(scaler.transform(benign))
    raw = raw_anomaly(model, scaler.transform(benign))
    ecdf = np.quantile(raw, np.linspace(0.0, 1.0, ECDF_POINTS))
    val_scores = calibrated_score(ecdf, raw_anomaly(model, scaler.transform(vbenign)))
    target_fpr = 0.05
    threshold = float(np.quantile(val_scores, 1.0 - target_fpr))
    meta = _base_meta("iforest", train.meta, {**IF_PARAMS, "seed": seed}, seed, len(benign))
    meta.update(
        trained_on="benign train rows only",
        scaler="StandardScaler fit on benign train rows only",
        score_calibration="empirical CDF of raw scores on benign train rows",
        alert_threshold=threshold,
        threshold_selection=f"benign validation quantile {1 - target_fpr:.2f}",
    )
    bundle = {"model": model, "scaler": scaler, "ecdf": ecdf, "threshold": threshold}
    return _write(models_dir / ANOMALY_FILE, bundle, meta)


def train_classifier(train: Dataset, models_dir: Path, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    if len(train) < MIN_TRAIN_ROWS or len(set(train.labels.tolist())) < 2:
        raise DatasetError("Not enough validated data to train classifier")
    scaler = StandardScaler().fit(train.X)  # train-only; used for top-feature deviations
    model = RandomForestClassifier(**RF_PARAMS, random_state=seed, n_jobs=1).fit(train.X, train.labels)
    meta = _base_meta("rf", train.meta, {**RF_PARAMS, "seed": seed}, seed, len(train))
    meta.update(classes=[str(c) for c in model.classes_], benign_class=BENIGN)
    bundle = {"model": model, "scaler": scaler, "classes": [str(c) for c in model.classes_]}
    return _write(models_dir / CLASSIFIER_FILE, bundle, meta)


def load_bundle(models_dir: Path, filename: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load joblib bundle after verifying its sha256 against the sidecar metadata."""
    path = models_dir / filename
    meta_path = path.with_suffix(".meta.json")
    if not path.exists() or not meta_path.exists():
        raise FileNotFoundError(path)
    meta = json.loads(meta_path.read_text())
    if meta.get("artifact_sha256") != sha256_file(path):
        raise ValueError(f"{path.name}: sha256 mismatch with metadata (tampered or stale); refusing to load")
    if meta.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            f"{path.name}: trained on feature schema {meta.get('feature_schema_version')}, "
            f"current is {FEATURE_SCHEMA_VERSION}"
        )
    bundle = joblib.load(path)  # trusted: hash-verified above
    return bundle, meta
