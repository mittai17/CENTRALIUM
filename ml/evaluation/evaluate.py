"""Evaluate trained models on the validation or held-out test split and write a JSON report."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from ml.datasets.scenarios import BENIGN
from ml.evaluation.metrics import NOT_ENOUGH, binary_report, multiclass_report
from ml.training.data import DatasetError, load_dataset, split_dataset
from ml.training.train import (
    ANOMALY_FILE,
    CLASSIFIER_FILE,
    calibrated_score,
    load_bundle,
    raw_anomaly,
)

REPORT_DIR = Path(__file__).parent / "reports"


def evaluate(models_dir: Path, dataset_dir: Path, split: str = "val") -> dict[str, Any]:
    if split not in ("val", "test"):
        raise ValueError("split must be 'val' or 'test'")
    ds = load_dataset(dataset_dir)
    report: dict[str, Any] = {
        "split": split,
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset_version": ds.meta["dataset_version"],
        "synthetic_data": bool(ds.meta.get("synthetic", False)),
        "disclaimer": (
            "Metrics are computed on SYNTHETIC data and demonstrate the pipeline only; they are not "
            "evidence of real-world detection performance."
            if ds.meta.get("synthetic", False)
            else "Metrics computed on the dataset named above."
        ),
    }
    for kind, fname in (("anomaly", ANOMALY_FILE), ("classifier", CLASSIFIER_FILE)):
        try:
            bundle, meta = load_bundle(models_dir, fname)
        except (FileNotFoundError, ValueError) as exc:
            report[kind] = {"status": NOT_ENOUGH, "reason": f"model unavailable: {exc}"}
            continue
        if meta["dataset_version"] != ds.meta["dataset_version"]:
            raise DatasetError(
                f"{fname} trained on {meta['dataset_version']} but evaluating {ds.meta['dataset_version']}"
            )
        part = split_dataset(ds, int(meta["random_seed"]))[split]
        y_bin = part.malicious
        if kind == "anomaly":
            raw = raw_anomaly(bundle["model"], bundle["scaler"].transform(part.X))
            score = calibrated_score(bundle["ecdf"], raw)
            pred = (score >= bundle["threshold"]).astype(int)
            rep = binary_report(y_bin, pred, score)
            rep["alert_threshold"] = bundle["threshold"]
            rep["note"] = "unsupervised: trained on benign only; threshold chosen on benign validation"
        else:
            model = bundle["model"]
            proba = model.predict_proba(part.X)
            classes = list(model.classes_)
            pred_cls = np.array(classes)[proba.argmax(1)]
            benign_idx = classes.index(BENIGN)
            mal_score = 1.0 - proba[:, benign_idx]
            rep = {
                "multiclass": multiclass_report(part.labels, pred_cls, classes),
                "binary_malicious_vs_benign": binary_report(
                    y_bin, (pred_cls != BENIGN).astype(int), mal_score
                ),
            }
        rep["model_version"] = meta["model_version"]
        rep["feature_schema_version"] = meta["feature_schema_version"]
        rep["n_rows_split"] = len(part)
        rep["n_groups_split"] = len(set(part.groups.tolist()))
        report[kind] = rep
    return report


def write_report(report: dict[str, Any], path: Path | None = None) -> Path:
    path = path or REPORT_DIR / f"{report['split']}_metrics.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return path
