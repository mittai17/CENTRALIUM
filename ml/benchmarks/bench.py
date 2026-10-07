"""Inference benchmarks (measured at run time on the current machine)."""

from __future__ import annotations

import json
import os
import platform
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from centralium.agent.ml.engine import SklearnMLEngine
from ml.features.schema import FEATURE_NAMES
from ml.training.data import load_dataset, split_dataset

RESULT_DIR = Path(__file__).parent / "results"


def run_benchmark(
    models_dir: Path, dataset_dir: Path, n: int = 3000, warmup: int = 200, batch: int = 256
) -> dict[str, Any]:
    engine = SklearnMLEngine(models_dir)
    if not engine.available():
        return {
            "status": "Not enough validated data",
            "reason": "no trained models",
            "errors": engine.load_errors,
        }
    ds = load_dataset(dataset_dir)
    seed = next(iter(engine._meta.values()))["random_seed"]
    test = split_dataset(ds, int(seed))["test"]
    idx = np.random.default_rng(0).integers(0, len(test), size=n)
    feats = [dict(zip(FEATURE_NAMES, map(float, test.X[i]), strict=True)) for i in idx]
    for f in feats[:warmup]:
        engine.predict_features(f)
    lat = np.empty(n)
    t_all = time.perf_counter()
    for k, f in enumerate(feats):
        t0 = time.perf_counter_ns()
        engine.predict_features(f)
        lat[k] = (time.perf_counter_ns() - t0) / 1e6
    total = time.perf_counter() - t_all

    out: dict[str, Any] = {
        "status": "ok",
        "measured_at": datetime.now(UTC).isoformat(),
        "machine": {
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "model_version": engine.model_version,
        "single_event": {
            "n": n,
            "latency_ms": {
                "p50": float(np.percentile(lat, 50)),
                "p95": float(np.percentile(lat, 95)),
                "p99": float(np.percentile(lat, 99)),
                "mean": float(lat.mean()),
                "max": float(lat.max()),
            },
            "throughput_events_per_sec": float(n / total),
        },
    }
    # Batched throughput straight on the estimators (upper bound for bulk scoring)
    X = test.X[idx[:batch]] if len(idx) >= batch else test.X
    bt: dict[str, Any] = {}
    if engine._anomaly is not None:
        a = engine._anomaly
        tb = time.perf_counter()
        reps = 20
        for _ in range(reps):
            a["model"].score_samples(a["scaler"].transform(X))
        bt["anomaly_rows_per_sec"] = float(reps * len(X) / (time.perf_counter() - tb))
    if engine._clf is not None:
        tc = time.perf_counter()
        reps = 20
        for _ in range(reps):
            engine._clf["model"].predict_proba(X)
        bt["classifier_rows_per_sec"] = float(reps * len(X) / (time.perf_counter() - tc))
    out["batch"] = {"batch_size": len(X), **bt}
    return out


def write_result(result: dict[str, Any], path: Path | None = None) -> Path:
    path = path or RESULT_DIR / "latest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path
