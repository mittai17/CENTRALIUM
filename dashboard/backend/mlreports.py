"""Read ML evaluation reports (JSON) from the ml/ tree. Never fabricates metrics.

Accepted report shape (any of these layouts, searched newest-first under ``ml/evaluation`` and
``ml/reports``)::

    {"model_version": "...", "feature_version": "...", "dataset_version": "...",
     "n_samples": 1234, "validated": true,
     "metrics": {"precision": .., "recall": .., "f1": .., "roc_auc": .., "false_positive_rate": ..,
                 "detection_rate": .., "inference_latency_ms": .., "throughput_eps": ..},
     "confusion_matrix": {"labels": ["benign","malicious"], "matrix": [[..],[..]]},
     "score_histogram": {"bins": [...], "counts": [...]}}

If no report exists, it is malformed, ``validated`` is false, or ``n_samples`` < MIN_SAMPLES the
API answers ``available: false`` with the message "Not enough validated data".
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

log = logging.getLogger("centralium.dashboard.ml")
MIN_SAMPLES = 30
NO_DATA = "Not enough validated data"
METRIC_KEYS = (
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "false_positive_rate",
    "detection_rate",
    "inference_latency_ms",
    "throughput_eps",
)
UNIT_KEYS = {"precision", "recall", "f1", "roc_auc", "false_positive_rate", "detection_rate"}


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


def _candidates(ml_dir: Path) -> list[Path]:
    out: list[Path] = []
    for sub in ("evaluation", "reports"):
        d = ml_dir / sub
        if d.is_dir():
            out += [p for p in d.rglob("*.json") if p.is_file() and p.stat().st_size < 5_000_000]
    return sorted(out, key=lambda p: p.stat().st_mtime, reverse=True)[:50]


def load_report(ml_dir: Path) -> dict[str, Any]:
    reasons: list[str] = []
    for path in _candidates(ml_dir):
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            reasons.append(f"{path.name}: unreadable")
            continue
        if not isinstance(data, dict):
            continue
        raw_metrics: dict[str, Any] = data["metrics"] if isinstance(data.get("metrics"), dict) else data
        metrics: dict[str, float] = {}
        for k in METRIC_KEYS:
            n = _num(raw_metrics.get(k))
            if n is None:
                continue
            if k in UNIT_KEYS and not 0.0 <= n <= 1.0:
                continue
            metrics[k] = n
        if not metrics:
            reasons.append(f"{path.name}: no valid metrics")
            continue
        ds = data.get("dataset")
        n_samples = data.get("n_samples", ds.get("n_samples") if isinstance(ds, dict) else None)
        ns = (
            int(n_samples)
            if isinstance(n_samples, (int, float)) and not isinstance(n_samples, bool)
            else None
        )
        if data.get("validated") is False:
            reasons.append(f"{path.name}: marked not validated")
            continue
        if ns is not None and ns < MIN_SAMPLES:
            reasons.append(f"{path.name}: only {ns} samples (< {MIN_SAMPLES})")
            continue
        cm = data.get("confusion_matrix")
        if not (
            isinstance(cm, dict) and isinstance(cm.get("matrix"), list) and isinstance(cm.get("labels"), list)
        ):
            cm = None
        hist = data.get("score_histogram")
        if not (isinstance(hist, dict) and isinstance(hist.get("counts"), list)):
            hist = None
        return {
            "available": True,
            "report_file": path.name,
            "model_version": data.get("model_version"),
            "feature_version": data.get("feature_version"),
            "dataset_version": data.get("dataset_version"),
            "n_samples": ns,
            "metrics": metrics,
            "confusion_matrix": cm,
            "score_histogram": hist,
        }
    return {"available": False, "message": NO_DATA, "reasons": reasons[:10]}
