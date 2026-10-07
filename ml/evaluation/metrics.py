"""Metric computation. Refuses to produce numbers without enough validated data."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

NOT_ENOUGH = "Not enough validated data"
MIN_ROWS = 50
MIN_PER_CLASS = 10


def _insufficient(reason: str, **counts: Any) -> dict[str, Any]:
    return {"status": NOT_ENOUGH, "reason": reason, **counts}


def binary_report(
    y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None
) -> dict[str, Any]:
    """Malicious(1) vs benign(0). ROC-AUC only when both classes are well represented."""
    y_true, y_pred = np.asarray(y_true).astype(int), np.asarray(y_pred).astype(int)
    pos, neg = int((y_true == 1).sum()), int((y_true == 0).sum())
    if len(y_true) < MIN_ROWS or pos < MIN_PER_CLASS or neg < MIN_PER_CLASS:
        return _insufficient(
            "too few rows or too few positives/negatives", n=len(y_true), positives=pos, negatives=neg
        )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    out: dict[str, Any] = {
        "status": "ok",
        "n": len(y_true),
        "positives": pos,
        "negatives": neg,
        "precision": float(p),
        "recall": float(r),
        "detection_rate": float(r),
        "f1": float(f1),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "confusion_matrix": {
            "labels": ["benign", "malicious"],
            "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        },
    }
    if y_score is not None:
        out["roc_auc"] = float(roc_auc_score(y_true, y_score))
    else:
        out["roc_auc"] = None
    return out


def multiclass_report(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str]) -> dict[str, Any]:
    if len(y_true) < MIN_ROWS:
        return _insufficient("too few rows", n=len(y_true))
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    p, r, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    per_class = {
        c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f1[i]), "support": int(support[i])}
        for i, c in enumerate(classes)
    }
    thin = [c for c, v in per_class.items() if v["support"] < MIN_PER_CLASS]
    return {
        "status": "ok",
        "n": len(y_true),
        "accuracy": float((np.asarray(y_true) == np.asarray(y_pred)).mean()),
        "macro_f1": float(np.mean([v["f1"] for v in per_class.values()])),
        "per_class": per_class,
        "classes_with_too_little_support": thin,
        "confusion_matrix": {"labels": classes, "matrix": cm.tolist()},
    }
