"""MLEngine implementation: Isolation Forest anomaly score + Random Forest classification.

* Lazy, thread-safe model loading; artifacts are sha256-verified against their metadata.
* Returns ``None`` (never a fabricated score) when no usable model exists or the behaviour
  feature dict does not overlap the ML schema enough.
* ``top_features`` = RF importance x |z-deviation from the benign-train distribution|, normalised.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import numpy as np

from centralium.agent.interfaces import BehaviorResult
from centralium.agent.models import MLResult, NormalizedEvent
from ml.features.behavior_adapter import RENAMES, adapt_for_event
from ml.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, vectorize
from ml.training.pipeline import DEFAULT_MODELS_DIR
from ml.training.train import (
    ANOMALY_FILE,
    CLASSIFIER_FILE,
    calibrated_score,
    load_bundle,
    raw_anomaly,
)

log = logging.getLogger("centralium.ml")

MIN_COVERAGE = 0.25  # fraction of schema features that must be supplied by the behaviour engine
TOP_K = 5


class SklearnMLEngine:
    def __init__(self, models_dir: Path | str | None = None, min_coverage: float = MIN_COVERAGE) -> None:
        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.min_coverage = min_coverage
        self.model_version = "none"
        self._lock = threading.Lock()
        self._loaded = False
        self._anomaly: dict[str, Any] | None = None
        self._clf: dict[str, Any] | None = None
        self._meta: dict[str, dict[str, Any]] = {}
        self._importances: np.ndarray | None = None
        self.load_errors: dict[str, str] = {}

    # ------------------------------------------------------------------ loading
    def _load(self) -> None:
        with self._lock:
            if self._loaded:
                return
            for key, fname in (("anomaly", ANOMALY_FILE), ("classifier", CLASSIFIER_FILE)):
                try:
                    bundle, meta = load_bundle(self.models_dir, fname)
                except Exception as exc:
                    self.load_errors[key] = f"{type(exc).__name__}: {exc}"
                    log.warning("ML %s model unavailable: %s", key, exc)
                    continue
                self._meta[key] = meta
                if key == "anomaly":
                    self._anomaly = bundle
                else:
                    self._clf = bundle
                    self._importances = np.asarray(bundle["model"].feature_importances_, dtype=float)
            parts = [f"{k}:{m['model_version']}" for k, m in sorted(self._meta.items())]
            self.model_version = "+".join(parts) if parts else "none"
            self._loaded = True

    def available(self) -> bool:
        self._load()
        return self._anomaly is not None or self._clf is not None

    def info(self) -> dict[str, Any]:
        """Metadata for the dashboard (model/feature/dataset versions); empty if unavailable."""
        self._load()
        return {
            "available": self.available(),
            "model_version": self.model_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "models": self._meta,
            "load_errors": self.load_errors,
        }

    # ------------------------------------------------------------------ inference
    def predict_features(self, features: dict[str, float]) -> MLResult | None:
        self._load()
        if self._anomaly is None and self._clf is None:
            return None
        vec, coverage = vectorize(features)
        if coverage < self.min_coverage:
            return None
        x = vec.reshape(1, -1)

        anomaly = 0.0
        z: np.ndarray | None = None
        if self._anomaly is not None:
            xs = self._anomaly["scaler"].transform(x)
            raw = raw_anomaly(self._anomaly["model"], xs)
            anomaly = float(np.clip(calibrated_score(self._anomaly["ecdf"], raw)[0], 0.0, 1.0))
            z = np.abs(xs[0])

        cls, conf = "unknown", 0.0
        if self._clf is not None:
            model = self._clf["model"]
            proba = model.predict_proba(x)[0]
            k = int(proba.argmax())
            cls, conf = str(model.classes_[k]), float(np.clip(proba[k], 0.0, 1.0))
            if z is None:
                z = np.abs(self._clf["scaler"].transform(x)[0])

        top: list[tuple[str, float]] = []
        if z is not None:
            imp = self._importances if self._importances is not None else np.ones(len(FEATURE_NAMES))
            contrib = imp * np.minimum(z, 10.0)
            total = float(contrib.sum())
            if total > 0:
                for i in np.argsort(contrib)[::-1][:TOP_K]:
                    top.append((FEATURE_NAMES[int(i)], round(float(contrib[i] / total), 4)))

        return MLResult(
            anomaly_score=anomaly,
            classification=cls,
            classification_confidence=conf,
            top_features=top,
            model_version=self.model_version,
            feature_version=FEATURE_SCHEMA_VERSION,
        )

    def predict(self, event: NormalizedEvent, behavior: BehaviorResult) -> MLResult | None:
        if not behavior.features:
            return None
        # The BehaviorEngine emits its own feature names/scales; map them onto the ML schema
        # (otherwise vectorize() silently drops nearly everything). See ml/features/behavior_adapter.py.
        if "evt_process" in behavior.features or any(k in behavior.features for k in RENAMES):
            return self.predict_features(adapt_for_event(behavior.features, event))
        return self.predict_features(behavior.features)
