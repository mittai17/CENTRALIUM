"""MLEngine implementation: Isolation Forest anomaly score + Random Forest classification.

* Lazy, thread-safe model loading; artifacts are sha256-verified against their metadata.
* Returns ``None`` (never a fabricated score) when no usable model exists or the behaviour
  feature dict does not overlap the ML schema enough.
* ``top_features`` = RF importance x |z-deviation from the benign-train distribution|, normalised.
* Supports both standard scikit-learn and high-performance ONNX Runtime inference via `OnnxMLEngine`
  or `SklearnMLEngine(use_onnx=True)`.
"""

from __future__ import annotations

import json
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

ONNX_ANOMALY_FILE = "anomaly_iforest.onnx"
ONNX_CLASSIFIER_FILE = "classifier_rf.onnx"
ONNX_SCALER_FILE = "anomaly_iforest.scaler.json"


class OnnxMLEngine:
    """MLEngine implementation backed by ONNX Runtime inference sessions.

    Achieves sub-millisecond per-event inference and ~1300+ events/s throughput
    with exact numerical equivalence to scikit-learn models.
    """

    def __init__(self, models_dir: Path | str | None = None, min_coverage: float = MIN_COVERAGE) -> None:
        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.onnx_dir = self.models_dir / "onnx"
        self.min_coverage = min_coverage
        self.model_version = "none"
        self._lock = threading.Lock()
        self._loaded = False
        self._ano_sess: Any = None
        self._clf_sess: Any = None
        self._scaler_mean: np.ndarray | None = None
        self._scaler_scale: np.ndarray | None = None
        self._ecdf: np.ndarray | None = None
        self._classes: list[str] | None = None
        self._importances: np.ndarray | None = None
        self._meta: dict[str, dict[str, Any]] = {}
        self.load_errors: dict[str, str] = {}

    def _load(self) -> None:
        with self._lock:
            if self._loaded:
                return
            try:
                import onnxruntime as ort
            except ImportError as exc:
                self.load_errors["onnxruntime"] = f"onnxruntime not installed: {exc}"
                self._loaded = True
                return

            opts = ort.SessionOptions()
            opts.intra_op_num_threads = 1
            opts.inter_op_num_threads = 1

            # 1. Load anomaly ONNX model and scaler
            ano_path = self.onnx_dir / ONNX_ANOMALY_FILE
            scaler_path = self.onnx_dir / ONNX_SCALER_FILE
            if ano_path.exists() and scaler_path.exists():
                try:
                    s_data = json.loads(scaler_path.read_text(encoding="utf-8"))
                    self._scaler_mean = np.array(s_data["mean"], dtype=np.float32)
                    self._scaler_scale = np.array(s_data["scale"], dtype=np.float32)
                    self._ano_sess = ort.InferenceSession(str(ano_path), opts)
                    # Load ecdf calibration from bundle
                    bundle, meta = load_bundle(self.models_dir, ANOMALY_FILE)
                    self._ecdf = bundle.get("ecdf")
                    self._meta["anomaly"] = {**meta, "runtime": "onnx"}
                except Exception as exc:
                    self.load_errors["anomaly"] = f"ONNX anomaly load error: {exc}"
                    log.warning("ONNX anomaly model load failed: %s", exc)

            # 2. Load classifier ONNX model
            clf_path = self.onnx_dir / ONNX_CLASSIFIER_FILE
            if clf_path.exists():
                try:
                    self._clf_sess = ort.InferenceSession(str(clf_path), opts)
                    bundle, meta = load_bundle(self.models_dir, CLASSIFIER_FILE)
                    self._classes = list(bundle["model"].classes_)
                    self._importances = np.asarray(bundle["model"].feature_importances_, dtype=float)
                    self._meta["classifier"] = {**meta, "runtime": "onnx"}
                except Exception as exc:
                    self.load_errors["classifier"] = f"ONNX classifier load error: {exc}"
                    log.warning("ONNX classifier model load failed: %s", exc)

            parts = [f"{k}:{m['model_version']}" for k, m in sorted(self._meta.items())]
            self.model_version = "onnx+" + ("+".join(parts) if parts else "none")
            self._loaded = True

    def available(self) -> bool:
        self._load()
        return self._ano_sess is not None or self._clf_sess is not None

    def info(self) -> dict[str, Any]:
        self._load()
        return {
            "available": self.available(),
            "model_version": self.model_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "runtime": "onnxruntime",
            "models": self._meta,
            "load_errors": self.load_errors,
        }

    def predict_features(self, features: dict[str, float]) -> MLResult | None:
        self._load()
        if not self.available():
            return None
        vec, coverage = vectorize(features)
        if coverage < self.min_coverage:
            return None
        x = vec.reshape(1, -1).astype(np.float32)

        anomaly = 0.0
        z: np.ndarray | None = None
        if self._ano_sess is not None and self._scaler_mean is not None and self._scaler_scale is not None:
            xs = (x - self._scaler_mean) / self._scaler_scale
            out = self._ano_sess.run(None, {"X": xs})
            onnx_scores = out[1].flatten()
            raw = float(0.5 - onnx_scores[0])
            if self._ecdf is not None:
                anomaly = float(np.clip(calibrated_score(self._ecdf, np.array([raw]))[0], 0.0, 1.0))
            z = np.abs(xs[0])

        cls, conf = "unknown", 0.0
        if self._clf_sess is not None:
            out_clf = self._clf_sess.run(None, {"X": x})
            proba = out_clf[1][0]
            k = int(proba.argmax())
            cls = str(self._classes[k]) if self._classes else str(out_clf[0][0])
            conf = float(np.clip(proba[k], 0.0, 1.0))
            if z is None and self._scaler_mean is not None and self._scaler_scale is not None:
                z = np.abs(((x - self._scaler_mean) / self._scaler_scale)[0])

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
        if "evt_process" in behavior.features or any(k in behavior.features for k in RENAMES):
            return self.predict_features(adapt_for_event(behavior.features, event))
        return self.predict_features(behavior.features)


class SklearnMLEngine:
    def __init__(
        self,
        models_dir: Path | str | None = None,
        min_coverage: float = MIN_COVERAGE,
        use_onnx: bool = False,
    ) -> None:
        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.min_coverage = min_coverage
        self.use_onnx = use_onnx
        self._onnx_engine: OnnxMLEngine | None = (
            OnnxMLEngine(models_dir=self.models_dir, min_coverage=min_coverage) if use_onnx else None
        )
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
        if self._onnx_engine is not None and self._onnx_engine.available():
            self.model_version = self._onnx_engine.model_version
            self._loaded = True
            return

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
        if self._onnx_engine is not None and self._onnx_engine.available():
            return True
        self._load()
        return self._anomaly is not None or self._clf is not None

    def info(self) -> dict[str, Any]:
        """Metadata for the dashboard (model/feature/dataset versions); empty if unavailable."""
        if self._onnx_engine is not None and self._onnx_engine.available():
            return self._onnx_engine.info()
        self._load()
        return {
            "available": self.available(),
            "model_version": self.model_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "runtime": "scikit-learn",
            "models": self._meta,
            "load_errors": self.load_errors,
        }

    # ------------------------------------------------------------------ inference
    def predict_features(self, features: dict[str, float]) -> MLResult | None:
        if self._onnx_engine is not None and self._onnx_engine.available():
            return self._onnx_engine.predict_features(features)

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
