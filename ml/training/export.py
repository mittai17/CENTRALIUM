"""Optional ONNX export (needs ``skl2onnx``; ``onnxruntime`` to verify parity)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from ml.features.schema import N_FEATURES
from ml.training.train import ANOMALY_FILE, CLASSIFIER_FILE, load_bundle


def export_onnx(models_dir: Path, out_dir: Path | None = None) -> dict[str, Any]:
    out_dir = out_dir or models_dir / "onnx"
    try:
        from skl2onnx import to_onnx  # type: ignore[import-untyped,unused-ignore]
    except ImportError:
        return {"status": "skipped", "reason": "skl2onnx not installed (pip install skl2onnx onnxruntime)"}
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"status": "ok", "models": {}}
    sample = np.zeros((1, N_FEATURES), dtype=np.float32)
    for fname, stem in ((CLASSIFIER_FILE, "classifier_rf"), (ANOMALY_FILE, "anomaly_iforest")):
        try:
            bundle, _ = load_bundle(models_dir, fname)
            # IsolationForest ONNX expects pre-scaled input; the scaler is exported separately as
            # mean/scale arrays in the sidecar JSON (applied by the consumer).
            model = bundle["model"]
            onx = to_onnx(
                model,
                sample,
                options={id(model): {"zipmap": False}} if stem == "classifier_rf" else None,
                target_opset={"": 17, "ai.onnx.ml": 3},
            )
            path = out_dir / f"{stem}.onnx"
            path.write_bytes(onx.SerializeToString())
            entry: dict[str, Any] = {"path": str(path), "bytes": path.stat().st_size}
            if stem == "anomaly_iforest":
                sc = bundle["scaler"]
                (out_dir / f"{stem}.scaler.json").write_text(
                    json.dumps({"mean": sc.mean_.tolist(), "scale": sc.scale_.tolist()})
                )
            entry["parity"] = _parity(path, bundle, stem)
            result["models"][stem] = entry
        except Exception as exc:
            result["models"][stem] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    return result


def _parity(path: Path, bundle: dict[str, Any], stem: str) -> dict[str, Any]:
    try:
        import onnxruntime as ort
    except ImportError:
        return {"status": "skipped", "reason": "onnxruntime not installed"}
    rng = np.random.default_rng(0)
    X = np.abs(rng.normal(1.0, 1.0, size=(200, N_FEATURES))).astype(np.float32)
    sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    name = sess.get_inputs()[0].name
    outs = sess.run(
        None, {name: X if stem == "classifier_rf" else bundle["scaler"].transform(X).astype(np.float32)}
    )
    if stem == "classifier_rf":
        ref = bundle["model"].predict_proba(X)
        got = np.asarray(outs[1])
        return {
            "status": "ok",
            "max_abs_diff_proba": float(np.abs(ref - got).max()),
            "label_agreement": float((np.asarray(outs[0]).astype(str) == bundle["model"].predict(X)).mean()),
        }
    ref = bundle["model"].decision_function(bundle["scaler"].transform(X))
    got = np.asarray(outs[1]).reshape(-1)
    return {"status": "ok", "max_abs_diff_decision": float(np.abs(ref - got).max())}
