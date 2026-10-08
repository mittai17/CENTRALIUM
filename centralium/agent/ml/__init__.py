"""ML engine (Isolation Forest + Random Forest). See engine.py."""

from __future__ import annotations

from pathlib import Path

from centralium.agent.ml.active_learning import (
    ActiveLearningItem,
    ActiveLearningQueue,
    QueueItemStatus,
    UncertaintyFactor,
    calculate_entropy,
    compute_uncertainty_score,
)
from centralium.agent.ml.drift import (
    DriftAlert,
    DriftReport,
    FeatureDriftMetric,
    FeatureDriftMonitor,
    calculate_ks,
    calculate_psi,
)
from centralium.agent.ml.engine import OnnxMLEngine, SklearnMLEngine
from centralium.agent.ml.feedback import (
    AnalystFeedbackRecord,
    AnalystFeedbackStore,
    FeedbackSuggestion,
    FeedbackType,
    RetrainingDataset,
    SuggestionKind,
    SuggestionStatus,
)
from centralium.agent.ml.provenance_model import (
    ModelComparisonMetrics,
    ProvenanceAnomalyResult,
    ProvenanceGraphAnomalyModel,
    compare_with_isolation_forest,
)
from centralium.agent.ml.registry import (
    ModelMetadata,
    ModelRegistry,
    ShadowComparisonReport,
    ShadowEvaluator,
    ShadowEventComparison,
    sign_digest,
    verify_digest_signature,
)
from centralium.agent.ml.sequence_model import (
    MarkovSequenceModel,
    SequenceAnomalyResult,
    TransitionSurprisal,
)
from centralium.agent.ml.static_classifier import (
    StaticMalwareClassifier,
    StaticScanResult,
)


def create_ml_engine(
    models_dir: Path | str | None = None,
    auto_install: bool = False,
    use_onnx: bool = False,
) -> SklearnMLEngine | OnnxMLEngine:
    """Build the engine. With ``auto_install=True`` missing default models are trained from
    synthetic data first (slow: seconds) so the system works out of the box."""
    if use_onnx:
        engine: SklearnMLEngine | OnnxMLEngine = OnnxMLEngine(models_dir)
        if engine.available():
            return engine

    engine = SklearnMLEngine(models_dir, use_onnx=use_onnx)
    if auto_install and not engine.available():
        install_default_models(models_dir)
        engine = SklearnMLEngine(models_dir, use_onnx=use_onnx)
    return engine


def install_default_models(models_dir: Path | str | None = None, seed: int = 1337) -> dict[str, object]:
    """Train + install default models from synthetic data (labelled synthetic in metadata)."""
    import tempfile

    from ml.training.pipeline import DEFAULT_MODELS_DIR
    from ml.training.pipeline import install_default_models as _install

    target = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    with tempfile.TemporaryDirectory(prefix="centralium-ml-") as tmp:
        return _install(target, Path(tmp), seed)


__all__ = [
    "ActiveLearningItem",
    "ActiveLearningQueue",
    "AnalystFeedbackRecord",
    "AnalystFeedbackStore",
    "DriftAlert",
    "DriftReport",
    "FeatureDriftMetric",
    "FeatureDriftMonitor",
    "FeedbackSuggestion",
    "FeedbackType",
    "MarkovSequenceModel",
    "ModelComparisonMetrics",
    "ModelMetadata",
    "ModelRegistry",
    "OnnxMLEngine",
    "ProvenanceAnomalyResult",
    "ProvenanceGraphAnomalyModel",
    "QueueItemStatus",
    "RetrainingDataset",
    "SequenceAnomalyResult",
    "ShadowComparisonReport",
    "ShadowEvaluator",
    "ShadowEventComparison",
    "SklearnMLEngine",
    "StaticMalwareClassifier",
    "StaticScanResult",
    "SuggestionKind",
    "SuggestionStatus",
    "TransitionSurprisal",
    "UncertaintyFactor",
    "calculate_entropy",
    "calculate_ks",
    "calculate_psi",
    "compare_with_isolation_forest",
    "compute_uncertainty_score",
    "create_ml_engine",
    "install_default_models",
    "sign_digest",
    "verify_digest_signature",
]
