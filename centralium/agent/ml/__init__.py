"""ML engine (Isolation Forest + Random Forest). See engine.py."""

from __future__ import annotations

from pathlib import Path

from centralium.agent.ml.engine import SklearnMLEngine


def create_ml_engine(models_dir: Path | str | None = None, auto_install: bool = False) -> SklearnMLEngine:
    """Build the engine. With ``auto_install=True`` missing default models are trained from
    synthetic data first (slow: seconds) so the system works out of the box."""
    engine = SklearnMLEngine(models_dir)
    if auto_install and not engine.available():
        install_default_models(models_dir)
        engine = SklearnMLEngine(models_dir)
    return engine


def install_default_models(models_dir: Path | str | None = None, seed: int = 1337) -> dict[str, object]:
    """Train + install default models from synthetic data (labelled synthetic in metadata)."""
    import tempfile

    from ml.training.pipeline import DEFAULT_MODELS_DIR
    from ml.training.pipeline import install_default_models as _install

    target = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    with tempfile.TemporaryDirectory(prefix="centralium-ml-") as tmp:
        return _install(target, Path(tmp), seed)


__all__ = ["SklearnMLEngine", "create_ml_engine", "install_default_models"]
