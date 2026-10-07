"""End-to-end helpers: prepare -> extract -> train (used by CLI and default-model install)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ml.datasets.synthetic import DEFAULT_SEED, write_dataset
from ml.training.data import extract_features, load_dataset, split_dataset
from ml.training.train import train_anomaly, train_classifier

DEFAULT_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "datasets" / "data" / "synthetic"


def train_all(dataset_dir: Path, models_dir: Path, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    ds = load_dataset(dataset_dir)
    parts = split_dataset(ds, seed)
    a = train_anomaly(parts["train"], parts["val"], models_dir, seed)
    c = train_classifier(parts["train"], models_dir, seed)
    return {"anomaly": a, "classifier": c}


def install_default_models(
    models_dir: Path | None = None,
    work_dir: Path | None = None,
    seed: int = DEFAULT_SEED,
    scale: float = 1.0,
) -> dict[str, Any]:
    """Generate the synthetic dataset and (re)train both default models. Deterministic given seed."""
    models_dir = models_dir or DEFAULT_MODELS_DIR
    work_dir = work_dir or DEFAULT_DATA_DIR
    write_dataset(work_dir, seed=seed, scale=scale)
    extract_features(work_dir)
    return train_all(work_dir, models_dir, seed)
