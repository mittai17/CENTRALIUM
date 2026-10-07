from __future__ import annotations

from pathlib import Path

import pytest

from ml.datasets.synthetic import write_dataset
from ml.training.data import extract_features, load_dataset, split_dataset
from ml.training.train import train_anomaly, train_classifier

SEED = 7


@pytest.fixture(scope="session")
def small_data(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("ds")
    write_dataset(d, seed=SEED, scale=0.5)
    extract_features(d)
    return d


@pytest.fixture(scope="session")
def trained(small_data: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    models = tmp_path_factory.mktemp("models")
    parts = split_dataset(load_dataset(small_data), SEED)
    train_anomaly(parts["train"], parts["val"], models, SEED)
    train_classifier(parts["train"], models, SEED)
    return models
