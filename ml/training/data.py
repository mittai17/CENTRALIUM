"""Dataset loading, feature extraction (jsonl -> matrix) and leakage-safe group splitting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.datasets.scenarios import BENIGN
from ml.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, N_FEATURES, vectorize

SPLITS = ("train", "val", "test")
FRACTIONS = (0.6, 0.2, 0.2)
MIN_GROUPS_PER_SCENARIO = 3


class DatasetError(RuntimeError):
    pass


@dataclass
class Dataset:
    X: np.ndarray
    labels: np.ndarray  # classifier class strings
    groups: np.ndarray
    scenarios: np.ndarray
    meta: dict[str, Any]

    @property
    def malicious(self) -> np.ndarray:
        return np.asarray((self.labels != BENIGN).astype(int))

    def __len__(self) -> int:
        return int(self.X.shape[0])


def group_split(
    groups: np.ndarray, scenarios: np.ndarray, seed: int, fractions: tuple[float, float, float] = FRACTIONS
) -> dict[str, str]:
    """Assign every *group* (never a row) to train/val/test, stratified by scenario.

    Returns ``{group_id: split}``. Rows of one group always share a split, so no session/host
    leaks between train and evaluation data.
    """
    rng = np.random.default_rng(seed)
    assignment: dict[str, str] = {}
    for sc in sorted({str(s) for s in scenarios}):
        gids = sorted({str(g) for g, s in zip(groups, scenarios, strict=True) if s == sc})
        if len(gids) < MIN_GROUPS_PER_SCENARIO:
            raise DatasetError(f"scenario {sc!r} has {len(gids)} groups; need >= {MIN_GROUPS_PER_SCENARIO}")
        order = rng.permutation(len(gids))
        n_val = max(1, round(len(gids) * fractions[1]))
        n_test = max(1, round(len(gids) * fractions[2]))
        for rank, idx in enumerate(order):
            split = "val" if rank < n_val else "test" if rank < n_val + n_test else "train"
            assignment[gids[idx]] = split
    return assignment


def extract_features(dataset_dir: Path) -> Path:
    """samples.jsonl -> features.npz (schema-validated, missing keys imputed and counted)."""
    meta_path, samples_path = dataset_dir / "dataset_meta.json", dataset_dir / "samples.jsonl"
    if not (meta_path.exists() and samples_path.exists()):
        raise DatasetError(f"{dataset_dir} has no samples.jsonl/dataset_meta.json; run prepare-dataset")
    meta = json.loads(meta_path.read_text())
    if meta.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise DatasetError(
            f"dataset schema {meta.get('feature_schema_version')} != current "
            f"{FEATURE_SCHEMA_VERSION}; regenerate"
        )
    xs, labels, groups, scen = [], [], [], []
    with samples_path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            vec, cov = vectorize(row["features"])
            if cov < 1.0:
                raise DatasetError(f"sample {row['sample_id']} missing features (coverage {cov:.2f})")
            xs.append(vec)
            labels.append(row["label"])
            groups.append(row["group_id"])
            scen.append(row["scenario"])
    out = dataset_dir / "features.npz"
    np.savez_compressed(
        out,
        X=np.vstack(xs),
        labels=np.array(labels),
        groups=np.array(groups),
        scenarios=np.array(scen),
        feature_names=np.array(FEATURE_NAMES),
        schema_version=np.array(FEATURE_SCHEMA_VERSION),
    )
    return out


def load_dataset(dataset_dir: Path) -> Dataset:
    path = dataset_dir / "features.npz"
    if not path.exists():
        raise DatasetError(f"{path} missing; run extract-features")
    z = np.load(path, allow_pickle=False)
    if (
        tuple(z["feature_names"].tolist()) != FEATURE_NAMES
        or str(z["schema_version"]) != FEATURE_SCHEMA_VERSION
    ):
        raise DatasetError("features.npz does not match current feature schema; re-run extract-features")
    meta = json.loads((dataset_dir / "dataset_meta.json").read_text())
    X = z["X"]
    assert X.shape[1] == N_FEATURES
    return Dataset(X, z["labels"], z["groups"], z["scenarios"], meta)


def split_dataset(ds: Dataset, seed: int) -> dict[str, Dataset]:
    assignment = group_split(ds.groups, ds.scenarios, seed)
    out: dict[str, Dataset] = {}
    row_split = np.array([assignment[str(g)] for g in ds.groups])
    for name in SPLITS:
        m = row_split == name
        out[name] = Dataset(ds.X[m], ds.labels[m], ds.groups[m], ds.scenarios[m], ds.meta)
    return out
