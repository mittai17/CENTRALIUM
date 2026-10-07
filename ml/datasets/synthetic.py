"""Deterministic SYNTHETIC feature-dataset generator.

Honesty notice: all rows are sampled from hand-written priors (``scenarios.py``). Any metric
computed on them measures separability of *these priors*, not real-world detection quality.
Datasets carry ``"synthetic": true`` in their metadata and metrics reports propagate it.

Hardness knobs (so results are not trivially perfect): per-group variation of means, per-sample
noise, "stealth" malicious groups blended toward benign, and "rare-benign" groups (admin-like)
blended toward a malicious profile but labelled benign.
"""

from __future__ import annotations

import hashlib
import json
import platform
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.datasets.scenarios import SCENARIOS, Scenario
from ml.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FEATURE_SPECS, FeatureSpec

GENERATOR_VERSION = "1.0"
DEFAULT_SEED = 1337
STEALTH_PROB = 0.25  # malicious groups that are blended 50% toward benign
RARE_BENIGN_PROB = 0.06  # benign groups blended 40% toward a malicious profile
SAMPLES_PER_GROUP = 20


@dataclass(frozen=True)
class Sample:
    sample_id: str
    group_id: str
    scenario: str
    label: str
    features: dict[str, float]
    variant: str  # "standard" | "stealth" | "rare_benign"


def _group_means(rng: np.random.Generator, sc: Scenario, variant: str, other: Scenario | None) -> np.ndarray:
    base = np.array([s.default for s in FEATURE_SPECS])
    target = base.copy()
    for i, name in enumerate(FEATURE_NAMES):
        if name in sc.means:
            target[i] = sc.means[name]
    if variant == "stealth":
        target = 0.5 * base + 0.5 * target
    elif variant == "rare_benign" and other is not None:
        mal = base.copy()
        for i, name in enumerate(FEATURE_NAMES):
            if name in other.means:
                mal[i] = other.means[name]
        target = 0.6 * target + 0.4 * mal
    # per-group multiplicative / additive jitter
    out = target.copy()
    for i, s in enumerate(FEATURE_SPECS):
        if s.kind == "count":
            out[i] = target[i] * rng.lognormal(0, 0.3)
        elif s.kind == "entropy":
            out[i] = target[i] + rng.normal(0, 0.25)
        else:
            out[i] = np.clip(target[i] + rng.normal(0, 0.05 + 0.1 * target[i]), 0, 1)
    return out


def _draw(rng: np.random.Generator, s: FeatureSpec, mean: float) -> float:
    if s.kind == "bin":
        return float(rng.random() < min(max(mean, 0.0), 1.0))
    if s.kind == "count":
        return float(min(max(round(mean * rng.lognormal(0, 0.45)), 0), s.cap))
    if s.kind == "entropy":
        return float(np.clip(rng.normal(mean, 0.35), 0.0, s.cap))
    return float(np.clip(rng.normal(mean, 0.07 + 0.15 * mean), 0.0, 1.0))


def generate_samples(
    seed: int = DEFAULT_SEED, scale: float = 1.0, samples_per_group: int = SAMPLES_PER_GROUP
) -> Iterator[Sample]:
    """Yield samples deterministically. ``scale`` multiplies group counts (min 1)."""
    rng = np.random.default_rng(seed)
    malicious = [s for s in SCENARIOS if s.malicious]
    n = 0
    for sc in SCENARIOS:
        for g in range(max(1, round(sc.groups * scale))):
            r = rng.random()
            variant, other = "standard", None
            if sc.malicious and r < STEALTH_PROB:
                variant = "stealth"
            elif not sc.malicious and r < RARE_BENIGN_PROB:
                variant, other = "rare_benign", malicious[int(rng.integers(len(malicious)))]
            means = _group_means(rng, sc, variant, other)
            gid = f"{sc.name}-g{g:04d}"
            for _ in range(samples_per_group):
                feats = {s.name: _draw(rng, s, float(means[i])) for i, s in enumerate(FEATURE_SPECS)}
                yield Sample(f"s{n:07d}", gid, sc.name, sc.label, feats, variant)
                n += 1


def write_dataset(out_dir: Path, seed: int = DEFAULT_SEED, scale: float = 1.0) -> dict[str, Any]:
    """Write ``samples.jsonl`` + ``dataset_meta.json`` and return the metadata."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "samples.jsonl"
    h = hashlib.sha256()
    count = 0
    per_label: dict[str, int] = {}
    groups: set[str] = set()
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for s in generate_samples(seed, scale):
            line = json.dumps(
                {
                    "sample_id": s.sample_id,
                    "group_id": s.group_id,
                    "scenario": s.scenario,
                    "label": s.label,
                    "variant": s.variant,
                    "features": {k: round(v, 6) for k, v in s.features.items()},
                },
                sort_keys=True,
            )
            fh.write(line + "\n")
            h.update(line.encode())
            count += 1
            per_label[s.label] = per_label.get(s.label, 0) + 1
            groups.add(s.group_id)
    digest = h.hexdigest()[:10]
    meta = {
        "dataset_version": f"synthetic-g{GENERATOR_VERSION}-s{seed}-x{scale:g}-{digest}",
        "synthetic": True,
        "disclaimer": (
            "SYNTHETIC data sampled from hand-written priors; metrics are NOT real-world performance."
        ),
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "scale": scale,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "n_samples": count,
        "n_groups": len(groups),
        "samples_per_group": SAMPLES_PER_GROUP,
        "per_label": dict(sorted(per_label.items())),
        "sha256_prefix": digest,
        "python": platform.python_version(),
        "numpy": np.__version__,
    }
    (out_dir / "dataset_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return meta
