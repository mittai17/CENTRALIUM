"""Authoritative, versioned ML feature schema for Centralium.

Bump ``FEATURE_SCHEMA_VERSION`` whenever a feature is added/removed/reordered/re-scaled:
models record the version they were trained on and the runtime refuses silent drift.

Runtime adapter contract: the BehaviorEngine emits ``dict[str, float]`` keyed by feature
*name*; :func:`vectorize` maps it to the fixed column order and tolerates missing keys
(imputed with the benign default) while reporting coverage.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np

FEATURE_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    family: str
    kind: str  # "unit" [0,1] | "bin" {0,1} | "count" >=0 | "entropy" [0,8]
    cap: float  # hard upper clip
    default: float  # benign/imputation default


def _f(family: str, rows: list[tuple[str, str, float, float]]) -> list[FeatureSpec]:
    return [FeatureSpec(n, family, k, c, d) for n, k, c, d in rows]


FEATURE_SPECS: tuple[FeatureSpec, ...] = tuple(
    _f(
        "process",
        [
            ("proc_frequency", "unit", 1.0, 0.6),
            ("parent_child_rarity", "unit", 1.0, 0.1),
            ("child_count", "count", 100.0, 3.0),
            ("process_rarity", "unit", 1.0, 0.1),
            ("executable_rarity", "unit", 1.0, 0.1),
            ("unsigned_binary", "bin", 1.0, 0.15),
            ("path_risk", "unit", 1.0, 0.1),
            ("privileged_context", "bin", 1.0, 0.1),
        ],
    )
    + _f(
        "network",
        [
            ("net_conn_count", "count", 500.0, 5.0),
            ("net_unique_dest", "count", 200.0, 3.0),
            ("net_dest_rarity", "unit", 1.0, 0.15),
            ("net_port_rarity", "unit", 1.0, 0.1),
            ("net_domain_rarity", "unit", 1.0, 0.15),
            ("dns_entropy", "entropy", 8.0, 2.8),
            ("ip_reputation_risk", "unit", 1.0, 0.03),
            ("net_conn_burst", "unit", 1.0, 0.1),
        ],
    )
    + _f(
        "file",
        [
            ("file_create_rate", "count", 2000.0, 4.0),
            ("file_modify_rate", "count", 2000.0, 10.0),
            ("file_delete_rate", "count", 2000.0, 1.0),
            ("file_rename_rate", "count", 2000.0, 1.0),
            ("file_ext_change_rate", "unit", 1.0, 0.01),
            ("file_write_entropy", "entropy", 8.0, 4.5),
            ("suspicious_dir_write", "unit", 1.0, 0.05),
            ("executable_created", "bin", 1.0, 0.03),
        ],
    )
    + _f(
        "behavior",
        [
            ("powershell_use", "bin", 1.0, 0.03),
            ("lolbin_use", "bin", 1.0, 0.04),
            ("script_interpreter_use", "bin", 1.0, 0.12),
            ("persistence_modification", "bin", 1.0, 0.01),
            ("privilege_change", "bin", 1.0, 0.03),
            ("injection_indicator", "bin", 1.0, 0.005),
            ("unusual_parent_child", "unit", 1.0, 0.06),
            ("download_execute_sequence", "bin", 1.0, 0.01),
            ("encoded_command", "bin", 1.0, 0.01),
            ("cmdline_entropy", "entropy", 8.0, 3.2),
            ("cmdline_length", "count", 2000.0, 60.0),
        ],
    )
    + _f(
        "ransomware",
        [
            ("write_burst", "unit", 1.0, 0.05),
            ("rename_burst", "unit", 1.0, 0.03),
            ("ext_mutation", "unit", 1.0, 0.01),
            ("entropy_increase", "unit", 1.0, 0.05),
            ("shadow_copy_activity", "bin", 1.0, 0.002),
        ],
    )
)

FEATURE_NAMES: tuple[str, ...] = tuple(s.name for s in FEATURE_SPECS)
N_FEATURES = len(FEATURE_NAMES)
FEATURE_INDEX: dict[str, int] = {n: i for i, n in enumerate(FEATURE_NAMES)}
FEATURE_FAMILIES: dict[str, tuple[str, ...]] = {}
for _s in FEATURE_SPECS:
    FEATURE_FAMILIES[_s.family] = (*FEATURE_FAMILIES.get(_s.family, ()), _s.name)
DEFAULTS = np.array([s.default for s in FEATURE_SPECS], dtype=np.float64)
CAPS = np.array([s.cap for s in FEATURE_SPECS], dtype=np.float64)

#: Optional aliases so another producer's names can be mapped without code changes.
FEATURE_ALIASES: dict[str, str] = {}


def schema_fingerprint() -> str:
    """Stable hash of names+kinds+caps (detects accidental schema edits without a version bump)."""
    import hashlib

    h = hashlib.sha256()
    for s in FEATURE_SPECS:
        h.update(f"{s.name}|{s.family}|{s.kind}|{s.cap}|{s.default};".encode())
    return h.hexdigest()[:16]


def vectorize(features: Mapping[str, float]) -> tuple[np.ndarray, float]:
    """Map a name->value dict to a ``(N_FEATURES,)`` float vector.

    Missing / non-finite / non-numeric values are imputed with the benign default.
    Unknown keys are ignored. Returns ``(vector, coverage)`` where coverage is the
    fraction of schema features that were actually supplied.
    """
    vec = DEFAULTS.copy()
    supplied = 0
    for key, raw in features.items():
        idx = FEATURE_INDEX.get(FEATURE_ALIASES.get(key, key))
        if idx is None:
            continue
        try:
            v = float(raw)
        except (TypeError, ValueError):
            continue
        if not np.isfinite(v):
            continue
        vec[idx] = min(max(v, 0.0), CAPS[idx])
        supplied += 1
    return vec, supplied / N_FEATURES


def matrix_from_dicts(rows: list[Mapping[str, float]]) -> np.ndarray:
    return np.vstack([vectorize(r)[0] for r in rows]) if rows else np.zeros((0, N_FEATURES))
