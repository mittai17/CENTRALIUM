"""Optional adapters for public defensive datasets (documented STUBS).

Nothing here downloads or redistributes data. Users must obtain datasets themselves and comply
with each licence.

* BETH (https://www.kaggle.com/datasets/katehighnam/beth-dataset): kernel-level process/network
  telemetry with ``sus`` / ``evil`` labels. Mapping idea: group by ``processId``/``hostName``
  windows, derive the schema features in ``ml/features/schema.py`` (process_rarity, child_count,
  net_*), label ``evil`` -> malicious.  Not implemented: raises ``NotImplementedError``.
* DARPA OpTC (https://github.com/FiveDirections/OpTC-data): large ECAR JSON; redistribution is
  restricted. Same approach: window per host/process, aggregate to schema features.

An implementation must yield ``ml.datasets.synthetic.Sample``-compatible rows (features keyed by
FEATURE_NAMES, a ``group_id`` for leakage-safe splitting) and set ``synthetic: false`` in the
dataset metadata only after real validation.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ml.datasets.synthetic import Sample


def load_beth(path: Path) -> Iterator[Sample]:
    raise NotImplementedError("BETH adapter is a documented stub; see module docstring")


def load_optc(path: Path) -> Iterator[Sample]:
    raise NotImplementedError("OpTC adapter is a documented stub; see module docstring")
