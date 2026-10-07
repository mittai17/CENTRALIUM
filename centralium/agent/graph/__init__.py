"""Attack graph: Kuzu adapter + in-memory fallback, chain reconstruction, scoring, stage prediction."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from centralium.agent.graph import mitre
from centralium.agent.graph.core import (
    NEXT_STAGE_PRIORS,
    STAGE_ORDER,
    ChainAnalysis,
    EventRec,
    MemoryGraph,
    StagePrediction,
    predict_stage,
    score_chain,
)
from centralium.agent.graph.kuzu_adapter import KuzuGraphAdapter, KuzuUnavailableError
from centralium.agent.graph.snapshot import graph_snapshot, write_graph_snapshot

log = logging.getLogger("centralium.graph")

InMemoryGraphAdapter = MemoryGraph


def create_graph_adapter(
    path: str | Path | None, *, prefer_kuzu: bool = True, batch_size: int = 500, **kw: Any
) -> MemoryGraph | KuzuGraphAdapter:
    """Kuzu when available and ``path`` given; otherwise the in-memory fallback (same behaviour)."""
    if prefer_kuzu and path is not None:
        try:
            return KuzuGraphAdapter(path, batch_size=batch_size, **kw)
        except KuzuUnavailableError as exc:
            log.warning("kuzu unavailable (%s); using in-memory graph", exc)
    return MemoryGraph(**kw)


__all__ = [
    "NEXT_STAGE_PRIORS",
    "STAGE_ORDER",
    "ChainAnalysis",
    "EventRec",
    "InMemoryGraphAdapter",
    "KuzuGraphAdapter",
    "KuzuUnavailableError",
    "MemoryGraph",
    "StagePrediction",
    "create_graph_adapter",
    "graph_snapshot",
    "mitre",
    "predict_stage",
    "score_chain",
    "write_graph_snapshot",
]
