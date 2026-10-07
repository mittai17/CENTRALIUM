"""RAGRetriever implementation: embed query -> vector search -> attributed RAGDocuments.

Used ONLY for gated high-risk events (the pipeline enforces the gate). Retrieval is
lexical when the default hashing embedder is active; this is reported via ``info()``.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from centralium.agent.models import RAGDocument
from centralium.agent.rag.embedder import CachedEmbedder, Embedder, HashingEmbedder
from centralium.agent.rag.ingestion import INDEX_VERSION_KEY, IngestReport, ingest_directory
from centralium.agent.rag.store import StoredDoc, VectorStore, open_store

log = logging.getLogger("centralium.rag")

_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
MIN_K, MAX_K = 3, 5


class LocalRAGRetriever:
    """Implements ``centralium.agent.interfaces.RAGRetriever``."""

    def __init__(
        self,
        store: VectorStore,
        embedder: Embedder,
        *,
        min_score: float = 0.05,
        cache_size: int = 256,
        max_per_file: int = 2,
    ) -> None:
        self.store = store
        self.embedder = embedder if isinstance(embedder, CachedEmbedder) else CachedEmbedder(embedder)
        self.min_score = min_score
        self.max_per_file = max_per_file
        self._cache: OrderedDict[tuple[str, int, str], list[RAGDocument]] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0
        self.last_latency_ms = 0.0
        st = store.get_meta("embedder_state")
        if st:
            import json

            self.embedder.load_state(json.loads(st))

    # ------------------------------------------------------------------ API
    def retrieve(self, query: str, k: int = 4) -> list[RAGDocument]:
        k = max(MIN_K, min(MAX_K, k))
        q = " ".join(query.split())[:2000]
        if not q or self.store.count() == 0:
            return []
        key = (q.lower(), k, self.store.get_meta(INDEX_VERSION_KEY) or "")
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                self.cache_hits += 1
                return [d.model_copy(deep=True) for d in hit]
            self.cache_misses += 1
        t0 = time.perf_counter()
        try:
            qv = self.embedder.embed(q)
            raw = self.store.search(qv, k * 3)
        except Exception as exc:  # retrieval must never break the pipeline
            log.warning("RAG retrieval failed: %s", exc)
            return []
        ids = {t.upper() for t in _TECH.findall(q)}
        scored = [(d, s + (0.5 if self._mentions(d, ids) else 0.0)) for d, s in raw]
        scored.sort(key=lambda x: -x[1])
        docs: list[RAGDocument] = []
        per_file: dict[str, int] = {}
        for d, s in scored:
            if s < self.min_score and len(docs) >= MIN_K - 1:
                continue
            f = str(d.metadata.get("file", d.doc_id))
            if per_file.get(f, 0) >= self.max_per_file:
                continue
            per_file[f] = per_file.get(f, 0) + 1
            docs.append(self._to_doc(d, s))
            if len(docs) >= k:
                break
        self.last_latency_ms = (time.perf_counter() - t0) * 1000
        with self._lock:
            self._cache[key] = docs
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return [d.model_copy(deep=True) for d in docs]

    @staticmethod
    def _mentions(d: StoredDoc, ids: set[str]) -> bool:
        return bool(ids) and str(d.metadata.get("technique_id", "")).upper() in ids

    @staticmethod
    def _to_doc(d: StoredDoc, score: float) -> RAGDocument:
        return RAGDocument(
            doc_id=d.doc_id,
            source=d.source,
            title=d.title,
            text=d.text,
            score=round(score, 4),
            metadata={**d.metadata, "attribution": f"{d.source}/{d.doc_id}"},
        )

    def info(self) -> dict[str, Any]:
        return {
            "store_backend": self.store.backend,
            "embedder": self.embedder.name,
            "lexical_embeddings": self.embedder.lexical,
            "documents": self.store.count(),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "embedding_cache_hits": self.embedder.hits,
            "last_latency_ms": round(self.last_latency_ms, 3),
        }

    def close(self) -> None:
        self.store.close()


def build_retriever(
    rag_dir: Path | str = "rag",
    db_path: Path | str | None = None,
    *,
    embedder: Embedder | None = None,
    prefer_store: str = "auto",
    force_reindex: bool = False,
) -> tuple[LocalRAGRetriever, IngestReport]:
    """Open/create the index at ``db_path`` (default ``<rag_dir>/index.db``) and ingest
    ``<rag_dir>/documents`` incrementally."""
    rag_dir = Path(rag_dir)
    emb = embedder or HashingEmbedder()
    store = open_store(db_path or rag_dir / "index.db", emb.dim, prefer_store)
    rep = ingest_directory(rag_dir / "documents", store, emb, force=force_reindex)
    return LocalRAGRetriever(store, emb), rep


__all__ = ["LocalRAGRetriever", "build_retriever"]
