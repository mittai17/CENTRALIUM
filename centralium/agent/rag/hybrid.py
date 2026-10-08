"""Hybrid retrieval combining BM25 lexical scoring and vector similarity.

Implements Okapi BM25, Reciprocal Rank Fusion (RRF), and weighted linear combination
for hybrid search over the centralium RAG knowledge base.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from centralium.agent.models import RAGDocument
from centralium.agent.rag.embedder import CachedEmbedder, Embedder, HashingEmbedder, tokenize
from centralium.agent.rag.ingestion import IngestReport, ingest_directory
from centralium.agent.rag.store import StoredDoc, VectorStore, open_store

log = logging.getLogger("centralium.rag.hybrid")

_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
MIN_K, MAX_K = 3, 5


class BM25Index:
    """In-memory Okapi BM25 index over StoredDoc instances."""

    def __init__(
        self,
        docs: Sequence[StoredDoc] = (),
        *,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> None:
        self.k1 = k1
        self.b = b
        self.docs: list[StoredDoc] = list(docs)
        self.doc_lens: list[int] = []
        self.avgdl: float = 0.0
        self.doc_freq: dict[str, int] = Counter()
        self.term_freqs: list[dict[str, int]] = []
        self._build_index()

    def _build_index(self) -> None:
        self.doc_lens = []
        self.term_freqs = []
        self.doc_freq = Counter()
        total_len = 0

        for d in self.docs:
            combined_text = f"{d.title} {d.text}"
            tokens = tokenize(combined_text)
            counts = Counter(tokens)
            d_len = len(tokens)
            self.doc_lens.append(d_len)
            self.term_freqs.append(dict(counts))
            total_len += d_len
            for term in counts:
                self.doc_freq[term] += 1

        self.avgdl = (total_len / len(self.docs)) if self.docs else 0.0

    def add_docs(self, docs: Sequence[StoredDoc]) -> None:
        self.docs.extend(docs)
        self._build_index()

    def search(self, query: str, k: int = 10) -> list[tuple[StoredDoc, float]]:
        """Okapi BM25 search."""
        if not self.docs or not query.strip():
            return []

        q_tokens = tokenize(query)
        if not q_tokens:
            return []

        n = len(self.docs)
        scores: list[float] = [0.0] * n

        for term in set(q_tokens):
            df = self.doc_freq.get(term, 0)
            if df == 0:
                continue
            # Robertson-Spärck Jones IDF with smoothing
            idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
            if idf <= 0:
                continue

            for i, tf_dict in enumerate(self.term_freqs):
                tf = tf_dict.get(term, 0)
                if tf == 0:
                    continue
                d_len = self.doc_lens[i]
                numerator = tf * (self.k1 + 1.0)
                len_norm = d_len / self.avgdl if self.avgdl else 1.0
                denominator = tf + self.k1 * (1.0 - self.b + self.b * len_norm)
                scores[i] += idf * (numerator / denominator)

        ranked = sorted(enumerate(scores), key=lambda x: -x[1])
        results: list[tuple[StoredDoc, float]] = []
        for i, sc in ranked[:k]:
            if sc > 0:
                results.append((self.docs[i], float(sc)))
        return results


def reciprocal_rank_fusion(
    vector_results: list[tuple[StoredDoc, float]],
    bm25_results: list[tuple[StoredDoc, float]],
    k_rrf: int = 60,
) -> list[tuple[StoredDoc, float]]:
    """Compute Reciprocal Rank Fusion (RRF) score for each doc.

    score(d) = sum(1 / (k_rrf + rank(d, source)))
    """
    scores: dict[str, float] = {}
    doc_map: dict[str, StoredDoc] = {}

    for rank, (doc, _) in enumerate(vector_results, start=1):
        scores[doc.doc_id] = scores.get(doc.doc_id, 0.0) + 1.0 / (k_rrf + rank)
        doc_map[doc.doc_id] = doc

    for rank, (doc, _) in enumerate(bm25_results, start=1):
        scores[doc.doc_id] = scores.get(doc.doc_id, 0.0) + 1.0 / (k_rrf + rank)
        doc_map[doc.doc_id] = doc

    sorted_docs = sorted(scores.items(), key=lambda kv: -kv[1])
    return [(doc_map[doc_id], score) for doc_id, score in sorted_docs]


def weighted_rerank(
    vector_results: list[tuple[StoredDoc, float]],
    bm25_results: list[tuple[StoredDoc, float]],
    alpha: float = 0.5,
) -> list[tuple[StoredDoc, float]]:
    """Linear combination of normalized vector and BM25 scores.

    score(d) = alpha * vec_norm + (1 - alpha) * bm25_norm
    """
    doc_map: dict[str, StoredDoc] = {}
    vec_scores: dict[str, float] = {}
    bm25_scores: dict[str, float] = {}

    for doc, s in vector_results:
        vec_scores[doc.doc_id] = s
        doc_map[doc.doc_id] = doc

    for doc, s in bm25_results:
        bm25_scores[doc.doc_id] = s
        doc_map[doc.doc_id] = doc

    # Normalize vector scores to 0..1
    v_max = max(vec_scores.values()) if vec_scores else 1.0
    v_min = min(vec_scores.values()) if vec_scores else 0.0
    v_denom = (v_max - v_min) or 1.0

    # Normalize BM25 scores to 0..1
    b_max = max(bm25_scores.values()) if bm25_scores else 1.0
    b_min = min(bm25_scores.values()) if bm25_scores else 0.0
    b_denom = (b_max - b_min) or 1.0

    final_scores: dict[str, float] = {}
    for doc_id in doc_map:
        v_norm = (vec_scores.get(doc_id, v_min) - v_min) / v_denom if doc_id in vec_scores else 0.0
        b_norm = (bm25_scores.get(doc_id, b_min) - b_min) / b_denom if doc_id in bm25_scores else 0.0
        final_scores[doc_id] = alpha * v_norm + (1.0 - alpha) * b_norm

    sorted_docs = sorted(final_scores.items(), key=lambda kv: -kv[1])
    return [(doc_map[doc_id], score) for doc_id, score in sorted_docs]


class HybridRetriever:
    """Hybrid RAG retriever combining vector search (sqlite-vec / numpy) and BM25 lexical search."""

    def __init__(
        self,
        store: VectorStore,
        embedder: Embedder,
        *,
        mode: Literal["rrf", "weighted"] = "rrf",
        rrf_k: int = 60,
        alpha: float = 0.5,
        min_score: float = 0.01,
        max_per_file: int = 2,
    ) -> None:
        self.store = store
        self.embedder = embedder if isinstance(embedder, CachedEmbedder) else CachedEmbedder(embedder)
        self.mode = mode
        self.rrf_k = rrf_k
        self.alpha = alpha
        self.min_score = min_score
        self.max_per_file = max_per_file
        self._lock = threading.Lock()
        self.last_latency_ms = 0.0
        self.bm25_index = BM25Index()
        self._refresh_bm25()

    def _refresh_bm25(self) -> None:
        """Fetch all documents from the store's SQLite database to build BM25 index."""
        docs: list[StoredDoc] = []
        db = getattr(self.store, "_db", None)
        if db is not None:
            with getattr(self.store, "_lock", threading.Lock()):
                cur = db.execute("SELECT doc_id, source, title, text, content_hash, metadata FROM rag_docs")
                import json

                for r in cur.fetchall():
                    docs.append(
                        StoredDoc(
                            doc_id=r["doc_id"],
                            source=r["source"],
                            title=r["title"],
                            text=r["text"],
                            content_hash=r["content_hash"],
                            metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                        )
                    )
        self.bm25_index = BM25Index(docs)

    def bm25_search(self, query: str, k: int = 10) -> list[tuple[StoredDoc, float]]:
        return self.bm25_index.search(query, k)

    def vector_search(self, query: str, k: int = 10) -> list[tuple[StoredDoc, float]]:
        qv = self.embedder.embed(query)
        return self.store.search(qv, k)

    def retrieve(self, query: str, k: int = 4) -> list[RAGDocument]:
        """Hybrid retrieval combining BM25 and vector search with RRF or weighted reranking."""
        k = max(MIN_K, min(MAX_K, k))
        q = " ".join(query.split())[:2000]
        if not q or self.store.count() == 0:
            return []

        t0 = time.perf_counter()
        candidate_k = k * 4

        try:
            vec_res = self.vector_search(q, candidate_k)
            bm25_res = self.bm25_search(q, candidate_k)

            if self.mode == "rrf":
                fused = reciprocal_rank_fusion(vec_res, bm25_res, k_rrf=self.rrf_k)
            else:
                fused = weighted_rerank(vec_res, bm25_res, alpha=self.alpha)

        except Exception as exc:
            log.warning("Hybrid retrieval failed: %s", exc)
            return []

        # MITRE technique ID mention boost
        ids = {t.upper() for t in _TECH.findall(q)}
        boosted = [(doc, score + (0.05 if self._mentions(doc, ids) else 0.0)) for doc, score in fused]
        boosted.sort(key=lambda x: -x[1])

        docs: list[RAGDocument] = []
        per_file: dict[str, int] = {}

        for d, s in boosted:
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
            metadata={**d.metadata, "attribution": f"{d.source}/{d.doc_id}", "retrieval_mode": "hybrid"},
        )

    def info(self) -> dict[str, Any]:
        return {
            "retriever_type": "hybrid",
            "store_backend": self.store.backend,
            "embedder": self.embedder.name,
            "mode": self.mode,
            "rrf_k": self.rrf_k,
            "alpha": self.alpha,
            "indexed_docs": len(self.bm25_index.docs),
            "last_latency_ms": round(self.last_latency_ms, 3),
        }

    def close(self) -> None:
        self.store.close()


def build_hybrid_retriever(
    rag_dir: Path | str = "rag",
    db_path: Path | str | None = None,
    *,
    embedder: Embedder | None = None,
    prefer_store: str = "auto",
    mode: Literal["rrf", "weighted"] = "rrf",
    force_reindex: bool = False,
) -> tuple[HybridRetriever, IngestReport]:
    """Ingest documents and instantiate HybridRetriever."""
    rag_dir = Path(rag_dir)
    emb = embedder or HashingEmbedder()
    store = open_store(db_path or rag_dir / "index.db", emb.dim, prefer_store)
    rep = ingest_directory(rag_dir / "documents", store, emb, force=force_reindex)
    return HybridRetriever(store, emb, mode=mode), rep
