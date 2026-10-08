"""Local RAG: SQLite(+sqlite-vec) vector store, offline embedders, retriever."""

from centralium.agent.rag.embedder import (
    CachedEmbedder,
    Embedder,
    HashingEmbedder,
    LlamaServerEmbedder,
    SentenceTransformerEmbedder,
    build_embedder,
)
from centralium.agent.rag.hybrid import (
    BM25Index,
    HybridRetriever,
    build_hybrid_retriever,
    reciprocal_rank_fusion,
    weighted_rerank,
)
from centralium.agent.rag.ingestion import IngestReport, ingest_directory
from centralium.agent.rag.retriever import LocalRAGRetriever, build_retriever
from centralium.agent.rag.store import NumpySQLiteStore, SqliteVecStore, StoredDoc, VectorStore, open_store

__all__ = [
    "BM25Index",
    "CachedEmbedder",
    "Embedder",
    "HashingEmbedder",
    "HybridRetriever",
    "IngestReport",
    "LlamaServerEmbedder",
    "LocalRAGRetriever",
    "NumpySQLiteStore",
    "SentenceTransformerEmbedder",
    "SqliteVecStore",
    "StoredDoc",
    "VectorStore",
    "build_embedder",
    "build_hybrid_retriever",
    "build_retriever",
    "ingest_directory",
    "open_store",
    "reciprocal_rank_fusion",
    "weighted_rerank",
]
