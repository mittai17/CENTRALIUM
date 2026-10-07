"""Local RAG: SQLite(+sqlite-vec) vector store, offline embedders, retriever."""

from centralium.agent.rag.embedder import (
    CachedEmbedder,
    Embedder,
    HashingEmbedder,
    LlamaServerEmbedder,
    SentenceTransformerEmbedder,
    build_embedder,
)
from centralium.agent.rag.ingestion import IngestReport, ingest_directory
from centralium.agent.rag.retriever import LocalRAGRetriever, build_retriever
from centralium.agent.rag.store import NumpySQLiteStore, SqliteVecStore, StoredDoc, VectorStore, open_store

__all__ = [
    "CachedEmbedder",
    "Embedder",
    "HashingEmbedder",
    "IngestReport",
    "LlamaServerEmbedder",
    "LocalRAGRetriever",
    "NumpySQLiteStore",
    "SentenceTransformerEmbedder",
    "SqliteVecStore",
    "StoredDoc",
    "VectorStore",
    "build_embedder",
    "build_retriever",
    "ingest_directory",
    "open_store",
]
