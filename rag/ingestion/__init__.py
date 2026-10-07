"""Ingestion entry points (implementation lives in ``centralium.agent.rag.ingestion``)."""

from centralium.agent.rag.ingestion import IngestReport, ingest_directory, load_documents

__all__ = ["IngestReport", "ingest_directory", "load_documents"]
