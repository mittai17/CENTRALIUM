# Local RAG

RAG supplies background knowledge to the LLM for **gated high-risk events only** (the pipeline
decides; known-malicious, allowlisted and low-risk events never reach it). It is not a detector.

## Components (`centralium/agent/rag`)

| Piece | File | Notes |
|---|---|---|
| Vector store abstraction | `store.py` | `VectorStore` ABC (Qdrant could be added behind it). `SqliteVecStore` = SQLite + sqlite-vec `vec0` (cosine); `NumpySQLiteStore` = vectors in BLOBs + brute-force numpy. `open_store(prefer="auto")` falls back with a log warning if the extension cannot load. |
| Embedders | `embedder.py` | Default `HashingEmbedder`: deterministic signed-hash TF-IDF over unigrams+bigrams (no downloads). **It is lexical**: it matches shared words/IDs, not meaning, so paraphrases and synonyms can miss. Optional `SentenceTransformerEmbedder` (local files only) and `LlamaServerEmbedder` (loopback `/v1/embeddings`); both fall back to hashing if unavailable. |
| Caches | `embedder.py`, `retriever.py` | In-memory LRU for embeddings (keyed by text hash + embedder fingerprint) and for retrieval results (keyed by query, k and index version; returns copies). Indexed vectors persist in SQLite. |
| Ingestion | `ingestion.py` (also `rag/ingestion`) | Incremental by content hash; removes chunks of deleted files; refits IDF and re-embeds when content changes (corpus is small). |
| Retriever | `retriever.py` | `LocalRAGRetriever.retrieve(query, k)`: k clamped to 3-5, max 2 chunks per file, explicit `Txxxx` IDs in the query are boosted, returns `RAGDocument` with `source`, `doc_id`, `score`, `metadata["attribution"]`. Returns `[]` on any failure. `info()` reports backend, embedder, lexical flag, cache stats. |

## Knowledge (`rag/documents`)

Original, concise text written for this project (not copied from MITRE or vendor material):
`mitre_attack.json` (53 techniques with id, tactic, platforms, description, detection ideas),
`centralium_rules.md`, `yara_metadata.md`, `lolbins_windows.md`, `lolbins_linux.md`,
`malware_behavior.md`, `ransomware.md`, `persistence.md`, `response_playbooks.md`,
`incident_knowledge.md`. Technique IDs are ATT&CK identifiers; descriptions are paraphrased summaries
and may be incomplete. Add files as Markdown (`## ` sections become chunks; front matter
`source:`/`title:`/`tags:`) or JSON (`techniques` or `documents` arrays) and re-run ingestion.

## Usage

```bash
.venv/bin/python scripts/rag_ingest.py --query "vssadmin delete shadows" [--force] [--store numpy]
```

```python
from centralium.agent.rag import build_retriever

rag, report = build_retriever("rag", "data/rag_index.db")  # ingests rag/documents incrementally
pipeline = Pipeline(config, rag=rag, llm=llm)
```

Limitations: lexical matching only by default (use an embedding backend for semantic recall);
relevance is verified on a small set of known queries, not a benchmark; the index is rebuilt in
full when any document changes.
