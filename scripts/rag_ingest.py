#!/usr/bin/env python
"""Build/refresh the local RAG index and optionally run a test query.

.venv/bin/python scripts/rag_ingest.py [--rag-dir rag] [--db PATH] [--force] [--query "text"]
"""

from __future__ import annotations

import argparse
import json
import sys

from centralium.agent.rag import build_retriever


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rag-dir", default="rag")
    ap.add_argument("--db", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--store", default="auto", choices=["auto", "sqlite-vec", "numpy"])
    ap.add_argument("--query", default=None)
    ap.add_argument("-k", type=int, default=4)
    a = ap.parse_args(argv)
    ret, rep = build_retriever(a.rag_dir, a.db, prefer_store=a.store, force_reindex=a.force)
    print(json.dumps({"ingest": rep.as_dict(), "index": ret.info()}, indent=2))
    if a.query:
        for d in ret.retrieve(a.query, a.k):
            print(f"{d.score:.3f}  {d.source}/{d.doc_id}  {d.title}")
    ret.close()
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
