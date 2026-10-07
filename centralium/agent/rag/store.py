"""Vector store abstraction: SQLite + sqlite-vec, with a pure numpy/SQLite fallback.

``VectorStore`` is the seam where a Qdrant backend could be added later. Both
shipped backends keep documents and metadata in the same SQLite file (WAL).
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger("centralium.rag.store")


@dataclass
class StoredDoc:
    doc_id: str
    source: str
    title: str
    text: str
    content_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore(ABC):
    backend: str = "abstract"

    @abstractmethod
    def upsert(self, docs: Sequence[StoredDoc], vectors: np.ndarray) -> None: ...
    @abstractmethod
    def delete(self, doc_ids: Sequence[str]) -> None: ...
    @abstractmethod
    def search(self, vector: np.ndarray, k: int) -> list[tuple[StoredDoc, float]]:
        """Top-k by cosine similarity (vectors are L2-normalised), best first."""

    @abstractmethod
    def hashes(self) -> dict[str, str]:
        """doc_id -> content_hash (for incremental ingestion)."""

    @abstractmethod
    def count(self) -> int: ...
    @abstractmethod
    def get_meta(self, key: str) -> str | None: ...
    @abstractmethod
    def set_meta(self, key: str, value: str) -> None: ...
    @abstractmethod
    def clear(self) -> None: ...
    @abstractmethod
    def close(self) -> None: ...


class _SQLiteBase(VectorStore):
    def __init__(self, path: Path | str, dim: int) -> None:
        self.dim = dim
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with contextlib.suppress(sqlite3.DatabaseError):
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS rag_docs(
              rowid INTEGER PRIMARY KEY AUTOINCREMENT,
              doc_id TEXT UNIQUE NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL,
              text TEXT NOT NULL, content_hash TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS rag_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """
        )
        self._init_vectors()

    @abstractmethod
    def _init_vectors(self) -> None: ...
    @abstractmethod
    def _put_vector(self, rowid: int, vec: np.ndarray) -> None: ...
    @abstractmethod
    def _del_vector(self, rowid: int) -> None: ...
    @abstractmethod
    def _knn(self, vec: np.ndarray, k: int) -> list[tuple[int, float]]: ...
    @abstractmethod
    def _clear_vectors(self) -> None: ...

    @staticmethod
    def _row_doc(r: sqlite3.Row) -> StoredDoc:
        return StoredDoc(
            r["doc_id"], r["source"], r["title"], r["text"], r["content_hash"], json.loads(r["metadata"])
        )

    def upsert(self, docs: Sequence[StoredDoc], vectors: np.ndarray) -> None:
        if len(docs) != len(vectors):
            raise ValueError("docs/vectors length mismatch")
        if len(docs) and vectors.shape[1] != self.dim:
            raise ValueError(f"vector dim {vectors.shape[1]} != store dim {self.dim}")
        with self._lock, self._db:
            for d, v in zip(docs, vectors, strict=True):
                row = self._db.execute("SELECT rowid FROM rag_docs WHERE doc_id=?", (d.doc_id,)).fetchone()
                if row:
                    rid = int(row["rowid"])
                    self._db.execute(
                        "UPDATE rag_docs SET source=?,title=?,text=?,content_hash=?,metadata=? WHERE rowid=?",
                        (d.source, d.title, d.text, d.content_hash, json.dumps(d.metadata), rid),
                    )
                    self._del_vector(rid)
                else:
                    cur = self._db.execute(
                        "INSERT INTO rag_docs(doc_id,source,title,text,content_hash,metadata) "
                        "VALUES(?,?,?,?,?,?)",
                        (d.doc_id, d.source, d.title, d.text, d.content_hash, json.dumps(d.metadata)),
                    )
                    rid = int(cur.lastrowid or 0)
                self._put_vector(rid, np.asarray(v, dtype=np.float32))

    def delete(self, doc_ids: Sequence[str]) -> None:
        with self._lock, self._db:
            for did in doc_ids:
                row = self._db.execute("SELECT rowid FROM rag_docs WHERE doc_id=?", (did,)).fetchone()
                if row:
                    self._del_vector(int(row["rowid"]))
                    self._db.execute("DELETE FROM rag_docs WHERE doc_id=?", (did,))

    def search(self, vector: np.ndarray, k: int) -> list[tuple[StoredDoc, float]]:
        if k <= 0:
            return []
        with self._lock:
            hits = self._knn(np.asarray(vector, dtype=np.float32), k)
            out: list[tuple[StoredDoc, float]] = []
            for rid, score in hits:
                r = self._db.execute("SELECT * FROM rag_docs WHERE rowid=?", (rid,)).fetchone()
                if r:
                    out.append((self._row_doc(r), score))
            return out

    def hashes(self) -> dict[str, str]:
        with self._lock:
            return {
                r["doc_id"]: r["content_hash"]
                for r in self._db.execute("SELECT doc_id,content_hash FROM rag_docs")
            }

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM rag_docs").fetchone()[0])

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            r = self._db.execute("SELECT value FROM rag_meta WHERE key=?", (key,)).fetchone()
            return None if r is None else str(r["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO rag_meta(key,value) VALUES(?,?)", (key, value))

    def clear(self) -> None:
        with self._lock, self._db:
            self._clear_vectors()
            self._db.execute("DELETE FROM rag_docs")
            self._db.execute("DELETE FROM rag_meta")

    def close(self) -> None:
        with self._lock:
            self._db.close()


class NumpySQLiteStore(_SQLiteBase):
    """Fallback: float32 vectors in a BLOB column, brute-force cosine with numpy."""

    backend = "numpy-sqlite"

    def _init_vectors(self) -> None:
        self._db.execute("CREATE TABLE IF NOT EXISTS rag_vecs(rowid INTEGER PRIMARY KEY, vec BLOB NOT NULL)")
        self._matrix: np.ndarray | None = None
        self._ids: list[int] = []

    def _invalidate(self) -> None:
        self._matrix = None

    def _put_vector(self, rowid: int, vec: np.ndarray) -> None:
        self._db.execute("INSERT OR REPLACE INTO rag_vecs(rowid,vec) VALUES(?,?)", (rowid, vec.tobytes()))
        self._invalidate()

    def _del_vector(self, rowid: int) -> None:
        self._db.execute("DELETE FROM rag_vecs WHERE rowid=?", (rowid,))
        self._invalidate()

    def _clear_vectors(self) -> None:
        self._db.execute("DELETE FROM rag_vecs")
        self._invalidate()

    def _load(self) -> None:
        rows = self._db.execute("SELECT rowid,vec FROM rag_vecs ORDER BY rowid").fetchall()
        self._ids = [int(r["rowid"]) for r in rows]
        self._matrix = (
            np.stack([np.frombuffer(r["vec"], dtype=np.float32) for r in rows])
            if rows
            else np.zeros((0, self.dim), dtype=np.float32)
        )

    def _knn(self, vec: np.ndarray, k: int) -> list[tuple[int, float]]:
        if self._matrix is None:
            self._load()
        assert self._matrix is not None
        if not len(self._ids):
            return []
        sims = self._matrix @ vec
        order = np.argsort(-sims, kind="stable")[:k]
        return [(self._ids[int(i)], float(sims[int(i)])) for i in order]


class SqliteVecStore(_SQLiteBase):
    """SQLite + sqlite-vec (``vec0`` virtual table, cosine distance)."""

    backend = "sqlite-vec"

    def __init__(self, path: Path | str, dim: int) -> None:
        import sqlite_vec  # ImportError -> caller falls back

        self._sqlite_vec = sqlite_vec
        super().__init__(path, dim)

    def _init_vectors(self) -> None:
        db = self._db
        db.enable_load_extension(True)  # AttributeError if Python built without it
        try:
            self._sqlite_vec.load(db)
        finally:
            db.enable_load_extension(False)
        db.execute(
            f"CREATE VIRTUAL TABLE IF NOT EXISTS rag_vec USING vec0("
            f"embedding float[{self.dim}] distance_metric=cosine)"
        )

    def _put_vector(self, rowid: int, vec: np.ndarray) -> None:
        self._db.execute(
            "INSERT INTO rag_vec(rowid, embedding) VALUES(?, ?)",
            (rowid, self._sqlite_vec.serialize_float32(vec.tolist())),
        )

    def _del_vector(self, rowid: int) -> None:
        self._db.execute("DELETE FROM rag_vec WHERE rowid=?", (rowid,))

    def _clear_vectors(self) -> None:
        self._db.execute("DELETE FROM rag_vec")

    def _knn(self, vec: np.ndarray, k: int) -> list[tuple[int, float]]:
        rows = self._db.execute(
            "SELECT rowid, distance FROM rag_vec WHERE embedding MATCH ? AND k = ? ORDER BY distance",
            (self._sqlite_vec.serialize_float32(vec.tolist()), k),
        ).fetchall()
        return [(int(r["rowid"]), 1.0 - float(r["distance"])) for r in rows]


def open_store(path: Path | str, dim: int, prefer: str = "auto") -> VectorStore:
    """``auto``/``sqlite-vec`` try the extension then fall back; ``numpy`` forces fallback."""
    if prefer in ("auto", "sqlite-vec"):
        try:
            return SqliteVecStore(path, dim)
        except (ImportError, AttributeError, sqlite3.Error, OSError) as exc:
            log.warning("sqlite-vec unavailable (%s); using numpy/SQLite fallback", exc)
    return NumpySQLiteStore(path, dim)


__all__ = ["NumpySQLiteStore", "SqliteVecStore", "StoredDoc", "VectorStore", "open_store"]
