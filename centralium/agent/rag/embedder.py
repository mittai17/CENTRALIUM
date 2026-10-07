"""Embedders for the local RAG index.

Default: :class:`HashingEmbedder` - deterministic, offline, no downloads. It is a
*lexical* (hashed TF-IDF over unigrams + bigrams) embedder: it matches shared
vocabulary, NOT meaning. Synonyms/paraphrases will not be bridged. Optional neural
backends (sentence-transformers, llama-server ``/v1/embeddings``) are available when
installed/running and are never required.
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import math
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np

log = logging.getLogger("centralium.rag.embedder")

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.\-]*[a-z0-9]|[a-z0-9]")
_SPLIT = re.compile(r"[._\-]+")
_STOP_WORDS = "a an and are as at be by for from has have in is it its of on or that the this"
_STOP = frozenset((_STOP_WORDS + " to was were with").split())


def tokenize(text: str) -> list[str]:
    """Lowercase tokens; ``T1059.001`` stays whole *and* its parts are emitted
    (so ``powershell.exe`` also yields ``powershell`` and ``exe``)."""
    out: list[str] = []
    for tok in _TOKEN.findall(text.lower()):
        parts = [p for p in _SPLIT.split(tok) if p]
        if len(parts) > 1:
            out.append(tok)
        out.extend(p for p in parts if p not in _STOP)
    return out


class Embedder(ABC):
    """Text -> L2-normalised float32 vectors."""

    dim: int

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    def fingerprint(self) -> str:
        """Identity of the vector space; a change invalidates caches and the index."""
        return f"{self.name}:{self.dim}"

    @property
    def lexical(self) -> bool:
        return False

    def fit(self, texts: Sequence[str]) -> None:  # noqa: B027 - optional hook
        """Learn corpus statistics (IDF). No-op for neural embedders."""

    @abstractmethod
    def embed_batch(self, texts: Sequence[str]) -> np.ndarray: ...

    def embed(self, text: str) -> np.ndarray:
        row: np.ndarray = self.embed_batch([text])[0]
        return row

    def state(self) -> dict[str, Any]:
        """JSON-serialisable fitted state, persisted in the vector store meta."""
        return {}

    def load_state(self, state: dict[str, Any]) -> None:
        return None


class HashingEmbedder(Embedder):
    """Signed feature hashing of unigrams+bigrams with optional corpus IDF weighting."""

    def __init__(self, dim: int = 512, use_bigrams: bool = True) -> None:
        if dim < 16:
            raise ValueError("dim too small")
        self.dim = dim
        self.use_bigrams = use_bigrams
        self._idf: np.ndarray | None = None

    name_prefix = "hashing-tfidf-v1"

    @property
    def name(self) -> str:
        idf = hashlib.sha256(self._idf.tobytes()).hexdigest()[:10] if self._idf is not None else "noidf"
        return f"{self.name_prefix}-{'bi' if self.use_bigrams else 'uni'}-{idf}"

    @property
    def lexical(self) -> bool:
        return True

    @staticmethod
    def _bucket(feature: str, dim: int) -> tuple[int, float]:
        h = hashlib.blake2b(feature.encode(), digest_size=8).digest()
        v = int.from_bytes(h, "little")
        return v % dim, 1.0 if (v >> 63) & 1 else -1.0

    def _features(self, text: str) -> list[str]:
        toks = tokenize(text)
        feats = list(toks)
        if self.use_bigrams:
            feats.extend(f"{a}_{b}" for a, b in itertools.pairwise(toks))
        return feats

    def fit(self, texts: Sequence[str]) -> None:
        df = np.zeros(self.dim, dtype=np.float64)
        n = max(len(texts), 1)
        for t in texts:
            seen = {self._bucket(f, self.dim)[0] for f in self._features(t)}
            for b in seen:
                df[b] += 1
        self._idf = (np.log((1 + n) / (1 + df)) + 1.0).astype(np.float32)

    def embed_batch(self, texts: Sequence[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            counts: dict[int, float] = {}
            for f in self._features(t):
                b, sign = self._bucket(f, self.dim)
                counts[b] = counts.get(b, 0.0) + sign
            for b, c in counts.items():
                w = math.copysign(1.0 + math.log(abs(c)), c) if c else 0.0
                if self._idf is not None:
                    w *= float(self._idf[b])
                out[i, b] = w
            n = float(np.linalg.norm(out[i]))
            if n > 0:
                out[i] /= n
        return out

    def state(self) -> dict[str, Any]:
        return {"idf": None if self._idf is None else [round(float(x), 6) for x in self._idf]}

    def load_state(self, state: dict[str, Any]) -> None:
        idf = state.get("idf")
        self._idf = None if idf is None else np.asarray(idf, dtype=np.float32)


class SentenceTransformerEmbedder(Embedder):
    """Optional. Loads a *local* model dir/name; never downloads (local_files_only)."""

    def __init__(self, model: str | Path) -> None:
        try:
            import importlib

            SentenceTransformer = importlib.import_module("sentence_transformers").SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("sentence-transformers is not installed") from exc
        self._model_name = str(model)
        self._m = SentenceTransformer(self._model_name, local_files_only=True)
        self.dim = int(self._m.get_sentence_embedding_dimension() or 0)

    @property
    def name(self) -> str:
        return f"st-{Path(self._model_name).name}"

    def embed_batch(self, texts: Sequence[str]) -> np.ndarray:
        v: np.ndarray = np.asarray(self._m.encode(list(texts), normalize_embeddings=True), dtype=np.float32)
        return v


class LlamaServerEmbedder(Embedder):
    """Optional. Uses a local llama-server started with ``--embeddings`` (127.0.0.1 only)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8081", timeout: float = 30.0, dim: int = 0) -> None:
        host = urlparse(base_url).hostname
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("llama-server embedder must be a loopback address")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.dim = dim

    @property
    def name(self) -> str:
        return "llama-server-embed"

    def embed_batch(self, texts: Sequence[str]) -> np.ndarray:
        import httpx

        r = httpx.post(f"{self.base_url}/v1/embeddings", json={"input": list(texts)}, timeout=self.timeout)
        r.raise_for_status()
        rows = [np.asarray(d["embedding"], dtype=np.float32) for d in r.json()["data"]]
        arr = np.stack(rows)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        arr = arr / np.where(norms == 0, 1, norms)
        self.dim = int(arr.shape[1])
        return arr


class CachedEmbedder(Embedder):
    """LRU memory cache keyed by sha256(text) in front of any embedder."""

    def __init__(self, inner: Embedder, max_entries: int = 4096) -> None:
        self.inner = inner
        self.dim = inner.dim
        self.max_entries = max_entries
        self._cache: OrderedDict[tuple[str, str], np.ndarray] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def fingerprint(self) -> str:
        return self.inner.fingerprint

    @property
    def lexical(self) -> bool:
        return self.inner.lexical

    def fit(self, texts: Sequence[str]) -> None:
        self.inner.fit(texts)
        self._cache.clear()

    def state(self) -> dict[str, Any]:
        return self.inner.state()

    def load_state(self, state: dict[str, Any]) -> None:
        self.inner.load_state(state)
        self._cache.clear()

    def embed_batch(self, texts: Sequence[str]) -> np.ndarray:
        fp = self.inner.fingerprint
        keys = [(fp, hashlib.sha256(t.encode()).hexdigest()) for t in texts]
        rows: list[np.ndarray | None] = []
        missing: list[int] = []
        for i, k in enumerate(keys):
            v = self._cache.get(k)
            if v is None:
                rows.append(None)
                missing.append(i)
                self.misses += 1
            else:
                self._cache.move_to_end(k)
                rows.append(v)
                self.hits += 1
        if missing:
            new = self.inner.embed_batch([texts[i] for i in missing])
            for j, i in enumerate(missing):
                rows[i] = new[j]
                self._cache[keys[i]] = new[j]
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)
        return np.stack([r for r in rows if r is not None]) if rows else np.zeros((0, self.dim), np.float32)


def build_embedder(kind: str = "hashing", **kw: Any) -> Embedder:
    """``hashing`` (default) | ``sentence-transformers`` | ``llama-server``. Neural
    kinds fall back to hashing (with a warning) if unavailable."""
    try:
        if kind == "hashing":
            return HashingEmbedder(dim=int(kw.get("dim", 512)))
        if kind == "sentence-transformers":
            return SentenceTransformerEmbedder(kw["model"])
        if kind == "llama-server":
            return LlamaServerEmbedder(kw.get("base_url", "http://127.0.0.1:8081"), dim=int(kw.get("dim", 0)))
    except (RuntimeError, KeyError, ValueError, OSError) as exc:
        log.warning("embedder %s unavailable (%s); falling back to hashing", kind, exc)
        return HashingEmbedder()
    raise ValueError(f"unknown embedder kind {kind!r}")


__all__ = [
    "CachedEmbedder",
    "Embedder",
    "HashingEmbedder",
    "LlamaServerEmbedder",
    "SentenceTransformerEmbedder",
    "build_embedder",
    "tokenize",
]
