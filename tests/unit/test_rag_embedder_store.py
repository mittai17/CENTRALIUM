from __future__ import annotations

import sys

import numpy as np
import pytest

from centralium.agent.rag.embedder import (
    CachedEmbedder,
    HashingEmbedder,
    LlamaServerEmbedder,
    build_embedder,
    tokenize,
)
from centralium.agent.rag.store import NumpySQLiteStore, SqliteVecStore, StoredDoc, open_store


def test_tokenize_keeps_technique_ids_and_parts():
    t = tokenize("Run powershell.exe for T1059.001 and the cmd")
    assert "t1059.001" in t and "powershell" in t and "exe" in t
    assert "the" not in t and "and" not in t


def test_hashing_embedder_is_deterministic_normalised_and_lexical():
    e1, e2 = HashingEmbedder(256), HashingEmbedder(256)
    v1, v2 = e1.embed("vssadmin delete shadows"), e2.embed("vssadmin delete shadows")
    assert np.array_equal(v1, v2)
    assert abs(float(np.linalg.norm(v1)) - 1.0) < 1e-5
    assert e1.lexical is True and "hashing" in e1.name
    assert float(np.linalg.norm(e1.embed(""))) == 0.0


def test_similarity_reflects_shared_vocabulary():
    e = HashingEmbedder(512)
    a, b, c = (
        e.embed("delete volume shadow copies"),
        e.embed("shadow copies deleted"),
        e.embed("ssh key login"),
    )
    assert float(a @ b) > float(a @ c)


def test_idf_fit_changes_fingerprint_and_state_roundtrips():
    e = HashingEmbedder(128)
    before = e.fingerprint
    e.fit(["alpha beta", "alpha gamma", "alpha delta"])
    assert e.fingerprint != before
    e2 = HashingEmbedder(128)
    e2.load_state(e.state())
    assert np.allclose(e.embed("alpha beta"), e2.embed("alpha beta"), atol=1e-5)


def test_embedding_cache_hits():
    c = CachedEmbedder(HashingEmbedder(128), max_entries=2)
    a = c.embed("one two")
    b = c.embed("one two")
    assert np.array_equal(a, b) and c.hits == 1 and c.misses == 1
    c.embed("x")
    c.embed("y")  # evicts "one two"
    c.embed("one two")
    assert c.misses == 4
    c.fit(["z"])  # refit invalidates
    assert len(c._cache) == 0


def test_build_embedder_falls_back_when_optional_backends_missing():
    e = build_embedder("sentence-transformers", model="/nonexistent")
    assert isinstance(e, HashingEmbedder)
    with pytest.raises(ValueError):
        LlamaServerEmbedder("http://example.com:8081")  # not loopback
    with pytest.raises(ValueError):
        build_embedder("bogus")


def _docs():
    e = HashingEmbedder(64)
    texts = ["ransom note files encrypted", "ssh authorized keys backdoor", "cron job persistence"]
    docs = [StoredDoc(f"d{i}", "t", f"T{i}", t, f"h{i}", {"n": i}) for i, t in enumerate(texts)]
    return e, docs, e.embed_batch(texts)


@pytest.fixture(params=["sqlite-vec", "numpy"])
def store(request, tmp_path):
    s = open_store(tmp_path / "s.db", 64, request.param)
    yield s
    s.close()


def test_store_upsert_search_delete_meta(store):
    e, docs, vecs = _docs()
    store.upsert(docs, vecs)
    assert store.count() == 3 and store.hashes() == {"d0": "h0", "d1": "h1", "d2": "h2"}
    top = store.search(e.embed("authorized keys ssh"), 2)
    assert top[0][0].doc_id == "d1" and top[0][1] > top[1][1]
    assert top[0][0].metadata == {"n": 1}
    # update keeps a single row and swaps vector
    store.upsert([StoredDoc("d1", "t", "T1", "totally different", "h1b")], e.embed_batch(["cron cron"]))
    assert store.count() == 3 and store.hashes()["d1"] == "h1b"
    assert store.search(e.embed("cron cron"), 1)[0][0].doc_id in {"d1", "d2"}
    store.delete(["d0"])
    assert store.count() == 2
    store.set_meta("k", "v")
    assert store.get_meta("k") == "v" and store.get_meta("nope") is None
    store.clear()
    assert store.count() == 0 and store.search(e.embed("x"), 3) == []


def test_store_rejects_dim_mismatch(store):
    with pytest.raises(ValueError):
        store.upsert([StoredDoc("a", "t", "t", "x", "h")], np.zeros((1, 8), dtype=np.float32))


def test_backends_agree_on_ranking(tmp_path):
    e, docs, vecs = _docs()
    a, b = open_store(tmp_path / "a.db", 64, "sqlite-vec"), open_store(tmp_path / "b.db", 64, "numpy")
    for s in (a, b):
        s.upsert(docs, vecs)
    q = e.embed("ransom files encrypted")
    ra, rb = a.search(q, 3), b.search(q, 3)
    assert ra[0][0].doc_id == rb[0][0].doc_id  # ties beyond the top hit may order differently
    assert all(abs(x[1] - y[1]) < 1e-4 for x, y in zip(ra, rb, strict=True))
    a.close()
    b.close()


def test_fallback_when_sqlite_vec_cannot_load(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlite_vec", None)  # import raises ImportError
    s = open_store(tmp_path / "f.db", 64, "auto")
    assert isinstance(s, NumpySQLiteStore) and s.backend == "numpy-sqlite"
    e, docs, vecs = _docs()
    s.upsert(docs, vecs)
    assert s.search(e.embed("cron job"), 1)[0][0].doc_id == "d2"
    s.close()


def test_fallback_when_extension_loading_disabled(tmp_path, monkeypatch):
    def boom(self):  # emulate Python built without loadable extensions
        raise AttributeError("enable_load_extension")

    monkeypatch.setattr(SqliteVecStore, "_init_vectors", boom)
    s = open_store(tmp_path / "g.db", 64, "auto")
    assert isinstance(s, NumpySQLiteStore)
    s.close()


def test_numpy_store_persists_across_reopen(tmp_path):
    e, docs, vecs = _docs()
    s = NumpySQLiteStore(tmp_path / "p.db", 64)
    s.upsert(docs, vecs)
    s.close()
    s2 = NumpySQLiteStore(tmp_path / "p.db", 64)
    assert s2.search(e.embed("ssh keys"), 1)[0][0].doc_id == "d1"
    s2.close()
