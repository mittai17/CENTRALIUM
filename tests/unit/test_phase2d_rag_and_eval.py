"""Unit tests for Phase 2D: Hybrid retrieval and RAG evaluation harness."""

from __future__ import annotations

from pathlib import Path

from centralium.agent.eval.rag_eval import (
    GOLDEN_RAG_QUERIES,
    RAGEvalReport,
    evaluate_retrieval_method,
    run_rag_eval,
)
from centralium.agent.rag.embedder import HashingEmbedder
from centralium.agent.rag.hybrid import (
    BM25Index,
    HybridRetriever,
    reciprocal_rank_fusion,
    weighted_rerank,
)
from centralium.agent.rag.store import StoredDoc, open_store


def test_bm25_index_and_scoring():
    docs = [
        StoredDoc("doc1", "kb", "PowerShell Execution", "PowerShell scriptblock logging T1059.001 cradle"),
        StoredDoc("doc2", "kb", "Ransomware Canary", "Ransomware encrypts files mass rename vssadmin"),
        StoredDoc("doc3", "kb", "Cron Persistence", "Linux persistence crontab timer systemd backdoor"),
    ]
    idx = BM25Index(docs)
    assert len(idx.docs) == 3

    # Query matching doc1
    res1 = idx.search("powershell download cradle", k=2)
    assert len(res1) >= 1
    assert res1[0][0].doc_id == "doc1"
    assert res1[0][1] > 0.0

    # Query matching doc2
    res2 = idx.search("ransomware encryption", k=2)
    assert len(res2) >= 1
    assert res2[0][0].doc_id == "doc2"

    # Empty query returns empty
    assert idx.search("", k=5) == []


def test_reciprocal_rank_fusion():
    d1 = StoredDoc("d1", "src", "T1", "text1")
    d2 = StoredDoc("d2", "src", "T2", "text2")
    d3 = StoredDoc("d3", "src", "T3", "text3")

    # Vector ranking: d1, d2
    vec_results = [(d1, 0.9), (d2, 0.7)]
    # BM25 ranking: d2, d3
    bm25_results = [(d2, 8.5), (d3, 4.2)]

    fused = reciprocal_rank_fusion(vec_results, bm25_results, k_rrf=60)
    # d2 appears in both lists, so its fused score should be highest
    assert fused[0][0].doc_id == "d2"
    fused_ids = [d.doc_id for d, _ in fused]
    assert "d1" in fused_ids and "d3" in fused_ids


def test_weighted_rerank():
    d1 = StoredDoc("d1", "src", "T1", "text1")
    d2 = StoredDoc("d2", "src", "T2", "text2")

    vec_results = [(d1, 0.9), (d2, 0.5)]
    bm25_results = [(d1, 2.0), (d2, 10.0)]

    # Equal weighting
    reranked = weighted_rerank(vec_results, bm25_results, alpha=0.5)
    assert len(reranked) == 2


def test_hybrid_retriever_e2e(tmp_path: Path):
    db_file = tmp_path / "hybrid_test.db"
    store = open_store(db_file, 64, prefer="numpy")
    emb = HashingEmbedder(dim=64)

    docs = [
        StoredDoc(
            "ps_playbook",
            "playbook",
            "PowerShell Attacks",
            "Attacks using powershell T1059.001 download cradle",
            metadata={"technique_id": "T1059.001"},
        ),
        StoredDoc(
            "rw_playbook",
            "playbook",
            "Ransomware Playbook",
            "Isolate host and detect canary files on ransomware",
            metadata={"technique_id": "T1486"},
        ),
    ]
    vectors = emb.embed_batch([f"{d.title} {d.text}" for d in docs])
    store.upsert(docs, vectors)

    retriever = HybridRetriever(store, emb, mode="rrf")
    assert retriever.info()["retriever_type"] == "hybrid"
    assert retriever.info()["indexed_docs"] == 2

    # Query with technique boost
    res = retriever.retrieve("investigate T1059.001 powershell execution", k=3)
    assert len(res) >= 1
    assert res[0].doc_id == "ps_playbook"
    assert res[0].metadata["attribution"] == "playbook/ps_playbook"

    retriever.close()


def test_rag_eval_harness(tmp_path: Path):
    # Test evaluation metrics helper directly
    docs = [
        StoredDoc(
            "ransomware.md", "kb", "Ransomware Guide", "ransomware payment decryptor canary file encryption"
        ),
        StoredDoc("mitre:T1059.001", "mitre", "PowerShell", "T1059.001 powershell scriptblock"),
    ]

    def mock_search(q: str, k: int) -> list[StoredDoc]:
        if "ransomware" in q.lower():
            return [docs[0], docs[1]]
        return [docs[1], docs[0]]

    metrics, details = evaluate_retrieval_method("MockRetriever", mock_search, GOLDEN_RAG_QUERIES[:4])
    assert metrics.total_queries == 4
    assert 0.0 <= metrics.recall_at_1 <= 1.0
    assert 0.0 <= metrics.mrr <= 1.0
    assert len(details) == 4


def test_run_rag_eval_cli_integration(tmp_path: Path):
    out_md = tmp_path / "rag_report.md"
    rep = run_rag_eval(rag_dir="rag", out_path=out_md)
    assert isinstance(rep, RAGEvalReport)
    assert rep.total_queries == len(GOLDEN_RAG_QUERIES)
    assert "Lexical (BM25)" in rep.methods
    assert "Hybrid (RRF)" in rep.methods
    assert out_md.exists()
    assert "Centralium RAG Evaluation Report" in out_md.read_text(encoding="utf-8")
