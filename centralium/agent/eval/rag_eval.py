"""RAG evaluation harness: golden query set, measuring recall@k and MRR.

Compares:
1. Lexical baseline (BM25 only)
2. Vector baseline (Cosine similarity with embedder)
3. Hybrid retrieval (BM25 + Vector + Reciprocal Rank Fusion)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.rag.hybrid import build_hybrid_retriever
from centralium.agent.rag.store import StoredDoc

log = logging.getLogger("centralium.eval.rag")

GOLDEN_RAG_QUERIES: list[dict[str, Any]] = [
    {
        "id": "q1",
        "category": "execution",
        "query": "T1059.001 powershell command execution download cradle scriptblock",
        "expected_matches": ["T1059.001", "lolbins_windows", "incident_knowledge"],
    },
    {
        "id": "q2",
        "category": "ransomware",
        "query": "ransomware payment decryptor canary file encryption vssadmin shadow copies",
        "expected_matches": ["ransomware", "response_playbooks"],
    },
    {
        "id": "q3",
        "category": "lolbins_windows",
        "query": "certutil exe urlcache split download payload decode base64 lolbin",
        "expected_matches": ["lolbins_windows"],
    },
    {
        "id": "q4",
        "category": "persistence",
        "query": "linux persistence crontab systemd timer cron service backdoor",
        "expected_matches": ["persistence", "lolbins_linux"],
    },
    {
        "id": "q5",
        "category": "playbook",
        "query": "host isolation containment network block process terminate quarantine response playbook",
        "expected_matches": ["response_playbooks"],
    },
    {
        "id": "q6",
        "category": "yara",
        "query": "yara rule strings condition hex meta compile scan suspicious file",
        "expected_matches": ["yara_metadata"],
    },
    {
        "id": "q7",
        "category": "lolbins_linux",
        "query": "curl bash pipe reverse shell nc ncat dev tcp socket",
        "expected_matches": ["lolbins_linux"],
    },
    {
        "id": "q8",
        "category": "credentials",
        "query": "credential access lsass memory minidump procdump sekurlsa dumping",
        "expected_matches": ["malware_behavior", "mitre_attack"],
    },
    {
        "id": "q9",
        "category": "persistence_windows",
        "query": "T1053.005 scheduled task schtasks create xml run at startup",
        "expected_matches": ["T1053.005", "persistence", "lolbins_windows"],
    },
    {
        "id": "q10",
        "category": "defense_evasion",
        "query": "process hollowing dll injection unhooking reflective memory injection",
        "expected_matches": ["malware_behavior"],
    },
    {
        "id": "q11",
        "category": "ransomware_canary",
        "query": "mass file extension rename encrypted entropy canary trigger",
        "expected_matches": ["ransomware"],
    },
    {
        "id": "q12",
        "category": "response_escalation",
        "query": "incident triage severity critical isolate endpoint kill tree",
        "expected_matches": ["response_playbooks", "incident_knowledge"],
    },
]


@dataclass
class MethodMetrics:
    method: str
    total_queries: int
    recall_at_1: float
    recall_at_3: float
    recall_at_5: float
    mrr: float
    avg_latency_ms: float


@dataclass
class QueryEvalDetail:
    query_id: str
    category: str
    query: str
    expected_matches: list[str]
    retrieved_docs: list[str]
    first_relevant_rank: int | None
    hit_at_1: bool
    hit_at_3: bool
    hit_at_5: bool


@dataclass
class RAGEvalReport:
    timestamp: str
    total_queries: int
    methods: dict[str, MethodMetrics]
    details: dict[str, list[QueryEvalDetail]] = field(default_factory=dict)

    def to_markdown(self) -> str:
        lines = [
            "# Centralium RAG Evaluation Report",
            "",
            f"**Total Golden Queries:** {self.total_queries}  ",
            f"**Generated:** {self.timestamp}  ",
            "",
            "## Summary Metrics Comparison",
            "",
            "| Retrieval Method | Recall@1 | Recall@3 | Recall@5 | MRR | Avg Latency (ms) |",
            "|---|---|---|---|---|---|",
        ]
        for m in self.methods.values():
            lines.append(
                f"| **{m.method}** | {m.recall_at_1 * 100:.1f}% | {m.recall_at_3 * 100:.1f}% | "
                f"{m.recall_at_5 * 100:.1f}% | {m.mrr:.3f} | {m.avg_latency_ms:.2f} ms |"
            )
        lines.append("")
        lines.append("## Detailed Golden Query Results (Hybrid Method)")
        lines.append("")
        lines.append("| Query ID | Category | Top Retrieved Doc | Relevant Rank | Hit@3 |")
        lines.append("|---|---|---|---|---|")
        for d in self.details.get("Hybrid (RRF)", []):
            top_doc = d.retrieved_docs[0] if d.retrieved_docs else "None"
            rank_str = str(d.first_relevant_rank) if d.first_relevant_rank is not None else "Miss"
            hit_str = "Yes" if d.hit_at_3 else "No"
            lines.append(f"| {d.query_id} | {d.category} | `{top_doc}` | {rank_str} | {hit_str} |")
        lines.append("")
        return "\n".join(lines)


def _is_match(doc: StoredDoc, expected: list[str]) -> bool:
    doc_id = doc.doc_id.lower()
    file_name = str(doc.metadata.get("file", "")).lower()
    tech_id = str(doc.metadata.get("technique_id", "")).lower()
    title = doc.title.lower()

    for exp in expected:
        exp_l = exp.lower()
        if exp_l in doc_id or exp_l in file_name or exp_l in tech_id or exp_l in title:
            return True
    return False


def evaluate_retrieval_method(
    name: str,
    search_fn: Any,
    queries: list[dict[str, Any]],
    k_max: int = 5,
) -> tuple[MethodMetrics, list[QueryEvalDetail]]:
    total = len(queries)
    hits_1 = 0
    hits_3 = 0
    hits_5 = 0
    rr_sum = 0.0
    latencies: list[float] = []
    details: list[QueryEvalDetail] = []

    for q in queries:
        t0 = time.perf_counter()
        results: list[StoredDoc] = search_fn(q["query"], k=k_max)
        latency = (time.perf_counter() - t0) * 1000
        latencies.append(latency)

        expected = q["expected_matches"]
        retrieved_ids = [r.doc_id for r in results]
        first_rank: int | None = None

        for rank, doc in enumerate(results, start=1):
            if _is_match(doc, expected):
                first_rank = rank
                break

        h1 = first_rank is not None and first_rank <= 1
        h3 = first_rank is not None and first_rank <= 3
        h5 = first_rank is not None and first_rank <= 5

        if h1:
            hits_1 += 1
        if h3:
            hits_3 += 1
        if h5:
            hits_5 += 1
        if first_rank is not None:
            rr_sum += 1.0 / first_rank

        details.append(
            QueryEvalDetail(
                query_id=q["id"],
                category=q["category"],
                query=q["query"],
                expected_matches=expected,
                retrieved_docs=retrieved_ids,
                first_relevant_rank=first_rank,
                hit_at_1=h1,
                hit_at_3=h3,
                hit_at_5=h5,
            )
        )

    metrics = MethodMetrics(
        method=name,
        total_queries=total,
        recall_at_1=round(hits_1 / total, 4) if total else 0.0,
        recall_at_3=round(hits_3 / total, 4) if total else 0.0,
        recall_at_5=round(hits_5 / total, 4) if total else 0.0,
        mrr=round(rr_sum / total, 4) if total else 0.0,
        avg_latency_ms=round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
    )
    return metrics, details


def run_rag_eval(
    rag_dir: Path | str = "rag",
    db_path: Path | str | None = None,
    out_path: Path | str | None = None,
) -> RAGEvalReport:
    """Run full evaluation comparing BM25, Vector, and Hybrid (RRF) retrieval."""
    from datetime import UTC, datetime

    hybrid, _ = build_hybrid_retriever(rag_dir=rag_dir, db_path=db_path)

    # 1. BM25 Search function
    def search_bm25(q: str, k: int) -> list[StoredDoc]:
        res = hybrid.bm25_search(q, k=k)
        return [doc for doc, _ in res]

    # 2. Vector Search function
    def search_vector(q: str, k: int) -> list[StoredDoc]:
        res = hybrid.vector_search(q, k=k)
        return [doc for doc, _ in res]

    # 3. Hybrid Search function
    def search_hybrid(q: str, k: int) -> list[StoredDoc]:
        res = hybrid.retrieve(q, k=k)
        # convert RAGDocument back to StoredDoc representation for matching
        return [
            StoredDoc(
                doc_id=d.doc_id,
                source=d.source,
                title=d.title,
                text=d.text,
                metadata=d.metadata,
            )
            for d in res
        ]

    m_bm25, d_bm25 = evaluate_retrieval_method("Lexical (BM25)", search_bm25, GOLDEN_RAG_QUERIES)
    m_vec, d_vec = evaluate_retrieval_method("Vector Only", search_vector, GOLDEN_RAG_QUERIES)
    m_hyb, d_hyb = evaluate_retrieval_method("Hybrid (RRF)", search_hybrid, GOLDEN_RAG_QUERIES)

    report = RAGEvalReport(
        timestamp=datetime.now(UTC).isoformat(),
        total_queries=len(GOLDEN_RAG_QUERIES),
        methods={
            "Lexical (BM25)": m_bm25,
            "Vector Only": m_vec,
            "Hybrid (RRF)": m_hyb,
        },
        details={
            "Lexical (BM25)": d_bm25,
            "Vector Only": d_vec,
            "Hybrid (RRF)": d_hyb,
        },
    )

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix.lower() == ".json":
            p.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        else:
            p.write_text(report.to_markdown(), encoding="utf-8")

    return report
