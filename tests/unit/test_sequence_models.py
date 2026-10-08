"""Unit tests for sequence and provenance anomaly models."""

from __future__ import annotations

import time

from centralium.agent.graph.core import MemoryGraph
from centralium.agent.ml.provenance_model import (
    ProvenanceGraphAnomalyModel,
    compare_with_isolation_forest,
)
from centralium.agent.ml.sequence_model import (
    MarkovSequenceModel,
)
from centralium.agent.models import EventType, NormalizedEvent


def test_markov_sequence_model_fast_inference_guarantee() -> None:
    model = MarkovSequenceModel(order=1)
    seq = ["explorer.exe", "cmd.exe", "powershell.exe", "whoami.exe"]

    latencies_us: list[float] = []
    for _ in range(50):
        t0 = time.perf_counter_ns()
        res = model.score_sequence(seq)
        t1 = time.perf_counter_ns()
        latencies_us.append((t1 - t0) / 1000.0)

    p95_latency_us = sorted(latencies_us)[int(0.95 * len(latencies_us))]
    # Strictly must be < 1000 us (1 ms)
    assert p95_latency_us < 1000.0
    assert res.latency_us < 1000.0


def test_markov_sequence_anomaly_and_explainability() -> None:
    model = MarkovSequenceModel(order=1)

    # Train on common benign developer/admin lineages
    benign_train = [
        ["explorer.exe", "chrome.exe"],
        ["explorer.exe", "code.exe", "node.exe"],
        ["init", "systemd", "sshd", "bash", "git"],
    ]
    model.fit(benign_train)

    # Test benign sequence
    benign_seq = ["explorer.exe", "chrome.exe"]
    benign_res = model.score_sequence(benign_seq)
    assert benign_res.anomaly_score < 0.5
    assert not benign_res.is_anomalous

    # Test anomalous attack sequence
    attack_seq = ["winword.exe", "powershell.exe", "mimikatz.exe"]
    attack_res = model.score_sequence(attack_seq)
    assert attack_res.anomaly_score > 0.6
    assert attack_res.is_anomalous

    # Explainability checks
    assert attack_res.worst_transition is not None
    assert attack_res.worst_transition.seen_in_baseline is False
    assert len(attack_res.transitions) == 2


def test_markov_sequence_event_and_serialization() -> None:
    model = MarkovSequenceModel(order=1)

    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        process_name="powershell.exe",
        parent_process="winword.exe",
        source="test",
    )
    res = model.score_event(ev)
    assert res.worst_transition is not None
    assert res.worst_transition.source == "winword.exe"
    assert res.worst_transition.target == "powershell.exe"

    # Serialization roundtrip
    data = model.to_dict()
    restored = MarkovSequenceModel.from_dict(data)
    restored_res = restored.score_event(ev)
    assert restored_res.anomaly_score == res.anomaly_score


def test_provenance_graph_anomaly_model_scoring() -> None:
    model = ProvenanceGraphAnomalyModel()

    benign_edges = [
        ("Process", "SPAWNED", "Process"),
        ("Process", "CREATED_FILE", "File"),
        ("Process", "RUNS_ON", "Host"),
    ]
    model.fit_baseline_relations(benign_edges)

    # Benign subgraph
    benign_nodes = [("p1", "Process"), ("p2", "Process"), ("f1", "File")]
    benign_graph_edges = [
        ("p1", "SPAWNED", "p2"),
        ("p2", "CREATED_FILE", "f1"),
    ]
    benign_res = model.score_graph(benign_nodes, benign_graph_edges)
    assert benign_res.anomaly_score < 0.6
    assert not benign_res.is_anomalous

    # Anomalous attack subgraph (e.g., untrusted user process authenticating as admin and modifying registry)
    attack_nodes = [
        ("p_bad", "Process"),
        ("u_root", "User"),
        ("reg_run", "RegistryKey"),
        ("c2_ip", "IP"),
    ]
    attack_graph_edges = [
        ("p_bad", "AUTHENTICATED_AS", "u_root"),
        ("p_bad", "MODIFIED_REG", "reg_run"),
        ("p_bad", "CONNECTED_TO", "c2_ip"),
    ]
    attack_res = model.score_graph(attack_nodes, attack_graph_edges)
    assert attack_res.anomaly_score > 0.5
    assert len(attack_res.top_anomalous_edges) > 0


def test_provenance_model_integration_with_memory_graph() -> None:
    graph = MemoryGraph()
    model = ProvenanceGraphAnomalyModel()

    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=1234,
        process_name="bash",
        parent_process="sshd",
        source="auditd",
    )
    graph.ingest(ev, findings=[])

    res = model.score_memory_graph(graph)
    assert res.node_count > 0
    assert len(res.embedding) == model.embedding_dim


def test_honest_model_comparison_with_isolation_forest() -> None:
    normal_graphs: list[dict] = []
    for i in range(20):
        normal_graphs.append(
            {
                "nodes": [f"proc_{i}_1", f"proc_{i}_2", f"file_{i}"],
                "node_types": {f"proc_{i}_1": "Process", f"proc_{i}_2": "Process", f"file_{i}": "File"},
                "edges": [
                    (f"proc_{i}_1", "SPAWNED", f"proc_{i}_2"),
                    (f"proc_{i}_2", "CREATED_FILE", f"file_{i}"),
                ],
            }
        )

    anomaly_graphs: list[dict] = []
    for j in range(10):
        anomaly_graphs.append(
            {
                "nodes": [f"sh_{j}", f"py_{j}", f"ip_{j}", f"reg_{j}"],
                "node_types": {
                    f"sh_{j}": "Process",
                    f"py_{j}": "Process",
                    f"ip_{j}": "IP",
                    f"reg_{j}": "RegistryKey",
                },
                "edges": [
                    (f"sh_{j}", "SPAWNED", f"py_{j}"),
                    (f"py_{j}", "CONNECTED_TO", f"ip_{j}"),
                    (f"py_{j}", "MODIFIED_REG", f"reg_{j}"),
                ],
            }
        )

    comparison = compare_with_isolation_forest(normal_graphs, anomaly_graphs)

    assert "provenance_random_walk" in comparison
    assert "isolation_forest_baseline" in comparison

    prov_metrics = comparison["provenance_random_walk"]
    if_metrics = comparison["isolation_forest_baseline"]

    # Honest metric reporting checks
    assert 0.0 <= prov_metrics.precision <= 1.0
    assert 0.0 <= prov_metrics.recall <= 1.0
    assert 0.0 <= prov_metrics.f1 <= 1.0
    assert 0.0 <= prov_metrics.roc_auc <= 1.0
    assert prov_metrics.p50_latency_ms >= 0.0

    assert 0.0 <= if_metrics.precision <= 1.0
    assert 0.0 <= if_metrics.recall <= 1.0
    assert 0.0 <= if_metrics.f1 <= 1.0
    assert 0.0 <= if_metrics.roc_auc <= 1.0
    assert if_metrics.p50_latency_ms >= 0.0
