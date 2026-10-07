"""The 10 end-to-end scenarios from the spec, through the real assembled pipeline
(real EPP/YARA/static, behavior, ML models, Kuzu graph, RAG, policy, executor in simulate mode).
The LLM is the clearly-labelled deterministic mock unless stated otherwise; nothing destructive
can run (BoomBackend/BoomRunner fail the test if the OS is touched)."""

from __future__ import annotations

import socket
from datetime import timedelta
from pathlib import Path

import pytest

from centralium.agent.config import LLMSettings
from centralium.agent.demo import clone_events
from centralium.agent.llm import MOCK_MODEL_NAME, LocalLLMClient, MockLLM
from centralium.agent.models import (
    ActionStatus,
    EventType,
    NormalizedEvent,
    OperatingMode,
    ResponseAction,
    RiskBand,
    ScoreFamily,
)
from centralium.agent.nulls import NullLLM
from centralium.agent.sync import TransportUnavailable
from tests.e2e.helpers import SpyLLM, best_risk, make_rt, run_events, sandbox_cfg, scenario

pytestmark = pytest.mark.e2e


# --------------------------------------------------------------------------- 1
def _notepad_events() -> list[NormalizedEvent]:
    kw = {"host_id": "demo-host", "user": "demo", "source": "test"}
    return [
        NormalizedEvent(event_type=EventType.PROCESS_START, pid=7700, ppid=1000, process_name="notepad.exe",
                        executable_path=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe notes.txt",
                        parent_process="explorer.exe", signer="Microsoft Windows", **kw),
        NormalizedEvent(event_type=EventType.FILE_MODIFY, pid=7700, ppid=1000, process_name="notepad.exe",
                        file_path=r"C:\Users\demo\Documents\notes.txt", **kw),
    ]  # fmt: skip


def test_1_benign_application_produces_no_alert(rt):
    outs = run_events(rt, scenario("developer_workflow").events + _notepad_events())
    assert all(o.incident is None for o in outs)
    assert all(not o.actions for o in outs), [a for o in outs for a in o.actions]
    assert best_risk(outs) < 40  # below the alert threshold
    assert rt.db.count("incidents") == 0
    assert all(o.ai is None for o in outs)


@pytest.mark.parametrize("name", ["normal_browser", "admin_backup_script"])
def test_1b_benign_application_with_learned_baseline_produces_no_alert(rt, name):
    rt.modes.set_mode(OperatingMode.LEARNING, actor="test", reason="learn normal activity")
    run_events(rt, clone_events(scenario(name).events, timedelta(hours=-2)))
    rt.modes.set_mode(OperatingMode.ACTIVE, actor="test", reason="detect")
    outs = run_events(rt, scenario(name).events)
    assert all(o.incident is None and not o.actions for o in outs)
    assert best_risk(outs) < 20


# --------------------------------------------------------------------------- 2
def test_2_known_test_ioc_is_detected_deterministically_and_never_sent_to_llm(tmp_path):
    spy = SpyLLM(MockLLM())
    rt = make_rt(sandbox_cfg(tmp_path), llm=spy)
    try:
        outs = run_events(rt, scenario("known_ioc").events)
        proc, net = outs
        assert proc.short_circuited and net.short_circuited
        assert any(f.known_malicious for f in proc.findings)
        assert {"EPP-HASH-BLOCKLIST", "EPP-IOC-IP-INTEL"} <= {f.rule_id for o in outs for f in o.findings}
        assert proc.incident is not None and proc.risk.final_score >= 90
        assert proc.risk.band == RiskBand.CRITICAL
        # never to the LLM, never through ML/RAG
        assert spy.requests == []
        assert all(o.ai is None for o in outs)
        assert "ml" not in proc.stages_reached and "llm" not in proc.stages_reached
        funnel = rt.pipeline.stats.snapshot()["funnel"]
        assert funnel["llm"] == 0 and funnel["ml"] == 0
        # deterministic: a second identical run yields the identical score
        rt2 = make_rt(sandbox_cfg(tmp_path / "again"), llm=SpyLLM())
        try:
            again = run_events(rt2, clone_events(scenario("known_ioc").events, timedelta(minutes=1)))
            assert again[0].risk.final_score == proc.risk.final_score
        finally:
            rt2.close()
    finally:
        rt.close()


# --------------------------------------------------------------------------- 3
def test_3_suspicious_chain_runs_ml_graph_rag_llm_and_creates_incident(rt):
    outs = run_events(rt, scenario("office_powershell_chain").events)
    reached = {s for o in outs for s in o.stages_reached}
    assert {"behavior", "ml", "graph", "novelty", "rag", "llm", "risk", "policy"} <= reached
    inc_outs = [o for o in outs if o.incident]
    assert inc_outs and rt.db.count("incidents") >= 1
    ai_outs = [o for o in outs if o.ai and o.ai.available]
    assert ai_outs
    ai = ai_outs[0].ai
    assert ai.model_name == MOCK_MODEL_NAME and "[MOCK]" in ai.verdict.summary  # honestly labelled
    assert ai.rag_sources, "RAG documents must have been retrieved for the gated event"
    # ML scored (real models) and was persisted
    assert rt.ml.available() and rt.db.count("ml_results") > 0
    assert any(
        ScoreFamily.ML_ANOMALY in o.scores and o.scores[ScoreFamily.ML_ANOMALY].available for o in outs
    )
    # graph holds the chain Word -> PowerShell -> ... and attack-stage prediction
    assert rt.graph.stats()["nodes"] >= 5
    incident = inc_outs[-1].incident
    assert incident.attack_stage is not None and incident.mitre_techniques
    assert any(
        "powershell" in step.lower() for o in outs for step in (rt.graph.chain_for(o.event_id) or [])
    ), "attack chain through PowerShell not reconstructed"
    assert rt.db.count("ai_analysis") >= 1


# --------------------------------------------------------------------------- 4
def test_4_ransomware_like_activity_high_risk_and_simulated_policy_response(rt):
    outs = run_events(rt, scenario("ransomware_like").events)
    assert best_risk(outs) >= 80  # CRITICAL
    rw = [f for o in outs for f in o.findings if f.rule_id.startswith("RW-")]
    assert {"RW-SHADOW-COPY-DESTRUCTION", "RW-COMPOSITE"} <= {f.rule_id for f in rw}
    acts = [a for o in outs for a in o.actions if a.action != ResponseAction.ALERT]
    assert acts, "policy must recommend a process response for CRITICAL ransomware"
    assert {a.action for a in acts} <= {ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS}
    assert all(a.status == ActionStatus.SIMULATED for a in acts)  # destructive disabled in test mode
    assert any(o.incident and o.incident.band == RiskBand.CRITICAL for o in outs)
    # composite is not triggered by a single file operation
    first_file_ops = [o for o in outs[2:6] if o.findings]
    assert not any(f.rule_id == "RW-COMPOSITE" for o in first_file_ops for f in o.findings)


# --------------------------------------------------------------------------- 5
def test_5_persistence_like_behavior_detected(rt):
    outs = run_events(rt, scenario("persistence_creation").events)
    rules = {f.rule_id for o in outs for f in o.findings}
    assert {"PERSIST-WIN-RUNKEY", "PERSIST-WIN-SCHTASKS", "PERSIST-LNX-SSHKEYS"} <= rules
    techs = {t for o in outs for f in o.findings for t in f.mitre_techniques}
    assert any(t.startswith("T1547") or t.startswith("T1053") for t in techs)
    assert any(o.incident for o in outs)
    assert best_risk(outs) >= 60


# --------------------------------------------------------------------------- 6
def test_6_internet_disabled_local_protection_continues(tmp_path, monkeypatch):
    def no_net(*a, **k):
        raise OSError("network disabled by test")

    monkeypatch.setattr(socket.socket, "connect", no_net)
    monkeypatch.setattr(socket, "getaddrinfo", no_net)
    cfg = sandbox_cfg(tmp_path, offline=True)
    rt = make_rt(cfg)
    try:
        outs = run_events(rt, scenario("office_powershell_chain").events + scenario("known_ioc").events)
        assert any(o.incident for o in outs)
        assert any(o.short_circuited for o in outs)
        assert rt.pipeline.stats.snapshot()["errors"] == {}
        # RAG/ML/graph are all local
        assert any(o.ai and o.ai.available for o in outs)
        assert rt.sync_worker is None  # no transport configured offline
    finally:
        rt.close()


# --------------------------------------------------------------------------- 7
class _BrokenLLM:
    model_name = "broken"

    def available(self) -> bool:
        return True

    def unload(self) -> None:
        return None

    def analyze(self, request):
        raise RuntimeError("model crashed")


@pytest.mark.parametrize("kind", ["unavailable", "raising", "null"])
def test_7_llm_unavailable_epp_ml_graph_continue(tmp_path, kind):
    if kind == "unavailable":
        llm = LocalLLMClient(LLMSettings(), None, unavailable_reason="no model")
    elif kind == "raising":
        llm = _BrokenLLM()
    else:
        llm = NullLLM()
    rt = make_rt(sandbox_cfg(tmp_path), llm=llm)
    try:
        outs = run_events(rt, scenario("office_powershell_chain").events + scenario("ransomware_like").events)
        assert all(o.ai is None or not o.ai.available for o in outs)
        assert any(o.incident for o in outs), "deterministic+ML+graph must still raise incidents"
        assert best_risk(outs) >= 80
        assert any(ScoreFamily.ML_ANOMALY in o.scores for o in outs)
        assert all(
            ScoreFamily.AI_ASSESSMENT not in o.scores or not o.scores[ScoreFamily.AI_ASSESSMENT].available
            for o in outs
        )
        if kind == "raising":
            assert rt.pipeline.stats.errors.get("llm", 0) > 0  # isolated + counted, not fatal
    finally:
        rt.close()


# --------------------------------------------------------------------------- 8
def test_8_dashboard_unavailable_endpoint_continues_and_queues_locally(tmp_path):
    class Down:
        calls = 0

        def send(self, items):
            Down.calls += 1
            raise TransportUnavailable("dashboard down")

    cfg = sandbox_cfg(tmp_path, sync_enabled=True)
    rt = make_rt(cfg, transport=Down())
    try:
        outs = run_events(rt, scenario("office_powershell_chain").events)
        assert any(o.incident for o in outs)  # detection is not blocked by the dead dashboard
        queued = rt.sync_queue.pending()
        assert queued > 0  # incident + events wait durably in the local queue
        assert rt.sync_worker is not None
        assert rt.sync_worker.run_once() == 0  # still down: nothing delivered, nothing lost
        assert Down.calls >= 1 and rt.sync_queue.pending() == queued
        assert rt.pipeline.stats.snapshot()["errors"] == {}
    finally:
        rt.close()
    # recovery against the real dashboard ingest endpoint: tests/e2e/test_acceptance_extras.py


# --------------------------------------------------------------------------- 9
def test_9_false_positive_reduced_by_baseline_and_allowlist(tmp_path):
    names = ["normal_browser", "admin_backup_script"]
    # without any baseline the same benign activity looks suspicious
    rt1 = make_rt(sandbox_cfg(tmp_path / "a"))
    try:
        before = {n: best_risk(run_events(rt1, scenario(n).events)) for n in names}
    finally:
        rt1.close()
    # LEARNING mode teaches the baseline (audited mode changes), then ACTIVE
    rt2 = make_rt(sandbox_cfg(tmp_path / "b"))
    try:
        rt2.modes.set_mode(OperatingMode.LEARNING, actor="test", reason="learn baseline")
        for n in names:
            run_events(rt2, clone_events(scenario(n).events, timedelta(hours=-2)))
        rt2.modes.set_mode(OperatingMode.ACTIVE, actor="test", reason="detect")
        after = {n: best_risk(run_events(rt2, scenario(n).events)) for n in names}
        # known-bad is never softened by a baseline
        known = run_events(rt2, scenario("known_ioc").events)
        assert known[0].risk.band == RiskBand.CRITICAL
        # allowlist (rules/allowlist: domain ok.example.test) skips ML/RAG/LLM and any response
        ev = NormalizedEvent(
            event_type=EventType.NETWORK_CONNECT, pid=9100, process_name="curl", destination_ip="198.51.100.200",
            destination_port=443, domain="ok.example.test", source="test",
        )  # fmt: skip
        out = rt2.pipeline.process(ev)
        assert out.allowlisted and not out.actions and out.ai is None
        audit = [r["event_type"] for r in rt2.db.query("SELECT event_type FROM audit_log")]
        assert audit.count("mode_change") >= 2  # never silent
    finally:
        rt2.close()
    for n in names:
        assert before[n] >= 40, f"{n} should look suspicious without baseline (got {before[n]})"
        assert after[n] < before[n] and after[n] < 40, (n, before[n], after[n])


# --------------------------------------------------------------------------- 10
def test_10_critical_attack_chain_triggers_predefined_response(rt):
    outs = run_events(rt, scenario("office_powershell_chain").events)
    actions = [a for o in outs for a in o.actions if a.action != ResponseAction.ALERT]
    kinds = {a.action for a in actions}
    assert ResponseAction.BLOCK_CONNECTION in kinds
    assert kinds & {ResponseAction.TERMINATE_PROCESS, ResponseAction.SUSPEND_PROCESS}
    assert ResponseAction.QUARANTINE_FILE in kinds
    assert all(a.status == ActionStatus.SIMULATED for a in actions)  # test mode: validated, never performed
    block = next(a for a in actions if a.action == ResponseAction.BLOCK_CONNECTION)
    assert block.target["ip"] == "203.0.113.50"
    assert block.target.get("planned_commands"), "simulating executor must show the validated firewall plan"
    # the predefined response is deterministic policy output; AI text never reaches targets
    for a in actions:
        assert "[MOCK]" not in repr(a.target)
    # destructive gate is closed independently of policy
    assert not rt.config.destructive_allowed(rt.modes.mode)
    assert rt.db.count("response_actions") >= len(actions)
    assert (
        Path(rt.config.paths.quarantine_dir).exists()
        and list(Path(rt.config.paths.quarantine_dir).glob("*")) == []
    )
