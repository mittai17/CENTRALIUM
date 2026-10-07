from __future__ import annotations

import json

import pytest

from centralium.agent import nulls
from centralium.agent.config import CentraliumConfig
from centralium.agent.graph import MemoryGraph
from centralium.agent.interfaces import (
    STAGE_PROTOCOLS,
    BehaviorResult,
    LLMRequest,
    PolicyContext,
)
from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    AIAnalysis,
    AIVerdict,
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    GraphSignal,
    MLResult,
    NoveltyResult,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
    RiskBand,
    ScoreFamily,
    Severity,
)
from centralium.agent.pipeline import Pipeline
from centralium.agent.storage import Database


# ------------------------------------------------------------------ fakes
class FakeEPP:
    def __init__(self, findings=None, raise_exc=False):
        self.findings, self.raise_exc, self.calls = findings or [], raise_exc, 0

    def inspect(self, event):
        self.calls += 1
        if self.raise_exc:
            raise RuntimeError("epp boom")
        return [f.model_copy(update={"event_id": event.event_id}) for f in self.findings]


class FakeBehavior:
    def __init__(self, score=0.0, eligible=True):
        self.score, self.eligible = score, eligible

    def analyze(self, event, findings):
        fs = []
        if self.score:
            fs.append(
                Finding(
                    event_id=event.event_id,
                    source=FindingSource.BEHAVIOR,
                    rule_id="B1",
                    title="suspicious chain",
                    score=self.score,
                    severity=Severity.HIGH,
                    mitre_techniques=["T1059.001"],
                )
            )
        return BehaviorResult(features={"x": 1.0}, findings=fs, ml_eligible=self.eligible)


class FakeML:
    model_version = "fake-1"

    def __init__(self, anomaly=0.9, raise_exc=False):
        self.anomaly, self.raise_exc, self.calls = anomaly, raise_exc, 0

    def predict(self, event, behavior):
        self.calls += 1
        if self.raise_exc:
            raise RuntimeError("ml boom")
        return MLResult(
            anomaly_score=self.anomaly,
            classification="malicious",
            classification_confidence=0.9,
            top_features=[("x", 1.0)],
            model_version="fake-1",
        )


class FakeGraph:
    def __init__(self, score=80.0, raise_exc=False):
        self.score, self.raise_exc, self.incidents, self.calls = score, raise_exc, [], 0

    def ingest(self, event, findings):
        self.calls += 1
        if self.raise_exc:
            raise RuntimeError("graph boom")
        return GraphSignal(
            score=self.score,
            attack_stage=AttackStage.EXECUTION,
            stage_confidence=0.8,
            chain=["winword -> powershell"],
        )

    def attach_incident(self, incident):
        self.incidents.append(incident)

    def chain_for(self, event_id):
        return []

    def flush(self):
        pass

    def close(self):
        pass


class FakeNovelty:
    def __init__(self, novel=True):
        self.novel, self.learned = novel, 0

    def assess(self, event, behavior):
        return NoveltyResult(is_novel=self.novel, novelty_score=1.0 if self.novel else 0.0)

    def learn(self, event):
        self.learned += 1


class FakeRAG:
    def __init__(self):
        self.calls = 0

    def retrieve(self, query, k=4):
        self.calls += 1
        from centralium.agent.models import RAGDocument

        return [RAGDocument(doc_id="mitre:T1059", source="mitre", title="PowerShell", text="...")]


class FakeLLM:
    def __init__(self, mode="ok"):
        self.mode, self.calls = mode, 0

    def available(self):
        return self.mode != "down"

    def analyze(self, request: LLMRequest):
        self.calls += 1
        if self.mode == "raise":
            raise TimeoutError("llm timed out")
        if self.mode == "invalid":
            return AIAnalysis(event_id=request.event.event_id, available=False, error="bad json")
        v = AIVerdict(
            verdict="MALICIOUS",
            severity="CRITICAL",
            confidence=0.95,
            threat_type="loader",
            summary="bad",
            attack_stage="EXECUTION",
            recommended_action="TERMINATE_PROCESS",
            mitre_techniques=["T1059.001"],
        )
        return AIAnalysis(event_id=request.event.event_id, verdict=v, model_name="fake")

    def unload(self):
        pass


class RecordingPolicy:
    def __init__(self, action=ResponseAction.TERMINATE_PROCESS, requires_approval=False):
        self.action, self.requires_approval, self.ctxs = action, requires_approval, []

    def decide(self, ctx: PolicyContext):
        self.ctxs.append(ctx)
        return PolicyDecision(
            action=self.action,
            allowed=True,
            mode=ctx.mode,
            requires_approval=self.requires_approval,
            target={"pid": 4242},
        )


class RecordingExecutor:
    def __init__(self, raise_exc=False):
        self.executed, self.raise_exc = [], raise_exc

    def execute(self, decision, event):
        if self.raise_exc:
            raise OSError("kill failed")
        self.executed.append(decision.action)
        return ActionResult(
            action=decision.action,
            status=ActionStatus.EXECUTED,
            target=decision.target,
            event_id=event.event_id,
        )

    def supported(self):
        return frozenset(ResponseAction)


def bad_hash_finding():
    return Finding(
        event_id="x",
        source=FindingSource.HASH,
        rule_id="HASH-1",
        title="known bad hash",
        score=100,
        severity=Severity.CRITICAL,
        known_malicious=True,
    )


def allow_finding():
    return Finding(event_id="x", source=FindingSource.ALLOWLIST, rule_id="AL-1", title="allowlisted", score=0)


def high_cfg(**kw):
    return CentraliumConfig(mode=OperatingMode.ACTIVE, **kw)


# ------------------------------------------------------------------ tests
def test_null_pipeline_runs_and_never_fabricates(make_event):
    p = Pipeline()
    out = p.process(make_event())
    assert out.risk is not None and out.risk.final_score == 0 and out.risk.band is RiskBand.SAFE
    assert out.incident is None and out.actions == []
    snap = p.stats.snapshot()
    assert snap["funnel"]["raw"] == 1 and snap["funnel"]["ml"] == 0 and snap["funnel"]["llm"] == 0


def test_null_implementations_satisfy_protocols():
    mapping = {
        "normalizer": nulls.NullNormalizer(),
        "epp": nulls.NullEPP(),
        "yara": nulls.NullYara(),
        "static": nulls.NullStatic(),
        "behavior": nulls.NullBehavior(),
        "ml": nulls.NullML(),
        "graph": nulls.NullGraph(),
        "novelty": nulls.NullNovelty(),
        "rag": nulls.NullRAG(),
        "llm": nulls.NullLLM(),
        "risk": nulls.ReferenceRiskEngine(),
        "policy": nulls.AlertOnlyPolicy(),
        "executor": nulls.NullExecutor(),
        "quarantine": nulls.NullQuarantine(),
        "threat_intel": nulls.NullThreatIntel(),
        "sync": nulls.NullSyncQueue(),
        "self_protection": nulls.NullSelfProtection(),
    }
    for name, impl in mapping.items():
        assert isinstance(impl, STAGE_PROTOCOLS[name]), name


def test_known_malware_short_circuits_and_never_reaches_llm(make_event):
    ml, llm, rag, nov = FakeML(), FakeLLM(), FakeRAG(), FakeNovelty()
    p = Pipeline(
        high_cfg(),
        epp=FakeEPP([bad_hash_finding()]),
        ml=ml,
        llm=llm,
        rag=rag,
        novelty=nov,
        behavior=FakeBehavior(90),
        graph=FakeGraph(),
    )
    out = p.process(make_event())
    assert out.short_circuited
    assert ml.calls == 0 and llm.calls == 0 and rag.calls == 0
    assert out.ai is None
    assert out.risk.final_score >= 90 and out.risk.band is RiskBand.CRITICAL
    assert out.incident is not None
    assert p.stats.snapshot()["counters"]["short_circuited"] == 1


def test_allowlisted_skips_expensive_stages_and_response(make_event):
    ml, llm = FakeML(), FakeLLM()
    pol = RecordingPolicy()
    p = Pipeline(
        high_cfg(),
        epp=FakeEPP([allow_finding()]),
        ml=ml,
        llm=llm,
        behavior=FakeBehavior(90),
        policy=nulls.AlertOnlyPolicy(),
        graph=FakeGraph(0),
    )
    out = p.process(make_event())
    assert out.allowlisted and ml.calls == 0 and llm.calls == 0
    assert out.actions == [] and out.incident is None
    assert pol.ctxs == []


def test_full_chain_reaches_llm_and_creates_incident(make_event, db):
    llm, rag = FakeLLM(), FakeRAG()
    p = Pipeline(
        high_cfg(),
        db=db,
        epp=FakeEPP(),
        behavior=FakeBehavior(85),
        ml=FakeML(),
        graph=FakeGraph(90),
        novelty=FakeNovelty(True),
        rag=rag,
        llm=llm,
    )
    out = p.process(make_event(process_name="powershell"))
    assert llm.calls == 1 and rag.calls == 1
    assert out.ai is not None and out.ai.rag_sources == ["mitre:T1059"]
    assert out.scores[ScoreFamily.AI_ASSESSMENT].available
    assert out.risk.band in (RiskBand.HIGH, RiskBand.CRITICAL)
    assert out.incident is not None and "T1059.001" in out.incident.mitre_techniques
    snap = p.stats.snapshot()["funnel"]
    assert snap == {"raw": 1, "epp": 1, "ml": 1, "graph": 1, "llm": 1, "incidents": 1}
    assert db.count("incidents") == 1 and db.count("ai_analysis") == 1 and db.count("ml_results") == 1
    assert db.count("events") == 1 and db.count("findings") >= 1
    assert db.audit.verify().ok and db.count("audit_log") >= 1


def test_llm_gatekeeping_requires_high_risk_and_novelty(make_event):
    # low risk -> no LLM
    llm = FakeLLM()
    p = Pipeline(high_cfg(), behavior=FakeBehavior(0), ml=FakeML(0.1), graph=FakeGraph(0), llm=llm)
    p.process(make_event())
    assert llm.calls == 0
    # high risk but NOT novel -> no LLM
    llm = FakeLLM()
    p = Pipeline(
        high_cfg(),
        behavior=FakeBehavior(95),
        ml=FakeML(),
        graph=FakeGraph(95),
        novelty=FakeNovelty(False),
        llm=llm,
    )
    p.process(make_event())
    assert llm.calls == 0
    # LLM unavailable -> skipped, pipeline continues
    llm = FakeLLM("down")
    p = Pipeline(high_cfg(), behavior=FakeBehavior(95), ml=FakeML(), graph=FakeGraph(95), llm=llm)
    out = p.process(make_event())
    assert llm.calls == 0 and out.risk is not None


@pytest.mark.parametrize("mode", ["raise", "invalid"])
def test_llm_failure_is_isolated(make_event, mode):
    p = Pipeline(high_cfg(), behavior=FakeBehavior(95), ml=FakeML(), graph=FakeGraph(95), llm=FakeLLM(mode))
    out = p.process(make_event())
    assert out.risk is not None and out.incident is not None
    assert not out.scores[ScoreFamily.AI_ASSESSMENT].available  # unavailable, NOT zero evidence
    if mode == "raise":
        assert "llm" in out.stage_errors and p.stats.errors["llm"] == 1


@pytest.mark.parametrize("stage", ["ml", "graph", "epp"])
def test_stage_failures_never_crash(make_event, stage):
    kw = {
        "ml": {"ml": FakeML(raise_exc=True)},
        "graph": {"graph": FakeGraph(raise_exc=True)},
        "epp": {"epp": FakeEPP(raise_exc=True)},
    }[stage]
    p = Pipeline(high_cfg(), behavior=FakeBehavior(70), **kw)
    out = p.process(make_event())
    assert stage in out.stage_errors
    assert out.risk is not None
    snap = p.stats.snapshot()
    assert snap["errors"][stage] == 1 and stage in snap["latency"]
    out2 = p.process(make_event())  # keeps working afterwards
    assert out2.risk is not None


def test_ml_failure_does_not_zero_out_other_evidence(make_event):
    p = Pipeline(high_cfg(), behavior=FakeBehavior(80), ml=FakeML(raise_exc=True), graph=FakeGraph(0))
    out = p.process(make_event())
    assert ScoreFamily.ML_ANOMALY not in out.scores
    ref = Pipeline(high_cfg(), behavior=FakeBehavior(80), graph=FakeGraph(0)).process(make_event())
    assert out.risk.final_score > 0
    assert out.risk.final_score == pytest.approx(ref.risk.final_score)  # evidence still counts


def test_ml_only_for_eligible_events(make_event):
    ml = FakeML()
    p = Pipeline(high_cfg(), behavior=FakeBehavior(0, eligible=False), ml=ml)
    p.process(make_event())
    assert ml.calls == 0 and p.stats.snapshot()["funnel"]["ml"] == 0


def test_destructive_actions_gated_in_demo_and_test_mode(make_event):
    for kw in ({"demo_mode": True}, {"test_mode": True}):
        ex = RecordingExecutor()
        p = Pipeline(
            high_cfg(**kw),
            behavior=FakeBehavior(95),
            ml=FakeML(),
            graph=FakeGraph(95),
            policy=RecordingPolicy(),
            executor=ex,
        )
        out = p.process(make_event())
        assert ex.executed == []
        assert out.actions[0].status is ActionStatus.SIMULATED


def test_destructive_gated_in_learning_and_passive_by_default(make_event):
    for mode in (OperatingMode.LEARNING, OperatingMode.PASSIVE):
        ex = RecordingExecutor()
        p = Pipeline(
            CentraliumConfig(mode=mode),
            behavior=FakeBehavior(95),
            ml=FakeML(),
            graph=FakeGraph(95),
            policy=RecordingPolicy(),
            executor=ex,
        )
        out = p.process(make_event())
        assert ex.executed == [] and out.actions[0].status is ActionStatus.SIMULATED


def test_active_mode_executes_and_audits(make_event, db):
    ex = RecordingExecutor()
    p = Pipeline(
        high_cfg(),
        db=db,
        behavior=FakeBehavior(95),
        ml=FakeML(),
        graph=FakeGraph(95),
        policy=RecordingPolicy(),
        executor=ex,
    )
    out = p.process(make_event())
    assert ex.executed == [ResponseAction.TERMINATE_PROCESS]
    assert out.actions[0].status is ActionStatus.EXECUTED and out.actions[0].incident_id
    assert db.count("response_actions") == 1
    assert any(e["event_type"] == "response_action" for e in db.audit.entries())


def test_approval_required_not_executed(make_event):
    ex = RecordingExecutor()
    p = Pipeline(
        high_cfg(),
        behavior=FakeBehavior(95),
        ml=FakeML(),
        graph=FakeGraph(95),
        policy=RecordingPolicy(requires_approval=True),
        executor=ex,
    )
    out = p.process(make_event())
    assert ex.executed == [] and out.actions[0].status is ActionStatus.PENDING_APPROVAL


def test_executor_failure_isolated(make_event):
    p = Pipeline(
        high_cfg(),
        behavior=FakeBehavior(95),
        ml=FakeML(),
        graph=FakeGraph(95),
        policy=RecordingPolicy(),
        executor=RecordingExecutor(raise_exc=True),
    )
    out = p.process(make_event())
    assert out.actions[0].status is ActionStatus.FAILED and "response" in out.stage_errors


def test_learning_mode_learns_and_skips_llm(make_event):
    nov, llm = FakeNovelty(), FakeLLM()
    p = Pipeline(
        CentraliumConfig(mode=OperatingMode.LEARNING),
        behavior=FakeBehavior(95),
        ml=FakeML(),
        graph=FakeGraph(95),
        novelty=nov,
        llm=llm,
    )
    p.process(make_event())
    assert nov.learned == 1 and llm.calls == 0


def test_mode_change_visible_to_pipeline_and_audited(make_event, db):
    p = Pipeline(CentraliumConfig(mode=OperatingMode.LEARNING), db=db)
    p.modes.set_mode(OperatingMode.ACTIVE, actor="admin", reason="baseline done")
    pol = RecordingPolicy(ResponseAction.ALERT)
    p.policy = pol
    p.process(make_event())
    assert pol.ctxs == [] or pol.ctxs[0].mode is OperatingMode.ACTIVE
    assert any(e["event_type"] == "mode_change" for e in db.audit.entries())


def test_process_raw_normalization_failure_returns_none():
    p = Pipeline()
    assert p.process_raw({"event_type": "nonsense"}) is None
    assert p.stats.errors["normalize"] == 1
    out = p.process_raw({"event_type": EventType.PROCESS_START.value, "process_name": "ls"})
    assert out is not None


def test_persistence_failure_isolated(make_event):
    db = Database(":memory:")
    p = Pipeline(db=db)
    db.close()  # every persist/audit now fails
    out = p.process(make_event())
    assert out.risk is not None and "persist" in out.stage_errors


def test_latency_timers_recorded(make_event):
    p = Pipeline(behavior=FakeBehavior(10), ml=FakeML())
    for _ in range(5):
        p.process(make_event())
    lat = p.stats.snapshot()["latency"]
    assert lat["end_to_end"]["count"] == 5 and lat["ml"]["p95_ms"] >= 0


def test_pipeline_executes_ordered_plan_multiple_actions(make_event, db):
    class MultiPlanPolicy:
        def decide(self, ctx):
            return self.plan(ctx)[0]

        def plan(self, ctx):
            return [
                PolicyDecision(
                    action=ResponseAction.BLOCK_CONNECTION,
                    allowed=True,
                    target={"ip": "198.51.100.1", "port": 443},
                    reason="c2 block",
                ),
                PolicyDecision(
                    action=ResponseAction.TERMINATE_PROCESS,
                    allowed=True,
                    target={"pid": ctx.event.pid or 1234},
                    reason="kill dropper",
                ),
                PolicyDecision(
                    action=ResponseAction.QUARANTINE_FILE,
                    allowed=True,
                    target={"path": "/tmp/malware.bin"},
                    reason="quarantine drop",
                ),
            ]

    ex = RecordingExecutor()
    p = Pipeline(
        high_cfg(),
        db=db,
        behavior=FakeBehavior(95),
        policy=MultiPlanPolicy(),
        executor=ex,
    )
    ev = make_event(pid=5000, process_name="dropper.exe")
    out = p.process(ev)
    assert len(out.actions) == 3
    executed_actions = [a.action for a in out.actions]
    assert executed_actions == [
        ResponseAction.BLOCK_CONNECTION,
        ResponseAction.TERMINATE_PROCESS,
        ResponseAction.QUARANTINE_FILE,
    ]
    assert ex.executed == [
        ResponseAction.BLOCK_CONNECTION,
        ResponseAction.TERMINATE_PROCESS,
        ResponseAction.QUARANTINE_FILE,
    ]
    assert db.count("response_actions") == 3


def test_pipeline_process_approved_actions_flows_through_policy_gate(db):
    from centralium.agent.models import ActionResult, NormalizedEvent

    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=9999,
        process_name="evil.exe",
        executable_path="/tmp/evil.exe",
        source="test",
        host_id="localhost",
    )
    ex = RecordingExecutor()
    pol = RecordingPolicy(action=ResponseAction.TERMINATE_PROCESS)
    p = Pipeline(high_cfg(), db=db, policy=pol, executor=ex)
    p.repo.add_event(ev)

    target = {"event_id": ev.event_id, "pid": 9999, "process_name": "evil.exe"}
    action = ActionResult(
        action=ResponseAction.TERMINATE_PROCESS,
        status=ActionStatus.APPROVED,
        target=target,
        event_id=ev.event_id,
        detail="approved by operator",
    )
    p.repo.add_action(action)
    assert db.count("response_actions") == 1

    dispatched = p.process_approved_actions()
    assert dispatched == 1
    assert ex.executed == [ResponseAction.TERMINATE_PROCESS]
    row = db.query_one("SELECT status, detail FROM response_actions WHERE action_id = ?", (action.action_id,))
    assert row["status"] == "executed"


def test_pipeline_writes_graph_snapshots_on_incident_and_manually(make_event, db):
    graph = MemoryGraph()
    p = Pipeline(
        high_cfg(),
        db=db,
        epp=FakeEPP([bad_hash_finding()]),
        graph=graph,
    )
    # Process event that creates an incident
    ev = make_event()
    out = p.process(ev)
    assert out.incident is not None

    # Snapshot should be automatically written to graph_snapshots table
    assert db.count("graph_snapshots") >= 1
    row = db.query_one("SELECT * FROM graph_snapshots ORDER BY snapshot_id DESC LIMIT 1")
    assert row is not None
    snap = json.loads(row["snapshot"])
    assert "nodes" in snap and "edges" in snap

    # Manual snapshot_graph call also works
    count = p.snapshot_graph()
    assert count >= 1

