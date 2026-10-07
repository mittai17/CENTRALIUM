"""Replay demo scenarios through the full pipeline and summarise what actually happened.

Everything in the report is read back from the pipeline outcomes / database; nothing is
hard-coded. The safety assertion at the end proves no destructive action was *executed*.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from centralium.agent.demo.scenarios import DemoScenario, build_scenarios
from centralium.agent.models import (
    DESTRUCTIVE_ACTIONS,
    ActionStatus,
    NormalizedEvent,
    OperatingMode,
    PipelineOutcome,
    RiskBand,
    ScoreFamily,
    new_id,
)
from centralium.agent.runtime import Runtime, set_mode_audited


class DemoSafetyError(RuntimeError):
    """Raised if anything destructive could have run in demo/test mode."""


_BAND_ORDER = [RiskBand.SAFE, RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL]


@dataclass
class ScenarioResult:
    name: str
    title: str
    expect: str
    events: int = 0
    max_risk: float = 0.0
    max_band: RiskBand = RiskBand.SAFE
    findings: int = 0
    known_short_circuited: int = 0
    allowlisted: int = 0
    ml_scored: int = 0
    max_anomaly: float = 0.0
    classifications: Counter[str] = field(default_factory=Counter)
    graph_stage: str | None = None
    llm_calls: int = 0
    ai_ids: set[str] = field(default_factory=set)  # distinct analyses (cached reuse is not a new call)
    llm_labels: set[str] = field(default_factory=set)
    llm_latency_ms: list[float] = field(default_factory=list)
    rag_sources: set[str] = field(default_factory=set)
    incident_ids: list[str] = field(default_factory=list)
    top_action: str | None = None
    actions: Counter[str] = field(default_factory=Counter)  # "ACTION/status" -> n
    rules: Counter[str] = field(default_factory=Counter)
    mitre: set[str] = field(default_factory=set)
    stage_errors: dict[str, str] = field(default_factory=dict)

    @property
    def met_expectation(self) -> bool:
        if self.expect == "benign":
            return not self.incident_ids and _BAND_ORDER.index(self.max_band) < _BAND_ORDER.index(
                RiskBand.HIGH
            )
        if self.expect == "known":
            return self.known_short_circuited > 0 and self.llm_calls == 0
        return bool(self.incident_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "expect": self.expect,
            "met_expectation": self.met_expectation,
            "events": self.events,
            "max_risk": round(self.max_risk, 1),
            "max_band": self.max_band.value,
            "findings": self.findings,
            "known_short_circuited": self.known_short_circuited,
            "allowlisted": self.allowlisted,
            "ml_scored": self.ml_scored,
            "max_anomaly_score": round(self.max_anomaly, 3),
            "ml_classes": dict(self.classifications),
            "graph_stage": self.graph_stage,
            "llm_calls": self.llm_calls,
            "llm_models": sorted(self.llm_labels),
            "llm_latency_ms": [round(x) for x in self.llm_latency_ms],
            "rag_sources": sorted(self.rag_sources)[:6],
            "incidents": len(set(self.incident_ids)),
            "actions": dict(self.actions),
            "top_rules": [r for r, _ in self.rules.most_common(4)],
            "mitre": sorted(self.mitre),
            "stage_errors": self.stage_errors,
        }


@dataclass
class DemoReport:
    results: list[ScenarioResult]
    funnel: dict[str, int]
    counters: dict[str, int]
    latency_e2e: dict[str, float]
    llm_kind: str
    llm_label: str
    ml_model: str
    graph_backend: str
    graph_stats: dict[str, int]
    db_path: str
    mode_final: str
    destructive_allowed: bool
    executor_simulate: bool
    incidents: int
    actions_by_status: dict[str, int]
    snapshot_nodes: int
    baseline_events: int
    wall_seconds: float
    safety_ok: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenarios": [r.to_dict() for r in self.results],
            "funnel": self.funnel,
            "counters": self.counters,
            "latency_end_to_end_ms": self.latency_e2e,
            "llm": {"kind": self.llm_kind, "label": self.llm_label},
            "ml_model": self.ml_model,
            "graph": {"backend": self.graph_backend, **self.graph_stats},
            "db": self.db_path,
            "mode": self.mode_final,
            "destructive_allowed": self.destructive_allowed,
            "executor_simulate": self.executor_simulate,
            "incidents": self.incidents,
            "actions_by_status": self.actions_by_status,
            "graph_snapshot_nodes": self.snapshot_nodes,
            "baseline_events": self.baseline_events,
            "wall_seconds": round(self.wall_seconds, 2),
            "safety_ok": self.safety_ok,
        }

    def format_text(self) -> str:
        lines = [
            "CENTRALIUM DEMO SUMMARY (synthetic events; destructive response disabled)",
            f"  LLM: {self.llm_kind} - {self.llm_label}",
            f"  ML models: {self.ml_model}   graph: {self.graph_backend} {self.graph_stats}",
            "  funnel raw->epp->ml->graph->llm->incidents: "
            + " -> ".join(str(self.funnel[k]) for k in ("raw", "epp", "ml", "graph", "llm", "incidents")),
            f"  mode: {self.mode_final}  destructive_allowed={self.destructive_allowed}  "
            f"executor_simulate={self.executor_simulate}  safety_ok={self.safety_ok}",
            "",
        ]
        hdr = (
            f"  {'scenario':26} {'expect':7} {'ok':3} {'ev':>4} {'risk':>5} {'band':8} "
            f"{'ml':>3} {'llm':>3} {'inc':>3}  actions"
        )
        lines.append(hdr)
        for r in self.results:
            acts = ", ".join(f"{k} x{v}" for k, v in r.actions.items()) or "-"
            lines.append(
                f"  {r.name:26} {r.expect:7} {'yes' if r.met_expectation else 'NO':3} {r.events:>4} "
                f"{r.max_risk:>5.0f} {r.max_band.value:8} {r.ml_scored:>3} {r.llm_calls:>3} "
                f"{len(set(r.incident_ids)):>3}  {acts}"
            )
        lines.append("")
        lines.append(f"  incidents: {self.incidents}   actions by status: {self.actions_by_status}")
        lines.append(f"  graph snapshot for dashboard: {self.snapshot_nodes} nodes   db: {self.db_path}")
        lines.append(f"  wall time: {self.wall_seconds:.1f}s")
        return "\n".join(lines)


def clone_events(events: list[NormalizedEvent], shift: timedelta) -> list[NormalizedEvent]:
    """Fresh copies (new event ids, shifted timestamps) so a scenario can be replayed again."""
    return [e.model_copy(update={"event_id": new_id(), "timestamp": e.timestamp + shift}) for e in events]


def assert_no_destructive(rt: Runtime) -> None:
    """Hard checks that demo/test mode cannot have performed (or be about to perform) anything real."""
    if rt.config.destructive_allowed(rt.modes.mode):
        raise DemoSafetyError("destructive response is enabled")
    if getattr(rt.executor, "simulate", False) is not True:
        raise DemoSafetyError("response executor is not in simulate mode")
    rows = rt.db.query("SELECT action, status FROM response_actions")
    bad = [
        (r["action"], r["status"])
        for r in rows
        if r["action"] in {a.value for a in DESTRUCTIVE_ACTIONS}
        and r["status"] not in (ActionStatus.SIMULATED.value, ActionStatus.DENIED.value)
    ]
    if bad:
        raise DemoSafetyError(f"destructive action recorded with a non-simulated status: {bad[:3]}")


def _absorb(res: ScenarioResult, out: PipelineOutcome | None) -> None:
    if out is None:
        return
    res.events += 1
    res.findings += len(out.findings)
    for f in out.findings:
        res.rules[f.rule_id] += 1
        res.mitre.update(f.mitre_techniques)
    if out.short_circuited:
        res.known_short_circuited += 1
    if out.allowlisted:
        res.allowlisted += 1
    if out.risk is not None:
        if out.risk.final_score > res.max_risk:
            res.max_risk = out.risk.final_score
        if _BAND_ORDER.index(out.risk.band) > _BAND_ORDER.index(res.max_band):
            res.max_band = out.risk.band
    ml = out.scores.get(ScoreFamily.ML_ANOMALY)
    if ml is not None and ml.available:
        res.ml_scored += 1
        res.max_anomaly = max(res.max_anomaly, ml.score / 100.0)
    if out.ai is not None and out.ai.analysis_id not in res.ai_ids:
        res.ai_ids.add(out.ai.analysis_id)
        res.llm_calls += 1
        if out.ai.available and out.ai.verdict is not None:
            res.llm_labels.add(out.ai.model_name)
            res.llm_latency_ms.append(out.ai.latency_ms)
            res.rag_sources.update(out.ai.rag_sources)
        else:
            res.llm_labels.add(f"unavailable:{out.ai.error}")
    if out.incident is not None:
        res.incident_ids.append(out.incident.incident_id)
        if out.incident.attack_stage:
            res.graph_stage = out.incident.attack_stage.value
    for a in out.actions:
        res.actions[f"{a.action.value}/{a.status.value}"] += 1
    res.stage_errors.update(out.stage_errors)


def run_demo(
    rt: Runtime,
    scenarios: list[DemoScenario] | None = None,
    *,
    baseline_phase: bool = True,
    actor: str = "demo",
    on_scenario_complete: Callable[[ScenarioResult, int, int], None] | None = None,
) -> DemoReport:
    """Replay ``scenarios`` (default: all) in two audited phases:

    1. LEARNING: baseline scenarios teach the novelty filter what normal looks like;
    2. ACTIVE (still demo/test: simulated executor, destructive gate closed): everything is replayed.
    """
    if not (rt.config.demo_mode or rt.config.test_mode):
        raise DemoSafetyError("run_demo requires demo_mode or test_mode")
    t0 = time.perf_counter()
    scenarios = scenarios if scenarios is not None else build_scenarios()
    baseline_events = 0
    if baseline_phase:
        base = [s for s in scenarios if s.baseline]
        if base:
            set_mode_audited(
                rt, OperatingMode.LEARNING, actor, "demo phase 1: learn baseline of normal activity"
            )
            last = max(e.timestamp for s in base for e in s.events)
            for s in base:
                for ev in clone_events(
                    s.events, -(last - min(e.timestamp for e in s.events)) - timedelta(minutes=5)
                ):
                    rt.pipeline.process(ev)
                    baseline_events += 1
    set_mode_audited(
        rt, OperatingMode.ACTIVE, actor, "demo phase 2: detection (destructive response simulated only)"
    )
    results: list[ScenarioResult] = []
    total_scenarios = len(scenarios)
    for idx, s in enumerate(scenarios, start=1):
        res = ScenarioResult(s.name, s.title, s.expect)
        for ev in s.events:
            _absorb(res, rt.pipeline.process(ev))
        results.append(res)
        if on_scenario_complete is not None:
            on_scenario_complete(res, idx, total_scenarios)
    nodes = rt.snapshot_graph()
    assert_no_destructive(rt)
    snap = rt.pipeline.stats.snapshot()
    rows = rt.db.query("SELECT status, COUNT(*) n FROM response_actions GROUP BY status")
    gstats = rt.graph.stats() if hasattr(rt.graph, "stats") else {}
    return DemoReport(
        results=results,
        funnel=snap["funnel"],
        counters=snap["counters"],
        latency_e2e={k: round(v, 3) for k, v in snap["latency"].get("end_to_end", {}).items()},
        llm_kind=rt.llm_kind,
        llm_label=rt.llm_label,
        ml_model=rt.ml.model_version,
        graph_backend=type(rt.graph).__name__,
        graph_stats=dict(gstats),
        db_path=str(rt.db.path),
        mode_final=rt.modes.mode.value,
        destructive_allowed=rt.config.destructive_allowed(rt.modes.mode),
        executor_simulate=bool(getattr(rt.executor, "simulate", False)),
        incidents=rt.db.count("incidents"),
        actions_by_status={r["status"]: r["n"] for r in rows},
        snapshot_nodes=nodes,
        baseline_events=baseline_events,
        wall_seconds=time.perf_counter() - t0,
        safety_ok=True,
    )
