"""Detection pipeline orchestrator.

Order (spec): normalize -> fast EPP (+YARA/static) -> behavior features -> ML -> graph
-> novelty -> RAG -> LLM -> risk -> policy -> response -> audit.

Guarantees
* Every stage is failure-isolated: an exception is logged, counted, recorded in
  ``PipelineOutcome.stage_errors`` and the pipeline continues with that stage's
  output treated as *unavailable* (never as zero risk). ML/graph/LLM failures can
  never crash ``process``.
* Known-malicious findings short-circuit: ML/novelty/RAG/LLM are skipped (known malware
  is NEVER sent to the LLM) and the event goes straight to risk -> policy -> response.
* Allowlisted events skip ML/RAG/LLM and produce no response (false-positive reduction).
* LLM gatekeeping: only events with ``pre_risk >= config.llm.gate_min_pre_risk`` that are
  novel (if ``gate_require_novel``), LLM-available, not short-circuited/allowlisted
  and not in LEARNING mode reach RAG + LLM.
* Hard destructive gate: non-ALERT actions are only handed to the executor if
  ``config.destructive_allowed(live_mode)`` (never in demo/test/LEARNING) and the policy
  decision does not require approval; otherwise they are recorded as SIMULATED /
  PENDING_APPROVAL. The LLM only ever influences this through the PolicyEngine.
* Per-stage counters (funnel raw -> epp -> ml -> graph -> llm -> incidents) and latency
  timers are exposed via ``Pipeline.stats.snapshot()``. Numbers are measured, not assumed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from centralium.agent.config import CentraliumConfig, ModeManager
from centralium.agent.graph.snapshot import write_graph_snapshot
from centralium.agent.interfaces import (
    BehaviorEngine,
    BehaviorResult,
    EPPEngine,
    GraphAdapter,
    IOCMatch,
    LLMClient,
    LLMRequest,
    MLEngine,
    Normalizer,
    NoveltyFilter,
    PolicyContext,
    PolicyEngine,
    RAGRetriever,
    ResponseExecutor,
    RiskEngine,
    StaticAnalyzer,
    ThreatIntelStore,
    YaraScanner,
)
from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    AIAnalysis,
    DetectionResult,
    EventType,
    Finding,
    FindingSource,
    GraphSignal,
    Incident,
    MLResult,
    NormalizedEvent,
    NoveltyResult,
    OperatingMode,
    PipelineOutcome,
    PolicyDecision,
    RAGDocument,
    ResponseAction,
    RiskAssessment,
    RiskBand,
    ScoreFamily,
    Severity,
    StaticAnalysisResult,
    Verdict,
)
from centralium.agent.nulls import (
    AlertOnlyPolicy,
    NullBehavior,
    NullEPP,
    NullExecutor,
    NullGraph,
    NullLLM,
    NullML,
    NullNormalizer,
    NullNovelty,
    NullRAG,
    NullStatic,
    NullThreatIntel,
    NullYara,
    ReferenceRiskEngine,
)
from centralium.agent.storage import Database, Repository
from centralium.agent.storage.projection import project_event

log = logging.getLogger("centralium.pipeline")
T = TypeVar("T")

STAGES = (
    "normalize",
    "epp",
    "yara",
    "static",
    "behavior",
    "ml",
    "graph",
    "novelty",
    "rag",
    "llm",
    "risk",
    "policy",
    "response",
    "persist",
    "audit",
)
_SCANNABLE = {EventType.PROCESS_START, EventType.FILE_CREATE, EventType.FILE_MODIFY}
_DETERMINISTIC_SOURCES = {
    FindingSource.RULE,
    FindingSource.BEHAVIOR,
    FindingSource.LOLBIN,
    FindingSource.PERSISTENCE,
    FindingSource.RANSOMWARE,
    FindingSource.SELF_PROTECTION,
    FindingSource.IOC,
    FindingSource.HASH,
}
_TI_SOURCES = {FindingSource.IOC, FindingSource.HASH}
_PROCESS_ACTIONS = {ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS}
_BAND_ORDER = [RiskBand.SAFE, RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL]
INCIDENT_WINDOW_SEC = 900.0  # events of the same process lineage within this window join one incident
LINEAGE_MIN_SCORE = 40.0  # findings at least this strong stay attached to their process lineage
LLM_REUSE_SEC = 300.0  # reuse an AI analysis for the same process lineage this long
LLM_REANALYZE_DELTA = 15.0  # ...unless the pre-risk rose by this much
ACTION_DEDUP_SEC = 600.0  # an identical action on an identical target is not repeated within this window
_SEV_SCORE = {
    Severity.INFO: 5.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 95.0,
}


# --------------------------------------------------------------------------- stats
class PipelineStats:
    """Thread-safe counters + latency timers (ms)."""

    FUNNEL = ("raw", "epp", "ml", "graph", "llm", "incidents")

    def __init__(self, window: int = 2048) -> None:
        self._lock = threading.Lock()
        self.counters: dict[str, int] = {}
        self.errors: dict[str, int] = {}
        self._lat: dict[str, deque[float]] = {}
        self._lat_total: dict[str, float] = {}
        self._lat_count: dict[str, int] = {}
        self._window = window
        self.started = time.time()

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + n

    def error(self, stage: str) -> None:
        with self._lock:
            self.errors[stage] = self.errors.get(stage, 0) + 1

    def observe(self, stage: str, ms: float) -> None:
        with self._lock:
            self._lat.setdefault(stage, deque(maxlen=self._window)).append(ms)
            self._lat_total[stage] = self._lat_total.get(stage, 0.0) + ms
            self._lat_count[stage] = self._lat_count.get(stage, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            lat: dict[str, dict[str, float]] = {}
            for stage, dq in self._lat.items():
                vals = sorted(dq)
                n = len(vals)
                lat[stage] = {
                    "count": float(self._lat_count[stage]),
                    "mean_ms": self._lat_total[stage] / self._lat_count[stage],
                    "p50_ms": vals[n // 2],
                    "p95_ms": vals[min(n - 1, int(n * 0.95))],
                    "max_ms": vals[-1],
                }
            return {
                "counters": dict(self.counters),
                "funnel": {k: self.counters.get(k, 0) for k in self.FUNNEL},
                "errors": dict(self.errors),
                "latency": lat,
                "uptime_sec": time.time() - self.started,
            }


# --------------------------------------------------------------------------- approvals
class ApprovedActionDispatcher:
    """Executes ``response_actions`` rows an operator approved in the dashboard.

    Gate order (each failure records the reason and never executes):
    1. the row must still be ``approved`` (atomically claimed -> ``dispatching``);
    2. the hard destructive gate ``config.destructive_allowed(live mode)`` (never in
       demo/test/LEARNING) - otherwise the row becomes ``simulated``;
    3. the recorded event must exist and the policy ``recheck`` must pass (allowed_actions,
       target validation, target == recorded event, protected processes/paths);
    4. the executor re-validates everything again. The decision is a ``PolicyDecision`` built
       from stored structured fields; no stored text is ever interpreted as a command (never a shell).
    """

    def __init__(
        self,
        db: Database,
        config: CentraliumConfig,
        modes: ModeManager,
        policy: Any,
        executor: Any,
    ) -> None:
        self.db, self.config, self.modes, self.policy, self.executor = db, config, modes, policy, executor
        self.repo = Repository(db)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self, limit: int = 50) -> int:
        rows = self.db.query(
            "SELECT * FROM response_actions WHERE status = 'approved' ORDER BY timestamp LIMIT ?",
            (limit,),
        )
        done = 0
        for row in rows:
            if self._dispatch(dict(row)):
                done += 1
        return done

    def dispatch_by_id(self, action_id: str) -> bool:
        row = self.db.query_one(
            "SELECT * FROM response_actions WHERE action_id = ? AND status = 'approved'",
            (action_id,),
        )
        if row is None:
            return False
        return self._dispatch(dict(row))

    def _finish(self, action_id: str, status: str, detail: str) -> None:
        self.db.execute(
            "UPDATE response_actions SET status = ?, detail = ? WHERE action_id = ?",
            (status, detail[:1000], action_id),
        )
        self.db.audit.append(
            "approvals", "approved_action_" + status, {"action_id": action_id, "detail": detail[:300]}
        )

    def _dispatch(self, row: dict[str, Any]) -> bool:
        aid = row["action_id"]
        claimed = self.db.execute(
            "UPDATE response_actions SET status = 'dispatching' WHERE action_id = ? AND status = 'approved'",
            (aid,),
        )
        if claimed != 1:
            return False
        try:
            action = ResponseAction(row["action"])
            target = json.loads(row["target"] or "{}")
            if not isinstance(target, dict):
                raise ValueError("stored target is not an object")
        except (ValueError, TypeError) as exc:
            self._finish(aid, ActionStatus.FAILED.value, f"unusable stored action: {exc}")
            return True
        mode = self.modes.mode
        if not self.config.destructive_allowed(mode):
            self._finish(
                aid,
                ActionStatus.SIMULATED.value,
                f"approved, but destructive response is disabled (mode={mode.value}, "
                f"demo={self.config.demo_mode}, test={self.config.test_mode}); nothing executed",
            )
            return True
        ev = self.repo.get_event(row["event_id"]) if row.get("event_id") else None
        if ev is None:
            self._finish(aid, ActionStatus.FAILED.value, "recorded event not found; refusing to act")
            return True
        recheck = getattr(self.policy, "recheck", None)
        if callable(recheck):
            refusal = recheck(action, target, ev)
            if refusal:
                self._finish(aid, ActionStatus.FAILED.value, f"refused by policy gate: {refusal}")
                return True
        clean = {k: v for k, v in target.items() if k not in ("simulate", "planned_commands")}
        decision = PolicyDecision(
            action=action,
            allowed=True,
            requires_approval=False,
            mode=mode,
            reason="operator-approved via dashboard",
            target=clean,
        )
        try:
            res = self.executor.execute(decision, ev)
        except Exception as exc:
            log.exception("approved action failed")
            self._finish(aid, ActionStatus.FAILED.value, f"executor error: {type(exc).__name__}: {exc}")
            return True
        self._finish(aid, res.status.value, res.detail)
        return True

    def start(self, interval_s: float = 2.0) -> None:
        if self._thread is not None:
            return

        def loop() -> None:
            while not self._stop.wait(interval_s):
                try:
                    self.run_once()
                except Exception:
                    log.exception("approval dispatcher error")

        self._thread = threading.Thread(target=loop, name="approvals", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


# --------------------------------------------------------------------------- pipeline
class Pipeline:
    def __init__(
        self,
        config: CentraliumConfig | None = None,
        *,
        db: Database | None = None,
        normalizer: Normalizer | None = None,
        epp: EPPEngine | None = None,
        yara: YaraScanner | None = None,
        static: StaticAnalyzer | None = None,
        behavior: BehaviorEngine | None = None,
        ml: MLEngine | None = None,
        graph: GraphAdapter | None = None,
        novelty: NoveltyFilter | None = None,
        rag: RAGRetriever | None = None,
        llm: LLMClient | None = None,
        risk: RiskEngine | None = None,
        policy: PolicyEngine | None = None,
        executor: ResponseExecutor | None = None,
        threat_intel: ThreatIntelStore | None = None,
        mode_manager: ModeManager | None = None,
        on_incident: Callable[[Incident], None] | None = None,
    ) -> None:
        self.config = config or CentraliumConfig()
        self.db = db
        self.repo = Repository(db) if db is not None else None
        self.normalizer = normalizer or NullNormalizer()
        self.epp = epp or NullEPP()
        self.yara = yara or NullYara()
        self.static = static or NullStatic()
        self.behavior = behavior or NullBehavior()
        self.ml = ml or NullML()
        self.graph = graph or NullGraph()
        self.novelty = novelty or NullNovelty()
        self.rag = rag or NullRAG()
        self.llm = llm or NullLLM()
        self.risk = risk or ReferenceRiskEngine(self.config.risk)
        self.policy = policy or AlertOnlyPolicy()
        self.executor = executor or NullExecutor()
        self.threat_intel = threat_intel or NullThreatIntel()
        self.modes = mode_manager or ModeManager(self.config, self._audit_fn(db))
        self.on_incident = on_incident
        self.approvals = (
            ApprovedActionDispatcher(db, self.config, self.modes, self.policy, self.executor)
            if db is not None
            else None
        )
        self._events_since_graph_snapshot = 0
        self._last_graph_snapshot_time = time.monotonic()
        self._graph_snapshot_interval_events = 50
        self.stats = PipelineStats()
        self._inc_lock = threading.Lock()
        self._incident_index: dict[tuple[Any, ...], tuple[Incident, float]] = {}
        self._action_seen: dict[tuple[Any, ...], float] = {}
        self._lineage: dict[tuple[str, int], list[Finding]] = {}
        self._ai_cache: dict[tuple[str, int], tuple[float, float, AIAnalysis]] = {}

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _audit_fn(db: Database | None) -> Callable[[str, str, dict[str, Any]], None] | None:
        if db is None:
            return None

        def _fn(actor: str, event_type: str, details: dict[str, Any]) -> None:
            db.audit.append(actor, event_type, details)

        return _fn

    def _stage(self, name: str, fn: Callable[[], T], default: T, out: PipelineOutcome) -> T:
        t0 = time.perf_counter()
        try:
            return fn()
        except Exception as exc:
            log.exception("stage %s failed", name)
            self.stats.error(name)
            out.stage_errors[name] = f"{type(exc).__name__}: {exc}"
            return default
        finally:
            self.stats.observe(name, (time.perf_counter() - t0) * 1000.0)

    def _audit(self, actor: str, event_type: str, details: dict[str, Any], out: PipelineOutcome) -> None:
        if self.db is None:
            return
        self._stage(
            "audit", lambda: self.db.audit.append(actor, event_type, details) if self.db else 0, 0, out
        )

    def _persist(self, out: PipelineOutcome, fn: Callable[[Repository], None]) -> None:
        if self.repo is None:
            return
        repo = self.repo
        self._stage("persist", lambda: fn(repo), None, out)

    def _scan_target(self, ev: NormalizedEvent) -> Path | None:
        if ev.event_type not in _SCANNABLE:
            return None
        raw = ev.file_path if ev.event_type != EventType.PROCESS_START else ev.executable_path
        raw = raw or ev.executable_path or ev.file_path
        if not raw:
            return None
        try:
            p = Path(raw).resolve()
            if not p.is_file():
                return None
            if p.stat().st_size > self.config.resource_profile.max_scan_file_mb * 1024 * 1024:
                return None
            return p
        except (OSError, ValueError):
            return None

    @staticmethod
    def _noisy_or(scores: list[float]) -> float:
        p = 1.0
        for s in scores:
            p *= 1.0 - max(0.0, min(100.0, s)) / 100.0
        return 100.0 * (1.0 - p)

    def _evidence_scores(
        self, findings: list[Finding], static_res: StaticAnalysisResult | None
    ) -> dict[ScoreFamily, DetectionResult]:
        scores: dict[ScoreFamily, DetectionResult] = {}
        det = [f for f in findings if f.source in _DETERMINISTIC_SOURCES]
        scores[ScoreFamily.DETERMINISTIC_EVIDENCE] = DetectionResult(
            family=ScoreFamily.DETERMINISTIC_EVIDENCE,
            score=self._noisy_or([f.score for f in det]),
            confidence=max((f.confidence for f in det), default=1.0),
            reasons=[f.title for f in det][:10],
        )
        ti = [f for f in findings if f.source in _TI_SOURCES]
        if ti:
            scores[ScoreFamily.THREAT_INTEL] = DetectionResult(
                family=ScoreFamily.THREAT_INTEL,
                score=100.0
                if any(f.known_malicious for f in ti)
                else max((f.score for f in ti), default=0.0),
                confidence=max((f.confidence for f in ti), default=1.0),
                reasons=[f.title for f in ti][:10],
            )
        else:
            # "Not in any local IOC feed" says nothing about safety (feeds only list *known* bad);
            # counting it as 0 would dilute every unknown-threat score by the family weight.
            scores[ScoreFamily.THREAT_INTEL] = DetectionResult.unavailable(
                ScoreFamily.THREAT_INTEL, "no threat-intel match"
            )
        yara = [f for f in findings if f.source == FindingSource.YARA]
        st = static_res.score if static_res else 0.0
        if static_res is None and not yara:
            # No file was scanned for this event: "not run" is not evidence of safety.
            scores[ScoreFamily.STATIC_MALWARE] = DetectionResult.unavailable(
                ScoreFamily.STATIC_MALWARE, "no file scanned for this event"
            )
            return scores
        scores[ScoreFamily.STATIC_MALWARE] = DetectionResult(
            family=ScoreFamily.STATIC_MALWARE,
            score=max([st] + [100.0 if f.known_malicious else f.score for f in yara]),
            reasons=(
                [f"static: {i}" for i in (static_res.indicators if static_res else [])][:5]
                + [f.title for f in yara][:5]
            ),
        )
        return scores

    @staticmethod
    def _ai_score(ai: AIAnalysis) -> DetectionResult:
        if not ai.available or ai.verdict is None:
            return DetectionResult.unavailable(ScoreFamily.AI_ASSESSMENT, ai.error or "AI unavailable")
        v = ai.verdict
        base = _SEV_SCORE[v.severity]
        if v.verdict == Verdict.BENIGN:
            base = min(base, 10.0)
        elif v.verdict == Verdict.UNKNOWN:
            base = min(base, 40.0)
        return DetectionResult(
            family=ScoreFamily.AI_ASSESSMENT,
            score=base,
            confidence=v.confidence,
            reasons=[v.summary[:200]],
            details={"verdict": v.verdict.value},
        )

    # ------------------------------------------------------------------ LLM re-analysis control
    def _cached_ai(self, ev: NormalizedEvent, pre_risk: float) -> AIAnalysis | None:
        """Reuse a recent analysis for the same process lineage instead of calling the (slow, CPU)
        model for every event of one ongoing attack. A materially higher risk re-analyzes."""
        if ev.pid is None:
            return None
        now = time.monotonic()
        with self._inc_lock:
            hit = self._ai_cache.get((ev.host_id, ev.pid))
        if hit is None:
            return None
        ts, risk0, ai = hit
        if (
            now - ts > LLM_REUSE_SEC
            or pre_risk >= risk0 + LLM_REANALYZE_DELTA
            or _BAND_ORDER.index(self.config.risk.band_for(pre_risk))
            > _BAND_ORDER.index(self.config.risk.band_for(risk0))
        ):
            return None
        return ai

    def _remember_ai(self, ev: NormalizedEvent, ai: AIAnalysis, pre_risk: float) -> None:
        if ev.pid is None or not ai.available:
            return  # a failed analysis is retried (the LLM client has its own failure backoff)
        with self._inc_lock:
            self._ai_cache[(ev.host_id, ev.pid)] = (time.monotonic(), pre_risk, ai)
            if len(self._ai_cache) > 5_000:
                self._ai_cache = dict(list(self._ai_cache.items())[-2_500:])

    # ------------------------------------------------------------------ lineage evidence
    def _lineage_keys(self, ev: NormalizedEvent) -> list[tuple[str, int]]:
        keys: list[tuple[str, int]] = []
        if ev.pid is not None:
            keys.append((ev.host_id, ev.pid))
        if ev.ppid is not None:
            keys.append((ev.host_id, ev.ppid))
        return keys

    def _carried_findings(self, ev: NormalizedEvent, current: list[Finding]) -> list[Finding]:
        """Strong deterministic findings recently raised for this process/parent (event time).

        A burst of renames is only individually suspicious at the moment the composite fires;
        later events of the same process must still be scored against that evidence, otherwise
        the risk of a running attack decays to zero between findings. Carried findings are used
        for scoring and policy only (never re-persisted) and known-malicious findings are not
        carried (their pid-reuse risk is not worth a false termination)."""
        have = {f.rule_id for f in current}
        out: list[Finding] = []
        with self._inc_lock:
            for key in self._lineage_keys(ev):
                hit = self._lineage.get(key)
                if hit is None:
                    continue
                for f in hit:
                    age = (ev.timestamp - f.timestamp).total_seconds()
                    if f.rule_id not in have and 0 <= age <= INCIDENT_WINDOW_SEC:
                        out.append(f)
                        have.add(f.rule_id)
        return out

    def _remember_findings(self, ev: NormalizedEvent, findings: list[Finding]) -> None:
        strong = [
            f
            for f in findings
            if f.source in _DETERMINISTIC_SOURCES
            and not f.known_malicious
            and f.score >= LINEAGE_MIN_SCORE
            and f.event_id == ev.event_id
        ]
        if not strong or ev.pid is None:
            return
        with self._inc_lock:
            key = (ev.host_id, ev.pid)
            cur = {f.rule_id: f for f in self._lineage.get(key, [])}
            for f in strong:
                cur[f.rule_id] = f
            self._lineage[key] = sorted(cur.values(), key=lambda f: f.score, reverse=True)[:10]
            if len(self._lineage) > 20_000:
                keep = list(self._lineage.items())[-10_000:]
                self._lineage = dict(keep)

    def _enrich_reputation(self, ev: NormalizedEvent, out: PipelineOutcome) -> NormalizedEvent:
        """Attach the local threat-intel reputation of the destination IP (0-1) as
        ``raw_metadata['ip_reputation']`` so the behavior engine can feed the ML feature.
        Local cache lookup only; never a remote query."""
        if not ev.destination_ip or "ip_reputation" in ev.raw_metadata:
            return ev
        ip = ev.destination_ip
        no_match: list[IOCMatch] = []
        matches = self._stage("threat_intel", lambda: self.threat_intel.match_ip(ip), no_match, out)
        if not matches:
            return ev
        rep = max(m.confidence for m in matches)
        return ev.model_copy(update={"raw_metadata": {**ev.raw_metadata, "ip_reputation": rep}})

    # ------------------------------------------------------------------ public API
    def process_raw(self, raw: dict[str, Any]) -> PipelineOutcome | None:
        """Normalize a raw collector record and process it. Returns None if normalization fails."""
        self.stats.inc("raw")
        t0 = time.perf_counter()
        try:
            ev = self.normalizer.normalize(raw)
        except Exception:
            log.warning("normalization failed", exc_info=True)
            self.stats.error("normalize")
            return None
        finally:
            self.stats.observe("normalize", (time.perf_counter() - t0) * 1000.0)
        return self._process(ev, counted=True)

    def process(self, event: NormalizedEvent, extra_findings: list[Finding] | None = None) -> PipelineOutcome:
        """Process an already-normalized event (collectors normally call this).

        ``extra_findings`` lets an internal producer (self-protection) attach evidence it already
        computed for this event; they are scored/persisted exactly like EPP findings."""
        self.stats.inc("raw")
        return self._process(event, counted=True, extra_findings=extra_findings)

    def process_approved_actions(self, limit: int = 50) -> int:
        """Process operator-approved actions from the response_actions table through the policy gate.

        Returns the number of actions dispatched.
        """
        if self.approvals is None:
            return 0
        return self.approvals.run_once(limit=limit)

    def execute_approved_action(self, action_id: str) -> bool:
        """Execute a specific operator-approved action through the policy gate (never a shell)."""
        if self.approvals is None:
            return False
        return self.approvals.dispatch_by_id(action_id)

    def snapshot_graph(self) -> int:
        """Persist an incident-centered snapshot to the database graph_snapshots table."""
        if self.db is None:
            return 0
        try:
            self.graph.flush()
            n = write_graph_snapshot(self.db, self.graph, self.config.host_id)
            self._events_since_graph_snapshot = 0
            self._last_graph_snapshot_time = time.monotonic()
            return n
        except Exception:
            log.exception("graph snapshot failed")
            return 0

    def close(self) -> None:
        try:
            self.snapshot_graph()
        except Exception:
            log.exception("graph snapshot on close failed")
        try:
            self.graph.flush()
        except Exception:
            log.exception("graph flush failed on close")

    # ------------------------------------------------------------------ core
    def _process(
        self, ev: NormalizedEvent, *, counted: bool, extra_findings: list[Finding] | None = None
    ) -> PipelineOutcome:
        t_start = time.perf_counter()
        out = PipelineOutcome(event_id=ev.event_id)
        mode = self.modes.mode
        out.stages_reached.append("normalize")
        ev = self._enrich_reputation(ev, out)
        self._persist(out, lambda r: r.add_event(ev))
        _ev = ev
        self._persist(out, lambda r: project_event(r.db, _ev))

        # ---- fast EPP (+ YARA / static when scan depth allows)
        self.stats.inc("epp")
        out.stages_reached.append("epp")
        epp_default: list[Finding] = []
        findings: list[Finding] = list(self._stage("epp", lambda: self.epp.inspect(ev), epp_default, out))
        if extra_findings:
            findings += extra_findings
        static_res: StaticAnalysisResult | None = None
        target = self._scan_target(ev)
        depth = self.config.resource_profile.scan_depth
        if target is not None and depth >= 2:
            findings += self._stage("yara", lambda: self.yara.scan_file(target, ev), [], out)
            static_res = self._stage("static", lambda: self.static.analyze(target), None, out)
        out.findings = findings

        known = any(f.known_malicious for f in findings)
        allowlisted = (not known) and any(f.source == FindingSource.ALLOWLIST for f in findings)
        out.short_circuited = known
        out.allowlisted = allowlisted
        if known:
            self.stats.inc("short_circuited")
        if allowlisted:
            self.stats.inc("allowlisted")

        eff: list[Finding] = findings  # findings used for scoring/policy (current + carried lineage evidence)
        scores = self._evidence_scores(findings, static_res)
        behavior = BehaviorResult(ml_eligible=False)
        ml_res: MLResult | None = None
        graph_sig: GraphSignal | None = None
        novelty_res: NoveltyResult | None = None
        ai: AIAnalysis | None = None

        if not known and not allowlisted:
            # ---- behavior features + deterministic behavior findings
            out.stages_reached.append("behavior")
            behavior = self._stage(
                "behavior",
                lambda: self.behavior.analyze(ev, findings),
                BehaviorResult(ml_eligible=False),
                out,
            )
            findings += behavior.findings
            eff = findings + self._carried_findings(ev, findings)
            scores.update(self._evidence_scores(eff, static_res))
            self._remember_findings(ev, findings)

            # ---- ML (gated: only eligible events)
            if behavior.ml_eligible and self.config.resource_profile.ml_enabled:
                self.stats.inc("ml")
                out.stages_reached.append("ml")
                ml_res = self._stage("ml", lambda: self.ml.predict(ev, behavior), None, out)
                if ml_res is not None:
                    scores[ScoreFamily.ML_ANOMALY] = DetectionResult(
                        family=ScoreFamily.ML_ANOMALY,
                        score=ml_res.anomaly_score * 100.0,
                        reasons=[f"{n}={v:.2f}" for n, v in ml_res.top_features[:5]],
                        details={"model_version": ml_res.model_version},
                    )
                    benign_cls = ml_res.classification.lower() in {"benign", "normal", "unknown"}
                    scores[ScoreFamily.ML_CLASSIFICATION] = DetectionResult(
                        family=ScoreFamily.ML_CLASSIFICATION,
                        score=0.0 if benign_cls else ml_res.classification_confidence * 100.0,
                        confidence=ml_res.classification_confidence,
                        reasons=[ml_res.classification],
                    )
                    _ml = ml_res
                    self._persist(out, lambda r: r.add_ml_result(ev.event_id, _ml))

        # ---- graph (also records known-malicious events for context; never skipped on error)
        self.stats.inc("graph")
        out.stages_reached.append("graph")
        graph_sig = self._stage("graph", lambda: self.graph.ingest(ev, findings), None, out)
        if graph_sig is not None:
            scores[ScoreFamily.GRAPH_ATTACK_CHAIN] = DetectionResult(
                family=ScoreFamily.GRAPH_ATTACK_CHAIN,
                score=graph_sig.score,
                confidence=max(graph_sig.stage_confidence, 0.5 if graph_sig.chain else 1.0),
                reasons=graph_sig.chain[:8],
            )
        if self.db is not None:
            self._events_since_graph_snapshot += 1
            now = time.monotonic()
            if self._events_since_graph_snapshot >= self._graph_snapshot_interval_events or (
                self._events_since_graph_snapshot >= 10 and now - self._last_graph_snapshot_time >= 15.0
            ):
                self._stage("graph", self.snapshot_graph, 0, out)

        if not known and not allowlisted:
            out.stages_reached.append("novelty")
            novelty_res = self._stage(
                "novelty", lambda: self.novelty.assess(ev, behavior), NoveltyResult(), out
            )
            if mode == OperatingMode.LEARNING:
                self._stage("novelty", lambda: self.novelty.learn(ev), None, out)

        # ---- pre-risk + LLM gate
        out.findings = findings
        risk: RiskAssessment = self._stage(
            "risk",
            lambda: self.risk.assess(scores, eff),
            RiskAssessment(
                final_score=0.0, band=RiskBand.SAFE, scores=dict(scores), notes=["risk engine failed"]
            ),
            out,
        )
        pre_risk = risk.final_score

        gate = (
            not known
            and not allowlisted
            and mode != OperatingMode.LEARNING
            and pre_risk >= self.config.llm.gate_min_pre_risk
            and (novelty_res is None or novelty_res.is_novel or not self.config.llm.gate_require_novel)
            and self._stage("llm", self.llm.available, False, out)
        )
        cached_ai = self._cached_ai(ev, pre_risk) if gate else None
        if cached_ai is not None:
            ai = cached_ai
            out.ai = ai
            self.stats.inc("llm_cached")
            scores[ScoreFamily.AI_ASSESSMENT] = self._ai_score(ai)
            risk = self._stage("risk", lambda: self.risk.assess(scores, eff), risk, out)
        elif gate:
            docs: list[RAGDocument] = []
            out.stages_reached.append("rag")
            self.stats.inc("rag")
            query = " ".join(
                filter(None, [ev.process_name, ev.command_line, ev.domain, *[f.title for f in findings][:5]])
            )
            docs = self._stage(
                "rag", lambda: self.rag.retrieve(query, self.config.resource_profile.rag_top_k), [], out
            )
            req = LLMRequest(
                event=ev,
                findings=eff,
                features=behavior.features,
                ml=ml_res,
                graph=graph_sig,
                novelty=novelty_res,
                rag_docs=docs,
                pre_risk=pre_risk,
            )
            out.stages_reached.append("llm")
            self.stats.inc("llm")
            ai = self._stage(
                "llm",
                lambda: self.llm.analyze(req),
                AIAnalysis(event_id=ev.event_id, available=False, error="stage failed"),
                out,
            )
            if ai.rag_sources == [] and docs:
                ai = ai.model_copy(update={"rag_sources": [d.doc_id for d in docs]})
            out.ai = ai
            scores[ScoreFamily.AI_ASSESSMENT] = self._ai_score(ai)
            _ai = ai
            self._persist(out, lambda r: r.add_ai_analysis(_ai))
            self._remember_ai(ev, ai, pre_risk)
            risk = self._stage("risk", lambda: self.risk.assess(scores, eff), risk, out)

        out.scores = scores
        out.risk = risk
        out.stages_reached.append("risk")
        for f in findings:
            self._persist(out, lambda r, _f=f: r.add_finding(_f))  # type: ignore[misc]

        # ---- incident (events of one process lineage are grouped into a single incident)
        incident: Incident | None = None
        if known or risk.band in (RiskBand.HIGH, RiskBand.CRITICAL):
            incident, created = self._upsert_incident(ev, findings, risk, graph_sig, ai, known)
            out.incident = incident
            _inc = incident
            self._persist(out, lambda r: r.save_incident(_inc))
            self._stage("graph", lambda: self.graph.attach_incident(_inc), None, out)
            if created:
                self.stats.inc("incidents")
                self._audit(
                    "pipeline",
                    "incident_created",
                    {
                        "incident_id": incident.incident_id,
                        "event_id": ev.event_id,
                        "risk": round(risk.final_score, 2),
                        "band": risk.band.value,
                        "known_malicious": known,
                    },
                    out,
                )
                if self.db is not None:
                    self._stage("graph", self.snapshot_graph, 0, out)
                if self.on_incident is not None:
                    cb = self.on_incident
                    self._stage("response", lambda: cb(_inc), None, out)
            else:
                self.stats.inc("incident_updates")

        # ---- policy -> response (ordered plan; every action still passes all safety gates)
        ctx = PolicyContext(
            event=ev,
            findings=eff,
            risk=risk,
            ai=ai,
            mode=mode,
            demo_mode=self.config.demo_mode,
            test_mode=self.config.test_mode,
            known_malicious=known,
            allowlisted=allowlisted,
        )
        decisions: list[PolicyDecision] = self._stage("policy", lambda: self._plan(ctx), [], out)
        out.decision = decisions[0] if decisions else None
        out.stages_reached.append("policy")
        for decision in self._select_plan(decisions):
            if self._duplicate_action(decision, ev, incident, eff):
                self.stats.inc("actions_deduplicated")
                continue
            result = self._respond(decision, ev, incident, mode, out)
            if result is None:
                continue
            out.actions.append(result)
            self.stats.inc("actions")
            _res = result
            self._persist(out, lambda r, _x=_res: r.add_action(_x))  # type: ignore[misc]
            self._audit(
                "pipeline",
                "response_action",
                {
                    "action": result.action.value,
                    "status": result.status.value,
                    "event_id": ev.event_id,
                    "target": result.target,
                    "incident_id": result.incident_id,
                },
                out,
            )
            if incident is not None:
                incident.actions.append(result.action_id)
        if incident is not None and out.actions:
            _inc2 = incident
            self._persist(out, lambda r: r.save_incident(_inc2))
        out.stages_reached.append("response")

        if out.stage_errors:
            self._audit(
                "pipeline", "stage_errors", {"event_id": ev.event_id, "errors": out.stage_errors}, out
            )
        self.stats.observe("end_to_end", (time.perf_counter() - t_start) * 1000.0)
        return out

    # ------------------------------------------------------------------ plan handling
    def _plan(self, ctx: PolicyContext) -> list[PolicyDecision]:
        plan_fn = getattr(self.policy, "plan", None)
        if callable(plan_fn):
            return list(plan_fn(ctx))
        return [self.policy.decide(ctx)]

    @staticmethod
    def _select_plan(decisions: list[PolicyDecision]) -> list[PolicyDecision]:
        """Turn the policy's ordered candidate list into the actions to execute.

        The plan contains complementary actions (block + stop process + quarantine) *and*
        alternatives for the same target (TERMINATE with SUSPEND as the conservative fallback).
        Execute at most one action per target class/instance (process per PID / network per IP /
        file per path / endpoint / alert), taking the policy's first (preferred) choice.
        """
        chosen: list[PolicyDecision] = []
        slots: set[Any] = set()
        for d in decisions:
            if d.action is None or not d.allowed:
                continue
            if d.action in _PROCESS_ACTIONS:
                pid = d.target.get("pid")
                slot: Any = ("process", pid) if pid is not None else "process"
            elif d.action == ResponseAction.BLOCK_CONNECTION:
                ip = d.target.get("ip")
                slot = ("network", ip) if ip is not None else d.action.value
            elif d.action == ResponseAction.QUARANTINE_FILE:
                path = d.target.get("path")
                slot = ("file", path) if path is not None else d.action.value
            else:
                slot = d.action.value
            if slot in slots:
                continue
            slots.add(slot)
            chosen.append(d)
        return chosen

    def _duplicate_action(
        self, d: PolicyDecision, ev: NormalizedEvent, incident: Incident | None, findings: list[Finding]
    ) -> bool:
        t = d.target
        if d.action == ResponseAction.ALERT:
            top = max(findings, key=lambda f: f.score, default=None)
            key: tuple[Any, ...] = (
                ("ALERT", incident.incident_id)
                if incident
                else ("ALERT", ev.host_id, ev.pid, top.rule_id if top else ev.event_type.value)
            )
        else:
            key = (
                d.action.value if d.action else "",
                t.get("pid"),
                t.get("path"),
                t.get("ip"),
                t.get("port"),
            )
        now = time.monotonic()
        with self._inc_lock:
            seen = self._action_seen.get(key)
            if seen is not None and now - seen < ACTION_DEDUP_SEC:
                return True
            self._action_seen[key] = now
            if len(self._action_seen) > 20_000:
                self._action_seen = {k: v for k, v in self._action_seen.items() if now - v < ACTION_DEDUP_SEC}
        return False

    def _respond(
        self,
        decision: PolicyDecision,
        ev: NormalizedEvent,
        incident: Incident | None,
        mode: OperatingMode,
        out: PipelineOutcome,
    ) -> ActionResult | None:
        action = decision.action
        if action is None:
            return None
        inc_id = incident.incident_id if incident else None
        if action != ResponseAction.ALERT:
            if not self.config.destructive_allowed(mode):
                detail = (
                    f"destructive response disabled (mode={mode.value}, "
                    f"demo={self.config.demo_mode}, test={self.config.test_mode}); "
                    f"policy: {decision.reason[:300]}"
                )
                target = dict(decision.target)
                # Network/file/endpoint actions can be planned (validated) by a *simulating* executor
                # without touching the OS. Process actions are not looked up (demo pids are synthetic).
                if (
                    (self.config.demo_mode or self.config.test_mode)
                    and getattr(self.executor, "simulate", False) is True
                    and action not in _PROCESS_ACTIONS
                ):
                    sim = self._stage("response", lambda: self.executor.execute(decision, ev), None, out)
                    if sim is not None:
                        target = sim.target
                        detail += f" | executor(simulate): {sim.detail}"
                return ActionResult(
                    action=action,
                    status=ActionStatus.SIMULATED,
                    target=target,
                    event_id=ev.event_id,
                    incident_id=inc_id,
                    detail=detail,
                )
            if decision.requires_approval:
                return ActionResult(
                    action=action,
                    status=ActionStatus.PENDING_APPROVAL,
                    target=decision.target,
                    event_id=ev.event_id,
                    incident_id=inc_id,
                    detail="awaiting user approval",
                )
        res = self._stage("response", lambda: self.executor.execute(decision, ev), None, out)
        if res is None:
            return ActionResult(
                action=action,
                status=ActionStatus.FAILED,
                target=decision.target,
                event_id=ev.event_id,
                incident_id=inc_id,
                detail="executor failed: " + out.stage_errors.get("response", ""),
            )
        if res.incident_id is None and inc_id:
            res = res.model_copy(update={"incident_id": inc_id})
        return res

    # ------------------------------------------------------------------ incidents
    def _upsert_incident(
        self,
        ev: NormalizedEvent,
        findings: list[Finding],
        risk: RiskAssessment,
        graph_sig: GraphSignal | None,
        ai: AIAnalysis | None,
        known: bool,
    ) -> tuple[Incident, bool]:
        """Create an incident, or merge into an open one for the same process lineage/signature."""
        # Lookup: own pid, parent pid (children join the parent's incident), signature.
        # Register: own pid + signature only - registering the parent would merge unrelated siblings
        # (every child of explorer.exe) into one incident.
        reg: list[tuple[Any, ...]] = []
        keys: list[tuple[Any, ...]] = []
        if ev.pid is not None:
            reg.append(("pid", ev.host_id, ev.pid))
            keys.append(("pid", ev.host_id, ev.pid))
        if ev.ppid is not None:
            keys.append(("pid", ev.host_id, ev.ppid))
        top = max(findings, key=lambda f: f.score).rule_id if findings else ""
        sig = ev.hash_sha256 or ev.destination_ip or ev.file_path or ev.executable_path
        if sig and top:
            reg.append(("sig", ev.host_id, top, sig))
            keys.append(("sig", ev.host_id, top, sig))
        now = time.monotonic()
        with self._inc_lock:
            existing: Incident | None = None
            for k in keys:
                hit = self._incident_index.get(k)
                if hit is not None and now - hit[1] < INCIDENT_WINDOW_SEC and hit[0].status == "open":
                    existing = hit[0]
                    break
            if existing is None:
                inc = self._make_incident(ev, findings, risk, graph_sig, ai)
                created = True
            else:
                inc = existing
                created = False
                new_inc = self._make_incident(ev, findings, risk, graph_sig, ai)
                if len(inc.event_ids) < 500:
                    inc.event_ids.append(ev.event_id)
                inc.finding_ids = list({*inc.finding_ids, *new_inc.finding_ids})[:500]
                inc.mitre_techniques = sorted({*inc.mitre_techniques, *new_inc.mitre_techniques})
                if risk.final_score > inc.risk_score:
                    inc.risk_score = risk.final_score
                if _BAND_ORDER.index(risk.band) > _BAND_ORDER.index(inc.band):
                    inc.band = risk.band
                if new_inc.attack_stage and (inc.attack_stage is None or risk.final_score >= inc.risk_score):
                    inc.attack_stage = new_inc.attack_stage
                if ai is not None and ai.verdict is not None:
                    inc.ai_analysis_id = ai.analysis_id
                    inc.summary = ai.verdict.summary
                inc.updated_at = new_inc.created_at
            for k in reg:
                self._incident_index[k] = (inc, now)
            if len(self._incident_index) > 20_000:
                self._incident_index = {
                    k: v for k, v in self._incident_index.items() if now - v[1] < INCIDENT_WINDOW_SEC
                }
        return inc, created

    def _make_incident(
        self,
        ev: NormalizedEvent,
        findings: list[Finding],
        risk: RiskAssessment,
        graph_sig: GraphSignal | None,
        ai: AIAnalysis | None,
    ) -> Incident:
        techniques = sorted(
            {t for f in findings for t in f.mitre_techniques}
            | set(graph_sig.mitre_techniques if graph_sig else [])
            | set(ai.verdict.mitre_techniques if ai and ai.verdict else [])
        )
        stage = (graph_sig.attack_stage if graph_sig and graph_sig.attack_stage else None) or next(
            (f.attack_stage for f in findings if f.attack_stage), None
        )
        title = (
            max(findings, key=lambda f: f.score).title
            if findings
            else f"High risk activity: {ev.process_name or ev.event_type.value}"
        )
        return Incident(
            host_id=ev.host_id,
            title=title,
            risk_score=risk.final_score,
            band=risk.band,
            attack_stage=stage,
            mitre_techniques=techniques,
            event_ids=[ev.event_id],
            finding_ids=[f.finding_id for f in findings],
            summary=(
                ai.verdict.summary
                if ai and ai.verdict
                else f"{len(findings)} finding(s); risk {risk.final_score:.0f} ({risk.band.value})"
            ),
            ai_analysis_id=ai.analysis_id if ai else None,
        )
