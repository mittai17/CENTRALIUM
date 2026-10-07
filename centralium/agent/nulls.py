"""Null / no-op default implementations of every stage so the pipeline always runs.

Real modules replace these via dependency injection. Defaults are *safe*: they never
fabricate detections or scores, never enforce, and never touch the OS.

``ReferenceRiskEngine`` implements the spec formula + calibration rules and is
adequate until the risk owner ships ``centralium.agent.risk``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from centralium.agent.config import RiskSettings
from centralium.agent.interfaces import (
    BehaviorResult,
    IOCMatch,
    LLMRequest,
    PolicyContext,
    QuarantineRecord,
    SyncItem,
)
from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    AIAnalysis,
    DetectionResult,
    Finding,
    GraphSignal,
    Incident,
    MLResult,
    NormalizedEvent,
    NoveltyResult,
    PolicyDecision,
    RAGDocument,
    ResponseAction,
    RiskAssessment,
    ScoreFamily,
    StaticAnalysisResult,
)


class NullNormalizer:
    """Accepts dicts already shaped like NormalizedEvent."""

    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent.model_validate(raw)


class NullEPP:
    def inspect(self, event: NormalizedEvent) -> list[Finding]:
        return []


class NullYara:
    def scan_file(self, path: Path, event: NormalizedEvent) -> list[Finding]:
        return []

    def scan_bytes(self, data: bytes, event: NormalizedEvent) -> list[Finding]:
        return []

    def validate_rules(self, source_text: str) -> tuple[bool, str]:
        return False, "yara not available"

    def reload(self) -> int:
        return 0


class NullStatic:
    def analyze(self, path: Path) -> StaticAnalysisResult:
        return StaticAnalysisResult(path=str(path))


class NullBehavior:
    def analyze(self, event: NormalizedEvent, findings: list[Finding]) -> BehaviorResult:
        return BehaviorResult(ml_eligible=False)  # no features -> nothing to send to ML


class NullML:
    model_version = "none"

    def predict(self, event: NormalizedEvent, behavior: BehaviorResult) -> MLResult | None:
        return None  # no model -> no score (never fabricate)


class NullGraph:
    def ingest(self, event: NormalizedEvent, findings: list[Finding]) -> GraphSignal:
        return GraphSignal()

    def attach_incident(self, incident: Incident) -> None:
        return None

    def chain_for(self, event_id: str) -> list[str]:
        return []

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class NullNovelty:
    """Without baselines everything is considered novel (conservative for gatekeeping)."""

    def assess(self, event: NormalizedEvent, behavior: BehaviorResult) -> NoveltyResult:
        return NoveltyResult(is_novel=True, novelty_score=1.0, reasons=["no novelty filter"])

    def learn(self, event: NormalizedEvent) -> None:
        return None


class NullRAG:
    def retrieve(self, query: str, k: int = 4) -> list[RAGDocument]:
        return []


class NullLLM:
    def available(self) -> bool:
        return False

    def analyze(self, request: LLMRequest) -> AIAnalysis:
        return AIAnalysis(event_id=request.event.event_id, available=False, error="no LLM configured")

    def unload(self) -> None:
        return None


class ReferenceRiskEngine:
    """Spec baseline: final = sum(w_i * score_i) over *available* families, re-normalized
    over the weights that were available. Calibration:
      * AI contribution is scaled by its confidence; below ``ai_min_confidence`` it is
        additionally halved, and the AI score can never LOWER a score below the
        non-AI score (AI may raise or leave unchanged; it cannot dominate).
      * Any known-malicious finding floors the result at ``known_malicious_floor``.
    Family A and B are merged into 'behavioral_ml' = max(A, B*conf) (documented choice).
    """

    def __init__(self, settings: RiskSettings | None = None) -> None:
        self.s = settings or RiskSettings()

    def _components(self, scores: dict[ScoreFamily, DetectionResult]) -> dict[str, DetectionResult]:
        comp: dict[str, DetectionResult] = {}
        a = scores.get(ScoreFamily.ML_ANOMALY)
        b = scores.get(ScoreFamily.ML_CLASSIFICATION)
        ml_parts = [x for x in (a, b) if x is not None and x.available]
        if ml_parts:
            best = max(ml_parts, key=lambda x: x.score)
            comp["behavioral_ml"] = best
        for key, fam in (
            ("deterministic_evidence", ScoreFamily.DETERMINISTIC_EVIDENCE),
            ("attack_graph", ScoreFamily.GRAPH_ATTACK_CHAIN),
            ("threat_intel", ScoreFamily.THREAT_INTEL),
            ("static_malware", ScoreFamily.STATIC_MALWARE),
            ("ai_assessment", ScoreFamily.AI_ASSESSMENT),
        ):
            r = scores.get(fam)
            if r is not None and r.available:
                comp[key] = r
        return comp

    def _combine(self, comp: dict[str, DetectionResult], weights: dict[str, float]) -> tuple[float, float]:
        num = den = 0.0
        for k, r in comp.items():
            w = weights.get(k, 0.0)
            if k == "ai_assessment":
                w *= r.confidence
                if r.confidence < self.s.ai_min_confidence:
                    w *= 0.5
            num += w * r.score
            den += w
        if den <= 0:
            return 0.0, 0.0
        return (num / den if self.s.normalize_weights else num), den

    def assess(self, scores: dict[ScoreFamily, DetectionResult], findings: list[Finding]) -> RiskAssessment:
        weights = self.s.weights()
        comp = self._components(scores)
        notes: list[str] = []
        total, _ = self._combine(comp, weights)
        if "ai_assessment" in comp:
            without_ai, _ = self._combine({k: v for k, v in comp.items() if k != "ai_assessment"}, weights)
            if total < without_ai:
                total = without_ai
                notes.append("AI score cannot lower non-AI risk")
        if any(f.known_malicious for f in findings):
            if total < self.s.known_malicious_floor:
                notes.append(f"known-malicious floor {self.s.known_malicious_floor} applied")
            total = max(total, self.s.known_malicious_floor)
        total = max(0.0, min(100.0, total))
        final = DetectionResult(family=ScoreFamily.FINAL_RISK, score=total, confidence=1.0)
        return RiskAssessment(
            final_score=total,
            band=self.s.band_for(total),
            scores={**scores, ScoreFamily.FINAL_RISK: final},
            weights_used=weights,
            notes=notes,
        )


class AlertOnlyPolicy:
    """Safe default: only ever allows ALERT for MEDIUM+ risk; never destructive."""

    def decide(self, ctx: PolicyContext) -> PolicyDecision:
        if ctx.allowlisted:
            return PolicyDecision(mode=ctx.mode, reason="allowlisted")
        if ctx.risk.final_score >= 40 or ctx.known_malicious:
            return PolicyDecision(
                action=ResponseAction.ALERT,
                allowed=True,
                mode=ctx.mode,
                reason="default alert-only policy",
                target={"event_id": ctx.event.event_id},
            )
        return PolicyDecision(mode=ctx.mode, reason="below alert threshold")


class NullExecutor:
    """ALERT => EXECUTED (logging only). Everything else is simulated, never performed."""

    def execute(self, decision: PolicyDecision, event: NormalizedEvent) -> ActionResult:
        assert decision.action is not None
        status = ActionStatus.EXECUTED if decision.action == ResponseAction.ALERT else ActionStatus.SIMULATED
        return ActionResult(
            action=decision.action,
            status=status,
            target=decision.target,
            detail="null executor",
            event_id=event.event_id,
        )

    def supported(self) -> frozenset[ResponseAction]:
        return frozenset({ResponseAction.ALERT})


class NullQuarantine:
    def quarantine(self, path: Path, reasons: list[str], sources: list[str]) -> QuarantineRecord:
        raise NotImplementedError("quarantine module not installed")

    def restore(self, quarantine_id: str, *, authorized_by: str, reason: str) -> Path:
        raise NotImplementedError("quarantine module not installed")

    def list(self) -> list[QuarantineRecord]:
        return []


class NullThreatIntel:
    def match_hash(self, sha256: str) -> list[IOCMatch]:
        return []

    def match_ip(self, ip: str) -> list[IOCMatch]:
        return []

    def match_domain(self, domain: str) -> list[IOCMatch]:
        return []

    def update(self) -> int:
        return 0


class NullSyncQueue:
    def enqueue(self, payload: dict[str, Any], dedup_key: str | None = None) -> bool:
        return False

    def claim_batch(self, limit: int = 100) -> list[SyncItem]:
        return []

    def mark_delivered(self, queue_id: int) -> None:
        return None

    def mark_failed(self, queue_id: int, error: str) -> None:
        return None

    def pending(self) -> int:
        return 0


class NullSelfProtection:
    def check(self) -> list[Finding]:
        return []

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None
