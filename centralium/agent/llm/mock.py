"""DETERMINISTIC MOCK LLM - TEST/DEMO ONLY.

This is NOT a language model and NOT Gemma. It derives a schema-valid ``AIVerdict``
from the evidence with fixed rules so tests and demo mode run without model weights.
Every output is labelled: ``model_name == MOCK_MODEL_NAME`` and the summary starts
with ``[MOCK]``. It is never selected automatically in production wiring.
"""

from __future__ import annotations

import time

from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm.prompts import injection_markers, normalize_role
from centralium.agent.models import (
    ActionRecommendation,
    AIAnalysis,
    AIVerdict,
    AttackStage,
    Finding,
    Severity,
    Verdict,
)

MOCK_MODEL_NAME = "MOCK-DETERMINISTIC (not an LLM, test/demo only)"

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_STAGE_FROM_TECH = {
    "T1486": AttackStage.IMPACT,
    "T1490": AttackStage.IMPACT,
    "T1003": AttackStage.CREDENTIAL_ACCESS,
    "T1053": AttackStage.PERSISTENCE,
    "T1547": AttackStage.PERSISTENCE,
    "T1543": AttackStage.PERSISTENCE,
    "T1071": AttackStage.COMMAND_AND_CONTROL,
    "T1105": AttackStage.COMMAND_AND_CONTROL,
    "T1059": AttackStage.EXECUTION,
    "T1218": AttackStage.DEFENSE_EVASION,
    "T1055": AttackStage.DEFENSE_EVASION,
    "T1021": AttackStage.LATERAL_MOVEMENT,
    "T1041": AttackStage.EXFILTRATION,
}


def _stage(req: LLMRequest, techs: list[str]) -> AttackStage:
    if req.graph and req.graph.attack_stage:
        return req.graph.attack_stage
    for f in req.findings:
        if f.attack_stage:
            return f.attack_stage
    for t in techs:
        if t.split(".")[0] in _STAGE_FROM_TECH:
            return _STAGE_FROM_TECH[t.split(".")[0]]
    return AttackStage.UNKNOWN


def _techs(req: LLMRequest) -> list[str]:
    out: list[str] = []
    pools = [f.mitre_techniques for f in req.findings]
    if req.graph:
        pools.append(req.graph.mitre_techniques)
    for pool in pools:
        for t in pool:
            if t not in out:
                out.append(t)
    return out[:6]


def _max_sev(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), key=_SEV_ORDER.index, default=Severity.INFO)


class MockLLM:
    """Implements the ``LLMClient`` protocol deterministically."""

    is_mock = True
    model_name = MOCK_MODEL_NAME

    def __init__(self) -> None:
        self.calls = 0

    def status(self) -> dict[str, object]:
        return {
            "mode": "mock",
            "is_mock": True,
            "model": MOCK_MODEL_NAME,
            "backend": "mock",
            "available": True,
            "reason": "deterministic mock selected explicitly (test/demo); real Gemma is NOT running",
        }

    def available(self) -> bool:
        return True

    def unload(self) -> None:
        return None

    def analyze(self, request: LLMRequest) -> AIAnalysis:
        t0 = time.perf_counter()
        self.calls += 1
        verdict = self._verdict(request)
        return AIAnalysis(
            event_id=request.event.event_id,
            available=True,
            verdict=verdict,
            role=normalize_role(request.role),
            model_name=MOCK_MODEL_NAME,
            latency_ms=(time.perf_counter() - t0) * 1000,
            rag_sources=[d.doc_id for d in request.rag_docs],
        )

    def _verdict(self, req: LLMRequest) -> AIVerdict:
        risk = req.pre_risk
        techs = _techs(req)
        # Mock never trusts instructions in event text: it only reads structured evidence.
        ev_texts = [req.event.command_line or "", req.event.process_name or ""]
        injected = bool(injection_markers(ev_texts))
        sev_f = _max_sev(req.findings)
        if risk >= 80:
            verdict, sev = Verdict.MALICIOUS, Severity.CRITICAL
        elif risk >= 60:
            verdict, sev = Verdict.SUSPICIOUS, max(Severity.HIGH, sev_f, key=_SEV_ORDER.index)
        elif risk >= 40:
            verdict, sev = Verdict.SUSPICIOUS, Severity.MEDIUM
        elif risk >= 20:
            verdict, sev = Verdict.UNKNOWN, Severity.LOW
        else:
            verdict, sev = Verdict.BENIGN, Severity.INFO
        if injected and verdict in (Verdict.BENIGN, Verdict.UNKNOWN):
            verdict = Verdict.SUSPICIOUS
        stage = _stage(req, techs)
        if verdict == Verdict.MALICIOUS:
            if stage == AttackStage.IMPACT:
                action = ActionRecommendation.SUSPEND_PROCESS
            elif req.event.file_path or req.event.executable_path:
                action = ActionRecommendation.QUARANTINE_FILE
            else:
                action = ActionRecommendation.TERMINATE_PROCESS
        elif verdict == Verdict.SUSPICIOUS:
            action = ActionRecommendation.ALERT
        else:
            action = ActionRecommendation.NONE
        conf = round(min(0.85, 0.35 + 0.5 * min(risk, 100) / 100 + (0.05 if techs else 0.0)), 2)
        titles = [f.title for f in req.findings[:5]]
        why = titles or ["elevated pre-risk score from deterministic/ML stages"]
        if injected:
            why.append("instruction-like text found in event data (ignored)")
        proc = req.event.process_name or "unknown process"
        fp: list[str] = []
        if req.novelty is not None and not req.novelty.is_novel:
            fp.append("behavior has been seen in the baseline")
        if req.event.signer:
            fp.append(f"binary signed by {req.event.signer[:80]}")
        return AIVerdict(
            verdict=verdict,
            severity=sev,
            confidence=conf,
            threat_type=(
                req.ml.classification
                if req.ml and req.ml.classification != "unknown"
                else "suspicious activity"
            )[:100],
            summary=(
                f"[MOCK] Rule-derived assessment (not Gemma): {proc} scored pre-risk {risk:.0f}/100 with "
                f"{len(req.findings)} finding(s); likely stage {stage.value}."
            )[:1000],
            why_suspicious=why,
            evidence=[f"{f.source.value}:{f.rule_id}" for f in req.findings[:8]],
            mitre_techniques=techs,
            attack_stage=stage,
            recommended_action=action,
            false_positive_indicators=fp,
            investigation_questions=[
                f"How was {proc} started and by whom?",
                "Has this binary/destination been seen on other hosts?",
            ],
        )
