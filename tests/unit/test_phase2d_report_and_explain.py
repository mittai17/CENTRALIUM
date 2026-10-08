"""Unit tests for Phase 2D: Incident reporting, explainability trace, and eval CLI commands."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from centralium.agent.main import app
from centralium.agent.models import (
    AIAnalysis,
    AIVerdict,
    AttackStage,
    DetectionResult,
    Finding,
    FindingSource,
    Incident,
    PolicyDecision,
    ResponseAction,
    RiskAssessment,
    RiskBand,
    ScoreFamily,
    Severity,
    Verdict,
)
from centralium.agent.reporting.incident_report import (
    export_incident_report_pdf,
    generate_incident_report,
)
from centralium.agent.risk.explainability import (
    ExplainabilityTrace,
    build_explainability_trace,
)

runner = CliRunner()


def test_generate_incident_report_labels_and_provenance(tmp_path: Path):
    inc = Incident(
        incident_id="inc-report-1",
        host_id="desktop-12",
        title="Ransomware Outbreak via PowerShell",
        risk_score=92.5,
        band=RiskBand.CRITICAL,
        attack_stage=AttackStage.IMPACT,
        mitre_techniques=["T1486", "T1059.001"],
        summary="Automated canary triggered by mass encryption.",
        event_ids=["ev-1"],
        finding_ids=["f-1"],
    )

    ai = AIAnalysis(
        analysis_id="ai-rep-1",
        event_id="ev-1",
        available=True,
        role="threat_analyst",
        model_name="gemma-3-1b-it-Q4_K_M",
        latency_ms=85.0,
        rag_sources=["ransomware.md"],
        verdict=AIVerdict(
            verdict=Verdict.MALICIOUS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            threat_type="Ransomware",
            summary="Attacker executed PowerShell script that rapidly encrypted system files.",
            why_suspicious=["Mass renaming to .locked", "High entropy spikes"],
            evidence=["ev-1"],
            mitre_techniques=["T1486"],
            attack_stage="IMPACT",
            recommended_action="ISOLATE_ENDPOINT",
            false_positive_indicators=["Legitimate backup software"],
            investigation_questions=["Check initial access point", "Verify active network shares"],
        ),
    )

    report = generate_incident_report(
        inc,
        ai_analysis=ai,
        model_status={"mode": "real"},
    )

    # Required sections
    assert "Incident Metadata [DETERMINISTIC]" in report
    assert "AI Provenance & Model Status [AI-ASSISTED]" in report
    assert "Executive Summary" in report
    assert "Deterministic Analysis [DETERMINISTIC]" in report
    assert "AI Analyst Assessment [AI-ASSISTED]" in report
    assert "Attack Chain & Tactics [DETERMINISTIC]" in report
    assert "Timeline of Events [DETERMINISTIC]" in report
    assert "MITRE ATT&CK Mapping [DETERMINISTIC]" in report
    assert "Response Actions Taken [DETERMINISTIC]" in report
    assert "Recommended Follow-up Actions [AI-ASSISTED]" in report

    # Model status disclosure
    assert "Real Local Model" in report
    assert "gemma-3-1b-it-Q4_K_M" in report

    # AI vs Deterministic labels check
    assert "[DETERMINISTIC]" in report
    assert "[AI-ASSISTED]" in report

    # Test PDF export function (safe offline fallback)
    pdf_path = tmp_path / "test_report.pdf"
    res = export_incident_report_pdf(report, pdf_path)
    assert isinstance(res, bool)


def test_build_explainability_trace():
    scores = {
        ScoreFamily.DETERMINISTIC_EVIDENCE: DetectionResult(
            family=ScoreFamily.DETERMINISTIC_EVIDENCE, score=85.0, confidence=0.9
        ),
        ScoreFamily.ML_ANOMALY: DetectionResult(family=ScoreFamily.ML_ANOMALY, score=70.0, confidence=0.8),
        ScoreFamily.GRAPH_ATTACK_CHAIN: DetectionResult(
            family=ScoreFamily.GRAPH_ATTACK_CHAIN, score=60.0, confidence=0.7
        ),
    }

    risk = RiskAssessment(
        final_score=78.5,
        band=RiskBand.HIGH,
        scores=scores,
        weights_used={
            "deterministic_evidence": 0.45,
            "behavioral_ml": 0.35,
            "attack_graph": 0.20,
        },
        notes=["evidence floor applied"],
    )

    finding = Finding(
        finding_id="f-exp-1",
        event_id="ev-exp-1",
        timestamp=datetime.now(UTC),
        source=FindingSource.BEHAVIOR,
        rule_id="RULE_UNSIGNED_BINARY",
        title="Unsigned Binary Execution",
        severity=Severity.HIGH,
        score=85.0,
        mitre_techniques=["T1059"],
        known_malicious=False,
    )

    decision = PolicyDecision(
        action=ResponseAction.ALERT,
        allowed=True,
        requires_approval=False,
        reason="high risk threshold reached",
    )

    trace = build_explainability_trace(
        event_id="ev-exp-1",
        risk=risk,
        findings=[finding],
        decision=decision,
    )

    assert isinstance(trace, ExplainabilityTrace)
    assert trace.final_score == 78.5
    assert trace.band == RiskBand.HIGH
    assert len(trace.family_contributions) >= 2
    assert "deterministic_evidence" in trace.family_contributions

    # Counterfactual check: "would be ... without the ... signal"
    assert len(trace.counterfactuals) >= 1
    assert any("without the" in c for c in trace.counterfactuals)

    # Narrative summary check
    assert "Event scored 78.5 (HIGH)" in trace.summary


def test_cli_eval_commands(tmp_path: Path):
    # 1. Test 'centralium eval rag'
    rag_out = tmp_path / "rag.md"
    res_rag = runner.invoke(app, ["eval", "rag", "--out", str(rag_out)])
    assert res_rag.exit_code == 0
    assert rag_out.exists()
    assert "Centralium RAG Evaluation Report" in rag_out.read_text(encoding="utf-8")

    # 2. Test 'centralium eval llm'
    llm_out = tmp_path / "llm.json"
    res_llm = runner.invoke(app, ["eval", "llm", "--out", str(llm_out)])
    assert res_llm.exit_code == 0
    assert llm_out.exists()
    llm_data = json.loads(llm_out.read_text(encoding="utf-8"))
    assert llm_data["total_cases"] >= 8
    assert llm_data["verdict_agreement_rate"] >= 0.8

    # 3. Test 'centralium eval injection'
    inj_out = tmp_path / "inj.md"
    res_inj = runner.invoke(app, ["eval", "injection", "--out", str(inj_out)])
    assert res_inj.exit_code == 0
    assert inj_out.exists()
    assert "Prompt-Injection Red-Team Report" in inj_out.read_text(encoding="utf-8")
