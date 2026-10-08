"""Unit tests for Phase 2D: LLM evaluation, prompt-injection resilience,
LRU fingerprint caching, and background analysis queue.
"""

from __future__ import annotations

from datetime import UTC, datetime

from centralium.agent.eval.injection_eval import evaluate_injection
from centralium.agent.eval.llm_eval import evaluate_llm
from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm.cache import IncidentFingerprintCache
from centralium.agent.llm.mock import MockLLM
from centralium.agent.llm.prompts import ROLE_TOKEN_BUDGETS, build_prompt
from centralium.agent.models import (
    AIAnalysis,
    AIVerdict,
    EventType,
    NormalizedEvent,
    Severity,
    Verdict,
)
from centralium.agent.pipeline import BackgroundLLMQueue


def test_llm_eval_golden_incidents():
    client = MockLLM()
    rep = evaluate_llm(client)
    assert rep.total_cases >= 8
    assert rep.verdict_agreement_rate >= 0.8
    assert rep.valid_json_rate == 1.0
    assert rep.avg_latency_ms >= 0.0
    md = rep.to_markdown()
    assert "Centralium LLM Evaluation Report" in md
    assert "Summary Metrics" in md


def test_prompt_injection_red_team_corpus():
    client = MockLLM()
    rep = evaluate_injection(client)
    assert rep.total_cases >= 16
    assert rep.pass_rate >= 0.9  # high resilience against injection
    assert "command_line" in rep.surface_stats
    assert "filename" in rep.surface_stats
    assert "domain" in rep.surface_stats
    assert "document_text" in rep.surface_stats
    md = rep.to_markdown()
    assert "Prompt-Injection Red-Team Report" in md


def test_incident_fingerprint_cache():
    cache = IncidentFingerprintCache(capacity=4)
    ts = datetime.now(UTC)

    ev1 = NormalizedEvent(
        event_id="ev-1",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="host1",
        process_name="powershell.exe",
        command_line="powershell.exe -enc AAA",
        parent_process="winword.exe",
        destination_ip="1.2.3.4",
        destination_port=443,
    )
    req1 = LLMRequest(event=ev1, role="threat_analyst")

    # Miss
    assert cache.get_by_request(req1) is None
    assert cache.stats()["misses"] == 1

    # Store analysis
    ai1 = AIAnalysis(
        analysis_id="ai-1",
        event_id="ev-1",
        available=True,
        verdict=AIVerdict(
            verdict=Verdict.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=0.8,
            threat_type="encoded powershell",
            summary="Suspicious execution",
            why_suspicious=["encoded"],
            evidence=["cmd"],
            mitre_techniques=["T1059.001"],
            attack_stage="EXECUTION",
            recommended_action="ALERT",
            false_positive_indicators=[],
            investigation_questions=[],
        ),
        latency_ms=120.0,
    )
    cache.put_by_request(req1, ai1)

    # Hit for another event with the same parent, command line, and destination
    ev2 = NormalizedEvent(
        event_id="ev-2",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="host1",
        process_name="powershell.exe",
        command_line="powershell.exe -enc AAA",
        parent_process="winword.exe",
        destination_ip="1.2.3.4",
        destination_port=443,
    )
    req2 = LLMRequest(event=ev2, role="threat_analyst")

    hit = cache.get_by_request(req2)
    assert hit is not None
    assert hit.event_id == "ev-2"  # event_id updated to current event
    assert hit.verdict.verdict == Verdict.SUSPICIOUS
    assert cache.stats()["hits"] == 1
    assert cache.stats()["saved_latency_ms"] == 120.0


def test_token_budgets_by_role_and_prefix_caching():
    assert "threat_analyst" in ROLE_TOKEN_BUDGETS
    assert "response_recommender" in ROLE_TOKEN_BUDGETS
    assert ROLE_TOKEN_BUDGETS["response_recommender"] < ROLE_TOKEN_BUDGETS["threat_analyst"]

    ev = NormalizedEvent(
        event_id="ev-test",
        event_type=EventType.PROCESS_START,
        timestamp=datetime.now(UTC),
        host_id="h1",
        process_name="test.exe",
    )
    req = LLMRequest(event=ev, role="mitre_explainer")
    p = build_prompt(req)
    assert p.prefix_caching_hint is True
    # System prompt contains static security rules
    assert "UNTRUSTED DATA" in p.system


def test_async_background_llm_queue():
    client = MockLLM()
    completed_jobs: list[str] = []

    def on_complete(req: LLMRequest, ai: AIAnalysis, pre_risk: float, inc_id: str | None) -> None:
        completed_jobs.append(req.event.event_id)

    bg_queue = BackgroundLLMQueue(client, on_complete=on_complete, max_size=10)
    ev = NormalizedEvent(
        event_id="bg-ev-1",
        event_type=EventType.PROCESS_START,
        timestamp=datetime.now(UTC),
        host_id="h1",
        process_name="test_bg.exe",
    )
    req = LLMRequest(event=ev, pre_risk=85.0)

    enqueued = bg_queue.enqueue(req, pre_risk=85.0)
    assert enqueued is True

    bg_queue.drain(timeout=2.0)
    bg_queue.stop()

    assert "bg-ev-1" in completed_jobs
    assert bg_queue.jobs_completed >= 1
