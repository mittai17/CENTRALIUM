from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from centralium.agent.models import (
    ActionRecommendation,
    AIVerdict,
    AttackStage,
    DetectionResult,
    EventType,
    NormalizedEvent,
    ScoreFamily,
    Severity,
    Verdict,
)


def valid_verdict(**over):
    d = {
        "verdict": "MALICIOUS",
        "severity": "HIGH",
        "confidence": 0.9,
        "threat_type": "loader",
        "summary": "Office spawned PowerShell",
        "why_suspicious": ["encoded command"],
        "evidence": ["pid 12"],
        "mitre_techniques": ["T1059.001", "T1204"],
        "attack_stage": "EXECUTION",
        "recommended_action": "SUSPEND_PROCESS",
        "false_positive_indicators": [],
        "investigation_questions": ["Who opened the doc?"],
    }
    d.update(over)
    return d


def test_valid_verdict_roundtrip():
    v = AIVerdict.model_validate(valid_verdict())
    assert v.verdict is Verdict.MALICIOUS and v.severity is Severity.HIGH
    assert v.attack_stage is AttackStage.EXECUTION
    assert v.recommended_action is ActionRecommendation.SUSPEND_PROCESS
    assert AIVerdict.model_validate_json(v.model_dump_json()) == v


@pytest.mark.parametrize(
    "bad",
    [
        {"verdict": "EVIL"},
        {"severity": "SEVERE"},
        {"confidence": 1.5},
        {"confidence": -0.1},
        {"recommended_action": "rm -rf /"},
        {"attack_stage": "WORLD_DOMINATION"},
        {"mitre_techniques": ["not-a-technique"]},
        {"threat_type": ""},
        {"extra_field": 1},
        {"recommended_action": "RUN_SHELL"},
    ],
)
def test_invalid_verdicts_rejected(bad):
    with pytest.raises(ValidationError):
        AIVerdict.model_validate(valid_verdict(**bad))


def test_missing_required_field():
    d = valid_verdict()
    del d["summary"]
    with pytest.raises(ValidationError):
        AIVerdict.model_validate(d)


def test_benign_cannot_recommend_enforcement():
    with pytest.raises(ValidationError):
        AIVerdict.model_validate(valid_verdict(verdict="BENIGN", recommended_action="TERMINATE_PROCESS"))
    AIVerdict.model_validate(valid_verdict(verdict="BENIGN", recommended_action="NONE"))


def test_mitre_normalized_uppercase():
    v = AIVerdict.model_validate(valid_verdict(mitre_techniques=["t1059.001"]))
    assert v.mitre_techniques == ["T1059.001"]


def test_parse_llm_text_tolerates_fences_and_prose():
    raw = "Sure!\n```json\n" + json.dumps(valid_verdict()) + "\n```"
    assert AIVerdict.parse_llm_text(raw).verdict is Verdict.MALICIOUS
    assert AIVerdict.parse_llm_text(json.dumps(valid_verdict())).confidence == 0.9


@pytest.mark.parametrize("text", ["", "no json here", "{broken", '{"verdict": "BENIGN"}'])
def test_parse_llm_text_failures_raise_valueerror(text):
    with pytest.raises(ValueError):  # ValidationError subclasses ValueError
        AIVerdict.parse_llm_text(text)


def test_event_validation():
    e = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, destination_port=443, hash_sha256="A" * 64)
    assert e.hash_sha256 == "a" * 64 and e.timestamp.tzinfo is not None
    with pytest.raises(ValidationError):
        NormalizedEvent(event_type=EventType.NETWORK_CONNECT, destination_port=70000)
    with pytest.raises(ValidationError):
        NormalizedEvent(event_type=EventType.PROCESS_START, hash_sha256="xyz")
    with pytest.raises(ValidationError):
        NormalizedEvent(event_type="bogus")
    with pytest.raises(ValidationError):
        NormalizedEvent(event_type=EventType.OTHER, surprise=1)


def test_detection_result_range_and_unavailable():
    with pytest.raises(ValidationError):
        DetectionResult(family=ScoreFamily.ML_ANOMALY, score=101)
    u = DetectionResult.unavailable(ScoreFamily.AI_ASSESSMENT, "down")
    assert not u.available and u.confidence == 0
