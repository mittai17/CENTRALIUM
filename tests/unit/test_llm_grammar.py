"""Unit tests for llama.cpp GBNF grammar and JSON-schema constraints on AIVerdict."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from centralium.agent.config import LLMSettings
from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm.backends import LlamaServerBackend
from centralium.agent.llm.client import LocalLLMClient
from centralium.agent.llm.grammar import (
    benchmark_grammar_simulation,
    get_ai_verdict_gbnf,
    get_ai_verdict_json_schema,
    validate_gbnf_syntax,
)
from centralium.agent.models import (
    ActionRecommendation,
    AIVerdict,
    AttackStage,
    EventType,
    NormalizedEvent,
    Severity,
    Verdict,
)


def test_gbnf_grammar_syntax_and_coverage() -> None:
    grammar = get_ai_verdict_gbnf()
    assert validate_gbnf_syntax(grammar)
    assert "root ::=" in grammar
    assert r"\"verdict\"" in grammar
    assert r"\"severity\"" in grammar
    assert r"\"confidence\"" in grammar
    assert r"\"threat_type\"" in grammar
    assert r"\"summary\"" in grammar
    assert r"\"why_suspicious\"" in grammar
    assert r"\"evidence\"" in grammar
    assert r"\"mitre_techniques\"" in grammar
    assert r"\"attack_stage\"" in grammar
    assert r"\"recommended_action\"" in grammar
    assert r"\"false_positive_indicators\"" in grammar
    assert r"\"investigation_questions\"" in grammar

    # Verify all enum values are present in the grammar
    for v in Verdict:
        assert v.value in grammar
    for s in Severity:
        assert s.value in grammar
    for stage in AttackStage:
        assert stage.value in grammar
    for act in ActionRecommendation:
        assert act.value in grammar


def test_json_schema_contract() -> None:
    schema = get_ai_verdict_json_schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    props = schema["properties"]
    assert set(schema["required"]) == {
        "verdict",
        "severity",
        "confidence",
        "threat_type",
        "summary",
        "why_suspicious",
        "evidence",
        "mitre_techniques",
        "attack_stage",
        "recommended_action",
        "false_positive_indicators",
        "investigation_questions",
    }
    assert props["verdict"]["enum"] == [v.value for v in Verdict]
    assert props["severity"]["enum"] == [s.value for s in Severity]
    assert props["attack_stage"]["enum"] == [a.value for a in AttackStage]
    assert props["recommended_action"]["enum"] == [r.value for r in ActionRecommendation]


def test_sample_matching_grammar_validates_as_ai_verdict() -> None:
    sample = {
        "verdict": "MALICIOUS",
        "severity": "HIGH",
        "confidence": 0.85,
        "threat_type": "credential_dumping",
        "summary": "LSASS memory dumping observed via comsvcs.dll MiniDump export.",
        "why_suspicious": ["comsvcs.dll rundll32 minidump invocation", "lsass access"],
        "evidence": ["rundll32.exe comsvcs.dll MiniDump"],
        "mitre_techniques": ["T1003.001"],
        "attack_stage": "CREDENTIAL_ACCESS",
        "recommended_action": "TERMINATE_PROCESS",
        "false_positive_indicators": [],
        "investigation_questions": ["What account executed rundll32?"],
    }
    text = json.dumps(sample)
    verdict = AIVerdict.parse_llm_text(text)
    assert verdict.verdict == Verdict.MALICIOUS
    assert verdict.severity == Severity.HIGH
    assert verdict.attack_stage == AttackStage.CREDENTIAL_ACCESS
    assert verdict.recommended_action == ActionRecommendation.TERMINATE_PROCESS


def test_grammar_benchmark_and_valid_first_try_rate() -> None:
    valid_sample = json.dumps(
        {
            "verdict": "SUSPICIOUS",
            "severity": "MEDIUM",
            "confidence": 0.6,
            "threat_type": "powershell_download",
            "summary": "Powershell downloading external script.",
            "why_suspicious": ["Net.WebClient call"],
            "evidence": ["powershell downloadstring"],
            "mitre_techniques": ["T1059.001"],
            "attack_stage": "EXECUTION",
            "recommended_action": "ALERT",
            "false_positive_indicators": [],
            "investigation_questions": ["Source URL status?"],
        }
    )

    # Unconstrained LLM failure patterns (prose prefix, markdown wrap, missing keys, hallucinated fields)
    unconstrained_samples = [
        "Here is my analysis: The process is suspicious.",
        '```json\n{"verdict": "NOT_A_VALID_VERDICT"}\n```',
        '{"verdict": "MALICIOUS", "missing_everything_else": true}',
        valid_sample,  # Only 1 in 4 is valid on first try
    ]

    # Grammar-constrained samples (guaranteed 100% adherence to schema)
    constrained_samples = [valid_sample] * 10

    unconstrained_bench = benchmark_grammar_simulation(unconstrained_samples)
    constrained_bench = benchmark_grammar_simulation(constrained_samples)

    # Valid-first-try rate with grammar is 100% (1.0), unconstrained is strictly lower
    assert constrained_bench["valid_first_try_rate"] == 1.0
    assert unconstrained_bench["valid_first_try_rate"] < 1.0
    assert constrained_bench["avg_parse_latency_us"] >= 0.0


def test_llama_server_backend_passes_grammar_and_schema() -> None:
    client_mock = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "verdict": "BENIGN",
                            "severity": "LOW",
                            "confidence": 0.9,
                            "threat_type": "normal_dev",
                            "summary": "Routine python execution.",
                            "why_suspicious": [],
                            "evidence": [],
                            "mitre_techniques": [],
                            "attack_stage": "EXECUTION",
                            "recommended_action": "NONE",
                            "false_positive_indicators": [],
                            "investigation_questions": [],
                        }
                    )
                }
            }
        ]
    }
    client_mock.post.return_value = mock_response

    backend = LlamaServerBackend("http://127.0.0.1:8080", client=client_mock)
    schema = get_ai_verdict_json_schema()
    grammar = get_ai_verdict_gbnf()

    res = backend.generate(
        [{"role": "user", "content": "analyze"}],
        max_tokens=256,
        temperature=0.1,
        timeout=10.0,
        schema=schema,
        grammar=grammar,
    )

    assert "BENIGN" in res
    assert client_mock.post.called
    _call_args, call_kwargs = client_mock.post.call_args
    posted_json = call_kwargs["json"]
    assert posted_json["grammar"] == grammar
    assert posted_json["response_format"]["type"] == "json_schema"
    assert posted_json["response_format"]["json_schema"]["schema"] == schema


def test_local_llm_client_passes_grammar_to_backend() -> None:
    class DummyBackend:
        name = "dummy"

        def __init__(self) -> None:
            self.last_grammar: str | None = None
            self.last_schema: dict | None = None

        def check(self) -> tuple[bool, str]:
            return True, "ready"

        def generate(self, messages, *, max_tokens, temperature, timeout, schema=None, grammar=None):
            self.last_grammar = grammar
            self.last_schema = schema
            return json.dumps(
                {
                    "verdict": "BENIGN",
                    "severity": "LOW",
                    "confidence": 0.9,
                    "threat_type": "normal",
                    "summary": "Clean execution.",
                    "why_suspicious": [],
                    "evidence": [],
                    "mitre_techniques": [],
                    "attack_stage": "EXECUTION",
                    "recommended_action": "NONE",
                    "false_positive_indicators": [],
                    "investigation_questions": [],
                }
            )

        def close(self) -> None:
            pass

    dummy = DummyBackend()
    settings = LLMSettings(enabled=True)
    client = LocalLLMClient(settings, dummy)

    event = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        process_name="ls",
        command_line="ls -l",
        source="test",
    )
    req = LLMRequest(event=event, findings=[], rag_docs=[])
    analysis = client.analyze(req)

    assert analysis.available is True
    assert analysis.verdict is not None
    assert analysis.verdict.verdict == Verdict.BENIGN
    # Check grammar was supplied to backend
    assert dummy.last_grammar is not None
    assert "root ::=" in dummy.last_grammar
    assert dummy.last_schema is not None
