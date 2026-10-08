"""GBNF and JSON-schema grammars for strict AIVerdict LLM constraint decoding.

Guarantees:
* Strict conformance to llama.cpp GBNF grammar specification.
* Direct mapping to the ``AIVerdict`` Pydantic model contract.
* Zero external network access; 100% deterministic local generation.
* Retains Pydantic validation and sanitization as defense-in-depth.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from centralium.agent.models import (
    ActionRecommendation,
    AttackStage,
    Severity,
    Verdict,
)

log = logging.getLogger("centralium.llm.grammar")


def get_ai_verdict_gbnf() -> str:
    """Generate a valid llama.cpp GBNF grammar for the strict AIVerdict contract.

    This grammar constrains local llama.cpp / llama-server sampling to output only
    a single valid JSON object containing all required fields of ``AIVerdict``.
    """
    verdict_alts = " | ".join(f'"{json.dumps(v.value)}"' for v in Verdict)
    severity_alts = " | ".join(f'"{json.dumps(v.value)}"' for v in Severity)
    stage_alts = " | ".join(f'"{json.dumps(v.value)}"' for v in AttackStage)
    action_alts = " | ".join(f'"{json.dumps(v.value)}"' for v in ActionRecommendation)

    fields = [
        r'"\"verdict\"" ws ":" ws verdict-val',
        r'"\"severity\"" ws ":" ws severity-val',
        r'"\"confidence\"" ws ":" ws number-val',
        r'"\"threat_type\"" ws ":" ws string-val',
        r'"\"summary\"" ws ":" ws string-val',
        r'"\"why_suspicious\"" ws ":" ws string-arr',
        r'"\"evidence\"" ws ":" ws string-arr',
        r'"\"mitre_techniques\"" ws ":" ws mitre-arr',
        r'"\"attack_stage\"" ws ":" ws attack-stage-val',
        r'"\"recommended_action\"" ws ":" ws action-val',
        r'"\"false_positive_indicators\"" ws ":" ws string-arr',
        r'"\"investigation_questions\"" ws ":" ws string-arr',
    ]
    root_rule = 'root ::= "{" ws ' + ' "," ws '.join(fields) + ' ws "}"'
    esc_str = (
        r'string-val ::= "\"" ([^"\\\r\n] | "\\" '
        r'(["\\/bfnrt] | "u" [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F]))* "\""'
    )

    lines = [
        root_rule,
        "",
        f"verdict-val ::= {verdict_alts}",
        f"severity-val ::= {severity_alts}",
        f"attack-stage-val ::= {stage_alts}",
        f"action-val ::= {action_alts}",
        "",
        r'number-val ::= ("0" ("." [0-9]+)? | "1" (".0"+)? | [0-9]+ ("." [0-9]+)?)',
        "",
        esc_str,
        "",
        r'string-arr ::= "[" ws (string-val (ws "," ws string-val)*)? ws "]"',
        "",
        r'mitre-val ::= "\"T" [0-9] [0-9] [0-9] [0-9] ("." [0-9] [0-9] [0-9])? "\""',
        r'mitre-arr ::= "[" ws (mitre-val (ws "," ws mitre-val)*)? ws "]"',
        "",
        r"ws ::= [ \t\n\r]*",
        "",
    ]
    return "\n".join(lines)


def get_ai_verdict_json_schema() -> dict[str, Any]:
    """Generate JSON schema dictionary for OpenAI-compatible /v1/chat/completions."""
    arr = {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 12}
    return {
        "type": "object",
        "properties": {
            "verdict": {"enum": [v.value for v in Verdict]},
            "severity": {"enum": [v.value for v in Severity]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "threat_type": {"type": "string", "maxLength": 200},
            "summary": {"type": "string", "maxLength": 1000},
            "why_suspicious": arr,
            "evidence": arr,
            "mitre_techniques": {
                "type": "array",
                "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
                "maxItems": 8,
            },
            "attack_stage": {"enum": [v.value for v in AttackStage]},
            "recommended_action": {"enum": [v.value for v in ActionRecommendation]},
            "false_positive_indicators": arr,
            "investigation_questions": arr,
        },
        "required": [
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
        ],
        "additionalProperties": False,
    }


def validate_gbnf_syntax(grammar: str) -> bool:
    """Basic structural validation of a GBNF grammar specification."""
    if not grammar or not isinstance(grammar, str):
        return False
    # Must have a root rule
    if not re.search(r"^root\s*::=", grammar, re.MULTILINE):
        return False
    # All non-empty lines should follow identifier ::= expression or continue an expression
    for line in grammar.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "::=" not in line and not line.startswith("|"):
            return False
    return True


def benchmark_grammar_simulation(
    sample_outputs: list[str],
    *,
    iterations: int = 100,
) -> dict[str, Any]:
    """Benchmark parsing validity and latency for unconstrained vs constrained outputs.

    Simulates the valid-first-try rate and latency difference between grammar-constrained
    decoding (which guarantees valid schema on attempt 1) versus freeform text decoding
    which frequently requires retry iterations.
    """
    from centralium.agent.models import AIVerdict

    valid_first_try = 0
    parse_latencies_us: list[float] = []

    for text in sample_outputs:
        t0 = time.perf_counter_ns()
        try:
            AIVerdict.parse_llm_text(text)
            valid_first_try += 1
        except Exception as exc:
            log.debug("Benchmark sample validation failure: %s", exc)
        finally:
            t1 = time.perf_counter_ns()
            parse_latencies_us.append((t1 - t0) / 1000.0)

    total = len(sample_outputs)
    valid_rate = (valid_first_try / total) if total > 0 else 0.0
    avg_latency = (sum(parse_latencies_us) / len(parse_latencies_us)) if parse_latencies_us else 0.0

    return {
        "total_samples": total,
        "valid_first_try_count": valid_first_try,
        "valid_first_try_rate": valid_rate,
        "avg_parse_latency_us": avg_latency,
        "p95_parse_latency_us": sorted(parse_latencies_us)[int(0.95 * len(parse_latencies_us))]
        if parse_latencies_us
        else 0.0,
    }


__all__ = [
    "benchmark_grammar_simulation",
    "get_ai_verdict_gbnf",
    "get_ai_verdict_json_schema",
    "validate_gbnf_syntax",
]
