"""ONE local LLM (Gemma 3 1B IT Q4_K_M via llama.cpp) + a clearly-labelled test mock."""

from centralium.agent.llm.backends import (
    LlamaCppPythonBackend,
    LlamaServerBackend,
    LLMBackend,
    LLMBackendError,
    LLMTimeoutError,
)
from centralium.agent.llm.cache import (
    IncidentFingerprintCache,
    fingerprint_from_event,
    fingerprint_from_request,
)
from centralium.agent.llm.client import LocalLLMClient, build_llm_client
from centralium.agent.llm.grammar import (
    benchmark_grammar_simulation,
    get_ai_verdict_gbnf,
    get_ai_verdict_json_schema,
)
from centralium.agent.llm.mock import MOCK_MODEL_NAME, MockLLM
from centralium.agent.llm.prompts import ROLE_TOKEN_BUDGETS, ROLES, build_prompt

__all__ = [
    "MOCK_MODEL_NAME",
    "ROLES",
    "ROLE_TOKEN_BUDGETS",
    "IncidentFingerprintCache",
    "LLMBackend",
    "LLMBackendError",
    "LLMTimeoutError",
    "LlamaCppPythonBackend",
    "LlamaServerBackend",
    "LocalLLMClient",
    "MockLLM",
    "benchmark_grammar_simulation",
    "build_llm_client",
    "build_prompt",
    "fingerprint_from_event",
    "fingerprint_from_request",
    "get_ai_verdict_gbnf",
    "get_ai_verdict_json_schema",
]
