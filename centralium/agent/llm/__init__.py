"""ONE local LLM (Gemma 3 1B IT Q4_K_M via llama.cpp) + a clearly-labelled test mock."""

from centralium.agent.llm.backends import (
    LlamaCppPythonBackend,
    LlamaServerBackend,
    LLMBackend,
    LLMBackendError,
    LLMTimeoutError,
)
from centralium.agent.llm.client import LocalLLMClient, build_llm_client
from centralium.agent.llm.mock import MOCK_MODEL_NAME, MockLLM
from centralium.agent.llm.prompts import ROLES, build_prompt

__all__ = [
    "MOCK_MODEL_NAME",
    "ROLES",
    "LLMBackend",
    "LLMBackendError",
    "LLMTimeoutError",
    "LlamaCppPythonBackend",
    "LlamaServerBackend",
    "LocalLLMClient",
    "MockLLM",
    "build_llm_client",
    "build_prompt",
]
