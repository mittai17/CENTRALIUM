"""Inference backends for the ONE local model (Gemma 3 1B IT Q4_K_M, llama.cpp).

* ``LlamaCppPythonBackend`` - in-process via ``llama_cpp`` when importable.
* ``LlamaServerBackend``    - HTTP to a local ``llama-server`` on loopback only.

This module deliberately imports no process-spawning facilities: the model server is
started by the operator (``scripts/llm_server.sh``), never by this package, and nothing
here can run model output.
"""

from __future__ import annotations

import concurrent.futures
import importlib.util
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

log = logging.getLogger("centralium.llm.backend")

Messages = list[dict[str, str]]
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class LLMBackendError(RuntimeError):
    """Backend failed (connection, load, bad HTTP status, malformed envelope)."""


class LLMTimeoutError(LLMBackendError):
    """Generation exceeded the configured timeout."""


class LLMBackend(Protocol):
    name: str

    def check(self) -> tuple[bool, str]:
        """Cheap readiness probe -> (ok, human reason)."""
        ...

    def generate(
        self,
        messages: Messages,
        *,
        max_tokens: int,
        temperature: float,
        timeout: float,
        schema: dict[str, Any] | None = None,
        grammar: str | None = None,
    ) -> str: ...

    def close(self) -> None: ...


class LlamaServerBackend:
    """OpenAI-compatible ``/v1/chat/completions`` of a local llama-server."""

    name = "llama-server"

    def __init__(self, base_url: str = "http://127.0.0.1:8080", client: httpx.Client | None = None) -> None:
        host = urlparse(base_url).hostname
        if host not in LOOPBACK:
            raise ValueError(
                f"llama-server must be on loopback (got {host!r}); remote/cloud LLMs are not allowed"
            )
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(trust_env=False)
        self._schema_ok = True
        self._grammar_ok = True

    def check(self) -> tuple[bool, str]:
        try:
            r = self._client.get(f"{self.base_url}/health", timeout=2.0)
        except httpx.HTTPError as exc:
            return False, f"llama-server unreachable: {type(exc).__name__}"
        if r.status_code == 200:
            return True, "llama-server ready"
        return False, f"llama-server not ready (HTTP {r.status_code})"

    def generate(
        self,
        messages: Messages,
        *,
        max_tokens: int,
        temperature: float,
        timeout: float,
        schema: dict[str, Any] | None = None,
        grammar: str | None = None,
    ) -> str:
        body: dict[str, Any] = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if schema is not None and self._schema_ok:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "verdict", "schema": schema},
            }
        if grammar is not None and self._grammar_ok:
            body["grammar"] = grammar
        try:
            r = self._client.post(f"{self.base_url}/v1/chat/completions", json=body, timeout=timeout)
            if r.status_code == 400 and ("response_format" in body or "grammar" in body):
                log.warning(
                    "llama-server rejected grammar/response_format constraint; retrying unconstrained"
                )
                self._schema_ok = False
                self._grammar_ok = False
                body.pop("response_format", None)
                body.pop("grammar", None)
                r = self._client.post(f"{self.base_url}/v1/chat/completions", json=body, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            return str(data["choices"][0]["message"]["content"] or "")
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(f"llama-server timeout after {timeout}s") from exc
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMBackendError(f"llama-server error: {type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        self._client.close()


class LlamaCppPythonBackend:
    """In-process llama-cpp-python. Lazy model load, optional GPU offload."""

    name = "llama-cpp-python"

    def __init__(
        self,
        model_path: Path,
        *,
        n_ctx: int = 2048,
        n_threads: int = 4,
        n_gpu_layers: int = 0,
        loader: Callable[..., Any] | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.n_ctx, self.n_threads, self.n_gpu_layers = n_ctx, n_threads, n_gpu_layers
        self._loader = loader
        self._llm: Any = None
        self._lock = threading.Lock()
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None

    @staticmethod
    def importable() -> bool:
        return importlib.util.find_spec("llama_cpp") is not None

    def check(self) -> tuple[bool, str]:
        if self._loader is None and not self.importable():
            return False, "llama_cpp (llama-cpp-python) is not installed"
        if not self.model_path.is_file():
            return False, f"model file not found: {self.model_path}"
        return True, "llama-cpp-python ready (model loads lazily)"

    def _load(self) -> Any:
        with self._lock:
            if self._llm is None:
                loader = self._loader
                if loader is None:
                    from llama_cpp import Llama  # type: ignore[import-not-found,unused-ignore]

                    loader = Llama
                log.info(
                    "loading %s (ctx=%s threads=%s gpu_layers=%s)",
                    self.model_path.name,
                    self.n_ctx,
                    self.n_threads,
                    self.n_gpu_layers,
                )
                self._llm = loader(
                    model_path=str(self.model_path),
                    n_ctx=self.n_ctx,
                    n_threads=self.n_threads,
                    n_gpu_layers=self.n_gpu_layers,
                    verbose=False,
                )
            return self._llm

    def generate(
        self,
        messages: Messages,
        *,
        max_tokens: int,
        temperature: float,
        timeout: float,
        schema: dict[str, Any] | None = None,
        grammar: str | None = None,
    ) -> str:
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm")

        def run() -> str:
            llm = self._load()
            kw: dict[str, Any] = {}
            if schema is not None:
                kw["response_format"] = {"type": "json_object", "schema": schema}
            if grammar is not None:
                kw["grammar"] = grammar
            out = llm.create_chat_completion(
                messages=messages, max_tokens=max_tokens, temperature=temperature, **kw
            )
            return str(out["choices"][0]["message"]["content"] or "")

        fut = self._pool.submit(run)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            # The C call cannot be interrupted; the single worker stays busy until it
            # returns, so later calls queue behind it (client semaphore accounts for it).
            raise LLMTimeoutError(f"generation timeout after {timeout}s") from exc
        except (KeyError, IndexError, TypeError, ValueError, RuntimeError, OSError) as exc:
            raise LLMBackendError(f"llama-cpp-python error: {type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            self._llm = None  # drop reference -> model memory freed by GC


__all__ = [
    "LLMBackend",
    "LLMBackendError",
    "LLMTimeoutError",
    "LlamaCppPythonBackend",
    "LlamaServerBackend",
    "Messages",
]
