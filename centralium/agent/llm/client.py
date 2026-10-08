"""LocalLLMClient: the ONE local model behind the pipeline's ``LLMClient`` protocol.

Guarantees
* never raises into the pipeline: every failure -> ``AIAnalysis(available=False, error=...)``;
* strict JSON contract: output validated with ``AIVerdict.parse_llm_text``; retried once
  (configurable) with a corrective message; still invalid -> unavailable;
* concurrency limit (default 1), per-call timeout, max ctx/output tokens;
* idle unload of the model; short unavailability cool-down after repeated failures;
* output is only ever a structured recommendation - nothing here executes anything.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from centralium.agent.config import LLMSettings
from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm.backends import (
    LlamaCppPythonBackend,
    LlamaServerBackend,
    LLMBackend,
    LLMBackendError,
    LLMTimeoutError,
    Messages,
)
from centralium.agent.llm.cache import IncidentFingerprintCache
from centralium.agent.llm.grammar import get_ai_verdict_gbnf
from centralium.agent.llm.prompts import (
    ROLE_TOKEN_BUDGETS,
    RenderedPrompt,
    build_prompt,
    json_schema,
    normalize_role,
    retry_message,
    sanitize,
)
from centralium.agent.models import AIAnalysis, AIVerdict, Verdict

log = logging.getLogger("centralium.llm")

SERVER_URL_ENV = "CENTRALIUM_LLM_SERVER_URL"
DEFAULT_SERVER_URL = "http://127.0.0.1:8080"
FAIL_THRESHOLD = 3
COOLDOWN_SEC = 30.0
AVAIL_CACHE_SEC = 5.0


class LocalLLMClient:
    """Real local Gemma (via llama-cpp-python or llama-server). ``is_mock`` is False."""

    is_mock = False

    def __init__(
        self,
        settings: LLMSettings,
        backend: LLMBackend | None,
        *,
        unavailable_reason: str = "",
        clock: Callable[[], float] | None = None,
        cache_capacity: int = 512,
    ) -> None:
        self.settings = settings
        self.backend = backend
        self._reason = unavailable_reason if backend is None else ""
        self._sem = threading.BoundedSemaphore(settings.concurrency)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._fails = 0
        self._down_until = 0.0
        self._avail: tuple[float, bool, str] = (-1e9, False, "")
        self._last_used = 0.0
        self._timer: threading.Timer | None = None
        self.cache = IncidentFingerprintCache(capacity=cache_capacity)
        self.calls = 0
        self.failures = 0
        self.last_error: str | None = None

    # ------------------------------------------------------------------ status
    @property
    def model_name(self) -> str:
        return self.settings.model_name

    @property
    def backend_name(self) -> str:
        return self.backend.name if self.backend else "none"

    def status(self) -> dict[str, object]:
        """What the UI shows: real Gemma vs mock vs unavailable."""
        ok, reason = self._probe()
        return {
            "mode": "real" if ok else "unavailable",
            "is_mock": False,
            "model": self.model_name,
            "backend": self.backend_name,
            "available": ok,
            "reason": reason,
            "calls": self.calls,
            "failures": self.failures,
            "last_error": self.last_error,
            "cache": self.cache.stats(),
        }

    def _probe(self) -> tuple[bool, str]:
        if not self.settings.enabled:
            return False, "LLM disabled in config"
        if self.backend is None:
            return False, self._reason or "no backend configured"
        now = self._clock()
        if now < self._down_until:
            return False, f"cooling down after repeated failures ({self.last_error})"
        ts, ok, reason = self._avail
        if now - ts < AVAIL_CACHE_SEC:
            return ok, reason
        ok, reason = self.backend.check()
        self._avail = (now, ok, reason)
        return ok, reason

    def available(self) -> bool:
        try:
            return self._probe()[0]
        except Exception as exc:  # never raise into the pipeline
            log.warning("availability probe failed: %s", exc)
            return False

    # ------------------------------------------------------------------ analysis
    def _unavailable(self, req: LLMRequest, error: str, started: float, sources: list[str]) -> AIAnalysis:
        self.last_error = error
        return AIAnalysis(
            event_id=req.event.event_id,
            available=False,
            verdict=None,
            role=normalize_role(req.role),
            model_name=self.model_name,
            latency_ms=(time.perf_counter() - started) * 1000,
            rag_sources=sources,
            error=error,
        )

    def analyze(self, request: LLMRequest) -> AIAnalysis:
        # Check LRU incident fingerprint cache first
        cached = self.cache.get_by_request(request)
        if cached is not None:
            return cached

        started = time.perf_counter()
        sources = [d.doc_id for d in request.rag_docs]
        try:
            return self._analyze(request, started, sources)
        except Exception as exc:  # last-resort guard
            log.exception("unexpected LLM client failure")
            self.failures += 1
            return self._unavailable(request, f"internal error: {type(exc).__name__}", started, sources)

    def _analyze(self, req: LLMRequest, started: float, sources: list[str]) -> AIAnalysis:
        ok, reason = self._probe()
        if not ok:
            return self._unavailable(req, f"LLM unavailable: {reason}", started, sources)
        s = self.settings
        if not self._sem.acquire(timeout=s.timeout_sec):
            self.failures += 1
            return self._unavailable(req, "LLM busy (concurrency limit)", started, sources)
        role = normalize_role(req.role)
        role_budget = ROLE_TOKEN_BUDGETS.get(role, s.max_tokens)
        gen_tokens = min(s.max_tokens, role_budget)
        try:
            self.calls += 1
            prompt = build_prompt(req, max_prompt_tokens=max(256, s.max_ctx - gen_tokens - 64))
            sources = prompt.sources or sources
            verdict, err = self._generate_validated(prompt, max_tokens=gen_tokens)
        finally:
            self._sem.release()
            self._touch()
        if verdict is None:
            self._record_failure(err)
            return self._unavailable(req, err, started, sources)
        self._fails = 0
        verdict = self._apply_injection_guard(verdict, prompt)
        analysis = AIAnalysis(
            event_id=req.event.event_id,
            available=True,
            verdict=verdict,
            role=role,
            model_name=self.model_name,
            latency_ms=(time.perf_counter() - started) * 1000,
            rag_sources=sources,
            error=None,
        )
        self.cache.put_by_request(req, analysis)
        return analysis

    def _generate_validated(
        self, prompt: RenderedPrompt, *, max_tokens: int | None = None
    ) -> tuple[AIVerdict | None, str]:
        assert self.backend is not None
        s = self.settings
        msgs: Messages = [
            {"role": "system", "content": prompt.system},
            {"role": "user", "content": prompt.user},
        ]
        tokens_to_gen = max_tokens if max_tokens is not None else s.max_tokens
        err = "no attempt"
        schema = json_schema()
        grammar = get_ai_verdict_gbnf()
        for attempt in range(1 + s.retries_on_invalid_json):
            try:
                text = self.backend.generate(
                    msgs,
                    max_tokens=tokens_to_gen,
                    temperature=s.temperature,
                    timeout=s.timeout_sec,
                    schema=schema,
                    grammar=grammar,
                )
            except LLMTimeoutError as exc:
                return None, f"LLM timeout: {exc}"  # do not retry a timeout
            except LLMBackendError as exc:
                return None, f"LLM backend error: {exc}"
            try:
                return AIVerdict.parse_llm_text(text), ""
            except (ValueError, ValidationError) as exc:
                err = f"invalid LLM output (attempt {attempt + 1}): {sanitize(exc, 200)}"
                log.warning(err)
                msgs = [
                    *msgs[:2],
                    {"role": "assistant", "content": sanitize(text, 300)},
                    {"role": "user", "content": retry_message(str(exc))},
                ]
        return None, err

    @staticmethod
    def _apply_injection_guard(v: AIVerdict, prompt: RenderedPrompt) -> AIVerdict:
        """If the untrusted evidence tried to instruct the model, never let the result be
        BENIGN/no-action: attackers must not be able to talk the verdict down."""
        if not prompt.injection_hits:
            return v
        note = "prompt-injection text present in evidence (treated as hostile)"
        upd: dict[str, object] = {"why_suspicious": [*v.why_suspicious, note][:50]}
        if v.verdict in (Verdict.BENIGN, Verdict.UNKNOWN):
            upd["verdict"] = Verdict.SUSPICIOUS
        return v.model_copy(update=upd)

    def _record_failure(self, err: str) -> None:
        self.failures += 1
        self._fails += 1
        if self._fails >= FAIL_THRESHOLD:
            self._down_until = self._clock() + COOLDOWN_SEC
            self._fails = 0
            log.warning("LLM marked unavailable for %ss: %s", COOLDOWN_SEC, err)

    # ------------------------------------------------------------------ lifecycle
    def _touch(self) -> None:
        idle = self.settings.idle_unload_sec
        if idle <= 0:
            return
        with self._lock:
            self._last_used = self._clock()
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(idle, self._idle_check)
            self._timer.daemon = True
            self._timer.start()

    def _idle_check(self) -> None:
        if self._clock() - self._last_used >= self.settings.idle_unload_sec:
            self.unload()

    def unload(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
        if self.backend is not None:
            try:
                self.backend.close()
            except Exception as exc:
                log.warning("unload failed: %s", exc)


def build_llm_client(settings: LLMSettings, *, server_url: str | None = None) -> LocalLLMClient:
    """Choose the backend: ``CENTRALIUM_LLM_SERVER_URL`` (loopback llama-server) if set,
    else settings.server_url (defaults to http://127.0.0.1:8080),
    else llama-cpp-python when importable and ``model_path`` exists. Otherwise a client
    that reports *unavailable* - it never silently substitutes a mock."""
    url = (
        server_url
        if server_url is not None
        else (os.environ.get(SERVER_URL_ENV) or getattr(settings, "server_url", None) or DEFAULT_SERVER_URL)
    )
    if url:
        try:
            server_backend = LlamaServerBackend(url)
            if server_url is None and not os.environ.get(SERVER_URL_ENV):
                ok, _ = server_backend.check()
                if not ok and settings.model_path is not None and LlamaCppPythonBackend.importable():
                    server_backend.close()
                    url = None
                else:
                    return LocalLLMClient(settings, server_backend)
            else:
                return LocalLLMClient(settings, server_backend)
        except ValueError as exc:
            return LocalLLMClient(settings, None, unavailable_reason=str(exc))
    if settings.model_path is not None and LlamaCppPythonBackend.importable():
        return LocalLLMClient(
            settings,
            LlamaCppPythonBackend(
                Path(settings.model_path),
                n_ctx=settings.max_ctx,
                n_threads=settings.threads,
                n_gpu_layers=settings.gpu_layers,
            ),
        )
    why = (
        "no model_path configured and no server_url"
        if settings.model_path is None
        else "llama-cpp-python not installed (set CENTRALIUM_LLM_SERVER_URL to use llama-server)"
    )
    return LocalLLMClient(settings, None, unavailable_reason=why)
