"""HTTP path against an in-process fake llama-server, pipeline wiring with RAG + LLM, and an
optional real-Gemma test (skipped unless CENTRALIUM_LLM_SERVER_URL points at a live server)."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from centralium.agent.config import CentraliumConfig, LLMSettings
from centralium.agent.interfaces import BehaviorResult
from centralium.agent.llm import LlamaServerBackend, LocalLLMClient, MockLLM, build_llm_client
from centralium.agent.models import (
    EventType,
    Finding,
    FindingSource,
    GraphSignal,
    NormalizedEvent,
    OperatingMode,
    ScoreFamily,
    Severity,
)
from centralium.agent.pipeline import Pipeline
from centralium.agent.rag import build_retriever
from tests.unit.test_llm_client import GOOD, make_req

RAG_DIR = Path(__file__).resolve().parents[2] / "rag"


class FakeLlamaServer:
    """Scriptable stand-in for llama-server (/health, /v1/chat/completions)."""

    def __init__(self) -> None:
        self.health = 200
        self.requests: list[dict[str, Any]] = []
        self.handler: Callable[[dict[str, Any]], tuple[int, Any]] = lambda body: (
            200,
            {"choices": [{"message": {"content": json.dumps(GOOD)}}]},
        )
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                return None

            def _send(self, code: int, payload: Any) -> None:
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                self._send(outer.health, {"status": "ok" if outer.health == 200 else "loading"})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                code, payload = outer.handler(body)
                self._send(code, payload)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def server() -> Iterator[FakeLlamaServer]:
    s = FakeLlamaServer()
    yield s
    s.stop()


def http_client(url: str, timeout: float = 5.0) -> LocalLLMClient:
    return LocalLLMClient(LLMSettings(idle_unload_sec=0, timeout_sec=timeout), LlamaServerBackend(url))


@pytest.mark.integration
def test_http_success_sends_loopback_chat_request_with_schema(server):
    c = http_client(server.url)
    assert c.available() and c.status()["backend"] == "llama-server"
    res = c.analyze(make_req())
    assert res.available and res.verdict is not None
    body = server.requests[0]
    assert body["messages"][0]["role"] == "system" and body["stream"] is False
    assert body["max_tokens"] == 384 and body["response_format"]["type"] == "json_schema"
    assert "UNTRUSTED DATA" in body["messages"][0]["content"]


@pytest.mark.integration
def test_http_falls_back_when_schema_unsupported(server):
    def h(body: dict[str, Any]) -> tuple[int, Any]:
        if "response_format" in body:
            return 400, {"error": "unsupported"}
        return 200, {"choices": [{"message": {"content": json.dumps(GOOD)}}]}

    server.handler = h
    assert http_client(server.url).analyze(make_req()).available
    assert len(server.requests) == 2 and "response_format" not in server.requests[1]


@pytest.mark.integration
def test_http_malformed_then_retry_then_ok(server):
    replies = iter(["garbage", json.dumps(GOOD)])
    server.handler = lambda b: (200, {"choices": [{"message": {"content": next(replies)}}]})
    res = http_client(server.url).analyze(make_req())
    assert res.available and len(server.requests) == 2


@pytest.mark.integration
@pytest.mark.parametrize(
    "payload", [{"unexpected": 1}, {"choices": []}, {"choices": [{"message": {}}]}, "str"]
)
def test_http_bad_envelope_is_unavailable(server, payload):
    server.handler = lambda b: (200, payload)
    res = http_client(server.url).analyze(make_req())
    assert not res.available and res.error


@pytest.mark.integration
def test_http_server_error_and_down_server(server):
    server.handler = lambda b: (500, {"error": "boom"})
    assert not http_client(server.url).analyze(make_req()).available
    server.stop()
    c = http_client(server.url)
    assert not c.available() and "unreachable" in str(c.status()["reason"])
    assert not c.analyze(make_req()).available


@pytest.mark.integration
def test_http_timeout(server):
    def slow(body: dict[str, Any]) -> tuple[int, Any]:
        time.sleep(1.0)
        return 200, {"choices": [{"message": {"content": json.dumps(GOOD)}}]}

    server.handler = slow
    t0 = time.perf_counter()
    res = http_client(server.url, timeout=0.3).analyze(make_req())
    assert not res.available and "timeout" in (res.error or "").lower()
    assert time.perf_counter() - t0 < 0.9 and len(server.requests) == 1  # no retry on timeout


@pytest.mark.integration
def test_http_loading_server_not_available(server):
    server.health = 503
    c = http_client(server.url)
    assert not c.available()
    assert not c.analyze(make_req()).available and server.requests == []


@pytest.mark.integration
def test_factory_uses_env_server_url(server, monkeypatch):
    monkeypatch.setenv("CENTRALIUM_LLM_SERVER_URL", server.url)
    c = build_llm_client(LLMSettings(idle_unload_sec=0))
    assert c.available() and c.analyze(make_req()).available


# --------------------------------------------------------------------- pipeline wiring
class _Behavior:
    def analyze(self, event: NormalizedEvent, findings: list[Finding]) -> BehaviorResult:
        f = Finding(
            event_id=event.event_id,
            source=FindingSource.BEHAVIOR,
            rule_id="B1",
            title="Office spawned PowerShell with encoded command",
            score=85,
            severity=Severity.HIGH,
            mitre_techniques=["T1059.001"],
        )
        return BehaviorResult(features={"enc": 1.0}, findings=[f])


class _Graph:
    def ingest(self, event: NormalizedEvent, findings: list[Finding]) -> GraphSignal:
        return GraphSignal(score=90, chain=["winword.exe -> powershell.exe"])

    def attach_incident(self, incident: Any) -> None: ...
    def chain_for(self, event_id: str) -> list[str]:
        return []

    def flush(self) -> None: ...
    def close(self) -> None: ...


def _event(**kw: Any) -> NormalizedEvent:
    kw.setdefault("command_line", "powershell -nop -w hidden -enc SQBFAFgA")
    return NormalizedEvent(
        event_type=EventType.PROCESS_START,
        process_name="powershell.exe",
        parent_process="winword.exe",
        source="test",
        **kw,
    )


@pytest.mark.integration
def test_pipeline_real_rag_with_mock_llm_runs_only_for_high_risk(tmp_path):
    rag, _ = build_retriever(RAG_DIR, tmp_path / "i.db")
    llm = MockLLM()
    cfg = CentraliumConfig(mode=OperatingMode.PASSIVE, llm=LLMSettings(gate_min_pre_risk=30))
    p = Pipeline(cfg, behavior=_Behavior(), graph=_Graph(), rag=rag, llm=llm)
    out = p.process(_event())
    assert out.ai is not None and out.ai.available and out.ai.model_name.startswith("MOCK")
    assert out.ai.rag_sources and any("T1059" in s or "powershell" in s for s in out.ai.rag_sources)
    assert out.scores[ScoreFamily.AI_ASSESSMENT].available
    assert rag.info()["documents"] > 100
    # benign low-risk events never touch RAG/LLM
    calls = llm.calls
    p2 = Pipeline(cfg, rag=rag, llm=llm)
    out2 = p2.process(_event())
    assert out2.ai is None and llm.calls == calls
    rag.close()


@pytest.mark.integration
def test_pipeline_survives_llm_http_outage(tmp_path, server):
    rag, _ = build_retriever(RAG_DIR, tmp_path / "i.db")
    server.handler = lambda b: (500, {})
    llm = http_client(server.url)
    cfg = CentraliumConfig(mode=OperatingMode.PASSIVE, llm=LLMSettings(gate_min_pre_risk=30))
    p = Pipeline(cfg, behavior=_Behavior(), graph=_Graph(), rag=rag, llm=llm)
    out = p.process(_event())
    assert out.ai is not None and not out.ai.available
    assert not out.scores[ScoreFamily.AI_ASSESSMENT].available  # excluded, not zero
    assert out.risk is not None and out.risk.final_score > 0
    rag.close()


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("CENTRALIUM_LLM_SERVER_URL"), reason="needs a live local llama-server with Gemma"
)
def test_real_gemma_via_llama_server_returns_valid_contract():
    c = build_llm_client(LLMSettings(timeout_sec=180, idle_unload_sec=0))
    assert c.available(), c.status()
    res = c.analyze(make_req())
    assert res.available and res.verdict is not None, res.error
    assert res.model_name == "gemma-3-1b-it-Q4_K_M"
