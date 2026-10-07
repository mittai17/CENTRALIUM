"""Shared helpers for the end-to-end suite. Everything here is isolated and non-destructive:
real modules, synthetic events, simulated/recording executors, throw-away data dirs."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.config import CentraliumConfig, load_config
from centralium.agent.demo import DemoScenario, build_scenarios
from centralium.agent.interfaces import LLMRequest
from centralium.agent.models import AIAnalysis, NormalizedEvent, PipelineOutcome
from centralium.agent.response.base import CommandResult, ProcInfo
from centralium.agent.runtime import Runtime, build_runtime

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def sandbox_cfg(tmp_path: Path, **kw: Any) -> CentraliumConfig:
    """Isolated TEST-mode config (simulated executor, destructive gate closed)."""
    base: dict[str, Any] = {
        "test_mode": True,
        "mode": "ACTIVE",
        "paths": {"data_dir": str(tmp_path / "data")},
    }
    base.update(kw)
    return load_config(None, env={}, **base)


def scenario(name: str) -> DemoScenario:
    return build_scenarios(names=[name])[0]


def run_events(rt: Runtime, events: Sequence[NormalizedEvent]) -> list[PipelineOutcome]:
    return [rt.pipeline.process(e) for e in events]


def best_risk(outs: list[PipelineOutcome]) -> float:
    return max((o.risk.final_score for o in outs if o.risk), default=0.0)


class BoomBackend:
    """Process backend that fails the test if anything tries to touch a process."""

    def info(self, pid: int) -> ProcInfo | None:  # pragma: no cover - must never run
        raise AssertionError(f"process lookup attempted in a sandbox run (pid={pid})")

    def suspend(self, pid: int) -> None:  # pragma: no cover
        raise AssertionError("suspend attempted in a sandbox run")

    def kill(self, pid: int) -> None:  # pragma: no cover
        raise AssertionError("kill attempted in a sandbox run")


class BoomRunner:
    def run(self, argv: Sequence[str], timeout: float = 15.0) -> CommandResult:  # pragma: no cover
        raise AssertionError(f"subprocess attempted in a sandbox run: {list(argv)}")


@dataclass
class RecordingRunner:
    """Mock command runner: records argv lists, never spawns anything."""

    calls: list[list[str]] = field(default_factory=list)

    def run(self, argv: Sequence[str], timeout: float = 15.0) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(0)


@dataclass
class RecordingBackend:
    """Mock process backend (records suspend/kill; reports a fixed process table)."""

    procs: dict[int, ProcInfo] = field(default_factory=dict)
    suspended: list[int] = field(default_factory=list)
    killed: list[int] = field(default_factory=list)
    lookups: list[int] = field(default_factory=list)

    def info(self, pid: int) -> ProcInfo | None:
        self.lookups.append(pid)
        return self.procs.get(pid)

    def suspend(self, pid: int) -> None:
        self.suspended.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


class SpyLLM:
    """LLM that records every request; used to prove known malware never reaches the model."""

    model_name = "spy"

    def __init__(self, inner: Any | None = None) -> None:
        self.inner = inner
        self.requests: list[LLMRequest] = []

    def available(self) -> bool:
        return True

    def unload(self) -> None:
        return None

    def analyze(self, request: LLMRequest) -> AIAnalysis:
        self.requests.append(request)
        if self.inner is not None:
            return self.inner.analyze(request)
        return AIAnalysis(event_id=request.event.event_id, available=False, error="spy")


def make_rt(cfg: CentraliumConfig, **kw: Any) -> Runtime:
    kw.setdefault("llm_mode", "mock")
    kw.setdefault("enable_self_protection", False)
    kw.setdefault("runner_guard", True)
    guard = kw.pop("runner_guard")
    if guard and "command_runner" not in kw:
        kw["command_runner"] = BoomRunner()
    rt = build_runtime(cfg, **kw)
    if guard and (cfg.demo_mode or cfg.test_mode):
        rt.executor.process_backend = BoomBackend()
    return rt
