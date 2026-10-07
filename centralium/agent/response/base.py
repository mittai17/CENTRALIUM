"""Shared pieces of the response executors: runner injection, process backends, validation.

Safety properties enforced here (for every platform):
* subprocesses only via argv lists - ``shell=True`` is never used (``SubprocessRunner``);
* every target is re-validated (pid/ip/port/protocol/path/unit) irrespective of the policy;
* protected processes/paths are refused again at execution time;
* PID-reuse guard: a process whose ``create_time`` is *after* the triggering event, or that
  differs from a ``create_time`` recorded at detection, or whose name changed, is not touched;
* simulate mode (demo/test, or ``target['simulate']``) validates and plans but performs nothing.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from centralium.agent.config import PolicySettings
from centralium.agent.interfaces import QuarantineManager
from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    NormalizedEvent,
    PolicyDecision,
    ResponseAction,
)
from centralium.agent.policy.protection import ProtectionRules
from centralium.agent.policy.validation import (
    IPNetwork,
    ValidationError,
    non_blockable_reason,
    validate_ip,
    validate_network,
    validate_path_str,
    validate_pid,
    validate_port,
    validate_protocol,
)

log = logging.getLogger("centralium.response")

AuditFn = Callable[[str, str, dict[str, Any]], None]
CREATE_TIME_TOLERANCE = 1.5  # seconds


class ExecutionRefusedError(RuntimeError):
    """Raised internally when an action must not be performed (turned into FAILED)."""


# --------------------------------------------------------------------------- command runner
@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], timeout: float = 15.0) -> CommandResult: ...


class SubprocessRunner:
    """The only place a real subprocess is spawned: argv list, shell=False, bounded time/output."""

    def run(self, argv: Sequence[str], timeout: float = 15.0) -> CommandResult:
        if not argv or not all(isinstance(a, str) for a in argv) or any("\x00" in a for a in argv):
            raise ValueError("argv must be a non-empty list of NUL-free strings")
        try:
            cp = subprocess.run(
                list(argv),
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return CommandResult(127, "", f"command not found: {argv[0]}")
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"timeout after {timeout}s: {argv[0]}")
        return CommandResult(cp.returncode, cp.stdout[-4000:], cp.stderr[-4000:])


# --------------------------------------------------------------------------- process backend
@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    create_time: float
    exe: str | None = None


class ProcessBackend(Protocol):
    def info(self, pid: int) -> ProcInfo | None: ...
    def suspend(self, pid: int) -> None: ...
    def kill(self, pid: int) -> None: ...


class PsutilProcessBackend:
    """Linux: SIGSTOP/SIGKILL via ``os.kill``. Windows: psutil suspend / kill."""

    def info(self, pid: int) -> ProcInfo | None:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        try:
            p = psutil.Process(pid)
            with p.oneshot():
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                return ProcInfo(pid, p.name(), p.create_time(), exe)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

    def suspend(self, pid: int) -> None:
        if os.name == "posix":
            os.kill(pid, signal.SIGSTOP)
        else:  # pragma: no cover - windows only
            import psutil  # type: ignore[import-untyped,unused-ignore]

            psutil.Process(pid).suspend()

    def kill(self, pid: int) -> None:
        if os.name == "posix":
            os.kill(pid, signal.SIGKILL)
        else:  # pragma: no cover - windows only
            import psutil  # type: ignore[import-untyped,unused-ignore]

            psutil.Process(pid).kill()


# --------------------------------------------------------------------------- base executor
@dataclass
class IsolationConfig:
    """Management exceptions kept open while the endpoint is isolated."""

    management_networks: tuple[str, ...] = ()  # e.g. SOC console / jump host (CIDR or IP)
    allow_loopback: bool = True  # always true; loopback exception is not optional
    allow_established: bool = True

    def parsed(self) -> list[IPNetwork]:
        return [validate_network(n) for n in self.management_networks]


@dataclass
class BaseResponseExecutor:
    quarantine: QuarantineManager | None = None
    runner: CommandRunner = field(default_factory=SubprocessRunner)
    process_backend: ProcessBackend = field(default_factory=PsutilProcessBackend)
    protection: ProtectionRules | None = None
    settings: PolicySettings = field(default_factory=PolicySettings)
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    audit: AuditFn | None = None
    simulate: bool = False  # demo/test mode: validate + plan, never act
    command_timeout: float = 15.0

    platform_name = "base"

    def __post_init__(self) -> None:
        if self.protection is None:
            self.protection = ProtectionRules.from_lists(
                self.settings.protected_processes, self.settings.protected_paths
            )
        self._planned: list[list[str]] = []

    # ---- protocol
    def supported(self) -> frozenset[ResponseAction]:
        return frozenset(ResponseAction)

    def execute(self, decision: PolicyDecision, event: NormalizedEvent) -> ActionResult:
        if decision.action is None:
            raise ValueError("decision has no action")
        action = decision.action
        target = dict(decision.target)
        simulate = self.simulate or bool(target.get("simulate"))
        self._planned = []
        status, detail = ActionStatus.FAILED, ""
        try:
            if not decision.allowed:
                raise ExecutionRefusedError("decision is not allowed")
            if action not in self.settings.allowed_actions:
                raise ExecutionRefusedError(f"{action.value} not permitted by configuration")
            detail = self._dispatch(action, target, event, simulate)
            status = (
                ActionStatus.SIMULATED
                if (simulate and action != ResponseAction.ALERT)
                else ActionStatus.EXECUTED
            )
        except (ExecutionRefusedError, ValidationError) as exc:
            detail = f"refused: {exc}"
            log.warning("response %s refused: %s", action.value, exc)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            log.exception("response %s failed", action.value)
        out_target = {k: v for k, v in target.items() if k != "event_time"}
        if self._planned:
            out_target["planned_commands"] = [list(c) for c in self._planned]
        result = ActionResult(
            action=action, status=status, target=out_target, detail=detail, event_id=event.event_id
        )
        self._emit(
            "response",
            "response_action",
            {"action": action.value, "status": status.value, "detail": detail[:500], "event_id": event.event_id,  # noqa: E501
             "simulate": simulate},
        )  # fmt: skip
        return result

    # ---- dispatch
    def _dispatch(
        self, action: ResponseAction, t: dict[str, Any], ev: NormalizedEvent, simulate: bool
    ) -> str:
        if action == ResponseAction.ALERT:
            log.warning("ALERT event=%s %s", ev.event_id, t.get("reasons"))
            return "alert logged"
        if action in (ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS):
            return self._process_action(action, t, ev, simulate)
        if action == ResponseAction.BLOCK_CONNECTION:
            ip = validate_ip(t.get("ip"))
            why = non_blockable_reason(ip)
            if why:
                raise ExecutionRefusedError(f"refusing to block {why} address")
            for net in self.isolation.parsed():
                if net.version == ip.version and ip in net:
                    raise ExecutionRefusedError("refusing to block a management network address")
            port = validate_port(t["port"]) if t.get("port") is not None else None
            proto = validate_protocol(t["protocol"]) if t.get("protocol") is not None else None
            return self.block_connection(str(ip), port, proto, simulate)
        if action == ResponseAction.QUARANTINE_FILE:
            return self._quarantine(t, simulate)
        if action == ResponseAction.ISOLATE_ENDPOINT:
            return self.isolate_endpoint(simulate)
        raise ExecutionRefusedError(f"unsupported action {action}")

    # ---- process control
    def _process_action(
        self, action: ResponseAction, t: dict[str, Any], ev: NormalizedEvent, simulate: bool
    ) -> str:
        pid = validate_pid(t.get("pid"))
        assert self.protection is not None
        info = self.process_backend.info(pid)
        name = t.get("process_name") or ev.process_name
        reason = self.protection.process_refusal(pid, name, t.get("executable_path"))
        if reason:
            raise ExecutionRefusedError(reason)
        if info is None:
            raise ExecutionRefusedError(f"process {pid} no longer exists")
        reason = self.protection.process_refusal(pid, info.name, info.exe)
        if reason:
            raise ExecutionRefusedError(reason)
        self._pid_reuse_check(info, t, ev, name)
        if simulate:
            return f"simulated {action.value} pid={pid} ({info.name})"
        if action == ResponseAction.SUSPEND_PROCESS:
            self.process_backend.suspend(pid)
            return f"suspended pid={pid} ({info.name})"
        self.process_backend.kill(pid)
        return f"terminated pid={pid} ({info.name})"

    @staticmethod
    def _pid_reuse_check(info: ProcInfo, t: dict[str, Any], ev: NormalizedEvent, name: str | None) -> None:
        expected = t.get("create_time")
        if (
            isinstance(expected, (int, float))
            and abs(info.create_time - float(expected)) > CREATE_TIME_TOLERANCE
        ):
            raise ExecutionRefusedError("PID reuse suspected: create_time differs from detection time")
        event_time = t.get("event_time") or ev.timestamp.timestamp()
        if info.create_time > float(event_time) + CREATE_TIME_TOLERANCE:
            raise ExecutionRefusedError("PID reuse suspected: process started after the triggering event")
        if name and not _same_name(info.name, str(name)):
            raise ExecutionRefusedError(f"PID reuse suspected: process name '{info.name}' != '{name}'")

    # ---- quarantine
    def _quarantine(self, t: dict[str, Any], simulate: bool) -> str:
        path = validate_path_str(t.get("path"))
        assert self.protection is not None
        reason = self.protection.path_refusal(path)
        if reason:
            raise ExecutionRefusedError(reason)
        if self.quarantine is None:
            raise ExecutionRefusedError("no quarantine manager configured")
        if simulate:
            return f"simulated quarantine of {path}"
        rec = self.quarantine.quarantine(Path(path), list(t.get("reasons", [])), list(t.get("sources", [])))
        return f"quarantined as {rec.quarantine_id} sha256={rec.sha256}"

    # ---- helpers
    def _run(self, argv: Sequence[str], simulate: bool, *, check: bool = True) -> CommandResult:
        self._planned.append(list(argv))
        if simulate:
            return CommandResult(0)
        res = self.runner.run(argv, self.command_timeout)
        if check and res.returncode != 0:
            raise RuntimeError(f"{argv[0]} failed rc={res.returncode}: {res.stderr.strip()[:300]}")
        return res

    def _emit(self, actor: str, event_type: str, details: dict[str, Any]) -> None:
        if self.audit is None:
            return
        try:
            self.audit(actor, event_type, details)
        except Exception:
            log.exception("audit callback failed")

    # ---- platform hooks (overridden)
    def block_connection(self, ip: str, port: int | None, proto: str | None, simulate: bool) -> str:
        raise NotImplementedError

    def isolate_endpoint(self, simulate: bool) -> str:
        raise NotImplementedError

    def release_isolation(self, simulate: bool = False) -> str:
        raise NotImplementedError

    def release_blocks(self, simulate: bool = False) -> str:
        raise NotImplementedError


def _same_name(actual: str, expected: str) -> bool:
    a, e = actual.lower(), expected.lower()
    # Linux comm is truncated to 15 chars; .exe suffix is optional
    return a == e or Path(a).stem == Path(e).stem or (len(a) >= 15 and e.startswith(a))


def env_flag(name: str, environ: Mapping[str, str] | None = None) -> bool:
    return (environ or os.environ).get(name, "").lower() in {"1", "true", "yes", "on"}
