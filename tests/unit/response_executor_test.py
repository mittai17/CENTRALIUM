"""Process suspend/terminate against throwaway child processes only (never anything else)."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time

import psutil
import pytest

from centralium.agent.config import PolicySettings
from centralium.agent.interfaces import ResponseExecutor
from centralium.agent.models import (
    ActionStatus,
    EventType,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
)
from centralium.agent.policy import ProtectionRules
from centralium.agent.response import LinuxResponseExecutor, WindowsResponseExecutor, create_executor
from centralium.agent.response.base import CommandResult

A = ResponseAction
pytestmark = pytest.mark.skipif(os.name != "posix", reason="posix signals")


class RecordingRunner:
    def __init__(self, rc: int = 0, stderr: str = ""):
        self.calls: list[list[str]] = []
        self.rc, self.stderr = rc, stderr

    def run(self, argv, timeout=15.0):
        self.calls.append(list(argv))
        return CommandResult(self.rc, "", self.stderr)


@pytest.fixture
def child():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    yield p
    with contextlib.suppress(ProcessLookupError):
        p.kill()
    p.wait(timeout=5)


def executor(**kw) -> LinuxResponseExecutor:
    kw.setdefault("runner", RecordingRunner())
    kw.setdefault("settings", PolicySettings())
    return LinuxResponseExecutor(**kw)


def decision(action, **target) -> PolicyDecision:
    return PolicyDecision(action=action, allowed=True, mode=OperatingMode.ACTIVE, target=target)


def event_for(p: subprocess.Popen, **kw) -> NormalizedEvent:
    proc = psutil.Process(p.pid)
    kw.setdefault("process_name", proc.name())
    return NormalizedEvent(event_type=EventType.PROCESS_START, pid=p.pid, source="test", **kw)


def test_protocol_and_factory():
    ex = executor()
    assert isinstance(ex, ResponseExecutor)
    assert A.TERMINATE_PROCESS in ex.supported()
    assert isinstance(create_executor("linux"), LinuxResponseExecutor)
    assert isinstance(create_executor("win32"), WindowsResponseExecutor)
    with pytest.raises(ValueError):
        create_executor("darwin")


def test_suspend_then_terminate_child(child):
    ex = executor()
    ev = event_for(child)
    r = ex.execute(decision(A.SUSPEND_PROCESS, pid=child.pid, process_name=ev.process_name), ev)
    assert r.status == ActionStatus.EXECUTED, r.detail
    time.sleep(0.2)
    assert psutil.Process(child.pid).status() == psutil.STATUS_STOPPED
    r = ex.execute(decision(A.TERMINATE_PROCESS, pid=child.pid, process_name=ev.process_name), ev)
    assert r.status == ActionStatus.EXECUTED, r.detail
    assert child.wait(timeout=5) == -9  # SIGKILL


def test_terminate_child_directly(child):
    ev = event_for(child)
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=child.pid), ev)
    assert r.status == ActionStatus.EXECUTED
    assert child.wait(timeout=5) == -9


def test_simulation_leaves_child_untouched(child):
    ev = event_for(child)
    for ex, tgt in ((executor(simulate=True), {}), (executor(), {"simulate": True})):
        r = ex.execute(decision(A.TERMINATE_PROCESS, pid=child.pid, **tgt), ev)
        assert r.status == ActionStatus.SIMULATED
    assert child.poll() is None and psutil.Process(child.pid).status() != psutil.STATUS_STOPPED


def test_protected_process_refused_by_name(child):
    ev = event_for(child)
    prot = ProtectionRules.from_lists([ev.process_name or ""], [], pid_resolver=None)
    r = executor(protection=prot).execute(decision(A.TERMINATE_PROCESS, pid=child.pid), ev)
    assert r.status == ActionStatus.FAILED and "protected" in r.detail
    assert child.poll() is None


@pytest.mark.parametrize("pid", [1, 2, os.getpid(), os.getppid()])
def test_own_and_system_pids_refused(pid):
    ev = NormalizedEvent(event_type=EventType.PROCESS_START, pid=pid, source="t", process_name="x")
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=pid), ev)
    assert r.status == ActionStatus.FAILED
    assert "refused" in r.detail
    assert psutil.pid_exists(pid)


def test_pid_reuse_create_time_mismatch_refused(child):
    ev = event_for(child)
    real = psutil.Process(child.pid).create_time()
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=child.pid, create_time=real - 500), ev)
    assert r.status == ActionStatus.FAILED and "PID reuse" in r.detail
    assert child.poll() is None
    ok = executor().execute(decision(A.SUSPEND_PROCESS, pid=child.pid, create_time=real), ev)
    assert ok.status == ActionStatus.EXECUTED
    psutil.Process(child.pid).resume()


def test_process_started_after_event_is_refused(child):
    stale = NormalizedEvent(
        event_type=EventType.PROCESS_START, pid=child.pid, source="t",
        timestamp=__import__("datetime").datetime.fromtimestamp(psutil.Process(child.pid).create_time() - 3600,
                                                               __import__("datetime").UTC),
    )  # fmt: skip
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=child.pid), stale)
    assert r.status == ActionStatus.FAILED and "after the triggering event" in r.detail
    assert child.poll() is None


def test_process_name_mismatch_refused(child):
    ev = event_for(child)
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=child.pid, process_name="totally-different"), ev)
    assert r.status == ActionStatus.FAILED and "name" in r.detail
    assert child.poll() is None


def test_nonexistent_pid_fails_cleanly():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    time.sleep(0.1)
    ev = NormalizedEvent(event_type=EventType.PROCESS_START, pid=p.pid, source="t")
    r = executor().execute(decision(A.TERMINATE_PROCESS, pid=p.pid), ev)
    assert r.status == ActionStatus.FAILED and "no longer exists" in r.detail


def test_undecided_or_disallowed_decisions_not_executed(child):
    ev = event_for(child)
    d = PolicyDecision(action=A.TERMINATE_PROCESS, allowed=False, target={"pid": child.pid})
    assert executor().execute(d, ev).status == ActionStatus.FAILED
    restricted = executor(settings=PolicySettings(allowed_actions=[A.ALERT]))
    assert restricted.execute(decision(A.TERMINATE_PROCESS, pid=child.pid), ev).status == ActionStatus.FAILED
    assert child.poll() is None


def test_alert_action_is_executed_without_side_effects():
    ev = NormalizedEvent(event_type=EventType.OTHER, source="t")
    r = executor().execute(decision(A.ALERT), ev)
    assert r.status == ActionStatus.EXECUTED


def test_audit_callback_receives_every_action(child):
    log = []
    ex = executor(audit=lambda a, t, d: log.append((t, d["status"])))
    ev = event_for(child)
    ex.execute(decision(A.TERMINATE_PROCESS, pid=child.pid, process_name="nope"), ev)
    ex.execute(decision(A.TERMINATE_PROCESS, pid=child.pid), ev)
    assert [s for _, s in log] == ["failed", "executed"]


def test_systemd_control_argv_validated_and_protected():
    runner = RecordingRunner()
    ex = executor(runner=runner)
    ex.systemd_control("evil-miner.service", "stop")
    assert runner.calls == [["systemctl", "stop", "--", "evil-miner.service"]]
    from centralium.agent.policy import ValidationError
    from centralium.agent.response.base import ExecutionRefusedError

    for bad in ("a b.service", "x.service; reboot", "../x.service", "--now.service ", "x", "$(id).service"):
        with pytest.raises(ValidationError):
            ex.systemd_control(bad, "stop")
    with pytest.raises(ValidationError):
        ex.systemd_control("x.service", "daemon-reexec")
    for prot in ("sshd.service", "systemd-logind.service", "dbus.service"):
        with pytest.raises(ExecutionRefusedError):
            ex.systemd_control(prot, "stop")
    assert len(runner.calls) == 1
