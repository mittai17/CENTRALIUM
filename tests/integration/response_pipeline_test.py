"""End-to-end: Pipeline wired with the real graph/novelty/risk/policy/response/quarantine modules.

Safety: test/demo mode never performs OS actions; the only real destructive operations are
SIGKILL/quarantine on a throwaway child process and a temp file, via explicit ACTIVE-mode
config pointing at temp dirs. Firewall commands go to a recording runner.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

import psutil
import pytest

from centralium.agent.config import CentraliumConfig, PolicySettings
from centralium.agent.graph import create_graph_adapter
from centralium.agent.interfaces import BehaviorResult
from centralium.agent.models import (
    ActionStatus,
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    OperatingMode,
    ResponseAction,
    RiskBand,
    Severity,
)
from centralium.agent.novelty import BaselineNoveltyFilter
from centralium.agent.pipeline import Pipeline
from centralium.agent.policy import RulesPolicyEngine
from centralium.agent.quarantine import FileQuarantineManager
from centralium.agent.response import LinuxResponseExecutor
from centralium.agent.response.base import CommandResult
from centralium.agent.risk import CalibratedRiskEngine

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.name != "posix", reason="posix")]
T0 = datetime(2026, 1, 1, tzinfo=UTC)


class Runner:
    def __init__(self):
        self.calls = []

    def run(self, argv, timeout=15.0):
        self.calls.append(list(argv))
        return CommandResult(0)


class KnownBadEPP:
    """Flags events marked raw_metadata['bad'] / process 'dropper' / *.evil files as known-malicious."""

    def inspect(self, ev):
        if (
            ev.raw_metadata.get("bad")
            or (ev.process_name == "dropper")
            or (ev.file_path or "").endswith(".evil")
        ):
            return [Finding(event_id=ev.event_id, source=FindingSource.HASH, rule_id="hash.known", title="known bad hash",
                            severity=Severity.CRITICAL, score=100, known_malicious=True)]  # fmt: skip
        return []


class ChainBehavior:
    def analyze(self, event, findings):
        return BehaviorResult(ml_eligible=False)


def build(tmp_path, *, mode, demo=False, test=False, runner=None, require_approval=False):
    cfg = CentraliumConfig(mode=mode, demo_mode=demo, test_mode=test,
                           policy=PolicySettings(require_approval=require_approval))  # fmt: skip
    cfg.paths.data_dir
    q = FileQuarantineManager(tmp_path / "quar", authorized_users={"admin"})
    ex = LinuxResponseExecutor(runner=runner or Runner(), quarantine=q, firewall="nft", simulate=demo or test,
                               settings=cfg.policy)  # fmt: skip
    graph = create_graph_adapter(tmp_path / "graph")
    pipe = Pipeline(cfg, epp=KnownBadEPP(), behavior=ChainBehavior(), graph=graph,
                    novelty=BaselineNoveltyFilter(tmp_path / "nov.db"), risk=CalibratedRiskEngine(cfg.risk),
                    policy=RulesPolicyEngine(cfg.policy), executor=ex)  # fmt: skip
    return pipe, q, graph


@pytest.fixture
def child():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    yield p
    p.kill()
    p.wait(timeout=5)


def start_event(p):
    """Process-start for the real child (its real comm name, so the executor's PID-reuse check passes)."""
    return NormalizedEvent(event_type=EventType.PROCESS_START, pid=p.pid, ppid=os.getpid(),
                           process_name=psutil.Process(p.pid).name(), timestamp=datetime.now(UTC), source="test",
                           raw_metadata={"bad": True})  # fmt: skip


def test_test_mode_known_malicious_is_simulated_and_child_survives(tmp_path, child):
    pipe, _, graph = build(tmp_path, mode=OperatingMode.ACTIVE, test=True)
    out = pipe.process(start_event(child))
    assert out.short_circuited and out.risk.band == RiskBand.CRITICAL
    assert out.decision.action == ResponseAction.TERMINATE_PROCESS
    assert out.actions[0].status == ActionStatus.SIMULATED
    assert child.poll() is None
    assert "graph" in out.stages_reached and not out.stage_errors
    pipe.close()
    graph.close()


def test_active_mode_terminates_only_the_throwaway_child(tmp_path, child):
    pipe, _, graph = build(tmp_path, mode=OperatingMode.ACTIVE)
    out = pipe.process(start_event(child))
    assert out.actions[0].status == ActionStatus.EXECUTED, out.actions[0].detail
    assert child.wait(timeout=5) == -9
    pipe.close()
    graph.close()


def test_approval_required_blocks_execution_until_approved(tmp_path, child):
    pipe, _, graph = build(tmp_path, mode=OperatingMode.ACTIVE, require_approval=True)
    out = pipe.process(start_event(child))
    assert out.actions[0].status == ActionStatus.PENDING_APPROVAL
    assert child.poll() is None
    graph.close()


def test_learning_and_passive_never_destructive(tmp_path, child):
    for mode in (OperatingMode.LEARNING, OperatingMode.PASSIVE):
        pipe, _, graph = build(tmp_path / mode.value, mode=mode)
        out = pipe.process(start_event(child))
        assert child.poll() is None
        assert all(a.action == ResponseAction.ALERT for a in out.actions)
        graph.close()


def test_file_quarantine_via_pipeline_then_authorized_restore(tmp_path):
    pipe, q, graph = build(tmp_path, mode=OperatingMode.ACTIVE)
    f = tmp_path / "drop.evil"
    f.write_bytes(b"MZ-not-really")
    ev = NormalizedEvent(event_type=EventType.FILE_CREATE, pid=os.getpid() + 100000, process_name="curl", file_path=str(f),
                         timestamp=datetime.now(UTC), source="test")  # fmt: skip
    out = pipe.process(ev)
    assert (
        out.actions[0].action == ResponseAction.QUARANTINE_FILE
        and out.actions[0].status == ActionStatus.EXECUTED
    )
    assert not f.exists()
    rec = q.list()[0]
    assert rec.sources == ["hash"] and rec.reasons == ["known bad hash"]
    q.restore(rec.quarantine_id, authorized_by="admin", reason="test")
    assert f.read_bytes() == b"MZ-not-really"
    graph.close()


def test_network_block_via_pipeline_uses_mock_runner(tmp_path):
    runner = Runner()

    class NetEPP:
        def inspect(self, ev):
            return [Finding(event_id=ev.event_id, source=FindingSource.IOC, rule_id="ioc.ip", title="C2 ip", score=100,
                            known_malicious=True, severity=Severity.CRITICAL)]  # fmt: skip

    pipe, _, graph = build(tmp_path, mode=OperatingMode.ACTIVE, runner=runner)
    pipe.epp = NetEPP()
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, destination_ip="203.0.113.50", destination_port=443,
                         protocol="tcp", process_name="x", source="test")  # fmt: skip
    out = pipe.process(ev)
    assert out.actions[0].action == ResponseAction.BLOCK_CONNECTION
    assert runner.calls[-1][-1] == "drop" and "203.0.113.50" in runner.calls[-1]
    graph.close()


def test_graph_chain_feeds_pipeline_and_incident_attached(tmp_path):
    pipe, _, graph = build(tmp_path, mode=OperatingMode.PASSIVE)
    t = T0
    evs = [
        NormalizedEvent(event_type=EventType.PROCESS_START, pid=900, ppid=800, process_name="winword.exe",
                        parent_process="explorer.exe", timestamp=t, source="t"),
        NormalizedEvent(event_type=EventType.PROCESS_START, pid=901, ppid=900, process_name="powershell.exe",
                        parent_process="winword.exe", command_line="powershell -enc AAA", timestamp=t + timedelta(seconds=1), source="t"),
        NormalizedEvent(event_type=EventType.PROCESS_START, pid=902, ppid=901, process_name="dropper",
                        parent_process="powershell.exe", timestamp=t + timedelta(seconds=2), source="t"),
    ]  # fmt: skip
    outs = [pipe.process(e) for e in evs]
    last = outs[-1]
    assert last.incident is not None and last.incident.attack_stage in (
        AttackStage.EXECUTION,
        AttackStage.INITIAL_ACCESS,
        AttackStage.DEFENSE_EVASION,
    )
    assert {"T1566.001", "T1059.001"} <= set(last.incident.mitre_techniques)
    assert any("powershell.exe" in line for line in graph.chain_for(evs[-1].event_id))
    pipe.close()
    assert graph.persisted_counts()["Incident"] == 1
    graph.close()


def test_novelty_gate_learning_then_assess(tmp_path):
    pipe, _, graph = build(tmp_path, mode=OperatingMode.LEARNING)
    nov = pipe.novelty
    for i in range(5):
        pipe.process(NormalizedEvent(event_type=EventType.PROCESS_START, pid=3000 + i, process_name="git", parent_process="bash",
                                     timestamp=T0 + timedelta(seconds=i), source="t"))  # fmt: skip
    r = nov.assess(NormalizedEvent(event_type=EventType.PROCESS_START, process_name="git", parent_process="bash", source="t"),
                   BehaviorResult())  # fmt: skip
    assert not r.is_novel
    assert psutil.pid_exists(os.getpid())
    graph.close()
