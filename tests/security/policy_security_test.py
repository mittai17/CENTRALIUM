from __future__ import annotations

import pytest

from centralium.agent.config import PolicySettings, RiskSettings
from centralium.agent.interfaces import PolicyContext
from centralium.agent.models import (
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    OperatingMode,
    ResponseAction,
    RiskAssessment,
    Severity,
)
from centralium.agent.policy import ProtectionRules, RulesPolicyEngine

pytestmark = pytest.mark.security


def run(ev: NormalizedEvent, *, mode=OperatingMode.ACTIVE):
    f = Finding(event_id="e", source=FindingSource.IOC, rule_id="r", title="t", severity=Severity.CRITICAL, score=95,
                known_malicious=True)  # fmt: skip
    ctx = PolicyContext(event=ev, findings=[f], risk=RiskAssessment(final_score=95, band=RiskSettings().band_for(95)),
                        mode=mode, known_malicious=True)  # fmt: skip
    s = PolicySettings(require_approval=False)
    eng = RulesPolicyEngine(
        s, protection=ProtectionRules.from_lists(s.protected_processes, s.protected_paths, pid_resolver=None)
    )
    return eng.plan(ctx)


@pytest.mark.parametrize(
    "ip", ["1.2.3.4; reboot", "$(id)", "1.2.3.4 -j ACCEPT", "evil.example.com", "1.2.3.4\n"]
)
def test_garbage_destination_never_becomes_block_target(ip):
    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT, destination_ip=ip, destination_port=80, source="t"
    )
    plan = run(ev)
    assert all(p.action != ResponseAction.BLOCK_CONNECTION for p in plan)
    assert plan[0].action == ResponseAction.ALERT
    assert ip not in repr([p.target for p in plan])


def test_traversal_file_path_hits_protected_prefix_after_normalisation():
    ev = NormalizedEvent(
        event_type=EventType.FILE_CREATE,
        file_path="/home/u/../../etc/cron.d/x",
        source="t",
        pid=9,
        process_name="x",
    )
    plan = run(ev)
    assert all(p.action != ResponseAction.QUARANTINE_FILE for p in plan)


def test_windows_style_protected_path_case_insensitive():
    ev = NormalizedEvent(
        event_type=EventType.FILE_CREATE,
        file_path="c:\\WINDOWS\\system32\\evil.dll",
        source="t",
        pid=9,
        process_name="x",
    )
    assert all(p.action != ResponseAction.QUARANTINE_FILE for p in run(ev))


def test_process_name_spoof_case_and_path_forms_still_protected():
    for name in ("SYSTEMD", "C:\\Windows\\System32\\lsass.exe", "/usr/lib/systemd/systemd", "lsass"):
        ev = NormalizedEvent(event_type=EventType.PROCESS_START, pid=555, process_name=name, source="t")
        assert all(
            p.action not in (ResponseAction.TERMINATE_PROCESS, ResponseAction.SUSPEND_PROCESS)
            for p in run(ev)
        ), name


def test_decision_target_contains_only_validated_scalars():
    ev = NormalizedEvent(event_type=EventType.PROCESS_START, pid=555, process_name="evil", command_line="x; rm -rf /",
                         source="t", raw_metadata={"create_time": "rm -rf"})  # fmt: skip
    d = run(ev)[0]
    assert d.action == ResponseAction.TERMINATE_PROCESS
    assert "command_line" not in d.target and "create_time" not in d.target
    assert isinstance(d.target["pid"], int)
