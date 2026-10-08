"""Windows-specific unit tests covering Sysmon XML parsing, wevtutil argv,

netsh argv, Windows service wrapper imports, and ETW fallback.

These tests are marked with `windows` and can run on both Linux (via mocks/fixtures)
and Windows hosts (where real OS modules/APIs can be exercised).
"""

from __future__ import annotations

import sys
import threading
from typing import Any

import pytest

from centralium.agent.collectors.windows import EtwCollector, EventLogCollector
from centralium.agent.collectors.windows.eventlog import SYSMON_CHANNEL
from centralium.agent.models import EventType, NormalizedEvent, PolicyDecision, ResponseAction
from centralium.agent.normalization import EventNormalizer
from centralium.agent.response import WindowsResponseExecutor
from centralium.agent.response.base import ExecutionRefusedError
from centralium.agent.self_protection import windows_service

pytestmark = pytest.mark.windows


class DummyRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: float = 15.0) -> Any:
        from centralium.agent.response.base import CommandResult

        self.calls.append(list(argv))
        return CommandResult(0)

    def __call__(self, argv: list[str]) -> str:
        self.calls.append(list(argv))
        return ""


# --------------------------------------------------------------------------- Windows service wrapper
def test_windows_service_wrapper_import_and_defaults():
    assert windows_service.SERVICE_NAME == "CentraliumAgent"
    assert "Centralium" in windows_service.SERVICE_DISPLAY
    evt = threading.Event()
    evt.set()
    windows_service.default_agent_main(evt)  # must not block

    called = []
    windows_service.set_agent_main(lambda stop: called.append(True))
    windows_service._agent_main(evt)
    assert called == [True]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Only executed on real Windows host")
def test_windows_service_framework_available_on_windows():
    assert windows_service.HAVE_PYWIN32 is True
    assert hasattr(windows_service, "CentraliumService")


# --------------------------------------------------------------------------- Sysmon XML & wevtutil
def test_sysmon_xml_parsing_into_normalized_events():
    xml_data = (
        "<Events>"
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
        "<EventID>1</EventID>"
        "<TimeCreated SystemTime='2026-10-07T12:00:00.0000000Z'/>"
        "<EventRecordID>1001</EventRecordID>"
        "<Computer>WIN-ENDPOINT-01</Computer>"
        "</System>"
        "<EventData>"
        "<Data Name='UtcTime'>2026-10-07 12:00:00.000</Data>"
        "<Data Name='ProcessGuid'>{11111111-2222-3333-4444-555555555555}</Data>"
        "<Data Name='ProcessId'>4128</Data>"
        "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
        "<Data Name='CommandLine'>cmd.exe /c whoami</Data>"
        "<Data Name='ParentProcessId'>1024</Data>"
        "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
        "<Data Name='ParentCommandLine'>explorer.exe</Data>"
        "<Data Name='User'>CORP\\alice</Data>"
        "</EventData>"
        "</Event>"
        "</Events>"
    )
    normalizer = EventNormalizer()
    ev = normalizer.normalize({"xml": xml_data})
    assert ev is not None
    assert ev.event_type is EventType.PROCESS_START
    assert ev.pid == 4128
    assert ev.ppid == 1024
    assert ev.process_name == "cmd.exe"
    assert ev.command_line == "cmd.exe /c whoami"
    assert ev.host_id == "WIN-ENDPOINT-01"
    assert ev.user == "CORP\\alice"


def test_wevtutil_command_construction_and_runner():
    r = DummyRunner()
    collector = EventLogCollector((SYSMON_CHANNEL,), runner=r)
    collector.poll_once()
    assert len(r.calls) == 1
    cmd = r.calls[0]
    assert cmd[0] == "wevtutil"
    assert cmd[1] == "qe"
    assert SYSMON_CHANNEL in cmd
    assert "/f:xml" in cmd


# --------------------------------------------------------------------------- netsh argv generation
def test_windows_netsh_block_connection_command():
    r = DummyRunner()
    ex = WindowsResponseExecutor(runner=r)
    dec = PolicyDecision(
        action=ResponseAction.BLOCK_CONNECTION,
        allowed=True,
        target={"ip": "198.51.100.55", "port": 4444},
        reason="C2 block",
    )
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="t", destination_ip="198.51.100.55")
    res = ex.execute(dec, ev)
    assert res.status.value == "executed"
    assert len(r.calls) == 1
    cmd = r.calls[0]
    assert cmd[:3] == ["netsh", "advfirewall", "firewall"]
    assert "add" in cmd and "rule" in cmd
    assert "remoteip=198.51.100.55" in cmd
    assert "remoteport=4444" in cmd
    assert "action=block" in cmd


def test_windows_netsh_isolate_endpoint_command():
    r = DummyRunner()
    ex = WindowsResponseExecutor(runner=r)
    dec = PolicyDecision(
        action=ResponseAction.ISOLATE_ENDPOINT,
        allowed=True,
        target={"allowed_ips": ["192.0.2.10"]},
        reason="containment",
    )
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="t", destination_ip="198.51.100.55")
    res = ex.execute(dec, ev)
    assert res.status.value == "executed"
    assert any("firewallpolicy" in call for call in r.calls)


# --------------------------------------------------------------------------- sc.exe and taskkill.exe
def test_windows_service_control_disable():
    r = DummyRunner()
    ex = WindowsResponseExecutor(runner=r)
    ex.service_control("SuspiciousSvc", "disable")
    assert r.calls == [["sc", "config", "SuspiciousSvc", "start=", "disabled"]]

    with pytest.raises(ExecutionRefusedError):
        ex.service_control("WinDefend", "stop")


def test_windows_taskkill_pid_and_immunity():
    r = DummyRunner()
    ex = WindowsResponseExecutor(runner=r)
    ex.terminate_via_taskkill(4444)
    assert r.calls == [["taskkill", "/PID", "4444", "/F"]]

    with pytest.raises(ExecutionRefusedError):
        ex.terminate_via_taskkill(4)  # System PID 4 is immune


# --------------------------------------------------------------------------- ETW collector fallback
def test_windows_etw_stub_fallback():
    c = EtwCollector()
    ok, reason = c.health()
    assert not ok and "psutil" in reason
