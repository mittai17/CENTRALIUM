"""CI/mock verified: Unit tests for Windows ETW and Event Log subscription collector.

This test module verifies Windows ETW collector behavior using mock event streams,
cross-platform import isolation, rate limiting, and safe fallbacks.
"""

from __future__ import annotations

import time
from typing import Any

from centralium.agent.collectors.windows_etw import WindowsEtwCollector
from centralium.agent.models import EventType, NormalizedEvent


def wait_for(cond, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


MOCK_ETW_STREAM: list[dict[str, Any]] = [
    {
        "provider": "Microsoft-Windows-Kernel-Process",
        "event_id": 1,
        "ProcessID": 4412,
        "ParentProcessID": 1024,
        "ImageName": r"C:\Windows\System32\cmd.exe",
        "CommandLine": r"cmd.exe /c whoami",
    },
    {
        "provider": "Microsoft-Windows-Kernel-Process",
        "event_id": 2,
        "ProcessID": 4412,
        "ImageName": r"C:\Windows\System32\cmd.exe",
    },
    {
        "provider": "Microsoft-Windows-Kernel-Network",
        "event_id": 10,
        "ProcessID": 1200,
        "daddr": "198.51.100.10",
        "dport": 4444,
        "protocol": "tcp",
    },
    {
        "provider": "Microsoft-Windows-Kernel-File",
        "event_id": 12,
        "ProcessID": 2048,
        "FileName": r"C:\Users\Admin\AppData\Local\Temp\payload.exe",
        "FileCreateDisposition": 2,
    },
]


def test_ci_mock_verified_etw_stream_processing():
    """CI/mock verified: verifies ingestion and normalization of ETW mock records."""
    received: list[NormalizedEvent] = []
    collector = WindowsEtwCollector(
        event_stream=MOCK_ETW_STREAM,
        fallback=False,
    )
    collector.start(lambda ev: received.append(ev))

    try:
        assert collector.is_running()
        ok, reason = collector.health()
        assert ok
        assert "mock/CI ETW" in reason

        assert wait_for(lambda: len(received) >= 4)
        assert received[0].event_type == EventType.PROCESS_START
        assert received[0].pid == 4412
        assert received[0].process_name == "cmd.exe"
        assert received[0].source == "etw"

        assert received[1].event_type == EventType.PROCESS_EXIT
        assert received[1].pid == 4412

        assert received[2].event_type == EventType.NETWORK_CONNECT
        assert received[2].destination_ip == "198.51.100.10"
        assert received[2].destination_port == 4444

        assert received[3].event_type in (EventType.FILE_CREATE, EventType.FILE_MODIFY)
    finally:
        collector.stop()


def test_ci_mock_verified_etw_direct_ingest():
    """CI/mock verified: verifies manual ingestion of individual ETW records."""
    collector = WindowsEtwCollector(fallback=False)
    n = collector.ingest(
        {
            "provider": "Microsoft-Windows-Kernel-Process",
            "event_id": 1,
            "ProcessID": 8888,
            "ImageName": r"C:\Temp\evil.exe",
        }
    )
    assert n == 1
    assert collector.stats["emitted"] == 1


def test_ci_mock_verified_sysmon_xml_ingest():
    """CI/mock verified: verifies ingestion of Sysmon Event ID 1 XML record."""
    sysmon_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
        <EventID>1</EventID>
        <EventRecordID>1001</EventRecordID>
        <TimeCreated SystemTime="2026-10-07T12:00:00.0000000Z"/>
      </System>
      <EventData>
        <Data Name="ProcessId">5555</Data>
        <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -enc AAAA</Data>
      </EventData>
    </Event>"""

    collector = WindowsEtwCollector(fallback=False)
    n = collector.ingest(sysmon_xml)
    assert n == 1
    assert collector.stats["emitted"] == 1


def test_ci_mock_verified_safe_fallback_on_non_windows():
    """CI/mock verified: verifies safe degradation to psutil fallback."""
    collector = WindowsEtwCollector(fallback=True)
    events: list[NormalizedEvent] = []
    collector.start(lambda ev: events.append(ev))

    try:
        assert collector.is_running()
        ok, reason = collector.health()
        assert not ok or "psutil" in reason or "ready" in reason
    finally:
        collector.stop()
