"""Unit tests for process injection and memory detection."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from centralium.agent.behavior.process_injection import (
    ProcessInjectionConfig,
    ProcessInjectionDetector,
)
from centralium.agent.models import EventType, NormalizedEvent


def _make_event(
    event_type: EventType = EventType.PROCESS_START,
    command_line: str = "",
    process_name: str = "",
    executable_path: str = "",
    file_path: str = "",
    pid: int = 1000,
    raw_metadata: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-inj-ev",
        timestamp=datetime.now(UTC),
        event_type=event_type,
        process_name=process_name or "target_app",
        pid=pid,
        command_line=command_line,
        executable_path=executable_path,
        file_path=file_path,
        raw_metadata=raw_metadata or {},
    )


def test_wx_memory_mapping_detection():
    detector = ProcessInjectionDetector()

    # W+X allocation via mprotect
    ev_wx = _make_event(
        event_type=EventType.PROCESS_INJECT,
        process_name="injector",
        raw_metadata={"syscall": "mprotect", "prot": 7, "permissions": "rwx"},
    )
    findings = detector.evaluate(ev_wx)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_WX_MAPPING"
    assert "T1055" in findings[0].mitre_techniques

    # Windows PAGE_EXECUTE_READWRITE VirtualAlloc
    ev_win_wx = _make_event(
        event_type=EventType.OTHER,
        process_name="win_loader.exe",
        raw_metadata={"syscall": "VirtualAlloc", "protection": "PAGE_EXECUTE_READWRITE"},
    )
    findings_win = detector.evaluate(ev_win_wx)
    assert len(findings_win) == 1
    assert findings_win[0].rule_id == "BEH_INJ_WX_MAPPING"

    # Benign RX allocation
    ev_rx = _make_event(
        event_type=EventType.MODULE_LOAD,
        raw_metadata={"syscall": "mprotect", "permissions": "r-x"},
    )
    assert len(detector.evaluate(ev_rx)) == 0


def test_memfd_fileless_execution():
    detector = ProcessInjectionDetector()

    # Execution of memfd binary
    ev_memfd = _make_event(
        event_type=EventType.PROCESS_START,
        command_line="/memfd:malware (deleted)",
        executable_path="/memfd:malware",
        process_name="malware",
    )
    findings = detector.evaluate(ev_memfd)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_MEMFD_EXEC"
    assert "T1027.010" in findings[0].mitre_techniques

    # Syscall metadata memfd_create
    ev_memfd_sys = _make_event(
        event_type=EventType.PROCESS_START,
        raw_metadata={"syscall": "memfd_create"},
    )
    assert any(f.rule_id == "BEH_INJ_MEMFD_EXEC" for f in detector.evaluate(ev_memfd_sys))


def test_ptrace_injection_and_debugger_whitelist():
    detector = ProcessInjectionDetector()

    # Suspicious ptrace attack
    ev_ptrace = _make_event(
        process_name="injector",
        pid=1234,
        raw_metadata={
            "syscall": "ptrace",
            "ptrace_request": "PTRACE_POKETEXT",
            "target_pid": 5678,
        },
    )
    findings = detector.evaluate(ev_ptrace)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_PTRACE"
    assert "T1055.008" in findings[0].mitre_techniques

    # Legitimate debugger (gdb)
    ev_gdb = _make_event(
        process_name="gdb",
        pid=1234,
        raw_metadata={
            "syscall": "ptrace",
            "ptrace_request": "PTRACE_ATTACH",
            "target_pid": 5678,
        },
    )
    assert len(detector.evaluate(ev_gdb)) == 0


def test_reflective_loading_detection():
    detector = ProcessInjectionDetector()

    # Unbacked memory module load
    ev_unbacked = _make_event(
        event_type=EventType.MODULE_LOAD,
        process_name="svchost.exe",
        raw_metadata={"unbacked": True, "is_in_memory": True},
    )
    findings = detector.evaluate(ev_unbacked)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_REFLECTIVE_LOAD"
    assert "T1620" in findings[0].mitre_techniques

    # Command line containing reflective loader tool
    ev_cmd = _make_event(
        command_line="donut.exe -i payload.dll -o loader.bin",
        process_name="donut.exe",
    )
    assert any(f.rule_id == "BEH_INJ_REFLECTIVE_LOAD" for f in detector.evaluate(ev_cmd))


def test_remote_thread_injection():
    detector = ProcessInjectionDetector()

    # Sysmon Event ID 8 CreateRemoteThread
    ev_sysmon8 = _make_event(
        event_type=EventType.PROCESS_INJECT,
        process_name="malicious.exe",
        pid=2000,
        raw_metadata={"event_id": 8, "target_pid": 4000, "start_address": "0x7fff0000"},
    )
    findings = detector.evaluate(ev_sysmon8)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_REMOTE_THREAD"
    assert findings[0].details["target_pid"] == 4000


def test_process_hollowing_detection():
    detector = ProcessInjectionDetector()

    # Process hollowing sequence
    ev_hollow = _make_event(
        event_type=EventType.PROCESS_START,
        process_name="hollower.exe",
        raw_metadata={"action": "NtUnmapViewOfSection", "target_pid": 3333},
    )
    findings = detector.evaluate(ev_hollow)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_PROCESS_HOLLOWING"
    assert "T1055.012" in findings[0].mitre_techniques


def test_proc_maps_inspection(tmp_path: Path):
    detector = ProcessInjectionDetector()

    # Mock procfs directory structure
    pid = 9999
    proc_dir = tmp_path / "proc" / str(pid)
    proc_dir.mkdir(parents=True)
    maps_file = proc_dir / "maps"

    maps_content = (
        "00400000-00401000 r-xp 00000000 08:01 12345 /usr/bin/cat\n"
        "00600000-00601000 r--p 00001000 08:01 12345 /usr/bin/cat\n"
        "00800000-00810000 rwxp 00000000 00:00 0     [heap]\n"
    )
    maps_file.write_text(maps_content)

    findings = detector.inspect_proc_maps(pid, proc_root=tmp_path / "proc")
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_INJ_WX_MAPPING"
    assert findings[0].details["pid"] == pid


def test_process_injection_config_toggles():
    cfg = ProcessInjectionConfig(enable_wx_detection=False, enable_memfd_detection=False)
    detector = ProcessInjectionDetector(config=cfg)

    ev_wx = _make_event(
        event_type=EventType.PROCESS_INJECT,
        raw_metadata={"syscall": "mprotect", "prot": 7},
    )
    assert len(detector.evaluate(ev_wx)) == 0
