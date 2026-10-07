"""Integration: normalizer + behavior engine inside the real Pipeline, plus live psutil collection."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from centralium.agent.behavior import DefaultBehaviorEngine
from centralium.agent.behavior.features import FEATURE_NAMES
from centralium.agent.collectors.linux import PsutilCollector
from centralium.agent.config import CentraliumConfig
from centralium.agent.models import FindingSource, NormalizedEvent
from centralium.agent.normalization import EventNormalizer
from centralium.agent.pipeline import Pipeline

pytestmark = pytest.mark.integration
T0 = datetime(2024, 6, 1, tzinfo=UTC)


def make_pipeline() -> Pipeline:
    return Pipeline(
        CentraliumConfig(test_mode=True), normalizer=EventNormalizer(), behavior=DefaultBehaviorEngine()
    )


def raw(t: float, **kw) -> dict:
    return {"timestamp": (T0 + timedelta(seconds=t)).isoformat(), **kw}


def test_benign_activity_produces_no_behavior_findings_and_little_ml():
    p = make_pipeline()
    outs = []
    for i in range(30):
        outs.append(
            p.process_raw(
                raw(
                    i,
                    event_type="process_start",
                    pid=100 + i,
                    ppid=1,
                    process_name="bash",
                    exe="/usr/bin/bash",
                    cmdline="bash -c ls",
                    parent="gnome-terminal-",
                    signer="distro",
                )
            )
        )
        outs.append(
            p.process_raw(
                raw(i + 0.5, event_type="file_modify", pid=100 + i, file_path=f"/home/u/doc{i}.txt")
            )
        )
    assert all(o is not None for o in outs)
    assert not [
        f
        for o in outs
        for f in o.findings
        if f.source in {FindingSource.LOLBIN, FindingSource.RANSOMWARE, FindingSource.PERSISTENCE}
    ]
    snap = p.stats.snapshot()
    assert snap["funnel"]["ml"] < snap["funnel"]["raw"] / 2


def test_office_to_powershell_chain_flows_through_pipeline():
    p = make_pipeline()
    out = p.process_raw(
        raw(
            0,
            format="sysmon",
            json='{"Event":{"System":{"EventID":1,"Provider":{"Name":"Microsoft-Windows-Sysmon"}},'
            '"EventData":{"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","ProcessId":"4242",'
            '"ParentImage":"C:\\\\Program Files\\\\Microsoft Office\\\\WINWORD.EXE","ParentProcessId":"100",'
            '"CommandLine":"powershell -nop -w hidden -enc ' + "A" * 40 + '"}}}',
        )
    )
    assert out is not None
    assert [f for f in out.findings if f.source == FindingSource.LOLBIN]
    assert "behavior" in out.stages_reached and "ml" in out.stages_reached  # ML-eligible
    assert not out.stage_errors


def test_ransomware_like_synthetic_activity_end_to_end():
    p = make_pipeline()
    p.process_raw(raw(0, event_type="process_start", pid=800, ppid=1, process_name="WINWORD.EXE"))
    p.process_raw(
        raw(
            1,
            event_type="process_start",
            pid=900,
            ppid=800,
            process_name="locker.exe",
            exe="C:\\Users\\a\\AppData\\Local\\Temp\\locker.exe",
            cmdline="locker.exe",
        )
    )
    p.process_raw(
        raw(
            2,
            event_type="process_start",
            pid=901,
            ppid=900,
            process_name="vssadmin.exe",
            cmdline="vssadmin delete shadows /all /quiet",
        )
    )
    rw = []
    for i in range(120):
        o = p.process_raw(
            raw(
                3 + i * 0.05,
                event_type="file_modify",
                pid=900,
                ppid=800,
                process_name="locker.exe",
                path=f"C:\\Users\\a\\Documents\\f{i}.docx",
                raw_metadata={"entropy_after": 7.9, "entropy_before": 4.0},
            )
        )
        if i % 2 == 0:
            o2 = p.process_raw(
                raw(
                    3 + i * 0.05,
                    event_type="file_rename",
                    pid=900,
                    ppid=800,
                    process_name="locker.exe",
                    path=f"C:\\Users\\a\\Documents\\f{i}.docx.locked",
                    raw_metadata={"old_path": f"C:\\Users\\a\\Documents\\f{i}.docx"},
                )
            )
            rw += o2.findings
        rw += o.findings
    comp = [f for f in rw if f.rule_id == "RW-COMPOSITE"]
    assert comp and max(f.score for f in comp) >= 60
    assert not p.stats.snapshot()["errors"]


def test_single_file_write_does_not_flag_ransomware():
    p = make_pipeline()
    out = p.process_raw(raw(0, event_type="file_modify", pid=5, process_name="vim", path="/home/u/a.txt"))
    assert out is not None and not [f for f in out.findings if f.source == FindingSource.RANSOMWARE]


def test_persistence_creation_detected_via_auditd_lines():
    p = make_pipeline()
    lines = [
        'type=SYSCALL msg=audit(1700000100.1:900): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=0 a2=241 items=2 ppid=1 pid=66 auid=1000 uid=0 comm="bash" exe="/usr/bin/bash"',
        'type=CWD msg=audit(1700000100.1:900): cwd="/root"',
        'type=PATH msg=audit(1700000100.1:900): item=1 name="/etc/cron.d/updater" inode=1 nametype=CREATE',
    ]
    out = p.process_raw({"format": "auditd", "lines": lines})
    assert out is not None
    assert any("T1053.003" in f.mitre_techniques for f in out.findings)


def test_features_exported_for_ml_match_schema():
    eng = DefaultBehaviorEngine()
    ev = EventNormalizer().normalize({"event_type": "process_start", "pid": 1, "process_name": "x"})
    assert list(eng.analyze(ev, []).features) == FEATURE_NAMES


def test_live_psutil_collector_emits_valid_events():
    pytest.importorskip("psutil")
    import subprocess
    import sys

    events: list[NormalizedEvent] = []
    c = PsutilCollector(poll_interval=0.2, emit_existing=True, hash_executables=True, max_events_per_poll=300)
    c.start(events.append)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not any(e.pid == child.pid for e in events):
            time.sleep(0.1)
    finally:
        child.kill()
        child.wait()
        c.stop()
    assert events, "no events collected"
    assert any(e.pid == child.pid for e in events)
    for e in events:
        NormalizedEvent.model_validate(e.model_dump())  # round-trips through the contract
        assert e.source == "psutil"
    p = make_pipeline()
    assert all(p.process(e) is not None for e in events[:50])
    ok, _ = c.health()
    assert ok or c.stats["emitted"] > 0
