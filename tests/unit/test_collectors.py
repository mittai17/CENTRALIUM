from __future__ import annotations

import importlib
import subprocess
import sys
import threading
import time

import pytest

from centralium.agent.collectors._base import BaseCollector, TokenBucket
from centralium.agent.collectors.linux import AuditdCollector, EbpfCollector, PsutilCollector
from centralium.agent.collectors.windows import EtwCollector, EventLogCollector
from centralium.agent.collectors.windows.eventlog import SYSMON_CHANNEL
from centralium.agent.interfaces import Collector
from centralium.agent.models import EventType, NormalizedEvent


def wait_for(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class Dummy(BaseCollector):
    name = "dummy"

    def _run(self) -> None:
        self._stop.wait()


def ev_raw(i: int = 0) -> dict:
    return {"event_type": "process_start", "pid": i, "process_name": "x"}


# --------------------------------------------------------------------------- base plumbing
def test_modules_import_cleanly_and_satisfy_protocol():
    for m in ("centralium.agent.collectors.linux", "centralium.agent.collectors.windows"):
        importlib.import_module(m)
    for c in (
        AuditdCollector("/nonexistent/audit.log"),
        PsutilCollector(),
        EbpfCollector(),
        EventLogCollector(),
        EtwCollector(),
    ):
        assert isinstance(c, Collector), c
        assert isinstance(c.health(), tuple)


def test_bounded_queue_drops_and_counts():
    c = Dummy(queue_size=5)
    for i in range(20):
        c.emit_raw(ev_raw(i))
    assert c.queue_depth() == 5 and c.stats["emitted"] == 5 and c.stats["dropped_queue_full"] == 15


def test_rate_limit_and_token_bucket():
    c = Dummy(max_events_per_sec=10, queue_size=1000)
    for i in range(200):
        c.emit_raw(ev_raw(i))
    assert c.stats["emitted"] <= 12 and c.stats["dropped_rate"] >= 188
    b = TokenBucket(0)
    assert all(b.allow() for _ in range(1000))


def test_normalize_errors_counted_not_raised():
    c = Dummy()
    assert c.emit_raw({"event_type": "nonsense"}) == 0
    assert c.stats["normalize_errors"] == 1


def test_dispatch_to_sink_and_sink_errors_isolated():
    got: list[NormalizedEvent] = []
    calls = {"n": 0}

    def sink(e: NormalizedEvent) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        got.append(e)

    c = Dummy()
    c.start(sink)
    assert c.is_running()
    for i in range(3):
        c.emit_raw(ev_raw(i))
    assert wait_for(lambda: len(got) == 2)
    assert c.stats["sink_errors"] == 1
    c.stop()
    assert not c.is_running()


# --------------------------------------------------------------------------- Linux
def test_ebpf_is_an_honest_stub():
    c = EbpfCollector()
    ok, reason = c.health()
    assert not ok and "not implemented" in reason
    c.start(lambda e: None)
    assert not c.is_running()


def test_auditd_health_without_access(tmp_path):
    assert AuditdCollector(str(tmp_path / "missing.log")).health()[0] is False
    p = tmp_path / "audit.log"
    p.write_text("")
    assert AuditdCollector(str(p)).health()[0] is True
    p.chmod(0)
    import os

    if os.geteuid() != 0:
        ok, reason = AuditdCollector(str(p)).health()
        assert not ok and "permission" in reason


AUDIT_SAMPLE = [
    'type=SYSCALL msg=audit(1700000000.100:10): arch=c000003e syscall=59 success=yes exit=0 a0=1 items=2 ppid=1 pid=22 auid=1000 uid=0 euid=0 comm="sh" exe="/usr/bin/dash" key="x"',
    'type=EXECVE msg=audit(1700000000.100:10): argc=3 a0="sh" a1="-c" a2="id"',
    "type=PROCTITLE msg=audit(1700000000.100:10): proctitle=7368002D630069640",
    'type=SYSCALL msg=audit(1700000001.200:11): arch=c000003e syscall=87 success=yes exit=0 items=1 ppid=1 pid=22 auid=1000 uid=0 comm="rm" exe="/usr/bin/rm"',
    'type=PATH msg=audit(1700000001.200:11): item=0 name="/tmp/gone" inode=5 nametype=DELETE',
    "type=EOE msg=audit(1700000001.200:11): ",
    "type=DAEMON_START msg=audit(1700000005.0:12): op=start",
]


def test_auditd_feed_lines_groups_by_serial():
    c = AuditdCollector("/nonexistent")
    n = c.feed_lines(AUDIT_SAMPLE)
    n += c.flush()
    assert n == 1 + 1  # execve group, unlink group (daemon_start produces nothing)
    evs = []
    while c.queue_depth():
        evs.append(c._queue.get_nowait())
    assert [e.event_type for e in evs] == [EventType.PROCESS_START, EventType.FILE_DELETE]
    assert evs[0].command_line == "sh -c id"


def test_auditd_tail_thread_with_rotation(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")
    got: list[NormalizedEvent] = []
    c = AuditdCollector(str(log), poll_interval=0.05, group_timeout=0.2)
    c.start(got.append)
    try:
        time.sleep(0.2)
        with open(log, "a") as fh:
            fh.write("\n".join(AUDIT_SAMPLE[:3]) + "\n")
        assert wait_for(lambda: len(got) >= 1)
        # rotate: new file with a new inode
        log.rename(tmp_path / "audit.log.1")
        log.write_text("\n".join(AUDIT_SAMPLE[3:6]) + "\n")
        assert wait_for(lambda: any(e.event_type == EventType.FILE_DELETE for e in got))
    finally:
        c.stop()
    assert c.health()[0] in (True, False)


def test_psutil_collector_detects_new_process_and_connection():
    pytest.importorskip("psutil")
    c = PsutilCollector(poll_interval=0.1, hash_executables=True)
    c.poll_once()  # baseline
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.2)
        c.poll_once()
        evs = []
        while c.queue_depth():
            evs.append(c._queue.get_nowait())
        mine = [e for e in evs if e.event_type == EventType.PROCESS_START and e.pid == child.pid]
        assert mine, [e.pid for e in evs]
        e = mine[0]
        assert (
            e.source == "psutil" and e.ppid is not None and e.command_line and "time.sleep" in e.command_line
        )
        assert e.hash_sha256 is None or len(e.hash_sha256) == 64
    finally:
        child.kill()
        child.wait()
    time.sleep(0.2)
    c.poll_once()
    exits = []
    while c.queue_depth():
        exits.append(c._queue.get_nowait())
    assert any(e.event_type == EventType.PROCESS_EXIT and e.pid == child.pid for e in exits)


def test_psutil_collector_sees_local_listener_and_outbound(tmp_path):
    pytest.importorskip("psutil")
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    c = PsutilCollector(poll_interval=0.1, skip_loopback=False, hash_executables=False)
    c.poll_once()
    cli = socket.create_connection(("127.0.0.1", port))
    srv2 = socket.socket()
    srv2.bind(("127.0.0.1", 0))
    srv2.listen(1)
    try:
        time.sleep(0.2)
        c.poll_once()
        evs = []
        while c.queue_depth():
            evs.append(c._queue.get_nowait())
        kinds = {(e.event_type, e.destination_port) for e in evs}
        assert (EventType.NETWORK_CONNECT, port) in kinds
        assert any(t == EventType.NETWORK_LISTEN and p == srv2.getsockname()[1] for t, p in kinds)
    finally:
        cli.close()
        srv.close()
        srv2.close()


# --------------------------------------------------------------------------- Windows (recorded samples, run on Linux)
def _sysmon(rec_id: int, image: str) -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
        "<TimeCreated SystemTime='2024-03-05T10:20:30.1234567Z'/>"
        f"<EventRecordID>{rec_id}</EventRecordID><Channel>{SYSMON_CHANNEL}</Channel><Computer>WS</Computer></System>"
        f"<EventData><Data Name='Image'>{image}</Data><Data Name='ProcessId'>{rec_id}</Data>"
        "<Data Name='CommandLine'>x</Data></EventData></Event>"
    )


def test_eventlog_collector_with_recorded_xml_and_record_id_tracking():
    store = [_sysmon(i, f"C:\\a{i}.exe") for i in range(1, 6)]
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        q = next(a for a in argv if a.startswith("/q:")) if any(a.startswith("/q:") for a in argv) else None
        if q is None:  # baseline: newest record
            return store[-1]
        last = int(q.split(">")[1].split(")")[0])
        return "\n".join(d for i, d in enumerate(store, 1) if i > last)

    c = EventLogCollector((SYSMON_CHANNEL,), runner=runner)
    assert c.health()[0]
    assert c.poll_once() == 0  # baseline skips existing records
    store.append(_sysmon(6, "C:\\new.exe"))
    store.append(_sysmon(7, "C:\\new2.exe"))
    assert c.poll_once() == 2
    assert c.poll_once() == 0
    evs = [c._queue.get_nowait() for _ in range(c.queue_depth())]
    assert [e.pid for e in evs] == [6, 7] and all(e.source == "sysmon" for e in evs)
    assert all(a == str(a) for call in calls for a in call)  # argv arrays only
    assert calls[-1][0] == "wevtutil" and calls[-1][1] == "qe"


def test_eventlog_rejects_bad_channel_and_reports_unavailable_on_linux():
    with pytest.raises(ValueError):
        EventLogCollector(("Security; calc.exe",))
    if not sys.platform.startswith("win"):
        ok, reason = EventLogCollector().health()
        assert not ok and "not available" in reason


def test_eventlog_runner_failure_sets_health_not_exception():
    def boom(argv: list[str]) -> str:
        raise OSError("access denied")

    c = EventLogCollector(("Security",), runner=boom)
    assert c.poll_once() == 0
    ok, reason = c.health()
    assert not ok and "access denied" in reason


def test_etw_stub_reports_state_and_falls_back_to_psutil():
    pytest.importorskip("psutil")
    c = EtwCollector()
    ok, reason = c.health()
    assert not ok and "not implemented" in reason and "psutil" in reason
    got: list[NormalizedEvent] = []
    c.start(got.append)
    try:
        assert c._fallback is not None and c._fallback.is_running()
        n = c.ingest(
            {
                "provider": "Microsoft-Windows-Kernel-Process",
                "event_id": 1,
                "ProcessID": 3,
                "ImageName": "C:\\a.exe",
            }
        )
        assert n == 1
        assert wait_for(lambda: any(e.source == "etw" for e in got))
    finally:
        c.stop()
    assert c._fallback is None


def test_threads_cleaned_up():
    before = threading.active_count()
    c = Dummy()
    c.start(lambda e: None)
    c.stop()
    assert threading.active_count() <= before + 1
