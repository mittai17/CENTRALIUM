"""Unit tests for Linux eBPF collector and privileged helper process."""

from __future__ import annotations

import os
import time

from centralium.agent.collectors.ebpf import (
    EbpfCollector,
    EbpfHelperServer,
    MockEbpfLoader,
    normalize_ebpf_event,
)
from centralium.agent.models import EventType, NormalizedEvent


def wait_for(cond, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_normalize_ebpf_all_event_types():
    # 1. exec
    ev_exec = normalize_ebpf_event(
        {
            "event_type": "exec",
            "pid": 1234,
            "ppid": 1000,
            "comm": "python3",
            "exe": "/usr/bin/python3",
            "args": "python3 script.py",
            "uid": 1000,
        }
    )
    assert ev_exec is not None
    assert ev_exec.event_type == EventType.PROCESS_START
    assert ev_exec.pid == 1234
    assert ev_exec.ppid == 1000
    assert ev_exec.process_name == "python3"
    assert ev_exec.executable_path == "/usr/bin/python3"
    assert ev_exec.command_line == "python3 script.py"
    assert ev_exec.source == "ebpf"

    # 2. connect
    ev_conn = normalize_ebpf_event(
        {
            "event_type": "connect",
            "pid": 1234,
            "comm": "curl",
            "destination_ip": "93.184.216.34",
            "destination_port": 443,
            "protocol": "tcp",
        }
    )
    assert ev_conn is not None
    assert ev_conn.event_type == EventType.NETWORK_CONNECT
    assert ev_conn.destination_ip == "93.184.216.34"
    assert ev_conn.destination_port == 443
    assert ev_conn.protocol == "tcp"

    # 3. accept
    ev_acc = normalize_ebpf_event(
        {
            "event_type": "accept",
            "pid": 500,
            "comm": "nginx",
            "destination_ip": "127.0.0.1",
            "destination_port": 80,
        }
    )
    assert ev_acc is not None
    assert ev_acc.event_type == EventType.NETWORK_LISTEN
    assert ev_acc.destination_port == 80

    # 4. openat (write intent)
    ev_open_write = normalize_ebpf_event(
        {
            "event_type": "openat",
            "pid": 200,
            "filename": "/tmp/test.txt",
            "flags": 0o2,  # O_RDWR
        }
    )
    assert ev_open_write is not None
    assert ev_open_write.event_type == EventType.FILE_MODIFY
    assert ev_open_write.file_path == "/tmp/test.txt"

    ev_open_creat = normalize_ebpf_event(
        {
            "event_type": "openat",
            "pid": 200,
            "filename": "/tmp/new.txt",
            "flags": 0o100 | 0o2,  # O_CREAT
        }
    )
    assert ev_open_creat is not None
    assert ev_open_creat.event_type == EventType.FILE_CREATE

    # 5. rename
    ev_ren = normalize_ebpf_event(
        {
            "event_type": "rename",
            "pid": 200,
            "old_path": "/tmp/doc.txt",
            "new_path": "/tmp/doc.txt.locked",
        }
    )
    assert ev_ren is not None
    assert ev_ren.event_type == EventType.FILE_RENAME
    assert ev_ren.file_path == "/tmp/doc.txt.locked"
    assert ev_ren.raw_metadata["old_path"] == "/tmp/doc.txt"

    # 6. unlink
    ev_unl = normalize_ebpf_event(
        {
            "event_type": "unlink",
            "pid": 200,
            "filename": "/tmp/victim.doc",
        }
    )
    assert ev_unl is not None
    assert ev_unl.event_type == EventType.FILE_DELETE
    assert ev_unl.file_path == "/tmp/victim.doc"

    # 7. ptrace & memfd
    ev_ptrace = normalize_ebpf_event(
        {
            "event_type": "ptrace",
            "pid": 666,
            "target_pid": 1234,
            "request": "PTRACE_POKETEXT",
        }
    )
    assert ev_ptrace is not None
    assert ev_ptrace.event_type == EventType.PROCESS_INJECT
    assert ev_ptrace.raw_metadata["technique"] == "ptrace"
    assert ev_ptrace.raw_metadata["target_pid"] == 1234

    ev_memfd = normalize_ebpf_event(
        {
            "event_type": "memfd",
            "pid": 777,
            "name": "elf_in_mem",
        }
    )
    assert ev_memfd is not None
    assert ev_memfd.event_type == EventType.PROCESS_INJECT
    assert ev_memfd.raw_metadata["technique"] == "memfd_create"


def test_ebpf_helper_socket_streaming(tmp_path):
    sock_path = str(tmp_path / "test_ebpf.sock")
    mock_loader = MockEbpfLoader()
    server = EbpfHelperServer(socket_path=sock_path, loader=mock_loader)
    server.start()

    received: list[NormalizedEvent] = []
    collector = EbpfCollector(socket_path=sock_path, fallback=False)
    collector.start(lambda ev: received.append(ev))

    try:
        assert collector.is_running()
        ok, reason = collector.health()
        assert ok
        assert "connected" in reason

        # Push events through mock loader
        mock_loader.push_event(
            {
                "event_type": "exec",
                "pid": 4321,
                "comm": "malware",
                "exe": "/tmp/malware",
            }
        )
        mock_loader.push_event(
            {
                "event_type": "connect",
                "pid": 4321,
                "destination_ip": "1.2.3.4",
                "destination_port": 8888,
            }
        )
        mock_loader.push_event(
            {
                "event_type": "memfd",
                "pid": 4321,
                "name": "payload",
            }
        )

        assert wait_for(lambda: len(received) >= 3)
        assert received[0].event_type == EventType.PROCESS_START
        assert received[1].event_type == EventType.NETWORK_CONNECT
        assert received[2].event_type == EventType.PROCESS_INJECT
    finally:
        collector.stop()
        server.stop()


def test_ebpf_fallback_when_socket_missing():
    # Socket path does not exist, fallback to psutil
    nonexistent = f"/tmp/nonexistent_ebpf_{os.getpid()}_{time.time_ns()}.sock"
    collector = EbpfCollector(socket_path=nonexistent, fallback="psutil")
    received: list[NormalizedEvent] = []
    collector.start(lambda ev: received.append(ev))

    try:
        assert collector.is_running()
        ok, reason = collector.health()
        assert ok
        assert "psutil" in reason or "falling back" in reason
    finally:
        collector.stop()
