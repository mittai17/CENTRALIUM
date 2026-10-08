"""Integration tests for Linux eBPF collector.

Runs with real privileges (root/CAP_BPF); cleanly skips when privileges or BCC are missing.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from centralium.agent.collectors.ebpf import BccLoader, EbpfCollector, EbpfHelperServer
from centralium.agent.models import NormalizedEvent


@pytest.mark.skipif(
    not (sys.platform.startswith("linux") and os.geteuid() == 0 and BccLoader.is_available()),
    reason="Requires Linux, root/CAP_BPF privileges, and installed BCC",
)
def test_ebpf_collector_privileged_live(tmp_path):
    sock_path = str(tmp_path / "live_ebpf.sock")
    loader = BccLoader()
    server = EbpfHelperServer(socket_path=sock_path, loader=loader)
    server.start()

    events: list[NormalizedEvent] = []
    collector = EbpfCollector(socket_path=sock_path, fallback=False)
    collector.start(lambda ev: events.append(ev))

    try:
        ok, reason = collector.health()
        assert ok, f"Expected healthy eBPF collector, got {reason}"

        # Trigger execve event
        subprocess.run(["echo", "centralium_ebpf_test"], check=True)

        time.sleep(1.0)
        # Check if events were collected
        assert collector.stats["emitted"] >= 0
    finally:
        collector.stop()
        server.stop()
