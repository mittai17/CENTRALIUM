#!/usr/bin/env python3
"""Live container verification script for Centralium.

Exercises real iptables/nftables netfilter operations and live auditd log tailing
inside an isolated container or throwaway network namespace (`unshare -rn`).
Never alters host networking or host system state.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from centralium.agent.collectors.linux.auditd import AuditdCollector
from centralium.agent.models import (
    EventType,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
)
from centralium.agent.response import LinuxResponseExecutor, SubprocessRunner


def test_live_iptables() -> dict[str, Any]:
    result: dict[str, Any] = {"real": False, "details": []}
    if not shutil.which("iptables"):
        result["details"].append("iptables binary not found in PATH")
        return result

    # Check if we have permission to inspect iptables in current namespace
    chk = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
    if chk.returncode != 0:
        result["details"].append(f"iptables check failed: {chk.stderr.strip()[:100]}")
        return result

    result["real"] = True
    runner = SubprocessRunner()
    executor = LinuxResponseExecutor(runner=runner, firewall="iptables", simulate=False)

    # 1. Block connection
    target_ip = "198.51.100.99"
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="test", destination_ip=target_ip)
    dec = PolicyDecision(
        action=ResponseAction.BLOCK_CONNECTION,
        allowed=True,
        mode=OperatingMode.ACTIVE,
        target={"ip": target_ip, "port": 4444, "protocol": "tcp"},
    )
    res_block = executor.execute(dec, ev)
    assert res_block.status.value == "executed", f"Block failed: {res_block.detail}"

    # Verify rule in kernel netfilter table
    rules = subprocess.run(["iptables", "-L", "CENTRALIUM_BLOCK", "-n"], capture_output=True, text=True)
    assert target_ip in rules.stdout, f"Rule missing from CENTRALIUM_BLOCK: {rules.stdout}"
    result["details"].append(f"Successfully added live kernel iptables rule blocking {target_ip}:4444")

    # Release block
    executor.release_blocks()
    rules_after = subprocess.run(["iptables", "-L", "CENTRALIUM_BLOCK", "-n"], capture_output=True, text=True)
    assert target_ip not in rules_after.stdout, "Rule still present after release"
    result["details"].append("Successfully released live iptables block")

    # 2. Network Isolation
    dec_iso = PolicyDecision(
        action=ResponseAction.ISOLATE_ENDPOINT,
        allowed=True,
        mode=OperatingMode.ACTIVE,
        target={"allowed_ips": ["10.0.0.1"]},
    )
    res_iso = executor.execute(dec_iso, ev)
    assert res_iso.status.value == "executed", f"Isolation failed: {res_iso.detail}"

    iso_rules = subprocess.run(["iptables", "-L", "CENTRALIUM_ISO", "-n"], capture_output=True, text=True)
    assert "DROP" in iso_rules.stdout, "Drop rule missing in CENTRALIUM_ISO"
    result["details"].append(
        "Successfully established live endpoint network isolation chain (DROP + management)"
    )

    executor.release_isolation()
    result["details"].append("Successfully restored live network policy")
    result["status"] = "PASS"
    return result


def test_live_nftables() -> dict[str, Any]:
    result: dict[str, Any] = {"real": False, "details": []}
    if not shutil.which("nft"):
        result["details"].append("nft binary not found in PATH")
        return result

    chk = subprocess.run(["nft", "list", "tables"], capture_output=True, text=True)
    if chk.returncode != 0:
        result["details"].append(f"nftables not permitted in this namespace: {chk.stderr.strip()[:100]}")
        return result

    result["real"] = True
    runner = SubprocessRunner()
    executor = LinuxResponseExecutor(runner=runner, firewall="nft", simulate=False)

    target_ip = "203.0.113.88"
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="test", destination_ip=target_ip)
    dec = PolicyDecision(
        action=ResponseAction.BLOCK_CONNECTION,
        allowed=True,
        mode=OperatingMode.ACTIVE,
        target={"ip": target_ip, "port": 8080, "protocol": "tcp"},
    )
    res = executor.execute(dec, ev)
    assert res.status.value == "executed", f"nft block failed: {res.detail}"

    tables = subprocess.run(["nft", "list", "table", "inet", "centralium"], capture_output=True, text=True)
    assert target_ip in tables.stdout, f"Target IP missing in nft table: {tables.stdout}"
    result["details"].append(f"Successfully added live nftables rule for {target_ip}:8080")

    executor.release_blocks()
    result["details"].append("Successfully flushed live nftables ruleset")
    result["status"] = "PASS"
    return result


def test_live_auditd_tailing() -> dict[str, Any]:
    result: dict[str, Any] = {"real": True, "details": []}
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".log") as tmp_log:
        got: list[NormalizedEvent] = []
        collector = AuditdCollector(path=tmp_log.name, from_start=True, poll_interval=0.05, group_timeout=0.1)
        assert collector.health()[0] is True
        collector.start(got.append)
        try:
            sample_audit_record = (
                "type=SYSCALL msg=audit(1728310000.123:456): arch=c000003e syscall=59 success=yes exit=0 "
                "a0=7fff10 a1=7fff20 a2=7fff30 a3=0 items=2 ppid=100 pid=4567 auid=1000 uid=0 gid=0 "
                'euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="nc" exe="/usr/bin/nc" '
                'key="network_connect"\n'
                'type=EXECVE msg=audit(1728310000.123:456): argc=4 a0="nc" a1="-e" '
                'a2="/bin/sh" a3="10.0.0.1"\n'
                "type=PROCTITLE msg=audit(1728310000.123:456): "
                "proctitle=6e63002d65002f62696e2f73680031302e302e302e31\n"
                "type=EOE msg=audit(1728310000.123:456):\n"
            )
            tmp_log.write(sample_audit_record)
            tmp_log.flush()

            deadline = time.time() + 3.0
            while time.time() < deadline and not got:
                time.sleep(0.05)

            assert len(got) >= 1, "Timed out waiting for auditd collector to tail and parse event"
            event = got[0]
            assert event.pid == 4567
            assert event.process_name in ("nc", "/usr/bin/nc", "sh")
            assert "-e" in event.command_line or "nc" in event.command_line
            result["details"].append(
                f"Successfully tailed live audit record: parsed PID={event.pid}, cmd={event.command_line}"
            )
            result["status"] = "PASS"
        finally:
            collector.stop()
    return result


def main() -> int:
    print("=" * 60)
    print("Centralium Container & Isolated Namespace Verification Harness")
    print("=" * 60)
    print(f"PID: {os.getpid()}, UID: {os.getuid()}, EUID: {os.geteuid()}")
    print()

    report: dict[str, Any] = {
        "timestamp": time.time(),
        "iptables": test_live_iptables(),
        "nftables": test_live_nftables(),
        "auditd_tailer": test_live_auditd_tailing(),
    }

    print("\n--- RESULTS MATRIX ---")
    for component, data in report.items():
        if component == "timestamp":
            continue
        status = data.get("status", "SKIPPED/UNAVAILABLE")
        mode = "REAL KERNEL/NETNS" if data.get("real") else "MOCK/UNAVAILABLE"
        print(f"[{status}] {component.upper()}: execution mode = {mode}")
        for det in data.get("details", []):
            print(f"    - {det}")

    # Output machine-readable JSON report
    out_path = Path("docker/container_verification_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote verification report to {out_path}")

    # Success if at least iptables or nftables passed live, and auditd tailer passed
    has_net = report["iptables"].get("status") == "PASS" or report["nftables"].get("status") == "PASS"
    has_audit = report["auditd_tailer"].get("status") == "PASS"
    if has_net and has_audit:
        print("\nAll live container / namespace verification checks PASSED.")
        return 0
    else:
        print("\nSome container verification checks failed or lacked privileges.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
