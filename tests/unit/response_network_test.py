"""Network block / isolation: exact argv assertions with a mocked runner (nothing is executed)."""

from __future__ import annotations

import pytest

from centralium.agent.models import (
    ActionStatus,
    EventType,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
)
from centralium.agent.response import IsolationConfig, LinuxResponseExecutor, WindowsResponseExecutor
from centralium.agent.response.base import CommandResult

A = ResponseAction


class Runner:
    def __init__(self, fail_on: str | None = None):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on

    def run(self, argv, timeout=15.0):
        self.calls.append(list(argv))
        if self.fail_on and self.fail_on in argv:
            return CommandResult(1, "", "Operation not permitted")
        return CommandResult(0)


EV = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="t", destination_ip="203.0.113.9")


def dec(action, **t):
    return PolicyDecision(action=action, allowed=True, mode=OperatingMode.ACTIVE, target=t)


def linux(runner, backend="nft", **kw):
    return LinuxResponseExecutor(runner=runner, firewall=backend, **kw)


def test_nft_block_exact_argv():
    r = Runner()
    res = linux(r).execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=443, protocol="tcp"), EV)
    assert res.status == ActionStatus.EXECUTED, res.detail
    assert r.calls == [
        ["nft", "add", "table", "inet", "centralium"],
        ["nft", "add", "chain", "inet", "centralium", "output", "{", "type", "filter", "hook", "output",
         "priority", "0", ";", "policy", "accept", ";", "}"],
        ["nft", "add", "rule", "inet", "centralium", "output", "ip", "daddr", "203.0.113.9", "tcp", "dport", "443", "drop"],
    ]  # fmt: skip


def test_nft_block_ipv6_no_port():
    r = Runner()
    linux(r).execute(dec(A.BLOCK_CONNECTION, ip="2001:db8::1"), EV)
    assert r.calls[-1] == [
        "nft",
        "add",
        "rule",
        "inet",
        "centralium",
        "output",
        "ip6",
        "daddr",
        "2001:db8::1",
        "drop",
    ]


def test_iptables_block_exact_argv():
    r = Runner()
    linux(r, "iptables").execute(dec(A.BLOCK_CONNECTION, ip="198.51.100.7", port=8080, protocol="udp"), EV)
    assert r.calls == [
        ["iptables", "-N", "CENTRALIUM_BLOCK"],
        ["iptables", "-C", "OUTPUT", "-j", "CENTRALIUM_BLOCK"],  # jump already present -> not duplicated
        [
            "iptables",
            "-A",
            "CENTRALIUM_BLOCK",
            "-d",
            "198.51.100.7",
            "-p",
            "udp",
            "--dport",
            "8080",
            "-j",
            "DROP",
        ],
    ]
    r2 = Runner(fail_on="-C")  # jump missing -> inserted
    linux(r2, "iptables").execute(dec(A.BLOCK_CONNECTION, ip="198.51.100.7"), EV)
    assert ["iptables", "-I", "OUTPUT", "1", "-j", "CENTRALIUM_BLOCK"] in r2.calls


def test_auto_backend_prefers_nft_then_iptables_else_refuses():
    r = Runner()
    ex = LinuxResponseExecutor(runner=r, which=lambda n: "/usr/sbin/" + n if n == "iptables" else None)
    ex.execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9"), EV)
    assert r.calls[0][0] == "iptables"
    none = LinuxResponseExecutor(runner=Runner(), which=lambda n: None)
    res = none.execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9"), EV)
    assert res.status == ActionStatus.FAILED and "no firewall tool" in res.detail


def test_runner_failure_reported_as_failed_not_silent():
    r = Runner(fail_on="drop")
    res = linux(r).execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=80, protocol="tcp"), EV)
    assert res.status == ActionStatus.FAILED and "Operation not permitted" in res.detail


def test_simulation_plans_but_never_runs():
    r = Runner()
    res = linux(r, simulate=True).execute(
        dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=22, protocol="tcp"), EV
    )
    assert res.status == ActionStatus.SIMULATED and r.calls == []
    assert res.target["planned_commands"][-1][-1] == "drop"


def test_isolation_nft_keeps_loopback_established_and_management():
    r = Runner()
    ex = linux(r, isolation=IsolationConfig(management_networks=("10.9.0.0/24", "2001:db8:ff::5")))
    res = ex.execute(dec(A.ISOLATE_ENDPOINT), EV)
    assert res.status == ActionStatus.EXECUTED, res.detail
    flat = [" ".join(c) for c in r.calls]
    assert "nft add table inet centralium_iso" in flat
    assert (
        "nft add chain inet centralium_iso output { type filter hook output priority -10 ; policy drop ; }"
        in flat
    )
    assert (
        "nft add chain inet centralium_iso input { type filter hook input priority -10 ; policy drop ; }"
        in flat
    )
    assert "nft add rule inet centralium_iso output oifname lo accept" in flat
    assert "nft add rule inet centralium_iso input iifname lo accept" in flat
    assert "nft add rule inet centralium_iso output ct state established,related accept" in flat
    assert "nft add rule inet centralium_iso output ip daddr 10.9.0.0/24 accept" in flat
    assert "nft add rule inet centralium_iso input ip saddr 10.9.0.0/24 accept" in flat
    assert "nft add rule inet centralium_iso output ip6 daddr 2001:db8:ff::5/128 accept" in flat
    # all accepts come after chain creation with drop policy (never a window of open policy)
    assert flat.index("nft add rule inet centralium_iso output oifname lo accept") > flat.index(
        "nft add chain inet centralium_iso output { type filter hook output priority -10 ; policy drop ; }"
    )


def test_isolation_rolls_back_on_failure():
    r = Runner(fail_on="established,related")
    res = linux(r).execute(dec(A.ISOLATE_ENDPOINT), EV)
    assert res.status == ActionStatus.FAILED
    assert r.calls[-1] == ["nft", "delete", "table", "inet", "centralium_iso"]


def test_isolation_iptables_argv():
    r = Runner()
    ex = linux(r, "iptables", isolation=IsolationConfig(management_networks=("192.0.2.10",)))
    ex.execute(dec(A.ISOLATE_ENDPOINT), EV)
    assert ["iptables", "-A", "CENTRALIUM_ISO", "-o", "lo", "-j", "ACCEPT"] in r.calls
    assert ["iptables", "-A", "CENTRALIUM_ISO", "-d", "192.0.2.10/32", "-j", "ACCEPT"] in r.calls
    assert ["iptables", "-A", "CENTRALIUM_ISO", "-j", "DROP"] in r.calls
    assert ["iptables", "-I", "OUTPUT", "1", "-j", "CENTRALIUM_ISO"] in r.calls
    assert ["ip6tables", "-A", "CENTRALIUM_ISO", "-j", "DROP"] in r.calls


def test_release_isolation_and_blocks():
    r = Runner()
    ex = linux(r)
    ex.release_isolation()
    ex.release_blocks()
    assert r.calls == [
        ["nft", "delete", "table", "inet", "centralium_iso"],
        ["nft", "delete", "table", "inet", "centralium"],
    ]


def test_management_address_is_never_blocked():
    r = Runner()
    ex = linux(r, isolation=IsolationConfig(management_networks=("203.0.113.0/24",)))
    res = ex.execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9"), EV)
    assert res.status == ActionStatus.FAILED and "management" in res.detail and r.calls == []


# ------------------------------------------------------------------ windows (argv only, importable everywhere)
def win(r, **kw):
    return WindowsResponseExecutor(runner=r, **kw)


def test_windows_block_exact_argv():
    r = Runner()
    res = win(r).execute(dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=443, protocol="tcp"), EV)
    assert res.status == ActionStatus.EXECUTED, res.detail
    assert r.calls == [[
        "netsh", "advfirewall", "firewall", "add", "rule", "name=Centralium_Block_203.0.113.9_443", "dir=out",
        "action=block", "remoteip=203.0.113.9", "protocol=TCP", "remoteport=443",
    ]]  # fmt: skip
    win(r).release_blocks()


def test_windows_isolation_and_release():
    r = Runner()
    ex = win(r, isolation=IsolationConfig(management_networks=("10.1.1.1",)))
    ex.execute(dec(A.ISOLATE_ENDPOINT), EV)
    assert r.calls[0][:6] == ["netsh", "advfirewall", "firewall", "add", "rule", "name=Centralium_Mgmt_0_in"]
    assert r.calls[-1] == [
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,blockoutbound",
    ]
    r.calls.clear()
    ex.release_isolation()
    assert r.calls[0] == [
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,allowoutbound",
    ]


def test_windows_service_control_and_protection():
    r = Runner()
    ex = win(r)
    ex.service_control("EvilSvc", "disable")
    assert r.calls == [["sc", "config", "EvilSvc", "start=", "disabled"]]
    from centralium.agent.response.base import ExecutionRefusedError

    with pytest.raises(ExecutionRefusedError):
        ex.service_control("WinDefend", "stop")
    from centralium.agent.policy import ValidationError

    with pytest.raises(ValidationError):
        ex.service_control("x & del *", "stop")


def test_windows_taskkill_argv_and_protection():
    r = Runner()
    ex = win(r)
    ex.terminate_via_taskkill(31337)
    assert r.calls == [["taskkill", "/PID", "31337", "/F"]]
    from centralium.agent.response.base import ExecutionRefusedError

    with pytest.raises(ExecutionRefusedError):
        ex.terminate_via_taskkill(4)
