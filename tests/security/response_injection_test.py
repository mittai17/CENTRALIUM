"""Injection / validation security tests for the response layer. Nothing real is executed."""

from __future__ import annotations

import ast

import pytest

from centralium.agent.models import (
    ActionStatus,
    EventType,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
)
from centralium.agent.policy import (
    ValidationError,
    validate_ip,
    validate_path_str,
    validate_pid,
    validate_port,
    validate_protocol,
    validate_unit_name,
)
from centralium.agent.response import LinuxResponseExecutor, SubprocessRunner, WindowsResponseExecutor
from centralium.agent.response.base import CommandResult

pytestmark = pytest.mark.security
A = ResponseAction

EV = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, source="t")


class Runner:
    def __init__(self):
        self.calls = []

    def run(self, argv, timeout=15.0):
        self.calls.append(list(argv))
        return CommandResult(0)


def dec(action, **t):
    return PolicyDecision(action=action, allowed=True, mode=OperatingMode.ACTIVE, target=t)


BAD_IPS = [
    "1.2.3.4; reboot", "1.2.3.4 -j ACCEPT", "$(id)", "`id`", "1.2.3.4\n5.6.7.8", "1.2.3.4/24", "fe80::1%eth0",
    "example.com", " 1.2.3.4", "1.2.3.4 ", "999.1.1.1", "", "0x7f000001", "1.2.3", "::1; x", None, 12345, ["1.2.3.4"],
]  # fmt: skip


@pytest.mark.parametrize("ip", BAD_IPS)
@pytest.mark.parametrize("cls", [LinuxResponseExecutor, WindowsResponseExecutor])
def test_malicious_ip_never_reaches_a_command_line(ip, cls):
    r = Runner()
    res = cls(runner=r).execute(dec(A.BLOCK_CONNECTION, ip=ip, port=80, protocol="tcp"), EV)
    assert res.status == ActionStatus.FAILED
    assert r.calls == []
    with pytest.raises(ValidationError):
        validate_ip(ip)


@pytest.mark.parametrize(
    "port", [-1, 0, 65536, 99999, "80", "80; reboot", 80.5, True, None.__class__, "", [80]]
)
def test_malicious_port_rejected(port):
    r = Runner()
    res = LinuxResponseExecutor(runner=r).execute(
        dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=port, protocol="tcp"), EV
    )
    assert res.status == ActionStatus.FAILED and r.calls == []
    with pytest.raises(ValidationError):
        validate_port(port)


@pytest.mark.parametrize("proto", ["tcp; reboot", "icmp", "TCP -j ACCEPT", "", 6, None])
def test_malicious_protocol_rejected(proto):
    r = Runner()
    res = LinuxResponseExecutor(runner=r).execute(
        dec(A.BLOCK_CONNECTION, ip="203.0.113.9", port=1, protocol=proto), EV
    )
    if proto is None:  # absent protocol defaults to tcp when a port is given
        assert res.status == ActionStatus.EXECUTED
    else:
        assert res.status == ActionStatus.FAILED and r.calls == []
        with pytest.raises(ValidationError):
            validate_protocol(proto)


@pytest.mark.parametrize("pid", [0, -5, "123", "1; rm -rf /", 2**40, 12.5, True, None])
def test_malicious_pid_rejected(pid):
    ev = NormalizedEvent(event_type=EventType.PROCESS_START, source="t")
    res = LinuxResponseExecutor(runner=Runner()).execute(dec(A.TERMINATE_PROCESS, pid=pid), ev)
    assert res.status == ActionStatus.FAILED
    with pytest.raises(ValidationError):
        validate_pid(pid)


@pytest.mark.parametrize("path", ["", "a\x00b", "x" * 5000, None, 5])
def test_malicious_path_rejected(path):
    res = LinuxResponseExecutor(runner=Runner()).execute(dec(A.QUARANTINE_FILE, path=path), EV)
    assert res.status == ActionStatus.FAILED
    with pytest.raises(ValidationError):
        validate_path_str(path)


@pytest.mark.parametrize(
    "unit",
    [
        "x.service;reboot",
        "a b.service",
        "-h.service",
        "$(id).service",
        "../../x.service",
        "x.service\n",
        "",
        "x.sh",
    ],
)
def test_unit_name_injection(unit):
    with pytest.raises(ValidationError):
        validate_unit_name(unit)


def test_quarantine_without_manager_is_refused_and_traversal_path_hits_protection():
    ex = LinuxResponseExecutor(runner=Runner())
    assert ex.execute(dec(A.QUARANTINE_FILE, path="/home/u/x"), EV).status == ActionStatus.FAILED
    r = ex.execute(dec(A.QUARANTINE_FILE, path="/home/u/../../etc/shadow"), EV)
    assert r.status == ActionStatus.FAILED and "protected" in r.detail


def test_management_network_config_injection_rejected_at_isolation_time():
    from centralium.agent.response import IsolationConfig

    r = Runner()
    ex = LinuxResponseExecutor(
        runner=r, firewall="nft", isolation=IsolationConfig(management_networks=("10.0.0.1; reboot",))
    )
    res = ex.execute(dec(A.ISOLATE_ENDPOINT), EV)
    assert res.status == ActionStatus.FAILED and r.calls == []


def test_subprocess_runner_never_uses_shell(monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured.update(kw, argv=argv)

        class CP:
            returncode, stdout, stderr = 0, "", ""

        return CP()

    monkeypatch.setattr("subprocess.run", fake_run)
    SubprocessRunner().run(["echo", "a; reboot"])
    assert captured["shell"] is False and captured["argv"] == ["echo", "a; reboot"]
    with pytest.raises(ValueError):
        SubprocessRunner().run(["echo", "a\x00b"])
    with pytest.raises(ValueError):
        SubprocessRunner().run([])


def test_subprocess_runner_reports_missing_binary_and_timeout():
    res = SubprocessRunner().run(["/nonexistent/binary-xyz"])
    assert res.returncode == 127
    import sys

    res = SubprocessRunner().run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.3)
    assert res.returncode == 124


def test_no_shell_true_anywhere_in_response_package():
    import pathlib

    import centralium.agent.response as pkg

    for f in pathlib.Path(pkg.__file__).parent.glob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
                assert node.attr not in {"system", "popen", "execv", "execl", "spawnl"}
