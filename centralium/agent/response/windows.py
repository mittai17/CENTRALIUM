"""Windows response executor (taskkill/psutil, netsh advfirewall, sc).

Guarded: importable on Linux (no Windows-only imports); every operation goes through the
injected ``CommandRunner`` as an argv list, so it is fully testable with a mock runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from centralium.agent.policy.validation import (
    ValidationError,
    validate_ip,
    validate_port,
    validate_protocol,
    validate_windows_service,
)
from centralium.agent.response.base import BaseResponseExecutor, ExecutionRefusedError, log

RULE_PREFIX = "Centralium_"
PROTECTED_SERVICES = frozenset(
    {"rpcss", "dcomlaunch", "lsm", "samss", "winmgmt", "eventlog", "wuauserv", "windefend", "mpssvc", "bfe",
     "dhcp", "dnscache", "lanmanserver", "lanmanworkstation", "termservice", "centralium"}
)  # fmt: skip
SC_VERBS = {"stop": ["stop"], "disable": ["config", "start=", "disabled"], "start": ["start"]}


@dataclass
class WindowsResponseExecutor(BaseResponseExecutor):
    platform_name = "windows"

    _blocked: list[str] = field(default_factory=list)

    def terminate_via_taskkill(self, pid: int, simulate: bool = False) -> None:
        """Alternative to the psutil backend: ``taskkill /PID n /F`` (validated pid, protected-checked)."""
        from centralium.agent.policy.validation import validate_pid

        pid = validate_pid(pid)
        assert self.protection is not None
        reason = self.protection.process_refusal(pid, None)
        if reason:
            raise ExecutionRefusedError(reason)
        self._run(["taskkill", "/PID", str(pid), "/F"], simulate)

    # ------------------------------------------------------------------ firewall
    def block_connection(self, ip: str, port: int | None, proto: str | None, simulate: bool) -> str:
        addr = validate_ip(ip)
        name = f"{RULE_PREFIX}Block_{str(addr).replace(':', '_')}" + (f"_{port}" if port is not None else "")
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=out",
            "action=block",
            f"remoteip={addr}",
        ]
        if port is not None:
            cmd += [
                f"protocol={validate_protocol('tcp' if proto is None else proto).upper()}",
                f"remoteport={validate_port(port)}",
            ]
        elif proto:
            cmd += [f"protocol={validate_protocol(proto).upper()}"]
        else:
            cmd += ["protocol=any"]
        self._run(cmd, simulate)
        if not simulate:
            self._blocked.append(name)
        return (
            f"blocked outbound {addr}"
            + (f":{port}" if port is not None else "")
            + " via Windows Defender Firewall"
        )

    def release_blocks(self, simulate: bool = False) -> str:
        names, self._blocked = list(self._blocked), []
        for name in names:
            self._run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], simulate, check=False
            )
        return f"removed {len(names)} centralium block rule(s)"

    def isolate_endpoint(self, simulate: bool) -> str:
        nets = self.isolation.parsed()
        try:
            for i, net in enumerate(nets):
                for direction in ("in", "out"):
                    self._run(
                        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}Mgmt_{i}_{direction}",  # noqa: E501
                         f"dir={direction}", "action=allow", f"remoteip={net}", "protocol=any"],
                        simulate,
                    )  # fmt: skip
            self._run(
                [
                    "netsh",
                    "advfirewall",
                    "set",
                    "allprofiles",
                    "firewallpolicy",
                    "blockinbound,blockoutbound",
                ],
                simulate,
            )
        except Exception:
            if not simulate:
                try:
                    self.release_isolation()
                except Exception:
                    log.exception("isolation rollback failed")
            raise
        return f"endpoint isolated via Windows Defender Firewall ({len(nets)} management exception(s); loopback is implicit)"  # noqa: E501

    def release_isolation(self, simulate: bool = False) -> str:
        self._run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
            simulate,
        )
        i = 0
        for i, _net in enumerate(self.isolation.parsed()):
            for direction in ("in", "out"):
                self._run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name={RULE_PREFIX}Mgmt_{i}_{direction}",
                    ],
                    simulate,
                    check=False,
                )
        return "isolation released (default policy blockinbound,allowoutbound restored)"

    # ------------------------------------------------------------------ services
    def service_control(self, name: str, verb: str, simulate: bool | None = None) -> str:
        name = validate_windows_service(name)
        if verb not in SC_VERBS:
            raise ValidationError(f"unsupported service verb: {verb!r}")
        if name.lower() in PROTECTED_SERVICES:
            raise ExecutionRefusedError(f"service {name} is protected")
        sim = self.simulate if simulate is None else simulate
        self._planned = []
        self._run(["sc", SC_VERBS[verb][0], name, *SC_VERBS[verb][1:]], sim)
        return f"sc {verb} {name}" + (" (simulated)" if sim else "")
