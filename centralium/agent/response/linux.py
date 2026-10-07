"""Linux response executor: SIGSTOP/SIGKILL, nftables (preferred) / iptables, systemd controls.

All firewall/systemd operations are argv lists run through the injected ``CommandRunner``.
Nothing escalates privileges: without root the commands simply fail and are reported as FAILED.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from centralium.agent.policy.validation import (
    ValidationError,
    validate_ip,
    validate_port,
    validate_protocol,
    validate_unit_name,
)
from centralium.agent.response.base import BaseResponseExecutor, ExecutionRefusedError, log

NFT_TABLE = "centralium"
NFT_ISO_TABLE = "centralium_iso"
IPT_BLOCK_CHAIN = "CENTRALIUM_BLOCK"
IPT_ISO_CHAIN = "CENTRALIUM_ISO"
PROTECTED_UNIT_PREFIXES = (
    "systemd-",
    "dbus",
    "sshd",
    "ssh.",
    "networkmanager",
    "centralium",
    "getty",
    "polkit",
    "udev",
)
SYSTEMD_VERBS = frozenset({"stop", "disable", "mask", "restart", "start", "unmask"})


@dataclass
class LinuxResponseExecutor(BaseResponseExecutor):
    firewall: Literal["auto", "nft", "iptables"] = "auto"
    which: Callable[[str], str | None] = field(default=shutil.which)

    platform_name = "linux"

    # ------------------------------------------------------------------ backend selection
    def _backend(self) -> str:
        if self.firewall in ("nft", "iptables"):
            return self.firewall
        if self.which("nft"):
            return "nft"
        if self.which("iptables"):
            return "iptables"
        raise ExecutionRefusedError("no firewall tool (nft/iptables) found")

    # ------------------------------------------------------------------ block
    def block_connection(self, ip: str, port: int | None, proto: str | None, simulate: bool) -> str:
        addr = validate_ip(ip)
        if port is not None:
            validate_port(port)
            proto = validate_protocol("tcp" if proto is None else proto)
        elif proto is not None:
            proto = validate_protocol(proto)
        backend = self._backend()
        v6 = addr.version == 6
        if backend == "nft":
            self._run(["nft", "add", "table", "inet", NFT_TABLE], simulate)
            self._run(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    NFT_TABLE,
                    "output",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "output",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "accept",
                    ";",
                    "}",
                ],
                simulate,
            )
            rule = [
                "nft",
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "output",
                "ip6" if v6 else "ip",
                "daddr",
                str(addr),
            ]
            if port is not None and proto:
                rule += [proto, "dport", str(port)]
            elif proto:
                rule += ["meta", "l4proto", proto]
            rule += ["drop"]
            self._run(rule, simulate)
        else:
            tool = "ip6tables" if v6 else "iptables"
            self._run([tool, "-N", IPT_BLOCK_CHAIN], simulate, check=False)
            if not simulate:
                chk = self.runner.run([tool, "-C", "OUTPUT", "-j", IPT_BLOCK_CHAIN], self.command_timeout)
                if chk.returncode != 0:
                    self._run([tool, "-I", "OUTPUT", "1", "-j", IPT_BLOCK_CHAIN], simulate)
            else:
                self._planned.append([tool, "-I", "OUTPUT", "1", "-j", IPT_BLOCK_CHAIN])
            rule = [tool, "-A", IPT_BLOCK_CHAIN, "-d", str(addr)]
            if proto:
                rule += ["-p", proto]
                if port is not None:
                    rule += ["--dport", str(port)]
            rule += ["-j", "DROP"]
            self._run(rule, simulate)
        where = f"{addr}" + (f":{port}/{proto}" if port is not None else "")
        return f"blocked outbound {where} via {backend}"

    def release_blocks(self, simulate: bool = False) -> str:
        backend = self._backend()
        if backend == "nft":
            self._run(["nft", "delete", "table", "inet", NFT_TABLE], simulate, check=False)
        else:
            for tool in ("iptables", "ip6tables"):
                self._run([tool, "-D", "OUTPUT", "-j", IPT_BLOCK_CHAIN], simulate, check=False)
                self._run([tool, "-F", IPT_BLOCK_CHAIN], simulate, check=False)
                self._run([tool, "-X", IPT_BLOCK_CHAIN], simulate, check=False)
        return f"released centralium block rules via {backend}"

    # ------------------------------------------------------------------ isolation
    def isolate_endpoint(self, simulate: bool) -> str:
        nets = self.isolation.parsed()
        backend = self._backend()
        try:
            if backend == "nft":
                self._isolate_nft(nets, simulate)
            else:
                self._isolate_iptables(nets, simulate)
        except Exception:
            if not simulate:
                try:
                    self.release_isolation()
                except Exception:
                    log.exception("isolation rollback failed")
            raise
        return f"endpoint isolated via {backend} (loopback + established + {len(nets)} management exception(s) kept)"  # noqa: E501

    def _isolate_nft(self, nets: list, simulate: bool) -> None:  # type: ignore[type-arg]
        t = NFT_ISO_TABLE
        self._run(["nft", "add", "table", "inet", t], simulate)
        for chain, hook in (("output", "output"), ("input", "input")):
            self._run(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    t,
                    chain,
                    "{",
                    "type",
                    "filter",
                    "hook",
                    hook,
                    "priority",
                    "-10",
                    ";",
                    "policy",
                    "drop",
                    ";",
                    "}",
                ],
                simulate,
            )
            iface = "oifname" if chain == "output" else "iifname"
            self._run(["nft", "add", "rule", "inet", t, chain, iface, "lo", "accept"], simulate)
            if self.isolation.allow_established:
                self._run(
                    ["nft", "add", "rule", "inet", t, chain, "ct", "state", "established,related", "accept"],
                    simulate,
                )
            side = "daddr" if chain == "output" else "saddr"
            for net in nets:
                fam = "ip6" if net.version == 6 else "ip"
                self._run(["nft", "add", "rule", "inet", t, chain, fam, side, str(net), "accept"], simulate)

    def _isolate_iptables(self, nets: list, simulate: bool) -> None:  # type: ignore[type-arg]
        for tool in ("iptables", "ip6tables"):
            v = 6 if tool == "ip6tables" else 4
            self._run([tool, "-N", IPT_ISO_CHAIN], simulate, check=False)
            self._run([tool, "-F", IPT_ISO_CHAIN], simulate)
            self._run([tool, "-A", IPT_ISO_CHAIN, "-o", "lo", "-j", "ACCEPT"], simulate)
            self._run([tool, "-A", IPT_ISO_CHAIN, "-i", "lo", "-j", "ACCEPT"], simulate)
            if self.isolation.allow_established:
                self._run(
                    [
                        tool,
                        "-A",
                        IPT_ISO_CHAIN,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                    simulate,
                )
            for net in nets:
                if net.version == v:
                    self._run([tool, "-A", IPT_ISO_CHAIN, "-d", str(net), "-j", "ACCEPT"], simulate)
                    self._run([tool, "-A", IPT_ISO_CHAIN, "-s", str(net), "-j", "ACCEPT"], simulate)
            self._run([tool, "-A", IPT_ISO_CHAIN, "-j", "DROP"], simulate)
            for hook in ("OUTPUT", "INPUT"):
                self._run([tool, "-I", hook, "1", "-j", IPT_ISO_CHAIN], simulate)

    def release_isolation(self, simulate: bool = False) -> str:
        backend = self._backend()
        if backend == "nft":
            self._run(["nft", "delete", "table", "inet", NFT_ISO_TABLE], simulate, check=False)
        else:
            for tool in ("iptables", "ip6tables"):
                for hook in ("OUTPUT", "INPUT"):
                    self._run([tool, "-D", hook, "-j", IPT_ISO_CHAIN], simulate, check=False)
                self._run([tool, "-F", IPT_ISO_CHAIN], simulate, check=False)
                self._run([tool, "-X", IPT_ISO_CHAIN], simulate, check=False)
        return f"isolation released via {backend}"

    # ------------------------------------------------------------------ systemd
    def systemd_control(self, unit: str, verb: str, simulate: bool | None = None) -> str:
        """stop/disable/mask... a unit. Unit name and verb are strictly validated; protected units refused."""
        unit = validate_unit_name(unit)
        if verb not in SYSTEMD_VERBS:
            raise ValidationError(f"unsupported systemd verb: {verb!r}")
        low = unit.lower()
        if any(low.startswith(p) for p in PROTECTED_UNIT_PREFIXES):
            raise ExecutionRefusedError(f"unit {unit} is protected")
        sim = self.simulate if simulate is None else simulate
        self._planned = []
        self._run(["systemctl", verb, "--", unit], sim)
        return f"systemctl {verb} {unit}" + (" (simulated)" if sim else "")
