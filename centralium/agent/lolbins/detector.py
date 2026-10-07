"""Context-scored LOLBin detection.

Score = noisy-OR of positive context signals (cmdline, parent, user, path, destination,
rarity) scaled by benign dampeners (interactive parent, high-frequency pair, package manager).
A LOLBin with no suspicious context scores <= ``BASE_SCORE`` and produces NO finding.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from centralium.agent.behavior.signals import (
    BROWSERS,
    OFFICE,
    SERVICE_ACCOUNTS,
    SERVICE_PARENTS,
    in_system_dir,
    norm_name,
    path_risk,
)
from centralium.agent.lolbins.data import CMD_SIGNALS, LOLBINS, canonical_lolbin
from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
)
from centralium.agent.normalization.common import shannon_entropy

BASE_SCORE = 5.0
_INTERACTIVE_PARENTS = frozenset(
    {
        "explorer",
        "gnome-terminal-",
        "gnome-terminal",
        "konsole",
        "xterm",
        "tmux",
        "tmux: server",
        "screen",
        "alacritty",
        "kitty",
        "wezterm-gui",
        "terminator",
        "code",
        "windowsterminal",
        "conhost",
        "login",
        "sshd",
        "su",
        "sudo",
        "fish",
        "zsh",
        "bash",
        "sh",
        "nvim",
        "vim",
        "emacs",
        "make",
        "cargo",
        "pip",
        "npm",
        "git",
    }
)
_PKG_PARENTS = frozenset(
    {
        "dpkg",
        "apt",
        "apt-get",
        "apt.systemd.daily",
        "rpm",
        "dnf",
        "yum",
        "pacman",
        "zypper",
        "msiexec",
        "trustedinstaller",
        "tiworker",
        "setup",
        "snapd",
        "flatpak",
        "pip",
        "pip3",
        "npm",
        "makepkg",
        "ansible-playbook",
    }
)
_REMOTE_EXEC_PARENTS = frozenset({"wmiprvse", "winrm", "wsmprovhost", "psexesvc", "sshd-session"})
_PROXY_EXEC = frozenset({"mshta", "rundll32", "regsvr32", "wscript", "cscript"})


@dataclass
class LolbinContext:
    """Frequency/destination context supplied by the behavior state (all optional)."""

    pair_count: int = 0  # times this (parent -> child) pair was seen, including now
    proc_count: int = 0  # times this process name was seen, including now
    dest_rarity: float = 0.0  # 0 common .. 1 never seen (for network events)
    parent_name: str | None = None


@dataclass
class LolbinAssessment:
    lolbin: str | None
    score: float = 0.0
    signals: list[tuple[str, float, str]] = field(default_factory=list)
    dampeners: list[tuple[str, float]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    stage: AttackStage = AttackStage.EXECUTION

    @property
    def is_lolbin(self) -> bool:
        return self.lolbin is not None

    def reasons(self) -> list[str]:
        return [f"{d} (+{w:.0f})" for _, w, d in self.signals] + [
            f"{n} (x{f:.2f})" for n, f in self.dampeners
        ]


_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "ff00::/8",
    )
)


def _is_public_ip(ip: str | None) -> bool:
    """External (routable) address. Documentation ranges count as external on purpose (test data)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in n for n in _INTERNAL_NETS if n.version == addr.version)


class LolbinDetector:
    """Evaluates a process/network event for LOLBin abuse in context."""

    def __init__(self, finding_threshold: float = 40.0) -> None:
        self.finding_threshold = finding_threshold

    def assess(self, event: NormalizedEvent, ctx: LolbinContext | None = None) -> LolbinAssessment:
        ctx = ctx or LolbinContext()
        name = canonical_lolbin(norm_name(event.process_name or event.executable_path))
        if name is None or event.event_type not in {
            EventType.PROCESS_START,
            EventType.NETWORK_CONNECT,
            EventType.DNS_QUERY,
            EventType.FILE_CREATE,
        }:
            return LolbinAssessment(lolbin=name)
        spec = LOLBINS[name]
        out = LolbinAssessment(
            lolbin=name, score=BASE_SCORE, techniques=list(spec.techniques), stage=spec.stage
        )
        parent = norm_name(ctx.parent_name or event.parent_process)
        cmd = event.command_line or ""
        pos: list[tuple[str, float, str]] = []

        if event.event_type == EventType.PROCESS_START:
            for sig in CMD_SIGNALS.get(name, []):
                if sig.pattern.search(cmd):
                    pos.append((sig.sid, sig.weight, sig.description))
                    for t in sig.techniques:
                        if t not in out.techniques:
                            out.techniques.append(t)
            if parent in OFFICE:
                pos.append(("parent_office", 40, f"spawned by Office app ({parent})"))
                out.techniques.append("T1204.002")
            elif parent in BROWSERS and name in {
                "powershell",
                "cmd",
                "wscript",
                "cscript",
                "mshta",
                "bash",
                "sh",
                "python",
                "perl",
            }:
                pos.append(("parent_browser", 25, f"interpreter spawned by browser ({parent})"))
            elif parent in SERVICE_PARENTS and name not in {"curl", "wget"} | _PROXY_EXEC:
                pos.append(("parent_service", 40, f"shell/interpreter spawned by service ({parent})"))
                out.techniques.append("T1505.003")
            if parent in _REMOTE_EXEC_PARENTS:
                pos.append(("parent_remote_exec", 30, f"spawned by remote execution broker ({parent})"))
                out.techniques.append("T1021")
            if parent in _PROXY_EXEC and name in {"powershell", "cmd", "bash", "sh"}:
                pos.append(("parent_script_host", 25, f"spawned by script host ({parent})"))
            if event.user and SERVICE_ACCOUNTS.match(event.user) and name not in {"curl", "wget"}:
                pos.append(("service_account", 30, f"run as service account ({event.user})"))
            exe_risk = path_risk(event.executable_path)
            if event.executable_path and exe_risk >= 0.8:
                pos.append(("exe_in_temp", 35, "LOLBin binary executed from temp/shm dir (masquerading)"))
                out.techniques.append("T1036")
            elif (
                event.executable_path
                and spec.platform == "windows"
                and not in_system_dir(event.executable_path)
                and name
                in {"cmd", "powershell", "rundll32", "regsvr32", "mshta", "certutil", "wmic", "bitsadmin"}
            ):
                pos.append(
                    ("exe_off_path", 30, "system binary name outside system directories (masquerading)")
                )
                out.techniques.append("T1036.005")
            if ctx.pair_count == 1 and ctx.proc_count <= 2:
                pos.append(("rare_chain", 8, "first-seen parent/child pair"))
        elif event.event_type in {EventType.NETWORK_CONNECT, EventType.DNS_QUERY}:
            dest_public = _is_public_ip(event.destination_ip)
            if name in {"curl", "wget", "python", "bash", "sh"} and dest_public and ctx.dest_rarity >= 0.8:
                pos.append(("rare_destination", 15, "connection to rare public destination"))
            elif dest_public and ctx.dest_rarity >= 0.8:
                pos.append(("rare_destination", 30, f"{name} connecting to rare public destination"))
            if (
                name
                in {
                    "mshta",
                    "rundll32",
                    "regsvr32",
                    "wscript",
                    "cscript",
                    "certutil",
                    "bitsadmin",
                    "cmd",
                    "nc",
                    "socat",
                }
                and dest_public
            ):
                pos.append(("network_from_proxy_exec", 20, f"{name} making outbound network connection"))
            dom = event.domain or ""
            first = dom.split(".")[0] if dom else ""
            if len(first) >= 12 and shannon_entropy(first) >= 3.6:
                pos.append(("high_entropy_domain", 20, "high-entropy (DGA-like) domain"))
            if (
                event.destination_port
                and event.destination_port not in {80, 443, 53, 22, 8080, 8443}
                and dest_public
            ):
                pos.append(("unusual_port", 12, f"unusual destination port {event.destination_port}"))
        else:  # FILE_CREATE by a LOLBin
            if path_risk(event.file_path) >= 0.8:
                pos.append(("drop_in_temp", 20, "LOLBin dropped file in temp/shm/public dir"))

        # noisy-OR combination (+ small base so benign LOLBins still carry a feature value)
        miss = 1.0
        for _, w, _ in pos:
            miss *= 1.0 - min(w, 99.0) / 100.0
        score = 100.0 * (1.0 - miss)
        out.signals = pos

        damp: list[tuple[str, float]] = []
        if pos:
            if parent in _INTERACTIVE_PARENTS:
                damp.append(("interactive/dev parent", 0.75))
            if parent in _PKG_PARENTS:
                damp.append(("package manager / installer parent", 0.4))
            if ctx.pair_count >= 20:
                damp.append(("frequent parent/child pair (baseline)", 0.6))
            elif ctx.pair_count >= 5:
                damp.append(("recurring parent/child pair", 0.85))
            # strong, unambiguous indicators are not dampened below 70% of strength
            strongest = max(w for _, w, _ in pos)
            for _, f in damp:
                score *= f
            if strongest >= 70:
                score = max(score, strongest * 0.9)
        out.dampeners = damp
        out.score = round(max(BASE_SCORE, min(100.0, score)), 2)
        out.techniques = list(dict.fromkeys(out.techniques))
        if any(
            s[0] in {"dl_pipe", "sh_pipe", "ps_download", "cu_download", "ba_url", "mshta_url"} for s in pos
        ):
            out.stage = AttackStage.COMMAND_AND_CONTROL
        return out

    def evaluate(
        self, event: NormalizedEvent, ctx: LolbinContext | None = None
    ) -> tuple[LolbinAssessment, list[Finding]]:
        a = self.assess(event, ctx)
        if not a.is_lolbin or a.score < self.finding_threshold:
            return a, []
        sev = Severity.HIGH if a.score >= 75 else Severity.MEDIUM if a.score >= 55 else Severity.LOW
        details: dict[str, Any] = {
            "lolbin": a.lolbin,
            "signals": [{"id": i, "weight": w, "description": d} for i, w, d in a.signals],
            "dampeners": [{"reason": n, "factor": f} for n, f in a.dampeners],
            "parent": event.parent_process,
            "user": event.user,
            "note": "LOLBin use is only reported when contextual evidence accumulates",
        }
        return a, [
            Finding(
                event_id=event.event_id,
                timestamp=event.timestamp,
                source=FindingSource.LOLBIN,
                rule_id=f"LOLBIN-{a.lolbin}-CONTEXT".upper(),
                title=f"Suspicious {a.lolbin} usage in context",
                severity=sev,
                score=a.score,
                confidence=min(0.95, 0.5 + 0.1 * len(a.signals)),
                mitre_techniques=a.techniques,
                attack_stage=a.stage,
                details=details,
            )
        ]


__all__ = ["BASE_SCORE", "LolbinAssessment", "LolbinContext", "LolbinDetector"]
