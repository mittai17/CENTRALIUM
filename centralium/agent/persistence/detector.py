"""Persistence detection (Windows + Linux) -> Findings with MITRE technique ids.

Stateless pattern matching on a single :class:`NormalizedEvent`:

Windows: Run/RunOnce keys (T1547.001), Startup folders (T1547.001), Winlogon helper (T1547.004),
Scheduled Tasks (T1053.005), Services (T1543.003), WMI event subscriptions (T1546.003),
IFEO / AppInit / Active Setup (T1546.012/.010, T1547.014), logon scripts (T1037.001).

Linux: cron/at (T1053.003/.002), systemd units (T1543.002), shell startup files (T1546.004),
SSH authorized_keys (T1098.004), rc.local/init.d/XDG autostart (T1037.004/T1547.013),
ld.so.preload (T1574.006).

Legitimate installers/package managers are recognised and downgraded (INFO), never ignored
silently: the finding still records that persistence was modified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from centralium.agent.behavior.signals import norm_name, path_risk
from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
)

_FILE_EVENTS = {EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_RENAME}
_REG_EVENTS = {EventType.REGISTRY_CREATE, EventType.REGISTRY_MODIFY}


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    technique: str
    title: str
    base: float
    kind: str  # location kind for details
    os: str


def _r(rule_id: str, rx: str, tech: str, title: str, base: float, kind: str, os: str) -> _Rule:
    return _Rule(rule_id, re.compile(rx, re.IGNORECASE), tech, title, base, kind, os)


REGISTRY_RULES = [
    _r(
        "PERSIST-WIN-RUNKEY",
        r"\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\(run|runonce|runonceex|runservices)(\\|$)",
        "T1547.001",
        "Registry Run key modified",
        55,
        "run_key",
        "windows",
    ),
    _r(
        "PERSIST-WIN-POLICIES-RUN",
        r"\\currentversion\\policies\\explorer\\run(\\|$)",
        "T1547.001",
        "Policies\\Explorer\\Run key modified",
        60,
        "run_key",
        "windows",
    ),
    _r(
        "PERSIST-WIN-WINLOGON",
        r"\\windows nt\\currentversion\\winlogon\\(shell|userinit|taskman|notify)",
        "T1547.004",
        "Winlogon helper value modified",
        70,
        "winlogon",
        "windows",
    ),
    _r(
        "PERSIST-WIN-IFEO",
        r"\\image file execution options\\[^\\]+\\?(debugger|globalflag)?",
        "T1546.012",
        "Image File Execution Options modified",
        70,
        "ifeo",
        "windows",
    ),
    _r(
        "PERSIST-WIN-APPINIT",
        r"\\windows nt\\currentversion\\windows\\appinit_dlls",
        "T1546.010",
        "AppInit_DLLs modified",
        70,
        "appinit",
        "windows",
    ),
    _r(
        "PERSIST-WIN-ACTIVESETUP",
        r"\\active setup\\installed components\\",
        "T1547.014",
        "Active Setup component added",
        50,
        "active_setup",
        "windows",
    ),
    _r(
        "PERSIST-WIN-LOGONSCRIPT",
        r"\\environment\\userinitmprlogonscript",
        "T1037.001",
        "Logon script registered",
        60,
        "logon_script",
        "windows",
    ),
    _r(
        "PERSIST-WIN-SERVICE-KEY",
        r"\\currentcontrolset\\services\\[^\\]+(\\|$)",
        "T1543.003",
        "Service registry key modified",
        45,
        "service",
        "windows",
    ),
    _r(
        "PERSIST-WIN-WMI-REG",
        r"\\wbem\\|\\subscription\\",
        "T1546.003",
        "WMI configuration modified",
        45,
        "wmi",
        "windows",
    ),
    _r(
        "PERSIST-WIN-COM-HIJACK",
        r"\\software\\classes\\clsid\\\{[^}]+\}\\(inprocserver32|localserver32)",
        "T1546.015",
        "COM server registration modified",
        50,
        "com_hijack",
        "windows",
    ),
]
FILE_RULES = [
    _r(
        "PERSIST-WIN-STARTUP",
        r"\\start menu\\programs\\startup\\",
        "T1547.001",
        "File placed in Startup folder",
        60,
        "startup_folder",
        "windows",
    ),
    _r(
        "PERSIST-WIN-TASKFILE",
        r"\\windows\\(system32|syswow64)\\tasks\\",
        "T1053.005",
        "Scheduled task definition written",
        55,
        "scheduled_task",
        "windows",
    ),
    _r(
        "PERSIST-LNX-CRON",
        r"^/(etc/(cron(\.d|\.daily|\.hourly|\.weekly|\.monthly)?(/|$)|crontab$|anacrontab$)|var/spool/(cron|anacron)(/|$))",
        "T1053.003",
        "Cron configuration modified",
        55,
        "cron",
        "linux",
    ),
    _r(
        "PERSIST-LNX-AT",
        r"^/var/spool/(at|atjobs)(/|$)",
        "T1053.002",
        "at job created",
        50,
        "at_job",
        "linux",
    ),
    _r(
        "PERSIST-LNX-SYSTEMD",
        r"^(/etc/systemd/(system|user)|/usr/lib/systemd/(system|user)|/lib/systemd/(system|user)|/run/systemd/(system|transient)|.*/\.config/systemd/user)/[^/]+\.(service|timer|socket|path)$",
        "T1543.002",
        "systemd unit created/modified",
        60,
        "systemd",
        "linux",
    ),
    _r(
        "PERSIST-LNX-SYSTEMD-WANTS",
        r"/systemd/(system|user)/[^/]+\.wants/",
        "T1543.002",
        "systemd enable symlink created",
        50,
        "systemd",
        "linux",
    ),
    _r(
        "PERSIST-LNX-SHELLRC",
        r"(^|/)(\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.config/fish/config\.fish)$|^/etc/(profile|bash\.bashrc|bashrc|zshrc|zsh/zshrc|environment)$|^/etc/profile\.d/",
        "T1546.004",
        "Shell startup file modified",
        50,
        "shell_rc",
        "linux",
    ),
    _r(
        "PERSIST-LNX-SSHKEYS",
        r"(^|/)\.ssh/(authorized_keys2?|rc|environment)$|^/etc/ssh/(sshd_config|sshrc)$",
        "T1098.004",
        "SSH authorized_keys / sshd config modified",
        65,
        "ssh_keys",
        "linux",
    ),
    _r(
        "PERSIST-LNX-RCLOCAL",
        r"^/etc/(rc\.local|rc\d?\.d/[^/]+|init\.d/[^/]+|init/[^/]+\.conf)$",
        "T1037.004",
        "Startup script (rc.local/init.d) modified",
        60,
        "startup_script",
        "linux",
    ),
    _r(
        "PERSIST-LNX-XDG",
        r"(^|/)(\.config|etc/xdg)/autostart/[^/]+\.desktop$",
        "T1547.013",
        "XDG autostart entry created",
        55,
        "xdg_autostart",
        "linux",
    ),
    _r(
        "PERSIST-LNX-PRELOAD",
        r"^/etc/ld\.so\.preload$",
        "T1574.006",
        "ld.so.preload modified",
        80,
        "ld_preload",
        "linux",
    ),
    _r(
        "PERSIST-LNX-UDEV",
        r"^/etc/udev/rules\.d/[^/]+\.rules$",
        "T1546.017",
        "udev rule created",
        45,
        "udev",
        "linux",
    ),
]

# command-line driven persistence (process creation events)
_CMD_RULES: list[tuple[str, re.Pattern[str], str, str, float, str, str, tuple[str, ...]]] = [
    (
        "PERSIST-WIN-SCHTASKS",
        re.compile(r"\bschtasks(\.exe)?\b.*\s/create\b", re.I | re.S),
        "T1053.005",
        "schtasks /create",
        55,
        "scheduled_task",
        "windows",
        ("schtasks",),
    ),
    (
        "PERSIST-WIN-AT",
        re.compile(r"^\"?[^\s\"]*\bat(\.exe)?\"?\s+\d{1,2}:\d{2}", re.I),
        "T1053.002",
        "at.exe job scheduled",
        50,
        "at_job",
        "windows",
        ("at",),
    ),
    (
        "PERSIST-WIN-SC-CREATE",
        re.compile(r"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b.*\bbinpath\s*=", re.I | re.S),
        "T1543.003",
        "sc create/config service binPath",
        60,
        "service",
        "windows",
        ("sc",),
    ),
    (
        "PERSIST-WIN-NEWSERVICE-PS",
        re.compile(r"\bnew-service\b|\bsc\.exe\s+create\b", re.I),
        "T1543.003",
        "New-Service",
        55,
        "service",
        "windows",
        ("powershell", "pwsh"),
    ),
    (
        "PERSIST-WIN-REGADD-RUN",
        re.compile(r"\breg(\.exe)?\s+add\b.*\\currentversion\\(run|runonce)\b", re.I | re.S),
        "T1547.001",
        "reg add Run key",
        65,
        "run_key",
        "windows",
        ("reg",),
    ),
    (
        "PERSIST-WIN-REG-WINLOGON",
        re.compile(r"\breg(\.exe)?\s+add\b.*\\winlogon\b", re.I | re.S),
        "T1547.004",
        "reg add Winlogon",
        70,
        "winlogon",
        "windows",
        ("reg",),
    ),
    (
        "PERSIST-WIN-WMI-CMD",
        re.compile(
            r"__eventfilter|commandlineeventconsumer|activescripteventconsumer|__filtertoconsumerbinding|register-wmievent|set-wmiinstance.*(consumer|filter)",
            re.I,
        ),
        "T1546.003",
        "WMI event subscription via command line",
        75,
        "wmi",
        "windows",
        (),
    ),
    (
        "PERSIST-WIN-MOFCOMP",
        re.compile(r"\bmofcomp(\.exe)?\b", re.I),
        "T1546.003",
        "mofcomp compiling MOF (WMI persistence)",
        60,
        "wmi",
        "windows",
        ("mofcomp",),
    ),
    (
        "PERSIST-WIN-BITSNOTIFY",
        re.compile(r"/setnotifycmdline", re.I),
        "T1197",
        "BITS job notify command",
        65,
        "bits",
        "windows",
        ("bitsadmin",),
    ),
    (
        "PERSIST-LNX-CRONTAB",
        re.compile(r"^(?!.*\s-[lrV]\b).*(^|\s|/)crontab\s+\S+", re.I | re.S),
        "T1053.003",
        "crontab invoked to install/modify jobs",
        50,
        "cron",
        "linux",
        ("crontab",),
    ),
    (
        "PERSIST-LNX-SYSTEMCTL-ENABLE",
        re.compile(r"\bsystemctl\s+(--user\s+)?(enable|link|preset)\b", re.I),
        "T1543.002",
        "systemctl enable",
        45,
        "systemd",
        "linux",
        ("systemctl",),
    ),
    (
        "PERSIST-LNX-AT",
        re.compile(r"(^|\s)(at|batch)\s+(now|\d{1,2}:\d{2}|-[fmqv])", re.I),
        "T1053.002",
        "at job scheduled",
        45,
        "at_job",
        "linux",
        ("at", "batch"),
    ),
    (
        "PERSIST-LNX-SSHKEY-CMD",
        re.compile(r"(>>?|tee\s+(-a\s+)?)\s*\S*\.ssh/authorized_keys", re.I),
        "T1098.004",
        "append to authorized_keys",
        70,
        "ssh_keys",
        "linux",
        ("bash", "sh", "tee", "echo", "cat", "python", "zsh", "dash"),
    ),
    (
        "PERSIST-LNX-RC-CMD",
        re.compile(
            r"(>>?|tee\s+(-a\s+)?)\s*(~|\S*/home/\S+|/root)?/?\.(bashrc|profile|bash_profile|zshrc)\b", re.I
        ),
        "T1546.004",
        "append to shell startup file",
        55,
        "shell_rc",
        "linux",
        ("bash", "sh", "tee", "echo", "cat", "python", "zsh", "dash"),
    ),
]

_BENIGN_WRITERS = frozenset(
    {
        "dpkg",
        "apt",
        "apt-get",
        "aptitude",
        "rpm",
        "dnf",
        "yum",
        "pacman",
        "zypper",
        "msiexec",
        "trustedinstaller",
        "tiworker",
        "setup",
        "systemd",
        "systemctl",
        "snapd",
        "flatpak",
        "ansible",
        "puppet",
        "chef-client",
        "salt-minion",
        "cloud-init",
        "useradd",
        "usermod",
        "update-rc.d",
        "chkconfig",
        "dkms",
        "svchost",
        "services",
        "wuauclt",
        "installer",
        "update",
        "googleupdate",
        "microsoftedgeupdate",
        "onedrivesetup",
        "teams",
    }
)
_SUSPECT_PAYLOAD = re.compile(
    r"(\\appdata\\|\\temp\\|\\users\\public\\|/tmp/|/dev/shm/|/var/tmp/|powershell|pwsh|-enc\b|frombase64|base64\s+-d|"
    r"https?://|curl\s|wget\s|mshta|regsvr32|rundll32|cscript|wscript|/dev/tcp|nc\s+-|bash\s+-i|\.ps1|\.vbs|\.hta)",
    re.I,
)
_STAGE = AttackStage.PERSISTENCE


def _severity(score: float) -> Severity:
    return (
        Severity.HIGH
        if score >= 75
        else Severity.MEDIUM
        if score >= 50
        else Severity.LOW
        if score >= 25
        else Severity.INFO
    )


class PersistenceDetector:
    """Detects persistence installation/modification on Windows and Linux."""

    def __init__(self, min_score: float = 0.0) -> None:
        self.min_score = min_score

    def evaluate(self, event: NormalizedEvent) -> list[Finding]:
        hits: list[
            tuple[str, str, str, float, str, dict[str, Any]]
        ] = []  # rule, tech, title, base, kind, extra
        et = event.event_type
        meta = event.raw_metadata or {}
        payload_text = " ".join(
            str(x)
            for x in (
                event.command_line,
                meta.get("registry_value"),
                meta.get("registry_new_value"),
                meta.get("wmi_query"),
                meta.get("wmi_consumer"),
                meta.get("task_name"),
            )
            if x
        )

        if et in _REG_EVENTS and event.registry_key:
            for r in REGISTRY_RULES:
                if r.pattern.search(event.registry_key):
                    hits.append(
                        (
                            r.rule_id,
                            r.technique,
                            r.title,
                            r.base,
                            r.kind,
                            {"registry_key": event.registry_key},
                        )
                    )
                    break
        if et in _FILE_EVENTS and event.file_path:
            path = event.file_path.replace("\\\\", "\\")
            for r in FILE_RULES:
                if r.pattern.search(path):
                    hits.append(
                        (r.rule_id, r.technique, r.title, r.base, r.kind, {"file_path": event.file_path})
                    )
                    break
        if et == EventType.SCHEDULED_TASK and meta.get("task_action") in {
            None,
            "created",
            "updated",
            "enabled",
        }:
            hits.append(
                (
                    "PERSIST-WIN-SCHEDTASK-EVENT",
                    "T1053.005",
                    "Scheduled task created/updated",
                    55,
                    "scheduled_task",
                    {"task_name": meta.get("task_name")},
                )
            )
        if et == EventType.SERVICE_CHANGE:
            hits.append(
                (
                    "PERSIST-WIN-SERVICE-EVENT",
                    "T1543.003",
                    "Service installed/changed",
                    50,
                    "service",
                    {"service_name": meta.get("service_name"), "image_path": event.command_line},
                )
            )
        if et == EventType.PERSISTENCE:
            kind = str(meta.get("persistence_kind") or "generic")
            if kind == "wmi":
                hits.append(
                    (
                        "PERSIST-WIN-WMI-EVENT",
                        "T1546.003",
                        "WMI event subscription created",
                        75,
                        "wmi",
                        {"wmi_name": meta.get("wmi_name"), "wmi_operation": meta.get("wmi_operation")},
                    )
                )
            else:
                hits.append(
                    ("PERSIST-GENERIC", "T1547", "Persistence mechanism reported by collector", 50, kind, {})
                )
        if et == EventType.PROCESS_START and event.command_line:
            proc = norm_name(event.process_name or event.executable_path)
            for rid, rx, tech, title, base, kind, osn, procs in _CMD_RULES:
                if (not procs or proc in procs) and rx.search(event.command_line):
                    hits.append(
                        (rid, tech, title, base, kind, {"command_line": event.command_line[:500], "os": osn})
                    )
                    break

        findings: list[Finding] = []
        writer = norm_name(event.process_name or event.executable_path)
        parent = norm_name(event.parent_process)
        for rule_id, tech, title, base, kind, extra in hits:
            score = float(base)
            reasons: list[str] = []
            if _SUSPECT_PAYLOAD.search(payload_text) or _SUSPECT_PAYLOAD.search(
                str(extra.get("command_line", ""))
            ):
                score += 25
                reasons.append("payload references temp path/network/encoded/interpreter content")
            if path_risk(event.executable_path) >= 0.8:
                score += 10
                reasons.append("writer executed from temp/shm directory")
            benign = writer in _BENIGN_WRITERS or parent in _BENIGN_WRITERS
            if benign and not reasons:
                score = min(score, 15.0)
                reasons.append(f"modified by installer/package manager ({writer or parent})")
            elif benign:
                score *= 0.6
                reasons.append("known installer writer (dampened) but payload still suspicious")
            if (
                event.user in {"root", "SYSTEM", "NT AUTHORITY\\SYSTEM"}
                and not benign
                and kind in {"ssh_keys", "systemd", "cron"}
            ):
                score += 5
            score = round(min(score, 100.0), 2)
            if score < self.min_score:
                continue
            findings.append(
                Finding(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.PERSISTENCE,
                    rule_id=rule_id,
                    title=title,
                    severity=_severity(score),
                    score=score,
                    confidence=0.9 if not benign else 0.5,
                    mitre_techniques=[tech],
                    attack_stage=_STAGE,
                    details={
                        "persistence_kind": kind,
                        "writer": event.process_name,
                        "parent": event.parent_process,
                        "reasons": reasons,
                        **{k: v for k, v in extra.items() if v is not None},
                    },
                )
            )
        return findings
