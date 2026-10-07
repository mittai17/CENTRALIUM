"""Small curated, local MITRE ATT&CK table + deterministic event/command mapping helpers.

This is intentionally NOT the full ATT&CK matrix: it is the subset Centralium's
detections can actually evidence. IDs/names/tactics follow ATT&CK Enterprise; the
mapping from tactic to Centralium's 12 ``AttackStage`` values is explicit below.
Unknown ids are reported as unknown, never guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from centralium.agent.models import AttackStage as S


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    stages: tuple[S, ...]


def _t(tid: str, name: str, *stages: S) -> tuple[str, Technique]:
    return tid, Technique(tid, name, stages)


TECHNIQUES: dict[str, Technique] = dict(
    [
        _t("T1566", "Phishing", S.INITIAL_ACCESS),
        _t("T1566.001", "Spearphishing Attachment", S.INITIAL_ACCESS),
        _t("T1189", "Drive-by Compromise", S.INITIAL_ACCESS),
        _t("T1190", "Exploit Public-Facing Application", S.INITIAL_ACCESS),
        _t(
            "T1078",
            "Valid Accounts",
            S.INITIAL_ACCESS,
            S.PERSISTENCE,
            S.PRIVILEGE_ESCALATION,
            S.DEFENSE_EVASION,
        ),
        _t("T1059", "Command and Scripting Interpreter", S.EXECUTION),
        _t("T1059.001", "PowerShell", S.EXECUTION),
        _t("T1059.003", "Windows Command Shell", S.EXECUTION),
        _t("T1059.004", "Unix Shell", S.EXECUTION),
        _t("T1059.005", "Visual Basic", S.EXECUTION),
        _t("T1059.006", "Python", S.EXECUTION),
        _t("T1059.007", "JavaScript", S.EXECUTION),
        _t("T1204", "User Execution", S.EXECUTION),
        _t("T1204.002", "Malicious File", S.EXECUTION),
        _t("T1047", "Windows Management Instrumentation", S.EXECUTION),
        _t("T1053", "Scheduled Task/Job", S.EXECUTION, S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1053.003", "Cron", S.EXECUTION, S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1053.005", "Scheduled Task", S.EXECUTION, S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1547", "Boot or Logon Autostart Execution", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1547.001", "Registry Run Keys / Startup Folder", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1543", "Create or Modify System Process", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1543.002", "Systemd Service", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1543.003", "Windows Service", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1546.004", "Unix Shell Configuration Modification", S.PERSISTENCE, S.PRIVILEGE_ESCALATION),
        _t("T1098.004", "SSH Authorized Keys", S.PERSISTENCE),
        _t("T1136", "Create Account", S.PERSISTENCE),
        _t("T1068", "Exploitation for Privilege Escalation", S.PRIVILEGE_ESCALATION),
        _t("T1548", "Abuse Elevation Control Mechanism", S.PRIVILEGE_ESCALATION, S.DEFENSE_EVASION),
        _t("T1548.003", "Sudo and Sudo Caching", S.PRIVILEGE_ESCALATION, S.DEFENSE_EVASION),
        _t("T1055", "Process Injection", S.DEFENSE_EVASION, S.PRIVILEGE_ESCALATION),
        _t("T1027", "Obfuscated Files or Information", S.DEFENSE_EVASION),
        _t("T1140", "Deobfuscate/Decode Files or Information", S.DEFENSE_EVASION),
        _t("T1070", "Indicator Removal", S.DEFENSE_EVASION),
        _t("T1070.004", "File Deletion", S.DEFENSE_EVASION),
        _t("T1562", "Impair Defenses", S.DEFENSE_EVASION),
        _t("T1562.001", "Disable or Modify Tools", S.DEFENSE_EVASION),
        _t("T1218", "System Binary Proxy Execution", S.DEFENSE_EVASION),
        _t("T1218.005", "Mshta", S.DEFENSE_EVASION),
        _t("T1218.010", "Regsvr32", S.DEFENSE_EVASION),
        _t("T1218.011", "Rundll32", S.DEFENSE_EVASION),
        _t("T1036", "Masquerading", S.DEFENSE_EVASION),
        _t("T1003", "OS Credential Dumping", S.CREDENTIAL_ACCESS),
        _t("T1003.001", "LSASS Memory", S.CREDENTIAL_ACCESS),
        _t("T1003.008", "/etc/passwd and /etc/shadow", S.CREDENTIAL_ACCESS),
        _t("T1110", "Brute Force", S.CREDENTIAL_ACCESS),
        _t("T1552", "Unsecured Credentials", S.CREDENTIAL_ACCESS),
        _t("T1082", "System Information Discovery", S.DISCOVERY),
        _t("T1083", "File and Directory Discovery", S.DISCOVERY),
        _t("T1033", "System Owner/User Discovery", S.DISCOVERY),
        _t("T1057", "Process Discovery", S.DISCOVERY),
        _t("T1016", "System Network Configuration Discovery", S.DISCOVERY),
        _t("T1046", "Network Service Discovery", S.DISCOVERY),
        _t("T1087", "Account Discovery", S.DISCOVERY),
        _t("T1021", "Remote Services", S.LATERAL_MOVEMENT),
        _t("T1021.001", "Remote Desktop Protocol", S.LATERAL_MOVEMENT),
        _t("T1021.002", "SMB/Windows Admin Shares", S.LATERAL_MOVEMENT),
        _t("T1021.004", "SSH", S.LATERAL_MOVEMENT),
        _t("T1570", "Lateral Tool Transfer", S.LATERAL_MOVEMENT),
        _t("T1560", "Archive Collected Data", S.COLLECTION),
        _t("T1005", "Data from Local System", S.COLLECTION),
        _t("T1074", "Data Staged", S.COLLECTION),
        _t("T1071", "Application Layer Protocol", S.COMMAND_AND_CONTROL),
        _t("T1071.001", "Web Protocols", S.COMMAND_AND_CONTROL),
        _t("T1071.004", "DNS", S.COMMAND_AND_CONTROL),
        _t("T1105", "Ingress Tool Transfer", S.COMMAND_AND_CONTROL),
        _t("T1095", "Non-Application Layer Protocol", S.COMMAND_AND_CONTROL),
        _t("T1572", "Protocol Tunneling", S.COMMAND_AND_CONTROL),
        _t("T1041", "Exfiltration Over C2 Channel", S.EXFILTRATION),
        _t("T1048", "Exfiltration Over Alternative Protocol", S.EXFILTRATION),
        _t("T1567", "Exfiltration Over Web Service", S.EXFILTRATION),
        _t("T1486", "Data Encrypted for Impact", S.IMPACT),
        _t("T1490", "Inhibit System Recovery", S.IMPACT),
        _t("T1485", "Data Destruction", S.IMPACT),
        _t("T1489", "Service Stop", S.IMPACT),
        _t("T1496", "Resource Hijacking", S.IMPACT),
    ]
)

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def lookup(technique_id: str) -> Technique | None:
    """Exact lookup; sub-technique ids fall back to nothing (no guessing)."""
    return TECHNIQUES.get(technique_id.strip().upper())


def is_valid_id(technique_id: str) -> bool:
    return bool(_ID_RE.fullmatch(technique_id.strip().upper()))


def stages_for(technique_id: str) -> tuple[S, ...]:
    """Stages a technique evidences; falls back to the parent technique for sub-techniques."""
    tid = technique_id.strip().upper()
    t = TECHNIQUES.get(tid) or TECHNIQUES.get(tid.split(".")[0])
    return t.stages if t else ()


def techniques_for_stage(stage: S) -> list[str]:
    return sorted(t.technique_id for t in TECHNIQUES.values() if stage in t.stages)


def describe(technique_id: str) -> str:
    t = lookup(technique_id) or TECHNIQUES.get(technique_id.split(".")[0].upper())
    return f"{technique_id} {t.name}" if t else f"{technique_id} (not in local table)"


# --------------------------------------------------------------------------- command-line mapping
@dataclass(frozen=True)
class _CmdRule:
    pattern: re.Pattern[str]
    technique: str
    stage: S


def _r(pat: str, tech: str, stage: S) -> _CmdRule:
    return _CmdRule(re.compile(pat, re.IGNORECASE), tech, stage)


_CMD_RULES: tuple[_CmdRule, ...] = (
    _r(r"\b(whoami|id\s+-un?|net\s+user|net\s+localgroup|getent\s+passwd)\b", "T1033", S.DISCOVERY),
    _r(r"\b(ipconfig|ifconfig|ip\s+(a|addr|route)|netstat|arp\s+-a|route\s+print)\b", "T1016", S.DISCOVERY),
    _r(r"\b(systeminfo|uname\s+-a|hostnamectl|lsb_release)\b", "T1082", S.DISCOVERY),
    _r(r"\b(tasklist|ps\s+(aux|-ef))\b", "T1057", S.DISCOVERY),
    _r(r"\b(nmap|masscan|nc\s+-z)\b", "T1046", S.DISCOVERY),
    _r(r"(mimikatz|sekurlsa|procdump.*lsass|comsvcs.*minidump|lsass)", "T1003.001", S.CREDENTIAL_ACCESS),
    _r(r"/etc/shadow", "T1003.008", S.CREDENTIAL_ACCESS),
    _r(
        r"(-enc(odedcommand)?\b|frombase64string|base64\s+-d|-nop\b.*-w\s+hidden)", "T1027", S.DEFENSE_EVASION
    ),
    _r(
        r"(set-mppreference\s+-disable|sc\s+(stop|config)\s+(windefend|sense)|setenforce\s+0|auditctl\s+-e\s*0)",
        "T1562.001",
        S.DEFENSE_EVASION,
    ),
    _r(
        r"(wevtutil\s+cl|history\s+-c|unset\s+histfile|shred\s|rm\s+-rf?\s+/var/log)",
        "T1070",
        S.DEFENSE_EVASION,
    ),
    _r(
        r"\b(curl|wget|certutil.*-urlcache|bitsadmin.*/transfer|invoke-webrequest|iwr|downloadstring|downloadfile)\b",
        "T1105",
        S.COMMAND_AND_CONTROL,
    ),
    _r(r"\b(tar\s+[a-z]*c|zip\s|7z\s+a|rar\s+a|compress-archive)\b", "T1560", S.COLLECTION),
    _r(r"\b(psexec|wmic\s+.*/node|winrs|ssh\s+\S+@|scp\s|smbclient)\b", "T1021", S.LATERAL_MOVEMENT),
    _r(
        r"(vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|cipher\s+/w)",
        "T1490",
        S.IMPACT,
    ),
    _r(r"(crontab\s+-|/etc/cron|schtasks\s+/create|at\s+now)", "T1053", S.PERSISTENCE),
    _r(r"(systemctl\s+enable|sc\s+create|new-service)", "T1543", S.PERSISTENCE),
    _r(r"(authorized_keys)", "T1098.004", S.PERSISTENCE),
    _r(r"(\.bashrc|\.profile|\.zshrc|/etc/profile)", "T1546.004", S.PERSISTENCE),
    _r(r"\bsudo\s+-[sil]\b|\bsu\s+-\s*$", "T1548.003", S.PRIVILEGE_ESCALATION),
)

_INTERPRETER_TECH: dict[str, str] = {
    "powershell.exe": "T1059.001",
    "powershell": "T1059.001",
    "pwsh": "T1059.001",
    "cmd.exe": "T1059.003",
    "wscript.exe": "T1059.005",
    "cscript.exe": "T1059.005",
    "mshta.exe": "T1218.005",
    "rundll32.exe": "T1218.011",
    "regsvr32.exe": "T1218.010",
    "bash": "T1059.004",
    "sh": "T1059.004",
    "dash": "T1059.004",
    "zsh": "T1059.004",
    "python": "T1059.006",
    "python3": "T1059.006",
    "perl": "T1059",
    "node": "T1059.007",
    "wmic.exe": "T1047",
}

INTERPRETERS: frozenset[str] = frozenset(_INTERPRETER_TECH)
LOLBIN_TRANSFER: frozenset[str] = frozenset(
    {"curl", "wget", "certutil.exe", "bitsadmin.exe", "nc", "ncat", "socat"}
)


def technique_for_process(name: str | None) -> str | None:
    return _INTERPRETER_TECH.get((name or "").lower())


def map_command_line(command_line: str | None) -> list[tuple[str, S]]:
    """Return ``(technique_id, stage)`` for every rule the command line matches (ordered, deduped)."""
    if not command_line:
        return []
    seen: set[str] = set()
    out: list[tuple[str, S]] = []
    for rule in _CMD_RULES:
        if rule.technique not in seen and rule.pattern.search(command_line[:8192]):
            seen.add(rule.technique)
            out.append((rule.technique, rule.stage))
    return out
