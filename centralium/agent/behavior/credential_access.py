"""Credential-access and lateral-movement detections.

Detects:
1. LSASS access and dumping (MiniDump, procdump, mimikatz, comsvcs.dll).
2. /etc/shadow and /etc/gshadow reads.
3. SSH agent hijacking (SSH_AUTH_SOCK tampering, socket access).
4. New remote service creation (sc.exe create, New-Service, systemd remote drops).
5. PsExec, WMI, and WinRM invocation.
6. SMB admin share access (IPC$, ADMIN$, C$, D$).

Mapped directly to MITRE ATT&CK:
- T1003.001: OS Credential Dumping: LSASS Memory
- T1003.008: OS Credential Dumping: /etc/passwd and /etc/shadow
- T1563.001: Remote Service Session Hijacking: SSH Hijacking
- T1021.002: Remote Services: SMB/Windows Admin Shares
- T1021.006: Remote Services: Windows Remote Management (WinRM)
- T1047: Windows Management Instrumentation (WMI)
- T1569.002: System Services: Service Execution
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
    new_id,
)

# --------------------------------------------------------------------------- regex patterns
# LSASS dumping patterns
_LSASS_CMD_RE = re.compile(
    r"(procdump.*lsass|mimikatz|comsvcs(\.dll)?\s*(,\s*)?(#24|minidump)|"
    r"sekurlsa|nanodump|lsass\.dmp|dumpert|out-minidump|rundll32.*comsvcs.*(24|minidump))",
    re.I,
)

# Shadow file access patterns
_SHADOW_PATHS = frozenset({"/etc/shadow", "/etc/gshadow", "/etc/security/opasswd", "/etc/master.passwd"})
_SHADOW_CMD_RE = re.compile(
    r"\b(cat|grep|head|tail|awk|cut|sed|strings|less|more|cp|scp)\s+.*(/etc/(g)?shadow)",
    re.I,
)

# Legitimate Linux authentication binaries that routinely read /etc/shadow
_LEGIT_AUTH_PROCS = frozenset(
    {"unix_chkpwd", "login", "sshd", "passwd", "shadowconfig", "sudo", "su", "systemd"}
)

# SSH agent hijack patterns
_SSH_SOCKET_RE = re.compile(
    r"(/tmp/ssh-[a-zA-Z0-9]+/.+|/tmp/\.ssh-.+|SSH_AUTH_SOCK|/run/user/\d+/keyring/ssh)",
    re.I,
)

# Service creation patterns
_SERVICE_CREATE_CMD_RE = re.compile(
    r"(sc(\.exe)?\s+((\\\\[^\s]+\s+)?create|config)|new-service\s+|systemctl\s+(enable|link)\s+)",
    re.I,
)

# PsExec patterns
_PSEXEC_CMD_RE = re.compile(r"\b(psexec(\.exe)?|psexesvc(\.exe)?|paexec(\.exe)?|remcom(\.exe)?)\b", re.I)

# WMI execution patterns
_WMI_CMD_RE = re.compile(
    r"(wmic(\.exe)?\s+.*process\s+call\s+create|wmic(\.exe)?\s+.*(/node:|-node:)|"
    r"invoke-wmimethod\s+.*win32_process|get-wmiobject\s+.*win32_process)",
    re.I,
)

# WinRM execution patterns
_WINRM_CMD_RE = re.compile(
    r"(winrm(\.cmd)?\s+(quickconfig|invoke|get)|enter-pssession\s+.*-computername|"
    r"invoke-command\s+.*-computername)",
    re.I,
)

# SMB Admin Shares: IPC$, ADMIN$, C$, D$
_SMB_ADMIN_SHARE_RE = re.compile(
    r"(\\\\[^\s\\]+\\(admin\$|ipc\$|[a-z]\$)|"
    r"smbclient\s+.*(admin\$|ipc\$|[a-z]\$)|"
    r"net\s+use\s+.*(admin\$|ipc\$|[a-z]\$))",
    re.I,
)


class CredentialAccessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enable_lsass_detection: bool = True
    enable_shadow_detection: bool = True
    enable_ssh_hijack_detection: bool = True
    enable_service_creation_detection: bool = True
    enable_lateral_tool_detection: bool = True
    enable_smb_admin_share_detection: bool = True

    # Whitelist for authorized processes reading shadow files
    shadow_allowed_processes: list[str] = Field(default_factory=lambda: list(_LEGIT_AUTH_PROCS))


class CredentialAccessDetector:
    """Evaluates events for credential theft and lateral movement techniques."""

    def __init__(self, config: CredentialAccessConfig | None = None) -> None:
        self.config = config or CredentialAccessConfig()
        self._shadow_allowed = {p.lower() for p in self.config.shadow_allowed_processes}

    def evaluate(self, event: NormalizedEvent) -> list[Finding]:
        findings: list[Finding] = []

        cmd = event.command_line or ""
        pname = (event.process_name or "").lower()
        fpath = (event.file_path or "").lower()
        epath = (event.executable_path or "").lower()
        meta: dict[str, Any] = event.raw_metadata or {}

        # -------------------------------------------------------------------
        # 1. LSASS access / dumping (T1003.001)
        # -------------------------------------------------------------------
        if self.config.enable_lsass_detection:
            lsass_target = (
                str(meta.get("target_process") or "").lower() == "lsass.exe"
                or str(meta.get("target_image") or "").lower().endswith("lsass.exe")
                or meta.get("target_name") == "lsass.exe"
            )
            lsass_cmd_match = bool(_LSASS_CMD_RE.search(cmd))
            if lsass_cmd_match or (lsass_target and meta.get("call_trace")):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_CRED_LSASS_ACCESS",
                        title=f"LSASS Memory Access or Dump Detected: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=90.0,
                        confidence=0.95,
                        mitre_techniques=["T1003.001"],
                        attack_stage=AttackStage.CREDENTIAL_ACCESS,
                        details={
                            "command_line": cmd[:500],
                            "process_name": pname,
                            "target": meta.get("target_process") or "lsass.exe",
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 2. /etc/shadow and /etc/gshadow reads (T1003.008)
        # -------------------------------------------------------------------
        if self.config.enable_shadow_detection:
            shadow_file_touch = any(fpath.endswith(s) for s in _SHADOW_PATHS)
            shadow_cmd_match = bool(_SHADOW_CMD_RE.search(cmd))

            if (shadow_file_touch or shadow_cmd_match) and pname not in self._shadow_allowed:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_CRED_SHADOW_READ",
                        title=f"Unauthorized Shadow Credential Read: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.90,
                        mitre_techniques=["T1003.008"],
                        attack_stage=AttackStage.CREDENTIAL_ACCESS,
                        details={
                            "file_path": fpath,
                            "command_line": cmd[:500],
                            "process_name": pname,
                            "user": event.user,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 3. SSH agent hijacking (T1563.001)
        # -------------------------------------------------------------------
        if self.config.enable_ssh_hijack_detection:
            ssh_sock_in_cmd = bool(_SSH_SOCKET_RE.search(cmd))
            ssh_sock_in_path = bool(_SSH_SOCKET_RE.search(fpath))
            if (ssh_sock_in_cmd or ssh_sock_in_path) and pname not in ("ssh", "ssh-agent"):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_CRED_SSH_AGENT_HIJACK",
                        title=f"SSH Agent Socket Tampering or Hijacking: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=80.0,
                        confidence=0.85,
                        mitre_techniques=["T1563.001"],
                        attack_stage=AttackStage.CREDENTIAL_ACCESS,
                        details={
                            "command_line": cmd[:500],
                            "file_path": fpath,
                            "process_name": pname,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 4. New remote service creation (T1569.002, T1543)
        # -------------------------------------------------------------------
        if self.config.enable_service_creation_detection:
            is_service_event = event.event_type == EventType.SERVICE_CHANGE
            service_cmd_match = bool(_SERVICE_CREATE_CMD_RE.search(cmd))
            if service_cmd_match or (is_service_event and meta.get("action") == "create"):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_LAT_SERVICE_CREATE",
                        title=f"New Remote or Local Service Creation: {cmd[:80] or pname}",
                        severity=Severity.MEDIUM,
                        score=75.0,
                        confidence=0.85,
                        mitre_techniques=["T1569.002", "T1543"],
                        attack_stage=AttackStage.LATERAL_MOVEMENT,
                        details={
                            "command_line": cmd[:500],
                            "process_name": pname,
                            "service_name": meta.get("service_name"),
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 5. PsExec, WMI, WinRM lateral execution (T1021.002, T1047, T1021.006)
        # -------------------------------------------------------------------
        if self.config.enable_lateral_tool_detection:
            # PsExec
            if _PSEXEC_CMD_RE.search(cmd) or _PSEXEC_CMD_RE.search(pname) or _PSEXEC_CMD_RE.search(epath):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_LAT_PSEXEC",
                        title=f"PsExec Remote Execution Tool Invoked: {cmd[:80] or pname}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.90,
                        mitre_techniques=["T1021.002", "T1569.002"],
                        attack_stage=AttackStage.LATERAL_MOVEMENT,
                        details={"command_line": cmd[:500], "process_name": pname},
                    )
                )

            # WMI
            if _WMI_CMD_RE.search(cmd):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_LAT_WMI",
                        title=f"WMI Lateral Process Execution: {cmd[:80]}",
                        severity=Severity.HIGH,
                        score=80.0,
                        confidence=0.90,
                        mitre_techniques=["T1047"],
                        attack_stage=AttackStage.LATERAL_MOVEMENT,
                        details={"command_line": cmd[:500], "process_name": pname},
                    )
                )

            # WinRM
            winrm_port = event.destination_port in (5985, 5986)
            if _WINRM_CMD_RE.search(cmd) or (winrm_port and pname in ("powershell", "pwsh")):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_LAT_WINRM",
                        title=f"WinRM Remote Execution Invoked: {cmd[:80] or pname}",
                        severity=Severity.MEDIUM,
                        score=75.0,
                        confidence=0.85,
                        mitre_techniques=["T1021.006"],
                        attack_stage=AttackStage.LATERAL_MOVEMENT,
                        details={
                            "command_line": cmd[:500],
                            "process_name": pname,
                            "destination_port": event.destination_port,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 6. SMB Admin Share Access (T1021.002)
        # -------------------------------------------------------------------
        if self.config.enable_smb_admin_share_detection:
            share_cmd_match = bool(_SMB_ADMIN_SHARE_RE.search(cmd))
            share_path_match = bool(_SMB_ADMIN_SHARE_RE.search(fpath))
            meta_share = str(meta.get("share_name") or "").upper()
            is_admin_share = meta_share in ("IPC$", "ADMIN$", "C$", "D$")

            if share_cmd_match or share_path_match or is_admin_share:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_LAT_SMB_ADMIN_SHARE",
                        title=f"SMB Admin Share Access: {fpath or meta_share or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=80.0,
                        confidence=0.90,
                        mitre_techniques=["T1021.002"],
                        attack_stage=AttackStage.LATERAL_MOVEMENT,
                        details={
                            "command_line": cmd[:500],
                            "file_path": fpath,
                            "share_name": meta_share or "admin_share",
                        },
                    )
                )

        return findings


__all__ = [
    "CredentialAccessConfig",
    "CredentialAccessDetector",
]
