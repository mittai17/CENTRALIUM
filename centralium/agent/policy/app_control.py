"""Application control and device control policy engine.

Provides:
1. Strict execution allowlist mode (blocks or alerts on any unapproved binary path or hash).
2. Removable media detection (USB / mass-storage mounts, execution from removable media, file transfers).

Mapped to MITRE ATT&CK:
- T1200: Hardware Additions
- T1052.001: Exfiltration Over Physical Medium: USB
- T1091: Replication Through Removable Media
- T1204: User Execution: Malicious File
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
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

DEFAULT_ALLOWED_SYSTEM_PATHS = (
    "/bin/*",
    "/sbin/*",
    "/usr/bin/*",
    "/usr/sbin/*",
    "/usr/local/bin/*",
    "/lib/*",
    "/usr/lib/*",
    "C:\\Windows\\*",
    "C:\\Program Files\\*",
    "C:\\Program Files (x86)\\*",
)

DEFAULT_REMOVABLE_PATH_PATTERNS = (
    "/media/*",
    "/mnt/*",
    "/run/media/*",
    "/volumes/*",
    "[a-z]:\\*",  # Non-C Windows drive letters
)


class AppControlConfig(BaseModel):
    """Configuration for execution allowlist and device control."""

    model_config = ConfigDict(extra="forbid")

    enable_allowlist_mode: bool = False
    enforce_blocking: bool = False
    allowed_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_SYSTEM_PATHS))
    allowed_hashes: list[str] = Field(default_factory=list)
    allowed_process_names: list[str] = Field(default_factory=list)

    enable_device_control: bool = True
    removable_path_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_REMOVABLE_PATH_PATTERNS))


class AppControlEngine:
    """Enforces execution allowlists and detects removable media activity."""

    def __init__(self, config: AppControlConfig | None = None) -> None:
        self.config = config or AppControlConfig()
        self._allowed_hashes = {h.lower() for h in self.config.allowed_hashes}
        self._allowed_names = {n.lower() for n in self.config.allowed_process_names}

    def _matches_any_pattern(self, path_str: str, patterns: list[str]) -> bool:
        normalized = str(Path(path_str).as_posix()).lower() if path_str else ""
        for pat in patterns:
            pat_norm = str(Path(pat).as_posix()).lower()
            if fnmatch.fnmatch(normalized, pat_norm):
                return True
            # Also test direct prefix match
            prefix = pat.replace("*", "").rstrip("/\\").lower()
            if prefix and normalized.startswith(prefix):
                return True
        return False

    def is_removable_path(self, path_str: str) -> bool:
        """Check if path resides on a removable media or mount point."""
        if not path_str:
            return False
        clean = path_str.strip()
        # Direct check for Windows secondary drive letters: D:\, E:\, etc.
        if len(clean) >= 3 and clean[1] == ":" and clean[0].upper() not in ("C", "X"):
            return True
        return self._matches_any_pattern(clean, self.config.removable_path_patterns)

    def is_execution_allowed(
        self,
        executable_path: str,
        process_name: str = "",
        file_hash: str | None = None,
    ) -> bool:
        """Check if execution is authorized under the allowlist."""
        if not self.config.enable_allowlist_mode:
            return True

        if file_hash and file_hash.lower() in self._allowed_hashes:
            return True

        if process_name and process_name.lower() in self._allowed_names:
            return True

        return bool(executable_path and self._matches_any_pattern(executable_path, self.config.allowed_paths))

    def evaluate_event(self, event: NormalizedEvent) -> list[Finding]:
        """Evaluate event against application control and device control policies."""
        findings: list[Finding] = []

        epath = event.executable_path or ""
        pname = event.process_name or ""
        fpath = event.file_path or ""
        meta: dict[str, Any] = event.raw_metadata or {}

        # -------------------------------------------------------------------
        # 1. Removable media hardware attachment / mount
        # -------------------------------------------------------------------
        if self.config.enable_device_control:
            is_device_attach = (
                meta.get("bus") == "usb"
                or meta.get("device_type") == "removable"
                or meta.get("action") in ("mount", "usb_insert", "device_connected")
            )
            if is_device_attach or (event.event_type == EventType.OTHER and meta.get("subsystem") == "block"):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.APP_CONTROL,
                        rule_id="DEV_REMOVABLE_MEDIA_ATTACHED",
                        title=f"Removable Storage Device Connected: {meta.get('device_name') or 'USB Media'}",
                        severity=Severity.INFO,
                        score=25.0,
                        confidence=0.90,
                        mitre_techniques=["T1200"],
                        attack_stage=AttackStage.INITIAL_ACCESS,
                        details={
                            "device_name": meta.get("device_name"),
                            "serial": meta.get("serial"),
                            "mount_point": meta.get("mount_point") or fpath,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 2. Execution from removable media (High risk)
        # -------------------------------------------------------------------
        if self.config.enable_device_control and event.event_type == EventType.PROCESS_START:
            target_exec = epath or fpath
            if self.is_removable_path(target_exec):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.APP_CONTROL,
                        rule_id="APP_REMOVABLE_MEDIA_EXEC",
                        title=f"Execution From Removable Media: {pname or target_exec}",
                        severity=Severity.HIGH,
                        score=80.0,
                        confidence=0.95,
                        mitre_techniques=["T1091", "T1204"],
                        attack_stage=AttackStage.EXECUTION,
                        details={
                            "executable_path": target_exec,
                            "command_line": event.command_line,
                            "process_name": pname,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 3. File activity on removable media
        # -------------------------------------------------------------------
        if (
            self.config.enable_device_control
            and event.event_type in (EventType.FILE_CREATE, EventType.FILE_MODIFY)
            and self.is_removable_path(fpath)
        ):
            findings.append(
                Finding(
                    finding_id=new_id(),
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.APP_CONTROL,
                    rule_id="DEV_REMOVABLE_MEDIA_FILE_ACTIVITY",
                    title=f"File Written to Removable Storage: {fpath}",
                    severity=Severity.LOW,
                    score=35.0,
                    confidence=0.85,
                    mitre_techniques=["T1052.001"],
                    attack_stage=AttackStage.EXFILTRATION,
                    details={
                        "file_path": fpath,
                        "process_name": pname,
                        "user": event.user,
                    },
                )
            )

        # -------------------------------------------------------------------
        # 4. Execution Allowlist enforcement
        # -------------------------------------------------------------------
        if self.config.enable_allowlist_mode and event.event_type == EventType.PROCESS_START:
            allowed = self.is_execution_allowed(
                executable_path=epath or fpath,
                process_name=pname,
                file_hash=event.hash_sha256,
            )
            if not allowed:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.APP_CONTROL,
                        rule_id="APP_ALLOWLIST_VIOLATION",
                        title=f"Unauthorized Application Execution: {pname or epath}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.98,
                        mitre_techniques=["T1204"],
                        attack_stage=AttackStage.EXECUTION,
                        details={
                            "executable_path": epath,
                            "process_name": pname,
                            "command_line": event.command_line,
                            "hash": event.hash_sha256,
                            "enforce_blocking": self.config.enforce_blocking,
                        },
                    )
                )

        return findings

    evaluate = evaluate_event


__all__ = [
    "DEFAULT_ALLOWED_SYSTEM_PATHS",
    "DEFAULT_REMOVABLE_PATH_PATTERNS",
    "AppControlConfig",
    "AppControlEngine",
]
