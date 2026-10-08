"""Ransomware honeyfile canaries.

Places deceptive, high-priority bait files (e.g. `!00_passwords.docx`, `00_budget_2026.xlsx`)
in monitored directories. Any read, write, modification, rename, or deletion of a canary file
triggers an immediate, high-confidence alert for ransomware activity.

Mapped to MITRE ATT&CK:
- T1486: Data Encrypted for Impact
"""

from __future__ import annotations

import contextlib
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    AttackStage,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
    new_id,
)

DEFAULT_CANARY_NAMES = (
    "!00_passwords.docx",
    "00_budget_2026.xlsx",
    "_confidential_recovery_keys.pdf",
    "~accounts_database.sqlite",
)

CANARY_PAYLOAD_TEMPLATE = (
    b"CENTRALIUM_CANARY_HONEYFILE_V1\n"
    b"DO NOT MODIFY, ENCRYPT, OR DELETE THIS FILE.\n"
    b"Timestamp: {timestamp}\n"
    b"Bait Content: " + (b"A" * 512) + b"\n"
)


class CanaryRecord(BaseModel):
    """Metadata tracking a deployed honeyfile canary."""

    model_config = ConfigDict(extra="forbid")

    path: str
    expected_sha256: str
    size_bytes: int
    deployed_at: datetime


class CanaryConfig(BaseModel):
    """Configuration for canary honeyfile deployment and monitoring."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    canary_names: list[str] = Field(default_factory=lambda: list(DEFAULT_CANARY_NAMES))
    monitored_dirs: list[str] = Field(default_factory=list)


class CanaryManager:
    """Deploys, monitors, and verifies ransomware honeyfile canaries."""

    def __init__(self, config: CanaryConfig | None = None) -> None:
        self.config = config or CanaryConfig()
        self._canaries: dict[str, CanaryRecord] = {}

    @property
    def deployed_canaries(self) -> dict[str, CanaryRecord]:
        return dict(self._canaries)

    def is_canary_path(self, path: Path | str) -> bool:
        """Check if a given path is an active or expected honeyfile canary."""
        resolved = str(Path(path).resolve())
        return resolved in self._canaries or any(resolved.endswith(name) for name in self.config.canary_names)

    def deploy(self, directories: list[Path | str]) -> list[CanaryRecord]:
        """Deploy honeyfiles to the specified directory list."""
        if not self.config.enabled:
            return []

        deployed: list[CanaryRecord] = []

        for target in directories:
            target_path = Path(target)
            target_path.mkdir(parents=True, exist_ok=True)

            for name in self.config.canary_names:
                file_path = target_path / name
                payload = CANARY_PAYLOAD_TEMPLATE.replace(
                    b"{timestamp}", datetime.now(UTC).isoformat().encode()
                )
                file_path.write_bytes(payload)
                sha = hashlib.sha256(payload).hexdigest()

                record = CanaryRecord(
                    path=str(file_path.resolve()),
                    expected_sha256=sha,
                    size_bytes=len(payload),
                    deployed_at=datetime.now(UTC),
                )
                self._canaries[record.path] = record
                deployed.append(record)

        return deployed

    def evaluate_event(self, event: NormalizedEvent) -> Finding | None:
        """Evaluate whether a telemetry event touched or tampered with a canary honeyfile."""
        if not self.config.enabled or not event.file_path:
            return None

        event_path = str(Path(event.file_path).resolve())
        matching_canary = self._canaries.get(event_path)
        is_known_name = any(event_path.endswith(name) for name in self.config.canary_names)

        if not matching_canary and not is_known_name:
            return None

        # Verify whether the file on disk was modified or deleted
        p = Path(event_path)
        action_desc = "accessed or touched"
        details: dict[str, Any] = {
            "canary_path": event_path,
            "process_name": event.process_name,
            "command_line": event.command_line,
            "event_type": str(event.event_type),
        }

        if not p.exists():
            action_desc = "deleted"
            details["tamper_mode"] = "deletion"
        else:
            current_bytes = p.read_bytes()
            current_sha = hashlib.sha256(current_bytes).hexdigest()
            if matching_canary and current_sha != matching_canary.expected_sha256:
                action_desc = "encrypted or modified"
                details["tamper_mode"] = "content_modification"
                details["expected_sha256"] = matching_canary.expected_sha256
                details["observed_sha256"] = current_sha

        return Finding(
            finding_id=new_id(),
            event_id=event.event_id,
            timestamp=event.timestamp,
            source=FindingSource.BEHAVIOR,
            rule_id="RANSOM_CANARY_TRIPPED",
            title=f"Ransomware Canary Tripped ({action_desc}): {event_path}",
            severity=Severity.CRITICAL,
            score=98.0,
            confidence=0.99,
            mitre_techniques=["T1486"],
            attack_stage=AttackStage.IMPACT,
            details=details,
        )

    def audit_integrity(self) -> list[Finding]:
        """Perform active audit of all deployed canaries on disk, detecting tampering."""
        findings: list[Finding] = []

        for canary_path, record in list(self._canaries.items()):
            p = Path(canary_path)
            if not p.exists():
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=f"canary-audit-{p.name}",
                        timestamp=datetime.now(UTC),
                        source=FindingSource.BEHAVIOR,
                        rule_id="RANSOM_CANARY_DELETED",
                        title=f"Canary Honeyfile Missing or Deleted: {canary_path}",
                        severity=Severity.CRITICAL,
                        score=95.0,
                        confidence=0.98,
                        mitre_techniques=["T1486"],
                        attack_stage=AttackStage.IMPACT,
                        details={"canary_path": canary_path, "status": "missing"},
                    )
                )
                continue

            content = p.read_bytes()
            current_sha = hashlib.sha256(content).hexdigest()
            if current_sha != record.expected_sha256:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=f"canary-audit-{p.name}",
                        timestamp=datetime.now(UTC),
                        source=FindingSource.BEHAVIOR,
                        rule_id="RANSOM_CANARY_MODIFIED",
                        title=f"Canary Honeyfile Tampered / Encrypted: {canary_path}",
                        severity=Severity.CRITICAL,
                        score=98.0,
                        confidence=0.99,
                        mitre_techniques=["T1486"],
                        attack_stage=AttackStage.IMPACT,
                        details={
                            "canary_path": canary_path,
                            "expected_sha256": record.expected_sha256,
                            "current_sha256": current_sha,
                        },
                    )
                )

        return findings

    def cleanup(self) -> None:
        """Remove all deployed honeyfiles and reset tracked records."""
        for path_str in list(self._canaries.keys()):
            with contextlib.suppress(Exception):
                p = Path(path_str)
                if p.exists():
                    p.unlink()
        self._canaries.clear()


__all__ = [
    "DEFAULT_CANARY_NAMES",
    "CanaryConfig",
    "CanaryManager",
    "CanaryRecord",
]
