"""Open Cybersecurity Schema Framework (OCSF) JSON exporter.

Converts Centralium NormalizedEvents, Findings, and Incidents into standard
OCSF schema representations (v1.1.0/v1.2.0).

OCSF Categories and Classes:
- Category 1 (System Activity):
  - Class 1007: Process Activity
  - Class 1001: File System Activity
- Category 4 (Network Activity):
  - Class 4001: Network Activity
  - Class 4003: DNS Activity
- Category 2 (Findings):
  - Class 2001: Security Finding
"""

from __future__ import annotations

import json
from typing import Any

from centralium.agent.models import (
    EventType,
    Finding,
    Incident,
    NormalizedEvent,
    Severity,
)

# OCSF Severity IDs
# 0: Unknown, 1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical, 6: Fatal
SEVERITY_MAP: dict[Severity, tuple[int, str]] = {
    Severity.INFO: (1, "Informational"),
    Severity.LOW: (2, "Low"),
    Severity.MEDIUM: (3, "Medium"),
    Severity.HIGH: (4, "High"),
    Severity.CRITICAL: (5, "Critical"),
}


def _severity_to_ocsf(sev: Severity) -> tuple[int, str]:
    return SEVERITY_MAP.get(sev, (0, "Unknown"))


def event_to_ocsf(event: NormalizedEvent) -> dict[str, Any]:
    """Convert a NormalizedEvent to an OCSF event object."""
    millis = int(event.timestamp.timestamp() * 1000)

    # Base OCSF metadata
    ocsf: dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Centralium EDR/EPP",
                "vendor_name": "Centralium",
                "version": "2.0.0",
            },
            "uid": event.event_id,
        },
        "time": millis,
        "time_dt": event.timestamp.isoformat(),
        "unmapped": event.raw_metadata or {},
    }

    if event.event_type in (
        EventType.PROCESS_START,
        EventType.PROCESS_EXIT,
        EventType.PROCESS_INJECT,
    ):
        ocsf["category_uid"] = 1
        ocsf["category_name"] = "System Activity"
        ocsf["class_uid"] = 1007
        ocsf["class_name"] = "Process Activity"
        ocsf["activity_id"] = 1 if event.event_type == EventType.PROCESS_START else 2
        ocsf["process"] = {
            "pid": event.pid,
            "name": event.process_name,
            "cmd_line": event.command_line,
            "file": {"path": event.executable_path or event.file_path},
            "parent_process": {"pid": event.ppid} if event.ppid else None,
        }
        if event.user:
            ocsf["actor"] = {"user": {"name": event.user}}

    elif event.event_type in (
        EventType.FILE_CREATE,
        EventType.FILE_MODIFY,
        EventType.FILE_DELETE,
        EventType.FILE_RENAME,
    ):
        ocsf["category_uid"] = 1
        ocsf["category_name"] = "System Activity"
        ocsf["class_uid"] = 1001
        ocsf["class_name"] = "File System Activity"
        activity_map = {
            EventType.FILE_CREATE: 1,
            EventType.FILE_MODIFY: 2,
            EventType.FILE_DELETE: 3,
            EventType.FILE_RENAME: 4,
        }
        ocsf["activity_id"] = activity_map.get(event.event_type, 99)
        ocsf["file"] = {
            "path": event.file_path,
            "hashes": [{"value": event.hash_sha256, "algorithm": "SHA-256"}] if event.hash_sha256 else [],
        }
        ocsf["actor"] = {"process": {"pid": event.pid, "name": event.process_name}}

    elif event.event_type in (EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN):
        ocsf["category_uid"] = 4
        ocsf["category_name"] = "Network Activity"
        ocsf["class_uid"] = 4001
        ocsf["class_name"] = "Network Activity"
        ocsf["activity_id"] = 1 if event.event_type == EventType.NETWORK_CONNECT else 2
        ocsf["connection_info"] = {
            "protocol_name": event.protocol or "TCP",
            "direction": "Outbound" if event.event_type == EventType.NETWORK_CONNECT else "Inbound",
        }
        meta = event.raw_metadata or {}
        ocsf["src_endpoint"] = {"ip": meta.get("source_ip"), "port": meta.get("source_port")}
        ocsf["dst_endpoint"] = {"ip": event.destination_ip, "port": event.destination_port}

    elif event.event_type == EventType.DNS_QUERY:
        ocsf["category_uid"] = 4
        ocsf["category_name"] = "Network Activity"
        ocsf["class_uid"] = 4003
        ocsf["class_name"] = "DNS Activity"
        ocsf["activity_id"] = 1
        ocsf["query"] = {"hostname": event.domain}

    else:
        ocsf["category_uid"] = 1
        ocsf["category_name"] = "System Activity"
        ocsf["class_uid"] = 1000
        ocsf["class_name"] = "General Activity"
        ocsf["activity_id"] = 99
        ocsf["message"] = str(event.event_type)

    return ocsf


def finding_to_ocsf(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to an OCSF Security Finding (Class 2001)."""
    sev_id, sev_name = _severity_to_ocsf(finding.severity)
    millis = int(finding.timestamp.timestamp() * 1000)

    # MITRE ATT&CK enrichment
    attacks = [{"technique": {"uid": t}} for t in (finding.mitre_techniques or [])]

    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Centralium EDR/EPP",
                "vendor_name": "Centralium",
                "version": "2.0.0",
            },
            "uid": finding.finding_id,
        },
        "time": millis,
        "time_dt": finding.timestamp.isoformat(),
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2001,
        "class_name": "Security Finding",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": sev_id,
        "severity": sev_name,
        "finding_info": {
            "uid": finding.finding_id,
            "title": finding.title,
            "attacks": attacks,
            "analytic": {"name": finding.rule_id},
        },
        "risk_score": finding.score,
        "confidence_score": int(finding.confidence * 100),
        "unmapped": finding.details,
    }


def incident_to_ocsf(incident: Incident) -> dict[str, Any]:
    """Convert an Incident to an OCSF Security Finding (Class 2001)."""
    millis = int(incident.created_at.timestamp() * 1000)
    attacks = [{"technique": {"uid": t}} for t in incident.mitre_techniques]

    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Centralium EDR/EPP",
                "vendor_name": "Centralium",
                "version": "2.0.0",
            },
            "uid": incident.incident_id,
        },
        "time": millis,
        "time_dt": incident.created_at.isoformat(),
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2001,
        "class_name": "Security Finding",
        "activity_id": 1,
        "activity_name": "Create",
        "severity": str(incident.band),
        "finding_info": {
            "uid": incident.incident_id,
            "title": incident.title,
            "attacks": attacks,
            "desc": incident.summary,
        },
        "risk_score": incident.risk_score,
        "unmapped": {
            "finding_ids": incident.finding_ids,
            "event_ids": incident.event_ids,
            "host_id": incident.host_id,
        },
    }


def export_events_to_ocsf_json(events: list[NormalizedEvent], indent: int | None = 2) -> str:
    """Export a list of NormalizedEvents to formatted OCSF JSON."""
    return json.dumps([event_to_ocsf(ev) for ev in events], indent=indent)


def export_findings_to_ocsf_json(findings: list[Finding], indent: int | None = 2) -> str:
    """Export a list of Findings to formatted OCSF JSON."""
    return json.dumps([finding_to_ocsf(f) for f in findings], indent=indent)


__all__ = [
    "SEVERITY_MAP",
    "event_to_ocsf",
    "export_events_to_ocsf_json",
    "export_findings_to_ocsf_json",
    "finding_to_ocsf",
    "incident_to_ocsf",
]
