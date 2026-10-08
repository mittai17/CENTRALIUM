"""Unit tests for OCSF JSON and MITRE ATT&CK Navigator layer exporters."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from centralium.agent.export.navigator import (
    export_navigator_layer,
    export_navigator_layer_json,
)
from centralium.agent.export.ocsf import (
    event_to_ocsf,
    export_events_to_ocsf_json,
    export_findings_to_ocsf_json,
    finding_to_ocsf,
    incident_to_ocsf,
)
from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    Incident,
    NormalizedEvent,
    RiskBand,
    Severity,
)


def _make_test_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id="ev-12345",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name="powershell.exe",
        pid=4321,
        command_line="powershell.exe -enc AAAA",
        executable_path="C:\\Windows\\System32\\powershell.exe",
        user="SYSTEM",
    )


def _make_test_finding() -> Finding:
    return Finding(
        finding_id="f-98765",
        event_id="ev-12345",
        timestamp=datetime.now(UTC),
        source=FindingSource.BEHAVIOR,
        rule_id="BEH_INJ_PTRACE",
        title="Ptrace Injection Detected",
        severity=Severity.HIGH,
        score=85.0,
        confidence=0.95,
        mitre_techniques=["T1055.008", "T1055"],
        attack_stage=AttackStage.PRIVILEGE_ESCALATION,
        details={"process": "evil"},
    )


def test_event_to_ocsf_conversion():
    ev = _make_test_event()
    ocsf = event_to_ocsf(ev)

    assert ocsf["metadata"]["version"] == "1.1.0"
    assert ocsf["category_uid"] == 1
    assert ocsf["class_uid"] == 1007
    assert ocsf["class_name"] == "Process Activity"
    assert ocsf["process"]["name"] == "powershell.exe"
    assert ocsf["process"]["pid"] == 4321
    assert ocsf["actor"]["user"]["name"] == "SYSTEM"

    # Test file event
    fev = NormalizedEvent(
        event_id="f-1",
        timestamp=datetime.now(UTC),
        event_type=EventType.FILE_CREATE,
        file_path="/tmp/malware.sh",
        hash_sha256="a" * 64,  # valid 64 char hex
    )
    f_ocsf = event_to_ocsf(fev)
    assert f_ocsf["class_uid"] == 1001
    assert f_ocsf["class_name"] == "File System Activity"
    assert f_ocsf["file"]["path"] == "/tmp/malware.sh"

    # JSON serialization
    json_str = export_events_to_ocsf_json([ev, fev])
    data = json.loads(json_str)
    assert len(data) == 2


def test_finding_and_incident_to_ocsf():
    finding = _make_test_finding()
    ocsf_f = finding_to_ocsf(finding)

    assert ocsf_f["class_uid"] == 2001
    assert ocsf_f["class_name"] == "Security Finding"
    assert ocsf_f["severity_id"] == 4  # High
    assert ocsf_f["severity"] == "High"
    assert ocsf_f["finding_info"]["attacks"][0]["technique"]["uid"] == "T1055.008"

    inc = Incident(
        incident_id="inc-1",
        title="Credential Theft Campaign",
        status="open",
        risk_score=90.0,
        band=RiskBand.CRITICAL,
        mitre_techniques=["T1003.001"],
    )
    ocsf_inc = incident_to_ocsf(inc)
    assert ocsf_inc["class_uid"] == 2001
    assert ocsf_inc["finding_info"]["attacks"][0]["technique"]["uid"] == "T1003.001"

    # Export json
    json_str = export_findings_to_ocsf_json([finding])
    assert "Security Finding" in json_str


def test_navigator_layer_export():
    finding = _make_test_finding()
    layer = export_navigator_layer([finding])

    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 2  # T1055 and T1055.008
    t_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1055" in t_ids
    assert "T1055.008" in t_ids
    assert layer["techniques"][0]["color"].startswith("#")

    # Dict of scores
    tech_scores = {"T1003.001": 90.0, "T1486": 98.0, "T1082": 25.0}
    layer_dict = export_navigator_layer(tech_scores)
    assert len(layer_dict["techniques"]) == 3

    # JSON export
    json_str = export_navigator_layer_json(tech_scores)
    parsed = json.loads(json_str)
    assert parsed["name"] == "Centralium Threat Detection Coverage"
