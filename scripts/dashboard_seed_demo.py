# ruff: noqa: E501
#!/usr/bin/env python3
"""Seed a SMALL SYNTHETIC dataset into a NEW database for dashboard UI checks (never use on real data).

Usage: python scripts/dashboard_seed_demo.py /path/to/new.db
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    AIAnalysis,
    AIVerdict,
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    Incident,
    MLResult,
    NormalizedEvent,
    ResponseAction,
    RiskBand,
    Severity,
)
from centralium.agent.storage import Database, Repository


def seed(path: Path) -> None:
    db = Database(path)
    if db.count("events"):
        raise SystemExit("refusing to seed a non-empty database")
    repo = Repository(db)
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=4242,
        ppid=1000,
        process_name="powershell",
        command_line="powershell -enc SQBFAFgA",
        source="demo",
    )
    ev2 = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT,
        pid=4242,
        process_name="powershell",
        destination_ip="203.0.113.9",
        destination_port=443,
        source="demo",
    )
    repo.add_event(ev)
    repo.add_event(ev2)
    for pid, ppid, name, t in (
        (1000, 1, "explorer.exe", "00"),
        (4242, 1000, "powershell", "01"),
        (4300, 4242, "whoami", "02"),
    ):
        db.insert(
            "processes",
            {
                "host_id": "localhost",
                "pid": pid,
                "start_time": f"2026-01-01T00:{t}:00+00:00",
                "ppid": ppid,
                "name": name,
                "command_line": name,
            },
        )
    db.insert(
        "network_connections",
        {
            "event_id": ev2.event_id,
            "timestamp": ev2.timestamp.isoformat(),
            "host_id": "localhost",
            "pid": 4242,
            "process_name": "powershell",
            "destination_ip": "203.0.113.9",
            "destination_port": 443,
            "protocol": "tcp",
        },
    )
    f = Finding(
        event_id=ev.event_id,
        source=FindingSource.LOLBIN,
        rule_id="LOLBIN-PS-ENC",
        title="Encoded PowerShell command",
        severity=Severity.CRITICAL,
        score=91,
        mitre_techniques=["T1059.001"],
        attack_stage=AttackStage.EXECUTION,
    )
    repo.add_finding(f, incident_id="demo-inc-1")
    repo.add_finding(
        Finding(
            event_id=ev2.event_id,
            source=FindingSource.BEHAVIOR,
            rule_id="BEH-C2-BEACON",
            title="Periodic outbound beaconing",
            severity=Severity.HIGH,
            score=70,
            mitre_techniques=["T1071"],
            attack_stage=AttackStage.COMMAND_AND_CONTROL,
        ),
        incident_id="demo-inc-1",
    )
    verdict = AIVerdict.model_validate(
        {
            "verdict": "MALICIOUS",
            "severity": "CRITICAL",
            "confidence": 0.88,
            "threat_type": "Encoded PowerShell downloader",
            "summary": "Base64-encoded PowerShell followed by an outbound connection is consistent with a staged downloader.",
            "why_suspicious": [
                "-enc argument",
                "child of explorer.exe",
                "outbound connection within seconds",
            ],
            "evidence": ["powershell -enc SQBFAFgA", "203.0.113.9:443"],
            "mitre_techniques": ["T1059.001", "T1071"],
            "attack_stage": "EXECUTION",
            "recommended_action": "TERMINATE_PROCESS",
        }
    )
    ai = AIAnalysis(
        event_id=ev.event_id,
        model_name="mock-llm (demo seed)",
        verdict=verdict,
        rag_sources=["mitre:T1059.001"],
    )
    repo.add_ai_analysis(ai)
    repo.add_ml_result(
        ev.event_id,
        MLResult(
            anomaly_score=0.91,
            classification="malicious",
            classification_confidence=0.8,
            top_features=[("cmdline_entropy", 0.42), ("encoded_args", 0.3)],
            model_version="demo",
            feature_version="1",
        ),
        2.4,
    )
    repo.save_incident(
        Incident(
            incident_id="demo-inc-1",
            title="Suspicious PowerShell with C2 beacon",
            risk_score=92,
            band=RiskBand.CRITICAL,
            attack_stage=AttackStage.EXECUTION,
            mitre_techniques=["T1059.001", "T1071"],
            event_ids=[ev.event_id, ev2.event_id],
            finding_ids=[f.finding_id],
            ai_analysis_id=ai.analysis_id,
            summary="Synthetic demo incident.",
        )
    )
    repo.add_action(
        ActionResult(
            action=ResponseAction.TERMINATE_PROCESS,
            status=ActionStatus.PENDING_APPROVAL,
            target={"pid": 4242},
            incident_id="demo-inc-1",
            event_id=ev.event_id,
            detail="demo seed",
        )
    )
    db.execute(
        "INSERT INTO rag_metadata (doc_id, source, title, ingested_at) VALUES ('mitre-T1059.001','mitre','T1059.001 PowerShell','2026-01-01')"
    )
    db.audit.append("demo-seed", "seed", {"note": "synthetic data"})
    db.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    seed(Path(sys.argv[1]))
    print("seeded", sys.argv[1])
