"""Shared builders for dashboard tests (imported explicitly; not a conftest to stay in-prefix)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from centralium.agent.config import CentraliumConfig
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
from dashboard.backend.app import create_app

TOKENS = {
    "viewer": "viewer-token-0123456789",
    "analyst": "analyst-token-0123456789",
    "admin": "admin-token-0123456789",
    "agent": "agent-token-0123456789",
}


def hdr(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def make_client(tmp_path: Path, **kw: object) -> TestClient:
    cfg = kw.pop("config", None) or CentraliumConfig(demo_mode=False)
    app = create_app(
        tmp_path / "d.db",
        config=cfg,
        tokens=TOKENS,
        static_dir=tmp_path / "nostatic",
        ml_dir=tmp_path / "ml",
        rules_dir=tmp_path / "rules",
        **kw,
    )  # type: ignore[arg-type]
    return TestClient(app, base_url="http://localhost")


def populate(db_path: Path) -> dict[str, str]:
    """Insert a coherent scenario through the foundation Repository."""
    db = Database(db_path)
    repo = Repository(db)
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=4242,
        ppid=1000,
        process_name="powershell",
        command_line="powershell -enc AAAA",
        source="test",
    )
    ev2 = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT,
        pid=4242,
        process_name="powershell",
        destination_ip="203.0.113.9",
        destination_port=443,
        source="test",
    )
    repo.add_event(ev)
    repo.add_event(ev2)
    db.insert(
        "processes",
        {
            "host_id": "localhost",
            "pid": 1000,
            "start_time": "2026-01-01T00:00:00+00:00",
            "name": "explorer",
            "ppid": 1,
        },
    )
    db.insert(
        "processes",
        {
            "host_id": "localhost",
            "pid": 4242,
            "start_time": "2026-01-01T00:01:00+00:00",
            "name": "powershell",
            "ppid": 1000,
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
        title="Encoded PowerShell",
        severity=Severity.HIGH,
        score=82,
        mitre_techniques=["T1059.001"],
        attack_stage=AttackStage.EXECUTION,
    )
    repo.add_finding(f, incident_id="inc1")
    verdict = AIVerdict.model_validate(
        {
            "verdict": "MALICIOUS",
            "severity": "HIGH",
            "confidence": 0.9,
            "threat_type": "Encoded PowerShell",
            "summary": "Encoded command",
            "why_suspicious": ["-enc flag"],
            "evidence": ["powershell -enc"],
            "mitre_techniques": ["T1059.001"],
            "attack_stage": "EXECUTION",
            "recommended_action": "TERMINATE_PROCESS",
        }
    )
    ai = AIAnalysis(
        event_id=ev.event_id,
        model_name="gemma-3-1b-it-Q4_K_M",
        verdict=verdict,
        rag_sources=["mitre:T1059.001"],
    )
    repo.add_ai_analysis(ai)
    repo.add_ml_result(
        ev.event_id,
        MLResult(
            anomaly_score=0.83,
            classification="malicious",
            classification_confidence=0.7,
            top_features=[("cmd_len", 0.4)],
            model_version="m1",
            feature_version="f1",
        ),
        3.2,
    )
    inc = Incident(
        incident_id="inc1",
        title="Suspicious PowerShell",
        risk_score=88,
        band=RiskBand.CRITICAL,
        attack_stage=AttackStage.EXECUTION,
        mitre_techniques=["T1059.001"],
        event_ids=[ev.event_id],
        finding_ids=[f.finding_id],
        ai_analysis_id=ai.analysis_id,
    )
    repo.save_incident(inc)
    act = ActionResult(
        action=ResponseAction.TERMINATE_PROCESS,
        status=ActionStatus.SIMULATED,
        target={"pid": 4242},
        event_id=ev.event_id,
        incident_id="inc1",
    )
    repo.add_action(act)
    db.execute(
        "INSERT INTO rag_metadata (doc_id, source, title, ingested_at) VALUES ('d1','mitre','T1059.001 PowerShell','2026-01-01')"
    )
    db.audit.append("test", "seed", {})
    db.close()
    return {"event_id": ev.event_id, "finding_id": f.finding_id}
