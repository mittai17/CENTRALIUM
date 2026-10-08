"""Unit tests for Phase 2F: SOC case management and SLA tracking in dashboard."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from dashboard.backend.app import create_app
from dashboard.backend.cases import (
    CaseCreate,
    CaseSeverity,
    CaseStatus,
    CaseStore,
    CaseUpdate,
    compute_sla_info,
)


def test_case_lifecycle_and_audit_trail():
    """Test case creation, status progression, notes, incident linking, and audit log."""
    conn = sqlite3.connect(":memory:")
    store = CaseStore(conn)

    # 1. Create Case
    create_req = CaseCreate(
        title="Active Ransomware Investigation",
        description="Multiple canary files modified by unknown binary in /tmp",
        severity=CaseSeverity.CRITICAL,
        assignee="analyst_bob",
        linked_incident_ids=["inc_001", "inc_002"],
        sla_hours=1,  # 1-hour SLA
    )
    case = store.create_case(create_req, actor="analyst:bob")
    assert case["case_id"].startswith("case_")
    assert case["status"] == CaseStatus.OPEN.value
    assert case["severity"] == CaseSeverity.CRITICAL.value
    assert case["assignee"] == "analyst_bob"
    assert case["linked_incident_ids"] == ["inc_001", "inc_002"]
    assert len(case["notes"]) == 0
    assert len(case["audit_trail"]) == 1
    assert case["audit_trail"][0]["action"] == "case_created"

    case_id = case["case_id"]

    # 2. Add Investigator Note
    updated_with_note = store.add_note(
        case_id=case_id,
        content="Analyzed memory dump; beaconing observed to IP 198.51.100.5",
        author="analyst:alice",
    )
    assert len(updated_with_note["notes"]) == 1
    assert updated_with_note["notes"][0]["author"] == "analyst:alice"
    assert "beaconing" in updated_with_note["notes"][0]["content"]

    # 3. Link additional incident
    updated_with_link = store.link_incidents(
        case_id=case_id,
        incident_ids=["inc_003"],
        actor="analyst:alice",
    )
    assert "inc_003" in updated_with_link["linked_incident_ids"]

    # 4. Update status to INVESTIGATING then RESOLVED
    store.update_case(
        case_id=case_id,
        updates=CaseUpdate(status=CaseStatus.INVESTIGATING),
        actor="analyst:bob",
    )
    resolved = store.update_case(
        case_id=case_id,
        updates=CaseUpdate(status=CaseStatus.RESOLVED),
        actor="analyst:bob",
    )
    assert resolved["status"] == CaseStatus.RESOLVED.value

    # Check full audit trail
    audit_actions = [e["action"] for e in resolved["audit_trail"]]
    assert "case_created" in audit_actions
    assert "note_added" in audit_actions
    assert "incidents_linked" in audit_actions
    assert "case_updated" in audit_actions


def test_sla_countdown_timer_calculations():
    """Test SLA countdown, breach detection, and met status calculations."""
    now = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
    created_at = (now - timedelta(minutes=30)).isoformat()
    updated_at = now.isoformat()

    # 1. Active SLA (deadline in 30 minutes)
    deadline_future = (now + timedelta(minutes=30)).isoformat()
    sla_active = compute_sla_info(
        deadline_iso=deadline_future,
        status=CaseStatus.OPEN,
        created_at_iso=created_at,
        updated_at_iso=updated_at,
        now=now,
    )
    assert sla_active["sla_status"] == "active"
    assert sla_active["is_breached"] is False
    assert 1700 < sla_active["remaining_seconds"] <= 1800

    # 2. Breached SLA (deadline was 10 minutes ago)
    deadline_past = (now - timedelta(minutes=10)).isoformat()
    sla_breached = compute_sla_info(
        deadline_iso=deadline_past,
        status=CaseStatus.INVESTIGATING,
        created_at_iso=created_at,
        updated_at_iso=updated_at,
        now=now,
    )
    assert sla_breached["sla_status"] == "breached"
    assert sla_breached["is_breached"] is True
    assert sla_breached["remaining_seconds"] == 0.0

    # 3. Met SLA (case was resolved before deadline)
    resolved_time = (now - timedelta(minutes=5)).isoformat()
    sla_met = compute_sla_info(
        deadline_iso=deadline_future,
        status=CaseStatus.RESOLVED,
        created_at_iso=created_at,
        updated_at_iso=resolved_time,
        now=now,
    )
    assert sla_met["sla_status"] == "met"
    assert sla_met["is_breached"] is False


def test_cases_dashboard_api_endpoints(tmp_path):
    """Test SOC cases REST API endpoints with authentication and authorization."""
    app = create_app(
        db_path=tmp_path / "dashboard.db",
        tokens={"viewer": "viewer_token_secret_123", "analyst": "analyst_token_secret_123"},
    )
    client = TestClient(app)
    analyst_hdr = {"Authorization": "Bearer analyst_token_secret_123"}
    viewer_hdr = {"Authorization": "Bearer viewer_token_secret_123"}

    # 1. Create case via API
    create_body = {
        "title": "Endpoint Lateral Movement Detected",
        "description": "SSH connection between jumpbox and db",
        "severity": "HIGH",
        "assignee": "soc_lead",
    }
    res = client.post("/api/cases", json=create_body, headers=analyst_hdr)
    assert res.status_code == 201
    case_data = res.json()
    case_id = case_data["case_id"]

    # 2. View case (viewer role permitted)
    get_res = client.get(f"/api/cases/{case_id}", headers=viewer_hdr)
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "Endpoint Lateral Movement Detected"

    # 3. Add note
    note_res = client.post(
        f"/api/cases/{case_id}/notes",
        json={"content": "Host has been isolated from network."},
        headers=analyst_hdr,
    )
    assert note_res.status_code == 201
    assert len(note_res.json()["notes"]) == 1

    # 4. List cases
    list_res = client.get("/api/cases", headers=viewer_hdr)
    assert list_res.status_code == 200
    assert list_res.json()["total"] >= 1
