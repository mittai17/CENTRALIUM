from __future__ import annotations

import json
import sqlite3

import pytest

from centralium.agent.config import CentraliumConfig
from tests.unit.dashboard_conftest_helpers import hdr, make_client, populate

GET_ENDPOINTS = [
    "/api/status",
    "/api/overview",
    "/api/findings",
    "/api/incidents",
    "/api/ai/analyses",
    "/api/mitre",
    "/api/endpoints",
    "/api/graph",
    "/api/processes",
    "/api/network",
    "/api/malware",
    "/api/response/actions",
    "/api/policies",
    "/api/rag",
    "/api/ml",
    "/api/audit",
    "/api/settings",
    "/api/hunt/schema",
    "/metrics",
]


# ------------------------------------------------------------------ auth / RBAC
def test_all_endpoints_require_auth(tmp_path):
    c = make_client(tmp_path)
    for url in GET_ENDPOINTS:
        assert c.get(url).status_code == 401, url
    assert c.get("/api/overview", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/api/overview", headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.get("/api/health").status_code == 200


def test_rbac_levels(tmp_path):
    c = make_client(tmp_path)
    assert c.get("/api/overview", headers=hdr("viewer")).status_code == 200
    assert c.get("/api/audit", headers=hdr("viewer")).status_code == 403
    assert c.get("/api/settings", headers=hdr("viewer")).status_code == 403
    assert c.get("/api/audit", headers=hdr("analyst")).status_code == 200
    body = {"action": "ALERT", "reason": "test reason"}
    assert c.post("/api/response/requests", json=body, headers=hdr("viewer")).status_code == 403
    assert c.post("/api/response/requests", json=body, headers=hdr("analyst")).status_code == 202
    assert c.post("/api/hunt", json={"source": "events"}, headers=hdr("viewer")).status_code == 403
    assert c.post("/api/ingest", json={"agent_id": "a1"}, headers=hdr("analyst")).status_code == 403
    assert c.post("/api/ingest", json={"agent_id": "a1"}, headers=hdr("agent")).status_code == 200


def test_agent_token_cannot_read(tmp_path):
    c = make_client(tmp_path)
    assert c.get("/api/overview", headers=hdr("agent")).status_code == 403


def test_token_generation_and_persistence(tmp_path):
    from dashboard.backend.app import create_app

    app = create_app(tmp_path / "g.db", static_dir=tmp_path / "x")
    gen = app.state.generated_tokens
    assert set(gen) == {"viewer", "analyst", "admin", "agent"}
    raw = (tmp_path / "dashboard_tokens.json").read_text()
    assert all(t not in raw for t in gen.values())  # only hashes persisted
    app2 = create_app(tmp_path / "g.db", static_dir=tmp_path / "x")
    assert app2.state.generated_tokens == {}  # not printed again
    from fastapi.testclient import TestClient

    c = TestClient(app2)
    assert c.get("/api/overview", headers={"Authorization": f"Bearer {gen['viewer']}"}).status_code == 200


def test_short_env_token_rejected(tmp_path, monkeypatch):
    from dashboard.backend.app import create_app

    monkeypatch.setenv("DASHBOARD_CENTRALIUM_ADMIN_TOKEN", "short")
    with pytest.raises(ValueError):
        create_app(tmp_path / "e.db", static_dir=tmp_path / "x")


def test_rate_limit_and_auth_lockout(tmp_path):
    c = make_client(tmp_path, rate_limit_per_minute=5)
    codes = [c.get("/api/health").status_code for _ in range(8)]
    assert 429 in codes
    c2 = make_client(tmp_path / "b")
    for _ in range(25):
        c2.get("/api/overview", headers={"Authorization": "Bearer wrong"})
    assert c2.get("/api/overview", headers=hdr("viewer")).status_code == 429


# ------------------------------------------------------------------ headers / CORS
def test_security_headers_and_cors(tmp_path):
    c = make_client(tmp_path)
    r = c.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    r = c.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    c2 = make_client(tmp_path / "c", cors_origins=["http://localhost:3000"])
    r = c2.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
    r = c2.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    assert c.get("/").headers["x-content-type-options"] == "nosniff"


# ------------------------------------------------------------------ empty DB
def test_empty_db_every_endpoint(tmp_path):
    c = make_client(tmp_path)
    for url in GET_ENDPOINTS:
        r = c.get(url, headers=hdr("admin"))
        assert r.status_code == 200, (url, r.text)
    ov = c.get("/api/overview", headers=hdr("viewer")).json()
    assert ov["empty"] is True and ov["counts"]["events"] == 0
    assert c.get("/api/graph", headers=hdr("viewer")).json() == {"source": "empty", "nodes": [], "edges": []}
    assert c.get("/api/findings", headers=hdr("viewer")).json()["items"] == []
    assert c.get("/api/audit/verify", headers=hdr("analyst")).json()["ok"] is True
    assert c.get("/api/findings/nonexistent", headers=hdr("viewer")).status_code == 404
    assert c.get("/api/incidents/nope", headers=hdr("viewer")).status_code == 404


# ------------------------------------------------------------------ populated
@pytest.fixture
def pop(tmp_path):
    c = make_client(tmp_path)
    ids = populate(tmp_path / "d.db")
    return c, ids


def test_populated_views(pop):
    c, ids = pop
    h = hdr("viewer")
    ov = c.get("/api/overview", headers=h).json()
    assert ov["counts"]["findings"] == 1 and ov["findings_by_severity"]["HIGH"] == 1
    assert ov["incidents_by_band"]["CRITICAL"] == 1 and ov["ai"]["backend"]["kind"] in (
        "gemma",
        "unavailable",
    )
    assert ov["ai"]["backend"]["kind"] == "gemma"
    fl = c.get("/api/findings?severity=HIGH&q=Encoded", headers=h).json()
    assert fl["total"] == 1 and fl["items"][0]["mitre_techniques"] == ["T1059.001"]
    assert c.get("/api/findings?q=%25%27", headers=h).json()["total"] == 0
    v = c.get(f"/api/findings/{ids['finding_id']}", headers=h).json()
    assert v["verdict"]["verdict"] == "MALICIOUS" and v["risk_score"] == 88
    assert v["recommended_action"] == "TERMINATE_PROCESS" and v["actions_taken"][0]["status"] == "simulated"
    assert v["rag_sources"] == ["mitre:T1059.001"] and v["ml"]["top_features"] == [["cmd_len", 0.4]]
    assert (
        v["attack_chain"][0]["stage"] == "EXECUTION"
        and v["timeline"]
        and "T1059.001" in v["mitre_techniques"]
    )
    inc = c.get("/api/incidents/inc1", headers=h).json()
    assert len(inc["findings"]) == 1 and inc["ai"]["verdict"]["severity"] == "HIGH"
    assert c.get("/api/mitre", headers=h).json()["detected"][0]["technique"] == "T1059.001"
    g = c.get("/api/graph", headers=h).json()
    assert g["source"] == "derived" and {e["type"] for e in g["edges"]} == {"spawned", "connected"}
    gi = c.get("/api/graph?incident_id=inc1", headers=h).json()
    assert any(n["type"] == "process" for n in gi["nodes"])
    assert c.get("/api/processes?q=power", headers=h).json()["items"][0]["finding_count"] == 1
    assert c.get("/api/network", headers=h).json()["top_destinations"][0]["destination_ip"] == "203.0.113.9"
    assert c.get("/api/endpoints", headers=h).json()["items"][0]["host_id"] == "localhost"
    assert c.get("/api/rag", headers=h).json()["total"] == 1
    assert c.get("/api/ai/analyses", headers=h).json()["items"][0]["finding_id"] == ids["finding_id"]
    m = c.get("/metrics", headers=h)
    assert "centralium_dashboard_findings_rows 1.0" in m.text


def test_graph_snapshot_table_used_when_present(tmp_path):
    c = make_client(tmp_path)
    populate(tmp_path / "d.db")
    con = sqlite3.connect(tmp_path / "d.db")
    # graph_snapshots is created by storage migration 2 (written by centralium.agent.runtime)
    con.execute(
        "INSERT INTO graph_snapshots (created_at, snapshot) VALUES ('2026-01-01T00:00:00+00:00', ?)",
        (json.dumps({"nodes": [{"id": "a"}], "edges": []}),),
    )
    con.commit()
    con.close()
    assert c.get("/api/graph", headers=hdr("viewer")).json()["source"] == "snapshot"


def test_ai_mock_detected(tmp_path):
    from centralium.agent.models import AIAnalysis
    from centralium.agent.storage import Database, Repository

    c = make_client(tmp_path)
    db = Database(tmp_path / "d.db")
    Repository(db).add_ai_analysis(
        AIAnalysis(event_id="e1", available=False, model_name="mock-llm", error="x")
    )
    db.close()
    assert c.get("/api/overview", headers=hdr("viewer")).json()["ai"]["backend"]["kind"] == "mock"


def test_runtime_banner_demo(tmp_path):
    c = make_client(tmp_path, config=CentraliumConfig(demo_mode=True))
    s = c.get("/api/status", headers=hdr("viewer")).json()
    assert s["demo_mode"] is True and s["destructive_allowed"] is False


# ------------------------------------------------------------------ validation
def test_validation_errors(tmp_path):
    c = make_client(tmp_path)
    a = hdr("analyst")
    assert c.get("/api/findings?limit=100000", headers=a).status_code == 422
    assert c.get("/api/findings?severity=DROP", headers=a).status_code == 422
    assert c.get("/api/findings/bad%20id%27", headers=a).status_code in (404, 422)
    bad = [
        {"action": "TERMINATE_PROCESS", "target": {"pid": "1; rm -rf /"}, "reason": "xxx"},
        {"action": "TERMINATE_PROCESS", "target": {"pid": 1}, "reason": "xxx"},
        {"action": "BLOCK_CONNECTION", "target": {"ip": "999.1.1.1", "port": 80}, "reason": "xxx"},
        {"action": "BLOCK_CONNECTION", "target": {"ip": "1.2.3.4", "port": 70000}, "reason": "xxx"},
        {"action": "QUARANTINE_FILE", "target": {"path": "relative/x"}, "reason": "xxx"},
        {"action": "QUARANTINE_FILE", "target": {"path": "/tmp/../etc/shadow"}, "reason": "xxx"},
        {"action": "RUN_SHELL", "target": {}, "reason": "xxx"},
        {"action": "ALERT", "reason": "xxx", "shell": "id"},
        {"action": "ISOLATE_ENDPOINT", "target": {}, "reason": "xxx"},
    ]
    for b in bad:
        assert c.post("/api/response/requests", json=b, headers=a).status_code == 422, b
    ok = {"action": "BLOCK_CONNECTION", "target": {"ip": "203.0.113.9", "port": 443}, "reason": "c2 beacon"}
    assert c.post("/api/response/requests", json=ok, headers=a).status_code == 202


def test_ingest_validation_and_dedup(tmp_path):
    c = make_client(tmp_path)
    ev = {"event_type": "process_start", "process_name": "x", "source": "test"}
    r = c.post(
        "/api/ingest",
        json={
            "agent_id": "a1",
            "events": [ev, {"event_type": "bogus"}, {"event_type": "other", "hash_sha256": "zz"}],
        },
        headers=hdr("agent"),
    )
    j = r.json()
    assert j["accepted_events"] == 1 and j["rejected"] == 2
    assert c.post("/api/ingest", json={"agent_id": "bad id!"}, headers=hdr("agent")).status_code == 422
    assert c.post("/api/ingest", json={"agent_id": "a", "evil": 1}, headers=hdr("agent")).status_code == 422
    assert c.get("/api/overview", headers=hdr("viewer")).json()["counts"]["events"] == 1


# ------------------------------------------------------------------ response queue + audit
def test_action_requests_queue_and_approval_never_execute(tmp_path):
    c = make_client(tmp_path)
    a, ad = hdr("analyst"), hdr("admin")
    r = c.post(
        "/api/response/requests",
        json={"action": "TERMINATE_PROCESS", "target": {"pid": 321}, "reason": "ransomware"},
        headers=a,
    ).json()
    assert r["status"] == "pending_approval" and r["executed"] is False
    lst = c.get("/api/response/actions", headers=a).json()
    assert lst["pending_approval"] == 1
    # analysts cannot approve
    assert (
        c.post(
            f"/api/response/actions/{r['action_id']}/decision", json={"decision": "approve"}, headers=a
        ).status_code
        == 403
    )
    # destructive approval blocked when destructive_allowed() is false (default demo/learning gate)
    resp = c.post(
        f"/api/response/actions/{r['action_id']}/decision",
        json={"decision": "deny", "note": "no"},
        headers=ad,
    )
    assert resp.json()["status"] == "denied"
    assert (
        c.post(
            f"/api/response/actions/{r['action_id']}/decision", json={"decision": "deny"}, headers=ad
        ).status_code
        == 409
    )
    audit = c.get("/api/audit", headers=a).json()
    types = [e["event_type"] for e in audit["items"]]
    assert "dashboard.action_requested" in types and "dashboard.action_denied" in types
    assert c.get("/api/audit/verify", headers=a).json()["ok"] is True


def test_destructive_approval_refused_in_demo(tmp_path):
    c = make_client(tmp_path, config=CentraliumConfig(demo_mode=True))
    r = c.post(
        "/api/response/requests",
        json={"action": "TERMINATE_PROCESS", "target": {"pid": 321}, "reason": "ransomware"},
        headers=hdr("analyst"),
    ).json()
    resp = c.post(
        f"/api/response/actions/{r['action_id']}/decision", json={"decision": "approve"}, headers=hdr("admin")
    )
    assert resp.status_code == 409


def test_lists_and_policy_toggle_audited(tmp_path):
    c = make_client(tmp_path)
    ad = hdr("admin")
    assert (
        c.post(
            "/api/lists/blocklist", json={"kind": "sha256", "value": "zz", "reason": "bad hash"}, headers=ad
        ).status_code
        == 422
    )
    assert (
        c.post(
            "/api/lists/blocklist", json={"kind": "ip", "value": "1.2.3.4", "reason": "c2 server"}, headers=ad
        ).status_code
        == 201
    )
    assert (
        c.post(
            "/api/lists/blocklist",
            json={"kind": "ip", "value": "1.2.3.4", "reason": "c2 server"},
            headers=hdr("analyst"),
        ).status_code
        == 403
    )
    assert c.get("/api/policies", headers=ad).json()["blocklist"][0]["value"] == "1.2.3.4"
    assert c.patch("/api/policies/nope", json={"enabled": False}, headers=ad).status_code == 404
    assert any(
        e["event_type"] == "dashboard.blocklist_add" for e in c.get("/api/audit", headers=ad).json()["items"]
    )


def test_audit_verify_detects_tamper(tmp_path):
    c = make_client(tmp_path)
    for _ in range(3):
        c.post(
            "/api/response/requests", json={"action": "ALERT", "reason": "audit me"}, headers=hdr("analyst")
        )
    con = sqlite3.connect(tmp_path / "d.db")
    con.execute("UPDATE audit_log SET actor='mallory' WHERE seq=2")
    con.commit()
    con.close()
    v = c.get("/api/audit/verify", headers=hdr("analyst")).json()
    assert v["ok"] is False and v["first_bad_seq"] == 2


# ------------------------------------------------------------------ ML honesty
def test_ml_no_report_says_not_enough_data(tmp_path):
    c = make_client(tmp_path)
    j = c.get("/api/ml", headers=hdr("viewer")).json()
    assert j["evaluation"] == {"available": False, "message": "Not enough validated data", "reasons": []}
    assert j["runtime"]["results"] == 0


def _report(tmp_path, data, name="r.json"):
    d = tmp_path / "ml" / "evaluation"
    d.mkdir(parents=True)
    (d / name).write_text(json.dumps(data))


def test_ml_rejects_unvalidated_and_tiny_reports(tmp_path):
    _report(tmp_path, {"validated": False, "n_samples": 5000, "metrics": {"f1": 0.99}})
    c = make_client(tmp_path)
    ev = c.get("/api/ml", headers=hdr("viewer")).json()["evaluation"]
    assert ev["available"] is False and ev["message"] == "Not enough validated data"
    (tmp_path / "ml" / "evaluation" / "r.json").write_text(
        json.dumps({"n_samples": 4, "metrics": {"f1": 0.99}})
    )
    assert c.get("/api/ml", headers=hdr("viewer")).json()["evaluation"]["available"] is False


def test_ml_reports_real_metrics_only(tmp_path):
    _report(
        tmp_path,
        {
            "model_version": "v3",
            "n_samples": 500,
            "validated": True,
            "metrics": {"precision": 0.9, "recall": 0.8, "f1": 0.85, "roc_auc": 7.0, "bogus": 1},
        },
    )
    c = make_client(tmp_path)
    ev = c.get("/api/ml", headers=hdr("viewer")).json()["evaluation"]
    assert ev["available"] is True and ev["model_version"] == "v3"
    assert ev["metrics"] == {"precision": 0.9, "recall": 0.8, "f1": 0.85}  # out-of-range / unknown dropped


def test_ml_runtime_stats_from_db(pop):
    c, _ = pop
    r = c.get("/api/ml", headers=hdr("viewer")).json()
    assert r["runtime"]["results"] == 1 and r["runtime"]["anomaly_histogram"]["counts"][8] == 1
    assert r["runtime"]["top_features"][0]["feature"] == "cmd_len"
    assert r["evaluation"]["available"] is False  # runtime stats never become eval metrics
