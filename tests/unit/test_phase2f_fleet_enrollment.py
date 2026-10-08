"""Unit tests for Phase 2F: Fleet server enrollment, mTLS PKI tooling, and health tracking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from centralium.fleet.models import (
    EndpointStatus,
    EnrollmentRequest,
    HealthState,
    PolicySyncStatus,
)
from centralium.fleet.server import FleetStore, create_fleet_app
from scripts.pki.generate_mtls import (
    generate_ca,
    generate_client_cert,
    generate_server_cert,
    save_pki_bundle,
    verify_certificate_signature,
)


def test_pki_mtls_generation_and_verification(tmp_path: Path):
    """Test self-signed Root CA, server cert, and client cert generation and validation."""
    # 1. Generate CA
    ca_cert, ca_key = generate_ca(common_name="Test Centralium Root CA", valid_days=30, key_size=2048)
    assert ca_cert.subject.rfc4514_string() == "O=Centralium Security,CN=Test Centralium Root CA"
    assert verify_certificate_signature(ca_cert, ca_cert) is True

    # 2. Generate Server Certificate
    server_cert, server_key = generate_server_cert(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name="fleet.centralium.local",
        sans=["localhost", "127.0.0.1", "fleet.centralium.local"],
        valid_days=10,
        key_size=2048,
    )
    assert verify_certificate_signature(server_cert, ca_cert) is True

    # Check SAN extension
    san_ext = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
    assert "fleet.centralium.local" in dns_names
    assert "localhost" in dns_names

    # 3. Generate Agent Client Certificate
    client_cert, client_key = generate_client_cert(
        ca_cert=ca_cert,
        ca_key=ca_key,
        agent_id="ep-linux-001",
        valid_days=7,
        key_size=2048,
    )
    assert verify_certificate_signature(client_cert, ca_cert) is True
    assert "CN=agent:ep-linux-001" in client_cert.subject.rfc4514_string()

    # 4. Save and inspect PEMs
    paths = save_pki_bundle(
        out_dir=tmp_path / "pki",
        ca_cert=ca_cert,
        ca_key=ca_key,
        server_cert=server_cert,
        server_key=server_key,
        client_cert=client_cert,
        client_key=client_key,
    )
    for path in paths.values():
        assert path.exists()
        assert path.stat().st_size > 0

    assert b"BEGIN CERTIFICATE" in paths["ca_cert"].read_bytes()
    assert b"BEGIN PRIVATE KEY" in paths["ca_key"].read_bytes()


def test_fleet_enrollment_tokens_lifecycle():
    """Test one-time enrollment token generation, single-use, and expiration."""
    store = FleetStore(":memory:")

    # Generate one-time token (max_uses=1)
    tok = store.create_enrollment_token(
        endpoint_group="prod-servers",
        tags=["pci", "dmz"],
        expires_in_hours=1,
        max_uses=1,
    )
    assert tok.is_valid() is True
    assert tok.use_count == 0
    assert tok.endpoint_group == "prod-servers"

    # Enroll first endpoint using token
    req1 = EnrollmentRequest(
        registration_token=tok.token,
        host_id="host-srv-101",
        hostname="srv-prod-101.internal",
        os_name="ubuntu-24.04",
        agent_version="1.2.0",
    )
    resp1 = store.enroll_endpoint(req1)
    assert resp1.endpoint_id.startswith("ep_")
    assert resp1.assigned_group == "prod-servers"

    # Token should now be exhausted
    tok_updated = store.get_token(tok.token)
    assert tok_updated is not None
    assert tok_updated.use_count == 1
    assert tok_updated.is_valid() is False

    # Attempt second enrollment with same one-time token should fail
    req2 = EnrollmentRequest(
        registration_token=tok.token,
        host_id="host-srv-102",
        hostname="srv-prod-102.internal",
        os_name="ubuntu-24.04",
        agent_version="1.2.0",
    )
    with pytest.raises(Exception) as exc_info:
        store.enroll_endpoint(req2)
    assert "expired or exhausted" in str(exc_info.value)


def test_fleet_heartbeats_and_policy_sync():
    """Test endpoint heartbeats, health tracking, and policy version discrepancy detection."""
    store = FleetStore(":memory:")
    app = create_fleet_app(store)
    client = TestClient(app)

    # 1. Create token & enroll endpoint
    tok = store.create_enrollment_token(endpoint_group="workstations")
    enroll_payload = {
        "registration_token": tok.token,
        "host_id": "host-laptop-42",
        "hostname": "alice-laptop",
        "os_name": "linux",
        "agent_version": "1.0.0",
    }
    enroll_res = client.post("/api/fleet/enroll", json=enroll_payload)
    assert enroll_res.status_code == 200
    ep_data = enroll_res.json()
    endpoint_id = ep_data["endpoint_id"]
    auth_token = ep_data["auth_token"]

    # 2. Server current policy is 1.0.0, agent sends heartbeat with 1.0.0
    hb1 = {
        "endpoint_id": endpoint_id,
        "host_id": "host-laptop-42",
        "agent_version": "1.0.0",
        "health": "healthy",
        "policy_version": "1.0.0",
        "metrics": {"cpu": 12.5, "mem_mb": 256},
        "active_threats": 0,
    }
    hb_res1 = client.post(
        "/api/fleet/heartbeat",
        json=hb1,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert hb_res1.status_code == 200
    hb_body1 = hb_res1.json()
    assert hb_body1["acknowledged"] is True
    assert hb_body1["policy_status"] == PolicySyncStatus.IN_SYNC.value
    assert hb_body1["action_required"] is None

    # 3. Server updates desired policy to 2.0.0
    store.set_desired_policy_version("2.0.0")

    # 4. Agent sends heartbeat still with 1.0.0 -> flagged OUTDATED with update action
    hb2 = dict(hb1)
    hb2["health"] = "degraded"
    hb2["last_error"] = "disk space warning"
    hb_res2 = client.post(
        "/api/fleet/heartbeat",
        json=hb2,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert hb_res2.status_code == 200
    hb_body2 = hb_res2.json()
    assert hb_body2["policy_status"] == PolicySyncStatus.OUTDATED.value
    assert hb_body2["action_required"] == "update_policy"

    # 5. Check endpoint view
    ep_view = client.get(f"/api/fleet/endpoints/{endpoint_id}").json()
    assert ep_view["health"] == HealthState.DEGRADED.value
    assert ep_view["status"] == EndpointStatus.ONLINE.value
    assert ep_view["policy_status"] == PolicySyncStatus.OUTDATED.value
    assert ep_view["last_heartbeat"]["last_error"] == "disk space warning"


def test_fleet_offline_detection():
    """Test that endpoints with stale last_seen timestamps are transitioned to OFFLINE."""
    store = FleetStore(":memory:")
    tok = store.create_enrollment_token()
    enroll_resp = store.enroll_endpoint(
        EnrollmentRequest(
            registration_token=tok.token,
            host_id="stale-host",
            hostname="stale-box",
            agent_version="1.0.0",
        )
    )

    # Manually backdate last_seen to 10 minutes ago
    ten_mins_ago = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    store._conn.execute(
        "UPDATE fleet_endpoints SET last_seen = ? WHERE endpoint_id = ?",
        (ten_mins_ago, enroll_resp.endpoint_id),
    )

    # Query with offline threshold 120s
    endpoints = store.list_endpoints(offline_threshold_seconds=120)
    assert len(endpoints) == 1
    assert endpoints[0].status == EndpointStatus.OFFLINE
