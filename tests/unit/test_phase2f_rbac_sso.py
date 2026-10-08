"""Unit tests for Phase 2F: RBAC refinement, OIDC SSO, and two-person approval."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from centralium.agent.config import CentraliumConfig
from centralium.agent.models import OperatingMode, ResponseAction
from dashboard.backend.app import create_app
from dashboard.backend.rbac import (
    MockOIDCProvider,
    OIDCAdapter,
    OIDCClaims,
    OIDCConfig,
    check_endpoint_group_access,
    create_auth_router,
    validate_two_person_approval,
)
from dashboard.backend.security import Principal


def test_oidc_adapter_and_mock_provider():
    """Test OIDC client adapter, authorization URL generation, and mock IdP exchange."""
    cfg = OIDCConfig(enabled=True, issuer="https://sso.enterprise.local", client_id="centralium-soc")
    adapter = OIDCAdapter(cfg)
    mock_idp = MockOIDCProvider(cfg)

    # 1. Authorization URL
    auth_url = adapter.get_authorization_url(state="random_state_123", nonce="random_nonce_456")
    assert "https://sso.enterprise.local/protocol/openid-connect/auth" in auth_url
    assert "client_id=centralium-soc" in auth_url
    assert "state=random_state_123" in auth_url

    # 2. Mock IdP code generation and exchange for analyst user
    code = mock_idp.authorize("analyst@centralium.local")
    token_resp = mock_idp.exchange_code(code)
    assert "access_token" in token_resp
    assert "id_token" in token_resp

    # 3. Parse claims & map to Principal
    claims: OIDCClaims = mock_idp.parse_mock_id_token(token_resp["id_token"])
    assert claims.email == "analyst@centralium.local"
    assert "analyst" in claims.roles

    principal = adapter.claims_to_principal(claims)
    assert principal.role == "analyst"
    assert principal.auth_provider == "oidc"
    assert principal.endpoint_groups == ("dmz", "workstations")
    assert principal.can_access_endpoint_group("workstations") is True
    assert principal.can_access_endpoint_group("pci-servers") is False


def test_endpoint_group_access_scoping():
    """Test scoping rules for restricted and unrestricted principals."""
    # Unrestricted admin
    admin_principal = Principal(role="admin", ident="admin:123", endpoint_groups=None)
    assert admin_principal.can_access_endpoint_group("any-group") is True
    check_endpoint_group_access(admin_principal, "any-group")  # Should not raise

    # Scoped analyst
    scoped_analyst = Principal(
        role="analyst",
        ident="analyst:456",
        endpoint_groups=("workstations", "branch-office"),
    )
    assert scoped_analyst.can_access_endpoint_group("workstations") is True
    assert scoped_analyst.can_access_endpoint_group("core-databases") is False

    # Unauthorized access check raises 403
    with pytest.raises(HTTPException) as exc:
        check_endpoint_group_access(scoped_analyst, "core-databases")
    assert exc.value.status_code == 403
    assert "cannot access endpoint group" in exc.value.detail


def test_two_person_approval_workflow():
    """Test two-person approval enforcement for ISOLATE_ENDPOINT in production mode."""
    requester_admin = Principal(role="admin", ident="admin:alice")
    second_admin = Principal(role="admin", ident="admin:bob")

    action_record = {
        "action_id": "act_isolate_01",
        "action": ResponseAction.ISOLATE_ENDPOINT.value,
        "detail": f"requested via dashboard by {requester_admin.ident}: suspicious C2 communication",
    }

    # In production, self-approval by requester must be rejected
    with pytest.raises(HTTPException) as exc:
        validate_two_person_approval(
            action_row=action_record,
            approver=requester_admin,
            mode="production",
            enforce=True,
        )
    assert exc.value.status_code == 403
    assert "Two-person approval required" in exc.value.detail

    # Approval by a different administrator succeeds
    validate_two_person_approval(
        action_row=action_record,
        approver=second_admin,
        mode="production",
        enforce=True,
    )  # Should not raise


def test_two_person_approval_in_dashboard_api(tmp_path):
    """Test two-person approval integration in the dashboard response action API."""
    cfg = CentraliumConfig(mode=OperatingMode.ACTIVE)
    app = create_app(
        db_path=tmp_path / "dashboard_prod.db",
        config=cfg,
        tokens={"admin": "admin_token_secret_12345"},
    )
    client = TestClient(app)
    admin_hdr = {"Authorization": "Bearer admin_token_secret_12345"}

    # 1. Request ISOLATE_ENDPOINT action as admin
    req_body = {
        "action": "ISOLATE_ENDPOINT",
        "target": {"host_id": "host-infected-01"},
        "reason": "Host exhibiting active lateral movement",
    }
    r = client.post("/api/response/requests", json=req_body, headers=admin_hdr).json()
    action_id = r["action_id"]

    # 2. The same admin principal attempts to approve own ISOLATE_ENDPOINT action
    decision_resp = client.post(
        f"/api/response/actions/{action_id}/decision",
        json={"decision": "approve", "note": "Approving my own isolation request"},
        headers=admin_hdr,
    )
    # Must be rejected with 403 (two-person approval violation)
    assert decision_resp.status_code == 403
    assert "Two-person approval" in decision_resp.json()["detail"]


def test_oidc_auth_router_api():
    """Test OIDC authentication API endpoints."""
    cfg = OIDCConfig(enabled=True)
    adapter = OIDCAdapter(cfg)
    mock_idp = MockOIDCProvider(cfg)
    router = create_auth_router(adapter, mock_idp)

    from fastapi import FastAPI

    test_app = FastAPI()
    test_app.include_router(router)
    client = TestClient(test_app)

    # 1. Config endpoint
    c_resp = client.get("/api/auth/oidc/config")
    assert c_resp.status_code == 200
    assert c_resp.json()["enabled"] is True

    # 2. Login endpoint
    l_resp = client.get("/api/auth/oidc/login")
    assert l_resp.status_code == 200
    assert "authorization_url" in l_resp.json()

    # 3. Callback exchange
    code = mock_idp.authorize("admin@centralium.local")
    cb_resp = client.post("/api/auth/oidc/callback", json={"code": code})
    assert cb_resp.status_code == 200
    cb_data = cb_resp.json()
    assert cb_data["principal"]["role"] == "admin"
    assert cb_data["principal"]["email"] == "admin@centralium.local"
