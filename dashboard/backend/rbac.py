# ruff: noqa: B008
"""RBAC Refinement, OIDC SSO Readiness, and Two-Person Approval.

Features:
- OIDC login provider adapter and mock provider for SSO readiness.
- Endpoint-group access scoping and access verification.
- Two-person approval workflow for high-impact response actions (ISOLATE_ENDPOINT).
"""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import ResponseAction
from dashboard.backend.security import Principal, current_principal

log = logging.getLogger("centralium.dashboard.rbac")

HIGH_IMPACT_ACTIONS: frozenset[str] = frozenset({ResponseAction.ISOLATE_ENDPOINT.value})
REQUESTER_PATTERN = re.compile(r"requested via dashboard by ([A-Za-z0-9_.:-]+):")


@dataclass
class OIDCConfig:
    enabled: bool = False
    issuer: str = "https://sso.centralium.local"
    client_id: str = "centralium-dashboard"
    client_secret: str = ""
    redirect_uri: str = "https://localhost:8443/api/auth/oidc/callback"
    default_role: str = "analyst"
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile", "groups"])
    admin_group_names: list[str] = field(default_factory=lambda: ["Centralium-Admins", "admin"])
    analyst_group_names: list[str] = field(default_factory=lambda: ["Centralium-Analysts", "analyst"])


@dataclass
class OIDCClaims:
    sub: str
    email: str
    name: str = ""
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    endpoint_groups: list[str] = field(default_factory=list)


class OIDCAdapter:
    """OIDC SSO provider client adapter."""

    def __init__(self, config: OIDCConfig) -> None:
        self.config = config

    def get_authorization_url(self, state: str, nonce: str | None = None) -> str:
        """Construct authorization URL for OIDC IdP redirect."""
        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "redirect_uri": self.config.redirect_uri,
            "state": state,
        }
        if nonce:
            params["nonce"] = nonce
        return f"{self.config.issuer.rstrip('/')}/protocol/openid-connect/auth?{urlencode(params)}"

    def claims_to_principal(self, claims: OIDCClaims) -> Principal:
        """Map OIDC IdP claims to a Centralium Principal with role and scoped endpoint groups."""
        # Check explicit roles or map from group memberships
        all_membership = {*claims.roles, *claims.groups}

        role = self.config.default_role
        if any(g in all_membership for g in self.config.admin_group_names) or "admin" in claims.roles:
            role = "admin"
        elif any(g in all_membership for g in self.config.analyst_group_names) or "analyst" in claims.roles:
            role = "analyst"

        endpoint_groups: tuple[str, ...] | None = None
        if role != "admin" and claims.endpoint_groups:
            endpoint_groups = tuple(sorted(claims.endpoint_groups))

        ident = f"oidc:{claims.sub[:16]}"
        return Principal(
            role=role,
            ident=ident,
            endpoint_groups=endpoint_groups,
            email=claims.email,
            auth_provider="oidc",
        )


class MockOIDCProvider:
    """Mock Identity Provider for SSO testing and offline deployments."""

    MOCK_USERS: dict[str, dict[str, Any]] = {
        "admin@centralium.local": {
            "sub": "user_admin_001",
            "name": "Admin User",
            "email": "admin@centralium.local",
            "roles": ["admin"],
            "groups": ["Centralium-Admins"],
            "endpoint_groups": ["*"],
        },
        "analyst@centralium.local": {
            "sub": "user_analyst_002",
            "name": "SOC Analyst",
            "email": "analyst@centralium.local",
            "roles": ["analyst"],
            "groups": ["Centralium-Analysts"],
            "endpoint_groups": ["workstations", "dmz"],
        },
        "viewer@centralium.local": {
            "sub": "user_viewer_003",
            "name": "Read-Only Viewer",
            "email": "viewer@centralium.local",
            "roles": ["viewer"],
            "groups": ["Centralium-Viewers"],
            "endpoint_groups": ["workstations"],
        },
    }

    def __init__(self, config: OIDCConfig | None = None) -> None:
        self.config = config or OIDCConfig(enabled=True)
        self._issued_codes: dict[str, str] = {}

    def authorize(self, user_email: str) -> str:
        """Simulate IdP login and authorization code generation."""
        if user_email not in self.MOCK_USERS:
            raise ValueError(f"Unknown mock user: {user_email}")
        code = f"mock_code_{secrets.token_urlsafe(16)}"
        self._issued_codes[code] = user_email
        return code

    def exchange_code(self, code: str) -> dict[str, Any]:
        """Exchange authorization code for simulated tokens."""
        user_email = self._issued_codes.pop(code, None)
        if not user_email:
            raise ValueError("Invalid or expired mock authorization code")

        user_info = self.MOCK_USERS[user_email]
        payload = {
            "iss": self.config.issuer,
            "aud": self.config.client_id,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            **user_info,
        }
        # Fake JWT (base64 header.payload.signature)
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        fake_jwt = f"{header_b64}.{payload_b64}.mock_signature"

        return {
            "access_token": f"mock_access_{secrets.token_urlsafe(16)}",
            "id_token": fake_jwt,
            "token_type": "Bearer",
            "expires_in": 3600,
            "user_info": user_info,
        }

    def parse_mock_id_token(self, id_token: str) -> OIDCClaims:
        parts = id_token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid token format")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(padded)
        data = json.loads(raw)
        return OIDCClaims(
            sub=data.get("sub", "unknown"),
            email=data.get("email", ""),
            name=data.get("name", ""),
            roles=data.get("roles", []),
            groups=data.get("groups", []),
            endpoint_groups=data.get("endpoint_groups", []),
        )


def check_endpoint_group_access(principal: Principal, endpoint_group: str | None) -> None:
    """Verify principal has permission to interact with target endpoint group."""
    if not principal.can_access_endpoint_group(endpoint_group):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Access denied: principal {principal.ident} cannot access endpoint group '{endpoint_group}'"
            ),
        )


def extract_requester_ident(detail: str | None) -> str | None:
    """Extract requester principal ident from response action detail string."""
    if not detail:
        return None
    match = REQUESTER_PATTERN.search(detail)
    return match.group(1) if match else None


def validate_two_person_approval(
    action_row: dict[str, Any] | Any,
    approver: Principal,
    mode: str = "production",
    enforce: bool = True,
) -> None:
    """Enforce two-person approval for high-impact actions like ISOLATE_ENDPOINT in production."""
    row_data = dict(action_row) if not isinstance(action_row, dict) else action_row
    action_type = row_data["action"]
    if action_type not in HIGH_IMPACT_ACTIONS:
        return

    # In production/active mode (or when explicitly enforced), require two distinct individuals
    if enforce or mode.lower() in ("production", "prod", "active"):
        requester = extract_requester_ident(row_data.get("detail"))
        if requester and requester == approver.ident:
            log.warning(
                "Two-person approval rejected: %s attempted to self-approve %s (%s)",
                approver.ident,
                action_type,
                row_data.get("action_id"),
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Two-person approval required: requester '{requester}' cannot approve "
                    f"their own high-impact action '{action_type}'"
                ),
            )


class OIDCExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1)
    state: str | None = None


def create_auth_router(
    adapter: OIDCAdapter,
    mock_provider: MockOIDCProvider | None = None,
) -> APIRouter:
    """FastAPI router for OIDC SSO authentication."""
    router = APIRouter(prefix="/api/auth", tags=["auth"])

    @router.get("/oidc/config")
    def get_oidc_config() -> dict[str, Any]:
        return {
            "enabled": adapter.config.enabled,
            "issuer": adapter.config.issuer,
            "client_id": adapter.config.client_id,
        }

    @router.get("/oidc/login")
    def oidc_login(state: str = Query(default_factory=lambda: secrets.token_urlsafe(16))) -> dict[str, str]:
        if not adapter.config.enabled:
            raise HTTPException(status_code=400, detail="OIDC SSO is disabled")
        auth_url = adapter.get_authorization_url(state=state)
        return {"authorization_url": auth_url, "state": state}

    @router.post("/oidc/callback")
    def oidc_callback(body: OIDCExchangeRequest) -> dict[str, Any]:
        if not adapter.config.enabled:
            raise HTTPException(status_code=400, detail="OIDC SSO is disabled")

        if mock_provider:
            token_resp = mock_provider.exchange_code(body.code)
            claims = mock_provider.parse_mock_id_token(token_resp["id_token"])
            principal = adapter.claims_to_principal(claims)
            return {
                "principal": {
                    "role": principal.role,
                    "ident": principal.ident,
                    "email": principal.email,
                    "endpoint_groups": principal.endpoint_groups,
                    "auth_provider": principal.auth_provider,
                },
                "tokens": token_resp,
            }

        raise HTTPException(status_code=501, detail="Live OIDC callback requires configured IdP client")

    @router.get("/scoped-test")
    def test_scoped_endpoint(
        group: str = Query(...),
        p: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        check_endpoint_group_access(p, group)
        return {"authorized": True, "group": group, "role": p.role}

    return router
