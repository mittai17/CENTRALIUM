"""Fleet management data models for endpoint tracking and enrollment."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EndpointStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class PolicySyncStatus(StrEnum):
    IN_SYNC = "in_sync"
    PENDING = "pending"
    OUTDATED = "outdated"
    ERROR = "error"


class EnrollmentTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_group: str = Field(default="default", max_length=100)
    tags: list[str] = Field(default_factory=list)
    expires_in_hours: int = Field(default=24, ge=1, le=8760)
    max_uses: int = Field(default=1, ge=1, le=1000)


class EnrollmentToken(BaseModel):
    model_config = ConfigDict(extra="ignore")
    token: str
    endpoint_group: str
    tags: list[str] = Field(default_factory=list)
    created_at: str
    expires_at: str
    max_uses: int = 1
    use_count: int = 0
    revoked: bool = False

    def is_valid(self) -> bool:
        from datetime import UTC, datetime

        if self.revoked:
            return False
        if self.use_count >= self.max_uses:
            return False
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now(UTC) < expires


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registration_token: str = Field(min_length=16, max_length=128)
    host_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(default="linux", max_length=64)
    agent_version: str = Field(min_length=1, max_length=32)
    client_cert_fingerprint: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnrollmentResponse(BaseModel):
    endpoint_id: str
    auth_token: str
    assigned_group: str
    enrolled_at: str
    server_version: str
    desired_policy_version: str


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=128)
    agent_version: str = Field(min_length=1, max_length=32)
    health: HealthState = HealthState.HEALTHY
    policy_version: str = Field(default="1.0.0", max_length=32)
    metrics: dict[str, Any] = Field(default_factory=dict)
    active_threats: int = Field(default=0, ge=0)
    last_error: str | None = Field(default=None, max_length=1000)


class HeartbeatResponse(BaseModel):
    acknowledged: bool
    server_time: str
    policy_status: PolicySyncStatus
    desired_policy_version: str
    action_required: str | None = None


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="ignore")
    endpoint_id: str
    host_id: str
    hostname: str
    os_name: str
    agent_version: str
    endpoint_group: str
    tags: list[str] = Field(default_factory=list)
    status: EndpointStatus = EndpointStatus.ONLINE
    health: HealthState = HealthState.HEALTHY
    enrolled_at: str
    last_seen: str
    policy_version: str = "1.0.0"
    policy_status: PolicySyncStatus = PolicySyncStatus.IN_SYNC
    client_cert_fingerprint: str | None = None
    last_heartbeat: dict[str, Any] | None = None
