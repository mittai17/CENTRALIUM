"""FastAPI Fleet Management Service.

Handles endpoint enrollment with one-time registration tokens,
heartbeats, per-endpoint health, last-seen, agent version, and policy state tracking.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, Request

from centralium.fleet.models import (
    Endpoint,
    EndpointStatus,
    EnrollmentRequest,
    EnrollmentResponse,
    EnrollmentToken,
    EnrollmentTokenCreate,
    HealthState,
    HeartbeatRequest,
    HeartbeatResponse,
    PolicySyncStatus,
)

log = logging.getLogger("centralium.fleet.server")

FLEET_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_tokens (
    token TEXT PRIMARY KEY,
    endpoint_group TEXT NOT NULL,
    tags TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fleet_endpoints (
    endpoint_id TEXT PRIMARY KEY,
    host_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    endpoint_group TEXT NOT NULL,
    tags TEXT NOT NULL,
    status TEXT NOT NULL,
    health TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_status TEXT NOT NULL,
    auth_token_hash TEXT NOT NULL,
    client_cert_fingerprint TEXT,
    last_heartbeat TEXT
);

CREATE TABLE IF NOT EXISTS fleet_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fleet_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL
);
"""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class FleetStore:
    """Thread-safe SQLite storage for the Centralium fleet server."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(FLEET_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO fleet_config (key, value) VALUES ('desired_policy_version', '1.0.0')"
            )

    def log_audit(self, actor: str, event_type: str, details: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fleet_audit (timestamp, actor, event_type, details) VALUES (?, ?, ?, ?)",
                (now, actor, event_type, json.dumps(details)),
            )

    def create_enrollment_token(
        self,
        endpoint_group: str = "default",
        tags: list[str] | None = None,
        expires_in_hours: int = 24,
        max_uses: int = 1,
        actor: str = "admin",
    ) -> EnrollmentToken:
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires = now + timedelta(hours=expires_in_hours)
        tags_list = tags or []
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO fleet_tokens
                   (token, endpoint_group, tags, created_at, expires_at, max_uses, use_count, revoked)
                   VALUES (?, ?, ?, ?, ?, ?, 0, 0)""",
                (
                    token,
                    endpoint_group,
                    json.dumps(tags_list),
                    now.isoformat(),
                    expires.isoformat(),
                    max_uses,
                ),
            )
        self.log_audit(
            actor,
            "fleet.token_created",
            {"endpoint_group": endpoint_group, "max_uses": max_uses, "expires_at": expires.isoformat()},
        )
        return EnrollmentToken(
            token=token,
            endpoint_group=endpoint_group,
            tags=tags_list,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            max_uses=max_uses,
            use_count=0,
            revoked=False,
        )

    def get_token(self, token: str) -> EnrollmentToken | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM fleet_tokens WHERE token = ?", (token,))
            row = cur.fetchone()
            if not row:
                return None
            return EnrollmentToken(
                token=row["token"],
                endpoint_group=row["endpoint_group"],
                tags=json.loads(row["tags"]),
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                max_uses=row["max_uses"],
                use_count=row["use_count"],
                revoked=bool(row["revoked"]),
            )

    def enroll_endpoint(self, req: EnrollmentRequest, actor: str = "agent") -> EnrollmentResponse:
        with self._lock, self._conn:
            token_row = self._conn.execute(
                "SELECT * FROM fleet_tokens WHERE token = ?", (req.registration_token,)
            ).fetchone()
            if not token_row:
                raise HTTPException(status_code=401, detail="Invalid registration token")
            token_obj = EnrollmentToken(
                token=token_row["token"],
                endpoint_group=token_row["endpoint_group"],
                tags=json.loads(token_row["tags"]),
                created_at=token_row["created_at"],
                expires_at=token_row["expires_at"],
                max_uses=token_row["max_uses"],
                use_count=token_row["use_count"],
                revoked=bool(token_row["revoked"]),
            )
            if not token_obj.is_valid():
                raise HTTPException(status_code=403, detail="Registration token expired or exhausted")

            # Consume 1 use
            self._conn.execute(
                "UPDATE fleet_tokens SET use_count = use_count + 1 WHERE token = ?",
                (req.registration_token,),
            )

            # Check if host already enrolled
            existing = self._conn.execute(
                "SELECT endpoint_id FROM fleet_endpoints WHERE host_id = ?", (req.host_id,)
            ).fetchone()

            endpoint_id = existing["endpoint_id"] if existing else f"ep_{secrets.token_hex(12)}"
            raw_auth_token = secrets.token_urlsafe(32)
            token_hash = _hash_token(raw_auth_token)
            now = datetime.now(UTC).isoformat()

            desired_policy_row = self._conn.execute(
                "SELECT value FROM fleet_config WHERE key = 'desired_policy_version'"
            ).fetchone()
            desired_policy = desired_policy_row["value"] if desired_policy_row else "1.0.0"

            if existing:
                self._conn.execute(
                    """UPDATE fleet_endpoints SET
                       hostname = ?, os_name = ?, agent_version = ?, endpoint_group = ?, tags = ?,
                       status = ?, health = ?, last_seen = ?, auth_token_hash = ?, client_cert_fingerprint = ?
                       WHERE endpoint_id = ?""",
                    (
                        req.hostname,
                        req.os_name,
                        req.agent_version,
                        token_obj.endpoint_group,
                        json.dumps(token_obj.tags),
                        EndpointStatus.ONLINE.value,
                        HealthState.HEALTHY.value,
                        now,
                        token_hash,
                        req.client_cert_fingerprint,
                        endpoint_id,
                    ),
                )
            else:
                self._conn.execute(
                    """INSERT INTO fleet_endpoints
                       (endpoint_id, host_id, hostname, os_name, agent_version, endpoint_group, tags,
                        status, health, enrolled_at, last_seen, policy_version, policy_status,
                        auth_token_hash, client_cert_fingerprint, last_heartbeat)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        endpoint_id,
                        req.host_id,
                        req.hostname,
                        req.os_name,
                        req.agent_version,
                        token_obj.endpoint_group,
                        json.dumps(token_obj.tags),
                        EndpointStatus.ONLINE.value,
                        HealthState.HEALTHY.value,
                        now,
                        now,
                        "1.0.0",
                        PolicySyncStatus.PENDING.value,
                        token_hash,
                        req.client_cert_fingerprint,
                        None,
                    ),
                )

        self.log_audit(
            actor,
            "fleet.endpoint_enrolled",
            {"endpoint_id": endpoint_id, "host_id": req.host_id, "group": token_obj.endpoint_group},
        )
        return EnrollmentResponse(
            endpoint_id=endpoint_id,
            auth_token=raw_auth_token,
            assigned_group=token_obj.endpoint_group,
            enrolled_at=now,
            server_version="1.0.0",
            desired_policy_version=desired_policy,
        )

    def authenticate_endpoint(self, endpoint_id: str, auth_token: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT auth_token_hash FROM fleet_endpoints WHERE endpoint_id = ?", (endpoint_id,)
            )
            row = cur.fetchone()
            if not row:
                return False
            expected = row["auth_token_hash"]
            return secrets.compare_digest(_hash_token(auth_token), expected)

    def record_heartbeat(self, req: HeartbeatRequest) -> HeartbeatResponse:
        now = datetime.now(UTC)
        now_str = now.isoformat()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT policy_version, endpoint_group FROM fleet_endpoints WHERE endpoint_id = ?",
                (req.endpoint_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Endpoint not found")

            desired_row = self._conn.execute(
                "SELECT value FROM fleet_config WHERE key = 'desired_policy_version'"
            ).fetchone()
            desired_policy = desired_row["value"] if desired_row else "1.0.0"

            if req.policy_version == desired_policy:
                policy_status = PolicySyncStatus.IN_SYNC
                action_required = None
            else:
                policy_status = PolicySyncStatus.OUTDATED
                action_required = "update_policy"

            hb_payload = {
                "metrics": req.metrics,
                "active_threats": req.active_threats,
                "last_error": req.last_error,
                "received_at": now_str,
            }

            self._conn.execute(
                """UPDATE fleet_endpoints SET
                   agent_version = ?, status = ?, health = ?, last_seen = ?,
                   policy_version = ?, policy_status = ?, last_heartbeat = ?
                   WHERE endpoint_id = ?""",
                (
                    req.agent_version,
                    EndpointStatus.ONLINE.value,
                    req.health.value,
                    now_str,
                    req.policy_version,
                    policy_status.value,
                    json.dumps(hb_payload),
                    req.endpoint_id,
                ),
            )

        return HeartbeatResponse(
            acknowledged=True,
            server_time=now_str,
            policy_status=policy_status,
            desired_policy_version=desired_policy,
            action_required=action_required,
        )

    def list_endpoints(
        self,
        group: str | None = None,
        status: str | None = None,
        health: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
        offline_threshold_seconds: int = 180,
    ) -> list[Endpoint]:
        now = datetime.now(UTC)
        threshold_dt = now - timedelta(seconds=offline_threshold_seconds)
        threshold_str = threshold_dt.isoformat()

        with self._lock, self._conn:
            # Mark endpoints offline if not seen recently
            self._conn.execute(
                "UPDATE fleet_endpoints SET status = ? WHERE last_seen < ? AND status != ?",
                (EndpointStatus.OFFLINE.value, threshold_str, EndpointStatus.OFFLINE.value),
            )

            query = "SELECT * FROM fleet_endpoints WHERE 1=1"
            params: list[Any] = []
            if group:
                query += " AND endpoint_group = ?"
                params.append(group)
            if status:
                query += " AND status = ?"
                params.append(status)
            if health:
                query += " AND health = ?"
                params.append(health)
            if search:
                query += " AND (hostname LIKE ? OR host_id LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])

            query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = self._conn.execute(query, params).fetchall()

        endpoints: list[Endpoint] = []
        for r in rows:
            endpoints.append(
                Endpoint(
                    endpoint_id=r["endpoint_id"],
                    host_id=r["host_id"],
                    hostname=r["hostname"],
                    os_name=r["os_name"],
                    agent_version=r["agent_version"],
                    endpoint_group=r["endpoint_group"],
                    tags=json.loads(r["tags"]),
                    status=EndpointStatus(r["status"]),
                    health=HealthState(r["health"]),
                    enrolled_at=r["enrolled_at"],
                    last_seen=r["last_seen"],
                    policy_version=r["policy_version"],
                    policy_status=PolicySyncStatus(r["policy_status"]),
                    client_cert_fingerprint=r["client_cert_fingerprint"],
                    last_heartbeat=json.loads(r["last_heartbeat"]) if r["last_heartbeat"] else None,
                )
            )
        return endpoints

    def get_endpoint(self, endpoint_id: str) -> Endpoint | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM fleet_endpoints WHERE endpoint_id = ?", (endpoint_id,))
            r = cur.fetchone()
            if not r:
                return None
            return Endpoint(
                endpoint_id=r["endpoint_id"],
                host_id=r["host_id"],
                hostname=r["hostname"],
                os_name=r["os_name"],
                agent_version=r["agent_version"],
                endpoint_group=r["endpoint_group"],
                tags=json.loads(r["tags"]),
                status=EndpointStatus(r["status"]),
                health=HealthState(r["health"]),
                enrolled_at=r["enrolled_at"],
                last_seen=r["last_seen"],
                policy_version=r["policy_version"],
                policy_status=PolicySyncStatus(r["policy_status"]),
                client_cert_fingerprint=r["client_cert_fingerprint"],
                last_heartbeat=json.loads(r["last_heartbeat"]) if r["last_heartbeat"] else None,
            )

    def set_desired_policy_version(self, version: str, actor: str = "admin") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fleet_config (key, value) VALUES ('desired_policy_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (version,),
            )
        self.log_audit(actor, "fleet.policy_version_updated", {"desired_policy_version": version})

    def get_desired_policy_version(self) -> str:
        with self._lock:
            cur = self._conn.execute("SELECT value FROM fleet_config WHERE key = 'desired_policy_version'")
            row = cur.fetchone()
            return row["value"] if row else "1.0.0"


def create_fleet_router(store: FleetStore) -> APIRouter:
    """Build the FastAPI APIRouter for the fleet management plane."""
    router = APIRouter(prefix="/api/fleet", tags=["fleet"])

    @router.post("/tokens", response_model=EnrollmentToken)
    def create_token(body: EnrollmentTokenCreate, request: Request) -> EnrollmentToken:
        return store.create_enrollment_token(
            endpoint_group=body.endpoint_group,
            tags=body.tags,
            expires_in_hours=body.expires_in_hours,
            max_uses=body.max_uses,
            actor="admin",
        )

    @router.post("/enroll", response_model=EnrollmentResponse)
    def enroll(body: EnrollmentRequest) -> EnrollmentResponse:
        return store.enroll_endpoint(body, actor=f"agent:{body.host_id}")

    @router.post("/heartbeat", response_model=HeartbeatResponse)
    def heartbeat(
        body: HeartbeatRequest,
        authorization: str | None = Header(None),
    ) -> HeartbeatResponse:
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
            if not store.authenticate_endpoint(body.endpoint_id, token):
                raise HTTPException(status_code=401, detail="Unauthorized endpoint token")
        return store.record_heartbeat(body)

    @router.get("/endpoints", response_model=list[Endpoint])
    def list_endpoints(
        group: str | None = Query(None),
        status: str | None = Query(None),
        health: str | None = Query(None),
        search: str | None = Query(None),
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> list[Endpoint]:
        return store.list_endpoints(
            group=group, status=status, health=health, search=search, limit=limit, offset=offset
        )

    @router.get("/endpoints/{endpoint_id}", response_model=Endpoint)
    def get_endpoint(endpoint_id: str) -> Endpoint:
        ep = store.get_endpoint(endpoint_id)
        if not ep:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return ep

    @router.get("/endpoints/{endpoint_id}/health")
    def get_endpoint_health(endpoint_id: str) -> dict[str, Any]:
        ep = store.get_endpoint(endpoint_id)
        if not ep:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return {
            "endpoint_id": ep.endpoint_id,
            "status": ep.status.value,
            "health": ep.health.value,
            "last_seen": ep.last_seen,
            "policy_status": ep.policy_status.value,
            "last_heartbeat": ep.last_heartbeat,
        }

    @router.get("/policy-version")
    def get_policy_version() -> dict[str, str]:
        return {"desired_policy_version": store.get_desired_policy_version()}

    @router.post("/policy-version")
    def update_policy_version(version: str = Query(..., min_length=1, max_length=32)) -> dict[str, str]:
        store.set_desired_policy_version(version)
        return {"desired_policy_version": version}

    return router


def create_fleet_app(store: FleetStore | None = None, db_path: str | Path = ":memory:") -> FastAPI:
    """FastAPI application factory for the Centralium fleet server."""
    app_store = store or FleetStore(db_path=db_path)
    app = FastAPI(title="Centralium Fleet Management Server", version="1.0.0")
    app.state.store = app_store
    app.include_router(create_fleet_router(app_store))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
