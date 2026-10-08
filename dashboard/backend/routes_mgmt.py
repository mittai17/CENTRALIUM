# ruff: noqa: B008, E501
"""Response center (approval queue only), policies, lists, RAG, ML analytics, audit."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from centralium.agent.models import DESTRUCTIVE_ACTIONS, ActionStatus, ResponseAction
from centralium.agent.storage.repositories import LIST_KINDS
from dashboard.backend import mlreports
from dashboard.backend.context import decode_row, jload, like_escape
from dashboard.backend.rbac import validate_two_person_approval
from dashboard.backend.routes_core import ai_backend, ctx_of
from dashboard.backend.security import Principal, require

router = APIRouter(prefix="/api", tags=["management"])
viewer = Depends(require("viewer"))
analyst = Depends(require("analyst"))
admin = Depends(require("admin"))
ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,100}")


# ---------------------------------------------------------------- response center
@router.get("/response/actions")
def list_actions(
    request: Request,
    status: str | None = Query(None, pattern=r"^[a-z_]{3,20}$"),
    limit: int = Query(100, ge=1, le=500),
    _: Principal = viewer,
) -> dict[str, Any]:
    ctx = ctx_of(request)
    if status:
        rows = ctx.db.query(
            "SELECT * FROM response_actions WHERE status = ? ORDER BY timestamp DESC LIMIT ?", (status, limit)
        )
    else:
        rows = ctx.db.query("SELECT * FROM response_actions ORDER BY timestamp DESC LIMIT ?", (limit,))
    pending = int(
        ctx.db.scalar("SELECT COUNT(*) FROM response_actions WHERE status = 'pending_approval'") or 0
    )
    return {
        "items": [decode_row(r, ("target",)) for r in rows],
        "pending_approval": pending,
        "destructive_allowed": ctx.config.destructive_allowed(),
        "mode": ctx.config.mode.value,
        "note": "The dashboard never executes actions. Approved requests are picked up by the agent's executor.",
    }


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: ResponseAction
    target: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=500)
    incident_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    event_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,100}$")

    @field_validator("target")
    @classmethod
    def _size(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 5:
            raise ValueError("too many target fields")
        return v


def validate_target(action: ResponseAction, target: dict[str, Any]) -> dict[str, Any]:
    """Strict, per-action target validation (re-validated again by the agent executor)."""

    def only(*keys: str) -> None:
        extra = set(target) - set(keys)
        if extra:
            raise ValueError(f"unexpected target field(s): {sorted(extra)}")

    if action == ResponseAction.ALERT:
        only("message")
        return {k: str(v)[:300] for k, v in target.items()}
    if action in (ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS):
        only("pid")
        pid = target.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or not 2 <= pid <= 4_194_304:
            raise ValueError("pid must be an integer between 2 and 4194304")
        return {"pid": pid}
    if action == ResponseAction.QUARANTINE_FILE:
        only("path")
        path = target.get("path")
        if not isinstance(path, str) or not path or len(path) > 4096 or "\x00" in path:
            raise ValueError("path must be a non-empty string")
        if not (path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path)):
            raise ValueError("path must be absolute")
        if ".." in re.split(r"[\\/]", path):
            raise ValueError("path must not contain '..'")
        return {"path": os.path.normpath(path) if path.startswith("/") else path}
    if action == ResponseAction.BLOCK_CONNECTION:
        only("ip", "port")
        try:
            ip = ipaddress.ip_address(str(target.get("ip", "")))
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4/IPv6 address") from exc
        if ip.is_unspecified or ip.is_multicast:
            raise ValueError("ip is not a routable unicast address")
        port = target.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer 1-65535")
        return {"ip": str(ip), "port": port}
    only("host_id")
    host = target.get("host_id")
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", host):
        raise ValueError("host_id is required for ISOLATE_ENDPOINT")
    return {"host_id": host}


@router.post("/response/requests", status_code=202)
def request_action(body: ActionRequest, request: Request, p: Principal = analyst) -> dict[str, Any]:
    """Queue an action for approval. Nothing is executed here."""
    ctx = ctx_of(request)
    try:
        target = validate_target(body.action, body.target)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    from centralium.agent.models import ActionResult

    result = ActionResult(
        action=body.action,
        status=ActionStatus.PENDING_APPROVAL,
        target=target,
        detail=f"requested via dashboard by {p.ident}: {body.reason}",
        event_id=body.event_id,
        incident_id=body.incident_id,
    )
    ctx.repo.add_action(result)
    ctx.audit(
        p,
        "dashboard.action_requested",
        {"action_id": result.action_id, "action": body.action.value, "target": target},
    )
    return {"action_id": result.action_id, "status": result.status.value, "executed": False}


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "deny"]
    note: str = Field(default="", max_length=300)


@router.post("/response/actions/{action_id}/decision")
def decide(action_id: str, body: Decision, request: Request, p: Principal = admin) -> dict[str, Any]:
    if not ID_RE.fullmatch(action_id):
        raise HTTPException(422, "invalid action id")
    ctx = ctx_of(request)
    row = ctx.db.query_one("SELECT * FROM response_actions WHERE action_id = ?", (action_id,))
    if row is None:
        raise HTTPException(404, "action not found")
    if row["status"] != ActionStatus.PENDING_APPROVAL.value:
        raise HTTPException(409, f"action is {row['status']}, not pending_approval")
    if body.decision == "approve":
        if ResponseAction(row["action"]) in DESTRUCTIVE_ACTIONS and not ctx.config.destructive_allowed():
            raise HTTPException(
                409, "destructive actions are disabled in the current mode (demo/test/learning)"
            )
        validate_two_person_approval(row, p, mode=ctx.config.mode.value)
    new = ActionStatus.APPROVED if body.decision == "approve" else ActionStatus.DENIED
    ctx.db.execute(
        "UPDATE response_actions SET status = ?, detail = ? WHERE action_id = ? AND status = 'pending_approval'",
        (new.value, f"{row['detail'] or ''} | {new.value} by {p.ident}: {body.note}"[:1000], action_id),
    )
    ctx.audit(p, f"dashboard.action_{new.value}", {"action_id": action_id, "note": body.note})
    return {"action_id": action_id, "status": new.value, "executed": False}


# ---------------------------------------------------------------- policies & lists
@router.get("/policies")
def policies(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    c = ctx.config.policy
    return {
        "stored": [
            decode_row(r, ("body",)) for r in ctx.db.query("SELECT * FROM policies ORDER BY name LIMIT 500")
        ],
        "effective": {
            "require_approval": c.require_approval,
            "min_confidence_destructive": c.min_confidence_destructive,
            "min_risk_destructive": c.min_risk_destructive,
            "passive_destructive_allowed": c.passive_destructive_allowed,
            "allowed_actions": [a.value for a in c.allowed_actions],
            "protected_processes": list(c.protected_processes),
            "protected_paths": list(c.protected_paths),
        },
        "allowlist": [
            dict(r) for r in ctx.db.query("SELECT * FROM allowlist ORDER BY added_at DESC LIMIT 500")
        ],
        "blocklist": [
            dict(r) for r in ctx.db.query("SELECT * FROM blocklist ORDER BY added_at DESC LIMIT 500")
        ],
        "list_kinds": sorted(LIST_KINDS),
    }


class ListEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["sha256", "path", "process", "ip", "domain", "signer", "parent_child"]
    value: str = Field(min_length=1, max_length=1000)
    reason: str = Field(min_length=3, max_length=300)

    @field_validator("value")
    @classmethod
    def _v(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("invalid value")
        return v


@router.post("/lists/{which}", status_code=201)
def add_list_entry(
    which: Literal["allowlist", "blocklist"], body: ListEntry, request: Request, p: Principal = admin
) -> dict[str, Any]:
    ctx = ctx_of(request)
    v = body.value
    try:
        if body.kind == "sha256" and not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("sha256 must be 64 hex characters")
        if body.kind == "ip":
            ipaddress.ip_address(v)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    add = ctx.repo.add_allowlist if which == "allowlist" else ctx.repo.add_blocklist
    add(body.kind, v, reason=body.reason, added_by=p.ident)
    ctx.audit(p, f"dashboard.{which}_add", {"kind": body.kind, "value": v[:200], "reason": body.reason})
    return {"ok": True}


class PolicyToggle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


@router.patch("/policies/{policy_id}")
def toggle_policy(
    policy_id: str, body: PolicyToggle, request: Request, p: Principal = admin
) -> dict[str, Any]:
    if not ID_RE.fullmatch(policy_id):
        raise HTTPException(422, "invalid policy id")
    ctx = ctx_of(request)
    n = ctx.db.execute("UPDATE policies SET enabled = ? WHERE policy_id = ?", (int(body.enabled), policy_id))
    if n == 0:
        raise HTTPException(404, "policy not found")
    ctx.audit(p, "dashboard.policy_toggle", {"policy_id": policy_id, "enabled": body.enabled})
    return {"policy_id": policy_id, "enabled": body.enabled}


# ---------------------------------------------------------------- RAG
@router.get("/rag")
def rag(
    request: Request,
    q: str | None = Query(None, max_length=100),
    source: str | None = Query(None, pattern=r"^[A-Za-z0-9_.-]{1,40}$"),
    limit: int = Query(100, ge=1, le=500),
    _: Principal = viewer,
) -> dict[str, Any]:
    ctx = ctx_of(request)
    where, params = ["1=1"], []
    if source:
        where.append("source = ?")
        params.append(source)
    if q:
        where.append("(title LIKE ? ESCAPE '\\' OR doc_id LIKE ? ESCAPE '\\')")
        pat = f"%{like_escape(q)}%"
        params += [pat, pat]
    cond = " AND ".join(where)
    rows = ctx.db.query(
        f"SELECT * FROM rag_metadata WHERE {cond} ORDER BY ingested_at DESC LIMIT ?",  # noqa: S608
        [*params, limit],
    )
    used: dict[str, int] = {}
    for r in ctx.db.query("SELECT rag_sources FROM ai_analysis ORDER BY timestamp DESC LIMIT 500"):
        for s in jload(r["rag_sources"], []):
            if isinstance(s, str):
                used[s] = used.get(s, 0) + 1
    return {
        "documents": [decode_row(r, ("metadata",)) for r in rows],
        "by_source": [
            dict(r)
            for r in ctx.db.query(
                "SELECT source, COUNT(*) n FROM rag_metadata GROUP BY source ORDER BY n DESC"
            )
        ],
        "total": ctx.db.count("rag_metadata"),
        "most_cited": [
            {"source": k, "count": v} for k, v in sorted(used.items(), key=lambda kv: -kv[1])[:10]
        ],
    }


# ---------------------------------------------------------------- ML analytics
@router.get("/ml")
def ml_analytics(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    db = ctx.db
    n = db.count("ml_results")
    runtime: dict[str, Any] = {"results": n}
    if n:
        bins = [0] * 10
        for r in db.query("SELECT anomaly_score FROM ml_results WHERE anomaly_score IS NOT NULL"):
            bins[min(9, max(0, int(r["anomaly_score"] * 10)))] += 1
        runtime["anomaly_histogram"] = {
            "bins": [f"{i / 10:.1f}-{(i + 1) / 10:.1f}" for i in range(10)],
            "counts": bins,
        }
        runtime["classification_distribution"] = [
            dict(r)
            for r in db.query(
                "SELECT classification, COUNT(*) n FROM ml_results GROUP BY classification ORDER BY n DESC"
            )
        ]
        feats: dict[str, list[float]] = {}
        for r in db.query("SELECT top_features FROM ml_results ORDER BY timestamp DESC LIMIT 500"):
            for item in jload(r["top_features"], []):
                if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
                    try:
                        feats.setdefault(item[0], []).append(abs(float(item[1])))
                    except (TypeError, ValueError):
                        continue
        ranked = sorted(feats.items(), key=lambda kv: -(sum(kv[1]) / len(kv[1])))[:15]
        runtime["top_features"] = [
            {"feature": k, "mean_abs_importance": sum(v) / len(v), "occurrences": len(v)} for k, v in ranked
        ]
        lat = db.query_one("SELECT AVG(latency_ms) avg, MAX(latency_ms) mx FROM ml_results")
        runtime["latency_ms"] = {"avg": lat["avg"], "max": lat["mx"]} if lat else None
        ver = db.query_one(
            "SELECT model_version, feature_version FROM ml_results ORDER BY timestamp DESC LIMIT 1"
        )
        runtime["model_version"] = ver["model_version"] if ver else None
        runtime["feature_version"] = ver["feature_version"] if ver else None
    return {
        "runtime": runtime,
        "evaluation": mlreports.load_report(ctx.ml_dir),
        "ai": ai_backend(ctx),
        "note": "Evaluation metrics come only from validated reports under ml/. Runtime stats are measured from stored results.",
    }


# ---------------------------------------------------------------- audit
@router.get("/audit")
def audit_entries(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _: Principal = Depends(require("analyst")),
) -> dict[str, Any]:
    db = ctx_of(request).db
    seq, head = db.audit.head()
    return {"total": seq, "head": {"seq": seq, "hash": head}, "items": db.audit.entries(limit, offset)}


@router.get("/audit/verify")
def audit_verify(
    request: Request,
    expected_head: str | None = Query(None, pattern=r"^[0-9a-f]{64}$"),
    p: Principal = Depends(require("analyst")),
) -> dict[str, Any]:
    ctx = ctx_of(request)
    v = ctx.db.audit.verify(expected_head)
    ctx.audit(p, "dashboard.audit_verify", {"ok": v.ok, "entries": v.entries})
    return {"ok": v.ok, "entries": v.entries, "first_bad_seq": v.first_bad_seq, "reason": v.reason}
