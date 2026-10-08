# ruff: noqa: B008, E501
"""Attack graph, process explorer, network, malware analysis, hunting and sync ingest."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from centralium.agent.models import Finding, Incident, NormalizedEvent
from dashboard.backend import hunting
from dashboard.backend.context import decode_row, jload, like_escape, table_exists
from dashboard.backend.routes_core import ctx_of
from dashboard.backend.security import Principal, require, require_ingest

router = APIRouter(prefix="/api", tags=["telemetry"])
viewer = Depends(require("viewer"))
ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,100}")

SNAPSHOT_TABLES = ("graph_snapshots", "graph_snapshot")
SNAPSHOT_COLS = ("snapshot", "payload", "data", "graph_json", "graph")


def _snapshot(ctx: Any) -> dict[str, Any] | None:
    """Best-effort read of a graph snapshot table written by the graph module (may not exist)."""
    for t in SNAPSHOT_TABLES:
        if not table_exists(ctx.db, t):
            continue
        cols = [r["name"] for r in ctx.db.query(f"PRAGMA table_info({t})")]  # t is from a constant tuple
        col = next((c for c in SNAPSHOT_COLS if c in cols), None)
        if col is None:
            continue
        order = "rowid"
        row = ctx.db.query_one(f'SELECT "{col}" AS s FROM {t} ORDER BY {order} DESC LIMIT 1')  # noqa: S608
        data = jload(row["s"], None) if row else None
        if (
            isinstance(data, dict)
            and isinstance(data.get("nodes"), list)
            and isinstance(data.get("edges"), list)
            and len(data["nodes"]) > 0
        ):
            return {"nodes": data["nodes"][:2000], "edges": data["edges"][:5000]}
    return None


@router.get("/graph")
def graph(
    request: Request,
    incident_id: str | None = Query(None, max_length=100),
    live: bool = Query(False),
    limit: int = Query(150, ge=10, le=1000),
    _: Principal = viewer,
) -> dict[str, Any]:
    ctx = ctx_of(request)
    if incident_id:
        incident_id = incident_id.strip() or None
    if incident_id is None and not live:
        snap = _snapshot(ctx)
        if snap and snap.get("nodes"):
            return {"source": "snapshot", **snap}
    pids: list[tuple[str, int]] = []
    if incident_id:
        if not ID_RE.fullmatch(incident_id):
            raise HTTPException(422, "invalid incident id")
        inc = ctx.repo.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "incident not found")
        ev_ids = jload(inc["event_ids"], [])[:500]
        if ev_ids:
            rows = ctx.db.query(
                f"SELECT DISTINCT host_id, pid FROM events WHERE pid IS NOT NULL AND event_id IN "  # noqa: S608
                f"({','.join('?' for _ in ev_ids)})",
                ev_ids,
            )
            pids = [(r["host_id"], r["pid"]) for r in rows]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    if incident_id:
        procs = []
        for host, pid in pids[:limit]:
            procs += ctx.db.query(
                "SELECT * FROM processes WHERE host_id = ? AND pid = ? ORDER BY start_time DESC LIMIT 1",
                (host, pid),
            )
    else:
        procs = ctx.db.query("SELECT * FROM processes ORDER BY start_time DESC LIMIT ?", (limit,))
    by_key = {(p["host_id"], p["pid"]): p for p in procs}
    missing_parents = {
        (p["host_id"], p["ppid"])
        for p in procs
        if p["ppid"] is not None and (p["host_id"], p["ppid"]) not in by_key
    }
    if missing_parents:
        for host, ppid in list(missing_parents)[:limit]:
            parent_row = ctx.db.query_one(
                "SELECT * FROM processes WHERE host_id = ? AND pid = ? ORDER BY start_time DESC LIMIT 1",
                (host, ppid),
            )
            if parent_row:
                by_key[(host, ppid)] = parent_row
                procs.append(parent_row)
    for p in procs:
        nid = f"proc:{p['host_id']}:{p['pid']}"
        nodes[nid] = {
            "id": nid,
            "type": "process",
            "label": p["name"] or f"pid {p['pid']}",
            "pid": p["pid"],
            "path": p["executable_path"],
        }
        parent = (p["host_id"], p["ppid"])
        if p["ppid"] is not None and parent in by_key:
            edges.append({"source": f"proc:{p['host_id']}:{p['ppid']}", "target": nid, "type": "spawned"})
    for key in by_key:
        host, pid = key
        for c in ctx.db.query(
            "SELECT destination_ip, destination_port, COUNT(*) n FROM network_connections "
            "WHERE host_id = ? AND pid = ? GROUP BY destination_ip, destination_port LIMIT 10",
            (host, pid),
        ):
            nid = f"net:{c['destination_ip']}:{c['destination_port']}"
            nodes.setdefault(
                nid, {"id": nid, "type": "network", "label": f"{c['destination_ip']}:{c['destination_port']}"}
            )
            edges.append(
                {"source": f"proc:{host}:{pid}", "target": nid, "type": "connected", "count": c["n"]}
            )
    if not incident_id:
        net_rows = ctx.db.query(
            "SELECT host_id, pid, process_name, destination_ip, destination_port, COUNT(*) n "
            "FROM network_connections WHERE destination_ip IS NOT NULL "
            "GROUP BY host_id, pid, destination_ip, destination_port "
            "ORDER BY timestamp DESC LIMIT 50"
        )
        for c in net_rows:
            host = c["host_id"]
            pid = c["pid"]
            if pid is not None:
                pnid = f"proc:{host}:{pid}"
                if pnid not in nodes:
                    nodes[pnid] = {
                        "id": pnid,
                        "type": "process",
                        "label": c["process_name"] or f"pid {pid}",
                        "pid": pid,
                    }
                nid = f"net:{c['destination_ip']}:{c['destination_port']}"
                nodes.setdefault(
                    nid, {"id": nid, "type": "network", "label": f"{c['destination_ip']}:{c['destination_port']}"}
                )
                edges.append(
                    {"source": pnid, "target": nid, "type": "connected", "count": c["n"]}
                )
    seen_edges: set[tuple[str, str, str]] = set()
    dedup_edges = []
    for e in edges:
        k = (str(e.get("source")), str(e.get("target")), str(e.get("type")))
        if k not in seen_edges:
            seen_edges.add(k)
            dedup_edges.append(e)
    edges = dedup_edges
    if not nodes:
        return {"source": "empty", "nodes": [], "edges": []}
    return {"source": "derived", "nodes": list(nodes.values()), "edges": edges}


# ---------------------------------------------------------------- process explorer
@router.get("/processes")
def processes(
    request: Request,
    q: str | None = Query(None, max_length=100),
    host_id: str | None = Query(None, max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _: Principal = viewer,
) -> dict[str, Any]:
    ctx = ctx_of(request)
    where, params = ["1=1"], []
    if host_id:
        where.append("host_id = ?")
        params.append(host_id)
    if q:
        pat = f"%{like_escape(q)}%"
        where.append(
            "(name LIKE ? ESCAPE '\\' OR executable_path LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\')"
        )
        params += [pat, pat, pat]
    cond = " AND ".join(where)
    total = ctx.db.scalar(f"SELECT COUNT(*) FROM processes WHERE {cond}", params)  # noqa: S608
    rows = ctx.db.query(
        f"SELECT p.*, (SELECT COUNT(*) FROM findings f JOIN events e ON e.event_id = f.event_id "  # noqa: S608
        "WHERE e.host_id = p.host_id AND e.pid = p.pid) AS finding_count "
        f"FROM processes p WHERE {cond} "
        "ORDER BY start_time DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    return {"total": int(total or 0), "items": [dict(r) for r in rows]}


# ---------------------------------------------------------------- network
@router.get("/network")
def network(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    _: Principal = viewer,
) -> dict[str, Any]:
    db = ctx_of(request).db
    return {
        "connections": [
            dict(r)
            for r in db.query("SELECT * FROM network_connections ORDER BY timestamp DESC LIMIT ?", (limit,))
        ],
        "dns": [
            dict(r) for r in db.query("SELECT * FROM dns_events ORDER BY timestamp DESC LIMIT ?", (limit,))
        ],
        "top_destinations": [
            dict(r)
            for r in db.query(
                "SELECT destination_ip, destination_port, COUNT(*) n FROM network_connections "
                "GROUP BY destination_ip, destination_port ORDER BY n DESC LIMIT 10"
            )
        ],
        "top_domains": [
            dict(r)
            for r in db.query(
                "SELECT domain, COUNT(*) n, MAX(entropy) max_entropy FROM dns_events GROUP BY domain ORDER BY n DESC LIMIT 10"
            )
        ],
        "totals": {"connections": db.count("network_connections"), "dns": db.count("dns_events")},
    }


# ---------------------------------------------------------------- malware analysis
@router.get("/malware")
def malware(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    _: Principal = viewer,
) -> dict[str, Any]:
    db = ctx_of(request).db
    return {
        "files": [dict(r) for r in db.query("SELECT * FROM files ORDER BY last_seen DESC LIMIT ?", (limit,))],
        "yara": [
            decode_row(r, ("matched_strings",))
            for r in db.query("SELECT * FROM yara_results ORDER BY timestamp DESC LIMIT ?", (limit,))
        ],
        "static_findings": [
            decode_row(r, ("mitre_techniques", "details"))
            for r in db.query(
                "SELECT * FROM findings WHERE source IN ('static','yara','hash','ioc','ransomware') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        ],
        "totals": {
            "files": db.count("files"),
            "yara_matches": db.count("yara_results"),
            "known_malicious_findings": int(
                db.scalar("SELECT COUNT(*) FROM findings WHERE known_malicious=1") or 0
            ),
        },
    }


# ---------------------------------------------------------------- hunting
@router.get("/hunt/schema")
def hunt_schema(_: Principal = Depends(require("analyst"))) -> dict[str, Any]:
    return hunting.describe()


@router.post("/hunt")
def hunt(
    body: hunting.HuntQuery, request: Request, p: Principal = Depends(require("analyst"))
) -> dict[str, Any]:
    ctx = ctx_of(request)
    try:
        sql, params, count_sql, group = hunting.build(body)
    except hunting.HuntError as exc:
        raise HTTPException(422, str(exc)) from exc
    rows = [dict(r) for r in ctx.db.query(sql, params)]
    total = int(ctx.db.scalar(count_sql, params[:-2]) or 0)
    ctx.audit(p, "dashboard.hunt", {"source": body.source, "filters": len(body.filters), "count_by": group})
    return {"total": total, "grouped_by": group, "items": rows}


class NLHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)


@router.post("/hunt/nl")
def hunt_nl(
    body: NLHuntRequest, request: Request, _: Principal = Depends(require("analyst"))
) -> dict[str, Any]:
    from dashboard.backend import nl_hunt

    try:
        res = nl_hunt.translate_nl_to_hunt(body.question)
    except nl_hunt.RawCommandOrSQLError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return res.model_dump()


class CopilotChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=1000)


@router.post("/copilot/chat")
def copilot_chat(
    body: CopilotChatRequest, request: Request, _: Principal = Depends(require("analyst"))
) -> dict[str, Any]:
    from dashboard.backend import copilot

    ctx = ctx_of(request)
    try:
        resp = copilot.run_copilot_investigation(body.incident_id, body.question, ctx.db)
        return resp.model_dump()
    except copilot.CopilotToolSecurityError as exc:
        raise HTTPException(403, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"Copilot investigation failed: {exc}") from exc


# ---------------------------------------------------------------- sync ingest
class IngestBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    host_id: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


def _unwrap(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Accept both a bare record and the agent sync envelope
    ``{"queue_id", "dedup_key", "payload": {"type": event|finding|incident, "data": {...}}}``."""
    if "payload" in item and isinstance(item["payload"], dict):
        pl = item["payload"]
        if isinstance(pl.get("data"), dict) and isinstance(pl.get("type"), str):
            return pl["type"], pl["data"]
        return "event", pl
    return "event", item


@router.post("/ingest")
def ingest(batch: IngestBatch, request: Request, p: Principal = Depends(require_ingest)) -> dict[str, Any]:
    """Accept queued telemetry from an agent. Every record is validated with the agent's own
    Pydantic models; invalid records are rejected individually and reported (never stored)."""
    ctx = ctx_of(request)
    agent = batch.agent_id or batch.host_id
    if not agent:
        raise HTTPException(422, "agent_id or host_id is required")
    accepted_e = accepted_f = 0
    errors: list[dict[str, Any]] = []
    for i, raw in enumerate(batch.events):
        try:
            kind, data = _unwrap(raw)
            if kind == "finding":
                ctx.repo.add_finding(Finding.model_validate(data))
                accepted_f += 1
            elif kind == "incident":
                ctx.repo.save_incident(Incident.model_validate(data))
                accepted_e += 1
            elif kind == "event":
                ctx.repo.add_event(NormalizedEvent.model_validate(data))
                accepted_e += 1
            else:
                raise ValueError(f"unknown record type {kind!r}")
        except (ValidationError, ValueError) as exc:
            errors.append({"kind": "event", "index": i, "error": str(exc)[:200]})
    for i, raw in enumerate(batch.findings):
        try:
            ctx.repo.add_finding(Finding.model_validate(raw))
            accepted_f += 1
        except (ValidationError, ValueError) as exc:
            errors.append({"kind": "finding", "index": i, "error": str(exc)[:200]})
    ctx.audit(
        p,
        "dashboard.ingest",
        {"agent_id": agent, "events": accepted_e, "findings": accepted_f, "rejected": len(errors)},
    )
    return {
        "accepted_events": accepted_e,
        "accepted_findings": accepted_f,
        "rejected": len(errors),
        "errors": errors[:20],
    }
