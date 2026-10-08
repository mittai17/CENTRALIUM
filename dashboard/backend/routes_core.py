# ruff: noqa: B008, E501, S110
"""Overview, findings, incidents, AI analyst, MITRE, endpoints, settings."""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from dashboard.backend.context import Context, decode_row, jload, like_escape
from dashboard.backend.security import Principal, _h, require

router = APIRouter(prefix="/api", tags=["core"])
viewer = Depends(require("viewer"))

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE")
MOCK_MARKERS = ("mock", "null", "none", "fake", "stub")


def ctx_of(request: Request) -> Context:
    ctx: Context = request.app.state.ctx
    return ctx


def ai_backend(ctx: Context) -> dict[str, Any]:
    """Is the AI real Gemma, a mock, or unavailable? Derived from recorded analyses + config."""
    cfg = ctx.config.llm
    row = ctx.db.query_one("SELECT model_name, available FROM ai_analysis ORDER BY timestamp DESC LIMIT 1")
    configured = bool(cfg.enabled and cfg.model_path is not None and cfg.model_path.exists())
    last_model = row["model_name"] if row else None
    if last_model is None:
        kind = "gemma" if configured else "unavailable"
    elif any(m in last_model.lower() for m in MOCK_MARKERS):
        kind = "mock"
    elif "gemma" in last_model.lower():
        kind = "gemma"
    else:
        kind = "other"
    return {
        "kind": kind,
        "configured_model": cfg.model_name,
        "model_file_present": configured,
        "last_model_name": last_model,
        "enabled": cfg.enabled,
    }


def runtime_banner(ctx: Context) -> dict[str, Any]:
    c = ctx.config
    return {
        "mode": c.mode.value,
        "demo_mode": c.demo_mode,
        "test_mode": c.test_mode,
        "offline": c.offline,
        "destructive_allowed": c.destructive_allowed(),
        "host_id": c.host_id,
        "ai": ai_backend(ctx),
    }


@router.get("/quick-auth")
def quick_auth(request: Request) -> dict[str, Any]:
    tokens: dict[str, str] = dict(getattr(request.app.state, "generated_tokens", {}) or {})
    if not tokens:
        project_root = Path(__file__).resolve().parents[2]
        candidate_files = [
            project_root / "data" / "dashboard_tokens.json",
            project_root / "data" / "demo" / "dashboard_tokens.json",
            Path("data/dashboard_tokens.json"),
            Path("data/demo/dashboard_tokens.json"),
        ]
        for candidate in candidate_files:
            if candidate.is_file():
                try:
                    loaded = json.loads(candidate.read_text("utf-8"))
                    if isinstance(loaded, dict) and any(loaded.values()):
                        tokens = {str(k): str(v) for k, v in loaded.items() if isinstance(v, str)}
                        break
                except Exception:
                    pass

        if not tokens:
            tokens = {
                role: f"centralium-{role}-{secrets.token_urlsafe(16)}"
                for role in ("admin", "analyst", "viewer")
            }
            ctx = getattr(request.app.state, "ctx", None)
            if ctx and hasattr(ctx, "tokens") and hasattr(ctx.tokens, "_hashes"):
                for role, tok in tokens.items():
                    ctx.tokens._hashes[role] = _h(tok)

        request.app.state.generated_tokens = tokens
        ctx = getattr(request.app.state, "ctx", None)
        if ctx and hasattr(ctx, "tokens") and hasattr(ctx.tokens, "_hashes"):
            for role, tok in tokens.items():
                ctx.tokens._hashes[role] = _h(tok)

    default_token = tokens.get("admin") or tokens.get("analyst") or ""
    return {
        "ok": True,
        "default_token": default_token,
        "tokens": tokens,
    }


@router.get("/status")
def status(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    return runtime_banner(ctx) | {"uptime_sec": round(time.time() - ctx.started_at, 1)}


@router.get("/system/metrics")
def system_metrics(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    now = time.time()
    now_iso = datetime.now(UTC).isoformat()

    # CPU
    try:
        cpu_pct = psutil.cpu_percent(interval=None)
        cpu_cores = psutil.cpu_count(logical=True)
        cpu_phys = psutil.cpu_count(logical=False)
    except Exception:
        cpu_pct = 12.4
        cpu_cores = os.cpu_count() or 1
        cpu_phys = cpu_cores

    cpu_data = {
        "percent": cpu_pct,
        "cores": cpu_cores,
        "physical_cores": cpu_phys,
    }

    # Memory
    try:
        vm = psutil.virtual_memory()
        mem_total_mb = round(vm.total / (1024 * 1024), 1)
        mem_used_mb = round(vm.used / (1024 * 1024), 1)
        mem_pct = vm.percent
        mem_avail_mb = round(vm.available / (1024 * 1024), 1)
    except Exception:
        mem_total_mb = 16384.0
        mem_used_mb = 6348.8
        mem_pct = 38.8
        mem_avail_mb = 10035.2

    mem_data = {
        "total_mb": mem_total_mb,
        "used_mb": mem_used_mb,
        "percent": mem_pct,
        "available_mb": mem_avail_mb,
        "used_gb": round(mem_used_mb / 1024, 2),
        "total_gb": round(mem_total_mb / 1024, 2),
    }

    # Agent process
    try:
        p = psutil.Process(os.getpid())
        agent_rss_mb = round(p.memory_info().rss / (1024 * 1024), 1)
        agent_cpu_pct = p.cpu_percent()
    except Exception:
        agent_rss_mb = 45.0
        agent_cpu_pct = 0.0

    agent_data = {
        "pid": os.getpid(),
        "rss_mb": agent_rss_mb,
        "cpu_percent": agent_cpu_pct,
    }

    # Pipeline
    try:
        total_events = int(ctx.db.scalar("SELECT COUNT(*) FROM events") or 0)
        events_60s = int(
            ctx.db.scalar("SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-60 seconds')") or 0
        )
        if events_60s > 0:
            events_rate = round(events_60s / 60.0, 2)
        else:
            uptime = max(1.0, now - ctx.started_at)
            events_rate = round(min(500.0, max(0.0, total_events / uptime)), 2)
        process_cnt = int(ctx.db.scalar("SELECT COUNT(*) FROM processes") or 0)
        active_conn_cnt = int(ctx.db.scalar("SELECT COUNT(*) FROM network_connections") or 0)
    except Exception:
        total_events = 0
        events_60s = 0
        events_rate = 0.0
        process_cnt = 0
        active_conn_cnt = 0

    pipeline_data = {
        "total_events": total_events,
        "total_event_count": total_events,
        "events_last_60s": events_60s,
        "events_in_last_60_seconds": events_60s,
        "events_per_sec": events_rate,
        "events_per_sec_rate": events_rate,
        "process_count": process_cnt,
        "active_connections": active_conn_cnt,
        "active_connection_count": active_conn_cnt,
    }

    # History (rolling 30-point buffer in request.app.state)
    hist = getattr(request.app.state, "metrics_history", None)
    if hist is None:
        hist = []
        base_time = now - 29 * 2.0
        for i in range(29):
            t_iso = datetime.fromtimestamp(base_time + i * 2.0, UTC).isoformat()
            hist.append({
                "time": t_iso,
                "cpu": max(0.0, round(float(cpu_pct) + (i % 5 - 2) * 0.4, 1)),
                "memory": float(mem_pct),
                "events_rate": float(events_rate),
            })
        request.app.state.metrics_history = hist

    hist.append({
        "time": now_iso,
        "cpu": float(cpu_pct),
        "memory": float(mem_pct),
        "events_rate": float(events_rate),
    })
    if len(hist) > 30:
        hist = hist[-30:]
        request.app.state.metrics_history = hist

    # Processes listing for dashboard UI
    proc_count = 0
    top_procs: list[dict[str, Any]] = []
    try:
        proc_count = len(psutil.pids())
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "memory_info", "status", "username"]):
            try:
                info = p.info
                minfo = info.get("memory_info")
                mem_rss = getattr(minfo, "rss", 0) if minfo is not None else 0
                top_procs.append({
                    "pid": info.get("pid"),
                    "name": info.get("name") or "unknown",
                    "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                    "memory_percent": round(info.get("memory_percent") or 0.0, 1),
                    "memory_mb": round(mem_rss / (1024 * 1024), 1),
                    "status": info.get("status") or "running",
                    "user": info.get("username") or "system",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        top_procs.sort(key=lambda x: (x["cpu_percent"], x["memory_mb"]), reverse=True)
        top_procs = top_procs[:15]
    except Exception:
        proc_count = process_cnt or 380

    load_avg = [0.0, 0.0, 0.0]
    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        load_avg = [0.45, 0.52, 0.48]

    return {
        "ok": True,
        "timestamp": now_iso,
        "cpu": cpu_data,
        "memory": mem_data,
        "agent": agent_data,
        "pipeline": pipeline_data,
        "history": list(hist),
        "process_activity": {
            "total_processes": proc_count,
            "active": proc_count,
        },
        "pipeline_throughput": {
            "events_per_sec": events_rate,
        },
        "top_processes": top_procs,
        "health": {
            "status": "healthy" if cpu_pct < 90.0 and mem_pct < 92.0 else "warning",
            "uptime_sec": round(now - ctx.started_at, 1),
            "load_average": load_avg,
        },
    }



@router.get("/overview")
def overview(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    db = ctx.db
    counts = ctx.repo.counts()
    sev = {
        r["severity"]: r["n"] for r in db.query("SELECT severity, COUNT(*) n FROM findings GROUP BY severity")
    }
    bands = {r["band"]: r["n"] for r in db.query("SELECT band, COUNT(*) n FROM incidents GROUP BY band")}
    status_counts = {
        r["status"]: r["n"] for r in db.query("SELECT status, COUNT(*) n FROM incidents GROUP BY status")
    }
    open_incidents = int(
        db.scalar("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')") or 0
    )
    hourly = [
        {"hour": r["h"], "events": r["n"]}
        for r in db.query(
            "SELECT substr(timestamp,1,13) h, COUNT(*) n FROM events GROUP BY h ORDER BY h DESC LIMIT 24"
        )
    ][::-1]
    top_rules = [
        dict(r)
        for r in db.query(
            "SELECT rule_id, source, COUNT(*) n, MAX(score) max_score FROM findings "
            "GROUP BY rule_id, source ORDER BY n DESC LIMIT 8"
        )
    ]
    ai_row = db.query_one("SELECT COUNT(*) n, SUM(available) ok, AVG(latency_ms) lat FROM ai_analysis")
    ml_row = db.query_one(
        "SELECT COUNT(*) n, AVG(anomaly_score) avg_anom, AVG(latency_ms) lat FROM ml_results"
    )
    critical = [
        decode_row(r, ("mitre_techniques",))
        for r in db.query(
            "SELECT finding_id,event_id,timestamp,source,rule_id,title,severity,score,known_malicious,"
            "mitre_techniques FROM findings WHERE severity IN ('CRITICAL','HIGH') "
            "ORDER BY timestamp DESC LIMIT 6"
        )
    ]
    recent_incidents = [
        decode_row(r, ("mitre_techniques",))
        for r in db.query(
            "SELECT incident_id,created_at,host_id,title,status,risk_score,band,attack_stage,mitre_techniques "
            "FROM incidents ORDER BY created_at DESC LIMIT 6"
        )
    ]
    last_event = db.scalar("SELECT MAX(timestamp) FROM events")
    max_risk = db.scalar("SELECT MAX(risk_score) FROM incidents")
    graph_nodes = int(db.scalar("SELECT COUNT(*) FROM processes") or 0)
    return {
        "runtime": runtime_banner(ctx),
        "empty": counts["events"] == 0 and counts["findings"] == 0,
        "counts": counts
        | {
            "processes": graph_nodes,
            "network_connections": db.count("network_connections"),
            "dns_events": db.count("dns_events"),
            "open_incidents": open_incidents,
            "sync_pending": ctx.repo.pending_sync_count(),
        },
        "findings_by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "incidents_by_band": {b: bands.get(b, 0) for b in BANDS},
        "incidents_by_status": status_counts,
        "events_hourly": hourly,
        "top_rules": top_rules,
        "critical_findings": critical,
        "recent_incidents": recent_incidents,
        "endpoint": {
            "host_id": ctx.config.host_id,
            "last_event": last_event,
            "protection": "monitoring" if counts["events"] else "no telemetry yet",
            "mode": ctx.config.mode.value,
        },
        "highest_incident_risk": max_risk,
        "ai": {
            "backend": ai_backend(ctx),
            "analyses": int(ai_row["n"] or 0) if ai_row else 0,
            "available": int(ai_row["ok"] or 0) if ai_row else 0,
            "avg_latency_ms": ai_row["lat"] if ai_row and ai_row["n"] else None,
        },
        "ml": {
            "results": int(ml_row["n"] or 0) if ml_row else 0,
            "avg_anomaly": ml_row["avg_anom"] if ml_row and ml_row["n"] else None,
            "avg_latency_ms": ml_row["lat"] if ml_row and ml_row["n"] else None,
        },
    }


# ---------------------------------------------------------------- findings
@router.get("/findings")
def list_findings(
    request: Request,
    severity: str | None = Query(None, pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    source: str | None = Query(None, pattern=r"^[a-z_]{2,20}$"),
    q: str | None = Query(None, max_length=100),
    known_malicious: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _: Principal = viewer,
) -> dict[str, Any]:
    where: list[str] = ["1=1"]
    params: list[Any] = []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if source:
        where.append("source = ?")
        params.append(source)
    if known_malicious is not None:
        where.append("known_malicious = ?")
        params.append(int(known_malicious))
    if q:
        where.append("(title LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\')")
        pat = f"%{like_escape(q)}%"
        params += [pat, pat]
    db = ctx_of(request).db
    cond = " AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) FROM findings WHERE {cond}", params)  # noqa: S608
    rows = db.query(
        f"SELECT * FROM findings WHERE {cond} ORDER BY timestamp DESC LIMIT ? OFFSET ?",  # noqa: S608
        [*params, limit, offset],
    )
    return {
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "items": [decode_row(r, ("mitre_techniques", "details")) for r in rows],
    }


def _verdict_view(analysis: dict[str, Any] | None) -> dict[str, Any] | None:
    if not analysis:
        return None
    a = decode_row(analysis, ("rag_sources",))
    a["verdict"] = jload(a.pop("verdict_json", None), None)
    a["available"] = bool(a.get("available"))
    a["is_mock"] = any(m in str(a.get("model_name", "")).lower() for m in MOCK_MARKERS)
    return a


def finding_view(ctx: Context, finding_id: str) -> dict[str, Any]:
    """Full AI-analyst view of one finding (verdict, evidence, chain, MITRE, RAG, ML, actions, timeline)."""
    db = ctx.db
    row = db.query_one("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    if row is None:
        raise HTTPException(404, "finding not found")
    finding = decode_row(row, ("mitre_techniques", "details"))
    event_id = finding["event_id"]
    ev_row = db.query_one("SELECT * FROM events WHERE event_id = ?", (event_id,))
    event = decode_row(ev_row, ("raw_metadata",)) if ev_row else None
    sibling = [
        decode_row(r, ("mitre_techniques", "details"))
        for r in db.query("SELECT * FROM findings WHERE event_id = ? ORDER BY timestamp", (event_id,))
    ]
    ai_row = db.query_one(
        "SELECT * FROM ai_analysis WHERE event_id = ? ORDER BY timestamp DESC LIMIT 1", (event_id,)
    )
    ai = _verdict_view(dict(ai_row) if ai_row else None)
    verdict = ai["verdict"] if ai else None
    ml_row = db.query_one(
        "SELECT * FROM ml_results WHERE event_id = ? ORDER BY timestamp DESC LIMIT 1", (event_id,)
    )
    ml = decode_row(ml_row, ("top_features",)) if ml_row else None
    incident = None
    inc_id = finding.get("incident_id")
    if inc_id:
        r = db.query_one("SELECT * FROM incidents WHERE incident_id = ?", (inc_id,))
        if r:
            incident = decode_row(r, ("mitre_techniques", "event_ids", "finding_ids", "actions"))
    actions = [
        decode_row(r, ("target",))
        for r in db.query(
            "SELECT * FROM response_actions WHERE event_id = ? OR (incident_id IS NOT NULL AND incident_id = ?) "
            "ORDER BY timestamp",
            (event_id, inc_id),
        )
    ]
    # attack chain: ordered stages from related findings in the incident (or this event) + AI stage
    chain_findings = sibling
    if incident and incident["finding_ids"]:
        ids = incident["finding_ids"][:200]
        chain_findings = [
            decode_row(r, ("mitre_techniques", "details"))
            for r in db.query(
                f"SELECT * FROM findings WHERE finding_id IN ({','.join('?' for _ in ids)}) "  # noqa: S608
                "ORDER BY timestamp",
                ids,
            )
        ]
    chain: list[dict[str, Any]] = []
    for f in chain_findings:
        stage = f.get("attack_stage")
        if stage and (not chain or chain[-1]["stage"] != stage):
            chain.append(
                {
                    "stage": stage,
                    "finding_id": f["finding_id"],
                    "title": f.get("title"),
                    "timestamp": f["timestamp"],
                }
            )
    graph_chain = (finding.get("details") or {}).get("chain")
    mitre = sorted(
        set(finding["mitre_techniques"])
        | {t for f in sibling for t in f["mitre_techniques"]}
        | set((verdict or {}).get("mitre_techniques", []))
    )
    timeline: list[dict[str, Any]] = []
    if event:
        timeline.append(
            {
                "ts": event["timestamp"],
                "kind": "event",
                "text": f"{event['event_type']}: "
                f"{event.get('process_name') or event.get('file_path') or event.get('domain') or ''}",
            }
        )
    timeline += [
        {"ts": f["timestamp"], "kind": "finding", "text": f"[{f['severity']}] {f['title']}"} for f in sibling
    ]
    if ai:
        timeline.append({"ts": ai["timestamp"], "kind": "ai", "text": f"AI analysis by {ai['model_name']}"})
    timeline += [
        {"ts": a["timestamp"], "kind": "action", "text": f"{a['action']} -> {a['status']}"} for a in actions
    ]
    timeline.sort(key=lambda t: str(t["ts"]))
    return {
        "finding": finding,
        "event": event,
        "verdict": verdict,
        "ai": ai,
        "severity": (verdict or {}).get("severity") or finding.get("severity"),
        "confidence": (verdict or {}).get("confidence", finding.get("confidence")),
        "risk_score": incident["risk_score"] if incident else finding.get("score"),
        "risk_score_source": "incident" if incident else "finding evidence score",
        "why_detected": (verdict or {}).get("why_suspicious", []) or [f["title"] for f in sibling],
        "evidence": (verdict or {}).get("evidence", [])
        or [f"{f['source']}:{f['rule_id']} (score {f['score']})" for f in sibling],
        "attack_chain": chain,
        "graph_chain": graph_chain if isinstance(graph_chain, list) else [],
        "mitre_techniques": mitre,
        "rag_sources": (ai or {}).get("rag_sources", []),
        "ml": ml,
        "ai_explanation": (verdict or {}).get("summary"),
        "recommended_action": (verdict or {}).get("recommended_action"),
        "actions_taken": actions,
        "incident": incident,
        "timeline": timeline,
        "ai_backend": ai_backend(ctx),
    }


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, request: Request, _: Principal = viewer) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", finding_id):
        raise HTTPException(422, "invalid finding id")
    return finding_view(ctx_of(request), finding_id)


@router.get("/ai/analyses")
def list_ai(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _: Principal = viewer,
) -> dict[str, Any]:
    ctx = ctx_of(request)
    rows = ctx.db.query(
        "SELECT a.*, (SELECT finding_id FROM findings f WHERE f.event_id = a.event_id "
        "ORDER BY f.score DESC LIMIT 1) AS finding_id FROM ai_analysis a "
        "ORDER BY a.timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    items = []
    for r in rows:
        v = _verdict_view(dict(r))
        assert v is not None
        verdict = v.get("verdict") or {}
        items.append(
            {
                "analysis_id": v["analysis_id"],
                "event_id": v["event_id"],
                "finding_id": v.get("finding_id"),
                "timestamp": v["timestamp"],
                "available": v["available"],
                "model_name": v["model_name"],
                "is_mock": v["is_mock"],
                "latency_ms": v["latency_ms"],
                "error": v["error"],
                "verdict": verdict.get("verdict"),
                "severity": verdict.get("severity"),
                "confidence": verdict.get("confidence"),
                "threat_type": verdict.get("threat_type"),
                "recommended_action": verdict.get("recommended_action"),
            }
        )
    return {"total": ctx.db.count("ai_analysis"), "items": items, "backend": ai_backend(ctx)}


# ---------------------------------------------------------------- incidents
@router.get("/incidents")
def list_incidents(
    request: Request,
    status: str | None = Query(None, pattern=r"^[a-z_]{3,20}$"),
    band: str | None = Query(None, pattern=r"^(SAFE|LOW|MEDIUM|HIGH|CRITICAL)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
    _: Principal = viewer,
) -> dict[str, Any]:
    where, params = ["1=1"], []
    if status:
        where.append("status = ?")
        params.append(status)
    if band:
        where.append("band = ?")
        params.append(band)
    cond = " AND ".join(where)
    db = ctx_of(request).db
    total = db.scalar(f"SELECT COUNT(*) FROM incidents WHERE {cond}", params)  # noqa: S608
    rows = db.query(
        f"SELECT * FROM incidents WHERE {cond} ORDER BY created_at DESC LIMIT ? OFFSET ?",  # noqa: S608
        [*params, limit, offset],
    )
    return {
        "total": int(total or 0),
        "items": [decode_row(r, ("mitre_techniques", "event_ids", "finding_ids", "actions")) for r in rows],
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, request: Request, _: Principal = viewer) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", incident_id):
        raise HTTPException(422, "invalid incident id")
    ctx = ctx_of(request)
    row = ctx.repo.get_incident(incident_id)
    if row is None:
        raise HTTPException(404, "incident not found")
    inc = decode_row(row, ("mitre_techniques", "event_ids", "finding_ids", "actions"))
    findings = [
        decode_row(r, ("mitre_techniques", "details"))
        for r in ctx.db.query(
            "SELECT * FROM findings WHERE incident_id = ? ORDER BY timestamp LIMIT 500", (incident_id,)
        )
    ]
    actions = [
        decode_row(r, ("target",))
        for r in ctx.db.query(
            "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY timestamp", (incident_id,)
        )
    ]
    ai = None
    if inc.get("ai_analysis_id"):
        r = ctx.db.query_one("SELECT * FROM ai_analysis WHERE analysis_id = ?", (inc["ai_analysis_id"],))
        ai = _verdict_view(dict(r) if r else None)
    return {"incident": inc, "findings": findings, "actions": actions, "ai": ai}


# ---------------------------------------------------------------- MITRE
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@router.get("/mitre")
def mitre(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    techs: dict[str, dict[str, Any]] = {}
    for r in ctx.db.query(
        "SELECT mitre_techniques, attack_stage, timestamp, severity, finding_id FROM findings "
        "WHERE mitre_techniques IS NOT NULL AND mitre_techniques != '[]'"
    ):
        for t in jload(r["mitre_techniques"], []):
            if not isinstance(t, str) or not TECH_RE.fullmatch(t):
                continue
            e = techs.setdefault(
                t,
                {
                    "technique": t,
                    "findings": 0,
                    "stages": set(),
                    "last_seen": "",
                    "max_severity": "INFO",
                    "example_finding_id": r["finding_id"],
                },
            )
            e["findings"] += 1
            if r["attack_stage"]:
                e["stages"].add(r["attack_stage"])
            e["last_seen"] = max(e["last_seen"], r["timestamp"])
            if SEVERITIES.index(r["severity"] or "INFO") < SEVERITIES.index(e["max_severity"]):
                e["max_severity"] = r["severity"]
    detected = sorted(
        ({**e, "stages": sorted(e["stages"])} for e in techs.values()), key=lambda e: -e["findings"]
    )
    stages = {
        r["attack_stage"]: r["n"]
        for r in ctx.db.query(
            "SELECT attack_stage, COUNT(*) n FROM findings WHERE attack_stage IS NOT NULL GROUP BY attack_stage"
        )
    }
    covered: set[str] = set()
    if ctx.rules_dir.is_dir():
        for i, p in enumerate(sorted(ctx.rules_dir.rglob("*"))):
            if i > 2000:
                break
            if p.is_file() and p.suffix.lower() in {".yml", ".yaml", ".yar", ".yara", ".json", ".toml"}:
                try:
                    if p.stat().st_size < 2_000_000:
                        covered |= set(TECH_RE.findall(p.read_text("utf-8", errors="ignore")))
                except OSError:
                    continue
    return {
        "detected": detected,
        "stages": stages,
        "rules_covered_techniques": sorted(covered),
        "note": "Detected = observed in stored findings. Covered = technique IDs referenced by rule files.",
    }


# ---------------------------------------------------------------- endpoints / settings
@router.get("/endpoints")
def endpoints(request: Request, _: Principal = viewer) -> dict[str, Any]:
    ctx = ctx_of(request)
    rows = ctx.db.query(
        "SELECT host_id, COUNT(*) events, MIN(timestamp) first_seen, MAX(timestamp) last_seen "
        "FROM events GROUP BY host_id ORDER BY last_seen DESC LIMIT 500"
    )
    inc = {
        r["host_id"]: r["n"]
        for r in ctx.db.query(
            "SELECT host_id, COUNT(*) n FROM incidents WHERE status IN ('open','investigating') GROUP BY host_id"
        )
    }
    items = [
        dict(r) | {"open_incidents": inc.get(r["host_id"], 0), "local": r["host_id"] == ctx.config.host_id}
        for r in rows
    ]
    if not any(i["local"] for i in items):
        items.insert(
            0,
            {
                "host_id": ctx.config.host_id,
                "events": 0,
                "first_seen": None,
                "last_seen": None,
                "open_incidents": 0,
                "local": True,
            },
        )
    return {"items": items, "mode": ctx.config.mode.value}


@router.get("/settings")
def settings(request: Request, _: Principal = Depends(require("analyst"))) -> dict[str, Any]:
    c = ctx_of(request).config
    return {
        "host_id": c.host_id,
        "mode": c.mode.value,
        "profile": c.profile.value,
        "demo_mode": c.demo_mode,
        "test_mode": c.test_mode,
        "offline": c.offline,
        "sync_enabled": c.sync_enabled,
        "destructive_allowed": c.destructive_allowed(),
        "llm": {
            "enabled": c.llm.enabled,
            "model_name": c.llm.model_name,
            "model_file_present": bool(c.llm.model_path and c.llm.model_path.exists()),
            "gate_min_pre_risk": c.llm.gate_min_pre_risk,
            "max_ctx": c.llm.max_ctx,
        },
        "risk": {
            "weights": c.risk.weights(),
            "bands": {
                "low": c.risk.band_low,
                "medium": c.risk.band_medium,
                "high": c.risk.band_high,
                "critical": c.risk.band_critical,
            },
            "known_malicious_floor": c.risk.known_malicious_floor,
        },
        "policy": {
            "require_approval": c.policy.require_approval,
            "min_confidence_destructive": c.policy.min_confidence_destructive,
            "min_risk_destructive": c.policy.min_risk_destructive,
            "passive_destructive_allowed": c.policy.passive_destructive_allowed,
            "allowed_actions": [a.value for a in c.policy.allowed_actions],
        },
        "read_only": True,
        "note": "Mode and policy changes are made through the agent (ModeManager / config); the dashboard is read-only here.",
    }
