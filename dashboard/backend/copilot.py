"""Investigation copilot for dashboard: read-only assistant restricted to whitelisted
read-only tool functions (get_incident, get_timeline, get_process_tree, get_related_iocs).

Returns structured citations to evidence rows. Strictly prohibits write tools.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.storage import Database

log = logging.getLogger("centralium.copilot")

ALLOWED_COPILOT_TOOLS = {
    "get_incident",
    "get_timeline",
    "get_process_tree",
    "get_related_iocs",
}


class CopilotToolSecurityError(PermissionError):
    """Raised when an unapproved or write tool execution is attempted."""

    pass


class CopilotCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str
    record_id: str
    field: str
    snippet: str


class CopilotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    question: str
    answer: str
    citations: list[CopilotCitation] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    read_only_verified: bool = True


# --------------------------------------------------------------------------- Read-only tools
def get_incident(incident_id: str, db: Database) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    if not row:
        return {}
    res = dict(row)
    if "mitre_techniques" in res and isinstance(res["mitre_techniques"], str):
        with contextlib.suppress(Exception):
            res["mitre_techniques"] = json.loads(res["mitre_techniques"])
    return res


def _get_incident_events(incident_id: str, db: Database, limit: int = 50) -> list[dict[str, Any]]:
    inc = db.query_one("SELECT host_id, event_ids FROM incidents WHERE incident_id = ?", (incident_id,))
    if not inc:
        return []
    event_ids: list[str] = []
    if inc["event_ids"]:
        with contextlib.suppress(Exception):
            parsed = json.loads(inc["event_ids"])
            if isinstance(parsed, list):
                event_ids = [str(e) for e in parsed]
    if event_ids:
        placeholders = ",".join("?" for _ in event_ids)
        sql = f"SELECT * FROM events WHERE event_id IN ({placeholders}) LIMIT ?"  # noqa: S608
        rows = db.query(sql, [*event_ids, limit])
        return [dict(r) for r in rows]
    elif inc["host_id"]:
        sql = "SELECT * FROM events WHERE host_id = ? ORDER BY timestamp DESC LIMIT ?"
        rows = db.query(sql, (inc["host_id"], limit))
        return [dict(r) for r in rows]
    return []


def get_timeline(incident_id: str, db: Database, limit: int = 50) -> list[dict[str, Any]]:
    events = _get_incident_events(incident_id, db, limit=limit)
    return [
        {
            "event_id": e.get("event_id"),
            "timestamp": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "process_name": e.get("process_name"),
            "command_line": e.get("command_line"),
            "file_path": e.get("file_path"),
            "destination_ip": e.get("destination_ip"),
        }
        for e in events
    ]


def get_process_tree(incident_id: str, db: Database) -> dict[str, Any]:
    events = _get_incident_events(incident_id, db, limit=50)
    nodes: list[dict[str, Any]] = []
    for e in events:
        nodes.append(
            {
                "pid": e.get("pid"),
                "ppid": e.get("ppid"),
                "name": e.get("process_name"),
                "parent": e.get("parent_process"),
                "cmd": e.get("command_line"),
            }
        )
    return {"incident_id": incident_id, "processes": nodes}


def get_related_iocs(incident_id: str, db: Database) -> dict[str, Any]:
    events = _get_incident_events(incident_id, db, limit=50)
    hashes: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()

    for e in events:
        if e.get("hash_sha256"):
            hashes.add(e["hash_sha256"])
        if e.get("destination_ip"):
            ips.add(e["destination_ip"])
        if e.get("domain"):
            domains.add(e["domain"])

    return {
        "hashes": sorted(hashes),
        "destination_ips": sorted(ips),
        "domains": sorted(domains),
    }


def execute_copilot_tool(tool_name: str, incident_id: str, db: Database, **kwargs: Any) -> Any:
    """Enforce strict read-only execution whitelist."""
    if tool_name not in ALLOWED_COPILOT_TOOLS:
        raise CopilotToolSecurityError(
            f"Unauthorized copilot tool '{tool_name}'. Copilot is strictly read-only and restricted to "
            f"whitelisted investigation tools: {sorted(ALLOWED_COPILOT_TOOLS)}"
        )

    if tool_name == "get_incident":
        return get_incident(incident_id, db)
    elif tool_name == "get_timeline":
        return get_timeline(incident_id, db, limit=kwargs.get("limit", 50))
    elif tool_name == "get_process_tree":
        return get_process_tree(incident_id, db)
    elif tool_name == "get_related_iocs":
        return get_related_iocs(incident_id, db)


def run_copilot_investigation(
    incident_id: str,
    question: str,
    db: Database,
    llm_client: Any | None = None,
) -> CopilotResponse:
    """Run an investigation analysis with citations to evidence rows."""
    tools_used: list[str] = []
    citations: list[CopilotCitation] = []

    # 1. Fetch incident metadata
    inc = execute_copilot_tool("get_incident", incident_id, db)
    tools_used.append("get_incident")
    if inc:
        citations.append(
            CopilotCitation(
                table="incidents",
                record_id=incident_id,
                field="title",
                snippet=f"Title: {inc.get('title', 'Unknown')} (Risk: {inc.get('risk_score', 0):.1f})",
            )
        )

    # 2. Fetch timeline
    timeline = execute_copilot_tool("get_timeline", incident_id, db, limit=10)
    tools_used.append("get_timeline")
    for ev in timeline[:3]:
        citations.append(
            CopilotCitation(
                table="events",
                record_id=ev.get("event_id", ""),
                field="command_line",
                snippet=f"Proc {ev.get('process_name')}: {str(ev.get('command_line'))[:80]}",
            )
        )

    # 3. Fetch process tree
    ptree = execute_copilot_tool("get_process_tree", incident_id, db)
    tools_used.append("get_process_tree")

    # 4. Fetch IOCs
    iocs = execute_copilot_tool("get_related_iocs", incident_id, db)
    tools_used.append("get_related_iocs")
    for ip in iocs.get("destination_ips", [])[:2]:
        citations.append(
            CopilotCitation(
                table="events",
                record_id=incident_id,
                field="destination_ip",
                snippet=f"Observed network destination: {ip}",
            )
        )

    # Construct synthesized answer
    title = inc.get("title", f"Incident {incident_id}")
    risk = inc.get("risk_score", 0.0)
    summary = inc.get("summary", "Activity under review.")
    techniques = inc.get("mitre_techniques", [])

    answer_parts = [
        f"**Investigation Summary for {title}** (Risk Score: {risk:.1f}):",
        f"{summary}",
        f"- **Timeline activity:** {len(timeline)} events recorded in lineage window.",
        f"- **Processes analyzed:** {len(ptree.get('processes', []))} process nodes.",
    ]
    if techniques:
        answer_parts.append(f"- **Identified MITRE ATT&CK Techniques:** {', '.join(techniques)}")
    if iocs.get("destination_ips"):
        answer_parts.append(f"- **Network indicators:** {', '.join(iocs['destination_ips'])}")

    answer = "\n".join(answer_parts)

    return CopilotResponse(
        incident_id=incident_id,
        question=question,
        answer=answer,
        citations=citations,
        tools_used=tools_used,
        read_only_verified=True,
    )
