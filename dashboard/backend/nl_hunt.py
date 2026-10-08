"""Natural-language threat hunting query builder.

Translates analyst questions into structured, validated HuntQuery specifications
validated against the whitelisted query builder in dashboard.backend.hunting.
Strictly refuses raw SQL or shell commands.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from dashboard.backend import hunting
from dashboard.backend.hunting import HuntFilter, HuntQuery

log = logging.getLogger("centralium.nl_hunt")

_RAW_SQL_PATTERN = re.compile(
    r"\b(SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|"
    r"UNION\s+ALL|UNION\s+SELECT|TRUNCATE\s+TABLE|EXEC\s+|EXECUTE\s+)\b|;|\bOR\s+1=1\b|\bAND\s+1=1\b",
    re.I,
)

_RAW_CMD_PATTERN = re.compile(
    r"(\bcurl\s+https?://|\bwget\s+https?://|\|\s*bash\b|\|\s*sh\b|\brm\s+-rf\b|\bpowershell\s+-enc\b)",
    re.I,
)


class RawCommandOrSQLError(ValueError):
    """Raised when raw SQL or shell command execution is detected."""

    pass


class NLHuntResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validated_query: HuntQuery
    sql_preview: str
    params: list[Any]
    explanation: str


NL_HUNT_SYSTEM_PROMPT = """You are a Natural Language to Threat Hunt Query translator.
Your job is to translate cybersecurity analyst questions into a structured JSON hunt specification.

CRITICAL RULES:
1. Output ONLY a valid JSON object matching the HuntQuery schema.
2. NEVER output raw SQL statements or commands (NO SELECT, NO DROP, NO INSERT).
3. NEVER output shell commands or scripts.
4. Use ONLY the allowed sources: events, processes, network, dns, findings, files.
5. Use ONLY allowed fields and operators for each source.

Schema:
{
  "source": "events | processes | network | dns | findings | files",
  "filters": [
    {"field": "...", "op": "eq | ne | contains | startswith | gt | gte | lt | lte | in", "value": "..."}
  ],
  "since": null,
  "until": null,
  "count_by": null,
  "limit": 100
}
"""


def _detect_raw_sql_or_cmd(text: str) -> None:
    if _RAW_SQL_PATTERN.search(text):
        raise RawCommandOrSQLError(
            "Raw SQL is strictly forbidden. The natural language hunt builder only produces "
            "whitelisted, structured query specifications."
        )
    if _RAW_CMD_PATTERN.search(text):
        raise RawCommandOrSQLError(
            "Shell commands are strictly forbidden. The natural language hunt builder only produces "
            "whitelisted, structured query specifications."
        )


def _heuristic_translate(question: str) -> HuntQuery:
    """Heuristic rule-based translation for offline/test environments."""
    q = question.lower().strip()

    # Determine source
    source = "events"
    if any(k in q for k in ("process", "proc", "binary", "executables")):
        source = "processes" if "processes" in q or "process list" in q else "events"
    elif any(k in q for k in ("network", "connection", "port", "ip", "traffic", "remote")):
        source = "network"
    elif any(k in q for k in ("dns", "domain", "query", "lookup")):
        source = "dns"
    elif any(k in q for k in ("finding", "alert", "detection", "rule")):
        source = "findings"
    elif any(k in q for k in ("file", "files", "hash", "path")):
        source = "files"

    filters: list[HuntFilter] = []

    # Process names / commands
    if "powershell" in q:
        field = "name" if source == "processes" else "process_name"
        filters.append(HuntFilter(field=field, op="contains", value="powershell"))
    elif "cmd.exe" in q or "cmd" in q:
        field = "name" if source == "processes" else "process_name"
        filters.append(HuntFilter(field=field, op="contains", value="cmd"))
    elif "certutil" in q:
        filters.append(HuntFilter(field="process_name", op="contains", value="certutil"))
    elif "bash" in q:
        filters.append(HuntFilter(field="process_name", op="contains", value="bash"))

    # Port extraction
    port_m = re.search(r"port\s+(\d+)", q)
    if port_m and source in ("network", "events"):
        port = int(port_m.group(1))
        filters.append(HuntFilter(field="destination_port", op="eq", value=port))

    # IP extraction
    ip_m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", q)
    if ip_m and source in ("network", "events"):
        filters.append(HuntFilter(field="destination_ip", op="eq", value=ip_m.group(1)))

    # Severity in findings
    if source == "findings":
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev.lower() in q:
                filters.append(HuntFilter(field="severity", op="eq", value=sev))
                break

    # DNS entropy
    if source == "dns" and "entropy" in q:
        filters.append(HuntFilter(field="entropy", op="gt", value=3.0))

    # File size
    if source == "files" and "large" in q:
        filters.append(HuntFilter(field="size", op="gt", value=1_000_000))

    # Limit
    limit = 100
    limit_m = re.search(r"limit\s+(\d+)", q)
    if limit_m:
        limit = min(500, max(1, int(limit_m.group(1))))

    return HuntQuery(source=source, filters=filters, limit=limit)


def translate_nl_to_hunt(
    question: str,
    llm_client: Any | None = None,
) -> NLHuntResult:
    """Translate natural-language query to a validated HuntQuery with SQL preview.

    Strictly refuses raw SQL or command lines.
    """
    _detect_raw_sql_or_cmd(question)

    query: HuntQuery | None = None

    if llm_client is not None and getattr(llm_client, "available", lambda: False)():
        try:
            prompt = (
                f"{NL_HUNT_SYSTEM_PROMPT}\n\n"
                f"Available schema: {json.dumps(hunting.describe())}\n\n"
                f"Analyst Question: {question}\n\n"
                f"JSON Hunt Specification:"
            )
            # Call client or backend
            raw = llm_client.backend.generate([{"role": "user", "content": prompt}], max_tokens=300)
            _detect_raw_sql_or_cmd(raw)
            # Parse JSON
            raw_clean = raw.strip()
            if raw_clean.startswith("```"):
                raw_clean = raw_clean.strip("`")
                if raw_clean.lower().startswith("json"):
                    raw_clean = raw_clean[4:]
            start = raw_clean.find("{")
            end = raw_clean.rfind("}")
            if start != -1 and end > start:
                data = json.loads(raw_clean[start : end + 1])
                query = HuntQuery.model_validate(data)
        except Exception as exc:
            log.warning("LLM NL hunt generation failed, using heuristic: %s", exc)

    if query is None:
        query = _heuristic_translate(question)

    # Validate against whitelisted query builder
    try:
        sql, params, _, _ = hunting.build(query)
    except hunting.HuntError as exc:
        raise ValueError(f"Hunt query validation failed: {exc}") from exc

    # Generate explanation
    filter_descs = [f"{f.field} {f.op} {f.value}" for f in query.filters]
    explanation = (
        f"Searching table '{query.source}' where {', '.join(filter_descs)}"
        if filter_descs
        else f"Querying all records from table '{query.source}'"
    )

    return NLHuntResult(
        validated_query=query,
        sql_preview=sql,
        params=params,
        explanation=explanation,
    )
