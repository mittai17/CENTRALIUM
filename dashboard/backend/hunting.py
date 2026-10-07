"""Whitelisted, parameterized threat-hunting query builder.

The client never supplies SQL: only a source name, field names, operators and values. Every
identifier is looked up in the static whitelist below (so identifiers in the SQL come from this
file, not the request) and every value is a bound parameter.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dashboard.backend.context import like_escape

# source -> (table, ordering column, {field: type})
SOURCES: dict[str, tuple[str, str, dict[str, str]]] = {
    "events": (
        "events",
        "timestamp",
        {
            "event_id": "text",
            "timestamp": "text",
            "event_type": "text",
            "host_id": "text",
            "user": "text",
            "pid": "int",
            "ppid": "int",
            "process_name": "text",
            "executable_path": "text",
            "command_line": "text",
            "parent_process": "text",
            "hash_sha256": "text",
            "signer": "text",
            "file_path": "text",
            "destination_ip": "text",
            "destination_port": "int",
            "domain": "text",
            "protocol": "text",
            "source": "text",
        },
    ),
    "processes": (
        "processes",
        "start_time",
        {
            "host_id": "text",
            "pid": "int",
            "ppid": "int",
            "name": "text",
            "executable_path": "text",
            "command_line": "text",
            "user": "text",
            "hash_sha256": "text",
            "signer": "text",
            "start_time": "text",
        },
    ),
    "network": (
        "network_connections",
        "timestamp",
        {
            "timestamp": "text",
            "host_id": "text",
            "pid": "int",
            "process_name": "text",
            "destination_ip": "text",
            "destination_port": "int",
            "protocol": "text",
            "domain": "text",
        },
    ),
    "dns": (
        "dns_events",
        "timestamp",
        {"timestamp": "text", "host_id": "text", "pid": "int", "domain": "text", "entropy": "real"},
    ),
    "findings": (
        "findings",
        "timestamp",
        {
            "finding_id": "text",
            "event_id": "text",
            "timestamp": "text",
            "source": "text",
            "rule_id": "text",
            "title": "text",
            "severity": "text",
            "score": "real",
            "confidence": "real",
            "known_malicious": "int",
            "attack_stage": "text",
            "mitre_techniques": "text",
            "incident_id": "text",
        },
    ),
    "files": (
        "files",
        "last_seen",
        {
            "path": "text",
            "hash_sha256": "text",
            "size": "int",
            "entropy": "real",
            "file_type": "text",
            "first_seen": "text",
            "last_seen": "text",
        },
    ),
}

Op = Literal["eq", "ne", "contains", "startswith", "gt", "gte", "lt", "lte", "in"]
OPS_BY_TYPE: dict[str, set[str]] = {
    "text": {"eq", "ne", "contains", "startswith", "in"},
    "int": {"eq", "ne", "gt", "gte", "lt", "lte", "in"},
    "real": {"eq", "ne", "gt", "gte", "lt", "lte", "in"},
}
SQL_OPS = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
Scalar = str | int | float


class HuntError(ValueError):
    pass


class HuntFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(min_length=1, max_length=40)
    op: Op
    value: Scalar | list[Scalar]


class HuntQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["events", "processes", "network", "dns", "findings", "files"]
    filters: list[HuntFilter] = Field(default_factory=list, max_length=10)
    since: str | None = Field(default=None, max_length=40)
    until: str | None = Field(default=None, max_length=40)
    count_by: str | None = Field(default=None, max_length=40)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100_000)

    @field_validator("since", "until")
    @classmethod
    def _iso(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            dt = datetime.fromisoformat(v)
        except ValueError as exc:
            raise ValueError("must be an ISO-8601 timestamp") from exc
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def _coerce(ftype: str, value: Scalar, field: str) -> Scalar:
    if isinstance(value, bool):
        raise HuntError(f"invalid value for {field}")
    try:
        if ftype == "int":
            if isinstance(value, float) and not value.is_integer():
                raise HuntError(f"{field} expects an integer")
            return int(value)
        if ftype == "real":
            return float(value)
    except (TypeError, ValueError) as exc:
        raise HuntError(f"invalid value for {field}") from exc
    if not isinstance(value, str):
        raise HuntError(f"{field} expects a string")
    if len(value) > 500 or "\x00" in value:
        raise HuntError(f"invalid value for {field}")
    return value


def build(q: HuntQuery) -> tuple[str, list[Any], str, str | None]:
    """Return (select sql, params, count sql, group col). Raises HuntError on policy violations."""
    table, order, fields = SOURCES[q.source]
    where: list[str] = []
    params: list[Any] = []
    for f in q.filters:
        if f.field not in fields:
            raise HuntError(f"field {f.field!r} is not queryable for source {q.source!r}")
        ftype = fields[f.field]
        if f.op not in OPS_BY_TYPE[ftype]:
            raise HuntError(f"operator {f.op!r} not allowed on {ftype} field {f.field!r}")
        col = f.field  # whitelisted identifier
        if f.op == "in":
            if not isinstance(f.value, list) or not 1 <= len(f.value) <= 50:
                raise HuntError("'in' requires a list of 1-50 values")
            vals = [_coerce(ftype, v, f.field) for v in f.value]
            where.append(f'"{col}" IN ({",".join("?" for _ in vals)})')
            params += vals
        else:
            if isinstance(f.value, list):
                raise HuntError(f"operator {f.op!r} requires a scalar value")
            v = _coerce(ftype, f.value, f.field)
            if f.op in ("contains", "startswith"):
                esc = like_escape(str(v))
                where.append(f"\"{col}\" LIKE ? ESCAPE '\\'")
                params.append(f"%{esc}%" if f.op == "contains" else f"{esc}%")
            else:
                where.append(f'"{col}" {SQL_OPS[f.op]} ?')
                params.append(v)
    if q.since:
        where.append(f'"{order}" >= ?')
        params.append(q.since)
    if q.until:
        where.append(f'"{order}" <= ?')
        params.append(q.until)
    cond = " AND ".join(where) if where else "1=1"
    count_sql = f'SELECT COUNT(*) FROM "{table}" WHERE {cond}'  # noqa: S608
    if q.count_by:
        if q.count_by not in fields:
            raise HuntError(f"count_by field {q.count_by!r} is not allowed")
        g = q.count_by
        sql = (
            f'SELECT "{g}" AS value, COUNT(*) AS count FROM "{table}" WHERE {cond} '  # noqa: S608
            f'GROUP BY "{g}" ORDER BY count DESC LIMIT ? OFFSET ?'
        )
        return sql, [*params, q.limit, q.offset], count_sql, g
    cols = ", ".join(f'"{c}"' for c in fields)
    sql = (
        f'SELECT {cols} FROM "{table}" WHERE {cond} '  # noqa: S608
        f'ORDER BY "{order}" DESC LIMIT ? OFFSET ?'
    )
    return sql, [*params, q.limit, q.offset], count_sql, None


def describe() -> dict[str, Any]:
    return {
        s: {"fields": fields, "order": order, "ops": {k: sorted(v) for k, v in OPS_BY_TYPE.items()}}
        for s, (_, order, fields) in SOURCES.items()
    }
