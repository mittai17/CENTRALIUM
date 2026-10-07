"""Shared application context and small DB/JSON helpers for dashboard routes."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.config import CentraliumConfig
from centralium.agent.storage import Database, Repository
from dashboard.backend.metrics import Metrics
from dashboard.backend.security import Principal, RateLimiter, TokenStore


@dataclass
class Context:
    db: Database
    repo: Repository
    config: CentraliumConfig
    tokens: TokenStore
    limiter: RateLimiter
    metrics: Metrics
    ml_dir: Path
    rules_dir: Path
    started_at: float
    generated_tokens: dict[str, str] = field(default_factory=dict)

    def audit(self, principal: Principal, event_type: str, details: dict[str, Any]) -> None:
        """Audit-log a management operation (never include secrets in ``details``)."""
        self.db.audit.append(f"dashboard:{principal.ident}", event_type, details)


def jload(value: Any, default: Any = None) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def decode_row(row: sqlite3.Row | dict[str, Any], json_cols: tuple[str, ...] = ()) -> dict[str, Any]:
    d = dict(row)
    for c in json_cols:
        if c in d:
            d[c] = jload(d[c], [] if c.endswith(("s", "ids")) else {})
    return d


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def table_exists(db: Database, name: str) -> bool:
    return db.query_one("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None
