"""Tamper-evident, hash-chained audit log.

entry_hash = SHA-256(prev_hash | seq | timestamp | actor | event_type | canonical_json(details))
The first entry chains from GENESIS_HASH. ``verify()`` recomputes the whole chain and
reports the first broken sequence number (modified row, deleted row, or reordered row).

Limitation: an attacker who can rewrite the *entire* table (including the tail) can
forge a consistent chain. Mitigate by periodically exporting/anchoring ``head()`` to
an external location (sync queue / remote) -- see docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from centralium.agent.storage.database import Database

GENESIS_HASH = "0" * 64


def _canon(details: dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(
    prev_hash: str, seq: int, timestamp: str, actor: str, event_type: str, details_json: str
) -> str:
    material = "\x1f".join([prev_hash, str(seq), timestamp, actor, event_type, details_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditVerification:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db

    def append(self, actor: str, event_type: str, details: dict[str, Any] | None = None) -> int:
        """Append an entry atomically (read head + insert under one transaction). Returns seq."""
        details_json = _canon(details or {})
        ts = datetime.now(UTC).isoformat()
        with self._db.transaction() as conn:
            row = conn.execute("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = row["entry_hash"] if row else GENESIS_HASH
            seq = (row["seq"] if row else 0) + 1
            entry_hash = compute_entry_hash(prev_hash, seq, ts, actor, event_type, details_json)
            conn.execute(
                "INSERT INTO audit_log (seq, timestamp, actor, event_type, details, prev_hash, "
                "entry_hash) VALUES (?,?,?,?,?,?,?)",
                (seq, ts, actor, event_type, details_json, prev_hash, entry_hash),
            )
        return seq

    def head(self) -> tuple[int, str]:
        row = self._db.query_one("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        return (row["seq"], row["entry_hash"]) if row else (0, GENESIS_HASH)

    def entries(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        rows = self._db.query(
            "SELECT seq, timestamp, actor, event_type, details, prev_hash, entry_hash "
            "FROM audit_log ORDER BY seq DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"])
            out.append(d)
        return out

    def verify(self, expected_head: str | None = None) -> AuditVerification:
        """Recompute the chain. If ``expected_head`` (an externally anchored hash) is
        given, the current head must equal it (detects tail truncation)."""
        prev = GENESIS_HASH
        expected_seq = 1
        count = 0
        for r in self._db.iter_query(
            "SELECT seq, timestamp, actor, event_type, details, prev_hash, entry_hash "
            "FROM audit_log ORDER BY seq ASC"
        ):
            if r["seq"] != expected_seq:
                return AuditVerification(False, count, expected_seq, "sequence gap (deleted row?)")
            if r["prev_hash"] != prev:
                return AuditVerification(False, count, r["seq"], "prev_hash mismatch")
            calc = compute_entry_hash(
                prev, r["seq"], r["timestamp"], r["actor"], r["event_type"], r["details"]
            )
            if calc != r["entry_hash"]:
                return AuditVerification(False, count, r["seq"], "entry_hash mismatch (modified)")
            prev = r["entry_hash"]
            expected_seq += 1
            count += 1
        if expected_head is not None and expected_head != prev:
            return AuditVerification(False, count, expected_seq, "head does not match anchor")
        return AuditVerification(True, count)
