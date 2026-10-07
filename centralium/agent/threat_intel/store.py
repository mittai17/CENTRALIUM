"""SQLite-backed IOC cache implementing the ``ThreatIntelStore`` protocol.

Lookups are local only (never network) and fronted by a small thread-safe LRU cache (including
negative results) so the per-event hot path is a dict hit. The cache is invalidated on any write.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from centralium.agent.interfaces import IOCMatch
from centralium.agent.storage import Database
from centralium.agent.threat_intel.feeds import (
    FeedParseError,
    IOCRecord,
    normalize_domain,
    normalize_ip,
    normalize_sha256,
    normalize_url,
    parse_feed,
)

log = logging.getLogger("centralium.threat_intel")

MAX_FEED_FILE_BYTES = 64 * 1024 * 1024


class CachedIOCStore:
    def __init__(
        self,
        db: Database,
        *,
        cache_size: int = 8192,
        negative_ttl_s: float = 60.0,
        default_ttl_days: float = 30.0,
        updater: Callable[[], int] | None = None,
    ) -> None:
        self.db = db
        self._cap = max(16, cache_size)
        self._ttl = negative_ttl_s
        self._default_ttl_days = default_ttl_days
        self._updater = updater
        self._cache: OrderedDict[tuple[str, str], tuple[float, list[IOCMatch]]] = OrderedDict()
        self._lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0

    # ------------------------------------------------------------------ lookup
    def _lookup(self, ioc_type: str, value: str) -> list[IOCMatch]:
        key = (ioc_type, value)
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None and now - hit[0] < self._ttl:
                self._cache.move_to_end(key)
                self.cache_hits += 1
                return list(hit[1])
            self.cache_misses += 1
        rows = self.db.query(
            "SELECT * FROM ioc_cache WHERE ioc_type = ? AND value = ? AND (expires_at IS NULL OR expires_at > ?)",  # noqa: E501
            (ioc_type, value, Database.now()),
        )
        matches = [self._to_match(dict(r)) for r in rows]
        with self._lock:
            self._cache[key] = (now, matches)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cap:
                self._cache.popitem(last=False)
        return list(matches)

    @staticmethod
    def _to_match(r: dict[str, Any]) -> IOCMatch:
        try:
            meta = json.loads(r.get("metadata") or "{}")
            meta = meta if isinstance(meta, dict) else {}
        except json.JSONDecodeError:
            meta = {}
        meta.update({"first_seen": r.get("first_seen"), "last_seen": r.get("last_seen")})
        conf = r.get("confidence")
        return IOCMatch(
            ioc_type=r["ioc_type"],
            value=r["value"],
            source=r["source"],
            threat_type=r.get("threat_type") or "",
            confidence=float(conf) if conf is not None else 1.0,
            metadata=meta,
        )

    def match_hash(self, sha256: str) -> list[IOCMatch]:
        h = normalize_sha256(sha256)
        return self._lookup("sha256", h) if h else []

    def match_ip(self, ip: str) -> list[IOCMatch]:
        v = normalize_ip(ip) if ip else None
        return self._lookup("ip", v) if v else []

    def match_domain(self, domain: str) -> list[IOCMatch]:
        """Exact domain or any parent domain (>= 2 labels) present in the cache."""
        d = normalize_domain(domain) if domain else None
        if not d:
            return []
        labels = d.split(".")
        out: list[IOCMatch] = []
        for i in range(0, min(len(labels) - 1, 6)):
            out += self._lookup("domain", ".".join(labels[i:]))
        return out

    def match_url(self, url: str) -> list[IOCMatch]:
        u = normalize_url(url) if url else None
        return self._lookup("url", u) if u else []

    # ------------------------------------------------------------------ writes
    def add_records(self, records: list[IOCRecord]) -> int:
        if not records:
            return 0
        now = Database.now()
        ttl = datetime.now(UTC) + timedelta(days=self._default_ttl_days)
        rows = []
        for r in records:
            exp = r.expires_at or ttl.isoformat()
            rows.append(
                (
                    r.ioc_type,
                    r.value,
                    r.source,
                    r.threat_type,
                    r.confidence,
                    r.first_seen or now,
                    r.last_seen or now,
                    exp,
                    json.dumps(r.metadata, separators=(",", ":"))[:4000],
                )
            )
        self.db.executemany(
            "INSERT INTO ioc_cache (ioc_type, value, source, threat_type, confidence, first_seen, last_seen,"
            " expires_at, metadata) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(ioc_type, value, source) DO UPDATE SET"  # noqa: E501
            " threat_type=excluded.threat_type, confidence=excluded.confidence, last_seen=excluded.last_seen,"
            " expires_at=excluded.expires_at, metadata=excluded.metadata",
            rows,
        )
        self.clear_cache()
        return len(rows)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def purge_expired(self) -> int:
        n = self.db.execute(
            "DELETE FROM ioc_cache WHERE expires_at IS NOT NULL AND expires_at <= ?", (Database.now(),)
        )
        self.clear_cache()
        return n

    def count(self) -> int:
        return self.db.count("ioc_cache")

    # ------------------------------------------------------------------ loading local feeds
    def load_file(self, path: str | Path, fmt: str, *, source: str | None = None) -> int:
        """Import a local feed file. Returns IOCs stored. Raises FeedParseError/OSError."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(str(p))
        if p.stat().st_size > MAX_FEED_FILE_BYTES:
            raise FeedParseError("feed file too large")
        res = parse_feed(fmt, p.read_bytes(), source=source)
        if res.rejected:
            log.warning("feed %s: %d invalid rows rejected", p.name, res.rejected)
        return self.add_records(res.records)

    def load_directory(self, directory: str | Path, *, fmt: str = "centralium") -> int:
        """Load every ``*.json`` IOC set in ``directory`` (bad files are logged and skipped)."""
        total = 0
        d = Path(directory)
        if not d.is_dir():
            return 0
        for f in sorted(d.glob("*.json")):
            try:
                total += self.load_file(f, fmt)
            except (OSError, FeedParseError) as exc:
                log.warning("skipping IOC file %s: %s", f.name, exc)
        return total

    def update(self) -> int:
        """Run the periodic updater if configured; offline-safe (never raises)."""
        if self._updater is None:
            return 0
        try:
            return int(self._updater())
        except Exception:
            log.exception("threat-intel update failed (ignored)")
            return 0
