"""Durable SQLite-WAL outbound event queue (implements ``SyncQueue``).

Design notes
* Own database file (default ``<data>/sync_queue.db``), separate from the main agent DB so a
  corrupt or oversized queue can never take detection storage down.
* ``enqueue`` never blocks detection: it uses a short lock timeout and a short SQLite
  busy-timeout; if the queue is contended or broken the payload goes to a small bounded in-memory
  spill buffer (flushed opportunistically) and, as a last resort, is counted as dropped.
* Dedup: ``dedup_key`` or, when absent, the SHA-256 of the canonical payload. Delivered rows are kept
  (until retention purges them) so a re-enqueue of an already delivered event is still rejected.
* Retry: exponential backoff with jitter (``base * 2**attempts`` capped, jittered into [50%,100%]).
  ``defer`` is used for connectivity failures (does not consume the attempt budget).
  Rows exceeding ``max_attempts`` become ``dead`` (kept for retention window, then purged).
* Retention: age (``max_age_s``), row count and on-disk payload bytes. Oldest delivered rows go first,
  then dead, then oldest pending (data loss is audited with counts).
* Corruption: ``PRAGMA quick_check`` at open and on ``DatabaseError`` -> DB (+wal/shm) moved aside to
  ``*.corrupt-<ts>``, fresh DB created, audit entry written. Queued-but-undelivered events in a
  corrupt file are lost from the queue (they remain in the main event store).
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from centralium.agent.interfaces import SyncItem

log = logging.getLogger("centralium.sync.queue")

AuditFn = Callable[[str, str, dict[str, Any]], Any]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_queue (
    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending|inflight|delivered|dead
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    lease_until TEXT,
    last_error TEXT,
    delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sq_status ON sync_queue(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_sq_created ON sync_queue(created_at);
"""


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def canonical_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def backoff_delay(attempts: int, base: float, cap: float, rng: Callable[[], float] = random.random) -> float:
    """Exponential backoff with jitter: uniform in [50%, 100%] of ``min(cap, base*2**attempts)``."""
    raw = min(cap, base * (2 ** max(0, attempts)))
    return float(raw * (0.5 + 0.5 * rng()))


class DurableSyncQueue:
    def __init__(
        self,
        path: str | Path,
        *,
        max_rows: int = 100_000,
        max_bytes: int = 256 * 1024 * 1024,
        max_age_s: float = 7 * 86400,
        delivered_keep_s: float = 3600,
        max_attempts: int = 50,
        base_backoff_s: float = 2.0,
        max_backoff_s: float = 900.0,
        lease_s: float = 120.0,
        lock_timeout_s: float = 0.05,
        spill_max: int = 1000,
        audit: AuditFn | None = None,
        clock: Callable[[], datetime] | None = None,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.path = Path(path)
        self.max_rows, self.max_bytes, self.max_age_s = max_rows, max_bytes, max_age_s
        self.delivered_keep_s, self.max_attempts = delivered_keep_s, max_attempts
        self.base_backoff_s, self.max_backoff_s, self.lease_s = base_backoff_s, max_backoff_s, lease_s
        self.lock_timeout_s = lock_timeout_s
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self._rng = rng
        self._lock = threading.RLock()
        self._spill: deque[tuple[dict[str, Any], str | None]] = deque(maxlen=spill_max)
        self._since_retention = 0
        self.metrics: dict[str, float] = {
            "enqueued": 0,
            "duplicates": 0,
            "dropped": 0,
            "spilled": 0,
            "recoveries": 0,
            "delivered": 0,
            "failed": 0,
            "dead": 0,
            "purged": 0,
            "enqueue_ns_total": 0,
            "enqueue_ns_max": 0,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        with self._lock:
            self._open()

    # ------------------------------------------------------------------ connection / recovery
    def _now(self) -> datetime:
        return self._clock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=0.25)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=250")
        return conn

    def _open(self) -> None:
        try:
            conn = self._connect()
            row = conn.execute("PRAGMA quick_check").fetchone()
            if row is None or row[0] != "ok":
                conn.close()
                raise sqlite3.DatabaseError(f"quick_check failed: {row[0] if row else 'no result'}")
            conn.executescript(_SCHEMA)
            self._conn = conn
        except sqlite3.DatabaseError as exc:
            if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
                raise
            self._recover(str(exc))

    def _recover(self, reason: str) -> None:
        """Move a corrupt DB aside and recreate. Caller holds the lock."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover - best effort
                log.debug("close during recovery failed", exc_info=True)
            self._conn = None
        stamp = self._now().strftime("%Y%m%dT%H%M%S%f")
        moved: list[str] = []
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(self.path) + suffix)
            if src.exists():
                dst = Path(f"{self.path}.corrupt-{stamp}{suffix}")
                src.replace(dst)
                moved.append(dst.name)
        conn = self._connect()
        conn.executescript(_SCHEMA)
        self._conn = conn
        self.metrics["recoveries"] += 1
        log.error("sync queue corrupt (%s); moved aside %s and recreated", reason, moved)
        self._do_audit("sync_queue_corruption_recovered", {"reason": reason[:300], "moved": moved})

    def _do_audit(self, event_type: str, details: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit("sync_queue", event_type, details)
        except Exception:
            log.exception("audit write failed for %s", event_type)

    @contextmanager
    def _db(self, timeout: float | None = None) -> Iterator[sqlite3.Connection]:
        if not self._lock.acquire(timeout=-1 if timeout is None else timeout):
            raise TimeoutError("sync queue busy")
        try:
            if self._conn is None:
                self._open()
            assert self._conn is not None
            yield self._conn
        finally:
            self._lock.release()

    def _guard(self, fn: Callable[[sqlite3.Connection], Any], timeout: float | None = None) -> Any:
        """Run ``fn``; on a corruption-type DatabaseError recover once and retry."""
        for attempt in (1, 2):
            try:
                with self._db(timeout) as conn:
                    return fn(conn)
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if "locked" in msg or "busy" in msg:
                    raise
                if attempt == 2 or not ("malformed" in msg or "disk image" in msg or "not a database" in msg):
                    raise
                with self._lock:
                    self._recover(str(exc))
            except sqlite3.DatabaseError as exc:
                if attempt == 2:
                    raise
                with self._lock:
                    self._recover(str(exc))
        raise RuntimeError("unreachable")  # pragma: no cover

    # ------------------------------------------------------------------ SyncQueue API
    def enqueue(self, payload: dict[str, Any], dedup_key: str | None = None) -> bool:
        """Non-blocking durable enqueue. True if newly stored (or buffered); False if duplicate/dropped."""
        t0 = time.perf_counter_ns()
        try:
            return self._enqueue(payload, dedup_key)
        finally:
            dt = time.perf_counter_ns() - t0
            self.metrics["enqueue_ns_total"] += dt
            self.metrics["enqueue_ns_max"] = max(self.metrics["enqueue_ns_max"], dt)

    def _enqueue(self, payload: dict[str, Any], dedup_key: str | None) -> bool:
        try:
            self._flush_spill()
            return self._insert(payload, dedup_key, self.lock_timeout_s)
        except (TimeoutError, sqlite3.Error) as exc:
            # Never block or raise into the detection path.
            if len(self._spill) == self._spill.maxlen:
                self.metrics["dropped"] += 1  # oldest spilled entry is evicted by the deque
            self._spill.append((payload, dedup_key))
            self.metrics["spilled"] += 1
            log.warning("sync enqueue deferred to memory spill: %s", type(exc).__name__)
            return True

    def _insert(self, payload: dict[str, Any], dedup_key: str | None, timeout: float | None) -> bool:
        key = dedup_key or canonical_hash(payload)
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        now = self._now()

        def op(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "INSERT OR IGNORE INTO sync_queue (dedup_key,payload,size,created_at,status,next_attempt_at)"
                " VALUES (?,?,?,?,'pending',?)",
                (key, blob, len(blob), _ts(now), _ts(now)),
            )
            return cur.rowcount > 0

        added = bool(self._guard(op, timeout))
        if added:
            self.metrics["enqueued"] += 1
            self._since_retention += 1
            if self._since_retention >= 200:
                self._since_retention = 0
                try:
                    self.enforce_retention(timeout=self.lock_timeout_s)
                except (TimeoutError, sqlite3.Error):
                    log.debug("retention deferred", exc_info=True)
        else:
            self.metrics["duplicates"] += 1
        return added

    def _flush_spill(self) -> None:
        while self._spill:
            payload, key = self._spill[0]
            self._insert(payload, key, self.lock_timeout_s)
            self._spill.popleft()

    def claim_batch(self, limit: int = 100) -> list[SyncItem]:
        now = self._now()
        lease = _ts(now + timedelta(seconds=self.lease_s))

        def op(conn: sqlite3.Connection) -> list[SyncItem]:
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    "SELECT queue_id,dedup_key,payload,attempts FROM sync_queue WHERE "
                    "(status='pending' AND next_attempt_at<=?) OR (status='inflight' AND lease_until<=?) "
                    "ORDER BY queue_id LIMIT ?",
                    (_ts(now), _ts(now), limit),
                ).fetchall()
                ids = [r["queue_id"] for r in rows]
                conn.executemany(
                    "UPDATE sync_queue SET status='inflight', lease_until=? WHERE queue_id=?",
                    [(lease, i) for i in ids],
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            return [
                SyncItem(
                    queue_id=r["queue_id"],
                    dedup_key=r["dedup_key"],
                    payload=json.loads(r["payload"]),
                    attempts=r["attempts"],
                )
                for r in rows
            ]

        result: list[SyncItem] = self._guard(op)
        return result

    def mark_delivered(self, queue_id: int) -> None:
        def op(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE sync_queue SET status='delivered', delivered_at=?, lease_until=NULL, last_error=NULL,"
                " payload='{}', size=2 WHERE queue_id=?",
                (_ts(self._now()), queue_id),
            )

        self._guard(op)
        self.metrics["delivered"] += 1

    def mark_failed(self, queue_id: int, error: str, *, permanent: bool = False) -> None:
        """Record a failed delivery: attempts+1, exponential backoff, ``dead`` after max_attempts."""
        err = error[:300]

        def op(conn: sqlite3.Connection) -> str:
            row = conn.execute("SELECT attempts FROM sync_queue WHERE queue_id=?", (queue_id,)).fetchone()
            if row is None:
                return "missing"
            attempts = row["attempts"] + 1
            if permanent or attempts >= self.max_attempts:
                conn.execute(
                    "UPDATE sync_queue SET status='dead', attempts=?, last_error=?, lease_until=NULL "
                    "WHERE queue_id=?",
                    (attempts, err, queue_id),
                )
                return "dead"
            delay = backoff_delay(attempts, self.base_backoff_s, self.max_backoff_s, self._rng)
            conn.execute(
                "UPDATE sync_queue SET status='pending', attempts=?, last_error=?, lease_until=NULL, "
                "next_attempt_at=? WHERE queue_id=?",
                (attempts, err, _ts(self._now() + timedelta(seconds=delay)), queue_id),
            )
            return "retry"

        outcome = self._guard(op)
        self.metrics["failed"] += 1
        if outcome == "dead":
            self.metrics["dead"] += 1
            self._do_audit("sync_item_dead", {"queue_id": queue_id, "error": err})

    def defer(self, queue_ids: list[int], error: str, delay_s: float) -> None:
        """Release claimed items after a connectivity failure without spending their attempt budget."""
        when = _ts(self._now() + timedelta(seconds=delay_s))

        def op(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "UPDATE sync_queue SET status='pending', lease_until=NULL, last_error=?, next_attempt_at=? "
                "WHERE queue_id=? AND status='inflight'",
                [(error[:300], when, i) for i in queue_ids],
            )

        self._guard(op)

    def pending(self) -> int:
        n = self._guard(
            lambda c: c.execute(
                "SELECT COUNT(*) FROM sync_queue WHERE status IN ('pending','inflight')"
            ).fetchone()[0]
        )
        return int(n) + len(self._spill)

    # ------------------------------------------------------------------ retention / stats
    def enforce_retention(self, timeout: float | None = None) -> dict[str, int]:
        now = self._now()

        def op(conn: sqlite3.Connection) -> dict[str, int]:
            out = {"aged": 0, "delivered_purged": 0, "overflow_dropped_undelivered": 0, "overflow_purged": 0}
            cutoff = _ts(now - timedelta(seconds=self.max_age_s))
            out["aged"] = conn.execute(
                "DELETE FROM sync_queue WHERE created_at<? AND status!='delivered'", (cutoff,)
            ).rowcount
            out["delivered_purged"] = conn.execute(
                "DELETE FROM sync_queue WHERE status='delivered' AND delivered_at<?",
                (_ts(now - timedelta(seconds=self.delivered_keep_s)),),
            ).rowcount
            for status in ("delivered", "dead", "pending"):
                while True:
                    count, size = conn.execute(
                        "SELECT COUNT(*), COALESCE(SUM(size),0) FROM sync_queue"
                    ).fetchone()
                    if count <= self.max_rows and size <= self.max_bytes:
                        break
                    # drop oldest rows of this status (in chunks) until within bounds
                    n = conn.execute(
                        "DELETE FROM sync_queue WHERE queue_id IN (SELECT queue_id FROM sync_queue "
                        "WHERE status=? ORDER BY queue_id LIMIT ?)",
                        (
                            status,
                            max(1, count - self.max_rows) if count > self.max_rows else max(1, count // 20),
                        ),
                    ).rowcount
                    if n == 0:
                        break
                    key = (
                        "overflow_purged"
                        if status in ("delivered", "dead")
                        else "overflow_dropped_undelivered"
                    )
                    out[key] += n
            return out

        res: dict[str, int] = self._guard(op, timeout)
        lost = res["aged"] + res["overflow_dropped_undelivered"]
        self.metrics["purged"] += sum(res.values())
        if lost:
            self.metrics["dropped"] += lost
            self._do_audit("sync_queue_retention_dropped_undelivered", res)
        return res

    def stats(self) -> dict[str, Any]:
        def op(conn: sqlite3.Connection) -> dict[str, int]:
            return {
                r["status"]: r["n"]
                for r in conn.execute("SELECT status, COUNT(*) n FROM sync_queue GROUP BY status")
            }

        by_status: dict[str, int] = self._guard(op)
        m = dict(self.metrics)
        n = m["enqueued"] + m["duplicates"]
        m["enqueue_mean_us"] = (m["enqueue_ns_total"] / n / 1000.0) if n else 0.0
        m["enqueue_max_us"] = m["enqueue_ns_max"] / 1000.0
        return {"by_status": by_status, "spill": len(self._spill), "metrics": m}

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def measure_throughput(queue: DurableSyncQueue, n: int = 5000) -> dict[str, float]:
    """Measured (not asserted) enqueue/claim/ack throughput on the given queue."""
    t0 = time.perf_counter()
    for i in range(n):
        queue.enqueue({"bench": i, "pad": "x" * 200}, dedup_key=f"bench-{time.time_ns()}-{i}")
    t_enq = time.perf_counter() - t0
    t0 = time.perf_counter()
    done = 0
    while True:
        batch = queue.claim_batch(500)
        if not batch:
            break
        for it in batch:
            queue.mark_delivered(it.queue_id)
        done += len(batch)
    t_ack = time.perf_counter() - t0
    return {
        "n": float(n),
        "enqueue_per_s": n / t_enq if t_enq else 0.0,
        "claim_ack_per_s": done / t_ack if t_ack else 0.0,
    }
