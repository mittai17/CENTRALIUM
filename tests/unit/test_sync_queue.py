from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from centralium.agent.interfaces import SyncQueue
from centralium.agent.storage import Database
from centralium.agent.sync import DurableSyncQueue, backoff_delay, measure_throughput


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, s: float) -> None:
        self.t += timedelta(seconds=s)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def q(tmp_path: Path, clock: Clock):
    audit: list[tuple[str, str, dict]] = []
    queue = DurableSyncQueue(
        tmp_path / "q.db", clock=clock, rng=lambda: 1.0, audit=lambda a, e, d: audit.append((a, e, d))
    )
    queue.audit_log = audit  # type: ignore[attr-defined]
    yield queue
    queue.close()


def test_satisfies_protocol(q):
    assert isinstance(q, SyncQueue)


def test_wal_mode(q):
    assert q._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_enqueue_claim_deliver(q):
    assert q.enqueue({"a": 1}, dedup_key="k1")
    assert q.pending() == 1
    (item,) = q.claim_batch()
    assert item.payload == {"a": 1} and item.dedup_key == "k1"
    assert q.claim_batch() == []  # inflight, leased
    q.mark_delivered(item.queue_id)
    assert q.pending() == 0
    assert q.stats()["by_status"]["delivered"] == 1


def test_dedup_explicit_and_content_hash(q):
    assert q.enqueue({"a": 1}, dedup_key="k")
    assert not q.enqueue({"a": 2}, dedup_key="k")
    assert q.enqueue({"x": 1, "y": 2})
    assert not q.enqueue({"y": 2, "x": 1})  # key order irrelevant
    assert q.pending() == 2
    assert q.stats()["metrics"]["duplicates"] == 2


def test_dedup_survives_delivery(q):
    q.enqueue({"a": 1})
    (it,) = q.claim_batch()
    q.mark_delivered(it.queue_id)
    assert not q.enqueue({"a": 1})


def test_backoff_formula():
    assert backoff_delay(1, 2, 900, lambda: 1.0) == 4
    assert backoff_delay(3, 2, 900, lambda: 1.0) == 16
    assert backoff_delay(3, 2, 900, lambda: 0.0) == 8  # jitter floor is 50%
    assert backoff_delay(30, 2, 900, lambda: 1.0) == 900  # capped


def test_retry_with_backoff(q, clock):
    q.enqueue({"a": 1}, dedup_key="k")
    (it,) = q.claim_batch()
    q.mark_failed(it.queue_id, "boom")
    assert q.claim_batch() == []  # not due yet
    clock.advance(3)
    assert q.claim_batch() == []  # delay is 4s with rng=1.0
    clock.advance(2)
    (again,) = q.claim_batch()
    assert again.attempts == 1
    q.mark_failed(again.queue_id, "boom")
    clock.advance(5)
    assert q.claim_batch() == []  # second delay is 8s
    clock.advance(4)
    assert len(q.claim_batch()) == 1


def test_dead_after_max_attempts_and_audited(tmp_path, clock):
    audit: list = []
    q = DurableSyncQueue(
        tmp_path / "q.db", clock=clock, max_attempts=2, audit=lambda a, e, d: audit.append(e)
    )
    q.enqueue({"a": 1})
    for _ in range(2):
        clock.advance(10_000)
        (it,) = q.claim_batch()
        q.mark_failed(it.queue_id, "x")
    assert q.stats()["by_status"] == {"dead": 1}
    assert "sync_item_dead" in audit
    q.close()


def test_lease_expiry_reclaims(q, clock):
    q.enqueue({"a": 1})
    assert len(q.claim_batch()) == 1
    clock.advance(q.lease_s + 1)
    assert len(q.claim_batch()) == 1  # crashed worker's claim is recovered


def test_defer_does_not_consume_attempts(q, clock):
    q.enqueue({"a": 1})
    (it,) = q.claim_batch()
    q.defer([it.queue_id], "offline", 10)
    clock.advance(11)
    (again,) = q.claim_batch()
    assert again.attempts == 0


def test_retention_age(tmp_path, clock):
    audit: list = []
    q = DurableSyncQueue(tmp_path / "q.db", clock=clock, max_age_s=100, audit=lambda a, e, d: audit.append(e))
    q.enqueue({"a": 1})
    clock.advance(101)
    q.enqueue({"a": 2})
    res = q.enforce_retention()
    assert res["aged"] == 1 and q.pending() == 1
    assert "sync_queue_retention_dropped_undelivered" in audit
    q.close()


def test_retention_rows_prefers_delivered_then_oldest_pending(tmp_path, clock):
    q = DurableSyncQueue(tmp_path / "q.db", clock=clock, max_rows=3)
    for i in range(3):
        q.enqueue({"i": i})
    (first,) = q.claim_batch(1)
    q.mark_delivered(first.queue_id)
    q.enqueue({"i": 3})
    q.enforce_retention()
    st = q.stats()["by_status"]
    assert st.get("delivered", 0) == 0 and st["pending"] == 3
    q.enqueue({"i": 4})
    q.enforce_retention()
    items = q.claim_batch(10)
    assert [i.payload["i"] for i in items] == [2, 3, 4]  # oldest pending dropped
    q.close()


def test_retention_bytes(tmp_path, clock):
    q = DurableSyncQueue(tmp_path / "q.db", clock=clock, max_bytes=1000)
    for i in range(20):
        q.enqueue({"i": i, "pad": "x" * 100})
    q.enforce_retention()
    assert 0 < q.pending() < 20
    q.close()


def test_delivered_rows_scrubbed_and_purged(tmp_path, clock):
    q = DurableSyncQueue(tmp_path / "q.db", clock=clock, delivered_keep_s=60)
    q.enqueue({"secret": "v"})
    (it,) = q.claim_batch()
    q.mark_delivered(it.queue_id)
    assert q._conn.execute("SELECT payload FROM sync_queue").fetchone()[0] == "{}"
    clock.advance(61)
    q.enforce_retention()
    assert q.stats()["by_status"] == {}
    q.close()


def test_corruption_recovery_at_open(tmp_path):
    p = tmp_path / "q.db"
    q = DurableSyncQueue(p)
    for i in range(50):
        q.enqueue({"i": i})
    q.close()
    for suffix in ("-wal", "-shm"):
        Path(str(p) + suffix).unlink(missing_ok=True)
    p.write_bytes(b"this is definitely not sqlite" * 500)
    audit: list = []
    q2 = DurableSyncQueue(p, audit=lambda a, e, d: audit.append((e, d)))
    assert q2.stats()["metrics"]["recoveries"] == 1
    assert list(tmp_path.glob("q.db.corrupt-*"))
    assert audit and audit[0][0] == "sync_queue_corruption_recovered"
    assert q2.enqueue({"fresh": 1}) and q2.pending() == 1
    q2.close()


def test_corruption_recovery_at_runtime(tmp_path):
    p = tmp_path / "q.db"
    audit: list = []
    q = DurableSyncQueue(p, audit=lambda a, e, d: audit.append(e))
    q.enqueue({"a": 1})
    real = q._conn
    calls = {"n": 0}

    class Boom:
        def __getattr__(self, name):
            return getattr(real, name)

        def execute(self, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.DatabaseError("database disk image is malformed")
            return real.execute(*a, **k)

    q._conn = Boom()  # type: ignore[assignment]
    assert q.enqueue({"b": 2})
    assert "sync_queue_corruption_recovered" in audit
    q.close()


def test_enqueue_never_raises_when_db_unavailable(tmp_path):
    q = DurableSyncQueue(tmp_path / "q.db", lock_timeout_s=0.01)

    def fail(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    q._insert = fail  # type: ignore[method-assign]
    assert q.enqueue({"a": 1}) is True  # spilled to memory, no exception
    assert q.stats()["spill"] == 1
    assert q.pending() == 1


def test_spill_flushes_when_db_returns(tmp_path):
    q = DurableSyncQueue(tmp_path / "q.db")
    q._spill.append(({"a": 1}, "spilled"))
    q.enqueue({"b": 2})
    assert q.stats()["spill"] == 0 and q.pending() == 2
    q.close()


def test_enqueue_not_blocked_by_held_lock(tmp_path):
    import threading
    import time

    q = DurableSyncQueue(tmp_path / "q.db", lock_timeout_s=0.02)
    hold, release = threading.Event(), threading.Event()

    def holder():
        with q._lock:
            hold.set()
            release.wait(2)

    t = threading.Thread(target=holder)
    t.start()
    hold.wait()
    t0 = time.perf_counter()
    assert q.enqueue({"a": 1})
    assert time.perf_counter() - t0 < 0.5
    release.set()
    t.join()
    assert q.stats()["spill"] == 1


def test_audit_integration_with_main_database(tmp_path):
    with Database(tmp_path / "main.db") as db:
        q = DurableSyncQueue(tmp_path / "q.db", audit=db.audit.append)
        q.close()
        (tmp_path / "q.db").write_bytes(b"garbage" * 1000)
        for s in ("-wal", "-shm"):
            Path(str(tmp_path / "q.db") + s).unlink(missing_ok=True)
        q2 = DurableSyncQueue(tmp_path / "q.db", audit=db.audit.append)
        q2.close()
        assert db.audit.entries()[0]["event_type"] == "sync_queue_corruption_recovered"
        assert db.audit.verify().ok


def test_throughput_measurable(tmp_path):
    q = DurableSyncQueue(tmp_path / "q.db")
    r = measure_throughput(q, 500)
    print("sync queue throughput:", r)  # measured, not asserted against a threshold
    assert r["enqueue_per_s"] > 0 and r["claim_ack_per_s"] > 0
    assert q.stats()["metrics"]["enqueue_mean_us"] > 0
    q.close()
