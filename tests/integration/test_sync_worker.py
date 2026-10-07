from __future__ import annotations

import httpx
import pytest

from centralium.agent.interfaces import SyncItem
from centralium.agent.sync import (
    DurableSyncQueue,
    HttpTransport,
    SyncWorker,
    TransportRejected,
    TransportResult,
    TransportUnavailable,
)

pytestmark = pytest.mark.integration


class FakeTransport:
    def __init__(self) -> None:
        self.online = False
        self.received: list[dict] = []
        self.calls = 0

    def send(self, items: list[SyncItem]) -> TransportResult:
        self.calls += 1
        if not self.online:
            raise TransportUnavailable("network down")
        self.received.extend(i.payload for i in items)
        return TransportResult(delivered=[i.queue_id for i in items])


def make(tmp_path, transport, **kw):
    q = DurableSyncQueue(tmp_path / "q.db", base_backoff_s=0.0, **kw)
    w = SyncWorker(q, transport, offline_base_s=0.0, offline_max_s=0.0, batch_size=10)
    return q, w


def test_offline_then_online_delivers_everything_once(tmp_path):
    t = FakeTransport()
    q, w = make(tmp_path, t)
    for i in range(25):
        q.enqueue({"i": i})
    assert w.run_once() == 0 and not w.online
    assert q.pending() == 25  # nothing lost while offline
    assert q.enqueue({"i": 0}) is False
    t.online = True
    assert w.run_once() == 25
    assert w.online and q.pending() == 0
    assert sorted(p["i"] for p in t.received) == list(range(25))
    q.close()


def test_offline_does_not_burn_attempt_budget(tmp_path):
    t = FakeTransport()
    q, w = make(tmp_path, t, max_attempts=2)
    q.enqueue({"a": 1})
    for _ in range(10):
        w.run_once()
    assert q.stats()["by_status"] == {"pending": 1}
    t.online = True
    assert w.run_once() == 1
    q.close()


def test_queue_survives_restart(tmp_path):
    q = DurableSyncQueue(tmp_path / "q.db")
    q.enqueue({"a": 1})
    q.close()
    t = FakeTransport()
    t.online = True
    q2 = DurableSyncQueue(tmp_path / "q.db")
    w = SyncWorker(q2, t)
    assert w.run_once() == 1
    q2.close()


def test_disabled_worker_does_nothing(tmp_path):
    t = FakeTransport()
    t.online = True
    q = DurableSyncQueue(tmp_path / "q.db")
    q.enqueue({"a": 1})
    w = SyncWorker(q, t, enabled=lambda: False)
    assert w.run_once() == 0 and t.calls == 0 and q.pending() == 1
    q.close()


def test_rejected_batch_backs_off(tmp_path):
    class Reject:
        def send(self, items):
            raise TransportRejected("HTTP 403")

    q = DurableSyncQueue(tmp_path / "q.db", max_attempts=2, base_backoff_s=0.0)
    q.enqueue({"a": 1})
    w = SyncWorker(q, Reject())
    w.run_once()
    w.run_once()
    assert q.stats()["by_status"] == {"dead": 1}
    q.close()


def test_worker_thread_recovers(tmp_path):
    import time

    t = FakeTransport()
    q = DurableSyncQueue(tmp_path / "q.db", base_backoff_s=0.0)
    w = SyncWorker(q, t, interval_s=0.02, offline_base_s=0.01, offline_max_s=0.02)
    q.enqueue({"a": 1})
    w.start()
    time.sleep(0.1)
    assert q.pending() == 1
    t.online = True
    deadline = time.time() + 3
    while q.pending() and time.time() < deadline:
        time.sleep(0.02)
    w.stop()
    assert q.pending() == 0
    q.close()


# --------------------------------------------------------------- HttpTransport
def _items(n=2):
    return [SyncItem(queue_id=i, dedup_key=f"k{i}", payload={"i": i}) for i in range(n)]


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_http_transport_posts_with_bearer_from_env(monkeypatch):
    monkeypatch.setenv("CENTRALIUM_SYNC_TOKEN", "s3cret-token")
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers["authorization"]
        seen["body"] = req.content
        return httpx.Response(200)

    t = HttpTransport("https://dash.example/api/v1/ingest", client=_client(handler))
    res = t.send(_items())
    assert res.delivered == [0, 1] and seen["auth"] == "Bearer s3cret-token"


@pytest.mark.parametrize(
    "code,exc", [(503, TransportUnavailable), (429, TransportUnavailable), (403, TransportRejected)]
)
def test_http_status_mapping_no_secret_in_errors(monkeypatch, code, exc):
    monkeypatch.setenv("CENTRALIUM_SYNC_TOKEN", "s3cret-token")
    t = HttpTransport("https://dash.example/ingest?key=zzz", client=_client(lambda r: httpx.Response(code)))
    with pytest.raises(exc) as ei:
        t.send(_items())
    assert "s3cret-token" not in str(ei.value) and "zzz" not in str(ei.value)


def test_http_network_error_is_unavailable(monkeypatch):
    monkeypatch.setenv("CENTRALIUM_SYNC_TOKEN", "tok")

    def handler(req):
        raise httpx.ConnectError("dns fail for https://dash.example/?token=tok")

    t = HttpTransport("https://dash.example/ingest", client=_client(handler))
    with pytest.raises(TransportUnavailable) as ei:
        t.send(_items())
    assert "tok" not in str(ei.value)


def test_http_missing_token_rejected(monkeypatch):
    monkeypatch.delenv("CENTRALIUM_SYNC_TOKEN", raising=False)
    t = HttpTransport("https://dash.example/ingest", client=_client(lambda r: httpx.Response(200)))
    with pytest.raises(TransportRejected):
        t.send(_items())


@pytest.mark.parametrize(
    "url", ["http://dash.example/x", "ftp://x/y", "https://user:pw@dash.example/x", "not a url"]
)
def test_http_url_validation(url):
    with pytest.raises(ValueError):
        HttpTransport(url)


def test_http_loopback_plain_allowed():
    HttpTransport("http://127.0.0.1:8000/ingest")
