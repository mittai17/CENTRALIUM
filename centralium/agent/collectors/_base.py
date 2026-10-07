"""Shared collector plumbing: bounded queue, rate limiting, normalization, dispatcher thread.

Producers call :meth:`BaseCollector.emit_raw` (raw dict -> NormalizedEvent via the injected
Normalizer) or :meth:`emit_event`. Events go through a *bounded* queue (drop-newest + counter
on overflow, never blocking the producer) drained by a dispatcher thread that calls ``sink``.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

from centralium.agent.interfaces import EventSink
from centralium.agent.models import NormalizedEvent
from centralium.agent.normalization import EventNormalizer

log = logging.getLogger(__name__)


class TokenBucket:
    """Simple token bucket; ``rate <= 0`` means unlimited. Thread-safe."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(rate, 1.0))
        self._tokens = self.capacity
        self._t = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        if self.rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._t) * self.rate)
            self._t = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class BaseCollector:
    name = "base"
    platforms: tuple[str, ...] = ("linux", "windows")

    def __init__(
        self,
        *,
        normalizer: EventNormalizer | None = None,
        host_id: str = "localhost",
        queue_size: int = 10_000,
        max_events_per_sec: float = 0.0,
        poll_interval: float = 1.0,
    ) -> None:
        self.normalizer = normalizer or EventNormalizer(host_id)
        self.host_id = host_id
        self.poll_interval = max(0.05, poll_interval)
        self._queue: queue.Queue[NormalizedEvent] = queue.Queue(maxsize=max(1, queue_size))
        self._bucket = TokenBucket(max_events_per_sec)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sink: EventSink | None = None
        self._lock = threading.Lock()
        self._healthy = True
        self._health_reason = "not started"
        self.stats: dict[str, int] = {
            "emitted": 0,
            "delivered": 0,
            "dropped_queue_full": 0,
            "dropped_rate": 0,
            "normalize_errors": 0,
            "sink_errors": 0,
        }

    # ------------------------------------------------------------------ Collector protocol
    def start(self, sink: EventSink) -> None:
        with self._lock:
            if self.is_running():
                return
            self._sink = sink
            self._stop.clear()
            self._threads = [
                threading.Thread(target=self._dispatch, name=f"{self.name}-dispatch", daemon=True),
                threading.Thread(target=self._guarded_run, name=f"{self.name}-producer", daemon=True),
            ]
            for t in self._threads:
                t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(timeout=5.0)
        self._threads = []
        self._health_reason = "stopped"

    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def health(self) -> tuple[bool, str]:
        return self._healthy, self._health_reason

    # ------------------------------------------------------------------ producer API
    def set_health(self, ok: bool, reason: str) -> None:
        self._healthy, self._health_reason = ok, reason

    def emit_raw(self, raw: dict[str, Any]) -> int:
        """Normalize ``raw`` and enqueue the resulting events. Returns the number enqueued."""
        try:
            events = self.normalizer.normalize_many(raw)
        except ValueError as exc:
            self.stats["normalize_errors"] += 1
            log.debug("%s: normalization failed: %s", self.name, exc)
            return 0
        return sum(1 for ev in events if self.emit_event(ev))

    def emit_event(self, ev: NormalizedEvent) -> bool:
        if not self._bucket.allow():
            self.stats["dropped_rate"] += 1
            return False
        try:
            self._queue.put_nowait(ev)
        except queue.Full:
            self.stats["dropped_queue_full"] += 1
            return False
        self.stats["emitted"] += 1
        return True

    def queue_depth(self) -> int:
        return self._queue.qsize()

    # ------------------------------------------------------------------ internals
    def _run(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _guarded_run(self) -> None:
        try:
            self._run()
        except Exception as exc:
            log.exception("%s collector crashed", self.name)
            self.set_health(False, f"crashed: {type(exc).__name__}: {exc}")

    def _dispatch(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                ev = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            try:
                if self._sink is not None:
                    self._sink(ev)
                self.stats["delivered"] += 1
            except Exception:
                self.stats["sink_errors"] += 1
                log.exception("%s: sink raised", self.name)
            if self._stop.is_set() and self._queue.qsize() > 1000:
                return  # do not spend long draining on shutdown
