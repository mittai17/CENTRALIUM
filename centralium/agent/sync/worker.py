"""Background sync worker: drains the durable queue through an injectable transport.

Tolerates offline operation (the queue just grows within its bounds), applies a worker-level
exponential backoff while the transport is unavailable, and resumes immediately after the first
successful delivery. Runs on its own daemon thread so it can never block detection.
"""

from __future__ import annotations

import logging
import random
import threading
from collections.abc import Callable
from typing import Any

from centralium.agent.sync.queue import DurableSyncQueue, backoff_delay
from centralium.agent.sync.transport import (
    Transport,
    TransportRejected,
    TransportUnavailable,
)

log = logging.getLogger("centralium.sync.worker")


class SyncWorker:
    def __init__(
        self,
        queue: DurableSyncQueue,
        transport: Transport,
        *,
        batch_size: int = 100,
        interval_s: float = 5.0,
        offline_base_s: float = 2.0,
        offline_max_s: float = 300.0,
        enabled: Callable[[], bool] = lambda: True,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.queue, self.transport = queue, transport
        self.batch_size, self.interval_s = batch_size, interval_s
        self.offline_base_s, self.offline_max_s = offline_base_s, offline_max_s
        self._enabled = enabled  # e.g. lambda: not cfg.offline and cfg.sync_enabled
        self._rng = rng
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.consecutive_unavailable = 0
        self.last_error = ""
        self.online = False

    def run_once(self) -> int:
        """One drain cycle. Returns number of items delivered."""
        if not self._enabled():
            return 0
        delivered_total = 0
        while not self._stop.is_set():
            batch = self.queue.claim_batch(self.batch_size)
            if not batch:
                break
            ids = [i.queue_id for i in batch]
            try:
                result = self.transport.send(batch)
            except TransportUnavailable as exc:
                self._unavailable(ids, str(exc))
                break
            except TransportRejected as exc:
                self.last_error = str(exc)
                for qid in ids:
                    self.queue.mark_failed(qid, str(exc))  # backoff; dead after max_attempts
                break
            except Exception as exc:
                log.exception("transport crashed")
                self.last_error = type(exc).__name__
                for qid in ids:
                    self.queue.mark_failed(qid, f"transport error: {type(exc).__name__}")
                break
            self.online = True
            self.consecutive_unavailable = 0
            self.last_error = ""
            for qid in result.delivered:
                self.queue.mark_delivered(qid)
            for qid, err in result.failed.items():
                self.queue.mark_failed(qid, err)
            delivered_total += len(result.delivered)
            unresolved = set(ids) - set(result.delivered) - set(result.failed)
            if unresolved:  # transport silently skipped items: treat as retryable failure
                for qid in unresolved:
                    self.queue.mark_failed(qid, "not acknowledged by transport")
                break
        return delivered_total

    def _unavailable(self, ids: list[int], err: str) -> None:
        self.online = False
        self.consecutive_unavailable += 1
        self.last_error = err
        delay = backoff_delay(
            self.consecutive_unavailable, self.offline_base_s, self.offline_max_s, self._rng
        )
        self.queue.defer(ids, err, delay)
        log.info("sync offline (%s); retry in %.1fs", err, delay)

    def next_sleep(self) -> float:
        if self.consecutive_unavailable:
            return backoff_delay(
                self.consecutive_unavailable, self.offline_base_s, self.offline_max_s, self._rng
            )
        return self.interval_s

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
                self.queue.enforce_retention()
            except Exception:
                log.exception("sync cycle failed")
            self._stop.wait(self.next_sleep())

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="centralium-sync", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict[str, Any]:
        return {
            "online": self.online,
            "consecutive_unavailable": self.consecutive_unavailable,
            "last_error": self.last_error,
            "pending": self.queue.pending(),
        }
