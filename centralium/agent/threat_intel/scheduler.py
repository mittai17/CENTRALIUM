"""Offline-safe periodic feed updater with per-feed rate limiting and exponential backoff.

Network is OFF by default (``allow_network=False``): ``run_once`` then only imports configured
local files. Any fetch/parse failure is logged, recorded and backed off - it never propagates.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from centralium.agent.threat_intel.feeds import FeedParseError, parse_feed
from centralium.agent.threat_intel.store import CachedIOCStore

log = logging.getLogger("centralium.threat_intel.updater")

Fetcher = Callable[[str, dict[str, str], float, int], bytes]


@dataclass(frozen=True, slots=True)
class FeedSpec:
    name: str
    fmt: str  # malwarebazaar|threatfox|urlhaus|feodo|centralium
    url: str | None = None
    path: str | None = None  # local file (offline import)
    min_interval_s: float = 3600.0  # provider rate-limit courtesy
    auth_env: str | None = None  # env var holding an abuse.ch Auth-Key
    enabled: bool = True


DEFAULT_FEEDS: tuple[FeedSpec, ...] = (
    FeedSpec(
        "malwarebazaar", "malwarebazaar", "https://bazaar.abuse.ch/export/csv/recent/", min_interval_s=3600
    ),
    FeedSpec("threatfox", "threatfox", "https://threatfox.abuse.ch/export/json/recent/", min_interval_s=3600),
    FeedSpec("urlhaus", "urlhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/", min_interval_s=300),
    FeedSpec(
        "feodotracker",
        "feodo",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        min_interval_s=300,
    ),
)


class NetworkDisabledError(RuntimeError):
    pass


def http_fetch(url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> bytes:
    """HTTPS-only bounded download (stdlib)."""
    if not url.lower().startswith("https://"):
        raise ValueError("only https feeds are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "centralium-ti/0.1", **headers})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data: bytes = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("feed exceeds size limit")
    return data


@dataclass(slots=True)
class _State:
    last_attempt: float = float("-inf")
    next_allowed: float = float("-inf")
    failures: int = 0
    last_error: str = ""
    last_count: int = 0


@dataclass(slots=True)
class UpdateReport:
    added: int = 0
    feeds: dict[str, str] = field(default_factory=dict)  # name -> ok:<n> | skipped:<why> | error:<msg>


class FeedUpdater:
    def __init__(
        self,
        store: CachedIOCStore,
        feeds: tuple[FeedSpec, ...] | list[FeedSpec] = (),
        *,
        allow_network: bool = False,
        fetcher: Fetcher | None = None,
        interval_s: float = 900.0,
        timeout_s: float = 10.0,
        max_bytes: int = 64 * 1024 * 1024,
        max_backoff_s: float = 86_400.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store, self.feeds = store, list(feeds)
        self.allow_network, self._fetcher = allow_network, fetcher or http_fetch
        self.interval_s, self.timeout_s, self.max_bytes = interval_s, timeout_s, max_bytes
        self.max_backoff_s, self._clock = max_backoff_s, clock
        self._state: dict[str, _State] = {f.name: _State() for f in self.feeds}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def state(self, name: str) -> _State:
        return self._state[name]

    def run_once(self, *, force: bool = False) -> UpdateReport:
        rep = UpdateReport()
        with self._lock:
            for f in self.feeds:
                rep.feeds[f.name] = self._run_feed(f, force, rep)
        if rep.added:
            self.store.clear_cache()
        return rep

    def _run_feed(self, f: FeedSpec, force: bool, rep: UpdateReport) -> str:
        st = self._state.setdefault(f.name, _State())
        if not f.enabled:
            return "skipped:disabled"
        now = self._clock()
        if not force and now < max(st.next_allowed, st.last_attempt + f.min_interval_s):
            return "skipped:rate-limited"
        st.last_attempt = now
        try:
            if f.path:
                p = Path(f.path)
                if p.stat().st_size > self.max_bytes:
                    raise ValueError("local feed too large")
                data = p.read_bytes()
            elif f.url:
                if not self.allow_network:
                    return "skipped:offline"
                headers: dict[str, str] = {}
                if f.auth_env and (key := os.environ.get(f.auth_env)):
                    headers["Auth-Key"] = key
                data = self._fetcher(f.url, headers, self.timeout_s, self.max_bytes)
            else:
                return "skipped:no-source"
            n = self.store.add_records(parse_feed(f.fmt, data, source=f.name).records)
        except (OSError, ValueError, FeedParseError, TimeoutError) as exc:
            return self._fail(f, st, now, exc)
        except Exception as exc:  # network libs raise many types; never break the agent
            return self._fail(f, st, now, exc)
        st.failures, st.last_error, st.last_count = 0, "", n
        rep.added += n
        return f"ok:{n}"

    def _fail(self, f: FeedSpec, st: _State, now: float, exc: Exception) -> str:
        st.failures += 1
        st.last_error = f"{type(exc).__name__}: {exc}"[:300]
        st.next_allowed = now + min(self.max_backoff_s, f.min_interval_s * (2 ** min(st.failures, 10)))
        log.warning("feed %s update failed (%d): %s", f.name, st.failures, st.last_error)
        return f"error:{st.last_error}"

    # ------------------------------------------------------------------ background loop
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ti-updater", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("updater loop error (ignored)")
            self._stop.wait(self.interval_s)
