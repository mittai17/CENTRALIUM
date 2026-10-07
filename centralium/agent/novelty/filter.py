"""Baseline novelty filter implementing ``NoveltyFilter``.

Dimensions (each only applies when the event carries the data):

* ``process``      process name (+ executable directory)
* ``user``         user -> process pairs
* ``parent_child`` parent -> child process pairs
* ``destination``  process -> destination (domain, else IP:port)
* ``frequency``    per-process event rate (events / minute) versus the learned peak

Semantics
---------
* ``learn()`` is the ONLY writer (the pipeline calls it in LEARNING mode); ``assess()`` is
  read-only, so attacker activity in PASSIVE/ACTIVE can never poison baselines.
* A key is *established* after ``min_hits`` observations; novelty of a dimension decays
  linearly from 1.0 (unseen) to 0.0 (established).
* Final novelty is the weighted mean over applicable dimensions, multiplied by
  ``1 - trust_discount`` when ``event.signer`` is in ``trusted_signers`` (signed-binary
  trust). The discount reduces but never zeroes novelty, and high-severity findings still win.
* An empty baseline treats everything as novel (conservative: gate keeps analysing).
* High-severity behavioural findings force ``is_novel=True`` regardless of baselines.
* Persisted in SQLite (``:memory:`` ok); writes are write-behind (``flush()``/``close()``).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from centralium.agent.interfaces import BehaviorResult
from centralium.agent.models import NormalizedEvent, NoveltyResult, Severity

log = logging.getLogger("centralium.novelty")

DIMENSIONS = ("process", "user", "parent_child", "destination", "frequency")
_HIGH = {Severity.HIGH, Severity.CRITICAL}


@dataclass
class NoveltySettings:
    min_hits: int = 3
    novel_threshold: float = 0.5
    trust_discount: float = 0.6  # multiplier reduction for trusted signer: score *= (1 - discount)
    trusted_signers: frozenset[str] = frozenset()
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "process": 0.30,
            "parent_child": 0.25,
            "destination": 0.20,
            "user": 0.15,
            "frequency": 0.10,
        }
    )
    freq_window_sec: float = 60.0
    freq_slack_factor: float = 2.0
    freq_slack_abs: int = 5
    flush_every: int = 200


def _n(s: str | None) -> str:
    return (s or "").strip().lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _dir(p: str | None) -> str:
    if not p:
        return ""
    p = p.replace("\\", "/").lower()
    return p.rsplit("/", 1)[0] if "/" in p else ""


class BaselineNoveltyFilter:
    def __init__(self, path: str | Path = ":memory:", settings: NoveltySettings | None = None) -> None:
        self.s = settings or NoveltySettings()
        self._lock = threading.RLock()
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS baseline(dim TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL, "  # noqa: E501
            "first_seen REAL NOT NULL, last_seen REAL NOT NULL, extra REAL NOT NULL DEFAULT 0, "
            "PRIMARY KEY(dim, key))"
        )
        self._counts: dict[tuple[str, str], list[float]] = {}  # (dim,key) -> [count, first, last, extra]
        self._dirty: set[tuple[str, str]] = set()
        self._since_flush = 0
        self._rates: dict[str, deque[float]] = {}
        self._load()

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        for dim, key, count, first, last, extra in self._db.execute(
            "SELECT dim, key, count, first_seen, last_seen, extra FROM baseline"
        ):
            self._counts[(dim, key)] = [float(count), first, last, extra]

    def flush(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            rows = [
                (d, k, int(v[0]), v[1], v[2], v[3])
                for (d, k) in self._dirty
                if (v := self._counts.get((d, k)))
            ]
            self._db.execute("BEGIN")
            try:
                self._db.executemany(
                    "INSERT INTO baseline(dim,key,count,first_seen,last_seen,extra) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(dim,key) DO UPDATE SET count=excluded.count, last_seen=excluded.last_seen, "
                    "extra=excluded.extra",
                    rows,
                )
                self._db.execute("COMMIT")
            except sqlite3.Error:
                self._db.execute("ROLLBACK")
                raise
            self._dirty.clear()
            self._since_flush = 0

    def close(self) -> None:
        with self._lock:
            self.flush()
            self._db.close()

    # ------------------------------------------------------------------ keys
    def _keys(self, ev: NormalizedEvent) -> dict[str, str]:
        keys: dict[str, str] = {}
        proc = _n(ev.process_name)
        if proc:
            keys["process"] = f"{proc}|{_dir(ev.executable_path)}"
            if ev.user:
                keys["user"] = f"{ev.user.lower()}|{proc}"
            if ev.parent_process:
                keys["parent_child"] = f"{_n(ev.parent_process)}>{proc}"
            dest = (
                ev.domain.lower()
                if ev.domain
                else (f"{ev.destination_ip}:{ev.destination_port}" if ev.destination_ip else "")
            )
            if dest:
                keys["destination"] = f"{proc}|{dest}"
            keys["frequency"] = proc
        return keys

    def _rate(self, proc: str, ts: float, record: bool) -> int:
        dq = self._rates.setdefault(proc, deque(maxlen=100_000))
        if record:
            dq.append(ts)
        cutoff = ts - self.s.freq_window_sec
        return sum(1 for t in dq if t > cutoff)

    # ------------------------------------------------------------------ learn
    def learn(self, event: NormalizedEvent) -> None:
        ts = event.timestamp.timestamp()
        with self._lock:
            keys = self._keys(event)
            for dim, key in keys.items():
                if dim == "frequency":
                    rate = self._rate(key, ts, record=True)
                    row = self._counts.setdefault((dim, key), [0.0, ts, ts, 0.0])
                    row[0] += 1
                    row[2] = ts
                    row[3] = max(row[3], float(rate))
                else:
                    row = self._counts.setdefault((dim, key), [0.0, ts, ts, 0.0])
                    row[0] += 1
                    row[2] = ts
                self._dirty.add((dim, key))
            self._since_flush += 1
            if self._since_flush >= self.s.flush_every:
                self.flush()

    # ------------------------------------------------------------------ assess
    def _dim_novelty(self, dim: str, key: str, ts: float) -> tuple[float, int, str]:
        row = self._counts.get((dim, key))
        hits = int(row[0]) if row else 0
        if dim == "frequency":
            if row is None or hits < self.s.min_hits:
                return 1.0, hits, f"no frequency baseline for {key}"
            rate = self._rate(key, ts, record=False) + 1  # +1: the event being assessed
            limit = row[3] * self.s.freq_slack_factor + self.s.freq_slack_abs
            if rate > limit:
                return (
                    1.0,
                    hits,
                    f"event rate {rate}/{int(self.s.freq_window_sec)}s exceeds baseline peak {row[3]:.0f}",
                )
            return 0.0, hits, ""
        if hits <= 0:
            return 1.0, 0, f"new {dim.replace('_', '-')}: {key}"
        nov = max(0.0, 1.0 - hits / self.s.min_hits)
        return nov, hits, (f"rare {dim.replace('_', '-')} ({hits} obs): {key}" if nov > 0 else "")

    def assess(self, event: NormalizedEvent, behavior: BehaviorResult) -> NoveltyResult:
        ts = event.timestamp.timestamp()
        with self._lock:
            keys = self._keys(event)
            total_w = acc = 0.0
            reasons: list[str] = []
            hits_total = 0
            for dim, key in keys.items():
                w = self.s.weights.get(dim, 0.0)
                nov, hits, why = self._dim_novelty(dim, key, ts)
                total_w += w
                acc += w * nov
                hits_total += hits
                if why:
                    reasons.append(why)
            empty = not self._counts
        if total_w <= 0:
            return NoveltyResult(
                is_novel=True, novelty_score=1.0, baseline_hits=0, reasons=["no baselinable fields"]
            )
        score = acc / total_w
        if empty:
            return NoveltyResult(
                is_novel=True,
                novelty_score=1.0,
                baseline_hits=0,
                reasons=["baseline empty (learning not done)"],
            )
        signer = (event.signer or "").strip().lower()
        if signer and signer in {x.lower() for x in self.s.trusted_signers}:
            score *= 1.0 - self.s.trust_discount
            reasons.append(f"trusted signer '{event.signer}' reduces novelty")
        score = round(max(0.0, min(1.0, score)), 4)
        is_novel = score >= self.s.novel_threshold
        if any(f.severity in _HIGH for f in behavior.findings):
            if not is_novel:
                reasons.append("high-severity behaviour finding overrides baseline")
            is_novel = True
        return NoveltyResult(
            is_novel=is_novel, novelty_score=score, baseline_hits=hits_total, reasons=reasons
        )

    # ------------------------------------------------------------------ admin
    def learn_many(self, events: Iterable[NormalizedEvent]) -> int:
        n = 0
        for e in events:
            self.learn(e)
            n += 1
        self.flush()
        return n

    def baseline_size(self) -> dict[str, int]:
        with self._lock:
            out = dict.fromkeys(DIMENSIONS, 0)
            for dim, _ in self._counts:
                out[dim] = out.get(dim, 0) + 1
            return out
