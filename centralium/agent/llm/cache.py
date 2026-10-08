"""LRU cache keyed by incident fingerprint (parent binary + cmdline hash + network destination).

Caches structured AI verdicts across identical execution contexts to reduce latency
and eliminate redundant LLM calls on recurring processes/commands.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Any

from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm.prompts import normalize_role
from centralium.agent.models import AIAnalysis, NormalizedEvent


def make_fingerprint(
    parent_binary: str | None,
    command_line: str | None,
    destination: str | None,
    role: str = "threat_analyst",
) -> str:
    """Compute 24-char hex fingerprint from parent binary, cmdline hash, destination, and role."""
    parent = (parent_binary or "none").strip().lower()
    cmd = (command_line or "").strip()
    cmd_hash = hashlib.sha256(cmd.encode("utf-8", errors="replace")).hexdigest()[:16]
    dest = (destination or "none").strip().lower()
    norm_role = normalize_role(role)
    raw = f"{parent}|{cmd_hash}|{dest}|{norm_role}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def fingerprint_from_event(event: NormalizedEvent, role: str = "threat_analyst") -> str:
    parent = event.parent_process or ""
    cmd = event.command_line or ""
    if event.destination_ip:
        dest = f"{event.destination_ip}:{event.destination_port}"
    else:
        dest = event.domain or "none"
    return make_fingerprint(parent, cmd, dest, role)


def fingerprint_from_request(request: LLMRequest) -> str:
    return fingerprint_from_event(request.event, request.role)


class IncidentFingerprintCache:
    """Thread-safe LRU cache storing AIAnalysis keyed by incident fingerprint."""

    def __init__(self, capacity: int = 512) -> None:
        self.capacity = max(1, capacity)
        self._cache: OrderedDict[str, AIAnalysis] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.saved_latency_ms = 0.0

    def get_by_request(self, request: LLMRequest) -> AIAnalysis | None:
        key = fingerprint_from_request(request)
        return self.get(key, event_id=request.event.event_id)

    def put_by_request(self, request: LLMRequest, analysis: AIAnalysis) -> None:
        if not analysis.available or analysis.verdict is None:
            return  # do not cache failed analyses
        key = fingerprint_from_request(request)
        self.put(key, analysis)

    def get(self, key: str, *, event_id: str | None = None) -> AIAnalysis | None:
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                self.hits += 1
                self.saved_latency_ms += hit.latency_ms
                # Return deep copy with current event_id if provided
                copy_dict = hit.model_dump()
                if event_id is not None:
                    copy_dict["event_id"] = event_id
                return AIAnalysis.model_validate(copy_dict)
            self.misses += 1
            return None

    def put(self, key: str, analysis: AIAnalysis) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = analysis
            else:
                if len(self._cache) >= self.capacity:
                    self._cache.popitem(last=False)
                    self.evictions += 1
                self._cache[key] = analysis

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            hit_ratio = round(self.hits / total, 4) if total else 0.0
            return {
                "size": len(self._cache),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio": hit_ratio,
                "evictions": self.evictions,
                "saved_latency_ms": round(self.saved_latency_ms, 2),
            }
