"""Top-level Normalizer: routes raw collector dicts to the right format parser.

Implements :class:`centralium.agent.interfaces.Normalizer`. ``normalize`` raises only
``ValueError`` (never any other exception) on unusable input; ``normalize_many`` returns
0..n events and ``try_normalize`` returns ``None`` instead of raising.

Accepted raw shapes (``format`` key optional; autodetected otherwise)::

    {"format": "auditd",   "lines": ["type=SYSCALL ...", "type=EXECVE ...", ...]}   # or "line": "..."
    {"format": "psutil",   "kind": "process"|"process_exit"|"connection", ...}
    {"format": "sysmon",   "xml": "<Event>...</Event>"}   # or Event-shaped JSON / "json": "<text>"
    {"format": "eventlog", "xml": ...} / {"Event": {"System": ..., "EventData": ...}}
    {"format": "etw",      "provider": "Microsoft-Windows-Kernel-Process", "event_id": 1, ...}
    {"format": "generic" | "replay", "event_type": "process_start", ...}
"""

from __future__ import annotations

import logging
from typing import Any

from centralium.agent.models import NormalizedEvent
from centralium.agent.normalization import auditd as _auditd
from centralium.agent.normalization import generic as _generic
from centralium.agent.normalization import windows as _win
from centralium.agent.normalization.common import pick

log = logging.getLogger(__name__)

FORMATS = ("auditd", "psutil", "sysmon", "eventlog", "etw", "generic", "replay")


def detect_format(raw: dict[str, Any]) -> str:
    fmt = pick(raw, "format")
    if isinstance(fmt, str) and fmt.lower() in FORMATS:
        return fmt.lower()
    if "lines" in raw or "line" in raw or "records" in raw:
        return "auditd"
    if any(k in raw for k in ("xml", "raw_xml", "Event", "EventData", "EventID")):
        return "eventlog"
    if "provider" in {str(k).lower() for k in raw} or "providername" in {str(k).lower() for k in raw}:
        return "etw"
    if raw.get("kind") in {"process", "process_exit", "connection", "listen"} and "event_type" not in raw:
        return "psutil"
    return "generic"


class EventNormalizer:
    """Stateless, thread-safe raw -> NormalizedEvent converter for every supported format."""

    def __init__(self, host_id: str = "localhost") -> None:
        self.host_id = host_id

    def normalize_many(self, raw: dict[str, Any]) -> list[NormalizedEvent]:
        if not isinstance(raw, dict):
            raise ValueError(f"raw record must be a dict, got {type(raw).__name__}")
        try:
            return self._dispatch(raw)
        except ValueError:
            raise
        except Exception as exc:  # never let a parser bug escape as a non-ValueError
            log.debug("normalizer internal error", exc_info=True)
            raise ValueError(f"unusable raw record: {type(exc).__name__}: {exc}") from exc

    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        events = self.normalize_many(raw)
        if not events:
            raise ValueError("record produced no event (not security-relevant)")
        return events[0]

    def try_normalize(self, raw: Any) -> NormalizedEvent | None:
        try:
            return self.normalize(raw)
        except ValueError:
            return None

    # ------------------------------------------------------------------ internals
    def _dispatch(self, raw: dict[str, Any]) -> list[NormalizedEvent]:
        fmt = detect_format(raw)
        host = self.host_id
        if fmt == "auditd":
            lines = raw.get("lines")
            if lines is None and isinstance(raw.get("line"), str):
                lines = [raw["line"]]
            if lines is None and isinstance(raw.get("records"), list):
                lines = raw["records"]
            if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
                raise ValueError("auditd record needs 'lines': list[str]")
            return _auditd.normalize_auditd(lines[:64], host)
        if fmt == "psutil":
            return [_generic.normalize_psutil(raw, host)]
        if fmt in {"sysmon", "eventlog"}:
            rec = _win.record_from_raw(raw)
            if rec.event_id is None:
                raise ValueError("Windows event has no EventID")
            if fmt == "sysmon" or _win.is_sysmon(rec):
                return [_win.normalize_sysmon(rec, host)]
            return [_win.normalize_eventlog(rec, host)]
        if fmt == "etw":
            return [_win.normalize_etw(raw, host)]
        return [_generic.normalize_generic(raw, host, "replay")]
