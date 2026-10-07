"""ETW collector - real-time ETW sessions are NOT implemented; documented safe fallback.

A real ETW consumer needs admin rights plus pywin32/``pywintrace``/ctypes TDH decoding of
Microsoft-Windows-Kernel-Process/File/Network/Registry and DNS-Client. Until that exists this
class (a) reports ``health() == (False, <reason>)`` and (b) transparently runs the psutil
poller as the fallback so process/network telemetry is still produced. ETW-shaped dicts that
another component captures can be normalized with ``EventNormalizer`` (format "etw") and
pushed in through :meth:`EtwCollector.ingest`.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from centralium.agent.collectors._base import BaseCollector
from centralium.agent.interfaces import EventSink

log = logging.getLogger(__name__)

ETW_NOT_IMPLEMENTED = "ETW real-time session not implemented; psutil poller fallback active"


class EtwCollector(BaseCollector):
    name = "etw"
    platforms = ("windows",)

    def __init__(self, *, fallback: bool = True, **kw: Any) -> None:
        super().__init__(**kw)
        self.use_fallback = fallback
        self._fallback: BaseCollector | None = None
        self._kw = kw
        self.set_health(False, ETW_NOT_IMPLEMENTED if fallback else "ETW real-time session not implemented")

    def start(self, sink: EventSink) -> None:
        super().start(sink)
        if self.use_fallback and self._fallback is None:
            from centralium.agent.collectors.linux.psutil_poller import PsutilCollector

            self._fallback = PsutilCollector(
                host_id=self.host_id,
                normalizer=self.normalizer,
                max_events_per_sec=self._kw.get("max_events_per_sec", 0.0),
            )
            self._fallback.start(sink)
            log.warning(ETW_NOT_IMPLEMENTED)

    def stop(self) -> None:
        if self._fallback is not None:
            self._fallback.stop()
            self._fallback = None
        super().stop()

    def ingest(self, etw_record: dict[str, Any]) -> int:
        """Normalize an externally captured ETW-shaped dict and enqueue it."""
        rec = dict(etw_record)
        rec.setdefault("format", "etw")
        return self.emit_raw(rec)

    def _run(self) -> None:
        self._stop.wait()  # no ETW session; dispatcher still drains ``ingest`` events

    @staticmethod
    def platform_supported() -> bool:
        return sys.platform.startswith("win")
