"""Optional eBPF collector - NOT IMPLEMENTED.

This is an honest stub: it reports ``health() == (False, ...)`` and never emits events.
A real implementation needs ``bcc`` (python3-bcc + kernel headers) or libbpf, root/CAP_BPF,
and kprobes/tracepoints for execve/connect/openat. Use :class:`AuditdCollector` (primary)
and :class:`PsutilCollector` (no-root) until then.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from typing import Any

from centralium.agent.interfaces import EventSink

log = logging.getLogger(__name__)

NOT_IMPLEMENTED = "eBPF collector not implemented (needs bcc/libbpf + root); use auditd or psutil collectors"


class EbpfCollector:
    name = "ebpf"
    platforms = ("linux",)

    def __init__(self, **_: Any) -> None:
        self._running = False

    @staticmethod
    def bcc_available() -> bool:
        return sys.platform.startswith("linux") and importlib.util.find_spec("bcc") is not None

    def start(self, sink: EventSink) -> None:
        log.warning(NOT_IMPLEMENTED)

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return False

    def health(self) -> tuple[bool, str]:
        suffix = (
            "bcc is importable but the probes are not written"
            if self.bcc_available()
            else "bcc not installed"
        )
        return False, f"{NOT_IMPLEMENTED} ({suffix})"
