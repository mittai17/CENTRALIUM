"""Windows Event Log / Sysmon reader using ``wevtutil`` (argument arrays, never a shell).

Imports cleanly on Linux; on non-Windows hosts ``health()`` reports unavailable unless a
``runner`` is injected (tests feed recorded XML through it). Per channel the reader keeps the
last seen ``EventRecordID`` and only queries newer records (baseline = skip existing records
unless ``from_start``). pywin32 (``win32evtlog``) is NOT used; wevtutil ships with Windows.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from centralium.agent.collectors._base import BaseCollector
from centralium.agent.normalization.windows import parse_event_xml, split_event_xml

log = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_CHANNELS = (SYSMON_CHANNEL, "Security", "System", "Microsoft-Windows-PowerShell/Operational")
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9._\- /]{1,200}$")

# runner(argv) -> stdout text; raises OSError/subprocess errors on failure
Runner = Callable[[list[str]], str]


def _default_runner(argv: list[str]) -> str:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        raise OSError(f"wevtutil exit {proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout


class EventLogCollector(BaseCollector):
    name = "eventlog"
    platforms = ("windows",)

    def __init__(
        self,
        channels: tuple[str, ...] = DEFAULT_CHANNELS,
        *,
        from_start: bool = False,
        batch_size: int = 200,
        runner: Runner | None = None,
        wevtutil: str = "wevtutil",
        poll_interval: float = 2.0,
        **kw: Any,
    ) -> None:
        super().__init__(poll_interval=poll_interval, **kw)
        for ch in channels:
            if not _CHANNEL_RE.match(ch):
                raise ValueError(f"invalid event log channel name: {ch!r}")
        self.channels = channels
        self.from_start = from_start
        self.batch_size = max(1, min(batch_size, 1000))
        self.wevtutil = wevtutil
        self._runner = runner
        self._last: dict[str, int] = {}
        if runner is None and not sys.platform.startswith("win"):
            self.set_health(False, "wevtutil/Windows Event Log not available on this platform")
        else:
            self.set_health(True, "ready")

    def _run_cmd(self, argv: list[str]) -> str:
        return (self._runner or _default_runner)(argv)

    def _query(self, channel: str, xpath: str | None, count: int, newest_first: bool) -> list[str]:
        argv = [
            self.wevtutil,
            "qe",
            channel,
            "/f:xml",
            f"/c:{int(count)}",
            f"/rd:{'true' if newest_first else 'false'}",
        ]
        if xpath:
            argv.append(f"/q:{xpath}")
        return split_event_xml(self._run_cmd(argv))

    def poll_once(self) -> int:
        """Poll every channel once; returns number of events enqueued."""
        n = 0
        for ch in self.channels:
            try:
                n += self._poll_channel(ch)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                self.set_health(False, f"{ch}: {exc}")
                log.warning("eventlog poll of %s failed: %s", ch, exc)
        return n

    def _poll_channel(self, channel: str) -> int:
        last = self._last.get(channel)
        if last is None:
            if self.from_start:
                self._last[channel] = 0
                last = 0
            else:  # baseline: remember newest record id, emit nothing
                docs = self._query(channel, None, 1, True)
                self._last[channel] = parse_event_xml(docs[0]).record_id or 0 if docs else 0
                return 0
        xpath = f"*[System[(EventRecordID>{int(last)})]]"
        docs = self._query(channel, xpath, self.batch_size, False)
        emitted = 0
        fmt = "sysmon" if "sysmon" in channel.lower() else "eventlog"
        for doc in docs:
            try:
                rid = parse_event_xml(doc).record_id
            except ValueError:
                self.stats["normalize_errors"] += 1
                continue
            if rid is not None and rid > self._last.get(channel, 0):
                self._last[channel] = rid
            emitted += self.emit_raw({"format": fmt, "xml": doc})
        self.set_health(True, "polling")
        return emitted

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.poll_interval)
