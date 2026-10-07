"""auditd log tailer (``/var/log/audit/audit.log``): groups records by serial and normalizes them.

Reading the audit log normally needs root or membership of the group set in ``log_group``
(auditd.conf). Without access the collector reports ``health() == (False, reason)`` and keeps
retrying; it never raises. Rotation/truncation is detected via inode/size.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from centralium.agent.collectors._base import BaseCollector
from centralium.agent.normalization.auditd import group_serial

log = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG = "/var/log/audit/audit.log"
MAX_LINE = 65536
MAX_GROUP_LINES = 64


class AuditdCollector(BaseCollector):
    name = "auditd"
    platforms = ("linux",)

    def __init__(
        self,
        path: str = DEFAULT_AUDIT_LOG,
        *,
        from_start: bool = False,
        group_timeout: float = 1.0,
        poll_interval: float = 0.5,
        **kw: Any,
    ) -> None:
        super().__init__(poll_interval=poll_interval, **kw)
        self.path = path
        self.from_start = from_start
        self.group_timeout = group_timeout
        self._buf: list[str] = []
        self._buf_serial: int | None = None
        self._buf_age = 0.0
        self._partial = b""
        self.refresh_health()

    def refresh_health(self) -> tuple[bool, str]:
        if not os.path.exists(self.path):
            self.set_health(False, f"{self.path} does not exist (auditd not installed/running?)")
        elif not os.access(self.path, os.R_OK):
            self.set_health(
                False, f"permission denied reading {self.path} (needs root or the audit log group)"
            )
        else:
            self.set_health(True, f"tailing {self.path}")
        return self.health()

    # ------------------------------------------------------------------ line handling (unit-testable)
    def feed_lines(self, lines: list[str], now: float = 0.0) -> int:
        """Feed audit lines; completed serial groups are normalized and enqueued."""
        n = 0
        for line in lines:
            line = line.rstrip("\n")
            if not line or len(line) > MAX_LINE:
                continue
            serial = group_serial(line)
            if serial is None:
                continue
            if self._buf and serial != self._buf_serial:
                n += self.flush()
            self._buf_serial = serial
            if len(self._buf) < MAX_GROUP_LINES:
                self._buf.append(line)
            self._buf_age = now
            if line.startswith("type=EOE"):
                n += self.flush()
        return n

    def flush(self) -> int:
        if not self._buf:
            return 0
        group, self._buf, self._buf_serial = self._buf, [], None
        return self.emit_raw({"format": "auditd", "lines": group})

    # ------------------------------------------------------------------ tail loop
    def _run(self) -> None:
        import time

        fh = None
        inode = -1
        pos = 0
        while not self._stop.is_set():
            try:
                if fh is None:
                    fh = open(self.path, "rb")  # noqa: SIM115 - long-lived handle
                    st = os.fstat(fh.fileno())
                    inode = st.st_ino
                    if not self.from_start:
                        fh.seek(0, os.SEEK_END)
                    pos = fh.tell()
                    self.set_health(True, f"tailing {self.path}")
                chunk = fh.read(1 << 20)
                if chunk:
                    pos += len(chunk)
                    data = self._partial + chunk
                    *complete, self._partial = data.split(b"\n")
                    if len(self._partial) > MAX_LINE:
                        self._partial = b""
                    self.feed_lines([c.decode("utf-8", "replace") for c in complete], time.monotonic())
                    continue
                if self._buf and time.monotonic() - self._buf_age >= self.group_timeout:
                    self.flush()
                try:
                    st = os.stat(self.path)
                    if st.st_ino != inode or st.st_size < pos:  # rotated or truncated
                        fh.close()
                        fh = None
                        self.from_start = True
                        self._partial = b""
                        continue
                except FileNotFoundError:
                    pass
            except PermissionError:
                self.set_health(
                    False, f"permission denied reading {self.path} (needs root or the audit log group)"
                )
                self._stop.wait(5.0)
                continue
            except FileNotFoundError:
                self.set_health(False, f"{self.path} does not exist (auditd not installed/running?)")
                self._stop.wait(5.0)
                continue
            self._stop.wait(self.poll_interval)
        if fh is not None:
            fh.close()
        self.flush()
