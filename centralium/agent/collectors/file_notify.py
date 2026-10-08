"""inotify / fanotify file telemetry collector for protected directories and ransomware canaries.

Features:
- Monitors protected system directories (e.g., /etc, /bin, /usr/bin) and ransomware canary paths.
- Emits NormalizedEvent instances for FILE_CREATE, FILE_MODIFY, FILE_DELETE, FILE_RENAME.
- Distinguishes honeyfile / canary access with ``is_canary: True`` in ``raw_metadata``.
- Built on BaseCollector: bounded queue, rate limiting (TokenBucket),
  non-blocking event drop under backpressure.
- Clean cross-platform degradation: honest health report when inotify/fanotify is unavailable.
"""

from __future__ import annotations

import ctypes
import logging
import os
import select
import struct
import sys
import threading
import time
from collections.abc import Iterable
from typing import Any

from centralium.agent.collectors._base import BaseCollector
from centralium.agent.models import EventType
from centralium.agent.normalization.common import canon_path, make_event

log = logging.getLogger(__name__)

# Linux inotify constants
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_NONBLOCK = 0x00000800
IN_CLOEXEC = 0x00080000

DEFAULT_WATCH_MASK = (
    IN_MODIFY
    | IN_CLOSE_WRITE
    | IN_ATTRIB
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

DEFAULT_PROTECTED_PATHS = ("/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin")
EVENT_STRUCT_FMT = "iIII"
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FMT)


class InotifyLib:
    """ctypes wrapper around libc inotify calls."""

    def __init__(self) -> None:
        self.available = False
        self._libc: Any = None
        if not sys.platform.startswith("linux"):
            return
        try:
            self._libc = ctypes.CDLL(None)
            self._libc.inotify_init1.argtypes = [ctypes.c_int]
            self._libc.inotify_init1.restype = ctypes.c_int
            self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self._libc.inotify_add_watch.restype = ctypes.c_int
            self._libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            self._libc.inotify_rm_watch.restype = ctypes.c_int
            self.available = True
        except (AttributeError, OSError) as exc:
            log.debug("libc inotify binding not available: %s", exc)

    def init(self, flags: int = IN_CLOEXEC | IN_NONBLOCK) -> int:
        if not self.available or self._libc is None:
            raise OSError("inotify not available on this platform")
        fd = self._libc.inotify_init1(flags)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"inotify_init1 failed: errno {err}")
        return int(fd)

    def add_watch(self, fd: int, path: str, mask: int) -> int:
        if not self.available or self._libc is None:
            raise OSError("inotify not available")
        wd = self._libc.inotify_add_watch(fd, path.encode("utf-8"), mask)
        if wd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"inotify_add_watch({path}) failed: errno {err}")
        return int(wd)

    def rm_watch(self, fd: int, wd: int) -> int:
        if not self.available or self._libc is None:
            return -1
        return int(self._libc.inotify_rm_watch(fd, wd))


_INOTIFY = InotifyLib()


class FileNotifyCollector(BaseCollector):
    """File telemetry collector utilizing inotify for protected dirs and canary paths."""

    name = "file_notify"
    platforms = ("linux",)

    def __init__(
        self,
        watch_paths: Iterable[str] | None = None,
        canary_paths: Iterable[str] | None = None,
        *,
        watch_mask: int = DEFAULT_WATCH_MASK,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.watch_paths: list[str] = [
            canon_path(p) or p for p in (watch_paths if watch_paths is not None else DEFAULT_PROTECTED_PATHS)
        ]
        self.canary_paths: set[str] = {canon_path(p) or p for p in (canary_paths or ())}
        self.watch_mask = watch_mask

        self._fd: int | None = None
        self._wd_to_path: dict[int, str] = {}
        self._lock = threading.Lock()
        self._pending_cookies: dict[int, tuple[float, str]] = {}  # cookie -> (ts, old_path)

        self.stats.update(
            {
                "kernel_overflows": 0,
                "watches_active": 0,
                "file_creates": 0,
                "file_modifies": 0,
                "file_deletes": 0,
                "file_renames": 0,
                "canary_touches": 0,
            }
        )

        if not _INOTIFY.available:
            self.set_health(False, "inotify not available on this platform")
        else:
            self.set_health(True, "ready")

    def add_watch_path(self, path: str, is_canary: bool = False) -> bool:
        """Add a path to monitor dynamically."""
        cpath = canon_path(path) or path
        if is_canary:
            self.canary_paths.add(cpath)
        if cpath not in self.watch_paths:
            self.watch_paths.append(cpath)
        if self._fd is not None:
            try:
                wd = _INOTIFY.add_watch(self._fd, cpath, self.watch_mask)
                with self._lock:
                    self._wd_to_path[wd] = cpath
                    self.stats["watches_active"] = len(self._wd_to_path)
                return True
            except OSError as exc:
                log.warning("failed to add watch for %s: %s", cpath, exc)
                return False
        return True

    def _init_watches(self) -> bool:
        if not _INOTIFY.available:
            self.set_health(False, "inotify not available on this platform")
            return False
        try:
            self._fd = _INOTIFY.init()
        except OSError as exc:
            self.set_health(False, f"inotify_init1 failed: {exc}")
            return False

        active = 0
        all_paths = set(self.watch_paths) | self.canary_paths
        for p in all_paths:
            if not os.path.exists(p):
                continue
            try:
                wd = _INOTIFY.add_watch(self._fd, p, self.watch_mask)
                self._wd_to_path[wd] = p
                active += 1
            except OSError as exc:
                log.debug("could not watch %s: %s", p, exc)

        self.stats["watches_active"] = active
        if active == 0 and all_paths:
            self.set_health(False, "none of the configured watch paths exist or could be watched")
            return False

        self.set_health(True, f"inotify monitoring {active} paths")
        return True

    def start(self, sink: Any) -> None:
        if self._init_watches():
            super().start(sink)
        else:
            log.warning("FileNotifyCollector did not start watches successfully")

    def stop(self) -> None:
        self._stop.set()
        if self._fd is not None:
            try:
                for wd in list(self._wd_to_path.keys()):
                    _INOTIFY.rm_watch(self._fd, wd)
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self._wd_to_path.clear()
        super().stop()

    def _run(self) -> None:
        if self._fd is None:
            return

        buf = bytearray()
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self._fd], [], [], 0.2)
                if not r:
                    continue
                chunk = os.read(self._fd, 65536)
                if not chunk:
                    break
                buf.extend(chunk)
                self._process_buffer(buf)
            except OSError as exc:
                if not self._stop.is_set():
                    log.warning("inotify read error: %s", exc)
                    self.set_health(False, f"read error: {exc}")
                break

    def _process_buffer(self, buf: bytearray) -> None:
        offset = 0
        while offset + EVENT_STRUCT_SIZE <= len(buf):
            wd, mask, cookie, name_len = struct.unpack_from(EVENT_STRUCT_FMT, buf, offset)
            offset += EVENT_STRUCT_SIZE
            if offset + name_len > len(buf):
                offset -= EVENT_STRUCT_SIZE
                break
            name_raw = bytes(buf[offset : offset + name_len])
            offset += name_len
            name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")

            if mask & IN_Q_OVERFLOW:
                self.stats["kernel_overflows"] += 1
                log.warning("inotify kernel queue overflowed; some file events were dropped")
                continue

            base_dir = self._wd_to_path.get(wd)
            if not base_dir:
                continue

            full_path = canon_path(os.path.join(base_dir, name) if name else base_dir) or base_dir
            self._handle_event(full_path, mask, cookie, base_dir)

        if offset > 0:
            del buf[:offset]

    def _handle_event(self, full_path: str, mask: int, cookie: int, base_dir: str) -> None:
        is_canary = full_path in self.canary_paths or base_dir in self.canary_paths
        if is_canary:
            self.stats["canary_touches"] += 1

        meta: dict[str, Any] = {
            "mask": mask,
            "base_dir": base_dir,
            "is_canary": is_canary,
        }

        # Check for rename cookie correlation
        if mask & IN_MOVED_FROM and cookie != 0:
            self._pending_cookies[cookie] = (time.monotonic(), full_path)
            self.stats["file_deletes"] += 1
            ev = make_event(
                event_type=EventType.FILE_DELETE,
                host_id=self.host_id,
                source="inotify",
                file_path=full_path,
                raw_metadata=meta,
            )
            self.emit_event(ev)
            return

        if mask & IN_MOVED_TO and cookie != 0 and cookie in self._pending_cookies:
            _, old_path = self._pending_cookies.pop(cookie)
            meta["old_path"] = old_path
            self.stats["file_renames"] += 1
            ev = make_event(
                event_type=EventType.FILE_RENAME,
                host_id=self.host_id,
                source="inotify",
                file_path=full_path,
                raw_metadata=meta,
            )
            self.emit_event(ev)
            return

        et: EventType | None = None
        if mask & (IN_CREATE | IN_MOVED_TO):
            et = EventType.FILE_CREATE
            self.stats["file_creates"] += 1
        elif mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB):
            et = EventType.FILE_MODIFY
            self.stats["file_modifies"] += 1
        elif mask & (IN_DELETE | IN_MOVED_FROM | IN_DELETE_SELF):
            et = EventType.FILE_DELETE
            self.stats["file_deletes"] += 1
        elif mask & IN_MOVE_SELF:
            et = EventType.FILE_RENAME
            self.stats["file_renames"] += 1

        if et is not None:
            ev = make_event(
                event_type=et,
                host_id=self.host_id,
                source="inotify",
                file_path=full_path,
                raw_metadata=meta,
            )
            self.emit_event(ev)
