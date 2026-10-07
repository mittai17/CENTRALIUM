"""Bounded, safe file hashing for the EPP hot path."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from collections import OrderedDict
from pathlib import Path

DEFAULT_MAX_HASH_BYTES = 64 * 1024 * 1024


def sha256_file(path: str | os.PathLike[str], *, max_bytes: int = DEFAULT_MAX_HASH_BYTES) -> str | None:
    """SHA-256 of a regular file <= ``max_bytes``; None otherwise (missing, FIFO/device/dir, too big,
    unreadable, NUL in path). Size is re-checked on the open fd to avoid TOCTOU/growth tricks."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except (OSError, ValueError):
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        h = hashlib.sha256()
        total = 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                return None
            h.update(b)
        return h.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


class HashCache:
    """LRU keyed by (path, size, mtime_ns) so unchanged files are not re-hashed."""

    def __init__(self, capacity: int = 4096, *, max_bytes: int = DEFAULT_MAX_HASH_BYTES) -> None:
        self._cap, self._max = capacity, max_bytes
        self._d: OrderedDict[tuple[str, int, int], str | None] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, path: str) -> str | None:
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_size > self._max:
            return None
        key = (path, st.st_size, st.st_mtime_ns)
        with self._lock:
            if key in self._d:
                self._d.move_to_end(key)
                return self._d[key]
        digest = sha256_file(Path(path), max_bytes=self._max)
        with self._lock:
            self._d[key] = digest
            while len(self._d) > self._cap:
                self._d.popitem(last=False)
        return digest
