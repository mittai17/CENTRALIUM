"""psutil process/network poller. Works WITHOUT root on Linux (and on Windows as the ETW fallback).

Emits raw psutil snapshot dicts through the shared normalizer. New processes -> PROCESS_START,
vanished -> PROCESS_EXIT, new outbound connections -> NETWORK_CONNECT, new listeners -> NETWORK_LISTEN.
Limits: polling can miss processes shorter than ``poll_interval``; connections of other users'
processes have no pid without root; no file events (use auditd/Sysmon for those).
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import time
from collections import OrderedDict
from typing import Any

from centralium.agent.collectors._base import BaseCollector

log = logging.getLogger(__name__)

_PROC_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]


class PsutilCollector(BaseCollector):
    name = "psutil"
    platforms = ("linux", "windows")

    def __init__(
        self,
        *,
        emit_existing: bool = False,
        track_connections: bool = True,
        skip_loopback: bool = True,
        hash_executables: bool = True,
        max_hash_mb: int = 64,
        max_events_per_poll: int = 1000,
        poll_interval: float = 2.0,
        **kw: Any,
    ) -> None:
        super().__init__(poll_interval=poll_interval, **kw)
        self.emit_existing = emit_existing
        self.track_connections = track_connections
        self.skip_loopback = skip_loopback
        self.hash_executables = hash_executables
        self.max_hash_bytes = max_hash_mb << 20
        self.max_events_per_poll = max_events_per_poll
        self._procs: dict[tuple[int, float], dict[str, Any]] = {}
        self._conns: set[tuple[Any, ...]] = set()
        self._hash_cache: OrderedDict[tuple[str, int, int], str | None] = OrderedDict()
        self._first = True
        try:
            import psutil  # type: ignore[import-untyped,unused-ignore]  # noqa: F401

            self.set_health(True, "psutil available")
        except ImportError:
            self.set_health(False, "psutil is not installed")

    # ------------------------------------------------------------------ main loop
    def _run(self) -> None:
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.poll_once()
                self.set_health(True, "polling")
            except Exception as exc:
                log.exception("psutil poll failed")
                self.set_health(False, f"poll error: {type(exc).__name__}: {exc}")
            self._stop.wait(max(0.0, self.poll_interval - (time.monotonic() - t0)))

    # ------------------------------------------------------------------ one poll cycle
    def poll_once(self) -> int:
        """Run one snapshot diff cycle; returns the number of events enqueued."""
        import psutil  # type: ignore[import-untyped,unused-ignore]

        emitted = 0
        budget = self.max_events_per_poll
        baseline = self._first and not self.emit_existing
        now = time.time()
        current: dict[tuple[int, float], dict[str, Any]] = {}
        names: dict[int, str] = {}
        for p in psutil.process_iter(_PROC_ATTRS, ad_value=None):
            info = dict(p.info)
            pid = info.get("pid")
            if pid is None:
                continue
            key = (pid, float(info.get("create_time") or 0.0))
            current[key] = info
            names[pid] = info.get("name") or ""

        for key, info in current.items():
            if key in self._procs:
                continue
            if budget <= 0 and not baseline:
                continue  # over the per-poll cap: stay "unseen" so it is emitted on a later poll
            self._procs[key] = {
                "name": info.get("name"),
                "exe": info.get("exe"),
                "ppid": info.get("ppid"),
                "username": info.get("username"),
            }
            if baseline:
                continue
            raw = self._process_raw(info, names, now)
            budget -= 1
            emitted += self.emit_raw(raw)
        for key in [k for k in self._procs if k not in current]:
            if budget <= 0 and not baseline:
                break
            old = self._procs.pop(key)
            if baseline:
                continue
            budget -= 1
            emitted += self.emit_raw(
                {
                    "format": "psutil",
                    "kind": "process_exit",
                    "pid": key[0],
                    "ppid": old.get("ppid"),
                    "name": old.get("name"),
                    "exe": old.get("exe"),
                    "username": old.get("username"),
                    "timestamp": now,
                }
            )

        if self.track_connections:
            emitted += self._poll_connections(names, now, baseline, budget)
        self._first = False
        return emitted

    def _process_raw(self, info: dict[str, Any], names: dict[int, str], now: float) -> dict[str, Any]:
        exe = info.get("exe")
        raw: dict[str, Any] = {
            "format": "psutil",
            "kind": "process",
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "name": info.get("name"),
            "exe": exe,
            "cmdline": info.get("cmdline") or None,
            "username": info.get("username"),
            "create_time": info.get("create_time"),
            "status": info.get("status"),
            "parent_name": names.get(info.get("ppid") or -1) or None,
            "timestamp": now,
        }
        if exe is None:
            raw["exe_unreadable"] = True
        elif self.hash_executables:
            raw["sha256"] = self._sha256(exe)
        return raw

    def _poll_connections(self, names: dict[int, str], now: float, baseline: bool, budget: int) -> int:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError) as exc:
            self.set_health(False, f"net_connections unavailable: {exc}")
            return 0
        emitted = 0
        seen: set[tuple[Any, ...]] = set()
        for c in conns:
            laddr = tuple(c.laddr) if c.laddr else ()
            raddr = tuple(c.raddr) if c.raddr else ()
            status = c.status
            if raddr:
                if status not in {"ESTABLISHED", "SYN_SENT", "NONE"}:
                    continue
                if self.skip_loopback and _is_loopback(str(raddr[0])):
                    continue
            elif status != "LISTEN" and status != "NONE":
                continue
            if not raddr and status != "LISTEN" and c.type is not None and int(c.type) != 2:
                continue
            k = (c.pid, laddr, raddr, status)
            if k in self._conns:
                seen.add(k)
                continue
            if budget <= 0 and not baseline:
                continue  # over cap: not marked seen, emitted on a later poll
            seen.add(k)
            if baseline:
                continue
            budget -= 1
            proc_name, proc_exe, user, ppid = None, None, None, None
            if c.pid is not None:
                proc_name = names.get(c.pid)
                for (pid, _), meta in self._procs.items():
                    if pid == c.pid:
                        proc_exe, user, ppid = meta.get("exe"), meta.get("username"), meta.get("ppid")
                        break
            emitted += self.emit_raw(
                {
                    "format": "psutil",
                    "kind": "connection" if raddr else "listen",
                    "pid": c.pid,
                    "ppid": ppid,
                    "name": proc_name,
                    "exe": proc_exe,
                    "username": user,
                    "laddr": list(laddr),
                    "raddr": list(raddr),
                    "status": status,
                    "type": "tcp" if int(c.type) == 1 else "udp",
                    "timestamp": now,
                }
            )
        self._conns = seen
        return emitted

    def _sha256(self, path: str) -> str | None:
        """SHA-256 of an executable with an (path, mtime, size) cache; None if unreadable/too large."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        ck = (path, st.st_mtime_ns, st.st_size)
        if ck in self._hash_cache:
            self._hash_cache.move_to_end(ck)
            return self._hash_cache[ck]
        digest: str | None = None
        if 0 < st.st_size <= self.max_hash_bytes:
            try:
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                digest = h.hexdigest()
            except OSError:
                digest = None
        self._hash_cache[ck] = digest
        if len(self._hash_cache) > 2048:
            self._hash_cache.popitem(last=False)
        return digest


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False
