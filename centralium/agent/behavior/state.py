"""Bounded, thread-safe sliding-window state for the behavior engine.

All time arithmetic uses *event* timestamps (so replayed/recorded telemetry behaves
identically to live telemetry). Every container is size-bounded (LRU / deque maxlen) so a
flood of events cannot grow memory without limit.
"""

from __future__ import annotations

import threading
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from typing import Any

from centralium.agent.behavior.signals import is_exec_path, is_ransom_ext, is_ransom_note, shadow_command_kind
from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.common import basename_any, ext_of

FILE_EVENT_TYPES = frozenset(
    {EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_DELETE, EventType.FILE_RENAME}
)


class LRUCounter:
    """Counter with a hard cap on distinct keys (least-recently-seen evicted first)."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self._d: OrderedDict[str, int] = OrderedDict()

    def inc(self, key: str) -> int:
        n = self._d.pop(key, 0) + 1
        self._d[key] = n
        if len(self._d) > self.cap:
            self._d.popitem(last=False)
        return n

    def get(self, key: str) -> int:
        return self._d.get(key, 0)

    def __len__(self) -> int:
        return len(self._d)

    def total(self) -> int:
        return sum(self._d.values())


@dataclass(slots=True)
class ProcInfo:
    name: str | None
    exe: str | None
    ppid: int | None
    cmdline: str | None
    user: str | None
    ts: float


@dataclass(slots=True)
class FileOp:
    ts: float
    kind: str  # create|modify|delete|rename
    path: str | None
    ext_changed: bool = False
    new_ext: str = ""
    appended_ext: bool = False  # new name == old name + extra suffix (e.g. a.docx -> a.docx.locked)
    ransom_ext: bool = False
    ransom_note: bool = False
    entropy_before: float | None = None
    entropy_after: float | None = None
    directory: str = ""


@dataclass
class FileWindowStats:
    creates: int = 0
    modifies: int = 0
    deletes: int = 0
    renames: int = 0
    distinct_files: int = 0
    distinct_dirs: int = 0
    ext_changes: int = 0
    appended_ext: int = 0
    ransom_ext_hits: int = 0
    dominant_ext: str = ""
    dominant_ext_count: int = 0
    ransom_notes: int = 0
    entropy_samples: int = 0
    avg_entropy_after: float = 0.0
    avg_entropy_delta: float | None = None
    exec_created: int = 0
    window_sec: float = 0.0

    @property
    def writes(self) -> int:
        return self.creates + self.modifies


def _dir_of(path: str | None) -> str:
    if not path:
        return ""
    i = max(path.rfind("/"), path.rfind("\\"))
    return path[:i] if i > 0 else ""


class BehaviorState:
    """Sliding-window + cumulative statistics shared by feature extraction and detectors."""

    def __init__(
        self,
        *,
        window_sec: float = 60.0,
        file_window_sec: float = 60.0,
        burst_sec: float = 10.0,
        max_pids: int = 4096,
        max_keys: int = 50_000,
        max_ops_per_pid: int = 4096,
    ) -> None:
        self.window_sec = window_sec
        self.file_window_sec = file_window_sec
        self.burst_sec = burst_sec
        self.max_pids = max_pids
        self.max_ops = max_ops_per_pid
        self.lock = threading.RLock()
        self.now = 0.0
        self.events_seen = 0
        self.proc_counts = LRUCounter(max_keys)
        self.exe_counts = LRUCounter(max_keys)
        self.pair_counts = LRUCounter(max_keys)
        self.user_counts = LRUCounter(max_keys)
        self.dest_counts = LRUCounter(max_keys)
        self.port_counts = LRUCounter(max_keys)
        self.domain_counts = LRUCounter(max_keys)
        self.proc_info: OrderedDict[int, ProcInfo] = OrderedDict()
        self.children: OrderedDict[int, deque[float]] = OrderedDict()
        self.net: deque[tuple[float, str, int | None, str, int | None]] = deque(maxlen=8192)
        self.net_pids: OrderedDict[int, float] = OrderedDict()
        self.file_ops: OrderedDict[int | str, deque[FileOp]] = OrderedDict()
        self.shadow: dict[int | str, deque[float]] = {}
        self.created_files: OrderedDict[str, tuple[float, int | None, bool]] = OrderedDict()
        self.persistence_mods: deque[float] = deque(maxlen=1024)
        self.priv_changes: deque[float] = deque(maxlen=1024)
        self.injections: deque[float] = deque(maxlen=1024)
        self.alerted: OrderedDict[str, float] = OrderedDict()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def pid_key(event: NormalizedEvent) -> int | str:
        if event.pid is not None:
            return event.pid
        return f"name:{event.process_name or 'unknown'}"

    def resolve_parent_name(self, event: NormalizedEvent) -> str | None:
        if event.parent_process:
            return event.parent_process
        if event.ppid is not None:
            info = self.proc_info.get(event.ppid)
            if info:
                return info.name
        return None

    def _bounded_dict_touch(self, d: OrderedDict[Any, Any], key: Any, cap: int) -> None:
        d.move_to_end(key)
        while len(d) > cap:
            d.popitem(last=False)

    def _prune(self, dq: deque[Any], horizon: float, idx: int | None = None) -> None:
        while dq and (dq[0] if idx is None else dq[0][idx]) < horizon:
            dq.popleft()

    # ------------------------------------------------------------------ observation
    def observe(self, event: NormalizedEvent, *, entropy: float | None = None) -> None:
        """Fold one event into the state. Call BEFORE ``extract_features`` for that event."""
        ts = event.timestamp.timestamp()
        et = event.event_type
        with self.lock:
            self.now = max(self.now, ts)
            now = self.now
            self.events_seen += 1
            key = self.pid_key(event)

            if et == EventType.PROCESS_START:
                name = (event.process_name or basename_any(event.executable_path) or "").lower()
                if name:
                    self.proc_counts.inc(name)
                if event.executable_path:
                    self.exe_counts.inc(event.executable_path.lower())
                if event.user:
                    self.user_counts.inc(event.user.lower())
                parent_name = (self.resolve_parent_name(event) or "").lower()
                if parent_name and name:
                    self.pair_counts.inc(f"{parent_name}>{name}")
                if event.pid is not None:
                    self.proc_info[event.pid] = ProcInfo(
                        event.process_name,
                        event.executable_path,
                        event.ppid,
                        event.command_line,
                        event.user,
                        ts,
                    )
                    self._bounded_dict_touch(self.proc_info, event.pid, self.max_pids)
                if event.ppid is not None:
                    dq = self.children.setdefault(event.ppid, deque(maxlen=1024))
                    dq.append(ts)
                    self._prune(dq, now - self.window_sec)
                    self._bounded_dict_touch(self.children, event.ppid, self.max_pids)
                kind = shadow_command_kind(event.command_line)
                if kind:
                    self.shadow.setdefault(key, deque(maxlen=256)).append(ts)
                    self.shadow.setdefault("*", deque(maxlen=1024)).append(ts)
                    if len(self.shadow) > self.max_pids:
                        for k in list(self.shadow)[: len(self.shadow) - self.max_pids]:
                            if k != "*":
                                self.shadow.pop(k, None)
            elif et == EventType.PROCESS_EXIT:
                if event.pid is not None:
                    self.proc_info.pop(event.pid, None)
                    self.children.pop(event.pid, None)
            elif et in {EventType.NETWORK_CONNECT, EventType.DNS_QUERY}:
                ip = event.destination_ip or ""
                if ip:
                    self.dest_counts.inc(ip)
                if event.destination_port is not None:
                    self.port_counts.inc(str(event.destination_port))
                if event.domain:
                    self.domain_counts.inc(event.domain)
                self.net.append((ts, ip, event.destination_port, event.domain or "", event.pid))
                self._prune(self.net, now - self.window_sec, 0)
                if event.pid is not None and et == EventType.NETWORK_CONNECT:
                    self.net_pids[event.pid] = ts
                    self._bounded_dict_touch(self.net_pids, event.pid, self.max_pids)
            elif et in FILE_EVENT_TYPES:
                self._observe_file(event, key, ts, entropy)
            elif et == EventType.PROCESS_INJECT:
                self.injections.append(ts)
            elif et == EventType.PRIVILEGE_CHANGE:
                self.priv_changes.append(ts)
            if et in {
                EventType.PERSISTENCE,
                EventType.REGISTRY_CREATE,
                EventType.REGISTRY_MODIFY,
                EventType.SERVICE_CHANGE,
                EventType.SCHEDULED_TASK,
            } and (
                et in {EventType.PERSISTENCE, EventType.SERVICE_CHANGE, EventType.SCHEDULED_TASK}
                or _run_key(event.registry_key)
            ):
                self.persistence_mods.append(ts)

    def _observe_file(self, event: NormalizedEvent, key: int | str, ts: float, entropy: float | None) -> None:
        et = event.event_type
        meta = event.raw_metadata or {}
        kind = {
            EventType.FILE_CREATE: "create",
            EventType.FILE_MODIFY: "modify",
            EventType.FILE_DELETE: "delete",
            EventType.FILE_RENAME: "rename",
        }[et]
        op = FileOp(ts=ts, kind=kind, path=event.file_path, directory=_dir_of(event.file_path))
        if kind == "rename":
            old = meta.get("old_path")
            old_s = old if isinstance(old, str) else None
            new_ext, old_ext = ext_of(event.file_path), ext_of(old_s)
            op.ext_changed = bool(old_s) and new_ext != old_ext
            op.new_ext = new_ext
            op.appended_ext = bool(
                old_s
                and event.file_path
                and event.file_path != old_s
                and event.file_path.startswith(old_s)
                and op.ext_changed
            )
            op.ransom_ext = is_ransom_ext(new_ext) if op.ext_changed else False
        elif kind == "create":
            op.ransom_ext = False
        op.ransom_note = kind == "create" and is_ransom_note(event.file_path)
        ent_after = entropy if entropy is not None else _num(meta.get("entropy_after", meta.get("entropy")))
        op.entropy_after = ent_after
        op.entropy_before = _num(meta.get("entropy_before"))
        if kind == "create" and is_exec_path(event.file_path) and event.file_path:
            via_net = event.pid in self.net_pids and (ts - self.net_pids[event.pid]) <= self.window_sec * 5  # type: ignore[index]
            self.created_files[event.file_path] = (ts, event.pid, bool(via_net))
            self._bounded_dict_touch(self.created_files, event.file_path, 4096)
        for k in {key, event.ppid} if event.ppid is not None else {key}:
            dq = self.file_ops.get(k)
            if dq is None:
                dq = self.file_ops[k] = deque(maxlen=self.max_ops)
            dq.append(op)
            self._prune_ops(dq, ts - self.file_window_sec)
            self._bounded_dict_touch(self.file_ops, k, self.max_pids)
        gdq = self.file_ops.get("*")
        if gdq is None:
            gdq = self.file_ops["*"] = deque(maxlen=self.max_ops * 2)
        gdq.append(op)
        self._prune_ops(gdq, ts - self.file_window_sec)

    @staticmethod
    def _prune_ops(dq: deque[FileOp], horizon: float) -> None:
        while dq and dq[0].ts < horizon:
            dq.popleft()

    # ------------------------------------------------------------------ queries (lock-protected)
    def file_stats(self, key: int | str, *, window_sec: float | None = None) -> FileWindowStats:
        w = window_sec or self.file_window_sec
        with self.lock:
            dq = self.file_ops.get(key)
            st = FileWindowStats(window_sec=w)
            if not dq:
                return st
            horizon = self.now - w
            files: set[str] = set()
            dirs: set[str] = set()
            exts: Counter[str] = Counter()
            ent_after: list[float] = []
            ent_delta: list[float] = []
            for op in dq:
                if op.ts < horizon:
                    continue
                if op.kind == "create":
                    st.creates += 1
                    if is_exec_path(op.path):
                        st.exec_created += 1
                elif op.kind == "modify":
                    st.modifies += 1
                elif op.kind == "delete":
                    st.deletes += 1
                else:
                    st.renames += 1
                if op.path:
                    files.add(op.path)
                if op.directory:
                    dirs.add(op.directory)
                if op.ext_changed:
                    st.ext_changes += 1
                    exts[op.new_ext] += 1
                    if op.appended_ext:
                        st.appended_ext += 1
                    if op.ransom_ext:
                        st.ransom_ext_hits += 1
                if op.ransom_note:
                    st.ransom_notes += 1
                if op.entropy_after is not None and op.kind in {"create", "modify", "rename"}:
                    ent_after.append(op.entropy_after)
                    if op.entropy_before is not None:
                        ent_delta.append(op.entropy_after - op.entropy_before)
            st.distinct_files = len(files)
            st.distinct_dirs = len(dirs)
            if exts:
                st.dominant_ext, st.dominant_ext_count = exts.most_common(1)[0]
            st.entropy_samples = len(ent_after)
            if ent_after:
                st.avg_entropy_after = sum(ent_after) / len(ent_after)
            if ent_delta:
                st.avg_entropy_delta = sum(ent_delta) / len(ent_delta)
            return st

    def shadow_count(self, key: int | str, window_sec: float = 300.0) -> int:
        with self.lock:
            dq = self.shadow.get(key)
            if not dq:
                return 0
            horizon = self.now - window_sec
            return sum(1 for t in dq if t >= horizon)

    def net_stats(self) -> dict[str, float]:
        with self.lock:
            horizon = self.now - self.window_sec
            burst_h = self.now - self.burst_sec
            conns = [c for c in self.net if c[0] >= horizon and c[1]]
            return {
                "count": float(len(conns)),
                "unique_dest": float(len({c[1] for c in conns})),
                "burst": float(sum(1 for c in conns if c[0] >= burst_h)),
            }

    def children_in_window(self, pid: int | None) -> int:
        if pid is None:
            return 0
        with self.lock:
            dq = self.children.get(pid)
            if not dq:
                return 0
            horizon = self.now - self.window_sec
            return sum(1 for t in dq if t >= horizon)

    def recently(self, dq: deque[float], window_sec: float | None = None) -> int:
        with self.lock:
            horizon = self.now - (window_sec or self.window_sec)
            return sum(1 for t in dq if t >= horizon)

    def created_recently(self, path: str | None, window_sec: float = 600.0) -> tuple[bool, bool]:
        """(created within window, created by a process that recently made network connections)."""
        if not path:
            return False, False
        with self.lock:
            rec = self.created_files.get(path)
            if rec and self.now - rec[0] <= window_sec:
                return True, rec[2]
            return False, False

    def should_alert(self, key: str, cooldown_sec: float) -> bool:
        """Rate-limit repeated findings: True at most once per ``cooldown_sec`` per key."""
        with self.lock:
            last = self.alerted.get(key)
            if last is not None and self.now - last < cooldown_sec:
                return False
            self.alerted[key] = self.now
            self._bounded_dict_touch(self.alerted, key, 8192)
            return True

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "events_seen": self.events_seen,
                "tracked_pids": len(self.proc_info),
                "file_windows": len(self.file_ops),
                "distinct_processes": len(self.proc_counts),
                "distinct_destinations": len(self.dest_counts),
            }


def _num(v: Any) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 8.0 else None


def _run_key(key: str | None) -> bool:
    if not key:
        return False
    low = key.lower()
    return any(
        t in low
        for t in (
            "\\currentversion\\run",
            "\\winlogon\\",
            "\\image file execution options\\",
            "\\appinit_dlls",
            "\\services\\",
        )
    )


__all__ = ["FILE_EVENT_TYPES", "BehaviorState", "FileOp", "FileWindowStats", "LRUCounter", "ProcInfo"]
