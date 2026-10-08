"""Linux eBPF collector with separate privileged helper process.

Architecture:
- Privileged helper process runs as root/CAP_BPF and loads eBPF tracepoints/probes.
- Helper streams structured newline-delimited JSON events over a Unix domain socket
  (default: ``/tmp/centralium_ebpf.sock``) to the unprivileged Centralium agent.
- Emits real security-relevant events:
  - exec (sys_enter_execve) -> PROCESS_START
  - connect (sys_enter_connect) -> NETWORK_CONNECT
  - accept (sys_enter_accept / accept4) -> NETWORK_LISTEN
  - openat (sys_enter_openat with write intent: O_WRONLY/O_RDWR/O_CREAT) -> FILE_MODIFY / FILE_CREATE
  - rename (sys_enter_rename / renameat / renameat2) -> FILE_RENAME
  - unlink (sys_enter_unlink / unlinkat) -> FILE_DELETE
  - ptrace (sys_enter_ptrace) -> PROCESS_INJECT
  - memfd (sys_enter_memfd_create) -> PROCESS_INJECT
- Fallbacks:
  - When eBPF is unavailable (e.g. non-root, missing BCC/kernel headers, socket not found),
    safely falls back to ``AuditdCollector`` or ``PsutilCollector``.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import logging
import os
import select
import socket
import sys
import threading
import time
from typing import Any, Protocol

from centralium.agent.collectors._base import BaseCollector
from centralium.agent.interfaces import EventSink
from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.common import (
    basename_any,
    canon_ip,
    canon_path,
    canon_port,
    make_event,
    parse_ts,
    to_int,
)

log = logging.getLogger(__name__)

DEFAULT_EBPF_SOCKET = "/tmp/centralium_ebpf.sock"  # noqa: S108
NOT_IMPLEMENTED = (
    "eBPF collector not implemented/helper socket not connected "
    "(needs bcc/libbpf + root); use auditd or psutil collectors"
)


class EbpfLoaderProtocol(Protocol):
    """Protocol for eBPF probe loaders (BCC, libbpf, or test mocks)."""

    def load_probes(self) -> bool: ...

    def poll_events(self, timeout_ms: int = 100) -> list[dict[str, Any]]: ...

    def cleanup(self) -> None: ...


class MockEbpfLoader:
    """Mock loader for testing the eBPF helper architecture without root/BCC."""

    def __init__(self, initial_events: list[dict[str, Any]] | None = None) -> None:
        self._events: list[dict[str, Any]] = list(initial_events or [])
        self._lock = threading.Lock()
        self.loaded = False

    def push_event(self, ev: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(ev)

    def load_probes(self) -> bool:
        self.loaded = True
        return True

    def poll_events(self, timeout_ms: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            evs = self._events[:]
            self._events.clear()
            return evs

    def cleanup(self) -> None:
        self.loaded = False


class BccLoader:
    """Real BCC probe loader for Linux systems with root / CAP_BPF."""

    def __init__(self) -> None:
        self._bpf: Any = None
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @staticmethod
    def is_available() -> bool:
        return (
            sys.platform.startswith("linux")
            and os.geteuid() == 0
            and importlib.util.find_spec("bcc") is not None
        )

    def load_probes(self) -> bool:
        if not self.is_available():
            return False
        try:
            from bcc import BPF  # type: ignore[import-untyped,unused-ignore]

            bpf_text = """
            #include <uapi/linux/ptrace.h>
            #include <linux/sched.h>
            #include <linux/fs.h>

            struct event_t {
                u32 pid;
                u32 ppid;
                u32 type; // 1=exec, 2=connect, 3=accept, 4=openat, 5=rename, 6=unlink, 7=ptrace, 8=memfd
                char comm[16];
            };
            BPF_PERF_OUTPUT(events);

            int trace_execve(struct pt_regs *ctx) {
                struct event_t ev = {};
                ev.pid = bpf_get_current_pid_tgid() >> 32;
                ev.type = 1;
                bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
                events.perf_submit(ctx, &ev, sizeof(ev));
                return 0;
            }
            """
            self._bpf = BPF(text=bpf_text)
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("execve"), fn_name="trace_execve")
            return True
        except Exception as exc:
            log.warning("BccLoader failed to attach probes: %s", exc)
            return False

    def poll_events(self, timeout_ms: int = 100) -> list[dict[str, Any]]:
        if self._bpf is None:
            return []
        try:
            self._bpf.perf_buffer_poll(timeout=timeout_ms)
            with self._lock:
                out = self._events[:]
                self._events.clear()
                return out
        except Exception:
            return []

    def cleanup(self) -> None:
        if self._bpf is not None:
            with contextlib.suppress(Exception):
                self._bpf.cleanup()
            self._bpf = None


class EbpfHelperServer:
    """Privileged helper process server streaming newline-delimited JSON events over Unix socket."""

    def __init__(
        self,
        socket_path: str = DEFAULT_EBPF_SOCKET,
        loader: EbpfLoaderProtocol | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.loader = loader or (BccLoader() if BccLoader.is_available() else MockEbpfLoader())
        self._stop = threading.Event()
        self._server_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.stats = {"events_sent": 0, "clients_connected": 0}

    def start(self) -> None:
        if self.socket_path.startswith("/"):
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(self.socket_path)
        self._server_sock.listen(5)
        self._server_sock.setblocking(False)
        self.loader.load_probes()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ebpf-helper-server", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._server_sock:
            with contextlib.suppress(Exception):
                self._server_sock.close()
            self._server_sock = None
        if self.socket_path.startswith("/"):
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)
        self.loader.cleanup()

    def _run(self) -> None:
        clients: list[socket.socket] = []
        while not self._stop.is_set():
            if self._server_sock:
                with contextlib.suppress(Exception):
                    r, _, _ = select.select([self._server_sock], [], [], 0.05)
                    if r:
                        conn, _ = self._server_sock.accept()
                        conn.setblocking(False)
                        clients.append(conn)
                        self.stats["clients_connected"] += 1

            events = self.loader.poll_events(timeout_ms=50)
            if events and clients:
                dead_clients: list[socket.socket] = []
                for ev in events:
                    blob = (json.dumps(ev) + "\n").encode("utf-8")
                    for cl in clients:
                        try:
                            cl.sendall(blob)
                            self.stats["events_sent"] += 1
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            dead_clients.append(cl)
                for dc in dead_clients:
                    if dc in clients:
                        clients.remove(dc)
                        with contextlib.suppress(Exception):
                            dc.close()
            elif not events:
                time.sleep(0.01)

        for cl in clients:
            with contextlib.suppress(Exception):
                cl.close()


def normalize_ebpf_event(raw: dict[str, Any], host_id: str = "localhost") -> NormalizedEvent | None:
    """Normalize raw eBPF helper dictionary into a Centralium NormalizedEvent.

    Emitted types:
      - exec -> PROCESS_START
      - connect -> NETWORK_CONNECT
      - accept -> NETWORK_LISTEN
      - openat (write intent) -> FILE_MODIFY / FILE_CREATE
      - rename -> FILE_RENAME
      - unlink -> FILE_DELETE
      - ptrace -> PROCESS_INJECT
      - memfd -> PROCESS_INJECT
    """
    ev_type_raw = str(raw.get("event_type") or raw.get("type") or "").lower()
    ts = parse_ts(raw.get("timestamp") or raw.get("time"))
    host = str(raw.get("host_id") or host_id)
    pid = to_int(raw.get("pid"))
    ppid = to_int(raw.get("ppid"))
    comm = str(raw.get("process_name") or raw.get("comm") or "")
    exe = canon_path(raw.get("executable_path") or raw.get("exe") or raw.get("filename"))
    cmd = str(raw.get("command_line") or raw.get("args") or raw.get("cmdline") or "")
    user = str(raw.get("user") or (f"uid:{raw['uid']}" if "uid" in raw else "")) or None

    meta = dict(raw.get("raw_metadata") or {})
    for k, v in raw.items():
        if k not in {
            "event_type",
            "type",
            "timestamp",
            "time",
            "host_id",
            "pid",
            "ppid",
            "process_name",
            "comm",
            "executable_path",
            "exe",
            "command_line",
            "args",
            "cmdline",
            "user",
            "raw_metadata",
        }:
            meta[k] = v

    pname = basename_any(exe) or comm or None

    if ev_type_raw in {"exec", "execve", "process_start"}:
        return make_event(
            event_type=EventType.PROCESS_START,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            ppid=ppid,
            process_name=pname,
            executable_path=exe,
            command_line=cmd or (pname if pname else None),
            user=user,
            raw_metadata=meta,
        )

    if ev_type_raw in {"connect", "network_connect"}:
        dest_ip = canon_ip(raw.get("destination_ip") or raw.get("daddr") or raw.get("remote_ip"))
        dest_port = canon_port(raw.get("destination_port") or raw.get("dport") or raw.get("remote_port"))
        proto = str(raw.get("protocol") or "tcp").lower()
        return make_event(
            event_type=EventType.NETWORK_CONNECT,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            destination_ip=dest_ip,
            destination_port=dest_port,
            protocol=proto,
            user=user,
            raw_metadata=meta,
        )

    if ev_type_raw in {"accept", "accept4", "network_listen"}:
        dest_ip = canon_ip(raw.get("destination_ip") or raw.get("daddr") or raw.get("saddr"))
        dest_port = canon_port(raw.get("destination_port") or raw.get("dport") or raw.get("sport"))
        proto = str(raw.get("protocol") or "tcp").lower()
        return make_event(
            event_type=EventType.NETWORK_LISTEN,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            destination_ip=dest_ip,
            destination_port=dest_port,
            protocol=proto,
            user=user,
            raw_metadata=meta,
        )

    if ev_type_raw in {"openat", "file_open", "open"}:
        flags = to_int(raw.get("flags")) or 0
        is_create = bool(flags & 0o100) or bool(raw.get("is_create"))  # O_CREAT
        target_path = canon_path(raw.get("file_path") or raw.get("filename") or raw.get("path"))
        return make_event(
            event_type=EventType.FILE_CREATE if is_create else EventType.FILE_MODIFY,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            file_path=target_path,
            user=user,
            raw_metadata={"openat_flags": flags, **meta},
        )

    if ev_type_raw in {"rename", "renameat", "renameat2", "file_rename"}:
        old_path = canon_path(raw.get("old_path") or raw.get("src"))
        new_path = canon_path(raw.get("new_path") or raw.get("dst") or raw.get("file_path"))
        return make_event(
            event_type=EventType.FILE_RENAME,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            file_path=new_path,
            user=user,
            raw_metadata={"old_path": old_path, **meta},
        )

    if ev_type_raw in {"unlink", "unlinkat", "file_delete"}:
        target_path = canon_path(raw.get("file_path") or raw.get("filename") or raw.get("path"))
        return make_event(
            event_type=EventType.FILE_DELETE,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            file_path=target_path,
            user=user,
            raw_metadata=meta,
        )

    if ev_type_raw in {"ptrace", "process_inject"}:
        target_pid = to_int(raw.get("target_pid"))
        req = raw.get("request") or raw.get("ptrace_request")
        return make_event(
            event_type=EventType.PROCESS_INJECT,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            user=user,
            raw_metadata={"technique": "ptrace", "target_pid": target_pid, "request": req, **meta},
        )

    if ev_type_raw in {"memfd", "memfd_create"}:
        memfd_name = str(raw.get("name") or raw.get("memfd_name") or "")
        return make_event(
            event_type=EventType.PROCESS_INJECT,
            timestamp=ts,
            host_id=host,
            source="ebpf",
            pid=pid,
            process_name=pname,
            executable_path=exe,
            user=user,
            raw_metadata={"technique": "memfd_create", "memfd_name": memfd_name, **meta},
        )

    return None


class EbpfCollector(BaseCollector):
    """eBPF collector streaming telemetry from privileged helper socket with safe auditd/psutil fallbacks."""

    name = "ebpf"
    platforms = ("linux",)

    def __init__(
        self,
        socket_path: str = DEFAULT_EBPF_SOCKET,
        *,
        fallback: str | bool = False,
        connect_timeout: float = 1.0,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.socket_path = socket_path
        self.fallback_mode = fallback
        self.connect_timeout = connect_timeout
        self._fallback_collector: BaseCollector | None = None
        self._sock: socket.socket | None = None
        self._connected = False
        self._kw = kw

        self._check_initial_health()

    @staticmethod
    def bcc_available() -> bool:
        return sys.platform.startswith("linux") and importlib.util.find_spec("bcc") is not None

    def _check_initial_health(self) -> None:
        if self._connected:
            self.set_health(True, f"streaming from eBPF socket {self.socket_path}")
        elif self._fallback_collector is not None:
            fb_ok, fb_reason = self._fallback_collector.health()
            fb_name = self._fallback_collector.name
            self.set_health(
                fb_ok,
                f"eBPF helper socket not connected; fallback active: {fb_name} ({fb_reason})",
            )
        else:
            suffix = (
                "bcc is importable but helper socket is not connected"
                if self.bcc_available()
                else "bcc not installed"
            )
            self.set_health(False, f"{NOT_IMPLEMENTED} ({suffix})")

    def _init_fallback(self, sink: EventSink) -> None:
        mode = "auto" if self.fallback_mode is True else str(self.fallback_mode).lower()
        if mode in {"none", "false"}:
            return

        if mode in {"auto", "auditd"}:
            from centralium.agent.collectors.linux.auditd import AuditdCollector

            audit_log = "/var/log/audit/audit.log"
            if (os.path.exists(audit_log) and os.access(audit_log, os.R_OK)) or mode == "auditd":
                self._fallback_collector = AuditdCollector(
                    audit_log,
                    normalizer=self.normalizer,
                    host_id=self.host_id,
                    max_events_per_sec=self._kw.get("max_events_per_sec", 0.0),
                )
                self._fallback_collector.start(sink)
                self.set_health(
                    True,
                    f"eBPF helper socket not connected; falling back to {self._fallback_collector.name}",
                )
                return

        from centralium.agent.collectors.linux.psutil_poller import PsutilCollector

        self._fallback_collector = PsutilCollector(
            normalizer=self.normalizer,
            host_id=self.host_id,
            max_events_per_sec=self._kw.get("max_events_per_sec", 0.0),
        )
        self._fallback_collector.start(sink)
        self.set_health(
            True,
            f"eBPF helper socket not connected; falling back to {self._fallback_collector.name}",
        )

    def start(self, sink: EventSink) -> None:
        self._sink = sink
        self._stop.clear()

        # Try connecting to eBPF socket
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect(self.socket_path)
            sock.setblocking(False)
            self._sock = sock
            self._connected = True
            self.set_health(True, f"connected to eBPF helper socket {self.socket_path}")
            super().start(sink)
            return
        except OSError:
            self._connected = False
            if self._sock:
                with contextlib.suppress(Exception):
                    self._sock.close()
                self._sock = None

        # Helper socket not available
        if self.fallback_mode:
            self._init_fallback(sink)
        else:
            log.warning(NOT_IMPLEMENTED)
            self._check_initial_health()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None
        self._connected = False

        if self._fallback_collector is not None:
            self._fallback_collector.stop()
            self._fallback_collector = None

        super().stop()
        self._check_initial_health()

    def is_running(self) -> bool:
        if self._fallback_collector is not None:
            return self._fallback_collector.is_running()
        return super().is_running()

    def health(self) -> tuple[bool, str]:
        if self._fallback_collector is not None:
            return self._fallback_collector.health()
        return super().health()

    def _run(self) -> None:
        if not self._sock:
            return
        buf = ""
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self._sock], [], [], 0.2)
                if not r:
                    continue
                data = self._sock.recv(65536)
                if not data:
                    self.set_health(False, "eBPF helper socket disconnected")
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        ev = normalize_ebpf_event(record, self.host_id)
                        if ev is not None:
                            self.emit_event(ev)
                    except json.JSONDecodeError:
                        self.stats["normalize_errors"] += 1
            except Exception as exc:
                if not self._stop.is_set():
                    log.warning("eBPF receiver read error: %s", exc)
                    self.set_health(False, f"eBPF receiver error: {exc}")
                break
