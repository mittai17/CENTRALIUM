"""Generic dict / replay and psutil-snapshot normalizers."""

from __future__ import annotations

import contextlib
from typing import Any

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.common import (
    MAX_CMD,
    basename_any,
    canon_domain,
    canon_ip,
    canon_path,
    canon_port,
    canon_sha256,
    clean_str,
    parse_ts,
    pick,
    safe_meta,
    to_int,
)

_TYPE_ALIASES = {
    "process": EventType.PROCESS_START,
    "exec": EventType.PROCESS_START,
    "proc_start": EventType.PROCESS_START,
    "process_create": EventType.PROCESS_START,
    "proc_exit": EventType.PROCESS_EXIT,
    "connect": EventType.NETWORK_CONNECT,
    "network": EventType.NETWORK_CONNECT,
    "net_connect": EventType.NETWORK_CONNECT,
    "dns": EventType.DNS_QUERY,
    "file_write": EventType.FILE_MODIFY,
    "write": EventType.FILE_MODIFY,
    "file_write_event": EventType.FILE_MODIFY,
    "rename": EventType.FILE_RENAME,
    "delete": EventType.FILE_DELETE,
    "create": EventType.FILE_CREATE,
    "registry_set": EventType.REGISTRY_MODIFY,
    "login": EventType.AUTH,
    "auth": EventType.AUTH,
    "auth_login": EventType.AUTH_LOGIN,
    "auth_logout": EventType.AUTH_LOGOUT,
    "auth_fail": EventType.AUTH_FAIL,
    "privilege_elevation": EventType.PRIVILEGE_ELEVATION,
    "privilege_change": EventType.PRIVILEGE_CHANGE,
    "inject": EventType.PROCESS_INJECT,
}
_KEYMAP = {
    "event_id": ("event_id", "id", "uuid"),
    "timestamp": ("timestamp", "ts", "time", "@timestamp", "utctime"),
    "user": ("user", "username", "account"),
    "pid": ("pid", "process_id"),
    "ppid": ("ppid", "parent_pid", "parent_process_id"),
    "process_name": ("process_name", "process", "name", "comm", "image_name"),
    "executable_path": ("executable_path", "exe", "image", "exe_path"),
    "command_line": ("command_line", "cmdline", "commandline", "cmd"),
    "parent_process": ("parent_process", "parent", "parent_name"),
    "signer": ("signer", "signature", "publisher"),
    "file_path": ("file_path", "path", "target_filename", "filename", "file"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "remote_ip", "daddr"),
    "destination_port": ("destination_port", "dest_port", "dst_port", "remote_port", "dport"),
    "domain": ("domain", "query", "hostname", "dns_name"),
    "protocol": ("protocol", "proto"),
    "registry_key": ("registry_key", "reg_key", "target_object"),
}
_CONSUMED = {a for names in _KEYMAP.values() for a in names} | {
    "event_type",
    "type",
    "event",
    "kind",
    "host_id",
    "host",
    "source",
    "confidence",
    "raw_metadata",
    "hash_sha256",
    "sha256",
    "hash",
    "format",
    "delay",
    "metadata",
}


def _event_type(raw: dict[str, Any]) -> EventType:
    v = pick(raw, "event_type", "type", "event", "kind")
    if v is None:
        raise ValueError("generic event has no event_type")
    s = str(v).strip().lower()
    try:
        return EventType(s)
    except ValueError:
        pass
    if s in _TYPE_ALIASES:
        return _TYPE_ALIASES[s]
    raise ValueError(f"unknown event_type {v!r}")


def normalize_generic(
    raw: dict[str, Any], host_id: str = "localhost", default_source: str = "replay"
) -> NormalizedEvent:
    if isinstance(raw.get("event"), dict):  # replay wrapper {"format":"replay","delay":..,"event":{...}}
        inner = dict(raw["event"])
        return normalize_generic(inner, host_id, default_source)
    et = _event_type(raw)
    kw: dict[str, Any] = {"event_type": et}
    for field_name, aliases in _KEYMAP.items():
        v = pick(raw, *aliases)
        if v is None:
            continue
        if field_name in {"pid", "ppid"}:
            kw[field_name] = to_int(v)
        elif field_name == "destination_port":
            kw[field_name] = canon_port(v)
        elif field_name == "destination_ip":
            kw[field_name] = canon_ip(v)
        elif field_name in {"executable_path", "file_path"}:
            kw[field_name] = canon_path(v)
        elif field_name == "domain":
            kw[field_name] = canon_domain(v)
        elif field_name == "timestamp":
            kw[field_name] = parse_ts(v)
        elif field_name == "command_line":
            kw[field_name] = clean_str(v, MAX_CMD)
        elif field_name == "event_id":
            kw[field_name] = clean_str(v, 128)
        else:
            kw[field_name] = clean_str(v, 1024)
    if kw.get("timestamp") is None:
        kw.pop("timestamp", None)
    if kw.get("event_id") is None:
        kw.pop("event_id", None)
    if kw.get("process_name") is None and kw.get("executable_path"):
        kw["process_name"] = basename_any(kw["executable_path"])
    h = canon_sha256(pick(raw, "hash_sha256", "sha256", "hash"))
    if h:
        kw["hash_sha256"] = h
    kw["host_id"] = clean_str(pick(raw, "host_id", "host"), 255) or host_id
    kw["source"] = clean_str(pick(raw, "source"), 32) or default_source
    conf = pick(raw, "confidence")
    if conf is not None:
        with contextlib.suppress(TypeError, ValueError):
            kw["confidence"] = min(1.0, max(0.0, float(conf)))
    meta = pick(raw, "raw_metadata", "metadata")
    extras = {k: v for k, v in raw.items() if str(k).lower() not in _CONSUMED}
    kw["raw_metadata"] = safe_meta({**(meta if isinstance(meta, dict) else {}), **extras})
    return NormalizedEvent(**kw)


# --------------------------------------------------------------------------- psutil
def normalize_psutil(raw: dict[str, Any], host_id: str = "localhost") -> NormalizedEvent:
    """psutil snapshot record. ``kind`` is process|process_exit|connection|listen."""
    kind = str(pick(raw, "kind", "type") or "process").lower()
    ts = parse_ts(pick(raw, "timestamp", "ts", "observed_at"))
    exe = canon_path(pick(raw, "exe", "executable_path"))
    name = clean_str(pick(raw, "name", "process_name")) or basename_any(exe)
    cmd = pick(raw, "cmdline", "command_line")
    base: dict[str, Any] = {
        "host_id": clean_str(pick(raw, "host_id"), 255) or host_id,
        "user": clean_str(pick(raw, "username", "user")),
        "pid": to_int(pick(raw, "pid")),
        "ppid": to_int(pick(raw, "ppid")),
        "process_name": name,
        "executable_path": exe,
        "command_line": clean_str(cmd, MAX_CMD),
        "parent_process": clean_str(pick(raw, "parent_name", "parent_process")),
        "hash_sha256": canon_sha256(pick(raw, "sha256", "hash_sha256")),
        "source": "psutil",
    }
    if ts is not None:
        base["timestamp"] = ts
    meta = safe_meta(
        {
            "cwd": pick(raw, "cwd"),
            "create_time": pick(raw, "create_time"),
            "status": pick(raw, "status"),
            "snapshot_kind": kind,
            "num_threads": pick(raw, "num_threads"),
            "uids": pick(raw, "uids"),
            "exe_unreadable": pick(raw, "exe_unreadable"),
        }
    )
    if kind in {"process", "process_start"}:
        return NormalizedEvent(event_type=EventType.PROCESS_START, raw_metadata=meta, **base)
    if kind in {"process_exit", "exit"}:
        return NormalizedEvent(event_type=EventType.PROCESS_EXIT, raw_metadata=meta, **base)
    if kind in {"connection", "listen", "conn"}:
        raddr = pick(raw, "raddr")
        laddr = pick(raw, "laddr")
        rip = rport = None
        if isinstance(raddr, (list, tuple)) and len(raddr) >= 2:
            rip, rport = canon_ip(raddr[0]), canon_port(raddr[1])
        elif isinstance(raddr, dict):
            rip, rport = canon_ip(raddr.get("ip")), canon_port(raddr.get("port"))
        listening = kind == "listen" or str(pick(raw, "status")).upper() == "LISTEN" or not rip
        if listening:
            lip = lport = None
            if isinstance(laddr, (list, tuple)) and len(laddr) >= 2:
                lip, lport = canon_ip(laddr[0]), canon_port(laddr[1])
            elif isinstance(laddr, dict):
                lip, lport = canon_ip(laddr.get("ip")), canon_port(laddr.get("port"))
            et, ip, port = EventType.NETWORK_LISTEN, lip, lport
        else:
            et, ip, port = EventType.NETWORK_CONNECT, rip, rport
        proto = clean_str(pick(raw, "type", "protocol", "transport"), 16)
        proto = proto if proto in {"tcp", "udp"} else (clean_str(pick(raw, "transport"), 16) or None)
        return NormalizedEvent(
            event_type=et,
            destination_ip=ip,
            destination_port=port,
            protocol=proto,
            raw_metadata={**meta, "local_addr": str(laddr)[:128] if laddr else None},
            **base,
        )
    raise ValueError(f"unknown psutil snapshot kind {kind!r}")
