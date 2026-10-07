"""Linux auditd record parsing + normalization.

Handles the raw ``audit.log`` text format (``type=SYSCALL msg=audit(ts:serial): k=v ...``)
for SYSCALL, EXECVE, PATH, CWD, SOCKADDR, PROCTITLE, USER_* and ANOM_* records.
Records sharing a serial form one logical event; ``normalize_auditd`` takes the lines
of one such group.

Example auditd rules that feed this normalizer (documentation only; Centralium never
installs rules itself)::

    -a always,exit -F arch=b64 -S execve -k centralium_exec
    -a always,exit -F arch=b64 -S connect -k centralium_net
    -a always,exit -F arch=b64 -S rename,renameat,renameat2,unlink,unlinkat -k centralium_file
    -w /etc/cron.d -p wa -k centralium_persist
    -w /etc/systemd/system -p wa -k centralium_persist
    -w /root/.ssh -p wa -k centralium_persist
"""

from __future__ import annotations

import os
import re
from typing import Any

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.common import (
    MAX_CMD,
    basename_any,
    canon_ip,
    canon_path,
    canon_port,
    clean_str,
    make_event,
    parse_ts,
    safe_meta,
    to_int,
)

_FIELD = re.compile(r"""([A-Za-z_][\w\[\]]*)=("[^"]*"|'[^']*'|[^\s]*)""")
_MSG = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")
_HEXISH = re.compile(r"^[0-9A-Fa-f]+$")

# syscall numbers -> canonical names (x86_64 and aarch64)
_SYSCALLS: dict[str, dict[int, str]] = {
    "c000003e": {
        2: "open",
        42: "connect",
        49: "bind",
        59: "execve",
        82: "rename",
        85: "creat",
        87: "unlink",
        101: "ptrace",
        105: "setuid",
        117: "setresuid",
        175: "init_module",
        257: "openat",
        263: "unlinkat",
        264: "renameat",
        313: "finit_module",
        316: "renameat2",
        322: "execveat",
        90: "chmod",
        268: "fchmodat",
        106: "setgid",
        119: "setresgid",
    },
    "c00000b7": {
        35: "unlinkat",
        38: "renameat",
        56: "openat",
        117: "ptrace",
        146: "setuid",
        147: "setresuid",
        105: "init_module",
        273: "finit_module",
        203: "connect",
        200: "bind",
        221: "execve",
        281: "execveat",
        276: "renameat2",
        53: "fchmodat",
        144: "setgid",
    },
}
_O_WRONLY, _O_RDWR, _O_CREAT, _O_TRUNC, _O_APPEND = 0x1, 0x2, 0x40, 0x200, 0x400


def _hex_decode(v: str) -> str:
    try:
        raw = bytes.fromhex(v)
    except ValueError:
        return v
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace")


def _value(key: str, raw: str) -> str:
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        return raw[1:-1]
    # unquoted values for these keys are hex-encoded by auditd when they contain special chars
    if (
        (
            key in {"comm", "exe", "name", "cwd", "proctitle", "key", "dir", "path"}
            or re.fullmatch(r"a\d+(\[\d+\])?", key)
        )
        and len(raw) % 2 == 0
        and len(raw) >= 2
        and _HEXISH.match(raw)
        and key != "key"
    ):
        return _hex_decode(raw)
    return raw


def parse_record(line: str) -> dict[str, Any] | None:
    """Parse one audit.log line -> {'type','ts','serial','fields'}; None if not a record."""
    if not line or len(line) > 65536:
        return None
    line = line.replace("\x1d", " ").strip()
    if not line.startswith("type="):
        return None
    head, _, rest = line.partition(" ")
    rtype = head[5:]
    m = _MSG.search(rest)
    if not m:
        return None
    fields: dict[str, str] = {}
    for fm in _FIELD.finditer(rest):
        k, v = fm.group(1), fm.group(2)
        if k == "msg":
            continue
        fields[k] = _value(k, v)
    return {"type": rtype, "ts": float(m.group(1)), "serial": int(m.group(2)), "fields": fields}


def group_serial(line: str) -> int | None:
    m = _MSG.search(line)
    return int(m.group(2)) if m else None


def parse_saddr(hexstr: str) -> dict[str, Any] | None:
    """Decode a SOCKADDR ``saddr`` hex blob (AF_INET/AF_INET6/AF_UNIX)."""
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(b) < 4:
        return None
    family = int.from_bytes(b[0:2], "little")
    if family == 2 and len(b) >= 8:
        return {
            "family": "inet",
            "port": int.from_bytes(b[2:4], "big"),
            "ip": ".".join(str(x) for x in b[4:8]),
        }
    if family == 10 and len(b) >= 24:
        import ipaddress

        return {
            "family": "inet6",
            "port": int.from_bytes(b[2:4], "big"),
            "ip": str(ipaddress.IPv6Address(b[8:24])),
        }
    if family == 1:
        return {"family": "unix", "path": b[2:].split(b"\x00")[0].decode("utf-8", "replace")}
    return None


_uid_cache: dict[int, str] = {}


def _user_for(fields: dict[str, str]) -> str | None:
    for key in ("uid", "auid"):
        v = fields.get(key)
        if v is None or v in {"unset", "4294967295"}:
            continue
        if not v.isdigit():
            return v
        uid = int(v)
        if uid in _uid_cache:
            return _uid_cache[uid]
        name = str(uid)
        try:
            import pwd  # posix only

            name = pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError, OSError):
            pass
        if len(_uid_cache) < 4096:
            _uid_cache[uid] = name
        return name
    return None


def _syscall_name(fields: dict[str, str]) -> str | None:
    sc = fields.get("syscall")
    if sc is None:
        return None
    if not sc.isdigit():
        return sc.lower()
    arch = fields.get("arch", "c000003e").lower()
    return _SYSCALLS.get(arch, {}).get(int(sc))


def _execve_cmdline(execve: dict[str, str]) -> str | None:
    argc = to_int(execve.get("argc")) or 0
    args: list[str] = []
    for i in range(min(argc, 512)):
        if f"a{i}" in execve:
            args.append(execve[f"a{i}"])
        else:  # split args: a1_len=.. a1[0]=.. a1[1]=..
            parts = [execve[k] for k in sorted(execve, key=_idx) if k.startswith(f"a{i}[")]
            if parts:
                args.append("".join(parts))
    if not args:
        return None
    return " ".join(args)[:MAX_CMD]


def _idx(k: str) -> int:
    m = re.search(r"\[(\d+)\]", k)
    return int(m.group(1)) if m else 0


def _resolve(name: str | None, cwd: str | None) -> str | None:
    p = canon_path(name)
    if p and not p.startswith("/") and cwd and cwd.startswith("/"):
        p = canon_path(os.path.join(cwd, p))
    return p


def normalize_auditd(lines: list[str], host_id: str = "localhost") -> list[NormalizedEvent]:
    """Normalize one serial-group of audit lines into 0..n events (usually 0 or 1)."""
    recs = [r for r in (parse_record(ln) for ln in lines) if r]
    if not recs:
        raise ValueError("no parsable auditd records")
    by_type: dict[str, list[dict[str, str]]] = {}
    for r in recs:
        by_type.setdefault(r["type"], []).append(r["fields"])
    ts = parse_ts(recs[0]["ts"])
    serial = recs[0]["serial"]
    meta_base = {"audit_serial": serial}
    cwd = (by_type.get("CWD") or [{}])[0].get("cwd")

    sysc = by_type["SYSCALL"][0] if by_type.get("SYSCALL") else None
    if sysc is None:
        return _non_syscall(recs, ts, host_id, meta_base)

    name = _syscall_name(sysc)
    exe = canon_path(sysc.get("exe"))
    comm = clean_str(sysc.get("comm"))
    common: dict[str, Any] = {
        "timestamp": ts or parse_ts(0),
        "host_id": host_id,
        "user": _user_for(sysc),
        "pid": to_int(sysc.get("pid")),
        "ppid": to_int(sysc.get("ppid")),
        "process_name": comm or basename_any(exe),
        "executable_path": exe,
        "source": "auditd",
    }
    ok = sysc.get("success", "yes") in {"yes", "1"}
    meta = safe_meta(
        {
            **meta_base,
            "syscall": name or sysc.get("syscall"),
            "success": ok,
            "exit": sysc.get("exit"),
            "euid": sysc.get("euid"),
            "auid": sysc.get("auid"),
            "tty": sysc.get("tty"),
            "audit_key": sysc.get("key"),
            "cwd": cwd,
        }
    )
    paths = by_type.get("PATH", [])

    def ev(et: EventType, **kw: Any) -> NormalizedEvent:
        return make_event(
            event_type=et, raw_metadata=safe_meta({**meta, **kw.pop("meta", {})}), **common, **kw
        )

    if name in {"execve", "execveat"}:
        if not ok:
            return []
        argv = by_type["EXECVE"][0] if by_type.get("EXECVE") else None
        cmd = _execve_cmdline(argv) if argv else None
        if cmd is None and by_type.get("PROCTITLE"):
            cmd = clean_str(by_type["PROCTITLE"][0].get("proctitle"), MAX_CMD)
        target = canon_path(paths[0].get("name")) if paths else None
        e = ev(EventType.PROCESS_START, command_line=cmd, meta={"exec_target": target})
        if e.executable_path is None and target:
            e = e.model_copy(update={"executable_path": _resolve(target, cwd)})
        return [e]
    if name in {"connect", "bind"}:
        sa = (by_type.get("SOCKADDR") or [{}])[0].get("saddr")
        info = parse_saddr(sa) if sa else None
        if not info or "ip" not in info:
            return []  # unix sockets / unparsable: not network telemetry
        et = EventType.NETWORK_CONNECT if name == "connect" else EventType.NETWORK_LISTEN
        return [ev(et, destination_ip=canon_ip(info["ip"]), destination_port=canon_port(info["port"]))]
    if name in {"rename", "renameat", "renameat2"}:
        old = next((p for p in paths if p.get("nametype") == "DELETE"), None)
        new = next((p for p in paths if p.get("nametype") == "CREATE"), None)
        if old is None or new is None:
            normal = [p for p in paths if p.get("nametype") in {"NORMAL", "DELETE", "CREATE"}]
            if len(normal) >= 2:
                old, new = normal[0], normal[-1]
        if old is None or new is None:
            return []
        return [
            ev(
                EventType.FILE_RENAME,
                file_path=_resolve(new.get("name"), cwd),
                meta={"old_path": _resolve(old.get("name"), cwd)},
            )
        ]
    if name in {"unlink", "unlinkat"}:
        target_p = next((p for p in paths if p.get("nametype") == "DELETE"), paths[-1] if paths else None)
        if target_p is None:
            return []
        return [ev(EventType.FILE_DELETE, file_path=_resolve(target_p.get("name"), cwd))]
    if name in {"open", "openat", "creat"}:
        flags = to_int(sysc.get("a1" if name == "open" else "a2"), 16) or 0
        if name == "creat":
            flags = _O_CREAT | _O_WRONLY | _O_TRUNC
        created = any(p.get("nametype") == "CREATE" for p in paths)
        writes = bool(flags & (_O_WRONLY | _O_RDWR | _O_TRUNC | _O_APPEND))
        if not ok or not (created or writes):
            return []
        target_p = next(
            (p for p in paths if p.get("nametype") in {"CREATE", "NORMAL"}), paths[-1] if paths else None
        )
        if target_p is None:
            return []
        et = EventType.FILE_CREATE if created else EventType.FILE_MODIFY
        return [ev(et, file_path=_resolve(target_p.get("name"), cwd))]
    if name in {"chmod", "fchmodat"}:
        if not ok or not paths:
            return []
        return [
            ev(EventType.FILE_MODIFY, file_path=_resolve(paths[0].get("name"), cwd), meta={"chmod": True})
        ]
    if name in {"setuid", "setresuid", "setgid", "setresgid"}:
        return [ev(EventType.PRIVILEGE_CHANGE, meta={"target_id": sysc.get("a0")})]
    if name == "ptrace":
        return [
            ev(
                EventType.PROCESS_INJECT,
                meta={"ptrace_request": sysc.get("a0"), "target_pid": sysc.get("a1")},
            )
        ]
    if name in {"init_module", "finit_module"}:
        return [ev(EventType.MODULE_LOAD)]
    return []


def _non_syscall(
    recs: list[dict[str, Any]], ts: Any, host_id: str, meta_base: dict[str, Any]
) -> list[NormalizedEvent]:
    r = recs[0]
    f = r["fields"]
    t = r["type"]
    if t in {"USER_LOGIN", "USER_AUTH", "USER_START", "USER_ACCT", "LOGIN"} or t.startswith("ANOM_LOGIN"):
        res = f.get("res", f.get("result", "unknown")).strip("'")
        return [
            make_event(
                event_type=EventType.AUTH,
                timestamp=ts,
                host_id=host_id,
                user=clean_str(f.get("acct")) or _user_for(f),
                pid=to_int(f.get("pid")),
                executable_path=canon_path(f.get("exe")),
                process_name=basename_any(canon_path(f.get("exe"))),
                destination_ip=canon_ip(f.get("addr")),
                source="auditd",
                raw_metadata=safe_meta(
                    {**meta_base, "audit_type": t, "result": res, "terminal": f.get("terminal")}
                ),
            )
        ]
    if t.startswith("ANOM_") or t in {"AVC", "SELINUX_ERR", "CONFIG_CHANGE", "DAEMON_END"}:
        return [
            make_event(
                event_type=EventType.TAMPER if t in {"CONFIG_CHANGE", "DAEMON_END"} else EventType.OTHER,
                timestamp=ts,
                host_id=host_id,
                pid=to_int(f.get("pid")),
                process_name=clean_str(f.get("comm")),
                executable_path=canon_path(f.get("exe")),
                source="auditd",
                confidence=0.6,
                raw_metadata=safe_meta({**meta_base, "audit_type": t, **f}),
            )
        ]
    return []
