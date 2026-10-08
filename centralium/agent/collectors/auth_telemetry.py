"""Authentication and identity telemetry collector.

Parsers and telemetry collection for:
1. Linux authentication logs (/var/log/auth.log, /var/log/secure, or journald):
   - SSH logins (success / fail / invalid user)
   - PAM session open and close
   - Sudo / su / pkexec privilege elevation
2. Windows Security Event Log:
   - Event ID 4624: Logon success -> AUTH_LOGIN
   - Event ID 4625: Logon failure -> AUTH_FAIL
   - Event ID 4634 / 4647: Logoff -> AUTH_LOGOUT
   - Event ID 4648: Explicit credentials logon -> AUTH_LOGIN
   - Event ID 4672: Special privileges assigned -> PRIVILEGE_ELEVATION
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from typing import Any

from centralium.agent.collectors._base import BaseCollector
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
from centralium.agent.normalization.windows import parse_event_xml, split_event_xml

log = logging.getLogger(__name__)

# Linux Auth regexes
_RE_SSH_ACCEPTED = re.compile(
    r"sshd(?:\[(?P<pid>\d+)\])?: Accepted (?P<method>password|publickey) "
    r"for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_RE_SSH_FAILED = re.compile(
    r"sshd(?:\[(?P<pid>\d+)\])?: Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_RE_PAM_OPEN = re.compile(
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?: "
    r"pam_unix\((?P<service>[^:]+):session\): session opened for user (?P<user>\S+)"
)
_RE_PAM_CLOSE = re.compile(
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?: "
    r"pam_unix\((?P<service>[^:]+):session\): session closed for user (?P<user>\S+)"
)
_RE_SUDO = re.compile(
    r"sudo(?:\[(?P<pid>\d+)\])?:\s+(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)"
)
_RE_SU = re.compile(
    r"su(?:\[(?P<pid>\d+)\])?:\s+(?:\(to (?P<target_user>\S+)\)\s+(?P<user>\S+)|"
    r"Successful su for (?P<target_user2>\S+) by (?P<user2>\S+))"
)


def parse_linux_auth_line(line: str, host_id: str = "localhost") -> NormalizedEvent | None:
    """Parse a single line from Linux auth.log / secure log into NormalizedEvent."""
    line = line.strip()
    if not line:
        return None

    # 1. SSH Accepted
    m = _RE_SSH_ACCEPTED.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd["user"]
        dest_ip = canon_ip(gd["ip"])
        port = canon_port(gd["port"])
        method = gd["method"]
        return make_event(
            event_type=EventType.AUTH_LOGIN,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name="sshd",
            destination_ip=dest_ip,
            destination_port=port,
            protocol="ssh",
            raw_metadata={"auth_method": method, "raw_line": line},
        )

    # 2. SSH Failed
    m = _RE_SSH_FAILED.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd["user"]
        dest_ip = canon_ip(gd["ip"])
        port = canon_port(gd["port"])
        return make_event(
            event_type=EventType.AUTH_FAIL,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name="sshd",
            destination_ip=dest_ip,
            destination_port=port,
            protocol="ssh",
            raw_metadata={"auth_method": "password", "raw_line": line},
        )

    # 3. Sudo elevation
    m = _RE_SUDO.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd["user"]
        target_user = gd["target_user"]
        cmd = gd["cmd"].strip()
        pwd = gd["pwd"].strip()
        return make_event(
            event_type=EventType.PRIVILEGE_ELEVATION,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name="sudo",
            command_line=cmd,
            raw_metadata={"target_user": target_user, "pwd": pwd, "tty": gd.get("tty")},
        )

    # 4. su elevation
    m = _RE_SU.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd.get("user") or gd.get("user2")
        target_user = gd.get("target_user") or gd.get("target_user2") or "root"
        return make_event(
            event_type=EventType.PRIVILEGE_ELEVATION,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name="su",
            command_line=f"su {target_user}",
            raw_metadata={"target_user": target_user},
        )

    # 5. PAM Session Opened
    m = _RE_PAM_OPEN.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd["user"]
        proc = gd["proc"]
        svc = gd["service"]
        return make_event(
            event_type=EventType.AUTH_LOGIN,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name=proc,
            raw_metadata={"service": svc, "pam_action": "open"},
        )

    # 6. PAM Session Closed
    m = _RE_PAM_CLOSE.search(line)
    if m:
        gd = m.groupdict()
        pid = to_int(gd.get("pid"))
        user = gd["user"]
        proc = gd["proc"]
        svc = gd["service"]
        return make_event(
            event_type=EventType.AUTH_LOGOUT,
            host_id=host_id,
            source="auth_log",
            pid=pid,
            user=user,
            process_name=proc,
            raw_metadata={"service": svc, "pam_action": "close"},
        )

    return None


def parse_windows_security_event(
    record: dict[str, Any] | str, host_id: str = "localhost"
) -> NormalizedEvent | None:
    """Parse Windows Security Event (Event ID 4624, 4625, 4634, 4648, 4672)."""
    if isinstance(record, str):
        docs = split_event_xml(record) or [record]
        win_rec = parse_event_xml(docs[0])
        eid = win_rec.event_id
        data = win_rec.data
        computer = win_rec.computer or host_id
        ts = parse_ts(win_rec.time)
    else:
        eid = to_int(record.get("event_id") or record.get("EventID") or record.get("id"))
        data = dict(record.get("data") or record.get("EventData") or record)
        computer = str(record.get("computer") or record.get("host_id") or host_id)
        ts = parse_ts(record.get("timestamp") or record.get("time"))

    if eid is None:
        return None

    # Helper user extraction
    user = str(data.get("TargetUserName") or data.get("SubjectUserName") or "") or None
    domain = str(data.get("TargetDomainName") or data.get("SubjectDomainName") or "")
    if user and domain and domain not in {"-", "."} and "\\" not in user:
        user = f"{domain}\\{user}"

    ip = canon_ip(data.get("IpAddress"))
    port = canon_port(data.get("IpPort"))
    proc_img = canon_path(data.get("ProcessName"))
    pname = basename_any(proc_img) if proc_img else None
    pid = to_int(data.get("ProcessId"))

    meta: dict[str, Any] = {
        "event_id": eid,
        "logon_type": data.get("LogonType"),
        "workstation": data.get("WorkstationName"),
    }

    # 4624: Successful Logon
    if eid == 4624:
        return make_event(
            event_type=EventType.AUTH_LOGIN,
            timestamp=ts,
            host_id=computer,
            source="security_eventlog",
            pid=pid,
            process_name=pname,
            executable_path=proc_img,
            user=user,
            destination_ip=ip,
            destination_port=port,
            raw_metadata=meta,
        )

    # 4625: Failed Logon
    if eid == 4625:
        meta.update(
            {
                "status": data.get("Status"),
                "sub_status": data.get("SubStatus"),
                "failure_reason": data.get("FailureReason"),
            }
        )
        return make_event(
            event_type=EventType.AUTH_FAIL,
            timestamp=ts,
            host_id=computer,
            source="security_eventlog",
            pid=pid,
            process_name=pname,
            executable_path=proc_img,
            user=user,
            destination_ip=ip,
            destination_port=port,
            raw_metadata=meta,
        )

    # 4634, 4647: Logoff
    if eid in (4634, 4647):
        return make_event(
            event_type=EventType.AUTH_LOGOUT,
            timestamp=ts,
            host_id=computer,
            source="security_eventlog",
            pid=pid,
            user=user,
            raw_metadata=meta,
        )

    # 4648: Explicit Credentials Logon
    if eid == 4648:
        meta.update(
            {
                "explicit_credentials": True,
                "target_server": data.get("TargetServerName"),
            }
        )
        return make_event(
            event_type=EventType.AUTH_LOGIN,
            timestamp=ts,
            host_id=computer,
            source="security_eventlog",
            pid=pid,
            process_name=pname,
            executable_path=proc_img,
            user=user,
            destination_ip=ip,
            destination_port=port,
            raw_metadata=meta,
        )

    # 4672: Special Privileges Assigned
    if eid == 4672:
        privs = str(data.get("PrivilegeList") or data.get("Privileges") or "")
        meta["privileges"] = privs
        return make_event(
            event_type=EventType.PRIVILEGE_ELEVATION,
            timestamp=ts,
            host_id=computer,
            source="security_eventlog",
            pid=pid,
            user=user,
            raw_metadata=meta,
        )

    return None


class AuthTelemetryCollector(BaseCollector):
    """Authentication and privilege telemetry collector."""

    name = "auth_telemetry"
    platforms = ("linux", "windows")

    def __init__(
        self,
        auth_log_path: str = "/var/log/auth.log",
        *,
        poll_interval: float = 1.0,
        **kw: Any,
    ) -> None:
        super().__init__(poll_interval=poll_interval, **kw)
        self.auth_log_path = auth_log_path
        self._file_pos = 0

        self.stats.update(
            {
                "auth_logins": 0,
                "auth_logouts": 0,
                "auth_fails": 0,
                "privilege_elevations": 0,
            }
        )

        if sys.platform.startswith("linux"):
            if os.path.exists(auth_log_path) and os.access(auth_log_path, os.R_OK):
                self.set_health(True, f"tailing {auth_log_path}")
            else:
                self.set_health(False, f"auth log {auth_log_path} not found or unreadable")
        elif sys.platform.startswith("win"):
            self.set_health(True, "ready for Windows security event log")
        else:
            self.set_health(True, "ready (manual ingest)")

    def ingest_linux_line(self, line: str) -> bool:
        """Parse and emit a Linux auth log line."""
        ev = parse_linux_auth_line(line, self.host_id)
        if ev is not None:
            self._update_stats(ev.event_type)
            return self.emit_event(ev)
        return False

    def ingest_windows_event(self, record: dict[str, Any] | str) -> bool:
        """Parse and emit a Windows security event."""
        ev = parse_windows_security_event(record, self.host_id)
        if ev is not None:
            self._update_stats(ev.event_type)
            return self.emit_event(ev)
        return False

    def _update_stats(self, et: EventType) -> None:
        if et == EventType.AUTH_LOGIN:
            self.stats["auth_logins"] += 1
        elif et == EventType.AUTH_LOGOUT:
            self.stats["auth_logouts"] += 1
        elif et == EventType.AUTH_FAIL:
            self.stats["auth_fails"] += 1
        elif et == EventType.PRIVILEGE_ELEVATION:
            self.stats["privilege_elevations"] += 1

    def _run(self) -> None:
        if not sys.platform.startswith("linux") or not os.path.exists(self.auth_log_path):
            self._stop.wait()
            return

        try:
            with open(self.auth_log_path, encoding="utf-8", errors="replace") as f:
                # Seek to end on startup to avoid replaying historic auth events
                f.seek(0, os.SEEK_END)
                self._file_pos = f.tell()

                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        self.ingest_linux_line(line)
                    else:
                        time.sleep(self.poll_interval)
        except OSError as exc:
            self.set_health(False, f"error reading {self.auth_log_path}: {exc}")
