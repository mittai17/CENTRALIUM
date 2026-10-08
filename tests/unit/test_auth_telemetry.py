"""Unit tests for Authentication telemetry collector (Linux auth.log and Windows Security logs)."""

from __future__ import annotations

from centralium.agent.collectors.auth_telemetry import (
    AuthTelemetryCollector,
    parse_linux_auth_line,
    parse_windows_security_event,
)
from centralium.agent.models import EventType, NormalizedEvent


def test_linux_auth_ssh_accepted():
    line_pwd = (
        "Oct  7 12:00:00 server sshd[12345]: Accepted password for root from 192.168.1.50 port 52341 ssh2"
    )
    ev = parse_linux_auth_line(line_pwd)
    assert ev is not None
    assert ev.event_type == EventType.AUTH_LOGIN
    assert ev.user == "root"
    assert ev.destination_ip == "192.168.1.50"
    assert ev.destination_port == 52341
    assert ev.process_name == "sshd"
    assert ev.raw_metadata["auth_method"] == "password"

    line_key = "Oct  7 12:01:00 server sshd[12346]: Accepted publickey for ubuntu from 10.0.0.1 port 43210 ssh2: RSA SHA256:abc"
    ev2 = parse_linux_auth_line(line_key)
    assert ev2 is not None
    assert ev2.event_type == EventType.AUTH_LOGIN
    assert ev2.user == "ubuntu"
    assert ev2.raw_metadata["auth_method"] == "publickey"


def test_linux_auth_ssh_failed():
    line = "Oct  7 12:02:00 server sshd[12347]: Failed password for invalid user admin from 192.168.1.100 port 38291 ssh2"
    ev = parse_linux_auth_line(line)
    assert ev is not None
    assert ev.event_type == EventType.AUTH_FAIL
    assert ev.user == "admin"
    assert ev.destination_ip == "192.168.1.100"
    assert ev.destination_port == 38291


def test_linux_auth_sudo_and_su_elevation():
    line_sudo = "Oct  7 12:03:00 server sudo[2000]:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    ev = parse_linux_auth_line(line_sudo)
    assert ev is not None
    assert ev.event_type == EventType.PRIVILEGE_ELEVATION
    assert ev.user == "alice"
    assert ev.command_line == "/bin/bash"
    assert ev.process_name == "sudo"
    assert ev.raw_metadata["target_user"] == "root"

    line_su = "Oct  7 12:04:00 server su[2001]: (to root) alice on pts/0"
    ev_su = parse_linux_auth_line(line_su)
    assert ev_su is not None
    assert ev_su.event_type == EventType.PRIVILEGE_ELEVATION
    assert ev_su.user == "alice"
    assert ev_su.process_name == "su"
    assert ev_su.raw_metadata["target_user"] == "root"


def test_linux_auth_pam_sessions():
    open_line = (
        "Oct  7 12:05:00 server sshd[12345]: pam_unix(sshd:session): session opened for user alice by (uid=0)"
    )
    ev_open = parse_linux_auth_line(open_line)
    assert ev_open is not None
    assert ev_open.event_type == EventType.AUTH_LOGIN
    assert ev_open.user == "alice"

    close_line = "Oct  7 12:06:00 server sshd[12345]: pam_unix(sshd:session): session closed for user alice"
    ev_close = parse_linux_auth_line(close_line)
    assert ev_close is not None
    assert ev_close.event_type == EventType.AUTH_LOGOUT
    assert ev_close.user == "alice"


def test_windows_security_4624_and_4625():
    # 4624: Logon success
    rec_4624 = {
        "event_id": 4624,
        "TargetUserName": "Administrator",
        "TargetDomainName": "CORP",
        "LogonType": 10,  # RemoteInteractive (RDP)
        "IpAddress": "192.168.1.75",
        "IpPort": 54321,
    }
    ev = parse_windows_security_event(rec_4624)
    assert ev is not None
    assert ev.event_type == EventType.AUTH_LOGIN
    assert ev.user == "CORP\\Administrator"
    assert ev.destination_ip == "192.168.1.75"
    assert ev.destination_port == 54321

    # 4625: Logon failure
    rec_4625 = {
        "event_id": 4625,
        "TargetUserName": "admin",
        "IpAddress": "203.0.113.5",
        "Status": "0xC000006D",
        "FailureReason": "Unknown user name or bad password",
    }
    ev_fail = parse_windows_security_event(rec_4625)
    assert ev_fail is not None
    assert ev_fail.event_type == EventType.AUTH_FAIL
    assert ev_fail.user == "admin"
    assert ev_fail.destination_ip == "203.0.113.5"


def test_windows_security_4634_4648_4672():
    # 4634: Logoff
    ev_off = parse_windows_security_event({"event_id": 4634, "TargetUserName": "alice"})
    assert ev_off is not None
    assert ev_off.event_type == EventType.AUTH_LOGOUT
    assert ev_off.user == "alice"

    # 4648: Explicit Credentials
    ev_exp = parse_windows_security_event(
        {
            "event_id": 4648,
            "TargetUserName": "svc_backup",
            "TargetServerName": "DC01",
        }
    )
    assert ev_exp is not None
    assert ev_exp.event_type == EventType.AUTH_LOGIN
    assert ev_exp.raw_metadata["explicit_credentials"] is True

    # 4672: Special Privileges Assigned
    ev_priv = parse_windows_security_event(
        {
            "event_id": 4672,
            "SubjectUserName": "SYSTEM",
            "PrivilegeList": "SeDebugPrivilege\nSeTcbPrivilege",
        }
    )
    assert ev_priv is not None
    assert ev_priv.event_type == EventType.PRIVILEGE_ELEVATION
    assert ev_priv.user == "SYSTEM"
    assert "SeDebugPrivilege" in ev_priv.raw_metadata["privileges"]


def test_auth_telemetry_collector_ingest():
    collector = AuthTelemetryCollector(auth_log_path="/nonexistent/auth.log")
    events: list[NormalizedEvent] = []
    collector.start(events.append)

    try:
        ok1 = collector.ingest_linux_line(
            "Oct  7 12:00:00 server sshd[123]: Accepted password for bob from 10.0.0.2 port 22 ssh2"
        )
        assert ok1 is True
        assert collector.stats["auth_logins"] == 1

        ok2 = collector.ingest_windows_event(
            {
                "event_id": 4672,
                "SubjectUserName": "admin",
                "PrivilegeList": "SeDebugPrivilege",
            }
        )
        assert ok2 is True
        assert collector.stats["privilege_elevations"] == 1

        assert collector.queue_depth() == 2
    finally:
        collector.stop()
