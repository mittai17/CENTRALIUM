"""Unit tests for credential access and lateral movement detection."""

from __future__ import annotations

from datetime import UTC, datetime

from centralium.agent.behavior.credential_access import (
    CredentialAccessConfig,
    CredentialAccessDetector,
)
from centralium.agent.models import EventType, NormalizedEvent


def _make_event(
    event_type: EventType = EventType.PROCESS_START,
    command_line: str = "",
    process_name: str = "",
    file_path: str = "",
    dest_port: int | None = None,
    raw_metadata: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-ev-1",
        timestamp=datetime.now(UTC),
        event_type=event_type,
        process_name=process_name or "test.exe",
        pid=1234,
        command_line=command_line,
        file_path=file_path,
        destination_port=dest_port,
        raw_metadata=raw_metadata or {},
    )


def test_lsass_dumping_detection():
    detector = CredentialAccessDetector()

    # Command line mimikatz
    ev_mimi = _make_event(
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        process_name="mimikatz.exe",
    )
    findings = detector.evaluate(ev_mimi)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_CRED_LSASS_ACCESS"
    assert "T1003.001" in findings[0].mitre_techniques

    # Comsvcs minidump
    ev_comsvcs = _make_event(
        command_line="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 652 C:\\temp\\lsass.dmp full",
        process_name="rundll32.exe",
    )
    findings = detector.evaluate(ev_comsvcs)
    assert any(f.rule_id == "BEH_CRED_LSASS_ACCESS" for f in findings)

    # Sysmon Event 10 style target process
    ev_sysmon = _make_event(
        command_line="",
        process_name="unknown.exe",
        raw_metadata={"target_process": "lsass.exe", "call_trace": "ntdll.dll+0x1234"},
    )
    findings = detector.evaluate(ev_sysmon)
    assert any(f.rule_id == "BEH_CRED_LSASS_ACCESS" for f in findings)

    # Benign process
    ev_benign = _make_event(
        command_line="notepad.exe C:\\notes.txt",
        process_name="notepad.exe",
    )
    assert len(detector.evaluate(ev_benign)) == 0


def test_shadow_reads_detection():
    detector = CredentialAccessDetector()

    # Unauthorized access via cat
    ev_cat = _make_event(
        command_line="cat /etc/shadow",
        process_name="cat",
        file_path="/etc/shadow",
    )
    findings = detector.evaluate(ev_cat)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_CRED_SHADOW_READ"
    assert "T1003.008" in findings[0].mitre_techniques

    # Authorized access via unix_chkpwd or sshd
    ev_sshd = _make_event(
        command_line="/usr/sbin/sshd -D",
        process_name="sshd",
        file_path="/etc/shadow",
    )
    assert len(detector.evaluate(ev_sshd)) == 0


def test_ssh_agent_hijacking():
    detector = CredentialAccessDetector()

    # Unauthorized socket access
    ev_hijack = _make_event(
        command_line="python3 exploit.py --sock /tmp/ssh-ABC123xyz/agent.456",
        process_name="python3",
        file_path="/tmp/ssh-ABC123xyz/agent.456",
    )
    findings = detector.evaluate(ev_hijack)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_CRED_SSH_AGENT_HIJACK"
    assert "T1563.001" in findings[0].mitre_techniques

    # Legitimate ssh binary
    ev_ssh = _make_event(
        command_line="ssh -A user@remote",
        process_name="ssh",
        file_path="/tmp/ssh-ABC123xyz/agent.456",
    )
    assert len(detector.evaluate(ev_ssh)) == 0


def test_remote_service_creation():
    detector = CredentialAccessDetector()

    # sc.exe create
    ev_sc = _make_event(
        command_line=r"sc.exe create MaliciousService binpath= C:\evil.exe start= auto",
        process_name="sc.exe",
    )
    findings = detector.evaluate(ev_sc)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_LAT_SERVICE_CREATE"
    assert "T1569.002" in findings[0].mitre_techniques

    # Service change event
    ev_svc = _make_event(
        event_type=EventType.SERVICE_CHANGE,
        raw_metadata={"action": "create", "service_name": "BackdoorSvc"},
    )
    findings = detector.evaluate(ev_svc)
    assert any(f.rule_id == "BEH_LAT_SERVICE_CREATE" for f in findings)


def test_psexec_wmi_winrm_lateral_movement():
    detector = CredentialAccessDetector()

    # PsExec
    ev_psexec = _make_event(
        command_line=r"psexec.exe \\192.168.1.50 -u admin -p pass cmd.exe",
        process_name="psexec.exe",
    )
    findings = detector.evaluate(ev_psexec)
    assert any(f.rule_id == "BEH_LAT_PSEXEC" for f in findings)

    # WMI
    ev_wmi = _make_event(
        command_line=r'wmic /node:192.168.1.50 process call create "powershell.exe -enc ..."',
        process_name="wmic.exe",
    )
    findings = detector.evaluate(ev_wmi)
    assert any(f.rule_id == "BEH_LAT_WMI" for f in findings)
    assert "T1047" in findings[0].mitre_techniques

    # WinRM
    ev_winrm = _make_event(
        command_line="Invoke-Command -ComputerName srv01 -ScriptBlock { whoami }",
        process_name="powershell.exe",
        dest_port=5985,
    )
    findings = detector.evaluate(ev_winrm)
    assert any(f.rule_id == "BEH_LAT_WINRM" for f in findings)


def test_smb_admin_shares():
    detector = CredentialAccessDetector()

    # Net use admin share
    ev_admin_share = _make_event(
        command_line=r"net use X: \\192.168.1.10\ADMIN$ /user:admin password",
        process_name="net.exe",
    )
    findings = detector.evaluate(ev_admin_share)
    assert len(findings) == 1
    assert findings[0].rule_id == "BEH_LAT_SMB_ADMIN_SHARE"
    assert "T1021.002" in findings[0].mitre_techniques

    # C$ share via metadata
    ev_c_share = _make_event(
        raw_metadata={"share_name": "C$"},
    )
    findings = detector.evaluate(ev_c_share)
    assert any(f.rule_id == "BEH_LAT_SMB_ADMIN_SHARE" for f in findings)

    # Benign public share
    ev_pub = _make_event(
        command_line=r"net use X: \\192.168.1.10\PublicDocs",
        raw_metadata={"share_name": "PublicDocs"},
    )
    assert len(detector.evaluate(ev_pub)) == 0


def test_credential_access_config_toggle():
    config = CredentialAccessConfig(enable_lsass_detection=False)
    detector = CredentialAccessDetector(config=config)

    ev_mimi = _make_event(command_line="mimikatz.exe sekurlsa::logonpasswords")
    assert len(detector.evaluate(ev_mimi)) == 0
