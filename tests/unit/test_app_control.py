"""Unit tests for application control and device control."""

from __future__ import annotations

from datetime import UTC, datetime

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.policy.app_control import (
    AppControlConfig,
    AppControlEngine,
)


def _make_proc_event(
    executable_path: str,
    process_name: str = "",
    command_line: str = "",
    file_hash: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-app-ev",
        timestamp=datetime.now(UTC),
        event_type=EventType.PROCESS_START,
        process_name=process_name or "proc.exe",
        executable_path=executable_path,
        command_line=command_line,
        hash_sha256=file_hash,
    )


def test_execution_allowlist_mode():
    approved_hash = "f" * 64
    cfg = AppControlConfig(
        enable_allowlist_mode=True,
        allowed_paths=["/usr/bin/*", "/bin/*"],
        allowed_hashes=[approved_hash],
        allowed_process_names=["authorized_app"],
    )
    engine = AppControlEngine(config=cfg)

    # Standard system binary -> Allowed
    ev_ok = _make_proc_event("/usr/bin/python3", process_name="python3")
    assert len(engine.evaluate_event(ev_ok)) == 0

    # Binary in unauthorized temp directory -> Violates allowlist
    ev_unauth = _make_proc_event("/tmp/evil_miner", process_name="evil_miner")
    findings = engine.evaluate_event(ev_unauth)
    assert len(findings) == 1
    assert findings[0].rule_id == "APP_ALLOWLIST_VIOLATION"

    # Unauthorized path but approved SHA-256 hash -> Allowed
    ev_hashed = _make_proc_event(
        "/opt/custom/agent",
        process_name="custom_agent",
        file_hash=approved_hash,
    )
    assert len(engine.evaluate_event(ev_hashed)) == 0

    # Unauthorized path but approved process name -> Allowed
    ev_named = _make_proc_event("/opt/tools/authorized_app", process_name="authorized_app")
    assert len(engine.evaluate_event(ev_named)) == 0


def test_removable_media_device_and_execution_detection():
    engine = AppControlEngine()

    # Removable storage device connected
    ev_attach = NormalizedEvent(
        event_id="dev-1",
        timestamp=datetime.now(UTC),
        event_type=EventType.OTHER,
        raw_metadata={"bus": "usb", "device_type": "removable", "device_name": "SanDisk USB"},
    )
    findings_attach = engine.evaluate_event(ev_attach)
    assert len(findings_attach) == 1
    assert findings_attach[0].rule_id == "DEV_REMOVABLE_MEDIA_ATTACHED"

    # Execution directly from USB mount (/media/...)
    ev_exec = _make_proc_event("/media/user/USB_DRIVE/payload.sh", process_name="payload.sh")
    findings_exec = engine.evaluate_event(ev_exec)
    assert any(f.rule_id == "APP_REMOVABLE_MEDIA_EXEC" for f in findings_exec)

    # Execution from Windows secondary drive (E:\payload.exe)
    ev_win_exec = _make_proc_event(r"E:\tools\setup.exe", process_name="setup.exe")
    findings_win = engine.evaluate_event(ev_win_exec)
    assert any(f.rule_id == "APP_REMOVABLE_MEDIA_EXEC" for f in findings_win)

    # File copy to removable media
    ev_file = NormalizedEvent(
        event_id="file-1",
        timestamp=datetime.now(UTC),
        event_type=EventType.FILE_CREATE,
        file_path="/media/user/USB_DRIVE/exfiltrated_db.sqlite",
    )
    findings_file = engine.evaluate_event(ev_file)
    assert any(f.rule_id == "DEV_REMOVABLE_MEDIA_FILE_ACTIVITY" for f in findings_file)
