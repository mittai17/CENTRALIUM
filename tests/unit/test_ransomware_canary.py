"""Unit tests for ransomware canaries and protective snapshot rollback."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from centralium.agent.models import ActionStatus, EventType, NormalizedEvent, ResponseAction
from centralium.agent.ransomware.canary import (
    CanaryConfig,
    CanaryManager,
)
from centralium.agent.response.snapshot import (
    SnapshotConfig,
    SnapshotManager,
    execute_snapshot_protect,
)


def _make_file_event(file_path: str, event_type: EventType = EventType.FILE_MODIFY) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-file-ev",
        timestamp=datetime.now(UTC),
        event_type=event_type,
        process_name="ransomware.exe",
        pid=5555,
        command_line="ransomware.exe -encrypt",
        file_path=file_path,
    )


def test_canary_deployment_and_detection(tmp_path: Path):
    target_dir = tmp_path / "documents"
    target_dir.mkdir()

    manager = CanaryManager()
    records = manager.deploy([target_dir])
    assert len(records) > 0
    assert any(Path(r.path).exists() for r in records)

    # Touch canary file
    canary_path = records[0].path
    ev = _make_file_event(canary_path)
    finding = manager.evaluate_event(ev)
    assert finding is not None
    assert finding.rule_id == "RANSOM_CANARY_TRIPPED"
    assert "T1486" in finding.mitre_techniques

    # Non-canary file event
    benign_ev = _make_file_event(str(tmp_path / "normal.txt"))
    assert manager.evaluate_event(benign_ev) is None

    # Cleanup
    manager.cleanup()
    assert not Path(canary_path).exists()


def test_canary_integrity_audit(tmp_path: Path):
    target_dir = tmp_path / "data"
    manager = CanaryManager(config=CanaryConfig(canary_names=["!test_canary.docx"]))
    records = manager.deploy([target_dir])
    canary_file = Path(records[0].path)

    # Initial audit should be clean
    assert len(manager.audit_integrity()) == 0

    # Tamper with canary content
    canary_file.write_bytes(b"ENCRYPTED_BLOB_RANSOM_NOTE_XYZ123")
    findings = manager.audit_integrity()
    assert len(findings) == 1
    assert findings[0].rule_id == "RANSOM_CANARY_MODIFIED"

    # Delete canary file
    canary_file.unlink()
    del_findings = manager.audit_integrity()
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "RANSOM_CANARY_DELETED"

    manager.cleanup()


def test_snapshot_protect_and_rollback(tmp_path: Path):
    user_docs = tmp_path / "user_docs"
    user_docs.mkdir()
    doc1 = user_docs / "financial_report.xlsx"
    doc2 = user_docs / "contract.docx"
    doc1.write_bytes(b"ORIGINAL FINANCIAL DATA 2026")
    doc2.write_bytes(b"ORIGINAL LEGAL CONTRACT TERMS")

    snap_dir = tmp_path / "snapshots"
    config = SnapshotConfig(storage_dir=str(snap_dir), max_snapshots_kept=3)
    snap_mgr = SnapshotManager(config=config)

    # Execute protective snapshot
    action_res = execute_snapshot_protect(snap_mgr, [user_docs], label="ransom_alert")
    assert action_res.action == ResponseAction.SNAPSHOT_PROTECT
    assert action_res.status == ActionStatus.EXECUTED
    assert action_res.target["file_count"] == 2
    snap_id = action_res.target["snapshot_id"]

    # Simulate ransomware encryption destroying the files
    doc1.write_bytes(b"ENCRYPTED BY LOCKBIT")
    doc2.write_bytes(b"ENCRYPTED BY LOCKBIT")
    assert doc1.read_bytes() == b"ENCRYPTED BY LOCKBIT"

    # Rollback snapshot
    success = snap_mgr.rollback(snap_id)
    assert success is True

    # Assert original content was restored
    assert doc1.read_bytes() == b"ORIGINAL FINANCIAL DATA 2026"
    assert doc2.read_bytes() == b"ORIGINAL LEGAL CONTRACT TERMS"


def test_snapshot_pruning(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "file.txt").write_text("content")

    snap_dir = tmp_path / "snaps"
    config = SnapshotConfig(storage_dir=str(snap_dir), max_snapshots_kept=2)
    snap_mgr = SnapshotManager(config=config)

    # Create 4 snapshots
    for i in range(4):
        snap_mgr.create_snapshot([src_dir], label=f"snap_{i}")

    # Only 2 snapshots should be retained
    assert len(snap_mgr.list_snapshots()) == 2
