"""Unit tests for Phase 2G: Rollback and reversibility engine with dead-man switch."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

from centralium.agent.models import ActionStatus, ResponseAction
from centralium.agent.response.base import BaseResponseExecutor
from centralium.agent.response.reversibility import (
    IsolationDeadManSwitch,
    ReversibilityJournal,
    UndoAction,
    UndoStatus,
)


class MockExecutor(BaseResponseExecutor):
    def __init__(self):
        super().__init__(simulate=True)
        self.released_blocks = False
        self.released_isolation = False

    def release_blocks(self, simulate: bool = False) -> str:
        self.released_blocks = True
        return "mock released blocks"

    def release_isolation(self, simulate: bool = False) -> str:
        self.released_isolation = True
        return "mock released isolation"


def test_reversibility_record_and_rollback_suspend():
    journal = ReversibilityJournal()
    target = {"pid": 99999, "process_name": "test_proc"}

    undo = journal.record(
        ResponseAction.SUSPEND_PROCESS,
        target,
        result_detail="suspended pid=99999",
    )

    assert isinstance(undo, UndoAction)
    assert undo.action_type == ResponseAction.SUSPEND_PROCESS
    assert undo.undo_operation == "RESUME_PROCESS"
    assert undo.is_reversible is True
    assert undo.status == UndoStatus.PENDING

    # Attempt rollback
    res = journal.rollback(undo.undo_id)
    assert res.status == ActionStatus.EXECUTED
    # On linux with non-existent process 99999 it reports "Process 99999 no longer exists" or "Sent SIGCONT"
    assert "process 99999" in res.detail.lower()

    updated = journal.get_action(undo.undo_id)
    assert updated is not None
    assert updated.status == UndoStatus.REVERSED


def test_reversibility_terminate_is_non_reversible():
    journal = ReversibilityJournal()
    undo = journal.record(
        ResponseAction.TERMINATE_PROCESS,
        {"pid": 1234},
        result_detail="terminated pid=1234",
    )

    assert undo.is_reversible is False
    assert undo.status == UndoStatus.NON_REVERSIBLE

    # Attempting to rollback a terminated process fails gracefully
    res = journal.rollback(undo.undo_id)
    assert res.status == ActionStatus.FAILED
    assert "marked non-reversible" in res.detail


def test_reversibility_firewall_blocks_rollback():
    journal = ReversibilityJournal()
    executor = MockExecutor()

    undo = journal.record(
        ResponseAction.BLOCK_CONNECTION,
        {"ip": "203.0.113.1", "port": 4444},
        executor=executor,
        result_detail="blocked outbound 203.0.113.1",
    )

    assert undo.undo_operation == "RELEASE_BLOCKS"
    res = journal.rollback(undo.undo_id, executor=executor)

    assert res.status == ActionStatus.EXECUTED
    assert executor.released_blocks is True
    assert "mock released blocks" in res.detail


def test_reversibility_quarantine_rollback():
    journal = ReversibilityJournal()
    quarantine_mgr = MagicMock()
    quarantine_mgr.restore.return_value = Path("/original/path/file.txt")

    undo = journal.record(
        ResponseAction.QUARANTINE_FILE,
        {"path": "/original/path/file.txt"},
        result_detail="quarantined as q-123456 sha256=abc123",
        quarantine_id="q-123456",
    )

    assert undo.undo_operation == "RESTORE_QUARANTINED_FILE"
    assert undo.undo_metadata.get("quarantine_id") == "q-123456"

    res = journal.rollback(undo.undo_id, quarantine_mgr=quarantine_mgr)
    assert res.status == ActionStatus.EXECUTED
    quarantine_mgr.restore.assert_called_once_with(
        "q-123456",
        authorized_by="reversibility_engine",
        reason="Operator rollback of quarantine action",
    )
    assert "/original/path/file.txt" in res.detail


def test_reversibility_isolation_and_dead_man_switch(tmp_path: Path):
    state_file = tmp_path / "deadman_test.json"
    deadman = IsolationDeadManSwitch(default_timeout=1.0, state_file=state_file)
    journal = ReversibilityJournal(dead_man_switch=deadman)
    executor = MockExecutor()

    # Record ISOLATE_ENDPOINT - arms dead man switch
    undo = journal.record(
        ResponseAction.ISOLATE_ENDPOINT,
        {"endpoint": True},
        executor=executor,
        result_detail="endpoint isolated",
    )

    assert deadman.is_armed is True
    assert deadman.time_remaining() > 0.0
    assert state_file.exists()

    # Heartbeat extends countdown
    rem_before = deadman.time_remaining()
    deadman.heartbeat(extend_seconds=5.0)
    assert deadman.time_remaining() > rem_before

    # Rollback releases isolation and disarms switch
    res = journal.rollback(undo.undo_id, executor=executor)
    assert res.status == ActionStatus.EXECUTED
    assert executor.released_isolation is True
    assert deadman.is_armed is False
    assert not state_file.exists()


def test_dead_man_switch_auto_release_on_timeout(tmp_path: Path):
    fired = []

    def on_release():
        fired.append(True)

    state_file = tmp_path / "deadman_timeout.json"
    # Set ultra-short timeout for unit test
    deadman = IsolationDeadManSwitch(default_timeout=0.05, state_file=state_file)
    deadman.arm(timeout=0.05, release_callback=on_release)

    assert deadman.is_armed is True
    time.sleep(0.12)  # Wait for timer to fire

    assert len(fired) == 1
    assert deadman.is_armed is False
    assert not state_file.exists()


def test_rollback_all_reverse_chronological():
    journal = ReversibilityJournal()
    executor = MockExecutor()

    journal.record(ResponseAction.BLOCK_CONNECTION, {"ip": "1.1.1.1"}, executor=executor)
    journal.record(ResponseAction.ISOLATE_ENDPOINT, {"endpoint": True}, executor=executor)

    results = journal.rollback_all(executor=executor)
    assert len(results) == 2
    # ISOLATE_ENDPOINT was recorded last, so rolled back first
    assert results[0].action == ResponseAction.ISOLATE_ENDPOINT
    assert results[1].action == ResponseAction.BLOCK_CONNECTION
