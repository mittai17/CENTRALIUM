"""Unit tests for Phase 2E: Analyst feedback loop, baseline/allowlist suggestions,
and retraining dataset generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from centralium.agent.ml.feedback import (
    AnalystFeedbackRecord,
    AnalystFeedbackStore,
    FeedbackSuggestion,
    FeedbackType,
    SuggestionKind,
    SuggestionStatus,
)
from centralium.agent.storage import Database


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_path = tmp_path / "agent_test.db"
    db = Database(db_path)
    # Seed events and findings tables
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO events (
                event_id, timestamp, event_type, host_id, user, pid,
                process_name, executable_path, command_line, hash_sha256,
                signer, destination_ip, domain, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "ev-101",
                "2026-10-08T00:00:00Z",
                "process_start",
                "host-soc-1",
                "alice",
                1234,
                "powershell.exe",
                "C:\\Windows\\System32\\powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -File backup.ps1",
                "a" * 64,
                "Microsoft Corporation",
                "192.168.1.50",
                "corp.internal",
                "sysmon",
            ),
        )
        conn.execute(
            """INSERT INTO findings (
                finding_id, event_id, timestamp, source, rule_id, title, severity, score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "find-201",
                "ev-101",
                "2026-10-08T00:00:01Z",
                "sigma",
                "SIG-0042",
                "PowerShell execution bypass detected",
                "HIGH",
                78.5,
            ),
        )
    return db


def test_record_feedback_true_positive(test_db: Database):
    store = AnalystFeedbackStore(test_db)
    rec = store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="soc_analyst_1",
        feedback_type=FeedbackType.TRUE_POSITIVE,
        comment="Confirmed malicious obfuscated command line",
    )

    assert isinstance(rec, AnalystFeedbackRecord)
    assert rec.feedback_type == FeedbackType.TRUE_POSITIVE
    assert rec.rule_id == "SIG-0042"
    assert rec.severity == "HIGH"
    assert rec.features_snapshot.get("process_name") == "powershell.exe"
    assert rec.provenance.get("recorded_by") == "soc_analyst_1"

    # Verify stored in SQLite table analyst_feedback
    row = test_db.query_one("SELECT * FROM analyst_feedback WHERE feedback_id = ?", (rec.feedback_id,))
    assert row is not None
    assert row["feedback_type"] == "TP"
    assert row["analyst"] == "soc_analyst_1"

    # TPs must never generate allowlist suggestions
    suggestions = store.generate_suggestions(rec.feedback_id)
    assert len(suggestions) == 0


def test_record_feedback_false_positive_and_suggestions(test_db: Database):
    store = AnalystFeedbackStore(test_db)
    rec = store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="soc_analyst_2",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        comment="Routine automated IT backup script",
    )

    assert rec.feedback_type == FeedbackType.FALSE_POSITIVE

    # Generate suggestions
    suggestions = store.generate_suggestions(rec.feedback_id)
    assert len(suggestions) > 0

    # CRITICAL REQUIREMENT: suggestions are strictly PENDING_REVIEW; never auto-applied
    for s in suggestions:
        assert isinstance(s, FeedbackSuggestion)
        assert s.status == SuggestionStatus.PENDING_REVIEW
        assert s.applied_at is None
        assert s.applied_by is None

    # Check that allowlist table is currently untouched
    allowlist_rows = test_db.query("SELECT * FROM allowlist")
    assert len(allowlist_rows) == 0

    # Types of generated suggestions
    kinds = {s.kind for s in suggestions}
    assert SuggestionKind.ALLOWLIST in kinds
    assert SuggestionKind.BASELINE in kinds


def test_admin_confirmation_required_to_apply(test_db: Database):
    store = AnalystFeedbackStore(test_db)
    rec = store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="soc_analyst_2",
        feedback_type="BENIGN_EXPECTED",
        comment="Scheduled enterprise telemetry script",
    )

    suggestions = store.generate_suggestions(rec.feedback_id)
    allowlist_sug = next(
        s for s in suggestions if s.kind == SuggestionKind.ALLOWLIST and s.target_type == "process_name"
    )

    # Confirm suggestion as admin
    ok = store.confirm_suggestion(
        suggestion_id=allowlist_sug.suggestion_id,
        admin_user="admin_carol",
        confirmation_note="Approved per change request CHG-9981",
    )
    assert ok is True

    # Verify status changed to CONFIRMED
    updated_sug = store.list_suggestions(status=SuggestionStatus.CONFIRMED)[0]
    assert updated_sug.suggestion_id == allowlist_sug.suggestion_id
    assert updated_sug.applied_by == "admin_carol"
    assert updated_sug.applied_at is not None

    # Verify allowlist table now has entry
    row = test_db.query_one(
        "SELECT * FROM allowlist WHERE kind = ? AND value = ?", ("process_name", "powershell.exe")
    )
    assert row is not None
    assert row["added_by"] == "admin_carol"
    assert "CHG-9981" in row["reason"]

    # Verify audited action in audit_log
    audit_row = test_db.query_one(
        "SELECT * FROM audit_log WHERE event_type = ? ORDER BY seq DESC LIMIT 1",
        ("FEEDBACK_SUGGESTION_CONFIRMED",),
    )
    assert audit_row is not None
    assert audit_row["actor"] == "admin_carol"
    details = json.loads(audit_row["details"])
    assert details["suggestion_id"] == allowlist_sug.suggestion_id


def test_admin_reject_suggestion(test_db: Database):
    store = AnalystFeedbackStore(test_db)
    rec = store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="soc_analyst_2",
        feedback_type="FP",
        comment="Unnecessary alert",
    )
    suggestions = store.generate_suggestions(rec.feedback_id)
    sug = suggestions[0]

    ok = store.reject_suggestion(
        suggestion_id=sug.suggestion_id,
        admin_user="admin_dave",
        rejection_reason="Powershell cannot be globally allowlisted",
    )
    assert ok is True

    rejected_sugs = store.list_suggestions(status=SuggestionStatus.REJECTED)
    assert any(s.suggestion_id == sug.suggestion_id for s in rejected_sugs)

    # Allowlist must still be empty
    assert len(test_db.query("SELECT * FROM allowlist")) == 0


def test_create_retraining_dataset(test_db: Database, tmp_path: Path):
    store = AnalystFeedbackStore(test_db)

    # Record 2 TPs and 1 FP
    store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="analyst_1",
        feedback_type=FeedbackType.TRUE_POSITIVE,
        comment="True malware execution",
        features_snapshot={"exec_entropy": 7.8, "cmd_len": 450, "port": 4444},
    )
    store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="analyst_2",
        feedback_type=FeedbackType.TRUE_POSITIVE,
        comment="C2 beaconing detected",
        features_snapshot={"exec_entropy": 6.9, "cmd_len": 320, "port": 8443},
    )
    store.record_feedback(
        finding_id="find-201",
        event_id="ev-101",
        analyst="analyst_3",
        feedback_type=FeedbackType.FALSE_POSITIVE,
        comment="Standard dev server",
        features_snapshot={"exec_entropy": 5.1, "cmd_len": 40, "port": 8080},
    )

    dataset_path = tmp_path / "retraining_v1.json"
    dataset = store.create_retraining_dataset(output_path=dataset_path)

    assert dataset.sample_count == 3
    assert dataset.positive_count == 2
    assert dataset.negative_count == 1
    assert "exec_entropy" in dataset.feature_names
    assert len(dataset.sha256_digest) == 64
    assert dataset_path.exists()

    loaded = json.loads(dataset_path.read_text(encoding="utf-8"))
    assert loaded["sample_count"] == 3
    assert len(loaded["samples"]) == 3
    labels = [s["label"] for s in loaded["samples"]]
    assert labels.count(1) == 2
    assert labels.count(0) == 1
