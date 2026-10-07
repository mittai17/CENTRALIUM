from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from centralium.agent.interfaces import QuarantineManager
from centralium.agent.quarantine import FileQuarantineManager, QuarantineAuthError, QuarantineError


@pytest.fixture
def audit_log():
    return []


@pytest.fixture
def qm(tmp_path, audit_log):
    return FileQuarantineManager(
        tmp_path / "q",
        audit=lambda actor, et, d: audit_log.append((actor, et, d)),
        authorized_users={"soc-admin"},
        protected_paths=[str(tmp_path / "protected")],
    )


@pytest.fixture
def sample(tmp_path) -> Path:
    d = tmp_path / "work"
    d.mkdir()
    p = d / "evil.sh"
    p.write_bytes(b"#!/bin/sh\necho pwned\n")
    p.chmod(0o755)
    return p


def test_protocol_and_root_mode(qm, tmp_path):
    assert isinstance(qm, QuarantineManager)
    assert stat.S_IMODE(os.stat(tmp_path / "q").st_mode) == 0o700


def test_existing_loose_root_is_tightened(tmp_path):
    root = tmp_path / "q2"
    root.mkdir(mode=0o777)
    root.chmod(0o777)
    FileQuarantineManager(root)
    assert stat.S_IMODE(os.stat(root).st_mode) == 0o700


def test_quarantine_moves_file_strips_exec_and_records_metadata(qm, sample, audit_log):
    data = sample.read_bytes()
    rec = qm.quarantine(sample, ["yara:Mirai"], ["yara", "hash"])
    assert not sample.exists()  # moved out of its (executable) location
    blob = Path(rec.quarantine_path)
    assert blob.read_bytes() == data
    assert stat.S_IMODE(blob.stat().st_mode) == 0o400  # no exec bits, read-only
    assert not blob.stat().st_mode & 0o111
    assert rec.sha256 == hashlib.sha256(data).hexdigest()
    assert rec.reasons == ["yara:Mirai"] and rec.sources == ["yara", "hash"]
    assert rec.original_path == str(sample.resolve())
    assert rec.metadata["mode"] == "0o755" and rec.metadata["size"] == len(data)
    meta = json.loads((blob.parent / f"{rec.quarantine_id}.json").read_text())
    assert meta["sha256"] == rec.sha256
    assert qm.list() == [rec]
    assert qm.verify(rec.quarantine_id)
    assert audit_log[-1][1] == "quarantine_file"
    with pytest.raises(PermissionError):  # cannot be executed / even opened for write
        os.execv(str(blob), [str(blob)])


def test_restore_requires_authorization(qm, sample, audit_log):
    rec = qm.quarantine(sample, ["r"], ["s"])
    with pytest.raises(QuarantineAuthError):
        qm.restore(rec.quarantine_id, authorized_by="mallory", reason="please")
    with pytest.raises(QuarantineAuthError):
        qm.restore(rec.quarantine_id, authorized_by="soc-admin", reason="  ")
    assert not sample.exists()
    assert any(e[1] == "quarantine_restore_denied" for e in audit_log)


def test_restore_denied_by_default_without_any_authorizer(tmp_path, sample):
    q = FileQuarantineManager(tmp_path / "q")
    rec = q.quarantine(sample, [], [])
    with pytest.raises(QuarantineAuthError):
        q.restore(rec.quarantine_id, authorized_by="anyone", reason="x")


def test_authorized_restore_roundtrip_keeps_evidence(qm, sample, audit_log):
    data = sample.read_bytes()
    rec = qm.quarantine(sample, ["r"], ["s"])
    out = qm.restore(rec.quarantine_id, authorized_by="soc-admin", reason="false positive FP-123")
    assert out == sample and sample.read_bytes() == data
    assert stat.S_IMODE(sample.stat().st_mode) == 0o755
    assert Path(rec.quarantine_path).exists()  # evidence retained by default
    again = qm.get(rec.quarantine_id)
    assert again.restored and again.metadata["restored_by"] == "soc-admin"
    assert audit_log[-1][1] == "quarantine_restore"
    with pytest.raises(QuarantineError):
        qm.restore(rec.quarantine_id, authorized_by="soc-admin", reason="again")


def test_custom_authorizer_callback(tmp_path, sample):
    seen = []
    q = FileQuarantineManager(
        tmp_path / "q", restore_authorizer=lambda a, r, rec: seen.append(a) or a == "ok"
    )
    rec = q.quarantine(sample, [], [])
    with pytest.raises(QuarantineAuthError):
        q.restore(rec.quarantine_id, authorized_by="bad", reason="x")
    q.restore(rec.quarantine_id, authorized_by="ok", reason="x")
    assert seen == ["bad", "ok"]


def test_restore_detects_tampered_blob(qm, sample):
    rec = qm.quarantine(sample, [], [])
    blob = Path(rec.quarantine_path)
    blob.chmod(0o600)
    blob.write_bytes(b"tampered")
    assert not qm.verify(rec.quarantine_id)
    with pytest.raises(QuarantineError, match="integrity"):
        qm.restore(rec.quarantine_id, authorized_by="soc-admin", reason="x")
    assert not sample.exists()


def test_restore_refuses_overwrite(qm, sample):
    rec = qm.quarantine(sample, [], [])
    sample.write_text("new legit file")
    with pytest.raises(QuarantineError, match="exists"):
        qm.restore(rec.quarantine_id, authorized_by="soc-admin", reason="x")
    assert sample.read_text() == "new legit file"


def test_evidence_destruction_disabled_by_default(qm, sample):
    rec = qm.quarantine(sample, [], [])
    with pytest.raises(QuarantineAuthError):
        qm.purge(rec.quarantine_id, authorized_by="soc-admin", reason="cleanup")
    assert Path(rec.quarantine_path).exists()


def test_purge_only_when_explicitly_enabled(tmp_path, sample):
    q = FileQuarantineManager(tmp_path / "q", authorized_users={"a"}, allow_purge=True)
    rec = q.quarantine(sample, [], [])
    q.purge(rec.quarantine_id, authorized_by="a", reason="legal hold ended")
    assert q.list() == []


def test_missing_and_directory_targets(qm, tmp_path):
    with pytest.raises(FileNotFoundError):
        qm.quarantine(tmp_path / "nope", [], [])
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(QuarantineError):
        qm.quarantine(d, [], [])


def test_size_limit(tmp_path, sample):
    q = FileQuarantineManager(tmp_path / "q", max_file_bytes=5)
    with pytest.raises(QuarantineError, match="size"):
        q.quarantine(sample, [], [])
    assert sample.exists() and list((tmp_path / "q").iterdir()) == []  # nothing half-written


def test_list_skips_corrupt_metadata(qm, sample):
    rec = qm.quarantine(sample, [], [])
    (Path(rec.quarantine_path).parent / ("f" * 32 + ".json")).write_text("{not json")
    assert [r.quarantine_id for r in qm.list()] == [rec.quarantine_id]
