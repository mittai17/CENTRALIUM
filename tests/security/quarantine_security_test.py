from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from centralium.agent.quarantine import FileQuarantineManager, QuarantineError

pytestmark = pytest.mark.security


@pytest.fixture
def qm(tmp_path):
    return FileQuarantineManager(
        tmp_path / "q", authorized_users={"admin"}, protected_paths=[str(tmp_path / "protected")]
    )


def test_symlink_to_sensitive_file_is_refused_not_followed(qm, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("do not touch")
    link = tmp_path / "innocent.txt"
    link.symlink_to(secret)
    with pytest.raises(QuarantineError, match="symlink"):
        qm.quarantine(link, ["x"], ["x"])
    assert secret.read_text() == "do not touch" and link.is_symlink()


def test_symlinked_parent_resolves_into_protected_path(qm, tmp_path):
    prot = tmp_path / "protected"
    prot.mkdir()
    (prot / "vital.conf").write_text("v")
    (tmp_path / "shortcut").symlink_to(prot)
    with pytest.raises(QuarantineError, match="protected"):
        qm.quarantine(tmp_path / "shortcut" / "vital.conf", [], [])
    assert (prot / "vital.conf").exists()


def test_cannot_quarantine_inside_quarantine_dir(qm, tmp_path):
    f = tmp_path / "w.bin"
    f.write_bytes(b"x")
    rec = qm.quarantine(f, [], [])
    with pytest.raises(QuarantineError, match="inside"):
        qm.quarantine(Path(rec.quarantine_path), [], [])
    with pytest.raises(QuarantineError, match="inside"):
        qm.quarantine(qm.root / ".." / "q" / Path(rec.quarantine_path).name, [], [])


@pytest.mark.parametrize(
    "bad_id",
    [
        "../../etc/passwd",
        "..",
        "a" * 31,
        "g" * 32,
        "A" * 32,
        "0" * 32 + "/../x",
        "",
        "0" * 32 + "\x00",
        "0" * 32 + "\n",
    ],
)
def test_quarantine_id_traversal_rejected(qm, bad_id):
    with pytest.raises(QuarantineError):
        qm.restore(bad_id, authorized_by="admin", reason="x")
    with pytest.raises(QuarantineError):
        qm.get(bad_id)


def test_nul_byte_path_rejected(qm):
    with pytest.raises(QuarantineError):
        qm.quarantine(Path("/tmp/a\x00b"), [], [])


def test_restore_refuses_when_original_dir_became_symlink(qm, tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    f = d / "m.bin"
    f.write_bytes(b"mal")
    rec = qm.quarantine(f, [], [])
    d.rmdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    d.symlink_to(target)
    with pytest.raises(QuarantineError, match="symlink"):
        qm.restore(rec.quarantine_id, authorized_by="admin", reason="x")
    assert not any(target.iterdir())


def test_tampered_metadata_original_path_cannot_redirect_restore_into_protected(qm, tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"mal")
    rec = qm.quarantine(f, [], [])
    prot = tmp_path / "protected"
    prot.mkdir()
    meta = Path(rec.quarantine_path).with_suffix(".json")
    data = json.loads(meta.read_text())
    data["original_path"] = str(prot / "evil")
    meta.write_text(json.dumps(data))
    with pytest.raises(QuarantineError, match="protected"):
        qm.restore(rec.quarantine_id, authorized_by="admin", reason="x")
    assert not (prot / "evil").exists()


def test_replaced_file_is_not_deleted_race(qm, tmp_path, monkeypatch):
    f = tmp_path / "r.bin"
    f.write_bytes(b"orig")
    real_replace = os.replace

    def swap(src, dst):
        real_replace(src, dst)
        f.unlink()
        f.write_bytes(b"attacker replacement")  # path now names a different inode

    monkeypatch.setattr(os, "replace", swap)
    with pytest.raises(QuarantineError, match="replaced"):
        qm.quarantine(f, [], [])
    assert f.read_bytes() == b"attacker replacement"
    assert list(qm.root.iterdir()) == []


def test_quarantine_dir_other_owner_perms_not_accessible(qm, tmp_path):
    f = tmp_path / "p.bin"
    f.write_bytes(b"x")
    rec = qm.quarantine(f, [], [])
    assert os.stat(qm.root).st_mode & 0o077 == 0
    assert os.stat(rec.quarantine_path).st_mode & 0o177 == 0
