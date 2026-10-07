from __future__ import annotations

import threading

import pytest

from centralium.agent.models import ActionResult, ActionStatus, Finding, FindingSource, ResponseAction
from centralium.agent.storage import GENESIS_HASH, LATEST_VERSION, Database, DatabaseError, Repository

EXPECTED_TABLES = {
    "events",
    "processes",
    "files",
    "network_connections",
    "dns_events",
    "findings",
    "incidents",
    "ioc_cache",
    "yara_results",
    "ml_results",
    "ai_analysis",
    "response_actions",
    "policies",
    "allowlist",
    "blocklist",
    "audit_log",
    "sync_queue",
    "rag_metadata",
}


def test_wal_mode_and_schema(db: Database):
    assert db.journal_mode() == "wal"
    assert db.schema_version() == LATEST_VERSION
    names = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names >= EXPECTED_TABLES
    assert db.integrity_check()


def test_migrate_idempotent_and_rejects_newer(tmp_path):
    p = tmp_path / "m.db"
    d = Database(p)
    assert d.migrate() == LATEST_VERSION
    d.execute(f"PRAGMA user_version = {LATEST_VERSION + 5}")
    d.close()
    with pytest.raises(DatabaseError):
        Database(p)


def test_generic_insert_validates_identifiers(db: Database):
    with pytest.raises(DatabaseError):
        db.insert("events; DROP TABLE events", {"event_id": "x"})
    with pytest.raises(DatabaseError):
        db.insert("events", {"event_id": "x", "evil) VALUES (1); --": 1})
    with pytest.raises(DatabaseError):
        db.count("sqlite_master")


def test_values_are_parameterized(db: Database, make_event):
    repo = Repository(db)
    nasty = "x'); DROP TABLE events; --"
    ev = make_event(command_line=nasty)
    repo.add_event(ev)
    assert db.count("events") == 1
    assert repo.get_event(ev.event_id).command_line == nasty
    repo.add_allowlist("path", nasty, "weird")
    assert repo.is_allowlisted("path", nasty)


def test_repository_roundtrip(db: Database, make_event):
    repo = Repository(db)
    ev = make_event(hash_sha256="b" * 64)
    repo.add_event(ev)
    f = Finding(
        event_id=ev.event_id,
        source=FindingSource.HASH,
        rule_id="H1",
        title="bad",
        score=100,
        known_malicious=True,
    )
    repo.add_finding(f)
    assert repo.findings_for_event(ev.event_id)[0]["known_malicious"] == 1
    repo.add_action(ActionResult(action=ResponseAction.ALERT, status=ActionStatus.EXECUTED))
    assert repo.list_actions()[0]["action"] == "ALERT"
    repo.add_blocklist("sha256", "B" * 64)
    assert repo.is_blocklisted("sha256", "b" * 64)
    assert not repo.is_allowlisted("sha256", "b" * 64)
    with pytest.raises(ValueError):
        repo.add_allowlist("bogus", "x")
    repo.upsert_ioc("sha256", "C" * 64, "test", threat_type="mal")
    repo.upsert_ioc("sha256", "c" * 64, "test", threat_type="mal2")
    hits = repo.lookup_ioc("sha256", "c" * 64)
    assert len(hits) == 1 and hits[0]["threat_type"] == "mal2"
    assert repo.enqueue_sync({"a": 1}, "k1") and not repo.enqueue_sync({"a": 1}, "k1")
    assert repo.pending_sync_count() == 1


def test_expired_list_entry_ignored(db: Database):
    repo = Repository(db)
    repo.add_allowlist("process", "old.exe", expires_at="2000-01-01T00:00:00+00:00")
    assert not repo.is_allowlisted("process", "old.exe")


def test_transaction_rollback(db: Database):
    with pytest.raises(RuntimeError), db.transaction() as c:
        c.execute("INSERT INTO allowlist (kind,value,added_at) VALUES ('path','/a','t')")
        raise RuntimeError("boom")
    assert db.count("allowlist") == 0


# ------------------------------------------------------------------ audit chain
def _fill(db: Database, n: int = 5) -> None:
    for i in range(n):
        db.audit.append("tester", "evt", {"i": i})


def test_audit_chain_valid_and_genesis(db: Database):
    assert db.audit.verify().ok
    assert db.audit.head() == (0, GENESIS_HASH)
    _fill(db)
    res = db.audit.verify()
    assert res.ok and res.entries == 5
    assert db.audit.entries()[-1]["prev_hash"] == GENESIS_HASH


def test_audit_detects_modification(db: Database):
    _fill(db)
    db.execute("UPDATE audit_log SET details = '{\"i\":99}' WHERE seq = 3")
    res = db.audit.verify()
    assert not res.ok and res.first_bad_seq == 3


def test_audit_detects_actor_change(db: Database):
    _fill(db)
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    assert db.audit.verify().first_bad_seq == 2


def test_audit_detects_deletion(db: Database):
    _fill(db)
    db.execute("DELETE FROM audit_log WHERE seq = 2")
    res = db.audit.verify()
    assert not res.ok and res.first_bad_seq == 2


def test_audit_detects_recomputed_row_via_chain(db: Database):
    """Editing a row AND fixing its own hash still breaks the next row's prev_hash."""
    from centralium.agent.storage.audit import compute_entry_hash

    _fill(db)
    r = db.query_one("SELECT * FROM audit_log WHERE seq = 2")
    new_details = '{"i":42}'
    h = compute_entry_hash(r["prev_hash"], 2, r["timestamp"], r["actor"], r["event_type"], new_details)
    db.execute("UPDATE audit_log SET details=?, entry_hash=? WHERE seq=2", (new_details, h))
    res = db.audit.verify()
    assert not res.ok and res.first_bad_seq == 3


def test_audit_tail_truncation_detected_with_anchor(db: Database):
    _fill(db)
    anchor = db.audit.head()[1]
    db.execute("DELETE FROM audit_log WHERE seq = 5")
    assert db.audit.verify().ok  # undetectable without an external anchor
    assert not db.audit.verify(expected_head=anchor).ok


def test_audit_concurrent_appends_keep_chain(tmp_path):
    d = Database(tmp_path / "c.db")

    def work(k: int) -> None:
        for i in range(25):
            d.audit.append(f"t{k}", "evt", {"i": i})

    ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    res = d.audit.verify()
    assert res.ok and res.entries == 200
    d.close()
