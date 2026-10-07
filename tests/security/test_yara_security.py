from __future__ import annotations

import os
from pathlib import Path

import pytest

from centralium.agent.yara import YaraManager, yara_available

pytestmark = [pytest.mark.security, pytest.mark.skipif(not yara_available(), reason="yara-python missing")]


def test_include_directive_rejected(tmp_path: Path) -> None:
    (tmp_path / "secret.yar").write_text("rule S { condition: true }")
    m = YaraManager()
    ok, msg = m.validate_rules(f'include "{tmp_path}/secret.yar"\nrule X {{ condition: true }}')
    assert not ok and "include" in msg


@pytest.mark.parametrize("mod", ["cuckoo", "magic", "console", "../../etc/passwd"])
def test_disallowed_imports_rejected(mod: str) -> None:
    ok, _ = YaraManager().validate_rules(f'import "{mod}"\nrule X {{ condition: true }}')
    assert not ok


def test_oversized_and_nul_rules_rejected() -> None:
    m = YaraManager()
    assert not m.validate_rules("// " + "A" * 1_100_000 + "\nrule X { condition: true }")[0]
    assert not m.validate_rules("rule X { condition: true }\x00")[0]
    assert not m.validate_rules("")[0]


def test_bad_bundle_id_rejected() -> None:
    m = YaraManager()
    assert not m.update_bundle("../evil", "rule X { condition: true }").ok
    assert not m.update_bundle("", "rule X { condition: true }").ok


def test_huge_file_skipped(make_event, tmp_path: Path) -> None:
    m = YaraManager(max_scan_bytes=1024)
    m.update_bundle("t", 'rule T { strings: $a = "AAAA" condition: $a }')
    p = tmp_path / "big"
    p.write_bytes(b"AAAA" * 1000)
    assert m.scan_file(p, make_event()) == []
    assert m.scan_bytes(b"AAAA" * 1000, make_event()) == []
    small = tmp_path / "small"
    small.write_bytes(b"AAAA")
    assert m.scan_file(small, make_event())


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="posix only")
def test_fifo_does_not_hang(make_event, tmp_path: Path) -> None:
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    m = YaraManager()
    m.update_bundle("t", "rule T { condition: true }")
    assert m.scan_file(fifo, make_event()) == []


def test_nul_path_and_garbage_input(make_event) -> None:
    m = YaraManager()
    m.update_bundle("t", "rule T { condition: true }")
    assert m.scan_file(Path("/tmp/a\x00b"), make_event()) == []
    assert m.scan_bytes("not bytes", make_event()) == []  # type: ignore[arg-type]


def test_pathological_regex_rule_times_out_safely(make_event) -> None:
    m = YaraManager(timeout_s=1)
    m.update_bundle("t", "rule T { strings: $a = /(a|aa)+b/ condition: $a }")
    m.scan_bytes(b"a" * 5000, make_event())  # must return (possibly empty), never hang or raise
