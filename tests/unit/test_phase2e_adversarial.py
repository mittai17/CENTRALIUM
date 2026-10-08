"""Unit tests for Phase 2E: Adversarial robustness, baseline poisoning resistance,
and parser fuzzing (Sysmon XML, auditd, PE/ELF, and sync payloads).
"""

from __future__ import annotations

import os
import random
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

from centralium.agent.interfaces import BehaviorResult
from centralium.agent.ml.sequence_model import MarkovSequenceModel
from centralium.agent.ml.static_classifier import (
    StaticMalwareClassifier,
    extract_elf_features,
    extract_pe_features,
)
from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.auditd import normalize_auditd, parse_record
from centralium.agent.normalization.windows import (
    normalize_sysmon,
    parse_event_xml,
    split_event_xml,
)
from centralium.agent.novelty import BaselineNoveltyFilter
from centralium.agent.sync.queue import DurableSyncQueue, canonical_hash

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def make_event(i: int = 0, **kw) -> NormalizedEvent:
    kw.setdefault("event_type", EventType.PROCESS_START)
    kw.setdefault("process_name", "cmd.exe")
    return NormalizedEvent(
        event_id=f"ev-{i}",
        timestamp=T0 + timedelta(seconds=i),
        source="test",
        **kw,
    )


# =========================================================================
# 1. Evasion test suite for ML (feature perturbation within bounds)
# =========================================================================


def test_static_classifier_adversarial_feature_perturbations():
    """Verify that feature extraction and classification remain bounded under perturbations."""
    classifier = StaticMalwareClassifier()

    # Minimal valid ELF binary header
    elf_base = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)  # 64-bit LE
    elf_base.extend(struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64, 0, 0))
    # Program header: PT_LOAD, flags PF_X | PF_R (5)
    elf_base.extend(struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 100, 100, 0x1000))

    base_features = extract_elf_features(bytes(elf_base))
    assert base_features["is_elf"] is True

    # Adversarial perturbations:
    # 1. Random non-functional padding appended
    padded = bytes(elf_base) + os.urandom(1024)
    res_padded = classifier.predict(padded)
    assert 0.0 <= res_padded.malware_score <= 100.0
    assert not np.isnan(res_padded.malware_score)

    # 2. Perturbed section and segment offsets
    for delta in [-10, 5, 50, 1000]:
        corrupted_hdr = bytearray(elf_base)
        # Shift e_phoff
        struct.pack_into("<Q", corrupted_hdr, 32, max(0, 64 + delta))
        res_corrupt = classifier.predict(bytes(corrupted_hdr))
        assert 0.0 <= res_corrupt.malware_score <= 100.0

    # 3. Shannon entropy perturbation: alternating high-entropy blocks
    mixed = bytes(elf_base) + b"\x00" * 500 + os.urandom(500)
    res_mixed = classifier.predict(mixed)
    assert 0.0 <= res_mixed.malware_score <= 100.0


def test_markov_sequence_model_evasion_perturbations():
    """Verify that inserting benign NOOP operations between malicious steps does not crash model."""
    model = MarkovSequenceModel(order=1)
    normal_seq = ["bash", "ls", "grep", "cat", "bash", "ls"]
    model.fit([normal_seq])

    # Attacker tries evasion by inserting dummy actions
    evasion_seq = ["bash", "sleep", "whoami", "sleep", "curl", "sleep", "chmod"]
    res = model.score_sequence(evasion_seq)
    assert 0.0 <= res.anomaly_score <= 1.0
    assert not np.isnan(res.anomaly_score)


# =========================================================================
# 2. Poisoning resistance test (write-gated baselines)
# =========================================================================


def test_novelty_filter_poisoning_resistance_outside_learning_mode(tmp_path: Path):
    """Verify that write-gated baselines reject poisoned events in PASSIVE / ACTIVE mode.

    CRITICAL SECURITY INVARIANT:
    `assess()` is read-only. An attacker cannot poison baselines by repeatedly
    executing malicious actions in production modes. Only `learn()` (called during
    LEARNING mode) can write to the baseline store.
    """
    db_file = tmp_path / "baseline.db"
    novelty = BaselineNoveltyFilter(path=db_file)
    behavior = BehaviorResult()

    # 1. Attacker attempts to flood system with 100 malicious LOLBin commands in non-LEARNING mode
    attacker_event = make_event(
        process_name="certutil.exe",
        user="SYSTEM",
        parent_process="cmd.exe",
        domain="c2-malicious-domain.xyz",
        executable_path="C:\\Windows\\System32\\certutil.exe",
    )

    for i in range(100):
        ev = make_event(
            i=i,
            process_name="certutil.exe",
            user="SYSTEM",
            parent_process="cmd.exe",
            domain="c2-malicious-domain.xyz",
            executable_path="C:\\Windows\\System32\\certutil.exe",
        )
        res = novelty.assess(ev, behavior)
        # Every assessment must report high novelty (unlearned)
        assert res.is_novel is True

    # Verify: baseline store was NEVER modified by assess()
    novelty.flush()
    # Check baseline hits on event 101
    final_assess = novelty.assess(attacker_event, behavior)
    assert final_assess.is_novel is True
    assert final_assess.baseline_hits == 0

    # 2. Conversely, in LEARNING mode (calling learn()), the baseline is properly taught
    benign_ev = make_event(
        process_name="legit_backup.exe",
        user="backup_admin",
        parent_process="taskhostw.exe",
        domain="backup-vault.internal",
        executable_path="/usr/bin/legit_backup",
    )
    for i in range(5):
        novelty.learn(benign_ev)

    novelty.flush()
    learned_assess = novelty.assess(benign_ev, behavior)
    assert learned_assess.is_novel is False
    assert learned_assess.novelty_score < 0.20
    assert learned_assess.baseline_hits >= 3

    novelty.close()


# =========================================================================
# 3. Parser fuzzing tests (Sysmon XML, auditd, PE/ELF, sync payloads)
# =========================================================================


def test_sysmon_xml_parser_fuzzing():
    """Fuzz Sysmon XML parser with crafted, corrupted, and adversarial XML payloads."""
    fuzz_cases = [
        # XXE / entity expansion attempts (must be rejected safely)
        """<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event>&xxe;</Event>""",
        """<!DOCTYPE test [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><Event>&lol2;</Event>""",
        # Malformed XML
        "<Event><System><EventID>1</EventID></Event>",  # Unclosed tags
        "<Event><<<>>></Event>",
        "<Event>" + "A" * 10000,
        "<Event><System><EventID>-999999</EventID></System></Event>",
        "<Event><System><EventID>NotAnInteger</EventID></System></Event>",
        '<Event><EventData><Data Name="CommandLine">' + "\x00" * 50 + "</Data></EventData></Event>",
        # Deeply nested tags
        "<div>" * 200 + "<Event></Event>" + "</div>" * 200,
        # Huge XML payload (exceeding MAX_XML)
        "<Event>" + ("x" * 1_000_001) + "</Event>",
    ]

    for xml_text in fuzz_cases:
        try:
            rec = parse_event_xml(xml_text)
            # If parse succeeded, ensure normalize_sysmon doesn't crash
            norm = normalize_sysmon(rec)
            assert isinstance(norm, NormalizedEvent)
        except (ValueError, Exception) as exc:
            # Expected rejection for malformed / XXE / oversized XML
            assert "xml" in str(exc).lower() or "doctype" in str(exc).lower() or "large" in str(exc).lower()

    # Fuzz split_event_xml with arbitrary bytes/strings
    assert split_event_xml("random non-xml text") == []
    assert len(split_event_xml("<Event>1</Event><Event>2</Event>")) == 2


def test_auditd_parser_fuzzing():
    """Fuzz Linux auditd parser with corrupted lines and edge cases."""
    auditd_fuzz_lines = [
        "",  # Empty
        "   ",
        "not_an_audit_line at all",
        "type=SYSCALL",  # Missing msg=
        "type=SYSCALL msg=audit():",  # Malformed msg
        "type=SYSCALL msg=audit(1670000000.123:abc):",  # Non-integer serial
        "type=EXECVE msg=audit(1670000000.123:456): a0=123 a1=4567 a2=GIBBERISH_HEX",
        "type=EXECVE msg=audit(1670000000.123:456): a0=000000 a1=FFFF",  # Null bytes in hex
        "type=SYSCALL msg=audit(1670000000.123:456): " + "key=" + ("B" * 70000),  # Oversized line
        "type=UNKNOWN_CUSTOM_TYPE msg=audit(1670000000.123:456): k=v",
        "\x1d" * 50,  # Group separators
        "type=SYSCALL msg=audit(1670000000.123:456): arch=c000003e syscall=99999 success=no exit=-13",  # Unknown syscall
    ]

    for line in auditd_fuzz_lines:
        parsed = parse_record(line)
        # Must return None or valid dict without crashing
        if parsed is not None:
            assert "type" in parsed
            assert "serial" in parsed

    # Fuzz normalize_auditd with groups of random records
    sample_group = [
        'type=SYSCALL msg=audit(1670000000.123:456): arch=c000003e syscall=59 success=yes pid=1234 comm="test"',
        'type=EXECVE msg=audit(1670000000.123:456): argc=2 a0="/bin/test" a1="--arg"',
    ]
    norm = normalize_auditd(sample_group)
    assert len(norm) > 0
    assert isinstance(norm[0], NormalizedEvent)
    assert norm[0].pid == 1234


def test_pe_and_elf_header_parser_fuzzing():
    """Fuzz standalone PE and ELF header parsers with truncated and random bytes."""
    # 1. Truncated inputs
    assert extract_elf_features(b"")["is_elf"] is False
    assert extract_elf_features(b"\x7fELF")["is_elf"] is False  # Too short (< 52 bytes)
    assert extract_pe_features(b"")["is_pe"] is False
    assert extract_pe_features(b"MZ")["is_pe"] is False  # Too short (< 64 bytes)

    # 2. Random bytes fuzzing (50 pseudo-random blobs)
    rng = random.Random(42)
    for _ in range(50):
        size = rng.randint(1, 2048)
        blob = rng.randbytes(size)
        elf_res = extract_elf_features(blob)
        pe_res = extract_pe_features(blob)
        assert isinstance(elf_res, dict)
        assert isinstance(pe_res, dict)

    # 3. Crafted ELF with corrupt header fields
    corrupt_elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
    # Put absurd offsets
    struct.pack_into("<Q", corrupt_elf, 32, 0xFFFFFFFFFFFF)  # e_phoff pointing to outer space
    struct.pack_into("<H", corrupt_elf, 56, 0xFFFF)  # e_phnum huge
    parsed_corrupt_elf = extract_elf_features(bytes(corrupt_elf))
    assert parsed_corrupt_elf["is_elf"] is True
    assert parsed_corrupt_elf["has_wx_segment"] is False

    # 4. Crafted PE with corrupt e_lfanew
    corrupt_pe = bytearray(b"MZ" + b"\x00" * 62)
    struct.pack_into("<I", corrupt_pe, 60, 0xFFFFFF)  # e_lfanew out of bounds
    parsed_corrupt_pe = extract_pe_features(bytes(corrupt_pe))
    assert parsed_corrupt_pe["is_pe"] is False


def test_sync_queue_payload_fuzzing(tmp_path: Path):
    """Fuzz DurableSyncQueue and canonical_hash with corrupt and edge-case payloads."""
    q_path = tmp_path / "sync_fuzz.db"
    queue = DurableSyncQueue(path=q_path)

    # 1. Valid payload enqueue
    valid_payload = {"event_id": "ev-1", "action": "test", "status": "ok"}
    h = canonical_hash(valid_payload)
    assert h.startswith("sha256:")

    assert queue.enqueue(valid_payload) is True

    # 2. SQL injection strings in payload fields
    sql_payload = {
        "event_id": "ev-sql'; DROP TABLE sync_queue; --",
        "action": "UNION SELECT 1, 2, 3",
        "data": "' OR '1'='1",
    }
    assert queue.enqueue(sql_payload) is True

    # Verify table is intact
    claimed = queue.claim_batch(limit=10)
    assert len(claimed) == 2

    # 3. Payloads with Unicode, null bytes, and deep nesting
    nested = {"a": {"b": {"c": {"d": "\x00\x01\uffff"}}}}
    assert queue.enqueue(nested) is True

    queue.close()
