"""Unit tests for the static malware classifier and PE/ELF feature extractor."""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np

from centralium.agent.ml.static_classifier import (
    StaticMalwareClassifier,
    StaticScanResult,
    compute_byte_histogram,
    extract_elf_features,
    extract_feature_vector,
    extract_pe_features,
)


def _build_mock_pe(
    sections: list[tuple[str, int, int, int]] | None = None,
    suspicious_api: str | None = None,
) -> bytes:
    """Build a synthetic PE header for testing."""
    # DOS Header: 'MZ' at 0x00, e_lfanew at 0x3C pointing to 0x80
    e_lfanew = 0x80
    dos_header = bytearray(e_lfanew)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes)
    # Machine=0x8664, NumberOfSections, TimeDateStamp=0, PtrToSymTable=0, NumOfSym=0, SizeOfOpt=240, Char=0x02
    num_sections = len(sections) if sections else 1
    coff = struct.pack("<HHIIIHH", 0x8664, num_sections, 0, 0, 0, 240, 0x0002)

    # Optional Header (240 bytes)
    # Magic=0x20b (PE32+)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)

    # Section Headers (40 bytes each)
    sec_headers = bytearray()
    sec_data_list = bytearray()

    if sections is None:
        sections = [(".text", 0x1000, 0x1000, 0x60000020)]  # R-X code

    current_raw_ptr = e_lfanew + 4 + 20 + 240 + len(sections) * 40

    for name, vsize, rsize, chars in sections:
        raw_name = name.encode("latin1").ljust(8, b"\x00")[:8]
        hdr = struct.pack(
            "<8sIIIIIIII",
            raw_name,
            vsize,
            0x1000,  # virtual address
            rsize,
            current_raw_ptr,
            0,
            0,
            0,
            chars,
        )
        sec_headers.extend(hdr)
        sec_bytes = b"\x90" * rsize  # NOP sled
        sec_data_list.extend(sec_bytes)
        current_raw_ptr += rsize

    pe_bytes = bytes(dos_header + pe_sig + coff + opt + sec_headers + sec_data_list)
    if suspicious_api:
        pe_bytes += b"\x00" + suspicious_api.encode("latin1") + b"\x00"

    return pe_bytes


def _build_mock_elf(has_wx: bool = False, suspicious_sym: str | None = None) -> bytes:
    """Build a synthetic 64-bit ELF binary."""
    # EI_MAG: \x7fELF, EI_CLASS: 2 (64-bit), EI_DATA: 1 (LE)
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    # ELF64 Header: ident(16), e_type(2), e_machine(2), e_version(4), e_entry(8),
    # e_phoff(8), e_shoff(8), e_flags(4), e_ehsize(2), e_phentsize(2), e_phnum(2),
    # e_shentsize(2), e_shnum(2), e_shstrndx(2)
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 2
    hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        0x400000,
        e_phoff,
        0,  # e_shoff
        0,
        64,
        e_phentsize,
        e_phnum,
        64,
        0,
        0,
    )

    # Program headers (2 segments)
    # Segment 1: PT_LOAD, flags: PF_R | PF_X = 5
    # Segment 2: PT_LOAD, flags: PF_R | PF_W | PF_X = 7 (if has_wx) else PF_R | PF_W = 6
    p_flags2 = 7 if has_wx else 6
    ph1 = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000)
    ph2 = struct.pack("<IIQQQQQQ", 1, p_flags2, 0x1000, 0x600000, 0x600000, 0x1000, 0x1000, 0x1000)

    elf_bytes = hdr + ph1 + ph2 + (b"\x90" * 512)
    if suspicious_sym:
        elf_bytes += b"\x00" + suspicious_sym.encode("latin1") + b"\x00"

    return elf_bytes


def test_byte_histogram_and_entropy():
    # Test all zeros
    zeros = b"\x00" * 100
    hist, entropy, stats = compute_byte_histogram(zeros)
    assert hist.shape == (256,)
    assert hist[0] == 1.0
    assert entropy == 0.0
    assert stats["zero_ratio"] == 1.0

    # Test uniform random distribution (high entropy)
    rng = np.random.default_rng(42)
    random_bytes = rng.integers(0, 256, size=5000, dtype=np.uint8).tobytes()
    _, entropy_rand, stats_rand = compute_byte_histogram(random_bytes)
    assert 7.8 < entropy_rand <= 8.0
    assert stats_rand["zero_ratio"] < 0.05


def test_pe_feature_extraction():
    # Build standard PE
    pe = _build_mock_pe(
        sections=[(".text", 0x200, 0x200, 0x60000020), (".data", 0x100, 0x100, 0xC0000040)],
        suspicious_api="VirtualAlloc",
    )
    res = extract_pe_features(pe)
    assert res["is_pe"] is True
    assert res["num_sections"] == 2
    assert res["has_wx_section"] is False
    assert "virtualalloc" in res["suspicious_apis"]

    # Build PE with W+X section (characteristics with 0x80000000 | 0x20000000 = 0xA0000020)
    pe_wx = _build_mock_pe(
        sections=[("UPX0", 0x5000, 0x200, 0xE0000020)],  # W+X and UPX packed section
        suspicious_api="WriteProcessMemory",
    )
    res_wx = extract_pe_features(pe_wx)
    assert res_wx["has_wx_section"] is True
    assert res_wx["packed_indicator"] is True
    assert "writeprocessmemory" in res_wx["suspicious_apis"]


def test_elf_feature_extraction():
    # Normal ELF
    elf = _build_mock_elf(has_wx=False, suspicious_sym="printf")
    res = extract_elf_features(elf)
    assert res["is_elf"] is True
    assert res["num_segments"] == 2
    assert res["has_wx_segment"] is False

    # ELF with W+X segment and ptrace symbol
    elf_wx = _build_mock_elf(has_wx=True, suspicious_sym="ptrace")
    res_wx = extract_elf_features(elf_wx)
    assert res_wx["is_elf"] is True
    assert res_wx["has_wx_segment"] is True
    assert "ptrace" in res_wx["suspicious_symbols"]


def test_feature_vector_extraction():
    pe = _build_mock_pe()
    vec, summary = extract_feature_vector(pe)
    assert vec.shape == (272,)
    assert summary["is_pe"] is True
    assert summary["is_elf"] is False

    non_pe = b"plain text shell script #!/bin/sh\necho hello\n"
    vec_txt, summary_txt = extract_feature_vector(non_pe)
    assert vec_txt.shape == (272,)
    assert summary_txt["is_pe"] is False
    assert summary_txt["is_elf"] is False


def test_static_malware_classifier_prediction(tmp_path: Path):
    clf = StaticMalwareClassifier(seed=42)

    # Benign-style binary (plain text or standard binary)
    benign_data = b"Hello world! This is a benign standard configuration text file." * 50
    benign_result = clf.predict(benign_data)
    assert isinstance(benign_result, StaticScanResult)
    assert benign_result.malware_score < 50.0
    assert not benign_result.is_malicious

    # Malicious-style payload: packed PE with W+X and dangerous injection APIs
    malware_pe = _build_mock_pe(
        sections=[
            ("UPX0", 0x8000, 0x200, 0xE0000020),
            (".text", 0x2000, 0x2000, 0x60000020),
        ],
        suspicious_api="CreateRemoteThread VirtualAlloc WriteProcessMemory",
    )
    malware_result = clf.predict(malware_pe)
    assert malware_result.file_type == "PE"
    assert malware_result.malware_score >= 50.0
    assert malware_result.is_malicious
    assert any("executable_and_writable" in ind for ind in malware_result.indicators)

    # Test file path input
    file_path = tmp_path / "sample.exe"
    file_path.write_bytes(malware_pe)
    path_result = clf.predict(file_path)
    assert path_result.is_malicious


def test_classifier_calibration_evaluation():
    clf = StaticMalwareClassifier(seed=123)
    rng = np.random.default_rng(123)
    X_test = rng.uniform(0.0, 1.0, size=(60, 272)).astype(np.float32)
    y_test = rng.integers(0, 2, size=60, dtype=np.int32)

    eval_res = clf.evaluate_calibration(X_test, y_test)
    assert "brier_score" in eval_res
    assert 0.0 <= eval_res["brier_score"] <= 1.0
    assert "bin_predicted" in eval_res
    assert "bin_actual" in eval_res
