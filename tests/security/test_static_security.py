from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from centralium.agent.malware_analysis import StaticFileAnalyzer
from tests.unit.static_builders import build_elf, build_pe

pytestmark = pytest.mark.security


def test_huge_file_not_parsed(tmp_path: Path) -> None:
    a = StaticFileAnalyzer(max_parse_bytes=4096)
    p = tmp_path / "big.exe"
    p.write_bytes(b"MZ" + b"\x00" * 10_000)
    r = a.analyze(p)
    assert r.indicators == ["file_too_large"] and r.score == 0


def test_nul_in_path() -> None:
    assert StaticFileAnalyzer().analyze(Path("/tmp/a\x00b")).indicators[0].startswith("cannot_open")


def test_pe_header_fuzz_never_raises(tmp_path: Path) -> None:
    good = bytearray(build_pe(imports={"kernel32.dll": ["A", "B"]}))
    rng_positions = list(range(0, 0x200, 7)) + [len(good) - 3]  # noqa: RUF005
    for i, pos in enumerate(rng_positions):
        d = bytearray(good)
        d[pos] ^= 0xFF
        d[(pos + 1) % len(d)] = 0xFF
        p = tmp_path / f"f{i}.exe"
        p.write_bytes(bytes(d))
        r = StaticFileAnalyzer().analyze(p)
        assert 0 <= r.score <= 100


def test_elf_header_fuzz_never_raises(tmp_path: Path) -> None:
    good = bytearray(build_elf(undefined_symbols=("ptrace", "x")))
    for i, pos in enumerate(list(range(0, 0x120, 5)) + [len(good) - 70, len(good) - 5]):  # noqa: RUF005
        d = bytearray(good)
        d[pos] ^= 0xFF
        p = tmp_path / f"f{i}.elf"
        p.write_bytes(bytes(d))
        assert 0 <= StaticFileAnalyzer().analyze(p).score <= 100


def test_absurd_section_count_and_giant_sizes(tmp_path: Path) -> None:
    d = bytearray(build_pe())
    pe_off = struct.unpack_from("<I", d, 0x3C)[0]
    struct.pack_into("<H", d, pe_off + 6, 0xFFFF)  # NumberOfSections
    p = tmp_path / "s.exe"
    p.write_bytes(bytes(d))
    assert 0 <= StaticFileAnalyzer().analyze(p).score <= 100


def test_symlink_loop_and_device(tmp_path: Path) -> None:
    a = StaticFileAnalyzer()
    loop = tmp_path / "loop"
    os.symlink(loop, loop)
    assert a.analyze(loop).score == 0
    assert a.analyze(Path("/dev/zero")).indicators == ["not_a_regular_file"]
