"""Synthetic PE / ELF builders for tests (harmless, never executable payloads)."""

from __future__ import annotations

import os
import struct


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_pe(
    sections: list[tuple[str, bytes, int]] | None = None,
    imports: dict[str, list[str]] | None = None,
    *,
    entry_section: int = 0,
    signed: bool = False,
    timestamp: int = 1_600_000_000,
) -> bytes:
    """Minimal PE32 image. ``sections`` = (name, raw_data, characteristics). Imports go in an extra .idata."""
    sections = list(sections or [(".text", b"\x90" * 0x200, 0x60000020)])
    FA, SA = 0x200, 0x1000
    idata = b""
    idata_rva = 0
    if imports:
        idata_rva = SA * (len(sections) + 1)
        n = len(imports)
        desc_size = 20 * (n + 1)
        blob = bytearray(desc_size)
        pos = desc_size
        for i, (dll, funcs) in enumerate(imports.items()):
            name_off = pos
            blob += dll.encode() + b"\x00"
            pos = len(blob)
            names_rva = []
            for f in funcs:
                names_rva.append(idata_rva + len(blob))
                blob += b"\x00\x00" + f.encode() + b"\x00"
                if len(blob) % 2:
                    blob += b"\x00"
            int_off = len(blob)
            for r in names_rva:
                blob += struct.pack("<I", r)
            blob += struct.pack("<I", 0)
            struct.pack_into(
                "<IIIII", blob, 20 * i, idata_rva + int_off, 0, 0, idata_rva + name_off, idata_rva + int_off
            )
        idata = bytes(blob)
        sections.append((".idata", idata, 0xC0000040))
    nsec = len(sections)
    e_lfanew = 0x80
    headers_size = _align(e_lfanew + 4 + 20 + 224 + 40 * nsec, FA)
    raw_off = headers_size
    sec_hdrs = b""
    bodies = b""
    for i, (name, data, ch) in enumerate(sections):
        rsize = _align(len(data), FA) if data else 0
        vsize = max(len(data), 1) if data else 0x2000  # empty raw => big virtual (UPX-like)
        sec_hdrs += struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8],
            vsize,
            SA * (i + 1),
            rsize,
            raw_off if rsize else 0,
            0,
            0,
            0,
            0,
            ch,
        )
        bodies += data.ljust(rsize, b"\x00")
        raw_off += rsize
    size_of_image = SA * (nsec + 1)
    ep = SA * (entry_section + 1)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        0x200,
        0x200,
        0,
        ep,
        SA,
        SA,
        0x400000,
        SA,
        FA,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    dirs = [(0, 0)] * 16
    if imports:
        dirs[1] = (idata_rva, len(idata))
    cert = b""
    if signed:
        cert = struct.pack("<IHH", 24, 0x200, 2) + b"\x00" * 16
        dirs[4] = (headers_size + len(bodies), len(cert))
    opt += b"".join(struct.pack("<II", a, b) for a, b in dirs)
    coff = struct.pack("<HHIIIHH", 0x14C, nsec, timestamp, 0, 0, 224, 0x102)
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", e_lfanew)
    hdr = dos.ljust(e_lfanew, b"\x00") + b"PE\x00\x00" + coff + opt + sec_hdrs
    return hdr.ljust(headers_size, b"\x00") + bodies + cert


def build_elf(
    *,
    undefined_symbols: tuple[str, ...] = (),
    text: bytes = b"\x90" * 256,
    with_sections: bool = True,
    rwx_segment: bool = False,
    extra_head: bytes = b"",
) -> bytes:
    """Minimal ELF64 little-endian x86-64 ET_DYN with optional .dynsym of undefined symbols."""
    ehsize, phentsize, shentsize = 64, 56, 64
    phnum = 1
    phoff = ehsize
    body = bytearray()
    base = ehsize + phentsize * phnum
    body += extra_head
    text_off = base + len(body)
    body += text
    dynstr = (
        b"\x00"
        + b"\x00".join(s.encode() for s in undefined_symbols)
        + (b"\x00" if undefined_symbols else b"")
    )
    dynstr_off = base + len(body)
    body += dynstr
    syms = bytearray(24)
    pos = 1
    for s in undefined_symbols:
        syms += struct.pack("<IBBHQQ", pos, 0x12, 0, 0, 0, 0)
        pos += len(s) + 1
    dynsym_off = base + len(body)
    body += syms
    shstr = b"\x00.text\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    shstr_off = base + len(body)
    body += shstr
    shoff = _align(base + len(body), 8)
    body += b"\x00" * (shoff - base - len(body))

    def sh(
        name: int, typ: int, flags: int, off: int, size: int, link: int = 0, info: int = 0, ent: int = 0
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name, typ, flags, 0, off, size, link, info, 8 if typ != 1 else 16, ent
        )

    shdrs = b""
    shnum = 0
    if with_sections:
        shdrs = (
            b"\x00" * shentsize
            + sh(1, 1, 6, text_off, len(text))
            + sh(7, 3, 2, dynstr_off, len(dynstr))
            + sh(15, 11, 2, dynsym_off, len(syms), link=2, info=1, ent=24)
            + sh(23, 3, 0, shstr_off, len(shstr))
        )
        shnum = 5
    flags = 7 if rwx_segment else 5
    ph = struct.pack("<IIQQQQQQ", 1, flags, 0, 0, 0, base + len(body), base + len(body), 0x1000)
    eh = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + b"\x00" * 8
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            62,
            1,
            text_off,
            phoff,
            shoff if with_sections else 0,
            0,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            4 if with_sections else 0,
        )
    )
    return eh + ph + bytes(body) + shdrs


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
