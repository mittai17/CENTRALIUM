"""File-integrity manifests (SHA-256) for agent code, rules and configuration.

A manifest is a JSON document ``{"version":1,"created":..,"root":..,"files":{relpath:sha256}}``.
It can be signed (Ed25519, see ``updates.py``) so a local attacker who can rewrite the manifest is
detected; an unsigned manifest only protects against accidental/partial tampering and is reported as such.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_PATTERNS = ("*.py", "*.yar", "*.yara", "*.toml", "*.json", "*.so", "*.service")
_SKIP_DIRS = {"__pycache__", ".git", ".venv", "node_modules", ".mypy_cache", ".pytest_cache"}


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def build_manifest(root: Path, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> dict[str, str]:
    """Hash all matching files under ``root`` -> {posix relpath: sha256}. Symlinks are not followed."""
    files: dict[str, str] = {}
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not any(p.match(pat) for pat in patterns):
                continue
            files[p.relative_to(root).as_posix()] = sha256_file(p)
    return files


def manifest_document(root: Path, files: dict[str, str], version: str = "") -> dict[str, object]:
    return {
        "format": 1,
        "created": datetime.now(UTC).isoformat(),
        "root": str(root),
        "version": version,
        "files": files,
    }


def canonical_bytes(doc: dict[str, object]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class IntegrityReport:
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    checked: int = 0

    @property
    def ok(self) -> bool:
        return not (self.modified or self.missing or self.unexpected)


def verify_manifest(
    root: Path, expected: dict[str, str], patterns: tuple[str, ...] = DEFAULT_PATTERNS
) -> IntegrityReport:
    rep = IntegrityReport()
    root = root.resolve()
    for rel, digest in expected.items():
        p = root / rel
        rep.checked += 1
        if not p.is_file():
            rep.missing.append(rel)
        else:
            try:
                if sha256_file(p) != digest:
                    rep.modified.append(rel)
            except OSError:
                rep.missing.append(rel)
    current = build_manifest(root, patterns)
    rep.unexpected = sorted(set(current) - set(expected))
    return rep


# ------------------------------------------------------------------ directory permissions
def check_dir_permissions(path: Path) -> list[str]:
    """Return human-readable problems for a protected directory (POSIX). Empty = fine/unsupported."""
    problems: list[str] = []
    if os.name != "posix":
        return problems  # Windows ACL audit is documented as not implemented
    try:
        st = path.lstat()
    except FileNotFoundError:
        return [f"{path}: missing"]
    except OSError as exc:
        return [f"{path}: cannot stat ({type(exc).__name__})"]
    if stat.S_ISLNK(st.st_mode):
        problems.append(f"{path}: is a symlink")
        return problems
    mode = stat.S_IMODE(st.st_mode)
    if mode & stat.S_IWOTH:
        problems.append(f"{path}: world-writable (mode {mode:04o})")
    elif mode & stat.S_IWGRP and not mode & stat.S_ISVTX:
        problems.append(f"{path}: group-writable (mode {mode:04o})")
    if st.st_uid != os.geteuid() and os.geteuid() != 0 and st.st_uid != 0:
        problems.append(f"{path}: owned by uid {st.st_uid}, not the agent user or root")
    return problems
