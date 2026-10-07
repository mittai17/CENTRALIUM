"""Deterministic path/process rules for the EPP hot path (pure functions, no I/O)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from centralium.agent.models import EventType, Severity

EXEC_EVENTS = frozenset({EventType.PROCESS_START, EventType.MODULE_LOAD})
DROP_EVENTS = frozenset({EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_RENAME})
_EXEC_EXT = (
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".jar",
    ".sh",
    ".so",
    ".elf",
    ".msi",
)
_DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp3", ".mp4")


def normalize_path(p: str | None) -> str:
    """Canonical comparison form: forward slashes, collapsed ``..``/``.``, Windows paths lower-cased."""
    if not p or "\x00" in p:
        return ""
    raw = p.strip()
    s = raw.replace("\\", "/")
    is_win = bool(re.match(r"^[A-Za-z]:/", s)) or raw.startswith("\\\\")
    s = posixpath.normpath(s)
    if s.startswith("//") and not is_win:
        s = s[1:]
    return s.lower() if is_win else s


def is_windows_path(p: str) -> bool:
    return bool(re.match(r"^[a-z]:/", p)) or p.startswith("//")


@dataclass(frozen=True, slots=True)
class PathRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    score: float
    mitre: tuple[str, ...]
    windows: bool  # True -> applies to normalized (lower-case) windows paths


def _r(
    rid: str, title: str, pat: str, sev: Severity, score: float, mitre: tuple[str, ...], win: bool
) -> PathRule:
    return PathRule(rid, title, re.compile(pat), sev, score, mitre, win)


EXEC_PATH_RULES: tuple[PathRule, ...] = (
    _r(
        "EPP-PATH-LNX-TMP",
        "Execution from /tmp or /var/tmp",
        r"^/(var/)?tmp/",
        Severity.MEDIUM,
        45,
        ("T1059", "T1036"),
        False,
    ),
    _r(
        "EPP-PATH-LNX-SHM",
        "Execution from /dev/shm (memory-backed, non-persistent staging)",
        r"^/dev/shm/",
        Severity.HIGH,
        60,
        ("T1059", "T1620"),
        False,
    ),
    _r(
        "EPP-PATH-LNX-MEMFD",
        "Execution from memfd / deleted file",
        r"^/proc/self/fd/|^/memfd:|\(deleted\)$",
        Severity.HIGH,
        65,
        ("T1620",),
        False,
    ),
    _r(
        "EPP-PATH-WIN-TEMP",
        "Execution from Windows Temp",
        r"^[a-z]:/windows/temp/",
        Severity.MEDIUM,
        50,
        ("T1059", "T1036"),
        True,
    ),
    _r(
        "EPP-PATH-WIN-APPDATA-TEMP",
        "Execution from user Temp",
        r"^[a-z]:/users/[^/]+/appdata/local/temp/",
        Severity.MEDIUM,
        50,
        ("T1204.002",),
        True,
    ),
    _r(
        "EPP-PATH-WIN-APPDATA",
        "Execution from user AppData",
        r"^[a-z]:/users/[^/]+/appdata/(roaming|local)/(?!temp/|programs/|microsoft/|google/)",
        Severity.LOW,
        35,
        ("T1204.002",),
        True,
    ),
    _r(
        "EPP-PATH-WIN-PUBLIC",
        "Execution from Users\\Public",
        r"^[a-z]:/users/public/",
        Severity.MEDIUM,
        50,
        ("T1036",),
        True,
    ),
    _r(
        "EPP-PATH-WIN-RECYCLE",
        "Execution from Recycle Bin",
        r"^[a-z]:/\$recycle\.bin/",
        Severity.HIGH,
        60,
        ("T1036",),
        True,
    ),
)

DROP_PATH_RULES: tuple[PathRule, ...] = (
    _r(
        "EPP-DROP-LNX-SHM",
        "Executable content written to /dev/shm",
        r"^/dev/shm/",
        Severity.MEDIUM,
        40,
        ("T1105", "T1620"),
        False,
    ),
    _r(
        "EPP-DROP-WIN-TEMP",
        "Executable content written to Temp",
        r"^[a-z]:/(windows/temp/|users/[^/]+/appdata/local/temp/)",
        Severity.LOW,
        30,
        ("T1105",),
        True,
    ),
    _r(
        "EPP-DROP-WIN-PUBLIC",
        "Executable content written to Users\\Public",
        r"^[a-z]:/users/public/",
        Severity.MEDIUM,
        40,
        ("T1105",),
        True,
    ),
)

# Core Windows processes that must live in System32 (masquerading detection).
WIN_SYSTEM_BINARIES = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "explorer.exe",
        "taskhostw.exe",
        "spoolsv.exe",
        "conhost.exe",
        "dllhost.exe",
        "rundll32.exe",
        "cmd.exe",
    }
)
WIN_SYSTEM_DIRS = ("c:/windows/system32/", "c:/windows/syswow64/", "c:/windows/", "c:/windows/winsxs/")


def path_rule_hits(path: str, event_type: EventType) -> list[PathRule]:
    n = normalize_path(path)
    if not n:
        return []
    rules = (
        EXEC_PATH_RULES if event_type in EXEC_EVENTS else DROP_PATH_RULES if event_type in DROP_EVENTS else ()
    )
    if rules is DROP_PATH_RULES and not n.endswith(_EXEC_EXT):
        return []
    win = is_windows_path(n)
    return [r for r in rules if r.windows == win and r.pattern.search(n)]


def masquerade_reason(process_name: str | None, exe_path: str | None) -> str | None:
    """Return a reason when a well-known Windows system binary runs from the wrong directory,
    or a document double-extension executable (``invoice.pdf.exe``)."""
    n = normalize_path(exe_path)
    if not n:
        return None
    base = n.rsplit("/", 1)[-1]
    if is_windows_path(n):
        if (
            base in WIN_SYSTEM_BINARIES
            and not n.startswith(WIN_SYSTEM_DIRS)
            and not (base == "explorer.exe" and n.startswith("c:/windows/"))
        ):
            return f"system binary name {base} outside system directory"
        parts = base.rsplit(".", 2)
        if len(parts) == 3 and f".{parts[1]}" in _DOC_EXT and base.endswith(_EXEC_EXT[:5]):
            return f"document double extension {base}"
    return None
