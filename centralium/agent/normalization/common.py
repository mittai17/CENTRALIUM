"""Shared canonicalization/validation helpers for all normalizers.

Every helper is total: it returns ``None`` (or a safe default) on unusable input
instead of raising, so format-specific normalizers can stay simple.
"""

from __future__ import annotations

import ipaddress
import math
import posixpath
import re
from datetime import UTC, datetime
from typing import Any

from centralium.agent.models import NormalizedEvent

MAX_PATH = 4096
MAX_CMD = 16384
MAX_STR = 2048
MAX_META_KEYS = 64
MAX_META_STR = 2048

_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA256_IN_HASHES = re.compile(r"SHA256=([0-9a-fA-F]{64})", re.IGNORECASE)


def clean_str(value: Any, limit: int = MAX_STR) -> str | None:
    """Return a stripped str without control chars (NUL etc.), truncated to ``limit``."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    s = str(value)
    s = "".join(ch for ch in s if ch >= " " or ch in "\t")
    s = s.strip()
    if not s or s.lower() in {"(null)", "null", "none", "-"}:
        return None
    return s[:limit]


def is_windows_path(p: str) -> bool:
    return bool(_WIN_DRIVE.match(p)) or p.startswith("\\\\") or ("\\" in p and "/" not in p)


def canon_path(value: Any) -> str | None:
    """Lexically canonicalize a path (never touches the filesystem, never follows links).

    POSIX absolute paths are normalized (``a/../b`` collapsed). Windows paths keep case and
    separators; surrounding quotes are stripped. Returns None for empty/NUL-bearing paths.
    """
    if value is None:
        return None
    raw = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    if "\x00" in raw:
        return None
    s = clean_str(raw, MAX_PATH)
    if s is None:
        return None
    s = s.strip("\"'")
    if not s:
        return None
    if is_windows_path(s):
        return s
    if s.startswith("/"):
        return posixpath.normpath(s) if not s.startswith("//") else "/" + posixpath.normpath(s).lstrip("/")
    return s


def basename_any(path: str | None) -> str | None:
    if not path:
        return None
    base = re.split(r"[\\/]", path.rstrip("\\/"))[-1]
    return base or None


def ext_of(path: str | None) -> str:
    """Lower-case extension including dot ('' if none)."""
    base = basename_any(path)
    if not base or "." not in base.lstrip("."):
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()


def canon_ip(value: Any) -> str | None:
    s = clean_str(value, 64)
    if s is None:
        return None
    s = s.strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def canon_port(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def canon_sha256(value: Any) -> str | None:
    s = clean_str(value, 200)
    if s is None:
        return None
    m = _SHA256_IN_HASHES.search(s)
    if m:
        return m.group(1).lower()
    return s.lower() if _HEX64.match(s) else None


def canon_domain(value: Any) -> str | None:
    s = clean_str(value, 255)
    if s is None:
        return None
    s = s.rstrip(".").lower()
    if not re.match(r"^[a-z0-9_*]([a-z0-9_\-.*]*[a-z0-9_*])?$", s):
        return None
    return s


def to_int(value: Any, base: int = 10) -> int | None:
    """Parse ints, including '0x1a4' hex strings; None on failure/negative."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, int):
            n = value
        elif isinstance(value, float):
            n = int(value)
        else:
            s = str(value).strip()
            n = int(s, 16) if s.lower().startswith("0x") else int(s, base)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")


def parse_ts(value: Any) -> datetime | None:
    """Epoch seconds/ms, ISO-8601 (incl. 'Z' and 7-digit fractions), Sysmon 'UtcTime'."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, (int, float)):
            v = float(value)
            if v > 1e14:  # microseconds
                v /= 1e6
            elif v > 1e11:  # milliseconds
                v /= 1e3
            return datetime.fromtimestamp(v, UTC)
        s = str(value).strip()
        if not s:
            return None
        if re.fullmatch(r"\d+(\.\d+)?", s):
            return parse_ts(float(s))
        s2 = re.sub(r"(\.\d{6})\d+", r"\1", s)  # 7-digit Windows fractions
        s2 = s2.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s2)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(s2, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
    except (OverflowError, OSError, ValueError):
        return None
    return None


def safe_meta(data: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    """JSON-safe, size-bounded metadata dict (strings capped, nested values stringified)."""
    out: dict[str, Any] = {}
    items = list((data or {}).items()) + list(extra.items())
    for k, v in items[:MAX_META_KEYS]:
        key = str(k)[:64]
        if v is None or isinstance(v, (bool, int, float)):
            out[key] = v
        elif isinstance(v, (list, tuple)):
            out[key] = [str(x)[:MAX_META_STR] for x in v[:32]]
        else:
            out[key] = str(v)[:MAX_META_STR]
    return out


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits/char (0 for empty)."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def pick(d: dict[str, Any], *names: str) -> Any:
    """First present (case-insensitive) key among ``names``."""
    if not d:
        return None
    lower = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        v = lower.get(n.lower())
        if v is not None and v != "":
            return v
    return None


def make_event(**kw: Any) -> NormalizedEvent:
    """Build a NormalizedEvent, omitting a ``None`` timestamp (-> now) so parse failures never crash."""
    if kw.get("timestamp") is None:
        kw.pop("timestamp", None)
    return NormalizedEvent(**kw)
