"""Feed parsers/normalizers for MalwareBazaar, ThreatFox, URLhaus and Feodo Tracker.

Pure functions: bytes/str in, validated :class:`IOCRecord` list out. No network, no DB. Malformed
rows are counted and skipped (never raise for a bad row); a structurally unusable document raises
:class:`FeedParseError`. Values are strictly validated so a poisoned feed cannot inject
loopback/unspecified IPs, bogus domains or oversized strings that would cause false-positive storms.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

IOC_TYPES = frozenset({"sha256", "ip", "domain", "url"})
MAX_FIELD_LEN = 2048
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class FeedParseError(ValueError):
    """The document as a whole is not a usable feed."""


@dataclass(frozen=True, slots=True)
class IOCRecord:
    ioc_type: str
    value: str
    source: str
    threat_type: str = ""
    confidence: float = 1.0
    first_seen: str | None = None
    last_seen: str | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParseResult:
    records: list[IOCRecord] = field(default_factory=list)
    rejected: int = 0
    source: str = ""


# --------------------------------------------------------------------------- validators
def normalize_sha256(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    return s if _SHA256.match(s) else None


def normalize_ip(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    try:
        ip = ipaddress.ip_address(v.strip().strip("[]"))
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return None
    return str(ip)


def normalize_domain(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip().lower().rstrip(".")
    if not s or len(s) > 253 or "." not in s:
        return None
    if not all(_LABEL.match(lbl) for lbl in s.split(".")):
        return None
    try:
        ipaddress.ip_address(s)
        return None  # an IP literal is not a domain
    except ValueError:
        return s


def normalize_url(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s or len(s) > MAX_FIELD_LEN or any(ord(c) < 0x20 for c in s):
        return None
    try:
        p = urlsplit(s)
        host = p.hostname
        _ = p.port  # validates port range
    except ValueError:
        return None
    if p.scheme.lower() not in {"http", "https", "ftp"} or not host:
        return None
    if normalize_domain(host) is None and normalize_ip(host) is None:
        return None
    netloc = host if ":" not in host else f"[{host}]"
    if p.port:
        netloc += f":{p.port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def parse_timestamp(v: object) -> str | None:
    """Best-effort UTC ISO-8601 from feed timestamps; None when unparsable."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(float(v), UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip().removesuffix("UTC").strip()
    if not s or s.lower() in {"n/a", "none", "null"}:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def _clip(v: object, n: int = 200) -> str:
    return str(v or "").strip()[:n]


def _decode(data: bytes | str) -> str:
    return data if isinstance(data, str) else data.decode("utf-8", errors="replace")


def _csv_rows(text: str, default_cols: list[str], header_hint: str) -> list[dict[str, str]]:
    """abuse.ch CSV exports carry the header as a ``# ...`` comment line."""
    cols = default_cols
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            cand = line.lstrip("# ").strip()
            if header_hint in cand:
                cols = [c.strip().strip('"') for c in next(csv.reader([cand], skipinitialspace=True))]
            continue
        if line.strip():
            body.append(line)
    out: list[dict[str, str]] = []
    for row in csv.reader(body, skipinitialspace=True):
        if row and row[0] == cols[0] and header_hint in ",".join(row):
            continue  # inline header
        out.append(dict(zip(cols, row, strict=False)))
    return out


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"invalid JSON: {exc}") from exc


# --------------------------------------------------------------------------- parsers
def parse_malwarebazaar(data: bytes | str, *, source: str = "malwarebazaar") -> ParseResult:
    """MalwareBazaar CSV export (``recent.csv``) or API JSON (``{"query_status","data":[...]}``)."""
    text = _decode(data).lstrip("﻿")
    res = ParseResult(source=source)
    rows: list[dict[str, Any]]
    if text.lstrip().startswith(("{", "[")):
        doc = _load_json(text)
        if isinstance(doc, dict):
            if doc.get("query_status") not in (None, "ok"):
                raise FeedParseError(f"query_status={doc.get('query_status')!r}")
            doc = doc.get("data", [])
        if not isinstance(doc, list):
            raise FeedParseError("unexpected MalwareBazaar JSON shape")
        rows = [r for r in doc if isinstance(r, dict)]
        res.rejected += len(doc) - len(rows)
        first_key = "first_seen"
    else:
        rows = list(
            _csv_rows(
                text,
                [
                    "first_seen_utc",
                    "sha256_hash",
                    "md5_hash",
                    "sha1_hash",
                    "reporter",
                    "file_name",
                    "file_type_guess",
                    "mime_type",
                    "signature",
                ],
                "sha256_hash",
            )
        )
        first_key = "first_seen_utc"
    for r in rows:
        h = normalize_sha256(r.get("sha256_hash"))
        if h is None:
            res.rejected += 1
            continue
        sig = _clip(r.get("signature"))
        ts = parse_timestamp(r.get(first_key))
        res.records.append(
            IOCRecord(
                "sha256",
                h,
                source,
                threat_type=sig if sig.lower() not in {"", "n/a", "none"} else "malware",
                confidence=0.9,
                first_seen=ts,
                last_seen=ts,
                metadata={
                    "file_name": _clip(r.get("file_name")),
                    "file_type": _clip(r.get("file_type_guess") or r.get("file_type"), 40),
                },
            )
        )
    return res


def parse_threatfox(data: bytes | str, *, source: str = "threatfox") -> ParseResult:
    """ThreatFox JSON (API/export): ip:port, domain, url, sha256_hash IOCs."""
    doc = _load_json(_decode(data).lstrip("﻿"))
    if isinstance(doc, dict):
        if doc.get("query_status") not in (None, "ok"):
            raise FeedParseError(f"query_status={doc.get('query_status')!r}")
        doc = doc.get("data", [])
    if isinstance(doc, dict):  # export format: {"<id>": [ {...} ]}
        doc = [e for v in doc.values() if isinstance(v, list) for e in v]
    if not isinstance(doc, list):
        raise FeedParseError("unexpected ThreatFox JSON shape")
    res = ParseResult(source=source)
    for r in doc:
        if not isinstance(r, dict):
            res.rejected += 1
            continue
        raw_type = str(r.get("ioc_type", "")).lower()
        raw = r.get("ioc")
        ioc_type: str | None
        value: str | None
        port = None
        if raw_type == "ip:port" and isinstance(raw, str) and ":" in raw:
            host, _, port = raw.rpartition(":")
            ioc_type, value = "ip", normalize_ip(host)
        elif raw_type == "ip":
            ioc_type, value = "ip", normalize_ip(raw)
        elif raw_type == "domain":
            ioc_type, value = "domain", normalize_domain(raw)
        elif raw_type == "url":
            ioc_type, value = "url", normalize_url(raw)
        elif raw_type in {"sha256_hash", "sha256"}:
            ioc_type, value = "sha256", normalize_sha256(raw)
        else:
            res.rejected += 1  # md5/sha1 etc. unsupported by the SHA-256 centric cache
            continue
        if value is None or ioc_type is None:
            res.rejected += 1
            continue
        try:
            conf = max(0.0, min(1.0, float(r.get("confidence_level", 75)) / 100.0))
        except (TypeError, ValueError):
            conf = 0.5
        res.records.append(
            IOCRecord(
                ioc_type,
                value,
                source,
                threat_type=_clip(r.get("malware_printable") or r.get("malware") or r.get("threat_type")),
                confidence=conf,
                first_seen=parse_timestamp(r.get("first_seen") or r.get("first_seen_utc")),
                last_seen=parse_timestamp(r.get("last_seen") or r.get("last_seen_utc")),
                metadata={"threatfox_id": _clip(r.get("id"), 32), "port": _clip(port, 6) if port else ""},
            )
        )
    return res


def parse_urlhaus(data: bytes | str, *, source: str = "urlhaus") -> ParseResult:
    """URLhaus CSV (``csv_recent``): produces ``url`` IOCs."""
    text = _decode(data).lstrip("﻿")
    res = ParseResult(source=source)
    rows = _csv_rows(
        text,
        ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
        "url_status",
    )
    for r in rows:
        u = normalize_url(r.get("url"))
        if u is None:
            res.rejected += 1
            continue
        online = _clip(r.get("url_status")).lower() == "online"
        res.records.append(
            IOCRecord(
                "url",
                u,
                source,
                threat_type=_clip(r.get("threat")) or "malware_download",
                confidence=0.9 if online else 0.6,
                first_seen=parse_timestamp(r.get("dateadded")),
                last_seen=parse_timestamp(r.get("last_online") or r.get("dateadded")),
                metadata={"url_status": _clip(r.get("url_status"), 20), "tags": _clip(r.get("tags"))},
            )
        )
    return res


def parse_feodo(data: bytes | str, *, source: str = "feodotracker") -> ParseResult:
    """Feodo Tracker botnet C2 blocklist: JSON array or plain-text (one IP per line)."""
    text = _decode(data).lstrip("﻿")
    res = ParseResult(source=source)
    if text.lstrip().startswith(("[", "{")):
        doc = _load_json(text)
        if isinstance(doc, dict):
            doc = doc.get("blocklist") or doc.get("data") or []
        if not isinstance(doc, list):
            raise FeedParseError("unexpected Feodo JSON shape")
        for r in doc:
            ip = normalize_ip(r.get("ip_address") or r.get("dst_ip")) if isinstance(r, dict) else None
            if ip is None:
                res.rejected += 1
                continue
            assert isinstance(r, dict)
            res.records.append(
                IOCRecord(
                    "ip",
                    ip,
                    source,
                    threat_type=_clip(r.get("malware")) or "botnet_c2",
                    confidence=0.95 if str(r.get("status", "")).lower() != "offline" else 0.7,
                    first_seen=parse_timestamp(r.get("first_seen")),
                    last_seen=parse_timestamp(r.get("last_online") or r.get("first_seen")),
                    metadata={"port": _clip(r.get("port"), 6), "status": _clip(r.get("status"), 20)},
                )
            )
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = normalize_ip(line.split()[0].split(",")[0])
            if ip is None:
                res.rejected += 1
                continue
            res.records.append(IOCRecord("ip", ip, source, threat_type="botnet_c2", confidence=0.9))
    return res


def parse_centralium_json(data: bytes | str, *, source: str = "centralium") -> ParseResult:
    """Local IOC set: ``{"source": str, "iocs": [{"type","value","threat_type","confidence"}]}``."""
    doc = _load_json(_decode(data))
    if not isinstance(doc, dict) or not isinstance(doc.get("iocs"), list):
        raise FeedParseError("expected object with 'iocs' list")
    src = _clip(doc.get("source"), 64) or source
    res = ParseResult(source=src)
    norm = {"sha256": normalize_sha256, "ip": normalize_ip, "domain": normalize_domain, "url": normalize_url}
    for r in doc["iocs"]:
        t = str(r.get("type", "")) if isinstance(r, dict) else ""
        fn = norm.get(t)
        v = fn(r.get("value")) if fn else None
        if v is None:
            res.rejected += 1
            continue
        try:
            conf = max(0.0, min(1.0, float(r.get("confidence", 1.0))))
        except (TypeError, ValueError):
            conf = 1.0
        res.records.append(
            IOCRecord(
                t,
                v,
                src,
                threat_type=_clip(r.get("threat_type")),
                confidence=conf,
                first_seen=parse_timestamp(r.get("first_seen")),
                metadata={"note": _clip(r.get("note"))},
            )
        )
    return res


PARSERS = {
    "malwarebazaar": parse_malwarebazaar,
    "threatfox": parse_threatfox,
    "urlhaus": parse_urlhaus,
    "feodo": parse_feodo,
    "centralium": parse_centralium_json,
}


def parse_feed(fmt: str, data: bytes | str, *, source: str | None = None) -> ParseResult:
    try:
        fn = PARSERS[fmt]
    except KeyError:
        raise FeedParseError(f"unknown feed format {fmt!r}") from None
    return fn(data, source=source) if source else fn(data)
