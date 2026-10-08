"""STIX 2.1 JSON file loader importing Indicators and Observable Objects into CachedIOCStore.

Supports STIX 2.1 Bundle specifications:
- Indicator objects with pattern matching (ipv4-addr, domain-name, file SHA-256, url)
- Cyber-observable Objects (SCOs): ipv4-addr, domain-name, file (hashes), url
- Validates records strictly against feed hygiene (rejecting private/loopback IPs, malformed hashes)
- Persists into CachedIOCStore via add_records
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from centralium.agent.threat_intel.feeds import (
    FeedParseError,
    IOCRecord,
    ParseResult,
    normalize_domain,
    normalize_ip,
    normalize_sha256,
    normalize_url,
)
from centralium.agent.threat_intel.store import CachedIOCStore

log = logging.getLogger("centralium.threat_intel.stix")

# Patterns matching STIX 2.1 indicator expressions
_PAT_SHA256 = re.compile(
    r"file:hashes\.(?:'|\")?(?:SHA-?256|sha-?256)(?:'|\")?\s*=\s*['\"]([a-fA-F0-9]{64})['\"]",
    re.IGNORECASE,
)
_PAT_IPV4 = re.compile(r"ipv4-addr:value\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_PAT_DOMAIN = re.compile(r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_PAT_URL = re.compile(r"url:value\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


def parse_stix_bundle(
    data: dict[str, Any] | str | bytes,
    source_name: str = "stix_2.1",
) -> ParseResult:
    """Parse STIX 2.1 JSON bundle (dict, str or bytes) into validated IOCRecords."""
    if isinstance(data, (str, bytes)):
        try:
            doc = json.loads(data)
        except Exception as exc:
            raise FeedParseError(f"Invalid STIX JSON document: {exc}") from exc
    elif isinstance(data, dict):
        doc = data
    else:
        raise FeedParseError(f"Unsupported data type for STIX bundle: {type(data)}")

    if not isinstance(doc, dict):
        raise FeedParseError("STIX document must be a JSON object")

    objects: list[dict[str, Any]]
    if doc.get("type") == "bundle" and isinstance(doc.get("objects"), list):
        objects = [o for o in doc["objects"] if isinstance(o, dict)]
    elif "type" in doc and isinstance(doc.get("type"), str):
        # Single STIX object passed directly
        objects = [doc]
    else:
        raise FeedParseError("Missing 'type' or 'objects' in STIX document")

    records: list[IOCRecord] = []
    rejected = 0

    for obj in objects:
        obj_type = obj.get("type")
        if not obj_type:
            continue

        if obj_type == "indicator":
            rec_list, rej = _parse_indicator(obj, source_name)
            records.extend(rec_list)
            rejected += rej
        elif obj_type == "ipv4-addr":
            rec, ok = _parse_sco_ip(obj, source_name)
            if ok and rec:
                records.append(rec)
            else:
                rejected += 1
        elif obj_type == "domain-name":
            rec, ok = _parse_sco_domain(obj, source_name)
            if ok and rec:
                records.append(rec)
            else:
                rejected += 1
        elif obj_type == "file":
            recs, rej = _parse_sco_file(obj, source_name)
            records.extend(recs)
            rejected += rej
        elif obj_type == "url":
            rec, ok = _parse_sco_url(obj, source_name)
            if ok and rec:
                records.append(rec)
            else:
                rejected += 1

    return ParseResult(records=records, rejected=rejected, source=source_name)


def _calc_confidence(obj: dict[str, Any]) -> float:
    conf = obj.get("confidence")
    if conf is None:
        return 1.0
    try:
        val = float(conf)
        if val > 1.0:
            return max(0.0, min(1.0, val / 100.0))
        return max(0.0, min(1.0, val))
    except (ValueError, TypeError):
        return 1.0


def _parse_indicator(obj: dict[str, Any], source: str) -> tuple[list[IOCRecord], int]:
    pattern = obj.get("pattern", "")
    if not isinstance(pattern, str) or not pattern.strip():
        return [], 1

    confidence = _calc_confidence(obj)
    types_list = obj.get("indicator_types") or []
    threat_type = ", ".join(str(t) for t in types_list) if isinstance(types_list, list) else "indicator"
    first_seen = obj.get("valid_from") or obj.get("created")
    last_seen = obj.get("modified") or first_seen
    expires_at = obj.get("valid_until")

    meta: dict[str, Any] = {
        "stix_id": obj.get("id"),
        "name": obj.get("name"),
        "description": obj.get("description"),
    }

    records: list[IOCRecord] = []
    rejected = 0

    # Extract SHA-256
    for m in _PAT_SHA256.finditer(pattern):
        h = normalize_sha256(m.group(1))
        if h:
            records.append(
                IOCRecord(
                    ioc_type="sha256",
                    value=h,
                    source=source,
                    threat_type=threat_type,
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    expires_at=expires_at,
                    metadata=meta,
                )
            )
        else:
            rejected += 1

    # Extract IPv4
    for m in _PAT_IPV4.finditer(pattern):
        ip = normalize_ip(m.group(1))
        if ip:
            records.append(
                IOCRecord(
                    ioc_type="ip",
                    value=ip,
                    source=source,
                    threat_type=threat_type,
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    expires_at=expires_at,
                    metadata=meta,
                )
            )
        else:
            rejected += 1

    # Extract Domain
    for m in _PAT_DOMAIN.finditer(pattern):
        d = normalize_domain(m.group(1))
        if d:
            records.append(
                IOCRecord(
                    ioc_type="domain",
                    value=d,
                    source=source,
                    threat_type=threat_type,
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    expires_at=expires_at,
                    metadata=meta,
                )
            )
        else:
            rejected += 1

    # Extract URL
    for m in _PAT_URL.finditer(pattern):
        u = normalize_url(m.group(1))
        if u:
            records.append(
                IOCRecord(
                    ioc_type="url",
                    value=u,
                    source=source,
                    threat_type=threat_type,
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    expires_at=expires_at,
                    metadata=meta,
                )
            )
        else:
            rejected += 1

    return records, rejected


def _parse_sco_ip(obj: dict[str, Any], source: str) -> tuple[IOCRecord | None, bool]:
    raw_val = obj.get("value")
    ip = normalize_ip(raw_val)
    if not ip:
        return None, False
    return (
        IOCRecord(
            ioc_type="ip",
            value=ip,
            source=source,
            threat_type="observable",
            confidence=1.0,
            metadata={"stix_id": obj.get("id")},
        ),
        True,
    )


def _parse_sco_domain(obj: dict[str, Any], source: str) -> tuple[IOCRecord | None, bool]:
    raw_val = obj.get("value")
    dom = normalize_domain(raw_val)
    if not dom:
        return None, False
    return (
        IOCRecord(
            ioc_type="domain",
            value=dom,
            source=source,
            threat_type="observable",
            confidence=1.0,
            metadata={"stix_id": obj.get("id")},
        ),
        True,
    )


def _parse_sco_url(obj: dict[str, Any], source: str) -> tuple[IOCRecord | None, bool]:
    raw_val = obj.get("value")
    u = normalize_url(raw_val)
    if not u:
        return None, False
    return (
        IOCRecord(
            ioc_type="url",
            value=u,
            source=source,
            threat_type="observable",
            confidence=1.0,
            metadata={"stix_id": obj.get("id")},
        ),
        True,
    )


def _parse_sco_file(obj: dict[str, Any], source: str) -> tuple[list[IOCRecord], int]:
    hashes = obj.get("hashes", {})
    if not isinstance(hashes, dict):
        return [], 1

    records: list[IOCRecord] = []
    rejected = 0

    # Look for SHA-256
    for k, v in hashes.items():
        if k.upper() in ("SHA-256", "SHA256"):
            h = normalize_sha256(v)
            if h:
                records.append(
                    IOCRecord(
                        ioc_type="sha256",
                        value=h,
                        source=source,
                        threat_type="observable",
                        confidence=1.0,
                        metadata={"stix_id": obj.get("id"), "name": obj.get("name")},
                    )
                )
            else:
                rejected += 1

    return records, rejected


def load_stix_file(
    file_path: Path | str,
    store: CachedIOCStore,
    source_name: str | None = None,
) -> int:
    """Load a STIX 2.1 JSON bundle from a file and import into CachedIOCStore."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"STIX file not found: {file_path}")

    content = p.read_text(encoding="utf-8")
    src = source_name or f"stix:{p.name}"
    parse_result = parse_stix_bundle(content, source_name=src)

    if not parse_result.records:
        log.info("No valid records found in STIX file: %s (rejected=%d)", file_path, parse_result.rejected)
        return 0

    count = store.add_records(parse_result.records)
    log.info(
        "Imported %d records from STIX bundle %s into IOC store (rejected=%d)",
        count,
        file_path,
        parse_result.rejected,
    )
    return count
