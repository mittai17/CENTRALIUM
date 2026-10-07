"""Fast deterministic EPP engine implementing ``EPPEngine``.

Order per event (cheap -> costly; everything is local, no network):
1. blocklist (file + DB) and hash/IOC lookups  -> ``known_malicious`` findings (HASH/IOC/RULE)
2. allowlist (only when step 1 produced nothing) -> single ``Finding(source=ALLOWLIST, score=0)``
3. deterministic path/process rules              -> heuristic findings (never known_malicious)
4. optional inline YARA (off by default: the pipeline already calls the YaraScanner)

Security notes: allowlist never overrides known-bad; ``process``-name allowlisting is ignored when
the executable is in a suspicious location; ``signer`` allowlisting needs a verifier hook (a
collector-supplied signer string is attacker-influenced unless verified).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from centralium.agent.epp.hashing import DEFAULT_MAX_HASH_BYTES, HashCache
from centralium.agent.epp.rules import (
    DROP_EVENTS,
    EXEC_EVENTS,
    masquerade_reason,
    normalize_path,
    path_rule_hits,
)
from centralium.agent.interfaces import IOCMatch, ThreatIntelStore, YaraScanner
from centralium.agent.models import (
    AttackStage,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
)
from centralium.agent.storage import Repository
from centralium.agent.threat_intel.feeds import normalize_domain, normalize_ip, normalize_sha256

log = logging.getLogger("centralium.epp")

SignerVerifier = Callable[[NormalizedEvent], bool]
LIST_KINDS = ("sha256", "path", "process", "ip", "domain", "signer", "parent_child")
HASHABLE_EVENTS = EXEC_EVENTS | DROP_EVENTS
_URL_RE = re.compile(r"https?://[^\s'\"<>|^`]{4,512}", re.IGNORECASE)
MAX_URLS_PER_EVENT = 4


class EntryLists:
    """In-memory allow/block entries parsed from ``rules/{allowlist,blocklist}/*.txt``."""

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, str]] = {k: {} for k in LIST_KINDS}

    def add(self, kind: str, value: str, reason: str = "") -> bool:
        if kind not in self.entries or not value:
            return False
        v = value.strip()
        if kind == "sha256":
            h = normalize_sha256(v)
            if h is None:
                return False
            v = h
        elif kind == "path":
            v = normalize_path(v)
        elif kind == "domain":
            d = normalize_domain(v)
            if d is None:
                return False
            v = d
        elif kind == "ip":
            i = normalize_ip(v)
            if i is None:
                return False
            v = i
        elif kind == "process":
            v = v.lower()
        if not v:
            return False
        self.entries[kind][v] = reason
        return True

    def get(self, kind: str, value: str) -> str | None:
        return self.entries[kind].get(value)

    @classmethod
    def from_directory(cls, directory: Path | None) -> EntryLists:
        lists = cls()
        if directory is None or not directory.is_dir():
            return lists
        for f in sorted(directory.glob("*.txt")):
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                log.warning("cannot read list file %s: %s", f.name, exc)
                continue
            for n, line in enumerate(text.splitlines(), 1):
                body, _, reason = line.partition("#")
                body = body.strip()
                if not body:
                    continue
                kind, sep, value = body.partition(":")
                if not sep or not lists.add(kind.strip().lower(), value.strip(), reason.strip()):
                    log.warning("%s:%d: ignoring invalid list entry", f.name, n)
        return lists


class _TTLCache:
    def __init__(self, capacity: int, ttl: float) -> None:
        self._cap, self._ttl = capacity, ttl
        self._d: OrderedDict[Any, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any, loader: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            hit = self._d.get(key)
            if hit and now - hit[0] < self._ttl:
                return hit[1]
        val = loader()
        with self._lock:
            self._d[key] = (now, val)
            self._d.move_to_end(key)
            while len(self._d) > self._cap:
                self._d.popitem(last=False)
        return val

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


class DefaultEPPEngine:
    def __init__(
        self,
        *,
        intel: ThreatIntelStore | None = None,
        repo: Repository | None = None,
        file_allowlist: EntryLists | None = None,
        file_blocklist: EntryLists | None = None,
        yara: YaraScanner | None = None,
        inline_yara: bool = False,
        signer_verifier: SignerVerifier | None = None,
        trust_unverified_signer: bool = False,
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
        list_cache_ttl_s: float = 15.0,
        min_known_confidence: float = 0.75,
        enable_path_rules: bool = True,
    ) -> None:
        self.intel, self.repo = intel, repo
        self.allow = file_allowlist or EntryLists()
        self.block = file_blocklist or EntryLists()
        self.yara, self.inline_yara = yara, inline_yara
        self.signer_verifier, self.trust_unverified_signer = signer_verifier, trust_unverified_signer
        self.min_known_confidence = min_known_confidence
        self.enable_path_rules = enable_path_rules
        self._hashes = HashCache(max_bytes=max_hash_bytes)
        self._dbcache = _TTLCache(8192, list_cache_ttl_s)

    def invalidate_list_cache(self) -> None:
        self._dbcache.clear()

    # ------------------------------------------------------------------ list lookups
    def _blocked(self, kind: str, value: str) -> str | None:
        r = self.block.get(kind, value)
        if r is not None:
            return r or "static blocklist"
        if self.repo is not None:
            hit = self._dbcache.get(("b", kind, value), lambda: self.repo.is_blocklisted(kind, value))  # type: ignore[union-attr]
            if hit:
                return "blocklist"
        return None

    def _allowed(self, kind: str, value: str) -> str | None:
        r = self.allow.get(kind, value)
        if r is not None:
            return r or "static allowlist"
        if self.repo is not None:
            hit = self._dbcache.get(("a", kind, value), lambda: self.repo.is_allowlisted(kind, value))  # type: ignore[union-attr]
            if hit:
                return "allowlist"
        return None

    # ------------------------------------------------------------------ main
    def inspect(self, event: NormalizedEvent) -> list[Finding]:
        exe = (
            event.executable_path
            if event.event_type in EXEC_EVENTS
            else (event.file_path or event.executable_path)
        )
        sha = self._sha(event, exe)
        known = self._known_bad(event, sha, exe)
        if known:
            return known
        allow = self._allow_finding(event, sha, exe)
        if allow is not None:
            return [allow]
        findings: list[Finding] = []
        if self.enable_path_rules:
            findings += self._path_findings(event, exe)
        if self.inline_yara and self.yara is not None and exe and event.event_type in HASHABLE_EVENTS:
            try:
                findings += self.yara.scan_file(Path(exe), event)
            except Exception:
                log.exception("inline yara failed")
        return findings

    def _sha(self, event: NormalizedEvent, exe: str | None) -> str | None:
        if event.hash_sha256:
            return event.hash_sha256
        if exe and event.event_type in HASHABLE_EVENTS and "\x00" not in exe:
            return self._hashes.get(exe)
        return None

    # ------------------------------------------------------------------ known-bad
    def _known_bad(self, ev: NormalizedEvent, sha: str | None, exe: str | None) -> list[Finding]:
        out: list[Finding] = []

        def add(
            source: FindingSource,
            rid: str,
            title: str,
            details: dict[str, Any],
            sev: Severity = Severity.CRITICAL,
            score: float = 100.0,
            conf: float = 1.0,
            mitre: list[str] | None = None,
        ) -> None:
            out.append(
                Finding(
                    event_id=ev.event_id,
                    source=source,
                    rule_id=rid,
                    title=title,
                    severity=sev,
                    score=score,
                    confidence=conf,
                    known_malicious=True,
                    mitre_techniques=mitre or [],
                    details=details,
                )
            )

        if sha and (reason := self._blocked("sha256", sha)):
            add(
                FindingSource.HASH,
                "EPP-HASH-BLOCKLIST",
                f"Blocklisted file hash ({reason})",
                {"sha256": sha, "path": exe},
            )
        if exe:
            n = normalize_path(exe)
            if n and (reason := self._blocked("path", n)):
                add(FindingSource.RULE, "EPP-PATH-BLOCKLIST", f"Blocklisted path ({reason})", {"path": exe})
            if ev.event_type in EXEC_EVENTS and (
                reason := self._blocked("process", n.rsplit("/", 1)[-1].lower())
            ):
                add(
                    FindingSource.RULE,
                    "EPP-PROC-BLOCKLIST",
                    f"Blocklisted process name ({reason})",
                    {"path": exe},
                )
        if (
            ev.destination_ip
            and (ip := normalize_ip(ev.destination_ip))
            and (reason := self._blocked("ip", ip))
        ):
            add(FindingSource.IOC, "EPP-IP-BLOCKLIST", f"Blocklisted IP ({reason})", {"ip": ip})
        dom = normalize_domain(ev.domain) if ev.domain else None
        if dom and (reason := self._blocked("domain", dom)):
            add(FindingSource.IOC, "EPP-DOMAIN-BLOCKLIST", f"Blocklisted domain ({reason})", {"domain": dom})
        if self.intel is not None:
            try:
                self._ioc_findings(ev, sha, dom, out)
            except Exception:
                log.exception("threat-intel lookup failed (continuing without IOC)")
        return out

    def _ioc_findings(
        self, ev: NormalizedEvent, sha: str | None, dom: str | None, out: list[Finding]
    ) -> None:
        assert self.intel is not None
        queries: list[tuple[str, str, list[IOCMatch]]] = []
        if sha:
            queries.append(("sha256", sha, self.intel.match_hash(sha)))
        if ev.destination_ip:
            queries.append(("ip", ev.destination_ip, self.intel.match_ip(ev.destination_ip)))
        if dom:
            queries.append(("domain", dom, self.intel.match_domain(dom)))
        match_url = getattr(self.intel, "match_url", None)
        if match_url is not None:
            urls = [u for u in (ev.raw_metadata.get("url"),) if isinstance(u, str)]
            if ev.command_line:
                urls += _URL_RE.findall(ev.command_line[:8192])
            for u in list(dict.fromkeys(urls))[:MAX_URLS_PER_EVENT]:
                queries.append(("url", u, match_url(u)))
        for ioc_type, value, matches in queries:
            if not matches:
                continue
            best = max(matches, key=lambda m: m.confidence)
            known = best.confidence >= self.min_known_confidence
            src = FindingSource.HASH if ioc_type == "sha256" else FindingSource.IOC
            out.append(
                Finding(
                    event_id=ev.event_id,
                    source=src,
                    rule_id=f"EPP-{src.value.upper()}-{ioc_type.upper()}-INTEL",
                    title=f"Threat-intel {ioc_type} match: {best.threat_type or 'malicious'} ({best.source})",
                    severity=Severity.CRITICAL if known else Severity.MEDIUM,
                    score=100.0 if known else round(best.confidence * 60, 1),
                    confidence=best.confidence,
                    known_malicious=known,
                    mitre_techniques=["T1071"] if ioc_type in {"ip", "domain", "url"} else [],
                    attack_stage=AttackStage.COMMAND_AND_CONTROL if ioc_type in {"ip", "domain"} else None,
                    details={
                        "ioc_type": ioc_type,
                        "value": value[:512],
                        "sources": sorted({m.source for m in matches}),
                        "threat_type": best.threat_type,
                        "matches": len(matches),
                    },
                )
            )

    # ------------------------------------------------------------------ allowlist
    def _allow_finding(self, ev: NormalizedEvent, sha: str | None, exe: str | None) -> Finding | None:
        reason: str | None = None
        kind = ""
        n = normalize_path(exe)
        suspicious_loc = bool(n and ev.event_type in EXEC_EVENTS and path_rule_hits(n, ev.event_type))
        checks: list[tuple[str, str | None]] = [("sha256", sha), ("path", n or None)]
        if not suspicious_loc and ev.event_type in EXEC_EVENTS and n:
            checks.append(("process", n.rsplit("/", 1)[-1].lower()))
        if ev.parent_process and ev.process_name:
            checks.append(("parent_child", f"{ev.parent_process.lower()}>{ev.process_name.lower()}"))
        if ev.destination_ip:
            checks.append(("ip", normalize_ip(ev.destination_ip)))
        if ev.domain:
            checks.append(("domain", normalize_domain(ev.domain)))
        if ev.signer and self._signer_trusted(ev):
            checks.append(("signer", ev.signer.lower()))
        for k, v in checks:
            if v and (r := self._allowed(k, v)) is not None:
                kind, reason = k, r
                break
        if reason is None:
            return None
        return Finding(
            event_id=ev.event_id,
            source=FindingSource.ALLOWLIST,
            rule_id=f"EPP-ALLOW-{kind.upper()}",
            title=f"Allowlisted {kind}: {reason}",
            severity=Severity.INFO,
            score=0.0,
            confidence=1.0,
            details={"kind": kind, "reason": reason},
        )

    def _signer_trusted(self, ev: NormalizedEvent) -> bool:
        if self.signer_verifier is not None:
            try:
                return bool(self.signer_verifier(ev))
            except Exception:
                log.exception("signer verifier failed; treating as untrusted")
                return False
        return self.trust_unverified_signer

    # ------------------------------------------------------------------ heuristics
    def _path_findings(self, ev: NormalizedEvent, exe: str | None) -> list[Finding]:
        out: list[Finding] = []
        if not exe:
            return out
        for r in path_rule_hits(exe, ev.event_type):
            out.append(
                Finding(
                    event_id=ev.event_id,
                    source=FindingSource.RULE,
                    rule_id=r.rule_id,
                    title=r.title,
                    severity=r.severity,
                    score=r.score,
                    confidence=0.6,
                    mitre_techniques=list(r.mitre),
                    attack_stage=AttackStage.EXECUTION
                    if ev.event_type in EXEC_EVENTS
                    else AttackStage.INITIAL_ACCESS,
                    details={"path": exe[:1024], "normalized": normalize_path(exe)},
                )
            )
        if ev.event_type in EXEC_EVENTS and (why := masquerade_reason(ev.process_name, exe)):
            out.append(
                Finding(
                    event_id=ev.event_id,
                    source=FindingSource.RULE,
                    rule_id="EPP-MASQUERADE",
                    title=f"Possible masquerading: {why}",
                    severity=Severity.HIGH,
                    score=65.0,
                    confidence=0.7,
                    mitre_techniques=["T1036.005"],
                    attack_stage=AttackStage.DEFENSE_EVASION,
                    details={"path": exe[:1024], "reason": why},
                )
            )
        return out
