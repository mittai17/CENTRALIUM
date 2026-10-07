"""YARA rule registry + scanner implementing ``YaraScanner``.

* Rules live in *bundles* (one source text, usually one ``.yar`` file). Each rule inside is
  registered with rule_id/name/family/severity/source/version/enabled/metadata, persisted in SQLite
  (additive tables created by :func:`ensure_yara_schema`; ``storage/schema.py`` is not touched).
* Updates are validated by compiling in isolation AND together with the active set; on any failure
  the previous compiled set stays active (atomic swap).
* ``include`` and non-allowlisted ``import`` are rejected (no file reads / unexpected modules from
  rule updates). Scans read through a bounded fd (regular files only, size cap), never hang on FIFOs.
* Degrades gracefully when ``yara-python`` is missing: scanner reports 0 active rules.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.models import AttackStage, Finding, FindingSource, NormalizedEvent, Severity
from centralium.agent.storage import Database

try:  # optional dependency
    import yara
except ImportError:  # pragma: no cover - exercised only without yara-python
    yara = None

log = logging.getLogger("centralium.yara")

SEVERITY_SCORE = {"info": 10.0, "low": 30.0, "medium": 55.0, "high": 80.0, "critical": 95.0}
SEVERITY_ENUM = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
ALLOWED_IMPORTS = frozenset({"pe", "elf", "math", "hash", "dotnet", "string", "time"})
MAX_RULE_SOURCE_BYTES = 1_000_000
MAX_SCAN_BYTES = 64 * 1024 * 1024
SCAN_TIMEOUT_S = 10
_INCLUDE = re.compile(r"^\s*include\s", re.MULTILINE)
_IMPORT = re.compile(r'^\s*import\s+"([^"]*)"', re.MULTILINE)
_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
_BUNDLE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS yara_bundles (
        bundle_id TEXT PRIMARY KEY, source TEXT, version TEXT, enabled INTEGER NOT NULL DEFAULT 1,
        sha256 TEXT NOT NULL, text TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS yara_rules (
        rule_id TEXT PRIMARY KEY, bundle_id TEXT NOT NULL, name TEXT NOT NULL, family TEXT,
        severity TEXT, source TEXT, version TEXT, enabled INTEGER NOT NULL DEFAULT 1,
        metadata TEXT, updated_at TEXT NOT NULL)""",
)


def ensure_yara_schema(db: Database) -> None:
    """Additive, idempotent table creation owned by this module (not a numbered migration)."""
    with db.transaction() as conn:
        for stmt in _SCHEMA:
            conn.execute(stmt)


def yara_available() -> bool:
    return yara is not None


@dataclass(slots=True)
class RuleInfo:
    rule_id: str
    name: str
    bundle_id: str
    family: str = "generic"
    severity: str = "medium"
    source: str = "local"
    version: str = "1"
    enabled: bool = True
    verdict: str = "suspicious"  # malicious -> Finding.known_malicious
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class UpdateResult:
    ok: bool
    message: str
    rules: int = 0


class RuleValidationError(ValueError):
    pass


def _meta_str(meta: dict[str, Any], key: str, default: str) -> str:
    v = meta.get(key)
    return str(v)[:200] if v not in (None, "") else default


def _extract(bundle_id: str, rules: Any, bundle_source: str, bundle_version: str) -> list[RuleInfo]:
    out: list[RuleInfo] = []
    for r in rules:
        meta = dict(r.meta)
        sev = _meta_str(meta, "severity", "medium").lower()
        if sev not in SEVERITY_SCORE:
            raise RuleValidationError(f"rule {r.identifier}: invalid severity {sev!r}")
        verdict = _meta_str(meta, "verdict", "suspicious").lower()
        if verdict not in {"malicious", "suspicious"}:
            raise RuleValidationError(f"rule {r.identifier}: invalid verdict {verdict!r}")
        out.append(
            RuleInfo(
                rule_id=_meta_str(meta, "rule_id", r.identifier),
                name=r.identifier,
                bundle_id=bundle_id,
                family=_meta_str(meta, "family", "generic"),
                severity=sev,
                source=_meta_str(meta, "source", bundle_source),
                version=_meta_str(meta, "version", bundle_version),
                verdict=verdict,
                metadata={
                    **{k: v for k, v in meta.items() if isinstance(v, (str, int, bool))},
                    "tags": list(r.tags),
                },
            )
        )
    ids = [i.rule_id for i in out]
    if len(ids) != len(set(ids)):
        raise RuleValidationError("duplicate rule_id inside bundle")
    return out


def _precheck(text: str) -> None:
    if not isinstance(text, str) or not text.strip():
        raise RuleValidationError("empty rule source")
    if len(text.encode("utf-8", errors="replace")) > MAX_RULE_SOURCE_BYTES:
        raise RuleValidationError("rule source too large")
    if "\x00" in text:
        raise RuleValidationError("NUL byte in rule source")
    if _INCLUDE.search(text):
        raise RuleValidationError("'include' is not allowed in rule updates")
    for mod in _IMPORT.findall(text):
        if mod not in ALLOWED_IMPORTS:
            raise RuleValidationError(f"import {mod!r} is not allowed")


class YaraManager:
    """Thread-safe rule registry and scanner (``YaraScanner`` protocol)."""

    def __init__(
        self,
        db: Database | None = None,
        rules_dir: str | Path | None = None,
        *,
        max_scan_bytes: int = MAX_SCAN_BYTES,
        timeout_s: int = SCAN_TIMEOUT_S,
    ) -> None:
        self.db, self.rules_dir = db, Path(rules_dir) if rules_dir else None
        self.max_scan_bytes, self.timeout_s = max_scan_bytes, timeout_s
        self._lock = threading.RLock()
        self._bundles: dict[str, dict[str, Any]] = {}  # id -> {text, source, version, enabled}
        self._infos: dict[str, RuleInfo] = {}  # rule_id -> info (all bundles)
        self._compiled: Any = None
        if db is not None:
            ensure_yara_schema(db)
        self.reload()

    # ------------------------------------------------------------------ compile helpers
    def _compile(self, bundles: dict[str, dict[str, Any]]) -> tuple[Any, dict[str, RuleInfo]]:
        if yara is None:
            raise RuleValidationError("yara-python is not installed")
        active = {b: v for b, v in bundles.items() if v["enabled"]}
        infos: dict[str, RuleInfo] = {}
        for bid, v in bundles.items():
            _precheck(v["text"])
            try:
                single = yara.compile(source=v["text"])
            except yara.Error as exc:
                raise RuleValidationError(f"bundle {bid}: {exc}") from exc
            for info in _extract(bid, single, v["source"], v["version"]):
                if info.rule_id in infos:
                    raise RuleValidationError(
                        f"duplicate rule_id {info.rule_id!r} (bundles {infos[info.rule_id].bundle_id}, {bid})"
                    )
                infos[info.rule_id] = info
        if not active:
            return None, infos
        try:
            compiled = yara.compile(sources={b: v["text"] for b, v in active.items()})
        except yara.Error as exc:
            raise RuleValidationError(str(exc)) from exc
        return compiled, infos

    def validate_rules(self, source_text: str) -> tuple[bool, str]:
        """Compile + policy-check ``source_text`` WITHOUT activating it."""
        try:
            _precheck(source_text)
            if yara is None:
                raise RuleValidationError("yara-python is not installed")
            try:
                rules = yara.compile(source=source_text)
            except yara.Error as exc:
                raise RuleValidationError(str(exc)) from exc
            infos = _extract("validate", rules, "local", "1")
        except RuleValidationError as exc:
            return False, str(exc)
        if not infos:
            return False, "no rules found"
        return True, f"ok: {len(infos)} rule(s)"

    # ------------------------------------------------------------------ updates
    def update_bundle(
        self, bundle_id: str, text: str, *, version: str = "1", source: str = "local"
    ) -> UpdateResult:
        """Validate then activate. On ANY failure the existing active rule set is kept."""
        if not _BUNDLE_ID.match(bundle_id or ""):
            return UpdateResult(False, "invalid bundle_id")
        with self._lock:
            cand = {
                **self._bundles,
                bundle_id: {"text": text, "source": source, "version": str(version)[:40], "enabled": True},
            }
            old = self._bundles.get(bundle_id)
            if old is not None:
                cand[bundle_id]["enabled"] = old["enabled"]
            try:
                compiled, infos = self._compile(cand)
            except RuleValidationError as exc:
                log.warning("rejected YARA update %s: %s", bundle_id, exc)
                return UpdateResult(False, str(exc), self.active_rule_count())
            self._activate(cand, compiled, infos)
            self._persist(bundle_id)
            return UpdateResult(True, "activated", self.active_rule_count())

    def _activate(
        self, bundles: dict[str, dict[str, Any]], compiled: Any, infos: dict[str, RuleInfo]
    ) -> None:
        prior = {rid: i.enabled for rid, i in self._infos.items()}
        for rid, info in infos.items():
            info.enabled = prior.get(rid, True)
        self._bundles, self._compiled, self._infos = bundles, compiled, infos

    def _persist(self, bundle_id: str) -> None:
        if self.db is None:
            return
        v = self._bundles[bundle_id]
        now = Database.now()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO yara_bundles (bundle_id, source, version, enabled, sha256, text, updated_at) VALUES (?,?,?,?,?,?,?)"  # noqa: E501
                " ON CONFLICT(bundle_id) DO UPDATE SET source=excluded.source, version=excluded.version,"
                " enabled=excluded.enabled, sha256=excluded.sha256, text=excluded.text, updated_at=excluded.updated_at",  # noqa: E501
                (
                    bundle_id,
                    v["source"],
                    v["version"],
                    int(v["enabled"]),
                    hashlib.sha256(v["text"].encode()).hexdigest(),
                    v["text"],
                    now,
                ),
            )
            conn.execute("DELETE FROM yara_rules WHERE bundle_id = ?", (bundle_id,))
            for info in self._infos.values():
                if info.bundle_id != bundle_id:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO yara_rules (rule_id, bundle_id, name, family, severity, source, version,"  # noqa: E501
                    " enabled, metadata, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        info.rule_id,
                        bundle_id,
                        info.name,
                        info.family,
                        info.severity,
                        info.source,
                        info.version,
                        int(info.enabled),
                        json.dumps(info.metadata, default=str)[:8000],
                        now,
                    ),
                )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            info = self._infos.get(rule_id)
            if info is None:
                return False
            info.enabled = enabled
            if self.db is not None:
                self.db.execute(
                    "UPDATE yara_rules SET enabled=?, updated_at=? WHERE rule_id=?",
                    (int(enabled), Database.now(), rule_id),
                )
            return True

    def set_bundle_enabled(self, bundle_id: str, enabled: bool) -> UpdateResult:
        with self._lock:
            if bundle_id not in self._bundles:
                return UpdateResult(False, "unknown bundle")
            cand = {k: dict(v) for k, v in self._bundles.items()}
            cand[bundle_id]["enabled"] = enabled
            try:
                compiled, infos = self._compile(cand)
            except RuleValidationError as exc:
                return UpdateResult(False, str(exc), self.active_rule_count())
            self._activate(cand, compiled, infos)
            self._persist(bundle_id)
            return UpdateResult(True, "ok", self.active_rule_count())

    # ------------------------------------------------------------------ loading
    def reload(self) -> int:
        """Reload rules from ``rules_dir`` (+ persisted bundles) and activate atomically.
        Invalid files are skipped (logged); the previous set stays if nothing valid compiles."""
        with self._lock:
            cand = {k: dict(v) for k, v in self._bundles.items()}
            if self.db is not None:
                for r in self.db.query("SELECT bundle_id, source, version, enabled, text FROM yara_bundles"):
                    cand.setdefault(
                        r["bundle_id"],
                        {
                            "text": r["text"],
                            "source": r["source"] or "db",
                            "version": r["version"] or "1",
                            "enabled": bool(r["enabled"]),
                        },
                    )
            if self.rules_dir and self.rules_dir.is_dir():
                for f in sorted([*self.rules_dir.glob("*.yar"), *self.rules_dir.glob("*.yara")]):
                    try:
                        if f.stat().st_size > MAX_RULE_SOURCE_BYTES:
                            raise RuleValidationError("file too large")
                        text = f.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError, RuleValidationError) as exc:
                        log.warning("skipping rule file %s: %s", f.name, exc)
                        continue
                    prev = cand.get(f.stem)
                    entry = {
                        "text": text,
                        "source": "file",
                        "version": "1",
                        "enabled": prev["enabled"] if prev else True,
                    }
                    try:
                        self._compile({**cand, f.stem: entry})
                    except RuleValidationError as exc:
                        log.warning("skipping invalid rule file %s: %s", f.name, exc)
                        continue
                    cand[f.stem] = entry
            if not cand:
                return self.active_rule_count()
            try:
                compiled, infos = self._compile(cand)
            except RuleValidationError as exc:
                log.error("YARA reload failed, keeping previous set: %s", exc)
                return self.active_rule_count()
            self._activate(cand, compiled, infos)
            for bid in cand:
                self._persist(bid)
            return self.active_rule_count()

    # ------------------------------------------------------------------ introspection
    def list_rules(self) -> list[RuleInfo]:
        with self._lock:
            return list(self._infos.values())

    def active_rule_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._infos.values() if i.enabled and self._bundles[i.bundle_id]["enabled"])

    # ------------------------------------------------------------------ scanning
    def scan_file(self, path: Path, event: NormalizedEvent) -> list[Finding]:
        data = self._read_bounded(Path(path))
        return self.scan_bytes(data, event, target=str(path)) if data is not None else []

    def _read_bounded(self, path: Path) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(str(path), flags)
        except (OSError, ValueError) as exc:  # ValueError: embedded NUL
            log.debug("yara: cannot open %r: %s", str(path)[:200], exc)
            return None
        try:
            st = os.fstat(fd)
            import stat as _st

            if not _st.S_ISREG(st.st_mode) or st.st_size > self.max_scan_bytes:
                return None
            chunks: list[bytes] = []
            total = 0
            while total <= self.max_scan_bytes:
                b = os.read(fd, 1 << 20)
                if not b:
                    break
                chunks.append(b)
                total += len(b)
            return None if total > self.max_scan_bytes else b"".join(chunks)
        except OSError as exc:
            log.debug("yara: read error: %s", exc)
            return None
        finally:
            os.close(fd)

    def scan_bytes(self, data: bytes, event: NormalizedEvent, *, target: str | None = None) -> list[Finding]:
        with self._lock:
            compiled, infos = self._compiled, dict(self._infos)
        if compiled is None or yara is None or not isinstance(data, (bytes, bytearray)):
            return []
        if len(data) > self.max_scan_bytes:
            return []
        try:
            matches = compiled.match(data=bytes(data), timeout=self.timeout_s)
        except yara.TimeoutError:
            log.warning("yara scan timed out (%ss)", self.timeout_s)
            return []
        except yara.Error as exc:
            log.warning("yara scan error: %s", exc)
            return []
        by_name = {(i.bundle_id, i.name): i for i in infos.values()}
        findings: list[Finding] = []
        sha = hashlib.sha256(data).hexdigest() if matches else None
        for m in matches:
            info = by_name.get((m.namespace, m.rule))
            if info is None or not info.enabled:
                continue
            findings.append(self._finding(info, m, event, target, sha))
        return findings

    def _finding(
        self, info: RuleInfo, m: Any, event: NormalizedEvent, target: str | None, sha: str | None
    ) -> Finding:
        strings = []
        for s in m.strings[:8]:
            for inst in s.instances[:3]:
                strings.append(
                    {"id": s.identifier, "offset": inst.offset, "data": inst.matched_data[:48].hex()}
                )
        malicious = info.verdict == "malicious"
        raw_score = info.metadata.get("score")
        score = (
            float(raw_score)
            if isinstance(raw_score, int) and 0 <= raw_score <= 100
            else SEVERITY_SCORE[info.severity]
        )
        if malicious:
            score = max(score, 90.0)
        mitre = [
            t.strip().upper()
            for t in str(info.metadata.get("mitre", "")).split(",")
            if _MITRE.match(t.strip().upper())
        ]
        stage = str(info.metadata.get("attack_stage", "")).upper()
        details = {
            "rule_name": info.name,
            "family": info.family,
            "bundle": info.bundle_id,
            "version": info.version,
            "source": info.source,
            "verdict": info.verdict,
            "target": target,
            "sha256": sha,
            "strings": strings[:12],
        }
        finding = Finding(
            event_id=event.event_id,
            source=FindingSource.YARA,
            rule_id=f"YARA:{info.rule_id}",
            title=f"YARA match: {info.name} ({info.family})",
            severity=SEVERITY_ENUM[info.severity],
            score=score,
            confidence=0.99 if malicious else 0.7,
            known_malicious=malicious,
            mitre_techniques=mitre,
            attack_stage=AttackStage(stage) if stage in AttackStage.__members__ else None,
            details=details,
        )
        if self.db is not None:
            try:
                self.db.insert(
                    "yara_results",
                    {
                        "event_id": event.event_id,
                        "timestamp": Database.now(),
                        "target_path": target,
                        "hash_sha256": sha,
                        "rule_id": info.rule_id,
                        "rule_name": info.name,
                        "family": info.family,
                        "severity": info.severity,
                        "matched_strings": json.dumps(strings[:12]),
                    },
                )
            except Exception:
                log.exception("failed to persist yara result")
        return finding
