"""Transparent self-protection monitor (implements ``SelfProtection``).

What it does (all visible in the audit log; no hooking, no hiding, no kernel code):
* executable/package integrity: SHA-256 manifest of agent files vs. a baseline (optionally Ed25519-signed)
* configuration integrity: hashes of config files vs. baseline
* protected directory permission checks (POSIX; Windows ACL audit is NOT implemented)
* process/component health + a watchdog thread that re-runs checks periodically and pings systemd
* tamper findings -> TAMPER ``NormalizedEvent`` + SELF_PROTECTION ``Finding`` + audit entry

Limits (honest): a root/Administrator attacker can disable the agent or rewrite baseline and
manifest together. Signing the manifest with an off-host key and anchoring ``audit.head()``
remotely raise the bar; this module detects and reports, it does not prevent.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.interfaces import EventSink
from centralium.agent.models import EventType, Finding, FindingSource, NormalizedEvent, Severity
from centralium.agent.self_protection import integrity
from centralium.agent.self_protection.updates import HAVE_CRYPTO

if HAVE_CRYPTO:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger("centralium.self_protection")
AuditFn = Callable[[str, str, dict[str, Any]], Any]
HealthFn = Callable[[], tuple[bool, str]]


def sd_notify(message: str) -> bool:
    """Minimal systemd notify (READY=1 / WATCHDOG=1). No-op when not run under systemd."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(message.encode())
        return True
    except OSError:
        log.debug("sd_notify failed", exc_info=True)
        return False


@dataclass
class SelfProtectionSettings:
    package_root: Path  # directory whose files are covered by the manifest
    baseline_path: Path  # JSON baseline written by ``create_baseline``
    config_files: list[Path] = field(default_factory=list)
    protected_dirs: list[Path] = field(default_factory=list)
    patterns: tuple[str, ...] = integrity.DEFAULT_PATTERNS
    public_key: bytes | None = None  # if set, baseline must have a valid <baseline>.sig (Ed25519)
    interval_s: float = 30.0
    host_id: str = "localhost"
    report_unexpected_files: bool = True


class SelfProtectionMonitor:
    def __init__(
        self,
        settings: SelfProtectionSettings,
        *,
        sink: EventSink | None = None,
        audit: AuditFn | None = None,
        finding_sink: Callable[[NormalizedEvent, Finding], None] | None = None,
    ) -> None:
        self.s = settings
        self._sink = sink
        # Integration hook: receives the event *and* its SELF_PROTECTION finding so the pipeline
        # can score the tamper (a bare event carries no evidence). Takes precedence over ``sink``.
        self._finding_sink = finding_sink
        self._audit = audit
        self._components: dict[str, HealthFn] = {}
        self._active: dict[str, Finding] = {}  # key -> finding currently open
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_check_ok_ts: float = 0.0
        self.checks_run = 0

    # ------------------------------------------------------------------ baseline management
    def create_baseline(self, actor: str = "operator", reason: str = "baseline created") -> dict[str, Any]:
        """Record the current state as trusted. Audited. Sign the file out-of-band for authenticity."""
        files = integrity.build_manifest(self.s.package_root, self.s.patterns)
        doc: dict[str, Any] = integrity.manifest_document(self.s.package_root, files)
        doc["config_files"] = {str(p): integrity.sha256_file(p) for p in self.s.config_files if p.is_file()}
        self.s.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.s.baseline_path.write_bytes(integrity.canonical_bytes(doc))
        self._do_audit(
            "baseline_created",
            {"actor": actor, "reason": reason, "files": len(files), "config_files": len(doc["config_files"])},
        )
        return doc

    def accept_config_change(self, actor: str, reason: str) -> None:
        """Operator-authorised re-baseline of config hashes (the only sanctioned way to change them)."""
        self.create_baseline(actor=actor, reason=f"config change accepted: {reason}")

    def update_baseline(self, actor: str = "operator", reason: str = "baseline updated") -> dict[str, Any]:
        """Operator-authorised re-baseline of package files and config hashes."""
        return self.create_baseline(actor=actor, reason=reason)

    def register_component(self, name: str, health: HealthFn) -> None:
        with self._lock:
            self._components[name] = health

    # ------------------------------------------------------------------ checks
    def check(self) -> list[Finding]:
        """Run all checks. Returns the currently-open tamper findings; new ones are emitted+audited once."""
        with self._lock:
            found: dict[str, tuple[str, str, Severity, float, dict[str, Any]]] = {}
            self._check_integrity(found)
            self._check_dirs(found)
            self._check_health(found)
            self.checks_run += 1

            current: dict[str, Finding] = {}
            for key, (rule, title, sev, score, details) in found.items():
                if key in self._active:
                    current[key] = self._active[key]
                    continue
                current[key] = self._emit(rule, title, sev, score, details)
            for key in set(self._active) - set(current):
                self._do_audit("tamper_resolved", {"key": key})
            self._active = current
            return list(current.values())

    def _check_integrity(self, found: dict[str, tuple[str, str, Severity, float, dict[str, Any]]]) -> None:
        bp = self.s.baseline_path
        if not bp.is_file():
            found["baseline-missing"] = (
                "SP-BASELINE-MISSING",
                "Integrity baseline missing",
                Severity.HIGH,
                70,
                {"path": str(bp)},
            )
            return
        raw = bp.read_bytes()
        if self.s.public_key is not None and not self._baseline_signature_ok(raw):
            found["baseline-sig"] = (
                "SP-BASELINE-SIGNATURE",
                "Integrity baseline signature invalid/missing",
                Severity.CRITICAL,
                95,
                {"path": str(bp)},
            )
            return
        try:
            doc = json.loads(raw)
            files: dict[str, str] = doc["files"]
            cfg: dict[str, str] = doc.get("config_files", {})
        except (ValueError, KeyError, TypeError):
            found["baseline-corrupt"] = (
                "SP-BASELINE-CORRUPT",
                "Integrity baseline unreadable",
                Severity.HIGH,
                80,
                {"path": str(bp)},
            )
            return
        rep = integrity.verify_manifest(self.s.package_root, files, self.s.patterns)
        for rel in rep.modified:
            found[f"mod:{rel}"] = (
                "SP-FILE-MODIFIED",
                "Agent file modified",
                Severity.CRITICAL,
                95,
                {"file": rel},
            )
        for rel in rep.missing:
            found[f"miss:{rel}"] = ("SP-FILE-MISSING", "Agent file missing", Severity.HIGH, 85, {"file": rel})
        if self.s.report_unexpected_files:
            for rel in rep.unexpected:
                found[f"new:{rel}"] = (
                    "SP-FILE-UNEXPECTED",
                    "Unexpected file in agent package",
                    Severity.MEDIUM,
                    55,
                    {"file": rel},
                )
        for path_s, want in cfg.items():
            p = Path(path_s)
            try:
                have = integrity.sha256_file(p) if p.is_file() else None
            except OSError:
                have = None
            if have != want:
                found[f"cfg:{path_s}"] = (
                    "SP-CONFIG-MODIFIED",
                    "Agent configuration changed or removed",
                    Severity.HIGH,
                    80,
                    {"file": path_s, "removed": have is None},
                )

    def _baseline_signature_ok(self, raw: bytes) -> bool:
        if not HAVE_CRYPTO or self.s.public_key is None:
            return False
        sig = Path(str(self.s.baseline_path) + ".sig")
        try:
            Ed25519PublicKey.from_public_bytes(self.s.public_key).verify(sig.read_bytes(), raw)
            return True
        except (OSError, InvalidSignature, ValueError):
            return False

    def _check_dirs(self, found: dict[str, tuple[str, str, Severity, float, dict[str, Any]]]) -> None:
        for d in self.s.protected_dirs:
            for problem in integrity.check_dir_permissions(d):
                found[f"perm:{problem}"] = (
                    "SP-DIR-PERMISSIONS",
                    "Protected directory permissions weak",
                    Severity.MEDIUM,
                    60,
                    {"dir": str(d), "problem": problem},
                )

    def _check_health(self, found: dict[str, tuple[str, str, Severity, float, dict[str, Any]]]) -> None:
        try:
            import psutil  # type: ignore[import-untyped,unused-ignore]

            st = psutil.Process().status()
            if st in (psutil.STATUS_ZOMBIE, psutil.STATUS_STOPPED):
                found["proc-state"] = (
                    "SP-PROCESS-STATE",
                    "Agent process in abnormal state",
                    Severity.HIGH,
                    75,
                    {"status": st},
                )
        except Exception:
            log.debug("psutil self-check unavailable", exc_info=True)
        for name, fn in list(self._components.items()):
            try:
                ok, why = fn()
            except Exception as exc:
                ok, why = False, f"health check raised {type(exc).__name__}"
            if not ok:
                found[f"health:{name}"] = (
                    "SP-COMPONENT-UNHEALTHY",
                    f"Component '{name}' unhealthy",
                    Severity.MEDIUM,
                    60,
                    {"component": name, "reason": why},
                )

    # ------------------------------------------------------------------ emission
    def _emit(self, rule: str, title: str, sev: Severity, score: float, details: dict[str, Any]) -> Finding:
        ev = NormalizedEvent(
            event_type=EventType.TAMPER,
            host_id=self.s.host_id,
            source="self_protection",
            file_path=str(details.get("file") or details.get("dir") or "") or None,
            raw_metadata={"rule_id": rule, **details},
        )
        f = Finding(
            event_id=ev.event_id,
            source=FindingSource.SELF_PROTECTION,
            rule_id=rule,
            title=title,
            severity=sev,
            score=score,
            details=details,
        )
        self._do_audit(
            "tamper_detected", {"rule_id": rule, "severity": sev.value, "event_id": ev.event_id, **details}
        )
        log.warning("tamper: %s %s", rule, details)
        try:
            if self._finding_sink is not None:
                self._finding_sink(ev, f)
            elif self._sink is not None:
                self._sink(ev)
        except Exception:
            log.exception("tamper event sink failed")
        return f

    def _do_audit(self, event_type: str, details: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit("self_protection", event_type, details)
        except Exception:
            log.exception("audit failed")

    # ------------------------------------------------------------------ watchdog
    def _loop(self) -> None:
        sd_notify("READY=1")
        while not self._stop.is_set():
            try:
                self.check()
                sd_notify("WATCHDOG=1")
            except Exception:
                log.exception("self-protection check crashed")
            self._stop.wait(self.s.interval_s)

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="centralium-selfprot", daemon=True)
            self._thread.start()
        self._do_audit("watchdog_started", {"interval_s": self.s.interval_s})

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t:
            t.join(5)
        self._do_audit("watchdog_stopped", {})

    def watchdog_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
