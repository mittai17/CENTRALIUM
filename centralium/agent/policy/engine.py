"""Deterministic policy engine implementing ``PolicyEngine``.

Order of evaluation (first match wins; nothing here executes anything):

1. Mode gate  LEARNING -> no action. demo/test -> destructive actions are *simulated*
   (``target['simulate']=True``); the executor and pipeline independently refuse too.
2. Allowlists (names/paths/hashes/IPs/domains + ``ctx.allowlisted``) -> no action. An
   allowlist can never suppress a *known-malicious* (hash/IOC/YARA) finding.
3. Thresholds  risk below ``alert_min_risk`` -> nothing; below the destructive threshold ->
   ALERT only. Destructive actions need risk >= ``min_risk_destructive`` (SUSPEND: that
   minus ``suspend_offset``) AND evidence confidence >= ``min_confidence_destructive``;
   known-malicious evidence bypasses the *risk* threshold but not the confidence one.
   PASSIVE only alerts unless ``passive_destructive_allowed``. PANIC lowers thresholds
   (``panic_min_risk`` / ``panic_min_confidence``), skips user approval and may isolate.
4. The LLM recommendation is a *structured input only*: it may select among actions the
   deterministic ladder already permits (never escalate), may downgrade to ALERT for
   non-known evidence when confident, and can never soften a known-malicious response.
5. Target validation + protected processes/paths (own pid and parents, init/systemd/sshd/
   lsass/...). A refused destructive action falls through to the next candidate and finally
   to ALERT with the refusal recorded in ``reason``.
6. ``allowed_actions`` restriction and user-approval flag (``requires_approval``).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.config import PolicySettings
from centralium.agent.interfaces import PolicyContext
from centralium.agent.models import (
    ActionRecommendation,
    EventType,
    FindingSource,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
    RiskBand,
    Verdict,
)
from centralium.agent.policy.protection import ProtectionRules
from centralium.agent.policy.validation import (
    ValidationError,
    non_blockable_reason,
    validate_ip,
    validate_network,
    validate_path_str,
    validate_pid,
    validate_port,
)

log = logging.getLogger("centralium.policy")

_NET_EVENTS = {EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN, EventType.DNS_QUERY}
_FILE_EVENTS = {EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_RENAME}
_A = ResponseAction


class PolicyTuning(BaseModel):
    """Policy knobs beyond ``PolicySettings`` (kept local; propose adding to config)."""

    model_config = ConfigDict(extra="forbid")

    alert_min_risk: float = Field(default=40.0, ge=0, le=100)
    suspend_offset: float = Field(default=10.0, ge=0, le=100)
    panic_min_risk: float = Field(default=60.0, ge=0, le=100)
    panic_min_confidence: float = Field(default=0.5, ge=0, le=1)
    panic_isolation_min_risk: float = Field(default=90.0, ge=0, le=100)
    ai_min_confidence: float = Field(default=0.6, ge=0, le=1)
    never_block_networks: list[str] = Field(default_factory=list)  # management/DNS etc. (CIDR or IP)


class RulesPolicyEngine:
    def __init__(
        self,
        settings: PolicySettings | None = None,
        tuning: PolicyTuning | None = None,
        *,
        protection: ProtectionRules | None = None,
        allow_names: Iterable[str] = (),
        allow_paths: Iterable[str] = (),
        allow_hashes: Iterable[str] = (),
        allow_ips: Iterable[str] = (),
        allow_domains: Iterable[str] = (),
    ) -> None:
        self.s = settings or PolicySettings()
        self.t = tuning or PolicyTuning()
        self.protection = protection or ProtectionRules.from_lists(
            self.s.protected_processes, self.s.protected_paths
        )
        self.allow_names = {n.lower() for n in allow_names}
        self.allow_paths = tuple(p.lower().replace("\\", "/").rstrip("/") for p in allow_paths)
        self.allow_hashes = {h.lower() for h in allow_hashes}
        self.allow_ips = set(allow_ips)
        self.allow_domains = {d.lower() for d in allow_domains}
        self._never_block = [validate_network(n) for n in self.t.never_block_networks]

    # ------------------------------------------------------------------ public API
    def decide(self, ctx: PolicyContext) -> PolicyDecision:
        return self.plan(ctx)[0]

    def plan(self, ctx: PolicyContext) -> list[PolicyDecision]:
        """Ordered decisions (primary first). ``decide`` returns ``plan(ctx)[0]``; the list is never empty."""
        mode = ctx.mode

        def none(reason: str) -> list[PolicyDecision]:
            return [PolicyDecision(mode=mode, reason=reason, target={"event_id": ctx.event.event_id})]

        if mode == OperatingMode.LEARNING:
            return none("LEARNING mode: baselining only, no response")
        known = ctx.known_malicious or any(f.known_malicious for f in ctx.findings)
        if not known and (ctx.allowlisted or self._allowlisted(ctx.event)):
            return none("allowlisted")
        risk = ctx.risk.final_score
        if not known and risk < self.t.alert_min_risk:
            return none(f"risk {risk:.0f} below alert threshold {self.t.alert_min_risk:g}")

        conf = self.evidence_confidence(ctx)
        notes: list[str] = []
        candidates = self._ladder(ctx, known, risk, conf, notes)
        candidates = self._apply_ai(ctx, candidates, known, notes)

        refusals: list[str] = []
        out: list[PolicyDecision] = []
        for action in candidates:
            dec = self._finalize(action, ctx, known, risk, conf, refusals, notes)
            if dec is not None:
                out.append(dec)
        if not any(d.action != _A.ALERT for d in out) or not out:
            alert = self._finalize(_A.ALERT, ctx, known, risk, conf, refusals, notes)
            if alert is not None and not any(d.action == _A.ALERT for d in out):
                out.append(alert)
        if not out:
            return none("; ".join(["no permitted action", *refusals]))
        if refusals:
            out[0] = out[0].model_copy(
                update={"reason": out[0].reason + " | refused: " + "; ".join(refusals)}
            )
        return out

    def recheck(self, action: ResponseAction, target: dict[str, Any], event: NormalizedEvent) -> str | None:
        """Re-validate a previously decided action (e.g. one a dashboard operator approved).

        The target is rebuilt from the *event* and must match the stored target for every
        security-relevant key (pid/path/ip/port), so a tampered row cannot redirect an action.
        Allowed-actions, validation and protected process/path rules are applied again.
        Returns a refusal reason, or ``None`` when the action may proceed.
        """
        if action not in self.s.allowed_actions:
            return f"{action.value} not in allowed_actions"
        fresh: dict[str, Any] = {}
        try:
            self._fill_target(action, event, fresh)
        except ValidationError as exc:
            return f"{action.value}: {exc}"
        for key in ("pid", "path", "ip", "port"):
            if target.get(key) != fresh.get(key):
                return f"stored target {key}={target.get(key)!r} does not match the recorded event"
        refusal = self._protection_refusal(action, fresh)
        return f"{action.value}: {refusal}" if refusal else None

    # ------------------------------------------------------------------ evidence
    @staticmethod
    def evidence_confidence(ctx: PolicyContext) -> float:
        """Confidence of the *deterministic* evidence (the AI never contributes)."""
        known = [f.confidence for f in ctx.findings if f.known_malicious]
        if known:
            return max(known)
        scored = [f for f in ctx.findings if f.score > 0]
        if scored:
            return max(scored, key=lambda f: (f.score, f.confidence)).confidence
        from centralium.agent.models import ScoreFamily

        confs = [
            r.confidence
            for fam, r in ctx.risk.scores.items()
            if r.available and r.score > 0 and fam not in (ScoreFamily.FINAL_RISK, ScoreFamily.AI_ASSESSMENT)
        ]
        return max(confs, default=0.0)

    def _allowlisted(self, ev: NormalizedEvent) -> bool:
        if ev.process_name and ev.process_name.lower() in self.allow_names:
            return True
        if ev.hash_sha256 and ev.hash_sha256.lower() in self.allow_hashes:
            return True
        if ev.destination_ip and ev.destination_ip in self.allow_ips:
            return True
        if ev.domain and ev.domain.lower() in self.allow_domains:
            return True
        for p in (ev.executable_path, ev.file_path):
            if p:
                low = p.lower().replace("\\", "/")
                if any(low == a or low.startswith(a + "/") for a in self.allow_paths):
                    return True
        return False

    # ------------------------------------------------------------------ ladder
    def _thresholds(self, mode: OperatingMode) -> tuple[float, float, float]:
        """(destructive risk, suspend risk, min confidence)."""
        if mode == OperatingMode.PANIC:
            dr = min(self.s.min_risk_destructive, self.t.panic_min_risk)
            return dr, dr, min(self.s.min_confidence_destructive, self.t.panic_min_confidence)
        dr = self.s.min_risk_destructive
        return dr, max(0.0, dr - self.t.suspend_offset), self.s.min_confidence_destructive

    def _destructive_enabled(self, mode: OperatingMode) -> bool:
        return mode in (OperatingMode.ACTIVE, OperatingMode.PANIC) or (
            mode == OperatingMode.PASSIVE and self.s.passive_destructive_allowed
        )

    def _ladder(
        self, ctx: PolicyContext, known: bool, risk: float, conf: float, notes: list[str]
    ) -> list[ResponseAction]:
        ev = ctx.event
        mode = ctx.mode
        out: list[ResponseAction] = []
        if self._destructive_enabled(mode):
            dr, sr, cm = self._thresholds(mode)
            conf_ok = conf >= cm
            strong = conf_ok and (known or risk >= dr)
            medium = conf_ok and risk >= sr
            ransom = any(f.source == FindingSource.RANSOMWARE for f in ctx.findings)
            if known and not conf_ok:
                notes.append(
                    f"known-malicious evidence confidence {conf:.2f} < {cm:.2f}: no destructive action"
                )
            elif not conf_ok and risk >= sr:
                notes.append(f"evidence confidence {conf:.2f} < {cm:.2f}: no destructive action")
            has_pid = ev.pid is not None
            if (
                mode == OperatingMode.PANIC
                and self.s.panic_isolation_allowed
                and conf_ok
                and (ransom or known or risk >= self.t.panic_isolation_min_risk)
                and risk >= dr
            ):
                out.append(_A.ISOLATE_ENDPOINT)
            if ev.event_type in _NET_EVENTS and ev.destination_ip and strong:
                out.append(_A.BLOCK_CONNECTION)
            if ransom and has_pid and strong:
                out.append(_A.TERMINATE_PROCESS)
            if ev.event_type in _FILE_EVENTS and ev.file_path and strong and not ransom:
                out.append(_A.QUARANTINE_FILE)
            if has_pid and ev.event_type not in _FILE_EVENTS | _NET_EVENTS:
                if strong:
                    out.append(_A.TERMINATE_PROCESS)
                elif medium:
                    out.append(_A.SUSPEND_PROCESS)
            elif has_pid and ev.event_type in _NET_EVENTS and ev.destination_ip and (strong or medium):
                # the connecting process: after the block, stop it (terminate) or freeze it (suspend)
                out.append(_A.TERMINATE_PROCESS if strong else _A.SUSPEND_PROCESS)
            if known and ev.event_type == EventType.PROCESS_START and ev.executable_path and strong:
                out.append(_A.QUARANTINE_FILE)
            if _A.TERMINATE_PROCESS in out and _A.SUSPEND_PROCESS not in out:
                out.append(_A.SUSPEND_PROCESS)  # more conservative alternative (AI/protection fallbacks)
        out.append(_A.ALERT)
        seen: set[ResponseAction] = set()
        uniq: list[ResponseAction] = []
        for a in out:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        return uniq

    def _apply_ai(
        self, ctx: PolicyContext, cands: list[ResponseAction], known: bool, notes: list[str]
    ) -> list[ResponseAction]:
        ai = ctx.ai
        if ai is None or not ai.available or ai.verdict is None:
            return cands
        v = ai.verdict
        if v.confidence < self.t.ai_min_confidence:
            notes.append(f"AI recommendation ignored: confidence {v.confidence:.2f}")
            return cands
        if known:
            notes.append("AI recommendation not applied: known-malicious evidence is deterministic")
            return cands
        rec = v.recommended_action
        if rec in (ActionRecommendation.NONE, ActionRecommendation.ALERT):
            if ctx.risk.band == RiskBand.CRITICAL and v.verdict != Verdict.BENIGN and cands != [_A.ALERT]:
                # A CRITICAL risk (deterministic + ML + graph evidence) triggers the predefined
                # response; an advisory model that still calls the activity SUSPICIOUS/MALICIOUS
                # may not talk the policy out of it (only an explicit BENIGN verdict can).
                notes.append(
                    "AI recommended no enforcement: not applied at CRITICAL risk (verdict not BENIGN)"
                )
                return cands
            if cands != [_A.ALERT]:
                notes.append("AI recommended no enforcement: downgraded to ALERT")
            return [_A.ALERT]
        action = ResponseAction(rec.value)
        if action in cands:
            return [action, *[a for a in cands if a != action]]
        notes.append(f"AI recommended {action.value} but deterministic evidence does not permit it")
        return cands

    # ------------------------------------------------------------------ finalize one action
    def _finalize(
        self,
        action: ResponseAction,
        ctx: PolicyContext,
        known: bool,
        risk: float,
        conf: float,
        refusals: list[str],
        notes: list[str],
    ) -> PolicyDecision | None:
        ev = ctx.event
        mode = ctx.mode
        if action not in self.s.allowed_actions:
            refusals.append(f"{action.value} not in allowed_actions")
            return None
        target: dict[str, Any] = {
            "event_id": ev.event_id,
            "risk": round(risk, 2),
            "evidence_confidence": round(conf, 3),
            "reasons": [f.title[:200] for f in ctx.findings if f.score > 0 or f.known_malicious][:10],
            "sources": sorted({f.source.value for f in ctx.findings if f.score > 0 or f.known_malicious}),
        }
        try:
            self._fill_target(action, ev, target)
        except ValidationError as exc:
            refusals.append(f"{action.value}: {exc}")
            return None
        refusal = self._protection_refusal(action, target)
        if refusal:
            refusals.append(f"{action.value}: {refusal}")
            return None
        destructive = action != _A.ALERT
        reason = f"{action.value} (risk {risk:.0f}, evidence confidence {conf:.2f}, mode {mode.value})"
        if known:
            reason += "; known-malicious evidence"
        if notes:
            reason += " | " + "; ".join(notes)
        approval = (
            destructive
            and mode != OperatingMode.PANIC
            and (self.s.require_approval or action == _A.ISOLATE_ENDPOINT)
        )
        if destructive and (ctx.demo_mode or ctx.test_mode):
            target["simulate"] = True
            return PolicyDecision(
                action=action, allowed=True, requires_approval=False, mode=mode,
                reason="[demo/test: simulated only] " + reason, target=target,
            )  # fmt: skip
        return PolicyDecision(
            action=action, allowed=True, requires_approval=approval, mode=mode, reason=reason, target=target
        )

    def _fill_target(self, action: ResponseAction, ev: NormalizedEvent, target: dict[str, Any]) -> None:
        if action in (_A.SUSPEND_PROCESS, _A.TERMINATE_PROCESS):
            target["pid"] = validate_pid(ev.pid)
            if ev.process_name:
                target["process_name"] = ev.process_name
            if ev.executable_path:
                target["executable_path"] = validate_path_str(ev.executable_path)
            ct = ev.raw_metadata.get("create_time")
            if isinstance(ct, (int, float)) and not isinstance(ct, bool):
                target["create_time"] = float(ct)
            target["event_time"] = ev.timestamp.timestamp()
        elif action == _A.BLOCK_CONNECTION:
            ip = validate_ip(ev.destination_ip)
            why = non_blockable_reason(ip)
            if why:
                raise ValidationError(f"refusing to block {why} address")
            if any(ip in net for net in self._never_block if net.version == ip.version):
                raise ValidationError("destination is on the never-block (management) list")
            target["ip"] = str(ip)
            if ev.destination_port is not None:
                target["port"] = validate_port(ev.destination_port)
            if ev.protocol and ev.protocol.lower() in ("tcp", "udp"):
                target["protocol"] = ev.protocol.lower()
        elif action == _A.QUARANTINE_FILE:
            raw = ev.file_path if ev.event_type in _FILE_EVENTS else (ev.executable_path or ev.file_path)
            target["path"] = validate_path_str(raw)
            if ev.hash_sha256:
                target["sha256"] = ev.hash_sha256
        elif action == _A.ALERT:
            return

    def _protection_refusal(self, action: ResponseAction, target: dict[str, Any]) -> str | None:
        if action in (_A.SUSPEND_PROCESS, _A.TERMINATE_PROCESS):
            return self.protection.process_refusal(
                target.get("pid"), target.get("process_name"), target.get("executable_path")
            )
        if action == _A.QUARANTINE_FILE:
            return self.protection.path_refusal(target["path"])
        return None


__all__ = ["PolicyTuning", "RulesPolicyEngine"]
