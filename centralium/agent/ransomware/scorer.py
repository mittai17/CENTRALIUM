"""Composite ransomware scoring.

Ransomware is never declared from a single file operation. The score combines six
independently thresholded components over a sliding window:

=============  ======  ==============================================================
component      weight  evidence
=============  ======  ==============================================================
write burst    0.25    distinct files created/modified by the process (family) / window
rename burst   0.15    rename count / window
ext mutation   0.20    extension changes, appended extensions (a.docx -> a.docx.x),
                       known ransom extensions, ransom-note drops
entropy rise   0.15    entropy increase (before/after, or high absolute entropy)
shadow copy    0.15    vssadmin/wmic/bcdedit/wbadmin/diskshadow backup destruction
ancestry       0.10    Office/browser/service/script-host parent, temp-dir executable
=============  ======  ==============================================================

Gating (see :class:`RansomwareConfig`): fewer than ``min_active_components`` behavioural
components (ancestry never counts) caps the score at ``single_component_cap``; a synergy
multiplier applies once ``synergy_components`` are active; CRITICAL (>=80) therefore needs
several corroborating behaviours.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.behavior.signals import ancestry_risk, norm_name, path_risk, shadow_command_kind
from centralium.agent.behavior.state import FILE_EVENT_TYPES, BehaviorState, FileWindowStats
from centralium.agent.models import (
    AttackStage,
    DetectionResult,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    ScoreFamily,
    Severity,
)

_BULK_WRITERS = frozenset(
    {
        "git",
        "rsync",
        "tar",
        "cp",
        "mv",
        "dpkg",
        "apt",
        "apt-get",
        "pacman",
        "dnf",
        "yum",
        "rpm",
        "make",
        "ninja",
        "gcc",
        "cc1",
        "cc1plus",
        "ld",
        "clang",
        "cargo",
        "rustc",
        "pip",
        "pip3",
        "npm",
        "yarn",
        "tracker-miner-fs-3",
        "baloo_file",
        "updatedb",
        "robocopy",
        "xcopy",
        "msbuild",
        "devenv",
        "searchindexer",
        "onedrive",
        "dropbox",
        "veeamagent",
        "restic",
        "borg",
        "duplicity",
        "timeshift",
        "unzip",
        "7z",
        "7za",
        "winrar",
        "zip",
        "msiexec",
    }
)


class RansomwareConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_sec: float = Field(default=60.0, gt=0)
    write_lo: int = 30  # distinct files written / window at which the component becomes "active"
    write_hi: int = 150
    rename_lo: int = 15
    rename_hi: int = 60
    ext_lo: int = 10
    ext_hi: int = 40
    entropy_min_samples: int = 5
    entropy_delta_lo: float = 1.0
    entropy_delta_hi: float = 3.0
    entropy_abs_lo: float = 7.0  # absolute-entropy fallback when no "before" value is known
    entropy_abs_hi: float = 7.8
    shadow_window_sec: float = 300.0
    w_write: float = 0.25
    w_rename: float = 0.15
    w_ext: float = 0.20
    w_entropy: float = 0.15
    w_shadow: float = 0.15
    w_ancestry: float = 0.10
    active_threshold: float = 0.5
    min_active_components: int = 2
    single_component_cap: float = 39.0
    synergy_components: int = 3
    synergy_multiplier: float = 1.15
    bulk_writer_factor: float = 0.5
    alert_score: float = 40.0
    critical_score: float = 80.0
    alert_cooldown_sec: float = 15.0


def _ramp(n: float, lo: float, hi: float) -> float:
    """0 at n<=0; <0.5 below ``lo`` (never 'active'); 0.5 at lo; 1.0 at hi."""
    if n <= 0 or lo <= 0:
        return 0.0
    if n < lo:
        return 0.49 * n / lo
    if hi <= lo:
        return 1.0
    return min(1.0, 0.5 + 0.5 * (n - lo) / (hi - lo))


@dataclass
class RansomwareAssessment:
    score: float = 0.0
    components: dict[str, float] = field(default_factory=dict)
    active: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    key: int | str = ""
    shadow_kind: str | None = None
    stats: FileWindowStats | None = None
    capped: bool = False

    @property
    def triggered(self) -> bool:
        return bool(self.active) and self.score > 0


class RansomwareScorer:
    """Stateless scorer over a :class:`BehaviorState` (all window data lives in the state)."""

    def __init__(self, config: RansomwareConfig | None = None) -> None:
        self.cfg = config or RansomwareConfig()

    # ------------------------------------------------------------------ core
    def assess(self, event: NormalizedEvent, state: BehaviorState) -> RansomwareAssessment:
        """Score the activity of the process (and its parent family) that produced ``event``."""
        cmd_kind = (
            shadow_command_kind(event.command_line) if event.event_type == EventType.PROCESS_START else None
        )
        relevant = event.event_type in FILE_EVENT_TYPES or cmd_kind is not None
        if not relevant:
            # non-file events still inherit the process's current window (cheap lookup)
            key = state.pid_key(event)
            if key not in state.file_ops and not state.shadow_count(key, self.cfg.shadow_window_sec):
                return RansomwareAssessment(key=key)
        keys: list[int | str] = [state.pid_key(event)]
        if event.ppid is not None:
            keys.append(event.ppid)
        best = RansomwareAssessment(key=keys[0])
        for k in keys:
            a = self._assess_key(event, state, k)
            if a.score >= best.score:
                best = a
        return best

    def _assess_key(
        self, event: NormalizedEvent, state: BehaviorState, key: int | str
    ) -> RansomwareAssessment:
        cfg = self.cfg
        st = state.file_stats(key, window_sec=cfg.window_sec)
        comps: dict[str, float] = {}
        reasons: list[str] = []

        comps["write_burst"] = _ramp(st.writes, cfg.write_lo, cfg.write_hi)
        if st.writes:
            reasons.append(f"{st.writes} files written/created in {cfg.window_sec:.0f}s")
        comps["rename_burst"] = _ramp(st.renames, cfg.rename_lo, cfg.rename_hi)

        ext = _ramp(st.ext_changes, cfg.ext_lo, cfg.ext_hi)
        if st.ransom_ext_hits >= 3:
            ext = max(ext, 0.8)
            reasons.append(f"{st.ransom_ext_hits} renames to known ransomware extensions")
        if st.appended_ext >= cfg.ext_lo:
            ext = max(ext, 0.7)
            reasons.append(f"{st.appended_ext} files renamed by appending a new extension")
        if st.ext_changes >= 8 and st.dominant_ext_count >= max(5, int(0.6 * st.ext_changes)):
            ext = max(ext, 0.7)
            reasons.append(f"{st.dominant_ext_count} files mutated to the same extension {st.dominant_ext!r}")
        if st.ransom_notes >= 2:
            ext = max(ext, 0.6)
            reasons.append(f"{st.ransom_notes} ransom-note-like files dropped")
        comps["extension_mutation"] = ext

        ent = 0.0
        if st.entropy_samples >= cfg.entropy_min_samples:
            if st.avg_entropy_delta is not None:
                ent = _ramp(st.avg_entropy_delta, cfg.entropy_delta_lo, cfg.entropy_delta_hi)
                reasons.append(
                    f"mean entropy increase {st.avg_entropy_delta:.2f} bits/byte "
                    f"over {st.entropy_samples} files"
                )
            elif st.avg_entropy_after > 6.0:
                span = cfg.entropy_abs_hi - cfg.entropy_abs_lo
                ent = _ramp(
                    st.avg_entropy_after - 6.0, cfg.entropy_abs_lo - 6.0, cfg.entropy_abs_lo - 6.0 + span
                )
                reasons.append(
                    f"mean written-file entropy {st.avg_entropy_after:.2f} over {st.entropy_samples} files"
                )
        comps["entropy_increase"] = ent

        n_shadow = max(
            state.shadow_count(key, cfg.shadow_window_sec),
            1 if shadow_command_kind(event.command_line) else 0,
        )
        shadow = 1.0 if n_shadow else 0.0
        shadow_kind = shadow_command_kind(event.command_line)
        if n_shadow:
            reasons.append("backup/shadow-copy destruction command observed")
        comps["shadow_copy"] = shadow

        chain_risk = self._ancestry(event, state)
        comps["ancestry"] = chain_risk
        if chain_risk >= 0.5:
            reasons.append(f"suspicious process ancestry (risk {chain_risk:.2f})")

        weights = {
            "write_burst": cfg.w_write,
            "rename_burst": cfg.w_rename,
            "extension_mutation": cfg.w_ext,
            "entropy_increase": cfg.w_entropy,
            "shadow_copy": cfg.w_shadow,
            "ancestry": cfg.w_ancestry,
        }
        raw = 100.0 * sum(weights[c] * v for c, v in comps.items())
        active = [c for c, v in comps.items() if c != "ancestry" and v >= cfg.active_threshold]
        capped = False
        if len(active) < cfg.min_active_components:
            if raw > cfg.single_component_cap:
                capped = True
            raw = min(raw, cfg.single_component_cap)
        elif len(active) >= cfg.synergy_components:
            raw = min(100.0, raw * cfg.synergy_multiplier)

        pname = norm_name(event.process_name)
        if pname in _BULK_WRITERS and st.ransom_ext_hits == 0 and not shadow and chain_risk < 0.5:
            raw *= cfg.bulk_writer_factor
            reasons.append(f"{pname} is a known bulk file writer (score dampened)")

        return RansomwareAssessment(
            score=round(min(100.0, raw), 2),
            components={k: round(v, 3) for k, v in comps.items()},
            active=active,
            reasons=reasons,
            key=key,
            shadow_kind=shadow_kind,
            stats=st,
            capped=capped,
        )

    def _ancestry(self, event: NormalizedEvent, state: BehaviorState) -> float:
        risk = ancestry_risk(state.resolve_parent_name(event), event.process_name, event.executable_path)
        # walk up to 3 ancestors using the process table
        pid, depth = event.ppid, 0
        while pid is not None and depth < 3:
            info = state.proc_info.get(pid)
            if info is None:
                break
            parent_info = state.proc_info.get(info.ppid) if info.ppid is not None else None
            if parent_info is not None:
                risk = max(risk, 0.8 * ancestry_risk(parent_info.name, info.name, info.exe))
            risk = max(risk, 0.6 * path_risk(info.exe))
            pid, depth = info.ppid, depth + 1
        return min(1.0, risk)

    # ------------------------------------------------------------------ public outputs
    def score(self, event: NormalizedEvent, state: BehaviorState) -> DetectionResult:
        """Composite ransomware score as a DetectionResult (deterministic-evidence family)."""
        a = self.assess(event, state)
        return self.to_result(a)

    def to_result(self, a: RansomwareAssessment) -> DetectionResult:
        conf = 0.5 + 0.1 * len(a.active)
        return DetectionResult(
            family=ScoreFamily.DETERMINISTIC_EVIDENCE,
            score=a.score,
            confidence=min(0.95, conf) if a.score > 0 else 1.0,
            available=True,
            reasons=a.reasons[:8],
            details={
                "detector": "ransomware_composite",
                "components": a.components,
                "active_components": a.active,
                "capped_single_component": a.capped,
                "pid_key": str(a.key),
            },
        )

    def findings(
        self, event: NormalizedEvent, a: RansomwareAssessment, state: BehaviorState | None = None
    ) -> list[Finding]:
        cfg = self.cfg
        out: list[Finding] = []
        if a.shadow_kind and (
            state is None or state.should_alert(f"rw-shadow:{a.key}", cfg.alert_cooldown_sec)
        ):
            out.append(
                Finding(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.RANSOMWARE,
                    rule_id="RW-SHADOW-COPY-DESTRUCTION",
                    title="Backup / shadow-copy destruction command",
                    severity=Severity.HIGH,
                    score=65.0,
                    confidence=0.85,
                    mitre_techniques=["T1490"],
                    attack_stage=AttackStage.IMPACT,
                    details={
                        "pattern": a.shadow_kind,
                        "command_line": (event.command_line or "")[:500],
                        "note": "also used by legitimate admin tooling; decisive with file bursts",
                    },
                )
            )
        if a.score >= cfg.alert_score and a.active:
            band = "critical" if a.score >= cfg.critical_score else "alert"
            if state is None or state.should_alert(f"rw:{a.key}:{band}", cfg.alert_cooldown_sec):
                sev = (
                    Severity.CRITICAL
                    if a.score >= cfg.critical_score
                    else Severity.HIGH
                    if a.score >= 60
                    else Severity.MEDIUM
                )
                techniques = ["T1486"] + (["T1490"] if a.components.get("shadow_copy") else [])
                details: dict[str, Any] = {
                    "components": a.components,
                    "active_components": a.active,
                    "reasons": a.reasons,
                    "pid_key": str(a.key),
                }
                if a.stats is not None:
                    details["window"] = {
                        "creates": a.stats.creates,
                        "modifies": a.stats.modifies,
                        "renames": a.stats.renames,
                        "deletes": a.stats.deletes,
                        "ext_changes": a.stats.ext_changes,
                        "distinct_files": a.stats.distinct_files,
                        "window_sec": a.stats.window_sec,
                    }
                out.append(
                    Finding(
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.RANSOMWARE,
                        rule_id="RW-COMPOSITE",
                        title="Ransomware-like behavior (composite)",
                        severity=sev,
                        score=a.score,
                        confidence=min(0.95, 0.5 + 0.1 * len(a.active)),
                        mitre_techniques=techniques,
                        attack_stage=AttackStage.IMPACT,
                        details=details,
                    )
                )
        return out
