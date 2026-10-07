"""BehaviorEngine implementation: features + LOLBin/persistence/ransomware findings + ML gating."""

from __future__ import annotations

import logging
import math
import os
import stat as statmod
import threading
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.behavior.features import (
    FEATURE_SCHEMA_VERSION,
    extract_features,
    lolbin_context,
)
from centralium.agent.behavior.state import FILE_EVENT_TYPES, BehaviorState
from centralium.agent.interfaces import BehaviorResult
from centralium.agent.lolbins.detector import LolbinDetector
from centralium.agent.models import EventType, Finding, FindingSource, NormalizedEvent
from centralium.agent.persistence.detector import PersistenceDetector
from centralium.agent.ransomware.scorer import RansomwareConfig, RansomwareScorer

log = logging.getLogger(__name__)


class BehaviorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_sec: float = Field(default=60.0, gt=0)
    lolbin_finding_threshold: float = Field(default=40.0, ge=0, le=100)
    ransomware: RansomwareConfig = Field(default_factory=RansomwareConfig)
    # --- ML gating (events NOT matching any criterion are never sent to ML)
    ml_rarity_threshold: float = 0.5
    ml_path_risk_threshold: float = 0.5
    ml_lolbin_score_threshold: float = 0.2  # 0..1 (lolbin context score / 100)
    ml_dns_entropy_threshold: float = 3.5
    ml_conn_burst_threshold: float = math.log1p(20)
    ml_ransomware_threshold: float = 0.15
    baseline_sample_every: int = Field(default=0, ge=0)  # 0 = off; N>0: also send every Nth ineligible event
    # --- optional file entropy sampling (reads up to N bytes of written files; default OFF)
    sample_file_entropy: bool = False
    entropy_sample_bytes: int = Field(default=65536, ge=256, le=4_194_304)
    entropy_max_file_mb: int = Field(default=512, ge=1)
    entropy_max_per_sec: int = Field(default=200, ge=1)


def bytes_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class DefaultBehaviorEngine:
    """Implements :class:`centralium.agent.interfaces.BehaviorEngine` (thread-safe)."""

    def __init__(self, config: BehaviorConfig | None = None, state: BehaviorState | None = None) -> None:
        self.config = config or BehaviorConfig()
        self.state = state or BehaviorState(
            window_sec=self.config.window_sec, file_window_sec=self.config.ransomware.window_sec
        )
        self.lolbins = LolbinDetector(self.config.lolbin_finding_threshold)
        self.persistence = PersistenceDetector()
        self.ransomware = RansomwareScorer(self.config.ransomware)
        self._lock = threading.Lock()
        self._sampled = 0
        self._sec = 0
        self._sec_n = 0
        self.counters = {"events": 0, "ml_eligible": 0, "findings": 0}

    # ------------------------------------------------------------------ BehaviorEngine
    def analyze(self, event: NormalizedEvent, findings: list[Finding]) -> BehaviorResult:
        entropy = self._sample_entropy(event) if self.config.sample_file_entropy else None
        with self.state.lock:
            self.state.observe(event, entropy=entropy)
            lb, lb_findings = self.lolbins.evaluate(event, lolbin_context(event, self.state))
            pers = self.persistence.evaluate(event)
            rw = self.ransomware.assess(event, self.state)
            rw_findings = self.ransomware.findings(event, rw, self.state)
            feats = extract_features(event, self.state, lolbin=lb, persistence=pers, ransomware=rw)
        new_findings = [*lb_findings, *pers, *rw_findings]
        eligible = self._ml_gate(event, feats, new_findings, findings)
        with self._lock:
            self.counters["events"] += 1
            self.counters["ml_eligible"] += int(eligible)
            self.counters["findings"] += len(new_findings)
        return BehaviorResult(
            features=feats,
            feature_version=FEATURE_SCHEMA_VERSION,
            findings=new_findings,
            ml_eligible=eligible,
        )

    # ------------------------------------------------------------------ gating
    def _ml_gate(
        self, event: NormalizedEvent, f: dict[str, float], new: list[Finding], epp: list[Finding]
    ) -> bool:
        """Only events with at least one anomaly-relevant signal reach the ML stage."""
        c = self.config
        et = event.event_type
        reasons = (
            any(x.score >= 20 for x in new)
            or any(x.source != FindingSource.ALLOWLIST and x.score > 0 for x in epp)
            or f["beh_injection"] > 0
            or (f["beh_priv_change"] > 0 and f["privilege_context"] > 0 and et == EventType.PRIVILEGE_CHANGE)
            or f["beh_persistence_mod"] > 0
            or f["beh_download_execute"] > 0
            or f["rw_composite_score"] >= c.ml_ransomware_threshold
            or f["rw_shadow_copy"] > 0
        )
        if not reasons:
            if et == EventType.PROCESS_START:
                reasons = (
                    f["beh_lolbin_context_score"] >= c.ml_lolbin_score_threshold
                    or f["beh_unusual_parent_child"] >= 0.5
                    or f["path_risk"] >= c.ml_path_risk_threshold
                    or (
                        f["proc_rarity"] >= c.ml_rarity_threshold
                        and f["parent_child_rarity"] >= c.ml_rarity_threshold
                        and f["exe_rarity"] >= c.ml_rarity_threshold
                        and f["unsigned"] > 0
                    )
                )
            elif et in {EventType.NETWORK_CONNECT, EventType.DNS_QUERY}:
                reasons = (
                    (
                        f["net_dest_rarity"] >= c.ml_rarity_threshold
                        and f["net_port_rarity"] >= c.ml_rarity_threshold
                    )
                    or f["net_dns_entropy"] >= c.ml_dns_entropy_threshold
                    or f["net_conn_burst"] >= c.ml_conn_burst_threshold
                    or f["net_ip_reputation"] >= 0.5
                    or f["beh_lolbin_context_score"] >= c.ml_lolbin_score_threshold
                )
            elif et in FILE_EVENT_TYPES:
                reasons = (
                    (f["file_exec_creation"] > 0 and f["file_suspicious_dir"] >= 0.5)
                    or f["rw_ext_mutation"] >= 0.5
                    or f["rw_entropy_increase"] >= 0.5
                )
            elif et in {
                EventType.SERVICE_CHANGE,
                EventType.SCHEDULED_TASK,
                EventType.PERSISTENCE,
                EventType.TAMPER,
            }:
                reasons = True
        if not reasons and c.baseline_sample_every:
            with self._lock:
                self._sampled += 1
                reasons = self._sampled % c.baseline_sample_every == 0
        return bool(reasons)

    # ------------------------------------------------------------------ entropy sampling
    def _sample_entropy(self, event: NormalizedEvent) -> float | None:
        if event.event_type not in {EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_RENAME}:
            return None
        meta: dict[str, Any] = event.raw_metadata or {}
        if "entropy" in meta or "entropy_after" in meta:
            return None
        path = event.file_path
        if not path or not os.path.isabs(path) or "\x00" in path:
            return None
        now = int(time.monotonic())
        with self._lock:
            if now != self._sec:
                self._sec, self._sec_n = now, 0
            if self._sec_n >= self.config.entropy_max_per_sec:
                return None
            self._sec_n += 1
        try:
            st = os.lstat(path)  # never follow symlinks
            if (
                not statmod.S_ISREG(st.st_mode)
                or st.st_size == 0
                or st.st_size > self.config.entropy_max_file_mb << 20
            ):
                return None
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags)
            try:
                data = os.read(fd, self.config.entropy_sample_bytes)
            finally:
                os.close(fd)
            return bytes_entropy(data)
        except OSError:
            return None
