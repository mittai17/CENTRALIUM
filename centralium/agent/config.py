"""Centralium configuration: plain Pydantic v2 + TOML file + environment overrides.

Precedence (lowest -> highest): defaults < TOML file < environment < explicit kwargs.
Environment variables: ``CENTRALIUM_<SECTION>__<FIELD>`` (e.g.
``CENTRALIUM_LLM__MAX_TOKENS=256``) or top-level ``CENTRALIUM_DEMO_MODE=1``.
JSON values are accepted for lists/dicts. No secrets live in config defaults.

Mode safety: ``ModeManager`` is the ONLY sanctioned way to change the operating
mode at runtime; every change is explicit, requires an actor + reason, and is
written to the audit log via an injected callback. Nothing switches mode silently.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Callable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from centralium.agent.models import (
    DEFAULT_BAND_LOWER_BOUNDS,
    OperatingMode,
    ResponseAction,
    RiskBand,
    ScoreFamily,
    risk_band_for,
)

ENV_PREFIX = "CENTRALIUM_"
CONFIG_PATH_ENV = "CENTRALIUM_CONFIG"

__all__ = [
    "DEFAULT_LLM_SERVER_URL",
    "ENV_PREFIX",
    "CentraliumConfig",
    "LLMSettings",
    "ModeChangeError",
    "ModeManager",
    "PathsSettings",
    "PolicySettings",
    "ResourceProfile",
    "ResourceProfileName",
    "RiskSettings",
    "load_config",
]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------------- risk
class RiskSettings(_Section):
    """Final-risk weights (spec baseline) and band thresholds. All tunable."""

    weight_behavioral_ml: float = Field(default=0.25, ge=0)
    weight_deterministic_evidence: float = Field(default=0.20, ge=0)
    weight_attack_graph: float = Field(default=0.20, ge=0)
    weight_threat_intel: float = Field(default=0.15, ge=0)
    weight_static_malware: float = Field(default=0.10, ge=0)
    weight_ai_assessment: float = Field(default=0.10, ge=0)
    # band lower bounds (inclusive)
    band_low: float = 20
    band_medium: float = 40
    band_high: float = 60
    band_critical: float = 80
    # calibration
    ai_min_confidence: float = Field(default=0.5, ge=0, le=1)  # below -> AI weight scaled down
    known_malicious_floor: float = Field(default=90.0, ge=0, le=100)  # IOC/YARA/hash hit floor
    normalize_weights: bool = True  # re-normalize over *available* families

    @model_validator(mode="after")
    def _check(self) -> RiskSettings:
        if not (0 <= self.band_low < self.band_medium < self.band_high < self.band_critical <= 100):
            raise ValueError("risk band thresholds must be strictly increasing within 0-100")
        if sum(self.weights().values()) <= 0:
            raise ValueError("at least one risk weight must be > 0")
        return self

    def weights(self) -> dict[str, float]:
        return {
            "behavioral_ml": self.weight_behavioral_ml,
            "deterministic_evidence": self.weight_deterministic_evidence,
            "attack_graph": self.weight_attack_graph,
            "threat_intel": self.weight_threat_intel,
            "static_malware": self.weight_static_malware,
            "ai_assessment": self.weight_ai_assessment,
        }

    def band_bounds(self) -> dict[RiskBand, float]:
        return {
            RiskBand.SAFE: DEFAULT_BAND_LOWER_BOUNDS[RiskBand.SAFE],
            RiskBand.LOW: self.band_low,
            RiskBand.MEDIUM: self.band_medium,
            RiskBand.HIGH: self.band_high,
            RiskBand.CRITICAL: self.band_critical,
        }

    def band_for(self, score: float) -> RiskBand:
        return risk_band_for(score, self.band_bounds())

    def weight_for_family(self, family: ScoreFamily) -> float:
        """Weight for a score family (A/B both feed behavioral_ml; H has none)."""
        mapping = {
            ScoreFamily.ML_ANOMALY: self.weight_behavioral_ml,
            ScoreFamily.ML_CLASSIFICATION: 0.0,  # folded into behavioral_ml by the RiskEngine
            ScoreFamily.DETERMINISTIC_EVIDENCE: self.weight_deterministic_evidence,
            ScoreFamily.GRAPH_ATTACK_CHAIN: self.weight_attack_graph,
            ScoreFamily.THREAT_INTEL: self.weight_threat_intel,
            ScoreFamily.STATIC_MALWARE: self.weight_static_malware,
            ScoreFamily.AI_ASSESSMENT: self.weight_ai_assessment,
            ScoreFamily.FINAL_RISK: 0.0,
        }
        return mapping[family]


# --------------------------------------------------------------------------- resource profiles
class ResourceProfileName(StrEnum):
    LOW_RESOURCE = "low-resource"
    BALANCED = "balanced"
    ANALYSIS = "analysis"


class ResourceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: ResourceProfileName
    max_events_per_sec: int  # telemetry rate cap (0 = unlimited)
    event_queue_size: int
    scan_depth: int  # 1 = hash/IOC only, 2 = +YARA/static, 3 = +deep static
    max_scan_file_mb: int
    graph_batch_size: int
    rag_top_k: int
    llm_enabled: bool
    llm_ctx: int
    llm_max_tokens: int
    llm_threads: int
    llm_idle_unload_sec: int  # 0 = never unload
    ml_enabled: bool = True


RESOURCE_PROFILES: dict[ResourceProfileName, ResourceProfile] = {
    ResourceProfileName.LOW_RESOURCE: ResourceProfile(
        name=ResourceProfileName.LOW_RESOURCE,
        max_events_per_sec=200,
        event_queue_size=2_000,
        scan_depth=1,
        max_scan_file_mb=16,
        graph_batch_size=200,
        rag_top_k=3,
        llm_enabled=False,
        llm_ctx=1024,
        llm_max_tokens=256,
        llm_threads=2,
        llm_idle_unload_sec=60,
    ),
    ResourceProfileName.BALANCED: ResourceProfile(
        name=ResourceProfileName.BALANCED,
        max_events_per_sec=2_000,
        event_queue_size=10_000,
        scan_depth=2,
        max_scan_file_mb=64,
        graph_batch_size=500,
        rag_top_k=4,
        llm_enabled=True,
        llm_ctx=2048,
        llm_max_tokens=384,
        llm_threads=4,
        llm_idle_unload_sec=300,
    ),
    ResourceProfileName.ANALYSIS: ResourceProfile(
        name=ResourceProfileName.ANALYSIS,
        max_events_per_sec=0,
        event_queue_size=50_000,
        scan_depth=3,
        max_scan_file_mb=256,
        graph_batch_size=1_000,
        rag_top_k=5,
        llm_enabled=True,
        llm_ctx=4096,
        llm_max_tokens=512,
        llm_threads=8,
        llm_idle_unload_sec=0,
    ),
}


DEFAULT_LLM_SERVER_URL: str = "http://127.0.0.1:8080"
SERVER_URL_ENV = "CENTRALIUM_LLM_SERVER_URL"


# --------------------------------------------------------------------------- LLM
class LLMSettings(_Section):
    """ONE local model (Gemma 3 1B IT Q4_K_M via llama.cpp). No cloud endpoints exist here."""

    enabled: bool = True
    model_name: str = "gemma-3-1b-it-Q4_K_M"
    model_path: Path | None = None  # *.gguf; None -> LLM unavailable (graceful)
    server_url: str = Field(
        default_factory=lambda: os.environ.get(SERVER_URL_ENV, DEFAULT_LLM_SERVER_URL)
    )
    max_ctx: int = Field(default=2048, ge=256, le=32768)
    max_tokens: int = Field(default=384, ge=16, le=4096)
    timeout_sec: float = Field(default=60.0, gt=0, le=600)
    concurrency: int = Field(default=1, ge=1, le=4)
    threads: int = Field(default=4, ge=1, le=256)
    gpu_layers: int = Field(default=0, ge=0)
    idle_unload_sec: int = Field(default=300, ge=0)
    temperature: float = Field(default=0.1, ge=0, le=2)
    retries_on_invalid_json: int = Field(default=1, ge=0, le=3)  # spec: retry once
    # Gatekeeping: only high-risk AND novel events reach the LLM.
    gate_min_pre_risk: float = Field(default=60.0, ge=0, le=100)
    gate_require_novel: bool = True


# --------------------------------------------------------------------------- paths
class PathsSettings(_Section):
    data_dir: Path = Path("data")
    db_path: Path | None = None
    graph_dir: Path | None = None
    quarantine_dir: Path | None = None
    models_dir: Path = Path("ml/models")
    rules_dir: Path = Path("rules")
    rag_dir: Path = Path("rag")
    log_dir: Path | None = None

    def resolved(self) -> PathsSettings:
        d = self.data_dir
        return self.model_copy(
            update={
                "db_path": self.db_path or d / "centralium.db",
                "graph_dir": self.graph_dir or d / "graph",
                "quarantine_dir": self.quarantine_dir or d / "quarantine",
                "log_dir": self.log_dir or d / "logs",
            }
        )


# --------------------------------------------------------------------------- policy
class PolicySettings(_Section):
    require_approval: bool = True  # user-approval mode for destructive actions
    min_confidence_destructive: float = Field(default=0.7, ge=0, le=1)
    min_risk_destructive: float = Field(default=80.0, ge=0, le=100)
    passive_destructive_allowed: bool = False  # PASSIVE: "unless configured"
    panic_isolation_allowed: bool = True
    allowed_actions: list[ResponseAction] = Field(default_factory=lambda: list(ResponseAction))
    protected_processes: list[str] = Field(
        default_factory=lambda: [
            "systemd",
            "init",
            "sshd",
            "dbus-daemon",
            "NetworkManager",
            "centralium",
            "System",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
        ]
    )
    protected_paths: list[str] = Field(
        default_factory=lambda: [
            "/boot",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/lib",
            "/etc",
            "C:\\Windows\\System32",
        ]
    )


# --------------------------------------------------------------------------- root
class CentraliumConfig(_Section):
    host_id: str = "localhost"
    mode: OperatingMode = OperatingMode.PASSIVE
    profile: ResourceProfileName = ResourceProfileName.BALANCED
    demo_mode: bool = False  # forces destructive response disabled
    test_mode: bool = False  # isolated: simulated OS actions, temp data dirs
    log_level: str = "INFO"
    offline: bool = False  # force-disable all network/sync
    sync_enabled: bool = False
    risk: RiskSettings = Field(default_factory=RiskSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    paths: PathsSettings = Field(default_factory=PathsSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    ml_use_onnx: bool = False  # use ONNX Runtime inference if available

    @field_validator("log_level")
    @classmethod
    def _lvl(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid log_level")
        return v

    @model_validator(mode="after")
    def _finalize(self) -> CentraliumConfig:
        object.__setattr__(self, "paths", self.paths.resolved())
        return self

    # -- derived helpers (stable API for other modules)
    @property
    def resource_profile(self) -> ResourceProfile:
        return RESOURCE_PROFILES[self.profile]

    def destructive_allowed(self, mode: OperatingMode | None = None) -> bool:
        """Hard gate. demo_mode/test_mode and LEARNING mode can never run real destructive
        actions. Pass the *live* mode (ModeManager.mode); defaults to the configured one."""
        m = mode or self.mode
        if self.demo_mode or self.test_mode:
            return False
        return m in (OperatingMode.ACTIVE, OperatingMode.PANIC) or (
            m == OperatingMode.PASSIVE and self.policy.passive_destructive_allowed
        )

    @property
    def destructive_response_enabled(self) -> bool:
        return self.destructive_allowed()

    @property
    def llm_effective_enabled(self) -> bool:
        return (
            self.llm.enabled
            and self.resource_profile.llm_enabled
            and (self.llm.model_path is not None or bool(self.llm.server_url))
        )

    def apply_resource_profile(self) -> CentraliumConfig:
        """Return a copy whose LLM ctx/tokens/threads/idle-unload follow the profile
        (explicit overrides must be applied *after* calling this)."""
        p = self.resource_profile
        llm = self.llm.model_copy(
            update={
                "max_ctx": p.llm_ctx,
                "max_tokens": p.llm_max_tokens,
                "threads": p.llm_threads,
                "idle_unload_sec": p.llm_idle_unload_sec,
            }
        )
        return self.model_copy(update={"llm": llm})


# --------------------------------------------------------------------------- loading
def _deep_merge(base: dict[str, Any], over: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce_env(value: str) -> Any:
    s = value.strip()
    low = s.lower()
    if low in {"1", "true", "yes", "on"}:
        return True
    if low in {"0", "false", "no", "off"}:
        return False
    if s[:1] in '[{"':
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
    return s  # pydantic coerces numerics/enums/paths from str


def _env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, raw in env.items():
        if not key.startswith(ENV_PREFIX) or key == CONFIG_PATH_ENV:
            continue
        parts = key[len(ENV_PREFIX) :].lower().split("__")
        if len(parts) == 1 and parts[0] not in CentraliumConfig.model_fields:
            # Single-token CENTRALIUM_* variables that are not config fields belong to other modules
            # (CENTRALIUM_LLM_SERVER_URL, CENTRALIUM_SYNC_URL, CENTRALIUM_SYNC_TOKEN, ...): not config.
            continue
        cur = out
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = _coerce_env(raw)
    return out


def load_config(
    path: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    **overrides: Any,
) -> CentraliumConfig:
    """Load config: defaults < TOML (path or $CENTRALIUM_CONFIG) < env < kwargs.

    Raises ``ValueError`` (pydantic ValidationError subclass) on invalid input and
    ``FileNotFoundError`` if an explicitly given path does not exist.
    """
    environ = os.environ if env is None else env
    data: dict[str, Any] = {}
    cfg_path = path or environ.get(CONFIG_PATH_ENV)
    if cfg_path:
        p = Path(cfg_path)
        with p.open("rb") as fh:
            data = tomllib.load(fh)
    data = _deep_merge(data, _env_overrides(environ))
    data = _deep_merge(data, overrides)
    return CentraliumConfig.model_validate(data)


# --------------------------------------------------------------------------- mode manager
class ModeChangeError(RuntimeError):
    pass


AuditFn = Callable[[str, str, dict[str, Any]], None]  # (actor, event_type, details)


class ModeManager:
    """Single owner of the runtime operating mode. Never switches implicitly.

    ``audit`` is called for every change (and every refused change). Wire it to
    ``Database.audit.append`` so mode changes land in the hash-chained audit log.
    """

    def __init__(self, config: CentraliumConfig, audit: AuditFn | None = None) -> None:
        self._config = config
        self._audit = audit
        self._mode = config.mode

    @property
    def mode(self) -> OperatingMode:
        return self._mode

    def set_mode(self, new_mode: OperatingMode, *, actor: str, reason: str) -> OperatingMode:
        if not actor.strip() or not reason.strip():
            raise ModeChangeError("mode change requires non-empty actor and reason")
        new_mode = OperatingMode(new_mode)
        old = self._mode
        details = {"from": old.value, "to": new_mode.value, "reason": reason}
        if (self._config.demo_mode or self._config.test_mode) and new_mode == OperatingMode.PANIC:
            self._emit(actor, "mode_change_refused", {**details, "why": "demo/test mode"})
            raise ModeChangeError("PANIC mode is not permitted in demo/test mode")
        if new_mode == old:
            return old
        self._mode = new_mode
        self._emit(actor, "mode_change", details)
        return new_mode

    def _emit(self, actor: str, event_type: str, details: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit(actor, event_type, details)
