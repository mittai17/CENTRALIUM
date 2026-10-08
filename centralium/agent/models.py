"""Core data contracts for Centralium (Pydantic v2).

Everything that crosses a stage boundary in the pipeline is defined here.
Scores are always normalized to 0-100 (``Score100``) unless a field name says
otherwise (ML anomaly score / confidences are 0.0-1.0, as the spec requires).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Score100 = Annotated[float, Field(ge=0.0, le=100.0)]
Unit = Annotated[float, Field(ge=0.0, le=1.0)]


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- enums
class EventType(StrEnum):
    PROCESS_START = "process_start"
    PROCESS_EXIT = "process_exit"
    PROCESS_INJECT = "process_inject"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    DNS_QUERY = "dns_query"
    REGISTRY_CREATE = "registry_create"
    REGISTRY_MODIFY = "registry_modify"
    REGISTRY_DELETE = "registry_delete"
    PERSISTENCE = "persistence"
    AUTH = "auth"
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_FAIL = "auth_fail"
    PRIVILEGE_CHANGE = "privilege_change"
    PRIVILEGE_ELEVATION = "privilege_elevation"
    MODULE_LOAD = "module_load"
    SERVICE_CHANGE = "service_change"
    SCHEDULED_TASK = "scheduled_task"
    TAMPER = "tamper"
    OTHER = "other"


class OperatingMode(StrEnum):
    LEARNING = "LEARNING"  # baseline only, no destructive action
    PASSIVE = "PASSIVE"  # detect + alert
    ACTIVE = "ACTIVE"  # enforce configured policy
    PANIC = "PANIC"  # emergency aggressive response


class RiskBand(StrEnum):
    SAFE = "SAFE"  # 0-19
    LOW = "LOW"  # 20-39
    MEDIUM = "MEDIUM"  # 40-59
    HIGH = "HIGH"  # 60-79
    CRITICAL = "CRITICAL"  # 80-100


DEFAULT_BAND_LOWER_BOUNDS: dict[RiskBand, float] = {
    RiskBand.SAFE: 0,
    RiskBand.LOW: 20,
    RiskBand.MEDIUM: 40,
    RiskBand.HIGH: 60,
    RiskBand.CRITICAL: 80,
}


def risk_band_for(score: float, bounds: dict[RiskBand, float] | None = None) -> RiskBand:
    """Map a 0-100 score to a band using lower bounds (defaults: 0/20/40/60/80)."""
    b = bounds or DEFAULT_BAND_LOWER_BOUNDS
    band = RiskBand.SAFE
    for candidate in (RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL):
        if score >= b[candidate]:
            band = candidate
    return band


class ActionRecommendation(StrEnum):
    """What the LLM / risk engine may *recommend* (includes NONE)."""

    NONE = "NONE"
    ALERT = "ALERT"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    SNAPSHOT_PROTECT = "SNAPSHOT_PROTECT"


class ResponseAction(StrEnum):
    """Concrete actions the ResponseExecutor can perform (NONE is not an action)."""

    ALERT = "ALERT"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    SNAPSHOT_PROTECT = "SNAPSHOT_PROTECT"


DESTRUCTIVE_ACTIONS: frozenset[ResponseAction] = frozenset(
    {
        ResponseAction.BLOCK_CONNECTION,
        ResponseAction.SUSPEND_PROCESS,
        ResponseAction.TERMINATE_PROCESS,
        ResponseAction.QUARANTINE_FILE,
        ResponseAction.ISOLATE_ENDPOINT,
    }
)


class AttackStage(StrEnum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    UNKNOWN = "UNKNOWN"


class Verdict(StrEnum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingSource(StrEnum):
    HASH = "hash"
    IOC = "ioc"
    YARA = "yara"
    RULE = "rule"
    STATIC = "static"
    BEHAVIOR = "behavior"
    LOLBIN = "lolbin"
    PERSISTENCE = "persistence"
    RANSOMWARE = "ransomware"
    ML = "ml"
    GRAPH = "graph"
    NOVELTY = "novelty"
    AI = "ai"
    ALLOWLIST = "allowlist"
    SELF_PROTECTION = "self_protection"
    SIGMA = "sigma"
    APP_CONTROL = "app_control"
    POSTURE = "posture"


class ScoreFamily(StrEnum):
    """Score families A-H from the spec."""

    ML_ANOMALY = "A"
    ML_CLASSIFICATION = "B"
    DETERMINISTIC_EVIDENCE = "C"
    GRAPH_ATTACK_CHAIN = "D"
    THREAT_INTEL = "E"
    STATIC_MALWARE = "F"
    AI_ASSESSMENT = "G"
    FINAL_RISK = "H"


class ActionStatus(StrEnum):
    RECOMMENDED = "recommended"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"
    SIMULATED = "simulated"  # demo/test mode: validated but not performed


# --------------------------------------------------------------------------- events
class NormalizedEvent(BaseModel):
    """OCSF-inspired normalized telemetry event. All fields optional except identity."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    event_id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utcnow)
    event_type: EventType
    host_id: str = "localhost"
    user: str | None = None
    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    process_name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    hash_sha256: str | None = None
    signer: str | None = None
    file_path: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    domain: str | None = None
    protocol: str | None = None
    registry_key: str | None = None
    source: str = "unknown"  # auditd|ebpf|etw|eventlog|sysmon|psutil|replay|test
    confidence: Unit = 1.0
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hash_sha256")
    @classmethod
    def _sha256(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("hash_sha256 must be 64 hex characters")
        return v

    @field_validator("timestamp")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return v if v.tzinfo else v.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- findings
class Finding(BaseModel):
    """A single piece of evidence emitted by any stage."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=new_id)
    event_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    source: FindingSource
    rule_id: str
    title: str
    severity: Severity = Severity.INFO
    score: Score100 = 0.0  # evidence strength 0-100
    confidence: Unit = 1.0
    known_malicious: bool = False  # hash/IOC/YARA confirmed -> short-circuit, never to LLM
    mitre_techniques: list[str] = Field(default_factory=list)
    attack_stage: AttackStage | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """One score from family A-H, normalized to 0-100.

    ``confidence`` (0-1) lets the risk engine down-weight uncertain producers.
    ``available`` False means the producing stage did not run / failed; the risk
    engine must then exclude it (not count it as zero risk evidence).
    """

    model_config = ConfigDict(extra="forbid")

    family: ScoreFamily
    score: Score100 = 0.0
    confidence: Unit = 1.0
    available: bool = True
    reasons: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def unavailable(cls, family: ScoreFamily, reason: str = "") -> DetectionResult:
        return cls(
            family=family, score=0.0, confidence=0.0, available=False, reasons=[reason] if reason else []
        )


class MLResult(BaseModel):
    """Raw ML output exactly as the spec defines it."""

    model_config = ConfigDict(extra="forbid")

    anomaly_score: Unit = 0.0
    classification: str = "unknown"
    classification_confidence: Unit = 0.0
    top_features: list[tuple[str, float]] = Field(default_factory=list)
    model_version: str = "none"
    feature_version: str = "0"


class StaticAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    file_type: str = "unknown"  # pe|elf|script|other
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    score: Score100 = 0.0
    indicators: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class GraphSignal(BaseModel):
    """Output of GraphAdapter correlation for one event."""

    model_config = ConfigDict(extra="forbid")

    score: Score100 = 0.0
    attack_stage: AttackStage | None = None
    stage_confidence: Unit = 0.0
    chain: list[str] = Field(default_factory=list)  # human-readable ordered chain
    related_event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class NoveltyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_novel: bool = True
    novelty_score: Unit = 1.0  # 1.0 = never seen
    baseline_hits: int = 0
    reasons: list[str] = Field(default_factory=list)


class RAGDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    doc_id: str
    source: str  # mitre|rule|yara|lolbin|playbook|ransomware|persistence|incident|ti
    title: str
    text: str
    score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- AI verdict
class AIVerdict(BaseModel):
    """Strict LLM output contract. Anything not matching is rejected (extra=forbid)."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    severity: Severity
    confidence: Unit
    threat_type: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=4000)
    why_suspicious: list[str] = Field(default_factory=list, max_length=50)
    evidence: list[str] = Field(default_factory=list, max_length=100)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=50)
    attack_stage: AttackStage
    recommended_action: ActionRecommendation
    false_positive_indicators: list[str] = Field(default_factory=list, max_length=50)
    investigation_questions: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("mitre_techniques")
    @classmethod
    def _mitre(cls, v: list[str]) -> list[str]:
        import re

        pat = re.compile(r"^T\d{4}(\.\d{3})?$")
        out = []
        for t in v:
            t = t.strip().upper()
            if not pat.match(t):
                raise ValueError(f"invalid MITRE technique id: {t!r}")
            out.append(t)
        return out

    @field_validator("why_suspicious", "evidence", "false_positive_indicators", "investigation_questions")
    @classmethod
    def _strs(cls, v: list[str]) -> list[str]:
        return [s[:2000] for s in v]

    @model_validator(mode="after")
    def _consistency(self) -> AIVerdict:
        # A benign verdict must never carry an enforcement recommendation.
        if self.verdict == Verdict.BENIGN and self.recommended_action not in (
            ActionRecommendation.NONE,
            ActionRecommendation.ALERT,
        ):
            raise ValueError("BENIGN verdict cannot recommend an enforcement action")
        return self

    @classmethod
    def parse_llm_text(cls, text: str) -> AIVerdict:
        """Parse raw LLM text (tolerates ```json fences / leading prose). Raises ValueError."""
        import json

        s = text.strip()
        if s.startswith("```"):
            s = s.strip("`")
            if s.lower().startswith("json"):
                s = s[4:]
        start, end = s.find("{"), s.rfind("}")
        if start == -1 or end <= start:
            raise ValueError("no JSON object in LLM output")
        try:
            data = json.loads(s[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        return cls.model_validate(data)


class AIAnalysis(BaseModel):
    """Wrapper persisted per analysis: verdict (or unavailability) + provenance."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(default_factory=new_id)
    event_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    available: bool = True
    verdict: AIVerdict | None = None
    role: str = "threat_analyst"  # threat_analyst|malware_analyst|summarizer|hunter|...
    model_name: str = "none"
    latency_ms: float = 0.0
    rag_sources: list[str] = Field(default_factory=list)
    error: str | None = None


# --------------------------------------------------------------------------- risk/policy/response
class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    final_score: Score100
    band: RiskBand
    scores: dict[ScoreFamily, DetectionResult] = Field(default_factory=dict)
    weights_used: dict[str, float] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)  # e.g. "floor applied: known IOC"


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ResponseAction | None = None  # None -> nothing to do
    allowed: bool = False
    requires_approval: bool = False
    reason: str = ""
    mode: OperatingMode = OperatingMode.PASSIVE
    target: dict[str, Any] = Field(default_factory=dict)  # pid/path/ip/port, validated


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utcnow)
    action: ResponseAction
    status: ActionStatus
    target: dict[str, Any] = Field(default_factory=dict)
    detail: str = ""
    event_id: str | None = None
    incident_id: str | None = None


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(default_factory=new_id)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    host_id: str = "localhost"
    title: str
    status: str = "open"  # open|investigating|resolved|false_positive
    risk_score: Score100 = 0.0
    band: RiskBand = RiskBand.SAFE
    attack_stage: AttackStage | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    ai_analysis_id: str | None = None
    actions: list[str] = Field(default_factory=list)


class PipelineOutcome(BaseModel):
    """Everything the pipeline produced for one event (returned by Pipeline.process)."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    event_id: str
    findings: list[Finding] = Field(default_factory=list)
    scores: dict[ScoreFamily, DetectionResult] = Field(default_factory=dict)
    risk: RiskAssessment | None = None
    ai: AIAnalysis | None = None
    decision: PolicyDecision | None = None
    actions: list[ActionResult] = Field(default_factory=list)
    incident: Incident | None = None
    short_circuited: bool = False  # known-malicious: skipped ML/RAG/LLM
    allowlisted: bool = False  # allowlist hit: skipped ML/RAG/LLM, no response
    stages_reached: list[str] = Field(default_factory=list)
    stage_errors: dict[str, str] = Field(default_factory=dict)
    explainability: Any | None = None


# Alias for compatibility with phase specifications
PipelineOutput = PipelineOutcome
