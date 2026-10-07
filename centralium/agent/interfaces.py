"""Stage contracts for every pluggable Centralium component.

Parallel engineers implement these Protocols in their own subpackage and the
pipeline (``centralium.agent.pipeline``) consumes them by dependency injection.

Conventions (binding for all implementers):
* All methods are SYNCHRONOUS and must be thread-safe. The pipeline may call them
  from worker threads. Long work (LLM) must honour its own timeout.
* Stage methods must not mutate the ``NormalizedEvent`` they receive.
* Raising is allowed - the pipeline isolates failures per stage - but implementers
  should prefer returning an "unavailable"/empty result and logging.
* Scores are 0-100 (``Score100``) unless the model says otherwise.
* Nothing here may execute LLM-provided text. ``ResponseExecutor`` only accepts a
  validated ``PolicyDecision`` produced by the deterministic ``PolicyEngine``.
* ``@runtime_checkable`` is used so tests can ``isinstance``-check structure
  (method names only; signatures are checked by mypy).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    ActionResult,
    AIAnalysis,
    DetectionResult,
    Finding,
    GraphSignal,
    Incident,
    MLResult,
    NormalizedEvent,
    NoveltyResult,
    OperatingMode,
    PolicyDecision,
    RAGDocument,
    ResponseAction,
    RiskAssessment,
    ScoreFamily,
    StaticAnalysisResult,
)

EventSink = Callable[[NormalizedEvent], None]


# --------------------------------------------------------------------------- stage payloads
class BehaviorResult(BaseModel):
    """Output of the BehaviorEngine: numeric features for ML + deterministic findings
    (LOLBin/persistence/ransomware/etc.)."""

    model_config = ConfigDict(extra="forbid")

    features: dict[str, float] = Field(default_factory=dict)  # versioned feature vector
    feature_version: str = "0"
    findings: list[Finding] = Field(default_factory=list)
    ml_eligible: bool = True  # False -> pipeline will NOT send this event to ML


class IOCMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_type: str  # sha256|ip|domain|url
    value: str
    source: str
    threat_type: str = ""
    confidence: float = Field(default=1.0, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMRequest(BaseModel):
    """Structured evidence handed to the local LLM. Contains NO instructions from
    untrusted data beyond quoted evidence; the client must delimit/quote it."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    event: NormalizedEvent
    findings: list[Finding] = Field(default_factory=list)
    features: dict[str, float] = Field(default_factory=dict)
    ml: MLResult | None = None
    graph: GraphSignal | None = None
    novelty: NoveltyResult | None = None
    rag_docs: list[RAGDocument] = Field(default_factory=list)
    pre_risk: float = 0.0
    role: str = "threat_analyst"  # threat_analyst|malware_analyst|summarizer|hunter|...


class PolicyContext(BaseModel):
    """Everything the PolicyEngine may consider. ``ai`` is advisory only."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    event: NormalizedEvent
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment
    ai: AIAnalysis | None = None
    mode: OperatingMode = OperatingMode.PASSIVE
    demo_mode: bool = False
    test_mode: bool = False
    known_malicious: bool = False
    allowlisted: bool = False


class QuarantineRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quarantine_id: str
    original_path: str
    quarantine_path: str
    sha256: str
    timestamp: str
    reasons: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    restored: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)  # perms/owner/mtime preserved


class SyncItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queue_id: int
    dedup_key: str | None = None
    payload: dict[str, Any]
    attempts: int = 0


# --------------------------------------------------------------------------- stage protocols
@runtime_checkable
class Collector(Protocol):
    """OS telemetry source (auditd/eBPF/ETW/Sysmon/psutil/replay). Emits NormalizedEvents.

    ``start`` must return promptly (spawn own thread/task) and call ``sink`` for
    each event. ``sink`` may drop under back-pressure; collectors must not block
    forever on it. A collector whose OS facility is missing must report
    ``healthy() == False`` with a reason instead of raising at import time.
    """

    name: str
    platforms: tuple[str, ...]  # subset of ("linux", "windows")

    def start(self, sink: EventSink) -> None: ...
    def stop(self) -> None: ...
    def is_running(self) -> bool: ...
    def health(self) -> tuple[bool, str]: ...


@runtime_checkable
class Normalizer(Protocol):
    """Raw collector record (dict) -> NormalizedEvent. Must validate/canonicalize
    (paths, IPs, ports, hashes) and raise ``ValueError`` on unusable input."""

    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent: ...


@runtime_checkable
class EPPEngine(Protocol):
    """Fast deterministic prevention: SHA-256, IOC, allowlist/blocklist, process/path
    rules. Must be cheap (hot path, every event). Known-bad => Finding.known_malicious=True.
    Allowlisted => Finding(source=ALLOWLIST, score=0) and no known_malicious findings."""

    def inspect(self, event: NormalizedEvent) -> list[Finding]: ...


@runtime_checkable
class YaraScanner(Protocol):
    """YARA rule management + scanning. Rules carry rule_id/name/family/severity/source/
    version/enabled/metadata; ``validate_rules`` must compile without activating."""

    def scan_file(self, path: Path, event: NormalizedEvent) -> list[Finding]: ...
    def scan_bytes(self, data: bytes, event: NormalizedEvent) -> list[Finding]: ...
    def validate_rules(self, source_text: str) -> tuple[bool, str]: ...
    def reload(self) -> int: ...  # returns number of active rules


@runtime_checkable
class StaticAnalyzer(Protocol):
    """PE/ELF/script static analysis + entropy. Never executes the target."""

    def analyze(self, path: Path) -> StaticAnalysisResult: ...


@runtime_checkable
class BehaviorEngine(Protocol):
    """Stateful behavior/feature extraction (process/network/file/behavior/ransomware
    families), LOLBin/persistence/ransomware heuristics. Called for every event that
    survived EPP; it decides ``ml_eligible``."""

    def analyze(self, event: NormalizedEvent, findings: list[Finding]) -> BehaviorResult: ...


@runtime_checkable
class MLEngine(Protocol):
    """Isolation Forest (anomaly) + Random Forest (classification). Lazy-load models.
    Return ``None`` when no trained model is available (do NOT fabricate scores)."""

    model_version: str

    def predict(self, event: NormalizedEvent, behavior: BehaviorResult) -> MLResult | None: ...


@runtime_checkable
class GraphAdapter(Protocol):
    """Kuzu (replaceable) attack graph. ``ingest`` records nodes/edges and returns
    temporal correlation for the event. Batched writes are an implementation detail
    (``flush`` forces them)."""

    def ingest(self, event: NormalizedEvent, findings: list[Finding]) -> GraphSignal: ...
    def attach_incident(self, incident: Incident) -> None: ...
    def chain_for(self, event_id: str) -> list[str]: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...


@runtime_checkable
class NoveltyFilter(Protocol):
    """Baselines (process/user/parent-child/destination/frequency, signed-binary trust).
    LEARNING mode feeds ``learn``; ``assess`` says whether the event is novel."""

    def assess(self, event: NormalizedEvent, behavior: BehaviorResult) -> NoveltyResult: ...
    def learn(self, event: NormalizedEvent) -> None: ...


@runtime_checkable
class RAGRetriever(Protocol):
    """Top-k knowledge retrieval (MITRE, rules, LOLBin, playbooks...). Only invoked for
    gated high-risk events. Return [] when the index is unavailable."""

    def retrieve(self, query: str, k: int = 4) -> list[RAGDocument]: ...


@runtime_checkable
class LLMClient(Protocol):
    """The ONE local model (Gemma 3 1B IT Q4_K_M via llama.cpp). Must: validate output
    with ``AIVerdict``, retry once on invalid JSON, enforce timeout/concurrency/ctx/tokens,
    and return ``AIAnalysis(available=False, error=...)`` instead of raising when it fails."""

    def available(self) -> bool: ...
    def analyze(self, request: LLMRequest) -> AIAnalysis: ...
    def unload(self) -> None: ...


@runtime_checkable
class RiskEngine(Protocol):
    """Combine score families A-G into final risk (H). Weights come from
    ``config.risk``. Must exclude ``available=False`` families, scale AI by confidence,
    and floor known-malicious evidence (LLM can never lower it)."""

    def assess(
        self, scores: dict[ScoreFamily, DetectionResult], findings: list[Finding]
    ) -> RiskAssessment: ...


@runtime_checkable
class PolicyEngine(Protocol):
    """Deterministic gate: allowlists, protected processes, severity/confidence thresholds,
    action restrictions, approval mode, emergency isolation. AI recommendation is only
    an input. Output target fields must be validated (pid/path/ip/port)."""

    def decide(self, ctx: PolicyContext) -> PolicyDecision: ...


@runtime_checkable
class ResponseExecutor(Protocol):
    """Performs an already-approved action. Must re-validate targets, never use
    shell=True, protect critical processes, and must be a no-op simulation when
    constructed in demo/test mode."""

    def execute(self, decision: PolicyDecision, event: NormalizedEvent) -> ActionResult: ...
    def supported(self) -> frozenset[ResponseAction]: ...


@runtime_checkable
class QuarantineManager(Protocol):
    def quarantine(self, path: Path, reasons: list[str], sources: list[str]) -> QuarantineRecord: ...
    def restore(self, quarantine_id: str, *, authorized_by: str, reason: str) -> Path: ...
    def list(self) -> list[QuarantineRecord]: ...


@runtime_checkable
class ThreatIntelStore(Protocol):
    """Local IOC cache (feeds updated periodically, never per event)."""

    def match_hash(self, sha256: str) -> list[IOCMatch]: ...
    def match_ip(self, ip: str) -> list[IOCMatch]: ...
    def match_domain(self, domain: str) -> list[IOCMatch]: ...
    def update(self) -> int: ...  # returns number of IOCs added/updated; may no-op offline


@runtime_checkable
class SyncQueue(Protocol):
    """Durable outbound queue (retry, dedup, backoff, bounded retention). Never blocks detection."""

    def enqueue(self, payload: dict[str, Any], dedup_key: str | None = None) -> bool: ...
    def claim_batch(self, limit: int = 100) -> list[SyncItem]: ...
    def mark_delivered(self, queue_id: int) -> None: ...
    def mark_failed(self, queue_id: int, error: str) -> None: ...
    def pending(self) -> int: ...


@runtime_checkable
class SelfProtection(Protocol):
    """Integrity checks (executable/config/rules), watchdog, tamper findings."""

    def check(self) -> list[Finding]: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...


STAGE_PROTOCOLS: dict[str, type] = {
    "collector": Collector,
    "normalizer": Normalizer,
    "epp": EPPEngine,
    "yara": YaraScanner,
    "static": StaticAnalyzer,
    "behavior": BehaviorEngine,
    "ml": MLEngine,
    "graph": GraphAdapter,
    "novelty": NoveltyFilter,
    "rag": RAGRetriever,
    "llm": LLMClient,
    "risk": RiskEngine,
    "policy": PolicyEngine,
    "executor": ResponseExecutor,
    "quarantine": QuarantineManager,
    "threat_intel": ThreatIntelStore,
    "sync": SyncQueue,
    "self_protection": SelfProtection,
}
