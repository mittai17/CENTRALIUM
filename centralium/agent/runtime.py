"""Runtime assembly: wires every real Centralium module into one :class:`Pipeline`.

``build_runtime(config)`` is the single composition root used by the CLI (``run``, ``demo``,
``test-mode``), the end-to-end tests and the benchmark. Everything is injected; nothing here
adds detection logic.

Safety properties enforced at assembly time
* the response executor is created with ``simulate=True`` whenever ``config.demo_mode`` or
  ``config.test_mode`` is set (and the pipeline's destructive gate independently refuses);
* the LLM client is the real ``llama-server`` only when ``CENTRALIUM_LLM_SERVER_URL`` is set and
  reachable; a labelled :class:`MockLLM` is used *only* in demo/test mode (or when explicitly
  requested); in a live run an unreachable model means "AI unavailable" - never a silent mock;
* dashboard-approved response rows are executed only through ``ApprovedActionDispatcher``,
  which re-applies the hard destructive gate, the policy's allowed-action/protected-target
  checks and the executor's own validation (no shell anywhere).
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from centralium.agent.behavior import DefaultBehaviorEngine
from centralium.agent.config import CentraliumConfig, ModeManager
from centralium.agent.epp import EPPStack, build_epp_stack
from centralium.agent.graph import create_graph_adapter
from centralium.agent.graph.snapshot import graph_snapshot, write_graph_snapshot
from centralium.agent.interfaces import LLMClient
from centralium.agent.llm import MOCK_MODEL_NAME, MockLLM, build_llm_client
from centralium.agent.ml import create_ml_engine
from centralium.agent.models import (
    Finding,
    Incident,
    NormalizedEvent,
    OperatingMode,
)
from centralium.agent.normalization import EventNormalizer
from centralium.agent.novelty import BaselineNoveltyFilter
from centralium.agent.nulls import NullLLM
from centralium.agent.pipeline import ApprovedActionDispatcher, Pipeline
from centralium.agent.policy import RulesPolicyEngine
from centralium.agent.quarantine import FileQuarantineManager
from centralium.agent.rag import build_retriever
from centralium.agent.response import create_executor
from centralium.agent.risk import CalibratedRiskEngine
from centralium.agent.self_protection import SelfProtectionMonitor, SelfProtectionSettings
from centralium.agent.storage import Database, Repository
from centralium.agent.sync import DurableSyncQueue, HttpTransport, SyncWorker

log = logging.getLogger("centralium.runtime")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LLM_SERVER_URL_ENV = "CENTRALIUM_LLM_SERVER_URL"
SYNC_URL_ENV = "CENTRALIUM_SYNC_URL"


# --------------------------------------------------------------------------- path helpers
def resolve_project_path(p: Path) -> Path:
    """Relative asset dirs (rules/, rag/, ml/models) fall back to the repository root when the
    current working directory does not contain them (so the CLI works from anywhere)."""
    if p.is_absolute() or p.exists():
        return p
    alt = PROJECT_ROOT / p
    return alt if alt.exists() else p


# --------------------------------------------------------------------------- re-exports
# The graph snapshot and approval dispatcher logic are defined canonically in:
# - centralium.agent.graph.snapshot (graph_snapshot, write_graph_snapshot)
# - centralium.agent.pipeline (ApprovedActionDispatcher)
# They are re-exported here for CLI, tests, and backward compatibility.
__all__ = [
    "ApprovedActionDispatcher",
    "EventLoop",
    "Runtime",
    "build_runtime",
    "graph_snapshot",
    "load_persisted_mode",
    "set_mode_audited",
    "write_graph_snapshot",
]


# --------------------------------------------------------------------------- event loop
class EventLoop:
    """Bounded queue + worker threads between collectors and the pipeline.

    ``submit`` never blocks: when the queue is full the event is dropped and counted
    (back-pressure must never stall a collector or detection).
    """

    def __init__(self, pipeline: Pipeline, *, size: int, workers: int = 2) -> None:
        self.pipeline = pipeline
        self._q: queue.Queue[NormalizedEvent] = queue.Queue(maxsize=max(1, size))
        self._workers = max(1, workers)
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.submitted = 0
        self.dropped = 0
        self.processed = 0
        self._lock = threading.Lock()

    def submit(self, ev: NormalizedEvent) -> bool:
        try:
            self._q.put_nowait(ev)
        except queue.Full:
            with self._lock:
                self.dropped += 1
            return False
        with self._lock:
            self.submitted += 1
        return True

    def start(self) -> None:
        for i in range(self._workers):
            t = threading.Thread(target=self._work, name=f"pipeline-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def _work(self) -> None:
        while not (self._stop.is_set() and self._q.empty()):
            try:
                ev = self._q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self.pipeline.process(ev)
            except Exception:
                log.exception("pipeline.process raised (event dropped)")
            finally:
                with self._lock:
                    self.processed += 1
                self._q.task_done()

    def depth(self) -> int:
        return self._q.qsize()

    def drain(self, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self._q.unfinished_tasks == 0:
                return True
            time.sleep(0.02)
        return False

    def stop(self, drain_timeout: float = 10.0) -> None:
        self.drain(drain_timeout)
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []


# --------------------------------------------------------------------------- runtime
@dataclass
class Runtime:
    config: CentraliumConfig
    db: Database
    pipeline: Pipeline
    modes: ModeManager
    epp_stack: EPPStack
    ml: Any
    graph: Any
    rag: Any
    novelty: BaselineNoveltyFilter
    llm: LLMClient
    llm_kind: str  # llama-server | llama-cpp-python | mock | unavailable | disabled
    llm_label: str
    quarantine: FileQuarantineManager
    executor: Any
    policy: RulesPolicyEngine
    sync_queue: DurableSyncQueue
    sync_worker: SyncWorker | None
    selfprot: SelfProtectionMonitor | None
    approvals: ApprovedActionDispatcher
    loop: EventLoop | None = None
    notes: list[str] = field(default_factory=list)
    _started: bool = False
    _closed: bool = False
    _snap_thread: threading.Thread | None = None
    _snap_stop: threading.Event = field(default_factory=threading.Event)

    # ------------------------------------------------------------------ lifecycle
    def start_background(self, *, snapshot_interval_s: float = 15.0, workers: int = 2) -> None:
        if self._started:
            return
        self._started = True
        self.loop = EventLoop(
            self.pipeline, size=self.config.resource_profile.event_queue_size, workers=workers
        )
        self.loop.start()
        if self.selfprot is not None:
            self.selfprot.start()
        if self.sync_worker is not None:
            self.sync_worker.start()
        self.approvals.start()

        def snap() -> None:
            while not self._snap_stop.wait(snapshot_interval_s):
                try:
                    self.snapshot_graph()
                except Exception:
                    log.exception("graph snapshot failed")

        self._snap_thread = threading.Thread(target=snap, name="graph-snapshot", daemon=True)
        self._snap_thread.start()

    def snapshot_graph(self) -> int:
        return self.pipeline.snapshot_graph()

    def status(self) -> dict[str, Any]:
        s = self.pipeline.stats.snapshot()
        return {
            "mode": self.modes.mode.value,
            "demo_mode": self.config.demo_mode,
            "test_mode": self.config.test_mode,
            "destructive_allowed": self.config.destructive_allowed(self.modes.mode),
            "executor_simulate": bool(getattr(self.executor, "simulate", False)),
            "llm": {"kind": self.llm_kind, "label": self.llm_label},
            "ml_available": bool(self.ml.available()),
            "ml_model_version": self.ml.model_version,
            "graph_backend": type(self.graph).__name__,
            "rag": self.rag.info(),
            "sync_pending": self.sync_queue.pending(),
            "queue_depth": self.loop.depth() if self.loop else 0,
            "queue_dropped": self.loop.dropped if self.loop else 0,
            "funnel": s["funnel"],
            "errors": s["errors"],
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        steps: list[tuple[str, Callable[[], Any]]] = [
            ("event loop", lambda: self.loop.stop() if self.loop else None),
            ("approvals", self.approvals.stop),
            ("self-protection", lambda: self.selfprot.stop() if self.selfprot else None),
            ("sync worker", lambda: self.sync_worker.stop() if self.sync_worker else None),
            ("graph snapshot", self._stop_snapshots),
            ("pipeline", self.pipeline.close),
            ("graph", self.graph.close),
            ("novelty", self.novelty.close),
            ("rag", self.rag.close),
            ("llm", self.llm.unload),
            ("db", self.db.close),
        ]
        for name, fn in steps:
            try:
                fn()
            except Exception:
                log.exception("shutdown step failed: %s", name)

    def _stop_snapshots(self) -> None:
        self._snap_stop.set()
        if self._snap_thread is not None:
            self._snap_thread.join(timeout=5)
        try:
            self.snapshot_graph()
        except Exception:
            log.exception("final graph snapshot failed")

    def __enter__(self) -> Runtime:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- LLM selection
def select_llm(config: CentraliumConfig, llm_mode: str = "auto") -> tuple[LLMClient, str, str]:
    """Return (client, kind, human label). ``llm_mode``: auto | real | mock | off."""
    sandbox = config.demo_mode or config.test_mode
    if llm_mode == "off" or not (config.llm.enabled and config.resource_profile.llm_enabled):
        if llm_mode == "mock":
            return MockLLM(), "mock", MOCK_MODEL_NAME
        return NullLLM(), "disabled", "LLM disabled by configuration/profile"
    if llm_mode == "mock":
        return MockLLM(), "mock", MOCK_MODEL_NAME
    client = build_llm_client(config.llm)
    try:
        ok = client.available()
    except Exception:
        log.exception("LLM availability probe failed")
        ok = False
    if ok:
        backend = "llama-server" if os.environ.get(LLM_SERVER_URL_ENV) else "llama-cpp-python"
        return client, backend, client.model_name
    if llm_mode == "auto" and sandbox:
        return MockLLM(), "mock", MOCK_MODEL_NAME + " [fallback: real model unavailable]"
    reason = ""
    status = getattr(client, "status", None)
    if callable(status):
        reason = str(status().get("unavailable_reason") or status().get("error") or "")
    return client, "unavailable", f"local LLM unavailable {reason}".strip()


# --------------------------------------------------------------------------- composition root
def build_runtime(
    config: CentraliumConfig,
    *,
    llm_mode: str = "auto",
    llm: LLMClient | None = None,
    auto_install_models: bool | None = None,
    enable_self_protection: bool = True,
    enable_sync: bool = True,
    config_files: list[Path] | None = None,
    transport: Any | None = None,
    command_runner: Any | None = None,
    quarantine_users: list[str] | None = None,
    restore_mode: bool = True,
) -> Runtime:
    """Assemble all real modules. Safe to call offline; nothing touches the network."""
    cfg = config
    paths = cfg.paths
    assert paths.db_path is not None and paths.graph_dir is not None and paths.quarantine_dir is not None
    data_dir = Path(paths.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    sandbox = cfg.demo_mode or cfg.test_mode

    db = Database(paths.db_path)

    def audit_fn(actor: str, event_type: str, details: dict[str, Any]) -> None:
        db.audit.append(actor, event_type, details)

    modes = ModeManager(cfg, audit_fn)
    if not sandbox and restore_mode:
        persisted = load_persisted_mode(db)
        if persisted is not None and persisted != modes.mode:
            if persisted == OperatingMode.PANIC:
                notes.append(
                    "persisted PANIC mode is not restored automatically; starting in configured mode"
                )
            else:
                modes.set_mode(
                    persisted, actor="runtime", reason="restored operator-selected mode at startup"
                )
    profile = cfg.resource_profile
    rules_dir = resolve_project_path(paths.rules_dir)
    rag_dir = resolve_project_path(paths.rag_dir)
    models_dir = resolve_project_path(paths.models_dir)

    stack = build_epp_stack(db, rules_dir, max_scan_mb=profile.max_scan_file_mb, allow_network=False)
    behavior = DefaultBehaviorEngine()
    normalizer = EventNormalizer(cfg.host_id)

    install = sandbox if auto_install_models is None else auto_install_models
    ml = create_ml_engine(models_dir, auto_install=install, use_onnx=cfg.ml_use_onnx)
    if not ml.available():
        notes.append(f"ML models unavailable in {models_dir}: ML stage disabled (no scores fabricated)")

    graph = create_graph_adapter(paths.graph_dir / "kuzu", batch_size=profile.graph_batch_size)
    if type(graph).__name__ != "KuzuGraphAdapter":
        notes.append("Kuzu unavailable: using in-memory graph (not persisted)")

    novelty = BaselineNoveltyFilter(data_dir / "novelty.db")
    rag, rag_report = build_retriever(rag_dir, data_dir / "rag_index.db")
    log.info("RAG index: %s", rag_report)

    if llm is not None:
        llm_client, llm_kind, llm_label = llm, "injected", getattr(llm, "model_name", type(llm).__name__)
    else:
        llm_client, llm_kind, llm_label = select_llm(cfg, llm_mode)
    if llm_kind in ("mock", "unavailable", "disabled"):
        notes.append(f"LLM: {llm_kind} ({llm_label})")

    quarantine = FileQuarantineManager(
        paths.quarantine_dir,
        audit=audit_fn,
        authorized_users=quarantine_users if quarantine_users is not None else [getpass.getuser()],
        protected_paths=cfg.policy.protected_paths,
    )
    exec_kwargs: dict[str, Any] = {
        "quarantine": quarantine,
        "settings": cfg.policy,
        "audit": audit_fn,
        "simulate": sandbox,  # MUST: demo/test never perform real OS actions
    }
    if command_runner is not None:
        exec_kwargs["runner"] = command_runner
    executor = create_executor(**exec_kwargs)
    policy = RulesPolicyEngine(cfg.policy)
    risk = CalibratedRiskEngine(cfg.risk)

    sync_queue = DurableSyncQueue(data_dir / "sync_queue.db", audit=audit_fn)
    repo = Repository(db)

    def on_incident(inc: Incident) -> None:
        """Queue the incident (+ its events/findings) for dashboard sync. Never blocks detection."""
        try:
            sync_queue.enqueue(
                {"type": "incident", "data": inc.model_dump(mode="json")}, f"incident:{inc.incident_id}"
            )
            for evid in inc.event_ids[:20]:
                ev = repo.get_event(evid)
                if ev is not None:
                    sync_queue.enqueue({"type": "event", "data": ev.model_dump(mode="json")}, f"event:{evid}")
        except Exception:
            log.exception("could not queue incident for sync")

    pipeline = Pipeline(
        cfg,
        db=db,
        normalizer=normalizer,
        epp=stack.epp,
        yara=stack.yara,
        static=stack.static,
        behavior=behavior,
        ml=ml,
        graph=graph,
        novelty=novelty,
        rag=rag,
        llm=llm_client,
        risk=risk,
        policy=policy,
        executor=executor,
        threat_intel=stack.threat_intel,
        mode_manager=modes,
        on_incident=on_incident,
    )

    sync_worker: SyncWorker | None = None
    if enable_sync:
        tp = transport
        url = os.environ.get(SYNC_URL_ENV)
        if tp is None and url and not cfg.offline:
            try:
                tp = HttpTransport(url, host_id=cfg.host_id)
            except ValueError as exc:
                notes.append(f"sync disabled: {exc}")
        if tp is not None:
            sync_worker = SyncWorker(sync_queue, tp, enabled=lambda: not cfg.offline and cfg.sync_enabled)
        else:
            notes.append("sync: no transport configured (events queue locally; detection unaffected)")

    selfprot: SelfProtectionMonitor | None = None
    if enable_self_protection:
        sp_cfg = SelfProtectionSettings(
            package_root=PROJECT_ROOT / "centralium",
            baseline_path=data_dir / "selfprot_baseline.json",
            config_files=list(config_files or []),
            protected_dirs=[paths.quarantine_dir],
            host_id=cfg.host_id,
        )

        def tamper_sink(ev: NormalizedEvent, finding: Finding) -> None:
            pipeline.process(ev, extra_findings=[finding])

        selfprot = SelfProtectionMonitor(sp_cfg, finding_sink=tamper_sink, audit=audit_fn)
        if not sp_cfg.baseline_path.exists():
            selfprot.create_baseline(actor="runtime", reason="first start: initial integrity baseline")

    approvals = pipeline.approvals or ApprovedActionDispatcher(db, cfg, modes, policy, executor)
    return Runtime(
        config=cfg,
        db=db,
        pipeline=pipeline,
        modes=modes,
        epp_stack=stack,
        ml=ml,
        graph=graph,
        rag=rag,
        novelty=novelty,
        llm=llm_client,
        llm_kind=llm_kind,
        llm_label=str(llm_label),
        quarantine=quarantine,
        executor=executor,
        policy=policy,
        sync_queue=sync_queue,
        sync_worker=sync_worker,
        selfprot=selfprot,
        approvals=approvals,
        notes=notes,
    )


MODE_POLICY_ID = "operating_mode"


def load_persisted_mode(db: Database) -> OperatingMode | None:
    """The operator's last explicit (audited) mode choice, stored in the ``policies`` table."""
    row = db.query_one("SELECT body FROM policies WHERE policy_id = ?", (MODE_POLICY_ID,))
    if row is None:
        return None
    try:
        return OperatingMode(json.loads(row["body"])["mode"])
    except (ValueError, KeyError, TypeError):
        return None


def set_mode_audited(rt: Runtime, mode: OperatingMode, actor: str, reason: str) -> OperatingMode:
    """Explicit, audited, persisted mode change. ``ModeManager`` refuses an empty actor/reason and
    PANIC in demo/test mode; the choice is stored so the next start restores it (also audited)."""
    new = rt.modes.set_mode(mode, actor=actor, reason=reason)
    rt.db.insert(
        "policies",
        {
            "policy_id": MODE_POLICY_ID,
            "name": "Operating mode",
            "version": 1,
            "enabled": 1,
            "body": json.dumps({"mode": new.value, "actor": actor, "reason": reason}),
            "updated_at": Database.now(),
        },
        on_conflict="REPLACE",
    )
    return new
