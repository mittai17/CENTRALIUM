# Centralium Architecture (foundation contracts)

This document is the binding contract for parallel module engineers. Code against
`centralium/agent/interfaces.py` and `centralium/agent/models.py`; do not change those files
without telling the foundation owner (additive changes only).

## Pipeline (centralium/agent/pipeline.py)

```
raw -> normalize -> fast EPP (+YARA/static, scan_depth>=2) -> behavior features -> ML
    -> graph -> novelty -> [pre-risk] -> (gate) RAG -> LLM -> risk -> policy -> response -> audit
```

* Entry points: `Pipeline.process(NormalizedEvent) -> PipelineOutcome`, `Pipeline.process_raw(dict)`.
* Synchronous and thread-safe; run it in worker threads (collector -> bounded queue -> workers).
* **Dependency injection**: every stage is a constructor kwarg; omitted ones default to the safe
  null implementations in `centralium/agent/nulls.py` (never fabricate scores, never enforce).
* **Failure isolation**: each stage runs inside `_stage()`; exceptions are logged, counted
  (`stats.errors[stage]`), stored in `PipelineOutcome.stage_errors`, and the stage's output is
  treated as *unavailable* (a missing score family is excluded from risk, not counted as 0).
* **Known-malware short-circuit**: any `Finding.known_malicious=True` skips behavior/ML/novelty/RAG/LLM.
  Known malware is never sent to the LLM. Graph ingest still records the event.
* **Allowlist**: a `Finding(source=ALLOWLIST)` (with no known-malicious finding) skips ML/RAG/LLM.
* **LLM gatekeeping**: RAG+LLM only if not short-circuited/allowlisted, mode != LEARNING,
  `pre_risk >= config.llm.gate_min_pre_risk` (60), novel (if `gate_require_novel`), and `llm.available()`.
* **ML gating**: only when `BehaviorResult.ml_eligible` (the BehaviorEngine decides).
* **Hard destructive gate** (pipeline-level, independent of policy): non-ALERT actions reach the
  executor only if `config.destructive_allowed(live_mode)` (false in demo/test/LEARNING; PASSIVE only
  if `policy.passive_destructive_allowed`) and `decision.requires_approval` is false. Otherwise the
  result is recorded as `SIMULATED` / `PENDING_APPROVAL`.
* **Metrics**: `pipeline.stats.snapshot()` -> `funnel` {raw, epp, ml, graph, llm, incidents},
  `counters` (short_circuited, allowlisted, rag, actions), per-stage latency (mean/p50/p95/max ms,
  incl. `end_to_end`) and `errors`. All measured at runtime.
* Incident rule: known-malicious OR final band HIGH/CRITICAL. (Grouping events into one incident is
  not done yet -> graph/incident owner.)

### Score families (A-H) produced by the pipeline
| Family | Producer in pipeline |
|---|---|
| A ML anomaly | `MLResult.anomaly_score*100` |
| B ML classification | `classification_confidence*100` (0 if benign/normal/unknown class) |
| C deterministic evidence | noisy-OR of findings from RULE/BEHAVIOR/LOLBIN/PERSISTENCE/RANSOMWARE/SELF_PROTECTION/IOC/HASH |
| D graph/attack chain | `GraphSignal.score` |
| E threat intel | 100 if known-malicious IOC/HASH finding else max IOC/HASH finding score |
| F static malware | max(StaticAnalysisResult.score, YARA findings) |
| G AI assessment | severity map (INFO5/LOW25/MED50/HIGH75/CRIT95; BENIGN<=10, UNKNOWN<=40), confidence=verdict.confidence |
| H final risk | `RiskEngine.assess` |

`ReferenceRiskEngine` (nulls.py) implements the spec formula, re-normalized over *available* weights,
merges A/B into `behavioral_ml = max(A,B)`, scales AI by confidence (halved below
`ai_min_confidence`), never lets AI lower non-AI risk, and floors known-malicious at 90. The risk owner
may replace it; known issue to tune: re-normalization means one strong family alone yields a middling
score unless other families corroborate (see calibration notes in tests).

## Config (centralium/agent/config.py)
Defaults < TOML (`--config` / `$CENTRALIUM_CONFIG`) < env (`CENTRALIUM_<SECTION>__<FIELD>`) < kwargs.
`ModeManager.set_mode(mode, actor=, reason=)` is the only way to change `OperatingMode`; every change
(and refused change) goes to the audit log; PANIC is refused in demo/test mode.
Profiles: `low-resource` (LLM off, scan depth 1), `balanced`, `analysis` (see `RESOURCE_PROFILES`).

## Storage (centralium/agent/storage/)
* `Database(path)` SQLite WAL, one RLock-guarded connection, `transaction()` context manager,
  `insert(table,row)` validates identifiers against the schema; **values always bound parameters**.
* Migrations: append to `schema.MIGRATIONS` (never edit old ones); `PRAGMA user_version` tracks version.
* `Repository(db)` typed helpers (events, findings, incidents, ML/AI results, actions, allow/block
  lists, IOC cache, minimal sync enqueue). Use it, don't scatter SQL.
* `db.audit` hash-chained log: `append(actor, event_type, details)`, `verify(expected_head=None)`.
  Detects modification, deletion, reorder. Tail truncation / full-chain rewrite are only detected
  against an externally anchored head hash (export `audit.head()` periodically).

## Module ownership map

| Package | Implements (interface) | Notes |
|---|---|---|
| `agent/collectors/linux`, `collectors/windows` | `Collector` | auditd/eBPF/psutil; ETW/EventLog/Sysmon; replay collector for demo |
| `agent/normalization` | `Normalizer` | raw -> `NormalizedEvent`; validate paths/IPs/ports |
| `agent/epp` | `EPPEngine` | hash/IOC/allowlist/blocklist/path rules; emits ALLOWLIST findings |
| `agent/yara` | `YaraScanner` | rule registry (rule_id,name,family,severity,source,version,enabled,metadata) |
| `agent/malware_analysis` | `StaticAnalyzer` | PE/ELF/entropy |
| `agent/behavior`, `lolbins`, `persistence`, `ransomware` | `BehaviorEngine` | features + deterministic findings |
| `agent/ml`, `ml/*` | `MLEngine` | IsolationForest + RandomForest, ONNX optional |
| `agent/graph` | `GraphAdapter` | Kuzu behind adapter |
| `agent/novelty` | `NoveltyFilter` | baselines, signed-binary trust |
| `agent/rag`, `rag/*` | `RAGRetriever` | sqlite-vec / vector-store abstraction |
| `agent/llm` | `LLMClient` | llama.cpp + Gemma 3 1B; strict `AIVerdict`; retry once |
| `agent/risk` | `RiskEngine` | replaces `ReferenceRiskEngine` |
| `agent/policy` | `PolicyEngine` | deterministic gate; AI is advisory |
| `agent/response`, `quarantine` | `ResponseExecutor`, `QuarantineManager` | no shell=True, protected processes |
| `agent/threat_intel` | `ThreatIntelStore` | local IOC cache; feeds updated periodically |
| `agent/sync` | `SyncQueue` | uses `sync_queue` table |
| `agent/self_protection` | `SelfProtection` | integrity, watchdog, tamper findings |
| `agent/main.py` | CLI (Typer) | add sub-apps; `demo` command stub exists |
| `dashboard/backend`, `dashboard/frontend` | FastAPI / React+TS | read via `Repository` |
| `tests/*` | - | unit/integration/e2e/ml/performance/security |

## Rules for implementers
1. Return unavailable/empty rather than fabricating scores. `MLEngine.predict` returns `None` w/o a model.
2. Never execute LLM output. LLM -> `AIVerdict` -> PolicyEngine -> validated `PolicyDecision` -> executor.
3. No `shell=True`; validate every pid/path/IP/port again inside the executor.
4. Optional deps (yara, kuzu, pefile, pyelftools, sqlite-vec, onnxruntime, llama.cpp) must import lazily
   and degrade gracefully (the engine must run without any of them).
5. Add tests under `tests/<area>`; keep `ruff check .`, `mypy`, `pytest` green.
