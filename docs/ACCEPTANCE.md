# Centralium Acceptance Matrix & Verification Report

This document tracks and exhaustively verifies the acceptance criteria defined in the Centralium Master Build Specification (`/home/mittai/Downloads/Centralium_Claude_Master_Build_Prompt.txt`).

Every capability is evaluated with uncompromising engineering honesty. No feature is marked `PASS` unless verified with passing automated test suites, hardware-calibrated benchmarks, or live CLI demonstrations in this environment.

---

## 1. Summary of Acceptance Criteria

Across the **41 core acceptance criteria** defined in the master prompt:
- **PASS**: 39 items
- **PARTIAL**: 2 items
- **NOT VERIFIED**: 0 items

| Category | Total Criteria | PASS | PARTIAL | NOT VERIFIED |
|---|---|---|---|---|
| **Core Architecture & Telemetry** | 6 | 4 | 2 | 0 |
| **Deterministic EPP & Static Detection** | 6 | 6 | 0 | 0 |
| **Specialized Behavioral Detectors** | 4 | 4 | 0 | 0 |
| **Machine Learning & Risk Engine** | 4 | 4 | 0 | 0 |
| **Attack Graph & Novelty Filtering** | 1 | 1 | 0 | 0 |
| **Local RAG & Local LLM** | 4 | 4 | 0 | 0 |
| **Policy Engine & Response Automation** | 2 | 2 | 0 | 0 |
| **Resilience, Self-Protection & Audit** | 3 | 3 | 0 | 0 |
| **SOC Dashboard & User Interface** | 2 | 2 | 0 | 0 |
| **Quality Gates, Safety & Verification** | 9 | 9 | 0 | 0 |
| **Total** | **41** | **39** | **2** | **0** |

---

## 2. Detailed Verification by Specification Criterion

### 2.1 Core Architecture & Telemetry

#### 1. [PASS] Linux collector works
- **Requirement**: Master Spec lines 139–143. Real Linux endpoint telemetry via auditd netlink or psutil process/network polling.
- **Implementation**:
  - `centralium/agent/collectors/linux/psutil_collector.py`: Polling daemon with process table diffing, rate limiting, and parent tracking.
  - `centralium/agent/collectors/linux/auditd_collector.py`: Parser for netlink audit records (`EXECVE`, `PROCTITLE`, `SYSCALL`).
- **Verification Evidence**:
  - `tests/unit/test_collectors.py::test_psutil_collector_emits_valid_events` (PASS)
  - `tests/integration/test_behavior_collectors_pipeline.py` (PASS)
  - Live execution verified via `centralium run --mode PASSIVE --duration 3`: successfully initialized psutil collector, detected file modifications via self-protection engine, processed 9 raw/EPP/ML/graph events, and cleanly exited upon duration completion.
- **Honest Limitations**: Live `AuditdCollector` netlink binding requires root privileges. When run non-root, it gracefully falls back to `PsutilCollector`.

#### 2. [PARTIAL] Windows collector works or has documented safe fallback
- **Requirement**: Master Spec lines 144–149. Windows telemetry via ETW, Event Log, Sysmon, or documented safe fallback.
- **Implementation**:
  - `centralium/agent/collectors/windows/eventlog.py`: `EventLogCollector` parses XML logs (`wevtutil.exe qe` or mock runner) into `NormalizedEvent`.
  - `centralium/agent/collectors/windows/etw_stub.py`: Structured ETW collector stub with documented fallback.
  - `.github/workflows/ci.yml`: GitHub Actions matrix CI testing `windows-latest` alongside `ubuntu-latest` on Python 3.13 with ruff, mypy, and Windows-guarded pytest.
  - `tests/unit/test_windows_platform.py`: Tests Windows Sysmon XML parsing, `wevtutil` query construction, `netsh` firewall argv, and Windows service wrapper imports.
- **Verification Evidence**:
  - `tests/unit/test_windows_collectors.py::test_eventlog_collector_parses_sysmon_xml` (PASS)
  - `tests/unit/test_windows_collectors.py::test_windows_collector_fallback_on_linux` (PASS)
  - `tests/unit/test_windows_platform.py` (PASS — all 5 test cases pass)
- **Honest Limitations**: **Never run on a physical production Windows host**. Windows collectors are verified via GitHub Actions CI (`windows-latest`), unit tests with mock command runners, and synthetic Sysmon XML fixtures. Real physical Windows deployment remains unverified.

#### 3. [PASS] normalized event schema works
- **Requirement**: Master Spec lines 150–162. Common OCSF-inspired schema with typed normalization and strict field validation.
- **Implementation**:
  - `centralium/agent/models/events.py`: `NormalizedEvent` Pydantic model with fields for `event_type`, `pid`, `ppid`, `process_name`, `command_line`, `hashes`, `destination_ip`, `file_path`, etc.
  - `centralium/agent/normalization/engine.py`: Normalizes raw auditd, psutil, and Sysmon dicts; validates and sanitizes IPs, ports, and paths.
- **Verification Evidence**:
  - `tests/unit/test_normalization.py` (PASS)
  - Benchmark latency: `0.0775 ms` mean normalization per event (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Path normalization handles POSIX and Windows delimiters, but UNC path edge cases rely on regex cleaning.

#### 4. [PASS] SQLite WAL works
- **Requirement**: Master Spec lines 163–166. SQLite with WAL mode, normalized tables, indexed queries, and bounded retention.
- **Implementation**:
  - `centralium/agent/storage/database.py`: Enforces `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;`.
  - `centralium/agent/storage/schema.py`: Versioned migrations tracked via `PRAGMA user_version`.
- **Verification Evidence**:
  - `tests/unit/test_storage.py::test_wal_mode_enabled` (PASS)
  - `tests/unit/test_storage.py::test_concurrent_reads_and_writes` (PASS)
  - Queue operations benchmark: 47,990 enqueues/sec and 59,758 claims+acks/sec under SQLite WAL.
- **Honest Limitations**: Single-writer constraint handled via Python `threading.RLock` and SQLite busy handler.

#### 5. [PASS] local event queue works
- **Requirement**: Master Spec lines 614–627. Durable local SQLite WAL queue with exponential retry backoff, deduplication, and size caps.
- **Implementation**:
  - `centralium/agent/sync/queue.py`: `DurableSyncQueue` supporting enqueue, claim, acknowledge, exponential backoff, and size-capped retention.
- **Verification Evidence**:
  - `tests/e2e/test_acceptance_extras.py::test_offline_queue_persists_across_agent_restarts` (PASS)
  - `tests/integration/test_sync_worker.py` (PASS)
  - Measured enqueue rate: 47,990 items/s; claim+ack rate: 59,758 items/s (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Large backlogs are capped at configured `max_queue_size` (e.g. 10,000 items), dropping oldest delivered items first.

#### 6. [PARTIAL] network isolation works
- **Requirement**: Master Spec lines 404–433. Host network isolation and per-connection blocking on Linux (`iptables`/`nftables`) and Windows (`netsh`).
- **Implementation**:
  - `centralium/agent/response/network.py`: Generates validated CLI argument arrays for `nftables`, `iptables`, and `netsh advfirewall`.
  - `docker/`: Isolated container / network namespace test harness (`Dockerfile.auditd_nftables`, `run_container_tests.sh`, `test_container_live.py`).
- **Verification Evidence**:
  - `tests/unit/test_response.py::test_network_block_command_generation` (PASS)
  - `tests/e2e/test_acceptance_extras.py::test_network_block_execution_uses_safe_runner` (PASS)
  - Live execution verified in unshared network namespace (`unshare -rn ./docker/run_container_tests.sh`):
    - Live `iptables` chain creation and DROP rule verification: REAL execution (PASS).
    - Live `nftables` table, chain, and rule creation: REAL execution (PASS).
    - Live `auditd` log tailing and JSON normalization: REAL execution (PASS).
    - Test report saved to `docker/container_verification_report.json`.
- **Honest Limitations**: In normal test/demo modes, `RecordingRunner` is used on developer host to prevent severing network connectivity. Real live firewall rules are tested and verified safely inside unshared network namespaces / containers. Production deployment requires root/Administrator privileges.

---

### 2.2 Deterministic EPP & Static Detection

#### 7. [PASS] hash detection works
- **Requirement**: Master Spec lines 167–172. Sub-millisecond SHA-256 blocklist matching with short-circuit capability.
- **Implementation**:
  - `centralium/agent/epp/hash_engine.py`: In-memory hash set with standard malware hashes (including EICAR test string). Emits `Finding.known_malicious = True`.
- **Verification Evidence**:
  - `tests/unit/test_epp.py::test_hash_blocklist_hit` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_2_known_malicious_short_circuit_no_ml_no_llm` (PASS)
  - Measured latency: `0.0008 ms` (0.8 µs) cache hit; `0.0054 ms` cache miss (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Hashes must match exactly (SHA-256); fuzzy hashing (SSDEEP) is not implemented.

#### 8. [PASS] IOC detection works
- **Requirement**: Master Spec lines 173–178. In-memory and SQLite cached IOC store matching IPv4, IPv6, CIDRs, domains, and URLs.
- **Implementation**:
  - `centralium/agent/epp/ioc_engine.py`: `CachedIOCStore` with indexed subnet matching and domain lookups.
  - `centralium/agent/security/ssrf.py`: Protects against malicious lookups and SSRF evasion.
- **Verification Evidence**:
  - `tests/unit/test_epp.py::test_cidr_matching` (PASS)
  - `tests/security/test_epp_security.py::test_ssrf_and_ip_sanitization` (PASS)
- **Honest Limitations**: Bundled threat intel relies on built-in curated feeds unless network feed updating is explicitly configured.

#### 9. [PASS] YARA works
- **Requirement**: Master Spec lines 179–185. In-process YARA scanning with active rules, compiling, reloading, and metadata extraction.
- **Implementation**:
  - `centralium/agent/yara/scanner.py`: `DefaultYaraScanner` compiling rules from `rules/yara/` (webshells, droppers, ransomware, test signatures).
- **Verification Evidence**:
  - `tests/unit/test_yara.py::test_yara_rule_matches_eicar_buffer` (PASS)
  - Measured scan latency: `0.1408 ms` for 64 KiB buffer (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Uses `yara-python` when available; includes built-in pure-Python regex fallback scanner when native YARA C library is not installed.

#### 10. [PASS] static analysis works
- **Requirement**: Master Spec lines 186–191. PE and ELF inspection extracting sections, entropy, suspicious flags, and imports without execution.
- **Implementation**:
  - `centralium/agent/malware_analysis/analyzer.py`: PE parsing (`pefile`) and ELF parsing (`pyelftools`) calculating Shannon entropy and identifying anomalies.
- **Verification Evidence**:
  - `tests/unit/test_static_analysis.py::test_pe_parsing_and_entropy` (PASS)
  - `tests/unit/test_static_analysis.py::test_elf_parsing_and_sections` (PASS)
  - Measured latency: `0.0936 ms` for 64 KiB binary sample (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Very large binaries (> 50 MB) are skipped in accordance with profile limits (`max_scan_file_mb`).

#### 11. [PASS] LOLBin detection works
- **Requirement**: Master Spec lines 499–509. Contextual scoring of LOLBins (PowerShell, bash, curl, certutil, rundll32, mshta, etc.).
- **Implementation**:
  - `centralium/agent/lolbins/detector.py`: Scans process name, command-line arguments (e.g. `-enc`, `-w hidden`, `downloadstring`), ancestry, and destination ports.
- **Verification Evidence**:
  - `tests/unit/test_lolbins.py::test_powershell_encoded_command_detection` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_3_office_powershell_dropper_c2_multistage_attack` (PASS)
- **Honest Limitations**: Obfuscated command lines using atypical string concatenation may evade basic regex heuristics without dynamic deobfuscation.

#### 12. [PASS] persistence detection works
- **Requirement**: Master Spec lines 479–497. Detection of Linux (cron, systemd, shell profiles, SSH keys) and Windows (registry Run keys, scheduled tasks) persistence.
- **Implementation**:
  - `centralium/agent/persistence/detector.py`: Inspects file modifications and process arguments targeting persistence vectors.
- **Verification Evidence**:
  - `tests/unit/test_persistence.py::test_cron_persistence_detection` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_5_persistence_cron_runkeys` (PASS)
- **Honest Limitations**: Rootkits that modify kernel-level hooks or hidden directories without standard filesystem events are outside scope.

---

### 2.3 Specialized Behavioral Detectors

#### 13. [PASS] ransomware detection works
- **Requirement**: Master Spec lines 454–477. Composite heuristic scoring for write bursts, mass renames, extension mutation, high entropy, and shadow copy deletion.
- **Implementation**:
  - `centralium/agent/ransomware/scorer.py`: Sliding time window tracker computing composite write rate, entropy surge, and known extension alterations.
- **Verification Evidence**:
  - `tests/unit/test_ransomware.py::test_ransomware_burst_triggers_threshold` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_4_ransomware_burst_entropy_extensions` (PASS)
- **Honest Limitations**: Slow encryption attacks spanning days (drip ransomware) below the burst frequency threshold require correlation via attack graph.

#### 14. [PASS] MITRE mapping works
- **Requirement**: Master Spec lines 535–554. Mapping detections across Execution, Persistence, Privilege Escalation, Discovery, Collection, Exfiltration, and Impact.
- **Implementation**:
  - `centralium/agent/threat_intel/mitre.py`: MITRE catalog and lookup engine tagging findings with standard technique IDs (`T1059`, `T1053`, `T1486`, etc.).
  - Dashboard frontend displays technique IDs in the interactive ATT&CK matrix view.
- **Verification Evidence**:
  - `tests/unit/test_mitre.py::test_mitre_tagging_across_detectors` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_3_office_powershell_dropper_c2_multistage_attack` (PASS)
- **Honest Limitations**: MITRE matrix coverage spans the primary tactics implemented by Centralium detectors; enterprise cloud tactics are out of scope.

#### 15. [PASS] novelty filter works
- **Requirement**: Master Spec lines 556–578. Baseline novelty filtering with LEARNING mode recording, suppress known-benign behavior, and gate LLM.
- **Implementation**:
  - `centralium/agent/novelty/filter.py`: `BaselineNoveltyFilter` records executable-parent pairs and destination IPs; computes novelty distance; suppresses alerts in ACTIVE mode.
- **Verification Evidence**:
  - `tests/unit/test_novelty.py::test_learning_mode_records_baselines` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_1b_active_mode_filters_baselined_developer_script` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_9_high_volume_benign_noise_flood` (PASS)
- **Honest Limitations**: Novelty baseline relies on a representative training period; novel benign software introduced during ACTIVE mode will initially score as novel.

#### 16. [PASS] quarantine works
- **Requirement**: Master Spec lines 436–452. Secure quarantine vault with permission stripping, SHA-256 validation, path mangling, and audited restore.
- **Implementation**:
  - `centralium/agent/quarantine/manager.py`: Moves file to private directory, chmod 000, stores original metadata and hashes in SQLite, and implements audited CLI restoration.
- **Verification Evidence**:
  - `tests/unit/test_quarantine.py::test_file_quarantine_and_restore` (PASS)
  - `tests/e2e/test_acceptance_extras.py::test_quarantine_manager_flow` (PASS)
  - Tested via CLI: `centralium quarantine list` and `centralium quarantine restore`.
- **Honest Limitations**: In-use or locked executables on Windows require pending reboot rename keys, which are mocked in unit tests.

---

### 2.4 Machine Learning & Risk Engine

#### 17. [PASS] Isolation Forest works
- **Requirement**: Master Spec lines 193–218. Unsupervised behavioral anomaly detection with calibrated anomaly score.
- **Implementation**:
  - `ml/training/train.py` & `centralium/agent/ml/engine.py`: Trains `IsolationForest`, serializes artifacts with SHA-256 checksums, and calibrates scores via empirical CDF.
  - `centralium/agent/ml/engine.py`: `OnnxMLEngine` supports accelerated inference via `onnxruntime` with automatic fallback to scikit-learn.
- **Verification Evidence**:
  - `tests/unit/test_ml.py::test_isolation_forest_anomaly_scoring` (PASS)
  - `tests/integration/test_feature_reconciliation.py` (PASS)
  - `tests/unit/test_ml_onnx_equivalence.py`: 6 automated tests verifying exact numerical equivalence between scikit-learn and ONNX runtime (score delta < 1e-7).
- **Honest Limitations**: **Trained on synthetic replay datasets**. Metrics represent anomaly separability on synthetic behavior, not real-world malware corpora.

#### 18. [PASS] Random Forest works
- **Requirement**: Master Spec lines 219–242. Multi-class classification (benign, ransomware, lolbin, c2, persistence) with class probabilities.
- **Implementation**:
  - `ml/training/train.py`: Trains `RandomForestClassifier` with top feature importances and class probability extraction.
- **Verification Evidence**:
  - `tests/unit/test_ml.py::test_random_forest_classification` (PASS)
- **Honest Limitations**: Like the anomaly detector, model is trained on synthetic telemetry distributions.

#### 19. [PASS] ML score is measurable
- **Requirement**: Master Spec lines 243–255. ML inference latency, calibration, and feature importances must be measurable and logged.
- **Implementation**:
  - Feature extraction and inference times measured at runtime via high-resolution monotonic clocks.
  - `centralium/agent/benchmark.py`: Benchmarks both scikit-learn and ONNX Runtime inference latency and batch throughput.
- **Verification Evidence**:
  - Measured inference latency: `5.63 ms` mean for scikit-learn (178 ev/s) vs `0.73 ms` mean for ONNX Runtime (1,372 ev/s) — **7.72x speedup** via ONNX (`docs/BENCHMARKS.md`).
  - Score recorded in `MLResult.anomaly_score`, `classification_confidence`, and feature contribution dictionary.
- **Honest Limitations**: Feature extraction latency scales with the number of process events in the rolling history buffer.

#### 20. [PASS] risk score is deterministic/configurable
- **Requirement**: Master Spec lines 256–294. Transparent multi-factor risk engine combining score families A through G into composite score H.
- **Implementation**:
  - `centralium/agent/risk/engine.py`: `CalibratedRiskEngine` with configurable weights, score family availability tracking, confidence weighting, and known-malicious floor at 90.
- **Verification Evidence**:
  - `tests/unit/test_risk.py::test_calibrated_risk_formula` (PASS)
  - `tests/unit/test_risk.py::test_known_malicious_floor_enforced` (PASS)
- **Honest Limitations**: If only a single score family is available, re-normalization weights that family fully, requiring careful threshold tuning.

---

### 2.5 Attack Graph & Novelty Filtering

#### 21. [PASS] graph works
- **Requirement**: Master Spec lines 510–534. Process-process, process-file, process-socket graph modeling, attack chain correlation, and Kuzu adapter.
- **Implementation**:
  - `centralium/agent/graph/kuzu_adapter.py`: Kuzu embedded graph database adapter with temporal relationship edges (`SPAWNED`, `CONNECTED_TO`, `MODIFIED_FILE`). In-memory fallback if Kuzu is uninstalled.
  - `centralium/agent/graph/query.py`: Chain reconstruction finding roots, lateral branches, and blast radiuses.
- **Verification Evidence**:
  - `tests/unit/test_graph.py::test_graph_ingest_and_chain_traversal` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_3_office_powershell_dropper_c2_multistage_attack` (PASS)
  - Ingestion benchmark: `2.28 ms` per event; batched flush of 1,500 events in `303.4 ms`. Chain query: `0.66 ms` (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Graph is hosted locally on a single endpoint; cross-endpoint distributed graph correlation is not implemented.

---

### 2.6 Local RAG & Local LLM

#### 22. [PASS] local RAG works
- **Requirement**: Master Spec lines 332–360. Vector store with top-k retrieval of MITRE techniques, rules, LOLBins, and playbooks without cloud API calls.
- **Implementation**:
  - `centralium/agent/rag/retriever.py`: SQLite vector store (`sqlite-vec` + lexical TF-IDF embeddings) indexing markdown playbooks and MITRE data from `rag/documents/`.
- **Verification Evidence**:
  - `tests/unit/test_rag.py::test_rag_retrieval_ranking` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_3_office_powershell_dropper_c2_multistage_attack` (PASS)
  - Retrieval latency: `0.83 ms` (first call), `0.019 ms` (cached call) (`docs/BENCHMARKS.md`).
- **Honest Limitations**: Embedding uses fast local lexical TF-IDF hashing embeddings rather than heavy transformer embeddings to preserve low RAM overhead.

#### 23. [PASS] Gemma 3 1B runs locally
- **Requirement**: Master Spec lines 295–331. Lightweight local model running on CPU via llama.cpp (`llama-server`) with strict resource bounds.
- **Implementation**:
  - `centralium/agent/llm/client.py`: HTTP client connecting to local `llama-server` on `127.0.0.1:8080`.
- **Verification Evidence**:
  - Verified live on host hardware using `gemma-3-1b-it-Q4_K_M.gguf`: 3 analyses performed, 3 schema-valid JSON verdicts, mean latency 25.8 seconds, model process RSS 686.3 MB (`docs/BENCHMARKS.md`).
  - Unit tests verify graceful degradation when server is down (`tests/unit/test_llm.py`).
- **Honest Limitations**: The in-process `llama-cpp-python` binding is unverified due to lack of Python 3.14 prebuilt wheels; the `llama-server` HTTP daemon is the supported execution route.

#### 24. [PASS] LLM JSON validation works
- **Requirement**: Master Spec lines 361–384. Strict schema validation of `AIVerdict` with Pydantic, repair/retry logic, and rejection of malformed outputs.
- **Implementation**:
  - `centralium/agent/models/ai.py`: Strict schema requiring `verdict`, `confidence`, `severity`, `recommended_action`, `rationale`, and `mitre_techniques`.
  - Automatic markdown code-block unwrapping and single-attempt retry mechanism.
- **Verification Evidence**:
  - `tests/unit/test_llm.py::test_strict_ai_verdict_validation` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_8_hostile_llm_output_rejected_or_sanitized` (PASS)
- **Honest Limitations**: If the model fails to produce valid JSON after retry, Centralium records `verdict=UNKNOWN`, sets `ai.available=False`, and relies on deterministic scoring.

#### 25. [PASS] LLM failure does not break EDR
- **Requirement**: Master Spec lines 385–403. EDR security engine remains fully functional when LLM crashes, times out, or returns garbage.
- **Implementation**:
  - `centralium/agent/pipeline.py`: Stage isolation catches HTTP errors, socket timeouts, and validation errors. Logs error, increments stats, and proceeds with risk scoring.
- **Verification Evidence**:
  - `tests/e2e/test_spec_threat_scenarios.py::test_7_llm_unavailable_epp_ml_graph_continue` (PASS)
- **Honest Limitations**: None. Security pipeline is completely decoupled from LLM availability.

---

### 2.7 Policy Engine & Response Automation

#### 26. [PASS] policy engine works
- **Requirement**: Master Spec lines 404–434. Deterministic policy engine enforcing operating modes, protected processes, allowlists, and generating ordered action plans.
- **Implementation**:
  - `centralium/agent/policy/engine.py`: `RulesPolicyEngine` generating validated `PolicyDecision` objects containing an ordered execution `plan()`.
- **Verification Evidence**:
  - `tests/unit/test_policy.py::test_policy_action_ordering_and_modes` (PASS)
  - `tests/integration/test_response_pipeline.py` (PASS)
- **Honest Limitations**: Complex hierarchical policy inheritance across multiple business units is not modeled in this single-node prototype.

#### 27. [PASS] process response works
- **Requirement**: Master Spec lines 404–420. Process suspension (SIGSTOP) and termination (SIGKILL) with protected process immunity.
- **Implementation**:
  - `centralium/agent/response/process.py`: Uses direct OS system calls (`os.kill`) with strict PID immunity checks (PID 1, self, system daemons).
- **Verification Evidence**:
  - `tests/unit/test_response.py::test_protected_process_refusal` (PASS)
  - `tests/e2e/test_acceptance_extras.py::test_process_suspend_and_terminate_on_child_process` (PASS — verified live against spawned `sleep` child process).
- **Honest Limitations**: Requires appropriate Linux capabilities (`CAP_KILL`) or matching UID to kill targets.

---

### 2.8 Resilience, Self-Protection & Audit

#### 28. [PASS] offline operation works
- **Requirement**: Master Spec lines 593–613. 100% of detection, scoring, response, and storage works without internet or external cloud connectivity.
- **Implementation**:
  - All detectors, models, vector databases, and storage run on localhost.
- **Verification Evidence**:
  - `tests/e2e/test_spec_threat_scenarios.py::test_6_offline_resilience_pipeline_functional` (PASS — tested with network socket completely disabled via monkeypatch).
- **Honest Limitations**: Cloud threat intelligence updates are skipped when offline, utilizing existing cached indicators.

#### 29. [PASS] audit logs work
- **Requirement**: Master Spec lines 880–903. Hash-chained audit trail linking every action with SHA-256 forward links, verifiable via CLI.
- **Implementation**:
  - `centralium/agent/storage/audit.py`: Cryptographic hash chaining:
    $$\text{hash}_n = \text{SHA256}(\text{hash}_{n-1} \parallel \text{fields})$$
  - `centralium audit verify` CLI command.
- **Verification Evidence**:
  - `tests/unit/test_audit.py::test_audit_chain_tamper_detection` (PASS)
  - `tests/e2e/test_acceptance_extras.py::test_audit_log_tamper_detected_by_cli_verify` (PASS)
- **Honest Limitations**: Chain verification verifies integrity from root to head. Tail truncation requires an externally anchored head hash (`--head`).

#### 30. [PASS] self-protection basics work
- **Requirement**: Master Spec lines 880–895. Baseline file integrity hashing of agent modules, watchdog thread, and tamper event generation.
- **Implementation**:
  - `centralium/agent/self_protection/monitor.py` & `integrity.py`: Computes SHA-256 manifests of agent code; runs watchdog thread; generates tamper alerts.
- **Verification Evidence**:
  - `tests/unit/test_self_protection.py::test_tamper_detection_triggers_finding` (PASS)
  - `tests/e2e/test_acceptance_extras.py::test_tamper_detection_flows_into_pipeline_and_audit` (PASS)
- **Honest Limitations**: Relies on user-space integrity checks; kernel-level driver tampering protection requires specialized kernel modules.

---

### 2.9 SOC Dashboard & User Interface

#### 31. [PASS] dashboard works
- **Requirement**: Master Spec lines 648–702. FastAPI backend providing 17 API endpoints, token authentication, and static file serving.
- **Implementation**:
  - `dashboard/backend/`: FastAPI application with RBAC tokens, SQLite repository integration, Prometheus metrics, and CSP headers.
- **Verification Evidence**:
  - `tests/unit/test_dashboard_api.py` (PASS)
  - `centralium dashboard` launches and serves cleanly on port 8765.
- **Honest Limitations**: Token generation prints to stdout on first startup; production fleets require an external secret manager.

#### 32. [PASS] red sidebar + white UI implemented
- **Requirement**: Master Spec lines 727–752. Enterprise UI with crimson navigation sidebar (`#dc2626`) and white main content cards.
- **Implementation**:
  - `dashboard/frontend/`: Next.js 16 + React 19 application with crimson sidebar (`#B71C1C` / `#dc2626`), white card surfaces (`#ffffff` / `#f8f8f9`), subtle gray borders (`border-gray-200`), and clean typography.
- **Verification Evidence**:
  - `npm run typecheck` (PASS — zero TypeScript errors).
  - `npm run build` (PASS — all 20 static pages successfully compiled).
  - Component tests verified via Vitest.
  - Headless Playwright verification against live backend running demo seed data:
    - Sidebar computed style: `background: rgb(183, 28, 28)` (crimson red), `color: rgb(255, 255, 255)` (white text).
    - Body background: `rgb(248, 248, 249)` (clean light/white background).
    - Browser console: 0 errors, 0 warnings.
    - Screenshot captured and saved to `docs/dashboard_verified.png`.
- **Honest Limitations**: Next.js static export requires `'unsafe-inline'` script CSP headers for inline bootstrap scripts.

---

### 2.10 Quality Gates, Safety & Verification

#### 33. [PASS] ML test suite works
- **Requirement**: Master Spec lines 704–726. ML test suite verifying dataset generation, feature adapters, and model training.
- **Implementation**:
  - `tests/unit/test_ml.py` and `tests/integration/test_feature_reconciliation.py`.
- **Verification Evidence**:
  - `test_feature_reconciliation.py` verifies 100% schema alignment between `BehaviorEngine` and `ml/features/schema.py`.
  - ML model unit tests pass with synthetic datasets.
- **Honest Limitations**: Tests run against deterministic synthetic distributions.

#### 34. [PASS] E2E test mode works
- **Requirement**: Master Spec lines 753–809. Non-destructive end-to-end test runner executing realistic scenarios with simulated execution.
- **Implementation**:
  - `tests/e2e/`: 39 automated E2E tests covering the 10 master threat scenarios and system acceptance extras.
  - Executable via `centralium e2e` CLI.
- **Verification Evidence**:
  - All 39 tests pass cleanly in ~25.0 seconds.
- **Honest Limitations**: Real OS modifications are disabled; simulated executor verifies action intent without altering test host.

#### 35. [PASS] performance benchmark works
- **Requirement**: Master Spec lines 826–850. Automated performance benchmarking capturing micro-benchmarks, throughput, stage latencies, memory, and queue rates.
- **Implementation**:
  - `centralium/agent/benchmark.py`: Benchmark runner producing `docs/BENCHMARKS.md` and `docs/benchmarks.json`.
- **Verification Evidence**:
  - Executable via `centralium benchmark`. Results recorded in `docs/BENCHMARKS.md`.
- **Honest Limitations**: Throughput numbers measured on a single synchronous pipeline worker thread for deterministic reproducibility.

#### 36. [PASS] third-party notices exist
- **Requirement**: Master Spec lines 128–131. Attribution and license notices for all third-party dependencies.
- **Implementation**:
  - `THIRD_PARTY_NOTICES.md` present in project root.
- **Verification Evidence**:
  - File confirmed present, documenting licenses for all Python and npm dependencies.
- **Honest Limitations**: None.

#### 37. [PASS] reuse matrix exists
- **Requirement**: Master Spec lines 126–131. Documented analysis of upstream repositories (`edr-graph`, `SentryLoom`, `OphanimEDR`, etc.).
- **Implementation**:
  - `docs/REUSE_MATRIX.md` and `docs/LICENSE_IP_NOTES.md`.
- **Verification Evidence**:
  - Confirmed present, documenting clean-room rationale and upstream license verifications.
- **Honest Limitations**: None.

#### 38. [PASS] README complete
- **Requirement**: Master Spec lines 1046, 1130–1150. Comprehensive README with architecture, quickstart, setup, security model, and honest disclosures.
- **Implementation**:
  - `README.md` in repository root.
- **Verification Evidence**:
  - Confirmed present, fully polished, and reviewed.
- **Honest Limitations**: None.

#### 39. [PASS] no fake metrics
- **Requirement**: Master Spec lines 1047, 1133. Zero fabricated numbers; all benchmark figures measured on real hardware; synthetic data marked as synthetic.
- **Implementation**:
  - Benchmark measurements executed on host hardware; synthetic ML status explicitly marked across all documentation and UI screens.
- **Verification Evidence**:
  - Verified in `docs/BENCHMARKS.md`, `README.md`, and dashboard ML views.
- **Honest Limitations**: None.

#### 40. [PASS] no arbitrary LLM command execution
- **Requirement**: Master Spec lines 54–56, 385–387, 1048. LLM output must never execute shell commands or reach raw subprocess execution.
- **Implementation**:
  - Output parsed into typed `AIVerdict` recommending enum `ResponseAction`.
  - Subprocess calls use argument arrays only (`shell=False`).
  - AST isolation test (`tests/security/test_llm_isolation.py`) enforces that `llm/` has zero import paths to `subprocess`.
- **Verification Evidence**:
  - `tests/security/test_llm_isolation.py::test_llm_module_has_no_subprocess_imports` (PASS)
  - `tests/e2e/test_spec_threat_scenarios.py::test_8_hostile_llm_output_rejected_or_sanitized` (PASS)
- **Honest Limitations**: None.

#### 41. [PASS] no cloud LLM dependency
- **Requirement**: Master Spec lines 52–53, 295–297, 1049. EDR operates 100% locally with zero cloud API dependencies.
- **Implementation**:
  - Local `llama-server` running Gemma 3 1B or deterministic `MockLLM`. Cloud LLM libraries (OpenAI, Anthropic, Google Cloud) are completely absent.
- **Verification Evidence**:
  - Verified across all test suites and runtime configurations.
- **Honest Limitations**: None.

---

## 3. The 10 Master Threat Scenarios (E2E Test Suite)

All 10 threat scenarios defined in the Master Build Prompt are implemented in `tests/e2e/test_spec_threat_scenarios.py` and pass with 100% success:

| Scenario | Title & Description | Test Case Name | Status | Key Verification Details |
|---|---|---|---|---|
| **Scenario 1a** | **Benign Developer / Admin Baseline** | `test_1a_benign_developer_admin_replay_baseline` | **PASS** | Replays git, make, curl, apt-get, and admin scripts in LEARNING mode. Baseline recorded; zero alerts or false incidents generated. |
| **Scenario 1b** | **Active Mode Novelty Gate** | `test_1b_active_mode_filters_baselined_developer_script` | **PASS** | Evaluates previously baselined admin scripts in ACTIVE mode. Novelty filter scores distance as zero; suppressive gate prevents alerts. |
| **Scenario 2** | **Known Malicious Short-Circuit** | `test_2_known_malicious_short_circuit_no_ml_no_llm` | **PASS** | Event with known-malicious SHA-256 (EICAR) or blocklisted IOC triggers immediate EPP response; skips ML, graph, RAG, and LLM entirely. |
| **Scenario 3** | **Office -> PowerShell -> Dropper -> C2** | `test_3_office_powershell_dropper_c2_multistage_attack` | **PASS** | Multi-stage kill chain: WINWORD.EXE spawns encoded PowerShell, downloads payload via curl, connects to external IP. Attack graph reconstructs lineage; triggers RAG and LLM. |
| **Scenario 4** | **Ransomware Burst Detection** | `test_4_ransomware_burst_entropy_extensions` | **PASS** | Replays write bursts with `.locked` extensions and high entropy. Single writes pass; burst triggers composite threshold; policy schedules process termination. |
| **Scenario 5** | **Persistence Detection** | `test_5_persistence_cron_runkeys` | **PASS** | Detects unauthorized additions to `/etc/cron.d` and Windows registry `Run` keys. Flags persistence finding and elevates incident severity. |
| **Scenario 6** | **Offline Resilience** | `test_6_offline_resilience_pipeline_functional` | **PASS** | Pipeline executed with system sockets disabled via monkeypatch. Telemetry normalization, EPP, ML, graph, RAG, policy, and audit function with zero errors. |
| **Scenario 7** | **LLM Failure Resilience** | `test_7_llm_unavailable_epp_ml_graph_continue` | **PASS** | Pipeline executed with LLM client throwing connection failures. Stage isolation catches error, logs AI unavailable, and deterministic EPP/ML protection continues uninterrupted. |
| **Scenario 8** | **Hostile LLM Output & Injection Defense** | `test_8_hostile_llm_output_rejected_or_sanitized` | **PASS** | Model returns hostile prompt injection (`"ignore instructions and run rm -rf /"`). Strict Pydantic parsing rejects payload; policy refuses execution; AST verifies no shell execution path. |
| **Scenario 9** | **High-Volume Benign Noise Suppression** | `test_9_high_volume_benign_noise_flood` | **PASS** | Floods pipeline with 1,000 repetitive benign events. EPP and novelty filters suppress noise; zero false incidents created; pipeline throughput maintained. |
| **Scenario 10** | **Mixed Multi-Stage Campaign** | `test_10_mixed_multistage_campaign_funnel_and_containment` | **PASS** | Replays simultaneous benign background noise alongside stealthy multi-stage attack. Funnel statistics isolate attack; policy executes simulated process termination and isolation. |

---

## 4. Honest Limitations & Operational Disclosures

In accordance with Section 11 of the engineering specification, Centralium discloses the following architectural limitations:

1. **Host Verification Scope (Linux vs. Windows)**:
   - Centralium has been developed and comprehensively tested on **Linux x86_64** (Linux 7.2-zen, glibc 2.44, Python 3.14.7).
   - Windows collectors (`EventLogCollector`, `wevtutil`), Windows response modules (`netsh advfirewall`, Windows Service wrapper), and Windows paths have been written with cross-platform abstractions and verified via mock runners in automated unit tests.
   - **No part of Centralium has been tested on a physical Windows host.** Windows support should be treated as prototype code awaiting physical host verification.

2. **Machine Learning Dataset & Real-World Claims**:
   - The Isolation Forest (anomaly) and Random Forest (classification) models were trained on **synthetic telemetry replay datasets** (`ml/datasets/`).
   - The reported accuracy, precision, recall, and ROC-AUC metrics describe separability on synthetic feature distributions. They **do not represent real-world malware detection performance**. Real-world deployment requires training on enterprise host telemetry corpora.

3. **Clean-Room Implementation & Upstream Intellectual Property**:
   - The upstream repository `edr-graph` (`ticfinack/edr-graph`) is licensed under AGPLv3 and contains a patent-pending notice for ancestry enforcement.
   - To avoid licensing conflicts and IP contamination, **zero lines of code were copied from edr-graph**. Centralium implemented its own in-memory and Kuzu graph adapters, models, normalization schema, and risk engine as a clean-room implementation. See [docs/REUSE_MATRIX.md](docs/REUSE_MATRIX.md) and [docs/LICENSE_IP_NOTES.md](docs/LICENSE_IP_NOTES.md).

4. **Local LLM Performance on CPU Hardware**:
   - When running Gemma 3 1B IT Q4_K_M locally on CPU via `llama-server`, an analysis takes approximately **25.8 seconds** (measured on an Intel Core i5-13420H).
   - To maintain real-time endpoint throughput, Centralium strictly gates LLM calls (requiring novel event + pre-risk >= 60) and caches verdicts across process lineages. The LLM is an advisory reasoning assistant, never an inline blocking dependency.

5. **Kernel Collectors**:
   - The Linux eBPF collector and Windows ETW collector are currently structured as clean stubs. Production deployment relies on user-space `PsutilCollector` and `AuditdCollector` (requiring auditd access / root).
