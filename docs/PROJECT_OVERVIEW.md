# Centralium: Project Write-up

**Centralium** is an offline-first endpoint detection and response (EDR/EPP) prototype for **Linux and Windows**. It combines fast deterministic protection (hash, IOC, YARA, rules) with behavioral machine learning, an attack graph, local RAG and **one** small local LLM (Gemma 3 1B). The LLM only explains and recommends. A deterministic policy engine decides and performs every action.

> Status: working prototype, verified on Linux. Windows support, firewall/systemd response and eBPF/ETW are only partly verified. See [Honest status](#12-honest-status-and-limitations). All ML metrics come from synthetic data.

---

## 1. The problem and the idea

Most "AI security" demos put an LLM in front of a log stream. That is slow, expensive, hard to trust and unsafe, because model output can be wrong, manipulated or hallucinated.

Centralium is built the other way round:

| Situation | What Centralium does |
|---|---|
| Known threat (hash, IOC, YARA hit) | Stop immediately. Never sent to the LLM. |
| Unknown behavior | Score it with features and ML, then correlate it in the attack graph. |
| High-risk and novel | Retrieve context (RAG) and ask the local LLM for a structured assessment. |
| Severe threat | The AI recommends. The **policy engine** validates and acts. |
| Offline, LLM down or dashboard down | Keep protecting. Nothing in the engine depends on them. |

Principle: *a real endpoint security engine that uses ML and a lightweight local reasoning model only where reasoning adds value*.

---

## 2. Feature overview

### Detection
- **Normalized telemetry** in an OCSF-inspired schema: timestamp, event id, host, user, pid/ppid, process, executable path, command line, parent, SHA-256, signer, file path, destination IP/port, domain, protocol, registry key, source, confidence, raw metadata.
- **Fast EPP**:
  - SHA-256 matching against blocklists.
  - IOC lookup (hash, IP, domain, URL) through a cached local store.
  - YARA with managed rules.
  - Path and process rules (execution from `/tmp`, `/dev/shm`, Windows Temp/AppData, system binaries outside System32, `.pdf.exe` double extensions).
  - Allowlists and blocklists.
- **YARA rule management**: each rule has id, name, family, severity, source, version, enabled flag and metadata. Updates are compiled and validated first. A bad rule is rejected and the old set stays active. `include` and unsafe imports are refused.
- **Static malware analysis**: PE (pefile) and ELF (pyelftools) parsing, section and Shannon entropy, suspicious import sets, a packer heuristic and a 0-100 static score.
- **Behavioral analysis**: 45 versioned features across five families (process, network, file, behavior, ransomware). A gate decides which events reach ML, so ML does not run on every event.
- **LOLBin detection** (PowerShell, cmd, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, wmic; bash, sh, curl, wget, python, perl, nc, socat). It scores *context* (parent, command line, user, path, destination, rarity, frequency). Using a LOLBin alone is never treated as malicious.
- **Persistence detection**:
  - Windows: Run keys, Startup folders, Scheduled Tasks, Services, WMI.
  - Linux: cron, systemd, shell rc files, SSH authorized_keys, startup scripts.
  - Findings carry MITRE technique IDs. Package-manager writes are downgraded instead of ignored.
- **Ransomware detection**: a composite of six weighted components (write burst, rename burst, extension mutation, entropy increase, shadow-copy destruction, suspicious ancestry). Fewer than two active behaviors cap the score, so one file operation never triggers it. CRITICAL requires corroboration.

### Machine learning
- **Isolation Forest** for behavioral anomaly detection, trained on benign data only.
- **Random Forest** for threat classification across 8 classes.
- Output per event: `anomaly_score` (0-1), classification, `classification_confidence`, `top_features`, `model_version`.
- Reproducible pipeline: dataset preparation, feature extraction, training, validation, testing, export and benchmark. Splits are by group to prevent leakage. Models are saved with version, timestamp, feature schema version, dataset version and hyperparameters, and ONNX export is supported.

### Attack graph and correlation
- Nodes: User, Process, File, IP, Domain, RegistryKey, Host, Incident.
- Relationships: SPAWNED, CREATED_FILE, MODIFIED_FILE, DELETED_FILE, CONNECTED_TO, RESOLVED, RESOLVES_TO, CREATED_REG, MODIFIED_REG, AUTHENTICATED_AS, PART_OF_INCIDENT.
- **Kuzu** graph database behind an adapter, with an in-memory fallback that gives identical scores and chains.
- Temporal chain reconstruction, for example `Word -> PowerShell -> download -> executable -> DNS -> C2 IP`.
- Attack-stage prediction over 12 stages, using deterministic sequences first. Confidence is capped, so it never claims certainty.
- A curated local MITRE ATT&CK mapping.

### Novelty and false-positive reduction
- Baselines for process, user, parent-child, destination and frequency, persisted in SQLite.
- Only the learning path writes baselines, so attacker activity cannot poison them.
- Signer trust reduces novelty but never erases it. A high-severity finding always forces "novel".
- Four operating modes, never switched silently: **LEARNING** (baseline only), **PASSIVE** (detect and alert), **ACTIVE** (enforce policy), **PANIC** (emergency response).

### Local RAG and the local LLM
- **RAG**: SQLite + sqlite-vec behind a `VectorStore` abstraction (Qdrant-ready), with a numpy fallback. The default embedder is lexical and runs fully offline. It is used only for high-risk events and returns 3-5 documents with source attribution.
- **Knowledge base**: original text covering 53 ATT&CK techniques plus Centralium rules, YARA metadata, LOLBins, malware behavior, ransomware, persistence, response playbooks and incident knowledge (128 chunks).
- **One model**: Gemma 3 1B IT, GGUF Q4_K_M, run through llama.cpp on CPU, with optional GPU.
- Eight analyst roles (Threat Analyst, Malware Analyst, Incident Summarizer, Threat Hunter, MITRE explainer, Risk explainer, Response recommender, Attack-chain explainer) are different system prompts over the same model.
- **Strict JSON contract** validated by Pydantic. Invalid output is retried once, then the AI is marked unavailable and detection continues. The LLM can never crash the engine.
- Controls: max context, max output tokens, timeout, concurrency 1, thread count, idle unload.

### Risk scoring
- Eight separate 0-100 score families: ML anomaly, ML classification confidence, deterministic evidence, graph, threat intel, static, AI assessment, and the final score.
- Config-driven weights (default 0.25 / 0.20 / 0.20 / 0.15 / 0.10 / 0.10) and bands: SAFE 0-19, LOW 20-39, MEDIUM 40-59, HIGH 60-79, CRITICAL 80-100.
- **Calibration**: strong single-family signals cannot be averaged away. The AI adds at most 15 points, is ignored at low confidence, and never lowers a score. A known-malicious hit is floored at 90 and nothing can lower it.

### Prevention and response
- Actions: ALERT, BLOCK_CONNECTION, SUSPEND_PROCESS, TERMINATE_PROCESS, QUARANTINE_FILE, ISOLATE_ENDPOINT.
- **Linux**: SIGSTOP/SIGKILL with a PID-reuse guard, nftables/iptables with validated addresses and ports, systemd controls.
- **Windows**: process termination, Windows Defender Firewall (`netsh`), service control. Written but never run on real Windows.
- Every command uses argument arrays, never `shell=True`.
- **Protected processes** (init, systemd, sshd, csrss, lsass and the agent itself) cannot be killed.
- **Secure quarantine**:
  - 0700 directory, files opened with `O_NOFOLLOW`, hashed from one file descriptor.
  - Stored as a read-only blob with metadata (SHA-256, reasons, sources, timestamp, original path and permissions).
  - Restore needs authorization, checks the hash, refuses to overwrite, and keeps the evidence copy.

### Threat intelligence
- Parsers for MalwareBazaar, ThreatFox, URLhaus and Feodo Tracker, with validation, timestamps and source tracking.
- Local cache with an LRU in front. No remote lookup per event.
- Updates are off by default, rate-limited, HTTPS-only and size-capped. Failures use exponential backoff and never break detection.

### Offline-first operation and self-protection
- **Durable event queue** (SQLite WAL): deduplication, retries with exponential backoff and jitter, delivery status, leases, bounded retention, and corruption recovery (the bad file is moved aside, a new one is created, and an audit entry is written). Enqueue never blocks detection.
- **Self-protection**: integrity baseline for agent files and config, watchdog thread, protected-directory permission checks, tamper events, systemd watchdog support, and a hardened systemd unit.
- **Signed updates**: Ed25519 bundles that reject unsigned, tampered, rolled-back or path-traversal bundles.
- No kernel rootkit techniques. Everything is transparent and auditable.

### Web SOC dashboard
- **17 pages**: Overview, Threats, Incidents, Attack Graph, Process Explorer, Network Activity, Malware Analysis, Threat Hunting, AI Analyst, MITRE ATT&CK, Response Center, Policies, RAG Knowledge, ML Analytics, Audit Logs, Endpoints, Settings.
- Red sidebar, near-white main area, white cards, gray borders and red critical markers.
- The **AI Analyst finding view** shows verdict, severity, confidence, risk score, why detected, evidence, attack chain, MITRE techniques, RAG sources, ML features, AI explanation, recommended action, action actually taken and timeline.
- A banner always states the operating mode, whether demo or test mode is on, and whether the AI is real Gemma, a labelled mock, or unavailable.
- **ML Analytics** shows evaluation metrics only from a validated report. Otherwise it displays "Not enough validated data".
- Threat hunting uses a whitelisted query builder, with no raw SQL from the client.
- The response center queues requests for approval. The dashboard itself never runs anything.

---

## 3. Architecture

```
TELEMETRY (auditd / psutil / eBPF stub | Sysmon / Event Log / ETW fallback)
  -> NORMALIZATION (OCSF-inspired NormalizedEvent)
  -> FAST EPP: hash / IOC / YARA / rules / allowlist
        known malicious -> short-circuit (never reaches ML or LLM)
  -> BEHAVIOR FEATURES (45) + LOLBin / persistence / ransomware
  -> ML (Isolation Forest + Random Forest)   [only ML-eligible events]
  -> ATTACK GRAPH (Kuzu) + MITRE + stage prediction
  -> NOVELTY FILTER (baselines)
  -> RAG (top 3-5 docs)                       [only high-risk and novel]
  -> LOCAL LLM (Gemma 3 1B)  -> validated AIVerdict (advisory only)
  -> RISK ENGINE (calibrated, config-driven)
  -> POLICY ENGINE (modes, thresholds, protected processes, approval)
  -> RESPONSE (quarantine / suspend / terminate / block / isolate)
  -> AUDIT (hash-chained) -> SQLite WAL -> offline sync queue -> SOC dashboard
```

**Design properties**
- Every stage sits behind an interface (`typing.Protocol`), so modules can be swapped (Kuzu, vector store, LLM backend).
- A failing stage is isolated and recorded. It yields an "unavailable" score, never a fake zero.
- Per-stage counters measure the funnel (raw -> EPP -> ML -> graph -> LLM -> incidents).

---

## 4. Technology stack

| Layer | Technology |
|---|---|
| Language | Python (developed on 3.14, targets 3.13+) |
| CLI | Typer |
| Validation / contracts | Pydantic v2 (strict LLM contract, config, events) |
| Storage | SQLite in WAL mode (all state, audit log, queue) |
| Graph | Kuzu (embedded graph database) behind an adapter, plus in-memory fallback |
| Linux telemetry | auditd, psutil, optional eBPF (stub) |
| Windows telemetry | Sysmon, Windows Event Log (`wevtutil`), ETW (fallback poller), psutil |
| Malware detection | yara-python, pefile, pyelftools, SHA-256 hashing |
| ML | scikit-learn (Isolation Forest, Random Forest), joblib, optional ONNX Runtime / skl2onnx |
| RAG | SQLite + sqlite-vec, numpy fallback, lexical hashing embedder (optional sentence-transformers) |
| Local LLM | Gemma 3 1B IT GGUF Q4_K_M, llama.cpp (`llama-server` over loopback HTTP, or llama-cpp-python) |
| Crypto | `cryptography` (Ed25519 signed updates, optional) |
| Backend / API | FastAPI, Uvicorn, token auth with RBAC, Prometheus-style `/metrics` |
| Frontend | Next.js (TypeScript, static export), served by the FastAPI app |
| Response (Linux) | os signals, nftables / iptables, systemd |
| Response (Windows) | taskkill / psutil, Windows Defender Firewall (`netsh`), `sc` |
| Quality | pytest, ruff, mypy (strict), vitest, tsc |
| Packaging / ops | pyproject, systemd unit, Windows service wrapper, docker-compose placeholder |

No cloud LLMs, no Ollama requirement, and no data leaves the machine unless a sync URL is explicitly configured.

---

## 5. Innovation and differentiators

1. **LLM as analyst, not enforcer.** Output flows `LLM -> structured recommendation -> deterministic policy engine -> validation -> approved action -> OS`. There is no path from model output to a shell. A test checks that the LLM package cannot reach subprocess, `os.system`, `eval` or `exec`.
2. **Tiered cost model.** Cheap deterministic checks run on every event, ML on a gated subset, graph correlation on events that pass the earlier gates, and the expensive LLM only on high-risk novel events. In the measured demo run the LLM saw 9 of 475 events (about 98% filtered out).
3. **One tiny local model.** A single 1B model with role-specific prompts, not a swarm of cloud models. It runs on a CPU and the data stays local.
4. **Confidence-aware risk calibration.** The AI can add a little, never subtract, is ignored when unsure, and can never override a known-bad indicator. Strong single-family signals are not diluted by weighted averaging.
5. **Prompt-injection hardening.** Command lines, file contents and domains are treated as untrusted data in nonce-delimited blocks. Flagged injection attempts cannot push a verdict down to BENIGN, and the policy engine is the real gate.
6. **Baseline-poisoning resistance.** Only the explicit learning path updates baselines.
7. **Honest by construction.** No random or fabricated scores. The ML analytics page and metric reports refuse to show numbers without enough validated data, and the AI source (real, mock or unavailable) is always visible.
8. **Failure-tolerant.** Offline, LLM-down, dashboard-down and model-missing cases are each covered by tests, and detection continues.
9. **Tamper-evident audit.** A hash-chained audit log detects edits, deletions and reordering. Detecting tail truncation or a full rewrite needs an externally stored head hash.
10. **Safe by default.** Demo and test modes force destructive actions off. Responses run in simulation unless enforcement is explicitly enabled. Protected processes, PID-reuse guards and validated network arguments sit under every action.
11. **Reuse with legal hygiene.** Upstream projects were inspected and none was copied. Each is recorded as reference-only in `docs/REUSE_MATRIX.md`, and the AGPL/patent-pending risk of edr-graph is flagged for legal review.

---

## 6. Security model

- No `shell=True`, no `eval`/`exec`, and all SQL is parameterized with whitelisted identifiers.
- Paths are canonicalized, with `O_NOFOLLOW` and same-inode checks in quarantine.
- IPs and ports are validated before any firewall call, and validators use `fullmatch`.
- ML model files (joblib) are loaded only after their SHA-256 and feature schema version match the metadata.
- XML input is rejected if it contains DOCTYPE/ENTITY or exceeds 1 MB.
- Dashboard: bearer tokens with viewer / analyst / admin / agent roles. Only token hashes are stored. It also applies strict CORS, security headers, rate limiting and lockout, a body size cap, and audit logging of management actions.
- Secrets come from the environment and are never hardcoded or logged. Sync tokens come from `CENTRALIUM_SYNC_TOKEN`.

---

## 7. Machine learning details

- **Data**: seeded synthetic generator for 11 scenarios (normal, suspicious PowerShell, suspicious shell, unusual network, mass file writes, ransomware-like, persistence, LOLBin abuse, benign installers, browser, developer workflows). BETH and DARPA OpTC adapters are documented stubs. No dataset is redistributed.
- **Split**: group-aware 60/20/20 train/validation/test. The scaler and Isolation Forest are fit on benign training rows only. The anomaly threshold is chosen on the benign validation split, never on test.
- **Measured test results (synthetic data only)**:

| Model | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|
| Isolation Forest | 0.957 | 0.599 | 0.736 | 0.916 | 0.035 |
| Random Forest (malicious vs benign) | 0.969 | 0.976 | 0.972 | 0.994 | 0.041 |

  8-class Random Forest accuracy on test: 0.960. These numbers show that the pipeline works on synthetic scenarios and are **not** real-world detection performance.
- **Inference**: about 5.7 ms p50 and 7.4 ms p95 per event with both models, single thread. That is why ML is gated to eligible events.

---

## 8. Performance (measured on the development machine)

Machine: 12 logical cores, about 15 GB RAM, Python 3.14. Full tables are in `docs/BENCHMARKS.md`.

- Pipeline throughput: about 160-175 events/s on benign-dominated traffic, about 95-107 events/s on attack-heavy traffic.
- Durable sync queue: about 48k enqueues/s and about 60k claim-and-ack/s.
- Local Gemma 3 1B on CPU: roughly 20-26 s per analysis, with schema-valid output in the runs recorded.
- Demo funnel: raw 475 -> EPP 475 -> ML 405 -> graph 475 -> LLM 9 -> incidents 8.

These are measurements, not guarantees. A different machine will give different numbers, and Centralium is not claimed to run on every computer. Low-resource, balanced and analysis profiles exist, and `docs/BENCHMARKS.md` documents what was measured for them.

---

## 9. Demo and test modes

- `centralium demo` replays safe synthetic scenarios (normal browser, developer workflow, admin backup script, Office-to-PowerShell chain, ransomware-like activity, persistence, C2-style beaconing, known test IOC). It populates the graph, ML scores, risk, RAG, the LLM (mock unless a real server is reachable) and incidents, shows response recommendations, and keeps destructive response disabled. `--serve` opens the dashboard on the resulting database.
- `centralium e2e` or `pytest tests/e2e` runs the 10 spec scenarios: benign, known IOC, suspicious chain, ransomware-like, persistence, internet disabled, LLM unavailable, dashboard unavailable, false-positive reduction, critical chain response.

Last independent run: demo completed in 5.6 s, 8 incidents, benign scenarios raised no alert.

---

## 10. Project layout

```
centralium/agent/   collectors, normalization, epp, yara, malware_analysis, behavior,
                    lolbins, persistence, ransomware, ml, graph, novelty, rag, llm,
                    risk, policy, response, quarantine, threat_intel, storage, sync,
                    self_protection, demo, runtime.py, pipeline.py, main.py
dashboard/          backend (FastAPI) and frontend (Next.js)
ml/                 datasets, features, training, evaluation, models, benchmarks
rag/                documents, ingestion, embeddings, retrieval
rules/              yara, ioc, allowlist, blocklist
tests/              unit, integration, e2e, ml, performance, security
docs/               ARCHITECTURE, ACCEPTANCE, BENCHMARKS, LOCAL_MODEL, RAG,
                    REUSE_MATRIX, LICENSE_IP_NOTES
```

---

## 11. Testing

Unit, integration, e2e, ML, performance and security suites cover each detection layer, the LLM failure modes (malformed JSON, timeout, unavailable, prompt injection), policy, quarantine, process suspend/terminate (only on spawned throwaway children), network block and isolation (mock runner), offline queue and sync recovery, tamper detection, and security cases (path traversal, injection, malformed input). The last full run gave 837 passed and 1 skipped (a test that needs a live Gemma server), with ruff and mypy clean. One pipeline test failed once in an earlier full run and did not reproduce, so treat it as possibly flaky.

---

## 12. Honest status and limitations

- **Windows**: collectors, firewall, service and quarantine permission handling are written but have not been run on a real Windows host.
- **Linux firewall, systemd and isolation**: verified only by exact-argument assertions against a mock runner, and they need root in production.
- **eBPF** is a stub. **ETW** has no real-time session and falls back to the process poller. The **auditd** tailer is tested on sample lines and rotation, not live auditd.
- **LLM**: real Gemma ran through `llama-server`. The in-process `llama-cpp-python` backend is not verified (no wheel for Python 3.14). A 1B model gives generic reasoning, so it stays advisory. GPU offload is untested.
- **ML**: all metrics are synthetic. Isolation Forest recall is about 0.6 at a 5% false-positive target. There is no real-world detection or false-positive claim.
- **RAG**: default retrieval is lexical, so paraphrases can miss.
- **Static analysis**: PE signer data records only that a signature is present, never verified. There is no pure-Python YARA fallback.
- **Dashboard**: no TLS, since it binds to localhost. The CSP must allow inline scripts because of the Next.js static export.
- **Self-protection**: it detects and reports tampering. A root-level attacker who can rewrite both the baseline and its signature is not stopped unless the signing key is kept off the host.
- **Legal**: edr-graph (AGPLv3, patent-pending notice) was used only as architectural reference. Review `docs/LICENSE_IP_NOTES.md` before any commercial distribution.
