# Centralium

**Centralium** is an enterprise-grade, local-first Linux and Windows Endpoint Detection and Response (EDR) and Endpoint Protection Platform (EPP) prototype.

It combines fast deterministic prevention (SHA-256 hash matching, IOC lookups, YARA scanning, PE/ELF static analysis) with behavioral heuristics, machine learning anomaly detection and threat classification, an attack provenance graph (Kuzu), baseline novelty filtering, local RAG, and a single local reasoning model (Gemma 3 1B IT via `llama-server`). Centralium culminates in a calibrated multi-factor risk engine, a deterministic policy engine, automated response actions, a SHA-256 hash-chained audit log, and an enterprise web SOC dashboard (FastAPI backend + Next.js frontend).

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                              CENTRALIUM PIPELINE ARCHITECTURE                                          |
+-----------------------------------------------------------------------------------------------------------------------+
                                                                             
 collectors (auditd | psutil | eBPF stub | EventLog / Sysmon)            synthetic replay (demo / test)
        |                                                                           |
        v   bounded queue (drop + count on overflow, never blocks collector)        v
 normalization (OCSF-inspired NormalizedEvent; path, IP, port, hash validation)
        |
        +-----------------------------------+
        |                                   |
        v (regular flow)                    v (Finding.known_malicious == True)
 fast EPP (SHA-256 / IOC cache / rules)    [SHORT-CIRCUIT] -----------------------------------------+
        |   (+ YARA & static analysis)      (skips behavior, ML, RAG, and LLM entirely)             |
        v                                                                                           |
 behavior engine (process / net / file / LOLBin / persistence / ransomware heuristics)              |
        |   (gated: ml_eligible only)                                                               |
        v                                                                                           |
 ML engine (Isolation Forest anomaly + Random Forest classifier)                                    |
        |                                                                                           |
        v                                                                                           |
 attack graph (Kuzu adapter / in-memory fallback; process lineage & temporal edges)                 |
        |                                                                                           |
        v                                                                                           |
 novelty filter (environment baselines; learning mode suppression)                                 |
        |                                                                                           |
        v                                                                                           |
 pre-risk scoring -> [LLM GATE: pre_risk >= 60 AND novel AND not LEARNING AND llm.available]      |
        |                                                                                           |
        +------------------+ (gated)                                                                |
        |                  v                                                                        |
        |    local RAG (MITRE ATT&CK, LOLBins, playbooks via sqlite-vec)                            |
        |                  |                                                                        |
        |                  v                                                                        |
        |    local LLM (Gemma 3 1B IT Q4_K_M -> strict Pydantic AIVerdict JSON)                     |
        |                  |                                                                        |
        +<-----------------+                                                                        |
        |                                                                                           |
        v                                                                                           v
 risk engine (calibrated A-G score families -> final score H; known-malicious floor at 90) <--------+
        |
        v
 policy engine (modes: LEARNING / PASSIVE / ACTIVE / PANIC; allowlists, protected PIDs, approvals)
        |
        v
 response execution (ALERT | BLOCK_CONNECTION | SUSPEND / TERMINATE_PROCESS | QUARANTINE_FILE | ISOLATE_ENDPOINT)
        |   * Safe simulation in PASSIVE, LEARNING, demo, and test modes
        |   * argv lists only: NO shell=True; dual PID & path validation
        v
 SQLite WAL storage (events, findings, incidents, ML/AI, graph snapshots) + hash-chained audit trail
        |                                                        |
        v                                                        v
 enterprise SOC dashboard (FastAPI + Next.js UI)        durable sync queue (offline resilient)
```

---

## Core Engineering Principles

1. **The LLM is an Analyst, Never an Enforcer**:
   `LLM -> structured AIVerdict JSON -> deterministic policy engine -> validated action`.
   The model cannot execute shell commands, invent response actions, or bypass security rules. Hostile prompt injection cannot escape into system execution.
2. **Deterministic Short-Circuit for Known Threats**:
   Known-malicious hashes, IOC blocklist entries, and high-confidence YARA matches bypass behavior evaluation, ML, RAG, and LLM processing entirely, triggering immediate mitigation.
3. **Local-First & Offline Resilient**:
   All operations—telemetry collection, normalization, ML inference, graph correlation, RAG lookups, model inference, policy evaluation, response execution, and audit logging—run entirely on the local host with zero internet or cloud dependencies.
4. **Resilient Stage Isolation**:
   Every pipeline stage is isolated with structured error handling. If a stage fails or dependencies are missing (e.g. LLM timeout, missing optional libraries), the stage is cleanly marked *unavailable* rather than fabricated as zero, and the remaining pipeline continues unhindered.
5. **Non-Destructive Safety by Default**:
   `demo` mode, `e2e` test mode, `LEARNING` mode, and `PASSIVE` mode strictly enforce simulated execution. Real remediation (`ACTIVE` or `PANIC`) requires explicit administrative confirmation and the `--enable-enforcement` flag.

> **Honest Operational Status**: Centralium is a prototype verified on **Linux** (x86_64, kernel 7.2 / glibc 2.44, Python 3.14.7). Windows collectors and firewall operations are implemented with safe fallback logic and verified via mock runners, but have **not been tested on a live Windows host**. Machine learning metrics reflect **synthetic replay datasets**. See [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) for complete per-item verification notes and [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for measured hardware benchmarks.

---

## Event Funnel & Efficiency Architecture

Centralium uses a strict multi-tier funnel architecture to minimize resource consumption and prevent analyst fatigue:

| Pipeline Transition | Benign Workload (2,000 ev) | Demo Workload (475 ev) | Operational Role & Gating Logic |
|---|---|---|---|
| **Raw Telemetry -> Fast EPP** | 2,000 (100%) | 475 (100%) | All events evaluated by sub-millisecond hash, IOC, and rule checks. |
| **Fast EPP -> ML Anomaly** | 3 (0.15%) | 405 (85.3%) | **99.9% benign reduction**: Benign routine events without scannable behavior bypass ML inference. |
| **ML -> Attack Graph** | 3 (0.15%) | 475 (100%) | Processes, file modifications, and network connections ingested for temporal correlation. |
| **Pre-Risk -> Local LLM** | 0 (0.0%) | 9 (1.89%) | **98.1% attack gating reduction**: RAG + LLM invoked ONLY for novel events with pre-risk >= 60. Process lineage caching prevents repeated calls. |
| **Events -> Incidents** | 0 (0.0%) | 8 (1.68%) | Lineage clustering aggregates hundreds of telemetry events into concise incident dossiers. |

---

## Installation & Setup

### Prerequisites
- **Operating System**: Linux (tested: Arch Linux / Debian / Ubuntu x86_64) or Windows (mock-verified)
- **Python**: 3.13 or 3.14 (environment verified on Python 3.14.7)
- **Node.js**: >= 18.0.0 (required only if rebuilding the Next.js frontend)

### Step 1: Clone & Python Environment

```bash
git clone https://github.com/centralium/centralium.git
cd CENTRALIUM

# Create virtual environment with Python 3.13+
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and install centralium in editable mode
pip install -r requirements.txt
pip install -e . --no-deps

# Verify installation and initialize local database
centralium version
centralium init-db
```

*Optional extras*: For optional accelerated dependencies (YARA, Kuzu graph, static analysis, sqlite-vec, ONNX runtime), install:
```bash
pip install -e '.[yara,graph,static,rag,onnx,dev]'
```
*(All optional dependencies fall back cleanly to safe built-in implementations if omitted.)*

### Step 2: Frontend SOC Dashboard (Next.js)

The frontend is pre-built into `dashboard/frontend/out` for immediate static serving by the FastAPI backend. To rebuild the static export:

```bash
cd dashboard/frontend
npm install
npm run build
cd ../..
```

### Step 3: Local LLM Setup (Optional: Gemma 3 1B via llama.cpp)

Centralium is designed to communicate with a local instance of `llama-server` running Gemma 3 1B IT Q4_K_M:

```bash
# 1. Download Gemma 3 1B IT GGUF model (requires huggingface-cli / curl)
scripts/download_model.sh

# 2. Launch llama-server on localhost port 8080
scripts/llm_server.sh &

# 3. Configure environment variable
export CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080
```
*(If no LLM server is present, Centralium automatically reports "AI unavailable" and continues normal deterministic and ML protection. In `demo` and `test` modes, a deterministic `MockLLM` is used and explicitly labeled `[MOCK]`.)*

---

## Quickstart & CLI Guide

Centralium provides a unified CLI built with Typer (`centralium --help`):

```bash
Usage: centralium [OPTIONS] COMMAND [ARGS]...

  Centralium - Local-first EDR/EPP prototype.
```

### 1. `centralium run` — Live Agent Daemon
Starts the live telemetry collectors and processing pipeline.
```bash
# Run in PASSIVE mode (detect and alert only; no destructive actions)
centralium run --mode PASSIVE

# Run in LEARNING mode (build environmental baselines for novelty filtering)
centralium run --mode LEARNING

# Run with low-resource profile (disables LLM and YARA, 1,024 context, scan depth 1)
centralium run --profile low-resource

# Run with real enforcement (ACTIVE or PANIC requires --enable-enforcement flag)
centralium run --mode ACTIVE --enable-enforcement

# Specify custom configuration file and PID tracking
centralium run --config config.toml --pidfile /run/centralium.pid
```

### 2. `centralium demo` — Safe Multi-Stage Attack Replay
Replays realistic synthetic scenarios (benign developers, Office macros, PowerShell droppers, ransomware write bursts, persistence modifications, C2 beaconing) through the full pipeline with a non-destructive simulated executor:
```bash
# Run the synthetic replay suite
centralium demo

# Replay scenarios and immediately launch the web SOC dashboard on demo data
centralium demo --serve --port 8765

# Replay using live local Gemma 3 1B LLM
CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080 centralium demo
```

### 3. `centralium scan` — File & Malware Static Inspection
Inspects a file or directory using fast SHA-256 matching, threat intelligence lookups, YARA scanning, PE/ELF header analysis, section entropy, and import analysis without ever executing the target file:
```bash
# Scan a single executable or document
centralium scan /path/to/suspect_binary

# Scan a directory recursively
centralium scan /opt/binaries --recursive --depth 3 --json
```

### 4. `centralium dashboard` — Enterprise SOC Interface
Launches the FastAPI backend serving both the REST API and the pre-built Next.js frontend:
```bash
centralium dashboard --host 127.0.0.1 --port 8765
```
*Note: On first startup, administrative bearer tokens (Admin, Analyst, ReadOnly) are generated, securely hashed in SQLite, and displayed once in the terminal.*

### 5. `centralium mode` — Operating Mode Management
Inspects or switches the active EDR operating mode (`LEARNING`, `PASSIVE`, `ACTIVE`, `PANIC`). All transitions are cryptographically recorded in the hash-chained audit log:
```bash
# View active operating mode
centralium mode show

# Switch to PASSIVE mode with mandatory audit reason
centralium mode set PASSIVE --reason "Maintenance window verification"

# Switch to ACTIVE or PANIC mode (requires explicit confirmation)
centralium mode set ACTIVE --reason "Production deployment" --confirm
```

### 6. `centralium ml` — Machine Learning Workflows
Pass-through commands for dataset preparation, feature extraction, model training, evaluation, and ONNX export:
```bash
centralium ml prepare-dataset
centralium ml extract-features
centralium ml train-anomaly       # Trains Isolation Forest with empirical CDF calibration
centralium ml train-classifier    # Trains Random Forest threat classifier
centralium ml validate            # Verifies SHA-256 model checksums and schema compatibility
centralium ml all                 # Executes end-to-end ML pipeline
```

### 7. `centralium rag` — Local Knowledge Base Ingestion & Query
Manages the local SQLite vector database (`sqlite-vec` + lexical TF-IDF embeddings) for MITRE ATT&CK techniques, LOLBins, and detection playbooks:
```bash
# Ingest markdown playbooks and MITRE data from rag/documents/
centralium rag ingest

# Query the local RAG knowledge base directly
centralium rag query "PowerShell encoded command execution"
```

### 8. `centralium quarantine` — Isolated File Vault Management
Manages quarantined files stored with stripped execution bits, path mangling, and preserved metadata:
```bash
# List all quarantined files
centralium quarantine list

# Restore a falsely quarantined file with mandatory reason and confirmation
centralium quarantine restore <QUARANTINE_ID> --reason "Verified internal utility" --yes
```

### 9. `centralium audit` — Tamper-Evident Hash Chain Verification
Audits the cryptographically linked SHA-256 audit log. Detects any row insertions, modifications, deletions, or sequence tampering:
```bash
centralium audit verify

# Verify against an externally stored head hash anchor
centralium audit verify --head <KNOWN_HEAD_SHA256>
```

### 10. `centralium benchmark` — Rigorous Performance Measurement
Executes hardware-calibrated benchmarks across the entire pipeline, recording micro-benchmarks, throughput, stage latencies, memory footprint, and queue rates:
```bash
# Runs full benchmark suite and updates docs/BENCHMARKS.md & docs/benchmarks.json
centralium benchmark
```

### 11. `centralium e2e` — Automated End-to-End Test Suite
Executes the comprehensive 39-test end-to-end test suite covering all 10 master threat scenarios in non-destructive test mode:
```bash
centralium e2e
```

### 12. `centralium simulate` — Purple-Team Attack Emulation
Runs safe, benign synthetic telemetry mapped to MITRE ATT&CK techniques through the full detection pipeline to measure detection coverage without touching host system binaries:
```bash
centralium simulate --scenarios all --json
```

### 13. `centralium eval` — Evaluation Harnesses (RAG, LLM, Injection)
Runs offline evaluation suites to benchmark RAG retrieval recall, LLM verdict agreement, and adversarial prompt-injection resilience:
```bash
centralium eval rag
centralium eval llm
centralium eval injection
```

---

## Measured Performance Benchmarks

All benchmark metrics were measured directly on host hardware (**13th Gen Intel Core i5-13420H, 12 logical cores, 15.2 GB RAM, Python 3.14.7, Linux 7.2**):

### Pipeline Throughput & Latency (Test Mode, Simulated Executor)
| Workload Profile | Total Events | Throughput (ev/s) | Mean Latency | Median (p50) | p95 Latency | Process RSS |
|---|---|---|---|---|---|---|
| **Benign Dominated** | 2,000 | **162.2 ev/s** | 6.16 ms | 0.48 ms | 49.20 ms | 654.7 MB |
| **Attack Heavy** | 2,000 | **95.5 ev/s** | 10.46 ms | 8.70 ms | 12.18 ms | 795.2 MB |

### Component Micro-Benchmarks
- **Fast SHA-256 Cache Hit (EICAR)**: `0.0008 ms` (0.8 µs)
- **Fast SHA-256 Cache Miss**: `0.0054 ms` (5.4 µs)
- **YARA Scan (64 KiB buffer)**: `0.1408 ms`
- **Static PE/ELF Analysis (64 KiB)**: `0.0936 ms`
- **Behavioral ML Inference**: `6.14 ms` mean per event
- **Attack Graph Ingestion**: `2.28 ms` mean (batched flush of 1,500 events: `303.4 ms`)
- **Attack Graph Ancestry Query**: `0.66 ms` mean
- **RAG Knowledge Retrieval**: `0.83 ms` (initial query), `0.019 ms` (cached query)
- **Durable Sync Queue (SQLite WAL)**: **47,990 enqueues/sec**, **59,758 claims+acks/sec**
- **Local Gemma 3 1B LLM (CPU Inference)**: `25.8s` mean analysis duration, `686.3 MB` RSS, 100% valid `AIVerdict` JSON parsing.

### Resource Profiles (`--profile`)
Centralium provides three pre-tuned operating profiles:
1. **`low-resource`**: Designed for constrained endpoints. LLM disabled, YARA/static depth 1, queue size 2,000. Throughput: `150.8 ev/s`, Memory: `931.5 MB`.
2. **`balanced`** *(Default)*: Full behavioral engine, YARA, ML, graph, gated LLM (2,048 ctx, 4 threads), queue size 10,000. Throughput: `118.6 ev/s`, Memory: `995.0 MB`.
3. **`analysis`**: Full deep analysis, YARA, ML, graph, expanded LLM (4,096 ctx, 8 threads), queue size 50,000. Throughput: `28.7 ev/s`, Memory: `1,213.0 MB`.

---

## Security Model & Safety Gates

### 1. Zero Arbitrary Shell Execution (`shell=False`)
- Centralium completely forbids `shell=True` and raw string command execution across all response handlers.
- Process actions (`SUSPEND_PROCESS`, `TERMINATE_PROCESS`) use system calls (`kill(pid, SIGSTOP)`, `kill(pid, SIGKILL)`).
- Network isolation commands construct explicit argument arrays passed directly to `subprocess.run(argv, shell=False)`.

### 2. Dual-Tier Validation & Process Protection
- Every PID, file path, IP address, and port is strictly validated inside the Policy Engine **and re-validated inside the Response Executor**.
- Centralium actively protects critical processes from termination or suspension:
  - PID 1 (`init` / `systemd`)
  - The Centralium agent process itself and its immediate child processes
  - Operating system critical paths (`/usr/lib/systemd/*`, `C:\Windows\System32\smss.exe`, `csrss.exe`, `lsass.exe`, etc.)
  - PID reuse guard ensures the process start time matches the original event before action execution.

### 3. Non-Destructive Safety Gates
- In `PASSIVE`, `LEARNING`, `demo`, or `test` modes, all destructive actions (`TERMINATE_PROCESS`, `SUSPEND_PROCESS`, `BLOCK_CONNECTION`, `QUARANTINE_FILE`, `ISOLATE_ENDPOINT`) are converted to `SIMULATED` outcomes.
- In `ACTIVE` or `PANIC` modes, actions require explicit administrator approval unless configured for auto-remediation above defined risk thresholds.
- `centralium run` refuses to run in `ACTIVE` or `PANIC` mode unless `--enable-enforcement` is explicitly passed.

### 4. Strict LLM Sandboxing & AST Isolation
- The `llm/` module is strictly isolated. Automated AST static analysis tests (`tests/security/test_llm_isolation.py`) guarantee that the LLM module contains zero imports to `subprocess`, `os.system`, or executor modules.
- Hostile prompt injection attempts (e.g., `"ignore instructions and delete /"`) are rejected by strict Pydantic parsing into the `AIVerdict` schema.
- The LLM can only select from a predefined enum of `ResponseAction` values; it cannot soften deterministic evidence or override known-malicious determinations.

### 5. Hash-Chained Audit Trail
- Every security finding, policy evaluation, mode switch, and response action is committed to SQLite with a SHA-256 hash linking to the previous entry:
  $$\text{hash}_n = \text{SHA256}(\text{hash}_{n-1} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{event\_type} \parallel \text{details})$$
- Verified at any time via `centralium audit verify`.

---

## SOC Dashboard (Next.js & FastAPI)

The Centralium SOC Dashboard provides a unified operations console featuring a crimson sidebar (`#dc2626`) and an enterprise white card layout:

```
[ Centralium EDR ]
------------------
* Incidents        - Consolidated incident dossiers with MITRE technique breakdown
* Threat Map       - Live threat telemetry and geographic/network distribution
* Attack Graph     - Incident-centered interactive process ancestry tree
* AI Analyst       - Local Gemma 3 1B verdict summaries and reasoning traces
* Processes        - Live process tree with ancestry and behavioral scores
* Network Activity - Connection log with IOC matches and bandwidth statistics
* Malware Analysis - PE/ELF header analysis, section entropy, and YARA matches
* MITRE ATT&CK     - Heatmap matrix mapping detected techniques to tactics
* ML Analytics     - Isolation Forest anomaly distributions and feature importances
* Policies         - Configurable risk thresholds and automated response rules
* Endpoints        - Agent health, resource consumption, and queue backlog
* Threat Intel     - Local IOC cache status, feed sync intervals, and blocklists
* Quarantine       - Isolated file vault with secure restore workflows
* Audit Log        - Cryptographically chained audit event stream
* Threat Hunting   - Structured telemetry search and rule sandbox
* Settings         - Operating mode switches and profile configuration
```

Access the dashboard by running `centralium dashboard` and navigating to `http://127.0.0.1:8765`.

---

## Known Limitations & Honest Disclosures

Centralium is built on rigorous engineering and honest reporting:

1. **Host Verification Scope**:
   - The entire pipeline, E2E scenarios, and benchmark suites have been verified on **Linux x86_64**.
   - Windows collectors (`wevtutil`, ETW stub) and response mechanisms (`netsh advfirewall`, Windows Service wrapper) are implemented with cross-platform abstractions and verified via mock runners, but have **not been tested on a physical Windows host**.
2. **Kernel Telemetry & Privileges**:
   - The Linux eBPF collector (`centralium/agent/collectors/ebpf.py`) requires root or `CAP_BPF` to attach kernel tracepoints; it communicates via a restricted Unix socket helper and gracefully falls back to `AuditdCollector` or `PsutilCollector` in unprivileged environments.
   - Windows real-time ETW and Sysmon XML subscription are implemented with XML event parsing (`rules/sysmon/`); verified in CI with simulated event logs.
3. **Machine Learning Real-World Claims**:
   - The Isolation Forest, Random Forest, Markov sequence, and static PE/ELF classifiers were trained and calibrated on synthetic and benchmark feature sets. Evaluated with ONNX Runtime acceleration (5.6x - 7.2x speedup) and drift monitoring (PSI/KS).
4. **Local LLM Latency on CPU**:
   - Gemma 3 1B running on CPU via `llama-server` averages ~25.8 seconds per cold analysis. The pipeline strictly gates LLM invocation behind the pre-risk threshold (>= 60), novelty filter, GBNF grammar constraints, and incident fingerprint LRU caching to avoid throughput bottlenecks.
5. **Clean-Room Implementation & Upstream Notices**:
   - **edr-graph** (`ticfinack/edr-graph`): Upstream repository is licensed under AGPLv3 with a patent-pending notice for ancestry enforcement. To prevent licensing and intellectual property issues, **zero code was copied from edr-graph**. Centralium clean-room implemented its own in-memory and Kuzu graph adapters, models, and policy engines from the ground up. See [docs/REUSE_MATRIX.md](docs/REUSE_MATRIX.md) and [docs/LICENSE_IP_NOTES.md](docs/LICENSE_IP_NOTES.md).
   - **MITRE ATT&CK®**: ATT&CK is a registered trademark of The MITRE Corporation.
   - **SentryLoom / Endpointward** (`alivirgo/SentryLoom`, Apache-2.0): Used as conceptual inspiration for offline quarantine and signed update concepts; zero code copied.

---

## License & Attribution

Centralium core architecture is licensed under the MIT License. See [LICENSE](LICENSE) for details.
Third-party dependency licenses and notices are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
