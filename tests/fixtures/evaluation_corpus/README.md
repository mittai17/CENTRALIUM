# Centralium Evaluation Test Corpus & Methodology

This directory contains standardized, benign test fixtures and documentation designed for independent judges, security evaluators, and benchmark auditors evaluating **Centralium EDR/EPP**.

---

## 1. Standard Testing Protocol

Centralium's evaluation corpus adheres strictly to industry-standard testing and validation methodologies:

* **AV-TEST & AV-Comparatives Standardized Testing**: Evaluates static Endpoint Protection (EPP) capability without introducing live malicious binaries. Standard test patterns (such as the harmless EICAR test string) verify pre-execution deterministic detection, file integrity inspection, and automatic quarantine isolation.
* **MITRE ATT&CK Evaluation Methodology**: Emulates multi-stage adversary tactics and techniques using synthetic telemetry events. Adversary chains progress across MITRE stages: Initial Access (`TA0001`), Execution (`TA0002`), Persistence (`TA0003`), Defense Evasion (`TA0005`), Credential Access (`TA0006`), Discovery (`TA0007`), Lateral Movement (`TA0008`), Collection (`TA0009`), Command and Control (`TA0011`), and Impact (`TA0040`).
* **RFC Reserved Test Networks**: All synthetic network telemetry uses reserved IP addresses and domains that can never touch public infrastructure:
  * IPv4: `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3) per RFC 5737.
  * Domains: `.test`, `.example`, `.invalid` per RFC 2606 and RFC 6761.
* **Zero Real-World Execution Risk**: All fixtures and synthetic replay sequences are inert strings and structured metadata. Nothing is ever executed or dropped to live system locations outside isolated quarantine sandboxes.

---

## 2. Detection Architecture

### 2.1 Static & EPP Line-Rate Signature Detection (Sub-Microsecond)

Centralium enforces a strict **deterministic first, generative last** pipeline. Known threats must never incur large language model latency, API cost, or non-deterministic variance.

```
Incoming Event / File
         │
         ▼
[ EPP Stage: IOC Store / Hash Lookup ] ──(Match)──► Short-Circuit: CRITICAL Risk (100.0)
         │                                          - Immediate Quarantine (0400 mode)
         ▼                                          - Process Kill / Connection Block
[ EPP Stage: YARA Engine ]             ──(Match)──► - Zero LLM / Zero ML Overhead
         │ (clean)
         ▼
[ Behavioral / ML / Graph Correlation ]
```

* **Instant SHA-256 Lookup**: The EICAR test file (`eicar_standard_test.txt`, SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) is evaluated against Centralium's in-memory blocklist and threat-intelligence cache in **0.8 µs (0.0008 ms)**.
* **In-Process YARA Inspection**: File contents are matched against precompiled YARA rules (e.g., `CENT_EICAR_Test_File`) in ~35 µs.
* **EPP Short-Circuit**: If a known-malicious signature is confirmed, Centralium terminates the pipeline immediately. ML classifiers, knowledge retrieval, and LLM inference are bypassed entirely, saving 100% of GPU/cloud budget while stopping threats instantaneously.
* **Cryptographic Quarantine**: Quarantined files are moved with descriptor-level TOCTOU protection to `data/quarantine/`, stripped of execution bits (mode `0400`), hashed, and accompanied by signed audit records.

### 2.2 Behavioral Pattern Detection (ML & Attack Graph)

Unknown, novel, and fileless threats bypass hash blocklists by definition. Centralium detects these via multi-layered behavioral analysis:

1. **LOLBin Abuse Detection**: Inspects legitimate administrative binaries (e.g. `powershell.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`) for anomalous invocation contexts:
   * Parent-process anomalies (e.g., `winword.exe` or `explorer.exe` spawning hidden PowerShell cradles).
   * High-entropy, Base64-encoded command-line arguments (`-enc`, `-w hidden`, `-nop`).
   * Download cradles retrieving remote executables into temporary user directories.
2. **Machine Learning Anomaly & Sequence Models**:
   * Extracted process features (argument entropy, parent lineage, token n-grams) are evaluated by trained Isolation Forest and random forest classifiers.
   * Behavioral anomaly scores (>0.70) trigger automated investigation and policy escalation.
3. **Multi-Stage Attack Graph Correlation**:
   * All process executions, file drops, DNS lookups, and network sockets are modeled as nodes and directed edges in the in-memory/embedded graph engine.
   * Centralium correlates related actions into unified incident chains, detecting progression from Initial Execution to Staging to Command-and-Control.
   * Correlated incidents automatically persist snapshots to `graph_snapshots` for live SOC dashboard visibility (`/api/graph`).

---

## 3. Demonstration Commands

Evaluators and judges can reproduce the full evaluation suite using the following commands:

### Option A: Complete Automated Judge Evaluation Script
Runs static EPP detection, quarantine verification, behavioral LOLBin analysis, and attack graph visibility in a single end-to-end evaluation report:

```bash
.venv/bin/python scripts/demo_judge_evaluation.py
```

### Option B: Individual Component Commands

1. **Static EPP Scan**:
   ```bash
   .venv/bin/centralium scan tests/fixtures/evaluation_corpus/eicar_standard_test.txt
   ```

2. **Static EPP Scan with Automatic Quarantine**:
   ```bash
   .venv/bin/centralium scan --quarantine tests/fixtures/evaluation_corpus/eicar_standard_test.txt
   ```

3. **Inspect Quarantine Log**:
   ```bash
   .venv/bin/centralium quarantine list
   ```

4. **Run Full Scenario Benchmark**:
   ```bash
   .venv/bin/centralium demo --profile analysis
   ```

5. **Verify Cryptographic Tamper-Proof Audit Chain**:
   ```bash
   .venv/bin/centralium audit verify
   ```

---

## 4. Test Fixtures Manifest

| Fixture File | Type | SHA-256 | Purpose |
|---|---|---|---|
| `eicar_standard_test.txt` | Text (68 B) | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | Standard harmless EICAR string for AV/EPP signature testing. |
