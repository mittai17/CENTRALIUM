# Centralium STRIDE Threat Model

**Version:** 1.0.0  
**Status:** Approved / Active  
**Scope:** Centralium EDR Agent, Collectors, Analysis Pipeline, Quarantine, Response Engine, and Management Interfaces  

---

## 1. Executive Summary & Scope

Centralium is an autonomous, open-source Endpoint Detection and Response (EDR) agent designed to detect, investigate, and remediate host-level intrusions in real time. Because Centralium executes directly on monitored endpoints with elevated observation privileges (and constrained remediation capabilities), it operates as both a high-value defensive control and a primary target for evasion, tampering, and denial-of-service attacks.

This threat model uses the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to analyze all trust boundaries, system components, and operational interactions within Centralium.

---

## 2. Trust Boundaries

```
                 +------------------------------------------------------+
                 |               Central Management / SOC                |
                 +--------------------------+---------------------------+
                                            ^
                              (TB-3: Remote Sync & mTLS)
                                            v
+---------------------------------------------------------------------------------------+
|  HOST OS                                                                              |
|                                                                                       |
|   +--------------------------+        +-------------------------------------------+   |
|   |   Monitored Userland     |        |          Centralium Agent Process         |   |
|   | (Adversaries, LOLBins,   |        |                                           |   |
|   |  Compromised Daemons)    |        |  +-------------------------------------+  |   |
|   +------------+-------------+        |  | Collectors (eBPF, auditd, procfs)   |  |   |
|                |                      |  +------------------+------------------+  |   |
|                |                      |                     v                     |   |
|                | (TB-2: Userland)     |  +------------------+------------------+  |   |
|                |                      |  | Normalization & Event Pipeline      |  |   |
|                v                      |  +------------------+------------------+  |   |
|   +------------+-------------+        |                     v                     |   |
|   |      OS Kernel           |<======>|  +------------------+------------------+  |   |
|   | (Syscalls, eBPF Maps,    | (TB-1) |  | ML & Heuristics Engines             |  |   |
|   |  audit netlink, netfilter)        |  +------------------+------------------+  |   |
|   +--------------------------+        |                     v                     |   |
|                                       |  +------------------+------------------+  |   |
|                                       |  | Local LLM / RAG Engine (TB-4)       |  |   |
|                                       |  +------------------+------------------+  |   |
|                                       |                     v                     |   |
|                                       |  +------------------+------------------+  |   |
|                                       |  | Response & Quarantine Engine (TB-6) |  |   |
|                                       |  +------------------+------------------+  |   |
|                                       |                     v                     |   |
|                                       |  +------------------+------------------+  |   |
|                                       |  | Storage (SQLite WAL, AES-256-GCM)   |  |   |
|                                       |  +-------------------------------------+  |   |
|                                       +-------------------------------------------+   |
+---------------------------------------------------------------------------------------+
```

### TB-1: Agent vs. OS Kernel
* **Description:** Boundary between kernel-space event generation (eBPF tracepoints, Linux audit netlink socket, Windows ETW) and user-space agent ingestion.
* **Trust Assumption:** The kernel is initially trusted and authoritative. The agent relies on kernel netlink and BPF maps to provide unforgeable process execution, network, and file system telemetry.

### TB-2: Agent vs. Monitored Userland
* **Description:** Boundary between the Centralium process and untrusted, potentially malicious userland processes executing on the endpoint.
* **Trust Assumption:** Monitored processes are completely untrusted. They may execute arbitrary shellcode, spawn LOLBins, manipulate symlinks, induce race conditions (TOCTOU), and attempt to flood system audit subsystems.

### TB-3: Agent vs. Remote Management & Sync
* **Description:** Boundary between the local outbound synchronization queue and central server endpoints over WAN/LAN.
* **Trust Assumption:** Network transit is insecure; all communication must be mutually authenticated (mTLS or signed auth tokens). The central management server could be unavailable for extended periods without degrading local agent detection or enforcement.

### TB-4: Agent Pipeline vs. Local LLM & RAG
* **Description:** Boundary between raw endpoint telemetry and the local LLM inference context (Gemma/llama.cpp).
* **Trust Assumption:** Telemetry strings (command-line arguments, process environments, downloaded filenames, DNS domains) may contain adversarial prompt-injection payloads specifically crafted to manipulate LLM reasoning. LLM recommendations must never directly trigger execution without deterministic policy validation.

### TB-5: Agent vs. SOC Operator Approvals
* **Description:** Boundary between autonomous responses and human-in-the-loop approvals.
* **Trust Assumption:** Operators may make mistakes or credentials may be abused; destructive response actions require explicit blast-radius bounds and reversibility playbooks.

### TB-6: Isolation & Quarantine Storage Boundary
* **Description:** Boundary between the live filesystem and isolated quarantine vaults or network isolation packet filters.
* **Trust Assumption:** Quarantined malware files are hostile and must have execute bits stripped, permissions clamped to `0400`/`0700`, and content encrypted at rest with AES-256-GCM to prevent secondary activation or exfiltration.

---

## 3. Attacker-on-Host Assumptions

| Attacker Profile | Capabilities & Assumptions | Out-of-Scope / Non-Preventable |
| :--- | :--- | :--- |
| **Unprivileged Local User** | Can create symlinks, named pipes, fork bombs, invoke LOLBins, attempt permission traversal, flood syslog. | Cannot inspect agent memory or delete agent state files owned by `0700` `centralium` user. |
| **Compromised High-Privilege Daemon** | Can attempt to flood audit netlink queues, manipulate shared temp directories (`/tmp`), initiate network connections. | If attacker achieves ring-0 (kernel privilege), software-level EDR detection can be blinded by rogue kernel modules. |
| **Active Adversary (Remote Shell)** | Executes interactive commands, downloads obfuscated binaries, crafts multi-stage attack chains, triggers prompt injection in command lines. | Blind process killing without audit trail is prevented by Centralium rollback logging. |
| **Malicious Operator / Compromised Key** | Possesses valid API credentials; attempts to isolate all endpoints simultaneously. | Prevented by blast-radius limits and automatic dead-man isolation timer. |

---

## 4. Component-by-Component STRIDE Analysis

### 4.1 Collectors (eBPF, auditd, File Watchers)
* **Spoofing:** Adversary attempts to fake auditd netlink sequence numbers or spoof parent PID.  
  * *Mitigation:* Inode verification, `/proc` cross-checking, eBPF kprobe verification.
* **Tampering:** Adversary closes the audit socket or deletes rules.  
  * *Mitigation:* Self-protection watcher continuously probes audit netlink socket state and restores rules if unregistered.
* **Repudiation:** Malicious actor terminates before event capture.  
  * *Mitigation:* Synchronous kprobe/audit capture logs `sys_enter_execve` before process entry.
* **Information Disclosure:** Unprivileged user reads raw collector buffers containing credentials.  
  * *Mitigation:* Collector socket descriptors are root/service-owned; memory structures reside in private agent heap with `ProtectHome=read-only`.
* **Denial of Service:** Massive process spawn flood to saturate event ring buffers.  
  * *Mitigation:* High-watermark drop counting, leaky bucket rate limiters, non-blocking spill queues.
* **Elevation of Privilege:** Vulnerability in collector parsing allows arbitrary code execution.  
  * *Mitigation:* Memory-safe Python normalization; strict boundary checking on raw struct buffers.

### 4.2 Normalization & Pipeline
* **Spoofing:** Maliciously crafted event IDs mimicking legitimate events.  
  * *Mitigation:* UUIDv4 generation with HMAC canonicalization.
* **Tampering:** Modifying event fields in-flight.  
  * *Mitigation:* Frozen/immutable Pydantic model contracts (`NormalizedEvent`).
* **Repudiation:** Event dropped without record.  
  * *Mitigation:* Monotonically increasing drop counters and error logs.
* **Information Disclosure:** Sensitive credentials written to unmasked logs.  
  * *Mitigation:* Automatic secret and PII redactor (`centralium/agent/privacy/redaction.py`).
* **Denial of Service:** Algorithmic complexity attacks (ReDoS) on regex engine.  
  * *Mitigation:* Timeout-guarded pre-compiled regular expressions and bounded string lengths.
* **Elevation of Privilege:** Subshell execution during event enrichment.  
  * *Mitigation:* Direct syscalls and `/proc` file reads only; no external shell execution (`shell=False`).

### 4.3 Storage & SQLite WAL
* **Spoofing:** Injecting fraudulent findings into `findings` table.  
  * *Mitigation:* Single-writer lock and schema constraints; database file owned exclusively by `centralium:centralium`.
* **Tampering:** Direct SQLite database file editing or WAL truncation.  
  * *Mitigation:* `PRAGMA quick_check` at open; automatic corrupt file rotation and integrity alarms.
* **Repudiation:** Deleting incident records to erase evidence of breach.  
  * *Mitigation:* Append-only audit table with sequential transaction logs.
* **Information Disclosure:** Reading sensitive incident telemetry from disk.  
  * *Mitigation:* Column-level AES-256-GCM encryption for sensitive fields (`raw_metadata`, `details`).
* **Denial of Service:** Disk full exhaustion by inflating SQLite logs.  
  * *Mitigation:* WAL autocheckpoint limits, maximum row count caps, retention eviction policies.
* **Elevation of Privilege:** SQLite load_extension privilege escalation.  
  * *Mitigation:* SQLite extension loading permanently disabled.

### 4.4 Quarantine & AES-256-GCM Crypto
* **Spoofing:** Faking quarantine IDs or restoring a malicious file to an unauthorized location.  
  * *Mitigation:* 32-hex UUID validation; strict canonical `realpath` validation; prohibited restoration over protected system directories (`/etc`, `/usr/bin`, `/bin`).
* **Tampering:** Attacker modifies quarantined malware blob or injects symlink into quarantine root.  
  * *Mitigation:* `O_NOFOLLOW` on file descriptors, root-owned `0700` directory check, SHA-256 digest validation before restore.
* **Repudiation:** Quarantining files without accountability.  
  * *Mitigation:* Audit log records actor, reason, hashes, and timestamp for every action.
* **Information Disclosure:** Malware stored in plaintext accessible by other users.  
  * *Mitigation:* AES-256-GCM authenticated encryption at rest (`CQGCM1` envelope) with root-protected key file (`0600`).
* **Denial of Service:** Quarantining vital system binaries (e.g., `/bin/sh`) to brick endpoint.  
  * *Mitigation:* Protected paths whitelist (`/bin`, `/usr/bin`, `/lib`, `/sbin`, `/etc`) actively refuses quarantine.
* **Elevation of Privilege:** Restoring a file with SUID/SGID bits set to elevate privileges.  
  * *Mitigation:* Strict sanitization of restored file modes (`mode & 0o7777` with SUID bits masked, owner verified).

### 4.5 Response Engine & Playbooks
* **Spoofing:** Malicious process sends fake response directives to agent.  
  * *Mitigation:* Response actions only accept cryptographically signed dispatch or internal deterministic policy engine output.
* **Tampering:** Modifying rollback instructions to permanently brick network connectivity.  
  * *Mitigation:* Atomic write of rollback records with timestamped dead-man auto-release timers.
* **Repudiation:** Unlogged process termination or firewall isolation.  
  * *Mitigation:* Every action logged to audit repository before execution.
* **Information Disclosure:** Exposing network isolation rules or secrets during response.  
  * *Mitigation:* Output logged through PII/secret redactor.
* **Denial of Service:** Host permanently isolated due to network loss or crashed agent.  
  * *Mitigation:* Kernel-level iptables temporary rules and timed dead-man switch auto-recovery.
* **Elevation of Privilege:** Response action executing shell commands from attacker-controlled inputs.  
  * *Mitigation:* Declarative playbook parameters; parameterized execution with no shell expansion.

### 4.6 LLM Integration & Prompt Injection Guardrails
* **Spoofing:** Attacker crafts command line that tricks model into assuming system role.  
  * *Mitigation:* Random per-invocation delimitation nonces (`<<<DATA-{nonce}>>>`), system instruction priority locking.
* **Tampering:** Prompt injection attempts to force `verdict="BENIGN"` or `recommended_action="NONE"`.  
  * *Mitigation:* Output constrained by GBNF grammar (`get_ai_verdict_gbnf()`); LLM output is strictly advisory and vetted by deterministic policy engine before any action.
* **Repudiation:** LLM hallucinations denying actual malicious detections.  
  * *Mitigation:* Heuristic, YARA, and ML detections independently raise incidents regardless of LLM output.
* **Information Disclosure:** Model echoes private system prompt or secret host data.  
  * *Mitigation:* Secret redactor scrubs all inputs before LLM ingestion; system prompt contains strict non-disclosure directives.
* **Denial of Service:** Excessive prompt token lengths causing memory exhaustion or inference timeout.  
  * *Mitigation:* Strict token budget per role (`ROLE_TOKEN_BUDGETS`), input string truncation, and inference timeout semaphore.
* **Elevation of Privilege:** Model attempting to execute arbitrary code.  
  * *Mitigation:* Model output schema contains zero executable fields; action is an enum restricted to validated playbooks.

### 4.7 Outbound Sync Queue & Remote Transport
* **Spoofing:** Man-in-the-middle server spoofing.  
  * *Mitigation:* Strict TLS server verification; pinned CA certificates.
* **Tampering:** Modifying queued sync payloads in SQLite queue.  
  * *Mitigation:* Canonical SHA-256 deduplication hashing, SQLite WAL verification.
* **Repudiation:** Lost events during host offline transitions.  
  * *Mitigation:* Durable disk queue with exponential backoff and jittered retries; retention policies that preserve pending rows.
* **Information Disclosure:** Plaintext secrets in outbound sync payloads.  
  * *Mitigation:* Mandatory PII/secret redaction applied immediately upon enqueueing.
* **Denial of Service:** Large backlogs starving local disk storage.  
  * *Mitigation:* Max age, max row count, and max byte size retention enforcement with emergency memory spill buffers.
* **Elevation of Privilege:** SQL injection through queue payload parameters.  
  * *Mitigation:* Parameterized queries exclusively (`?` SQLite placeholders).

### 4.8 Observability & Health Endpoints
* **Spoofing:** Spoofing `/healthz` or `/readyz` status.  
  * *Mitigation:* Endpoints bound to localhost or protected by systemd socket filters; read-only status reporting.
* **Tampering:** Corrupting OpenTelemetry traces or metric streams.  
  * *Mitigation:* Authenticated OTLP transport, in-memory buffering with bounds.
* **Repudiation:** Unmonitored degradation of agent detection stages.  
  * *Mitigation:* Pipeline stage-latency export (P50, P95, Mean, Error counts) directly exposed via metrics.
* **Information Disclosure:** Metrics leaking sensitive command-lines or host secrets.  
  * *Mitigation:* Metrics only expose aggregated latency floats, counters, and generic stage names.
* **Denial of Service:** HTTP flood against agent `/healthz` endpoint.  
  * *Mitigation:* Threading server with short connection timeouts and lightweight static status checks.
* **Elevation of Privilege:** Web server vulnerabilities in metric/health server.  
  * *Mitigation:* Standard Python `http.server` with zero shell/file execution capabilities; non-root user execution.

---

## 5. Mitigated Threats Matrix & Code Cross-References

| Threat ID | STRIDE Category | Specific Threat Description | Mitigating Code & Architectural Control |
| :--- | :--- | :--- | :--- |
| **TH-01** | **Tampering** | Quarantined malware file altered or replaced on disk. | `centralium/agent/quarantine/crypto.py` (AES-256-GCM AEAD tag) & `quarantine/manager.py` (SHA-256 pre-restore check). |
| **TH-02** | **Elevation** | SUID/SGID binary restored to compromise root. | `centralium/agent/quarantine/manager.py` (strips execute bits, checks canonical target directory). |
| **TH-03** | **Info Disclosure** | Plaintext API keys, passwords, or AWS tokens logged or sent to LLM/sync. | `centralium/agent/privacy/redaction.py` (`SecretRedactor`, `RedactingLogFilter`, `install_log_redaction`). |
| **TH-04** | **Tampering** | Binary or update tampering during release or distribution. | `scripts/sign_manifest.py` (Ed25519 cryptographic signature & SHA-256 manifest verification). |
| **TH-05** | **Elevation** | Compromised agent daemon takes over host operating system. | `packaging/systemd/centralium.service` (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=...`). |
| **TH-06** | **Tampering** | Adversarial prompt injection hijacking EDR recommendations. | `centralium/agent/llm/prompts.py` (delimitation nonces, `sanitize()`) & `centralium/agent/llm/grammar.py` (GBNF schema). |
| **TH-07** | **Denial of Service** | Host offline network isolation stranded indefinitely. | `centralium/agent/response/reversibility.py` (timed dead-man auto-release switch). |
| **TH-08** | **Denial of Service** | High-volume event flood crashes agent sync pipeline. | `centralium/agent/sync/queue.py` (non-blocking bounded memory spill buffer + WAL durable queue). |
| **TH-09** | **Repudiation** | Operator executes destructive remediation without trail. | `centralium/agent/storage/audit.py` & `response/dispatcher.py` (mandatory audit logging with actor and justification). |
| **TH-10** | **Info Disclosure** | Unencrypted sensitive SQLite database columns leaked in backup. | `centralium/agent/quarantine/crypto.py` (`encrypt_field` / `decrypt_field` AES-256-GCM column encryption). |

---

## 6. Residual Risk Disclosures

Despite multi-layered defense-in-depth controls, certain residual risks cannot be eliminated without hardware or kernel hypervisor guarantees:

1. **Kernel-Space (Ring-0) Compromise:**
   * *Risk:* If an adversary achieves ring-0 kernel code execution (e.g., exploiting a vulnerable signed driver or kernel zero-day), they can detach eBPF kprobes, terminate the `centralium` process, or manipulate kernel memory directly.
   * *Disclosure:* EDR agents operating as user-space daemons cannot guarantee survival against an in-kernel adversary. Detection of initial exploitation before ring-0 transition remains the primary defense.

2. **Active AES Key Residence in Process RAM:**
   * *Risk:* While quarantined blobs and sensitive DB fields are encrypted at rest with AES-256-GCM, the active key is loaded into agent memory while the agent is running. A local root attacker with `CAP_SYS_PTRACE` or physical memory dump access could extract keys from process memory.
   * *Disclosure:* Ephemeral in-memory key exposure is inherent to live encryption without dedicated HSM/TPM enclave hardware.

3. **LLM Non-Determinism & Semantic Drift:**
   * *Risk:* Although prompt injection is mitigated by delimitation, GBNF grammar constraints, and sanitization, local language models remain probabilistic. A highly novel adversarial phrasing might cause the model to generate suboptimal reasoning summaries.
   * *Disclosure:* Centralium enforces that the LLM is **never** in the critical remediation execution loop—all automated blocking actions are evaluated by deterministic policy rules.

4. **Extreme Kernel Event Dropping under DoS Floods:**
   * *Risk:* In synthetic worst-case scenarios where millions of processes are spawned per second, the kernel audit ring buffer or eBPF ring buffer may overflow before userland ingestion.
   * *Disclosure:* Centralium increments drop counters and generates telemetry alerts when buffer overflow occurs, alerting the SOC that blind-spot conditions existed.

---

## 7. Security Verification & Auditing

* **Static Analysis:** Linted with `ruff check` and type-checked with `mypy`.
* **Automated Security Suites:** Tested via `tests/security/quarantine_security_test.py`, `tests/unit/test_phase2h_crypto.py`, `tests/unit/test_phase2h_redaction.py`, and `tests/unit/test_phase2h_packaging_and_signing.py`.
* **Sandboxing Validation:** Service unit checked against `systemd-analyze security centralium.service` targeting exposure score `<= 1.5` (LOW RISK).
