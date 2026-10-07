# CENTRALIUM PHASE 2: NEXT-GEN BUILD PROMPT (for Antigravity / agy)

## Context
Phase 1 is complete: a working Linux/Windows EDR prototype. Read first: `README.md`, `HANDOFF.md`, `docs/ARCHITECTURE.md`, `docs/ACCEPTANCE.md`, `docs/BENCHMARKS.md`, `docs/PROJECT_OVERVIEW.md`, and the original spec `/home/mittai/Downloads/Centralium_Claude_Master_Build_Prompt.txt`. All Phase 1 contracts (`centralium/agent/models.py`, `interfaces.py`, `pipeline.py`) stay stable. Extend them additively and keep every existing test green.

Work autonomously. Do not ask questions. Make sensible decisions, document assumptions, and keep going until each phase's exit criteria are met.

## Non-negotiable rules (unchanged from Phase 1)
1. The LLM never executes anything: `LLM -> structured output -> deterministic policy -> validation -> approved action`. No `shell=True`, `eval`, `exec` or `os.system` anywhere. Everything uses argv lists.
2. Demo and test modes never perform destructive actions. No real destructive tests on this machine. Use spawned throwaway children, temp directories and mock runners.
3. No fabricated numbers. Every metric, latency or detection claim is measured and reproducible by a command, or marked "Not enough validated data" / "not measured". Synthetic-data results are labelled synthetic.
4. The engine must keep working with the internet, the dashboard, the LLM and the models all unavailable.
5. No cloud LLMs. One local model, Gemma 3 1B IT Q4_K_M, for all generative AI. Embedding models are allowed if small and local, but disclose them.
6. No sudo, nothing outside the project directory, no secrets in code or logs. Treat downloaded files (datasets, binaries, repos) as untrusted: read-only, never execute them, verify checksums, record provenance.
7. Respect licenses. Do not redistribute restricted datasets. Update `docs/REUSE_MATRIX.md` and `THIRD_PARTY_NOTICES.md` for every new dependency or reference. Do not copy AGPL/patent-pending code from edr-graph.
8. Quality gates after every phase: `ruff check .`, `ruff format --check .`, `mypy`, full `pytest`, and in `dashboard/frontend` `npm run typecheck`, `npm run build`, `npm test`. Fix real bugs and never weaken a test. Keep `docs/ACCEPTANCE.md` honest (PASS / PARTIAL / NOT VERIFIED with evidence).

Use subagents or parallel workstreams where modules are independent. Keep module boundaries behind the existing interfaces so components stay swappable.

---

## PHASE 2A: Close the Phase 1 gaps (do first)

1. **Flaky test.** `tests/unit/test_pipeline.py::test_pipeline_process_approved_actions_flows_through_policy_gate` failed once in a full run and passed alone. Find the order or timing dependence, fix the root cause, then run the full suite 5 times in a row (also with `pytest -p no:randomly` and with random ordering) to prove it is stable.
2. **Reconcile the numbers.** Check that `ACCEPTANCE.md` counts match the file's actual items (it claimed 39 PASS and 2 PARTIAL, but the file shows three PARTIAL headings). Make the summary generated from the file by a script so it cannot drift.
3. **Real Windows verification.** Add a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs on `ubuntu-latest` and `windows-latest` (Python 3.13): install, ruff, mypy, pytest, Windows-guarded tests. Windows-only tests (Sysmon XML, `wevtutil`, `netsh` argv, Windows service wrapper import) must be marked and run in CI. Document that Windows is verified only by CI and mocks until run on a real endpoint. Do not claim more.
4. **Live auditd and firewall verification in a container.** Provide `docker/` test harness (rootless where possible, documented privileged mode otherwise) to exercise the auditd tailer and nftables/iptables isolation inside a throwaway container or network namespace (`unshare -n` where available), never on the host network. Report what ran for real vs mocked.
5. **ONNX benchmark.** Add ONNX Runtime inference to the benchmark and compare to sklearn (latency p50/p95, batch throughput). Use it in the runtime if it is faster, with a config switch and an equivalence test.
6. **Dependency hygiene.** Run `pip-audit` and `npm audit`, report findings, upgrade what is safe, and generate a CycloneDX SBOM (`scripts/gen_sbom.py`).
7. Re-run the live paths and record evidence in `docs/ACCEPTANCE.md`: `centralium run --mode PASSIVE` briefly on this machine, plus a Playwright/Chrome screenshot check of the dashboard on demo data (red sidebar, white UI, zero console errors).

**Exit criteria:** stable suite across repeated runs, CI workflow committed, container harness documented, acceptance file generated and consistent.

---

## PHASE 2B: Real telemetry (replace the stubs)

1. **Linux eBPF collector** (replace the stub): exec, connect, accept, openat (write intent), rename, unlink and ptrace/memfd events using `bcc` or `libbpf` through a Python loader (or `bpftrace` JSON output if that is more portable). It needs root or CAP_BPF, so run the privileged part in a minimal separate helper process that emits events over a Unix socket to the unprivileged agent. Keep auditd and psutil fallbacks. Test with a loader-mock plus a privileged integration test that is skipped (and reported as such) when privileges are missing.
2. **fanotify/inotify file telemetry** for the protected-directory and ransomware paths, with bounded queues and rate limits.
3. **Windows real-time ETW** (via `pywin32` or a `krabsetw`/`pyetw` binding if installable; otherwise Sysmon subscription through the Event Log API) replacing the poller fallback. Provide a Sysmon config file in `rules/sysmon/` (original, minimal, documented). Verified only through CI/mocks, so label it so.
4. **Container and cloud-workload awareness:** cgroup/container id enrichment (Docker/containerd/Kubernetes pod metadata from `/proc/<pid>/cgroup`), container-escape heuristics (mounting the Docker socket, privileged flags, `nsenter`, host-PID access).
5. **Authentication telemetry:** Linux `auth.log`/journald and Windows 4624/4625/4648/4672 normalized to events, to feed identity detections.

**Exit criteria:** each collector emits valid `NormalizedEvent`s in a live or recorded test, reports health honestly, and degrades safely.

---

## PHASE 2C: Next-gen detection and ML

1. **Grammar-constrained LLM output.** Use llama.cpp GBNF / JSON-schema grammar so Gemma can only emit the `AIVerdict` contract. Keep Pydantic validation and retry as defense in depth. Measure the valid-first-try rate before and after and the latency impact.
2. **Sequence and provenance models.**
   - (a) Process-lineage and syscall n-gram / Markov anomaly model (fast, explainable).
   - (b) Graph-based anomaly detection on the provenance graph (node2vec-style embeddings or a small GNN via PyTorch Geometric only if it installs on Python 3.14; otherwise a sparse-matrix approach). Compare against the Isolation Forest baseline on the same held-out groups and report honestly, including negative results.
3. **Static malware classifier.** EMBER-style PE feature extraction and a gradient-boosted classifier (LightGBM or sklearn HistGradientBoosting) trained on a legally usable public dataset (for example EMBER 2018 features or SOREL-20M if license and size permit; else a documented adapter plus a tiny synthetic fixture). Add ELF features. Show precision/recall/FPR on a held-out split with calibration (reliability curve).
4. **DNS tunneling, DGA and exfiltration** detection (entropy, n-gram language model, query-rate and volume anomalies), wired into the C2 and exfil stages.
5. **Credential-access and lateral-movement detections:** LSASS access, `/etc/shadow` reads, SSH agent hijack, new remote-service logins, PsExec/WMI/WinRM and SMB admin-share patterns, mapped to ATT&CK.
6. **Process-injection and memory detection:** W+X mappings, `memfd_create` execution, ptrace injection, reflective loader indicators on Linux; remote-thread / hollowing indicators on Windows events. Optional bounded YARA scan of suspicious process memory (read-only, size-capped, never stops the process).
7. **Ransomware canaries and rollback.**
   - Honeyfile canaries in monitored directories (instant high-confidence signal when touched).
   - Pre-emptive protective snapshot action `SNAPSHOT_PROTECT` (btrfs/LVM/ZFS/VSS where available, otherwise copy-on-write of canary and critical files), run only through the policy gate.
   - Entropy sampling of written files (bounded and opt-in).
8. **Sigma and standards support.**
   - Sigma rule loader (a subset: process creation, file, network, registry) compiled into the normalized schema, with a local rules dir and validation.
   - STIX 2.1/TAXII-style IOC import (offline file import first).
   - OCSF-compatible JSON export.
   - ATT&CK Navigator layer export from detected coverage.
9. **Application control and device control** (policy-driven): execution allowlist mode, removable-media event detection. Detect and alert by default.
10. **Posture and exposure:** offline vulnerable-package inventory (OSV/NVD-style local DB import) and a minimal CIS-style hardening check set (SSH config, world-writable dirs, sudoers, firewall state), reported as posture findings, not blockers.

**Exit criteria:** each detector has positive and negative tests, honest metrics where ML is involved, and does not add LLM calls on the hot path.

---

## PHASE 2D: LLM, RAG and analyst experience

1. **Better retrieval.** Add hybrid retrieval (BM25 + vectors) with reranking, and an optional small local embedding model through llama-server (embedding GGUF, disclosed and checksummed). Build a RAG evaluation harness (a golden query set, recall@k and MRR) and report real numbers against the lexical baseline.
2. **LLM evaluation harness.** A golden set of structured incidents with expected verdict, severity and technique range. Report verdict agreement, valid-JSON rate, latency and the prompt-injection red-team pass rate. Add an expanded prompt-injection corpus (command lines, filenames, domains, document text) and run it in CI.
3. **Latency work for the 1B model.** KV-cache prefix reuse for the static system prompt, shorter evidence packing, token budgets by role, an LRU cache keyed by incident fingerprint, and a background analysis queue so the response never waits on the LLM. Report before and after.
4. **Natural-language threat hunting.** The analyst types a question. The LLM only produces a JSON hunt specification (source, fields, operators, values, time range), which is validated against the existing whitelisted query builder. It never produces SQL or commands. Show the validated query to the user before it runs.
5. **Investigation copilot** in the dashboard: a read-only assistant restricted to a whitelist of read-only functions (get incident, get timeline, get process tree, get related IOCs). Citations to the evidence rows used. No write tools.
6. **Auto-generated incident report** (Markdown, then PDF if a library is available offline): timeline, attack chain, MITRE mapping, evidence, risk breakdown, actions taken, recommended follow-up, with the AI parts labelled and the mock/real status stated.
7. **Explainability.** A per-decision "why this score" trace: contribution of each score family, top ML features with their deviation from baseline, the graph path used, the policy rule that fired. Counterfactuals ("would be MEDIUM without the unsigned-binary signal"). Show it in the AI Analyst page.

**Exit criteria:** the evaluation harnesses run from the CLI (`centralium eval rag|llm|injection`) and write reports, and the dashboard shows only measured results.

---

## PHASE 2E: Learning loop and model operations

1. **Analyst feedback loop.** Mark true positive / false positive / benign-expected on findings in the UI. Feedback goes to a labelled store, feeds baseline and allowlist suggestions (never auto-applied), and builds a retraining dataset with provenance.
2. **Retraining and model registry.** Versioned models with metadata, SHA-256 and optional Ed25519 signatures. Shadow-mode evaluation (a candidate model scores live traffic without acting) and an automatic comparison report. Promote or roll back through an audited admin action only.
3. **Drift monitoring.** Feature distribution drift (PSI / KS) against the training reference, a model-health dashboard card and alerts when drift is high. Never claim accuracy without labels.
4. **Active learning queue.** Rank uncertain events for analyst labelling.
5. **Adversarial robustness.** An evasion test suite for ML (feature perturbation within realistic limits), poisoning resistance tests (baseline-learning guard), and fuzzers for parsers (auditd, Sysmon XML, PE/ELF, YARA bundle, sync payloads). Report the findings and fix them.

---

## PHASE 2F: Fleet and enterprise (management plane)

1. **Fleet server** (FastAPI service, `dashboard/` or a new `fleet/` package): endpoint enrollment with one-time tokens, mTLS between agent and server (self-signed CA tooling in `scripts/pki/`), heartbeats, per-endpoint health, last-seen, version and policy state.
2. **Signed policy and rule distribution.** Policies, YARA bundles, Sigma rules and models are pushed as signed bundles using the existing update verifier. The agent verifies, stages and applies, with rollback on failure and an audit entry on both sides.
3. **Cross-host correlation.** Shared IOC and indicator sightings, lateral-movement graph across hosts, fleet-wide threat hunting with the same whitelisted query model, and a fleet-level incident view.
4. **Outbound integrations (optional, off by default):** syslog/CEF, Splunk HEC and Elastic bulk forwarders, a webhook notifier, and ticket export (JSON). Each is HTTPS-only with the token from the environment, queued through the durable queue, and never blocks detection.
5. **Case management** in the dashboard: assign, notes, status, SLA timers, linked incidents, audit trail.
6. **RBAC refinement and SSO readiness:** OIDC login as an optional provider (disabled by default), per-endpoint-group scoping, and approval workflows with two-person approval for ISOLATE_ENDPOINT in production mode.

---

## PHASE 2G: Safer, smarter response

1. **Blast-radius estimator and dry-run diff.** Before any destructive action, show exactly what would happen (processes, files, connections affected, dependent services) and require approval above a configurable threshold.
2. **Rollback and reversibility.** Every action records an undo (resume process, remove firewall rule set, restore quarantined file, release isolation) with a timed auto-release for isolation (dead-man switch, so a lost agent cannot strand a host offline forever).
3. **Playbooks as data.** Declarative, validated response playbooks (YAML/JSON schema) selected by the policy engine. The LLM may rank candidates but never writes or edits a playbook.
4. **Purple-team simulator.** A safe emulation harness that generates benign, clearly marked synthetic telemetry for ATT&CK techniques (no real malicious payloads and nothing that touches the host beyond temp dirs), runs it through the pipeline and reports detection coverage per technique. This yields a measured coverage score and a gap list.

---

## PHASE 2H: Privacy, supply chain and hardening

1. **Encryption at rest** for quarantine blobs and sensitive DB fields (AES-GCM through `cryptography`, key from the OS keyring or a root-only key file, rotation supported).
2. **PII and secret redaction** before anything is sent to the LLM, written to logs or queued for sync (configurable patterns, tested).
3. **Release engineering.** Reproducible builds where feasible, a signed release manifest (the Ed25519 tooling exists), SBOM, `deb`/`rpm` packaging recipes (`packaging/`), and a Windows MSI/winget recipe (documented, built only in CI). Hardened systemd unit review with `systemd-analyze security` score recorded.
4. **Threat-model document** (`docs/THREAT_MODEL.md`): trust boundaries, STRIDE per component, attacker-on-host assumptions, and a residual-risk list. Cross-check against the code and fix any gap you find.
5. **Observability.** OpenTelemetry-compatible traces/metrics (optional), a structured JSON log schema with secret redaction, a `/healthz` and `/readyz` for agent and server, and a stage-latency dashboard card.

---

## PHASE 2I: Performance (measure first)

1. Profile the hot path (`cProfile` / `py-spy`) and publish the profile summary.
2. Batch and parallelize where measurements justify it (multiprocessing for CPU-bound feature extraction, batched ML inference, batched graph writes), with a bounded-memory guarantee.
3. Consider an optional native accelerator (Cython, PyO3/Rust) only for a measured top-3 hotspot, behind a feature flag with a pure-Python fallback and an equivalence test. Do not rewrite the engine.
4. Re-run `centralium benchmark` and report before and after for every optimization, including regressions. Update the three resource profiles with measured RAM/CPU.

---

## Deliverables
- Code, tests and docs for every phase you complete, behind the existing interfaces.
- New CLI commands as needed (`centralium eval`, `centralium simulate`, `centralium fleet ...`, `centralium model ...`) with `--help` text.
- Updated: `README.md`, `docs/ARCHITECTURE.md`, `docs/ACCEPTANCE.md` (generated summary), `docs/BENCHMARKS.md`, `docs/REUSE_MATRIX.md`, `THIRD_PARTY_NOTICES.md`, `docs/LICENSE_IP_NOTES.md`, `docs/THREAT_MODEL.md`, `HANDOFF.md`.
- A `docs/PHASE2_REPORT.md` listing per item: DONE / PARTIAL / SKIPPED, the evidence command and its real output, measured numbers, and known limitations. Anything not run for real must be called out as mocked or unverified.

## Priority order if time is short
2A (gaps) > 2C items 1, 4, 7 (grammar output, DNS/exfil, ransomware canaries) > 2B items 1-2 (eBPF, fanotify) > 2D items 1-2, 7 (retrieval and LLM evaluation, explainability) > 2G (dry-run, rollback) > 2E > 2F > 2H > 2I. Finish and verify each item before starting the next, and leave the repo green at every stopping point.
