# Centralium

Local-first Linux/Windows EDR/EPP **prototype**: deterministic EPP (hash / IOC / YARA / rules / static analysis)
-> behavior features -> ML (Isolation Forest + Random Forest) -> attack graph (Kuzu) -> novelty filter ->
local RAG -> ONE local LLM (Gemma 3 1B IT Q4_K_M via llama.cpp) -> risk -> deterministic policy -> response ->
audit -> SOC dashboard (FastAPI + Next.js/React/TypeScript).

The LLM is an analyst, never an enforcer: `LLM -> structured verdict -> deterministic policy -> validated
action`. Known malware is stopped by the deterministic path and never sent to the LLM. Everything keeps working
with the dashboard, the internet, or the LLM unavailable.

> Honest status: this is a prototype verified on **Linux** only. See [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) for
> a per-item PASS / PARTIAL / NOT VERIFIED list. ML metrics are on **synthetic** data and are not real-world
> performance. Performance numbers are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (measured, hardware listed).

## Architecture

```
 collectors (auditd | psutil | eBPF stub | Windows EventLog/ETW/Sysmon)        replay (demo/test)
        |                                                                              |
        v   bounded queue (drop + count on overflow, never blocks a collector)         v
 normalization (OCSF-like NormalizedEvent; path/IP/port/hash validation)
        |
        v
 fast EPP: SHA-256 / IOC cache / blocklist / allowlist / path rules --(known malicious)--> risk -> policy -> response
        |   (+ YARA + PE/ELF static analysis, scan_depth >= 2)                              (short-circuit: no ML/RAG/LLM)
        v
 behavior engine: process/network/file/behavior/ransomware features + LOLBin, persistence, ransomware findings
        |  (ml_eligible gate)           lineage evidence carried to later events of the same process
        v
 ML: Isolation Forest (anomaly) + Random Forest (class)  <- ml/features/behavior_adapter.py maps feature names/scales
        |
        v
 graph (Kuzu behind an adapter; batched writes) -> chain reconstruction, MITRE, attack-stage prediction
        |
        v
 novelty filter (baselines, learning mode) -> pre-risk
        |  gate: pre_risk >= 60 AND novel AND mode != LEARNING AND LLM available
        v
 RAG (top-k from MITRE / rules / LOLBin / playbooks)  ->  local Gemma 3 1B (strict AIVerdict JSON, retry once)
        |
        v
 risk engine (A-G -> H, config weights, confidence-aware, known-bad floor) -> incident (grouped by process lineage)
        |
        v
 policy engine (allowlists, protected processes, thresholds, approval, mode) -> ordered plan
        |        PASSIVE/LEARNING/demo/test: simulated only          ACTIVE/PANIC: executor (argv only, no shell)
        v
 response: ALERT | BLOCK_CONNECTION | SUSPEND/TERMINATE_PROCESS | QUARANTINE_FILE | ISOLATE_ENDPOINT
        |
        v
 SQLite WAL (events, findings, incidents, ML/AI, actions, audit hash chain, sync queue) + graph snapshots
        |                                                  |
        v                                                  v
 SOC dashboard (read/management API)             durable sync queue -> dashboard /api/ingest (retry, backoff)
 (dashboard-approved actions -> ApprovedActionDispatcher -> policy recheck -> executor)
```

Composition root: `centralium/agent/runtime.py` (`build_runtime`). Module contracts: `docs/ARCHITECTURE.md`.

## Install (Linux)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e . --no-deps
# optional extras (all have graceful fallbacks): .venv/bin/pip install -e '.[yara,graph,static,rag,onnx,dev]'
.venv/bin/centralium version
.venv/bin/centralium init-db
```
Python 3.13+ is the target; the dev machine runs 3.14.7 (all dependencies have wheels). The dashboard UI is
prebuilt into `dashboard/frontend/out` (rebuild: `cd dashboard/frontend && npm install && npm run build`).

## Run

```bash
centralium run --mode PASSIVE              # live agent: psutil (+auditd if readable); detect + alert only
centralium run --mode LEARNING             # baseline only, never destructive
centralium run --profile low-resource      # LLM off, hash/IOC only
centralium dashboard                       # http://127.0.0.1:8765 ; tokens printed ONCE on first start
centralium mode show | mode set PASSIVE --reason "why"   # explicit, audited, persisted; ACTIVE/PANIC need --confirm
centralium scan /path/to/file              # EPP + YARA + static analysis of one file (never executed)
centralium quarantine list | quarantine restore ID --reason "..." --yes
centralium audit verify                    # hash-chained audit log; exit 1 on tampering
```
`run` refuses to start in ACTIVE/PANIC unless `--enable-enforcement` is given (real response actions).
Without root, auditd is skipped and psutil polling is used; firewall actions need privileges and otherwise fail
visibly (never escalated). Config: TOML (`--config` / `$CENTRALIUM_CONFIG`), env `CENTRALIUM_<SECTION>__<FIELD>`.
`CENTRALIUM_LLM_SERVER_URL`, `CENTRALIUM_SYNC_URL`, `CENTRALIUM_SYNC_TOKEN` are read by their modules.

### Windows (UNTESTED on real Windows)
```powershell
py -3.13 -m venv .venv; .venv\Scripts\pip install -r requirements.txt; .venv\Scripts\pip install -e . --no-deps
.venv\Scripts\centralium run --mode PASSIVE
```
Windows collectors (Event Log/Sysmon via `wevtutil`, ETW stub), Windows Firewall/service responders and the
Windows-service wrapper exist and are unit-tested with mocks, but **no part of Centralium has been run on a real
Windows host**. Treat Windows support as unverified. `requirements.txt` pins were resolved on Linux.

## Demo (safe, synthetic)

```bash
centralium demo                       # fresh data/demo/, mock LLM unless a real one is reachable (labelled)
centralium demo --serve               # then serve the dashboard on the demo DB
CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080 centralium demo   # real Gemma (slow on CPU: minutes)
```
Replays: normal browser, developer workflow, admin script (baselined in an audited LEARNING phase), Office ->
PowerShell -> dropper -> C2 chain, ransomware-like burst, persistence, C2-like beacon, known test IOC. Populates
graph, ML scores, risk, RAG, LLM verdicts, incidents and response *recommendations*. Demo mode forces a simulating
executor and a closed destructive gate; the run asserts that no destructive action was executed.
Indicators are TEST-NET IPs, `.test`/`.invalid` domains and the EICAR hash - inert strings only.

## Local model (Gemma 3 1B IT Q4_K_M, llama.cpp)
See [docs/LOCAL_MODEL.md](docs/LOCAL_MODEL.md).
```bash
scripts/download_model.sh && scripts/llm_server.sh &      # llama-server on 127.0.0.1:8080
export CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080
```
Weights are not in the repo (accept the Gemma terms yourself). If the server is down, Centralium reports "AI
unavailable" and keeps protecting; a mock is only ever used in demo/test mode and is labelled `[MOCK]`.

## RAG
`centralium rag ingest` (index in `<data_dir>/rag_index.db`), `centralium rag query "text"`. Documents live in
`rag/documents/`. RAG is invoked only for gated high-risk events. See [docs/RAG.md](docs/RAG.md).

## ML commands
`centralium ml prepare-dataset | extract-features | train-anomaly | train-classifier | validate | test | export | benchmark | all`
(pass-through to `ml/cli.py`). Models are sha256-verified before `joblib` loads them. The dataset is **synthetic**
(hand-written priors): reported precision/recall/F1/ROC-AUC describe separability of synthetic scenarios only.
`ml/features/behavior_adapter.py` reconciles the behavior engine's feature names/scales with the ML schema
(`tests/integration/test_feature_reconciliation.py`).

## Tests and quality gates
```bash
.venv/bin/pytest -q                    # everything (unit, integration, security, ml, e2e, performance smoke)
centralium e2e                         # only tests/e2e: the 10 spec scenarios + acceptance extras (test mode)
.venv/bin/pytest tests/e2e -q -m e2e   # same, via pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy
cd dashboard/frontend && npm run typecheck && npm run build
centralium benchmark                   # writes docs/BENCHMARKS.md + docs/benchmarks.json
```
E2E tests run only in demo/test mode: process/firewall back-ends are replaced by failing stubs so any OS touch
fails the test; the only real process actions target a `sleep` child the test spawned itself.

## Profiles
`--profile low-resource | balanced | analysis` (`config.RESOURCE_PROFILES`): LLM on/off, ctx/tokens/threads,
scan depth, queue size, telemetry rate cap, graph batch size. Measured requirements per profile:
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) (section "Profiles"). Not every machine can run the LLM; measure first.

## Security model
* No `shell=True`; the single subprocess spawner for responses takes argv lists; every pid/path/IP/port is validated
  in the policy engine *and again* in the executor; protected processes/paths and own process lineage are refused;
  PID-reuse guard.
* Destructive actions need: mode ACTIVE/PANIC (PASSIVE only if configured) AND not demo/test AND policy allow AND
  (user approval unless PANIC). Mode changes are explicit, audited, persisted. LLM output only selects among actions
  the deterministic ladder already permits and cannot soften a known-malicious or CRITICAL response (except an
  explicit BENIGN verdict at non-known evidence).
* `llm/` cannot import `subprocess` or any executor (AST test), and hostile model output never reaches argv/pids
  (`tests/security/test_llm_isolation.py`).
* Audit log is hash-chained; `audit verify` detects edits/deletions (tail truncation needs an external head anchor).
* Dashboard: bearer tokens (hashed at rest, shown once), RBAC, rate limit, security headers, loopback by default.
* Sync: bearer token from env, https (http only on loopback), dedup + backoff, no automatic file upload.
* Models: joblib artifacts are sha256-verified before load. YAML/pickle from untrusted input is not used.

## Limitations
Linux-only verification; eBPF and ETW collectors are stubs; auditd needs root; firewall/systemd/Windows-service
response paths are verified with a mock runner only; the in-process `llama-cpp-python` backend is unverified (the
`llama-server` backend is verified); the 1B model often returns invalid JSON (retry once, else "AI unavailable") and
takes 15-45 s per analysis on CPU; ML trained on synthetic data; threat-intel feeds are bundled test IOCs unless
you enable network updates; graph is single-host; dashboard is single-node; no signed-update distribution service.
Licensing: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/REUSE_MATRIX.md](docs/REUSE_MATRIX.md).
