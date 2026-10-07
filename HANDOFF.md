# Centralium: handoff for the next coding agent

Spec: /home/mittai/Downloads/Centralium_Claude_Master_Build_Prompt.txt (read it fully; it is the source of truth).
Env: Python 3.14 venv at .venv (spec says 3.13; requires-python >=3.13). No sudo needed. Never run destructive actions on this machine; demo/test mode must stay non-destructive.
Frontend decision (user): Next.js (static export), not Vite. Backend: FastAPI.

## Done by module agents (self-reported, not independently re-verified)
- Foundation: config, models (strict AIVerdict), interfaces, nulls, pipeline (stage isolation, known-malware short-circuit, LLM gating), SQLite WAL storage, hash-chained audit log. docs/ARCHITECTURE.md
- Collectors/behavior/LOLBin/persistence/ransomware/normalization: centralium/agent/{collectors,normalization,behavior,lolbins,persistence,ransomware}
- EPP/YARA/static analysis/threat intel: centralium/agent/{epp,yara,malware_analysis,threat_intel}, rules/
- ML (IsolationForest + RandomForest, synthetic data, ONNX export): ml/, centralium/agent/ml. Metrics are SYNTHETIC-data only.
- Graph (Kuzu + in-memory), novelty, risk (calibrated), policy, response, quarantine: centralium/agent/{graph,novelty,risk,policy,response,quarantine}
- RAG (sqlite-vec) + LLM client (llama-server HTTP; MockLLM labelled): centralium/agent/{rag,llm}; docs/LOCAL_MODEL.md, docs/RAG.md. Real Gemma 3 1B reported working via llama-server (~20 s/analysis CPU); model in data/models (git-ignored).
- Sync queue, self-protection, signed updates, reuse matrix, notices: centralium/agent/{sync,self_protection}, docs/REUSE_MATRIX.md, docs/LICENSE_IP_NOTES.md, THIRD_PARTY_NOTICES.md
- Dashboard: dashboard/backend (FastAPI, RBAC tokens), dashboard/frontend (Next.js, 17 pages, red sidebar/white UI)
- Last reported full suite: 788 passed, 1 skipped; ruff + mypy clean.

## Remaining (integration stage; was in progress when handed off, check what already exists first)
1. centralium/agent/runtime.py: build_runtime(config) wiring all real modules into Pipeline. Executor must get simulate=config.demo_mode or config.test_mode.
2. Pipeline must execute the policy engine's ordered plan() (currently only first action). Dashboard-approved response_actions rows must flow through the policy gate to the executor (never a shell).
3. Write graph snapshots (table graph_snapshots, JSON column `snapshot` {nodes,edges}) so the dashboard graph page shows data.
4. Reconcile behavior FEATURE_NAMES with ml/features/schema.py (mismatch silently drops features); add test.
5. CLI (Typer) in centralium/agent/main.py: run, demo, e2e/test-mode, dashboard (snippet: lazy-import dashboard.backend.run.serve), mode set/show (audited), ml, rag ingest, scan, quarantine list/restore, audit verify, benchmark. `demo` is currently a stub.
6. Demo mode: replay ml/datasets/replay/demo_replay.jsonl (+ scenarios) through the full pipeline; destructive disabled.
7. E2E tests for the 10 spec scenarios + remaining acceptance items (tamper, offline queue recovery, process suspend/terminate on throwaway child, network block with mock runner).
8. Benchmarks (measured only) -> docs/BENCHMARKS.md. Funnel counts raw->EPP->ML->graph->LLM->incidents.
9. [DONE] Deps: add cryptography (optional/dep), skl2onnx (optional), types-psutil or mypy override; .gitignore data/, node_modules, out, ml/datasets/data/.
10. Whole-repo security pass; ruff, mypy, pytest, npm build/typecheck all green.
11. README.md complete; docs/ACCEPTANCE.md with honest PASS/PARTIAL/NOT VERIFIED per item.

## Known honest limitations
- Windows collectors/firewall/service never run on real Windows; firewall/systemd paths only verified with a mock runner.
- eBPF and ETW are stubs; auditd tailer untested against live auditd; llama-cpp-python in-process path unverified (no 3.14 wheel).
- ML metrics synthetic; IsolationForest recall ~0.6 at 5% FPR. No real-world detection claims.
- edr-graph is AGPLv3 + patent-pending notice: nothing was copied; flagged for legal review.
- Dashboard CSP needs 'unsafe-inline' scripts (Next static export). Escape LLM output in the UI.
