# Local model (Gemma 3 1B IT, Q4_K_M, llama.cpp)

Centralium uses exactly ONE runtime model for every generative role (Threat Analyst, Malware
Analyst, Incident Summarizer, Threat Hunter, MITRE explainer, Risk explainer, Response
recommender, Attack-chain explainer). Roles differ only by system prompt
(`centralium/agent/llm/prompts.py`). No cloud LLM, no Ollama requirement.

## Verification status (honest)

On the development machine (Linux x86_64, 12 cores, CPU only) the real model was run:

* GGUF `gemma-3-1b-it-Q4_K_M.gguf` (806,058,240 bytes, SHA-256
  `8ccc5cd1f1b3602548715ae25a66ed73fd5dc68a210412eea643eb20eb75a135`) downloaded anonymously from
  the community conversion `ggml-org/gemma-3-1b-it-GGUF` (the official Google repos are gated).
* `llama-server` build b11474 (prebuilt CPU binary from the llama.cpp GitHub release) served it on
  127.0.0.1:8080 and `LocalLLMClient` (HTTP backend) returned schema-valid `AIVerdict`s, including
  for an event carrying a prompt-injection string (`scripts/llm_smoke.py [--injection]`) and in the
  pytest `test_real_gemma_via_llama_server_returns_valid_contract`.
* Observed CPU latency: about 20 s per analysis with 4 threads and a ~1k-token prompt. Output
  quality of a 1B model is modest (generic wording, occasionally odd `recommended_action`
  choices or echoed prompt fragments in `evidence`). That is why the LLM is advisory only and is
  scaled by confidence and clamped by the deterministic risk/policy engines.
* NOT verified: the in-process `llama-cpp-python` backend with the real model (the package has no
  prebuilt wheel for this Python 3.14 and needs cmake, which is absent). That backend is covered
  only by a fake-loader unit test. GPU offload (`gpu_layers`) was not exercised.

The model weights are not part of the repository (`*.gguf` and `data/` are git-ignored). You are
responsible for accepting the Gemma Terms of Use (https://ai.google.dev/gemma/terms).

## Setup

```bash
scripts/download_model.sh                     # -> data/models/gemma-3-1b-it-Q4_K_M.gguf
# Option A (recommended): llama-server (prebuilt release from github.com/ggml-org/llama.cpp)
export LLAMA_SERVER=/path/to/llama-server     # or put it on PATH, or under data/llama.cpp/
scripts/llm_server.sh &                       # binds 127.0.0.1:8080 only
export CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080
# Option B: in-process
pip install llama-cpp-python                  # needs a C/C++ toolchain + cmake
# then set llm.model_path = "data/models/gemma-3-1b-it-Q4_K_M.gguf" in the config
.venv/bin/python scripts/llm_smoke.py         # prints status, RAG sources, verdict
```

If the download is blocked (HTTP 401/403 = gated mirror): sign in to Hugging Face in a browser,
accept the Gemma license on the model page, download `gemma-3-1b-it-Q4_K_M.gguf` yourself and
place it at `data/models/`. Centralium never asks for or stores a token. Override the mirror with
`CENTRALIUM_MODEL_URL=<url> scripts/download_model.sh`.

Backend selection (`build_llm_client`): `CENTRALIUM_LLM_SERVER_URL` (loopback hosts only; any other
host is refused) -> llama-cpp-python if importable and `llm.model_path` exists -> otherwise a client
that reports **unavailable** (it never silently falls back to the mock).

## Runtime controls (`config.llm`)

`max_ctx`, `max_tokens`, `timeout_sec`, `concurrency` (default 1, enforced by a semaphore),
`threads`, `gpu_layers` (optional), `idle_unload_sec`, `temperature`,
`retries_on_invalid_json` (default 1). The model loads lazily on first use (llama-cpp-python) or
is served by the external server. After 3 consecutive failures the client reports unavailable for
30 s. The prompt is trimmed (RAG notes first) to fit `max_ctx - max_tokens`.
Caveat: a timed-out in-process generation cannot be interrupted; later calls queue behind it
until it finishes (and time out themselves).

## Output contract and safety

* The model must return one JSON object validated by `AIVerdict.parse_llm_text` (strict, unknown
  keys rejected). llama.cpp grammar-constrained decoding (`response_format: json_schema`) is
  requested, with automatic fallback if the server rejects it. Invalid output -> one retry with a
  corrective message -> `AIAnalysis(available=False, error=...)`. The client never raises.
* Prompt-injection hardening: event/command-line/file/domain text is sanitized (control chars, Gemma
  turn tokens, our delimiters removed; length-capped) and placed only inside a per-request
  random-nonce `<<<DATA-xxxx>>> ... <<<END-xxxx>>>` block; system rules say it is untrusted data.
  Heuristic injection phrases are flagged; if flagged, a BENIGN/UNKNOWN verdict is raised to
  SUSPICIOUS so an attacker cannot talk the verdict down. This is defence-in-depth, not a proof:
  a 1B model can still be misled, which is why its output only feeds the policy engine.
* The model can only emit one of the enumerated `recommended_action` values. Nothing in
  `centralium/agent/llm` or `rag` can execute commands: a static test forbids `subprocess`,
  `os.system/popen/exec*`, `eval/exec`, `shell=` in both packages. The llama-server is started by
  the operator (`scripts/llm_server.sh`), never by Centralium.

## Mock (test/demo only)

`MockLLM` derives a schema-valid verdict from the evidence with fixed rules. It is not a language
model: `model_name` is `MOCK-DETERMINISTIC (not an LLM, test/demo only)`, summaries start with
`[MOCK]`, and `status()` returns `{"mode": "mock", "is_mock": true}`. Both clients expose
`status()` (`mode` = `real` | `mock` | `unavailable`, backend, reason) for the UI, and every
`AIAnalysis.model_name` records which one produced it.
