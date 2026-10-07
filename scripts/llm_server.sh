#!/usr/bin/env bash
# Start a local llama.cpp server bound to 127.0.0.1 only, for Centralium.
#
#   scripts/llm_server.sh            # foreground
#   export CENTRALIUM_LLM_SERVER_URL=http://127.0.0.1:8080   # tell Centralium to use it
#
# Env: LLAMA_SERVER (binary path), CENTRALIUM_MODEL (gguf), PORT, CTX, THREADS, GPU_LAYERS
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${LLAMA_SERVER:-$(command -v llama-server || true)}"
[[ -z "$BIN" ]] && BIN="$(find data/llama.cpp -name llama-server -type f 2>/dev/null | head -n1 || true)"
[[ -x "${BIN:-}" ]] || { echo "llama-server not found; see docs/LOCAL_MODEL.md" >&2; exit 1; }
MODEL="${CENTRALIUM_MODEL:-data/models/gemma-3-1b-it-Q4_K_M.gguf}"
[[ -f "$MODEL" ]] || { echo "model missing: $MODEL (run scripts/download_model.sh)" >&2; exit 1; }
exec "$BIN" -m "$MODEL" --host 127.0.0.1 --port "${PORT:-8080}" -c "${CTX:-2048}" \
  -t "${THREADS:-4}" -ngl "${GPU_LAYERS:-0}" --parallel 1 --no-webui
