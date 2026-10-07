#!/usr/bin/env bash
# Download Gemma 3 1B IT Q4_K_M (GGUF) into data/models/ and print its SHA-256.
#
# The official google/gemma-3-1b-it-qat-* repos are gated on Hugging Face. This script
# defaults to the community GGUF conversion ggml-org/gemma-3-1b-it-GGUF, which was
# downloadable anonymously when this was written. YOU are responsible for accepting the
# Gemma Terms of Use (https://ai.google.dev/gemma/terms) before using the weights.
#
# No token is read, requested or stored by this script. If a mirror requires one, download
# the file in a browser while logged in and place it at the destination path below.
#
# Usage: scripts/download_model.sh [dest_dir]    (default: data/models)
set -euo pipefail
cd "$(dirname "$0")/.."
DEST="${1:-data/models}"
FILE="gemma-3-1b-it-Q4_K_M.gguf"
URL="${CENTRALIUM_MODEL_URL:-https://huggingface.co/ggml-org/gemma-3-1b-it-GGUF/resolve/main/${FILE}}"
mkdir -p "$DEST"
if [[ -s "$DEST/$FILE" ]]; then
  echo "already present: $DEST/$FILE"
else
  echo "downloading $URL"
  curl -fL --retry 3 -o "$DEST/$FILE.part" "$URL" || {
    echo "download failed (HTTP error; possibly gated). See docs/LOCAL_MODEL.md for manual steps." >&2
    rm -f "$DEST/$FILE.part"; exit 1; }
  head -c4 "$DEST/$FILE.part" | grep -q GGUF || { echo "not a GGUF file" >&2; rm -f "$DEST/$FILE.part"; exit 1; }
  mv "$DEST/$FILE.part" "$DEST/$FILE"
fi
sha256sum "$DEST/$FILE"
