#!/usr/bin/env sh
# Build the UI if needed, then serve API + UI. Usage: scripts/dashboard_run.sh [--db PATH] [--port N]
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -f "$ROOT/dashboard/frontend/out/index.html" ]; then
  (cd "$ROOT/dashboard/frontend" && npm install && npm run build)
fi
exec "$ROOT/.venv/bin/python" "$ROOT/scripts/dashboard_run.py" "$@"
