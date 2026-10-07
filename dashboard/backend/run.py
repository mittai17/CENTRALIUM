"""Entry point: ``serve()`` runs the dashboard (API + static UI) with uvicorn."""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

from centralium.agent.config import load_config
from dashboard.backend.app import create_app


def serve(
    db_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    config_path: str | None = None,
) -> None:
    cfg = load_config(config_path)
    path = db_path or cfg.paths.resolved().db_path or (cfg.paths.data_dir / "centralium.db")
    app = create_app(path, config=cfg)
    generated: dict[str, str] = app.state.generated_tokens
    if generated:
        # Shown exactly once; only SHA-256 hashes are persisted next to the DB.
        print("=" * 64, file=sys.stderr)
        print("Centralium dashboard: access tokens generated (shown ONCE, store them now):", file=sys.stderr)
        for role, tok in generated.items():
            print(f"  {role:8s} {tok}", file=sys.stderr)
        print("=" * 64, file=sys.stderr)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {host}; put TLS in front of the dashboard.", file=sys.stderr)
    print(f"Centralium dashboard on http://{host}:{port}  (db: {path})", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="info")
