# ruff: noqa: B008
"""Centralium SOC dashboard: FastAPI application factory.

``create_app(db_path, ...)`` builds the API and (if built) mounts the static Next.js export, so a
single process serves everything. The agent does not depend on this package at all.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from centralium.agent.config import CentraliumConfig, load_config
from centralium.agent.storage import Database, Repository
from dashboard.backend import routes_core, routes_mgmt, routes_telemetry
from dashboard.backend.cases import CaseStore, create_cases_router
from dashboard.backend.context import Context
from dashboard.backend.metrics import Metrics
from dashboard.backend.rbac import (
    MockOIDCProvider,
    OIDCAdapter,
    OIDCConfig,
    create_auth_router,
)
from dashboard.backend.security import (
    Principal,
    RateLimiter,
    build_token_store,
    current_principal,
    make_middleware,
    require,
)

log = logging.getLogger("centralium.dashboard")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATIC_DIR = PROJECT_ROOT / "dashboard" / "frontend" / "out"

NOT_BUILT_HTML = (
    "<!doctype html><title>Centralium</title><body style='font-family:sans-serif;padding:2rem'>"
    "<h1>Centralium dashboard API is running</h1><p>The web UI has not been built. Run "
    "<code>npm install &amp;&amp; npm run build</code> in <code>dashboard/frontend</code>.</p></body>"
)


def create_app(
    db_path: str | Path,
    *,
    config: CentraliumConfig | None = None,
    tokens: dict[str, str] | None = None,
    token_file: Path | None = None,
    static_dir: Path | None = None,
    ml_dir: Path | None = None,
    rules_dir: Path | None = None,
    cors_origins: list[str] | None = None,
    rate_limit_per_minute: int = 600,
) -> FastAPI:
    """Build the dashboard app. Works against an empty/new DB. Tokens are never hardcoded."""
    cfg = config or load_config()
    db = Database(db_path)
    if token_file is None and str(db_path) != ":memory:":
        token_file = Path(db_path).expanduser().parent / "dashboard_tokens.json"
    store, generated = build_token_store(tokens, hash_file=token_file)
    ctx = Context(
        db=db,
        repo=Repository(db),
        config=cfg,
        tokens=store,
        limiter=RateLimiter(per_minute=rate_limit_per_minute),
        metrics=Metrics(),
        ml_dir=ml_dir or PROJECT_ROOT / "ml",
        rules_dir=rules_dir or PROJECT_ROOT / "rules",
        started_at=time.time(),
        generated_tokens=generated,
    )
    app = FastAPI(
        title="Centralium Dashboard API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.ctx = ctx
    app.state.generated_tokens = generated

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or [],
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,
        max_age=600,
    )
    sec = make_middleware(lambda r: r.app.state.ctx.limiter)

    @app.middleware("http")
    async def security_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        t0 = time.perf_counter()
        resp = await sec(request, call_next)
        ctx.metrics.observe(request.method, resp.status_code, time.perf_counter() - t0)
        return resp

    app.include_router(routes_core.router)
    app.include_router(routes_telemetry.router)
    app.include_router(routes_mgmt.router)

    case_store = CaseStore(db._conn)
    app.state.case_store = case_store
    app.include_router(create_cases_router(case_store))

    oidc_cfg = OIDCConfig(enabled=False)
    oidc_adapter = OIDCAdapter(oidc_cfg)
    mock_oidc = MockOIDCProvider(oidc_cfg)
    app.include_router(create_auth_router(oidc_adapter, mock_oidc))

    @app.get("/api/health")
    @app.get("/healthz")
    @app.get("/api/healthz")
    def health() -> dict[str, Any]:
        return {"status": "ok", "uptime_s": round(time.time() - ctx.started_at, 2)}

    @app.get("/readyz")
    @app.get("/api/readyz")
    def readyz() -> Response:
        try:
            with ctx.db._lock:
                row = ctx.db._conn.execute("SELECT 1").fetchone()
                if row is None or row[0] != 1:
                    return JSONResponse(
                        status_code=503,
                        content={"status": "not_ready", "error": "db check failed"},
                    )
        except Exception as exc:
            return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(exc)})
        return JSONResponse(status_code=200, content={"status": "ready", "database": "connected"})

    @app.get("/api/whoami")
    def whoami(p: Principal = Depends(current_principal)) -> dict[str, Any]:
        return {"role": p.role}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(request: Request, _: Principal = Depends(require("viewer"))) -> str:
        c = ctx.repo.counts()
        gauges: dict[str, float] = {f"centralium_dashboard_{k}_rows": float(v) for k, v in c.items()}
        gauges["centralium_dashboard_sync_pending"] = float(ctx.repo.pending_sync_count())
        gauges["centralium_dashboard_uptime_seconds"] = round(time.time() - ctx.started_at, 1)
        return ctx.metrics.render(gauges)

    static = static_dir if static_dir is not None else DEFAULT_STATIC_DIR
    if static.is_dir() and (static / "index.html").exists():
        app.mount("/", StaticFiles(directory=static, html=True), name="ui")
    else:

        @app.get("/", response_class=HTMLResponse)
        def not_built() -> str:
            return NOT_BUILT_HTML

    return app
