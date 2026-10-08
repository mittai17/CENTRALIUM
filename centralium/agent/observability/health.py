"""Health check registry and HTTP server (/healthz, /readyz, /metrics).

Implements liveness (/healthz) and readiness (/readyz) endpoints for agent and server.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("centralium.observability.health")

CheckFn = Callable[[], bool | tuple[bool, str]]


class HealthRegistry:
    """Registry for liveness and readiness health checks."""

    def __init__(self, started_at: float | None = None) -> None:
        self.started_at = started_at if started_at is not None else time.time()
        self._liveness_checks: dict[str, CheckFn] = {}
        self._readiness_checks: dict[str, CheckFn] = {}
        self._lock = threading.Lock()

    def register_liveness(self, name: str, fn: CheckFn) -> None:
        with self._lock:
            self._liveness_checks[name] = fn

    def register_readiness(self, name: str, fn: CheckFn) -> None:
        with self._lock:
            self._readiness_checks[name] = fn

    def check_liveness(self) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            checks = dict(self._liveness_checks)
        uptime = round(time.time() - self.started_at, 2)
        results: dict[str, Any] = {}
        all_ok = True

        for name, fn in checks.items():
            try:
                res = fn()
                if isinstance(res, tuple):
                    ok, msg = res
                else:
                    ok, msg = bool(res), "ok" if res else "failed"
            except Exception as exc:
                ok, msg = False, f"exception: {exc}"
            results[name] = {"status": "ok" if ok else "error", "message": msg}
            if not ok:
                all_ok = False

        status_str = "ok" if all_ok else "unhealthy"
        return all_ok, {"status": status_str, "uptime_s": uptime, "checks": results}

    def check_readiness(self) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            checks = dict(self._readiness_checks)
        uptime = round(time.time() - self.started_at, 2)
        results: dict[str, Any] = {}
        all_ok = True

        for name, fn in checks.items():
            try:
                res = fn()
                if isinstance(res, tuple):
                    ok, msg = res
                else:
                    ok, msg = bool(res), "ready" if res else "not ready"
            except Exception as exc:
                ok, msg = False, f"exception: {exc}"
            results[name] = {"status": "ready" if ok else "not_ready", "message": msg}
            if not ok:
                all_ok = False

        status_str = "ready" if all_ok else "not_ready"
        return all_ok, {"status": status_str, "uptime_s": uptime, "checks": results}


class _HealthHandler(BaseHTTPRequestHandler):
    """Internal HTTP handler for /healthz, /readyz, and /metrics."""

    server: HealthServer  # Type annotation

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard logging to prevent log noise
        pass

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        registry = self.server.registry

        if path in ("/healthz", "/api/healthz", "/health"):
            ok, data = registry.check_liveness()
            code = 200 if ok else 503
            self._send_json(code, data)
        elif path in ("/readyz", "/api/readyz"):
            ok, data = registry.check_readiness()
            code = 200 if ok else 503
            self._send_json(code, data)
        elif path == "/metrics":
            if self.server.metrics_provider:
                body = self.server.metrics_provider()
            else:
                body = "# No metrics provider configured\n"
            self._send_text(200, body, content_type="text/plain; version=0.0.4; charset=utf-8")
        else:
            self._send_json(404, {"error": "not found"})

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain") -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(payload)


class HealthServer(ThreadingHTTPServer):
    """Background HTTP server providing /healthz and /readyz."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9090,
        registry: HealthRegistry | None = None,
        metrics_provider: Callable[[], str] | None = None,
    ) -> None:
        self.registry = registry or HealthRegistry()
        self.metrics_provider = metrics_provider
        self._thread: threading.Thread | None = None
        super().__init__((host, port), _HealthHandler)

    def start(self) -> None:
        """Start server in background thread."""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True, name="CentraliumHealthServer")
        self._thread.start()
        log.info("Centralium HealthServer listening on %s:%d", self.server_address[0], self.server_address[1])

    def stop(self) -> None:
        """Shutdown and close health server."""
        self.shutdown()
        self.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
