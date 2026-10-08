"""Token auth, RBAC, rate limiting and security headers for the dashboard API.

Tokens are never hardcoded. Sources, in priority order, per role:
  1. explicit ``tokens`` argument (tests / embedding),
  2. env ``DASHBOARD_CENTRALIUM_<ROLE>_TOKEN`` (min 16 chars; not CENTRALIUM_* because
     the agent config loader rejects unknown CENTRALIUM_* variables),
  3. a hash file in the data dir (only SHA-256 hashes are persisted),
  4. generated on first run (plaintext returned once so the runner can print it).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger("centralium.dashboard.security")

ROLES: tuple[str, ...] = ("viewer", "analyst", "admin", "agent")
RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3, "agent": 0}
MIN_TOKEN_LEN = 16


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    role: str
    ident: str  # non-secret identifier (role + hash prefix) used for audit logging
    endpoint_groups: tuple[str, ...] | None = None  # None indicates unrestricted access
    email: str | None = None
    auth_provider: str = "token"  # "token" | "oidc"

    def at_least(self, role: str) -> bool:
        return RANK[self.role] >= RANK[role]

    def can_access_endpoint_group(self, group: str | None) -> bool:
        if self.role == "admin" or self.endpoint_groups is None or group is None:
            return True
        return group in self.endpoint_groups


class TokenStore:
    def __init__(self, hashes: Mapping[str, str]) -> None:
        self._hashes = dict(hashes)

    def authenticate(self, token: str) -> Principal | None:
        digest = _h(token)
        found: str | None = None
        for role, expected in self._hashes.items():  # no early exit: constant-ish time
            if hmac.compare_digest(digest, expected) or hmac.compare_digest(token, expected):
                found = role
        if found is None:
            return None
        return Principal(found, f"{found}:{digest[:8]}")

    @property
    def roles(self) -> list[str]:
        return sorted(self._hashes)


def build_token_store(
    explicit: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    hash_file: Path | None = None,
) -> tuple[TokenStore, dict[str, str]]:
    """Return (store, newly_generated_plaintext_tokens). Generated tokens must be shown once."""
    environ = os.environ if env is None else env
    hashes: dict[str, str] = {}
    generated: dict[str, str] = {}
    persisted: dict[str, str] = {}
    if hash_file is not None and hash_file.exists():
        try:
            raw = json.loads(hash_file.read_text("utf-8"))
            persisted = {k: v for k, v in raw.items() if k in ROLES and isinstance(v, str)}
        except (OSError, ValueError):
            log.warning("could not read dashboard token hash file; regenerating")
    dirty = False
    for role in ROLES:
        tok = (explicit or {}).get(role) or environ.get(f"DASHBOARD_CENTRALIUM_{role.upper()}_TOKEN")
        if tok:
            if len(tok) < MIN_TOKEN_LEN:
                raise ValueError(f"{role} token must be at least {MIN_TOKEN_LEN} characters")
            hashes[role] = _h(tok)
        elif role in persisted:
            hashes[role] = persisted[role]
        else:
            tok = secrets.token_urlsafe(32)
            generated[role] = tok
            hashes[role] = _h(tok)
            persisted[role] = hashes[role]
            dirty = True
    if dirty and hash_file is not None:
        hash_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(hash_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(persisted, fh)
    return TokenStore(hashes), generated


# ------------------------------------------------------------------ dependencies
def current_principal(request: Request) -> Principal:
    ctx = request.app.state.ctx
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    principal: Principal | None = ctx.tokens.authenticate(token.strip())
    if principal is None:
        ctx.limiter.record_auth_failure(client_ip(request))
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    request.state.principal = principal
    return principal


def require(role: str) -> Callable[[Request], Principal]:
    """Dependency factory: caller must hold ``role`` or higher (viewer < analyst < admin)."""

    def dep(request: Request) -> Principal:
        p = current_principal(request)
        if not p.at_least(role):
            raise HTTPException(403, f"requires role {role}")
        return p

    return dep


def require_ingest(request: Request) -> Principal:
    p = current_principal(request)
    if p.role not in ("agent", "admin"):
        raise HTTPException(403, "ingest requires agent or admin token")
    return p


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ------------------------------------------------------------------ rate limiting
class RateLimiter:
    """In-memory sliding window. Basic protection, not a DDoS defense."""

    def __init__(self, per_minute: int = 600, auth_failures_per_minute: int = 20) -> None:
        self.per_minute = per_minute
        self.auth_fail_limit = auth_failures_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def _trim(q: deque[float], now: float) -> None:
        while q and now - q[0] > 60:
            q.popleft()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        if len(self._hits) > 10_000:
            self._hits.clear()
        q = self._hits[ip]
        self._trim(q, now)
        f = self._fails[ip]
        self._trim(f, now)
        if len(f) >= self.auth_fail_limit or len(q) >= self.per_minute:
            return False
        q.append(now)
        return True

    def record_auth_failure(self, ip: str) -> None:
        self._fails[ip].append(time.monotonic())


# ------------------------------------------------------------------ headers
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Next.js static export hydrates with inline bootstrap scripts, hence 'unsafe-inline' for the UI only.
UI_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'self'; form-action 'self'; object-src 'none'"
)


def apply_security_headers(request: Request, response: Response) -> None:
    is_api = request.url.path.startswith("/api") or request.url.path == "/metrics"
    h = response.headers
    h["Content-Security-Policy"] = API_CSP if is_api else UI_CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    if is_api:
        h["Cache-Control"] = "no-store"


MAX_BODY_BYTES = 2 * 1024 * 1024


def make_middleware(
    app_limiter_getter: Callable[[Request], RateLimiter],
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    async def middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        limiter = app_limiter_getter(request)
        path = request.url.path
        is_api = path.startswith("/api") or path == "/metrics"  # static UI assets are not rate limited
        if is_api and not limiter.allow(client_ip(request)):
            resp: Response = JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
            resp.headers["Retry-After"] = "60"
        else:
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
                resp = JSONResponse({"detail": "request body too large"}, status_code=413)
            else:
                resp = await call_next(request)
        apply_security_headers(request, resp)
        return resp

    return middleware
