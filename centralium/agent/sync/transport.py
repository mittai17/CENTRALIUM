"""Sync transports. The worker only depends on the ``Transport`` protocol so tests inject fakes.

``HttpTransport`` posts batches to a dashboard URL. Security properties:
* TLS certificate verification is always on (``verify=True``); plain ``http://`` is refused unless the
  host is loopback or ``allow_insecure_loopback`` semantics apply (never for remote hosts).
* The bearer token is read from an environment variable at send time (never stored in config,
  never logged, never included in exception text).
* Redirects are not followed (a redirect could leak the Authorization header to another host).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from centralium.agent.interfaces import SyncItem

log = logging.getLogger("centralium.sync.transport")

DEFAULT_TOKEN_ENV = "CENTRALIUM_SYNC_TOKEN"  # noqa: S105 - env var NAME, not a secret


class TransportUnavailable(Exception):
    """Network/server unavailable (offline, DNS, timeout, 5xx, 429). Items should be retried later."""


class TransportRejected(Exception):
    """Server permanently rejected the batch (4xx other than 408/429)."""


@dataclass
class TransportResult:
    delivered: list[int] = field(default_factory=list)
    failed: dict[int, str] = field(default_factory=dict)


@runtime_checkable
class Transport(Protocol):
    def send(self, items: list[SyncItem]) -> TransportResult:
        """Deliver ``items``. Raise ``TransportUnavailable``/``TransportRejected`` for whole-batch
        failures, or return per-item results."""
        ...


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class HttpTransport:
    def __init__(
        self,
        url: str,
        *,
        token_env: str = DEFAULT_TOKEN_ENV,
        timeout_s: float = 10.0,
        host_id: str = "localhost",
        client: Any | None = None,  # injectable httpx.Client (tests use httpx.MockTransport)
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("sync url must be an absolute http(s) URL")
        if parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ValueError("plain http is only allowed for loopback; use https")
        if parts.username or parts.password:
            raise ValueError("credentials must not be embedded in the sync URL")
        self._url = url
        self._token_env = token_env
        self._host_id = host_id
        self._timeout = timeout_s
        self._client = client

    @property
    def safe_url(self) -> str:
        p = urlsplit(self._url)
        return f"{p.scheme}://{p.netloc}{p.path}"  # strips query/fragment which may carry secrets

    def send(self, items: list[SyncItem]) -> TransportResult:
        import httpx  # local import: keeps module importable when offline-only

        token = os.environ.get(self._token_env, "")
        if not token:
            raise TransportRejected(f"no auth token in ${self._token_env}")
        body = {
            "host_id": self._host_id,
            "events": [
                {"queue_id": i.queue_id, "dedup_key": i.dedup_key, "payload": i.payload} for i in items
            ],
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        client = self._client or httpx.Client(verify=True, timeout=self._timeout, follow_redirects=False)
        try:
            resp = client.post(self._url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            # exception text can embed URLs; report only the class
            raise TransportUnavailable(f"{type(exc).__name__} contacting {self.safe_url}") from None
        finally:
            if self._client is None:
                client.close()
        code = resp.status_code
        if 200 <= code < 300:
            return TransportResult(delivered=[i.queue_id for i in items])
        if code in (408, 425, 429) or code >= 500:
            raise TransportUnavailable(f"HTTP {code} from {self.safe_url}")
        raise TransportRejected(f"HTTP {code} from {self.safe_url}")
