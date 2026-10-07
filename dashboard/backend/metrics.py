"""Tiny Prometheus text-format registry (no external dependency)."""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, int], int] = defaultdict(int)
        self.latency_sum = 0.0
        self.latency_count = 0

    def observe(self, method: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(method, status)] += 1
            self.latency_sum += seconds
            self.latency_count += 1

    def render(self, gauges: dict[str, float]) -> str:
        lines = [
            "# HELP centralium_dashboard_http_requests_total HTTP requests by method and status.",
            "# TYPE centralium_dashboard_http_requests_total counter",
        ]
        with self._lock:
            for (method, status), n in sorted(self.requests.items()):
                lines.append(
                    f'centralium_dashboard_http_requests_total{{method="{method}",status="{status}"}} {n}'
                )
            lines += [
                "# TYPE centralium_dashboard_http_request_seconds summary",
                f"centralium_dashboard_http_request_seconds_sum {self.latency_sum:.6f}",
                f"centralium_dashboard_http_request_seconds_count {self.latency_count}",
            ]
        for name, val in sorted(gauges.items()):
            lines += [f"# TYPE {name} gauge", f"{name} {val}"]
        return "\n".join(lines) + "\n"
