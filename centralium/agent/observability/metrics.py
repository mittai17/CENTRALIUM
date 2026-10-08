"""OpenTelemetry-compatible metrics instruments and metric exporters.

Provides Counter, Gauge, Histogram instruments, Meter registry, and
exporters (In-Memory, File, OTLP/HTTP, and Prometheus).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("centralium.observability.metrics")


@dataclass
class MetricPoint:
    attributes: dict[str, str]
    value: float
    timestamp_ns: int = field(default_factory=time.time_ns)


class Counter:
    """Monotonically increasing cumulative counter."""

    def __init__(self, name: str, unit: str = "1", description: str = "") -> None:
        self.name = name
        self.unit = unit
        self.description = description
        self._values: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)
        self._lock = threading.RLock()

    def add(self, value: float | int, attributes: dict[str, str] | None = None) -> None:
        key = tuple(sorted((attributes or {}).items()))
        with self._lock:
            self._values[key] += float(value)

    def collect(self) -> list[MetricPoint]:
        now = time.time_ns()
        with self._lock:
            return [
                MetricPoint(attributes=dict(k), value=v, timestamp_ns=now) for k, v in self._values.items()
            ]


class Gauge:
    """Instantaneous numerical value measurement."""

    def __init__(self, name: str, unit: str = "1", description: str = "") -> None:
        self.name = name
        self.unit = unit
        self.description = description
        self._values: dict[tuple[tuple[str, str], ...], float] = {}
        self._lock = threading.RLock()

    def set(self, value: float | int, attributes: dict[str, str] | None = None) -> None:
        key = tuple(sorted((attributes or {}).items()))
        with self._lock:
            self._values[key] = float(value)

    def collect(self) -> list[MetricPoint]:
        now = time.time_ns()
        with self._lock:
            return [
                MetricPoint(attributes=dict(k), value=v, timestamp_ns=now) for k, v in self._values.items()
            ]


class Histogram:
    """Distribution of measured values (e.g. latency, size)."""

    def __init__(self, name: str, unit: str = "ms", description: str = "", max_samples: int = 1024) -> None:
        self.name = name
        self.unit = unit
        self.description = description
        self._samples: dict[tuple[tuple[str, str], ...], deque[float]] = defaultdict(
            lambda: deque(maxlen=max_samples)
        )
        self._counts: dict[tuple[tuple[str, str], ...], int] = defaultdict(int)
        self._sums: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)
        self._lock = threading.RLock()

    def record(self, value: float | int, attributes: dict[str, str] | None = None) -> None:
        val = float(value)
        key = tuple(sorted((attributes or {}).items()))
        with self._lock:
            self._samples[key].append(val)
            self._counts[key] += 1
            self._sums[key] += val

    def get_summary(self, attributes: dict[str, str] | None = None) -> dict[str, float]:
        key = tuple(sorted((attributes or {}).items()))
        with self._lock:
            vals = sorted(self._samples[key])
            n = len(vals)
            if n == 0:
                return {"count": 0.0, "sum": 0.0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
            return {
                "count": float(self._counts[key]),
                "sum": self._sums[key],
                "mean": self._sums[key] / self._counts[key],
                "p50": vals[n // 2],
                "p95": vals[min(n - 1, int(n * 0.95))],
                "max": vals[-1],
            }


@dataclass
class MetricSnapshot:
    name: str
    type: str  # counter | gauge | histogram
    unit: str
    description: str
    points: list[MetricPoint]


class Meter:
    """Meter registry managing instruments and collecting snapshots."""

    def __init__(self, name: str = "centralium-agent") -> None:
        self.name = name
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._histograms: dict[str, Histogram] = {}
        self._lock = threading.RLock()

    def create_counter(self, name: str, unit: str = "1", description: str = "") -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, unit, description)
            return self._counters[name]

    def create_gauge(self, name: str, unit: str = "1", description: str = "") -> Gauge:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, unit, description)
            return self._gauges[name]

    def create_histogram(self, name: str, unit: str = "ms", description: str = "") -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, unit, description)
            return self._histograms[name]

    def collect_snapshots(self) -> list[MetricSnapshot]:
        snaps: list[MetricSnapshot] = []
        with self._lock:
            for c in self._counters.values():
                snaps.append(
                    MetricSnapshot(
                        name=c.name,
                        type="counter",
                        unit=c.unit,
                        description=c.description,
                        points=c.collect(),
                    )
                )
            for g in self._gauges.values():
                snaps.append(
                    MetricSnapshot(
                        name=g.name,
                        type="gauge",
                        unit=g.unit,
                        description=g.description,
                        points=g.collect(),
                    )
                )
            for h in self._histograms.values():
                # For histograms, expose summary gauge points
                points: list[MetricPoint] = []
                now = time.time_ns()
                with h._lock:
                    for k in h._samples:
                        attrs = dict(k)
                        summary = h.get_summary(attrs)
                        for stat_name, stat_val in summary.items():
                            pt_attrs = {**attrs, "stat": stat_name}
                            points.append(MetricPoint(attributes=pt_attrs, value=stat_val, timestamp_ns=now))
                snaps.append(
                    MetricSnapshot(
                        name=h.name,
                        type="histogram",
                        unit=h.unit,
                        description=h.description,
                        points=points,
                    )
                )
        return snaps


# ---------------------------------------------------------------------- Exporters
class MetricExporter(ABC):
    @abstractmethod
    def export(self, snapshots: list[MetricSnapshot]) -> bool:
        """Export metric snapshots."""


class InMemoryMetricExporter(MetricExporter):
    """Stores exported metric snapshots in memory."""

    def __init__(self) -> None:
        self._history: list[list[MetricSnapshot]] = []

    def export(self, snapshots: list[MetricSnapshot]) -> bool:
        self._history.append(snapshots)
        return True

    def get_latest(self) -> list[MetricSnapshot]:
        return self._history[-1] if self._history else []


class FileMetricExporter(MetricExporter):
    """Writes metric snapshots as JSON lines to file."""

    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, snapshots: list[MetricSnapshot]) -> bool:
        try:
            data = [
                {
                    "name": s.name,
                    "type": s.type,
                    "unit": s.unit,
                    "points": [
                        {"attributes": p.attributes, "value": p.value, "ts": p.timestamp_ns} for p in s.points
                    ],
                }
                for s in snapshots
            ]
            with self.file_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(data) + "\n")
            return True
        except Exception as exc:
            log.warning("FileMetricExporter failed: %s", exc)
            return False


class OTLPHttpMetricExporter(MetricExporter):
    """Sends OTLP JSON formatted metrics over HTTP POST."""

    def __init__(
        self,
        endpoint: str = "http://localhost:4318/v1/metrics",
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout

    def export(self, snapshots: list[MetricSnapshot]) -> bool:
        if not snapshots:
            return True
        metrics_list = []
        for s in snapshots:
            points_list = []
            for p in s.points:
                otlp_attrs = [{"key": k, "value": {"stringValue": str(v)}} for k, v in p.attributes.items()]
                points_list.append(
                    {
                        "attributes": otlp_attrs,
                        "timeUnixNano": str(p.timestamp_ns),
                        "asDouble": p.value,
                    }
                )
            metrics_list.append(
                {
                    "name": s.name,
                    "description": s.description,
                    "unit": s.unit,
                    "gauge" if s.type != "counter" else "sum": {"dataPoints": points_list},
                }
            )

        payload = {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "centralium-agent"}}]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "centralium.meter"},
                            "metrics": metrics_list,
                        }
                    ],
                }
            ]
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=self.headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return bool(200 <= resp.status < 300)
        except Exception as exc:
            log.debug("OTLPHttpMetricExporter error: %s", exc)
            return False


class PrometheusExporter:
    """Renders Prometheus plain text exposition format from metric snapshots."""

    @staticmethod
    def render(snapshots: list[MetricSnapshot]) -> str:
        lines: list[str] = []
        for s in snapshots:
            clean_name = s.name.replace(".", "_").replace("-", "_")
            if s.description:
                lines.append(f"# HELP {clean_name} {s.description}")
            lines.append(f"# TYPE {clean_name} {s.type}")
            for p in s.points:
                if p.attributes:
                    labels = ",".join(f'{k}="{v}"' for k, v in sorted(p.attributes.items()))
                    lines.append(f"{clean_name}{{{labels}}} {p.value}")
                else:
                    lines.append(f"{clean_name} {p.value}")
        return "\n".join(lines) + "\n"
