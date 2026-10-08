"""OpenTelemetry-compatible trace span and span exporter module.

Provides Span, Tracer, and Exporters (In-Memory, File, and OTLP/HTTP)
with contextvars-based trace context propagation.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import time
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("centralium.observability.tracer")


def generate_trace_id() -> str:
    """Generate a 16-byte (32-character hex) trace ID."""
    return os.urandom(16).hex()


def generate_span_id() -> str:
    """Generate an 8-byte (16-character hex) span ID."""
    return os.urandom(8).hex()


@dataclass
class SpanContext:
    trace_id: str
    span_id: str
    trace_flags: int = 1  # 1 = sampled


@dataclass
class SpanEvent:
    name: str
    timestamp_ns: int
    attributes: dict[str, Any] = field(default_factory=dict)


class Span:
    """OpenTelemetry-compatible Span representation."""

    def __init__(
        self,
        name: str,
        context: SpanContext,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
        start_time_ns: int | None = None,
    ) -> None:
        self.name = name
        self.context = context
        self.parent_span_id = parent_span_id
        self.attributes: dict[str, Any] = dict(attributes or {})
        self.start_time_ns: int = start_time_ns if start_time_ns is not None else time.time_ns()
        self.end_time_ns: int | None = None
        self.status: str = "UNSET"  # OK | ERROR | UNSET
        self.status_description: str = ""
        self.events: list[SpanEvent] = []
        self._ended: bool = False

    def set_attribute(self, key: str, value: Any) -> Span:
        self.attributes[key] = value
        return self

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> Span:
        self.events.append(
            SpanEvent(
                name=name,
                timestamp_ns=time.time_ns(),
                attributes=dict(attributes or {}),
            )
        )
        return self

    def set_status(self, status: str, description: str = "") -> Span:
        self.status = status.upper()
        self.status_description = description
        return self

    def end(self, end_time_ns: int | None = None) -> None:
        if not self._ended:
            self.end_time_ns = end_time_ns if end_time_ns is not None else time.time_ns()
            self._ended = True

    @property
    def duration_ms(self) -> float:
        if self.end_time_ns is None:
            return 0.0
        return (self.end_time_ns - self.start_time_ns) / 1_000_000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.context.trace_id,
            "span_id": self.context.span_id,
            "parent_span_id": self.parent_span_id,
            "start_time_ns": self.start_time_ns,
            "end_time_ns": self.end_time_ns,
            "duration_ms": self.duration_ms,
            "status": {"code": self.status, "description": self.status_description},
            "attributes": self.attributes,
            "events": [
                {"name": e.name, "timestamp_ns": e.timestamp_ns, "attributes": e.attributes}
                for e in self.events
            ],
        }

    def to_otlp(self) -> dict[str, Any]:
        """Convert to OpenTelemetry standard OTLP JSON format."""
        otlp_attrs = []
        for k, v in self.attributes.items():
            val: dict[str, Any]
            if isinstance(v, bool):
                val = {"boolValue": v}
            elif isinstance(v, int):
                val = {"intValue": str(v)}
            elif isinstance(v, float):
                val = {"doubleValue": v}
            else:
                val = {"stringValue": str(v)}
            otlp_attrs.append({"key": k, "value": val})

        return {
            "traceId": self.context.trace_id,
            "spanId": self.context.span_id,
            "parentSpanId": self.parent_span_id or "",
            "name": self.name,
            "kind": 1,  # SPAN_KIND_INTERNAL
            "startTimeUnixNano": str(self.start_time_ns),
            "endTimeUnixNano": str(self.end_time_ns or self.start_time_ns),
            "attributes": otlp_attrs,
            "status": {
                "code": 1 if self.status == "OK" else (2 if self.status == "ERROR" else 0),
                "message": self.status_description,
            },
        }


# Context variable for current active span
_CURRENT_SPAN: contextvars.ContextVar[Span | None] = contextvars.ContextVar("current_span", default=None)


class SpanExporter(ABC):
    """Abstract base class for OpenTelemetry span exporters."""

    @abstractmethod
    def export(self, spans: list[Span]) -> bool:
        """Export finished spans. Returns True if successful."""

    def shutdown(self) -> None:  # noqa: B027
        """Clean up exporter resources."""
        pass


class InMemorySpanExporter(SpanExporter):
    """Stores exported spans in memory for inspection and unit testing."""

    def __init__(self) -> None:
        self._spans: list[Span] = []

    def export(self, spans: list[Span]) -> bool:
        self._spans.extend(spans)
        return True

    def get_finished_spans(self) -> list[Span]:
        return list(self._spans)

    def clear(self) -> None:
        self._spans.clear()


class FileSpanExporter(SpanExporter):
    """Appends exported spans as newline-delimited JSON to disk."""

    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, spans: list[Span]) -> bool:
        try:
            with self.file_path.open("a", encoding="utf-8") as fh:
                for span in spans:
                    fh.write(json.dumps(span.to_dict()) + "\n")
                fh.flush()
            return True
        except Exception as exc:
            log.warning("FileSpanExporter export failed: %s", exc)
            return False


class OTLPHttpSpanExporter(SpanExporter):
    """Sends OTLP JSON formatted trace spans over HTTP POST."""

    def __init__(
        self,
        endpoint: str = "http://localhost:4318/v1/traces",
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout

    def export(self, spans: list[Span]) -> bool:
        if not spans:
            return True
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "centralium-agent"}}]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "centralium.tracer"},
                            "spans": [span.to_otlp() for span in spans],
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
            log.debug("OTLPHttpSpanExporter post failed: %s", exc)
            return False


class Tracer:
    """Tracer creating and managing OpenTelemetry-compatible trace spans."""

    def __init__(
        self,
        service_name: str = "centralium-agent",
        exporters: list[SpanExporter] | None = None,
    ) -> None:
        self.service_name = service_name
        self.exporters: list[SpanExporter] = exporters or []

    def add_exporter(self, exporter: SpanExporter) -> None:
        self.exporters.append(exporter)

    def start_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
        parent: Span | None = None,
    ) -> Span:
        current = parent if parent is not None else _CURRENT_SPAN.get()
        if current is not None:
            trace_id = current.context.trace_id
            parent_span_id = current.context.span_id
        else:
            trace_id = generate_trace_id()
            parent_span_id = None

        span_id = generate_span_id()
        ctx = SpanContext(trace_id=trace_id, span_id=span_id)
        span = Span(name=name, context=ctx, parent_span_id=parent_span_id, attributes=attributes)
        span.set_attribute("service.name", self.service_name)
        return span

    @contextmanager
    def start_as_current_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[Span]:
        """Context manager setting active span for the execution block and exporting on exit."""
        span = self.start_span(name, attributes=attributes)
        token = _CURRENT_SPAN.set(span)
        try:
            yield span
            if span.status == "UNSET":
                span.set_status("OK")
        except Exception as exc:
            span.set_status("ERROR", description=str(exc))
            span.add_event("exception", {"exception.type": type(exc).__name__, "exception.message": str(exc)})
            raise
        finally:
            span.end()
            _CURRENT_SPAN.reset(token)
            for exp in self.exporters:
                try:
                    exp.export([span])
                except Exception as exp_err:
                    log.warning("Exporter %s error: %s", type(exp).__name__, exp_err)
