"""Unit tests for Phase 2H: OpenTelemetry-compatible tracing, metrics, stage latency, and /healthz, /readyz endpoints."""

import json
import socket
import urllib.request
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from centralium.agent.observability.health import HealthRegistry, HealthServer
from centralium.agent.observability.metrics import (
    FileMetricExporter,
    InMemoryMetricExporter,
    Meter,
    PrometheusExporter,
)
from centralium.agent.observability.pipeline_metrics import PipelineLatencyExporter
from centralium.agent.observability.tracer import (
    FileSpanExporter,
    InMemorySpanExporter,
    Tracer,
)
from dashboard.backend.app import create_app


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_opentelemetry_tracing(tmp_path: Path):
    in_memory_exporter = InMemorySpanExporter()
    file_path = tmp_path / "spans.ndjson"
    file_exporter = FileSpanExporter(file_path)

    tracer = Tracer(service_name="test-agent", exporters=[in_memory_exporter, file_exporter])

    with tracer.start_as_current_span("parent_stage", attributes={"component": "pipeline"}) as parent_span:
        parent_span.add_event("stage_started")
        with tracer.start_as_current_span("child_stage", attributes={"stage": "ml"}) as child_span:
            child_span.set_attribute("ml.model", "anomaly_v1")

    finished = in_memory_exporter.get_finished_spans()
    assert len(finished) == 2

    child, parent = finished[0], finished[1]
    assert child.name == "child_stage"
    assert parent.name == "parent_stage"
    assert child.context.trace_id == parent.context.trace_id
    assert child.parent_span_id == parent.context.span_id
    assert child.attributes["ml.model"] == "anomaly_v1"
    assert child.status == "OK"

    # Verify file exporter wrote both spans
    assert file_path.exists()
    lines = file_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    parsed_child = json.loads(lines[0])
    assert parsed_child["name"] == "child_stage"


def test_opentelemetry_metrics(tmp_path: Path):
    meter = Meter("test-meter")
    counter = meter.create_counter("events_processed_total", description="Processed events")
    gauge = meter.create_gauge("queue_depth", description="Current queue depth")
    hist = meter.create_histogram("duration_ms", description="Latency in ms")

    counter.add(5, {"stage": "epp"})
    counter.add(3, {"stage": "epp"})
    gauge.set(42, {"subsystem": "sync"})

    for val in (10.0, 20.0, 30.0, 40.0, 50.0):
        hist.record(val, {"op": "scan"})

    snaps = meter.collect_snapshots()
    assert len(snaps) == 3

    # Test in-memory and file exporters
    mem_exp = InMemoryMetricExporter()
    mem_exp.export(snaps)
    assert len(mem_exp.get_latest()) == 3

    metrics_file = tmp_path / "metrics.jsonl"
    file_exp = FileMetricExporter(metrics_file)
    file_exp.export(snaps)
    assert metrics_file.exists()

    # Test Prometheus format rendering
    prom_text = PrometheusExporter.render(snaps)
    assert 'events_processed_total{stage="epp"} 8.0' in prom_text
    assert 'queue_depth{subsystem="sync"} 42.0' in prom_text
    assert 'duration_ms{op="scan",stat="p50"} 30.0' in prom_text
    assert 'duration_ms{op="scan",stat="mean"} 30.0' in prom_text


def test_pipeline_stage_latency_exporter():
    exporter = PipelineLatencyExporter()
    fake_stats = {
        "counters": {"raw": 100, "epp": 90, "ml": 20, "incidents": 2},
        "errors": {"ml": 1},
        "latency": {
            "ml": {
                "count": 20.0,
                "mean_ms": 14.5,
                "p50_ms": 12.0,
                "p95_ms": 25.0,
                "max_ms": 32.0,
            },
            "response": {
                "count": 2.0,
                "mean_ms": 5.0,
                "p50_ms": 5.0,
                "p95_ms": 6.0,
                "max_ms": 6.0,
            },
        },
        "uptime_sec": 123.4,
    }

    snaps = exporter.export_from_stats_snapshot(fake_stats)
    names = {s.name for s in snaps}
    assert "centralium_pipeline_stage_latency_ms" in names
    assert "centralium_pipeline_stage_events_total" in names
    assert "centralium_pipeline_stage_errors_total" in names
    assert "centralium_agent_uptime_seconds" in names

    prom_text = exporter.render_prometheus(fake_stats)
    assert 'centralium_pipeline_stage_latency_ms{stage="ml",stat="p95"} 25.0' in prom_text
    assert 'centralium_pipeline_stage_events_total{stage="raw"} 100.0' in prom_text


def test_health_registry_and_server():
    registry = HealthRegistry()
    registry.register_liveness("event_loop", lambda: True)

    db_ready = True

    def check_db():
        return (db_ready, "db is active" if db_ready else "db locked")

    registry.register_readiness("storage", check_db)

    # Initial state: both healthy
    live_ok, live_data = registry.check_liveness()
    assert live_ok is True
    assert live_data["status"] == "ok"

    ready_ok, ready_data = registry.check_readiness()
    assert ready_ok is True
    assert ready_data["status"] == "ready"

    # Simulate degradation
    db_ready = False
    ready_ok, ready_data = registry.check_readiness()
    assert ready_ok is False
    assert ready_data["status"] == "not_ready"
    assert ready_data["checks"]["storage"]["status"] == "not_ready"

    # Start live HTTP server
    port = get_free_port()
    server = HealthServer(
        host="127.0.0.1",
        port=port,
        registry=registry,
        metrics_provider=lambda: "# HELP uptime_gauge\nuptime 42\n",
    )
    server.start()
    try:
        base_url = f"http://127.0.0.1:{port}"

        # /healthz -> 200
        with urllib.request.urlopen(f"{base_url}/healthz") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"

        # /readyz -> 503 because db_ready is False
        try:
            urllib.request.urlopen(f"{base_url}/readyz")
            pytest.fail("Expected 503 HTTPError")
        except urllib.error.HTTPError as err:
            assert err.code == 503
            err_data = json.loads(err.read().decode("utf-8"))
            assert err_data["status"] == "not_ready"

        # /metrics -> 200
        with urllib.request.urlopen(f"{base_url}/metrics") as resp:
            assert resp.status == 200
            content = resp.read().decode("utf-8")
            assert "uptime 42" in content
    finally:
        server.stop()


def test_dashboard_server_healthz_and_readyz(tmp_path: Path):
    db_file = tmp_path / "dash.db"
    app = create_app(db_file)
    client = TestClient(app)

    # Test /healthz
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert "uptime_s" in res.json()

    # Test /readyz
    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json()["status"] == "ready"
    assert res.json()["database"] == "connected"
