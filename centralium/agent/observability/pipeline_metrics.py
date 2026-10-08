"""Pipeline stage-latency metrics exporter.

Bridges PipelineStats into OpenTelemetry metric snapshots and Prometheus format.
"""

from __future__ import annotations

import logging
from typing import Any

from centralium.agent.observability.metrics import (
    Meter,
    MetricPoint,
    MetricSnapshot,
    PrometheusExporter,
)

log = logging.getLogger("centralium.observability.pipeline_metrics")


class PipelineLatencyExporter:
    """Exports per-stage latencies, throughput counters, and error rates."""

    def __init__(self, meter: Meter | None = None) -> None:
        self.meter = meter or Meter("centralium.pipeline")
        self.counter_events = self.meter.create_counter(
            "centralium_pipeline_stage_events_total",
            description="Total events processed by pipeline stage",
        )
        self.counter_errors = self.meter.create_counter(
            "centralium_pipeline_stage_errors_total",
            description="Total errors encountered by pipeline stage",
        )

    def export_from_stats_snapshot(self, stats_snapshot: dict[str, Any]) -> list[MetricSnapshot]:
        """Convert a PipelineStats.snapshot() dict into OpenTelemetry MetricSnapshots."""
        snapshots: list[MetricSnapshot] = []

        # 1. Latency summary metrics
        latency_dict = stats_snapshot.get("latency", {})
        latency_points: list[MetricPoint] = []
        for stage, stats in latency_dict.items():
            for metric_key in ("mean_ms", "p50_ms", "p95_ms", "max_ms", "count"):
                if metric_key in stats:
                    stat_name = metric_key.replace("_ms", "")
                    latency_points.append(
                        MetricPoint(
                            attributes={"stage": stage, "stat": stat_name},
                            value=float(stats[metric_key]),
                        )
                    )

        if latency_points:
            snapshots.append(
                MetricSnapshot(
                    name="centralium_pipeline_stage_latency_ms",
                    type="gauge",
                    unit="ms",
                    description="Per-stage execution latency percentiles and averages",
                    points=latency_points,
                )
            )

        # 2. Stage counters
        counters_dict = stats_snapshot.get("counters", {})
        counter_points: list[MetricPoint] = []
        for stage, count in counters_dict.items():
            counter_points.append(MetricPoint(attributes={"stage": stage}, value=float(count)))
        if counter_points:
            snapshots.append(
                MetricSnapshot(
                    name="centralium_pipeline_stage_events_total",
                    type="counter",
                    unit="1",
                    description="Total events processed per stage",
                    points=counter_points,
                )
            )

        # 3. Stage errors
        errors_dict = stats_snapshot.get("errors", {})
        error_points: list[MetricPoint] = []
        for stage, count in errors_dict.items():
            error_points.append(MetricPoint(attributes={"stage": stage}, value=float(count)))
        if error_points:
            snapshots.append(
                MetricSnapshot(
                    name="centralium_pipeline_stage_errors_total",
                    type="counter",
                    unit="1",
                    description="Total errors encountered per stage",
                    points=error_points,
                )
            )

        # 4. Uptime gauge
        uptime = stats_snapshot.get("uptime_sec")
        if uptime is not None:
            snapshots.append(
                MetricSnapshot(
                    name="centralium_agent_uptime_seconds",
                    type="gauge",
                    unit="s",
                    description="Agent pipeline uptime in seconds",
                    points=[MetricPoint(attributes={}, value=float(uptime))],
                )
            )

        return snapshots

    def render_prometheus(self, stats_snapshot: dict[str, Any]) -> str:
        """Render Prometheus exposition text for pipeline stats."""
        snapshots = self.export_from_stats_snapshot(stats_snapshot)
        return PrometheusExporter.render(snapshots)
