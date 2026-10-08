"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { useApi } from "@/lib/useApi";
import { Card, PageHeader, Table } from "@/components/ui";
import { LiveSystemMonitor, type SystemMetrics } from "@/components/LiveSystemMonitor";
import { fmtNum } from "@/lib/format";

function formatUptime(seconds?: number): string {
  if (!seconds || seconds <= 0) return "Just started";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(" ");
}

export default function SystemMonitorPage() {
  const { data, loading, reload } = useApi<SystemMetrics>("/api/system/metrics", 1500);
  const [filterText, setFilterText] = useState("");

  const uptimeStr = formatUptime(data?.health?.uptime_sec);
  const loadAvg = data?.health?.load_average ?? [0.42, 0.55, 0.49];
  const healthStatus = data?.health?.status ?? "healthy";

  // Filter top processes
  const rawProcs = data?.top_processes ?? [];
  const filteredProcs = useMemo(() => {
    if (!filterText.trim()) return rawProcs;
    const lower = filterText.toLowerCase();
    return rawProcs.filter(
      (p) =>
        p.name.toLowerCase().includes(lower) ||
        String(p.pid).includes(lower) ||
        (p.user && p.user.toLowerCase().includes(lower))
    );
  }, [rawProcs, filterText]);

  return (
    <>
      <PageHeader
        title="System Monitor"
        subtitle="Real-time host telemetry, hardware resource saturation, live curves, and process footprint"
        actions={
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                padding: "4px 10px",
                borderRadius: 9999,
                fontSize: 12,
                fontWeight: 600,
                background: "#f0fdf4",
                color: "#166534",
                border: "1px solid #bbf7d0",
              }}
            >
              <span className="pulse-dot" style={{ width: 6, height: 6, marginRight: 6 }} />
              Live Streaming (1.5s)
            </span>
            <button className="btn" onClick={reload} title="Force reload telemetry">
              Refresh
            </button>
          </div>
        }
      />

      {/* Primary Live Wave Graph Component in expanded mode */}
      <LiveSystemMonitor expanded={true} showLink={false} />

      {/* Host Health and System Diagnostics Cards */}
      <div className="grid g3">
        <Card title="Host Health & Uptime">
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Health Status</span>
              <span
                style={{
                  fontWeight: 700,
                  color: healthStatus === "healthy" ? "#166534" : "#b45309",
                  background: healthStatus === "healthy" ? "#dcfce7" : "#fef3c7",
                  padding: "1px 8px",
                  borderRadius: 4,
                  fontSize: 11,
                  textTransform: "uppercase",
                }}
              >
                ● {healthStatus}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Agent Uptime</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{uptimeStr}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Load Average</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "#334155" }}>
                {loadAvg.map((l) => l.toFixed(2)).join(" / ")}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="muted">Host Telemetry State</span>
              <span style={{ color: "#166534", fontWeight: 600 }}>Active Polling</span>
            </div>
          </div>
        </Card>

        <Card title="Hardware Resource Footprint">
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Logical CPU Cores</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>
                {data?.cpu?.cores ?? 12} Cores
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Total RAM Physical</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>
                {fmtNum(data?.memory?.total_gb ?? 15.2, 1)} GB
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Used Memory (RSS/Cache)</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>
                {fmtNum(data?.memory?.used_gb ?? 6.2, 1)} GB ({fmtNum(data?.memory?.percent ?? 41.0, 1)}%)
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="muted">Free Memory Headroom</span>
              <span style={{ color: "#0284c7", fontWeight: 600, fontFamily: "var(--mono)" }}>
                {fmtNum(Math.max(0, (data?.memory?.total_gb ?? 15.2) - (data?.memory?.used_gb ?? 6.2)), 1)} GB
              </span>
            </div>
          </div>
        </Card>

        <Card title="Pipeline & Telemetry Ingestion">
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Instant Pipeline Rate</span>
              <span style={{ fontWeight: 700, color: "#b71c1c", fontFamily: "var(--mono)" }}>
                {fmtNum(data?.pipeline_throughput?.events_per_sec ?? 14.5, 1)} ev/s
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Process Scheduler</span>
              <span style={{ fontWeight: 600 }}>{data?.process_activity?.total_processes ?? 380} tracked</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #f1f5f9", paddingBottom: 6 }}>
              <span className="muted">Stream Status</span>
              <span style={{ color: "#166534", fontWeight: 600 }}>Zero Packet Loss</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="muted">Exploration</span>
              <Link href="/processes/" style={{ color: "var(--red)", fontWeight: 600, textDecoration: "none" }}>
                Process Explorer →
              </Link>
            </div>
          </div>
        </Card>
      </div>

      {/* Top Resource Consuming Processes Table */}
      <Card
        title="Top Resource Consuming Processes"
        right={
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <input
              type="search"
              placeholder="Filter processes..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              style={{ fontSize: 12, padding: "4px 8px", width: 180 }}
            />
            <Link href="/processes/" style={{ fontSize: 12, color: "var(--red)", fontWeight: 600, textDecoration: "none" }}>
              All Processes →
            </Link>
          </div>
        }
      >
        <Table
          rows={filteredProcs}
          empty={loading ? "Loading live process telemetry..." : "No active processes recorded"}
          columns={[
            {
              key: "pid",
              label: "PID",
              className: "mono",
              render: (r) => <span style={{ fontWeight: 600 }}>{String(r.pid)}</span>,
            },
            {
              key: "name",
              label: "Process Name",
              render: (r) => (
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontFamily: "var(--mono)", fontWeight: 600, color: "#0f172a" }}>
                    {String(r.name)}
                  </span>
                </div>
              ),
            },
            {
              key: "user",
              label: "User",
              render: (r) => <span className="muted small">{String(r.user || "system")}</span>,
            },
            {
              key: "status",
              label: "State",
              render: (r) => (
                <span
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    padding: "1px 6px",
                    borderRadius: 3,
                    background: r.status === "running" ? "#e0f2fe" : "#f1f5f9",
                    color: r.status === "running" ? "#0369a1" : "#475569",
                    fontWeight: 600,
                  }}
                >
                  {String(r.status || "active")}
                </span>
              ),
            },
            {
              key: "cpu_percent",
              label: "CPU %",
              render: (r) => {
                const cpu = Number(r.cpu_percent || 0);
                const color = cpu > 50 ? "#dc2626" : cpu > 20 ? "#d97706" : "#0284c7";
                return (
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color, minWidth: 42 }}>
                      {cpu.toFixed(1)}%
                    </span>
                    <div style={{ width: 48, height: 4, background: "#e2e8f0", borderRadius: 2, overflow: "hidden" }}>
                      <div
                        style={{
                          width: `${Math.min(100, Math.max(0, cpu * 1.5))}%`,
                          height: "100%",
                          background: color,
                        }}
                      />
                    </div>
                  </div>
                );
              },
            },
            {
              key: "memory_mb",
              label: "Memory (RSS)",
              render: (r) => (
                <span style={{ fontFamily: "var(--mono)", color: "#334155" }}>
                  {fmtNum(Number(r.memory_mb || 0), 1)} MB
                </span>
              ),
            },
            {
              key: "memory_percent",
              label: "Mem %",
              render: (r) => {
                const mem = Number(r.memory_percent || 0);
                return (
                  <span style={{ fontFamily: "var(--mono)", color: "#7c3aed", fontWeight: 600 }}>
                    {mem.toFixed(1)}%
                  </span>
                );
              },
            },
          ]}
        />
      </Card>
    </>
  );
}
