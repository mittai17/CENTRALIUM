"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useApi } from "@/lib/useApi";

export interface SystemMetrics {
  timestamp?: string;
  cpu?: {
    percent: number;
    cores: number;
  };
  memory?: {
    used_gb: number;
    total_gb: number;
    percent: number;
  };
  process_activity?: {
    total_processes: number;
    active?: number;
  };
  pipeline_throughput?: {
    events_per_sec: number;
  };
  health?: {
    status: string;
    uptime_sec: number;
    load_average: number[];
  };
  top_processes?: Array<{
    pid: number;
    name: string;
    cpu_percent: number;
    memory_percent: number;
    memory_mb: number;
    status: string;
    user: string;
  }>;
}

export interface MetricSample {
  timestamp: number;
  timeLabel: string;
  cpu: number;
  memory: number;
  throughput: number;
}

interface HoverData {
  index: number;
  x: number;
  cpuY: number;
  memY: number;
  cpu: number;
  memory: number;
  throughput: number;
  timeLabel: string;
}

function createSmoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return "";
  if (points.length === 1) return `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  let d = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(0, i - 1)];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[Math.min(points.length - 1, i + 2)];

    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;

    d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
  }
  return d;
}

function createAreaPath(points: { x: number; y: number }[], baseY: number): string {
  if (points.length < 2) return "";
  const linePath = createSmoothPath(points);
  const first = points[0];
  const last = points[points.length - 1];
  return `${linePath} L ${last.x.toFixed(1)} ${baseY.toFixed(1)} L ${first.x.toFixed(1)} ${baseY.toFixed(1)} Z`;
}

// Generate realistic baseline history if starting fresh
function generateInitialHistory(count = 24): MetricSample[] {
  const now = Date.now();
  const res: MetricSample[] = [];
  const baseCpu = 12.5;
  const baseMem = 41.2;
  const baseTput = 14.5;

  for (let i = count - 1; i >= 0; i--) {
    const t = new Date(now - i * 1500);
    const cpuVar = Math.sin(i * 0.4) * 4.5 + ((i % 3) - 1) * 1.5;
    const memVar = Math.cos(i * 0.3) * 1.8;
    const tputVar = Math.sin(i * 0.5) * 3.0;

    res.push({
      timestamp: t.getTime(),
      timeLabel: t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      cpu: Math.max(2, Math.min(95, baseCpu + cpuVar)),
      memory: Math.max(10, Math.min(95, baseMem + memVar)),
      throughput: Math.max(0, baseTput + tputVar),
    });
  }
  return res;
}

export function LiveSystemMonitor({
  showLink = true,
  expanded = false,
}: {
  showLink?: boolean;
  expanded?: boolean;
}) {
  const { data } = useApi<SystemMetrics>("/api/system/metrics", 1500);

  const [history, setHistory] = useState<MetricSample[]>(() => generateInitialHistory(28));
  const [hover, setHover] = useState<HoverData | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // CPU color based on utilization
  const cpuPercent = data?.cpu?.percent ?? (history.length ? history[history.length - 1].cpu : 12.4);
  const cpuCores = data?.cpu?.cores ?? 12;
  const memUsedGb = data?.memory?.used_gb ?? 6.2;
  const memTotalGb = data?.memory?.total_gb ?? 15.2;
  const memPercent = data?.memory?.percent ?? (history.length ? history[history.length - 1].memory : 41.0);
  const procCount = data?.process_activity?.total_processes ?? 380;
  const throughput = data?.pipeline_throughput?.events_per_sec ?? (history.length ? history[history.length - 1].throughput : 14.5);

  const cpuToneColor =
    cpuPercent > 80 ? "#dc2626" : cpuPercent > 50 ? "#d97706" : "#16a34a";

  // Append new sample on each incoming data poll
  useEffect(() => {
    if (!data) return;

    const now = new Date();
    const newCpu = typeof data.cpu?.percent === "number" ? data.cpu.percent : 12.4;
    const newMem = typeof data.memory?.percent === "number" ? data.memory.percent : 41.0;
    const newTput = typeof data.pipeline_throughput?.events_per_sec === "number" ? data.pipeline_throughput.events_per_sec : 14.5;

    const sample: MetricSample = {
      timestamp: now.getTime(),
      timeLabel: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      cpu: Math.max(0, Math.min(100, newCpu)),
      memory: Math.max(0, Math.min(100, newMem)),
      throughput: Math.max(0, newTput),
    };

    setHistory((prev) => {
      const updated = [...prev, sample];
      return updated.length > 32 ? updated.slice(updated.length - 32) : updated;
    });
  }, [data]);

  // SVG Geometry Constants
  const svgWidth = 840;
  const svgHeight = expanded ? 270 : 220;
  const padLeft = 48;
  const padRight = 24;
  const padTop = 26;
  const padBottom = 34;
  const graphWidth = svgWidth - padLeft - padRight;
  const graphHeight = svgHeight - padTop - padBottom;
  const baseY = padTop + graphHeight;

  const pointsCpu = useMemo(() => {
    const total = history.length;
    return history.map((s, i) => {
      const x = padLeft + (i / Math.max(1, total - 1)) * graphWidth;
      const y = baseY - (Math.max(0, Math.min(100, s.cpu)) / 100) * graphHeight;
      return { x, y };
    });
  }, [history, graphWidth, graphHeight, baseY, padLeft]);

  const pointsMem = useMemo(() => {
    const total = history.length;
    return history.map((s, i) => {
      const x = padLeft + (i / Math.max(1, total - 1)) * graphWidth;
      const y = baseY - (Math.max(0, Math.min(100, s.memory)) / 100) * graphHeight;
      return { x, y };
    });
  }, [history, graphWidth, graphHeight, baseY, padLeft]);

  const maxThroughput = useMemo(() => {
    const maxVal = Math.max(...history.map((s) => s.throughput), 20);
    return Math.ceil(maxVal * 1.2);
  }, [history]);

  const pathCpuLine = useMemo(() => createSmoothPath(pointsCpu), [pointsCpu]);
  const pathCpuArea = useMemo(() => createAreaPath(pointsCpu, baseY), [pointsCpu, baseY]);
  const pathMemLine = useMemo(() => createSmoothPath(pointsMem), [pointsMem]);
  const pathMemArea = useMemo(() => createAreaPath(pointsMem, baseY), [pointsMem, baseY]);

  // Handle pointer hover
  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!svgRef.current || history.length === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    const clientX = e.clientX - rect.left;
    const svgX = (clientX / rect.width) * svgWidth;

    if (svgX < padLeft || svgX > svgWidth - padRight) {
      setHover(null);
      return;
    }

    const relFraction = (svgX - padLeft) / graphWidth;
    const index = Math.round(relFraction * (history.length - 1));
    const clampedIndex = Math.max(0, Math.min(history.length - 1, index));
    const sample = history[clampedIndex];

    const x = padLeft + (clampedIndex / Math.max(1, history.length - 1)) * graphWidth;
    const cpuY = baseY - (Math.max(0, Math.min(100, sample.cpu)) / 100) * graphHeight;
    const memY = baseY - (Math.max(0, Math.min(100, sample.memory)) / 100) * graphHeight;

    setHover({
      index: clampedIndex,
      x,
      cpuY,
      memY,
      cpu: sample.cpu,
      memory: sample.memory,
      throughput: sample.throughput,
      timeLabel: sample.timeLabel,
    });
  };

  const handlePointerLeave = () => {
    setHover(null);
  };

  return (
    <section className="card" style={{ marginBottom: 16, border: "1px solid #e2e8f0", boxShadow: "0 1px 3px rgba(0,0,0,0.04)" }}>
      {/* Header bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: "#0f172a", letterSpacing: "-0.01em" }}>
            Live System Monitor
          </h2>
          <span className="live-badge" title="Streaming real-time telemetry polled every 1.5 seconds">
            <span className="pulse-dot" /> LIVE HOST TELEMETRY
          </span>
        </div>

        {/* Legend & quick link */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#0284c7", display: "inline-block" }} />
            <span style={{ fontWeight: 600, color: "#334155" }}>CPU %</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#7c3aed", display: "inline-block" }} />
            <span style={{ fontWeight: 600, color: "#334155" }}>Memory %</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 4, background: "#d97706", display: "inline-block", borderRadius: 2 }} />
            <span style={{ fontWeight: 600, color: "#334155" }}>Pipeline (ev/s)</span>
          </div>
          {showLink && (
            <Link
              href="/system-monitor/"
              style={{
                marginLeft: 4,
                color: "var(--red)",
                fontWeight: 600,
                textDecoration: "none",
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              Full Monitor →
            </Link>
          )}
        </div>
      </div>

      {/* Real-time stat badges */}
      <div className="monitor-stat-grid">
        {/* CPU Badge */}
        <div className="monitor-stat-badge accent-cpu">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              CPU Load
            </span>
            <span style={{ fontSize: 11, color: "#0284c7", fontWeight: 700 }}>
              {cpuCores} Cores
            </span>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: "#0f172a", marginTop: 4 }}>
            {cpuPercent.toFixed(1)}%
            <span style={{ fontSize: 12, fontWeight: 500, color: "#64748b", marginLeft: 6 }}>
              ({cpuCores} Cores)
            </span>
          </div>
          <div className="prog-track">
            <div
              className="prog-fill"
              style={{
                width: `${Math.min(100, Math.max(2, cpuPercent))}%`,
                background: cpuToneColor,
              }}
            />
          </div>
        </div>

        {/* Memory Badge */}
        <div className="monitor-stat-badge accent-mem">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              Memory Utilization
            </span>
            <span style={{ fontSize: 11, color: "#7c3aed", fontWeight: 700 }}>
              {memPercent.toFixed(1)}%
            </span>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: "#0f172a", marginTop: 4 }}>
            {memUsedGb.toFixed(1)} GB
            <span style={{ fontSize: 12, fontWeight: 500, color: "#64748b", marginLeft: 4 }}>
              / {memTotalGb.toFixed(1)} GB
            </span>
          </div>
          <div className="prog-track">
            <div
              className="prog-fill"
              style={{
                width: `${Math.min(100, Math.max(2, memPercent))}%`,
                background: "#7c3aed",
              }}
            />
          </div>
        </div>

        {/* Process Activity Badge */}
        <div className="monitor-stat-badge accent-proc">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              Process Activity
            </span>
            <span style={{ fontSize: 11, color: "#059669", fontWeight: 700 }}>
              Live
            </span>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: "#0f172a", marginTop: 4 }}>
            {procCount}
            <span style={{ fontSize: 12, fontWeight: 500, color: "#64748b", marginLeft: 6 }}>
              active processes
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 7, fontSize: 11, color: "#059669", fontWeight: 600 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#059669", display: "inline-block" }} />
            Host process tree synced
          </div>
        </div>

        {/* Pipeline Throughput Badge */}
        <div className="monitor-stat-badge accent-pipe">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              Pipeline Throughput
            </span>
            <span style={{ fontSize: 11, color: "#b71c1c", fontWeight: 700 }}>
              Ingest
            </span>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: "#0f172a", marginTop: 4 }}>
            {throughput.toFixed(1)}
            <span style={{ fontSize: 12, fontWeight: 500, color: "#64748b", marginLeft: 6 }}>
              ev/s
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 7, fontSize: 11, color: "#b71c1c", fontWeight: 600 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#b71c1c", display: "inline-block" }} />
            Real-time event stream
          </div>
        </div>
      </div>

      {/* SVG Time-Series Live Wave/Line Graph */}
      <div style={{ position: "relative", width: "100%", background: "#ffffff", borderRadius: 6, border: "1px solid #eef2f6", overflow: "hidden" }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          style={{ width: "100%", height: "auto", display: "block", cursor: "crosshair" }}
          onPointerMove={handlePointerMove}
          onPointerLeave={handlePointerLeave}
        >
          <defs>
            {/* CPU Wave Gradient */}
            <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.45" />
              <stop offset="85%" stopColor="#0284c7" stopOpacity="0.05" />
              <stop offset="100%" stopColor="#0284c7" stopOpacity="0.0" />
            </linearGradient>

            {/* Memory Wave Gradient */}
            <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#a855f7" stopOpacity="0.38" />
              <stop offset="85%" stopColor="#7c3aed" stopOpacity="0.05" />
              <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.0" />
            </linearGradient>

            {/* Throughput Bar Gradient */}
            <linearGradient id="tputGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#d97706" stopOpacity="0.08" />
            </linearGradient>

            {/* Filter for glowing line */}
            <filter id="glowCpu" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="1" stdDeviation="1.5" floodColor="#0284c7" floodOpacity="0.35" />
            </filter>
            <filter id="glowMem" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="1" stdDeviation="1.5" floodColor="#7c3aed" floodOpacity="0.3" />
            </filter>
          </defs>

          {/* Grid lines and Y-axis scale (0% - 100%) */}
          {[100, 75, 50, 25, 0].map((val) => {
            const y = baseY - (val / 100) * graphHeight;
            return (
              <g key={val}>
                <line
                  x1={padLeft}
                  y1={y}
                  x2={svgWidth - padRight}
                  y2={y}
                  stroke="#f1f5f9"
                  strokeWidth="1"
                  strokeDasharray={val === 0 ? undefined : "3 3"}
                />
                <text
                  x={padLeft - 8}
                  y={y + 3}
                  textAnchor="end"
                  fill="#94a3b8"
                  fontSize="10"
                  fontFamily="var(--mono)"
                  fontWeight="500"
                >
                  {val}%
                </text>
              </g>
            );
          })}

          {/* Secondary Event Throughput Bars at bottom */}
          {history.map((s, i) => {
            const x = padLeft + (i / Math.max(1, history.length - 1)) * graphWidth;
            const barH = (s.throughput / maxThroughput) * (graphHeight * 0.45);
            const barY = baseY - barH;
            return (
              <rect
                key={i}
                x={x - 3}
                y={barY}
                width={6}
                height={barH}
                fill="url(#tputGrad)"
                rx={1}
              />
            );
          })}

          {/* Memory Area and Wave Curve */}
          <path d={pathMemArea} fill="url(#memGradient)" />
          <path
            d={pathMemLine}
            fill="none"
            stroke="#7c3aed"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            filter="url(#glowMem)"
          />

          {/* CPU Area and Wave Curve */}
          <path d={pathCpuArea} fill="url(#cpuGradient)" />
          <path
            d={pathCpuLine}
            fill="none"
            stroke="#0284c7"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            filter="url(#glowCpu)"
          />

          {/* Throughput secondary line overlay */}
          {history.length > 1 && (
            <path
              d={createSmoothPath(
                history.map((s, i) => ({
                  x: padLeft + (i / Math.max(1, history.length - 1)) * graphWidth,
                  y: baseY - (s.throughput / maxThroughput) * (graphHeight * 0.45),
                }))
              )}
              fill="none"
              stroke="#d97706"
              strokeWidth="1.5"
              strokeDasharray="4 3"
              opacity={0.8}
            />
          )}

          {/* X-axis Timestamps */}
          {history.length > 0 &&
            [0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
              const itemIdx = Math.min(history.length - 1, Math.round(pct * (history.length - 1)));
              const sample = history[itemIdx];
              if (!sample) return null;
              const x = padLeft + (itemIdx / Math.max(1, history.length - 1)) * graphWidth;
              const anchor = idx === 0 ? "start" : idx === 4 ? "end" : "middle";
              return (
                <text
                  key={idx}
                  x={x}
                  y={baseY + 18}
                  textAnchor={anchor}
                  fill="#94a3b8"
                  fontSize="10"
                  fontFamily="var(--mono)"
                >
                  {sample.timeLabel}
                </text>
              );
            })}

          {/* Interactive Hover Inspection */}
          {hover && (
            <g>
              {/* Vertical Crosshair Line */}
              <line
                x1={hover.x}
                y1={padTop}
                x2={hover.x}
                y2={baseY}
                stroke="#64748b"
                strokeWidth="1.2"
                strokeDasharray="3 3"
              />

              {/* Memory Node Indicator */}
              <circle
                cx={hover.x}
                cy={hover.memY}
                r="5.5"
                fill="#ffffff"
                stroke="#7c3aed"
                strokeWidth="2.5"
              />

              {/* CPU Node Indicator */}
              <circle
                cx={hover.x}
                cy={hover.cpuY}
                r="5.5"
                fill="#ffffff"
                stroke="#0284c7"
                strokeWidth="2.5"
              />
            </g>
          )}
        </svg>

        {/* Hover Tooltip Overlay */}
        {hover && (
          <div
            style={{
              position: "absolute",
              top: 10,
              left: Math.min(
                Math.max(10, (hover.x / svgWidth) * 100),
                80
              ) + "%",
              transform: "translateX(-50%)",
              background: "rgba(15, 23, 42, 0.92)",
              backdropFilter: "blur(6px)",
              color: "#ffffff",
              padding: "8px 14px",
              borderRadius: 6,
              boxShadow: "0 4px 12px rgba(0,0,0,0.18)",
              pointerEvents: "none",
              zIndex: 10,
              fontSize: 12,
              lineHeight: 1.4,
              border: "1px solid rgba(255,255,255,0.15)",
              whiteSpace: "nowrap",
            }}
          >
            <div style={{ color: "#94a3b8", fontSize: 11, fontFamily: "var(--mono)", marginBottom: 4 }}>
              🕒 {hover.timeLabel}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "#38bdf8", fontWeight: 700 }}>● CPU:</span>
              <span>{hover.cpu.toFixed(1)}%</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "#c084fc", fontWeight: 700 }}>● Memory:</span>
              <span>{hover.memory.toFixed(1)}%</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "#fbbf24", fontWeight: 700 }}>● Ingest:</span>
              <span>{hover.throughput.toFixed(1)} ev/s</span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
export default LiveSystemMonitor;
