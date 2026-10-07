"use client";
import { useMemo, useState } from "react";
import type { Rec } from "@/lib/api";

interface N { id: string; type?: string; label?: string; [k: string]: unknown }
interface E { source: string; target: string; type?: string; count?: number }

/** Simple layered layout: depth = distance from roots along edges; no external graph library. */
export function GraphView({ nodes, edges }: { nodes: N[]; edges: E[] }) {
  const [sel, setSel] = useState<N | null>(null);
  const layout = useMemo(() => {
    const ids = new Set(nodes.map((n) => n.id));
    const valid = edges.filter((e) => ids.has(e.source) && ids.has(e.target));
    const indeg = new Map<string, number>();
    valid.forEach((e) => indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1));
    const depth = new Map<string, number>();
    const queue = nodes.filter((n) => !indeg.get(n.id)).map((n) => n.id);
    queue.forEach((id) => depth.set(id, 0));
    for (let i = 0; i < queue.length; i++) {
      const cur = queue[i];
      for (const e of valid) {
        if (e.source === cur && !depth.has(e.target)) {
          depth.set(e.target, (depth.get(cur) ?? 0) + 1);
          queue.push(e.target);
        }
      }
    }
    nodes.forEach((n) => { if (!depth.has(n.id)) depth.set(n.id, 0); });
    const cols = new Map<number, N[]>();
    nodes.forEach((n) => { const d = depth.get(n.id) ?? 0; cols.set(d, [...(cols.get(d) ?? []), n]); });
    const pos = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    cols.forEach((list, d) => {
      maxRows = Math.max(maxRows, list.length);
      list.forEach((n, i) => pos.set(n.id, { x: 90 + d * 190, y: 30 + i * 46 }));
    });
    return { pos, valid, width: 180 + (Math.max(...cols.keys(), 0) + 1) * 190, height: 60 + maxRows * 46 };
  }, [nodes, edges]);

  return (
    <div>
      <div style={{ overflow: "auto", maxHeight: 560 }}>
        <svg className="graph-svg" width={layout.width} height={layout.height} role="img" aria-label={`Attack graph with ${nodes.length} nodes and ${edges.length} edges`}>
          <defs>
            <marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" fill="#94a3b8" />
            </marker>
          </defs>
          {layout.valid.map((e, i) => {
            const a = layout.pos.get(e.source)!;
            const b = layout.pos.get(e.target)!;
            return <line key={i} x1={a.x + 70} y1={a.y} x2={b.x - 70} y2={b.y} stroke={e.type === "connected" ? "#b71c1c" : "#94a3b8"} strokeWidth={1.4} markerEnd="url(#arr)" />;
          })}
          {nodes.map((n) => {
            const p = layout.pos.get(n.id)!;
            const net = n.type === "network";
            return (
              <g key={n.id} tabIndex={0} role="button" aria-label={`${n.type ?? "node"} ${n.label ?? n.id}`} onClick={() => setSel(n)} onKeyDown={(e) => e.key === "Enter" && setSel(n)} style={{ cursor: "pointer" }}>
                <rect x={p.x - 70} y={p.y - 16} width={140} height={32} rx={6} fill={net ? "#fdecec" : "#fff"} stroke={sel?.id === n.id ? "#b71c1c" : "#cbd5e1"} strokeWidth={sel?.id === n.id ? 2 : 1} />
                <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={12} fill="#15181d">{String(n.label ?? n.id).slice(0, 22)}</text>
              </g>
            );
          })}
        </svg>
      </div>
      <p className="muted small">Grey edges: process spawn. Red edges: network connection. Select a node for details.</p>
      {sel && <pre className="json">{JSON.stringify(sel as Rec, null, 2)}</pre>}
    </div>
  );
}
