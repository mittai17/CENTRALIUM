"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, Empty, PageHeader } from "@/components/ui";
import { GraphView } from "@/components/GraphView";
import type { Rec } from "@/lib/api";

export default function AttackGraph() {
  const [inc, setInc] = useState("");
  const incidents = useApi<Rec>("/api/incidents?limit=100");
  const s = useApi<Rec>(inc ? `/api/graph?incident_id=${encodeURIComponent(inc)}` : "/api/graph");
  return (
    <>
      <PageHeader title="Attack Graph" subtitle="Process lineage and network relationships" />
      <Card>
        <label htmlFor="inc">Scope</label>
        <select id="inc" value={inc} onChange={(e) => setInc(e.target.value)}>
          <option value="">Recent activity (all)</option>
          {(incidents.data?.items ?? []).map((i: Rec) => (
            <option key={i.incident_id} value={i.incident_id}>{i.title}</option>
          ))}
        </select>
      </Card>
      <div style={{ height: 14 }} />
      <Card title="Graph" right={s.data && <Badge>{`source: ${s.data.source}`}</Badge>}>
        <Async state={s}>
          {(d) => d.nodes.length ? <GraphView nodes={d.nodes} edges={d.edges} /> : <Empty title="No graph data" hint="No graph snapshot or process telemetry is available yet." />}
        </Async>
      </Card>
    </>
  );
}
