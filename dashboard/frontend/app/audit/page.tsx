"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { api, Rec } from "@/lib/api";
import { useAuth } from "@/components/AuthProvider";
import { Async, Badge, Card, Empty, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";

export default function Audit() {
  const { can } = useAuth();
  const s = useApi<Rec>(can("analyst") ? "/api/audit?limit=200" : null, 30000);
  const [v, setV] = useState<Rec | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (!can("analyst")) return <><PageHeader title="Audit Logs" /><Empty title="Analyst role required" /></>;
  async function verify() {
    setErr(null);
    try { setV(await api("/api/audit/verify")); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Tamper-evident, hash-chained record of management and enforcement events" actions={<button className="btn btn-primary" onClick={verify}>Verify chain</button>} />
      {v && (
        <div role="status" className="card" style={{ marginBottom: 14, borderLeft: `4px solid ${v.ok ? "#166534" : "#c62828"}` }}>
          {v.ok ? <><Badge tone="ok">Chain verified</Badge> {v.entries} entries intact.</> : <><Badge tone="sev-critical">Chain broken</Badge> first bad sequence {v.first_bad_seq}: {v.reason}</>}
          <p className="muted small">Tail truncation or a full rewrite is only detectable against an externally anchored head hash.</p>
        </div>
      )}
      {err && <p role="alert" className="error-text">{err}</p>}
      <Async state={s}>
        {(d) => (
          <Card title={`Entries (${d.total} total, newest first)`} right={<span className="mono small">head {String(d.head.hash).slice(0, 16)}</span>}>
            <Table rows={d.items} empty="No audit entries" columns={[
              { key: "seq", label: "#" }, { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
              { key: "actor", label: "Actor" }, { key: "event_type", label: "Event" },
              { key: "details", label: "Details", render: (r) => <span className="mono">{JSON.stringify(r.details)}</span> },
              { key: "entry_hash", label: "Hash", render: (r) => <span className="mono">{String(r.entry_hash).slice(0, 12)}</span> },
            ]} />
          </Card>
        )}
      </Async>
    </>
  );
}
