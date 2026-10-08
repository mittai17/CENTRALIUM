"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Processes() {
  const [q, setQ] = useState("");
  const [qd, setQd] = useState("");
  const s = useApi<Rec>(`/api/processes?limit=200${qd ? `&q=${encodeURIComponent(qd)}` : ""}`, 3000);
  return (
    <>
      <PageHeader title="Process Explorer" subtitle="Observed processes with parent relationships" />
      <Card>
        <form className="row" role="search" onSubmit={(e) => { e.preventDefault(); setQd(q); }}>
          <div>
            <label htmlFor="pq">Name, path or command line</label>
            <input id="pq" value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} />
          </div>
          <button className="btn btn-primary">Search</button>
        </form>
      </Card>
      <div style={{ height: 14 }} />
      <Card title="Processes">
        <Async state={s}>
          {(d) => (
            <Table
              rows={d.items}
              empty="No processes recorded"
              columns={[
                { key: "pid", label: "PID" },
                { key: "ppid", label: "PPID" },
                { key: "name", label: "Name" },
                { key: "user", label: "User" },
                { key: "command_line", label: "Command line", className: "mono" },
                { key: "signer", label: "Signer" },
                { key: "finding_count", label: "Findings", render: (r) => ((r.finding_count as number) > 0 ? <Badge tone="sev-high">{String(r.finding_count)}</Badge> : "0") },
                { key: "start_time", label: "Started", render: (r) => fmtTime(r.start_time as string) },
              ]}
            />
          )}
        </Async>
      </Card>
    </>
  );
}
