"use client";
import Link from "next/link";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, PageHeader, Severity, Table } from "@/components/ui";
import { fmtNum, fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Threats() {
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [qd, setQd] = useState("");
  const params = new URLSearchParams({ limit: "100" });
  if (sev) params.set("severity", sev);
  if (qd) params.set("q", qd);
  const s = useApi<Rec>(`/api/findings?${params}`, 20000);
  return (
    <>
      <PageHeader title="Threats" subtitle="Findings from EPP, behavior, rules, ML and graph correlation" />
      <Card>
        <form className="row" onSubmit={(e) => { e.preventDefault(); setQd(q); }} role="search">
          <div>
            <label htmlFor="sev">Severity</label>
            <select id="sev" value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="">All</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((x) => <option key={x}>{x}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="q">Search title / rule</label>
            <input id="q" value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} />
          </div>
          <button className="btn btn-primary">Search</button>
        </form>
      </Card>
      <div style={{ height: 14 }} />
      <Card title="Findings">
        <Async state={s}>
          {(d) => (
            <>
              <p className="muted small">{d.total} matching finding(s)</p>
              <Table
                rows={d.items}
                empty="No findings"
                hint="Nothing has been detected yet, or no finding matches the filter."
                columns={[
                  { key: "severity", label: "Severity", render: (r) => <Severity value={r.severity as string} /> },
                  { key: "title", label: "Title", render: (r) => <Link href={`/ai-analyst/?id=${r.finding_id}`}>{String(r.title)}</Link> },
                  { key: "source", label: "Source" },
                  { key: "rule_id", label: "Rule", className: "mono" },
                  { key: "score", label: "Score", render: (r) => fmtNum(r.score as number, 0) },
                  { key: "known_malicious", label: "Known", render: (r) => (r.known_malicious ? <Badge tone="warn">known malicious</Badge> : "-") },
                  { key: "mitre_techniques", label: "MITRE", render: (r) => (r.mitre_techniques as string[]).join(", ") || "-" },
                  { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
                ]}
              />
            </>
          )}
        </Async>
      </Card>
    </>
  );
}
