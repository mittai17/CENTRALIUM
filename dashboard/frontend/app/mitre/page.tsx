"use client";
import Link from "next/link";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, HBars, PageHeader, Severity, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Mitre() {
  const s = useApi<Rec>("/api/mitre", 30000);
  return (
    <>
      <PageHeader title="MITRE ATT&CK" subtitle="Techniques observed in findings and referenced by detection rules" />
      <Async state={s}>
        {(d) => (
          <>
            <div className="grid g2">
              <Card title="Observed attack stages"><HBars color="#b71c1c" items={Object.entries(d.stages).map(([label, value]) => ({ label, value: value as number }))} /></Card>
              <Card title="Rule coverage (technique IDs referenced by rule files)">
                {d.rules_covered_techniques.length ? <div className="tags">{d.rules_covered_techniques.map((t: string) => <Badge key={t}>{t}</Badge>)}</div> : <p className="muted">No technique IDs found in rule files.</p>}
              </Card>
            </div>
            <Card title="Detected techniques">
              <Table rows={d.detected} empty="No techniques observed" hint="Techniques appear once findings carry MITRE mappings." columns={[
                { key: "technique", label: "Technique", render: (r) => <a href={`https://attack.mitre.org/techniques/${String(r.technique).replace(".", "/")}/`} rel="noopener noreferrer" target="_blank">{String(r.technique)}</a> },
                { key: "findings", label: "Findings" },
                { key: "max_severity", label: "Max severity", render: (r) => <Severity value={r.max_severity as string} /> },
                { key: "stages", label: "Stages", render: (r) => (r.stages as string[]).join(", ") },
                { key: "last_seen", label: "Last seen", render: (r) => fmtTime(r.last_seen as string) },
                { key: "example_finding_id", label: "Example", render: (r) => <Link href={`/ai-analyst/?id=${r.example_finding_id}`}>view</Link> },
              ]} />
            </Card>
            <p className="muted small">{d.note}</p>
          </>
        )}
      </Async>
    </>
  );
}
