"use client";
import Link from "next/link";
import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { Async, Card, KV, Loading, PageHeader, Severity, Table } from "@/components/ui";
import { fmtNum, fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

function Detail({ id }: { id: string }) {
  const s = useApi<Rec>(`/api/incidents/${encodeURIComponent(id)}`);
  return (
    <Async state={s}>
      {(d) => (
        <>
          <Card title={d.incident.title} right={<Link href="/incidents/">Back to list</Link>}>
            <KV
              rows={[
                ["Band", <Severity key="b" value={d.incident.band} />],
                ["Risk score", fmtNum(d.incident.risk_score, 0)],
                ["Status", d.incident.status],
                ["Host", d.incident.host_id],
                ["Attack stage", d.incident.attack_stage],
                ["MITRE", d.incident.mitre_techniques.join(", ")],
                ["Created", fmtTime(d.incident.created_at)],
                ["Summary", d.incident.summary],
              ]}
            />
          </Card>
          <div style={{ height: 14 }} />
          <Card title="Findings">
            <Table
              rows={d.findings}
              empty="No findings linked"
              columns={[
                { key: "severity", label: "Severity", render: (r) => <Severity value={r.severity as string} /> },
                { key: "title", label: "Title", render: (r) => <Link href={`/ai-analyst/?id=${r.finding_id}`}>{String(r.title)}</Link> },
                { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
              ]}
            />
          </Card>
          <div style={{ height: 14 }} />
          <Card title="Response actions">
            <Table rows={d.actions} empty="No actions recorded" columns={[{ key: "action", label: "Action" }, { key: "status", label: "Status" }, { key: "detail", label: "Detail" }, { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) }]} />
          </Card>
        </>
      )}
    </Async>
  );
}

function List() {
  const router = useRouter();
  const s = useApi<Rec>("/api/incidents?limit=100", 20000);
  return (
    <Card title="Incidents">
      <Async state={s}>
        {(d) => (
          <Table
            rows={d.items}
            empty="No incidents"
            hint="Incidents are created when known-malicious evidence or HIGH/CRITICAL risk is observed."
            onRow={(r) => router.push(`/incidents/?id=${encodeURIComponent(r.incident_id as string)}`)}
            columns={[
              { key: "band", label: "Band", render: (r) => <Severity value={r.band as string} /> },
              { key: "title", label: "Title" },
              { key: "risk_score", label: "Risk", render: (r) => fmtNum(r.risk_score as number, 0) },
              { key: "status", label: "Status" },
              { key: "attack_stage", label: "Stage" },
              { key: "host_id", label: "Host" },
              { key: "created_at", label: "Created", render: (r) => fmtTime(r.created_at as string) },
            ]}
          />
        )}
      </Async>
    </Card>
  );
}

function Inner() {
  const id = useSearchParams().get("id");
  return id ? <Detail id={id} /> : <List />;
}

export default function Incidents() {
  return (
    <>
      <PageHeader title="Incidents" subtitle="Correlated detections requiring attention" />
      <Suspense fallback={<Loading />}>
        <Inner />
      </Suspense>
    </>
  );
}
