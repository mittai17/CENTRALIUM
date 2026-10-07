"use client";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Endpoints() {
  const s = useApi<Rec>("/api/endpoints", 30000);
  return (
    <>
      <PageHeader title="Endpoints" subtitle="Hosts reporting telemetry to this database" />
      <Card>
        <Async state={s}>
          {(d) => (
            <Table rows={d.items} empty="No endpoints" columns={[
              { key: "host_id", label: "Host", render: (r) => <>{String(r.host_id)} {r.local ? <Badge>this agent</Badge> : null}</> },
              { key: "events", label: "Events" },
              { key: "open_incidents", label: "Open incidents", render: (r) => ((r.open_incidents as number) > 0 ? <Badge tone="sev-critical">{String(r.open_incidents)}</Badge> : "0") },
              { key: "first_seen", label: "First seen", render: (r) => fmtTime(r.first_seen as string) },
              { key: "last_seen", label: "Last seen", render: (r) => fmtTime(r.last_seen as string) },
            ]} />
          )}
        </Async>
      </Card>
    </>
  );
}
