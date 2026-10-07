"use client";
import { useApi } from "@/lib/useApi";
import { Async, Card, HBars, PageHeader, Stat, Table } from "@/components/ui";
import { fmtNum, fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Network() {
  const s = useApi<Rec>("/api/network?limit=100", 20000);
  return (
    <>
      <PageHeader title="Network Activity" subtitle="Connections and DNS observed by the agent" />
      <Async state={s}>
        {(d) => (
          <>
            <div className="grid g4">
              <Stat label="Connections" value={d.totals.connections} />
              <Stat label="DNS events" value={d.totals.dns} />
            </div>
            <div className="grid g2">
              <Card title="Top destinations">
                <HBars items={d.top_destinations.map((r: Rec) => ({ label: `${r.destination_ip}:${r.destination_port}`, value: r.n }))} />
              </Card>
              <Card title="Top domains">
                <HBars items={d.top_domains.map((r: Rec) => ({ label: r.domain, value: r.n }))} />
              </Card>
            </div>
            <Card title="Recent connections">
              <Table rows={d.connections} empty="No connections recorded" columns={[
                { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
                { key: "process_name", label: "Process" },
                { key: "pid", label: "PID" },
                { key: "destination_ip", label: "Destination", className: "mono" },
                { key: "destination_port", label: "Port" },
                { key: "protocol", label: "Proto" },
                { key: "domain", label: "Domain" },
              ]} />
            </Card>
            <div style={{ height: 14 }} />
            <Card title="Recent DNS">
              <Table rows={d.dns} empty="No DNS events recorded" columns={[
                { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
                { key: "domain", label: "Domain" },
                { key: "entropy", label: "Entropy", render: (r) => fmtNum(r.entropy as number, 2) },
                { key: "resolved_ips", label: "Resolved", className: "mono" },
              ]} />
            </Card>
          </>
        )}
      </Async>
    </>
  );
}
