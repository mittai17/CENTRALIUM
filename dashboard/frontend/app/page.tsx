"use client";
import Link from "next/link";
import { useApi } from "@/lib/useApi";
import { Async, Bars, Card, Empty, HBars, KV, PageHeader, Severity, Stat, Table } from "@/components/ui";
import { fmtNum, fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

const SEV_COLORS: Record<string, string> = { CRITICAL: "#c62828", HIGH: "#c2410c", MEDIUM: "#b45309", LOW: "#64748b", INFO: "#9ca3af" };

export default function Overview() {
  const s = useApi<Rec>("/api/overview", 15000);
  return (
    <>
      <PageHeader title="Overview" subtitle="Endpoint status, protection, risk and detection activity" />
      <Async state={s}>
        {(d) => (
          <>
            {d.empty && <Empty title="No telemetry yet" hint="The agent has not recorded events in this database. Data appears here once the agent runs (or demo replay is started)." />}
            <div className="grid g4">
              <Stat label="Endpoint" value={d.endpoint.host_id} hint={`Last event: ${fmtTime(d.endpoint.last_event)}`} />
              <Stat label="Protection" value={d.endpoint.protection} hint={`Mode ${d.endpoint.mode}`} />
              <Stat label="Highest incident risk" value={fmtNum(d.highest_incident_risk, 0)} tone={d.highest_incident_risk >= 80 ? "critical" : undefined} hint="0-100" />
              <Stat label="Open incidents" value={d.counts.open_incidents} tone={d.counts.open_incidents > 0 ? "critical" : undefined} />
            </div>
            <div className="grid g4">
              <Stat label="Events" value={d.counts.events} />
              <Stat label="Findings" value={d.counts.findings} />
              <Stat label="Critical findings" value={d.findings_by_severity.CRITICAL} tone={d.findings_by_severity.CRITICAL > 0 ? "critical" : undefined} />
              <Stat label="Pending sync" value={d.counts.sync_pending} />
            </div>
            <div className="grid g23">
              <Card title="Events per hour (last 24 buckets)">
                <Bars ariaLabel="Events per hour" items={d.events_hourly.map((h: Rec) => ({ label: h.hour.slice(11, 13), value: h.events }))} />
              </Card>
              <Card title="Findings by severity">
                <Bars ariaLabel="Findings by severity" colors={SEV_COLORS} items={Object.entries(d.findings_by_severity).map(([label, value]) => ({ label, value: value as number }))} />
              </Card>
            </div>
            <div className="grid g2">
              <Card title="Critical and high findings" right={<Link href="/threats/">All threats</Link>}>
                <Table
                  rows={d.critical_findings}
                  empty="No high-severity findings"
                  columns={[
                    { key: "severity", label: "Sev", render: (r) => <Severity value={r.severity as string} /> },
                    { key: "title", label: "Title", render: (r) => <Link href={`/ai-analyst/?id=${r.finding_id}`}>{String(r.title)}</Link> },
                    { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
                  ]}
                />
              </Card>
              <Card title="Recent incidents" right={<Link href="/incidents/">All incidents</Link>}>
                <Table
                  rows={d.recent_incidents}
                  empty="No incidents"
                  columns={[
                    { key: "band", label: "Band", render: (r) => <Severity value={r.band as string} /> },
                    { key: "title", label: "Title" },
                    { key: "risk_score", label: "Risk", render: (r) => fmtNum(r.risk_score as number, 0) },
                    { key: "status", label: "Status" },
                  ]}
                />
              </Card>
            </div>
            <div className="grid g3">
              <Card title="Activity and graph">
                <KV rows={[["Processes tracked", d.counts.processes], ["Network connections", d.counts.network_connections], ["DNS events", d.counts.dns_events], ["Attack-graph nodes (derived)", d.counts.processes]]} />
              </Card>
              <Card title="ML statistics">
                <KV rows={[["ML results", d.ml.results], ["Avg anomaly score", fmtNum(d.ml.avg_anomaly, 3)], ["Avg latency (ms)", fmtNum(d.ml.avg_latency_ms, 2)]]} />
              </Card>
              <Card title="AI statistics">
                <KV rows={[["Backend", d.ai.backend.kind], ["Analyses", d.ai.analyses], ["Model available", d.ai.available], ["Avg latency (ms)", fmtNum(d.ai.avg_latency_ms, 0)]]} />
              </Card>
            </div>
            <Card title="Top detection rules">
              <HBars items={d.top_rules.map((r: Rec) => ({ label: `${r.rule_id} (${r.source})`, value: r.n }))} color="#b71c1c" />
            </Card>
          </>
        )}
      </Async>
    </>
  );
}
