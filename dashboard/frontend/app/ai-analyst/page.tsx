"use client";
import Link from "next/link";
import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { Async, Badge, Card, Empty, KV, Loading, PageHeader, Severity, Table } from "@/components/ui";
import { fmtNum, fmtTime, pct } from "@/lib/format";
import type { Rec } from "@/lib/api";

function BackendBadge({ b }: { b: Rec }) {
  return b.kind === "gemma" ? <Badge tone="ok">Gemma (real)</Badge> : b.kind === "mock" ? <Badge tone="warn">MOCK - not a real model</Badge> : <Badge>{String(b.kind)}</Badge>;
}

function Detail({ id }: { id: string }) {
  const s = useApi<Rec>(`/api/findings/${encodeURIComponent(id)}`);
  return (
    <Async state={s}>
      {(d) => (
        <>
          <Card title={d.finding.title} right={<Link href="/ai-analyst/">Back to list</Link>}>
            <div className="tags" style={{ marginBottom: 12 }}>
              <Badge>{d.verdict ? `Verdict: ${d.verdict.verdict}` : "No AI verdict"}</Badge>
              <Severity value={d.severity} />
              <Badge>Confidence {d.confidence == null ? "-" : pct(d.confidence)}</Badge>
              <Badge tone={d.risk_score >= 80 ? "sev-critical" : ""}>{`Risk ${fmtNum(d.risk_score, 0)}`}</Badge>
              <BackendBadge b={d.ai_backend} />
            </div>
            <p className="muted small">Risk score source: {d.risk_score_source}. AI output is advisory; actions are decided by the deterministic policy engine.</p>
            {!d.verdict && <Empty title="No AI analysis for this event" hint="The AI is gated: it runs only for novel, medium-risk-or-above events, and never for known malware." />}
          </Card>
          <div className="grid g2" style={{ marginTop: 14 }}>
            <Card title="Why detected">{d.why_detected.length ? <ul>{d.why_detected.map((w: string, i: number) => <li key={i}>{w}</li>)}</ul> : <Empty title="None recorded" />}</Card>
            <Card title="Evidence">{d.evidence.length ? <ul>{d.evidence.map((w: string, i: number) => <li key={i} className="mono">{w}</li>)}</ul> : <Empty title="None recorded" />}</Card>
            <Card title="Attack chain">
              {d.attack_chain.length ? (
                <div className="chain">{d.attack_chain.map((c: Rec, i: number) => <span key={i}>{i > 0 && <span className="arrow">&rarr; </span>}<Badge>{c.stage}</Badge></span>)}</div>
              ) : <Empty title="No chain stages" />}
              {d.graph_chain.length > 0 && <ol className="small">{d.graph_chain.map((c: string, i: number) => <li key={i}>{c}</li>)}</ol>}
            </Card>
            <Card title="MITRE ATT&CK">{d.mitre_techniques.length ? <div className="tags">{d.mitre_techniques.map((t: string) => <Badge key={t}>{t}</Badge>)}</div> : <Empty title="No techniques" />}</Card>
            <Card title="RAG sources">{d.rag_sources.length ? <ul>{d.rag_sources.map((t: string) => <li key={t}>{t}</li>)}</ul> : <Empty title="No RAG context used" />}</Card>
            <Card title="ML features">
              {d.ml ? (
                <>
                  <KV rows={[["Anomaly score", fmtNum(d.ml.anomaly_score, 3)], ["Classification", `${d.ml.classification} (${pct(d.ml.classification_confidence)})`], ["Model / features", `${d.ml.model_version} / ${d.ml.feature_version}`]]} />
                  <Table rows={d.ml.top_features.map((f: [string, number]) => ({ feature: f[0], weight: f[1] }))} empty="No feature attribution" columns={[{ key: "feature", label: "Feature" }, { key: "weight", label: "Weight", render: (r) => fmtNum(r.weight as number, 3) }]} />
                </>
              ) : <Empty title="No ML result" hint="ML runs only when the behavior engine marks the event eligible." />}
            </Card>
            <Card title="AI explanation">{d.ai_explanation ? <p>{d.ai_explanation}</p> : <Empty title="No explanation available" />}</Card>
            <Card title="Recommended vs. actual action">
              <KV rows={[["Recommended (advisory)", d.recommended_action ?? "-"]]} />
              <Table rows={d.actions_taken} empty="No action taken" columns={[{ key: "action", label: "Action taken" }, { key: "status", label: "Status" }, { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) }]} />
            </Card>
          </div>
          <Card title="Timeline">
            <ul className="timeline">{d.timeline.map((t: Rec, i: number) => <li key={i} className={`k-${t.kind}`}><span className="muted small">{fmtTime(t.ts)}</span> &nbsp;{t.text}</li>)}</ul>
          </Card>
        </>
      )}
    </Async>
  );
}

function List() {
  const router = useRouter();
  const s = useApi<Rec>("/api/ai/analyses?limit=100", 20000);
  return (
    <Card title="AI analyses" right={s.data && <BackendBadge b={s.data.backend} />}>
      <Async state={s}>
        {(d) => (
          <Table
            rows={d.items}
            empty="No AI analyses yet"
            hint="The AI analyst runs only on gated events. Without a model the engine continues deterministically."
            onRow={(r) => r.finding_id && router.push(`/ai-analyst/?id=${encodeURIComponent(r.finding_id as string)}`)}
            columns={[
              { key: "verdict", label: "Verdict", render: (r) => (r.available ? String(r.verdict ?? "-") : <Badge>unavailable</Badge>) },
              { key: "severity", label: "Severity", render: (r) => <Severity value={r.severity as string} /> },
              { key: "confidence", label: "Conf.", render: (r) => (r.confidence == null ? "-" : pct(r.confidence as number)) },
              { key: "threat_type", label: "Threat" },
              { key: "recommended_action", label: "Recommended" },
              { key: "model_name", label: "Model", render: (r) => <>{String(r.model_name)} {r.is_mock ? <Badge tone="warn">mock</Badge> : null}</> },
              { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
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

export default function AIAnalyst() {
  return (
    <>
      <PageHeader title="AI Analyst" subtitle="Verdict, evidence and reasoning for each finding" />
      <Suspense fallback={<Loading />}><Inner /></Suspense>
    </>
  );
}
