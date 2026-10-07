"use client";
import { useApi } from "@/lib/useApi";
import { Async, Bars, Card, HBars, KV, PageHeader, Stat } from "@/components/ui";
import { fmtNum, pct } from "@/lib/format";
import type { Rec } from "@/lib/api";

function NotValidated({ reasons }: { reasons?: string[] }) {
  return (
    <div className="not-validated" role="status">
      <strong>Not enough validated data</strong>
      <p className="muted">Precision, recall, F1, ROC-AUC, false-positive rate and the confusion matrix are shown only from a validated evaluation report under <code>ml/</code>. None is available, so no numbers are displayed.</p>
      {reasons && reasons.length > 0 && <ul className="small muted">{reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
    </div>
  );
}

export default function MLAnalytics() {
  const s = useApi<Rec>("/api/ml", 30000);
  return (
    <>
      <PageHeader title="ML Analytics" subtitle="Runtime ML statistics (measured) and validated evaluation metrics (from reports)" />
      <Async state={s}>
        {(d) => {
          const rt = d.runtime, ev = d.evaluation;
          return (
            <>
              <h2 style={{ margin: "0 0 10px" }}>Evaluation (validated report)</h2>
              {ev.available ? (
                <>
                  <div className="grid g4">
                    {(["precision", "recall", "f1", "roc_auc", "false_positive_rate", "detection_rate"] as const).filter((k) => ev.metrics[k] !== undefined).map((k) => <Stat key={k} label={k.replace(/_/g, " ")} value={pct(ev.metrics[k])} />)}
                    {ev.metrics.inference_latency_ms !== undefined && <Stat label="Inference latency (ms)" value={fmtNum(ev.metrics.inference_latency_ms, 2)} />}
                    {ev.metrics.throughput_eps !== undefined && <Stat label="Throughput (events/s)" value={fmtNum(ev.metrics.throughput_eps, 0)} />}
                  </div>
                  <Card title="Report"><KV rows={[["File", ev.report_file], ["Model version", ev.model_version], ["Feature version", ev.feature_version], ["Dataset version", ev.dataset_version], ["Samples", ev.n_samples]]} /></Card>
                  {ev.confusion_matrix && (
                    <Card title="Confusion matrix">
                      <table><thead><tr><th>actual / predicted</th>{ev.confusion_matrix.labels.map((l: string) => <th key={l}>{l}</th>)}</tr></thead>
                        <tbody>{ev.confusion_matrix.matrix.map((row: number[], i: number) => <tr key={i}><th scope="row">{ev.confusion_matrix.labels[i]}</th>{row.map((v, j) => <td key={j}>{v}</td>)}</tr>)}</tbody></table>
                    </Card>
                  )}
                  {ev.score_histogram && <Card title="Score histogram (evaluation set)"><Bars ariaLabel="Evaluation score histogram" items={ev.score_histogram.counts.map((c: number, i: number) => ({ label: String(ev.score_histogram.bins?.[i] ?? i), value: c }))} /></Card>}
                </>
              ) : <NotValidated reasons={ev.reasons} />}
              <h2 style={{ margin: "22px 0 10px" }}>Runtime statistics (measured from stored results)</h2>
              {rt.results === 0 ? <Card><p className="muted">No ML results recorded yet. The ML engine returns nothing without a trained model; no scores are fabricated.</p></Card> : (
                <>
                  <div className="grid g4">
                    <Stat label="Results" value={rt.results} />
                    <Stat label="Model version" value={rt.model_version ?? "-"} />
                    <Stat label="Feature version" value={rt.feature_version ?? "-"} />
                    <Stat label="Avg latency (ms)" value={fmtNum(rt.latency_ms?.avg, 2)} hint={`max ${fmtNum(rt.latency_ms?.max, 2)}`} />
                  </div>
                  <div className="grid g2">
                    <Card title="Anomaly score distribution"><Bars ariaLabel="Anomaly score histogram" items={rt.anomaly_histogram.bins.map((b: string, i: number) => ({ label: b, value: rt.anomaly_histogram.counts[i] }))} /></Card>
                    <Card title="Classification distribution"><HBars items={rt.classification_distribution.map((r: Rec) => ({ label: r.classification, value: r.n }))} /></Card>
                  </div>
                  <Card title="Top features (mean absolute importance)"><HBars color="#b71c1c" items={rt.top_features.map((f: Rec) => ({ label: f.feature, value: Number(f.mean_abs_importance.toFixed(3)) }))} /></Card>
                </>
              )}
              <p className="muted small">AI backend: {d.ai.kind}. {d.note}</p>
            </>
          );
        }}
      </Async>
    </>
  );
}
