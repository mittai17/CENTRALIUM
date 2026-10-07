"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { api, Rec } from "@/lib/api";
import { useAuth } from "@/components/AuthProvider";
import { Async, Card, Empty, ErrorState, PageHeader, Table } from "@/components/ui";

interface Filter { field: string; op: string; value: string }

export default function Hunting() {
  const { can } = useAuth();
  const schema = useApi<Rec>(can("analyst") ? "/api/hunt/schema" : null);
  const [source, setSource] = useState("events");
  const [filters, setFilters] = useState<Filter[]>([]);
  const [countBy, setCountBy] = useState("");
  const [result, setResult] = useState<Rec | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!can("analyst")) return <><PageHeader title="Threat Hunting" /><Empty title="Analyst role required" hint="Sign in with an analyst or admin token to run hunts." /></>;

  async function run() {
    const sc: Rec = schema.data?.[source] ?? {};
    const body = {
      source,
      filters: filters.filter((f) => f.field && f.value !== "").map((f) => {
        const t: string = sc.fields[f.field];
        let value: string | number | (string | number)[] = f.value;
        const conv = (v: string) => (t === "text" ? v : Number(v));
        value = f.op === "in" ? f.value.split(",").map((x) => conv(x.trim())) : conv(f.value);
        return { field: f.field, op: f.op, value };
      }),
      count_by: countBy || undefined,
      limit: 200,
    };
    setBusy(true); setErr(null);
    try { setResult(await api("/api/hunt", { method: "POST", json: body })); }
    catch (e) { setResult(null); setErr(e instanceof Error ? e.message : "Hunt failed"); }
    finally { setBusy(false); }
  }

  return (
    <>
      <PageHeader title="Threat Hunting" subtitle="Structured, parameterized queries over whitelisted fields. Raw SQL is not accepted." />
      <Async state={schema}>
        {(sch) => {
          const fields: Record<string, string> = sch[source]?.fields ?? {};
          const opsFor = (field: string) => sch[source].ops[fields[field]] ?? [];
          return (
            <Card title="Query builder">
              <div className="row">
                <div>
                  <label htmlFor="src">Source</label>
                  <select id="src" value={source} onChange={(e) => { setSource(e.target.value); setFilters([]); setCountBy(""); setResult(null); }}>
                    {Object.keys(sch).map((s) => <option key={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label htmlFor="cb">Group by (count)</label>
                  <select id="cb" value={countBy} onChange={(e) => setCountBy(e.target.value)}>
                    <option value="">None</option>
                    {Object.keys(fields).map((f) => <option key={f}>{f}</option>)}
                  </select>
                </div>
              </div>
              {filters.map((f, i) => (
                <div className="row" key={i}>
                  <div>
                    <label htmlFor={`f${i}`}>Field</label>
                    <select id={`f${i}`} value={f.field} onChange={(e) => setFilters(filters.map((x, j) => (j === i ? { field: e.target.value, op: sch[source].ops[fields[e.target.value]][0], value: "" } : x)))}>
                      {Object.keys(fields).map((n) => <option key={n}>{n}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor={`o${i}`}>Operator</label>
                    <select id={`o${i}`} value={f.op} onChange={(e) => setFilters(filters.map((x, j) => (j === i ? { ...x, op: e.target.value } : x)))}>
                      {opsFor(f.field).map((o: string) => <option key={o}>{o}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor={`v${i}`}>Value{f.op === "in" ? " (comma separated)" : ""}</label>
                    <input id={`v${i}`} value={f.value} maxLength={500} onChange={(e) => setFilters(filters.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
                  </div>
                  <button className="btn" onClick={() => setFilters(filters.filter((_, j) => j !== i))}>Remove</button>
                </div>
              ))}
              <div className="row" style={{ marginTop: 12 }}>
                <button className="btn" disabled={filters.length >= 10} onClick={() => { const first = Object.keys(fields)[0]; setFilters([...filters, { field: first, op: sch[source].ops[fields[first]][0], value: "" }]); }}>Add filter</button>
                <button className="btn btn-primary" onClick={run} disabled={busy}>{busy ? "Running..." : "Run hunt"}</button>
              </div>
            </Card>
          );
        }}
      </Async>
      <div style={{ height: 14 }} />
      {err && <ErrorState message={err} />}
      {result && (
        <Card title={`Results (${result.total} total${result.grouped_by ? `, grouped by ${result.grouped_by}` : ""})`}>
          <Table
            rows={result.items}
            empty="No matching records"
            columns={result.items[0] ? Object.keys(result.items[0]).filter((k) => result.items.some((r: Rec) => r[k] !== null)).map((k) => ({ key: k, label: k })) : []}
          />
        </Card>
      )}
    </>
  );
}
