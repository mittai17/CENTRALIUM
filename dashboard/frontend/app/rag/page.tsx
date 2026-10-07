"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { Async, Card, HBars, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";
import type { Rec } from "@/lib/api";

export default function Rag() {
  const [q, setQ] = useState("");
  const [qd, setQd] = useState("");
  const s = useApi<Rec>(`/api/rag?limit=200${qd ? `&q=${encodeURIComponent(qd)}` : ""}`);
  return (
    <>
      <PageHeader title="RAG Knowledge" subtitle="Local knowledge base used to ground AI analysis (metadata only; document text is not exposed)" />
      <Card>
        <form className="row" role="search" onSubmit={(e) => { e.preventDefault(); setQd(q); }}>
          <div><label htmlFor="rq">Search title or document ID</label><input id="rq" value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} /></div>
          <button className="btn btn-primary">Search</button>
        </form>
      </Card>
      <div style={{ height: 14 }} />
      <Async state={s}>
        {(d) => (
          <>
            <div className="grid g2">
              <Card title={`Documents by source (${d.total} total)`}><HBars items={d.by_source.map((r: Rec) => ({ label: r.source, value: r.n }))} /></Card>
              <Card title="Most cited in AI analyses"><HBars items={d.most_cited.map((r: Rec) => ({ label: r.source, value: r.count }))} color="#b71c1c" /></Card>
            </div>
            <Card title="Documents"><Table rows={d.documents} empty="No knowledge documents ingested" hint="Run RAG ingestion on the agent to populate the knowledge base." columns={[
              { key: "doc_id", label: "ID", className: "mono" }, { key: "source", label: "Source" }, { key: "title", label: "Title" }, { key: "embedding_model", label: "Embedding" }, { key: "ingested_at", label: "Ingested", render: (r) => fmtTime(r.ingested_at as string) },
            ]} /></Card>
          </>
        )}
      </Async>
    </>
  );
}
