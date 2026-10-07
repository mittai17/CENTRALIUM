"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { api, Rec } from "@/lib/api";
import { useAuth } from "@/components/AuthProvider";
import { Async, Badge, Card, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";

const ACTIONS = ["ALERT", "BLOCK_CONNECTION", "SUSPEND_PROCESS", "TERMINATE_PROCESS", "QUARANTINE_FILE", "ISOLATE_ENDPOINT"];

function RequestForm({ onDone }: { onDone: () => void }) {
  const [action, setAction] = useState("ALERT");
  const [t, setT] = useState<Record<string, string>>({});
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const set = (k: string, v: string) => setT({ ...t, [k]: v });
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    let target: Rec = {};
    if (action.endsWith("_PROCESS")) target = { pid: Number(t.pid) };
    else if (action === "QUARANTINE_FILE") target = { path: t.path };
    else if (action === "BLOCK_CONNECTION") target = { ip: t.ip, port: Number(t.port) };
    else if (action === "ISOLATE_ENDPOINT") target = { host_id: t.host_id };
    else if (t.message) target = { message: t.message };
    try {
      const r = await api("/api/response/requests", { method: "POST", json: { action, target, reason } });
      setMsg({ ok: true, text: `Queued for approval (${r.action_id}). Nothing was executed.` });
      onDone();
    } catch (err) { setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed" }); }
  }
  const field = (k: string, label: string, type = "text") => (<div><label htmlFor={`t-${k}`}>{label}</label><input id={`t-${k}`} type={type} value={t[k] ?? ""} onChange={(e) => set(k, e.target.value)} required /></div>);
  return (
    <form onSubmit={submit}>
      <div className="row">
        <div><label htmlFor="act">Action</label><select id="act" value={action} onChange={(e) => { setAction(e.target.value); setT({}); }}>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</select></div>
        {action.endsWith("_PROCESS") && field("pid", "PID", "number")}
        {action === "QUARANTINE_FILE" && field("path", "Absolute file path")}
        {action === "BLOCK_CONNECTION" && <>{field("ip", "IP address")}{field("port", "Port", "number")}</>}
        {action === "ISOLATE_ENDPOINT" && field("host_id", "Host ID")}
        <div style={{ flex: 1, minWidth: 220 }}><label htmlFor="rsn">Reason</label><input id="rsn" style={{ width: "100%" }} value={reason} minLength={3} maxLength={500} onChange={(e) => setReason(e.target.value)} required /></div>
        <button className="btn btn-primary">Request approval</button>
      </div>
      {msg && <p role="status" className={msg.ok ? "ok-text" : "error-text"}>{msg.text}</p>}
    </form>
  );
}

export default function Response() {
  const { can } = useAuth();
  const s = useApi<Rec>("/api/response/actions?limit=200", 15000);
  const [err, setErr] = useState<string | null>(null);
  async function decide(id: string, decision: "approve" | "deny") {
    setErr(null);
    try { await api(`/api/response/actions/${id}/decision`, { method: "POST", json: { decision } }); s.reload(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <>
      <PageHeader title="Response Center" subtitle="Requested and recorded response actions. The dashboard never executes actions: requests wait for approval and are carried out by the agent under policy." />
      <Async state={s}>
        {(d) => (
          <>
            <div className="tags" style={{ marginBottom: 14 }}>
              <Badge tone={d.pending_approval ? "warn" : ""}>{`${d.pending_approval} pending approval`}</Badge>
              <Badge>{`Mode ${d.mode}`}</Badge>
              <Badge tone={d.destructive_allowed ? "" : "ok"}>{d.destructive_allowed ? "Destructive actions permitted by mode" : "Destructive actions disabled"}</Badge>
            </div>
            {can("analyst") && <Card title="Request an action"><RequestForm onDone={s.reload} /></Card>}
            <div style={{ height: 14 }} />
            {err && <p role="alert" className="error-text">{err}</p>}
            <Card title="Actions">
              <Table rows={d.items} empty="No response actions" columns={[
                { key: "timestamp", label: "Time", render: (r) => fmtTime(r.timestamp as string) },
                { key: "action", label: "Action" },
                { key: "status", label: "Status", render: (r) => <Badge tone={r.status === "pending_approval" ? "warn" : r.status === "executed" ? "ok" : ""}>{String(r.status)}</Badge> },
                { key: "target", label: "Target", render: (r) => <span className="mono">{JSON.stringify(r.target)}</span> },
                { key: "detail", label: "Detail" },
                { key: "x", label: "", render: (r) => (can("admin") && r.status === "pending_approval" ? (
                  <span className="row"><button className="btn btn-primary" onClick={() => decide(r.action_id as string, "approve")}>Approve</button><button className="btn" onClick={() => decide(r.action_id as string, "deny")}>Deny</button></span>) : null) },
              ]} />
            </Card>
            <p className="muted small">{d.note}</p>
          </>
        )}
      </Async>
    </>
  );
}
