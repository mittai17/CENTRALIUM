"use client";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { api, Rec } from "@/lib/api";
import { useAuth } from "@/components/AuthProvider";
import { Async, Badge, Card, KV, PageHeader, Table } from "@/components/ui";
import { fmtTime } from "@/lib/format";

function AddEntry({ kinds, onDone }: { kinds: string[]; onDone: () => void }) {
  const [which, setWhich] = useState("blocklist");
  const [kind, setKind] = useState(kinds[0] ?? "sha256");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try { await api(`/api/lists/${which}`, { method: "POST", json: { kind, value, reason } }); setMsg("Added."); setValue(""); onDone(); }
    catch (err) { setMsg(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <form className="row" onSubmit={submit}>
      <div><label htmlFor="w">List</label><select id="w" value={which} onChange={(e) => setWhich(e.target.value)}><option>blocklist</option><option>allowlist</option></select></div>
      <div><label htmlFor="k">Kind</label><select id="k" value={kind} onChange={(e) => setKind(e.target.value)}>{kinds.map((k) => <option key={k}>{k}</option>)}</select></div>
      <div><label htmlFor="v">Value</label><input id="v" value={value} onChange={(e) => setValue(e.target.value)} required maxLength={1000} /></div>
      <div><label htmlFor="r">Reason</label><input id="r" value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={300} /></div>
      <button className="btn btn-primary">Add entry</button>
      {msg && <span role="status" className="small">{msg}</span>}
    </form>
  );
}

export default function Policies() {
  const { can } = useAuth();
  const s = useApi<Rec>("/api/policies");
  const cols = [{ key: "kind", label: "Kind" }, { key: "value", label: "Value", className: "mono" }, { key: "reason", label: "Reason" }, { key: "added_by", label: "Added by" }, { key: "added_at", label: "Added", render: (r: Rec) => fmtTime(r.added_at) }];
  return (
    <>
      <PageHeader title="Policies" subtitle="Effective response policy, stored policies, allowlist and blocklist" />
      <Async state={s}>
        {(d) => (
          <>
            <Card title="Effective response policy">
              <KV rows={[
                ["Require approval for destructive actions", <Badge key="a" tone={d.effective.require_approval ? "ok" : "warn"}>{String(d.effective.require_approval)}</Badge>],
                ["Min. confidence (destructive)", d.effective.min_confidence_destructive],
                ["Min. risk (destructive)", d.effective.min_risk_destructive],
                ["Destructive in PASSIVE mode", String(d.effective.passive_destructive_allowed)],
                ["Allowed actions", d.effective.allowed_actions.join(", ")],
                ["Protected processes", d.effective.protected_processes.join(", ")],
              ]} />
            </Card>
            <div style={{ height: 14 }} />
            <Card title="Stored policies"><Table rows={d.stored} empty="No stored policies" columns={[{ key: "name", label: "Name" }, { key: "version", label: "Version" }, { key: "enabled", label: "Enabled", render: (r) => (r.enabled ? "yes" : "no") }, { key: "updated_at", label: "Updated", render: (r) => fmtTime(r.updated_at as string) }]} /></Card>
            {can("admin") && <><div style={{ height: 14 }} /><Card title="Add allowlist / blocklist entry"><AddEntry kinds={d.list_kinds} onDone={s.reload} /></Card></>}
            <div className="grid g2" style={{ marginTop: 14 }}>
              <Card title="Allowlist"><Table rows={d.allowlist} empty="Allowlist is empty" columns={cols} /></Card>
              <Card title="Blocklist"><Table rows={d.blocklist} empty="Blocklist is empty" columns={cols} /></Card>
            </div>
          </>
        )}
      </Async>
    </>
  );
}
