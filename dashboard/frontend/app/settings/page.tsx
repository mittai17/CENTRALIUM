"use client";
import { useApi } from "@/lib/useApi";
import { useAuth } from "@/components/AuthProvider";
import { Async, Badge, Card, Empty, KV, PageHeader } from "@/components/ui";
import type { Rec } from "@/lib/api";

export default function Settings() {
  const { can, role } = useAuth();
  const s = useApi<Rec>(can("analyst") ? "/api/settings" : null);
  if (!can("analyst")) return <><PageHeader title="Settings" /><Empty title="Analyst role required" hint={`Signed in as ${role}.`} /></>;
  return (
    <>
      <PageHeader title="Settings" subtitle="Read-only view of the agent configuration. Mode and policy are changed through the agent." />
      <Async state={s}>
        {(d) => (
          <div className="grid g2">
            <Card title="Runtime">
              <KV rows={[["Host", d.host_id], ["Operating mode", <Badge key="m">{d.mode}</Badge>], ["Resource profile", d.profile], ["Demo mode", String(d.demo_mode)], ["Test mode", String(d.test_mode)], ["Offline", String(d.offline)], ["Cloud sync", String(d.sync_enabled)], ["Destructive actions allowed", String(d.destructive_allowed)]]} />
            </Card>
            <Card title="Local LLM">
              <KV rows={[["Enabled", String(d.llm.enabled)], ["Model", d.llm.model_name], ["Model file present", String(d.llm.model_file_present)], ["Gate (min pre-risk)", d.llm.gate_min_pre_risk], ["Context", d.llm.max_ctx]]} />
              {!d.llm.model_file_present && <p className="muted small">No model file is configured; AI analysis is unavailable (or a mock is in use).</p>}
            </Card>
            <Card title="Risk model">
              <KV rows={[...Object.entries(d.risk.weights).map(([k, v]) => [`Weight: ${k}`, String(v)] as [string, string]), ...Object.entries(d.risk.bands).map(([k, v]) => [`Band ${k} from`, String(v)] as [string, string]), ["Known-malicious floor", d.risk.known_malicious_floor]]} />
            </Card>
            <Card title="Response policy">
              <KV rows={[["Require approval", String(d.policy.require_approval)], ["Min confidence", d.policy.min_confidence_destructive], ["Min risk", d.policy.min_risk_destructive], ["Allowed actions", d.policy.allowed_actions.join(", ")]]} />
            </Card>
            <Card title="Session">
              <KV rows={[["Role", role], ["Token storage", "sessionStorage (cleared when the tab closes)"]]} />
            </Card>
          </div>
        )}
      </Async>
    </>
  );
}
