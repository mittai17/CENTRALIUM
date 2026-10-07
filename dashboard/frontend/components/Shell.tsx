"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type FormEvent, type ReactNode } from "react";
import { useAuth } from "./AuthProvider";
import { useApi } from "@/lib/useApi";
import { Loading } from "./ui";

export const NAV: { href: string; label: string }[] = [
  { href: "/", label: "Overview" },
  { href: "/threats/", label: "Threats" },
  { href: "/incidents/", label: "Incidents" },
  { href: "/attack-graph/", label: "Attack Graph" },
  { href: "/processes/", label: "Process Explorer" },
  { href: "/network/", label: "Network Activity" },
  { href: "/malware/", label: "Malware Analysis" },
  { href: "/hunting/", label: "Threat Hunting" },
  { href: "/ai-analyst/", label: "AI Analyst" },
  { href: "/mitre/", label: "MITRE ATT&CK" },
  { href: "/response/", label: "Response Center" },
  { href: "/policies/", label: "Policies" },
  { href: "/rag/", label: "RAG Knowledge" },
  { href: "/ml/", label: "ML Analytics" },
  { href: "/audit/", label: "Audit Logs" },
  { href: "/endpoints/", label: "Endpoints" },
  { href: "/settings/", label: "Settings" },
];

function Login() {
  const { login } = useAuth();
  const [token, setTok] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(await login(token));
    setBusy(false);
  }
  return (
    <main className="login">
      <form onSubmit={submit} className="card login-card">
        <div className="brand brand-dark">CENTRALIUM</div>
        <h1>Sign in</h1>
        <p className="muted">Enter a dashboard access token (viewer, analyst or admin). Tokens are printed once on first start.</p>
        <label htmlFor="tok">Access token</label>
        <input id="tok" type="password" autoComplete="off" value={token} onChange={(e) => setTok(e.target.value)} required />
        {err && (
          <p role="alert" className="error-text">
            {err}
          </p>
        )}
        <button className="btn btn-primary" disabled={busy || !token}>
          {busy ? "Checking..." : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function StatusBar() {
  const { role, logout } = useAuth();
  const s = useApi<Record<string, any>>("/api/status", 30000); // eslint-disable-line @typescript-eslint/no-explicit-any
  const d = s.data;
  const aiKind: string = d?.ai?.kind ?? "unknown";
  const aiLabel = aiKind === "gemma" ? "AI: Gemma (real)" : aiKind === "mock" ? "AI: MOCK (not a real model)" : aiKind === "unavailable" ? "AI: unavailable" : `AI: ${aiKind}`;
  return (
    <>
      {d?.demo_mode && (
        <div className="banner banner-demo" role="status">
          DEMO MODE - destructive response is disabled; data may be synthetic.
        </div>
      )}
      {d?.test_mode && (
        <div className="banner banner-demo" role="status">
          TEST MODE - OS actions are simulated.
        </div>
      )}
      <div className="statusbar">
        <span className="chip" title="Operating mode">
          Mode: <strong>{d?.mode ?? "..."}</strong>
        </span>
        <span className={`chip ${aiKind === "gemma" ? "chip-ok" : aiKind === "mock" ? "chip-warn" : ""}`}>{aiLabel}</span>
        {d?.offline && <span className="chip">Offline</span>}
        <span className="chip">Host: {d?.host_id ?? "..."}</span>
        <span className="spacer" />
        <span className="muted small">Role: {role}</span>
        <button className="btn btn-quiet" onClick={logout}>
          Sign out
        </button>
      </div>
    </>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { role, ready } = useAuth();
  const path = usePathname() ?? "/";
  const [open, setOpen] = useState(false);
  if (!ready)
    return (
      <div className="login">
        <Loading />
      </div>
    );
  if (!role) return <Login />;
  const norm = (p: string) => (p.endsWith("/") ? p : p + "/");
  return (
    <div className="shell">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside id="primary-nav" className={`sidebar ${open ? "open" : ""}`} aria-label="Primary">
        <div className="brand">CENTRALIUM</div>
        <div className="brand-sub">Endpoint Detection &amp; Response</div>
        <nav>
          <ul>
            {NAV.map((n) => {
              const active = norm(path) === norm(n.href);
              return (
                <li key={n.href}>
                  <Link href={n.href} aria-current={active ? "page" : undefined} className={active ? "active" : ""} onClick={() => setOpen(false)}>
                    {n.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
      </aside>
      <div className="main-col">
        <button className="menu-btn" aria-expanded={open} aria-controls="primary-nav" onClick={() => setOpen((o) => !o)}>
          Menu
        </button>
        <StatusBar />
        <main id="main" className="main">
          {children}
        </main>
      </div>
    </div>
  );
}
