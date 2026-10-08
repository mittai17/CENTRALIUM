"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useAuth } from "./AuthProvider";
import { useApi } from "@/lib/useApi";
import { Loading } from "./ui";

export const NAV: { href: string; label: string }[] = [
  { href: "/", label: "Overview" },
  { href: "/system-monitor/", label: "System Monitor" },
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
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    fetch("/api/quick-auth")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!active || !data) return;
        if (data.tokens) {
          setTokens(data.tokens);
        }
        if (data.default_token) {
          setTok(data.default_token);
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  async function submit(e?: FormEvent, tokenToUse?: string) {
    if (e) e.preventDefault();
    const targetToken = (tokenToUse ?? token).trim();
    if (!targetToken) return;
    setBusy(true);
    setErr(await login(targetToken));
    setBusy(false);
  }

  async function handleRoleSelect(role: string) {
    const roleToken = tokens[role] || (role === "admin" ? token : "");
    if (!roleToken) return;
    setTok(roleToken);
    await submit(undefined, roleToken);
  }

  return (
    <main className="login">
      <form onSubmit={(e) => submit(e)} className="card login-card">
        <div className="brand brand-dark">CENTRALIUM</div>
        <h1>Sign in</h1>
        <p className="muted">
          Access token is pre-filled for local access. Click &apos;Get Started&apos; to enter the SOC dashboard.
        </p>

        <div style={{ margin: "10px 0 6px" }}>
          <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--muted)", marginBottom: "6px" }}>
            Quick select role:
          </div>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            <button
              type="button"
              className="btn"
              style={{
                fontSize: "12px",
                padding: "4px 10px",
                borderColor: "var(--red, #cf222e)",
                color: "var(--red, #cf222e)",
                fontWeight: 600,
                background: "#fff",
              }}
              onClick={() => handleRoleSelect("admin")}
              disabled={busy}
              title="Sign in with Admin privileges"
            >
              ★ Get Started as Admin
            </button>
            <button
              type="button"
              className="btn"
              style={{ fontSize: "12px", padding: "4px 10px" }}
              onClick={() => handleRoleSelect("analyst")}
              disabled={busy}
              title="Sign in with Analyst privileges"
            >
              Analyst
            </button>
            <button
              type="button"
              className="btn"
              style={{ fontSize: "12px", padding: "4px 10px" }}
              onClick={() => handleRoleSelect("viewer")}
              disabled={busy}
              title="Sign in with Viewer privileges"
            >
              Viewer
            </button>
          </div>
        </div>

        <label htmlFor="tok">Access token</label>
        <input
          id="tok"
          type="text"
          autoComplete="off"
          value={token}
          onChange={(e) => setTok(e.target.value)}
          placeholder="Pre-filling token..."
          style={{ fontFamily: "monospace", fontSize: "12px", padding: "8px 10px" }}
          required
        />
        {token && (
          <div className="muted small" style={{ fontSize: "11px", marginTop: "2px" }}>
            Active token loaded ({token.length} chars)
          </div>
        )}
        {err && (
          <p role="alert" className="error-text">
            {err}
          </p>
        )}
        <button
          type="submit"
          className="btn btn-primary"
          style={{ padding: "10px 16px", fontSize: "15px", fontWeight: 600, marginTop: "14px" }}
          disabled={busy || !token}
        >
          {busy ? "Starting..." : "Get Started"}
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
