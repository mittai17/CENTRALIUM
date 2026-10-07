"use client";
import type { ReactNode } from "react";
import { severityClass } from "@/lib/format";
import type { ApiState } from "@/lib/useApi";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Card({ title, children, className = "", right }: { title?: string; children: ReactNode; className?: string; right?: ReactNode }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone, hint }: { label: string; value: ReactNode; tone?: "critical" | "ok"; hint?: string }) {
  return (
    <div className={`card stat ${tone === "critical" ? "stat-critical" : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  );
}

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone ?? ""}`}>{children}</span>;
}
export function Severity({ value }: { value?: string | null }) {
  if (!value) return <span className="muted">-</span>;
  return <span className={`badge ${severityClass(value)}`}>{value}</span>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" /> {label}...
    </div>
  );
}
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <strong>Could not load data.</strong> {message}
      {onRetry && (
        <button className="btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="state empty">
      <strong>{title}</strong>
      {hint && <div className="muted">{hint}</div>}
    </div>
  );
}

/** Render loading / error / data for an ApiState. */
export function Async<T>({ state, children }: { state: ApiState<T>; children: (d: T) => ReactNode }) {
  if (state.error && !state.data) return <ErrorState message={state.error} onRetry={state.reload} />;
  if (!state.data) return <Loading />;
  return <>{children(state.data)}</>;
}

export interface Column<R> {
  key: string;
  label: string;
  render?: (row: R) => ReactNode;
  className?: string;
}
export function Table<R extends Record<string, unknown>>({
  columns,
  rows,
  empty = "No records",
  hint,
  onRow,
  caption,
}: {
  columns: Column<R>[];
  rows: R[];
  empty?: string;
  hint?: string;
  onRow?: (r: R) => void;
  caption?: string;
}) {
  if (!rows.length) return <Empty title={empty} hint={hint} />;
  return (
    <div className="table-wrap">
      <table>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr
              key={i}
              className={onRow ? "clickable" : ""}
              tabIndex={onRow ? 0 : undefined}
              onClick={onRow ? () => onRow(r) : undefined}
              onKeyDown={onRow ? (e) => e.key === "Enter" && onRow(r) : undefined}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.className}>
                  {c.render ? c.render(r) : String(r[c.key] ?? "-")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Bars({
  items,
  color = "var(--slate)",
  colors,
  height = 120,
  ariaLabel,
}: {
  items: { label: string; value: number }[];
  color?: string;
  colors?: Record<string, string>;
  height?: number;
  ariaLabel: string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length || items.every((i) => i.value === 0)) return <Empty title="No data yet" />;
  return (
    <div role="img" aria-label={ariaLabel}>
      <div className="vbars" style={{ height }}>
        {items.map((i) => (
          <div key={i.label} className="vbar-col" title={`${i.label}: ${i.value}`}>
            <span className="vbar-val">{i.value}</span>
            <div className="vbar" style={{ height: `${(i.value / max) * 100}%`, background: colors?.[i.label] ?? color }} />
          </div>
        ))}
      </div>
      <div className="vbars-labels">
        {items.map((i) => (
          <span key={i.label}>{i.label}</span>
        ))}
      </div>
    </div>
  );
}

export function HBars({ items, color = "var(--slate)" }: { items: { label: string; value: number }[]; color?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <Empty title="No data yet" />;
  return (
    <ul className="hbars">
      {items.map((i) => (
        <li key={i.label}>
          <span className="hbar-label" title={i.label}>
            {i.label}
          </span>
          <span className="hbar-track">
            <span className="hbar-fill" style={{ width: `${(i.value / max) * 100}%`, background: color }} />
          </span>
          <span className="hbar-val">{i.value}</span>
        </li>
      ))}
    </ul>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v ?? "-"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Json({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}
