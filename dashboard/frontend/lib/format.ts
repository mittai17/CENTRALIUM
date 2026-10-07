export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function fmtTime(ts?: string | null): string {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function fmtNum(n?: number | null, digits = 1): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "-";
  return Number.isInteger(n) ? String(n) : n.toFixed(digits);
}

export function pct(n?: number | null): string {
  if (n === null || n === undefined) return "-";
  return `${(n * 100).toFixed(1)}%`;
}

export function severityClass(s?: string | null): string {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL":
      return "sev-critical";
    case "HIGH":
      return "sev-high";
    case "MEDIUM":
      return "sev-medium";
    case "LOW":
      return "sev-low";
    default:
      return "sev-info";
  }
}
