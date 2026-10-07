// Thin, typed-enough API client. The token lives in sessionStorage only (cleared on tab close).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Rec = Record<string, any>;

const KEY = "centralium.token";
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}
export function setToken(t: string | null): void {
  try {
    if (t) sessionStorage.setItem(KEY, t);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: session-only in memory is not supported, user re-enters token */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as Rec).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((e: Rec) => `${(e.loc ?? []).slice(1).join(".")}: ${e.msg}`).join("; ");
  }
  return fallback;
}

export async function api<T = Rec>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers, body });
  } catch {
    throw new ApiError(0, "Cannot reach the Centralium dashboard API");
  }
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) throw new ApiError(res.status, detailMessage(parsed, `Request failed (${res.status})`));
  return parsed as T;
}
