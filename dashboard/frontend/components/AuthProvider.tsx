"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "@/lib/api";

interface AuthState {
  role: string | null;
  ready: boolean;
  login: (token: string) => Promise<string | null>;
  logout: () => void;
  can: (min: "viewer" | "analyst" | "admin") => boolean;
}
const RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 };
const Ctx = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const c = useContext(Ctx);
  if (!c) throw new Error("AuthProvider missing");
  return c;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) {
      setReady(true);
      return;
    }
    api<{ role: string }>("/api/whoami")
      .then((r) => setRole(r.role))
      .catch(() => setToken(null))
      .finally(() => setReady(true));
  }, []);

  const login = useCallback(async (token: string) => {
    setToken(token.trim());
    try {
      const r = await api<{ role: string }>("/api/whoami");
      setRole(r.role);
      return null;
    } catch (e) {
      setToken(null);
      return e instanceof Error ? e.message : "Login failed";
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setRole(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({ role, ready, login, logout, can: (min) => (role ? (RANK[role] ?? 0) >= RANK[min] : false) }),
    [role, ready, login, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
