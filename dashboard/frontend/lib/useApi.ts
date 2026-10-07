"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, Rec } from "./api";
import { useAuth } from "@/components/AuthProvider";

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useApi<T = Rec>(path: string | null, refreshMs = 0): ApiState<T> {
  const { logout } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);

  useEffect(() => {
    if (path === null) return;
    const mine = ++seq.current;
    setLoading(true);
    api<T>(path)
      .then((d) => {
        if (mine !== seq.current) return;
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (mine !== seq.current) return;
        if (e instanceof ApiError && e.status === 401) logout();
        setError(e instanceof Error ? e.message : "Unknown error");
      })
      .finally(() => {
        if (mine === seq.current) setLoading(false);
      });
  }, [path, tick, logout]);

  useEffect(() => {
    if (!refreshMs) return;
    const id = setInterval(() => setTick((t) => t + 1), refreshMs);
    return () => clearInterval(id);
  }, [refreshMs]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}
