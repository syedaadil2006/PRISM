/**
 * Shared investigation state.
 *
 * Polls while an investigation is running and stops once it settles, so a
 * finished case is not re-fetched every second. Both the dashboard and the
 * investigation page use this, which keeps them showing the same case.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "./api";
import type { AgentRoster, Investigation } from "../types/agents";

const ACTIVE_POLL_MS = 900;
const IDLE_POLL_MS = 6000;

export interface InvestigationState {
  investigation: Investigation | null;
  roster: AgentRoster | null;
  busy: boolean;
  error: string | null;
  start: (chainId?: string) => Promise<void>;
  replace: (next: Investigation) => void;
}

export function useInvestigation(): InvestigationState {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [roster, setRoster] = useState<AgentRoster | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    api
      .agentRoster()
      .then((value) => mounted.current && setRoster(value))
      .catch(() => undefined);
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const latest = await api.latestInvestigation();
      if (mounted.current) {
        setInvestigation(latest);
        setError(null);
      }
    } catch (cause) {
      if (mounted.current) {
        setError(cause instanceof Error ? cause.message : "request failed");
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Poll quickly while agents are working, slowly once the case has settled.
  const active = investigation?.status === "active" || investigation?.status === "pending";
  useEffect(() => {
    const interval = window.setInterval(
      () => void refresh(),
      active ? ACTIVE_POLL_MS : IDLE_POLL_MS,
    );
    return () => window.clearInterval(interval);
  }, [active, refresh]);

  const start = useCallback(
    async (chainId?: string) => {
      setBusy(true);
      setError(null);
      try {
        const started = await api.startInvestigation(chainId);
        if (mounted.current) setInvestigation(started);
      } catch (cause) {
        if (mounted.current) {
          setError(cause instanceof Error ? cause.message : "could not start");
        }
      } finally {
        if (mounted.current) setBusy(false);
      }
    },
    [],
  );

  const replace = useCallback((next: Investigation) => {
    if (mounted.current) setInvestigation(next);
  }, []);

  return { investigation, roster, busy, error, start, replace };
}
