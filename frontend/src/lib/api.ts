/**
 * Typed PRISM API client.
 *
 * Every panel in the UI reads from here, so there is exactly one place that
 * knows how to reach the backend.
 */

import type {
  AgentRoster,
  AgentStep,
  AnalystDecision,
  EvidenceBundle,
  Investigation,
  InvestigationSummaryView,
} from "../types/agents";
import type {
  AttackChain,
  AttackChainDetail,
  Correlation,
  DashboardStats,
  EngineConfig,
  GraphPayload,
  Health,
  HostView,
  IngestSummary,
  NormalizedEvent,
  SimulationStatus,
  TacticView,
  TargetPrediction,
  UserView,
} from "../types";

const BASE = import.meta.env.VITE_API_BASE ?? "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: init?.body instanceof FormData ? undefined : { Accept: "application/json" },
    ...init,
  });

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // Non-JSON error body; the status line is all we have.
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "" && value !== false) {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export interface EventFilters {
  event_type?: string;
  host?: string;
  user?: string;
  suspicious_only?: boolean;
  chain_id?: string;
  limit?: number;
}

export const api = {
  health: () => request<Health>("/health"),
  config: () => request<EngineConfig>("/config"),
  stats: () => request<DashboardStats>("/stats"),

  attacks: (status?: string) => request<AttackChain[]>(`/attacks${query({ status })}`),
  attack: (chainId: string) => request<AttackChainDetail>(`/attacks/${chainId}`),

  events: (filters: EventFilters = {}) =>
    request<NormalizedEvent[]>(`/events${query({ ...filters })}`),
  correlations: (eventId?: string, limit = 300) =>
    request<Correlation[]>(`/correlations${query({ event_id: eventId, limit })}`),

  graph: (chainId?: string) => request<GraphPayload>(`/graph${query({ chain_id: chainId })}`),
  hosts: () => request<HostView[]>("/hosts"),
  users: () => request<UserView[]>("/users"),
  mitre: () => request<TacticView[]>("/mitre"),
  predictions: () => request<TargetPrediction[]>("/predictions"),

  simulation: () => request<SimulationStatus>("/simulation"),
  simulationStart: () => request<SimulationStatus>("/simulation/start", { method: "POST" }),
  simulationPause: () => request<SimulationStatus>("/simulation/pause", { method: "POST" }),
  simulationResume: () => request<SimulationStatus>("/simulation/resume", { method: "POST" }),
  simulationStep: (count = 1) =>
    request<SimulationStatus>(`/simulation/step${query({ count })}`, { method: "POST" }),
  simulationReset: (showAll = false) =>
    request<SimulationStatus>(`/simulation/reset${query({ show_all: showAll })}`, {
      method: "POST",
    }),

  // --- agentic investigation layer ---
  agentRoster: () => request<AgentRoster>("/agents/roster"),
  agentTools: () =>
    request<{ count: number; tools: { name: string; category: string; description: string }[] }>(
      "/agents/tools",
    ),
  investigations: () => request<InvestigationSummaryView[]>("/agents/investigations"),
  latestInvestigation: () => request<Investigation | null>("/agents/investigations/latest"),
  investigation: (id: string) => request<Investigation>(`/agents/investigations/${id}`),
  investigationTimeline: (id: string) =>
    request<AgentStep[]>(`/agents/investigations/${id}/timeline`),
  investigationEvidence: (id: string, findingId?: string) =>
    request<EvidenceBundle>(
      `/agents/investigations/${id}/evidence${query({ finding_id: findingId })}`,
    ),
  startInvestigation: (chainId?: string) =>
    request<Investigation>(`/agents/investigations${query({ chain_id: chainId })}`, {
      method: "POST",
    }),
  cancelInvestigation: (id: string) =>
    request<Investigation>(`/agents/investigations/${id}/cancel`, { method: "POST" }),
  recordDecision: (id: string, findingId: string, decision: AnalystDecision, note = "") =>
    request<Investigation>(
      `/agents/investigations/${id}/findings/${findingId}/decision${query({ decision })}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ note }),
      },
    ),

  ingest: (files: File[], logFormat?: string) => {
    const form = new FormData();
    for (const file of files) form.append("files", file);
    return request<IngestSummary>(`/logs/ingest${query({ log_format: logFormat })}`, {
      method: "POST",
      body: form,
    });
  },
  resetLogs: () => request<IngestSummary>("/logs/reset", { method: "POST" }),
};
