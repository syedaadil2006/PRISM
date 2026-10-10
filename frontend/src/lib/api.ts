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
  LiveStatus,
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
    if (response.status === 401 && !path.startsWith("/auth/")) {
      // Signed out or the session expired: let the app show the sign-in screen.
      window.dispatchEvent(new Event("prism:unauthorized"));
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

export type Role = "viewer" | "analyst" | "admin";

export interface AuthStatus {
  enabled: boolean;
  authenticated: boolean;
  user?: string | null;
  role?: Role | null;
  /** "user" (named account) or "access-code". */
  kind?: string | null;
  accounts?: boolean;
  has_accounts?: boolean;
  password_change_required?: boolean;
  access_code?: boolean;
}

export interface Account {
  username: string;
  role: Role;
  disabled: boolean;
  created_at: string;
  last_login: string | null;
  must_change_password?: boolean;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  address: string;
  detail: Record<string, unknown>;
}

export interface SuppressionEntry {
  id: string;
  action: string;
  indicator: string;
  host: string;
  user: string;
  chain_id: string;
  analyst: string;
  note: string;
  created_at: string;
}

export interface DetectionInfo {
  version: string;
  sigma: { loaded: number; skipped: number };
  intel: { indicators: number; domains: number; ips: number; hashes: number; urls: number; files: { file: string; indicators: number; error?: string }[] };
  baseline: { enabled: boolean; min_history: number; learning_hours: number };
  suppressions: number;
  rules: { id: string; title: string; level: string; techniques: string[]; logsource: string; source: string }[];
  skipped_rules: { file: string; reason: string }[];
}

export interface AuditCheck {
  ok: boolean;
  entries: number;
  first_broken: number | null;
  reason: string | null;
}

const json = (body: unknown, method = "POST"): RequestInit => ({
  method,
  headers: { Accept: "application/json", "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  authStatus: () => request<AuthStatus>("/auth/status"),
  login: (token: string) => request<AuthStatus>("/auth/login", json({ token })),
  loginUser: (username: string, password: string) =>
    request<AuthStatus>("/auth/login", json({ username, password })),
  logout: () => request<AuthStatus>("/auth/logout", { method: "POST" }),
  changePassword: (current_password: string, new_password: string) =>
    request<AuthStatus>("/auth/password", json({ current_password, new_password })),

  accounts: () => request<Account[]>("/admin/users"),
  createAccount: (username: string, password: string, role: Role) =>
    request<Account>("/admin/users", json({ username, password, role })),
  updateAccount: (username: string, change: { role?: Role; disabled?: boolean; password?: string }) =>
    request<Account>(`/admin/users/${encodeURIComponent(username)}`, json(change, "PATCH")),
  deleteAccount: async (username: string) => {
    const response = await fetch(`${BASE}/admin/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as { detail?: string };
      throw new ApiError(body.detail ?? `${response.status} ${response.statusText}`, response.status);
    }
  },
  chainFeedback: (chainId: string, verdict: "true_positive" | "false_positive", note: string) =>
    request<{ verdict: string; suppressions_created: SuppressionEntry[]; chains_now: number }>(
      `/attacks/${encodeURIComponent(chainId)}/feedback`,
      json({ verdict, note }),
    ),
  detection: () => request<DetectionInfo>("/detection"),
  reloadDetection: () => request<DetectionInfo>("/admin/detection/reload", { method: "POST" }),
  feedback: () =>
    request<{ suppressions: SuppressionEntry[]; verdicts: Record<string, string>[] }>("/feedback"),
  deleteSuppression: (id: string) =>
    request<{ removed: string }>(`/feedback/suppressions/${encodeURIComponent(id)}`, { method: "DELETE" }),
  audit: (limit = 200) => request<AuditEntry[]>(`/admin/audit${query({ limit })}`),
  verifyAudit: () => request<AuditCheck>("/admin/audit/verify"),

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
  live: () => request<LiveStatus>("/live/status"),
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
