/**
 * TypeScript mirrors of the agentic investigation layer.
 *
 * Follows backend/app/agents/state.py. As with the rest of the UI, nothing here
 * is invented: if the backend does not return a field, it does not belong in
 * this file.
 */

import type { Assurance } from "./index";

export type AgentKey =
  | "triage"
  | "correlation"
  | "investigation"
  | "evidence"
  | "graph"
  | "mitre"
  | "chain"
  | "next_target"
  | "verification";

export type AgentStatus = "pending" | "running" | "complete" | "skipped" | "failed";

export type AnalystDecision = "approved" | "rejected" | "false_positive";

export type EvidenceKind = "event" | "graph" | "mitre" | "inventory" | "correlation";

export interface ToolCall {
  call_id: string;
  tool: string;
  arguments: Record<string, unknown>;
  result_count: number;
  result_summary: string;
  duration_ms: number;
  at: string;
  produced_evidence: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  kind: EvidenceKind;
  summary: string;
  detail: string;
  event_ids: string[];
  node_ids: string[];
  source_tool: string;
  source_call_id: string;
  assurance: Assurance;
  at: string;
}

export interface Finding {
  finding_id: string;
  agent: AgentKey;
  title: string;
  statement: string;
  assurance: Assurance;
  confidence: number;
  evidence_ids: string[];
  verified: boolean | null;
  verification_notes: string[];
  confidence_before_verification: number | null;
  analyst_decision: AnalystDecision | null;
  analyst_note: string;
  decided_at: string | null;
  at: string;
}

export interface AgentStep {
  step_id: string;
  agent: AgentKey;
  action: string;
  detail: string;
  at: string;
  tool_calls: ToolCall[];
  evidence_ids: string[];
  finding_ids: string[];
}

export interface AgentRun {
  agent: AgentKey;
  label: string;
  purpose: string;
  status: AgentStatus;
  summary: string;
  started_at: string | null;
  finished_at: string | null;
  step_ids: string[];
  finding_ids: string[];
  tool_call_count: number;
  skip_reason: string;
}

export interface InvestigationMetrics {
  raw_events: number;
  notable_events: number;
  correlated_events: number;
  suspicious_clusters: number;
  attack_chains: number;
  investigations: number;
  false_positive_candidates: number;
  analyst_false_positives: number;
  tool_calls: number;
  evidence_items: number;
  investigation_seconds: number;
}

export interface AISummary {
  headline: string;
  narrative: string;
  observed: string[];
  inferred: string[];
  predicted: string[];
  recommended_actions: string[];
  evidence_count: number;
  technique_count: number;
  confidence: number;
  status: string;
  generated_by: string;
}

export interface Investigation {
  investigation_id: string;
  status: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  attack_chain_id: string | null;
  trigger: string;
  initial_host: string | null;
  current_host: string | null;
  current_stage: string | null;
  user: string | null;
  observed_techniques: string[];
  potential_targets: string[];
  evidence_count: number;
  confidence: number;
  severity: string;
  agents: AgentRun[];
  steps: AgentStep[];
  findings: Finding[];
  evidence: EvidenceItem[];
  metrics: InvestigationMetrics;
  summary: AISummary | null;
}

export interface InvestigationSummaryView {
  investigation_id: string;
  status: string;
  created_at: string;
  attack_chain_id: string | null;
  initial_host: string | null;
  current_host: string | null;
  current_stage: string | null;
  user: string | null;
  confidence: number;
  severity: string;
  evidence_count: number;
  technique_count: number;
  potential_targets: string[];
  agents_complete: number;
  agents_total: number;
}

export interface AgentRosterEntry {
  agent: AgentKey;
  label: string;
  purpose: string;
  order: number;
}

export interface AgentRoster {
  enabled: boolean;
  /** "deterministic", or the configured LLM provider name. */
  narrator: string;
  llm_configured: boolean;
  step_delay_seconds: number;
  agents: AgentRosterEntry[];
}

export interface EvidenceBundle {
  investigation_id: string;
  finding_id: string | null;
  count: number;
  evidence: EvidenceItem[];
  source_event_ids: string[];
}
