/**
 * TypeScript mirrors of the PRISM backend models.
 *
 * These follow backend/app/models/*.py. Nothing here invents data: if a field
 * is not returned by the API it does not belong in this file.
 */

export type Assurance = "observed" | "correlated" | "inferred" | "predicted";
export type Confidence = "low" | "medium" | "high";
export type EventTypeName = "authentication" | "dns" | "endpoint";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  event_type: EventTypeName;
  action: string;
  user: string | null;
  source_host: string | null;
  destination_host: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  process: string | null;
  parent_process: string | null;
  command_line: string | null;
  domain: string | null;
  file_name: string | null;
  logon_type: string | null;
  outcome: string | null;
  severity: Severity;
  suspicious: boolean;
  tags: string[];
  source_log: string;
  raw: Record<string, unknown>;
}

export interface CorrelationFactor {
  name: string;
  weight: number;
  detail: string;
}

export interface Correlation {
  source_event_id: string;
  target_event_id: string;
  score: number;
  time_delta_seconds: number;
  factors: CorrelationFactor[];
  assurance: Assurance;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic: string;
  event_id: string;
  evidence: string;
  explanation: string;
  confidence: Confidence;
  assurance: Assurance;
  reference: string | null;
}

export interface AttackStage {
  order: number;
  tactic: string;
  label: string;
  timestamp: string;
  last_timestamp: string | null;
  host: string | null;
  user: string | null;
  event_ids: string[];
  technique_ids: string[];
  description: string;
  assurance: Assurance;
}

export interface LateralMovement {
  movement_id: string;
  timestamp: string;
  user: string | null;
  source_host: string;
  destination_host: string;
  method: string;
  event_id: string;
  correlation_score: number;
  confidence: Confidence;
  assurance: Assurance;
  rule_evaluation: string[];
  explanation: string;
}

export interface PredictionFactor {
  name: string;
  points: number;
  max_points: number;
  detail: string;
}

export interface TargetPrediction {
  host: string;
  raw_score: number;
  score: number;
  confidence: Confidence;
  assurance: Assurance;
  factors: PredictionFactor[];
  reasons: string[];
  narrative: string;
  attack_chain_id: string | null;
  is_critical_infrastructure: boolean;
}

export interface RootCause {
  initial_host: string | null;
  initial_user: string | null;
  initial_event_id: string | null;
  initial_evidence: string;
  observed_progression: string[];
  current_status: string;
  potential_next_target: string | null;
  inference_notes: string[];
}

export interface AttackChain {
  attack_chain_id: string;
  name: string;
  status: string;
  severity: string;
  risk_score: number;
  start_time: string;
  last_seen: string;
  initial_host: string | null;
  current_host: string | null;
  users: string[];
  hosts: string[];
  targeted_hosts: string[];
  event_ids: string[];
  event_count: number;
  correlation_count: number;
  mean_correlation_score: number;
  current_stage: string;
  stages: AttackStage[];
  mitre: MitreMapping[];
  lateral_movements: LateralMovement[];
  predictions: TargetPrediction[];
  root_cause: RootCause | null;
  confidence: Confidence;
}

export interface AttackChainDetail {
  chain: AttackChain;
  events: NormalizedEvent[];
  correlations: Correlation[];
}

export interface DashboardStats {
  active_attack_chains: number;
  correlated_events: number;
  total_events: number;
  compromised_hosts: number;
  lateral_movements: number;
  potential_targets: number;
  mitre_techniques: number;
  raw_alert_count: number;
  alert_reduction_ratio: number;
}

export type NodeKind =
  | "user"
  | "host"
  | "ip"
  | "domain"
  | "process"
  | "file"
  | "event"
  | "attack";

export type NodeState =
  | "normal"
  | "suspicious"
  | "compromised"
  | "current_position"
  | "potential_target";

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  state: NodeState;
  assurance: Assurance;
  attack_chain_ids: string[];
  stage_order: number | null;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
  assurance: Assurance;
  predicted: boolean;
  attack_chain_ids: string[];
  event_ids: string[];
  metadata: Record<string, unknown>;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
  generated_at: string | null;
  stats: Record<string, number>;
}

export interface HostView {
  name: string;
  ip: string | null;
  role: string;
  zone: string;
  os: string | null;
  criticality: number;
  is_critical_infrastructure: boolean;
  state: NodeState;
  event_count: number;
  suspicious_event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  users: string[];
  attack_chain_ids: string[];
  prediction_score: number | null;
  reachable_hosts: string[];
}

export interface UserView {
  name: string;
  display_name: string | null;
  department: string | null;
  privilege: number;
  is_privileged: boolean;
  groups: string[];
  accessible_hosts: string[];
  hosts_observed: string[];
  event_count: number;
  failed_logons: number;
  compromised: boolean;
  attack_chain_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface TechniqueView {
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic: string;
  reference: string | null;
  occurrences: number;
  confidence: Confidence;
  attack_chain_ids: string[];
  evidence: MitreMapping[];
}

export interface TacticView {
  tactic_id: string;
  tactic: string;
  order: number;
  techniques: TechniqueView[];
}

export interface SimulationStatus {
  state: "idle" | "running" | "paused" | "completed";
  revealed: number;
  total: number;
  tick_seconds: number;
  events_per_tick: number;
  current_time: string | null;
  gating: boolean;
}

export interface LiveStreamView {
  name: string;
  events: number;
  rejected: number;
  last_event_at: string | null;
  last_received_at: string | null;
}

/** Real-time feed status (GET /api/live/status). */
export interface LiveStatus {
  enabled: boolean;
  receiving: boolean;
  live_only: boolean;
  watch_dir: string | null;
  received: number;
  accepted: number;
  rejected: number;
  duplicates: number;
  events_per_minute: number;
  last_received_at: string | null;
  pending_analysis: boolean;
  last_analysis_at: string | null;
  last_analysis_ms: number | null;
  streams: LiveStreamView[];
  recent_errors: string[];
}

export interface EngineConfig {
  correlation_window_seconds: number;
  correlation_min_score: number;
  correlation_min_chain_events: number;
  correlation_weights: Record<string, number>;
  lateral_window_seconds: number;
  lateral_min_correlation_score: number;
  lateral_movement_actions: string[];
  prediction_weights: Record<string, number>;
  prediction_normalisation_ceiling: number;
  neo4j_enabled: boolean;
  demo_mode: boolean;
}

export interface Health {
  status: string;
  version: string;
  events: number;
  chains: number;
  sources: string[];
  ingest_errors: string[];
  computed_at: string | null;
}

export interface IngestSummary {
  accepted: number;
  rejected: number;
  total_events: number;
  errors: string[];
  sources: string[];
}
