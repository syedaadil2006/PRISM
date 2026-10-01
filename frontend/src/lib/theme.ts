/**
 * Shared visual vocabulary.
 *
 * The graph, the badges and the tables all read their colours from here, so a
 * "predicted" relationship never looks like an observed one.
 */

import type { Assurance, NodeState, Severity } from "../types";

export const ASSURANCE_COLOR: Record<Assurance, string> = {
  observed: "#38bdf8",
  correlated: "#a78bfa",
  inferred: "#fb923c",
  predicted: "#f472b6",
};

export const ASSURANCE_LABEL: Record<Assurance, string> = {
  observed: "Observed",
  correlated: "Correlated",
  inferred: "Inferred",
  predicted: "Predicted",
};

export const ASSURANCE_MEANING: Record<Assurance, string> = {
  observed: "Taken directly from a source log record.",
  correlated: "Grouped from several events by shared identity, host, address or timing.",
  inferred: "Produced by the lateral-movement rule engine, not stated by any single record.",
  predicted: "Risk-based graph scoring. Not observed attacker activity.",
};

export const ASSURANCE_CLASS: Record<Assurance, string> = {
  observed: "border-sky-400/50 bg-sky-400/10 text-sky-300",
  correlated: "border-violet-400/50 bg-violet-400/10 text-violet-300",
  inferred: "border-orange-400/50 bg-orange-400/10 text-orange-300",
  predicted: "border-pink-400/50 bg-pink-400/10 text-pink-300",
};

export const STATE_COLOR: Record<NodeState, string> = {
  normal: "#64748b",
  suspicious: "#f59e0b",
  compromised: "#ef4444",
  current_position: "#22d3ee",
  potential_target: "#f472b6",
};

export const STATE_LABEL: Record<NodeState, string> = {
  normal: "Normal",
  suspicious: "Suspicious",
  compromised: "Compromised",
  current_position: "Attacker position",
  potential_target: "Potential target",
};

export const STATE_CLASS: Record<NodeState, string> = {
  normal: "border-slate-500/40 bg-slate-500/10 text-slate-300",
  suspicious: "border-amber-400/50 bg-amber-400/10 text-amber-300",
  compromised: "border-rose-500/50 bg-rose-500/10 text-rose-300",
  current_position: "border-cyan-400/60 bg-cyan-400/10 text-cyan-300",
  potential_target: "border-pink-400/50 bg-pink-400/10 text-pink-300",
};

export const SEVERITY_CLASS: Record<Severity, string> = {
  info: "border-slate-500/40 bg-slate-500/10 text-slate-400",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  high: "border-orange-500/50 bg-orange-500/10 text-orange-300",
  critical: "border-rose-500/60 bg-rose-500/15 text-rose-300",
};

export const CONFIDENCE_CLASS: Record<string, string> = {
  low: "border-slate-500/40 bg-slate-500/10 text-slate-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  high: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
};

/** Tactic accents used on the timeline and the MITRE page. */
export const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "#f472b6",
  Execution: "#fbbf24",
  Persistence: "#a3e635",
  "Privilege Escalation": "#fb923c",
  "Defense Evasion": "#94a3b8",
  "Credential Access": "#ef4444",
  Discovery: "#38bdf8",
  "Lateral Movement": "#22d3ee",
  Collection: "#c084fc",
  "Command and Control": "#a78bfa",
  Exfiltration: "#f97316",
  Impact: "#dc2626",
};

export function tacticColor(tactic: string): string {
  return TACTIC_COLOR[tactic] ?? "#64748b";
}
