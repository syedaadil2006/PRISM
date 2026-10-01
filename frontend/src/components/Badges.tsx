/** Assurance, state, severity and confidence badges. */

import {
  ASSURANCE_CLASS,
  ASSURANCE_LABEL,
  ASSURANCE_MEANING,
  CONFIDENCE_CLASS,
  SEVERITY_CLASS,
  STATE_CLASS,
  STATE_LABEL,
} from "../lib/theme";
import type { Assurance, Confidence, NodeState, Severity } from "../types";

export function AssuranceBadge({ value, className = "" }: { value: Assurance; className?: string }) {
  return (
    <span className={`chip ${ASSURANCE_CLASS[value]} ${className}`} title={ASSURANCE_MEANING[value]}>
      {ASSURANCE_LABEL[value]}
    </span>
  );
}

export function StateBadge({ value }: { value: NodeState }) {
  return <span className={`chip ${STATE_CLASS[value]}`}>{STATE_LABEL[value]}</span>;
}

export function SeverityBadge({ value }: { value: Severity | string }) {
  const key = (value as Severity) in SEVERITY_CLASS ? (value as Severity) : "low";
  return <span className={`chip ${SEVERITY_CLASS[key]}`}>{value}</span>;
}

export function ConfidenceBadge({ value }: { value: Confidence | string }) {
  return (
    <span className={`chip ${CONFIDENCE_CLASS[value] ?? CONFIDENCE_CLASS.medium}`}>
      {value} confidence
    </span>
  );
}

export function TechniqueChip({
  id,
  name,
  reference,
}: {
  id: string;
  name?: string;
  reference?: string | null;
}) {
  const body = (
    <span className="chip border-ink-600 bg-ink-800 font-mono !normal-case text-slate-300">
      {id}
      {name ? <span className="hidden text-slate-500 sm:inline">{name}</span> : null}
    </span>
  );
  if (!reference) return body;
  return (
    <a href={reference} target="_blank" rel="noreferrer" title={name ?? id}>
      {body}
    </a>
  );
}
