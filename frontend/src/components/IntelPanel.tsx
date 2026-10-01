/**
 * The right-hand intelligence panel.
 *
 * Answers the brief's six questions in order: where it started, what happened,
 * where the attacker is, what is happening now, what could happen next, and why.
 */

import type { ReactNode } from "react";

import { dateTime, duration } from "../lib/format";
import { tacticColor } from "../lib/theme";
import { AssuranceBadge, ConfidenceBadge, SeverityBadge, TechniqueChip } from "./Badges";
import { LateralMovementList } from "./LateralMovementList";
import { PredictionCard } from "./PredictionCard";
import type { AttackChain } from "../types";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-0.5 font-mono text-sm text-slate-100">{children}</p>
    </div>
  );
}

export function IntelPanel({ chain }: { chain: AttackChain | null }) {
  if (!chain) {
    return (
      <div className="panel px-4 py-6 text-xs text-slate-500">
        No attack chain selected. PRISM shows a chain as soon as events correlate.
      </div>
    );
  }

  const techniques = [...new Map(chain.mitre.map((m) => [m.technique_id, m])).values()];

  return (
    <div className="space-y-3">
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold text-slate-100">
              {chain.attack_chain_id}
            </span>
            <SeverityBadge value={chain.severity} />
          </div>
          <span
            className={`chip ${
              chain.status === "active"
                ? "border-rose-500/60 bg-rose-500/15 text-rose-300"
                : "border-slate-500/40 bg-slate-500/10 text-slate-400"
            }`}
          >
            {chain.status}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3 px-4 py-3">
          <Field label="Initial access">{chain.initial_host ?? "unknown"}</Field>
          <Field label="Current host">
            <span className="text-cyan-300">{chain.current_host ?? "unknown"}</span>
          </Field>
          <Field label="Current stage">
            <span style={{ color: tacticColor(chain.current_stage) }}>{chain.current_stage}</span>
          </Field>
          <Field label="Account">{chain.users.join(", ") || "unknown"}</Field>
          <Field label="Risk score">
            {chain.risk_score}
            <span className="text-[10px] text-slate-500">/100</span>
          </Field>
          <Field label="Duration">{duration(chain.start_time, chain.last_seen)}</Field>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-ink-700/70 px-4 py-2">
          <AssuranceBadge value="correlated" />
          <span className="text-[11px] text-slate-500">
            {chain.event_count} events joined by {chain.correlation_count} correlations, mean score{" "}
            <span className="font-mono text-slate-300">
              {chain.mean_correlation_score.toFixed(2)}
            </span>
          </span>
          <ConfidenceBadge value={chain.confidence} />
        </div>
      </div>

      {chain.predictions.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <p className="panel-title">Potential next target</p>
            <AssuranceBadge value="predicted" />
          </div>
          <div className="space-y-2 px-3 py-3">
            {chain.predictions.map((prediction, index) => (
              <PredictionCard
                key={prediction.host}
                prediction={prediction}
                defaultOpen={index === 0}
              />
            ))}
            <p className="px-1 text-[10px] leading-relaxed text-slate-500">
              Risk-based predictions from graph context. No attacker activity has been observed on
              these hosts.
            </p>
          </div>
        </div>
      )}

      <LateralMovementList movements={chain.lateral_movements} />

      <div className="panel">
        <div className="panel-header">
          <p className="panel-title">MITRE ATT&amp;CK observed</p>
          <span className="font-mono text-[10px] text-slate-500">
            {techniques.length} techniques
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5 px-4 py-3">
          {techniques.map((mapping) => (
            <TechniqueChip
              key={mapping.technique_id}
              id={mapping.technique_id}
              name={mapping.technique_name}
              reference={mapping.reference}
            />
          ))}
        </div>
        <p className="border-t border-ink-700/70 px-4 py-2 text-[10px] text-slate-500">
          Last observed {dateTime(chain.last_seen)}
        </p>
      </div>
    </div>
  );
}
