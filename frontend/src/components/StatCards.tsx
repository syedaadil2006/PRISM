/**
 * The headline numbers.
 *
 * The last card is the point of the product: how many fragmented alerts a
 * classic console would have shown, versus how many stories PRISM shows.
 */

import type { DashboardStats } from "../types";
import type { StatKey } from "./StatDetail";

interface Props {
  stats: DashboardStats | null;
  /** Investigations opened in this session, from the agent layer. */
  investigations?: number;
  onSelect?: (key: StatKey) => void;
}

interface Card {
  key: StatKey;
  label: string;
  value: string;
  hint: string;
  accent: string;
}

export function StatCards({ stats, investigations = 0, onSelect }: Props) {
  if (!stats) {
    return (
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-7">
        {Array.from({ length: 7 }).map((_, index) => (
          <div key={index} className="panel h-[86px] animate-pulse" />
        ))}
      </div>
    );
  }

  const cards: Card[] = [
    {
      key: "investigations",
      label: "Investigations",
      value: String(investigations),
      hint: investigations ? "Agent-led, evidence-backed" : "None opened yet",
      accent: "text-cyan-300",
    },
    {
      key: "chains",
      label: "Active attack chains",
      value: String(stats.active_attack_chains),
      hint: "Correlated stories, not alerts",
      accent: "text-rose-300",
    },
    {
      key: "correlated",
      label: "Correlated events",
      value: `${stats.correlated_events}`,
      hint: `of ${stats.total_events} ingested`,
      accent: "text-sky-300",
    },
    {
      key: "compromised",
      label: "Compromised hosts",
      value: String(stats.compromised_hosts),
      hint: "Activity observed on host",
      accent: "text-orange-300",
    },
    {
      key: "lateral",
      label: "Lateral movements",
      value: String(stats.lateral_movements),
      hint: "Inferred by the rule engine",
      accent: "text-cyan-300",
    },
    {
      key: "targets",
      label: "Potential targets",
      value: String(stats.potential_targets),
      hint: "Predicted, not observed",
      accent: "text-pink-300",
    },
    {
      key: "reduction",
      label: "Alert reduction",
      value: `${Math.round(stats.alert_reduction_ratio * 100)}%`,
      hint: `${stats.raw_alert_count} raw alerts to ${stats.active_attack_chains} chain${
        stats.active_attack_chains === 1 ? "" : "s"
      }`,
      accent: "text-emerald-300",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-7">
      {cards.map((card) => (
        <button
          key={card.label}
          type="button"
          onClick={() => onSelect?.(card.key)}
          title="Click to see what this number is made of"
          className="panel group px-4 py-3 text-left transition hover:-translate-y-0.5 hover:border-sky-500/50 hover:shadow-glow focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          <p className="panel-title">{card.label}</p>
          <p className={`mt-1 font-mono text-2xl font-semibold ${card.accent}`}>{card.value}</p>
          <p className="mt-0.5 truncate text-[11px] text-slate-500" title={card.hint}>
            {card.hint}
          </p>
          <p className="mt-1 text-[10px] text-sky-400 opacity-0 transition group-hover:opacity-100">
            View details &rarr;
          </p>
        </button>
      ))}
    </div>
  );
}
