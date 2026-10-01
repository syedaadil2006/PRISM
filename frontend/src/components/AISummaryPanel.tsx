/**
 * The final analyst-facing conclusion.
 *
 * Observed, inferred and predicted are kept in separate blocks rather than
 * blended into one paragraph, because the difference between "this happened"
 * and "this might happen next" is the difference between a containment decision
 * and a monitoring decision.
 *
 * The footer names who wrote the prose. When no model is configured that is the
 * deterministic narrator, and an analyst should not have to guess.
 */

import type { Investigation } from "../types/agents";

function Block({
  title,
  lines,
  tone,
  mark,
}: {
  title: string;
  lines: string[];
  tone: string;
  mark: string;
}) {
  if (lines.length === 0) return null;
  return (
    <div>
      <p className={`text-[10px] font-semibold uppercase tracking-[0.14em] ${tone}`}>{title}</p>
      <ul className="mt-1 space-y-1">
        {lines.map((line, index) => (
          <li key={index} className="flex gap-2 text-[11px] leading-relaxed text-slate-300">
            <span className={`shrink-0 ${tone}`}>{mark}</span>
            <span>{line}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
        {label}
      </p>
      <p className="mt-0.5 font-mono text-sm text-slate-100">{value}</p>
    </div>
  );
}

export function AISummaryPanel({ investigation }: { investigation: Investigation | null }) {
  const summary = investigation?.summary;
  if (!investigation || !summary) {
    return (
      <div className="panel px-4 py-6 text-xs text-slate-500">
        The investigation summary appears once the agents have verified their findings.
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">Attack summary</p>
        <span className="font-mono text-[10px] text-slate-500">
          {Math.round(summary.confidence * 100)}% confidence
        </span>
      </div>

      <div className="space-y-3 px-4 py-3">
        <p className="font-mono text-sm font-semibold text-slate-100">{summary.headline}</p>

        {summary.narrative.split("\n\n").map((paragraph, index) => (
          <p key={index} className="text-[12px] leading-relaxed text-slate-300">
            {paragraph}
          </p>
        ))}

        <div className="grid grid-cols-2 gap-3 border-y border-ink-700/70 py-2.5 sm:grid-cols-4">
          <Stat label="Root cause" value={investigation.initial_host ?? "unknown"} />
          <Stat label="Current host" value={investigation.current_host ?? "unknown"} />
          <Stat label="Evidence" value={String(summary.evidence_count)} />
          <Stat label="Techniques" value={String(summary.technique_count)} />
        </div>

        <Block
          title="Observed"
          lines={summary.observed}
          tone="text-sky-400"
          mark="&#10003;"
        />
        <Block
          title="Inferred"
          lines={summary.inferred}
          tone="text-orange-400"
          mark="&#8594;"
        />
        <Block
          title="Predicted"
          lines={summary.predicted}
          tone="text-pink-400"
          mark="&#9888;"
        />

        {summary.recommended_actions.length > 0 && (
          <div className="rounded border border-ink-700 bg-ink-850 px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
              Recommended actions
            </p>
            <ul className="mt-1 space-y-0.5">
              {summary.recommended_actions.map((action, index) => (
                <li key={index} className="text-[11px] leading-snug text-slate-300">
                  {index + 1}. {action}
                </li>
              ))}
            </ul>
            <p className="mt-1.5 text-[10px] text-slate-500">
              Recommendations only. PRISM does not act on hosts.
            </p>
          </div>
        )}
      </div>

      <p className="border-t border-ink-700/70 px-4 py-2 text-[10px] text-slate-500">
        Status: {summary.status} &middot; written by{" "}
        <span className="text-slate-400">
          {summary.generated_by === "deterministic"
            ? "the deterministic narrator"
            : summary.generated_by}
        </span>
        {summary.generated_by !== "deterministic" &&
          " (checked against the verified findings before display)"}
      </p>
    </div>
  );
}
