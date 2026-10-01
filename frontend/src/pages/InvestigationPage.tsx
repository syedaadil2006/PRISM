/**
 * The investigation workspace: summary, findings, agents and reasoning in one
 * place, for an analyst working the case rather than glancing at the board.
 */

import { AgentActivityPanel } from "../components/AgentActivityPanel";
import { AgentTimeline } from "../components/AgentTimeline";
import { AISummaryPanel } from "../components/AISummaryPanel";
import { InvestigationPanel } from "../components/InvestigationPanel";
import { useInvestigation } from "../lib/useInvestigation";
import type { InvestigationMetrics } from "../types/agents";

/**
 * The funnel, measured on the data actually loaded. These are counts, not
 * claimed improvements: the reduction is whatever this dataset produced.
 */
function FunnelStrip({ metrics }: { metrics: InvestigationMetrics }) {
  const stages = [
    { label: "Raw events", value: metrics.raw_events },
    { label: "Would alert", value: metrics.notable_events },
    { label: "Correlated", value: metrics.correlated_events },
    { label: "Clusters", value: metrics.suspicious_clusters },
    { label: "Attack chains", value: metrics.attack_chains },
    { label: "Investigations", value: metrics.investigations },
  ];

  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">From telemetry to one case</p>
        <span className="font-mono text-[10px] text-slate-500">
          {metrics.tool_calls} tool calls &middot; {metrics.evidence_items} evidence items
          &middot; {metrics.investigation_seconds.toFixed(2)}s
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1 px-4 py-3">
        {stages.map((stage, index) => (
          <div key={stage.label} className="flex items-center gap-1">
            <div className="min-w-[92px] rounded border border-ink-700 bg-ink-850 px-2.5 py-1.5">
              <p className="font-mono text-base font-semibold text-slate-100">{stage.value}</p>
              <p className="text-[10px] leading-none text-slate-500">{stage.label}</p>
            </div>
            {index < stages.length - 1 && (
              <span className="text-slate-600" aria-hidden>
                &rarr;
              </span>
            )}
          </div>
        ))}
        <div className="ml-2 max-w-[230px] space-y-1">
          {metrics.false_positive_candidates > 0 && (
            <p className="text-[10px] leading-snug text-slate-500">
              {metrics.false_positive_candidates} flagged event(s) were left out of the chain
              because nothing tied them to it.
            </p>
          )}
          {metrics.analyst_false_positives > 0 && (
            <p className="text-[10px] leading-snug text-amber-400/80">
              {metrics.analyst_false_positives} finding(s) dismissed by the analyst.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export function InvestigationPage() {
  const { investigation, roster, busy, error, start, replace } = useInvestigation();

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">
            Agentic investigation
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            Nine agents gather evidence through a tool layer, reason over the attack graph,
            and verify each other before anything reaches you.
          </p>
        </div>
        {investigation && (
          <div className="flex items-center gap-3 font-mono text-[11px] text-slate-400">
            <span>{investigation.investigation_id}</span>
            <span className="text-slate-600">|</span>
            <span>{investigation.status}</span>
            <span className="text-slate-600">|</span>
            <span>{Math.round(investigation.confidence * 100)}% confidence</span>
            {investigation.status === "complete" && (
              <>
                <a
                  className="btn btn-primary !font-sans"
                  href={`/api/agents/investigations/${investigation.investigation_id}/report`}
                  target="_blank"
                  rel="noreferrer"
                >
                  View report / PDF
                </a>
                <a
                  className="btn !font-sans"
                  href={`/api/agents/investigations/${investigation.investigation_id}/report?format=md&download=true`}
                >
                  Download .md
                </a>
              </>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="panel border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-200">
          {error}
        </div>
      )}

      {investigation && <FunnelStrip metrics={investigation.metrics} />}

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-3">
          <AISummaryPanel investigation={investigation} />
          <InvestigationPanel investigation={investigation} onUpdated={replace} />
        </div>
        <div className="space-y-3">
          <AgentActivityPanel
            investigation={investigation}
            roster={roster}
            busy={busy}
            onStart={() => void start()}
          />
          <AgentTimeline investigation={investigation} />
        </div>
      </div>
    </div>
  );
}
