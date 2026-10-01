/**
 * What the agents are doing right now.
 *
 * Shows the whole roster from the first frame, pending included, so the analyst
 * can see the plan rather than watching agents appear one at a time. Each row
 * carries its own summary once it finishes, and a skipped agent says why it was
 * skipped -- an agent that did not run is information, not an absence.
 */

import type { AgentRoster, AgentRun, AgentStatus, Investigation } from "../types/agents";

const STATUS_MARK: Record<AgentStatus, string> = {
  complete: "✓",
  running: "●",
  pending: "○",
  skipped: "—",
  failed: "✗",
};

const STATUS_CLASS: Record<AgentStatus, string> = {
  complete: "text-emerald-400",
  running: "animate-pulse text-cyan-300",
  pending: "text-slate-600",
  skipped: "text-slate-500",
  failed: "text-rose-400",
};

function AgentRow({ run }: { run: AgentRun }) {
  const detail =
    run.status === "skipped" ? run.skip_reason || "Skipped" : run.summary;

  return (
    <li className="flex gap-2.5 px-4 py-2">
      <span
        className={`mt-0.5 w-3 shrink-0 text-center font-mono text-xs ${STATUS_CLASS[run.status]}`}
        aria-hidden
      >
        {STATUS_MARK[run.status]}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span
            className={`text-[11px] font-semibold ${
              run.status === "pending" ? "text-slate-500" : "text-slate-200"
            }`}
          >
            {run.label}
          </span>
          {run.tool_call_count > 0 && (
            <span className="shrink-0 font-mono text-[10px] text-slate-500">
              {run.tool_call_count} tool call{run.tool_call_count === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <p className="mt-0.5 text-[11px] leading-snug text-slate-400">
          {detail || run.purpose}
        </p>
      </div>
    </li>
  );
}

export function AgentActivityPanel({
  investigation,
  roster,
  busy,
  onStart,
  collapsed = false,
  onToggleCollapse,
}: {
  investigation: Investigation | null;
  roster: AgentRoster | null;
  busy: boolean;
  onStart: () => void;
  /** Folds the panel to its header so the panels below slide up. */
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}) {
  const runs = investigation?.agents ?? [];
  const done = runs.filter((r) => r.status === "complete" || r.status === "skipped").length;
  const running = investigation?.status === "active";

  return (
    <div className="panel">
      <div className="panel-header">
        <button
          type="button"
          className="flex items-center gap-2 text-left"
          onClick={onToggleCollapse}
          disabled={!onToggleCollapse}
          title={collapsed ? "Show agent details" : "Hide agent details"}
        >
          {onToggleCollapse && (
            <span
              className={`text-[10px] text-slate-500 transition-transform duration-300 ${
                collapsed ? "-rotate-90" : ""
              }`}
              aria-hidden
            >
              &#9660;
            </span>
          )}
          <p className="panel-title">Agent investigation</p>
          {investigation && (
            <span className="font-mono text-[10px] text-slate-500">
              {done}/{runs.length}
            </span>
          )}
          {collapsed && investigation?.status === "complete" && (
            <span className="text-[10px] text-emerald-400">
              complete &middot; {Math.round(investigation.confidence * 100)}% confidence
            </span>
          )}
        </button>
        {running ? (
          <span className="chip animate-pulse border-cyan-400/50 bg-cyan-400/10 text-cyan-300">
            investigating
          </span>
        ) : (
          <button className="btn btn-primary !py-1" disabled={busy} onClick={onStart}>
            {busy ? "Starting..." : "Start investigation"}
          </button>
        )}
      </div>

      {/* Animated fold: grid rows 1fr -> 0fr slides the content away. */}
      <div
        className={`grid transition-[grid-template-rows,opacity] duration-500 ease-in-out ${
          collapsed ? "grid-rows-[0fr] opacity-0" : "grid-rows-[1fr] opacity-100"
        }`}
      >
      <div className="overflow-hidden">
      {!investigation && (
        <div className="px-4 py-5">
          <p className="text-xs text-slate-400">
            Nine specialised agents gather evidence through the tool layer, reason over the
            attack graph, map ATT&amp;CK, project the next target and verify each other.
          </p>
          {roster && (
            <ul className="mt-3 space-y-1">
              {roster.agents.map((entry) => (
                <li key={entry.agent} className="flex gap-2 text-[11px] text-slate-500">
                  <span className="font-mono text-slate-600">{entry.order}</span>
                  <span className="text-slate-400">{entry.label}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {investigation && (
        <>
          <ul className="divide-y divide-ink-800">
            {runs.map((run) => (
              <AgentRow key={run.agent} run={run} />
            ))}
          </ul>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-ink-700/70 px-4 py-2 text-[10px] text-slate-500">
            <span className="font-mono">{investigation.investigation_id}</span>
            {investigation.status === "complete" && (
              <a
                className="text-sky-400 hover:text-sky-300"
                href={`/api/agents/investigations/${investigation.investigation_id}/report`}
                target="_blank"
                rel="noreferrer"
              >
                Report &rarr;
              </a>
            )}
            <span>
              {investigation.metrics.tool_calls} tool calls &middot;{" "}
              {investigation.evidence_count} evidence items
            </span>
            {roster && (
              <span title="Who wrote the summary paragraph">
                narrator: <span className="text-slate-400">{roster.narrator}</span>
              </span>
            )}
          </div>
        </>
      )}
      </div>
      </div>
    </div>
  );
}
