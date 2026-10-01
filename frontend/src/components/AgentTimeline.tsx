/**
 * The agent reasoning timeline.
 *
 * Concise actions, the tools each one called, and the conclusions reached. This
 * is deliberately not a chain-of-thought view: an analyst reviewing a case needs
 * to know what was checked and what it returned, not to read deliberation.
 *
 * Expanding a step shows the tool calls with their arguments and result counts,
 * which is the level at which a reviewer can disagree with the investigation.
 */

import { useState } from "react";

import { timeOnly } from "../lib/format";
import type { AgentKey, AgentStep, Investigation } from "../types/agents";

const AGENT_COLOR: Record<AgentKey, string> = {
  triage: "#38bdf8",
  correlation: "#a78bfa",
  investigation: "#fbbf24",
  evidence: "#34d399",
  graph: "#22d3ee",
  mitre: "#f472b6",
  chain: "#c084fc",
  next_target: "#fb923c",
  verification: "#4ade80",
};

const AGENT_SHORT: Record<AgentKey, string> = {
  triage: "Triage",
  correlation: "Correlation",
  investigation: "Investigation",
  evidence: "Evidence",
  graph: "Graph",
  mitre: "MITRE",
  chain: "Chain",
  next_target: "Next Target",
  verification: "Verification",
};

function StepRow({
  step,
  investigation,
}: {
  step: AgentStep;
  investigation: Investigation;
}) {
  const [open, setOpen] = useState(false);
  const color = AGENT_COLOR[step.agent];
  const findings = step.finding_ids
    .map((id) => investigation.findings.find((f) => f.finding_id === id))
    .filter(Boolean);

  const expandable = step.tool_calls.length > 0 || findings.length > 0;

  return (
    <li className="relative pl-6">
      <span
        className="absolute left-[7px] top-2 h-2 w-2 rounded-full ring-2 ring-ink-900"
        style={{ backgroundColor: color }}
      />
      <button
        className={`w-full rounded px-2 py-1.5 text-left transition ${
          expandable ? "hover:bg-ink-800/60" : "cursor-default"
        }`}
        onClick={() => expandable && setOpen(!open)}
      >
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="font-mono text-[10px] text-slate-500">{timeOnly(step.at)}</span>
          <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color }}>
            {AGENT_SHORT[step.agent]}
          </span>
          <span className="text-[11px] text-slate-200">{step.action}</span>
          {step.tool_calls.length > 0 && (
            <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-600">
              {step.tool_calls.length} call{step.tool_calls.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
        {step.detail && (
          <p className="mt-0.5 text-[11px] leading-snug text-slate-400">{step.detail}</p>
        )}
      </button>

      {open && (
        <div className="mb-2 ml-2 space-y-2 border-l border-ink-700 pl-3">
          {step.tool_calls.map((call) => (
            <div key={call.call_id} className="text-[10px]">
              <p className="font-mono text-slate-300">
                {call.tool}
                <span className="text-slate-600">
                  (
                  {Object.entries(call.arguments)
                    .map(([key, value]) => `${key}=${String(value)}`)
                    .join(", ")}
                  )
                </span>
              </p>
              <p className="text-slate-500">
                {call.result_summary}
                {call.result_count > 0 && (
                  <span className="text-slate-600"> &middot; {call.result_count} row(s)</span>
                )}
              </p>
            </div>
          ))}
          {findings.map((finding) => (
            <p key={finding!.finding_id} className="text-[10px] text-emerald-300">
              Finding: {finding!.title}{" "}
              <span className="text-slate-500">
                ({Math.round(finding!.confidence * 100)}% confidence)
              </span>
            </p>
          ))}
        </div>
      )}
    </li>
  );
}

export function AgentTimeline({ investigation }: { investigation: Investigation | null }) {
  const [filter, setFilter] = useState<AgentKey | "all">("all");

  if (!investigation || investigation.steps.length === 0) {
    return (
      <div className="panel px-4 py-5 text-center text-xs text-slate-500">
        The agent reasoning timeline appears once an investigation is running.
      </div>
    );
  }

  const agents = [...new Set(investigation.steps.map((s) => s.agent))];
  const steps =
    filter === "all"
      ? investigation.steps
      : investigation.steps.filter((s) => s.agent === filter);

  return (
    <div className="panel">
      <div className="panel-header flex-wrap">
        <div className="flex items-center gap-2">
          <p className="panel-title">Agent reasoning timeline</p>
          <span className="font-mono text-[10px] text-slate-500">
            {investigation.steps.length} steps
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <button
            className={`chip border-ink-600 ${
              filter === "all" ? "bg-ink-700 text-slate-200" : "bg-ink-850 text-slate-500"
            }`}
            onClick={() => setFilter("all")}
          >
            all
          </button>
          {agents.map((agent) => (
            <button
              key={agent}
              className={`chip border-ink-600 ${
                filter === agent ? "bg-ink-700 text-slate-200" : "bg-ink-850 text-slate-500"
              }`}
              onClick={() => setFilter(agent)}
            >
              {AGENT_SHORT[agent]}
            </button>
          ))}
        </div>
      </div>

      <div className="max-h-[320px] overflow-auto px-3 py-2">
        <ul className="relative space-y-0.5">
          <span className="absolute bottom-2 left-[11px] top-2 w-px bg-ink-700" aria-hidden />
          {steps.map((step) => (
            <StepRow key={step.step_id} step={step} investigation={investigation} />
          ))}
        </ul>
      </div>
    </div>
  );
}
