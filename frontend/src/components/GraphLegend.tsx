/** Legend for the attack graph: what a shape, a colour and a line style mean. */

import { ASSURANCE_LABEL, ASSURANCE_MEANING, STATE_COLOR, STATE_LABEL } from "../lib/theme";
import type { Assurance, NodeState } from "../types";

const STATES: NodeState[] = [
  "current_position",
  "compromised",
  "suspicious",
  "potential_target",
  "normal",
];

const LINES: { assurance: Assurance; style: string }[] = [
  { assurance: "observed", style: "border-t-2 border-solid border-[#3a4a72]" },
  { assurance: "correlated", style: "border-t-2 border-dashed border-[#a78bfa]" },
  { assurance: "inferred", style: "border-t-[3px] border-solid border-[#fb923c]" },
  { assurance: "predicted", style: "border-t-[3px] border-dotted border-[#f472b6]" },
];

const SHAPES = [
  { label: "Host", className: "h-3 w-5 rounded-sm" },
  { label: "User", className: "h-4 w-4 rounded-full" },
  { label: "Process", className: "h-4 w-4 rotate-45 rounded-sm" },
  { label: "Domain", className: "h-3.5 w-3.5 rotate-45" },
];

export function GraphLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-ink-700/70 px-4 py-2 text-[10px]">
      <div className="flex items-center gap-2">
        <span className="font-semibold uppercase tracking-wider text-slate-500">State</span>
        {STATES.map((state) => (
          <span key={state} className="flex items-center gap-1 text-slate-400">
            <span
              className="h-2.5 w-2.5 rounded-sm border-2"
              style={{ borderColor: STATE_COLOR[state] }}
            />
            {STATE_LABEL[state]}
          </span>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <span className="font-semibold uppercase tracking-wider text-slate-500">Relationship</span>
        {LINES.map(({ assurance, style }) => (
          <span
            key={assurance}
            className="flex items-center gap-1 text-slate-400"
            title={ASSURANCE_MEANING[assurance]}
          >
            <span className={`inline-block w-5 ${style}`} />
            {ASSURANCE_LABEL[assurance]}
          </span>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <span className="font-semibold uppercase tracking-wider text-slate-500">Entity</span>
        {SHAPES.map((shape) => (
          <span key={shape.label} className="flex items-center gap-1 text-slate-400">
            <span className={`border-2 border-slate-500 ${shape.className}`} />
            {shape.label}
          </span>
        ))}
      </div>
    </div>
  );
}
