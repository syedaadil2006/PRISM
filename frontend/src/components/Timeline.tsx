/**
 * The horizontal attack timeline.
 *
 * Each marker is one (tactic, host) stage from the backend. Clicking a stage
 * spotlights the matching nodes in the graph.
 */

import { timeOnly } from "../lib/format";
import { tacticColor } from "../lib/theme";
import type { AttackChain } from "../types";

interface Props {
  chain: AttackChain | null;
  selectedStage: number | null;
  onSelectStage: (order: number | null) => void;
}

export function Timeline({ chain, selectedStage, onSelectStage }: Props) {
  if (!chain || chain.stages.length === 0) {
    return (
      <div className="panel px-4 py-6 text-center text-xs text-slate-500">
        The attack timeline appears as soon as events correlate into a chain.
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="flex items-center gap-3">
          <p className="panel-title">Attack timeline</p>
          <span className="font-mono text-[11px] text-slate-500">
            {timeOnly(chain.start_time)} to {timeOnly(chain.last_seen)}
          </span>
        </div>
        {selectedStage !== null && (
          <button className="btn !py-1 text-[10px]" onClick={() => onSelectStage(null)}>
            Clear highlight
          </button>
        )}
      </div>

      <div className="overflow-x-auto px-4 py-4">
        <div className="flex min-w-max items-start gap-0">
          {chain.stages.map((stage, index) => {
            const active = selectedStage === stage.order;
            const color = tacticColor(stage.tactic);
            return (
              <div key={stage.order} className="flex items-start">
                <button
                  onClick={() => onSelectStage(active ? null : stage.order)}
                  className={`group relative w-[136px] rounded-md border px-2 py-2 text-left transition ${
                    active
                      ? "border-slate-200 bg-ink-700"
                      : "border-ink-700 bg-ink-850 hover:border-ink-500"
                  }`}
                  title={stage.description}
                >
                  <span className="font-mono text-[10px] text-slate-500">
                    {timeOnly(stage.timestamp)}
                  </span>
                  <span
                    className="mt-1 block text-[11px] font-semibold leading-tight"
                    style={{ color }}
                  >
                    {stage.tactic}
                  </span>
                  <span className="mt-0.5 block truncate font-mono text-[10px] text-slate-400">
                    {stage.host ?? "unknown host"}
                  </span>
                  <span
                    className="absolute inset-x-0 bottom-0 h-0.5 rounded-b"
                    style={{ backgroundColor: color, opacity: active ? 1 : 0.5 }}
                  />
                </button>
                {index < chain.stages.length - 1 && (
                  <span className="mt-6 px-1 text-slate-600" aria-hidden>
                    &rarr;
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
