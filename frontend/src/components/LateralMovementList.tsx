/** Lateral-movement detections with the rule clauses that fired. */

import { timeOnly } from "../lib/format";
import { AssuranceBadge } from "./Badges";
import type { LateralMovement } from "../types";

export function LateralMovementList({ movements }: { movements: LateralMovement[] }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">Lateral movement</p>
        <AssuranceBadge value="inferred" />
      </div>
      <div className="divide-y divide-ink-700/60">
        {movements.length === 0 && (
          <p className="px-4 py-3 text-xs text-slate-500">No lateral movement detected yet.</p>
        )}
        {movements.map((movement) => (
          <details key={movement.movement_id} className="px-4 py-2.5">
            <summary className="flex cursor-pointer items-center justify-between gap-2">
              <span className="font-mono text-xs text-slate-200">
                {movement.source_host}
                <span className="px-1 text-orange-300">&rarr;</span>
                {movement.destination_host}
              </span>
              <span className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-slate-500">{movement.method}</span>
                <span className="font-mono text-[10px] text-orange-300">
                  {movement.correlation_score.toFixed(2)}
                </span>
              </span>
            </summary>
            <div className="mt-2 space-y-1.5">
              <p className="text-[11px] leading-relaxed text-slate-400">{movement.explanation}</p>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Rule evaluation
              </p>
              <ol className="space-y-1">
                {movement.rule_evaluation.map((clause, index) => (
                  <li key={index} className="flex gap-2 text-[11px] text-slate-400">
                    <span className="font-mono text-emerald-400">PASS</span>
                    <span>{clause}</span>
                  </li>
                ))}
              </ol>
              <p className="font-mono text-[10px] text-slate-500">
                {timeOnly(movement.timestamp)} &middot; evidence {movement.event_id}
              </p>
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}
