/**
 * One potential next target, with the full scoring breakdown.
 *
 * A prediction is only useful if the analyst can see every point that produced
 * it, so each factor shows its own contribution and its own sentence.
 */

import type { TargetPrediction } from "../types";

export function PredictionCard({
  prediction,
  defaultOpen = false,
}: {
  prediction: TargetPrediction;
  defaultOpen?: boolean;
}) {
  return (
    <details
      open={defaultOpen}
      className="rounded-md border border-pink-500/30 bg-pink-500/[0.06]"
    >
      <summary className="flex cursor-pointer items-center justify-between gap-2 px-3 py-2">
        <span className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-pink-200">{prediction.host}</span>
          {prediction.is_critical_infrastructure && (
            <span className="chip border-rose-500/50 bg-rose-500/10 text-rose-300">critical</span>
          )}
        </span>
        <span className="font-mono text-sm font-semibold text-pink-200">
          {Math.round(prediction.score)}
          <span className="text-[10px] text-pink-400/70">/100</span>
        </span>
      </summary>

      <div className="space-y-2 border-t border-pink-500/20 px-3 py-2">
        <p className="text-[11px] leading-relaxed text-slate-400">{prediction.narrative}</p>

        <div className="space-y-1.5">
          {prediction.factors.map((factor) => (
            <div key={factor.name}>
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-[11px] text-slate-300">{factor.name}</span>
                <span className="font-mono text-[10px] text-slate-400">
                  +{factor.points.toFixed(1)}
                  <span className="text-slate-600"> / {factor.max_points.toFixed(0)}</span>
                </span>
              </div>
              <div className="mt-0.5 h-1 overflow-hidden rounded-full bg-ink-700">
                <div
                  className="h-full rounded-full bg-pink-400/70"
                  style={{ width: `${Math.min(100, (factor.points / factor.max_points) * 100)}%` }}
                />
              </div>
              <p className="mt-0.5 text-[10px] leading-snug text-slate-500">{factor.detail}</p>
            </div>
          ))}
        </div>

        <p className="border-t border-pink-500/20 pt-2 font-mono text-[10px] text-slate-500">
          raw {prediction.raw_score.toFixed(1)} normalised to {prediction.score.toFixed(1)}/100
        </p>
      </div>
    </details>
  );
}
