/**
 * MITRE ATT&CK page.
 *
 * Techniques are grouped by tactic in kill-chain order, and every technique can
 * be expanded to the individual events that justified it. Nothing is assigned
 * without evidence.
 */

import { AssuranceBadge, ConfidenceBadge } from "../components/Badges";
import { api } from "../lib/api";
import { tacticColor } from "../lib/theme";
import { useApi } from "../lib/useApi";

export function Mitre() {
  const matrix = useApi(() => api.mitre(), [], 5000);
  const tactics = matrix.data ?? [];

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">
            MITRE ATT&amp;CK coverage
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            Observed techniques in kill-chain order. Expand any technique to see the source events
            behind it.
          </p>
        </div>
        <AssuranceBadge value="observed" />
      </div>

      {tactics.length === 0 && (
        <div className="panel px-4 py-6 text-center text-xs text-slate-500">
          No techniques observed yet.
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-2 2xl:grid-cols-3">
        {tactics.map((tactic) => (
          <div key={tactic.tactic_id} className="panel">
            <div
              className="panel-header"
              style={{ borderBottomColor: tacticColor(tactic.tactic) + "44" }}
            >
              <div className="flex items-center gap-2">
                <span
                  className="h-2.5 w-2.5 rounded-sm"
                  style={{ backgroundColor: tacticColor(tactic.tactic) }}
                />
                <p className="text-xs font-semibold text-slate-100">{tactic.tactic}</p>
                <span className="font-mono text-[10px] text-slate-500">{tactic.tactic_id}</span>
              </div>
              <span className="font-mono text-[10px] text-slate-500">
                {tactic.techniques.length}
              </span>
            </div>

            <div className="divide-y divide-ink-800">
              {tactic.techniques.map((technique) => (
                <details key={technique.technique_id} className="px-4 py-2">
                  <summary className="flex cursor-pointer items-start justify-between gap-2">
                    <span>
                      <span className="font-mono text-[11px] font-semibold text-slate-100">
                        {technique.technique_id}
                      </span>
                      <span className="ml-2 text-[11px] text-slate-400">
                        {technique.technique_name}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-1.5">
                      <span className="font-mono text-[10px] text-slate-500">
                        {technique.occurrences}x
                      </span>
                      <ConfidenceBadge value={technique.confidence} />
                    </span>
                  </summary>

                  <div className="mt-2 space-y-2">
                    {technique.evidence.slice(0, 6).map((item, index) => (
                      <div
                        key={item.event_id + "-" + index}
                        className="rounded border border-ink-700 bg-ink-850 px-2.5 py-1.5"
                      >
                        <p className="font-mono text-[10px] text-slate-500">
                          source event {item.event_id}
                        </p>
                        <p className="mt-0.5 font-mono text-[11px] leading-relaxed text-slate-300">
                          {item.evidence}
                        </p>
                        <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
                          {item.explanation}
                        </p>
                      </div>
                    ))}
                    {technique.evidence.length > 6 && (
                      <p className="text-[10px] text-slate-500">
                        and {technique.evidence.length - 6} more matching events
                      </p>
                    )}
                    {technique.reference && (
                      <a
                        href={technique.reference}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-block text-[10px] text-sky-400 hover:text-sky-300"
                      >
                        View on attack.mitre.org
                      </a>
                    )}
                  </div>
                </details>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
