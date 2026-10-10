/**
 * Attack Chains page: the chain, its evidence, and the correlations that built
 * it, side by side. This is the page that answers "why are these one incident?".
 */

import { useState } from "react";

import { AttackChainList } from "../components/AttackChainList";
import { ChainFeedback, detectionFindings } from "../components/ChainFeedback";
import { AssuranceBadge, SeverityBadge } from "../components/Badges";
import { IntelPanel } from "../components/IntelPanel";
import { RootCausePanel } from "../components/RootCausePanel";
import { api } from "../lib/api";
import { relativeSeconds, timeOnly } from "../lib/format";
import { useApi } from "../lib/useApi";

export function AttackChains() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const chains = useApi(() => api.attacks(), [], 4000);
  const chainList = chains.data ?? [];
  const activeId = selectedId ?? chainList[0]?.attack_chain_id ?? null;
  const detail = useApi(
    () => (activeId ? api.attack(activeId) : Promise.resolve(null)),
    [activeId],
    4000,
  );

  const chain = detail.data?.chain ?? null;
  const events = detail.data?.events ?? [];
  const correlations = detail.data?.correlations ?? [];

  return (
    <div className="grid gap-3 p-4 xl:grid-cols-[300px_minmax(0,1fr)_340px]">
      <AttackChainList chains={chainList} selectedId={activeId} onSelect={setSelectedId} />

      <div className="space-y-3">
        <RootCausePanel chain={chain} />
        {chain && (
          <ChainFeedback
            chainId={chain.attack_chain_id}
            onChanged={() => {
              setSelectedId(null);
              void chains.refresh();
              void detail.refresh();
            }}
          />
        )}

        <div className="panel">
          <div className="panel-header">
            <p className="panel-title">Correlated evidence</p>
            <span className="font-mono text-[10px] text-slate-500">{events.length} events</span>
          </div>
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-semibold">Time</th>
                  <th className="px-3 py-2 font-semibold">Action</th>
                  <th className="px-3 py-2 font-semibold">Host</th>
                  <th className="px-3 py-2 font-semibold">Account</th>
                  <th className="px-3 py-2 font-semibold">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {events.map((event) => (
                  <tr key={event.event_id} className="row-hover">
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-400">
                      {timeOnly(event.timestamp)}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-slate-200">
                      {event.action}
                      {detectionFindings(event.tags).map((f) => (
                        <span
                          key={f.text}
                          title={f.text}
                          className={`ml-1.5 rounded px-1 py-0.5 font-sans text-[9px] ring-1 ${
                            f.kind === "Baseline"
                              ? "text-amber-300 ring-amber-500/30"
                              : "text-fuchsia-300 ring-fuchsia-500/30"
                          }`}
                        >
                          {f.kind}
                        </span>
                      ))}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-400">
                      {event.source_host ?? "-"}
                      {event.destination_host && event.destination_host !== event.source_host
                        ? ` → ${event.destination_host}`
                        : ""}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-slate-400">{event.user ?? "-"}</td>
                    <td className="px-3 py-1.5">
                      <SeverityBadge value={event.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <p className="panel-title">Why these events are one incident</p>
              <AssuranceBadge value="correlated" />
            </div>
            <span className="font-mono text-[10px] text-slate-500">{correlations.length} links</span>
          </div>
          <div className="max-h-[320px] divide-y divide-ink-800 overflow-auto">
            {correlations.slice(0, 40).map((link) => (
              <div
                key={`${link.source_event_id}-${link.target_event_id}`}
                className="px-4 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-slate-300">
                    {link.source_event_id}
                    <span className="px-1 text-slate-600">&harr;</span>
                    {link.target_event_id}
                  </span>
                  <span className="flex items-center gap-2 font-mono text-[10px]">
                    <span className="text-slate-500">
                      {relativeSeconds(link.time_delta_seconds)} apart
                    </span>
                    <span className="text-violet-300">{link.score.toFixed(2)}</span>
                  </span>
                </div>
                <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                  {link.factors.map((factor) => (
                    <li key={factor.name} className="text-[10px] text-slate-500">
                      <span className="font-mono text-slate-400">+{factor.weight.toFixed(2)}</span>{" "}
                      {factor.detail}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {correlations.length > 40 && (
              <p className="px-4 py-2 text-[10px] text-slate-500">
                Showing the 40 highest-scoring links of {correlations.length}.
              </p>
            )}
          </div>
        </div>
      </div>

      <IntelPanel chain={chain} />
    </div>
  );
}
