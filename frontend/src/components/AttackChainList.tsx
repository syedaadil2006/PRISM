/** Compact, selectable list of detected attack chains. */

import { timeOnly } from "../lib/format";
import { tacticColor } from "../lib/theme";
import { SeverityBadge } from "./Badges";
import type { AttackChain } from "../types";

export function AttackChainList({
  chains,
  selectedId,
  onSelect,
}: {
  chains: AttackChain[];
  selectedId: string | null;
  onSelect: (chainId: string) => void;
}) {
  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">Attack chains</p>
        <span className="font-mono text-[10px] text-slate-500">{chains.length}</span>
      </div>
      <div className="divide-y divide-ink-700/60">
        {chains.length === 0 && (
          <p className="px-4 py-4 text-xs text-slate-500">
            Nothing correlated yet. Events that do not form a chain stay out of this list on purpose.
          </p>
        )}
        {chains.map((chain) => {
          const active = chain.attack_chain_id === selectedId;
          return (
            <button
              key={chain.attack_chain_id}
              onClick={() => onSelect(chain.attack_chain_id)}
              className={`row-hover block w-full px-4 py-2.5 text-left ${
                active ? "bg-ink-800/80" : ""
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-100">
                  {chain.attack_chain_id}
                </span>
                <SeverityBadge value={chain.severity} />
              </div>
              <p className="mt-1 font-mono text-[11px] text-slate-400">
                {chain.initial_host ?? "?"}
                <span className="px-1 text-slate-600">&rarr;</span>
                <span className="text-cyan-300">{chain.current_host ?? "?"}</span>
              </p>
              <div className="mt-1 flex items-center justify-between gap-2 text-[10px]">
                <span style={{ color: tacticColor(chain.current_stage) }}>{chain.current_stage}</span>
                <span className="font-mono text-slate-500">
                  {chain.event_count} events &middot; {timeOnly(chain.last_seen)}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
