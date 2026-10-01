/**
 * Relationship inspector.
 *
 * Whatever the analyst clicks in the graph, this shows the backend's own record
 * for it -- including the source event ids, so every claim stays traceable.
 */

import { AssuranceBadge } from "./Badges";
import { STATE_LABEL } from "../lib/theme";
import type { GraphSelection } from "./AttackGraph";

function Rows({ entries }: { entries: [string, unknown][] }) {
  const visible = entries.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (visible.length === 0) return null;
  return (
    <dl className="space-y-1">
      {visible.map(([key, value]) => (
        <div key={key} className="grid grid-cols-[110px_1fr] gap-2">
          <dt className="truncate text-[10px] uppercase tracking-wider text-slate-500">
            {key.replace(/_/g, " ")}
          </dt>
          <dd className="break-words font-mono text-[11px] text-slate-300">
            {Array.isArray(value) ? value.join(", ") : String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function DetailDrawer({
  selection,
  onClose,
}: {
  selection: GraphSelection | null;
  onClose: () => void;
}) {
  if (!selection) return null;

  const node = selection.node;
  const edge = selection.edge;

  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">
          {node ? `${node.kind} detail` : "Relationship detail"}
        </p>
        <div className="flex items-center gap-2">
          <AssuranceBadge value={(node?.assurance ?? edge?.assurance ?? "observed") as never} />
          <button className="btn !px-2 !py-0.5 text-[10px]" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      <div className="space-y-2 px-4 py-3">
        {node && (
          <>
            <p className="font-mono text-sm font-semibold text-slate-100">{node.label}</p>
            <p className="text-[11px] text-slate-500">
              {STATE_LABEL[node.state]}
              {node.attack_chain_ids.length > 0 && ` - part of ${node.attack_chain_ids.join(", ")}`}
            </p>
            <Rows entries={Object.entries(node.metadata)} />
          </>
        )}

        {edge && (
          <>
            <p className="font-mono text-sm font-semibold text-slate-100">{edge.label}</p>
            <p className="font-mono text-[11px] text-slate-400">
              {edge.source.split(":").slice(1).join(":")}
              <span className="px-1 text-slate-600">&rarr;</span>
              {edge.target.split(":").slice(1).join(":")}
            </p>
            <Rows
              entries={[
                ["kind", edge.kind],
                ["predicted", edge.predicted ? "yes" : "no"],
                ["chains", edge.attack_chain_ids],
                ["source events", edge.event_ids],
                ...Object.entries(edge.metadata),
              ]}
            />
          </>
        )}
      </div>
    </div>
  );
}
