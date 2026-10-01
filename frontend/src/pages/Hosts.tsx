/** Hosts page: inventory joined with what was observed on each machine. */

import { StateBadge } from "../components/Badges";
import { api } from "../lib/api";
import { dateTime } from "../lib/format";
import { useApi } from "../lib/useApi";

export function Hosts() {
  const hosts = useApi(() => api.hosts(), [], 5000);
  const rows = hosts.data ?? [];

  return (
    <div className="space-y-3 p-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-slate-100">Hosts</h1>
        <p className="mt-0.5 text-xs text-slate-500">
          Asset context from the environment inventory, with the state PRISM assigned to each
          host.
        </p>
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">Host</th>
                <th className="px-3 py-2 font-semibold">State</th>
                <th className="px-3 py-2 font-semibold">Role</th>
                <th className="px-3 py-2 font-semibold">Address</th>
                <th className="px-3 py-2 font-semibold">Criticality</th>
                <th className="px-3 py-2 font-semibold">Events</th>
                <th className="px-3 py-2 font-semibold">Accounts seen</th>
                <th className="px-3 py-2 font-semibold">Target score</th>
                <th className="px-3 py-2 font-semibold">Last activity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {rows.map((host) => (
                <tr key={host.name} className="row-hover">
                  <td className="whitespace-nowrap px-3 py-2">
                    <span className="font-mono font-semibold text-slate-100">{host.name}</span>
                    {host.is_critical_infrastructure && (
                      <span className="chip ml-2 border-rose-500/50 bg-rose-500/10 text-rose-300">
                        critical
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <StateBadge value={host.state} />
                  </td>
                  <td className="px-3 py-2 text-slate-400">{host.role}</td>
                  <td className="px-3 py-2 font-mono text-slate-500">{host.ip ?? "-"}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1 w-14 overflow-hidden rounded-full bg-ink-700">
                        <div
                          className="h-full rounded-full bg-sky-400/70"
                          style={{ width: `${host.criticality * 100}%` }}
                        />
                      </div>
                      <span className="font-mono text-[10px] text-slate-500">
                        {host.criticality.toFixed(1)}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-400">
                    {host.event_count}
                    {host.suspicious_event_count > 0 && (
                      <span className="ml-1 text-amber-400">({host.suspicious_event_count})</span>
                    )}
                  </td>
                  <td className="max-w-[180px] truncate px-3 py-2 font-mono text-slate-500">
                    {host.users.join(", ") || "-"}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {host.prediction_score != null ? (
                      <span className="text-pink-300">{Math.round(host.prediction_score)}/100</span>
                    ) : (
                      <span className="text-slate-600">-</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-slate-500">
                    {host.last_seen ? dateTime(host.last_seen) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
