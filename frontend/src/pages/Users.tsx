/** Users page: identities, their entitlements, and whether a chain involves them. */

import { api } from "../lib/api";
import { dateTime } from "../lib/format";
import { useApi } from "../lib/useApi";

export function Users() {
  const users = useApi(() => api.users(), [], 5000);
  const rows = users.data ?? [];

  return (
    <div className="space-y-3 p-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-slate-100">Users</h1>
        <p className="mt-0.5 text-xs text-slate-500">
          Entitlements come from the environment inventory; they are what makes the next-target
          prediction explainable.
        </p>
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">Account</th>
                <th className="px-3 py-2 font-semibold">Status</th>
                <th className="px-3 py-2 font-semibold">Department</th>
                <th className="px-3 py-2 font-semibold">Privilege</th>
                <th className="px-3 py-2 font-semibold">Groups</th>
                <th className="px-3 py-2 font-semibold">Entitled hosts</th>
                <th className="px-3 py-2 font-semibold">Hosts observed</th>
                <th className="px-3 py-2 font-semibold">Events</th>
                <th className="px-3 py-2 font-semibold">Last activity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {rows.map((user) => (
                <tr key={user.name} className="row-hover">
                  <td className="whitespace-nowrap px-3 py-2">
                    <span className="font-mono font-semibold text-slate-100">{user.name}</span>
                    {user.is_privileged && (
                      <span className="chip ml-2 border-orange-500/50 bg-orange-500/10 text-orange-300">
                        privileged
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {user.compromised ? (
                      <span className="chip border-rose-500/50 bg-rose-500/10 text-rose-300">
                        compromised
                      </span>
                    ) : (
                      <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
                        clean
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-400">{user.department ?? "-"}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1 w-14 overflow-hidden rounded-full bg-ink-700">
                        <div
                          className="h-full rounded-full bg-orange-400/70"
                          style={{ width: `${user.privilege * 100}%` }}
                        />
                      </div>
                      <span className="font-mono text-[10px] text-slate-500">
                        {user.privilege.toFixed(1)}
                      </span>
                    </div>
                  </td>
                  <td className="max-w-[170px] truncate px-3 py-2 text-slate-500">
                    {user.groups.join(", ") || "-"}
                  </td>
                  <td className="max-w-[200px] truncate px-3 py-2 font-mono text-slate-400">
                    {user.accessible_hosts.join(", ") || "-"}
                  </td>
                  <td className="max-w-[180px] truncate px-3 py-2 font-mono text-slate-400">
                    {user.hosts_observed.join(", ") || "-"}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-400">
                    {user.event_count}
                    {user.failed_logons > 0 && (
                      <span className="ml-1 text-amber-400">({user.failed_logons} failed)</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-slate-500">
                    {user.last_seen ? dateTime(user.last_seen) : "-"}
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
