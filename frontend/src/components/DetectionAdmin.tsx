/** Admin: detection content (Sigma rules, threat intel, baselines) and analyst suppressions. */

import { useState } from "react";

import { api, ApiError } from "../lib/api";
import { dateTime } from "../lib/format";
import { useApi } from "../lib/useApi";

const BUTTON =
  "rounded px-2 py-1 text-[11px] text-slate-300 ring-1 ring-ink-600 transition hover:text-white disabled:opacity-40";

export function DetectionAdmin() {
  const info = useApi(() => api.detection(), [], 15000);
  const feedback = useApi(() => api.feedback(), [], 10000);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [showRules, setShowRules] = useState(false);

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage(done);
      void info.refresh();
      void feedback.refresh();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : "Could not reach PRISM.");
    } finally {
      setBusy(false);
    }
  }

  const data = info.data;
  const suppressions = feedback.data?.suppressions ?? [];

  return (
    <section className="panel space-y-3 p-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-semibold text-slate-200">Detection</h2>
        <button
          type="button"
          disabled={busy}
          className={BUTTON}
          onClick={() => void run(() => api.reloadDetection(), "Rules and indicator files re-read; all events re-checked.")}
        >
          Reload rules and intel
        </button>
        {message && <span className="text-[11px] text-slate-400">{message}</span>}
      </div>

      {data && (
        <div className="grid gap-2 text-[11px] sm:grid-cols-3">
          <div className="rounded-md bg-ink-850 p-2.5">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Sigma rules</p>
            <p className="mt-1 text-slate-200">
              {data.sigma.loaded} loaded{data.sigma.skipped ? `, ${data.sigma.skipped} skipped` : ""}
            </p>
            <button type="button" className="mt-1 text-[10px] text-sky-300" onClick={() => setShowRules(!showRules)}>
              {showRules ? "Hide list" : "Show list"}
            </button>
          </div>
          <div className="rounded-md bg-ink-850 p-2.5">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Threat intel</p>
            <p className="mt-1 text-slate-200">
              {data.intel.indicators} indicators ({data.intel.domains} domains, {data.intel.ips} IPs,{" "}
              {data.intel.hashes} hashes, {data.intel.urls} URLs)
            </p>
            <p className="mt-1 text-[10px] text-slate-500">
              Files in backend\data\intel (STIX 2.1, CSV or one per line)
            </p>
          </div>
          <div className="rounded-md bg-ink-850 p-2.5">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Behaviour baselines</p>
            <p className="mt-1 text-slate-200">
              {data.baseline.enabled
                ? `On: after ${data.baseline.min_history} events over ${data.baseline.learning_hours} h`
                : "Off"}
            </p>
          </div>
        </div>
      )}

      {showRules && data && (
        <div className="max-h-[260px] overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-1.5 font-semibold">Rule</th>
                <th className="px-3 py-1.5 font-semibold">Level</th>
                <th className="px-3 py-1.5 font-semibold">ATT&CK</th>
                <th className="px-3 py-1.5 font-semibold">Log source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800 text-slate-300">
              {data.rules.map((rule) => (
                <tr key={rule.id}>
                  <td className="px-3 py-1.5">{rule.title}</td>
                  <td className="px-3 py-1.5">{rule.level}</td>
                  <td className="px-3 py-1.5 font-mono">{rule.techniques.join(", ")}</td>
                  <td className="px-3 py-1.5 text-slate-500">{rule.logsource}</td>
                </tr>
              ))}
              {data.skipped_rules.slice(0, 20).map((skip) => (
                <tr key={skip.file + skip.reason} className="text-slate-500">
                  <td className="px-3 py-1.5" colSpan={4}>
                    Skipped {skip.file.replace(/\\/g, "/").split("/").pop()}: {skip.reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div>
        <p className="mb-1.5 text-[11px] text-slate-400">
          False-positive suppressions ({suppressions.length}). Matching activity is kept in the event list but no
          longer raises attack chains.
        </p>
        {suppressions.length > 0 && (
          <div className="max-h-[260px] overflow-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-1.5 font-semibold">Activity</th>
                  <th className="px-3 py-1.5 font-semibold">Computer / account</th>
                  <th className="px-3 py-1.5 font-semibold">From</th>
                  <th className="px-3 py-1.5 font-semibold">By</th>
                  <th className="px-3 py-1.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800 text-slate-300">
                {suppressions.map((s) => (
                  <tr key={s.id}>
                    <td className="px-3 py-1.5 font-mono">
                      {s.action} {s.indicator}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-slate-400">
                      {s.host || "-"} / {s.user || "-"}
                    </td>
                    <td className="px-3 py-1.5 text-slate-400">
                      {s.chain_id}
                      {s.note ? `: ${s.note}` : ""}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-slate-500">
                      {s.analyst}, {dateTime(s.created_at)}
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      <button
                        type="button"
                        disabled={busy}
                        className={BUTTON}
                        onClick={() => void run(() => api.deleteSuppression(s.id), "Suppression removed.")}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
