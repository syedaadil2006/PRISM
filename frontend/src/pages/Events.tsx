/**
 * Events page: the normalized stream, plus the log-ingestion entry point.
 *
 * Deliberately the least prominent page. The product argument is that an
 * analyst should rarely need to work at this level.
 */

import { useRef, useState } from "react";

import { AssuranceBadge } from "../components/Badges";
import { EventRow } from "../components/EventRow";
import { api } from "../lib/api";
import { useApi } from "../lib/useApi";
import type { IngestSummary } from "../types";

const TYPES = [
  { value: "", label: "All sources" },
  { value: "authentication", label: "Authentication" },
  { value: "dns", label: "DNS" },
  { value: "endpoint", label: "Endpoint" },
  { value: "network", label: "Network (firewall)" },
  { value: "cloud", label: "Cloud" },
];

export function Events() {
  const [eventType, setEventType] = useState("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [summary, setSummary] = useState<IngestSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const events = useApi(
    () => api.events({ event_type: eventType, suspicious_only: suspiciousOnly, limit: 1000 }),
    [eventType, suspiciousOnly, summary],
    4000,
  );

  const rows = (events.data ?? []).filter((event) => {
    if (!search) return true;
    const needle = search.toLowerCase();
    return [
      event.action,
      event.user,
      event.source_host,
      event.destination_host,
      event.process,
      event.domain,
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(needle));
  });

  const upload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setBusy(true);
    try {
      setSummary(await api.ingest(Array.from(files)));
    } catch (cause) {
      setSummary({
        accepted: 0,
        rejected: 0,
        total_events: 0,
        errors: [cause instanceof Error ? cause.message : "upload failed"],
        sources: [],
      });
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  const reload = async () => {
    setBusy(true);
    try {
      setSummary(await api.resetLogs());
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 p-4">
      <div className="panel">
        <div className="panel-header flex-wrap">
          <div className="flex flex-wrap items-center gap-2">
            <p className="panel-title">Normalized events</p>
            <AssuranceBadge value="observed" />
            <span className="font-mono text-[10px] text-slate-500">
              {rows.length} of {events.data?.length ?? 0}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter host, account, process..."
              className="w-52 rounded-md border border-ink-600 bg-ink-850 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
            />
            <select
              value={eventType}
              onChange={(event) => setEventType(event.target.value)}
              className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              {TYPES.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
            <label className="flex cursor-pointer items-center gap-1.5 text-[10px] text-slate-400">
              <input
                type="checkbox"
                className="h-3 w-3 accent-sky-400"
                checked={suspiciousOnly}
                onChange={(event) => setSuspiciousOnly(event.target.checked)}
              />
              Flagged only
            </label>
            <input
              ref={fileInput}
              type="file"
              multiple
              accept=".csv,.json,.jsonl,.ndjson,.log"
              className="hidden"
              onChange={(event) => void upload(event.target.files)}
            />
            <button
              className="btn btn-primary"
              disabled={busy}
              onClick={() => fileInput.current?.click()}
            >
              {busy ? "Working..." : "Ingest logs"}
            </button>
            <button className="btn" disabled={busy} onClick={() => void reload()}>
              Reload dataset
            </button>
          </div>
        </div>

        {summary && (
          <div className="border-b border-ink-700/70 px-4 py-2 text-[11px]">
            <span className="text-emerald-300">{summary.accepted} events accepted</span>
            {summary.rejected > 0 && (
              <span className="ml-3 text-amber-300">{summary.rejected} rejected</span>
            )}
            <span className="ml-3 text-slate-500">{summary.total_events} total</span>
            {summary.errors.slice(0, 3).map((error, index) => (
              <p key={index} className="mt-0.5 font-mono text-[10px] text-rose-300">
                {error}
              </p>
            ))}
          </div>
        )}

        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">Time</th>
                <th className="px-3 py-2 font-semibold">Source</th>
                <th className="px-3 py-2 font-semibold">Action</th>
                <th className="px-3 py-2 font-semibold">Host</th>
                <th className="px-3 py-2 font-semibold">Account</th>
                <th className="px-3 py-2 font-semibold">Detail</th>
                <th className="px-3 py-2 font-semibold">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {rows.map((event) => (
                <EventRow key={event.event_id} event={event} />
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <p className="px-4 py-6 text-center text-xs text-slate-500">
              No events match these filters.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
