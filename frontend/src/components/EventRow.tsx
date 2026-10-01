/**
 * One row of the event table, expandable to show why it was flagged and the
 * original vendor record it came from.
 */

import { useState } from "react";

import { findings, plainTags, timeOnly } from "../lib/format";
import { SeverityBadge } from "./Badges";
import type { NormalizedEvent } from "../types";

export function EventRow({ event }: { event: NormalizedEvent }) {
  const [open, setOpen] = useState(false);
  const reasons = findings(event.tags);

  return (
    <>
      <tr className="row-hover cursor-pointer" onClick={() => setOpen(!open)}>
        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-400">
          {timeOnly(event.timestamp)}
        </td>
        <td className="px-3 py-1.5">
          <span className="chip border-ink-600 bg-ink-800 !normal-case text-slate-400">
            {event.event_type}
          </span>
        </td>
        <td className="px-3 py-1.5 font-mono text-slate-200">{event.action}</td>
        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-400">
          {event.source_host ?? "-"}
          {event.destination_host && event.destination_host !== event.source_host
            ? " → " + event.destination_host
            : ""}
        </td>
        <td className="px-3 py-1.5 font-mono text-slate-400">{event.user ?? "-"}</td>
        <td className="max-w-[320px] truncate px-3 py-1.5 font-mono text-[10px] text-slate-500">
          {event.process ?? event.domain ?? event.file_name ?? ""}
        </td>
        <td className="px-3 py-1.5">
          <SeverityBadge value={event.severity} />
        </td>
      </tr>

      {open && (
        <tr className="bg-ink-850/60">
          <td colSpan={7} className="px-6 py-3">
            <div className="grid gap-3 lg:grid-cols-2">
              <div className="space-y-1.5">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Why this was flagged
                </p>
                {reasons.length === 0 ? (
                  <p className="text-[11px] text-slate-500">
                    Not flagged. Kept for correlation context only.
                  </p>
                ) : (
                  <ul className="space-y-0.5">
                    {reasons.map((reason, index) => (
                      <li key={index} className="flex gap-2 text-[11px] text-slate-300">
                        <span className="text-amber-400">!</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                )}
                <div className="flex flex-wrap gap-1 pt-1">
                  {plainTags(event.tags).map((tag) => (
                    <span
                      key={tag}
                      className="chip border-ink-600 bg-ink-800 font-mono !normal-case text-slate-500"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
                {event.command_line && (
                  <p className="mt-1 break-all rounded border border-ink-700 bg-ink-900 px-2 py-1.5 font-mono text-[10px] text-slate-400">
                    {event.command_line}
                  </p>
                )}
              </div>

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Original record ({event.source_log})
                </p>
                <pre className="mt-1 max-h-40 overflow-auto rounded border border-ink-700 bg-ink-900 px-2 py-1.5 font-mono text-[10px] leading-relaxed text-slate-400">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
