/**
 * The root-cause panel.
 *
 * This is where evidence and inference are pulled apart explicitly, because an
 * analyst who cannot tell them apart will not trust either.
 */

import { AssuranceBadge } from "./Badges";
import type { AttackChain } from "../types";

const ASSURANCE_WORDS = ["OBSERVED", "CORRELATED", "INFERRED", "PREDICTED"] as const;

/** Render a note with its assurance keyword emphasised. */
function Note({ text }: { text: string }) {
  const word = ASSURANCE_WORDS.find((candidate) => text.includes(candidate));
  if (!word) return <span>{text}</span>;
  const [before, after] = text.split(word);
  const color = {
    OBSERVED: "text-sky-300",
    CORRELATED: "text-violet-300",
    INFERRED: "text-orange-300",
    PREDICTED: "text-pink-300",
  }[word];
  return (
    <span>
      {before}
      <span className={`font-semibold ${color}`}>{word}</span>
      {after}
    </span>
  );
}

export function RootCausePanel({ chain }: { chain: AttackChain | null }) {
  const root = chain?.root_cause;
  if (!chain || !root) {
    return (
      <div className="panel px-4 py-6 text-xs text-slate-500">
        The root-cause narrative appears once a chain has been detected.
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <p className="panel-title">Root cause</p>
        <AssuranceBadge value="observed" />
      </div>

      <div className="space-y-3 px-4 py-3">
        <p className="text-sm leading-relaxed text-slate-300">
          This attack chain started on{" "}
          <span className="font-mono font-semibold text-rose-300">
            {root.initial_host ?? "an unknown host"}
          </span>
          {root.initial_user && (
            <>
              {" "}
              under the account{" "}
              <span className="font-mono font-semibold text-slate-100">{root.initial_user}</span>
            </>
          )}
          .
        </p>

        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            Initial evidence
          </p>
          <p className="mt-1 rounded border border-ink-700 bg-ink-850 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-300">
            {root.initial_evidence}
            {root.initial_event_id && (
              <span className="mt-1 block text-slate-500">source event {root.initial_event_id}</span>
            )}
          </p>
        </div>

        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            Observed progression
          </p>
          <ol className="mt-1 space-y-0.5">
            {root.observed_progression.map((step, index) => (
              <li key={index} className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
                <span className="w-4 text-right text-slate-600">{index + 1}</span>
                <span className="text-slate-600">{index === 0 ? "" : "↳"}</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded border border-cyan-500/30 bg-cyan-500/[0.06] px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-400/80">
              Current status
            </p>
            <p className="mt-0.5 font-mono text-xs text-cyan-200">{root.current_status}</p>
          </div>
          <div className="rounded border border-pink-500/30 bg-pink-500/[0.06] px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-pink-400/80">
              Potential next target
            </p>
            <p className="mt-0.5 font-mono text-xs text-pink-200">
              {root.potential_next_target ?? "none scored"}
            </p>
          </div>
        </div>

        <div className="border-t border-ink-700/70 pt-2">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            How each statement was derived
          </p>
          <ul className="mt-1 space-y-1">
            {root.inference_notes.map((note, index) => (
              <li key={index} className="flex gap-2 text-[11px] leading-relaxed text-slate-400">
                <span className="text-slate-600">&bull;</span>
                <Note text={note} />
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
