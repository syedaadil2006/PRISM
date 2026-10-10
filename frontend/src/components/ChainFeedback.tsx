/**
 * Analyst verdict on an attack chain. "False positive" turns the chain's notable
 * events into suppressions, so the same harmless pattern stops raising chains;
 * they are listed (and can be removed) on the Admin page.
 */

import { useState } from "react";

import { api, ApiError } from "../lib/api";

export function ChainFeedback({ chainId, onChanged }: { chainId: string; onChanged: () => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);

  async function send(verdict: "true_positive" | "false_positive") {
    if (
      verdict === "false_positive" &&
      !window.confirm(
        `Mark ${chainId} as a false positive? Matching activity (same action, program or domain, ` +
          "computer and account) will stop raising chains until the suppression is removed on the Admin page.",
      )
    )
      return;
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.chainFeedback(chainId, verdict, note.trim());
      setMessage({
        ok: true,
        text:
          verdict === "false_positive"
            ? `Marked as false positive: ${result.suppressions_created.length} suppression(s) added.`
            : "Confirmed as a true positive.",
      });
      setNote("");
      onChanged();
    } catch (cause) {
      setMessage({ ok: false, text: cause instanceof ApiError ? cause.message : "Could not reach PRISM." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="panel-title mr-auto">Analyst verdict</p>
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Note (optional), e.g. approved admin work"
          maxLength={500}
          className="min-w-[220px] flex-1 rounded-md border border-ink-600 bg-ink-850 px-2.5 py-1.5 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
        />
        <button
          type="button"
          disabled={busy}
          onClick={() => void send("true_positive")}
          className="rounded-md bg-rose-600/80 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-rose-500 disabled:opacity-50"
        >
          True positive
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => void send("false_positive")}
          className="rounded-md px-3 py-1.5 text-xs font-medium text-slate-300 ring-1 ring-ink-600 transition hover:text-white disabled:opacity-50"
        >
          False positive
        </button>
      </div>
      {message && (
        <p className={`mt-2 text-[11px] ${message.ok ? "text-emerald-300" : "text-rose-300"}`}>{message.text}</p>
      )}
    </div>
  );
}

/** Findings added by Sigma rules, threat intel and behaviour baselines. */
export function detectionFindings(tags: string[]): { kind: string; text: string }[] {
  const out: { kind: string; text: string }[] = [];
  for (const tag of tags) {
    if (tag.startsWith("finding:Sigma: ")) out.push({ kind: "Sigma", text: tag.slice(15) });
    else if (tag.startsWith("finding:Threat intel: ")) out.push({ kind: "Intel", text: tag.slice(22) });
    else if (tag.startsWith("finding:Baseline: ")) out.push({ kind: "Baseline", text: tag.slice(18) });
  }
  return out;
}
