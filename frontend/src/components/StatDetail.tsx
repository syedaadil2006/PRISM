/**
 * What sits behind a headline number.
 *
 * Every stat card opens this panel with the actual items it counts, so a
 * number is never a dead end: "3 compromised hosts" becomes the three hosts.
 */

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../lib/api";
import { timeOnly } from "../lib/format";
import type { AttackChain, DashboardStats, NormalizedEvent } from "../types";
import type { InvestigationSummaryView } from "../types/agents";
import { SeverityBadge } from "./Badges";

export type StatKey =
  | "investigations"
  | "chains"
  | "correlated"
  | "compromised"
  | "lateral"
  | "targets"
  | "reduction";

const TITLES: Record<StatKey, [string, string]> = {
  investigations: ["Investigations", "Cases the AI agents have worked on. Click one to open it."],
  chains: ["Active attack chains", "Each chain is one attack story built from many related events."],
  correlated: ["Correlated events", "The individual log records that were joined into an attack story."],
  compromised: ["Compromised hosts", "Computers where attacker activity was actually seen."],
  lateral: ["Lateral movements", "Times the attacker jumped from one computer to another."],
  targets: ["Potential targets", "Where the attacker might go next. These are predictions, not events."],
  reduction: ["Alert reduction", "How many separate alerts were collapsed into attack stories."],
};

function Row({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) {
  return (
    <li
      onClick={onClick}
      className={`rounded-md border border-ink-700 bg-ink-850 px-3 py-2 text-[13px] text-slate-200 ${
        onClick ? "cursor-pointer transition hover:border-sky-500/50 hover:bg-ink-800" : ""
      }`}
    >
      {children}
    </li>
  );
}

export function StatDetail({
  statKey,
  stats,
  chains,
  onClose,
  onSelectChain,
}: {
  statKey: StatKey;
  stats: DashboardStats | null;
  chains: AttackChain[];
  onClose: () => void;
  onSelectChain: (id: string) => void;
}) {
  const navigate = useNavigate();
  const [events, setEvents] = useState<NormalizedEvent[] | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummaryView[] | null>(null);

  useEffect(() => {
    if (statKey === "correlated" || statKey === "reduction") {
      api.events({ limit: 2000 }).then(setEvents).catch(() => setEvents([]));
    }
    if (statKey === "investigations") {
      api.investigations().then(setInvestigations).catch(() => setInvestigations([]));
    }
  }, [statKey]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const inChain = new Set(chains.flatMap((c) => c.event_ids));
  const [title, subtitle] = TITLES[statKey];

  let body: React.ReactNode = null;

  if (statKey === "investigations") {
    body = !investigations ? (
      <p className="text-sm text-slate-500">Loading…</p>
    ) : investigations.length === 0 ? (
      <p className="text-sm text-slate-400">
        No investigation yet. Press <b>Start investigation</b> in the agent panel.
      </p>
    ) : (
      <ul className="space-y-2">
        {investigations.map((inv) => (
          <Row key={inv.investigation_id} onClick={() => navigate("/investigation")}>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-semibold">{inv.investigation_id}</span>
              <span className="text-xs text-slate-400">
                {inv.status} &middot; {Math.round(inv.confidence * 100)}% confidence
              </span>
            </div>
            <p className="mt-1 text-slate-400">
              {inv.initial_host} &rarr; {inv.current_host} &middot; {inv.current_stage} &middot;{" "}
              {inv.evidence_count} evidence items
            </p>
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "chains") {
    body = (
      <ul className="space-y-2">
        {chains.map((c) => (
          <Row
            key={c.attack_chain_id}
            onClick={() => {
              onSelectChain(c.attack_chain_id);
              onClose();
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-semibold">{c.attack_chain_id}</span>
              <SeverityBadge value={c.severity} />
            </div>
            <p className="mt-1 text-slate-400">
              Started on <b className="text-slate-200">{c.initial_host}</b>, now on{" "}
              <b className="text-cyan-300">{c.current_host}</b> &middot; {c.event_count} events &middot;{" "}
              {c.current_stage}
            </p>
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "correlated") {
    const rows = (events ?? []).filter((e) => inChain.has(e.event_id)).reverse();
    body = !events ? (
      <p className="text-sm text-slate-500">Loading…</p>
    ) : (
      <ul className="space-y-1.5">
        {rows.map((e) => (
          <Row key={e.event_id}>
            <span className="font-mono text-xs text-slate-500">{timeOnly(e.timestamp)}</span>{" "}
            <span className="font-semibold">{e.action}</span> on{" "}
            <span className="text-cyan-300">{e.destination_host ?? e.source_host ?? "?"}</span>
            {e.user && <span className="text-slate-400"> &middot; {e.user}</span>}
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "compromised") {
    const seen = new Map<string, AttackChain>();
    chains.forEach((c) => c.hosts.forEach((h) => !seen.has(h) && seen.set(h, c)));
    body = (
      <ul className="space-y-2">
        {[...seen.entries()].map(([host, c]) => (
          <Row key={host}>
            <span className="font-mono font-semibold">{host}</span>
            {host === c.current_host && (
              <span className="chip ml-2 border-cyan-400/60 bg-cyan-400/10 text-cyan-300">
                attacker is here now
              </span>
            )}
            {host === c.initial_host && (
              <span className="chip ml-2 border-rose-500/50 bg-rose-500/10 text-rose-300">
                where it started
              </span>
            )}
          </Row>
        ))}
        {chains.flatMap((c) => c.targeted_hosts).map((h) => (
          <Row key={"t-" + h}>
            <span className="font-mono font-semibold text-slate-400">{h}</span>
            <span className="ml-2 text-xs text-amber-300">
              attacked but NOT compromised (only failed logins)
            </span>
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "lateral") {
    const moves = chains.flatMap((c) => c.lateral_movements);
    body = (
      <ul className="space-y-2">
        {moves.map((m) => (
          <Row key={m.movement_id}>
            <p className="font-mono font-semibold">
              {m.source_host} <span className="text-orange-300">&rarr;</span> {m.destination_host}
            </p>
            <p className="mt-1 text-slate-400">
              {timeOnly(m.timestamp)} &middot; {m.method} &middot; account {m.user}
            </p>
            <p className="mt-1 text-xs text-slate-500">{m.explanation}</p>
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "targets") {
    const preds = chains.flatMap((c) => c.predictions);
    body = (
      <ul className="space-y-2">
        {preds.map((p) => (
          <Row key={p.host}>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-semibold text-pink-200">{p.host}</span>
              <span className="font-mono text-pink-200">{Math.round(p.score)}/100</span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-ink-700">
              <div className="h-full rounded-full bg-pink-400/70" style={{ width: `${p.score}%` }} />
            </div>
            <p className="mt-1.5 text-xs text-slate-400">{p.narrative}</p>
          </Row>
        ))}
      </ul>
    );
  }

  if (statKey === "reduction" && stats) {
    const leftOut = (events ?? []).filter((e) => e.suspicious && !inChain.has(e.event_id));
    body = (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-center">
          {[
            [stats.total_events, "log records"],
            [stats.raw_alert_count, "would each raise an alert"],
            [stats.correlated_events, "joined into stories"],
            [stats.active_attack_chains, "attack story to review"],
          ].map(([n, label], i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="rounded-md border border-ink-700 bg-ink-850 px-3 py-2">
                <p className="font-mono text-xl font-semibold text-emerald-300">{n}</p>
                <p className="text-[11px] text-slate-400">{label}</p>
              </div>
              {i < 3 && <span className="text-slate-600">&rarr;</span>}
            </div>
          ))}
        </div>
        <p className="text-sm text-slate-300">
          Instead of reading {stats.raw_alert_count} separate alerts, an analyst reviews{" "}
          {stats.active_attack_chains} story. That is a{" "}
          {Math.round(stats.alert_reduction_ratio * 100)}% reduction, measured on the data loaded.
        </p>
        {leftOut.length > 0 && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Flagged but left out (nothing linked them to the attack)
            </p>
            <ul className="mt-1.5 space-y-1.5">
              {leftOut.map((e) => (
                <Row key={e.event_id}>
                  <span className="font-mono text-xs text-slate-500">{timeOnly(e.timestamp)}</span>{" "}
                  {e.action} &middot; {e.source_host ?? "?"} {e.domain ? `· ${e.domain}` : ""}
                </Row>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-24 backdrop-blur-sm animate-[fadeIn_.15s_ease-out]"
      onClick={onClose}
    >
      <div
        className="panel w-full max-w-xl bg-ink-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label={title}
      >
        <div className="panel-header">
          <div>
            <p className="text-base font-semibold text-slate-100">{title}</p>
            <p className="text-xs text-slate-400">{subtitle}</p>
          </div>
          <button className="btn !py-1" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="max-h-[65vh] overflow-auto p-4">{body}</div>
      </div>
    </div>
  );
}
