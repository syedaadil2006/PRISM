/**
 * The explainable investigation panel.
 *
 * Every finding shows its assurance, its confidence, whether verification
 * re-derived it, and the evidence it rests on. The analyst can approve, reject
 * or mark a false positive; a rejected finding stays on the record and leaves
 * the summary, because the disagreement is itself worth keeping.
 *
 * The agents recommend. Nothing here takes an action on a host.
 */

import { useState } from "react";

import { AssuranceBadge } from "./Badges";
import { api } from "../lib/api";
import { ASSURANCE_LABEL } from "../lib/theme";
import type { AnalystDecision, EvidenceItem, Finding, Investigation } from "../types/agents";

const DECISION_LABEL: Record<AnalystDecision, string> = {
  approved: "Approved",
  rejected: "Rejected",
  false_positive: "False positive",
};

const DECISION_CLASS: Record<AnalystDecision, string> = {
  approved: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
  rejected: "border-rose-500/50 bg-rose-500/10 text-rose-300",
  false_positive: "border-amber-500/50 bg-amber-500/10 text-amber-300",
};

function Evidence({ items }: { items: EvidenceItem[] }) {
  if (items.length === 0) {
    return <p className="text-[10px] text-slate-500">No evidence recorded.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item.evidence_id} className="rounded border border-ink-700 bg-ink-900 px-2 py-1.5">
          <p className="text-[11px] leading-snug text-slate-300">
            <span className="text-emerald-400">&#10003;</span> {item.summary}
          </p>
          {item.detail && (
            <p className="mt-0.5 text-[10px] leading-snug text-slate-500">{item.detail}</p>
          )}
          <p className="mt-1 font-mono text-[9px] text-slate-600">
            via {item.source_tool || "agent"}
            {item.event_ids.length > 0 && (
              <>
                {" "}
                &middot; sources {item.event_ids.slice(0, 4).join(", ")}
                {item.event_ids.length > 4 && ` +${item.event_ids.length - 4}`}
              </>
            )}
          </p>
        </li>
      ))}
    </ul>
  );
}

function FindingCard({
  finding,
  investigation,
  onDecide,
  busy,
}: {
  finding: Finding;
  investigation: Investigation;
  onDecide: (findingId: string, decision: AnalystDecision) => void;
  busy: boolean;
}) {
  const [open, setOpen] = useState(false);
  const evidence = finding.evidence_ids
    .map((id) => investigation.evidence.find((e) => e.evidence_id === id))
    .filter((e): e is EvidenceItem => Boolean(e));

  const rejected =
    finding.analyst_decision === "rejected" || finding.analyst_decision === "false_positive";

  return (
    <div
      className={`rounded-md border px-3 py-2 transition ${
        rejected ? "border-ink-700 bg-ink-900/50 opacity-60" : "border-ink-700 bg-ink-850"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[12px] font-semibold text-slate-100">{finding.title}</p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-slate-400">{finding.statement}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className="font-mono text-xs text-slate-200">
            {Math.round(finding.confidence * 100)}%
          </span>
          {finding.verified === false && (
            <span className="chip border-amber-500/50 bg-amber-500/10 text-amber-300">
              downgraded
            </span>
          )}
        </div>
      </div>

      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
        <AssuranceBadge value={finding.assurance} />
        {finding.verified === true && (
          <span className="chip border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
            verified
          </span>
        )}
        {finding.analyst_decision && (
          <span className={`chip ${DECISION_CLASS[finding.analyst_decision]}`}>
            {DECISION_LABEL[finding.analyst_decision]}
          </span>
        )}
        <button
          className="ml-auto text-[10px] text-sky-400 hover:text-sky-300"
          onClick={() => setOpen(!open)}
        >
          {open ? "Hide evidence" : `View evidence (${evidence.length})`}
        </button>
      </div>

      {open && (
        <div className="mt-2 space-y-2">
          <Evidence items={evidence} />

          {finding.verification_notes.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Verification
              </p>
              <ul className="mt-0.5 space-y-0.5">
                {finding.verification_notes.map((note, index) => (
                  <li key={index} className="text-[10px] leading-snug text-slate-400">
                    {finding.verified ? "✓" : "⚠"} {note}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {finding.confidence_before_verification != null && (
            <p className="text-[10px] text-amber-300/80">
              Confidence reduced from{" "}
              {Math.round(finding.confidence_before_verification * 100)}% after verification.
            </p>
          )}

          <div className="flex flex-wrap gap-1.5 border-t border-ink-700 pt-2">
            <button
              className="btn !py-1 !text-[10px] border-emerald-500/40 text-emerald-200 hover:border-emerald-400"
              disabled={busy}
              onClick={() => onDecide(finding.finding_id, "approved")}
            >
              Approve finding
            </button>
            <button
              className="btn !py-1 !text-[10px]"
              disabled={busy}
              onClick={() => onDecide(finding.finding_id, "rejected")}
            >
              Reject finding
            </button>
            <button
              className="btn btn-danger !py-1 !text-[10px]"
              disabled={busy}
              onClick={() => onDecide(finding.finding_id, "false_positive")}
            >
              Mark false positive
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function InvestigationPanel({
  investigation,
  onUpdated,
}: {
  investigation: Investigation | null;
  onUpdated: (next: Investigation) => void;
}) {
  const [busy, setBusy] = useState(false);

  if (!investigation) {
    return (
      <div className="panel px-4 py-6 text-xs text-slate-500">
        Start an investigation to see the agents' findings and the evidence behind them.
      </div>
    );
  }

  const decide = async (findingId: string, decision: AnalystDecision) => {
    setBusy(true);
    try {
      onUpdated(
        await api.recordDecision(investigation.investigation_id, findingId, decision),
      );
    } finally {
      setBusy(false);
    }
  };

  const byAssurance = ["observed", "correlated", "inferred", "predicted"] as const;
  const ordered = [...investigation.findings].sort(
    (a, b) => byAssurance.indexOf(a.assurance) - byAssurance.indexOf(b.assurance),
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <p className="panel-title">Findings</p>
          <span className="font-mono text-[10px] text-slate-500">
            {investigation.findings.length}
          </span>
        </div>
        <span className="font-mono text-[10px] text-slate-500">
          confidence {Math.round(investigation.confidence * 100)}%
        </span>
      </div>

      <div className="space-y-2 px-3 py-3">
        {ordered.map((finding) => (
          <FindingCard
            key={finding.finding_id}
            finding={finding}
            investigation={investigation}
            onDecide={decide}
            busy={busy}
          />
        ))}
      </div>

      <p className="border-t border-ink-700/70 px-4 py-2 text-[10px] leading-relaxed text-slate-500">
        Findings are labelled by how they were derived:{" "}
        {byAssurance.map((value) => ASSURANCE_LABEL[value]).join(", ")}. The agents recommend;
        containment decisions stay with you.
      </p>
    </div>
  );
}
