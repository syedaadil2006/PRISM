/**
 * The attack, told for someone who has never worked in a SOC.
 *
 * Same backend data as the analyst panels, translated out of jargon: no tactic
 * names, no technique ids, no scores without a word next to them.
 */

import { timeOnly } from "../lib/format";
import type { AttackChain, GraphPayload } from "../types";
import { AttackMap } from "./AttackMap";

/** MITRE tactic names in everyday words. */
const PLAIN: Record<string, string> = {
  "Initial Access": "Got into the network",
  Execution: "Ran harmful software",
  "Command and Control": "Contacted the attacker's server",
  Discovery: "Looked around to see what's there",
  "Credential Access": "Stole passwords",
  "Lateral Movement": "Moved to another computer",
  "Privilege Escalation": "Gave itself admin powers",
  "Defense Evasion": "Tried to hide its tracks",
  Persistence: "Set itself up to come back",
  Collection: "Gathered data",
  Exfiltration: "Sent data out",
  Impact: "Caused damage",
};

export function plain(tactic: string): string {
  return PLAIN[tactic] ?? tactic;
}

function riskWord(score: number): { word: string; tone: string } {
  if (score >= 80) return { word: "Very likely", tone: "text-rose-300" };
  if (score >= 60) return { word: "Likely", tone: "text-orange-300" };
  if (score >= 40) return { word: "Possible", tone: "text-amber-300" };
  return { word: "Unlikely", tone: "text-slate-300" };
}

function Card({
  step,
  title,
  children,
  accent,
}: {
  step: string;
  title: string;
  children: React.ReactNode;
  accent: string;
}) {
  return (
    <div className="panel flex flex-col gap-2 p-5">
      <div className="flex items-center gap-2">
        <span
          className={`grid h-7 w-7 place-content-center rounded-full text-sm font-bold ${accent}`}
        >
          {step}
        </span>
        <p className="text-sm font-semibold text-slate-300">{title}</p>
      </div>
      <div className="text-[15px] leading-relaxed text-slate-100">{children}</div>
    </div>
  );
}

export function PlainStory({
  chain,
  graph = null,
}: {
  chain: AttackChain | null;
  graph?: GraphPayload | null;
}) {
  if (!chain) {
    return (
      <div className="panel p-8 text-center">
        <p className="text-2xl font-semibold text-emerald-300">All clear</p>
        <p className="mt-2 text-base text-slate-400">
          Nothing suspicious has been connected together. There is no attack to show right now.
        </p>
      </div>
    );
  }

  const steps = chain.stages.map((s) => plain(s.tactic));
  const uniqueSteps = steps.filter((s, i) => steps.indexOf(s) === i);
  const next = chain.predictions[0];
  const risk = next ? riskWord(next.score) : null;
  const moved = chain.initial_host !== chain.current_host;

  return (
    <div className="space-y-4">
      <div className="panel border-rose-500/40 bg-rose-500/[0.07] p-6">
        <p className="text-sm font-semibold uppercase tracking-wider text-rose-300">
          Attack in progress
        </p>
        <p className="mt-2 text-2xl font-semibold leading-snug text-slate-50">
          Someone broke into <span className="text-rose-300">{chain.initial_host}</span>
          {moved ? (
            <>
              {" "}
              and has moved to <span className="text-cyan-300">{chain.current_host}</span>.
            </>
          ) : (
            " and is still active there."
          )}
        </p>
        <p className="mt-2 text-base text-slate-300">
          PRISM joined {chain.event_count} separate warning signs into this one story, so
          nobody has to piece them together by hand.
        </p>
      </div>

      <AttackMap chain={chain} graph={graph} />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card step="1" title="Where it started" accent="bg-rose-500/20 text-rose-300">
          On the computer <b>{chain.initial_host}</b>
          {chain.users[0] && (
            <>
              , using <b>{chain.users[0]}</b>'s account
            </>
          )}
          , at {timeOnly(chain.start_time)}.
        </Card>

        <Card step="2" title="What it did" accent="bg-amber-500/20 text-amber-300">
          <ol className="space-y-1">
            {uniqueSteps.slice(0, 5).map((s) => (
              <li key={s}>&bull; {s}</li>
            ))}
          </ol>
        </Card>

        <Card step="3" title="Where it is now" accent="bg-cyan-500/20 text-cyan-300">
          On <b>{chain.current_host}</b>. Right now it is trying to:{" "}
          <b>{plain(chain.current_stage).toLowerCase()}</b>.
        </Card>

        <Card step="4" title="What might be next" accent="bg-pink-500/20 text-pink-300">
          {next && risk ? (
            <>
              <b>{next.host}</b> — <span className={risk.tone}>{risk.word}</span> to be targeted
              next.
              <p className="mt-1 text-sm text-slate-400">
                This is a warning based on who can reach what, not something that has happened
                yet.
              </p>
            </>
          ) : (
            "No obvious next target."
          )}
        </Card>
      </div>

      {chain.current_host && (
        <div className="panel border-emerald-500/30 bg-emerald-500/[0.06] p-5">
          <p className="text-sm font-semibold text-emerald-300">What to do now</p>
          <ul className="mt-2 space-y-1 text-[15px] text-slate-100">
            <li>&bull; Disconnect <b>{chain.current_host}</b> from the network.</li>
            {chain.users[0] && (
              <li>&bull; Change the password for <b>{chain.users[0]}</b>.</li>
            )}
            {next && (
              <li>&bull; Keep a close eye on <b>{next.host}</b>.</li>
            )}
          </ul>
          <p className="mt-2 text-xs text-slate-500">
            These are suggestions. PRISM never takes action on its own.
          </p>
        </div>
      )}
    </div>
  );
}
