/**
 * The simple attack map: machines only, animated, readable by anyone.
 *
 * The detailed Cytoscape graph shows every process, file and domain, which is
 * what an analyst wants and what a manager does not. This view keeps one
 * circle per machine (plus the attacker's server outside the network) and
 * plays the attack across them: machines turn from green to red as they are
 * taken over, dots travel along the lines to show traffic moving, and a live
 * log narrates each step in plain words.
 *
 * All positions and states come from the attack chain the backend built.
 */

import { useEffect, useMemo, useState } from "react";

import { timeOnly } from "../lib/format";
import { plain } from "./PlainStory";
import type { AttackChain, GraphPayload } from "../types";

type Status = "safe" | "attacked" | "compromised" | "current" | "predicted" | "external";

interface MapNode {
  id: string;
  label: string;
  role: string;
  x: number;
  y: number;
  /** Step at which the node changes from safe to its final status. */
  step: number;
  status: Status;
}

interface MapEdge {
  from: string;
  to: string;
  step: number;
  kind: "c2" | "move" | "attempt" | "predicted";
}

const COLORS: Record<Status, { fill: string; ring: string; word: string }> = {
  safe: { fill: "#10b981", ring: "#34d399", word: "Safe" },
  attacked: { fill: "#f59e0b", ring: "#fbbf24", word: "Attacked (not taken over)" },
  compromised: { fill: "#ef4444", ring: "#f87171", word: "Taken over by the attacker" },
  current: { fill: "#ef4444", ring: "#22d3ee", word: "Attacker is here now" },
  predicted: { fill: "#10b981", ring: "#f472b6", word: "Might be attacked next (prediction)" },
  external: { fill: "#ef4444", ring: "#f87171", word: "Attacker's server on the internet" },
};

const EDGE_STYLE: Record<MapEdge["kind"], { color: string; dash?: string; label: string }> = {
  c2: { color: "#a78bfa", label: "talking to attacker" },
  move: { color: "#ef4444", label: "attacker moved" },
  attempt: { color: "#f59e0b", dash: "6 6", label: "tried to break in" },
  predicted: { color: "#f472b6", dash: "3 7", label: "might go next" },
};

function buildMap(chain: AttackChain, graph: GraphPayload | null) {
  const stages = chain.stages;
  const finalStep = stages.length + 1;
  const firstStep = new Map<string, number>();
  stages.forEach((s, i) => {
    if (s.host && !firstStep.has(s.host)) firstStep.set(s.host, i + 1);
  });

  const roleOf = (host: string) => {
    const node = graph?.nodes.find((n) => n.kind === "host" && n.label === host);
    return String(node?.metadata.role ?? "computer");
  };

  const c2Stage = stages.findIndex((s) => s.tactic === "Command and Control");
  const c2Domains = (graph?.nodes ?? [])
    .filter((n) => n.kind === "domain" && n.state === "suspicious")
    .map((n) => n.label);

  const ordered = [...firstStep.keys()];
  const attempted = chain.targeted_hosts.filter((h) => !ordered.includes(h));
  const predicted = chain.predictions
    .filter((p) => p.score >= 60 || p === chain.predictions[0])
    .map((p) => p.host)
    .filter((h) => !ordered.includes(h));
  const hosts = [...ordered, ...attempted.filter((h) => !predicted.includes(h)), ...predicted];

  // Spread machines left to right in the order the attack reached them,
  // zig-zagging between two rows so lines never overlap.
  const left = c2Stage >= 0 ? 230 : 110;
  const span = 890 - left;
  const nodes: MapNode[] = hosts.map((host, i) => {
    let status: Status = "safe";
    let step = finalStep;
    if (chain.hosts.includes(host)) {
      status = host === chain.current_host ? "current" : "compromised";
      step = firstStep.get(host) ?? finalStep - 1;
    } else if (predicted.includes(host)) {
      status = "predicted";
    } else if (chain.targeted_hosts.includes(host)) {
      status = "attacked";
      step = finalStep - 1;
    }
    return {
      id: host,
      label: host,
      role: roleOf(host),
      x: hosts.length === 1 ? left + span / 2 : left + (span * i) / (hosts.length - 1),
      y: i % 2 === 0 ? 150 : 320,
      step,
      status,
    };
  });

  if (c2Stage >= 0) {
    nodes.unshift({
      id: "__internet__",
      label: "Attacker's server",
      role: c2Domains[0] ?? "on the internet",
      x: 90,
      y: 235,
      step: c2Stage + 1,
      status: "external",
    });
  }

  const edges: MapEdge[] = [];
  if (c2Stage >= 0) {
    [...new Set(stages.filter((s) => s.tactic === "Command and Control").map((s) => s.host))]
      .filter((h): h is string => Boolean(h))
      .forEach((h) =>
        edges.push({
          from: h,
          to: "__internet__",
          step: stages.findIndex((s) => s.tactic === "Command and Control" && s.host === h) + 1,
          kind: "c2",
        }),
      );
  }
  chain.lateral_movements.forEach((m) =>
    edges.push({
      from: m.source_host,
      to: m.destination_host,
      step: firstStep.get(m.destination_host) ?? finalStep - 1,
      kind: "move",
    }),
  );
  if (chain.current_host) {
    attempted
      .filter((h) => !predicted.includes(h))
      .forEach((h) =>
        edges.push({ from: chain.current_host!, to: h, step: finalStep - 1, kind: "attempt" }),
      );
    predicted.forEach((h) =>
      edges.push({ from: chain.current_host!, to: h, step: finalStep, kind: "predicted" }),
    );
  }
  return { nodes, edges, finalStep };
}

export function AttackMap({
  chain,
  graph,
  height = 460,
}: {
  chain: AttackChain;
  graph: GraphPayload | null;
  height?: number;
}) {
  const { nodes, edges, finalStep } = useMemo(() => buildMap(chain, graph), [chain, graph]);
  const [step, setStep] = useState(1);
  const [playing, setPlaying] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);

  // Plays itself once on load, one step every 2.2 seconds.
  useEffect(() => {
    if (!playing) return;
    const timer = window.setInterval(() => {
      setStep((s) => {
        if (s >= finalStep) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, 2200);
    return () => window.clearInterval(timer);
  }, [playing, finalStep]);

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const shownStatus = (n: MapNode): Status =>
    step >= n.step ? n.status : n.status === "external" ? "safe" : "safe";

  const log = chain.stages.slice(0, Math.min(step, chain.stages.length)).map((s, i) => ({
    key: i,
    time: timeOnly(s.timestamp),
    text: `${plain(s.tactic)} on ${s.host ?? "unknown machine"}`,
  }));
  if (step >= finalStep && chain.predictions[0]) {
    log.push({
      key: 999,
      time: "next?",
      text: `${chain.predictions[0].host} may be targeted next (prediction)`,
    });
  }

  const pick = selected ? byId.get(selected) : null;
  const pickStages = pick ? chain.stages.filter((s) => s.host === pick.id) : [];

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_300px]">
      <div className="relative overflow-hidden rounded-lg border border-ink-700 bg-[#070b14]">
        <svg viewBox="0 0 1000 470" className="w-full" style={{ height }} role="img"
             aria-label="Animated attack map">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1d2740" strokeWidth="1" />
            </pattern>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>
          <rect width="1000" height="470" fill="url(#grid)" />

          {edges.map((e, i) => {
            const a = byId.get(e.from);
            const b = byId.get(e.to);
            if (!a || !b) return null;
            const on = step >= e.step;
            const style = EDGE_STYLE[e.kind];
            const path = `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
            return (
              <g key={i} style={{ opacity: on ? 1 : 0, transition: "opacity 900ms ease" }}>
                <path d={path} stroke={style.color} strokeWidth={e.kind === "move" ? 3 : 2}
                      strokeDasharray={style.dash} fill="none" opacity={0.75} />
                {on && e.kind !== "predicted" && [0, 0.5].map((offset) => (
                  <circle key={offset} r={e.kind === "move" ? 5 : 4} fill={style.color}
                          filter="url(#glow)">
                    <animateMotion dur="1.8s" repeatCount="indefinite" path={path}
                                   begin={`${offset * 1.8}s`} />
                  </circle>
                ))}
                <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 8} textAnchor="middle"
                      fill={style.color} fontSize="12" opacity={0.9}>
                  {style.label}
                </text>
              </g>
            );
          })}

          {nodes.map((n) => {
            const status = shownStatus(n);
            const c = COLORS[status];
            const isNew = step === n.step && n.status !== "predicted";
            const reached = step >= n.step;
            return (
              <g key={n.id} onClick={() => setSelected(n.id)} style={{ cursor: "pointer" }}>
                {(status === "current" || isNew) && (
                  <circle cx={n.x} cy={n.y} r="26" fill="none" stroke={c.ring} strokeWidth="2">
                    <animate attributeName="r" values="24;42;24" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.9;0;0.9" dur="2s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle cx={n.x} cy={n.y} r="24" fill={c.fill} opacity={0.22}
                        style={{ transition: "fill 900ms ease" }} />
                <circle cx={n.x} cy={n.y} r="14" fill={c.fill} filter="url(#glow)"
                        stroke={status === "predicted" && reached ? c.ring : "none"}
                        strokeWidth={status === "predicted" ? 4 : 0}
                        strokeDasharray={status === "predicted" ? "4 4" : undefined}
                        style={{ transition: "fill 900ms ease" }} />
                {selected === n.id && (
                  <circle cx={n.x} cy={n.y} r="32" fill="none" stroke="#e2e8f0" strokeWidth="2" />
                )}
                <text x={n.x} y={n.y + 46} textAnchor="middle" fill="#f1f5f9" fontSize="15"
                      fontWeight="600">
                  {n.label}
                </text>
                <text x={n.x} y={n.y + 64} textAnchor="middle" fill="#94a3b8" fontSize="12">
                  {n.role}
                </text>
              </g>
            );
          })}
        </svg>

        <div className="absolute left-3 top-3 flex flex-wrap gap-3 rounded-md bg-black/50 px-3 py-1.5 text-[11px] text-slate-300">
          <span><span className="text-emerald-400">&#9679;</span> Safe</span>
          <span><span className="text-amber-400">&#9679;</span> Attacked</span>
          <span><span className="text-rose-400">&#9679;</span> Taken over</span>
          <span><span className="text-cyan-300">&#9711;</span> Attacker is here</span>
          <span><span className="text-pink-400">&#9711;</span> Might be next</span>
        </div>
      </div>

      <div className="space-y-3">
        <div className="panel p-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Attack progress
            </p>
            <span className="font-mono text-xs text-slate-400">
              step {Math.min(step, finalStep)}/{finalStep}
            </span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-ink-700">
            <div
              className="h-full rounded-full bg-gradient-to-r from-sky-400 via-amber-400 to-rose-500"
              style={{ width: `${(Math.min(step, finalStep) / finalStep) * 100}%`,
                       transition: "width 900ms ease" }}
            />
          </div>
          <div className="mt-2.5 flex gap-2">
            <button className="btn btn-primary !py-1" onClick={() => {
              if (playing) return setPlaying(false);
              if (step >= finalStep) setStep(1);
              setPlaying(true);
            }}>
              {playing ? "Pause" : step >= finalStep ? "Replay" : "Play"}
            </button>
            <button className="btn !py-1" disabled={step <= 1}
                    onClick={() => { setPlaying(false); setStep((s) => Math.max(1, s - 1)); }}>
              &larr;
            </button>
            <button className="btn !py-1" disabled={step >= finalStep}
                    onClick={() => { setPlaying(false); setStep((s) => Math.min(finalStep, s + 1)); }}>
              &rarr;
            </button>
            <button className="btn !py-1" onClick={() => { setPlaying(false); setStep(finalStep); }}>
              End
            </button>
          </div>
        </div>

        <div className="panel p-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Selected machine
          </p>
          {pick ? (
            <div className="mt-1.5 text-sm">
              <p className="font-semibold text-slate-100">{pick.label}</p>
              <p className="text-xs text-slate-400">{pick.role}</p>
              <p className="mt-1" style={{ color: COLORS[shownStatus(pick)].ring }}>
                {COLORS[shownStatus(pick)].word}
              </p>
              {pickStages.length > 0 && (
                <ul className="mt-1.5 space-y-0.5 text-xs text-slate-300">
                  {pickStages.map((s) => (
                    <li key={s.order}>
                      {timeOnly(s.timestamp)} &middot; {plain(s.tactic)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <p className="mt-1.5 text-xs text-slate-500">Click a circle to see what happened there.</p>
          )}
        </div>

        <div className="panel p-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            What is happening
          </p>
          <ul className="mt-2 max-h-[190px] space-y-1.5 overflow-auto">
            {[...log].reverse().map((entry, i) => (
              <li
                key={entry.key}
                className={`rounded border px-2 py-1.5 text-xs animate-[fadeIn_.5s_ease-out] ${
                  i === 0
                    ? "border-rose-500/50 bg-rose-500/15 text-rose-100"
                    : "border-ink-700 bg-ink-850 text-slate-300"
                }`}
              >
                <span className="font-mono text-slate-400">{entry.time}</span> {entry.text}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
