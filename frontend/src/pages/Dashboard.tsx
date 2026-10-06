/**
 * The SOC dashboard.
 *
 * Layout follows the product brief: statistics across the top, the attack graph
 * as the centrepiece, the timeline beneath it, and the intelligence panel on the
 * right. A first-time viewer should understand the attack in a few seconds.
 */

import { useEffect, useMemo, useState } from "react";

import { AttackGraph, type GraphSelection } from "../components/AttackGraph";
import { AttackMap } from "../components/AttackMap";
import { AgentActivityPanel } from "../components/AgentActivityPanel";
import { AgentTimeline } from "../components/AgentTimeline";
import { AISummaryPanel } from "../components/AISummaryPanel";
import { AttackChainList } from "../components/AttackChainList";
import { DetailDrawer } from "../components/DetailDrawer";
import { GraphLegend } from "../components/GraphLegend";
import { IntelPanel } from "../components/IntelPanel";
import { PlainStory, plain } from "../components/PlainStory";
import { StatDetail, type StatKey } from "../components/StatDetail";
import { timeOnly } from "../lib/format";
import { RootCausePanel } from "../components/RootCausePanel";
import { SimulationControls } from "../components/SimulationControls";
import { StatCards } from "../components/StatCards";
import { Timeline } from "../components/Timeline";
import { api } from "../lib/api";
import { useApi } from "../lib/useApi";
import { useInvestigation } from "../lib/useInvestigation";
import type { SimulationStatus } from "../types";

/** Poll fast enough that the simulation feels live, slow enough to stay calm. */
const POLL_MS = 1500;

export function Dashboard() {
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [selectedStage, setSelectedStage] = useState<number | null>(null);
  const [selection, setSelection] = useState<GraphSelection | null>(null);
  const [focusChain, setFocusChain] = useState(false);
  const [simulation, setSimulation] = useState<SimulationStatus | null>(null);
  // Plain-language view by default; the full analyst console is one click away.
  // ?view=analyst opens straight into the analyst console (handy for demos).
  const [simple, setSimple] = useState(
    () => new URLSearchParams(window.location.search).get("view") !== "analyst",
  );
  const [agentCollapsed, setAgentCollapsed] = useState(false);
  const [statKey, setStatKey] = useState<StatKey | null>(null);
  // ?graph=detailed opens the analyst graph instead of the simple map.
  const [graphMode, setGraphMode] = useState<"map" | "detailed">(() =>
    new URLSearchParams(window.location.search).get("graph") === "detailed" ? "detailed" : "map",
  );
  // Story playback on the graph: null shows everything.
  const [storyStep, setStoryStep] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);

  // Once the agents are done, clicking into the graph means the analyst has
  // moved on to the evidence: fold the agent panel so the chain list and the
  // selected object's details slide up into view.

  const investigation = useInvestigation();
  const investigationDone = investigation.investigation?.status === "complete";
  const selectGraph = (next: GraphSelection | null) => {
    setSelection(next);
    if (next && investigationDone) setAgentCollapsed(true);
  };
  const stats = useApi(() => api.stats(), [], POLL_MS);
  const chains = useApi(() => api.attacks(), [], POLL_MS);
  const simStatus = useApi(() => api.simulation(), [], POLL_MS);

  const chainList = chains.data ?? [];
  const activeChainId = selectedChainId ?? chainList[0]?.attack_chain_id ?? null;
  const chain = chainList.find((c) => c.attack_chain_id === activeChainId) ?? null;

  const graph = useApi(
    () => api.graph(focusChain && activeChainId ? activeChainId : undefined),
    [focusChain, activeChainId],
    POLL_MS,
  );

  useEffect(() => {
    if (simStatus.data) setSimulation(simStatus.data);
  }, [simStatus.data]);

  // A stage highlight only makes sense for the chain it came from.
  useEffect(() => setSelectedStage(null), [activeChainId]);

  /** Hosts of the selected chain, used to spotlight it inside a multi-chain graph. */
  const chainNodeIds = useMemo(() => {
    if (!chain || selectedStage !== null) return [];
    if (chainList.length <= 1) return [];
    return chain.hosts.map((host) => `host:${host.toUpperCase()}`);
  }, [chain, chainList.length, selectedStage]);

  const finalStep = chain ? chain.stages.length + 1 : 0;

  useEffect(() => {
    if (!playing) return;
    const timer = window.setInterval(() => {
      setStoryStep((step) => {
        const next = (step ?? 0) + 1;
        if (next >= finalStep) setPlaying(false);
        return Math.min(next, finalStep);
      });
    }, 2400);
    return () => window.clearInterval(timer);
  }, [playing, finalStep]);

  const storyCaption = (() => {
    if (!chain || storyStep == null) return null;
    if (storyStep >= finalStep) {
      const p = chain.predictions[0];
      return p
        ? `Possible next target: ${p.host} (${Math.round(p.score)}/100) — a prediction, not something that happened`
        : "End of the attack story";
    }
    const stage = chain.stages[storyStep - 1];
    return stage
      ? `${timeOnly(stage.timestamp)} · ${plain(stage.tactic)} on ${stage.host ?? "an unknown host"}`
      : null;
  })();

  const error = stats.error ?? chains.error ?? graph.error;

  return (
    <div className="space-y-3 p-4">
      {error && (
        <div className="panel border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-200">
          Cannot reach the PRISM API: {error}. Is the backend running on port 8000?
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">
            {chain ? (
              <>
                Active attack detected:{" "}
                <span className="font-mono text-rose-300">{chain.initial_host}</span>
                <span className="px-1.5 text-slate-600">&rarr;</span>
                <span className="font-mono text-cyan-300">{chain.current_host}</span>
              </>
            ) : (
              "No correlated attack activity"
            )}
          </h1>
          <p className="mt-0.5 text-xs text-slate-500">
            {chain
              ? `${chain.current_stage} in progress. ${
                  chain.predictions[0]
                    ? `${chain.predictions[0].host} is the highest-scoring potential next target.`
                    : ""
                }`
              : "PRISM shows one connected story instead of a list of isolated alerts."}
          </p>
        </div>
        <SimulationControls status={simulation} onChange={setSimulation} />
      </div>

      <div className="flex gap-1 self-start rounded-lg border border-ink-600 bg-ink-850 p-1 text-sm">
        {[
          [true, "Simple view"],
          [false, "Analyst view"],
        ].map(([value, label]) => (
          <button
            key={String(label)}
            onClick={() => setSimple(value as boolean)}
            className={`rounded-md px-3 py-1.5 font-medium transition ${
              simple === value ? "bg-sky-500/20 text-sky-200" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {label as string}
          </button>
        ))}
      </div>

      {simple ? (
        <PlainStory chain={chain} graph={graph.data} />
      ) : (
      <>
      <StatCards
        stats={stats.data}
        investigations={investigation.investigation ? 1 : 0}
        onSelect={setStatKey}
      />

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-3">
          <div className="flex items-center gap-1 text-xs">
            <span className="mr-1 text-slate-500">Attack graph:</span>
            {([
              ["map", "Simple map"],
              ["detailed", "Detailed graph"],
            ] as const).map(([value, label]) => (
              <button
                key={value}
                onClick={() => setGraphMode(value)}
                className={`rounded-md px-2.5 py-1 font-medium transition ${
                  graphMode === value
                    ? "bg-sky-500/20 text-sky-200"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          {graphMode === "map" && chain ? (
            <AttackMap chain={chain} graph={graph.data} />
          ) : (
          <div className="panel flex h-[62vh] max-h-[680px] min-h-[380px] flex-col">
            <div className="panel-header">
              <div className="flex items-center gap-3">
                <p className="panel-title">Attack graph</p>
                {graph.data && (
                  <span className="font-mono text-[10px] text-slate-500">
                    {graph.data.stats.nodes} nodes &middot; {graph.data.stats.edges} relationships
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {selectedStage !== null && (
                  <span className="chip border-slate-400/40 bg-slate-400/10 text-slate-300">
                    stage {selectedStage} highlighted
                  </span>
                )}
                <label className="flex cursor-pointer items-center gap-1.5 text-[10px] text-slate-400">
                  <input
                    type="checkbox"
                    className="h-3 w-3 accent-sky-400"
                    checked={focusChain}
                    onChange={(event) => setFocusChain(event.target.checked)}
                  />
                  Focus selected chain
                </label>
              </div>
            </div>

            {chain && (
              <div className="flex flex-wrap items-center gap-2 border-b border-ink-700/70 px-4 py-2">
                <button
                  className="btn btn-primary !py-1"
                  onClick={() => {
                    if (playing) return setPlaying(false);
                    if (storyStep == null || storyStep >= finalStep) setStoryStep(1);
                    setPlaying(true);
                  }}
                >
                  {playing ? "⏸ Pause" : storyStep == null ? "▶ Play attack step by step" : "▶ Play"}
                </button>
                <button
                  className="btn !py-1"
                  disabled={storyStep == null || storyStep <= 1}
                  onClick={() => { setPlaying(false); setStoryStep((s) => Math.max(1, (s ?? 1) - 1)); }}
                >
                  &larr; Back
                </button>
                <button
                  className="btn !py-1"
                  disabled={storyStep != null && storyStep >= finalStep}
                  onClick={() => { setPlaying(false); setStoryStep((s) => Math.min(finalStep, (s ?? 0) + 1)); }}
                >
                  Next &rarr;
                </button>
                {storyStep != null && (
                  <button className="btn !py-1" onClick={() => { setPlaying(false); setStoryStep(null); }}>
                    Show everything
                  </button>
                )}
                {storyStep != null && (
                  <div className="ml-auto flex min-w-0 items-center gap-3">
                    <div className="flex gap-1">
                      {Array.from({ length: finalStep }).map((_, i) => (
                        <button
                          key={i}
                          onClick={() => { setPlaying(false); setStoryStep(i + 1); }}
                          className={`h-2 w-2 rounded-full transition ${
                            i + 1 <= storyStep ? (i + 1 === finalStep ? "bg-pink-400" : "bg-sky-400") : "bg-ink-600"
                          }`}
                          title={`Step ${i + 1}`}
                        />
                      ))}
                    </div>
                    <p
                      key={storyStep}
                      className="truncate text-sm text-slate-200 animate-[fadeIn_.5s_ease-out]"
                    >
                      <span className="font-mono text-xs text-slate-500">
                        Step {storyStep}/{finalStep}
                      </span>{" "}
                      {storyCaption}
                    </p>
                  </div>
                )}
              </div>
            )}
            <div className="min-h-0 flex-1">
              <AttackGraph
                revealStep={storyStep}
                finalStep={finalStep}
                payload={graph.data}
                highlightStage={selectedStage}
                highlightNodeIds={chainNodeIds}
                onSelect={selectGraph}
              />
            </div>
            <GraphLegend />
          </div>
          )}
          <Timeline chain={chain} selectedStage={selectedStage} onSelectStage={setSelectedStage} />
          <AISummaryPanel investigation={investigation.investigation} />
          <AgentTimeline investigation={investigation.investigation} />
          <RootCausePanel chain={chain} />
        </div>

        <div className="space-y-3">
          <AgentActivityPanel
            investigation={investigation.investigation}
            roster={investigation.roster}
            busy={investigation.busy}
            onStart={() => {
              setAgentCollapsed(false);
              void investigation.start(activeChainId ?? undefined);
            }}
            collapsed={agentCollapsed}
            onToggleCollapse={
              investigation.investigation ? () => setAgentCollapsed((c) => !c) : undefined
            }
          />
          <AttackChainList
            chains={chainList}
            selectedId={activeChainId}
            onSelect={setSelectedChainId}
          />
          <DetailDrawer selection={selection} onClose={() => setSelection(null)} />
          <IntelPanel chain={chain} />
        </div>
      </div>
      </>
      )}
      {statKey && (
        <StatDetail
          statKey={statKey}
          stats={stats.data}
          chains={chainList}
          onClose={() => setStatKey(null)}
          onSelectChain={setSelectedChainId}
        />
      )}
    </div>
  );
}
