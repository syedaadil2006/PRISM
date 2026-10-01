/**
 * The attack graph: the visual centrepiece of the dashboard.
 *
 * Elements come straight from /api/graph. This component only decides layout
 * and interaction -- never which entities exist or what state they are in.
 */

import cytoscape from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";

import { graphStylesheet } from "../lib/graphStyle";
import { computeStoryLayout } from "../lib/storyLayout";
import type { GraphEdge, GraphNode, GraphPayload, NodeKind } from "../types";

/** Below this, node labels stop being legible, so never auto-fit past it. */
const MIN_READABLE_ZOOM = 0.62;

/** Grouping hint kept on each node for styling and debugging. */
const KIND_RANK: Record<NodeKind, number> = {
  attack: 0,
  user: 1,
  host: 2,
  process: 3,
  file: 4,
  domain: 4,
  ip: 5,
  event: 5,
};

export interface GraphSelection {
  type: "node" | "edge";
  node?: GraphNode;
  edge?: GraphEdge;
}

interface Props {
  payload: GraphPayload | null;
  /** Stage order to spotlight, from the timeline. */
  highlightStage?: number | null;
  /** Node ids to spotlight, e.g. the hosts of a selected chain. */
  highlightNodeIds?: string[];
  onSelect?: (selection: GraphSelection | null) => void;
  /** Story playback: show only what had happened by this step (null = all). */
  revealStep?: number | null;
  /** Step after the last stage, at which predictions are revealed. */
  finalStep?: number;
  className?: string;
}

function toElements(payload: GraphPayload): cytoscape.ElementDefinition[] {
  const nodeIds = new Set(payload.nodes.map((n) => n.id));
  const nodes = payload.nodes.map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      kind: node.kind,
      state: node.state,
      assurance: node.assurance,
      stage: node.stage_order ?? 0,
      rank: KIND_RANK[node.kind] ?? 5,
      raw: node,
    },
  }));
  const edges = payload.edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge) => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        kind: edge.kind,
        assurance: edge.assurance,
        predicted: edge.predicted,
        outcome: (edge.metadata.outcome as string | undefined) ?? "",
        raw: edge,
      },
    }));
  return [...nodes, ...edges];
}

export function AttackGraph({
  payload,
  highlightStage,
  highlightNodeIds,
  onSelect,
  revealStep = null,
  finalStep = 0,
  className = "",
}: Props) {
  const container = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [ready, setReady] = useState(false);
  // Cytoscape handlers are bound once at mount; read the latest callback via a
  // ref so they never call a stale closure.
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  const elements = useMemo(() => (payload ? toElements(payload) : []), [payload]);
  const positions = useMemo(() => (payload ? computeStoryLayout(payload) : {}), [payload]);
  // Re-run layout only when the graph's shape actually changes, so a polling
  // refresh does not make the whole board jump around.
  const topology = useMemo(
    () =>
      payload
        ? `${payload.nodes.map((n) => n.id).join(",")}|${payload.edges.map((e) => e.id).join(",")}`
        : "",
    [payload],
  );

  useEffect(() => {
    if (!container.current) return;

    const cy = cytoscape({
      container: container.current,
      style: graphStylesheet,
      elements: [],
      minZoom: 0.25,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
      boxSelectionEnabled: false,
    });
    cyRef.current = cy;
    setReady(true);

    cy.on("tap", "node", (event) => {
      onSelectRef.current?.({ type: "node", node: event.target.data("raw") as GraphNode });
    });
    cy.on("tap", "edge", (event) => {
      onSelectRef.current?.({ type: "edge", edge: event.target.data("raw") as GraphEdge });
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelectRef.current?.(null);
    });

    const observer = new ResizeObserver(() => {
      cy.resize();
    });
    observer.observe(container.current);

    return () => {
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
    // onSelect is stable enough for this prototype; re-creating the graph on
    // every render would destroy the layout.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync elements and re-layout when the topology changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !ready) return;

    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });

    if (elements.length === 0) return;

    // The panel is a flex child, so on first mount Cytoscape may still be
    // holding a zero-sized viewport. Measure again before laying out.
    cy.resize();

    // Lay the graph out along the backend's own stage ordering rather than by
    // edge topology; see lib/storyLayout.ts for why.
    cy.layout({
      name: "preset",
      positions: (element: cytoscape.NodeSingular) =>
        positions[element.id()] ?? { x: 0, y: 0 },
      animate: false,
      fit: true,
      padding: 44,
    } as cytoscape.LayoutOptions).run();

    // Framing runs a frame later, once the flex panel has its final size.
    //
    // A long chain only fits by zooming out past the point where the labels are
    // legible, so the zoom is clamped instead. The view is then parked at the
    // start of the story, which is where an analyst reads from; panning right
    // follows the attack forwards.
    requestAnimationFrame(() => {
      if (cyRef.current !== cy) return;
      cy.resize();
      cy.fit(undefined, 44);
      if (cy.zoom() < MIN_READABLE_ZOOM) {
        cy.zoom({
          level: MIN_READABLE_ZOOM,
          renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
        });
        cy.center(cy.nodes());
        const leftEdge = Math.min(...cy.nodes().map((node) => node.renderedPosition().x));
        cy.panBy({ x: 80 - leftEdge, y: 0 });
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topology, ready]);

  // Update data in place when only labels/states changed (no relayout).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !ready || !payload) return;
    cy.batch(() => {
      for (const node of payload.nodes) {
        const element = cy.getElementById(node.id);
        if (element.nonempty()) {
          element.data({ state: node.state, label: node.label, raw: node });
        }
      }
      for (const edge of payload.edges) {
        const element = cy.getElementById(edge.id);
        if (element.nonempty()) {
          element.data({ label: edge.label, assurance: edge.assurance, raw: edge });
        }
      }
    });
  }, [payload, ready]);

  // Spotlight the selected timeline stage or host set.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !ready) return;

    cy.elements().removeClass("dimmed stage-highlight");

    const ids = new Set(highlightNodeIds ?? []);
    if (highlightStage != null) {
      cy.nodes().forEach((node) => {
        if (node.data("stage") === highlightStage) ids.add(node.id());
      });
    }
    if (ids.size === 0) return;

    const focus = cy.collection();
    ids.forEach((id) => {
      const node = cy.getElementById(id);
      if (node.nonempty()) {
        focus.merge(node);
        focus.merge(node.connectedEdges());
        focus.merge(node.neighborhood());
      }
    });

    cy.elements().difference(focus).addClass("dimmed");
    ids.forEach((id) => cy.getElementById(id).addClass("stage-highlight"));
  }, [highlightStage, highlightNodeIds, ready, topology]);

  // Story playback: reveal the graph stage by stage, newest stage glowing.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !ready) return;
    cy.elements().removeClass("step-hidden step-new");
    if (revealStep == null) return;

    const visible = (node: cytoscape.NodeSingular): boolean => {
      const kind = node.data("kind");
      const stage = node.data("stage") as number;
      if (kind === "user" || kind === "attack") return true;
      if (node.data("state") === "potential_target") return revealStep >= finalStep;
      if (!stage) return revealStep >= finalStep;
      return stage <= revealStep;
    };

    cy.batch(() => {
      cy.nodes().forEach((node) => {
        if (!visible(node)) node.addClass("step-hidden");
        else if (node.data("stage") === revealStep ||
                 (revealStep >= finalStep && node.data("state") === "potential_target"))
          node.addClass("step-new");
      });
      cy.edges().forEach((edge) => {
        const hidden =
          edge.source().hasClass("step-hidden") ||
          edge.target().hasClass("step-hidden") ||
          (edge.data("predicted") && revealStep < finalStep);
        if (hidden) edge.addClass("step-hidden");
      });
    });

    // Glide the camera to the new stage. Stop any glide still in flight first,
    // so fast clicking never stacks animations into a jerk, and keep the zoom
    // steady unless it is too far out to read.
    const fresh = cy.nodes(".step-new");
    if (fresh.nonempty()) {
      cy.stop(true, false);
      cy.animate(
        { center: { eles: fresh }, zoom: Math.max(cy.zoom(), MIN_READABLE_ZOOM) },
        { duration: 1100, easing: "ease-in-out-sine", queue: false },
      );
    }
  }, [revealStep, finalStep, ready, topology]);

  const fit = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.animate({ fit: { eles: cy.elements(), padding: 36 } }, { duration: 260 });
  };
  const zoomBy = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  return (
    <div className={`relative h-full w-full ${className}`}>
      <div ref={container} className="h-full w-full" />

      {(!payload || payload.nodes.length === 0) && (
        <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
          <p className="text-sm font-semibold text-slate-300">No correlated activity yet</p>
          <p className="mt-1 max-w-xs text-xs text-slate-500">
            Start the attack simulation, or ingest authentication, DNS and endpoint logs.
          </p>
        </div>
      )}

      <div className="absolute right-3 top-3 flex flex-col gap-1">
        <button className="btn !px-2 !py-1" title="Zoom in" onClick={() => zoomBy(1.25)}>
          +
        </button>
        <button className="btn !px-2 !py-1" title="Zoom out" onClick={() => zoomBy(0.8)}>
          &minus;
        </button>
        <button className="btn !px-2 !py-1 text-[10px]" title="Fit to screen" onClick={fit}>
          FIT
        </button>
      </div>
    </div>
  );
}
