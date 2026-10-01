/**
 * Stage-driven layout for the attack graph.
 *
 * A generic force or hierarchical layout arranges a graph by its edges, which
 * on a star-shaped host/process graph produces a tangle. PRISM already
 * knows the order of the story -- the backend stamps every node with the
 * timeline stage it belongs to -- so the graph is laid out along that order
 * instead: one column per stage, left to right, hosts on the spine and the
 * processes, files and domains they touched stacked around them.
 *
 * The result is the diagram an analyst expects: where it started on the left,
 * where the attacker is now in the middle, and what may be next on the right.
 */

import type { GraphNode, GraphPayload } from "../types";

const COLUMN_WIDTH = 190;
const ROW_HEIGHT = 92;

/** Nodes that form the horizontal spine of the story. */
const SPINE_KINDS = new Set(["host", "attack", "user"]);

export type Positions = Record<string, { x: number; y: number }>;

function columnFor(node: GraphNode, lastStage: number): number {
  // Identity and the chain marker anchor the left edge.
  if (node.kind === "attack" || node.kind === "user") return 0;
  // Predictions are the right edge: they are where the story might go next.
  if (node.state === "potential_target") return lastStage + 1;
  return node.stage_order ?? lastStage + 1;
}

/** Rows fan out from the spine: 0, -1, +1, -2, +2 ... */
function rowOffset(index: number): number {
  if (index === 0) return 0;
  const step = Math.ceil(index / 2);
  return index % 2 === 1 ? -step : step;
}

export function computeStoryLayout(payload: GraphPayload): Positions {
  const stages = payload.nodes
    .map((node) => node.stage_order)
    .filter((stage): stage is number => typeof stage === "number");
  const lastStage = stages.length > 0 ? Math.max(...stages) : 1;

  // Group by logical column, then collapse to contiguous columns so that a
  // stage with no graph entities does not leave an empty gap.
  const byColumn = new Map<number, GraphNode[]>();
  for (const node of payload.nodes) {
    const column = columnFor(node, lastStage);
    const bucket = byColumn.get(column);
    if (bucket) bucket.push(node);
    else byColumn.set(column, [node]);
  }

  const orderedColumns = [...byColumn.keys()].sort((a, b) => a - b);
  const positions: Positions = {};

  orderedColumns.forEach((column, columnIndex) => {
    const members = byColumn.get(column) ?? [];
    // Spine entities sit on the centre line; everything else fans out around
    // them, which keeps the host-to-host path readable across the whole board.
    members.sort((a, b) => {
      const aSpine = SPINE_KINDS.has(a.kind) ? 0 : 1;
      const bSpine = SPINE_KINDS.has(b.kind) ? 0 : 1;
      if (aSpine !== bSpine) return aSpine - bSpine;
      return a.label.localeCompare(b.label);
    });

    members.forEach((node, index) => {
      positions[node.id] = {
        x: columnIndex * COLUMN_WIDTH,
        y: rowOffset(index) * ROW_HEIGHT,
      };
    });
  });

  return positions;
}
