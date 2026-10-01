/**
 * Cytoscape.js stylesheet for the attack graph.
 *
 * Shape encodes *what* an entity is; colour encodes *what state the backend put
 * it in*; line style encodes *how sure we are*. Nothing here decides state --
 * that arrives from /api/graph.
 */

import type cytoscape from "cytoscape";

import { ASSURANCE_COLOR, STATE_COLOR } from "./theme";

const SHAPES: Record<string, cytoscape.Css.NodeShape> = {
  host: "round-rectangle",
  user: "ellipse",
  process: "hexagon",
  domain: "diamond",
  file: "round-tag",
  ip: "ellipse",
  event: "round-rectangle",
  attack: "octagon",
};

export function nodeShape(kind: string): cytoscape.Css.NodeShape {
  return SHAPES[kind] ?? "ellipse";
}

export const graphStylesheet: cytoscape.StylesheetJson = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "font-family": "Inter, system-ui, sans-serif",
      "font-size": 11,
      "font-weight": 600,
      color: "#e2e8f0",
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 6,
      "text-wrap": "wrap",
      "text-max-width": "96px",
      "min-zoomed-font-size": 7,
      "background-color": "#1d2740",
      "border-width": 2,
      "border-color": STATE_COLOR.normal,
      width: 34,
      height: 34,
      "overlay-opacity": 0,
      "transition-property":
        "border-color, border-width, background-color, width, height, opacity, text-opacity, overlay-opacity",
      "transition-duration": 700,
      "transition-timing-function": "ease-in-out-sine",
    },
  },

  // --- what the entity is -------------------------------------------------
  { selector: 'node[kind = "host"]', style: { shape: "round-rectangle", width: 62, height: 40 } },
  { selector: 'node[kind = "user"]', style: { shape: "ellipse", width: 44, height: 44 } },
  { selector: 'node[kind = "process"]', style: { shape: "hexagon", width: 40, height: 36 } },
  { selector: 'node[kind = "domain"]', style: { shape: "diamond", width: 40, height: 40 } },
  { selector: 'node[kind = "file"]', style: { shape: "round-tag", width: 38, height: 30 } },
  { selector: 'node[kind = "ip"]', style: { shape: "ellipse", width: 26, height: 26, "font-size": 9 } },
  {
    selector: 'node[kind = "attack"]',
    style: {
      shape: "octagon",
      width: 58,
      height: 58,
      "background-color": "#3b0764",
      "border-color": ASSURANCE_COLOR.correlated,
      "border-width": 3,
      "font-size": 11,
      "font-weight": 700,
      color: "#ede9fe",
    },
  },

  // --- what state the backend put it in -----------------------------------
  {
    selector: 'node[state = "suspicious"]',
    style: {
      "border-color": STATE_COLOR.suspicious,
      "background-color": "#3a2a08",
    },
  },
  {
    selector: 'node[state = "compromised"]',
    style: {
      "border-color": STATE_COLOR.compromised,
      "background-color": "#3f1418",
      "border-width": 3,
    },
  },
  {
    selector: 'node[state = "current_position"]',
    style: {
      "border-color": STATE_COLOR.current_position,
      "background-color": "#0b3b45",
      "border-width": 4,
      width: 76,
      height: 48,
      "font-size": 12,
      color: "#cffafe",
    },
  },
  {
    selector: 'node[state = "potential_target"]',
    style: {
      "border-color": STATE_COLOR.potential_target,
      "background-color": "#3b0f2b",
      "border-width": 3,
      "border-style": "dashed",
      color: "#fbcfe8",
    },
  },

  // --- relationships ------------------------------------------------------
  {
    selector: "edge",
    style: {
      width: 1.6,
      "line-color": "#334166",
      "target-arrow-color": "#334166",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.9,
      "curve-style": "bezier",
      label: "data(label)",
      "font-family": "JetBrains Mono, monospace",
      "font-size": 8,
      color: "#7c8db5",
      "text-background-color": "#05070d",
      "text-background-opacity": 0.85,
      "text-background-padding": "2px",
      "text-rotation": "autorotate",
      "min-zoomed-font-size": 7,
      opacity: 0.9,
      "overlay-opacity": 0,
      "transition-property": "line-color, width, opacity, text-opacity",
      "transition-duration": 700,
      "transition-delay": 250,
      "transition-timing-function": "ease-in-out-sine",
    },
  },
  {
    selector: 'edge[assurance = "observed"]',
    style: { "line-color": "#3a4a72", "target-arrow-color": "#3a4a72" },
  },
  {
    selector: 'edge[assurance = "correlated"]',
    style: {
      "line-color": ASSURANCE_COLOR.correlated,
      "target-arrow-color": ASSURANCE_COLOR.correlated,
      "line-style": "dashed",
      opacity: 0.55,
    },
  },
  {
    selector: 'edge[kind = "LATERAL_MOVE"]',
    style: {
      "line-color": ASSURANCE_COLOR.inferred,
      "target-arrow-color": ASSURANCE_COLOR.inferred,
      width: 3.4,
      "line-style": "solid",
      color: "#fdba74",
      "font-size": 9,
      "font-weight": 700,
      "arrow-scale": 1.2,
    },
  },
  {
    selector: 'edge[kind = "PREDICTED_MOVE"]',
    style: {
      "line-color": ASSURANCE_COLOR.predicted,
      "target-arrow-color": ASSURANCE_COLOR.predicted,
      "line-style": "dotted",
      width: 3,
      color: "#f9a8d4",
      "font-size": 9,
      "font-weight": 700,
      "arrow-scale": 1.2,
    },
  },
  {
    selector: 'edge[kind = "ACCESSES"]',
    style: {
      "line-color": "#475569",
      "target-arrow-color": "#475569",
      "line-style": "dashed",
      opacity: 0.45,
      width: 1.2,
    },
  },
  {
    selector: 'edge[outcome = "failure"]',
    style: {
      "line-color": "#f59e0b",
      "target-arrow-color": "#f59e0b",
      "line-style": "dashed",
      color: "#fcd34d",
    },
  },

  // --- interaction states -------------------------------------------------
  {
    selector: ".step-hidden",
    style: { opacity: 0, "text-opacity": 0, events: "no" },
  },
  {
    selector: "node.step-new",
    style: {
      "border-width": 6,
      "overlay-color": "#38bdf8",
      "overlay-opacity": 0.18,
      "overlay-padding": 12,
      "font-size": 13,
    },
  },
  {
    selector: ".dimmed",
    style: { opacity: 0.12, "text-opacity": 0.1 },
  },
  {
    selector: "node.stage-highlight",
    style: {
      "border-width": 5,
      "background-blacken": -0.2,
      "font-size": 13,
    },
  },
  {
    selector: "edge.stage-highlight",
    style: { width: 4, opacity: 1, "line-color": "#f8fafc", "target-arrow-color": "#f8fafc" },
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#f8fafc",
      "border-width": 4,
    },
  },
  {
    selector: "edge:selected",
    style: { width: 4, "line-color": "#f8fafc", "target-arrow-color": "#f8fafc" },
  },
];
