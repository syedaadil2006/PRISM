/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // SOC console palette. The assurance colours below are shared with the
        // graph stylesheet in src/lib/graphStyle.ts, so a "predicted" edge and a
        // "predicted" badge always read as the same thing.
        ink: {
          950: "#05070d",
          900: "#0a0f1a",
          850: "#0f1524",
          800: "#141c2f",
          700: "#1d2740",
          600: "#2a3554",
          500: "#3c4a70",
        },
        observed: "#38bdf8",
        correlated: "#a78bfa",
        inferred: "#fb923c",
        predicted: "#f472b6",
        compromised: "#ef4444",
        suspicious: "#f59e0b",
        position: "#22d3ee",
        safe: "#34d399",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "SFMono-Regular",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(148, 163, 184, 0.08) inset",
        glow: "0 0 24px -6px rgba(56, 189, 248, 0.45)",
      },
      keyframes: {
        pulseRing: {
          "0%": { boxShadow: "0 0 0 0 rgba(239, 68, 68, 0.55)" },
          "70%": { boxShadow: "0 0 0 10px rgba(239, 68, 68, 0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(239, 68, 68, 0)" },
        },
      },
      animation: {
        "pulse-ring": "pulseRing 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};
