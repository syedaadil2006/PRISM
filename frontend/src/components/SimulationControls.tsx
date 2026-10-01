/**
 * Demo Mode controls.
 *
 * The backend gates which events are visible, so pressing Start Attack
 * Simulation replays the dataset through the real pipeline rather than
 * animating a canned picture.
 */

import { useState } from "react";

import { api } from "../lib/api";
import { timeOnly } from "../lib/format";
import type { SimulationStatus } from "../types";

interface Props {
  status: SimulationStatus | null;
  onChange: (status: SimulationStatus) => void;
}

export function SimulationControls({ status, onChange }: Props) {
  const [busy, setBusy] = useState(false);

  const run = async (action: () => Promise<SimulationStatus>) => {
    setBusy(true);
    try {
      onChange(await action());
    } finally {
      setBusy(false);
    }
  };

  const running = status?.state === "running";
  const progress =
    status && status.total > 0 ? Math.round((status.revealed / status.total) * 100) : 0;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {running ? (
        <button className="btn btn-danger" disabled={busy} onClick={() => run(api.simulationPause)}>
          Pause simulation
        </button>
      ) : (
        <button
          className="btn btn-primary"
          disabled={busy}
          onClick={() =>
            run(
              status?.state === "paused" && status.revealed > 0
                ? api.simulationResume
                : api.simulationStart,
            )
          }
        >
          {status?.state === "paused" && status.revealed > 0
            ? "Resume simulation"
            : "Start attack simulation"}
        </button>
      )}

      <button className="btn" disabled={busy} onClick={() => run(() => api.simulationStep(1))}>
        Step
      </button>
      <button className="btn" disabled={busy} onClick={() => run(() => api.simulationReset(false))}>
        Rewind
      </button>
      <button className="btn" disabled={busy} onClick={() => run(() => api.simulationReset(true))}>
        Show full dataset
      </button>

      {status && (
        <div className="flex items-center gap-2">
          <div className="h-1.5 w-28 overflow-hidden rounded-full bg-ink-700">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                running ? "bg-rose-400" : "bg-sky-400"
              }`}
              style={{ width: `${progress}%` }}
            />
          </div>
          <span className="font-mono text-[10px] text-slate-500">
            {status.revealed}/{status.total}
            {status.current_time ? ` @ ${timeOnly(status.current_time)}` : ""}
          </span>
        </div>
      )}
    </div>
  );
}
