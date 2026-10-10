/** Shown after signing in with the default or a temporary password: a new one must be chosen first. */

import { useState, type FormEvent } from "react";

import { api, ApiError, type AuthStatus } from "../lib/api";

const INPUT =
  "w-full rounded-md border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none";

export function ChangePassword({ status, onDone }: { status: AuthStatus; onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = Boolean(confirm) && next !== confirm;
  const ready = Boolean(current && next.length >= 12 && next === confirm);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(current, next);
      onDone();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "Could not reach PRISM.");
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    try {
      await api.logout();
    } finally {
      onDone();
    }
  }

  return (
    <div className="grid min-h-screen place-content-center px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-xl border border-ink-700 bg-ink-900/80 p-6 shadow-xl"
      >
        <div>
          <p className="text-sm font-semibold text-slate-100">Choose a new password</p>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
            Signed in as <span className="font-mono text-slate-300">{status.user}</span> with a default or
            temporary password. Choose your own before continuing: at least 12 characters.
          </p>
        </div>
        <label className="block space-y-1.5">
          <span className="text-xs text-slate-400">Current password</span>
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className={INPUT}
          />
        </label>
        <label className="block space-y-1.5">
          <span className="text-xs text-slate-400">New password</span>
          <input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            className={INPUT}
          />
        </label>
        <label className="block space-y-1.5">
          <span className="text-xs text-slate-400">New password again</span>
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={INPUT}
          />
        </label>
        {next && next.length < 12 && <p className="text-xs text-amber-300">{12 - next.length} more character(s).</p>}
        {mismatch && <p className="text-xs text-amber-300">The two new passwords differ.</p>}
        {error && <p className="text-xs text-rose-300">{error}</p>}
        <button
          type="submit"
          disabled={busy || !ready}
          className="w-full rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-sky-500 disabled:opacity-50"
        >
          {busy ? "Saving..." : "Save and continue"}
        </button>
        <button
          type="button"
          onClick={() => void signOut()}
          className="w-full text-center text-[11px] text-slate-500 hover:text-slate-300"
        >
          Sign out
        </button>
      </form>
    </div>
  );
}
