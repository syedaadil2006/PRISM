/** Sign-in screen: a named account (user name + password) or the shared access code. */

import { useState, type FormEvent } from "react";

import { api, ApiError, type AuthStatus } from "../lib/api";

const INPUT =
  "w-full rounded-md border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none";

export function SignIn({ status, onSignedIn }: { status: AuthStatus; onSignedIn: () => void }) {
  const accounts = status.accounts !== false;
  const codeAllowed = status.access_code !== false;
  // A fresh install has no accounts yet: start on the access code.
  const [mode, setMode] = useState<"account" | "code">(
    accounts && status.has_accounts ? "account" : "code",
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ready = mode === "code" ? Boolean(code.trim()) : Boolean(username.trim() && password);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      if (mode === "code") await api.login(code.trim());
      else await api.loginUser(username.trim(), password);
      onSignedIn();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "Could not reach PRISM.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen place-content-center px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-xl border border-ink-700 bg-ink-900/80 p-6 shadow-xl"
      >
        <div className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-content-center rounded bg-sky-500/15 font-mono text-sm font-bold text-sky-300 ring-1 ring-sky-500/40">
            P
          </span>
          <div>
            <p className="text-sm font-semibold text-slate-100">PRISM</p>
            <p className="text-[11px] text-slate-500">Sign in to continue</p>
          </div>
        </div>

        {accounts && codeAllowed && (
          <div className="grid grid-cols-2 gap-1 rounded-md bg-ink-850 p-1 text-xs">
            {(["account", "code"] as const).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => {
                  setMode(option);
                  setError(null);
                }}
                className={`rounded px-2 py-1.5 font-medium transition ${
                  mode === option ? "bg-ink-700 text-slate-100" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {option === "account" ? "Account" : "Access code"}
              </button>
            ))}
          </div>
        )}

        {mode === "account" ? (
          <>
            <label className="block space-y-1.5">
              <span className="text-xs text-slate-400">User name</span>
              <input
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className={INPUT}
              />
            </label>
            <label className="block space-y-1.5">
              <span className="text-xs text-slate-400">Password</span>
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={INPUT}
              />
            </label>
          </>
        ) : (
          <label className="block space-y-1.5">
            <span className="text-xs text-slate-400">Access code</span>
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className={`${INPUT} font-mono`}
            />
          </label>
        )}

        {error && <p className="text-xs text-rose-300">{error}</p>}
        <button
          type="submit"
          disabled={busy || !ready}
          className="w-full rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-sky-500 disabled:opacity-50"
        >
          {busy ? "Signing in..." : "Sign in"}
        </button>
        <p className="text-[11px] leading-relaxed text-slate-500">
          {mode === "account" ? (
            <>
              Accounts are created by a PRISM admin on the Admin page. No account yet? Use the access
              code.
            </>
          ) : (
            <>
              Start PRISM.bat signs you in automatically. Otherwise paste the code from{" "}
              <span className="font-mono text-slate-400">backend\data\.prism_token</span> on the
              computer running PRISM (with Docker:{" "}
              <span className="font-mono text-slate-400">docker compose exec prism cat /data/.prism_token</span>
              ). There is no default password: every installation gets its own random code.
            </>
          )}
        </p>
      </form>
    </div>
  );
}
