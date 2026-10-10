/** Admin page: PRISM user accounts and the tamper-evident audit log. */

import { useState, type FormEvent } from "react";

import { api, ApiError, type Account, type AuditCheck, type AuthStatus, type Role } from "../lib/api";
import { DetectionAdmin } from "../components/DetectionAdmin";
import { dateTime } from "../lib/format";
import { useApi } from "../lib/useApi";

const ROLES: Role[] = ["viewer", "analyst", "admin"];
const ROLE_HELP: Record<Role, string> = {
  viewer: "Read only",
  analyst: "Investigate, decide on findings, add data",
  admin: "Everything, plus accounts, audit log and clearing data",
};
const INPUT =
  "rounded-md border border-ink-600 bg-ink-850 px-2.5 py-1.5 text-xs text-slate-100 focus:border-sky-500 focus:outline-none";
const BUTTON =
  "rounded px-2 py-1 text-[11px] text-slate-300 ring-1 ring-ink-600 transition hover:text-white disabled:opacity-40";

function message(cause: unknown): string {
  return cause instanceof ApiError ? cause.message : "Could not reach PRISM.";
}

export function Admin({ auth }: { auth: AuthStatus }) {
  const accounts = useApi(() => api.accounts(), [], 10000);
  const audit = useApi(() => api.audit(200), [], 5000);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [check, setCheck] = useState<AuditCheck | null>(null);

  async function run(action: () => Promise<unknown>, done: string) {
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(done);
      void accounts.refresh();
      void audit.refresh();
    } catch (cause) {
      setError(message(cause));
    }
  }

  function resetPassword(account: Account) {
    const password = window.prompt(`New password for ${account.username} (at least 12 characters):`);
    if (password) void run(() => api.updateAccount(account.username, { password }), `Password reset for ${account.username}.`);
  }

  function remove(account: Account) {
    if (window.confirm(`Delete the account ${account.username}? This cannot be undone.`)) {
      void run(() => api.deleteAccount(account.username), `Deleted ${account.username}.`);
    }
  }

  return (
    <div className="space-y-4 p-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-slate-100">Admin</h1>
        <p className="mt-0.5 text-xs text-slate-500">
          Accounts and roles for this PRISM server, and the audit log of who did what.
        </p>
      </div>

      {error && <p className="rounded-md bg-rose-500/10 px-3 py-2 text-xs text-rose-300 ring-1 ring-rose-500/30">{error}</p>}
      {notice && (
        <p className="rounded-md bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300 ring-1 ring-emerald-500/30">{notice}</p>
      )}

      <section className="panel space-y-3 p-3">
        <h2 className="text-sm font-semibold text-slate-200">Accounts</h2>
        <NewAccountForm onCreate={(u, p, r) => run(() => api.createAccount(u, p, r), `Created ${u}.`)} />
        <div className="overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">User</th>
                <th className="px-3 py-2 font-semibold">Role</th>
                <th className="px-3 py-2 font-semibold">Status</th>
                <th className="px-3 py-2 font-semibold">Last sign-in</th>
                <th className="px-3 py-2 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {(accounts.data ?? []).map((account) => {
                const self = account.username === auth.user;
                return (
                  <tr key={account.username} className="text-slate-300">
                    <td className="px-3 py-2 font-mono">
                      {account.username}
                      {self && <span className="ml-1.5 text-slate-500">(you)</span>}
                      {account.must_change_password && (
                        <span className="ml-1.5 text-amber-300" title="Must choose a new password at next sign-in">
                          (password change pending)
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <select
                        value={account.role}
                        disabled={self}
                        title={ROLE_HELP[account.role]}
                        onChange={(e) =>
                          void run(
                            () => api.updateAccount(account.username, { role: e.target.value as Role }),
                            `${account.username} is now ${e.target.value}.`,
                          )
                        }
                        className={INPUT}
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-3 py-2">
                      {account.disabled ? (
                        <span className="text-rose-300">disabled</span>
                      ) : (
                        <span className="text-emerald-300">active</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-slate-400">
                      {account.last_login ? dateTime(account.last_login) : "never"}
                    </td>
                    <td className="space-x-1.5 px-3 py-2">
                      <button
                        type="button"
                        disabled={self}
                        className={BUTTON}
                        onClick={() =>
                          void run(
                            () => api.updateAccount(account.username, { disabled: !account.disabled }),
                            `${account.username} ${account.disabled ? "enabled" : "disabled"}.`,
                          )
                        }
                      >
                        {account.disabled ? "Enable" : "Disable"}
                      </button>
                      <button type="button" className={BUTTON} onClick={() => resetPassword(account)}>
                        Reset password
                      </button>
                      <button type="button" disabled={self} className={BUTTON} onClick={() => remove(account)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
              {accounts.data?.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-3 text-slate-500">
                    No accounts yet. You are signed in with the shared access code; create named accounts
                    so each person's actions are recorded under their own name.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <DetectionAdmin />

      <section className="panel space-y-3 p-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-slate-200">Audit log</h2>
          <button
            type="button"
            className={BUTTON}
            onClick={() =>
              void api
                .verifyAudit()
                .then(setCheck)
                .catch((cause) => setError(message(cause)))
            }
          >
            Verify integrity
          </button>
          {check &&
            (check.ok ? (
              <span className="text-[11px] text-emerald-300">
                Intact: all {check.entries} entries match their hash chain.
              </span>
            ) : (
              <span className="text-[11px] text-rose-300">
                Broken at entry {check.first_broken}: {check.reason}.
              </span>
            ))}
        </div>
        <div className="max-h-[480px] overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">#</th>
                <th className="px-3 py-2 font-semibold">Time</th>
                <th className="px-3 py-2 font-semibold">Who</th>
                <th className="px-3 py-2 font-semibold">Action</th>
                <th className="px-3 py-2 font-semibold">Target</th>
                <th className="px-3 py-2 font-semibold">Outcome</th>
                <th className="px-3 py-2 font-semibold">From</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800 font-mono">
              {(audit.data ?? []).map((entry) => (
                <tr key={entry.seq} className="text-slate-300">
                  <td className="px-3 py-1.5 text-slate-500">{entry.seq}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-slate-400">{dateTime(entry.ts)}</td>
                  <td className="px-3 py-1.5">{entry.actor}</td>
                  <td className="px-3 py-1.5">{entry.action}</td>
                  <td className="px-3 py-1.5 text-slate-400">{entry.target}</td>
                  <td
                    className={`px-3 py-1.5 ${
                      entry.outcome === "success" ? "text-emerald-300" : "text-amber-300"
                    }`}
                  >
                    {entry.outcome}
                  </td>
                  <td className="px-3 py-1.5 text-slate-500">{entry.address}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function NewAccountForm({ onCreate }: { onCreate: (username: string, password: string, role: Role) => Promise<void> }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");

  async function submit(event: FormEvent) {
    event.preventDefault();
    await onCreate(username.trim().toLowerCase(), password, role);
    setUsername("");
    setPassword("");
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
      <label className="space-y-1">
        <span className="block text-[10px] uppercase tracking-wider text-slate-500">User name</span>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" className={INPUT} />
      </label>
      <label className="space-y-1">
        <span className="block text-[10px] uppercase tracking-wider text-slate-500">Password (12+ characters)</span>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          className={INPUT}
        />
      </label>
      <label className="space-y-1">
        <span className="block text-[10px] uppercase tracking-wider text-slate-500">Role</span>
        <select value={role} onChange={(e) => setRole(e.target.value as Role)} className={INPUT}>
          {ROLES.map((option) => (
            <option key={option} value={option}>
              {option} - {ROLE_HELP[option]}
            </option>
          ))}
        </select>
      </label>
      <button
        type="submit"
        disabled={!username.trim() || !password}
        className="rounded-md bg-sky-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-sky-500 disabled:opacity-50"
      >
        Create account
      </button>
    </form>
  );
}
