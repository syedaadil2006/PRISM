/** Top navigation and the live status strip. */

import { NavLink } from "react-router-dom";

import { api, type AuthStatus } from "../lib/api";
import type { Health, LiveStatus, SimulationStatus } from "../types";

const LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/investigation", label: "Investigation" },
  { to: "/attacks", label: "Attack Chains" },
  { to: "/events", label: "Events" },
  { to: "/mitre", label: "MITRE ATT&CK" },
  { to: "/hosts", label: "Hosts" },
  { to: "/users", label: "Users" },
];

export function TopNav({
  health,
  simulation,
  live: feed,
  auth,
  onSignedOut,
}: {
  health: Health | null;
  simulation: SimulationStatus | null;
  live: LiveStatus | null;
  auth: AuthStatus;
  onSignedOut: () => void;
}) {
  const links = auth.role === "admin" ? [...LINKS, { to: "/admin", label: "Admin" }] : LINKS;

  async function signOut() {
    try {
      await api.logout();
    } finally {
      onSignedOut();
    }
  }

  const live = simulation?.state === "running";
  const streaming = Boolean(feed?.receiving);

  return (
    <header className="sticky top-0 z-20 border-b border-ink-700/70 bg-ink-950/90 backdrop-blur">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5">
        <div className="flex items-center gap-2.5">
          <span className="grid h-7 w-7 place-content-center rounded bg-sky-500/15 font-mono text-xs font-bold text-sky-300 ring-1 ring-sky-500/40">
            P
          </span>
          <div>
            <p className="text-sm font-semibold leading-none tracking-wide text-slate-100">
              PRISM
            </p>
            <p className="mt-0.5 text-[10px] leading-none text-slate-500">
              Agentic SOC investigation platform
            </p>
          </div>
        </div>

        <nav className="flex flex-wrap items-center gap-1">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                `rounded-md px-2.5 py-1.5 text-xs font-medium transition ${
                  isActive
                    ? "bg-ink-800 text-slate-100 ring-1 ring-ink-600"
                    : "text-slate-400 hover:bg-ink-850 hover:text-slate-200"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-3 font-mono text-[10px] text-slate-500">
          {streaming && feed ? (
            <span
              className="flex items-center gap-1.5 rounded bg-rose-500/10 px-1.5 py-0.5 text-rose-300 ring-1 ring-rose-500/30"
              title={`Live feed: ${feed.streams.length} source(s), ${feed.accepted} events received${
                feed.pending_analysis ? ", analysis catching up" : ""
              }`}
            >
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-rose-400" />
              LIVE FEED · {feed.events_per_minute}/min
            </span>
          ) : (
            <span className="flex items-center gap-1.5">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  live ? "animate-pulse bg-rose-400" : health ? "bg-emerald-400" : "bg-slate-600"
                }`}
              />
              {live
                ? "SIMULATION LIVE"
                : feed?.live_only
                  ? "LIVE MODE · WAITING FOR EVENTS"
                  : health
                    ? "PIPELINE READY"
                    : "CONNECTING"}
            </span>
          )}
          {health && (
            <>
              <span>{health.events} events</span>
              <span>{health.chains} chains</span>
              <span className="hidden sm:inline">v{health.version}</span>
            </>
          )}
          {auth.enabled && auth.user && (
            <span className="flex items-center gap-2 border-l border-ink-700 pl-3">
              <span className="text-slate-300" title={`Signed in as ${auth.user} (${auth.role})`}>
                {auth.kind === "access-code" ? "access code" : auth.user}
                <span className="ml-1 rounded bg-ink-800 px-1 py-0.5 uppercase text-slate-400 ring-1 ring-ink-600">
                  {auth.role}
                </span>
              </span>
              <button
                type="button"
                onClick={() => void signOut()}
                className="rounded px-1.5 py-0.5 text-slate-400 ring-1 ring-ink-600 transition hover:text-slate-100"
              >
                Sign out
              </button>
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
