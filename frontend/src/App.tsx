/** Application shell: navigation, routes and the shared live status. */

import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { ChangePassword } from "./components/ChangePassword";
import { SignIn } from "./components/SignIn";
import { TopNav } from "./components/TopNav";
import { api, type AuthStatus } from "./lib/api";
import { useApi } from "./lib/useApi";
import { Admin } from "./pages/Admin";
import { AttackChains } from "./pages/AttackChains";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Hosts } from "./pages/Hosts";
import { InvestigationPage } from "./pages/InvestigationPage";
import { Mitre } from "./pages/Mitre";
import { Users } from "./pages/Users";

/**
 * Sign-in gate. Start PRISM.bat opens the dashboard with #token=<code>; that
 * code is exchanged for an HttpOnly session cookie and removed from the
 * address bar, so the user is signed in without typing anything.
 */
export default function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);

  const check = useCallback(async () => {
    try {
      setAuth(await api.authStatus());
    } catch {
      setAuth({ enabled: true, authenticated: false });
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const match = window.location.hash.match(/token=([^&]+)/);
      if (match) {
        try {
          await api.login(decodeURIComponent(match[1]));
        } catch {
          // Wrong or stale code: the sign-in screen will ask for it.
        }
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
      await check();
    })();
    const onUnauthorized = () => void check();
    window.addEventListener("prism:unauthorized", onUnauthorized);
    return () => window.removeEventListener("prism:unauthorized", onUnauthorized);
  }, [check]);

  if (!auth) return <div className="p-8 text-sm text-slate-500">Connecting to PRISM...</div>;
  if (auth.enabled && !auth.authenticated) return <SignIn status={auth} onSignedIn={() => void check()} />;
  if (auth.password_change_required) return <ChangePassword status={auth} onDone={() => void check()} />;
  return <Shell auth={auth} onSignedOut={() => void check()} />;
}

/** The hashed bundle this tab is running, e.g. index-Bf_91Y4d.js (none in dev). */
const RUNNING_BUILD = (() => {
  const script = document.querySelector<HTMLScriptElement>('script[type="module"][src*="/assets/index-"]');
  return script ? script.src.split("/").pop() ?? null : null;
})();

function Shell({ auth, onSignedOut }: { auth: AuthStatus; onSignedOut: () => void }) {
  const health = useApi(() => api.health(), [], 4000);

  // After PRISM is updated and restarted, a tab left open would keep running
  // the old dashboard. Reload once the server reports a newer build.
  useEffect(() => {
    const served = health.data?.ui_build;
    if (served && RUNNING_BUILD && served !== RUNNING_BUILD) window.location.reload();
  }, [health.data?.ui_build]);
  const simulation = useApi(() => api.simulation(), [], 2000);
  const live = useApi(() => api.live(), [], 2000);

  return (
    <div className="min-h-full">
      <TopNav
        health={health.data}
        simulation={simulation.data}
        live={live.data}
        auth={auth}
        onSignedOut={onSignedOut}
      />
      <main className="mx-auto max-w-[1800px]">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/investigation" element={<InvestigationPage />} />
          <Route path="/attacks" element={<AttackChains />} />
          <Route path="/events" element={<Events />} />
          <Route path="/mitre" element={<Mitre />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/users" element={<Users />} />
          <Route
            path="/admin"
            element={auth.role === "admin" ? <Admin auth={auth} /> : <Navigate to="/" replace />}
          />
          <Route
            path="*"
            element={
              <div className="p-8 text-sm text-slate-400">
                That page does not exist. Use the navigation above.
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
