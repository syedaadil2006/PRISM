/** Application shell: navigation, routes and the shared live status. */

import { Route, Routes } from "react-router-dom";

import { TopNav } from "./components/TopNav";
import { api } from "./lib/api";
import { useApi } from "./lib/useApi";
import { AttackChains } from "./pages/AttackChains";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Hosts } from "./pages/Hosts";
import { InvestigationPage } from "./pages/InvestigationPage";
import { Mitre } from "./pages/Mitre";
import { Users } from "./pages/Users";

export default function App() {
  const health = useApi(() => api.health(), [], 4000);
  const simulation = useApi(() => api.simulation(), [], 2000);

  return (
    <div className="min-h-full">
      <TopNav health={health.data} simulation={simulation.data} />
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
