import { useState } from "react";

import FindingsPage from "./pages/FindingsPage.jsx";
import ImportPage from "./pages/ImportPage.jsx";
import StatusPage from "./pages/StatusPage.jsx";
import TopologyPage from "./pages/TopologyPage.jsx";

const TABS = [
  { id: "status", label: "Status" },
  { id: "import", label: "Import" },
  { id: "topology", label: "Topology" },
  { id: "findings", label: "Findings" },
];

export default function App() {
  const [tab, setTab] = useState("status");
  const [focus, setFocus] = useState(null); // snapshot to open on the Topology tab

  const viewTopology = (snapshot) => {
    setFocus({ projectId: snapshot.project, snapshotId: snapshot.id });
    setTab("topology");
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight">CloudGuard AI</h1>
            <p className="text-xs text-slate-500">
              Cloud network security copilot with digital twin simulation
            </p>
          </div>
          <span className="rounded-full bg-indigo-50 px-3 py-1 text-xs font-medium text-indigo-700">
            Read-only · no changes are applied to real infrastructure
          </span>
        </div>
        <nav aria-label="Primary" className="mx-auto flex max-w-5xl gap-1 px-4">
          {TABS.map(({ id, label }) => (
            <button
              key={id}
              type="button"
              aria-current={tab === id ? "page" : undefined}
              onClick={() => setTab(id)}
              className={`border-b-2 px-3 py-2 text-sm font-medium ${
                tab === id
                  ? "border-indigo-600 text-indigo-700"
                  : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main
        className={`mx-auto px-4 py-8 ${tab === "topology" ? "max-w-[1500px]" : "max-w-5xl"}`}
      >
        {tab === "status" && <StatusPage />}
        {tab === "import" && <ImportPage onViewTopology={viewTopology} />}
        {tab === "topology" && <TopologyPage focus={focus} />}
        {tab === "findings" && <FindingsPage focus={focus} />}
      </main>
    </div>
  );
}