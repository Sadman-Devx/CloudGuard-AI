import { useState } from "react";

import ImportPage from "./pages/ImportPage.jsx";
import StatusPage from "./pages/StatusPage.jsx";

const TABS = [
  { id: "status", label: "Status", Page: StatusPage },
  { id: "import", label: "Import", Page: ImportPage },
];

export default function App() {
  const [tab, setTab] = useState("status");
  const { Page } = TABS.find((t) => t.id === tab);

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight">CloudGuard AI</h1>
            <p className="text-xs text-slate-500">Cloud network security copilot with digital twin simulation</p>
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
      <main className="mx-auto max-w-5xl px-4 py-8">
        <Page />
      </main>
    </div>
  );
}
