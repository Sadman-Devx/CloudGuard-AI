import { useState } from "react";

export default function ProjectPicker({ projects, selectedId, onSelect, onCreate, busy }) {
  const [name, setName] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    const ok = await onCreate(trimmed);
    if (ok) setName("");
  };

  return (
    <div className="space-y-3">
      <div>
        <label htmlFor="project-select" className="block text-sm font-medium text-slate-700">
          Project
        </label>
        <select
          id="project-select"
          value={selectedId ?? ""}
          onChange={(e) => onSelect(e.target.value ? Number(e.target.value) : null)}
          className="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
        >
          <option value="">{projects.length ? "Select a project…" : "No projects yet"}</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      <form onSubmit={submit} className="flex gap-2">
        <label htmlFor="project-name" className="sr-only">
          New project name
        </label>
        <input
          id="project-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={120}
          placeholder="New project name"
          className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm"
        />
        <button
          type="submit"
          disabled={busy || !name.trim()}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          Create project
        </button>
      </form>
    </div>
  );
}
