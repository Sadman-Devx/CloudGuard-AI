const percent = (p) => `${Math.round(p * 100)}%`;

/** Ranked attack paths. Selecting one highlights it on the graph. */
export default function PathList({ paths, selectedIndex, onSelect }) {
  if (paths.length === 0) {
    return (
      <p className="rounded-lg border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        No attack path from the internet to a crown jewel was found in this
        snapshot. Crown jewels are sensitive databases and buckets declared in
        the configuration&apos;s <code>extensions</code>.
      </p>
    );
  }
  return (
    <ol aria-label="Attack paths" className="space-y-2">
      {paths.map((path, index) => (
        <li key={path.node_ids.join(">")}>
          <button
            type="button"
            aria-pressed={selectedIndex === index}
            onClick={() => onSelect(index)}
            className={`w-full rounded-lg border px-3 py-2 text-left text-sm ${
              selectedIndex === index
                ? "border-rose-400 bg-rose-50"
                : "border-slate-200 bg-white hover:border-slate-400"
            }`}
          >
            <span className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span className="font-semibold text-slate-900">
                #{index + 1} · risk {path.risk}
              </span>
              <span>likelihood {percent(path.probability)}</span>
              <span>
                {path.hops} hop{path.hops === 1 ? "" : "s"}
              </span>
            </span>
            <span className="mt-1 block text-slate-800">
              {path.nodes.map((n) => n.name).join(" → ")}
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}
