import { getBlastRadius } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";
import { useAsyncData } from "../../hooks/useAsyncData.js";
import { typeLabel } from "./graphStyle.js";

const TONES = {
  critical: "bg-red-700 text-white",
  high: "bg-orange-100 text-orange-900",
  medium: "bg-amber-100 text-amber-900",
  low: "bg-sky-100 text-sky-900",
};

/** What an attacker who controls one resource could reach next. */
export default function BlastRadiusPanel({ snapshotId, nodeId }) {
  const radius = useAsyncData(nodeId ? `${snapshotId}:${nodeId}` : null, (signal) =>
    getBlastRadius(snapshotId, nodeId, signal),
  );

  if (!nodeId) {
    return (
      <p className="rounded-lg border border-dashed border-slate-300 p-4 text-sm text-slate-500">
        Select a resource on the graph to see its blast radius.
      </p>
    );
  }
  if (radius.error) {
    return (
      <Notice tone="error" title="Could not load the blast radius">
        {radius.error.message}
      </Notice>
    );
  }
  if (!radius.data) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Loading blast radius…
      </p>
    );
  }

  const data = radius.data;
  return (
    <section
      aria-label="Blast radius"
      className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">Blast radius of {data.start.name}</h3>
        <span
          className={`rounded px-2 py-0.5 text-[11px] font-semibold uppercase ${
            TONES[data.severity] ?? TONES.low
          }`}
        >
          {data.severity}
        </span>
      </div>
      <p className="text-slate-600">
        {data.reachable_count === 0
          ? "Nothing else is reachable from here in this model."
          : `${data.reachable_count} resource(s) reachable, ${data.crown_jewels_reached.length} crown jewel(s).`}
      </p>
      {data.reachable.length > 0 && (
        <ul className="space-y-1">
          {data.reachable.slice(0, 8).map((r) => (
            <li key={r.id} className="flex justify-between gap-2">
              <span>
                {r.name}{" "}
                <span className="text-xs text-slate-500">
                  ({typeLabel(r.type)}
                  {r.crown_jewel ? ", crown jewel" : ""})
                </span>
              </span>
              <span className="text-xs text-slate-500">
                {Math.round(r.probability * 100)}% · {r.hops} hop
                {r.hops === 1 ? "" : "s"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
