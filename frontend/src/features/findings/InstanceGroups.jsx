import SeverityBadge from "./SeverityBadge.jsx";

/** Findings grouped by the instance they affect, worst instance first. */
export default function InstanceGroups({ data, selectedId, onSelect }) {
  if (data.instances.length === 0 && data.unattached.length === 0) {
    return <p className="text-sm text-slate-500">No instances are affected.</p>;
  }
  return (
    <div aria-label="Findings by instance" className="space-y-3">
      {data.instances.map((inst) => (
        <section
          key={inst.id}
          aria-label={`Instance ${inst.name}`}
          className="rounded-lg border border-slate-200 bg-white p-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={inst.worst_severity} />
            <h3 className="text-sm font-semibold">{inst.name}</h3>
            <span className="text-xs text-slate-500">
              {inst.has_public_ip ? "public IP" : "no public IP"}
              {inst.subnet_kind ? ` · ${inst.subnet_kind} subnet` : ""}
            </span>
            <span className="ml-auto text-xs text-slate-500">
              {inst.finding_count} finding{inst.finding_count === 1 ? "" : "s"} via{" "}
              {inst.security_groups.join(", ")}
            </span>
          </div>
          <ul className="mt-2 space-y-1">
            {inst.findings.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => onSelect(f.id)}
                  aria-pressed={selectedId === f.id}
                  className={`flex w-full items-center gap-2 rounded px-2 py-1 text-left text-sm ${
                    selectedId === f.id ? "bg-indigo-50" : "hover:bg-slate-50"
                  }`}
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="font-mono text-xs">{f.rule_id}</span>
                  <span className="flex-1">{f.title}</span>
                  {f.affected_instance_count > 1 && (
                    <span className="text-xs text-slate-500">
                      shared by {f.affected_instance_count} instances
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </section>
      ))}
      {data.unattached.length > 0 && (
        <section
          aria-label="Unattached security groups"
          className="rounded-lg border border-dashed border-slate-300 p-3"
        >
          <h3 className="text-sm font-semibold">
            Security groups no instance uses
          </h3>
          <ul className="mt-2 space-y-1">
            {data.unattached.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => onSelect(f.id)}
                  className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-sm hover:bg-slate-50"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="font-mono text-xs">{f.rule_id}</span>
                  <span className="flex-1">
                    {f.title} ({f.resource_id})
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
