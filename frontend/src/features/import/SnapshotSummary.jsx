import Notice from "../../components/Notice.jsx";

const LABELS = {
  vpc: "VPCs",
  subnet: "Subnets",
  internet_gateway: "Internet gateways",
  route_table: "Route tables",
  security_group: "Security groups",
  network_acl: "Network ACLs",
  instance: "Instances",
};

export default function SnapshotSummary({ snapshot, onViewTopology }) {
  return (
    <section aria-label="Imported snapshot" className="space-y-4">
      <Notice tone="success" title={`Snapshot v${snapshot.version} saved and validated`}>
        {snapshot.name || "Unnamed configuration"} · {snapshot.region} · {snapshot.relationship_count}{" "}
        relationships
      </Notice>

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {Object.entries(LABELS).map(([key, label]) => (
          <div key={key} className="rounded-lg border border-slate-200 bg-white px-3 py-2">
            <dt className="text-xs text-slate-500">{label}</dt>
            <dd className="text-xl font-semibold" data-testid={`count-${key}`}>
              {snapshot.resource_counts?.[key] ?? 0}
            </dd>
          </div>
        ))}
      </dl>

      {onViewTopology && (
        <button
          type="button"
          onClick={() => onViewTopology(snapshot)}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
        >
          View topology
        </button>
      )}

      {snapshot.warnings?.length > 0 && (
        <Notice tone="warning" title={`${snapshot.warnings.length} warning(s)`}>
          <ul className="list-disc pl-5">
            {snapshot.warnings.map((w) => (
              <li key={`${w.path}-${w.code}`}>
                <code className="text-xs">{w.path}</code> — {w.message}
              </li>
            ))}
          </ul>
        </Notice>
      )}
    </section>
  );
}