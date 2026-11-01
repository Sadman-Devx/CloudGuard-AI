import { SIDES_TEXT, describeSgRule, detailRows } from "./describe.js";
import { TYPE_LABELS } from "./layout.js";

const KIND_TEXT = {
  attached: "attached to",
  routes_via: "routes via",
  associated_route_table: "uses route table",
  associated_network_acl: "uses network ACL",
  placed_in_subnet: "is in subnet",
  protected_by: "is protected by",
  sg_traffic: "traffic allowed to",
};

function connectionsOf(nodeId, topology) {
  const label = new Map(topology.nodes.map((n) => [n.id, n]));
  return topology.edges
    .filter((e) => e.source === nodeId || e.target === nodeId)
    .map((e) => {
      const outgoing = e.source === nodeId;
      const other = label.get(outgoing ? e.target : e.source);
      return {
        edgeId: e.id,
        otherId: other?.id,
        otherLabel: other?.label ?? (outgoing ? e.target : e.source),
        text: outgoing ? KIND_TEXT[e.kind] : `${KIND_TEXT[e.kind]} (from)`,
        detail: e.label,
      };
    });
}

function NodeDetails({ node, topology, onSelect }) {
  const rows = detailRows(node);
  const connections = connectionsOf(node.id, topology);
  return (
    <>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{TYPE_LABELS[node.type]}</p>
      <h3 className="text-lg font-semibold text-slate-900">{node.label}</h3>
      {node.label !== node.id && <p className="text-xs text-slate-500">{node.id}</p>}

      <dl className="mt-4 space-y-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs font-medium text-slate-500">{row.label}</dt>
            <dd className="mt-0.5 text-sm text-slate-900">
              {row.values.length === 1 ? (
                row.values[0]
              ) : (
                <ul className="space-y-0.5">
                  {row.values.map((v, i) => (
                    <li key={`${v}-${i}`} className="break-words font-mono text-xs">
                      {v}
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </div>
        ))}
      </dl>

      {connections.length > 0 && (
        <div className="mt-5">
          <h4 className="text-xs font-medium uppercase tracking-wide text-slate-500">Connections</h4>
          <ul className="mt-2 space-y-1">
            {connections.map((c) => (
              <li key={c.edgeId} className="text-sm text-slate-700">
                {c.text}{" "}
                <button
                  type="button"
                  onClick={() => c.otherId && onSelect({ kind: "node", id: c.otherId })}
                  className="font-medium text-indigo-700 underline-offset-2 hover:underline"
                >
                  {c.otherLabel}
                </button>
                {c.detail && <span className="text-slate-500"> ({c.detail})</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function EdgeDetails({ edge, topology, onSelect }) {
  const names = new Map(topology.nodes.map((n) => [n.id, n.label]));
  const sides = edge.data?.sides;
  return (
    <>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {edge.kind === "sg_traffic" ? "Security group traffic" : "Connection"}
      </p>
      <h3 className="text-lg font-semibold text-slate-900">
        {names.get(edge.source)} → {names.get(edge.target)}
      </h3>
      {edge.label && <p className="font-mono text-xs text-slate-600">{edge.label}</p>}

      {sides && (
        <p
          className={`mt-3 rounded-lg border px-3 py-2 text-sm ${
            sides === "both" ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-rose-200 bg-rose-50 text-rose-900"
          }`}
        >
          {SIDES_TEXT[sides]}
        </p>
      )}

      {["ingress_rules", "egress_rules"].map((key) => {
        const rules = edge.data?.[key] ?? [];
        const direction = key === "ingress_rules" ? "ingress" : "egress";
        return (
          rules.length > 0 && (
            <div key={key} className="mt-4">
              <h4 className="text-xs font-medium uppercase tracking-wide text-slate-500">
                {direction === "ingress" ? `Ingress on ${names.get(edge.target)}` : `Egress on ${names.get(edge.source)}`}
              </h4>
              <ul className="mt-1 space-y-0.5">
                {rules.map((r, i) => (
                  <li key={i} className="font-mono text-xs">
                    {describeSgRule({ ...r, source_security_group_id: names.get(edge.source), destination_security_group_id: names.get(edge.target) }, direction)}
                  </li>
                ))}
              </ul>
            </div>
          )
        );
      })}

      <div className="mt-5 flex gap-3 text-sm">
        <button type="button" onClick={() => onSelect({ kind: "node", id: edge.source })} className="font-medium text-indigo-700 hover:underline">
          Open {names.get(edge.source)}
        </button>
        <button type="button" onClick={() => onSelect({ kind: "node", id: edge.target })} className="font-medium text-indigo-700 hover:underline">
          Open {names.get(edge.target)}
        </button>
      </div>
    </>
  );
}

export default function DetailPanel({ topology, selection, onSelect, onClear }) {
  const node = selection?.kind === "node" ? topology.nodes.find((n) => n.id === selection.id) : null;
  const edge = selection?.kind === "edge" ? topology.edges.find((e) => e.id === selection.id) : null;

  return (
    <aside aria-label="Resource details" className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      {!node && !edge && (
        <p className="text-sm text-slate-500">Select a resource or connection in the graph to inspect it.</p>
      )}
      {node && <NodeDetails node={node} topology={topology} onSelect={onSelect} />}
      {edge && <EdgeDetails edge={edge} topology={topology} onSelect={onSelect} />}
      {(node || edge) && (
        <button type="button" onClick={onClear} className="mt-5 text-xs font-medium text-slate-500 hover:text-slate-800">
          Clear selection
        </button>
      )}
    </aside>
  );
}