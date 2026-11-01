import { Handle, Position } from "@xyflow/react";

import { NODE_H, NODE_W, TYPE_LABELS } from "./layout.js";

const ACCENT = {
  internet: "border-l-sky-500",
  internet_gateway: "border-l-sky-500",
  route_table: "border-l-amber-500",
  subnet: "border-l-emerald-500",
  network_acl: "border-l-violet-500",
  instance: "border-l-indigo-500",
  security_group: "border-l-rose-400",
};

function subtitle(node) {
  const d = node.data ?? {};
  switch (node.type) {
    case "subnet":
      return d.cidr;
    case "instance":
      return d.public_ip ? `${d.private_ip} · ${d.public_ip}` : d.private_ip;
    case "security_group":
      return `${d.ingress_rule_count} in · ${d.egress_rule_count} out`;
    case "route_table":
      return `${d.routes?.length ?? 0} route(s)`;
    case "network_acl":
      return `${d.subnet_ids?.length ?? 0} subnet(s)`;
    case "internet_gateway":
      return "Gateway";
    default:
      return "";
  }
}

function Chip({ tone, children }) {
  const tones = {
    public: "bg-amber-100 text-amber-900",
    private: "bg-slate-200 text-slate-700",
    ip: "bg-indigo-100 text-indigo-800",
  };
  return <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${tones[tone]}`}>{children}</span>;
}

/** Both-sided handles: edges pick the side facing their other end (see layout.js). */
function Handles() {
  return (
    <>
      <Handle id="l" type="source" position={Position.Left} className="!h-2 !w-2 !bg-slate-400" />
      <Handle id="r" type="source" position={Position.Right} className="!h-2 !w-2 !bg-slate-400" />
    </>
  );
}

export function ResourceNode({ data: node, selected }) {
  const sub = subtitle(node);
  return (
    <div
      aria-label={`${TYPE_LABELS[node.type]} ${node.label}`}
      style={{ width: NODE_W, height: NODE_H }}
      className={`rounded-lg border border-l-4 bg-white px-3 py-1.5 shadow-sm ${ACCENT[node.type] ?? ""} ${
        selected ? "border-indigo-500 ring-2 ring-indigo-300" : "border-slate-200"
      }`}
    >
      <Handles />
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-medium uppercase tracking-wide text-slate-500">{TYPE_LABELS[node.type]}</span>
        <span className="flex gap-1">
          {node.type === "subnet" && <Chip tone={node.data.kind}>{node.data.kind}</Chip>}
          {node.type === "instance" && node.data.has_public_ip && <Chip tone="ip">public IP</Chip>}
        </span>
      </div>
      <div className="truncate text-sm font-semibold text-slate-900" title={node.label}>
        {node.label}
      </div>
      {sub && <div className="truncate text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function InternetNode({ data: node, selected }) {
  return (
    <div
      aria-label="Internet"
      style={{ width: NODE_W, height: NODE_H }}
      className={`flex flex-col justify-center rounded-lg border-2 border-dashed bg-sky-50 px-3 ${
        selected ? "border-sky-600 ring-2 ring-sky-300" : "border-sky-300"
      }`}
    >
      <Handles />
      <div className="text-[10px] font-medium uppercase tracking-wide text-sky-700">Outside</div>
      <div className="text-sm font-semibold text-sky-900">{node.label}</div>
    </div>
  );
}

export function VpcNode({ data: node, selected }) {
  return (
    <div
      aria-label={`VPC ${node.label}`}
      className={`h-full w-full rounded-xl border-2 ${
        selected ? "border-indigo-500 bg-indigo-50/50" : "border-slate-300 bg-slate-100/60"
      }`}
    >
      <div className="px-4 pt-3 text-sm font-semibold text-slate-700">
        VPC · {node.label} <span className="font-normal text-slate-500">{node.data?.cidr}</span>
      </div>
    </div>
  );
}