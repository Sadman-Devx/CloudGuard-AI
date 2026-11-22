import { useMemo } from "react";

import { FALLBACK, TYPE_STYLE } from "./graphStyle.js";
import { edgeKey, layerGraph, NODE_H, NODE_W } from "./layout.js";

/**
 * Attack graph as an SVG. `highlight` is a Set of edge keys ("source>target") drawn in red.
 * Nodes are keyboard-focusable buttons; selecting one asks the page for its blast radius.
 */
export default function AttackGraphView({
  nodes,
  edges,
  highlight,
  selectedId,
  onSelect,
}) {
  const { positions, width, height } = useMemo(
    () => layerGraph(nodes, edges),
    [nodes, edges],
  );

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <svg
        role="group"
        aria-label="Attack graph"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="block"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
          </marker>
          <marker
            id="arrow-hot"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626" />
          </marker>
        </defs>

        {edges.map((e) => {
          const from = positions.get(e.source);
          const to = positions.get(e.target);
          if (!from || !to) return null;
          const hot = highlight?.has(edgeKey(e.source, e.target));
          const x1 = from.x + NODE_W;
          const y1 = from.y + NODE_H / 2;
          const x2 = to.x;
          const y2 = to.y + NODE_H / 2;
          const bend = Math.max(30, (x2 - x1) / 2);
          return (
            <path
              key={edgeKey(e.source, e.target) + e.kind}
              d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke={hot ? "#dc2626" : "#cbd5e1"}
              strokeWidth={hot ? 2.5 : 1.25}
              markerEnd={`url(#${hot ? "arrow-hot" : "arrow"})`}
              opacity={highlight?.size && !hot ? 0.45 : 1}
            >
              <title>{e.label || e.kind}</title>
            </path>
          );
        })}

        {nodes.map((n) => {
          const pos = positions.get(n.id);
          if (!pos) return null;
          const style = TYPE_STYLE[n.type] ?? FALLBACK;
          const selected = selectedId === n.id;
          return (
            <g
              key={n.id}
              role="button"
              tabIndex={0}
              aria-label={`${style.label} ${n.name}${n.crown_jewel ? ", crown jewel" : ""}`}
              aria-pressed={selected}
              transform={`translate(${pos.x} ${pos.y})`}
              onClick={() => onSelect?.(n.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect?.(n.id);
                }
              }}
              className="cursor-pointer outline-none focus-visible:opacity-80"
            >
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={8}
                fill={style.fill}
                stroke={n.crown_jewel ? "#dc2626" : style.stroke}
                strokeWidth={selected ? 3 : n.crown_jewel ? 2.5 : 1.5}
              />
              <text x={10} y={19} fontSize={12} fontWeight={600} fill="#0f172a">
                {n.name.length > 22 ? `${n.name.slice(0, 21)}…` : n.name}
              </text>
              <text x={10} y={35} fontSize={10.5} fill="#475569">
                {style.label}
                {n.crown_jewel ? " · crown jewel" : ""}
              </text>
              <title>{`${n.name} (${n.id})`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
