import { scoreColor } from "./colors.js";

const W = 560;
const H = 190;
const PAD = { left: 34, right: 14, top: 12, bottom: 26 };

/** Score (0-100) of every analysed snapshot, oldest to newest. Hover a point for its details. */
export default function TrendChart({ points }) {
  if (!points || points.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        No analysed snapshots yet, so there is no trend to draw.
      </p>
    );
  }
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;
  const x = (i) =>
    PAD.left + (points.length === 1 ? innerW / 2 : (i / (points.length - 1)) * innerW);
  const y = (score) => PAD.top + (1 - Math.max(0, Math.min(100, score)) / 100) * innerH;
  const line = points.map((p, i) => `${x(i)},${y(p.score)}`).join(" ");

  return (
    <svg
      role="img"
      aria-label={`Score trend over ${points.length} snapshot${points.length === 1 ? "" : "s"}`}
      viewBox={`0 0 ${W} ${H}`}
      className="h-auto w-full"
    >
      {[0, 25, 50, 75, 100].map((tick) => (
        <g key={tick}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(tick)} y2={y(tick)} stroke="#e2e8f0" />
          <text x={PAD.left - 6} y={y(tick) + 4} textAnchor="end" fontSize="10" fill="#64748b">
            {tick}
          </text>
        </g>
      ))}
      {points.length > 1 && (
        <polyline points={line} fill="none" stroke="#475569" strokeWidth="2" />
      )}
      {points.map((p, i) => (
        <g key={p.snapshot_id ?? i}>
          <circle cx={x(i)} cy={y(p.score)} r="5" fill={scoreColor(p.score)} stroke="#fff" strokeWidth="1.5">
            <title>{`v${p.version} · score ${p.score} (${p.grade}) · ${p.total} finding${p.total === 1 ? "" : "s"}`}</title>
          </circle>
          <text x={x(i)} y={H - 8} textAnchor="middle" fontSize="10" fill="#64748b">
            v{p.version}
          </text>
        </g>
      ))}
    </svg>
  );
}
