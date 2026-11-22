import { scoreColor } from "./colors.js";

/** Tiny trend line for a project card. */
export default function Sparkline({ points }) {
  if (!points || points.length < 2) return null;
  const W = 96;
  const H = 28;
  const line = points
    .map((p, i) => `${(i / (points.length - 1)) * (W - 4) + 2},${H - 2 - (p.score / 100) * (H - 4)}`)
    .join(" ");
  const last = points[points.length - 1];
  return (
    <svg role="img" aria-label="Score history" viewBox={`0 0 ${W} ${H}`} width={W} height={H}>
      <polyline points={line} fill="none" stroke={scoreColor(last.score)} strokeWidth="2" />
    </svg>
  );
}
