const GRADE_COLORS = {
  A: "#059669",
  B: "#65a30d",
  C: "#d97706",
  D: "#ea580c",
  F: "#dc2626",
};

const RADIUS = 40;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * Circular 0-100 security score. `value` and `grade` come from the backend score object; the
 * gauge only draws them. `label` names what is being scored (for screen readers).
 */
export default function ScoreGauge({ value, grade, max = 100, label = "Security score" }) {
  const safe = Math.min(Math.max(Number(value) || 0, 0), max);
  const color = GRADE_COLORS[grade] ?? GRADE_COLORS.F;
  const offset = CIRCUMFERENCE * (1 - safe / max);

  return (
    <div
      role="img"
      aria-label={`${label}: ${safe} out of ${max}, grade ${grade}`}
      className="relative inline-block h-28 w-28"
    >
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="50" cy="50" r={RADIUS} fill="none" stroke="#e2e8f0" strokeWidth="10" />
        <circle
          cx="50"
          cy="50"
          r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 150ms ease-out, stroke 150ms ease-out" }}
        />
      </svg>
      <div
        aria-hidden="true"
        className="absolute inset-0 flex flex-col items-center justify-center"
      >
        <span className="text-2xl font-semibold text-slate-900">{safe}</span>
        <span className="text-xs font-semibold" style={{ color }}>
          Grade {grade}
        </span>
      </div>
    </div>
  );
}